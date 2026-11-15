#!/usr/bin/env python3
"""c46_field_read.py — #46 字段读通道(`C3Field*`)的驱动 + N1 判据。

**必须经 `session_bridge.py` 跑**:SSH 落 session 0 时门读不到窗口(`gate_install`
读的是交互式会话的窗口状态),与其它 shot 驱动同一条规矩。

**这一发问的是什么**(偏移的唯一出处 = `evidence/analysis/runtime_444_transitability_4_4_4.md`
§6.1 / §6.2 / §7):

  * `[系统对象 + 0x1370]`(u32)是不是「这个星系的主人」——三个已知归属不同的星系读出
    **三个互不相同、且 `& 0xffffff` 落在国家 id 集合内**的值;无主星系读到 `0xffffffff`;
  * `[+0x1374]`(u32 锁)+ `[+0x1378..0x1379]`(两个旗标 byte)是不是「锁 + 两旗标」形状
    ——**同一次 6 B 读**回来才算形状成立(分开读的两段不能证明它们相邻)。

**只读**:本驱动只做 `C3FieldLayout` / `C3FieldReadInto` 两个只读导出;不注入
(模块必须**已经在**进程里,通常是 `c2_boot_inject.py` 注进去的那一份)、不挂钩子、
不写引擎内存、不改页保护。

**协议**(契约在 `src/dll/api/field_read.zig` 的 `LAYOUT`;本节与它逐字一致):

  * 一块缓冲 **296 B** = 40 B 头 + 256 B 数据;
  * 请求四格 `kind`(u64 @0, 1=系统 id / 2=国家 id / 3=裸地址)、`subject`(u64 @8)、
    `off`(u32 @16)、`len`(u32 @20);
  * 回复三格 `status`(i32 @24)、`got`(u32 @28)、`resolved`(u64 @32 = 解析到的对象地址),
    数据从 `+40` 起;
  * 六个状态码:`0` 成功 / `-1` 模块基址取不到 / `-2` 对象解析不上 / `-3` 长度越界 /
    `-4` 读不到 / `-5` kind 非法;
  * **`header.status` 必须等于导出返回值**,不等 ⇒ `protocol_desync`(不是「读到了」)。

**四条判读陷阱**(详版在 `docs/offline-tooling.md` 的本脚本一节):

  1. 半途读数:每次调用前整块 296 B 清零再写请求;回读后先比 `status` 与 rc。
  2. `len` 由请求方给:`0` 与 `> 256` 一律 `-3`,DLL 不截断 —— 截断后的成功读数是伪造证据。
  3. 主菜单期两张表全局是 0 ⇒ `-2`,不是「无主 / 没有国家」。
  4. 值域判据要 raw 与 masked 两列:国家 id 带高位(存档里 `0x06000014`),`& 0xffffff`
     才是表索引。

判据纯函数(`decode_layout` / `layout_mismatch` / `decode_reply` / `country_domain` /
`judge_n1` / `classify`)由 `python3 -m pytest scripts/test_c46_field_read.py -q` 覆盖:
无游戏、无 Windows API、无进程。
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
from typing import NamedTuple

# --- wire contract(the DLL's own constants; drift = a red fence) -----------------

LAYOUT_VERSION = 1
BUF_SIZE = 296
OFF_KIND = 0        # u64
OFF_SUBJECT = 8     # u64
OFF_OFF = 16        # u32
OFF_LEN = 20        # u32
OFF_STATUS = 24     # i32
OFF_GOT = 28        # u32
OFF_RESOLVED = 32   # u64
OFF_DATA = 40
MAX_LEN = 256
MAX_KIND = 3

KIND_SYSTEM = 1
KIND_COUNTRY = 2
KIND_RAW = 3

#: `src/dll/shared/offsets.zig` 的 `system_owner` 段(静态推断(未验证) —
#: runtime_444_transitability_4_4_4.md §6.1 owner 行 / §6.2 N1 判据 / §7 store 路径)。
OWNER_OFF = 0x1370
OWNER_LOCK_OFF = 0x1374
OWNER_FLAG_A_OFF = 0x1378
OWNER_FLAG_B_OFF = 0x1379
NO_OWNER = 0xFFFF_FFFF
ID_MASK = 0x00FF_FFFF

#: 「锁 + 两旗标」必须**同一次读**回来:4 B 锁 + 1 B + 1 B。
LOCK_READ_LEN = 6

#: 八个词的对账契约,顺序 = `field_read.LAYOUT` = `docs/offline-tooling.md` 的表格。
EXPECTED_LAYOUT = (
    LAYOUT_VERSION, BUF_SIZE, OFF_DATA, MAX_LEN, MAX_KIND,
    OWNER_OFF, OWNER_LOCK_OFF, ID_MASK,
)

#: 国家表(`src/dll/shared/offsets.zig` 的 `country_table` 段;形状与系统索引相同,
#: 只有全局 RVA 与对象自己的 id 偏移不同)。值域判据要这张表,不是存档(§5.2)。
COUNTRY_TABLE_GLOBAL_RVA = 0x3260FD8
COUNTRY_BOUND_OFF = 0x20
COUNTRY_TABLE_OFF = 0x18
COUNTRY_RECORD_SIZE = 16
COUNTRY_RECORD_PTR_OFF = 8
COUNTRY_OBJECT_ID_OFF = 0x20
#: 防御性上限(不是引擎常量):槽数超过它按「头部不像索引对象」处理,不逐槽扫 2^32 次。
COUNTRY_MAX_SLOTS = 4096

STATUS_OK = 0
STATUS_NO_BASE = -1
STATUS_UNRESOLVED = -2
STATUS_BAD_LEN = -3
STATUS_UNREADABLE = -4
STATUS_BAD_KIND = -5
STATUSES = (STATUS_OK, STATUS_NO_BASE, STATUS_UNRESOLVED, STATUS_BAD_LEN,
            STATUS_UNREADABLE, STATUS_BAD_KIND)

REQUIRED_EXPORTS = ("C3FieldLayout", "C3FieldReadInto")

#: 判词值域。四个 `owner_*` 是 §6.2 的原文;四个通道档是本脚本自己的口径
#: (仪器/环境/协议优先于值域:读数不可信时不许出值域判词)。
VERDICTS = (
    "field_read_ok",
    "protocol_desync",
    "instrument_broken",
    "environment",
    "owner_named",
    "owner_constant",
    "owner_out_of_domain",
    "owner_lock_shape_mismatch",
)
OWNER_VERDICTS = ("owner_named", "owner_constant", "owner_out_of_domain",
                  "owner_lock_shape_mismatch")

#: `#meta` 的固定键序 —— artifact 是给人读的,顺序固定才 diff 得动。
META_ORDER = (
    "overall_verdict",
    "detail",
    "dll",
    "dll_sha256",
    "layout",
    "pid",
    "module_base",
    "game_base",
    "systems",
    "domain_n",
    "domain",
    "unowned",
    "layout_rc",
    "host_alive",
)

EXIT_REFUSED = 2        # pre-flight / environment gate refusal (same code as the siblings)
EXIT_HOST_DEAD = 3      # the pid did not survive the shot


# --- request / reply codec --------------------------------------------------------


def encode_request(kind: int, subject: int, off: int, length: int) -> bytes:
    """The 24 B request header.

    The other 16 header bytes (`status`/`got`/`resolved`) are left at 0 by the
    pre-call clear, and the DLL overwrites them on the way back.

    `struct.pack` refuses values it cannot represent, which is the behaviour we want:
    a caller that hands us an out-of-range id hears about it here, not as a silent
    `-2` from the DLL.
    """
    return struct.pack("<QQII", kind & 0xFFFF_FFFF_FFFF_FFFF,
                       subject & 0xFFFF_FFFF_FFFF_FFFF,
                       off & 0xFFFF_FFFF, length & 0xFFFF_FFFF)
def decode_reply(blob):
    """A 296 B reply -> dict. A short blob raises: it is not a protocol buffer.

    `data` is `got` bytes from `OFF_DATA` — **not** the whole 256 B window: the
    difference between "the DLL read 4 bytes" and "the buffer still had 252 stale
    bytes after them" is the whole point of `got`.
    """
    if len(blob) < BUF_SIZE:
        raise ValueError(f"reply is {len(blob)} B, expected {BUF_SIZE}")
    kind, subject, off, length, status, got, resolved = struct.unpack_from(
        "<QQIIiIQ", blob, 0)
    data = blob[OFF_DATA:OFF_DATA + min(got, MAX_LEN)]
    return {
        "kind": kind,
        "subject": subject,
        "off": off,
        "len": length,
        "status": status,
        "got": got,
        "resolved": resolved,
        "data": data,
        "raw": blob,
    }


def decode_layout(words):
    """The eight layout words -> tuple. Kept separate so the fence compares tuples."""
    return tuple(int(word) & 0xFFFF_FFFF for word in words)


def layout_mismatch(words):
    """`None` when the DLL's layout is ours, otherwise a human-readable diff."""
    got = decode_layout(words)
    if got == EXPECTED_LAYOUT:
        return None
    diffs = [f"word[{i}]={got[i]:#x}!={want:#x}"
             for i, want in enumerate(EXPECTED_LAYOUT)
             if i >= len(got) or got[i] != want]
    if len(got) != len(EXPECTED_LAYOUT):
        diffs.append(f"words={len(got)}!={len(EXPECTED_LAYOUT)}")
    return "layout " + " ".join(diffs)


def format_layout(words):
    return ",".join(f"{word:#x}" for word in decode_layout(words))


# --- judgement: one reply ---------------------------------------------------------


def classify(*, rc, reply, sent, layout_words=EXPECTED_LAYOUT, exports_ok=True,
             missing=(), no_game=False, gate="world_state", alive=True):
    """`(verdict, detail)` for ONE reply. Channel health only — never a value judgement.

    Firing order is fixed, and it is the message: environment first (nothing was
    measured), then instrument (the tool is wrong), then protocol (the buffer is not
    this shot's), and only then `field_read_ok`.

    A **consistent** reply is `field_read_ok` even when its status is `-2`/`-4`: "the
    object did not resolve" and "the address was unreadable" are readings, not tool
    failures — the value judgement is `judge_n1`'s job, and it needs those rows.
    """
    if no_game:
        return "environment", "stellaris.exe is not running"
    if gate == "refused":
        return "environment", "gate_install refused: not IN_GAME_RUNNING"
    if not exports_ok:
        return "instrument_broken", "DLL is missing exports: " + ", ".join(missing)
    if rc == STATUS_NO_BASE:
        return "instrument_broken", "C3FieldReadInto == -1 (module base unresolved: not in the game)"
    if rc not in STATUSES:
        return "instrument_broken", f"C3FieldReadInto == {rc!r}, outside 0/-1..-5"
    if not alive:
        return "environment", "the game process did not survive the shot"

    mismatch = layout_mismatch(layout_words)
    if mismatch:
        return "instrument_broken", mismatch

    if reply is None:
        return "instrument_broken", "no reply buffer was read back"
    if reply["status"] != rc:
        return "protocol_desync", (
            f"header.status={reply['status']} but the export returned {rc} — "
            "the buffer holds another shot's reading")
    for field in ("kind", "subject", "off", "len"):
        if reply[field] != sent[field]:
            return "protocol_desync", (
                f"header.{field}={reply[field]!r} but this shot sent {sent[field]!r}")
    if reply["got"] > MAX_LEN:
        return "protocol_desync", f"got={reply['got']} > MAX_LEN {MAX_LEN}"
    if rc == STATUS_OK and reply["got"] != reply["len"]:
        return "protocol_desync", (
            f"status=0 but got={reply['got']} != len={reply['len']} (a truncated read "
            "is forged evidence)")
    if rc != STATUS_OK and reply["got"] != 0:
        return "protocol_desync", f"status={rc} but got={reply['got']} (partial data on failure)"

    return "field_read_ok", f"status={rc} got={reply['got']} resolved={reply['resolved']:#x}"


# --- judgement: the country id domain (§5.2) --------------------------------------


def country_domain(bound, ids):
    """`(domain, problems)` from one table walk: `bound` = dword `[table_obj+0x20]`,
    `ids` = the per-slot object ids read at `[slot_ptr + 0x20]`.

    The domain is the **raw** ids, sorted; the masked index check (`& 0xffffff`) is a
    shape check on the table itself: a slot index that is outside `bound` means the
    walker is not looking at an index object (or at a different table), not that the
    campaign has an extra country.
    """
    problems = []
    domain = sorted({int(value) for value in ids})
    if bound == 0:
        problems.append("bound=0 — the country table has not been built (main menu); "
                        "the domain is unknown, not empty")
    elif bound > COUNTRY_MAX_SLOTS:
        problems.append(f"bound={bound} exceeds the defensive cap {COUNTRY_MAX_SLOTS} — "
                        "the header does not look like an index object")
    else:
        stray = sorted({value for value in domain if (value & ID_MASK) >= bound})
        if stray:
            problems.append(f"掩码后的槽索引超出 bound={bound}: "
                            f"{[hex(value) for value in stray[:5]]} — 这张表不是国家索引")
    if not domain:
        problems.append("the walk read no ids at all")
    return domain, problems


# --- judgement: N1 (§6.2, verbatim verdicts) --------------------------------------


class OwnerReading(NamedTuple):
    """One system's N1 reading: `owner` at `+0x1370`, then `lock` + two flag bytes.

    `lock_len` is the `got` of the 6 B lock/flags read. It is part of the datum, not
    bookkeeping: the shape claim is "these three fields sit next to each other and came
    back in one read", and two separate reads cannot support it.
    """
    system: int
    owner: int
    lock: int = 0
    flag_a: int = 0
    flag_b: int = 1
    lock_len: int = LOCK_READ_LEN


def judge_n1(*, owned, unowned=None, domain=()):
    """`(verdict, detail)` — §6.2's N1 criteria, in §6.2's failure order.

    `owned` = the A/B/C readings (three systems, three different countries), `unowned`
    = the U row (expected `0xffffffff`), `domain` = the country ids read in the **same**
    shot. The three failure words are the evidence volume's, verbatim:
    `owner_constant` (三值相同) / `owner_out_of_domain` (有值不在国家 id 集合内) /
    `owner_lock_shape_mismatch` (锁/旗标形状不符 ⇒ 那一格不是「带锁的单值格」).

    A non-sentinel U row is reported as `owner_out_of_domain` with a detail that names
    it: §6.2 has no separate word for "the no-owner system has an owner", and inventing
    one here would put a word in the artifact that the evidence volume does not define.
    """
    owned = list(owned)
    if len(owned) < 3:
        return "instrument_broken", (
            f"N1 needs 3 distinctly-owned systems (A/B/C = 3), got {len(owned)} — "
            "the three-value criterion has nothing to be true of")

    owners = [reading.owner for reading in owned]
    repeated = sorted({value for value in owners if owners.count(value) > 1})
    if repeated:
        return "owner_constant", (
            f"owner values {[hex(value) for value in owners]} repeat "
            f"({[hex(value) for value in repeated]}) — the cell is a constant, "
            "not a per-system owner")

    domain_set = {int(value) & ID_MASK for value in domain}
    if not domain_set:
        return "instrument_broken", (
            "the country id domain is empty — the table walk read nothing, so "
            "'the value is a country id' cannot be tested")

    stray = [(reading.system, reading.owner) for reading in owned
             if (reading.owner & ID_MASK) not in domain_set]
    if stray:
        return "owner_out_of_domain", (
            f"systems {[system for system, _ in stray]} read "
            f"{[hex(value) for _, value in stray]} whose masked index is not in the "
            f"{len(domain_set)}-id country domain")

    if unowned is not None and (unowned.owner & 0xFFFF_FFFF) != NO_OWNER:
        return "owner_out_of_domain", (
            f"unowned system {unowned.system} read {unowned.owner & 0xFFFF_FFFF:#010x}, "
            f"expected the no-owner sentinel {NO_OWNER:#010x}")

    every = owned + ([unowned] if unowned is not None else [])
    for reading in every:
        if reading.lock_len != LOCK_READ_LEN:
            return "owner_lock_shape_mismatch", (
                f"system {reading.system}: lock+flags came back as {reading.lock_len} B, "
                f"not one {LOCK_READ_LEN} B read — a torn read cannot prove they are "
                "adjacent")
        if reading.flag_a not in (0, 1) or reading.flag_b not in (0, 1):
            return "owner_lock_shape_mismatch", (
                f"system {reading.system}: flag bytes {reading.flag_a}/{reading.flag_b} "
                "are not 0/1 — this is not the 'lock + two flags' shape")

    unowned_note = ("unowned=absent (no U row: the sentinel was not tested)"
                    if unowned is None else
                    f"unowned system {unowned.system} = {NO_OWNER:#010x}")
    return "owner_named", (
        f"three distinct owners {[hex(value) for value in owners]} all inside a "
        f"{len(domain_set)}-id country domain; lock+flags read as one "
        f"{LOCK_READ_LEN} B window; {unowned_note}")


# --- zero-process plan ------------------------------------------------------------


def plan_n1():
    """N1's expression chain, as text. Pure: no pid, no DLL, no harness import."""
    return "\n".join((
        "N1(读侧,最便宜,先发这一发;一次 install → 读 → uninstall)",
        "1. [sys+0x1370]                u32   owner(无主 = 0xffffffff)",
        "2. [sys+0x1374]                u32   锁",
        "3. [sys+0x1378..0x1379]        2 B   旗标 A / 旗标 B(与锁同一次 6 B 读回)",
        "4. [sys+0x1370] & 0xffffff     ∈ 同趟读出的国家 id 集合(表索引口径,§5.2)",
        "判据: 1 的三个值互不相同;4 成立;2/3 呈「锁 + 两旗标」形状",
        "判词: owner_named",
        "      owner_constant(三值相同)",
        "      owner_out_of_domain(有值不在国家 id 集合内,或 U 行不是 0xffffffff)",
        "      owner_lock_shape_mismatch(锁/旗标形状不符 ⇒ 那一格不是「带锁的单值格」)",
        ("命令: python C:\\temp\\c46_field_read.py <dll> --systems A,B,C,U "
         "--out C:/temp/c46_n1.tsv"),
        ("注: 本命令只读(不注入、不挂钩子);模块必须已经在进程里,且必须经 "
         "session_bridge.py 跑。"),
    ))


# --- artifact ---------------------------------------------------------------------


def build_meta(values):
    """`k=v` lines in `META_ORDER`, then any extra key sorted (a shot may add readings)."""
    lines = [f"{key}={values[key]}" for key in META_ORDER if key in values]
    lines.extend(f"{key}={values[key]}" for key in sorted(values) if key not in META_ORDER)
    return lines


def write_artifact(path, meta_lines, rows, header):
    """Meta first, then a header line, then rows: the artifact survives a lost stdout."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(f"#meta {line}\n" for line in meta_lines)
        handle.write("#" + "\t".join(header) + "\n")
        handle.writelines("\t".join(str(cell) for cell in row) + "\n" for row in rows)


ROW_HEADER = ("system", "kind", "off", "len", "status", "got", "owner_raw",
              "owner_masked", "lock", "flag_a", "flag_b", "channel", "resolved", "detail")


# --- argument parsing -------------------------------------------------------------


def parse_systems(text):
    """`7,42,99` -> `[7, 42, 99]`. Empty / non-integer / negative are refusals."""
    parts = [part.strip() for part in str(text).split(",")]
    if not parts or any(not part for part in parts):
        raise ValueError(f"--systems wants comma-separated ids, got {text!r}")
    systems = []
    for part in parts:
        try:
            value = int(part, 0)
        except ValueError as exc:
            raise ValueError(f"--systems: {part!r} is not an integer") from exc
        if value < 0:
            raise ValueError(f"--systems: {part!r} is negative")
        systems.append(value)
    return systems


def parse_probe(text):
    """`SUBJECT:OFF:LEN` -> `(subject, off, len)`. `len` must be inside 1..MAX_LEN."""
    parts = str(text).split(":")
    if len(parts) != 3:
        raise ValueError(f"--probe wants SUBJECT:OFF:LEN, got {text!r}")
    try:
        subject, off, length = (int(part, 0) for part in parts)
    except ValueError as exc:
        raise ValueError(f"--probe: {text!r} has a non-integer field") from exc
    if subject < 0 or off < 0:
        raise ValueError(f"--probe: {text!r} has a negative subject/off")
    if not 1 <= length <= MAX_LEN:
        raise ValueError(f"--probe: len={length} is outside 1..{MAX_LEN}")
    return subject, off, length


# --- pre-flight -------------------------------------------------------------------


def sha_gate(path):
    """The sha256 of the DLL we are about to attach to. Missing = refuse (exit 2)."""
    if not path or not os.path.exists(path):
        print(f"[field] DLL not found: {path}", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _signed32(value):
    value &= 0xFFFF_FFFF
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


# --- live path (Windows only; not exercised by the host tests) ---------------------


def probe(pid, base, exports, buf, *, kind, subject, off, length):
    """One call: zero the whole buffer -> write the request -> call -> read it back.

    The zeroing is not hygiene, it is the reading's premise (Review Focus #1): the
    remote call gets **one** register, so a buffer that was not cleared can still hold
    the previous shot's bytes, and a failed call would then look like a successful one.
    """
    import c2_harness as harness

    harness.remote_write(pid, buf, bytes(BUF_SIZE))
    harness.remote_write(pid, buf, encode_request(kind, subject, off, length))
    rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C3FieldReadInto"], buf))
    return rc, decode_reply(harness.read_memory(pid, buf, BUF_SIZE))


def _read_scalar(pid, base, exports, buf, addr, length):
    """A raw read through the channel itself (`kind=3`), for the country table walk."""
    rc, reply = probe(pid, base, exports, buf, kind=KIND_RAW, subject=addr, off=0,
                      length=length)
    if rc != STATUS_OK or reply["status"] != STATUS_OK or reply["got"] != length:
        return None, f"read {addr:#x}/{length} -> rc={rc} status={reply['status']}"
    return reply["data"], ""


def _read_ptr(pid, base, exports, buf, addr):
    data, problem = _read_scalar(pid, base, exports, buf, addr, 8)
    if data is None:
        return None, problem
    return struct.unpack("<Q", data)[0], ""


def _read_u32(pid, base, exports, buf, addr):
    data, problem = _read_scalar(pid, base, exports, buf, addr, 4)
    if data is None:
        return None, problem
    return struct.unpack("<I", data)[0], ""


def live_country_domain(pid, base, exports, buf, game_base):
    """The country id domain, walked live through `kind=3` (three steps + per slot).

    `[game_base + 0x3260FD8]` -> table object -> `+0x20` bound, `+0x18` record array ->
    per slot `qword[表 + slot*16 + 8]` -> `dword[对象 + 0x20]`. Every address is checked:
    a failed read is a `problem`, never a zero that would silently shrink the domain.
    """
    problems = []
    if not game_base:
        return [], ["the game module base did not resolve — no domain"]
    table_obj, problem = _read_ptr(pid, base, exports, buf,
                                   game_base + COUNTRY_TABLE_GLOBAL_RVA)
    if table_obj is None:
        return [], [f"country table global: {problem}"]
    if table_obj == 0:
        return [], ["the country table global is 0 — campaign not loaded"]
    bound, problem = _read_u32(pid, base, exports, buf, table_obj + COUNTRY_BOUND_OFF)
    if bound is None:
        return [], [f"table bound: {problem}"]
    table, problem = _read_ptr(pid, base, exports, buf, table_obj + COUNTRY_TABLE_OFF)
    if table is None or table == 0:
        domain, shape = country_domain(bound, [])
        return domain, shape + ([f"table pointer: {problem}"] if problem else
                                ["the table pointer is 0"])

    ids = []
    for slot in range(min(bound, COUNTRY_MAX_SLOTS)):
        entry, problem = _read_ptr(pid, base, exports, buf,
                                   table + slot * COUNTRY_RECORD_SIZE + COUNTRY_RECORD_PTR_OFF)
        if entry is None:
            problems.append(f"slot {slot} pointer: {problem}")
            continue
        if entry == 0:
            continue                      # empty slot: legal, not a country
        ident, problem = _read_u32(pid, base, exports, buf, entry + COUNTRY_OBJECT_ID_OFF)
        if ident is None:
            problems.append(f"slot {slot} id: {problem}")
            continue
        ids.append(ident)
    domain, shape = country_domain(bound, ids)
    return domain, shape + problems


def attach(pid, dll_path, harness):
    """`(base, exports)` for the module that is ALREADY resident. Never injects.

    Why attach-only: the channel has no install step (no hook, no patch), so the only
    thing to resolve is where our code is. Injecting here would mean a second copy in
    the same process on any re-run, which is exactly the ambiguity ruling P8 refuses —
    and a shot driver that injects must also carry a world-state gate, which this
    zero-window plan cannot specify.
    """
    exports = harness.list_exports(dll_path)
    missing = [name for name in REQUIRED_EXPORTS if name not in exports]
    if missing:
        print(f"[field] {dll_path} is missing {missing} — refusing", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)
    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    try:
        base = harness.resolve_base_address(pid, dll_name)
    except RuntimeError as exc:
        print(f"[field] {dll_name} is not resident in pid {pid} ({exc}) — refusing: this "
              "driver attaches, it never injects", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED) from exc
    head = harness.read_memory(pid, base, 2)
    if head != b"MZ":
        print(f"[field] bad header at {base:#x}: {head!r} — refusing", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)
    return base, exports


def run(dll_path, out_path, *, systems=(), probes=(), probe_kind=KIND_SYSTEM):
    """One shot: layout check -> per-system owner/lock/flags -> country domain -> judge.

    `systems` = `[A, B, C]` (+ optional `U` as the 4th): the first three are the
    distinctly-owned systems, the fourth is the unowned one. `probes` =
    `[(subject, off, len), ...]` raw single-point readings, reported verbatim.
    """
    import c2_harness as harness

    dll_sha = sha_gate(dll_path)
    print(f"[field] dll={dll_path} sha256={dll_sha}")

    try:
        pid = harness.resolve_pid("stellaris.exe")
    except RuntimeError:
        print("[field] stellaris.exe is not running — no shot", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    base, exports = attach(pid, dll_path, harness)
    print(f"[field] attached pid={pid} base={base:#x} (no injection)")

    buf = harness.remote_alloc(pid, BUF_SIZE)
    layout_buf = harness.remote_alloc(pid, len(EXPECTED_LAYOUT) * 4)
    harness.call_remote_with_arg(pid, base, exports["C3FieldLayout"], layout_buf)
    layout = struct.unpack(f"<{len(EXPECTED_LAYOUT)}I",
                           harness.read_memory(pid, layout_buf, len(EXPECTED_LAYOUT) * 4))
    print(f"[field] layout={format_layout(layout)}")
    mismatch = layout_mismatch(layout)
    if mismatch:
        print(f"[field] {mismatch} — refusing to read", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    try:
        game_base = harness.resolve_base_address(pid, "stellaris.exe")
    except RuntimeError:
        game_base = 0

    rows, readings, channel = [], [], "field_read_ok"

    def one(kind, subject, off, length):
        """One reading + its channel verdict. A channel-level failure is sticky: the
        first non-`field_read_ok` decides the shot's verdict (later rows cannot repair
        an instrument that was broken at row 1)."""
        nonlocal channel
        rc, reply = probe(pid, base, exports, buf, kind=kind, subject=subject, off=off,
                          length=length)
        verdict, detail = classify(rc=rc, reply=reply,
                                   sent={"kind": kind, "subject": subject,
                                         "off": off, "len": length},
                                   layout_words=layout)
        if verdict != "field_read_ok":
            channel = verdict
            print(f"[field] {verdict}: kind={kind} subject={subject} "
                  f"off={off:#x} len={length} — {detail}", file=sys.stderr)
        return reply, verdict, detail

    for system in systems:
        owner_reply, owner_channel, owner_detail = one(KIND_SYSTEM, system, OWNER_OFF, 4)
        lock_reply, lock_channel, lock_detail = one(KIND_SYSTEM, system,
                                                    OWNER_LOCK_OFF, LOCK_READ_LEN)
        complete = owner_reply["status"] == STATUS_OK and owner_reply["got"] == 4
        owner = int.from_bytes(owner_reply["data"], "little") if complete else 0
        lock_ok = lock_reply["status"] == STATUS_OK and lock_reply["got"] == LOCK_READ_LEN
        lock = int.from_bytes(lock_reply["data"][0:4], "little") if lock_ok else 0
        flag_a = lock_reply["data"][4] if lock_ok else 0
        flag_b = lock_reply["data"][5] if lock_ok else 0
        rows.append((system, "owner", f"{OWNER_OFF:#x}", 4, owner_reply["status"],
                     owner_reply["got"], owner, f"{owner & ID_MASK:#x}", "-", "-", "-",
                     owner_channel, f"{owner_reply['resolved']:#x}", owner_detail))
        rows.append((system, "lock+flags", f"{OWNER_LOCK_OFF:#x}", LOCK_READ_LEN,
                     lock_reply["status"], lock_reply["got"], "-", "-", lock,
                     flag_a, flag_b, lock_channel,
                     f"{lock_reply['resolved']:#x}", lock_detail))
        readings.append(OwnerReading(system=system, owner=owner, lock=lock,
                                     flag_a=flag_a, flag_b=flag_b,
                                     lock_len=lock_reply["got"]))

    for subject, off, length in probes:
        reply, verdict, detail = one(probe_kind, subject, off, length)
        rows.append((subject, f"probe{probe_kind}", f"{off:#x}", length,
                     reply["status"], reply["got"], reply["data"].hex() or "-",
                     "-", "-", "-", "-", verdict, f"{reply['resolved']:#x}", detail))

    domain, problems = live_country_domain(pid, base, exports, buf, game_base)
    for problem in problems:
        print(f"[field] domain: {problem}", file=sys.stderr)

    if len(systems) > 3:
        owned, unowned = readings[:3], readings[3]
    else:
        owned, unowned = readings[:3], None

    try:
        harness.assert_game_alive(pid)
        alive = True
    except Exception:                    # noqa: BLE001 — a dead host is a reading
        alive = False

    if channel != "field_read_ok":
        verdict, detail = channel, "channel-level verdict wins: see the stderr lines"
    elif not alive:
        verdict, detail = "environment", "the game process did not survive the shot"
    elif problems:
        verdict, detail = "instrument_broken", "; ".join(problems)
    else:
        verdict, detail = judge_n1(owned=owned, unowned=unowned, domain=domain)

    meta = {
        "overall_verdict": verdict,
        "detail": detail,
        "dll": os.path.basename(dll_path.replace("\\", "/")),
        "dll_sha256": dll_sha,
        "layout": format_layout(layout),
        "pid": pid,
        "module_base": f"{base:#x}",
        "game_base": f"{game_base:#x}",
        "systems": ",".join(str(system) for system in systems),
        "domain_n": len(domain),
        "domain": ",".join(str(ident) for ident in domain),
        "unowned": "absent" if unowned is None else f"{unowned.system}:{unowned.owner:#x}",
        "host_alive": int(alive),
    }
    write_artifact(out_path, build_meta(meta), rows, ROW_HEADER)
    print(f"[field] verdict={verdict}  {detail}")
    print(f"[field] artifact={out_path}")

    if not alive:
        print("[field] HOST DIED — run scripts/c2_selfabort_repro.py and "
              "scripts/dll_ubsan_site.py before anything else (AGENTS 约束 8)",
              file=sys.stderr)
        return meta, EXIT_HOST_DEAD
    return meta, 0


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"C:\temp\sqjs_g1.dll")
    parser.add_argument("--plan", choices=("n1",), default=None,
                        help="print N1's expression chain and verdicts; no process, no DLL")
    parser.add_argument("--systems", default=None,
                        help="A,B,C[,U] — three distinctly-owned systems, the 4th unowned")
    parser.add_argument("--probe", action="append", default=[], metavar="SUBJECT:OFF:LEN",
                        help="single raw reading (repeatable); kind comes from --probe-kind")
    parser.add_argument("--probe-kind", type=int, default=KIND_SYSTEM,
                        choices=(KIND_SYSTEM, KIND_COUNTRY, KIND_RAW))
    parser.add_argument("--out", default="C:/temp/c46_n1.tsv")
    args = parser.parse_args(argv)

    if args.plan:
        print(plan_n1())
        return 0

    systems = []
    try:
        if args.systems:
            systems = parse_systems(args.systems)
        probes = [parse_probe(text) for text in args.probe]
    except ValueError as exc:
        parser.error(str(exc))
    if not systems and not probes:
        parser.error("give --systems and/or --probe (or --plan n1 for the zero-process plan)")
    if systems and len(systems) not in (3, 4):
        parser.error("--systems wants 3 ids (A,B,C) or 4 (A,B,C,U)")

    _, code = run(args.dll, args.out, systems=systems, probes=probes,
                  probe_kind=args.probe_kind)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
