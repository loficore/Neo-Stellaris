"""Offline fence for the C4 witness instrument — ``src/dll/c2/instantiate_witness_probe.zig``
and ``scripts/c2_witness_probe.py``.

Sibling of ``test_c2_donor_probe.py`` (same shape, different target): the witness
guards the family's slot[2] instantiate helper at RVA ``0x3B01A0``, not the
donor's slot[1] Execute override.  Both pieces of reverse-engineered fact the Zig
module hard-codes — the 24-byte prologue fingerprint and the five CEffect-family
vtables — were copied out of tools by hand, so this file re-reads them from their
*authorities* and fails when the copy drifts:

* the prologue is compared byte-for-byte against the on-disk stellaris.exe, read
  through ``disrva.rd`` (the only exe-path resolution allowed here — the layout
  fence's R-env rule rejects any literal exe path in a top-level script);
* the vtable list is compared against 取证卷 §57.2 observation 4, the row that
  recorded the five-table verdict.

The two tests this instrument adds on top of the donor's fourteen are the honest
clause of the spec (§2.3): ``test_verdicts_has_no_tier3_value`` pins that a
silent window can never be reported as engine evidence, and
``test_prologue_bytes_pinned`` pins the Task-1 transcription itself, so the
driver, the Zig module and the exe must all three agree on the same 24 bytes.

Host-only, zero shots: a file read, one exe byte window, no process, no
Windows API (ruling P3).
"""

import inspect
import pathlib
import re
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import disrva  # noqa: E402
import c2_witness_probe as witness  # noqa: E402
from c2_witness_probe import (  # noqa: E402
    VERDICTS,
    decode_entry,
    decode_layout,
    decode_stats,
    table_rvas,
    verdict_for,
)

WITNESS_RVA = 0x3B01A0
ZIG_MODULE = REPO / "src" / "dll" / "c2" / "instantiate_witness_probe.zig"
EVIDENCE_VOLUME = REPO / "evidence" / "analysis" / "runtime_444_c1_validation.md"

# Task 1 的权威读数(scripts/scratch/2026-10_c4_sentinel_window/pin_prologue.py
# 对 RVA 0x3B01A0 的 24 字节窗口)。这里把它当作**独立的第三方**写死:测试文件、
# Zig 模块、磁盘上的 exe 三方必须逐字一致,任何一方漂了就红。
TASK1_PROLOGUE = [
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x4C, 0x89, 0x4C, 0x24, 0x20,
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54,
    0x41, 0x55, 0x41, 0x56,
]
TASK1_FAMILY_VTABLES = [0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0]

# The 6-word layout contract as the Zig module writes it (layoutInto):
# [Entry size, Stats size, RING_LEN, mask low 32, mask high 32, version].
GOOD_LAYOUT = [48, 56, 256, 0, 0, 1]
STATS_KEYS = ("calls", "samples", "invalid_self", "unmatched",
              "h0", "h1", "h2", "h3", "h4", "patch_size", "installed", "mask")


def _stats(**over):
    """A complete 12-key stats dict (decode_stats' output shape) with zeros."""
    base = {key: 0 for key in STATS_KEYS}
    base["installed"] = 1
    base.update(over)
    return base


def _strip_comments(text: str) -> str:
    """Drop `//`-to-end-of-line comments.

    Small reader for hex literal arrays only: neither constant embeds a string
    that could contain `//`, so a plain per-line cut is enough — and it has to
    run *before* brace matching, because a comment in these arrays carries
    disassembly text (`mov [rsp+0x18], rbx`) whose commas and stray braces would
    otherwise be parsed as parts of the literal.
    """
    out = []
    for line in text.splitlines():
        cut = line.find("//")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def zig_array_literal(source: str, name: str) -> list[int]:
    """The integer body of Zig's `pub const <name> … { … }`, as a Python list.

    The anchor is anchored at line start (`^pub const`), so a doc comment that
    quotes the same identifier cannot register as a second declaration.
    """
    anchor = re.search(rf"(?m)^pub const {re.escape(name)}\b", source)
    assert anchor is not None, f"源码里没有 `pub const {name}` 声明"
    rest = _strip_comments(source[anchor.end():])
    open_i = rest.index("{")
    depth = 0
    close_i = -1
    for i in range(open_i, len(rest)):
        if rest[i] == "{":
            depth += 1
        elif rest[i] == "}":
            depth -= 1
            if depth == 0:
                close_i = i
                break
    assert close_i > open_i, f"`pub const {name}` 的花括号不闭合"
    values = []
    for token in rest[open_i + 1:close_i].split(","):
        token = token.strip()
        if not token:
            continue
        assert re.fullmatch(r"0[xX][0-9A-Fa-f]+", token), \
            f"`pub const {name}` 里出现了非十六进制字面量 {token!r}"
        values.append(int(token, 16))
    return values


def evidence_family_vtables() -> list[int]:
    """The five family vtables as recorded in the 取证卷.

    Row-anchor rule, not a "contains these two hex tokens" scan: the volume has
    more than one `| 4 |` line (1022/2771/5067) and more than one line mentioning
    both 0x24B1D98 and 0x2606FE0 (§57.2 观测 4 at 4955 and the three-tier
    judgement table at 5014) — only the observation row is the data source.  The
    discriminator is 「候选表首」 in the second cell, and it is unique as of
    2026-10-26, so a silent drift to another row fails rather than guessing.
    Cell 3 is the 「**5 张**:…」 cell; its five `0x…` tokens are read in the
    volume's own order, which is FAMILY_VTABLES' order.  The witness joins
    against the *same* five tables as the donor — that is the point of §57.4's
    tier-1 question — so this row is the authority for both instruments.
    """
    text = EVIDENCE_VOLUME.read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines()
            if ln.startswith("| 4 |") and "候选表首" in ln]
    assert len(rows) == 1, f"取证卷取证行应唯一,得到 {len(rows)} 行"
    cells = rows[0].split("|")
    readings = re.findall(r"0x[0-9A-Fa-f]{5,7}", cells[3])
    assert len(readings) == 5, f"§57.2 观测 4 应恰有五张表,得到 {readings}"
    return [int(tok, 16) for tok in readings]


def test_witness_family_vtables_match_evidence_volume():
    src = ZIG_MODULE.read_text(encoding="utf-8")
    assert zig_array_literal(src, "FAMILY_VTABLES") == evidence_family_vtables()


def test_witness_prologue_bytes_match_the_exe():
    src = ZIG_MODULE.read_text(encoding="utf-8")
    want = zig_array_literal(src, "EXPECTED_CODE")
    assert len(want) == 24
    got = list(disrva.rd(WITNESS_RVA, 24)[0])   # rd 返回 (bytes, section_name) —— 不取 [0] 会把 section 名当字节比
    assert want == got, "Zig 指纹与磁盘上的 stellaris.exe 不一致"


def test_decode_layout_rejects_unknown_version():
    """The version word is the driver's only defence against a re-ordered layout.

    A driver that "knew" version 2 might guess what the new words mean; the only
    safe reading of an unknown version is refusal, before any install.
    """
    assert decode_layout(GOOD_LAYOUT)["version"] == 1
    for bad_version in (0, 2, 99):
        words = list(GOOD_LAYOUT)
        words[5] = bad_version
        with pytest.raises(ValueError):
            decode_layout(words)


def test_decode_layout_rejects_wrong_entry_size():
    """Every drift away from [48, 56, 256, mask_lo, mask_hi, 1] raises.

    The 5-word copy from c2_scope_probe is the specific trap this fence keeps
    open: mask is a u64 here, so it occupies two words and a 5-word read would
    silently answer `mask=512` for a mask of `1<<32`.
    """
    for short in (GOOD_LAYOUT[:5], list(GOOD_LAYOUT) + [0]):
        with pytest.raises(ValueError):
            decode_layout(short)
    for entry in (40, 56, 64):
        words = list(GOOD_LAYOUT)
        words[0] = entry
        with pytest.raises(ValueError):
            decode_layout(words)
    words = list(GOOD_LAYOUT)
    words[1] = 48           # Stats drifted
    with pytest.raises(ValueError):
        decode_layout(words)
    words = list(GOOD_LAYOUT)
    words[2] = 512          # ring length drifted
    with pytest.raises(ValueError):
        decode_layout(words)
    # mask is split across two words; the driver must recombine, not read word 3.
    assert decode_layout([48, 56, 256, 0x1FF, 0, 1])["mask"] == 0x1FF
    assert decode_layout([48, 56, 256, 0, 1, 1])["mask"] == 1 << 32


def test_decode_entry_reads_all_fields():
    """48-byte Entry, `matched` is 1 + table index, 0 means "not one of the five"."""
    raw = struct.pack("<BBHII4xQQQQ", 1, 3, 0, 0x25F4440, 0x1A2B3C,
                      0x10AB, 0x20CD, 0x30EF, 0x4001)
    assert len(raw) == witness.ENTRY_SIZE == 48
    entry = decode_entry(raw)
    assert entry["valid"] == 1
    assert entry["matched"] == 3
    assert entry["table_index"] == 2
    assert entry["self_vtable_rva"] == 0x25F4440
    assert entry["caller_rva"] == 0x1A2B3C
    assert entry["self_ptr"] == 0x10AB
    assert entry["ctx_ptr"] == 0x20CD
    assert entry["a3"] == 0x30EF
    assert entry["a4"] == 0x4001

    unmatched = decode_entry(struct.pack("<BBHII4xQQQQ", 1, 0, 0, 0x2607100,
                                         0x10, 1, 2, 3, 4))
    assert unmatched["matched"] == 0
    assert unmatched["table_index"] is None
    with pytest.raises(ValueError):
        decode_entry(raw[:47])


def test_decode_stats_parses_every_key():
    """The stats line is the shot's whole verdict surface: 12 keys, `mask` in hex."""
    text = ("calls=17 samples=17 invalid_self=1 unmatched=5 h0=2 h1=0 h2=3 h3=0 "
            "h4=0 patch_size=16 installed=1 mask=1ff\n")
    stats = decode_stats(text)
    assert set(stats) == set(STATS_KEYS)
    assert stats["calls"] == 17
    assert stats["samples"] == 17
    assert stats["invalid_self"] == 1
    assert stats["unmatched"] == 5
    assert [stats[f"h{i}"] for i in range(5)] == [2, 0, 3, 0, 0]
    assert stats["patch_size"] == 16
    assert stats["installed"] == 1
    assert stats["mask"] == 0x1FF
    assert decode_stats("calls=0 samples=0 invalid_self=0 unmatched=0 h0=0 h1=0 "
                        "h2=0 h3=0 h4=0 patch_size=0 installed=0 mask=0")["mask"] == 0


def test_verdict_named_table_and_unknown_table():
    """§57.4 tier 1 names the table; tier 2 is the off-five-table handoff.

    The named tier must resolve to a real RVA through ``table_rvas``, so the
    driver's wording and the Zig module's table cannot drift apart: the same
    five entries the module classifies against are the five the driver can name,
    and index 2 is 0x25F4440 — the table §57.4 actually observed.
    """
    named = verdict_for(_stats(calls=17, samples=17, h0=2, h2=3, unmatched=5,
                               invalid_self=1, patch_size=16))
    assert named == "witness_family_hit_named"
    assert named in VERDICTS
    assert table_rvas() == zig_array_literal(
        ZIG_MODULE.read_text(encoding="utf-8"), "FAMILY_VTABLES")
    assert table_rvas()[2] == 0x25F4440
    assert witness.TARGET_RVA == WITNESS_RVA

    unknown = verdict_for(_stats(calls=9, samples=9, unmatched=9, patch_size=16))
    assert unknown == "witness_family_hit_unknown_table"
    assert unknown in VERDICTS


def test_verdict_never_returns_the_third_tier():
    """Review Focus 1: §57.4's tier (c) is NOT reachable by this instrument.

    The witness is a *stronger* claim than the donor here, so this is the ladder
    read directly: ``calls == 0`` decodes to ``no_calls_inconclusive`` and
    nothing else.  The instantiate helper may only be reached from parse /
    full-tree enumeration (§57.2 观测 4), so a silent witness has two readings
    (the family is not executing / the family executes but not through
    runtime-instantiate) that this instrument cannot separate — it can only
    report "本仪器没问出执行在发生".  The value domain is owned by
    ``test_verdicts_has_no_tier3_value``; here we check the ladder's shape.
    """
    assert verdict_for(_stats()) == "no_calls_inconclusive"
    assert verdict_for(_stats(calls=0, samples=0, invalid_self=0)) == \
        "no_calls_inconclusive"
    assert verdict_for(_stats(calls=7, samples=7, invalid_self=7)) == \
        "instrument_broken"

    # verdict_for only ever answers with a domain member, on every counter shape
    # the stats line can produce (this is what makes VERDICTS the single
    # authority rather than a comment).
    for calls, invalid, unmatched, hit in (
        (0, 0, 0, 0), (5, 5, 0, 0), (5, 2, 3, 0), (5, 0, 0, 1),
        (5, 0, 5, 0), (5, 3, 0, 0), (5, 4, 0, 0), (5, 0, 0, 0),
    ):
        stats = _stats(calls=calls, invalid_self=invalid, unmatched=unmatched,
                       patch_size=16)
        if hit:
            stats["h1"] = hit
        if invalid or unmatched or hit:
            stats["samples"] = calls
        assert verdict_for(stats) in VERDICTS


def test_verdicts_has_no_tier3_value():
    """Review Focus 1 的钉死条款:证人安静不许被写成引擎的陈述。

    donor 一族用「值域里没有第三档」钉同一件事(判读陷阱 1)。证人这一族被问的
    正是 §57.4 的第三档,所以「没有第三档」必须逐字钉住:五档字面完全相等,且
    ``no_calls_inconclusive`` 永远不在证据档里 —— 它只描述本窗口的环境,不描述
    这一族。新增档名同样禁止入值域。
    """
    assert set(VERDICTS) == {
        "no_calls_inconclusive",
        "witness_family_hit_named",
        "witness_family_hit_unknown_table",
        "instrument_broken",
        "counter_desync",
    }
    assert "no_calls_inconclusive" not in witness.EVIDENCE_VERDICTS
    assert set(witness.EVIDENCE_VERDICTS) == {
        "witness_family_hit_named", "witness_family_hit_unknown_table"}
    for banned in ("no_family_execution", "witness_family_never_executes",
                   "tier3_no_execution"):
        assert banned not in VERDICTS


# ---------------------------------------------------------------------------
# Final-review fix pass (donor 一侧的五条):顺序保护与 verify 升级
# ---------------------------------------------------------------------------

def test_verdict_requires_installed_for_code_tiers():
    """Finding 1a: both code tiers are gated on ``installed == 1``.

    ``calls > 0`` with ``installed == 0`` means the numbers did not come from an
    installed probe in this process (a ``Reset`` under a live patch, or a stats
    line read from a different module copy).  That is exactly the cause
    ``counter_desync`` already owns ("the shot's own bookkeeping is broken"), so
    neither code tier may fire — and no sixth verdict is introduced.  The
    ``_stats`` helper keeps ``installed = 1`` by default, so the surviving tier
    assertions below only hold because the gate is checked, not because a code
    tier was removed.
    """
    # tier-2 shape (all h zero, unmatched>0): installed flips the answer.
    assert verdict_for(_stats(calls=9, samples=9, unmatched=9, patch_size=16,
                              installed=0)) == "counter_desync"
    assert verdict_for(_stats(calls=9, samples=9, unmatched=9, patch_size=16,
                              installed=1)) == "witness_family_hit_unknown_table"
    # tier-1 shape (a named table hit) is refused too, not just tier 2.
    assert verdict_for(_stats(calls=17, samples=17, h2=3, unmatched=5,
                              invalid_self=1, patch_size=16,
                              installed=0)) == "counter_desync"


def test_partition_unmatched_splits_by_image_span():
    """Finding 1b: the ring witness splits ``unmatched`` by where the RVA landed.

    Buckets must mirror the ``toRva`` refusal (rva==0), a real in-image RVA, and
    the ``at_or_above`` tail past the live ``SizeOfImage``; a ``matched != 0``
    record is a family hit, not an unmatched row, and must not be counted.
    """
    image_size = 0x3927000            # 4.4.4 SizeOfImage, < the 64 MiB toRva window
    entries = [
        {"matched": 0, "self_vtable_rva": 0},                  # rva_zero (toRva refused)
        {"matched": 0, "self_vtable_rva": 0x1000},             # in_image
        {"matched": 0, "self_vtable_rva": image_size - 1},     # in_image (just below end)
        {"matched": 0, "self_vtable_rva": image_size},         # at_or_above (== SizeOfImage)
        {"matched": 0, "self_vtable_rva": image_size + 0x100},  # at_or_above (the tail)
        {"matched": 3, "self_vtable_rva": 0x25F4440},          # matched -> excluded
    ]
    got = witness.partition_unmatched(entries, image_size)
    assert got == {
        "unmatched_rows": 5,
        "rva_zero": 1,
        "in_image": 2,
        "at_or_above_image": 2,
    }


def test_write_tsv_writes_meta_when_there_are_no_rows(tmp_path):
    """Finding 2's precondition: a meta-only artifact is writable with no rows.

    ``run()`` now writes the ``#meta`` line *before* draining so a torn drain
    cannot erase the whole evidence artifact.  This locks the ``write_tsv``
    contract that makes that ordering meaningful.
    """
    out = tmp_path / "witness_meta_only.tsv"
    meta = {"exe_base": "0x140000000", "verdict": "counter_desync", "calls": 0}
    rows = witness.write_tsv(str(out), [], meta)
    assert rows == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#meta ")
    assert "verdict=counter_desync" in lines[0]
    assert lines[1].startswith("kind\tvalid\tmatched\ttable_index")
    assert len(lines) == 2   # meta + header, no data rows


def test_build_meta_records_entries_error_and_partitions():
    """Finding 1b + 2: build_meta is pure, keeps every key, adds two optionally.

    With ``partitions`` and ``entries_error`` present, the four span numbers and
    the error string are appended alongside the unchanged original keys.  With
    them absent (the pre-drain meta-only write) neither appears — so the first
    artifact line does not carry half-known partition data.
    """
    common = dict(
        exe_base=0x140000000,
        image_end=0x140000000 + 0x3927000,
        dll_path=r"C:/temp/sqjs_c4.dll",
        dll_sha="deadbeef",
        mask=0,
        poll_s=120.0,
        layout={"entry": 48, "stats": 56, "ring": 256, "mask": 0, "version": 1},
        stats=_stats(calls=3, samples=3, unmatched=3),
        stats_text="calls=3 samples=3 invalid_self=0 unmatched=3 h0=0 h1=0 "
                   "h2=0 h3=0 h4=0 patch_size=16 installed=1 mask=0",
        entries=[],
        verdict="witness_family_hit_unknown_table",
        table=None,
        install_rc=0,
    )
    original_keys = (
        "exe_base", "image_size", "image_end", "dll", "dll_sha256", "target_rva",
        "mask", "poll_s", "layout", "calls", "samples", "entries", "tiers",
        "verdict", "named_table", "install_rc", "stats",
    )
    partitions = {"unmatched_rows": 3, "rva_zero": 1, "in_image": 1,
                  "at_or_above_image": 1}

    with_both = witness.build_meta(partitions=partitions, entries_error="short read",
                                   **common)
    for key in original_keys:
        assert key in with_both, f"build_meta dropped an original key {key!r}"
    assert with_both["image_size"] == f"0x{0x3927000:x}"
    assert with_both["unmatched_rows"] == 3
    assert with_both["rva_zero"] == 1
    assert with_both["in_image"] == 1
    assert with_both["at_or_above_image"] == 1
    assert with_both["entries_error"] == "short read"
    assert with_both["target_rva"] == f"0x{WITNESS_RVA:x}"

    without = witness.build_meta(**common)
    for key in ("unmatched_rows", "rva_zero", "in_image", "at_or_above_image",
                "entries_error"):
        assert key not in without, f"{key!r} must only appear when present"
    for key in original_keys:
        assert key in without


def test_prologue_bytes_pinned():
    """Task 1 的转录本身也要被钉住:三方(exe / Zig 模块 / 本文件的字面量)一字不差。

    ``test_witness_prologue_bytes_match_the_exe`` 只证「Zig 抄的是 exe 的字节」;
    本条把 Task 1 从 exe 拷下来的那 24 字节当**独立第三方**压进去,同时要求驱动
    自己的 ``TARGET_RVA`` 与 ``table_rvas()`` 站在这同一个三角里。漂移的形状是:
    靶子换成邻居函数(前序长得一样)、或五表顺序变了但集合不变(那样
    ``h0..h4`` 的编号会指错表)。
    """
    exe_bytes = list(disrva.rd(WITNESS_RVA, 24)[0])
    src = ZIG_MODULE.read_text(encoding="utf-8")
    assert TASK1_PROLOGUE == exe_bytes == zig_array_literal(src, "EXPECTED_CODE")
    assert len(TASK1_PROLOGUE) == 24
    assert witness.TARGET_RVA == 0x3B01A0
    assert witness.table_rvas() == TASK1_FAMILY_VTABLES == evidence_family_vtables()


def test_cleanup_escalates_verify_without_install(monkeypatch, capsys):
    """Finding 3: a bad verify escalates even when this run did not install.

    This is the one test that must stub, because the dependency is a live process
    API (``call_remote`` / ``assert_game_alive`` on a running game).  It exercises
    only the pure control flow of the verify-escalation decision — zero shots.
    ``-6`` (PatchTooWide) armed the patch and then refused it, so the bytes may
    still be modified even though this run never completed an install; ``-3``
    (this process never resolved the target) stays forgiven.
    """
    exports = {"C4WitnessProbeUninstall": 0x11, "C4WitnessProbeVerify": 0x22}
    state = {"verify": -2}

    def fake_call_remote(pid, base, rva, *a, **k):
        if rva == exports["C4WitnessProbeVerify"]:
            return state["verify"]
        return 0                       # uninstall reports a clean return

    monkeypatch.setattr(witness, "call_remote", fake_call_remote)
    monkeypatch.setattr(witness, "call_remote_with_arg", lambda *a, **k: 0)
    monkeypatch.setattr(witness, "assert_game_alive", lambda pid: None)

    # verify=-2 with installed_ok=False must escalate (banner, not-ok).
    state["verify"] = -2
    ok = witness._cleanup(1234, 0x140000000, exports, False, 0)
    assert ok is False
    out = capsys.readouterr().out
    assert "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY" in out

    # verify=-3 (never resolved here) stays forgiven even without an install.
    state["verify"] = -3
    ok = witness._cleanup(1234, 0x140000000, exports, False, 0)
    assert ok is True
    out = capsys.readouterr().out
    assert "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY" not in out


def test_run_writes_the_artifact_before_it_drains_the_ring():
    """终修 Finding 2 的顺序保护:meta-only artifact 必须先于 drain 落盘。

    `write_tsv(path, [], meta)` 本身从来没坏过(所以它单飞时是一条基线就绿的特征
    测试),真正修的是 `run()` 里的**写序**:先写统计、再碰环。这条源文本断言
    把顺序钉住 —— 一次坏 drain 不许吃掉已经拿到的读数(§56 整段 stdout 被
    ssh reset 吃掉的失效模式),证人 shot 同样适用。
    """
    src = inspect.getsource(witness.run)
    readable = src.index("stats, stats_text = last_good")
    drained = src.index("entries = drain_entries(", readable)
    window = src[readable:drained]
    assert "write_tsv(out_path, [], meta)" in window, (
        "run() 必须在 drain 之前写一次 meta-only artifact:一次坏 drain 不许吃掉"
        "已经拿到的读数(§56 整段 stdout 被 ssh reset 吃掉的失效模式)")
    assert "entries_error=None" in src[:drained] or "entries_error = None" in window, (
        "drain 前必须先把 entries_error 初始化,否则 except 分支会引用未绑定变量")
    assert "rows = write_tsv(out_path, entries, meta)" in src[drained:], (
        "drain 之后仍要用环记录重写 artifact,行与 #meta 同源")
