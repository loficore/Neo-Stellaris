"""Offline fence for src/dll/c2/donor_exec_probe.zig's pinned readings.

The Zig module hard-codes two pieces of reverse-engineered fact: the 24-byte
prologue fingerprint of the donor Execute override (0x3AFD30) and the five
CEffect-family vtables it classifies against.  Both were copied out of tools by
hand, so this file re-reads them from their *authorities* and fails when the
copy drifts:

* the prologue is compared byte-for-byte against the on-disk stellaris.exe,
  read through ``disrva.rd`` (the only exe-path resolution allowed here — the
  layout fence's R-env rule rejects any literal exe path in a top-level script);
* the vtable table is compared against 取证卷 §57.2 observation 4, the row that
  recorded the five-table verdict.

Why the test reads the Zig *source* and not the built DLL: 约束 8 of the plan —
the DLL's ``.text`` sha is only comparable inside the same build directory, so a
built artifact is not a durable authority for a fingerprint.  The exe is the
authority; the source is the place the constant is written down.

Host-only, zero shots: a file read, one exe byte window, no process, no
Windows API (ruling P3).
"""

import pathlib
import re
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import disrva  # noqa: E402
import c2_donor_probe as donor  # noqa: E402
from c2_donor_probe import (  # noqa: E402
    VERDICTS,
    decode_entry,
    decode_layout,
    decode_stats,
    table_rvas,
    verdict_for,
)

DONOR_RVA = 0x3AFD30
ZIG_MODULE = REPO / "src" / "dll" / "c2" / "donor_exec_probe.zig"
EVIDENCE_VOLUME = REPO / "evidence" / "analysis" / "runtime_444_c1_validation.md"

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
    disassembly text (`mov [rsp+0x10], rbx`) whose commas and stray braces would
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
    volume's own order, which is FAMILY_VTABLES' order.
    """
    text = EVIDENCE_VOLUME.read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines()
            if ln.startswith("| 4 |") and "候选表首" in ln]
    assert len(rows) == 1, f"取证卷取证行应唯一,得到 {len(rows)} 行"
    cells = rows[0].split("|")
    readings = re.findall(r"0x[0-9A-Fa-f]{5,7}", cells[3])
    assert len(readings) == 5, f"§57.2 观测 4 应恰有五张表,得到 {readings}"
    return [int(tok, 16) for tok in readings]


def test_donor_family_vtables_match_evidence_volume():
    src = ZIG_MODULE.read_text(encoding="utf-8")
    assert zig_array_literal(src, "FAMILY_VTABLES") == evidence_family_vtables()


def test_donor_prologue_bytes_match_the_exe():
    src = (REPO / "src/dll/c2/donor_exec_probe.zig").read_text(encoding="utf-8")
    want = zig_array_literal(src, "EXPECTED_CODE")
    assert len(want) == 24
    got = list(disrva.rd(0x3AFD30, 24)[0])   # rd 返回 (bytes, section_name) —— 不取 [0] 会把 section 名当字节比
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
    assert len(raw) == donor.ENTRY_SIZE == 48
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
    """§57.4 tier 1 names the table; tier 2 is the runtime-generated-table case.

    The named tier must resolve to a real RVA through ``table_rvas``, so the
    driver's wording and the Zig module's table cannot drift apart: the same
    five entries the module classifies against are the five the driver can name,
    and index 2 is 0x25F4440 — the table §57.4 actually observed.
    """
    named = verdict_for(_stats(calls=17, samples=17, h0=2, h2=3, unmatched=5,
                               invalid_self=1, patch_size=16))
    assert named == "donor_family_hit_named"
    assert named in VERDICTS
    assert table_rvas() == zig_array_literal(
        ZIG_MODULE.read_text(encoding="utf-8"), "FAMILY_VTABLES")
    assert table_rvas()[2] == 0x25F4440
    assert donor.TARGET_RVA == DONOR_RVA

    unknown = verdict_for(_stats(calls=9, samples=9, unmatched=9, patch_size=16))
    assert unknown == "donor_family_hit_unknown_table"
    assert unknown in VERDICTS


def test_verdict_never_returns_the_third_tier():
    """Review Focus 2: §57.4's tier (c) is NOT reachable by this instrument.

    Tier (c) ("这一族根本不执行") needs the sentinel-body wait plus a proven
    absence, and a calls==0 window in a live campaign only ever means
    "unobserved" (ENVIRONMENT). So the value domain has no third tier at all —
    `no_calls_inconclusive` is what a silent window decodes to, and the ladder
    can never answer with a negative about the family.
    """
    assert verdict_for(_stats()) == "no_calls_inconclusive"
    assert verdict_for(_stats(calls=0, samples=0, invalid_self=0)) == \
        "no_calls_inconclusive"
    assert verdict_for(_stats(calls=7, samples=7, invalid_self=7)) == \
        "instrument_broken"

    assert set(VERDICTS) == {
        "no_calls_inconclusive",
        "donor_family_hit_named",
        "donor_family_hit_unknown_table",
        "instrument_broken",
        "counter_desync",
    }
    assert "no_donor_family_execution" not in VERDICTS

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
