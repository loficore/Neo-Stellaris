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
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import disrva  # noqa: E402

DONOR_RVA = 0x3AFD30
ZIG_MODULE = REPO / "src" / "dll" / "c2" / "donor_exec_probe.zig"
EVIDENCE_VOLUME = REPO / "evidence" / "analysis" / "runtime_444_c1_validation.md"


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
