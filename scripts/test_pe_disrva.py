"""Contract tests for ``scripts/pe_disrva.py`` — the offline disassembler for
**our own** PE artifact (not the game exe).

The subject is the shipping ``zig-out/bin/stellaris_quickjs.dll``. §47 disassembled the
UBSan trap at ``quickjs.c:1494`` (``js_rc`` -> ``container_of``), a 131-byte function at
``rva 0xbd70..0xbdf3`` in the artifact of that section. §48 removed the
``TypeMismatchData`` record that anchored that listing, so the old span is dead bytes
now; what remains at the same source location is the ``PointerOverflowData`` record for
the ``ptr - offsetof(...)`` arithmetic, and the function that loads it is still ``js_rc``.
These tests derive the span from the artifact itself — record -> LEA site -> ``.pdata``
range — so a rebuild moves the range instead of breaking the tests. They pin the tool's
surface: a range with a subtract-8 and a zero test, rip annotations that resolve to real
RVAs, exit 2 for bad invocations, exit 1 (not 0) for a range that is not code, and exit 2
for a truncated image whose section table claims bytes past EOF.

Everything runs as a subprocess against the built artifact: no game, no process to
attach to, no Windows channel.
"""
import functools
import re
import struct
import subprocess
import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "pe_disrva.py"
DLL = REPO / "zig-out" / "bin" / "stellaris_quickjs.dll"

# The tests cross-check against the *other* offline reader of this same artifact:
# record locations, LEA sites and .pdata function starts. Imported here, in the
# test, so pe_disrva.py itself stays a single-file tool.
sys.path.insert(0, str(REPO / "scripts"))
import dll_ubsan_site  # noqa: E402


@functools.lru_cache(maxsize=1)
def trap_span():
    """((begin, end), record_rva) — ``js_rc``'s .pdata span and the record it loads.

    Anchored on the ``quickjs.c:1494:12`` SourceLocation rather than a fixed RVA. The
    old anchor (a ``TypeMismatchData`` record at that location) was removed by §48;
    the pointer-overflow record for the same expression remains and is still loaded by
    the first ``lea rcx,[rip+…]`` in ``js_rc``. Finding the loading function goes
    through .pdata, so the span is whatever this build emitted.
    """
    data = DLL.read_bytes()
    image_base, secs = dll_ubsan_site.parse(data)
    off_of, _ = dll_ubsan_site.make_maps(secs)
    records = set()
    for name, s_rva, _vsize, raw_size, raw_off in secs:
        if name == ".text" or not raw_size:
            continue
        blob = data[raw_off:raw_off + raw_size]
        for off in range(0, len(blob) - 16, 8):
            ptr, line, col = struct.unpack_from("<QII", blob, off)
            if line != 1494 or col != 12:
                continue
            where = dll_ubsan_site.cstring(data, off_of(ptr - image_base))
            if where.endswith("quickjs.c"):
                records.add(s_rva + off)
    assert len(records) == 1, sorted(records)
    record = records.pop()
    name, text_rva, text_vsize, _raw_size, _raw_off = next(
        s for s in secs if s[0] == ".text")
    hits = dll_ubsan_site.lea_record_targets(
        data, secs, text_rva, text_rva + text_vsize, {record})
    assert record in hits, f"no code loads the {record:#x} record"
    code_rva = min(hits[record])
    span = next(((b, e) for b, e in dll_ubsan_site.runtime_functions(data, secs)
                 if b <= code_rva < e), None)
    assert span, f"rva {code_rva:#x} is not inside any .pdata function entry"
    return span, record


def _run(argv):
    return subprocess.run([sys.executable, str(TOOL), *argv],
                          capture_output=True, text=True)


def _disasm(start, end):
    r = _run([str(DLL), start, end])
    assert r.returncode == 0, f"exit {r.returncode}: {r.stderr}"
    return r.stdout


def _run_args(start, count):
    return _run([str(DLL), start, str(count)])


# "Subtract 8" is a semantic, not an opcode: clang/LLVM may emit sub reg,8,
# add reg,-8 (0xfffffffffffffff8) or lea reg,[reg-8], and the ruler forbids
# rewriting the bytes to match the plan's word "sub".
_SUB8 = (
    re.compile(r"\bsub\s+[a-z][a-z0-9]*,\s*(?:0x)?0*8\b"),
    re.compile(r"\badd\s+[a-z][a-z0-9]*,\s*(?:-0x0*8|-8|0x0*f{15}8)\b"),
    re.compile(r"\blea\s+[a-z][a-z0-9]*,\s*\[[^\]]*-\s*(?:0x)?0*8\s*\]"),
)

# A zero test must compare the register with itself (test r,r) or with literal 0.
# `test al,1` is deliberately NOT accepted: it tests a computed validity flag,
# not "is this pointer null". A je/jz counts as the branch form of the same test.
_TEST_RR = re.compile(r"\btest\s+([a-z][a-z0-9]*),\s*\1\b")
_CMP_ZERO = re.compile(r"\bcmp\s+[a-z][a-z0-9]*,\s*(?:0x0+|0)\b")
_BRANCH_ZERO = re.compile(r"\bj(?:e|z)\b")


def _has_sub8(out):
    return any(p.search(out) for p in _SUB8)


def _has_zero_test(out):
    return any(_TEST_RR.search(line) or _CMP_ZERO.search(line)
               or _BRANCH_ZERO.search(line) for line in out.splitlines())


def test_disasm_finds_the_sub_and_the_null_check_in_the_trap_function():
    # The derived js_rc body must still show: at least one instruction subtracting 8
    # from some register, and a test/cmp against zero — both from the same bytes.
    (start, end), _record = trap_span()
    out = _disasm(hex(start), hex(end))
    assert _has_sub8(out) and _has_zero_test(out)
    # The ruler's byte accounting: printed count == end - start (exclusive end).
    assert f"{end - start} bytes" in out


def test_rip_relative_operands_are_annotated_with_resolved_rvas():
    # Two independent witnesses from the artifact on disk, both derived (never
    # pinned), so this survives a re-link:
    #   (a) at least one `#0x…` equals the quickjs.c:1494:12 record that the
    #       function's `lea` loads — §48 made it a PointerOverflowData, which the
    #       maintained reader does not decode, so the test finds it directly;
    #   (b) at least one `#0x…` equals a .pdata function start (the handler call
    #       target in this function).
    (start, end), record = trap_span()
    data = DLL.read_bytes()
    _image_base, secs = dll_ubsan_site.parse(data)
    function_starts = {begin for begin, _end in
                       dll_ubsan_site.runtime_functions(data, secs)}
    out = _disasm(hex(start), hex(end))
    annotated = {int(m, 16) for m in re.findall(r"#0x([0-9a-f]+)", out)}
    assert annotated, out
    assert record in annotated, sorted(annotated)
    assert annotated & function_starts, sorted(annotated)


def test_bad_inputs_exit_2_not_a_traceback():
    for argv in ([], ["only-one"], ["x.dll", "not-hex"], ["no-such-file.dll", "0x1"]):
        r = _run(argv)
        assert r.returncode == 2, (argv, r.returncode, r.stderr)
        assert "Traceback" not in r.stderr, (argv, r.stderr)
        # One line, and it must come from the tool: a missing script also makes
        # python exit 2, which would make this test green for the wrong reason.
        assert r.stderr.startswith("[pe_disrva] "), (argv, r.stderr)


def test_zero_instruction_range_exits_1_not_0():
    # 落在 .pdata 之外/热数据里的范围反汇编出 0 条 —— 那是「这段不是代码」的结论,
    # 必须与「成功」分开(退出 0 会被 Task 3 读成「这里没有 sub」)。
    # RVA 0 lies in the PE headers; capstone would otherwise decode "MZ..." as
    # instructions, so the executability gate (IMAGE_SCN_MEM_EXECUTE) decides this.
    assert _run_args("0x0", 4).returncode == 1


def test_truncated_image_exits_2_instead_of_clipping_to_the_surviving_prefix(tmp_path):
    # A file cut at 0xb180 — inside .text by RVA, but 4.9 MB short of the raw
    # bytes the section table claims. Before the section-range check the tool
    # decoded the surviving prefix of the trap range and exited 0: a truncated
    # input read as "the listing is the artifact". Truncation is an invocation
    # error (2), the same class as a non-PE file, not a finding.
    (start, end), _record = trap_span()
    trunc = tmp_path / "trunc.dll"
    trunc.write_bytes(DLL.read_bytes()[:0xb180])
    r = _run([str(trunc), hex(start), hex(end)])
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.stderr.startswith("[pe_disrva] "), r.stderr
    assert r.stderr.count("\n") == 1, r.stderr
