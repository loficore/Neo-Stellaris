"""Contract tests for ``scripts/pe_disrva.py`` — the offline disassembler for
**our own** PE artifact (not the game exe).

The subject is the shipping ``zig-out/bin/stellaris_quickjs.dll``. §45 pinned the
UBSan trap to ``quickjs.c:1494`` (``js_rc`` -> ``container_of``) inside the 131-byte
function at ``rva 0xbd70..0xbdf3`` (end exclusive, per ``.pdata``); §47 needs a
disassembly of those bytes to decide whether the null check tests the pointer
before or after the ``-8``. These four tests pin the tool's surface — a range with
a subtract-8 and a zero test, rip annotations, exit 2 for bad invocations, and
exit 1 (not 0) for a range that is not code.

Everything runs as a subprocess against the built artifact: no game, no process
to attach to, no Windows channel.
"""
import re
import subprocess
import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "pe_disrva.py"
DLL = REPO / "zig-out" / "bin" / "stellaris_quickjs.dll"

# 131 bytes from .pdata (begin inclusive, end exclusive). The tool must print the
# same byte count so "end exclusive" cannot silently become "end inclusive".
TRAP_START, TRAP_END = "0xbd70", "0xbdf3"
TRAP_BYTES = int(TRAP_END, 16) - int(TRAP_START, 16)


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
    # 0xbd70..0xbdf3 里必须能数出:至少一条把某寄存器减 8 的指令,
    # 以及一条 test/cmp 对 0 的判零;两者都反汇编自同一段字节。
    out = _disasm(TRAP_START, TRAP_END)
    assert _has_sub8(out) and _has_zero_test(out)
    # The ruler's byte accounting: printed count == end - start (exclusive end).
    assert f"{TRAP_BYTES} bytes" in out


def test_rip_relative_operands_are_annotated_with_resolved_rvas():
    out = _disasm(TRAP_START, TRAP_END)
    assert re.search(r"#0x[0-9a-f]+", out)      # 标注格式:<disasm>  #<resolved rva>


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
