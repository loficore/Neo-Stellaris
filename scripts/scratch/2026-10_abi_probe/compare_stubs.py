#!/usr/bin/env python3
"""§65 compare_stubs.py — Zig/C QuickJS call-stub comparison for the abi probes.

For every `probe_*` export of zig-out/bin/abi_probe_zig.dll and
abi_probe_c.dll: read the PE export table for the RVA, locate the enclosing
function range in **that DLL's own** .pdata (SDD Task 5 ruling: scripts/pdata.py
opens stellaris.exe at import time and cannot serve the probes; fall back to a
fixed instruction count when the PE carries no .pdata), then disassemble the
range through `scripts/pe_disrva.py` (mandated by the brief, works on any PE)
and print the parameter-assembly window that precedes each call to a QuickJS
symbol.

Detector-first (§62.4 family): each stub body must contain exactly ONE `call`
instruction in its function range (the probes are written one-call-per-export;
the C module compiles -fno-stack-protector so no __stack_chk_fail tail sneaks
in). Any other count prints FAIL for that symbol and the script exits 1
without a comparison table.

Judgement traps:
1. Debug codegen is verbose on both sides; compare the ABI *mechanism* (sret
   hidden return pointer, 16 B struct passed as lea'd stack temp, register
   roles), not byte equality.
2. Win64 passes 16 B structs as a pointer to a caller-visible copy (only
   1/2/4/8 B structs get a register) — a `lea r8, [stack]` here is by-value,
   not by-reference, at the language level.
3. The vendored quickjs.c symbols are NOT exported from the probe DLLs, so
   call targets cannot be named from the PE; pairing is by construction (see
   above). pe_disrva `#0x...` annotations are RVAs; the mnemonic operand is
   the link-time VA.

usage: python3 compare_stubs.py [--dll-a PATH] [--dll-b PATH]
"""
from __future__ import annotations

import argparse
import os
import re
import struct as st
import subprocess
import sys

import pefile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DIS = os.path.join(REPO, "scripts", "pe_disrva.py")
WIN_INSNS = 16

LINE = re.compile(r"^\s*([0-9a-f]{4,})\s+(\S+)\s*(.*?)\s*$")
ANNOT = re.compile(r"\s#0x([0-9a-f]+)\s*$")


def load(path):
    pe = pefile.PE(path)
    exports = {}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            exports[e.address] = e.name.decode()
    by_name = {v: k for k, v in exports.items()}
    pdata = None
    for s in pe.sections:
        nm = s.Name.rstrip(b"\0").decode()
        if nm == ".pdata":
            pdata = s.get_data()
            break
    funcs = []
    if pdata:
        for i in range(0, len(pdata) - 11, 12):
            b, e, _u = st.unpack_from("<III", pdata, i)
            funcs.append((b, e))
        funcs.sort()
    return exports, by_name, funcs, int(pe.OPTIONAL_HEADER.ImageBase)


def func_of(funcs, rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, e = funcs[mid]
        if b <= rva < e:
            return b, e
        if rva < b:
            hi = mid - 1
        else:
            lo = mid + 1
    return None


def disasm(dll, begin, end=None, count=None):
    args = [sys.executable, DIS, dll, hex(begin)]
    args.append(hex(end) if end is not None else str(count or 64))
    out = subprocess.run(args, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"pe_disrva failed on {dll} {begin:x}: {out.stderr.strip()}")
    insns = []
    for ln in out.stdout.splitlines():
        if ln.lstrip().startswith(";"):
            continue
        m = LINE.match(ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        rest = m.group(3)
        ann = ANNOT.search(rest)
        target = int(ann.group(1), 16) if ann else None
        text = ANNOT.sub("", rest)
        insns.append((addr, m.group(2), text, target))
    return insns


def norm(insns, upto):
    """Window ending at instruction index `upto` (the call), as mnemonic+shape.

    Absolute addresses become stack/register shapes; rip annotations are kept
    as `#?` so register roles and lea-of-slot stay readable without RVA noise.
    """
    out = []
    for a, mn, op, tgt in insns[max(0, upto - WIN_INSNS):upto + 1]:
        op = re.sub(r"0x[0-9a-f]{5,}", "ADDR", op)
        out.append(f"{mn} {op}".strip())
    return out


def analyze(dll, exports, by_name, funcs, base):
    """{symbol_under_probe: [(call_rva, window)]} with self-check.

    The vendored quickjs.c symbols are NOT in the probe DLLs' export tables,
    so the callee cannot be named from the PE. Pairing is by construction
    instead — each stub body contains exactly ONE call, to its own QuickJS
    symbol (abi_probe.c / abi_probe.zig are written one-call-per-export, the
    C module compiles -fno-stack-protector so clang's __stack_chk_fail tail
    cannot sneak in, and both modules build ReleaseFast so debug artifacts —
    outlined JSValue ctors, panic wrappers — don't masquerade as calls; an
    in-function self-loop call is excluded). The self-check is that count:
    exactly one call/jmp to outside the function, else FAIL. pe_disrva's
    `#0x` annotations are RVAs already (the mnemonic operand is the VA).
    """
    res, fails = {}, []
    for rva, name in sorted(exports.items(), key=lambda kv: kv[1]):
        if not name.startswith("probe_"):
            continue
        want = name[len("probe_"):]
        fr = func_of(funcs, rva) if funcs else None
        insns = (disasm(dll, fr[0], fr[1]) if fr
                 else disasm(dll, rva, count=96))
        lo = fr[0] if fr else rva
        hi = fr[1] if fr else rva + 0x600
        calls = [(i, t) for i, (_a, mn, _op, t) in enumerate(insns)
                 if mn in ("call", "jmp") and t is not None
                 and not (lo <= t < hi)]
        if len(calls) != 1:
            fails.append((name, f"found {len(calls)} calls "
                          f"(want exactly 1 to {want}) in "
                          f"{[('%s:%x' % (insns[i][1], t or 0)) for i, t in calls]}"))
            continue
        i, _t = calls[0]
        res[want] = (insns[i][0], [ln for ln in norm(insns, i)])
    return res, fails


def main(argv=None):
    ap = argparse.ArgumentParser(prog="compare_stubs.py")
    ap.add_argument("--dll-a", default="zig-out/bin/abi_probe_zig.dll")
    ap.add_argument("--dll-b", default="zig-out/bin/abi_probe_c.dll")
    a = ap.parse_args(argv)
    tables, any_fail = {}, []
    for side, path in (("zig", a.dll_a), ("c", a.dll_b)):
        full = path if os.path.isabs(path) else os.path.join(REPO, path)
        exports, by_name, funcs, base = load(full)
        if not funcs:
            print(f"[{side}] no .pdata in {os.path.basename(full)} — "
                  f"fallback: 96 insns from each export")
        res, fails = analyze(full, exports, by_name, funcs, base)
        for f in fails:
            any_fail.append((side,) + f)
        tables[side] = res
    if any_fail:
        for side, name, why in any_fail:
            print(f"FAIL {side} {name}: {why} —— 检测器坏了,停")
        return 1
    names = sorted(set(tables["zig"]) | set(tables["c"]))
    if set(names) != set(tables["zig"]) or set(names) != set(tables["c"]):
        print("FAIL: 双侧符号集合不一致:",
              set(tables["zig"]) ^ set(tables["c"]), "—— 停")
        return 1
    for nm in names:
        z, c = tables["zig"][nm], tables["c"][nm]
        print(f"\n=== {nm} ===")
        print(f"-- zig @0x{z[0]:x} --")
        print("\n".join(z[1]))
        print(f"-- c   @0x{c[0]:x} --")
        print("\n".join(c[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
