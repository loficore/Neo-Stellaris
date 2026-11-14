#!/usr/bin/env python3
"""One-off probe (#55 SDK API stub audit, Task 0 Step 2): every rip-relative
reference whose **target** lands in an RVA range.

Why this exists: `global_xrefs.py` answers "who references THIS address" one
address at a time (~20 s per run). Asking "is any address in this window
referenced at all" therefore costs 8 s per 8-byte candidate -- a window of one
object becomes an hour. This probe inverts the search: one linear pass over
.text computes, for every disp32 position, the 4..8-byte-away instruction end
and the target it resolves to, and keeps the hits inside [lo, hi]. Same
arithmetic as `global_xrefs.candidates_for_global`, same confirmation step
(decode the containing .pdata function and require an instruction that really
ends at the resolved address), same traps -- the two disagreeing is a finding.

usage: global_xref_range.py <lo_hex> <hi_hex> [--json]
    TSV rows: target \t refs \t insn_rva[,insn_rva...] \t mnemonic/op_str of first
    last line: targets=N refs=M

Reading traps (inherited, do not relax):
  * a `mov [rip+..], imm` is a write, `mov reg,[rip+..]` is a read -- this probe
    reports references, not shape; use `global_xrefs.py <target>` for the shape
    of any target that shows up here.
  * `mov reg,[rip+..]` with the *address* taken (`lea`) is a base load: an object
    field is reachable as `[base + off]` and its base -- not the field -- is the
    referenced address. That is exactly the question this probe answers.
  * a target with 0 refs in this window is not "unused memory": .data can be
    read by non-rip-relative forms (absolute 64-bit operand, tables of pointers).
    The verdicts here are about *code* references.

Reads only a local exe copy (NS_STELLARIS_EXE or the 4.4.4 default). No process,
no IDA, no Frida.
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                + "/2026-11_dirty_bit")
import global_xrefs as gx  # same algorithm, one copy (import after the sys.path insert)


def candidates_in_range(text, tva, lo, hi):
    """Every (p_rva, target) whose disp32 at p resolves into [lo, hi]."""
    out = []
    up = struct.unpack_from
    n = len(text)
    for p in range(n - 8):
        rva = tva + p
        v = up('<i', text, p)[0]
        # instruction ends 4..8 bytes after p -> target spans [rva+4+v, rva+8+v]
        t_lo = rva + 4 + v
        t_hi = rva + 8 + v
        if t_hi < lo or t_lo > hi:
            continue
        for k in range(4, 9):
            t = rva + k + v
            if lo <= t <= hi:
                out.append((rva, t))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('lo', help='range start RVA, hex like 0x3287000')
    ap.add_argument('hi', help='range end RVA (inclusive), hex')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    exe = gx.resolve_exe()
    if exe is None:
        sys.exit('stellaris.exe not found - set NS_STELLARIS_EXE')
    lo, hi = int(a.lo, 16), int(a.hi, 16)
    img = gx.Image(exe)
    raw = candidates_in_range(img.text, img.tva, lo, hi)

    # Confirm each candidate the same way global_xrefs does: the containing
    # function must decode to an instruction that ends exactly at the resolved
    # address and carries a rip-relative operand resolving to the target.
    confirmed = {}
    cache = {}
    for p, target in raw:
        fn = img.func_of(target - 1) or img.func_of(p)
        key = fn
        if key not in cache:
            cache[key] = img.decode(fn[0], fn[1]) if fn else None
        ins_list = cache[key]
        hit = None
        if ins_list:
            for ins in ins_list:
                start = ins.address - gx.BASE
                if start <= p < start + ins.size and any(
                        op.type == gx.X86_OP_MEM
                        and op.mem.base in (gx.X86_REG_RIP, gx.X86_REG_EIP)
                        and start + ins.size + op.mem.disp == target
                        for op in ins.operands):
                    hit = ins
                    break
        if hit is None:
            # leaf fragment without .pdata: decode locally, accept only an exact
            # end-at-target match (same fallback as global_xrefs)
            local = img.decode(p - 2, p - 2 + 0x40)
            for ins in local:
                start = ins.address - gx.BASE
                if start <= p < start + ins.size and any(
                        op.type == gx.X86_OP_MEM
                        and op.mem.base in (gx.X86_REG_RIP, gx.X86_REG_EIP)
                        and start + ins.size + op.mem.disp == target
                        for op in ins.operands):
                    hit = ins
                    break
        rec = confirmed.setdefault(target, {'insns': [], 'first': None})
        if hit is not None:
            rec['insns'].append(hit.address - gx.BASE)
            if rec['first'] is None:
                rec['first'] = f'{hit.mnemonic} {hit.op_str}'

    rows = []
    for target in sorted(confirmed):
        rec = confirmed[target]
        rows.append({'target': target, 'refs': len(rec['insns']),
                     'insns': sorted(rec['insns']), 'first': rec['first'] or '<no decode>'})

    if a.json:
        print(json.dumps({'module': exe, 'range': [f'0x{lo:x}', f'0x{hi:x}'],
                          'rows': [{**r, 'target': f"0x{r['target']:x}",
                                    'insns': [f'0x{i:x}' for i in r['insns']]}
                                   for r in rows]}, indent=2))
        return
    print(f'# module {exe}')
    print(f'# range 0x{lo:x}..0x{hi:x}  raw_candidates={len(raw)}')
    for r in rows:
        insns = ','.join(f'0x{i:x}' for i in r['insns'][:4])
        print(f"0x{r['target']:x}\t{r['refs']}\t{insns}\t{r['first']}")
    print(f"targets={len(rows)} refs={sum(r['refs'] for r in rows)}")


if __name__ == '__main__':
    main()
