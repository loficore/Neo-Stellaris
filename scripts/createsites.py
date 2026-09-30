#!/usr/bin/env python3
"""Locate every code site that calls a `create`-style slot out of a value record.

§22.4: the two halves of a keyword `class_info` have ZERO direct call sites, so the
consumer cannot be found by address search. It can be found by *shape*. The value record
is `new(0x10){&class_info, &docstring}` at `BST node+0x28` (std::map<u32,void*> with the
MSVC node layout _Left/_Parent/_Right/_Color+Isnil/_Key@0x20/_Value@0x28, and `create` is
`class_info+8`). So a reader must contain, close together:

    mov r?, [r? + 0x28]      ; value record out of the node
    mov r?, [r?]             ; class_info
    call qword ptr [r? + 8]  ; create -- an indirect call whose target is never an immediate

Decoding is aligned per `.pdata` function, never from an arbitrary offset: a linear
capstone window starting mid-instruction resynchronises by luck and reports phantom
matches (a first draft of this tool "found" 190 sites in one function that way). To keep
it to a few seconds, only functions whose raw bytes contain the `call [reg+disp8=8]`
encoding (`REX? FF /2 08`) are decoded at all.

usage: createsites.py [--gap 8] [--list 40]
"""
import sys, os, struct, re, argparse
from collections import defaultdict
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(nsec):
    nm = f[no + i * 40:no + i * 40 + 8].rstrip(b'\0').decode()
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, no + i * 40 + 8)
    secs.append((nm, va, vs, rsz, rp))

def rd(rva, n, sec='.text'):
    for nm, va, vs, rsz, rp in secs:
        if nm == sec and va <= rva < va + vs:
            return f[rp + rva - va: rp + rva - va + n]
    return b''

PDATA = next(s for s in secs if s[0] == '.pdata')
raw = rd(PDATA[1], PDATA[2], '.pdata')
funcs = []
for i in range(0, len(raw) - 11, 12):
    begin, end = struct.unpack_from('<II', raw, i)
    funcs.append((begin, end))
funcs.sort()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# FF /2, modrm mod=01, rm 0..7 (no SIB): `call qword ptr [reg + disp8]` with disp8 == 8.
# An optional REX prefix (0x40-0x4f) precedes. Only a prefilter -- alignment is settled
# by decoding the whole function.
CALL8 = re.compile(rb'(?:[\x40-\x4f])?\xff[\x50-\x57]\x08')

def is_value_load(ins):
    ops = ins.operands
    return (ins.mnemonic == 'mov' and len(ops) == 2
            and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM
            and ops[1].mem.disp == 0x28 and not ops[1].mem.index)

def is_indirect_call8(ins):
    ops = ins.operands
    return (ins.mnemonic == 'call' and len(ops) == 1 and ops[0].type == X86_OP_MEM
            and ops[0].mem.disp == 8 and not ops[0].mem.index)

def touches_key(ins):
    """Any operand or call target reading dword [reg+0x20] -- the map key slot. A
    `_Tree` walk compares it against the sought id before it ever reaches +0x28, so
    requiring it in the same function is what turns 237 candidates into the BST readers."""
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.disp == 0x20 and not op.mem.index:
            return True
    return False

def scan(gap, need_key=True):
    """-> (dict function -> [(call_site, load_site, load_text)], functions decoded)"""
    hits = defaultdict(list)
    decoded = 0
    for begin, end in funcs:
        size = end - begin
        if size <= 0 or size > 0x400000:
            continue
        blob = rd(begin, size)
        if not CALL8.search(blob):
            continue
        decoded += 1
        insns = list(md.disasm(blob, BASE + begin))
        if need_key and not any(touches_key(i) for i in insns):
            continue
        last = None
        for i, ins in enumerate(insns):
            if is_value_load(ins):
                last = (ins.address - BASE, ins.op_str, i)
            elif last is not None and is_indirect_call8(ins) and i - last[2] <= gap:
                hits[(begin, end)].append((ins.address - BASE, last[0], last[1]))
    return hits, decoded

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gap', type=int, default=8,
                    help='max instructions between the +0x28 load and the indirect call')
    ap.add_argument('--list', type=int, default=40)
    ap.add_argument('--no-key', action='store_true',
                    help='drop the [reg+0x20] key-compare requirement')
    a = ap.parse_args()
    hits, decoded = scan(a.gap, need_key=not a.no_key)
    total = sum(len(v) for v in hits.values())
    print(f'# {decoded:,} functions contain a `call [reg+8]` encoding; {total} matching '
          f'load->call pairs in {len(hits)} functions (gap<={a.gap}, '
          f'key-slot {"required" if not a.no_key else "not required"})')
    for (begin, end), sites in sorted(hits.items(), key=lambda kv: -len(kv[1]))[:a.list]:
        print(f'func {begin:x}..{end:x} ({end-begin:#x} B) {len(sites)} site(s)')
        for call_site, load_site, load_text in sites[:6]:
            print(f'    {load_site:x}: {load_text}   ->  {call_site:x}: call [..+8]')

if __name__ == '__main__':
    main()
