"""§56.9's ptr-layer re-ask: is the candidate qword *itself* a vtable, by the unfiltered shape set?

scope_reclassify.py answers the layer the driver probed (`vptr_rva`, i.e. the qword at the
candidate) and the answer is 0 new rows.  This one-off probe answers the layer §56.8 actually
retracted on -- the candidate pointer itself -- which the shipped artifact can only express as
an absolute address, so it needs the live exe base recorded in §56/§56.8.  No process, no gun.

Run from the repo root:
    python3 scripts/scratch/2026-10_scope_shot/ns_scope_ptr_shape.py

Reads three committed artifacts plus the exe copy (section names only, NS_STELLARIS_EXE honoured
by rttibatch).  A scratch probe: the numbers it prints are quoted in
evidence/analysis/runtime_444_c1_validation.md §56.9, and it is not a maintained interface.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'scripts'))

import rttibatch                                          # noqa: E402
from scope_reclassify import (                            # noqa: E402
    load_candidate_map, parse_object_rows,
)
from c2_scope_probe import load_vtable_map               # noqa: E402

TSV = 'evidence/logs/scope_probe_v2_4_4_4.tsv'
FLOOR = 'evidence/xrefs/ceffect_vtable_map_4_4_4.txt'
ALLV = 'evidence/xrefs/vtable_candidates_all_4_4_4.txt'
EXE_BASE = 0x7FF6A4270000      # the live exe base of the §56 shot; NOT the DLL base (trap 4)
SIZE_OF_IMAGE = 0x3927000
IMG_END = EXE_BASE + SIZE_OF_IMAGE


def main():
    rows = parse_object_rows(open(TSV, encoding='utf-8').read())
    floor = load_vtable_map(FLOOR)
    allv = load_candidate_map(ALLV)
    img = rttibatch.Image(open(rttibatch.EXE, 'rb').read())

    def sect(rva):
        for i, (va, vs, _praw) in enumerate(img.secs):
            if va <= rva < va + vs:
                return rttibatch.section_name(img, i)
        return 'outside'

    in_image = [(r, r['ptr'] - EXE_BASE) for r in rows
                if r['ptr'] is not None and EXE_BASE <= r['ptr'] < IMG_END]
    new_only = [(r, rv) for r, rv in in_image if rv not in floor]
    print(f'object rows                {len(rows)}')
    print(f'  candidate ptr in-image   {len(in_image)}  (out of image {len(rows) - len(in_image)})')
    print(f'  in-image by section      {collections.Counter(sect(rv) for _r, rv in in_image)}')
    print(f'  ptr is a floor vtable    {len(in_image) - len(new_only)}')
    print(f'  ptr is shape-not-floor   {len(new_only)} rows, '
          f'{len({rv for _r, rv in new_only})} distinct RVAs, '
          f'{len({r["root"] for r, _rv in new_only})} distinct roots')
    for r, rv in sorted(new_only, key=lambda p: (p[1], p[0]['root'], p[0]['off'])):
        run, slot0, slot1, slot2 = allv[rv]
        print(f'  ptr_rva={rv:#010x} run={run} slot0={slot0:#x} slot1={slot1:#x} '
              f'slot2={slot2:#x}  root={r["root"]:#x} source={r["source"]} off={r["off"]:#x} '
              f'row_vptr_rva={r["vptr_rva"]:#x}')
    print(f'vptr_rva by section (83 resolvable rows) '
          f'{collections.Counter(sect(r["vptr_rva"]) for r in rows if r["vptr_rva"] is not None)}')
    low = [r for r in rows if r['ptr'] is not None and r['ptr'] < EXE_BASE]
    print(f'candidate ptr below the image base: {len(low)} rows, '
          f'{sorted({r["ptr"] for r in low})[:4]}')


if __name__ == '__main__':
    main()
