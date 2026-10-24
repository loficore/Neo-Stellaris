"""Re-ask the §56 scope candidates against the unfiltered vtable shape set — offline.

usage: python3 scripts/scope_reclassify.py [--tsv PATH] [--floor PATH] [--all PATH] [--json PATH]

Reads three artifacts that are already in the repo and nothing else: the object rows of
`evidence/logs/scope_probe_v2_4_4_4.tsv`, the floor map `ceffect_vtable_map_4_4_4.txt`
(1,805 vtables whose slot[1] is still base Execute — parsed by importing
`c2_scope_probe.load_vtable_map`, not re-implemented here), and the unfiltered shape set
`vtable_candidates_all_4_4_4.txt` (Task 3's `rttibatch.py --all-vtables`). **It does not
open stellaris.exe**, so it needs no `NS_STELLARIS_EXE`, no process, and no licence.

The question this answers: §56.8 retracted "helper is not an object" because the candidate
RVA `0x26dc2d0` is vtable-shaped but absent from the floor set, and the floor set
structurally cannot contain any class that overrides Execute. Bucketing every candidate
against both sets says how many rows the floor set was hiding.

Bucket definitions (mutually exclusive, sum == total — pinned by a test):
  floor_hits        vptr_rva resolves and is in the floor set
  new_only_hits     vptr_rva resolves, is NOT in the floor set, and IS in the shape set
  still_no          vptr_rva resolves and is in neither set
  undecidable_no_rva  the qword did not resolve to an image RVA (`vptr_rva=-`), or the row
                      never carried one — "no datum", never "not an object"
"""
import argparse
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from c2_scope_probe import load_vtable_map

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_TSV = os.path.join(REPO_ROOT, 'evidence/logs/scope_probe_v2_4_4_4.tsv')
DEFAULT_FLOOR = os.path.join(REPO_ROOT, 'evidence/xrefs/ceffect_vtable_map_4_4_4.txt')
DEFAULT_ALL = os.path.join(REPO_ROOT, 'evidence/xrefs/vtable_candidates_all_4_4_4.txt')


def _int_or_none(text):
    """`0x1234` -> 0x1234; the artifact's dash, or anything unparseable -> None."""
    if text is None or text == '-' or text == '':
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def parse_object_rows(text):
    """TSV text -> the `object` rows as dicts.

    Keys: root, known, source, off, ptr, vptr_rva, has_vptr_abs. A row whose vptr_rva is a
    dash is KEPT with `vptr_rva=None` — dropping it is what turned "no datum" into
    "not an object" in §56.4. `has_vptr_abs` records whether the row carried the absolute
    `vptr=` qword at all; the pre-fix driver never wrote it, so every row in the shipped
    artifact reads False and the absolute value cannot be recovered offline.
    """
    rows = []
    for line in text.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        cols = line.split('\t')
        if len(cols) < 4 or cols[0] != 'object':
            continue
        fields = {}
        for token in cols[3].split():
            if '=' in token:
                key, value = token.split('=', 1)
                fields[key] = value
        rows.append({
            'root': _int_or_none(cols[1]),
            'known': bool(_int_or_none(cols[2]) or 0),
            'source': fields.get('source'),
            'off': _int_or_none(fields.get('off')),
            'ptr': _int_or_none(fields.get('ptr')),
            'vptr_rva': _int_or_none(fields.get('vptr_rva')),
            'has_vptr_abs': _int_or_none(fields.get('vptr')) is not None,
        })
    return rows


def load_candidate_map(path):
    """vtable_candidates_all_4_4_4.txt -> {vtable_rva: (run, slot0, slot1, slot2)}.

    The header is a comment; each row is `vtable 0x<VT>  run=<N>  slot0 0x<A>  slot1 0x<B>
    slot2 0x<C>` — slot names and values are separate columns, which is how Task 3's CLI
    writes them. Rows missing a column are skipped rather than guessed at: a shape set we
    cannot parse exactly is not a judgement we can make.
    """
    out = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            cols = line.split()
            if len(cols) < 9 or cols[0] != 'vtable' or cols[3] != 'slot0':
                continue
            try:
                vtable_rva = int(cols[1], 16)
                run = int(cols[2].split('=', 1)[1])
                slots = [int(cols[i + 1], 16) for i in (3, 5, 7)]
            except (ValueError, IndexError):
                continue
            out[vtable_rva] = (run, *slots)
    return out


def reclassify(rows, floor, allv):
    """Split candidate rows against the floor set and the unfiltered shape set.

    Returns exactly {total, floor_hits, new_only_hits, still_no, undecidable_no_rva,
    new_rows}. `new_rows` is the retracted datum made countable: rows that hit only the
    shape set, each carrying `slot1` and `run` from that set so a reader can keep filtering
    (shape is not "is a vtable", and neither is "is in the CEffect family").
    """
    out = {'total': len(rows), 'floor_hits': 0, 'new_only_hits': 0,
           'still_no': 0, 'undecidable_no_rva': 0, 'new_rows': []}
    for row in rows:
        rva = row['vptr_rva']
        if rva is None:
            out['undecidable_no_rva'] += 1
        elif rva in floor:
            out['floor_hits'] += 1
        elif rva in allv:
            out['new_only_hits'] += 1
            run, _slot0, slot1, _slot2 = allv[rva]
            hit = dict(row)
            hit['run'] = run
            hit['slot1'] = slot1
            out['new_rows'].append(hit)
        else:
            out['still_no'] += 1
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description='offline re-ask of the §56 scope candidates')
    ap.add_argument('--tsv', default=DEFAULT_TSV)
    ap.add_argument('--floor', default=DEFAULT_FLOOR)
    ap.add_argument('--all', dest='allv', default=DEFAULT_ALL)
    ap.add_argument('--json', dest='json_path')
    args = ap.parse_args(argv)

    with open(args.tsv, 'r', encoding='utf-8') as f:
        rows = parse_object_rows(f.read())
    result = reclassify(rows, load_vtable_map(args.floor), load_candidate_map(args.allv))

    print(f'tsv             {args.tsv}')
    print(f'object rows     {result["total"]}')
    print(f'floor_hits      {result["floor_hits"]}')
    print(f'new_only_hits   {result["new_only_hits"]}')
    print(f'still_no        {result["still_no"]}')
    print(f'undecidable     {result["undecidable_no_rva"]}')
    for row in result['new_rows']:
        print(f'  new  root={row["root"]:#x} source={row["source"]} off={row["off"]:#x} '
              f'vptr_rva={row["vptr_rva"]:#x} slot1={row["slot1"]:#x} run={row["run"]}')
    if args.json_path:
        with open(args.json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=1, sort_keys=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
