#!/usr/bin/env python3
"""One-off probe (#46): the *value domain* of `owner` in one 4.4.4 save.

This is a falsifier, not a proof. It answers "could a u32 read at some candidate
offset be a country id?" -- never "the owner field is at offset N".

usage: owner_domain.py /mnt/cache/tmp/opencode/autosave_2257.07.01.sav

Reads only the save (zip -> `gamestate` text). No process, no game, no Frida.

Reading traps baked in (all four were hit while writing this):
  * `galactic_object` blocks in a 4.4.4 save carry **no `owner=` scalar at all**.
    Ownership is derived (from `colonies` / `starbases` / `sectors`), so the plan's
    expected line `systems=N owners=<distinct>` comes out as `owners=0`. That is a
    finding, not a bug: see evidence §5. The script therefore reports the observed
    absence *and* the domain it can still measure.
  * `claims={ { owner=... } }` carries owner-looking ids that are **not** the
    system's owner; only per-system scalars count, which is why this parses the tree
    instead of grepping `owner=` (a grep over 2257.07.01 finds claim rows whose owner
    is the 0xffffff "none" sentinel).
  * ids in the save are unmasked and carry flag bits above bit 23 (e.g. 16777220 =
    0x1000004); engine reads do `and 0xffffff` before the table index. Compare
    *both* raw and masked sets.
  * the save nests deeper than CPython's recursion limit -> the parser is iterative.
"""
import sys
import zipfile

WS = ' \t\r\n'


def skip(s, i):
    while i < len(s) and s[i] in WS:
        i += 1
    return i


def token(s, i):
    """Read a bare token or a quoted string starting at i; return (text, next_i)."""
    if s[i] == '"':
        j = i + 1
        out = []
        while j < len(s):
            c = s[j]
            if c == '\\' and j + 1 < len(s):
                out.append(s[j + 1])
                j += 2
                continue
            if c == '"':
                return ''.join(out), j + 1
            out.append(c)
            j += 1
        return ''.join(out), j
    j = i
    while j < len(s) and s[j] not in WS and s[j] not in '{}=':
        j += 1
    return s[i:j], j


def parse_items(s, i, in_block):
    """Parse `key=value` items until '}' (in_block) or EOF.

    Returns (items, next_i). items = [(key, value)] where value is
    ('scalar', str) or ('block', items). Iterative: the save nests deeper than
    CPython's recursion limit.
    """
    frames = [[]]
    keys = []
    while True:
        i = skip(s, i)
        if i >= len(s):
            break
        if s[i] == '}':
            if len(frames) == 1:
                if in_block:
                    return frames[0], i + 1
                raise ValueError('unbalanced } at top level')
            k = keys.pop()
            blk = frames.pop()
            frames[-1].append((k, ('block', blk)))
            i += 1
            continue
        if s[i] == '{':
            # anonymous nested block, e.g. player={ { name=... } }
            keys.append(None)
            frames.append([])
            i += 1
            continue
        tok, nxt = token(s, i)
        j = skip(s, nxt)
        if j < len(s) and s[j] == '=':
            i = skip(s, j + 1)
            if i < len(s) and s[i] == '{':
                keys.append(tok)
                frames.append([])
                i += 1
            else:
                val, i = token(s, i)
                frames[-1].append((tok, ('scalar', val)))
        else:
            # bare value (Clausewitz list bodies: `{ 44 413 "null" }`)
            frames[-1].append((None, ('scalar', tok)))
            i = nxt
    if len(frames) == 1:
        return frames[0], i
    raise ValueError('unbalanced {')


def find_block(items, name):
    for k, v in items:
        if k == name and v[0] == 'block':
            return v[1]
    return None


def scalar(items, name):
    for k, v in items:
        if k == name and v[0] == 'scalar':
            try:
                return int(v[1])
            except ValueError:
                return None
    return None


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    path = argv[1]
    text = zipfile.ZipFile(path).read('gamestate').decode('utf-8', 'replace')
    root, _ = parse_items(text, 0, False)

    gobj = find_block(root, 'galactic_object') or []
    systems = []
    for key, val in gobj:
        if val[0] != 'block' or not (key and key.isdigit()):
            continue
        systems.append((int(key), scalar(val[1], 'owner')))

    countries = [int(k) for k, v in (find_block(root, 'country') or [])
                 if v[0] == 'block' and k and k.isdigit()]
    cset = set(countries)

    owned = [(i, o) for i, o in systems if o is not None]
    owners = sorted({o for _, o in owned})

    print(f'save={path}')
    print(f'systems={len(systems)} owners={len(owners)} owned={len(owned)} '
          f'owner_missing={len(systems) - len(owned)}')
    print(f'countries={len(countries)} ids={min(countries)}..{max(countries)}'
          if countries else 'countries=0')
    print('first10 systems (id -> owner):')
    for i, o in systems[:10]:
        print(f'  {i} -> {o}')

    print('\n# fallback domain: the top-level blocks that DO carry an `owner=`')
    print('# scalar, plus the raw/masked test against the country id set')
    all_zero_mask = all((c & 0xFFFFFF) == c for c in countries)
    for key, val in root:
        if val[0] != 'block' or key in ('galactic_object', 'country'):
            continue
        pairs = [(ck, scalar(cv[1], 'owner')) for ck, cv in val[1]
                 if cv[0] == 'block']
        pairs = [(a, b) for a, b in pairs if b is not None]
        if not pairs:
            continue
        vals = sorted({b for _, b in pairs})
        raw = all(v in cset for v in vals)
        masked = all((v & 0xFFFFFF) in {(c & 0xFFFFFF) for c in countries}
                     for v in vals)
        print(f'{key}: children_with_owner={len(pairs)} distinct={len(vals)} '
              f'range={vals[0]}..{vals[-1]} raw_subset={raw} '
              f'masked_subset={masked}')
    print(f'country_ids_fit_in_24_bits={all_zero_mask}')

    # §4 support: war / truce / federation are separate top-level blocks, not
    # country scalars. Counting them gives the "relation object" claim a save-side
    # witness independent of the exe reading.
    print()
    for key in ('war', 'truce', 'federation', 'dead_war', 'dead_federation'):
        b = find_block(root, key)
        print(f'{key}_blocks={"absent" if b is None else len(b)}')


if __name__ == '__main__':
    sys.exit(main(sys.argv))
