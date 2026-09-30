#!/usr/bin/env python3
"""C1 pre-flight for a candidate keyword name -- offline, read-only, mutates nothing.

§25.5 turned one of A5's findings into a hard constraint: token lookup case-folds, and `0x1D13270` is
GetOrAddToken, so a name that differs from a shipped keyword only by case does NOT mint -- it returns
the existing id, and `eax` cannot distinguish the two. The new keyword would then be registered onto
an official keyword's own db slot. That is the one C1 failure mode that is invisible from the inside,
so it gets checked before anything is injected, against the full shipped name space:

  * the 9,863 descriptor names (`descriptor_oracle_4_4_4.tsv`, produced by replaying the engine's own
    writers under unicorn);
  * the 1,610 keyword-db names with a `class_info` (`keyword_behaviour_registration_4_4_4.tsv`).

It also checks §20's rule (leading '-' or digit => eax = 0), reports the id we expect the allocator to
hand back, and prints the decided §24.6 parameters for whichever db the name is going into. Nothing
here touches a process, a pipe, or the game: it reads two TSVs and prints a verdict.

The predicted id is a REAL observable for C1's pass criteria, and it is derived, not guessed: the
static table spans 11..18817 (9,863 entries, 8,944 gaps, no duplicates), and §21 pinned the allocator's
formula as `[db+0x64] + [db+0x84] + 1`. So a first-ever mint is 18818, and any larger number tells us
something else minted between start-up and our call -- which §19's timing argument says is normal
(lazy Meyers accessors mint on first touch). A return value BELOW 18818 is the collision case this
script exists to rule out.

usage: c1_preflight.py <candidate_name> [--db trigger|effect]
"""
import sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XREFS = os.path.join(ROOT, 'evidence', 'xrefs')
ORACLE = os.path.join(XREFS, 'descriptor_oracle_4_4_4.tsv')
REG = os.path.join(XREFS, 'keyword_behaviour_registration_4_4_4.tsv')

DB_PARAMS = {
    'trigger': {
        'global': '0x32611C8', 'ensure': '0x347BD0 (no args; news 0x98, ctor, publishes itself)',
        'insert': '0x348150', 'walk': 'db+0x88', 'class_info': '0x269CAA8',
        'docstring': '0x26C1BA0', 'vtbl_read': '+0x80', 'obj_id': '+0x38', 'obj_name': '+0x40',
    },
    'effect': {
        'global': '0x33746E8', 'ensure': 'new(0x70) then 0x3AEBA0, WE publish the global',
        'insert': '0x3AEF60', 'walk': 'db+0x18', 'class_info': '0x2611070',
        'docstring': '0x2616260', 'vtbl_read': '+0x98', 'obj_id': '+0x20', 'obj_name': '+0x28',
    },
}


def names():
    """name -> id for every descriptor, plus the set of keyword-db names."""
    desc = {}
    with open(ORACLE, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('#'):
                continue
            p = line.rstrip('\n').split('\t')
            if len(p) >= 2:
                try:
                    desc[p[1]] = int(p[0])
                except ValueError:
                    pass
    kw = {}
    with open(REG, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('#'):
                continue
            p = line.rstrip('\n').split('\t')
            if len(p) < 6 or p[3] not in ('0x33746e8', '0x32611c8'):
                continue
            try:
                kw[p[5]] = int(p[4])
            except ValueError:
                pass
    return desc, kw


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    db = 'trigger'
    for a in sys.argv[1:]:
        if a.startswith('--db'):
            db = a.split('=', 1)[1] if '=' in a else 'trigger'
    if not args:
        print(__doc__)
        return 2
    name = args[0]
    desc, kw = names()
    max_static = max(desc.values())
    p = DB_PARAMS[db]

    print(f'candidate name : {name!r}')
    print(f'target db      : {db} ({p["global"]})')
    print()

    ok = True
    # §20's rule, from the allocator's own code (cmp byte [rax],0x2d / cmp eax,9 at 0x1d132bb/0x1d132d6).
    if not name:
        print('  FAIL  empty name')
        ok = False
    elif name[0] == '-' or name[0].isdigit():
        print(f'  FAIL  §20: starts with {name[0]!r} -> 0x1D13270 returns eax = 0, no token')
        ok = False
    else:
        print('  ok    §20 leading-char rule (no \'-\', no digit)')

    if name != name.lower():
        print(f'  WARN  not all-lowercase; lookup case-folds, so this is keyed as {name.lower()!r}')

    low = name.lower()
    exact = [n for n in desc if n == name]
    folded = [n for n in desc if n.lower() == low and n != name]
    kwhit = [n for n in kw if n.lower() == low]
    if exact:
        print(f'  FAIL  EXACT collision: descriptor {name!r} already has id {desc[name]}; '
              f'GetOrAddToken returns that id, it does not mint')
        ok = False
    elif folded:
        print(f'  FAIL  §25.5 case-fold collision with {folded!r} '
              f'(id {desc[folded[0]]}) -- would silently register onto that keyword')
        ok = False
    elif kwhit:
        print(f'  FAIL  case-fold collision with a keyword-db name {kwhit!r} '
              f'(id {kw[kwhit[0]]})')
        ok = False
    else:
        print(f'  ok    no collision, exact or case-folded, over {len(desc)} descriptors '
              f'+ {len(kw)} keyword names')

    print()
    print(f'  predicted id : {max_static + 1} (= [db+0x84] max static {max_static} + [db+0x64] 0 + 1)')
    print(f'                 a LARGER id is normal: §19, lazy accessors mint during start-up.')
    print(f'                 a SMALLER id means the §25.5 collision this script just checked for.')
    print()
    print(f'  planned sequence for {db} (§19 order, one call sequence, no two-phase wait):')
    print(f'    1. 0x1D13270(rcx = *NameHolder)                  -> edx = token id')
    print(f'    2. new(0x10){{ {p["class_info"]}, {p["docstring"]} }}   value record')
    print(f'    3. {p["ensure"]}')
    print(f'    4. {p["insert"]}(rcx = db, edx = id, r8 = value)  walks {p["walk"]}')
    print(f'  engine then writes id at obj{p["obj_id"]}, name at obj{p["obj_name"]}, calls vtbl{p["vtbl_read"]}')
    print()
    print('  still required before any of this runs:')
    print('    - C1 authorization: authorize.c1_registration = false in keyword_registry.zig (user flips)')
    print('    - Windows_Jiaolong reachable + game running (ssh Windows_Jiaolong, scp DLL, inject.exe)')
    print('    - never FreeLibrary while ExecHookVerify != 0 (§1 iron rule)')
    print()
    print('VERDICT:', 'name is clear' if ok else 'NAME IS NOT USABLE')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
