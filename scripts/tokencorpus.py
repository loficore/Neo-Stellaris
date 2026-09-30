#!/usr/bin/env python3
"""A5: cross-check the token space against the shipped scripts, offline.

Two independent instruments, then a join that is supposed to be exact:

(a) **id agreement.** `evidence/xrefs/descriptor_oracle_4_4_4.tsv` (9,863 rows) is the engine's OWN
    descriptor writers replayed under unicorn; `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`
    (1,615 keyword rows over the two keyword dbs) is `.rdata` registration thunk arrays read by
    `thunkarrays.py`. Neither derives its numbers from the other, yet a keyword's token id must appear
    identically in both -- the driver wrote the descriptor's id field, the thunk inserts the same value
    as `edx`. So agreement is a real check, and disagreement localizes to one of the two readers.

(b) **corpus coverage.** §19 proved the script parser never MINTS tokens. The other half of that claim
    is what C1 depends on: it LOOKS words up in the token space, so a word the shipped scripts use as a
    block head either has a static descriptor, or is explained by a mechanism that resolves it some
    other way. Bucketing the misses is therefore not bookkeeping -- it is the list of mechanisms that
    compete with the token path, and each one has to be named before C1 can claim the token path is the
    only way to add a hardcoded keyword.

Head-token extraction is deliberately structural, `WORD = {`, not `WORD =`: the loose form also matches
every `which = foo` / `value = 3` operand and had this tool reporting 9,858/9,863 "present", a number
too smooth to be anything but an artifact of measuring the wrong relation.

Miss classes, in priority order (all derived from data, none guessed per-word):
  localisation_key      -- key of a `*_localisation.txt` line; resolved by the loc reader.
  custom_loc_object     -- `custom_tp_*`/`change_tp_*`/`hidden_event_*`: loc object names built by the
                           text renderer, never parsed as keywords.
  scripted_template     -- defined as a column-0 name inside scripted_effects|scripted_triggers|
                           scripted_loc|scripted_actions; resolved by STRING through
                           `0x89F960`/`0x8A0450`.
  db_entry_name / event_entry_name -- column-0 head in a `common/<collection>/` file or an `events/`
                           file: the key of a string-indexed database (an army, a name list, a map
                           mode, an event id), not a keyword. The discriminator is the INDENT -- a
                           keyword head is always nested, a db entry head is what the file lists.
  runtime_built_name    -- `prefix_suffix` where the exe holds BOTH `prefix_` and `suffix` as separate
                           standalone strings and no string `prefix_suffix` at all. This is §19's scope
                           iterator family: name builders concatenate the parts at run time and mint the
                           id through `0x1D13270`, which is why a working keyword can be absent from the
                           static table. Verified in code: `0x195a580` loads `count_` (6 bytes at
                           `0x266A818`) and `owned_pop_amount` (16 bytes at `0x266A620`) into two
                           std::strings and appends them -- 104 functions reference `count_`, one each,
                           and the whole file has ZERO bytes of the string `count_owned_pop_amount`.
  iterator_name_parts_missing -- iterator-shaped name whose parts are NOT all in the image. `any_`,
                           `all_` and `ordered_` never appear as standalone strings, so those names are
                           not built by concatenating literals; this class is the honest statement that
                           §19's iterator family has a second mechanism we have not pinned.
  string_special        -- the word IS a standalone exe string but has no descriptor: the parser's
                           special-cases. `NOT` (`0x26B3F90`), `AND` (`0x25BC480`), `OR`, `ICON`.
                           Note this class is a *counterexample* to a naive reading of §19: these words
                           are head tokens the engine resolves without any descriptor at all. `NOR`,
                           `NAND`, `IF` and `FROMFROM` do NOT even appear as standalone strings, so they
                           belong to no explained class yet -- see iterator_name_parts_missing.

Usage: python3 scripts/tokencorpus.py [corpus_root ...]
"""
import sys, os, re, struct, collections

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XREFS = os.path.join(ROOT, 'evidence', 'xrefs')
EXE = os.environ.get('NS_STELLARIS_EXE', '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
CORPUS = sys.argv[1:] or ['/var/lofibass_ssd/data/stellaris/4.4.4']
ORACLE = os.path.join(XREFS, 'descriptor_oracle_4_4_4.tsv')
REG = os.path.join(XREFS, 'keyword_behaviour_registration_4_4_4.tsv')
OUT = os.path.join(XREFS, 'token_corpus_crosscheck_4_4_4.tsv')

HEAD = re.compile(rb'(?:^|[\s{}])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{')
# Any left-hand position, whatever follows the `=`. `HEAD` alone is not enough for check (c): most
# trigger keywords in shipped scripts take a SCALAR (`num_ships_in_debris = 10`), not a block, so a
# block-only regex reports live keywords as unused. Measured: `has_crisis_perk` reads as unused under
# HEAD and appears under ANYEQ -- so the two regexes answer different questions and are kept apart.
# This is NOT used for the miss classification in (b), where the block form is what makes a word a
# head rather than the value of somebody else's assignment.
ANYEQ = re.compile(rb'(?:^|[\s{}])([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*')
# Column-0 head: the entry name of a database object (`robotic_army = {` in common/armies/, an event
# id in events/). Those are keys of a string-indexed db, not keywords -- no token involved. Note the
# discriminator is the INDENT: a keyword head is always nested inside something, a db entry head is
# what the file is a list OF, so it starts the line.
TOPLEVEL = re.compile(rb'^([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*\{', re.M)
TEMPLATE_DIRS = ('scripted_effects', 'scripted_triggers', 'scripted_loc', 'scripted_actions',
                 'scripted_governments', 'scripted_names')
ITER_PREFIX = re.compile(r'^(any_|every_|all_|ordered_|random_|count_|per_)')


def sections(data):
    mz = struct.unpack_from('<I', data, 0x3c)[0]
    no = mz + 24 + struct.unpack_from('<H', data, mz + 20)[0]
    out = []
    for i in range(struct.unpack_from('<H', data, mz + 6)[0]):
        o = no + i * 40
        nm = data[o:o + 8].split(b'\0')[0].decode('latin1')
        vs, va, rsz, rp = struct.unpack_from('<IIII', data, o + 8)
        out.append((nm, va, vs, rsz, rp))
    return out


def standalone_strings(data, secs):
    """Every NUL-terminated ASCII run that starts on a NUL boundary -- i.e. real C strings, not the
    interior of a longer word. `.rdata`/`.data` only; the keyword names live there (§17)."""
    found = set()
    for nm, va, vs, rsz, rp in secs:
        if nm not in ('.rdata', '.data'):
            continue
        blob = data[rp:rp + rsz]
        i = 0
        n = len(blob)
        while i < n:
            c = blob[i]
            if c == 0:
                i += 1
                continue
            j = i
            while j < n and 32 <= blob[j] < 127:
                j += 1
            run = blob[i:j]
            # a real string start: the byte before is NUL (or we are at the section start)
            if (i == 0 or blob[i - 1] == 0) and 1 <= len(run) <= 64 and b' ' not in run:
                found.add(run.decode('ascii'))
            i = max(j, i + 1)
    return found


def tsv_rows(path):
    rows = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            rows.append(line.rstrip('\n').split('\t'))
    return rows


def corpus_files():
    for base in CORPUS:
        for dirpath, _, names in os.walk(base):
            for n in names:
                if n.lower().endswith('.txt'):
                    yield os.path.join(dirpath, n)


def main():
    data = open(EXE, 'rb').read()
    exe_strings = standalone_strings(data, sections(data))

    # ---------------- (a) id agreement ----------------
    oracle = {}
    oracle_ci = {}           # lowercase name -> id; see the case-fold finding below
    for r in tsv_rows(ORACLE):
        if len(r) >= 2:
            try:
                oracle[r[1]] = int(r[0])
                oracle_ci[r[1].lower()] = int(r[0])
            except ValueError:
                pass
    # The join is case-INSENSITIVE, because the corpus says it has to be: scripts write `NOT = {`,
    # `ICON = n`, `IF = {`, `NOR = {` and the descriptor table holds only lowercase `not`/`icon`/`if`/
    # `nor` -- uppercase forms exist nowhere in it, yet those words work in shipped scripts. So the
    # lexer case-folds on lookup while the descriptor keeps the authored spelling (the table also holds
    # mixed-case GUI names -- `noOfFrames`, `fontName`, `xFile` -- and has ZERO pairs differing only by
    # case, which is what a case-insensitive key demands). Consequence for C1, and it is not cosmetic:
    # `0x1D13270` is GetOrAddToken, so a name that collides case-insensitively with an existing token
    # returns THAT id instead of minting ours -- the new keyword would silently hijack an official one,
    # and nothing in the return value distinguishes the two.
    def lookup(w):
        if w in oracle:
            return oracle[w], 'exact'
        if w.lower() in oracle_ci:
            return oracle_ci[w.lower()], 'case_folded'
        return None, None

    EFFECT_DB, TRIGGER_DB = '0x33746e8', '0x32611c8'
    reg = collections.defaultdict(set)
    reg_rows = 0
    for r in tsv_rows(REG):
        if len(r) < 6 or r[3] not in (EFFECT_DB, TRIGGER_DB):
            continue
        reg_rows += 1
        try:
            reg[r[5]].add(int(r[4]))
        except ValueError:
            pass
    agree = [n for n, ids in reg.items() if ids == {lookup(n)[0]}]
    disagree = [n for n, ids in reg.items() if lookup(n)[0] is not None and n not in agree]
    absent = [n for n in reg if lookup(n)[0] is None]
    print(f'(a) keyword rows={reg_rows} distinct names={len(reg)}')
    print(f'    id agrees with the replayed descriptor: {len(agree)}')
    print(f'    id DISAGREES: {len(disagree)} {disagree[:5]}')
    print(f'    name absent from the 9,863: {len(absent)} {sorted(absent)[:8]}')

    # ---------------- corpus head tokens ----------------
    counts = collections.Counter()
    anyeq = collections.Counter()
    files_seen = collections.defaultdict(set)
    template_names = set()
    db_entries = set()
    event_entries = set()
    loc_keys = set()
    nfiles = 0
    for path in corpus_files():
        nfiles += 1
        try:
            raw = open(path, 'rb').read()
        except OSError as e:
            print('unreadable', path, e)
            continue
        rel = os.path.relpath(path, CORPUS[0]).replace('\\', '/')
        parts = rel.split('/')
        text = raw.decode('utf-8', 'replace')
        for m in HEAD.finditer(raw):
            w = m.group(1).decode('ascii', 'replace')
            counts[w] += 1
            files_seen[w].add(rel)
        for m in ANYEQ.finditer(raw):
            anyeq[m.group(1).decode('ascii', 'replace')] += 1
        tops = {x.decode() for x in TOPLEVEL.findall(raw)}
        if parts[0] == 'events':
            event_entries |= tops
        elif parts[0] == 'common' and not any(d in parts for d in TEMPLATE_DIRS) \
                and 'localisation' not in rel:
            db_entries |= tops
        if any(d in parts for d in TEMPLATE_DIRS) and 'localisation' not in rel:
            template_names |= tops
        if 'localisation' in rel:
            for line in text.splitlines():
                k = line.split('=', 1)[0].strip()
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k):
                    loc_keys.add(k)

    match_kind = {w: lookup(w)[1] for w in counts}
    present = {w for w in counts if match_kind[w]}
    folded = {w for w in present if match_kind[w] == 'case_folded'}
    missing = {w: c for w, c in counts.items() if not match_kind[w]}

    def classify(w):
        if w in loc_keys:
            return 'localisation_key'
        if re.match(r'^(custom_(tp|inf|sec|cap|orb|pha|dis|anom)_|change_tp_|hidden_event_)', w):
            return 'custom_loc_object'
        if w in template_names:
            return 'scripted_template'
        if w in db_entries:
            return 'db_entry_name'
        if w in event_entries:
            return 'event_entry_name'
        if ITER_PREFIX.match(w):
            pre = ITER_PREFIX.match(w).group(0)
            rest = w[len(pre):]
            if w not in exe_strings and pre in exe_strings and rest in exe_strings:
                return 'runtime_built_name'
            # iterator-shaped name whose parts are NOT all in the image (`any_`, `all_`, `ordered_` never
            # appear as standalone strings, so no concatenation of literals can build them). Kept as its
            # own class rather than "unexplained": the shape tells us it is §19's scope-iterator family,
            # the missing parts tell us the mechanism is not the count_/every_/random_ one.
            return 'iterator_name_parts_missing'
        if w in exe_strings:
            return 'string_special'
        return 'UNEXPLAINED'

    buckets = collections.defaultdict(collections.Counter)
    for w, c in missing.items():
        buckets[classify(w)][w] += c

    print(f'\n(b) {nfiles} files, {len(counts)} distinct head words, {sum(counts.values())} occurrences')
    print(f'    head words WITH a static descriptor: {len(present)} '
          f'({sum(counts[w] for w in present)} occurrences)')
    print(f'      of those, matched only after case-folding: {len(folded)} '
          f'{sorted(folded, key=lambda w: -counts[w])[:8]}')
    print(f'    head words WITHOUT: {len(missing)} ({sum(missing.values())} occurrences)')
    used = len([n for n in oracle if n in counts])
    print(f'    descriptors used by the shipped scripts: {used}/{len(oracle)}')

    # (c) the reverse direction, and the one C1 cares about: does every keyword that owns a class_info
    # actually appear in shipped scripts? A donor that ships unused is a donor whose virtuals no
    # shipped script ever reaches, which is a different (and worse) bet for C1 than aliasing a live one.
    # Both regexes are reported: HEAD counts block heads only, ANYEQ counts every LHS position -- and
    # the check is case-folded, because §19's name rule is not the whole collision story.
    anyeq_ci = collections.Counter()
    for w, c in anyeq.items():
        anyeq_ci[w.lower()] += c
    kw_block = sorted(n for n in reg if n in counts)
    kw_any = sorted(n for n in reg if n.lower() in anyeq_ci)
    kw_none = sorted(n for n in reg if n.lower() not in anyeq_ci)
    print(f'(c) keyword-db names: as a block head {len(kw_block)}, as any LHS {len(kw_any)}, '
          f'in neither {len(kw_none)}')
    print(f'    §24 donors (block/LHS): ' + ' '.join(
        f'{d}={counts.get(d, 0)}/{anyeq_ci.get(d.lower(), 0)}'
        for d in ('has_crisis_perk', 'has_menace_perk', 'hidden_effect')))
    print(f'    never-used keyword names: {kw_none[:12]}')
    order = sorted(buckets.items(), key=lambda kv: -sum(kv[1].values()))
    for b, words in order:
        print(f'      {b:20} {len(words):6} distinct {sum(words.values()):9} occurrences')
    un = buckets['UNEXPLAINED']
    if un:
        print(f'      top UNEXPLAINED ({len(un)} distinct):')
        for w, c in un.most_common(30):
            inexe = 'EXE-STRING' if w in exe_strings else 'no exe string'
            print(f'        {w:44} {c:7} {inexe:11} {sorted(files_seen[w])[0]}')

    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('# word\toccurrences\tfiles\ttoken_id\tclass\tmatched_as\tin_exe_as_standalone_string\n')
        for w, c in counts.most_common():
            tid = lookup(w)[0]
            cls = 'token' if tid is not None else classify(w)
            f.write(f'{w}\t{c}\t{len(files_seen[w])}\t{tid if tid is not None else ""}\t'
                    f'{cls}\t{match_kind[w] or ""}\t{w in exe_strings}\n')
    print('\nwrote', OUT)


if __name__ == '__main__':
    main()
