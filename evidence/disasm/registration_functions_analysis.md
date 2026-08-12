# Scripted Effect / Trigger Registration Functions — `sub_1408A6EB0` & `sub_1408A79A0`

**Binary**: `stellaris.exe` (Clausewitz "augustus")
**IDA session**: `a8808ebb` (opened fresh; prior session `cdd1c2bb` was unreachable)
**Companion file**: `string_to_id_registration_analysis.md` (covers `sub_140173C30`, the static token table)

## Function Profiles

| Attribute | Scripted Effect | Scripted Trigger |
|-----------|-----------------|------------------|
| Address | `0x1408A6EB0` | `0x1408A79A0` |
| Source file | `scriptedeffect.cpp` | `scriptedtrigger.cpp` |
| Size | 457 bytes, 27 basic blocks | 457 bytes, 27 basic blocks |
| Prototype | `__int64 __fastcall(__int64 a1, int a2, __int64 a3)` | identical |
| Registers to | `qword_14339AEA8` (ScriptedEffectDB) | `qword_143287968` (ScriptedTriggerDB) |
| Conflict message | `"scripted effect %s is overwriting an existing effect, rename it"` | `"scripted trigger %s is overwriting an existing trigger, rename it"` |

Both functions are **byte-for-byte identical in structure** and differ only in:
1. The destination BST global (`qword_14339AEA8` vs `qword_143287968`)
2. The BST root offset used for traversal (`+24` vs `+136`)
3. The log message / source-file tag

## Pseudocode — `sub_1408A6EB0` (Scripted Effect)

```c
__int64 __fastcall sub_1408A6EB0(__int64 a1, int a2, __int64 a3)
{
  v5 = (const char *)(a3 + 16);                 // a3 = source registration record
  v6 = (__int64 *)(a3 + 16);
  if ( *(_QWORD *)(a3 + 40) >= 0x10 )           // SSO string: take heap ptr if len>=16
    v6 = *(__int64 **)v5;

  // build name string (SSO) from keyword bytes
  sub_1401604E0(&v22 /*string*/, keyword, strlen);
  *(_QWORD *)a1 = &off_1424D4F00;              // vtable #1 (base CEffect?)
  *(_DWORD *)(a1 + 8) = a2;                     // numeric ID
  *(__m256i *)(a1 + 16) = v22;                  // name (SSO)
  *(_OWORD *)(a1 + 48) = v23;

  // a second string for the template body at a1+64
  sub_1401604E0(&v22 /*string*/, ...);
  sub_140B6B4D0(a1 + 64, &v22);                 // assign into template body buffer
  *(_QWORD *)a1 = &off_14253BAB8;              // vtable #2 (CScriptedEffectTemplate)
  *(_QWORD *)(a1 + 64) = off_14253BAD0;        // sub-vtable

  v10 = qword_14339AEA8;                        // ScriptedEffectDB (BST root holder)
  if ( qword_14339AEA8 )
  {
    // map keyword string -> numeric ID via the global string-to-ID hash
    v12 = sub_141D34530();                      // returns &qword_14375D000 (mapper)
    v13 = (*(vtable+16))(v12, keyword);         // hash lookup: string -> int*
    v14 = v13 ? *v13 : 12;                      // default ID 12 when unmapped

    // BST search for existing node with matching ID
    v15 = *(__int64 **)(v10 + 24);              // BST root
    v16 = v15[1];                               // current node
    v17 = v15;                                  // parent = sentinel
    while ( !*((_BYTE *)v16 + 25) )             // node not null (marker at +25)
    {
      if ( *((_DWORD *)v16 + 8) >= v14 )        // node.id >= target -> go left
      { v17 = v16;  v16 = *v16; }
      else                                     // node.id < target -> go right
      { v16 = v16[2]; }
    }
    if ( !*((_BYTE *)v17 + 25)                  // found a real node
      && v14 >= *((_DWORD *)v17 + 8)            // IDs equal (>= & <=)
      && v17 != v15 )                           // not the sentinel
    {
      // CONFLICT: same ID already registered
      sub_141CB3210(&err, "scripted effect %s is overwriting an existing effect, rename it", keyword);
      // source tag: C:\mnt\gsg\stellaris\augustus\augustus\source\scriptedeffect.cpp   line 33
    }
  }
  return a1;
}
```

`sub_1408A79A0` is identical with three substitutions (see profiles table).

## BST Structure Documented

The BST (`CGameSingleObjectDatabase`-style template / `game_singleobjectdatabase.h`) stores
nodes of two sorts: **value nodes** and **internal link nodes**. Each node is 32 bytes:

| Offset | Size | Meaning |
|--------|------|---------|
| `+0x00` | 8 | left child pointer |
| `+0x08` | 4 | **ID** (`_DWORD *v16 + 8`) — sort key |
| `+0x0C` | 4 | (padding / flag) |
| `+0x10` | 8 | value / object pointer |
| `+0x18` | 1 | null-marker byte (`*((_BYTE*)v16 + 25)` == 0 ⇒ node present) |

- Search key is the **numeric ID** (`v14`), not the string.
- The tree is **ordered by ID** (left child for smaller, right child for larger).
- A node is "empty"/sentinel when `byte at +25` is non-zero — this is the standard
  Clausewitz `game_singleobjectdatabase` binary-tree sentinel encoding, giving an
  unthreaded BST with embedded null-markers instead of `nullptr` leaves.

### BST root access differences (why +24 vs +136)

- **Effects**: root pointer loaded from `*(BST_holder + 24)`.
- **Triggers**: root pointer loaded from `*(BST_holder + 136)`.

The differing offsets reflect different enclosing structures: `qword_14339AEA8`
(ScriptedEffectDB) holds its tree-root at `+24`, while `qword_143287968`
(ScriptedTriggerDB) holds its tree-root at `+136`.

### Conflict detection logic

The registration performs a **duplicate-ID check** before adding the template to the
database. If a node with the same numeric ID already exists in the tree (and is not
the sentinel), it logs a warning:

```
scripted effect %s is overwriting an existing effect, rename it
scripted trigger %s is overwriting an existing trigger, rename it
```

This is a **soft warning** (via `sub_141CB3210`, the thread-safe `log_or_throw`-style
reporter) — it does not abort registration; the caller proceeds and the new template
replaces/clobbers the old one in the DB. This is why overridden built-in effects produce
a spammed in-game error log rather than a crash.

## String-to-ID Mapper — `sub_141D34530` / `qword_14375D000`

The function is a **thread-safe magic-static accessor** for a global hash-map singleton
at `qword_14375D000`:

```c
__int64 *sub_141D34530()
{
  if ( dword_14375CFF0 <= TLS_epoch )            // already initialized
    return &qword_14375D000;
  Init_thread_header(&dword_14375CFF0);
  if ( dword_14375CFF0 != -1 )
    return &qword_14375D000;                      // another thread is init'ing
  sub_141D34E40();                                // one-time construction
  atexit(sub_1423A4DB0);                          // destruction
  Init_thread_footer(&dword_14375CFF0);
  return &qword_14375D000;
}
```

### Construction — `sub_141D34E40`

Lazily builds the hash map from the giant static registration table produced by
`sub_140173C30` (see `string_to_id_registration_analysis.md`). For each of
`2848896 / 288 = 9892` records (stride 288 bytes each):

```c
for ( i = 0; i < 2848896; i += 288 )
{
  v3 = operator new(4);
  *v3 = *(_DWORD *)(sub_140173C30() + i);        // record: 4-byte numeric ID
  v4 = *(_BYTE **)(sub_140173C30() + i + 16);    // record+16: keyword string ptr
  // build SSO string from keyword, then insert (string -> int*) into the hash
  sub_141D366A0(&qword_14375D000, &keyword_string, v3);
  // track max ID seen: HIDWORD(qword_14375D080) = max(id)
}
LODWORD(qword_14375D080) = max_id + 1;           // -> table capacity / next free ID
```

Record layout in the static table (stride 288):
| Offset | Meaning |
|--------|---------|
| `+0x00` | 4-byte numeric ID |
| `+0x10` | pointer to keyword string |

The mapper's role in registration: given the script keyword string (e.g. `my_effect`),
`sub_141D34530()` returns the singleton, and the caller invokes vtable slot `+16` on it
(`hash_string_to_id`) to obtain the keyword's **numeric ID**. If unmapped, default ID `12`
is used. That numeric ID is then the BST sort key and the conflict-detection key above.

## Key Callees

| Address | Purpose |
|---------|---------|
| `sub_1401604E0` | String (SSO) assignment/construction helper |
| `sub_140B6B4D0` | Assign into template-body sub-object at `a1+64` |
| `sub_141D34530` | Magic-static accessor for the string→ID hash singleton |
| `sub_141D366A0` | Hash-map insert (string → int*) used during mapper construction |
| `sub_141CB3210` | Thread-safe warning/error logger (vsnprintf + mutex) |
| `sub_141CB28D0` | Logger backing state accessor (called by `sub_141CB3210`) |

## Extension Point Significance

These two functions are the **runtime registration entry points** for scripted
effects/triggers loaded from `common/scripted_effects/` and `common/scripted_triggers/`.
They confirm the extension architecture:

1. Script keywords are interned to numeric IDs by the global string→ID hash
   (`qword_14375D000`, built from the huge static registration table).
2. Registration templates are stored in **ID-ordered binary search trees**
   (`qword_14339AEA8` / `qword_143287968`) with embedded-null-marker sentinels.
3. Duplicate IDs are detected and soft-warned, not fatal — the newly-loaded definition
   **overwrites** the existing one in the BST.

This matches the AGENTS.md note: a mod's scripted effect/trigger with the same name as a
built-in will overwrite it, and the engine *fails soft* (warning log) rather than refusing
the duplicate. There is **no dynamic registration of new hardcoded effect keywords** here —
only the mapping of script-defined names to existing interned IDs is exercised.

## Status

- [x] Both registration functions decompiled (`sub_1408A6EB0`, `sub_1408A79A0`)
- [x] Pseudocode captured for both
- [x] BST structure documented (node layout, sentinel encoding, ordering)
- [x] String-to-ID mapper analyzed (`sub_141D34530` / `sub_141D34E40` / `qword_14375D000`)
- [x] Conflict (overwrite) detection documented
