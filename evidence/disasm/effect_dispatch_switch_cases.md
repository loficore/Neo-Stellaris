# Effect Dispatch Switch-Cases — `sub_14180B050`

## Overview

- **Address**: `0x14180B050`
- **Source file**: `effect_impl\effect_impl.cpp` (`0x14260ee30`)
- **Size**: 2166 bytes, 141 basic blocks, cyclomatic complexity 113
- **Prototype**: `__int64 __fastcall(__int64, __int64, __int64, __int64)`
- **Callers**: `sub_14181B740`, `sub_141851260` (code xrefs at `0x14181c47c`, `0x1418513b0`), plus vtable entry at `0x143824504`
- **Dispatch key**: effect ID is read as a **DWORD from object `a3` + 0x68 (offset 104)**
  ```asm
  mov eax, [r8+68h]        ; 14180b09c — a3+104 = effect type ID
  ```

## Switch Table Structure

Three jump tables handle contiguous ID ranges. Each range is dispatched via a two-level
jump: a sparse comparison ladder filters outlier IDs, then a byte-indexed jump table
(`byte_` → `jpt_`) handles the dense range.

| Jump table | Base addr | Index byte array | Case base ID (dec) | Case count | ID range |
|-----------|-----------|------------------|--------------------|------------|----------|
| `jpt_14180B169` | `0x14180B169` | `byte_14180B670` | 11213 (`0x2BCD`) | 254 | 11213–11466 |
| `jpt_14180B1D3` | `0x14180B1D3` | `byte_14180B778` | 11706 (`0x2DBA`) | 159 | 11706–11864 |
| `jpt_14180B25F` | `0x14180B25F` | `byte_14180B820` | 12835 (`0x3223`) | 166 | 12835–13000 |

Dispatch skeleton for each dense table (identical pattern; e.g. table 1):
```asm
sub eax, 2BCDh        ; 14180b13d  switch 254 cases — subtract case base
cmp eax, 0FDh         ; 14180b142  bounds check (0xFD = 253)
ja  def_14180B169     ; 14180b147  default → LABEL_99
movzx eax, (byte_14180B670)[rdx+rcx]  ; 14180b157  index byte (sparse → dense)
mov ecx, (jpt_14180B169)[rdx+rax*4]   ; 14180b15f  jumptable entry
add rcx, rdx          ; 14180b166  rebase
jmp rcx               ; 14180b169  switch jump
```

## Effect ID → Case Mapping

All cases in the lists below resolve to **LABEL_97** (`loc_14180B3E9`), the shared
execution path that dispatches the effect into scope handling. The rest (all other IDs
in each table's range) fall through to **LABEL_99** (`def_14180B169`), which is the
default handler comparing `[rbx+68h]` against `0x165`.

### Table 1 (`jpt_14180B169`, base 11213, 254 cases) — LABEL_97 cases
```
11213, 11294, 11344, 11365, 11378,
11403, 11404, 11405, 11410, 11411, 11412, 11466
```

### Table 2 (`jpt_14180B1D3`, base 11706, 159 cases) — LABEL_97 cases
```
11706, 11707, 11818, 11839, 11855, 11856, 11864
```

### Table 3 (`jpt_14180B25F`, base 12835, 166 cases) — LABEL_97 cases
```
12835, 12868, 12886, 12895, 12935,
12949, 12950, 12951, 12952, 12953, 12999, 13000
```

> **Note**: These are the IDs the switch explicitly routes to the shared handler.
> The default path (LABEL_99) at `0x14180B406` compares the object's ID against
> `0x165` and handles generic `create_species`/`modify_species` logic — most effect
> IDs in each table range fall into this generic handler, meaning this function is a
> **special-case dispatcher over the create_species family of effects** rather than a
> complete effect-keyword dispatch table.

## Key Callees (execution paths)

| Address | Purpose (from call site context) |
|---------|----------------------------------|
| `sub_140358B20` | `0x14180b503` — primary handler; called with the effect scope, dispatches generic create/modify species work |
| `sub_1403F27F0` | `0x14180b4a7`, `0x14180b56a`, `0x14180b5af` — attaches resolved species pointer to scope `+0x1B0` |
| `sub_140355070` | `0x14180b3f9` — validation predicate on `[r8+188h]` (if true, skip species creation) |
| `sub_14039A060` | `0x14180b579`, `0x14180b591` — resolves planet class from target |
| `sub_1403EB140` | `0x14180b59d` — loads planet class data (`+1B0` accessor) |
| `sub_140DB7330` | `0x14180b46c` — string/name DB lookup (species name resolution) |
| `sub_1401604E0` | `0x14180b45f` — string construction helper |
| `sub_141CB3210` | `0x14180b4eb`, `0x14180b5fa` — error logging (`log_or_throw`-style) |
| `sub_14023C540` / `sub_14023BD10` | `0x14180b604` / `0x14180b646` — cleanup / teardown of stack temporaries |

## Error Paths (evidence of effect identity)

The LABEL_97 handler emits species-effect-specific errors, confirming the function
handles the **create_species / modify_species** effect family:

- `0x14260eec0` — `"Error in create_species/modify_species: Trying to set the ideal planet class of a species to an invalid planet class (&S) in %s"` (reported at `0x14180b4b1`, line 0x8E)
- `0x14260ee80` — `"Could not resolve a valid planet class from target \"%s\". %s"` (reported at `0x14180b5b6`, line 0x7F)
- Source file tag: `C:\mnt\gsg\stellaris\augustus\augustus\source\effect_impl\effect_impl.cpp`

## Analysis Notes

- The `*_BYTE*(a3+408) || *(_DWORD*)(a3+404)` early-out at `0x14180b08e` gates the
  entire dispatch — an already-initialized/marked object skips straight to LABEL_97.
- ID values 0x6B (107), 0x26C2, 0xE1, 0x204 etc. are handled as individual
  equality cases in the sparse ladder (`sub eax, ...; jz loc_14180B3E9`) — these are
  low/high-frequency IDs checked before the dense jump tables.
- The object layout at `a3`: +0x40 name string (SSO), +0x68 effect type ID, +0x78
  class name ptr, +0x188 validity flag, +0x194/+0x198 init markers.

## Status

- [x] Function disassembled (359 instructions shown, full function)
- [x] 3 jump tables identified with bases, index arrays, case counts
- [x] Effect IDs extracted from IDA repeatable comments
- [x] Key callees identified with call-site semantics
