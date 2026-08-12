# String-to-ID Registration System Analysis

**Binary**: `stellaris.exe` (Clausewitz "augustus")
**IDA session**: `cdd1c2bb`

## 1. Function Profile — `sub_140173C30`

| Attribute | Value |
|-----------|-------|
| Address | `0x140173C30` |
| Size | `0x3C66C` (247,660 bytes ≈ 247 KB) |
| Instruction count | 49,481 |
| Basic blocks | 4 |
| Caller count | 5 |
| Callee count | 5 (incl. `sub_141D36B40`, `_Init_thread_header`) |
| String refs | 9,876 |
| Constants | 9,896 |

**Role**: Thread-safe magic-static initializer (one-time registration run guarded by
`_Init_thread_header`/`_Init_thread_epoch`). Registers a large set of script/graphics
keyword tokens into global symbol table `unk_1433A1B70` onward.

## 2. Assembly Structure — Registration Call Pattern

Every registration is the same 5-instruction idiom (one per keyword):

```asm
140173c8d  lea  r8, aIdtype          ; r8 = keyword string ptr  ("idtype")
140173c94  mov  edx, 15h             ; edx = numeric ID (0x15)
140173c99  lea  rcx, unk_1433A1C90   ; rcx = destination token struct (global)
140173ca0  call sub_141D36B40        ; construct token {id, name}
140173ca5  nop                       ; padding after inlined ctor
```

Canonical register conventions:
- `rcx` = destination object (a global token struct, stride 0x120 in `.bss`)
- `edx` = assigned numeric ID (sequential, but not strictly 1:1 — see `borderless`)
- `r8`  = string literal (keyword text, loaded via `lea` from `.rdata`)
- `call sub_141D36B40` → token constructor, then a padding `nop`

### Prologue / Wrapper Structure
```asm
140173c30  sub rsp, 28h
140173c34  mov eax, 14h                    ; TlsSlot index
140173c3b  mov rcx, gs:58h                 ; PEB → TLS
140173c44  mov rcx, [rcx]                  ; thread-local storage array
140173c4d  mov eax, [rax]                  ; read TLS epoch
140173c4f  cmp cs:dword_1433A1B60, eax     ; compare init guard
140173c55  jle loc_1401B0290               ; already initialized → done
140173c5b  lea rcx, dword_1433A1B60
140173c62  call _Init_thread_header        ; claim one-time init lock
...
; ~49,000 instructions of `lea r8,str / mov edx,id / lea rcx,tok / call` triads
...
1401b0290  lea rax, unk_1433A1B70          ; tail: return symbol-table base
1401b0297  add rsp, 28h
1401b029b  retn
```

Guard globals:
- `dword_1433A1B60` — `_Init_thread_header` guard / epoch value
- `unk_1433A1B70` — first token object; token array base returned at tail

## 3. Keyword → ID Mappings (extracted)

Target token structs live in `.bss` starting at `0x1433A1B70`; string literals in `.rdata` at `0x14249B288`+.

| Keyword | ID (hex) | ID (dec) | String addr | Token struct addr |
|---------|----------|----------|-------------|-------------------|
| (unnamed token) | 0x0B | 11 | `0x14249B288` | `0x1433A1B70` |
| idtype | 0x15 | 21 | `0x14249E6BC` | `0x1433A1C90` |
| machineid | 0x16 | 22 | `0x14249E6D8` | `0x1433A1DB0` |
| filelist | 0x18 | 24 | `0x14249E6C8` | `0x1433A1ED0` |
| dir | 0x19 | 25 | `0x14249E6EC` | `0x1433A1FF0` |
| file | 0x1A | 26 | `0x14249E6E4` | `0x1433A2110` |
| name | 0x1B | 27 | `0x14249DC00` | `0x1433A2230` |
| noOfFrames | 0x1C | 28 | `0x14249E6F8` | `0x1433A2350` |
| fonts | 0x1D | 29 | `0x14249E6F0` | `0x1433A2470` |
| font | 0x1E | 30 | `0x14249E70C` | `0x1433A2590` |
| height | 0x1F | 31 | `0x14249E704` | `0x1433A26B0` |
| x | 0x20 | 32 | `0x14249DA08` | `0x1433A27D0` |
| y | 0x21 | 33 | `0x14249E724` | `0x1433A28F0` |
| fontName | 0x22 | 34 | `0x14249E718` | `0x1433A2A10` |
| charSet | 0x23 | 35 | `0x14249E730` | `0x1433A2B30` |
| xFile | 0x24 | 36 | `0x14249E728` | `0x1433A2C50` |
| textureFile | 0x25 | 37 | `0x14249E748` | `0x1433A2D70` |
| textureFile1 | 0x26 | 38 | `0x14249E738` | `0x1433A2E90` |
| textureFile2 | 0x27 | 39 | `0x14249E768` | `0x1433A2FB0` |
| textureFile3 | 0x28 | 40 | `0x14249E758` | `0x1433A30D0` |
| textureFile4 | 0x29 | 41 | `0x14249E788` | `0x1433A31F0` |
| textureFile5 | 0x2A | 42 | `0x14249E778` | `0x1433A3310` |
| textureFile6 | 0x2B | 43 | `0x14249E7A8` | `0x1433A3430` |
| textureFile7 | 0x2C | 44 | `0x14249E798` | `0x1433A3550` |
| textureFile8 | 0x2D | 45 | `0x14249E7C8` | `0x1433A3670` |
| textureFile9 | 0x2E | 46 | `0x14249E7B8` | `0x1433A3790` |
| size | 0x2F | 47 | `0x14249E7E4` | `0x1433A38B0` |
| fullScreen | 0x30 | 48 | `0x14249E7D8` | `0x1433A39D0` |
| borderless | 0x1D5 | 469 | `0x14249E7F8` | `0x1433A3AF0` |
| cube | 0x31 | 49 | `0x14249E7EC` | `0x1433A3C10` |
| center | 0x32 | 50 | `0x1424D3124` | `0x1433A3D30` |
| side | 0x33 | 51 | `0x14249E818` | `0x1433A3E50` |
| animatedMesh | 0x34 | 52 | `0x14249E808` | `0x1433A3F70` |
| spriteTypes | 0x35 | 53 | `0x14249E830` | `0x1433A4090` |
| spriteType | 0x36 | 54 | `0x14249E820` | `0x1433A41B0` |
| objectTypes | 0x37 | 55 | `0x14249E850` | `0x1433A42D0` |
| cubeType | 0x38 | 56 | `0x14249E840` | `0x1433A43F0` |
| meshType | 0x39 | 57 | `0x14249E870` | `0x1433A4510` |
| mapMeshType | 0x3A | 58 | `0x14249E860` | `0x1433A4630` |
| animatedMeshType | 0x3B | 59 | `0x14249E888` | `0x1433A4750` |
| sprites | 0x3C | 60 | `0x14249E880` | `0x1433A4870` |
| sprite | 0x3D | 61 | `0x14249E8A8` | `0x1433A4990` |
| objects | 0x3E | 62 | `0x14249E8A0` | `0x1433A4AB0` |
| group | 0x3F | 63 | `0x14249E8BC` | `0x1433A4BD0` |
| animation | 0x40 | 64 | `0x14249E8B0` | `0x1433A4CF0` |
| object | 0x41 | 65 | `0x14249E8E0` | `0x1433A4E10` |
| defaultAnimationTime | 0x42 | 66 | `0x14249E8C8` | `0x1433A4F30` |
| particleType | 0x43 | 67 | `0x14249E8F8` | `0x1433A5050` |
| flareType | 0x44 | 68 | `0x14249E8E8` | `0x1433A5170` |

**Observations**:
- Keyword family = **graphics/sprite/GUI system** (fonts, textures, sprites, meshes,
  particles, screen modes) — this is the Clausewitz graphics config token table, not the
  effect/trigger table.
- IDs are mostly sequential but gaps exist (`0x0B→0x15`, `0x16→0x18` skipped 0x17)
  and one offset out-of-sequence (`borderless = 0x1D5`, likely a late-added keyword).
- Token structs are laid out contiguously at 0x120-byte stride (`0x1433A1C90 → 0x1433A1DB0 = 0x120`).

## 4. Registration Function — `sub_141D36B40` (token constructor, 92 bytes)

```c
__int64 __fastcall sub_141D36B40(__int64 a1, __int64 a2, __int64 a3)
{
  *(_BYTE *)(a1 + 4)  = 0;                 // flags / type byte
  *(_OWORD *)(a1 + 8) = 0;                 // clear vtable + data ptr
  *(_QWORD *)(a1 + 24) = 256;              // capacity = 256
  *(_QWORD *)(a1 + 8) = &off_14249E1D8;    // vtable / type tag
  *(_QWORD *)(a1 + 16) = a1 + 32;          // inline buffer at +32
  v4 = -1;
  do ++v4; while (*(BYTE *)(a3 + v4));     // strlen(a3)
  sub_141D37170(a1, a2, a3, v4);           // set id + copy string
  return a1;
}
```

Called only from `sub_140173C30` (10+ call sites in the first ~100 instructions alone).

## 5. String-setter — `sub_141D37170` (113 bytes)

```c
void *__fastcall sub_141D37170(__int64 a1, int a2, const void *a3, unsigned int a4)
{
  *(_BYTE *)(a1 + 4) = 0;
  *(_DWORD *)a1 = a2;                      // store numeric ID at +0
  v7 = a4 + 1;
  if ((int)(a4 + 1) > *(_DWORD *)(a1 + 28))  // grow if needed
    sub_140171290(a1 + 8, v7);            // buffer grow helper
  *(_DWORD *)(a1 + 28) = v7;              // update size
  v8 = *(void **)(a1 + 16);
  memmove(v8, a3, a4);                    // copy keyword bytes
  *((BYTE *)v8 + a4) = 0;                 // null-terminate
  return result;
}
```

Also called from `sub_140355930`, `sub_1403567D0`, `sub_140356C70`, `sub_141D36BA0`
(token reload paths).

### Token struct layout (inferred)
| Offset | Size | Field |
|--------|------|-------|
| +0x00 | 4 | numeric ID |
| +0x04 | 4 | flags/type |
| +0x08 | 8 | vtable `off_14249E1D8` (type tag) |
| +0x10 | 8 | data buffer ptr (inline at +32 by default) |
| +0x18 | 4 | capacity = 256 |
| +0x1C | 4 | current string size |
| +0x20 | … | inline string buffer |

## 6. Key Takeaways

1. **ID assignment is compiler-emitted, not hashed** — numeric IDs are plain immediates
   in `mov edx, imm`; the string is copied verbatim via `memmove`. Lookups later
   presumably compare ID ints, giving a fast int-keyed token table.
2. **Static-init gate** means all tokens exist before game scripts parse; the returned
   base `unk_1433A1B70` is the symbol table entry point.
3. **Extension point**: a modded/DLL-hooked registration could append entries by
   replicating the `sub_141D36B40` ctor into a new token struct at the next 0x120 slot
   (IDs must be unique and non-clashing with existing immediates).
4. This function registers **graphics keywords**, distinct from the effect/trigger
   string tables registered at `sub_140173C30`'s sibling initializers.
