# The `js_rc` trap — 131-byte function at rva `0xbd70..0xbdf3`

**Artifact**: `zig-out/bin/stellaris_quickjs.dll`
**sha256**: `77c0c35ec5b74abc8ccb849515621aaf53abd3fdc0a5e6ab8b9466acc0c11ad0` — verified
before and after this file was produced. No build ran in this task (`zig build` not invoked), and
`src/`, `build.zig`, `libs/quickjs/` were not edited, so the bytes are the same artifact §45/§46 used.
**Producer**: `scripts/pe_disrva.py` (new: disassembles a byte range of *our own* PE, not the game exe).
**Range**: `rva 0xbd70..0xbdf3`, **end exclusive**. `scripts/dll_ubsan_site.py func 0x18000bd9b`
prints the `.pdata` span as `rva 0xbd70..0xbdf3 (131 bytes)`; the listing below accounts for all
**131 bytes** in **40 instructions**, so the exclusive end and the byte count agree.

Command (exit code 0):

```
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbd70 0xbdf3
```

## Listing (verbatim tool output)

```text
; stellaris_quickjs.dll .text rva 0xbd70..0xbdf3 (end exclusive) image_base=0x180000000: 40 insns, 131 bytes
  0000bd70  push    rbp
  0000bd71  sub     rsp, 0x50
  0000bd75  lea     rbp, [rsp + 0x50]
  0000bd7a  mov     qword ptr [rbp - 8], rcx
  0000bd7e  mov     rax, qword ptr [rbp - 8]
  0000bd82  mov     qword ptr [rbp - 0x10], rax
  0000bd86  xor     eax, eax
  0000bd88  test    al, 1
  0000bd8a  jne     0x18000bd9c
  0000bd8c  lea     rcx, [rip + 0x59f69d]  #0x5ab430
  0000bd93  xor     eax, eax
  0000bd95  mov     edx, eax
  0000bd97  call    0x180498170  #0x498170
  0000bd9c  mov     r8, qword ptr [rbp - 0x10]
  0000bda0  test    r8, r8
  0000bda3  setne   al
  0000bda6  xor     edx, edx
  0000bda8  mov     rcx, r8
  0000bdab  add     rcx, -8
  0000bdaf  mov     qword ptr [rbp - 0x28], rcx
  0000bdb3  mov     qword ptr [rbp - 0x20], r8
  0000bdb7  mov     qword ptr [rbp - 0x18], rcx
  0000bdbb  setne   r9b
  0000bdbf  xor     al, r9b
  0000bdc2  xor     al, 1
  0000bdc4  xor     dl, 0xff
  0000bdc7  cmp     rcx, r8
  0000bdca  setbe   cl
  0000bdcd  and     cl, dl
  0000bdcf  and     al, cl
  0000bdd1  test    al, 1
  0000bdd3  jne     0x18000bde9
  0000bdd5  mov     r8, qword ptr [rbp - 0x18]
  0000bdd9  mov     rdx, qword ptr [rbp - 0x20]
  0000bddd  lea     rcx, [rip + 0x59f66c]  #0x5ab450
  0000bde4  call    0x180499cc0  #0x499cc0
  0000bde9  mov     rax, qword ptr [rbp - 0x28]
  0000bded  add     rsp, 0x50
  0000bdf1  pop     rbp
  0000bdf2  ret
```

The `#0x...` columns are RVAs (relative to `image_base=0x180000000`), not VAs; they compare
directly with the `record_rva=` values `dll_ubsan_site.py` prints.

## Reading — operand order and encodings

### "Subtract 8" is `add rcx, -8`, not `sub`

At `0xbdab` the bytes are `48 83 c1 f8` = `add rcx, -8` (sign-extended imm8 `0xf8`). The artifact
does **not** contain a `sub rcx, 8` for this header trick, so a text grep for "sub" would miss it.
The offset is 8 because `user_data` is at offset 8 in `JSMallocBlockHeader`
(`libs/quickjs/quickjs.c:270-280`: 2 + 1 + 1 + 4 header bytes), which is the `container_of` in
`js_rc` at `quickjs.c:1490-1495`. `scripts/test_pe_disrva.py::_has_sub8` accepts `sub r,8`,
`add r,-8` (also the 64-bit `0xfffffffffffffff8` spelling) and `lea r,[r-8]`, so this measured
encoding is reported as it is instead of being rewritten to match the plan's word "sub".

### The zero test is `test r8, r8` on the **original** pointer

- `0xbd9c` `mov r8, [rbp - 0x10]` reloads the argument saved at `0xbd82`; that value came from
  `rcx` at entry (`0xbd7a`, `0xbd7e`). `r8` is the caller's `ptr`, untouched so far.
- `0xbda0` `test r8, r8` (`4d 85 c0`) + `0xbda3` `setne al` — the null test reads the
  **pre-subtract** value.
- `0xbda8` `mov rcx, r8`; `0xbdab` `add rcx, -8`; `0xbdaf` stores the result.
- `0xbdbb` `setne r9b` consumes the flags left by the `add` (result != 0); `0xbdbf` `xor al, r9b`;
  `0xbdc7` `cmp rcx, r8`; `0xbdca` `setbe cl` (new <= old, i.e. no unsigned wrap); `0xbdd1`
  `test al, 1`; `0xbdd3` `jne 0x18000bde9` skips the second UBSan call.
- No instruction in the function dereferences `ptr`: the `mov`s are stack saves, and `cmp` is
  register-only. So performing the `-8` before the guard cannot fault by itself.

**Operand-order answer for Task 3**: the expression whose nullness is tested is the *original*
pointer `r8`, and that `test` executes at `0xbda0`, **before** the `add -8` at `0xbdab`. The
conditional branch that consumes the combined flag (`test al,1; jne`) is at `0xbdd1`, after the
`add`, but it branches on a value already computed from the pre-subtract test. There is no encoding
here that tests the post-subtract `rcx` for null.

### The two UBSan records this function loads

- `0xbd8c` `lea rcx, [rip + 0x59f69d]` → `#0x5ab430`; `0xbd97` `call` → `#0x498170`. The record at
  `0x5ab430` is `quickjs.c:1494:12 member_access type='JSMallocBlockHeader'` — exactly what §45
  pinned; `dll_ubsan_site.py func 0x18000bd9b` prints the same record with
  `loaded_at=0x18000bd8c`. `rdx` is zeroed before the call (`xor eax,eax` / `mov edx,eax`), so the
  reported pointer value is the literal 0, not `r8`.
- `0xbddd` `lea rcx, [rip + 0x59f66c]` → `#0x5ab450`; `0xbde4` `call` → `#0x499cc0`. The record at
  `0x5ab450` is `quickjs.c:1494:12 reference_binding`; the call's arguments are
  `r8 = [rbp-0x18] = ptr-8` and `rdx = [rbp-0x20] = ptr`.
- §45's abort frame prints `0x18000bd9b` (``ip − 1``), which falls inside the first call
  (`0xbd97..0xbd9c`) — the `member_access` handler.

### Caveat: what this listing does not decide

As encoded, `0xbd86 xor eax,eax` zeroes AL, so `0xbd88 test al,1` / `0xbd8a jne 0xbd9c` can never
take the jump on the straight-line entry from `0xbd70`: the first handler call at `0xbd97` is
reached unconditionally on that path. The in-function null test is the later `test r8,r8`. Whether
`0xbd70` is additionally entered by a branch from a caller (i.e. whether this function is an
outlined check block) is **not observable in this listing** and was not scanned for in this task.
What the bytes do establish is narrow and sufficient for the operand-order question: within the
131-byte function, the only zero test of the pointer is on the value before `add -8`.

Disassembly proves **which expression** is checked, never a runtime value; whether `r8` was null in
the failing run remains with the §45/§46 repro (`scripts/c2_selfabort_repro.py`).
