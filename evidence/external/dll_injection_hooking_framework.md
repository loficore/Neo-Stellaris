# DLL Injection & Hooking Framework Research — External Evidence

**Date**: 2026-08-11
**Scope**: x86-64 Windows game modding; sources: stellarstellaris-win, MinHook, Detours, khalladay/hooking-by-example, sigmatch

## Sources & SHAs

| Repo | URL | HEAD SHA |
|------|-----|----------|
| stellarstellaris-win | github.com/MattMills/stellarstellaris-win | `f46c328f50b4a997b9c0ad33a7964f5fd1a1b473` |
| hooking-by-example | github.com/khalladay/hooking-by-example | `32b2f9b7f9a3d3bb6c86ba2d413923dc58bffc74` |
| MinHook | github.com/TsudaKageyu/minhook | `d94c64d32ea37bc4f5ee47d580709f70c6fb6080` |
| sigmatch | github.com/SpriteOvO/sigmatch | `91571520dda49903f2b7de7a1a44e2daaa27e607` |
| Detours | github.com/microsoft/Detours | wiki: OverviewInterception |

## Key Files (stellarstellaris-win)

- `src/loader/main.cpp` — loader exe: PID discovery, memory search, version detection, injection
- `src/hooking/windows.cpp` — searchMemory, AllocatePageNearAddress, InjectPayload (CreateRemoteThread), thread suspend
- `src/hooking/asm.cpp` — Capstone-based trampoline builder, absolute jump/call emission
- `src/dll/dllmain.cpp` — DllMain, PushCApplicationPtr export, init thread (suspend → hook init → resume)
- `src/dll/hooking_common.cpp` — installHook: relay + trampoline assembly, TLS trampoline-address passing
- `src/dll/address_helper.cpp` — version×OS×platform symbol→VA map + sigmatch signatures
- `src/dll/cship.cpp` — example payload/trampoline pattern (CalcRegenAmount overflow fix)
- `src/dll/assembly_patches.cpp` — direct byte-patch examples (NOP-out calls, xor fix)

## Architecture: loader → injection → DLL init → hook install

```
stellar-loader.exe                        stellaris.exe (target)
┌──────────────────────┐                  ┌──────────────────────────────────┐
│ FindPidByName        │   OpenProcess    │                                  │
│ searchMemory("augustus") ──────────────►│  CApplication struct located by  │
│   → p_application    │   ReadProcessMem │  string search (augustus) - 56   │
│ version detection    │                  │                                  │
│ InjectPayload:       │                  │                                  │
│  VirtualAllocEx      │  WriteProcessMem │  ┌────────────────────────────┐  │
│  WriteProcessMemory  │                 │  │ LoadLibraryA (remote thread)│  │
│  CreateRemoteThread  │──► LoadLibraryA ─►  │   → DllMain attach          │  │
│   (LoadLibraryA)     │                  │  └────────────────────────────┘  │
│  CreateRemoteThread  │──► exported ─────►  │ PushCApplicationPtr(ptr,base)│  │
│   (PushCApplicationPtr)                  │  │   → spawns detached init     │  │
│  VirtualFreeEx       │                  │  │     thread                    │  │
└──────────────────────┘                  │  │     1. sleep 3s (avoid deadlock)│
                                          │  │     2. SetOtherThreadsSuspended(true)
                                          │  │     3. init_address_map()      │
                                          │  │     4. installHook(...)        │
                                          │  │     5. SetOtherThreadsSuspended(false)
                                          │  │     6. heartbeat loop          │
                                          │  └────────────────────────────┘  │
                                          └──────────────────────────────────┘
```

## Trampoline layout (installHook, hooking_common.cpp)

```
hookMemory (AllocatePageNearAddress(func2hook), PAGE_EXECUTE_READWRITE)
├─ 0..102   : pre-payload "argument-shuttle" machine code:
│    save arg regs (rcx/rdx/r8/r9 + xmm0-3)
│    mov rcx, trampolineAddress      ; pass trampoline addr as arg
│    sub rsp, 0x20                   ; home space
│    call PushAddress                ; TLS stack: push trampoline addr
│    add rsp, 0x20
│    restore arg regs
│    jmp  payload function
├─ 102..    : BuildTrampoline output (stolen instructions +
│    jmp back to target+5 + absolute instruction table)
├─ after    : relay function = WriteAbsoluteJump64 → hookMemory (loop back)
target func: E9 rel32 → relayFuncMemory   (5-byte relative jump)
```

## Trampoline build (asm.cpp, BuildTrampoline)

- StealBytes: Capstone disassembles first ≤20 bytes, collects instrs covering ≥5 bytes
- memset stolen bytes to 0x90 (NOP) in target
- per-instruction handling:
  - relative Jcc/JMP → add entry to Absolute Instruction Table (movabs r10 + jmp r10), rewrite operand as short jump to table
  - relative CALL (E8) → replace with NOP-padded `EB xx` jump to table; table entry = `movabs r10, target; call r10; EB xx` back-jump
  - RIP-relative (e.g. `lea rcx,[rip+X]`) → RelocateInstruction rewrites displacement
  - LOOP instructions → bail out (return 0)
- final `jmp target+5` appended; absolute jump to relay installed at target start

## ASLR / version handling (address_helper.cpp)

- addr_map: `[version][OS][platform][symbol] → VA` (versions 3.4.5 / 3.5.2 / 3.6.1 / 3.7.4, Steam/GOG)
- runtime: `addr = base_offset + map[...] - hModule` where hModule = GetBaseModuleForProcess
- fallback for unknown version: sigmatch byte-signatures (e.g. `48 89 5c 24 08 ...` with `??` wildcards)
- loader locates CApplication live via ReadProcessMemory string scan for "augustus", passes pointer to DLL via exported PushCApplicationPtr
- version string read from `_GameVersion._szName` with local/remote pointer heuristic (see loader main.cpp L119-134)

## Thread safety

- installHook: SetOtherThreadsSuspended(true/false) around patch (commented out in final hooking_common.cpp but performed at init_thread level)
- dllmain.cpp init thread: sleep 3000ms first (avoid deadlock with loader), suspend all other threads → init_address_map + hooks → resume (3× with 100ms sleeps)
- hooking_common.cpp: `thread_local std::stack<uint64_t> hookJumpAddresses` — each thread gets its own trampoline address stack; PopAddress memcpy's the trampoline pointer into caller's function pointer
- MinHook: ProcessThreadIPs — when enabling/disabling, enumerates threads with Toolhelp snapshot and rewrites EIP/RIP if it points inside the patched region (hook.c)

## MinHook x64 buffer strategy (buffer.c)

- GetMemoryBlock seeks a VirtualAlloc region within ±512MB (MAX_MEMORY_RANGE 0x40000000) of target, so the 5-byte E9 relative jump stays in ±2GB range
- FindPrevFreeRegion/FindNextFreeRegion walk allocation-granularity steps via VirtualQuery, preferring MEM_FREE regions
- MEMORY_SLOT slots carved out of 0x1000 blocks; PAGE_EXECUTE_READWRITE

## Direct patch examples (assembly_patches.cpp)

- NOP-out a call: `e8 a8 46 c2 ff` → 5× 0x90 (CAlertManager::Update species-modification check)
- Fix multiplication: `41 8b c4 41 0f af c4` (mov eax,r12d; imul eax,r12d) → xor rax,rax; mov eax,r12d; nop (COutlinerGroupArmy::UpdateInternal)
- Uses VirtualProtectEx + memcpy; addresses resolved via find_address_from_symbol

## Fixed-point replacement pattern (cship.cpp)

- Hooks CShip::CalcRegenAmount: converts CFixedPoint params to double, computes `(max_hp * multiplier/1e7) + static_add`, clamps negative to INT64_MAX/2, writes result via `*((int64_t*)ptr1) = result; return ptr1` — an out-param style return, bypassing the trampoline (original never called)
- PopAddress retrieves trampoline pointer to call original when needed
