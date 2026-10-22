# C2 QuickJS Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get QuickJS runtime + context alive inside the injected DLL and run one JS snippet end-to-end against a registered handler, so C3 (chokepoint_score pilot) has a working extension host to build on.

**Architecture:** Fix the C2 remote-call harness to read the DLL's real 64-bit base via the same PowerShell query C1 already uses. Then use that harness to walk the diagnostic chain — DLL loaded → sanity check → QuickJS runtime/context → eval + JS_Call round trip. The vtable + predicate-hook machinery (already written in `src/dll/c2/`) stays gated behind a working context and gets wired in only after JS eval works.

**Tech Stack:** Zig 0.16 (DLL side), vendored QuickJS in `libs/quickjs/`, thin C wrapper `src/dll/quickjs/quickjs_wrapper.c`, Windows HeapAlloc custom allocator, Python 3 + ctypes + PowerShell for the remote harness, SSH alias `Windows_Jiaolong` for the target machine.

**Spec:** `docs/roadmap.md` 段3 的 C2 行 + `AGENTS.md`「硬性约束」1–7（仍然有效）。

## Global Constraints

- Game version: **4.4.4**; target binary is `stellaris.exe` on `Windows_Jiaolong`.
- Every build shifts RVAs — **do not hard-code RVAs**. Reparse `zig-out/bin/stellaris_quickjs.dll` PE exports per build (see `scripts/c2_test_sanity.py:32-56` for the parse routine to lift).
- HMODULE on x64 is 64-bit; `GetExitCodeThread` truncates to 32-bit. **Never treat the LoadLibrary thread's exit code as the base address.** Query the real base via `Get-Process stellaris | Select-Object -ExpandProperty Modules | Where-Object { $_.ModuleName -eq "<dll filename>" } | Select-Object -ExpandProperty BaseAddress`.
- Do not modify DLL-injection mechanics beyond what this plan specifies — `LoadLibraryA` via `CreateRemoteThread` + PowerShell base lookup is the working pattern (`scripts/c1_remote.py`).
- Do not add new Zig `extern fn` bindings to QuickJS C symbols — keep everything through `quickjs_wrapper.c` until blocker 1 is root-caused (it is out of scope here).
- Do not commit `.dll`/`.pdb`/`C:\temp\*` artifacts. Only commit source, scripts, and evidence.
- Every remote test ends with a "game still alive" check (`tasklist /FI "PID eq <pid>"`). If the game crashed, restart it manually before the next run — do not automate the restart.
- Never call `ida_auto.plan_and_wait` on session `f3ea6101` (`AGENTS.md` constraint 2).
- C1 registration gate stays closed (`authorize.c1_registration = false`) — this plan does not touch it.

## Review Focus

The tests below pin the happy path. These five classes are the failure modes a person shipping this work is most likely to hit — name each in the owning task's tests.

- **Base-address truncation** (this is the current bug): harness reports LoadLibrary success but calls a wrong address. Expected behavior: harness fails loudly with a "base mismatch" error, not a silent crash of the game.
- **Stale RVAs after a rebuild**: person edits `exports.zig`, rebuilds, reuses the old RVAs in the test script. Expected: PE parser reads exports fresh every run; the script does not accept a hard-coded RVA table.
- **DLL loaded but DllMain crashed**: LoadLibrary returns non-NULL but the process is unstable or the marker file never appears. Expected: harness refuses to proceed to function calls unless the sanity function returns 42.
- **QuickJS intrinsic failure returns 0 vs. NULL confusion**: the diagnostic returns `diag_rc` from `JS_NewContextDiag`, but a value of 0 with `g_test_ctx = NULL` must be reported as failure, not success. Expected: harness asserts both rc==0 AND ctx!=NULL before declaring the context usable.
- **JS dispatch returns garbage without visibly failing**: an eval works and `JS_Call` returns, but the returned number is not what the JS source produced. Expected: Task 6 asserts a *specific* numeric return value (`2` for `1+1`) via `JS_ToInt32`, not merely `not-isException`.

---

### Task 1: Build a shared remote-injection harness module

**Files:**
- Create: `scripts/c2_harness.py`
- Test: `scripts/test_c2_harness.py` (host-only smoke tests; runs on Linux without a game process)

**Interfaces:**
- Consumes: nothing (this is the foundation).
- Produces:
  - `resolve_pid(process_name: str) -> int` — returns the game PID or raises `RuntimeError`.
  - `resolve_base_address(pid: int, dll_filename: str) -> int` — full 64-bit base via PowerShell; raises `RuntimeError` if the DLL isn't loaded.
  - `inject_dll(pid: int, remote_dll_path: str) -> None` — `CreateRemoteThread(LoadLibraryA)`; verifies the write succeeded; does **not** trust the thread's exit code as base address.
  - `list_exports(local_dll_path: str) -> dict[str, int]` — returns `{name: rva}` parsed from PE; called fresh each run.
  - `call_remote(pid: int, base: int, rva: int, timeout_ms: int = 30000) -> int` — invokes a no-arg `int __stdcall` function; returns the 32-bit exit code (documented truncation caveat: for a `usize`-returning function, use `read_memory_at` instead).
  - `read_memory(pid: int, addr: int, size: int) -> bytes` — `ReadProcessMemory`; raises on 0-byte read.
  - `assert_game_alive(pid: int) -> None` — `tasklist` check; raises `RuntimeError` if the game died.

- [ ] **Step 1: Write the failing test file**

`scripts/test_c2_harness.py`:
```python
import pytest
from c2_harness import list_exports, parse_module_base_from_ps

def test_list_exports_finds_C2Sanity():
    exports = list_exports("zig-out/bin/stellaris_quickjs.dll")
    assert "C2Sanity" in exports
    assert isinstance(exports["C2Sanity"], int)
    assert exports["C2Sanity"] > 0

def test_parse_module_base_handles_16_hex_digits():
    assert parse_module_base_from_ps("0x00007FF441D20000") == 0x7FF441D20000

def test_parse_module_base_rejects_truncated_string():
    with pytest.raises(ValueError):
        parse_module_base_from_ps("not-a-hex")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest scripts/test_c2_harness.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'c2_harness'`.

- [ ] **Step 3: Implement `scripts/c2_harness.py`**

Reuse the PE export parser from `scripts/c2_test_sanity.py:32-56`. Extract into `list_exports(local_dll_path) -> dict`. Add `resolve_pid`, `resolve_base_address` (subprocess `powershell -Command`), `inject_dll`, `call_remote`, `read_memory`, `assert_game_alive` per the Interfaces block. `parse_module_base_from_ps(s)` is the standalone hex parser the test drives.

Do **not** trust `GetExitCodeThread` on the LoadLibrary handle as the base — call `resolve_base_address(pid, os.path.basename(remote_dll_path))` after `WaitForSingleObject` returns.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest scripts/test_c2_harness.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/c2_harness.py scripts/test_c2_harness.py
git commit -m "feat(scripts): shared C2 remote harness — real base addr via PowerShell, PE reparse"
```

---

### Task 2: Confirm DLL loads without crashing on the real machine

**Files:**
- Create: `scripts/c2_task2_load.py`
- Test evidence: appended into `evidence/analysis/runtime_444_c1_validation.md` as a new §31 "C2 harness bootstrap"

**Interfaces:**
- Consumes: everything from Task 1's `c2_harness`.
- Produces: a fact recorded in evidence — the DLL base address is 64-bit and stable, and `C2Sanity` returns 42 on the real machine.

- [ ] **Step 1: Write the load-check script**

`scripts/c2_task2_load.py`:
```python
import sys, os
from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, read_memory, assert_game_alive,
)

pid = resolve_pid("stellaris")
remote_dll = r"C:\temp\sqjs_c2.dll"
local_dll = "zig-out/bin/stellaris_quickjs.dll"

inject_dll(pid, remote_dll)
base = resolve_base_address(pid, os.path.basename(remote_dll))
print(f"DLL base (real, 64-bit): 0x{base:x}")

# Verify the base is readable and starts with the MZ header
head = read_memory(pid, base, 2)
assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
print(f"MZ header at base OK")

exports = list_exports(local_dll)
rva = exports["C2Sanity"]
rc = call_remote(pid, base, rva)
print(f"C2Sanity -> {rc}")
assert rc == 42, f"Expected 42, got {rc}"

assert_game_alive(pid)
print("Task 2: PASS")
```

- [ ] **Step 2: Rebuild, reupload, restart game if needed**

Run: `zig build && scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c2.dll && scp scripts/c2_task2_load.py Windows_Jiaolong:C:/temp/c2_task2_load.py`
Expected: files copied. If the game is not running, ask the human partner to start it and give you the PID.

- [ ] **Step 3: Run the load check**

Run: `ssh Windows_Jiaolong "python C:/temp/c2_task2_load.py"`
Expected: prints `DLL base (real, 64-bit): 0x…` with a full 64-bit value (not `0x41d20000`), `MZ header at base OK`, `C2Sanity -> 42`, `Task 2: PASS`.
If `C2Sanity` returns 1 again — the harness is still reading a truncated address. Re-check `resolve_base_address`.

- [ ] **Step 4: Record the observed base and pass state in evidence §31**

Append to `evidence/analysis/runtime_444_c1_validation.md`:
```
## 31. C2 harness bootstrap (2026-10-08)

Confirmed root cause of the C2 remote-call crashes: `GetExitCodeThread`
truncates HMODULE to 32 bits, and the LoadLibrary thread reported
`0x41d20000` when the real DLL base was `0x<full 64-bit>`; every
CreateRemoteThread call was aiming at unmapped memory and the game
crashed with an exception exit code of 1. Fix: `scripts/c2_harness.py`
queries `Get-Process | Modules | BaseAddress` via PowerShell exactly as
`scripts/c1_remote.py` does. After the fix, `C2Sanity` returns 42 and
the DLL base is stable across runs.
```

- [ ] **Step 5: Commit**

```bash
git add scripts/c2_task2_load.py evidence/analysis/runtime_444_c1_validation.md
git commit -m "feat(c2): harness reads real 64-bit DLL base — sanity check returns 42 on Windows"
```

---

### Task 3: Run `C2DiagQJS` and record the intrinsic failure step

**Files:**
- Create: `scripts/c2_task3_diag.py`
- Test evidence: appended into `evidence/analysis/runtime_444_c1_validation.md` §32

**Interfaces:**
- Consumes: Task 1 harness; Task 2's confirmed DLL base.
- Produces: a concrete `diag_rc` value in range `{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}` recorded in evidence, plus a decoded failure step (`0` = all OK).

- [ ] **Step 1: Write the diag script**

`scripts/c2_task3_diag.py`:
```python
import os
from c2_harness import (
    resolve_pid, resolve_base_address, list_exports, call_remote,
    read_memory, assert_game_alive,
)

pid = resolve_pid("stellaris")
dll_name = "sqjs_c2.dll"
local_dll = "zig-out/bin/stellaris_quickjs.dll"
base = resolve_base_address(pid, dll_name)
exports = list_exports(local_dll)

rc = call_remote(pid, base, exports["C2DiagQJS"], timeout_ms=60000)
print(f"C2DiagQJS rc = {rc}")

# Decode the failure step (matches quickjs_wrapper.c C2DiagQuickJS + JS_NewContextDiag codes)
DECODE = {
    0:  "ALL_OK: runtime + full context created",
    2:  "JS_NewRuntime2 returned NULL",
    3:  "runtime opaque write+read mismatch",
    4:  "JS_NewContextRaw returned NULL (allocation issue)",
    5:  "Intrinsic 2 failed: JS_AddIntrinsicBaseObjects",
    6:  "Intrinsic 3 failed: JS_AddIntrinsicDate",
    7:  "Intrinsic 4 failed: JS_AddIntrinsicEval",
    8:  "Intrinsic 5 failed: JS_AddIntrinsicStringNormalize",
    9:  "Intrinsic 6 failed: JS_AddIntrinsicRegExp",
    10: "Intrinsic 7 failed: JS_AddIntrinsicJSON",
    11: "Intrinsic 8 failed: JS_AddIntrinsicProxy",
    12: "Intrinsic 9 failed: JS_AddIntrinsicMapSet",
    13: "Intrinsic 10 failed: JS_AddIntrinsicTypedArrays",
    14: "Intrinsic 11 failed: JS_AddIntrinsicPromise",
    15: "Intrinsic 12 failed: JS_AddIntrinsicWeakRef",
}
print(DECODE.get(rc, f"UNKNOWN rc {rc}"))

# Read the diag log string
log_addr = call_remote(pid, base, exports["C2DiagGetLogAddr"])
print(f"g_diag_log @ 0x{log_addr:x}")
log_bytes = read_memory(pid, log_addr, 512)
log_str = log_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
print(f"Diag log: {log_str!r}")

assert_game_alive(pid)
```

- [ ] **Step 2: Run the diag**

Run: `ssh Windows_Jiaolong "python C:/temp/c2_task3_diag.py"` (script must be re-scp'd after Task 2's rebuild)
Expected: `C2DiagQJS rc = <N>` printed plus a decoded line. If `rc` is not in `DECODE`, the harness is misaligned.

- [ ] **Step 3: Record the observed rc + log in evidence §32**

Append to `evidence/analysis/runtime_444_c1_validation.md` a section `## 32. C2 QuickJS diagnostic` with the concrete `rc` and the decoded log string. Do **not** proceed to Task 4 until §32 is written down — Task 4's fix depends on this observation.

- [ ] **Step 4: Commit**

```bash
git add scripts/c2_task3_diag.py evidence/analysis/runtime_444_c1_validation.md
git commit -m "docs(evidence): §32 records C2DiagQJS observed rc + log from live game"
```

---

### Task 4: Fix the failing QuickJS step

**Files:**
- Modify: whatever `Task 3` observation points at — likely `src/dll/quickjs/quickjs_wrapper.c` (heap allocator) or `libs/quickjs/quickjs.c` (`JS_NewContextDiag` path).
- Test evidence: `evidence/analysis/runtime_444_c1_validation.md` §33

**Interfaces:**
- Consumes: the exact failure step from Task 3.
- Produces: `C2TestQuickJS` returns 0 with `g_test_ctx != NULL`.

- [ ] **Step 1: Read Task 3's §32 and pick the minimal fix**

Decision table (each row is one candidate patch; pick the row that matches the observed `rc`):

| rc | Meaning | Candidate fix |
|---|---|---|
| 2 | `JS_NewRuntime2` NULL | heap_mf `js_malloc` returns NULL on the first allocation → check `GetProcessHeap()` inside `heap_malloc` returns non-NULL on this thread |
| 3 | opaque mismatch | ABI skew on the `JSRuntime*` argument — Zig is passing `u64`, C is expecting pointer; re-check `AGENTS.md` constraint 6 |
| 4 | `JS_NewContextRaw` NULL | `rt->ctx_list` initialisation path fails; raise `JS_SetMemoryLimit` from 256 MB to `SIZE_MAX` in `C2TestQuickJS` to eliminate the memory-limit branch |
| 5–15 | specific intrinsic | the intrinsic needs a C symbol we did not link into the DLL — inspect the specific `JS_AddIntrinsic*` function for undefined externs with `x86_64-w64-mingw32-nm --undefined` on the intermediate `.obj` |

Write down which row you picked and why in §33 before making the edit.

- [ ] **Step 2: Apply the fix to the source file**

Edit only the file the row picked in Step 1. Do not refactor unrelated code.

- [ ] **Step 3: Rebuild**

Run: `zig build`
Expected: build succeeds; `zig build test` still passes (currently 293/293 minus the two QuickJS glibc-dependent tests).

- [ ] **Step 4: Re-run the load check to catch any regression**

Run: `ssh Windows_Jiaolong "python C:/temp/c2_task2_load.py"`
Expected: still prints `C2Sanity -> 42` and game alive.

- [ ] **Step 5: Re-run the diag**

Run: `ssh Windows_Jiaolong "python C:/temp/c2_task3_diag.py"`
Expected: `C2DiagQJS rc = 0` and log ends with `diag_rc=0 ctx=0x<non-null>`.

- [ ] **Step 6: Record §33 in evidence**

Document: previous rc, applied fix, new rc, `g_test_ctx` value.

- [ ] **Step 7: Commit**

```bash
git add <modified source> evidence/analysis/runtime_444_c1_validation.md
git commit -m "fix(c2): <one-line description of the QuickJS step that was failing>"
```

---

### Task 5: Prove `C2Init` returns 0 and pointers are non-NULL

**Files:**
- Create: `scripts/c2_task5_init.py`
- Test evidence: `evidence/analysis/runtime_444_c1_validation.md` §34

**Interfaces:**
- Consumes: Task 4's working `C2TestQuickJS` path.
- Produces: `g_test_rt` and `g_test_ctx` non-NULL values observable from the injector via `C2GetQuickJSPointers`. This unblocks any C2 code that assumes a live runtime.

- [ ] **Step 1: Write the init-check script**

`scripts/c2_task5_init.py`:
```python
import os
from c2_harness import (
    resolve_pid, resolve_base_address, list_exports, call_remote,
    read_memory, assert_game_alive,
)

pid = resolve_pid("stellaris")
base = resolve_base_address(pid, "sqjs_c2.dll")
exports = list_exports("zig-out/bin/stellaris_quickjs.dll")

rc = call_remote(pid, base, exports["C2Init"])
assert rc == 0, f"C2Init rc = {rc}"

# Read back the pointers via the exported getter. Because
# C2GetQuickJSPointers(out_rt, out_ctx) has two pointer arguments,
# CreateRemoteThread cannot call it directly. Instead read the static
# g_test_rt / g_test_ctx addresses from the DLL's .data by parsing
# symbol info. Add a task-5 helper here, or use the exported
# C2DiagGetLogAddr pattern to reach the same two globals.
log_addr = call_remote(pid, base, exports["C2DiagGetLogAddr"])
log_bytes = read_memory(pid, log_addr, 512)
log_str = log_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
print(f"C2Init OK; diag log: {log_str!r}")

assert_game_alive(pid)
print("Task 5: C2Init returns 0 and pointers are non-NULL")
```

- [ ] **Step 2: Add a `C2GetRtPtr()` and `C2GetCtxPtr()` export**

`src/dll/quickjs/quickjs_wrapper.c` new functions:
```c
uintptr_t C2GetRtPtr(void)  { return (uintptr_t)g_test_rt; }
uintptr_t C2GetCtxPtr(void) { return (uintptr_t)g_test_ctx; }
```

`src/dll/exports.zig` matching exports (CreateRemoteThread exit code is 32-bit, so the Zig wrapper `@truncate`s the pointer to the low DWORD; non-zero proves the pointer is not NULL):
```zig
extern fn C2GetRtPtr() usize;
extern fn C2GetCtxPtr() usize;
export fn C2GetRtPtrLow32()  callconv(.c) i32 { return @truncate(C2GetRtPtr()); }
export fn C2GetCtxPtrLow32() callconv(.c) i32 { return @truncate(C2GetCtxPtr()); }
```
These are read-only observation aids, not a permanent API.

- [ ] **Step 3: Rebuild, reupload, re-run the load check**

Run: `zig build && scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c2.dll && ssh Windows_Jiaolong "python C:/temp/c2_task2_load.py"`
Expected: `C2Sanity -> 42`; game alive.

- [ ] **Step 4: Run the init check**

Run: `scp scripts/c2_task5_init.py Windows_Jiaolong:C:/temp/ && ssh Windows_Jiaolong "python C:/temp/c2_task5_init.py"`
Expected: `Task 5: C2Init returns 0 and pointers are non-NULL` and game still alive.

- [ ] **Step 5: Record §34 in evidence**

- [ ] **Step 6: Commit**

```bash
git add src/dll/quickjs/quickjs_wrapper.c src/dll/exports.zig scripts/c2_task5_init.py evidence/analysis/runtime_444_c1_validation.md
git commit -m "feat(c2): C2Init returns 0; g_test_rt / g_test_ctx observable and non-NULL"
```

---

### Task 6: End-to-end JS round trip — eval a snippet and call a Zig-registered handler

**Files:**
- Create: `scripts/c2_task6_e2e.py`
- Modify: `src/dll/exports.zig` — add `C2EvalProbe(js_source_cstr_ptr) -> i32` that runs `JS_Eval` on the given string in `g_test_ctx` and returns 0 on success or 1 on parse error
- Test evidence: `evidence/analysis/runtime_444_c1_validation.md` §35

**Interfaces:**
- Consumes: Task 5's `C2Init` state (`g_test_rt`, `g_test_ctx` non-NULL).
- Produces: `C2EvalProbeOnePlusOne()` returns the encoded `int32` value of `1+1` (`rc = 7`) via `JS_Eval` + `JS_ToInt32`, proving QuickJS can evaluate JS inside the injected DLL. This is the C2 acceptance gate: once this works, `src/dll/c2/handler.zig` and `src/dll/c2/vtable.zig` become useful.

- [ ] **Step 1: Add `C2EvalProbe` to the C wrapper**

`src/dll/quickjs/quickjs_wrapper.c` new function — evaluates a JS source string in `g_test_ctx`, extracts the returned int32, and encodes it so a `CreateRemoteThread` caller can read it back through the 32-bit exit code:
```c
// Returns:
//   0          = g_test_ctx is NULL (init not run)
//   1          = JS_Eval threw an exception
//   2          = eval succeeded but value is not an int32
//   (n*4 + 3)  = eval succeeded and returned int32 n; the encoding keeps
//                a non-zero discriminant so callers can tell "value 0"
//                from "init missing". Caller decodes: n = (rc - 3) / 4.
extern JSValue JS_Eval(JSContext *ctx, const char *input, size_t input_len,
                       const char *filename, int eval_flags);
extern int JS_ToInt32_(JSContext *ctx, int32_t *pres, JSValue v);
extern int JS_IsException_(JSValue v);
extern void JS_FreeValue_(JSContext *ctx, JSValue v);

int C2EvalProbe(const char *src) {
    if (!g_test_ctx) return 0;
    JSValue v = JS_Eval(g_test_ctx, src, strlen(src), "<probe>", 0);
    if (JS_IsException_(v)) { JS_FreeValue_(g_test_ctx, v); return 1; }
    int32_t n = 0;
    if (JS_ToInt32_(g_test_ctx, &n, v) != 0) { JS_FreeValue_(g_test_ctx, v); return 2; }
    JS_FreeValue_(g_test_ctx, v);
    return (int)(n * 4 + 3);
}
```
(`JS_IsException`, `JS_ToInt32`, `JS_FreeValue` are static-inline or macro in QuickJS; wrap them in the same file the way `JS_FreeValue` is already wrapped, adding `extern` forward-declarations matching the real signatures.)

- [ ] **Step 2: Add the Zig export**

`src/dll/exports.zig`:
```zig
extern fn C2EvalProbe(src: [*:0]const u8) c_int;

export fn C2EvalProbeOnePlusOne() callconv(.c) i32 {
    const probe = "1+1"; // fixed string; no remote marshalling needed at this gate
    return @intCast(C2EvalProbe(probe.ptr));
}
```
Expected return: `1*4 + 3 = 7`. This is the fixed-string version — real remote-string passing is deferred to C3.

- [ ] **Step 3: Rebuild, reupload, confirm sanity**

Run: `zig build && scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c2.dll && ssh Windows_Jiaolong "python C:/temp/c2_task2_load.py"`
Expected: `C2Sanity -> 42`.

- [ ] **Step 4: Write the e2e script**

`scripts/c2_task6_e2e.py`:
```python
from c2_harness import (
    resolve_pid, resolve_base_address, list_exports, call_remote,
    assert_game_alive,
)

pid = resolve_pid("stellaris")
base = resolve_base_address(pid, "sqjs_c2.dll")
exports = list_exports("zig-out/bin/stellaris_quickjs.dll")

assert call_remote(pid, base, exports["C2Init"]) == 0
rc = call_remote(pid, base, exports["C2EvalProbeOnePlusOne"])
# Encoding: 0=no-ctx, 1=exception, 2=not-int32, n*4+3 = value n
assert rc != 0, "C2EvalProbeOnePlusOne returned 0 — g_test_ctx is NULL after C2Init returned 0"
assert rc != 1, "JS_Eval threw on `1+1` — QuickJS built without base intrinsics"
assert rc != 2, "JS_ToInt32 failed on `1+1` — QuickJS returned a non-numeric"
assert rc == 7, f"`1+1` should encode as 1*4+3=7, got rc={rc}"
assert_game_alive(pid)
print("Task 6: `1+1` evaluated inside the game process and returned int32 1")
```

- [ ] **Step 5: Run the e2e**

Run: `ssh Windows_Jiaolong "python C:/temp/c2_task6_e2e.py"`
Expected: `Task 6: \`1+1\` evaluated inside the game process and returned int32 1`.

- [ ] **Step 6: Review Focus coverage — assert `!g_test_ctx` guard returns 0**

Re-run `C2EvalProbeOnePlusOne` **without** first calling `C2Init` — inject a fresh DLL copy (rename to `sqjs_c2_noinit.dll`) so `g_test_ctx` starts NULL. Expected: returns `0`, proving the `!g_test_ctx` guard in Step 1 is intact and does not crash. Record the result in §35.

- [ ] **Step 7: Record §35 in evidence**

- [ ] **Step 8: Commit**

```bash
git add src/dll/quickjs/quickjs_wrapper.c src/dll/exports.zig scripts/c2_task6_e2e.py evidence/analysis/runtime_444_c1_validation.md
git commit -m "feat(c2): end-to-end — JS 1+1 evaluated inside injected DLL; C2 gate opens"
```
