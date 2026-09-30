# Zig Unit Test Coverage Report

**Date**: 2026-08-12
**Total Tests**: 286
**Status**: All tests pass with `zig build test`

## Summary by Module

| Module | Tests | Coverage |
|--------|-------|----------|
| `hooking/detour.zig` | 42 | Instruction decoder, prologue length, JMP patch size |
| `ui/dynamic_text.zig` | 31 | Provider registry, text resolution, caching, fallbacks |
| `triggers/ctrigger.zig` | 25 | **never ran** — nothing imported it, no build.zig test step; file deleted (see §26.3) |
| `ui/window.zig` | 21 | Window lifecycle, Font, Position, Size, Element union |
| `effects/id_mapper.zig` | 21 | **file retired 2026-09-30 (§29)** — zero importers, and its built-in id table was illustrative, not an engine table |
| `ui/button.zig` | 21 | Effect registry, processClick, enable/disable |
| `api/bridge.zig` | 19 | JS value conversion, API function registry |
| `ui/gui.zig` | 18 | .gui file generation, textboxes, buttons, close effects |
| `quickjs/runtime.zig` | 17 | JSValue tags, Value wrapper, EvalResult, Config |
| `ui/callbacks.zig` | 16 | Callback registry, handleButtonClick, statistics |
| `api/gamestate.zig` | 11 | Stub functions for game object access |
| `exports.zig` | 9 | DLL exports, engine pointer storage |
| `api/scope.zig` | 8 | CEventScope access, scope type names |
| `shared/offsets.zig` | 8 | Object offsets, scope types, effect IDs |
| `effects/ceffect.zig` | 8 | **never ran** — nothing imported it, no build.zig test step; file deleted (see §26.3) |
| `effects/handler.zig` | 5 | Handler registry (skipped in cross-compilation) |
| `triggers/handler.zig` | 5 | Handler registry (skipped in cross-compilation) |
| `hooking/windows.zig` | 1 | Memory protection enum |
| `scripted/lookup_hook.zig` | 10 | Was 4; rewritten against §27 — see the addendum below |
| `scripted/keyword_registry.zig` | 18 | §20/§21 byte layer + gated executor, golden-vector sha256 |

## Test Categories

### Pure Logic Tests (no external dependencies)
- `effects/id_mapper.zig`: Hash map operations, bidirectional lookup
- `shared/offsets.zig`: Constant value verification
- `ui/window.zig`: Window manager state machine
- `ui/button.zig`: Button effect registry
- `ui/callbacks.zig`: Callback registry
- `ui/dynamic_text.zig`: Text provider registry, cache operations
- `quickjs/runtime.zig`: JSValue tag operations, Value wrapper

### Memory Layout Tests (mock objects)
- `api/scope.zig`: CEventScope access functions — runs transitively via the `exports.zig` test root,
  but note §26: the `+8`/`+16` fields it asserts against are a 3.x layout that 4.4.4 contradicts, so
  these tests pin the *code's* assumption, not the engine's memory
- `api/gamestate.zig`: Stub game state functions
- (`effects/ceffect.zig` and `triggers/ctrigger.zig` used to be listed here. Their field reads were
  mock-object tests over offsets §26.3 shows are out of bounds, and because nothing imported them their
  tests were never in the build graph — proof by the `SCRIPTED_EFFECT_BASE == 4081` assertion that
  would have failed against the `10000` in `offsets.zig`. Deleted 2026-09-30.)

### Code Generation Tests
- `ui/gui.zig`: .gui file content generation
- `api/bridge.zig`: JS value conversion functions

### x86_64 Instruction Decoder Tests
- `hooking/detour.zig`: 40+ instruction patterns

## Cross-Compilation Notes

The project targets x86_64-windows for DLL injection. Some modules cannot be tested in cross-compilation:

- `effects/handler.zig`: Uses `std.Thread.Mutex` (unavailable for Windows target in Zig 0.16)
- `triggers/handler.zig`: Same issue
- `hooking/windows.zig`: Win32 API calls (VirtualProtect, VirtualAlloc) not available on Linux

These modules have tests that would pass on native Windows builds or when the target matches the host.

## Build Command

```bash
zig build test           # Run all tests
zig build test 2>&1      # Run with error output
```

## Files Modified

- `build.zig`: Added test steps for UI modules (window, callbacks, dynamic_text, gui, button)
- `src/dll/ui/dynamic_text.zig`: Fixed compilation error (`_ = err;` → `catch {}`)
- All test files: Added comprehensive test coverage

## Addendum — 2026-09-30 (§26/§27 work, current baseline)

This report's header (2026-08-12, **286 tests**) is a stale snapshot; the table above has been patched in
place where files were deleted or rewritten, and the live count is:

```
zig build test  ->  22/25 steps, 272/272 tests passed
```
*(Superseded mid-session: the §27 work reached **24/27 steps, 293/293**; the count dropped to 272 when
`effects/id_mapper.zig` was retired with its 21 tests later the same day — see §29.)*

The two failing steps are the QuickJS-linked test binaries that cannot start on this host
(`/lib64/libm.so.6: GLIBC_2.35 not found`) — pre-existing, unrelated to any of these changes.

What moved since the snapshot:

| File | Tests | Why |
|---|---|---|
| `scripted/lookup_hook.zig` | 4 → 11 | §27: `NameHolder`/`NameString` (1-byte `std::string` at `r8+0x10`), `ScriptedRef` with `name` at `+0x10` and `ceffect_vtable` at `+0x40`, `Shape.classify` against the install-time image base, `ENTRY_SIZE = 192` (the drain's fixed slot width is injector ABI), and three ring tests — consume-once, cursor-does-not-rewind-`seq`, in-flight-slot-resume. |
| `shared/offsets.zig` | +1 | `scripted_lookup` constants: the four vtables are distinct and non-code, `RVA_LOG` is code, `UNMINTED_SEARCH_KEY = 12`, `HOLDER_STRING_OFFSET = 0x10`, `REF_SIZE = 0x118`. |
| `scripted/keyword_registry.zig` | 18 | C0 executor + golden vectors + §25.5 `NameCheck` (was not in this report at all). |
| `effects/ceffect.zig`, `triggers/ctrigger.zig` | deleted | Their tests never entered the build graph; see §26.3. |

Note on what these numbers mean: a count like `293/293` is a statement about the **build graph** (every
test that compiles and runs), not about the engine. The layout tests in `api/scope.zig` and the old
`ScriptedRef` assertions are the clearest example — they used to pin assumptions that §26/§27 then
falsified offline. A green suite with a wrong model is precisely the failure mode §26.3 called out.
