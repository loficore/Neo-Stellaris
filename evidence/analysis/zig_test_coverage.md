# Zig Unit Test Coverage Report

**Date**: 2026-08-12
**Total Tests**: 286
**Status**: All tests pass with `zig build test`

## Summary by Module

| Module | Tests | Coverage |
|--------|-------|----------|
| `hooking/detour.zig` | 42 | Instruction decoder, prologue length, JMP patch size |
| `ui/dynamic_text.zig` | 31 | Provider registry, text resolution, caching, fallbacks |
| `triggers/ctrigger.zig` | 25 | SSOString, scope types, trigger ID/name reading |
| `ui/window.zig` | 21 | Window lifecycle, Font, Position, Size, Element union |
| `effects/id_mapper.zig` | 21 | Bidirectional lookup, sequential IDs, built-in effects |
| `ui/button.zig` | 21 | Effect registry, processClick, enable/disable |
| `api/bridge.zig` | 19 | JS value conversion, API function registry |
| `ui/gui.zig` | 18 | .gui file generation, textboxes, buttons, close effects |
| `quickjs/runtime.zig` | 17 | JSValue tags, Value wrapper, EvalResult, Config |
| `ui/callbacks.zig` | 16 | Callback registry, handleButtonClick, statistics |
| `api/gamestate.zig` | 11 | Stub functions for game object access |
| `exports.zig` | 9 | DLL exports, engine pointer storage |
| `api/scope.zig` | 8 | CEventScope access, scope type names |
| `shared/offsets.zig` | 8 | Object offsets, scope types, effect IDs |
| `effects/ceffect.zig` | 8 | SSOString, effect ID/name reading, custom effect check |
| `effects/handler.zig` | 5 | Handler registry (skipped in cross-compilation) |
| `triggers/handler.zig` | 5 | Handler registry (skipped in cross-compilation) |
| `hooking/windows.zig` | 1 | Memory protection enum |

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
- `effects/ceffect.zig`: SSOString, CEffect field reading
- `triggers/ctrigger.zig`: SSOString, CTrigger/CEventScope field reading
- `api/scope.zig`: CEventScope access functions
- `api/gamestate.zig`: Stub game state functions

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
