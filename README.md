# stellaris-quickjs-extension

A Zig-based DLL extension for Stellaris that embeds a QuickJS JavaScript runtime, enabling modders to write custom effects, triggers, and UI logic in JavaScript while hooking into the Clausewitz engine's CEffect/CTrigger dispatch pipeline.

## Features

- **Custom Effects** — Register JavaScript handlers for scripted effects (ID > 4081)
- **Custom Triggers** — Register JavaScript handlers for scripted triggers
- **Game State Access** — Read countries, planets, pops, systems, and game date/tick
- **Scope Inspection** — Query CEventScope type and object ID from JS
- **UI System** — Create .gui windows with buttons, text, and dynamic text providers
- **Button Effects** — Bridge .gui button clicks to JavaScript callbacks
- **Dynamic Text** — Resolve `$SCRIPTED_LOC$` references via JS functions
- **Detour Hooking** — x86_64 trampoline-based function hooking framework
- **Effect ID Mapping** — Bidirectional ID↔name lookup for all effects

## Architecture

```
stellaris-quickjs.dll
├── exports.zig          — DLL entry points (PushCApplicationPtr, DllMain)
├── quickjs/
│   ├── runtime.zig      — QuickJS lifecycle, eval, function registration
│   └── bindings.zig     — C API bindings for QuickJS
├── api/
│   ├── bridge.zig       — JS→Zig bridge (Stellaris.* functions)
│   ├── gamestate.zig    — Game object access (stubs → real offsets)
│   └── scope.zig        — CEventScope read access
├── effects/
│   ├── ceffect.zig      — CEffect::ExecuteActual hook
│   ├── handler.zig      — JS callback routing for effects
│   └── id_mapper.zig    — Effect ID↔name mapping
├── triggers/
│   ├── ctrigger.zig     — CTrigger::Evaluate hook
│   └── handler.zig      — JS callback routing for triggers
├── hooking/
│   ├── detour.zig       — Trampoline detour framework
│   └── windows.zig      — Win32 API wrappers (VirtualProtect, alloc)
├── ui/
│   ├── window.zig       — Window manager, .gui element types
│   ├── gui.zig          — .gui file generation from code
│   ├── button.zig       — Button effect registry and click processing
│   ├── callbacks.zig    — JS callback registry for button effects
│   └── dynamic_text.zig — Scripted localisation / dynamic text system
├── shared/
│   └── offsets.zig      — Verified engine object offsets (from IDA)
└── main.zig             — DLL root (pulls in exports)
```

## Quick Start

### Prerequisites

- **Zig** ≥ 0.16.0
- **Stellaris** installed (Windows, x86_64)
- **Git**

### Build

```bash
# Clone the repository
git clone <repo-url>
cd stellaris-quickjs

# Build the DLL (targets x86_64-windows by default)
zig build

# The output DLL is at:
# zig-out/bin/stellaris_quickjs.dll
```

### Run Tests

```bash
# Run all unit tests
zig build test
```

### Install

1. Copy `zig-out/bin/stellaris_quickjs.dll` to your Stellaris game directory
2. Use a DLL injector (or the companion C++ loader) to inject into the Stellaris process
3. The DLL exports `PushCApplicationPtr` — the loader calls this after injection to pass the engine pointer

### Write Your First Mod

Create a JavaScript file that uses the `Stellaris` API:

```javascript
// Register a custom effect
Stellaris.registerEffect("my_custom_effect", function(name, scope) {
    console.log("Effect triggered: " + name);
    // Access game state
    var tick = Stellaris.getGameTick();
    console.log("Current tick: " + tick);
});

// Register a custom trigger
Stellaris.registerTrigger("has_my_flag", function(name, scope) {
    var scopeType = Stellaris.getScopeType(scope);
    // Return true if condition is met
    return scopeType === 4; // COUNTRY scope
});

// Create a UI window
Stellaris.createWindow("my_panel", 500, 400);
Stellaris.setWindowTitle("my_panel", "My Custom Panel");
Stellaris.showWindow("my_panel");
```

## JavaScript API

All functions are available on the global `Stellaris` object:

### Game State Reads

| Function | Returns | Description |
|----------|---------|-------------|
| `getCountry(id)` | `object \| null` | Get country by numeric ID |
| `getPlanet(id)` | `object \| null` | Get planet by numeric ID |
| `getPop(id)` | `object \| null` | Get pop by numeric ID |
| `getSystem(id)` | `object \| null` | Get star system by numeric ID |
| `getGameDate()` | `string` | Current in-game date |
| `getGameTick()` | `number` | Current game tick count |

### Game State Writes

| Function | Returns | Description |
|----------|---------|-------------|
| `setVariable(name, value)` | `boolean` | Set a variable on the current scope |
| `addModifier(scope, name, value)` | `boolean` | Add a modifier to a game object |
| `removeModifier(scope, name)` | `boolean` | Remove a modifier from a game object |
| `triggerEvent(eventId, scope)` | `boolean` | Trigger a game event |

### Scope Access

| Function | Returns | Description |
|----------|---------|-------------|
| `getScopeType(scope)` | `number` | Scope type as bit flag |
| `getScopeObjectId(scope)` | `number` | Object ID within the scope |
| `getScopeTypeName(scope)` | `string` | Human-readable scope type |
| `hasScopeType(scope, flag)` | `boolean` | Check if scope has a specific type |

### Effect & Trigger Registration

| Function | Returns | Description |
|----------|---------|-------------|
| `registerEffect(name, func)` | `void` | Register a JS handler for a custom effect |
| `registerTrigger(name, func)` | `void` | Register a JS handler for a custom trigger |
| `registerButtonEffect(name, func)` | `void` | Register a button click handler |

### UI System

| Function | Returns | Description |
|----------|---------|-------------|
| `createWindow(name, width, height)` | `void` | Create a new .gui window |
| `setWindowTitle(name, title)` | `void` | Set window title text |
| `showWindow(name)` | `void` | Show a window |
| `hideWindow(name)` | `void` | Hide a window |
| `destroyWindow(name)` | `void` | Destroy a window |

### Dynamic Text

| Function | Returns | Description |
|----------|---------|-------------|
| `registerTextProvider(name, func)` | `void` | Register a JS function for `$NAME$` text resolution |

## Scope Types

Scopes use power-of-2 bit flags (multiple can be set simultaneously):

| Constant | Value | Description |
|----------|-------|-------------|
| `PLANET` | 2 | Planet scope |
| `COUNTRY` | 4 | Country/empire scope |
| `SHIP` | 8 | Ship scope |
| `POP` | 16 | Population scope |
| `FLEET` | 32 | Fleet scope |
| `GALACTIC_OBJECT` | 64 | Star system scope |
| `LEADER` | 128 | Leader scope |
| `ARMY` | 256 | Army scope |
| `AMBIENT_OBJECT` | 512 | Ambient object scope |
| `SPECIES` | 1024 | Species scope |
| `NO_SCOPE` | 1048576 | No scope / global |

## Build Configuration

The build system (`build.zig`) produces a shared library targeting x86_64-windows:

```zig
// Default target
.target = .{ .os_tag = .windows, .cpu_arch = .x86_64 }
```

### Test Targets

Run individual test suites:

```bash
# Exports (DLL entry points)
zig build test -- --test-filter "exports"

# QuickJS runtime
zig build test -- --test-filter "runtime"

# Effect ID mapper
zig build test -- --test-filter "id_mapper"

# Hooking framework
zig build test -- --test-filter "detour"

# API modules (gamestate, scope)
zig build test -- --test-filter "gamestate"
zig build test -- --test-filter "scope"

# UI modules (window, gui, button, callbacks, dynamic_text)
zig build test -- --test-filter "window"
zig build test -- --test-filter "gui"
zig build test -- --test-filter "button"
zig build test -- --test-filter "callbacks"
zig build test -- --test-filter "dynamic_text"
```

## Engine Integration

### Hook Points

The extension hooks two critical engine functions:

| Function | Address | Purpose |
|----------|---------|---------|
| `CEffect::ExecuteActual` | `0x14181B740` | Intercepts effect execution; routes custom effects to JS |
| `CTrigger::Evaluate` | `0x1408A6F20` | Intercepts trigger evaluation; routes custom triggers to JS |

### Key Offsets (from IDA Reverse Engineering)

| Object | Offset | Field | Type |
|--------|--------|-------|------|
| CEffect | +0x038 (56) | Effect name | SSO string |
| CEffect | +0xFF0 (4080) | Effect ID | i32 |
| CEffect | +0x6A8 (1704) | Vtable pointer | ptr |
| CEventScope | +8 | Scope type | i64 (bit flag) |
| CEventScope | +16 | Object ID | i64 |

### Scripted Effect Threshold

Effects with ID > 4081 are treated as custom/scripted and routed to JavaScript handlers. Vanilla effects (ID ≤ 4081) pass through to the original engine function.

## Project Status

**Version**: 0.1.0  
**Status**: Active development

- [x] DLL injection and entry points
- [x] QuickJS runtime integration
- [x] Effect/Trigger hooking framework
- [x] Game state API (stubs)
- [x] Scope access API
- [x] UI window system
- [x] Button effect system
- [x] Dynamic text system
- [x] x86_64 detour hooking
- [x] Effect ID mapper
- [ ] Full game state implementation (wiring real engine offsets)
- [ ] Clausewitz text format parser
- [ ] Save/load integration
- [ ] Hot-reload support

## License

This project is for educational and modding purposes. Stellaris and the Clausewitz engine are trademarks of Paradox Interactive.
