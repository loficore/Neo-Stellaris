# API Reference

Complete reference for the stellaris-quickjs JavaScript API. All functions are available on the global `Stellaris` object after the DLL is injected and the QuickJS runtime is initialized.

## Table of Contents

- [Game State Reads](#game-state-reads)
- [Game State Writes](#game-state-writes)
- [Scope Access](#scope-access)
- [Effect Registration](#effect-registration)
- [Trigger Registration](#trigger-registration)
- [UI System](#ui-system)
- [Button Effects](#button-effects)
- [Dynamic Text](#dynamic-text)

---

## Game State Reads

### `Stellaris.getCountry(id)`

Get a country object by its numeric ID.

```javascript
let country = Stellaris.getCountry(1);
if (country !== null) {
    // country is an opaque handle (integer pointer)
    console.log("Country handle: " + country);
}
```

**Parameters:**
- `id` (number) — Country ID (matches in-game country ID from save files)

**Returns:** `object | null` — Opaque handle to the country object, or `null` if not found.

**Engine offset:** Looks up via `CountryDB` at `0x143287788`.

---

### `Stellaris.getPlanet(id)`

Get a planet object by its numeric ID.

```javascript
let planet = Stellaris.getPlanet(42);
```

**Parameters:**
- `id` (number) — Planet ID

**Returns:** `object | null`

---

### `Stellaris.getPop(id)`

Get a pop object by its numeric ID.

```javascript
let pop = Stellaris.getPop(100);
```

**Parameters:**
- `id` (number) — Pop ID

**Returns:** `object | null`

---

### `Stellaris.getSystem(id)`

Get a star system (galactic object) by its numeric ID.

```javascript
let system = Stellaris.getSystem(255);
```

**Parameters:**
- `id` (number) — System/galactic object ID

**Returns:** `object | null`

---

### `Stellaris.getGameDate()`

Get the current in-game date as a string.

```javascript
let date = Stellaris.getGameDate();
console.log("Current date: " + date); // e.g., "2200.1.1"
```

**Returns:** `string | null` — Date string, or `null` if unavailable.

---

### `Stellaris.getGameTick()`

Get the current game tick count.

```javascript
let tick = Stellaris.getGameTick();
console.log("Tick: " + tick);
```

**Returns:** `number` — Current tick count, or `0` if unavailable.

---

## Game State Writes

### `Stellaris.setVariable(name, value)`

Set a variable on the current scope's variable storage.

```javascript
let success = Stellaris.setVariable("my_mod_var", 42);
console.log("Variable set: " + success);
```

**Parameters:**
- `name` (string) — Variable name
- `value` (number) — New value (integer)

**Returns:** `boolean` — `true` if successful.

---

### `Stellaris.addModifier(scope, name, value)`

Add a modifier to a game object (e.g., pop happiness modifier, country buff).

```javascript
let scope = Stellaris.getCountry(1);
let success = Stellaris.addModifier(scope, "happiness", 10);
```

**Parameters:**
- `scope` (pointer) — Target game object handle
- `name` (string) — Modifier name
- `value` (number) — Modifier value

**Returns:** `boolean` — `true` if the modifier was applied.

---

### `Stellaris.removeModifier(scope, name)`

Remove a modifier from a game object.

```javascript
let scope = Stellaris.getCountry(1);
let success = Stellaris.removeModifier(scope, "happiness");
```

**Parameters:**
- `scope` (pointer) — Target game object handle
- `name` (string) — Modifier name to remove

**Returns:** `boolean` — `true` if removed.

---

### `Stellaris.triggerEvent(eventId, scope)`

Trigger a game event by its string ID.

```javascript
let scope = Stellaris.getCountry(1);
let success = Stellaris.triggerEvent("my_event.1", scope);
```

**Parameters:**
- `eventId` (string) — Event ID (e.g., `"my_event.1"`)
- `scope` (pointer) — Scope to trigger the event in

**Returns:** `boolean` — `true` if the event was triggered.

---

## Scope Access

Scopes define the execution context for effects and triggers. The `CEventScope` object tells the engine what game object the current operation targets.

### `Stellaris.getScopeType(scope)`

Get the scope type as a numeric bit flag.

```javascript
let scopeType = Stellaris.getScopeType(scope);
// PLANET=2, COUNTRY=4, SHIP=8, POP=16, FLEET=32, etc.
if (scopeType === 4) {
    console.log("Scope is a country");
}
```

**Parameters:**
- `scope` (pointer) — CEventScope handle

**Returns:** `number` — Scope type bit flag.

**Bit flag values:**

| Value | Name |
|-------|------|
| 2 | PLANET |
| 4 | COUNTRY |
| 8 | SHIP |
| 16 | POP |
| 32 | FLEET |
| 64 | GALACTIC_OBJECT |
| 128 | LEADER |
| 256 | ARMY |
| 512 | AMBIENT_OBJECT |
| 1024 | SPECIES |
| 1048576 | NO_SCOPE |

Multiple flags can be set simultaneously (e.g., a fleet member is both `SHIP | FLEET = 40`).

---

### `Stellaris.getScopeObjectId(scope)`

Get the numeric object ID within the scope.

```javascript
let objectId = Stellaris.getScopeObjectId(scope);
console.log("Object ID: " + objectId);
```

**Parameters:**
- `scope` (pointer) — CEventScope handle

**Returns:** `number` — The object ID (valid when scope type matches a known type).

---

### `Stellaris.getScopeTypeName(scope)`

Get a human-readable name for the scope type.

```javascript
let typeName = Stellaris.getScopeTypeName(scope);
console.log("Scope type: " + typeName); // e.g., "country", "planet"
```

**Parameters:**
- `scope` (pointer) — CEventScope handle

**Returns:** `string` — One of: `"planet"`, `"country"`, `"ship"`, `"pop"`, `"fleet"`, `"galactic_object"`, `"leader"`, `"army"`, `"ambient_object"`, `"species"`, `"no_scope"`, `"unknown"`.

---

### `Stellaris.hasScopeType(scope, flag)`

Check if the scope has a specific type flag set.

```javascript
if (Stellaris.hasScopeType(scope, 4)) { // COUNTRY
    console.log("Scope is a country");
}
```

**Parameters:**
- `scope` (pointer) — CEventScope handle
- `flag` (number) — Type flag to check

**Returns:** `boolean` — `true` if the flag is set.

---

## Effect Registration

### `Stellaris.registerEffect(name, jsFunc)`

Register a JavaScript handler for a custom scripted effect. When the engine encounters an effect with this name in game scripts, it will call your JS function.

```javascript
Stellaris.registerEffect("my_custom_effect", function(effectName, effectId, scope) {
    console.log("Effect triggered: " + effectName);
    console.log("Effect ID: " + effectId);

    // Read scope info
    let scopeType = Stellaris.getScopeType(scope);
    let objectId = Stellaris.getScopeObjectId(scope);

    console.log("Scope type: " + scopeType + ", Object: " + objectId);

    // Return value (typically 0 for effects)
    return 0;
});
```

**Parameters:**
- `name` (string) — Effect name (must match the name in your game scripts)
- `jsFunc` (function) — Callback function with signature: `(effectName, effectId, scope) → number`

**Notes:**
- Effects with ID > 4081 are routed to JS handlers
- Vanilla effects (ID ≤ 4081) pass through to the engine
- Maximum 256 registered effect handlers
- Re-registering an existing effect updates the handler

---

## Trigger Registration

### `Stellaris.registerTrigger(name, jsFunc)`

Register a JavaScript handler for a custom scripted trigger. When the engine evaluates this trigger, it will call your JS function and use the boolean return value.

```javascript
Stellaris.registerTrigger("has_my_flag", function(triggerName, triggerId, scope) {
    console.log("Trigger evaluated: " + triggerName);

    // Check conditions
    let scopeType = Stellaris.getScopeType(scope);
    let objectId = Stellaris.getScopeObjectId(scope);

    // Return true if the trigger passes, false otherwise
    return scopeType === 4; // Only pass in country scope
});
```

**Parameters:**
- `name` (string) — Trigger name (must match the name in your game scripts)
- `jsFunc` (function) — Callback function with signature: `(triggerName, triggerId, scope) → boolean`

**Return value semantics:**
- `true` — Trigger passes (condition is met)
- `false` — Trigger fails (condition not met)
- `null`, `undefined`, `0` — Treated as `false`
- Objects, non-empty strings — Treated as `true`

**Notes:**
- Maximum 256 registered trigger handlers
- Re-registering an existing trigger updates the handler

---

## UI System

### Window Management

#### `Stellaris.createWindow(name, width, height)`

Create a new .gui window.

```javascript
Stellaris.createWindow("my_panel", 500, 400);
```

**Parameters:**
- `name` (string) — Unique window identifier
- `width` (number) — Window width in pixels (default: 400)
- `height` (number) — Window height in pixels (default: 300)

---

#### `Stellaris.setWindowTitle(name, title)`

Set the title text of a window.

```javascript
Stellaris.setWindowTitle("my_panel", "My Custom Panel");
```

---

#### `Stellaris.showWindow(name)`

Show a window (makes it visible).

```javascript
Stellaris.showWindow("my_panel");
```

---

#### `Stellaris.hideWindow(name)`

Hide a window (makes it invisible but keeps it alive).

```javascript
Stellaris.hideWindow("my_panel");
```

---

#### `Stellaris.destroyWindow(name)`

Permanently destroy a window.

```javascript
Stellaris.destroyWindow("my_panel");
```

---

### .gui File Reference

The UI system generates `.gui` files that the Clausewitz engine loads from `interface/`. The format uses these element types:

#### containerWindowType

Top-level window container:

```
containerWindowType = {
    name = "my_window"
    size = { width = 500 height = 400 }
    position = { x = 100 y = 100 }
    draggable = yes
    movable = yes
}
```

#### instantTextBoxType

Text display element:

```
instantTextBoxType = {
    name = "title"
    text = "Hello World"
    font = "cg_20"
    position = { x = 10 y = 10 }
    maxWidth = 300
    format = left
}
```

**Fonts:** `cg_16`, `cg_20`, `cg_24`

**Alignment:** `left`, `center`, `right`

#### effectButtonType

Clickable button with an effect:

```
effectButtonType = {
    name = "my_button"
    effect = "my_button_effect"
    position = { x = 100 y = 100 }
    size = { width = 100 height = 30 }
    tooltip = "Click me"
    shortcut = "F5"
}
```

---

## Button Effects

### `Stellaris.registerButtonEffect(name, jsFunc)`

Register a callback for when a button with the given effect name is clicked.

```javascript
Stellaris.registerButtonEffect("close_my_window", function(btnName, scope) {
    console.log("Button clicked: " + btnName);
    Stellaris.hideWindow("my_panel");
});
```

**Parameters:**
- `name` (string) — Effect name (matches `effectButtonType.effect` in .gui files)
- `jsFunc` (function) — Callback with signature: `(buttonName, scope) → void`

---

### Button Effect System Architecture

```
GUI Button Click
    ↓
Engine extracts effect name from effectButtonType
    ↓
Button effect registry lookup
    ↓
JS callback invoked via QuickJS
    ↓
Callback executes game logic
```

The button effect system supports:
- **Enable/disable** — Temporarily disable effects without unregistering
- **Statistics** — Track total clicks, successful/failed callbacks
- **Duplicate handling** — Re-registering updates the existing handler

---

## Dynamic Text

### `Stellaris.registerTextProvider(name, jsFunc)`

Register a JavaScript function that provides text for `$NAME$` references in .gui elements.

```javascript
Stellaris.registerTextProvider("get_resource_count", function(scope) {
    // Return dynamic text based on game state
    return "Resources: 42";
});
```

**Parameters:**
- `name` (string) — Provider name (used as `$NAME$` in .gui text)
- `jsFunc` (function) — Callback with signature: `(scope) → string`

---

### .gui Integration

Use `$NAME$` syntax in .gui text fields:

```
instantTextBoxType = {
    name = "status_text"
    text = "Status: $STATUS_TEXT$"
    font = "cg_20"
    position = { x = 10 y = 10 }
}
```

The dynamic text system resolves `$STATUS_TEXT$` by looking up the registered provider and calling its JS function.

---

### Text Provider Types

| Type | Description |
|------|-------------|
| `static_loc` | Maps to a localisation key in the engine |
| `js_function` | Calls a JavaScript function |
| `zig_function` | Calls a native Zig function pointer |

### Text Resolution Priority

1. Check text cache (element name → last resolved text)
2. Look up provider by name
3. Check if provider is enabled
4. Resolve based on provider type
5. On failure, try fallback provider if configured

---

## Error Handling

All API functions that can fail return sensible defaults:

| Function | Error Behavior |
|----------|---------------|
| `getCountry(id)` | Returns `null` if not found |
| `setVariable(...)` | Returns `false` on failure |
| `addModifier(...)` | Returns `false` on failure |
| `triggerEvent(...)` | Returns `false` on failure |
| `getScopeType(scope)` | Returns `0` on error |
| `getScopeObjectId(scope)` | Returns `0` on error |
| `getScopeTypeName(scope)` | Returns `"unknown"` on error |

JS exceptions in effect/trigger handlers are caught and logged. The engine receives a safe default return value (0 for effects, false for triggers).

---

## Thread Safety

- **Effect/Trigger registries** are protected by mutexes
- **Game state reads** are stateless (no shared state)
- **UI operations** should be called from the main game thread
- **QuickJS runtime** is single-threaded — all JS execution is serialized

---

## Memory Model

- JS values returned to Zig are either consumed (via `EvalResult.deinit`) or intentionally leaked
- Scope handles are opaque pointers to engine memory — do not store them long-term
- Object handles returned by `getCountry`/`getPlanet`/etc. are valid for the current frame only
