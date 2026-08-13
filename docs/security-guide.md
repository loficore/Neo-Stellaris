# Security Guide

Security considerations for stellaris-quickjs-extension modding.

## Overview

The extension embeds a JavaScript runtime (QuickJS) inside the Stellaris process and hooks critical engine functions. This creates a trust boundary between mod code and the game engine.

## Threat Model

### What Mods Can Do

| Capability | Risk Level | Mitigation |
|------------|------------|------------|
| Execute arbitrary JavaScript | High | QuickJS sandbox (no file/network access) |
| Read game state (countries, planets, etc.) | Medium | Read-only access; no mutation without explicit API |
| Write game state (variables, modifiers) | High | Limited to specific API functions |
| Hook engine functions | Critical | Only CEffect::ExecuteActual and CTrigger::Evaluate |
| Create UI windows | Low | Limited to .gui file generation |
| Access process memory | Critical | Via scope handles (opaque pointers) |

### What Mods Cannot Do

- Access the file system (no `require()`, `fs`, or `import`)
- Make network requests (no `fetch`, `XMLHttpRequest`, or `WebSocket`)
- Spawn processes (no `child_process`)
- Access environment variables
- Modify the DLL itself
- Bypass the QuickJS sandbox

## Security Boundaries

### 1. QuickJS Sandbox

QuickJS is a minimal JavaScript engine with no built-in I/O. Mods run in a sandboxed environment:

- **No file system access** — `require()` is not available
- **No network access** — No HTTP/client modules
- **No process spawning** — No `child_process` or `exec`
- **Memory limited** — 256 MiB default heap limit
- **Stack limited** — 1 MiB default stack limit

**Risk:** A mod can still consume all available memory/CPU within the sandbox.

**Mitigation:** The memory and stack limits prevent runaway scripts from crashing the game.

### 2. API Boundary

The `Stellaris` global object exposes a limited set of functions:

| API Function | Access Level | Risk |
|--------------|--------------|------|
| `getCountry(id)` | Read-only | Low — returns opaque handle |
| `getPlanet(id)` | Read-only | Low |
| `getPop(id)` | Read-only | Low |
| `getSystem(id)` | Read-only | Low |
| `getGameDate()` | Read-only | Low |
| `getGameTick()` | Read-only | Low |
| `setVariable(name, value)` | Write | Medium — modifies game state |
| `addModifier(scope, name, value)` | Write | Medium — modifies game state |
| `removeModifier(scope, name)` | Write | Medium |
| `triggerEvent(eventId, scope)` | Write | Medium — can trigger arbitrary events |
| `getScopeType(scope)` | Read-only | Low |
| `getScopeObjectId(scope)` | Read-only | Low |
| `getScopeTypeName(scope)` | Read-only | Low |
| `hasScopeType(scope, flag)` | Read-only | Low |
| `registerEffect(name, func)` | Registration | Low |
| `registerTrigger(name, func)` | Registration | Low |
| `createWindow(...)` | UI | Low |
| `registerButtonEffect(...)` | UI | Low |
| `registerTextProvider(...)` | UI | Low |

**Risk:** `triggerEvent` can trigger any event by ID, potentially disrupting gameplay.

**Mitigation:** Events are still processed by the engine's normal event system with all its checks.

### 3. Scope Handle Safety

Scope handles are opaque pointers to engine memory. Mods receive them as integers:

```javascript
let scope = /* pointer as integer */;
let scopeType = Stellaris.getScopeType(scope);
```

**Risk:** A malicious mod could craft invalid scope pointers and read arbitrary memory.

**Mitigation:**
- Scope pointers are only valid within the current effect/trigger execution context
- The engine validates scope access internally
- Passing invalid pointers will cause a crash (fail-safe)

### 4. Effect/Trigger Registration

Mods register handlers by name:

```javascript
Stellaris.registerEffect("my_effect", function(...) { ... });
```

**Risk:** A mod could register handlers for built-in effects (ID ≤ 4081) to intercept them.

**Mitigation:**
- Only effects with ID > 4081 are routed to JS
- Vanilla effects pass through to the engine unchanged
- Registration is limited to 256 handlers per system

## Best Practices for Mod Authors

### 1. Validate Inputs

Always validate scope and object handles before using them:

```javascript
Stellaris.registerEffect("safe_effect", function(name, id, scope) {
    // Validate scope type before accessing object
    let scopeType = Stellaris.getScopeType(scope);
    if (scopeType !== 4) { // Not a country
        return 0;
    }

    let objectId = Stellaris.getScopeObjectId(scope);
    let country = Stellaris.getCountry(objectId);
    if (country === null) {
        return 0; // Object not found
    }

    // Safe to use country handle
    Stellaris.setVariable("safe_var", 1);
    return 0;
});
```

### 2. Handle Null Returns

All getter functions can return `null`. Always check:

```javascript
let country = Stellaris.getCountry(id);
if (country === null) {
    // Handle missing object
    return;
}
```

### 3. Avoid Trigger Side Effects

Triggers should be pure predicates (no side effects):

```javascript
// Bad: Trigger has side effects
Stellaris.registerTrigger("bad_trigger", function(name, id, scope) {
    Stellaris.setVariable("counter", 1); // Side effect!
    return true;
});

// Good: Trigger is pure
Stellaris.registerTrigger("good_trigger", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    return scopeType === 4; // Pure check
});
```

### 4. Limit Event Triggering

Avoid triggering events in tight loops:

```javascript
// Bad: Triggers event every tick
Stellaris.registerEffect("spam_event", function(name, id, scope) {
    Stellaris.triggerEvent("my_event.1", scope); // Don't do this!
    return 0;
});

// Good: Trigger events sparingly
Stellaris.registerEffect("smart_event", function(name, id, scope) {
    let tick = Stellaris.getGameTick();
    if (tick % 1000 === 0) { // Every 1000 ticks
        Stellaris.triggerEvent("my_event.1", scope);
    }
    return 0;
});
```

### 5. Don't Store Scope Handles

Scope handles are only valid during the current effect/trigger execution:

```javascript
// Bad: Storing scope handle for later use
let savedScope = null;
Stellaris.registerEffect("store_scope", function(name, id, scope) {
    savedScope = scope; // Will be invalid later!
    return 0;
});

// Good: Use scope only within the handler
Stellaris.registerEffect("use_scope", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    // Process and return — don't store scope
    return 0;
});
```

## Security for DLL Users

### 1. Trust Your Mods

Only install mods from trusted sources. The DLL executes whatever JavaScript mods provide.

### 2. Check Mod Sources

Review mod code before installation:

```bash
# Check for suspicious patterns
grep -r "eval(" mod_directory/
grep -r "while(true)" mod_directory/
grep -r "while(1)" mod_directory/
```

### 3. Monitor Performance

If the game becomes slow or unresponsive after installing a mod:

1. Check console logs for excessive output
2. Look for infinite loops in effect/trigger handlers
3. Monitor memory usage (256 MiB limit should prevent crashes)

### 4. Backup Save Games

Before testing new mods, back up your save games:

```bash
# Stellaris saves are typically in:
# Documents/Paradox Interactive/Stellaris/save games/
```

## Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No file I/O | Cannot read/write mod data files | Use `setVariable` for state persistence |
| No network | Cannot fetch external data | Hardcode data in JS |
| Single-threaded | JS blocks game thread | Keep handlers fast |
| No async | Cannot do background work | Use tick-based scheduling |
| No DOM | Cannot manipulate HTML | Use .gui file generation |

## Reporting Security Issues

If you discover a security vulnerability in the extension:

1. Do not disclose publicly
2. Document the vulnerability with reproduction steps
3. Contact the project maintainers
4. Allow time for a fix before disclosure

## Security Checklist for Mod Authors

- [ ] Validate scope types before accessing objects
- [ ] Check for null returns from getter functions
- [ ] Keep effect/trigger handlers fast (< 1ms execution)
- [ ] Avoid storing scope handles across calls
- [ ] Don't trigger events in tight loops
- [ ] Test with large save games (many objects)
- [ ] Avoid infinite loops (use tick-based checks)
- [ ] Minimize string operations in hot paths
