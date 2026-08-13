# Performance Guide

Best practices for writing performant JavaScript mods with stellaris-quickjs.

## Overview

The QuickJS runtime is lightweight but runs synchronously within the game's main loop. Poorly written JS can cause frame drops or freezes. Follow these guidelines to keep your mods performant.

## QuickJS Runtime Limits

| Setting | Default | Description |
|---------|---------|-------------|
| Max stack size | 1 MiB | JavaScript call stack limit |
| Memory limit | 256 MiB | Total JS heap allocation limit |

These can be configured via `Config` when initializing the runtime:

```zig
const config = Config{
    .max_stack_size = 2 * 1024 * 1024,  // 2 MiB
    .mem_limit = 512 * 1024 * 1024,     // 512 MiB
};
```

## Performance Guidelines

### 1. Cache Repeated Lookups

**Bad:** Looking up the same object multiple times per effect call.

```javascript
Stellaris.registerEffect("bad_effect", function(name, id, scope) {
    // This calls getScopeType TWICE — wasteful
    if (Stellaris.getScopeType(scope) === 4) {
        let objId = Stellaris.getScopeObjectId(scope);
        let country = Stellaris.getCountry(objId);
        // Use country...
    }
    // Called again — redundant!
    if (Stellaris.getScopeType(scope) === 4) {
        // ...
    }
});
```

**Good:** Cache values in local variables.

```javascript
Stellaris.registerEffect("good_effect", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    let objectId = Stellaris.getScopeObjectId(scope);

    if (scopeType === 4) { // COUNTRY
        let country = Stellaris.getCountry(objectId);
        if (country !== null) {
            // Use country — single lookup
        }
    }
});
```

### 2. Avoid Deep Call Chains

**Bad:** Nested function calls that create deep stacks.

```javascript
function getCountryInfo(countryId) {
    let country = Stellaris.getCountry(countryId);
    if (country === null) return null;
    return {
        handle: country,
        type: Stellaris.getScopeType(country),
    };
}

function processCountry(countryId) {
    let info = getCountryInfo(countryId);
    if (info === null) return;
    // More nesting...
}
```

**Good:** Flatten logic where possible.

```javascript
Stellaris.registerEffect("flat_effect", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    let objectId = Stellaris.getScopeObjectId(scope);

    if (scopeType !== 4) return 0; // Not a country

    let country = Stellaris.getCountry(objectId);
    if (country === null) return 0;

    // Direct logic, no nested calls
    Stellaris.setVariable("processed", 1);
    return 0;
});
```

### 3. Minimize String Operations

**Bad:** Creating many temporary strings.

```javascript
Stellaris.registerEffect("string_heavy", function(name, id, scope) {
    for (let i = 0; i < 100; i++) {
        let key = "var_" + i;  // Creates 100 temporary strings
        Stellaris.setVariable(key, i);
    }
});
```

**Good:** Reuse strings and minimize concatenation.

```javascript
Stellaris.registerEffect("string_light", function(name, id, scope) {
    // Use a single variable name
    Stellaris.setVariable("counter", 42);
});
```

### 4. Early Returns

**Bad:** Deeply nested conditionals.

```javascript
Stellaris.registerEffect("nested", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    if (scopeType === 4) {
        let objectId = Stellaris.getScopeObjectId(scope);
        let country = Stellaris.getCountry(objectId);
        if (country !== null) {
            let tick = Stellaris.getGameTick();
            if (tick > 100) {
                // Finally do work
            }
        }
    }
});
```

**Good:** Guard clauses with early returns.

```javascript
Stellaris.registerEffect("early_return", function(name, id, scope) {
    let scopeType = Stellaris.getScopeType(scope);
    if (scopeType !== 4) return 0;

    let objectId = Stellaris.getScopeObjectId(scope);
    let country = Stellaris.getCountry(objectId);
    if (country === null) return 0;

    let tick = Stellaris.getGameTick();
    if (tick <= 100) return 0;

    // Main logic here — flat and readable
    Stellaris.setVariable("processed", 1);
    return 0;
});
```

### 5. Limit Registered Handlers

Each registered effect/trigger handler consumes memory. The maximum is 256 per system.

**Bad:** Registering handlers you don't use.

```javascript
// Don't register handlers you'll never call
Stellaris.registerEffect("unused_1", function() {});
Stellaris.registerEffect("unused_2", function() {});
// ... 200 more unused handlers
```

**Good:** Only register what you need.

```javascript
// Register only the effects/triggers your mod actually uses
Stellaris.registerEffect("my_effect", myEffectHandler);
Stellaris.registerTrigger("my_trigger", myTriggerHandler);
```

### 6. Avoid Blocking Operations

**Bad:** Long-running loops that freeze the game.

```javascript
Stellaris.registerEffect("blocking", function(name, id, scope) {
    // This blocks the game thread!
    for (let i = 0; i < 1000000; i++) {
        // Expensive computation
    }
});
```

**Good:** Keep operations fast and return quickly.

```javascript
Stellaris.registerEffect("non_blocking", function(name, id, scope) {
    // Quick check and return
    let tick = Stellaris.getGameTick();
    if (tick % 100 === 0) {
        Stellaris.setVariable("milestone", 1);
    }
    return 0;
});
```

## Hooking Performance

The detour hooking framework has minimal overhead:

| Operation | Overhead |
|-----------|----------|
| Hook installation | One-time cost (writes 14+ bytes) |
| Effect dispatch check | ~5 instructions (read ID, compare, branch) |
| Trampoline call | Same as original function call |
| Hook removal | Restores original bytes |

### Effect Dispatch Flow

```
Engine calls CEffect::ExecuteActual
    ↓
Hook reads CEffect+4080 (effect ID)    ← ~2 cycles
    ↓
Compare ID > 4081?                     ← ~1 cycle
    ↓ (yes)
Read CEffect+56 (effect name)          ← ~2 cycles
    ↓
Look up JS handler in registry         ← ~10 cycles (linear scan)
    ↓
Call JS handler via QuickJS            ← Variable (JS execution time)
    ↓
Return result to engine                ← ~1 cycle
```

**Total overhead for vanilla effects:** ~5 instructions (just the ID check and branch)  
**Total overhead for custom effects:** ~15 instructions + JS execution time

## UI Performance

### Window Creation

Creating windows generates .gui file content. This is a one-time cost per window.

### Text Resolution

Dynamic text (`$NAME$` references) is resolved on every frame the element is visible.

**Bad:** Expensive computation in text providers.

```javascript
Stellaris.registerTextProvider("EXPENSIVE_TEXT", function(scope) {
    // This runs every frame — avoid expensive operations!
    let result = "";
    for (let i = 0; i < 1000; i++) {
        result += "x";
    }
    return result;
});
```

**Good:** Cache results and keep providers fast.

```javascript
let cachedStatus = "Ready";

Stellaris.registerTextProvider("FAST_TEXT", function(scope) {
    return cachedStatus; // Return cached value
});

// Update cache less frequently
Stellaris.registerEffect("update_status", function(name, id, scope) {
    cachedStatus = "Updated at tick " + Stellaris.getGameTick();
    return 0;
});
```

### Text Cache

The dynamic text system has a built-in 64-entry LRU cache. Entries are evicted when the cache is full.

**Cache behavior:**
- Cache key: element name
- Cache value: last resolved text
- Eviction: oldest entry when full
- Clearing: `clearCache()` resets all entries

## Memory Management

### JS Value Lifecycle

QuickJS uses reference counting. Values returned to Zig are either:
- **Consumed** — Must call `JS_FreeValue` (via `EvalResult.deinit`)
- **Borrowed** — Do not free (engine-owned)

**Never** free a value you don't own, and **always** free values you do own.

### String Handling

JS strings passed to Zig are C strings that must be freed with `JS_FreeCString`:

```javascript
// Bridge code (Zig):
fn jsToString(ctx, val) {
    let ptr = JS_ToCStringLen2(ctx, &len, val);
    // Use ptr...
    JS_FreeCString(ctx, ptr); // Must free!
}
```

## Benchmarking

### Measuring JS Execution Time

Wrap your effect handler to measure execution time:

```javascript
Stellaris.registerEffect("timed_effect", function(name, id, scope) {
    let startTick = Stellaris.getGameTick();

    // Your logic here
    Stellaris.setVariable("result", 42);

    let endTick = Stellaris.getGameTick();
    if (endTick !== startTick) {
        console.log("[Perf] Effect took " + (endTick - startTick) + " ticks");
    }

    return 0;
});
```

### Profiling Tips

1. **Use console.log sparingly** — String operations are expensive in hot paths
2. **Test with large saves** — More game objects = more overhead
3. **Monitor tick rate** — If the game slows down, your JS is too slow
4. **Profile individual effects** — Use timing wrappers to find bottlenecks

## Summary

| Guideline | Impact |
|-----------|--------|
| Cache lookups | Reduces redundant API calls |
| Early returns | Flattens logic, reduces branches |
| Minimize strings | Reduces memory allocation |
| Limit handlers | Reduces memory footprint |
| Fast returns | Prevents frame drops |
| Cache text | Reduces per-frame computation |
