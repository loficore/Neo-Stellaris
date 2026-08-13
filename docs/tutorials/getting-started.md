# Getting Started Tutorial

A step-by-step guide to building your first Stellaris QuickJS extension mod.

## Prerequisites

1. **Stellaris** installed on Windows (Steam or Paradox Launcher)
2. **Zig** ≥ 0.16.0 installed ([ziglang.org](https://ziglang.org/download/))
3. **Git** for version control
4. A **DLL injector** (e.g., [Xenos](https://github.com/DarthTon/Xenos) or the companion C++ loader)

## Step 1: Build the Extension

```bash
# Clone the repository
git clone <repo-url>
cd stellaris-quickjs

# Build the DLL
zig build

# Verify the output exists
ls zig-out/bin/stellaris_quickjs.dll
```

## Step 2: Inject the DLL

1. Start Stellaris
2. Once you're in the main menu (or in-game), use your DLL injector to inject `stellaris_quickjs.dll`
3. The DLL will log: `stellaris_quickjs: CApplication ptr received @ 0x...`

## Step 3: Write Your First Effect

Create a file called `my_mod.js` in your Stellaris mod directory:

```javascript
// my_mod.js — Custom effects for my Stellaris mod

// Register a custom effect called "give_bonus_resources"
// This can be used in any scripted_effect or event
Stellaris.registerEffect("give_bonus_resources", function(effectName, effectId, scope) {
    console.log("[MyMod] Effect triggered: " + effectName);

    // Read the current scope
    let scopeType = Stellaris.getScopeType(scope);
    let objectId = Stellaris.getScopeObjectId(scope);
    let typeName = Stellaris.getScopeTypeName(scope);

    console.log("[MyMod] Scope: " + typeName + " (ID: " + objectId + ")");

    // Get game state
    let tick = Stellaris.getGameTick();
    let date = Stellaris.getGameDate();
    console.log("[MyMod] Game tick: " + tick + ", Date: " + date);

    // Set a variable on the scope
    Stellaris.setVariable("bonus_applied", 1);

    return 0; // Effects typically return 0
});
```

## Step 4: Write Your First Trigger

Add a custom trigger to `my_mod.js`:

```javascript
// Register a custom trigger called "has_bonus_applied"
// This can be used in any scripted_trigger or event condition
Stellaris.registerTrigger("has_bonus_applied", function(triggerName, triggerId, scope) {
    console.log("[MyMod] Trigger evaluated: " + triggerName);

    // Check if we're in country scope
    if (!Stellaris.hasScopeType(scope, 4)) { // 4 = COUNTRY
        return false;
    }

    // Read the object ID (country ID)
    let countryId = Stellaris.getScopeObjectId(scope);

    // Get the country object
    let country = Stellaris.getCountry(countryId);
    if (country === null) {
        return false;
    }

    // Custom logic: return true on even ticks
    let tick = Stellaris.getGameTick();
    return (tick % 2 === 0);
});
```

## Step 5: Create a UI Window

Add a custom UI panel to `my_mod.js`:

```javascript
// Create a window
Stellaris.createWindow("my_debug_panel", 400, 300);
Stellaris.setWindowTitle("my_debug_panel", "My Debug Panel");
Stellaris.showWindow("my_debug_panel");

// Register a button effect to close the window
Stellaris.registerButtonEffect("close_debug_panel", function(btnName, scope) {
    console.log("[MyMod] Closing debug panel");
    Stellaris.hideWindow("my_debug_panel");
});
```

Create the corresponding .gui file in your mod's `interface/` directory:

```
# interface/my_debug_panel.gui
containerWindowType = {
    name = "my_debug_panel"
    size = { width = 400 height = 300 }
    draggable = yes
    movable = yes

    instantTextBoxType = {
        name = "title"
        text = "Debug Panel"
        font = "cg_24"
        position = { x = 10 y = 10 }
    }

    instantTextBoxType = {
        name = "status_text"
        text = "Status: $MOD_STATUS$"
        font = "cg_20"
        position = { x = 10 y = 50 }
    }

    effectButtonType = {
        name = "close_button"
        effect = "close_debug_panel"
        position = { x = 340 y = 260 }
        size = { width = 50 height = 25 }
        tooltip = "Close"
    }
}
```

## Step 6: Add Dynamic Text

Register a text provider for the `$MOD_STATUS$` reference:

```javascript
Stellaris.registerTextProvider("MOD_STATUS", function(scope) {
    let tick = Stellaris.getGameTick();
    let date = Stellaris.getGameDate();
    return "Tick " + tick + " | " + date;
});
```

## Step 7: Use in Game Scripts

Now you can use your custom effects and triggers in Stellaris game scripts:

```pdx
# common/scripted_effects/my_effects.txt
give_bonus_resources = {
    add_resource = {
        minerals = 1000
        energy = 500
    }
    set_country_flag = bonus_received
}
```

```pdx
# common/scripted_triggers/my_triggers.txt
has_bonus_applied = {
    # This calls your JavaScript trigger
}
```

```pdx
# events/my_events.txt
namespace = my_mod

country_event = {
    id = my_mod.1
    title = "Bonus Resources"
    desc = "You received bonus resources!"

    trigger = {
        has_bonus_applied = yes  # Your custom trigger
    }

    immediate = {
        give_bonus_resources = yes  # Your custom effect
    }

    option = {
        name = "Great!"
    }
}
```

## Complete Example

Here's a complete `my_mod.js` that combines everything:

```javascript
// my_mod.js — Complete example mod

console.log("[MyMod] Loading custom mod...");

// ============================================================
// Custom Effects
// ============================================================

Stellaris.registerEffect("give_bonus_resources", function(name, id, scope) {
    let typeName = Stellaris.getScopeTypeName(scope);
    let objectId = Stellaris.getScopeObjectId(scope);

    console.log("[MyMod] Giving bonus resources in " + typeName + " scope (ID: " + objectId + ")");

    Stellaris.setVariable("bonus_applied", 1);
    return 0;
});

Stellaris.registerEffect("apply_custom_modifier", function(name, id, scope) {
    console.log("[MyMod] Applying custom modifier");

    // Add a modifier to the scoped object
    let success = Stellaris.addModifier(scope, "my_custom_modifier", 10);
    console.log("[MyMod] Modifier applied: " + success);

    return 0;
});

// ============================================================
// Custom Triggers
// ============================================================

Stellaris.registerTrigger("has_bonus_applied", function(name, id, scope) {
    if (!Stellaris.hasScopeType(scope, 4)) { // COUNTRY
        return false;
    }

    let countryId = Stellaris.getScopeObjectId(scope);
    let country = Stellaris.getCountry(countryId);
    return country !== null;
});

Stellaris.registerTrigger("is_even_tick", function(name, id, scope) {
    let tick = Stellaris.getGameTick();
    return tick % 2 === 0;
});

// ============================================================
// UI
// ============================================================

Stellaris.createWindow("my_panel", 400, 300);
Stellaris.setWindowTitle("my_panel", "My Custom Panel");
Stellaris.showWindow("my_panel");

Stellaris.registerButtonEffect("close_panel", function(btnName, scope) {
    Stellaris.hideWindow("my_panel");
});

Stellaris.registerButtonEffect("apply_bonus", function(btnName, scope) {
    console.log("[MyMod] Applying bonus via button");
    // Apply bonus to the current scope
    if (scope !== null) {
        Stellaris.addModifier(scope, "button_bonus", 5);
    }
});

// ============================================================
// Dynamic Text
// ============================================================

Stellaris.registerTextProvider("MY_MOD_STATUS", function(scope) {
    let tick = Stellaris.getGameTick();
    let date = Stellaris.getGameDate();
    return "Tick: " + tick + " | Date: " + date;
});

Stellaris.registerTextProvider("MY_MOD_VERSION", function(scope) {
    return "v1.0.0";
});

console.log("[MyMod] Custom mod loaded successfully!");
```

## Testing

### Run Unit Tests

```bash
# Run all tests
zig build test

# Run specific test suites
zig build test -- --test-filter "bridge"
zig build test -- --test-filter "scope"
zig build test -- --test-filter "window"
```

### Debug Logging

The extension uses Zig's `std.log` system. Look for log messages with `[MyMod]` prefix in the game's output or debugger console.

## Next Steps

- Read the [API Reference](../api-reference.md) for complete function documentation
- Check the [Version Compatibility](../version-compatibility.md) guide for supported Stellaris versions
- Review the [Performance Guide](../performance-guide.md) for optimization tips
- See the [Security Guide](../security-guide.md) for safety considerations

## Troubleshooting

### DLL injection fails

- Ensure Stellaris is running and fully loaded
- Check that `stellaris_quickjs.dll` is in the correct path
- Try running the injector as administrator
- Verify the DLL architecture matches (x86_64)

### JS errors in console

- Check function names match exactly (case-sensitive)
- Ensure you're calling functions after the runtime is initialized
- Look for null pointer errors when accessing scope handles

### Window not appearing

- Verify the .gui file is in the correct `interface/` directory
- Check that the window name matches between JS and .gui files
- Ensure the .gui file syntax is correct (no missing braces)

### Effect/Trigger not firing

- Verify the effect/trigger name matches exactly in game scripts
- Check that the effect ID is > 4081 (custom threshold)
- Look for log messages about handler registration
