# Stellaris .gui System Integration — Reference Guide
#
# This document explains how to create custom UI windows using the
# Stellaris .gui file system and integrate them with the DLL's
# window management API.

## .gui File Format

### Container (Window)
Every window starts with a `containerWindowType`:

```
containerWindowType = {
    name = "unique_window_name"
    size = { width = 400 height = 300 }
    position = { x = 100 y = 100 }  # Optional
    draggable = yes                  # Optional
    movable = yes                    # Optional
}
```

### Text Display
`instantTextBoxType` renders static or dynamic text:

```
instantTextBoxType = {
    name = "element_name"
    text = "Display text or $LOCALIZATION_KEY$"
    font = "cg_20"                   # cg_16, cg_20, cg_24
    position = { x = 10 y = 10 }
    maxWidth = 380                   # Optional text wrap
    format = left                    # left, center, right
}
```

### Button
`effectButtonType` creates a clickable button:

```
effectButtonType = {
    name = "button_name"
    effect = "effect_name"           # From common/button_effects/
    position = { x = 10 y = 10 }
    size = { width = 100 height = 30 }
    tooltip = "Button description"
    shortcut = "F1"                  # Optional keyboard shortcut
}
```

## File Placement

```
my_mod/
├── common/
│   └── button_effects/
│       └── custom_effects.txt       # Effect definitions
├── interface/
│   └── my_windows.gui               # Window definitions
└── events/
    └── my_events.txt                # Events triggered by effects
```

## Effect System Integration

Button effects in `common/button_effects/` are called when buttons
are clicked. The effect can:

1. Trigger events
2. Set game variables
3. Call scripted effects
4. Update UI elements

Example effect:
```
close_my_window = {
    tooltip = "Close this window"
    # The DLL intercepts this effect name
    # and calls the window management API
}
```

## DLL API Usage

### From Zig (direct)
```zig
const gui = @import("dll/ui/gui.zig");

// Generate .gui file content
const content = try gui.generateWindow(allocator, .{
    .name = "my_window",
    .width = 500,
    .height = 400,
    .title = "My Window",
});
```

### From JavaScript (via QuickJS)
```javascript
// Create and show a window
Stellaris.createWindow("my_window", 500, 400);
Stellaris.setWindowTitle("my_window", "My Window");
Stellaris.showWindow("my_window");

// Later: hide or destroy
Stellaris.hideWindow("my_window");
Stellaris.destroyWindow("my_window");
```

## Localization

Use `$KEY$` syntax for localized text:

```
instantTextBoxType = {
    name = "title"
    text = "$MY_MOD_WINDOW_TITLE$"
    font = "cg_20"
}
```

Define keys in `localisation/english/`:
```
l_english:
 MY_MOD_WINDOW_TITLE:0 "My Window Title"
```

## Best Practices

1. **Unique Names**: Use mod prefix for all element names (e.g., `mymod_window`)
2. **Tooltips**: Always add tooltips to buttons for accessibility
3. **Font Sizes**: Use cg_16 for body text, cg_20 for titles, cg_24 for headers
4. **Max Width**: Set maxWidth on long text to prevent overflow
5. **Positioning**: Use relative positions from parent container
6. **Close Buttons**: Always provide a way to close windows

## Common Pitfalls

- **Missing effects**: Button effects must exist in `common/button_effects/`
- **Duplicate names**: Each element name must be unique within a window
- **File encoding**: Use UTF-8 without BOM for .gui files
- **Load order**: Interface files load after common/ files
