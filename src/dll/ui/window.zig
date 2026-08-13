// window.zig — Window management for Stellaris .gui system.
//
// Provides types and functions for creating, showing, hiding, and
// destroying custom UI windows defined in .gui files. Windows are
// rendered by the Clausewitz engine's GUI system and can contain
// text, buttons, images, and other UI elements.
//
// .gui File Format Reference:
//   containerWindowType — top-level window container
//     name: string           — unique identifier
//     size: {width, height}  — window dimensions in pixels
//     position: {x, y}       — screen position (optional)
//     draggable: bool        — can user drag window
//     movable: bool          — alias for draggable
//     
//   instantTextBoxType — text display element
//     name: string           — element identifier
//     text: string           — display text (localization key or literal)
//     font: string           — font name (cg_16, cg_20, cg_24)
//     position: {x, y}       — offset from parent
//     maxWidth: number       — text wrap width (optional)
//     format:left|center|right — text alignment
//
//   effectButtonType — clickable button with effect
//     name: string           — element identifier
//     effect: string         — button effect name (from common/button_effects/)
//     position: {x, y}       — offset from parent
//     size: {width, height}  — button dimensions
//     shortcut: string       — keyboard shortcut (optional)
//     tooltip: string        — hover tooltip (optional)

const std = @import("std");

// ---------------------------------------------------------------------------
// Window Types
// ---------------------------------------------------------------------------

/// Window state in the engine.
pub const WindowState = enum {
    hidden,
    visible,
    minimized,
    destroyed,
};

/// Position on screen (pixels from top-left).
pub const Position = struct {
    x: i32 = 0,
    y: i32 = 0,
};

/// Dimensions in pixels.
pub const Size = struct {
    width: u32 = 400,
    height: u32 = 300,
};

/// Alignment options for text elements.
pub const Alignment = enum {
    left,
    center,
    right,
};

/// Font sizes available in Stellaris.
pub const Font = enum {
    cg_16,
    cg_20,
    cg_24,

    pub fn name(self: Font) []const u8 {
        return switch (self) {
            .cg_16 => "cg_16",
            .cg_20 => "cg_20",
            .cg_24 => "cg_24",
        };
    }
};

// ---------------------------------------------------------------------------
// UI Element Types
// ---------------------------------------------------------------------------

/// Text display element within a window.
pub const TextBox = struct {
    name: []const u8,
    text: []const u8,
    font: Font = .cg_20,
    position: Position = .{},
    max_width: ?u32 = null,
    alignment: Alignment = .left,
};

/// Button element that triggers an effect.
pub const Button = struct {
    name: []const u8,
    effect: []const u8,
    position: Position = .{},
    size: Size = .{ .width = 100, .height = 30 },
    shortcut: ?[]const u8 = null,
    tooltip: ?[]const u8 = null,
};

/// Image display element.
pub const Image = struct {
    name: []const u8,
    texture: []const u8,
    position: Position = .{},
    size: Size = .{ .width = 64, .height = 64 },
};

/// Union of all UI element types.
pub const Element = union(enum) {
    textbox: TextBox,
    button: Button,
    image: Image,
};

// ---------------------------------------------------------------------------
// Window Definition
// ---------------------------------------------------------------------------

/// A complete window definition matching .gui containerWindowType.
pub const WindowDef = struct {
    name: []const u8,
    size: Size = .{},
    position: Position = .{},
    draggable: bool = false,
    elements: []const Element = &.{},
};

/// Runtime handle to a window instance.
pub const Window = struct {
    id: u32,
    name: []const u8,
    state: WindowState = .hidden,

    pub fn isVisible(self: Window) bool {
        return self.state == .visible;
    }

    pub fn isHidden(self: Window) bool {
        return self.state == .hidden;
    }
};

// ---------------------------------------------------------------------------
// Window Manager
// ---------------------------------------------------------------------------

/// Maximum number of tracked windows.
const MAX_WINDOWS: usize = 64;

/// Window manager that tracks all created windows.
pub const WindowManager = struct {
    windows: [MAX_WINDOWS]?Window = [_]?Window{null} ** MAX_WINDOWS,
    count: u32 = 0,

    /// Create a new window and return its handle.
    pub fn create(self: *WindowManager, def: WindowDef) ?Window {
        if (self.count >= MAX_WINDOWS) return null;

        const id = self.count;
        const window = Window{
            .id = id,
            .name = def.name,
            .state = .hidden,
        };

        self.windows[id] = window;
        self.count += 1;

        std.log.info("Window created: {s} (id={d})", .{ def.name, id });
        return window;
    }

    /// Show a window by ID.
    pub fn show(self: *WindowManager, id: u32) bool {
        if (id >= MAX_WINDOWS) return false;
        if (self.windows[id]) |*win| {
            win.state = .visible;
            std.log.info("Window shown: {s} (id={d})", .{ win.name, id });
            return true;
        }
        return false;
    }

    /// Hide a window by ID.
    pub fn hide(self: *WindowManager, id: u32) bool {
        if (id >= MAX_WINDOWS) return false;
        if (self.windows[id]) |*win| {
            win.state = .hidden;
            std.log.info("Window hidden: {s} (id={d})", .{ win.name, id });
            return true;
        }
        return false;
    }

    /// Destroy a window by ID.
    pub fn destroy(self: *WindowManager, id: u32) bool {
        if (id >= MAX_WINDOWS) return false;
        if (self.windows[id]) |*win| {
            win.state = .destroyed;
            self.windows[id] = null;
            std.log.info("Window destroyed: {s} (id={d})", .{ win.name, id });
            return true;
        }
        return false;
    }

    /// Get a window handle by ID.
    pub fn get(self: *WindowManager, id: u32) ?Window {
        if (id >= MAX_WINDOWS) return null;
        return self.windows[id];
    }

    /// Find a window by name.
    pub fn findByName(self: *WindowManager, name: []const u8) ?Window {
        for (self.windows) |maybe_win| {
            if (maybe_win) |win| {
                if (std.mem.eql(u8, win.name, name)) return win;
            }
        }
        return null;
    }

    /// Get count of active (non-destroyed) windows.
    pub fn activeCount(self: *WindowManager) u32 {
        var count: u32 = 0;
        for (self.windows) |maybe_win| {
            if (maybe_win != null) count += 1;
        }
        return count;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Window creation and lifecycle" {
    var mgr = WindowManager{};

    const def = WindowDef{
        .name = "test_window",
        .size = .{ .width = 400, .height = 300 },
    };

    const win = mgr.create(def) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 0), win.id);
    try std.testing.expectEqual(WindowState.hidden, win.state);
    try std.testing.expect(win.isHidden());
    try std.testing.expect(!win.isVisible());

    // Show
    try std.testing.expect(mgr.show(win.id));
    const shown = mgr.get(win.id) orelse return error.TestFailed;
    try std.testing.expect(shown.isVisible());

    // Hide
    try std.testing.expect(mgr.hide(win.id));
    const hidden = mgr.get(win.id) orelse return error.TestFailed;
    try std.testing.expect(hidden.isHidden());

    // Destroy
    try std.testing.expect(mgr.destroy(win.id));
    try std.testing.expectEqual(@as(?Window, null), mgr.get(win.id));
}

test "WindowManager: findByName" {
    var mgr = WindowManager{};

    _ = mgr.create(.{ .name = "window_a" });
    _ = mgr.create(.{ .name = "window_b" });

    const found = mgr.findByName("window_b") orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 1), found.id);

    try std.testing.expectEqual(@as(?Window, null), mgr.findByName("window_c"));
}

test "WindowManager: activeCount" {
    var mgr = WindowManager{};

    try std.testing.expectEqual(@as(u32, 0), mgr.activeCount());

    const w1 = mgr.create(.{ .name = "w1" }) orelse return error.TestFailed;
    const w2 = mgr.create(.{ .name = "w2" }) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 2), mgr.activeCount());

    _ = mgr.destroy(w1.id);
    try std.testing.expectEqual(@as(u32, 1), mgr.activeCount());

    _ = mgr.destroy(w2.id);
    try std.testing.expectEqual(@as(u32, 0), mgr.activeCount());
}

test "TextBox defaults" {
    const tb = TextBox{
        .name = "title",
        .text = "Hello",
    };
    try std.testing.expectEqual(Font.cg_20, tb.font);
    try std.testing.expectEqual(Alignment.left, tb.alignment);
    try std.testing.expectEqual(@as(?u32, null), tb.max_width);
}

test "Button struct" {
    const btn = Button{
        .name = "close_btn",
        .effect = "close_my_window",
    };
    try std.testing.expectEqual(@as(u32, 100), btn.size.width);
    try std.testing.expectEqual(@as(u32, 30), btn.size.height);
    try std.testing.expectEqual(@as(?[]const u8, null), btn.shortcut);
}

test "Font.name: all values" {
    try std.testing.expectEqualStrings("cg_16", Font.cg_16.name());
    try std.testing.expectEqualStrings("cg_20", Font.cg_20.name());
    try std.testing.expectEqualStrings("cg_24", Font.cg_24.name());
}

test "WindowDef: default values" {
    const def = WindowDef{
        .name = "test",
    };
    try std.testing.expectEqual(@as(u32, 400), def.size.width);
    try std.testing.expectEqual(@as(u32, 300), def.size.height);
    try std.testing.expectEqual(@as(i32, 0), def.position.x);
    try std.testing.expectEqual(@as(i32, 0), def.position.y);
    try std.testing.expect(!def.draggable);
    try std.testing.expectEqual(@as(usize, 0), def.elements.len);
}

test "Position: default values" {
    const pos = Position{};
    try std.testing.expectEqual(@as(i32, 0), pos.x);
    try std.testing.expectEqual(@as(i32, 0), pos.y);
}

test "Size: default values" {
    const size = Size{};
    try std.testing.expectEqual(@as(u32, 400), size.width);
    try std.testing.expectEqual(@as(u32, 300), size.height);
}

test "Image struct" {
    const img = Image{
        .name = "icon",
        .texture = "my_texture.dds",
    };
    try std.testing.expectEqual(@as(u32, 64), img.size.width);
    try std.testing.expectEqual(@as(u32, 64), img.size.height);
    try std.testing.expectEqual(@as(i32, 0), img.position.x);
    try std.testing.expectEqual(@as(i32, 0), img.position.y);
}

test "Element union: all variants" {
    const textbox_elem = Element{ .textbox = .{ .name = "tb", .text = "text" } };
    const button_elem = Element{ .button = .{ .name = "btn", .effect = "eff" } };
    const image_elem = Element{ .image = .{ .name = "img", .texture = "tex" } };

    try std.testing.expect(textbox_elem == .textbox);
    try std.testing.expect(button_elem == .button);
    try std.testing.expect(image_elem == .image);
}

test "WindowState: all values" {
    try std.testing.expect(WindowState.hidden != WindowState.visible);
    try std.testing.expect(WindowState.visible != WindowState.minimized);
    try std.testing.expect(WindowState.minimized != WindowState.destroyed);
}

test "Alignment: all values" {
    try std.testing.expect(Alignment.left != Alignment.center);
    try std.testing.expect(Alignment.center != Alignment.right);
    try std.testing.expect(Alignment.left != Alignment.right);
}

test "WindowManager: show non-existent window" {
    var mgr = WindowManager{};
    try std.testing.expect(!mgr.show(999));
}

test "WindowManager: hide non-existent window" {
    var mgr = WindowManager{};
    try std.testing.expect(!mgr.hide(999));
}

test "WindowManager: destroy non-existent window" {
    var mgr = WindowManager{};
    try std.testing.expect(!mgr.destroy(999));
}

test "WindowManager: get non-existent window" {
    var mgr = WindowManager{};
    try std.testing.expectEqual(@as(?Window, null), mgr.get(999));
}

test "WindowManager: findByName with no match" {
    var mgr = WindowManager{};
    _ = mgr.create(.{ .name = "window_a" });
    try std.testing.expectEqual(@as(?Window, null), mgr.findByName("window_b"));
}

test "WindowManager: multiple create and destroy" {
    var mgr = WindowManager{};

    const w1 = mgr.create(.{ .name = "w1" }) orelse return error.TestFailed;
    const w2 = mgr.create(.{ .name = "w2" }) orelse return error.TestFailed;
    const w3 = mgr.create(.{ .name = "w3" }) orelse return error.TestFailed;

    try std.testing.expectEqual(@as(u32, 3), mgr.activeCount());

    _ = mgr.destroy(w2.id);
    try std.testing.expectEqual(@as(u32, 2), mgr.activeCount());

    // w1 and w3 should still be accessible
    try std.testing.expect(mgr.get(w1.id) != null);
    try std.testing.expectEqual(@as(?Window, null), mgr.get(w2.id));
    try std.testing.expect(mgr.get(w3.id) != null);
}

test "TextBox: custom values" {
    const tb = TextBox{
        .name = "custom_tb",
        .text = "Custom text",
        .font = .cg_24,
        .position = .{ .x = 50, .y = 100 },
        .max_width = 300,
        .alignment = .center,
    };
    try std.testing.expectEqualStrings("custom_tb", tb.name);
    try std.testing.expectEqualStrings("Custom text", tb.text);
    try std.testing.expectEqual(Font.cg_24, tb.font);
    try std.testing.expectEqual(@as(i32, 50), tb.position.x);
    try std.testing.expectEqual(@as(i32, 100), tb.position.y);
    try std.testing.expectEqual(@as(?u32, 300), tb.max_width);
    try std.testing.expectEqual(Alignment.center, tb.alignment);
}

test "Button: custom values" {
    const btn = Button{
        .name = "custom_btn",
        .effect = "custom_effect",
        .position = .{ .x = 10, .y = 20 },
        .size = .{ .width = 200, .height = 50 },
        .shortcut = "F5",
        .tooltip = "Click me",
    };
    try std.testing.expectEqualStrings("custom_btn", btn.name);
    try std.testing.expectEqualStrings("custom_effect", btn.effect);
    try std.testing.expectEqual(@as(i32, 10), btn.position.x);
    try std.testing.expectEqual(@as(i32, 20), btn.position.y);
    try std.testing.expectEqual(@as(u32, 200), btn.size.width);
    try std.testing.expectEqual(@as(u32, 50), btn.size.height);
    try std.testing.expectEqualStrings("F5", btn.shortcut orelse unreachable);
    try std.testing.expectEqualStrings("Click me", btn.tooltip orelse unreachable);
}
