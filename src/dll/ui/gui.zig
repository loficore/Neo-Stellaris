// gui.zig — .gui file integration for Stellaris UI system.
//
// Provides functions for generating .gui files that define custom UI windows
// in the Clausewitz engine. The engine loads .gui files from the interface/
// directory and renders them as native game UI.
//
// Usage from Zig:
//   const gui = @import("gui.zig");
//   const content = try gui.generateWindow(allocator, .{
//       .name = "my_window",
//       .width = 500,
//       .height = 400,
//       .title = "My Custom Window",
//       .buttons = &.{
//           .{ .name = "ok_btn", .effect = "close_my_window", .label = "OK" },
//       },
//   });
//
// Usage from JavaScript (via QuickJS bridge):
//   Stellaris.createWindow("my_window", 500, 400);
//   Stellaris.setWindowTitle("my_window", "My Custom Window");
//   Stellaris.showWindow("my_window");

const std = @import("std");
const window = @import("window.zig");

/// Export window types for convenience.
pub const WindowDef = window.WindowDef;
pub const WindowState = window.WindowState;
pub const Position = window.Position;
pub const Size = window.Size;
pub const Font = window.Font;
pub const Alignment = window.Alignment;
pub const TextBox = window.TextBox;
pub const Button = window.Button;
pub const Image = window.Image;
pub const Element = window.Element;
pub const WindowManager = window.WindowManager;

// ---------------------------------------------------------------------------
// .gui File Generation
// ---------------------------------------------------------------------------

/// Options for generating a .gui file.
pub const GuiOptions = struct {
    /// Window name (must match what you use in code to reference it).
    name: []const u8,
    /// Window width in pixels.
    width: u32 = 400,
    /// Window height in pixels.
    height: u32 = 300,
    /// Window title text (optional).
    title: ?[]const u8 = null,
    /// Title font.
    title_font: Font = .cg_20,
    /// Whether the window can be dragged.
    draggable: bool = true,
    /// Whether the window is movable.
    movable: bool = true,
    /// Additional buttons to add.
    buttons: []const ButtonDef = &.{},
    /// Additional text boxes.
    textboxes: []const TextBoxDef = &.{},
    /// Whether to add a default close button.
    add_close_button: bool = true,
    /// Close button effect name (default: close_<name>).
    close_effect: ?[]const u8 = null,
};

/// Definition for a button in the .gui file.
pub const ButtonDef = struct {
    name: []const u8,
    effect: []const u8,
    x: i32 = 0,
    y: i32 = 0,
    width: u32 = 100,
    height: u32 = 30,
    tooltip: ?[]const u8 = null,
};

/// Definition for a text box in the .gui file.
pub const TextBoxDef = struct {
    name: []const u8,
    text: []const u8,
    font: Font = .cg_20,
    x: i32 = 10,
    y: i32 = 10,
    max_width: ?u32 = null,
    alignment: Alignment = .left,
};

/// Generate a .gui file content string for a window.
///
/// The returned string is allocated using the provided allocator.
/// Caller must free the returned string.
pub fn generateWindow(alloc: std.mem.Allocator, opts: GuiOptions) ![]const u8 {
    // Build the .gui content using allocPrint
    var result = std.ArrayList(u8).empty;

    // Header
    const header = try std.fmt.allocPrint(alloc, "containerWindowType = {{\n\tname = \"{s}\"\n\tsize = {{ width = {d} height = {d} }}\n\tdraggable = {s}\n\tmovable = {s}\n", .{
        opts.name,
        opts.width,
        opts.height,
        if (opts.draggable) "yes" else "no",
        if (opts.movable) "yes" else "no",
    });
    defer alloc.free(header);
    try result.appendSlice(alloc, header);

    // Title text box
    if (opts.title) |title| {
        const title_block = try std.fmt.allocPrint(alloc, "\n\tinstantTextBoxType = {{\n\t\tname = \"title\"\n\t\ttext = \"{s}\"\n\t\tfont = \"{s}\"\n\t\tposition = {{ x = 10 y = 10 }}\n\t}}\n", .{
            title,
            opts.title_font.name(),
        });
        defer alloc.free(title_block);
        try result.appendSlice(alloc, title_block);
    }

    // Additional text boxes
    for (opts.textboxes) |tb| {
        const align_str = switch (tb.alignment) {
            .left => "left",
            .center => "center",
            .right => "right",
        };
        const max_width_str = if (tb.max_width) |mw|
            try std.fmt.allocPrint(alloc, "\t\tmaxWidth = {d}\n", .{mw})
        else
            try std.fmt.allocPrint(alloc, "", .{});
        defer alloc.free(max_width_str);

        const tb_block = try std.fmt.allocPrint(alloc, "\n\tinstantTextBoxType = {{\n\t\tname = \"{s}\"\n\t\ttext = \"{s}\"\n\t\tfont = \"{s}\"\n\t\tposition = {{ x = {d} y = {d} }}\n{s}\t\tformat = {s}\n\t}}\n", .{
            tb.name,
            tb.text,
            tb.font.name(),
            tb.x,
            tb.y,
            max_width_str,
            align_str,
        });
        defer alloc.free(tb_block);
        try result.appendSlice(alloc, tb_block);
    }

    // Additional buttons
    for (opts.buttons) |btn| {
        const btn_block = try std.fmt.allocPrint(alloc, "\n\teffectButtonType = {{\n\t\tname = \"{s}\"\n\t\teffect = \"{s}\"\n\t\tposition = {{ x = {d} y = {d} }}\n\t\tsize = {{ width = {d} height = {d} }}\n", .{
            btn.name,
            btn.effect,
            btn.x,
            btn.y,
            btn.width,
            btn.height,
        });
        defer alloc.free(btn_block);
        try result.appendSlice(alloc, btn_block);

        if (btn.tooltip) |tip| {
            const tip_line = try std.fmt.allocPrint(alloc, "\t\ttooltip = \"{s}\"\n", .{tip});
            defer alloc.free(tip_line);
            try result.appendSlice(alloc, tip_line);
        }

        const btn_end = try std.fmt.allocPrint(alloc, "\t}}\n", .{});
        defer alloc.free(btn_end);
        try result.appendSlice(alloc, btn_end);
    }

    // Default close button
    if (opts.add_close_button) {
        const close_effect_name = opts.close_effect orelse blk: {
            const name_buf = try std.fmt.allocPrint(alloc, "close_{s}", .{opts.name});
            break :blk name_buf;
        };
        defer if (opts.close_effect == null) alloc.free(close_effect_name);

        const btn_x: i32 = @intCast(opts.width - 50);
        const btn_y: i32 = @intCast(opts.height - 40);

        const close_btn = try std.fmt.allocPrint(alloc, "\n\teffectButtonType = {{\n\t\tname = \"close_button\"\n\t\teffect = \"{s}\"\n\t\tposition = {{ x = {d} y = {d} }}\n\t\tsize = {{ width = 40 height = 25 }}\n\t\ttooltip = \"Close\"\n\t}}\n", .{
            close_effect_name,
            btn_x,
            btn_y,
        });
        defer alloc.free(close_btn);
        try result.appendSlice(alloc, close_btn);
    }

    const footer = try std.fmt.allocPrint(alloc, "}}\n", .{});
    defer alloc.free(footer);
    try result.appendSlice(alloc, footer);

    return try result.toOwnedSlice(alloc);
}

/// Generate a minimal .gui file for a window with just a title and close button.
pub fn generateSimpleWindow(
    alloc: std.mem.Allocator,
    name: []const u8,
    title: []const u8,
    width: u32,
    height: u32,
) ![]const u8 {
    return generateWindow(alloc, .{
        .name = name,
        .width = width,
        .height = height,
        .title = title,
    });
}

// ---------------------------------------------------------------------------
// Button Effects File Generation
// ---------------------------------------------------------------------------

/// Options for generating a button_effects file.
pub const ButtonEffectsOptions = struct {
    /// Effect definitions.
    effects: []const EffectDef = &.{},
};

/// Definition for a button effect.
pub const EffectDef = struct {
    name: []const u8,
    tooltip: []const u8,
    condition: ?[]const u8 = null,
};

/// Generate a button_effects .txt file content.
///
/// Button effects are defined in common/button_effects/ and are called
/// when the user clicks a button in a .gui window.
pub fn generateButtonEffects(
    alloc: std.mem.Allocator,
    opts: ButtonEffectsOptions,
) ![]const u8 {
    var result = std.ArrayList(u8).empty;

    for (opts.effects) |eff| {
        const eff_block = try std.fmt.allocPrint(alloc, "{s} = {{\n\ttooltip = \"{s}\"\n", .{
            eff.name,
            eff.tooltip,
        });
        defer alloc.free(eff_block);
        try result.appendSlice(alloc, eff_block);

        if (eff.condition) |cond| {
            const cond_line = try std.fmt.allocPrint(alloc, "\t{s}\n", .{cond});
            defer alloc.free(cond_line);
            try result.appendSlice(alloc, cond_line);
        }

        const eff_end = try std.fmt.allocPrint(alloc, "}}\n\n", .{});
        defer alloc.free(eff_end);
        try result.appendSlice(alloc, eff_end);
    }

    return try result.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// JS Bridge Integration
// ---------------------------------------------------------------------------

/// Generate a .gui file from JavaScript-style parameters.
/// This is called from the QuickJS bridge when JS code invokes
/// Stellaris.createWindow() or similar functions.
pub const JsWindowParams = struct {
    name: []const u8,
    width: u32 = 400,
    height: u32 = 300,
    title: ?[]const u8 = null,
    draggable: bool = true,
};

/// Create a window definition from JS parameters.
pub fn createWindowFromJs(params: JsWindowParams) WindowDef {
    return .{
        .name = params.name,
        .size = .{ .width = params.width, .height = params.height },
        .draggable = params.draggable,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "generateWindow: basic window" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "test_win",
        .width = 400,
        .height = 300,
        .title = "Test Window",
    });
    defer alloc.free(content);

    // Verify key strings are present
    try std.testing.expect(std.mem.indexOf(u8, content, "containerWindowType") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "test_win") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "400") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Test Window") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "close_button") != null);
}

test "generateWindow: no close button" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "no_close",
        .width = 200,
        .height = 150,
        .add_close_button = false,
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "close_button") == null);
}

test "generateSimpleWindow: minimal" {
    const alloc = std.testing.allocator;
    const content = try generateSimpleWindow(alloc, "simple", "Simple", 300, 200);
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "simple") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Simple") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "300") != null);
}

test "generateButtonEffects: with effects" {
    const alloc = std.testing.allocator;
    const content = try generateButtonEffects(alloc, .{
        .effects = &.{
            .{ .name = "close_my_win", .tooltip = "Close window" },
            .{ .name = "open_settings", .tooltip = "Open settings" },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "close_my_win") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "open_settings") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "tooltip") != null);
}

test "createWindowFromJs: default values" {
    const params = JsWindowParams{
        .name = "js_window",
    };
    const def = createWindowFromJs(params);

    try std.testing.expectEqualStrings("js_window", def.name);
    try std.testing.expectEqual(@as(u32, 400), def.size.width);
    try std.testing.expectEqual(@as(u32, 300), def.size.height);
    try std.testing.expect(def.draggable);
}

test "generateWindow: custom buttons" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "custom",
        .width = 500,
        .height = 400,
        .buttons = &.{
            .{ .name = "save_btn", .effect = "save_data", .x = 10, .y = 350, .tooltip = "Save" },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "save_btn") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "save_data") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Save") != null);
}

test "generateWindow: with textboxes" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "text_win",
        .width = 600,
        .height = 400,
        .textboxes = &.{
            .{ .name = "label1", .text = "Hello World", .x = 10, .y = 50 },
            .{ .name = "label2", .text = "Status", .x = 10, .y = 80, .font = .cg_24 },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "label1") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Hello World") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "label2") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "cg_24") != null);
}

test "generateWindow: custom close effect" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "custom_close",
        .width = 400,
        .height = 300,
        .close_effect = "my_custom_close",
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "my_custom_close") != null);
    // Should not have the default close_<name> pattern
    try std.testing.expect(std.mem.indexOf(u8, content, "close_custom_close") == null);
}

test "generateButtonEffects: with condition" {
    const alloc = std.testing.allocator;
    const content = try generateButtonEffects(alloc, .{
        .effects = &.{
            .{ .name = "conditional_btn", .tooltip = "Click me", .condition = "has_country_flag = my_flag" },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "conditional_btn") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "has_country_flag = my_flag") != null);
}

test "generateButtonEffects: empty effects" {
    const alloc = std.testing.allocator;
    const content = try generateButtonEffects(alloc, .{
        .effects = &.{},
    });
    defer alloc.free(content);

    // Empty effects should produce minimal content
    try std.testing.expectEqual(@as(usize, 0), content.len);
}

test "generateWindow: draggable and movable options" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "opts_win",
        .width = 300,
        .height = 200,
        .draggable = false,
        .movable = false,
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "draggable = no") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "movable = no") != null);
}

test "createWindowFromJs: custom values" {
    const params = JsWindowParams{
        .name = "custom_window",
        .width = 800,
        .height = 600,
        .title = "Custom Title",
        .draggable = false,
    };
    const def = createWindowFromJs(params);

    try std.testing.expectEqualStrings("custom_window", def.name);
    try std.testing.expectEqual(@as(u32, 800), def.size.width);
    try std.testing.expectEqual(@as(u32, 600), def.size.height);
    try std.testing.expect(!def.draggable);
}

test "Font.name: all font values" {
    try std.testing.expectEqualStrings("cg_16", Font.cg_16.name());
    try std.testing.expectEqualStrings("cg_20", Font.cg_20.name());
    try std.testing.expectEqualStrings("cg_24", Font.cg_24.name());
}

test "generateWindow: textboxes with alignment" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "align_win",
        .width = 400,
        .height = 300,
        .textboxes = &.{
            .{ .name = "left_tb", .text = "Left", .alignment = .left },
            .{ .name = "center_tb", .text = "Center", .alignment = .center },
            .{ .name = "right_tb", .text = "Right", .alignment = .right },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "format = left") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "format = center") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "format = right") != null);
}

test "generateWindow: textboxes with maxWidth" {
    const alloc = std.testing.allocator;
    const content = try generateWindow(alloc, .{
        .name = "maxwidth_win",
        .width = 400,
        .height = 300,
        .textboxes = &.{
            .{ .name = "wrapped", .text = "Long text", .max_width = 200 },
        },
    });
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "maxWidth = 200") != null);
}

test "ButtonDef struct defaults" {
    const btn = ButtonDef{
        .name = "test_btn",
        .effect = "test_effect",
    };
    try std.testing.expectEqual(@as(i32, 0), btn.x);
    try std.testing.expectEqual(@as(i32, 0), btn.y);
    try std.testing.expectEqual(@as(u32, 100), btn.width);
    try std.testing.expectEqual(@as(u32, 30), btn.height);
    try std.testing.expectEqual(@as(?[]const u8, null), btn.tooltip);
}

test "TextBoxDef struct defaults" {
    const tb = TextBoxDef{
        .name = "test_tb",
        .text = "test text",
    };
    try std.testing.expectEqual(Font.cg_20, tb.font);
    try std.testing.expectEqual(@as(i32, 10), tb.x);
    try std.testing.expectEqual(@as(i32, 10), tb.y);
    try std.testing.expectEqual(@as(?u32, null), tb.max_width);
    try std.testing.expectEqual(Alignment.left, tb.alignment);
}

test "EffectDef struct defaults" {
    const eff = EffectDef{
        .name = "test_eff",
        .tooltip = "Test tooltip",
    };
    try std.testing.expectEqual(@as(?[]const u8, null), eff.condition);
}
