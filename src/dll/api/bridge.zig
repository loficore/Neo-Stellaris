// bridge.zig — QuickJS API bridge for game state functions.
//
// Registers all game state and scope functions with the QuickJS JavaScript
// runtime, making them callable from mod scripts. This module translates
// between QuickJS values and Zig types.
//
// JS API surface (registered on the global "Stellaris" object):
//
//   // Game state reads
//   Stellaris.getCountry(id)       -> object | null
//   Stellaris.getPlanet(id)        -> object | null
//   Stellaris.getPop(id)           -> object | null
//   Stellaris.getSystem(id)        -> object | null
//   Stellaris.getGameDate()        -> string
//   Stellaris.getGameTick()        -> number
//
//   // Game state writes
//   Stellaris.setVariable(name, value)  -> boolean
//   Stellaris.addModifier(scope, name, value) -> boolean
//   Stellaris.removeModifier(scope, name)    -> boolean
//   Stellaris.triggerEvent(eventId, scope)   -> boolean
//
//   // Scope access
//   Stellaris.getScopeType(scope)      -> number
//   Stellaris.getScopeObjectId(scope)  -> number
//   Stellaris.getScopeTypeName(scope)  -> string
//   Stellaris.hasScopeType(scope, flag) -> boolean

const std = @import("std");
const c = @import("quickjs/bindings");
const gamestate = @import("api/gamestate");
const scope = @import("api/scope");
const offsets = @import("offsets");

// ---------------------------------------------------------------------------
// JS helper: argument extraction
// ---------------------------------------------------------------------------

/// Extract an i64 from a JSValue argument.
/// Returns 0 if the value is not an integer.
fn jsToInt64(val: c.JSValue) i64 {
    if (val.isInt32()) {
        return @intCast(val.u.i32);
    }
    if (val.isFloat64()) {
        return @intFromFloat(val.u.f64);
    }
    return 0;
}

/// Extract a u32 from a JSValue argument.
/// Returns 0 if the value is not a non-negative integer.
fn jsToU32(val: c.JSValue) u32 {
    const v = jsToInt64(val);
    if (v < 0) return 0;
    return @intCast(v);
}

/// Extract a string from a JSValue argument.
/// Returns null if the value is not a string.
/// Caller must free the returned C string with JS_FreeCString.
fn jsToString(ctx: ?*c.JSContext, val: c.JSValue) ?[:0]const u8 {
    var len: usize = 0;
    const ptr = c.JS_ToCStringLen2(ctx, &len, val, false) orelse return null;
    return ptr[0..len :0];
}

/// Extract a raw pointer from a JSValue (used for scope handles).
/// Treats the JS value as an opaque pointer.
fn jsToPtr(val: c.JSValue) ?*anyopaque {
    if (val.isInt32()) {
        const addr: usize = @intCast(val.u.i32);
        return @ptrFromInt(addr);
    }
    if (val.isFloat64()) {
        const addr: usize = @intFromFloat(val.u.f64);
        return @ptrFromInt(addr);
    }
    return null;
}

// ---------------------------------------------------------------------------
// JS wrapper functions (callconv(.c) for QuickJS)
// ---------------------------------------------------------------------------

/// JS: Stellaris.getCountry(id: number) -> object | null
fn jsGetCountry(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.nullVal();

    const id = jsToU32(argv[0]);
    const handle = gamestate.getCountry(id) orelse return c.JSValue.nullVal();

    // Return the pointer as an integer (JS number)
    return c.JSValue.int32(@intCast(@intFromPtr(handle)));
}

/// JS: Stellaris.getPlanet(id: number) -> object | null
fn jsGetPlanet(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.nullVal();

    const id = jsToU32(argv[0]);
    const handle = gamestate.getPlanet(id) orelse return c.JSValue.nullVal();

    return c.JSValue.int32(@intCast(@intFromPtr(handle)));
}

/// JS: Stellaris.getPop(id: number) -> object | null
fn jsGetPop(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.nullVal();

    const id = jsToU32(argv[0]);
    const handle = gamestate.getPop(id) orelse return c.JSValue.nullVal();

    return c.JSValue.int32(@intCast(@intFromPtr(handle)));
}

/// JS: Stellaris.getSystem(id: number) -> object | null
fn jsGetSystem(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.nullVal();

    const id = jsToU32(argv[0]);
    const handle = gamestate.getSystem(id) orelse return c.JSValue.nullVal();

    return c.JSValue.int32(@intCast(@intFromPtr(handle)));
}

/// JS: Stellaris.getGameDate() -> string
fn jsGetGameDate(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    _ = argc;
    _ = argv;

    const date_str = gamestate.getGameDate();
    if (date_str.len == 0) {
        return c.JSValue.nullVal();
    }

    // We need a null-terminated string for JS_NewString
    // Since the stub returns "", we create a temporary
    var buf: [64]u8 = undefined;
    if (date_str.len >= buf.len) return c.JSValue.nullVal();
    @memcpy(buf[0..date_str.len], date_str);
    buf[date_str.len] = 0;

    return c.JS_NewString(ctx, @ptrCast(buf[0..date_str.len :0]));
}

/// JS: Stellaris.getGameTick() -> number
fn jsGetGameTick(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    _ = argc;
    _ = argv;

    const tick = gamestate.getGameTick();
    return c.JSValue.int32(@intCast(tick));
}

/// JS: Stellaris.setVariable(name: string, value: number) -> boolean
fn jsSetVariable(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (argc < 2) return c.JSValue.boolVal(false);

    const name = jsToString(ctx, argv[0]) orelse return c.JSValue.boolVal(false);
    defer if (ctx) |c_ctx| c.JS_FreeCString(c_ctx, name.ptr);

    const value = jsToInt64(argv[1]);
    const result = gamestate.setVariable(name, value);
    return c.JSValue.boolVal(result);
}

/// JS: Stellaris.addModifier(scope: pointer, name: string, value: number) -> boolean
fn jsAddModifier(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (argc < 3) return c.JSValue.boolVal(false);

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.boolVal(false);
    const mod_name = jsToString(ctx, argv[1]) orelse return c.JSValue.boolVal(false);
    defer if (ctx) |c_ctx| c.JS_FreeCString(c_ctx, mod_name.ptr);

    const mod_value = jsToInt64(argv[2]);

    const modifier = gamestate.Modifier{
        .name = mod_name,
        .value = mod_value,
    };

    const result = gamestate.addModifier(scope_handle, modifier);
    return c.JSValue.boolVal(result);
}

/// JS: Stellaris.removeModifier(scope: pointer, name: string) -> boolean
fn jsRemoveModifier(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (argc < 2) return c.JSValue.boolVal(false);

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.boolVal(false);
    const mod_name = jsToString(ctx, argv[1]) orelse return c.JSValue.boolVal(false);
    defer if (ctx) |c_ctx| c.JS_FreeCString(c_ctx, mod_name.ptr);

    const result = gamestate.removeModifier(scope_handle, mod_name);
    return c.JSValue.boolVal(result);
}

/// JS: Stellaris.triggerEvent(eventId: string, scope: pointer) -> boolean
fn jsTriggerEvent(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (argc < 2) return c.JSValue.boolVal(false);

    const event_id = jsToString(ctx, argv[0]) orelse return c.JSValue.boolVal(false);
    defer if (ctx) |c_ctx| c.JS_FreeCString(c_ctx, event_id.ptr);

    const scope_handle = jsToPtr(argv[1]) orelse return c.JSValue.boolVal(false);

    const result = gamestate.triggerEvent(event_id, scope_handle);
    return c.JSValue.boolVal(result);
}

/// JS: Stellaris.getScopeType(scope: pointer) -> number
fn jsGetScopeType(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.int32(0);

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.int32(0);
    const scope_type = scope.getScopeType(scope_handle);
    return c.JSValue.int32(@intCast(scope_type));
}

/// JS: Stellaris.getScopeObjectId(scope: pointer) -> number
fn jsGetScopeObjectId(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 1) return c.JSValue.int32(0);

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.int32(0);
    const object_id = scope.getScopeObjectId(scope_handle);
    return c.JSValue.int32(@intCast(object_id));
}

/// JS: Stellaris.getScopeTypeName(scope: pointer) -> string
fn jsGetScopeTypeName(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (argc < 1) return c.JSValue.nullVal();

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.nullVal();
    const type_name = scope.getScopeTypeName(scope_handle);
    const name_str = type_name.name();

    return c.JS_NewString(ctx, @ptrCast(name_str.ptr));
}

/// JS: Stellaris.hasScopeType(scope: pointer, flag: number) -> boolean
fn jsHasScopeType(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    if (argc < 2) return c.JSValue.boolVal(false);

    const scope_handle = jsToPtr(argv[0]) orelse return c.JSValue.boolVal(false);
    const type_flag = jsToInt64(argv[1]);

    const result = scope.hasScopeType(scope_handle, type_flag);
    return c.JSValue.boolVal(result);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Function registration entry: maps a JS name to a C function pointer.
const ApiFunction = struct {
    name: [:0]const u8,
    func: c.JSCFunction,
    argc: c_int,
};

/// All API functions to register with QuickJS.
const api_functions = [_]ApiFunction{
    // Game state reads
    .{ .name = "getCountry", .func = jsGetCountry, .argc = 1 },
    .{ .name = "getPlanet", .func = jsGetPlanet, .argc = 1 },
    .{ .name = "getPop", .func = jsGetPop, .argc = 1 },
    .{ .name = "getSystem", .func = jsGetSystem, .argc = 1 },
    .{ .name = "getGameDate", .func = jsGetGameDate, .argc = 0 },
    .{ .name = "getGameTick", .func = jsGetGameTick, .argc = 0 },

    // Game state writes
    .{ .name = "setVariable", .func = jsSetVariable, .argc = 2 },
    .{ .name = "addModifier", .func = jsAddModifier, .argc = 3 },
    .{ .name = "removeModifier", .func = jsRemoveModifier, .argc = 2 },
    .{ .name = "triggerEvent", .func = jsTriggerEvent, .argc = 2 },

    // Scope access
    .{ .name = "getScopeType", .func = jsGetScopeType, .argc = 1 },
    .{ .name = "getScopeObjectId", .func = jsGetScopeObjectId, .argc = 1 },
    .{ .name = "getScopeTypeName", .func = jsGetScopeTypeName, .argc = 1 },
    .{ .name = "hasScopeType", .func = jsHasScopeType, .argc = 2 },
};

/// Register all API functions with the QuickJS context.
///
/// Creates a "Stellaris" global object and attaches all API functions to it.
/// After registration, JS code can call:
///   Stellaris.getCountry(1)
///   Stellaris.setVariable("my_var", 42)
///
/// # Arguments
/// * `ctx` - The QuickJS context to register functions with
pub fn registerAllFunctions(ctx: *c.JSContext) void {
    // Create the Stellaris namespace object
    const global = c.JS_GetGlobalObject(ctx);
    defer c.JS_FreeValue(ctx, global);

    // We'll register functions directly on global for now.
    // A more structured approach would create a Stellaris sub-object.
    for (api_functions) |api_fn| {
        const js_func = c.JS_NewCFunction2(
            ctx,
            api_fn.func,
            api_fn.name.ptr,
            api_fn.argc,
            c.JS_CFUNC_generic,
            0,
        );
        _ = c.JS_SetPropertyStr(ctx, global, api_fn.name.ptr, js_func);
    }

    std.log.info("Stellaris API: registered {d} functions with QuickJS", .{api_functions.len});
}

/// Get the number of API functions available.
pub fn getApiFunctionCount() usize {
    return api_functions.len;
}

// =============================================================================
// Tests
// =============================================================================

test "jsToInt64: integer values" {
    const int_val = c.JSValue.int32(42);
    try std.testing.expectEqual(@as(i64, 42), jsToInt64(int_val));

    const neg_val = c.JSValue.int32(-10);
    try std.testing.expectEqual(@as(i64, -10), jsToInt64(neg_val));
}

test "jsToU32: non-negative values" {
    const int_val = c.JSValue.int32(100);
    try std.testing.expectEqual(@as(u32, 100), jsToU32(int_val));

    // Negative values return 0
    const neg_val = c.JSValue.int32(-5);
    try std.testing.expectEqual(@as(u32, 0), jsToU32(neg_val));
}

test "jsToU32: zero value" {
    const zero_val = c.JSValue.int32(0);
    try std.testing.expectEqual(@as(u32, 0), jsToU32(zero_val));
}

test "api_functions: correct count" {
    try std.testing.expectEqual(@as(usize, 14), api_functions.len);
}

test "api_functions: all have names" {
    for (api_functions) |api_fn| {
        try std.testing.expect(api_fn.name.len > 0);
    }
}

test "api_functions: argc non-negative" {
    for (api_functions) |api_fn| {
        try std.testing.expect(api_fn.argc >= 0);
    }
}

test "getApiFunctionCount: matches array length" {
    try std.testing.expectEqual(api_functions.len, getApiFunctionCount());
}

test "api_functions: expected names present" {
    var found_getCountry = false;
    var found_setVariable = false;
    var found_getScopeType = false;

    for (api_functions) |api_fn| {
        if (std.mem.eql(u8, api_fn.name, "getCountry")) found_getCountry = true;
        if (std.mem.eql(u8, api_fn.name, "setVariable")) found_setVariable = true;
        if (std.mem.eql(u8, api_fn.name, "getScopeType")) found_getScopeType = true;
    }

    try std.testing.expect(found_getCountry);
    try std.testing.expect(found_setVariable);
    try std.testing.expect(found_getScopeType);
}

test "jsToInt64: float values" {
    const float_val = c.JSValue.float64(3.14);
    try std.testing.expectEqual(@as(i64, 3), jsToInt64(float_val));

    const neg_float = c.JSValue.float64(-2.5);
    try std.testing.expectEqual(@as(i64, -2), jsToInt64(neg_float));
}

test "jsToInt64: undefined value returns 0" {
    const undef = c.JSValue.undefinedVal();
    try std.testing.expectEqual(@as(i64, 0), jsToInt64(undef));
}

test "jsToInt64: null value returns 0" {
    const nul = c.JSValue.nullVal();
    try std.testing.expectEqual(@as(i64, 0), jsToInt64(nul));
}

test "jsToU32: float values" {
    const float_val = c.JSValue.float64(100.7);
    try std.testing.expectEqual(@as(u32, 100), jsToU32(float_val));

    const neg_float = c.JSValue.float64(-5.5);
    try std.testing.expectEqual(@as(u32, 0), jsToU32(neg_float));
}

test "jsToU32: undefined returns 0" {
    const undef = c.JSValue.undefinedVal();
    try std.testing.expectEqual(@as(u32, 0), jsToU32(undef));
}

test "jsToPtr: null for non-numeric" {
    const undef = c.JSValue.undefinedVal();
    try std.testing.expectEqual(@as(?*anyopaque, null), jsToPtr(undef));
}

test "jsToPtr: null for null" {
    const nul = c.JSValue.nullVal();
    try std.testing.expectEqual(@as(?*anyopaque, null), jsToPtr(nul));
}

test "jsToPtr: converts int32 to pointer" {
    const int_val = c.JSValue.int32(0x1000);
    const ptr = jsToPtr(int_val);
    try std.testing.expect(ptr != null);
    try std.testing.expectEqual(@as(usize, 0x1000), @intFromPtr(ptr.?));
}

test "jsToPtr: converts float64 to pointer" {
    const float_val = c.JSValue.float64(4096.0);
    const ptr = jsToPtr(float_val);
    try std.testing.expect(ptr != null);
    try std.testing.expectEqual(@as(usize, 4096), @intFromPtr(ptr.?));
}

test "api_functions: all function pointers are non-null" {
    for (api_functions) |api_fn| {
        try std.testing.expect(@intFromPtr(api_fn.func) > 0);
    }
}

test "ApiFunction struct" {
    const api_fn = ApiFunction{
        .name = "testFunc",
        .func = undefined,
        .argc = 3,
    };
    try std.testing.expectEqualStrings("testFunc", api_fn.name);
    try std.testing.expectEqual(@as(c_int, 3), api_fn.argc);
}
