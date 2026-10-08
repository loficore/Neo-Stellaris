// handler.zig — C2 JS function registry and dispatch bridge.
//
// Maps registered keyword token IDs to JavaScript handler functions.
// When the engine calls ExecuteActual on a patched object, the custom vtable
// routes here to invoke the JS handler with the CEventScope pointer.
//
// Lifecycle: registerHandler stores a JS_DupValue'd reference; deinit frees it.
// Thread safety: handler registry is protected by a spinlock (same pattern as
// detour.zig). JS_Call is not thread-safe, but engine effect execution is
// single-threaded (recursion counter at [ctx+8] is not atomic).

const std = @import("std");
const c = @import("../quickjs/bindings.zig");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub const Kind = enum(u8) {
    effect,
    trigger,
};

pub const HandlerEntry = struct {
    token_id: u32 = 0,
    js_func: c.JSValue = .{},
    kind: Kind = .effect,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    active: bool = false,
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

const MAX_HANDLERS: usize = 64;

var handlers: [MAX_HANDLERS]HandlerEntry = [_]HandlerEntry{.{}} ** MAX_HANDLERS;
var handler_count: usize = 0;
var handler_lock: u32 = 0;
var js_ctx: ?*c.JSContext = null;

fn lockHandlers() void {
    while (@atomicRmw(u32, &handler_lock, .Xchg, 1, .acquire) != 0) {}
}

fn unlockHandlers() void {
    _ = @atomicRmw(u32, &handler_lock, .Xchg, 0, .release);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set the QuickJS context for handler dispatch. Must be called before registerHandler.
pub fn setContext(ctx: *c.JSContext) void {
    js_ctx = ctx;
}

/// Register a JS function as the handler for a keyword.
/// `name` is the keyword name (e.g., "neo_action").
/// `js_func` is the JS function value (will be JS_DupValue'd).
/// `kind` determines effect vs trigger dispatch.
/// Returns the token_id (set later by C1 registration) or error.
pub const RegisterError = error{
    NoContext,
    RegistryFull,
    DuplicateName,
    NameTooLong,
};

pub fn registerHandler(name: []const u8, js_func: c.JSValue, kind: Kind) RegisterError!u32 {
    const ctx = js_ctx orelse return error.NoContext;
    if (name.len > 63) return error.NameTooLong;

    lockHandlers();
    defer unlockHandlers();

    // Check for duplicate name.
    for (handlers[0..handler_count]) |*h| {
        if (h.active and h.name_len == name.len) {
            if (std.mem.eql(u8, h.name[0..name.len], name)) {
                return error.DuplicateName;
            }
        }
    }

    if (handler_count >= MAX_HANDLERS) return error.RegistryFull;

    const idx = handler_count;
    handler_count += 1;

    handlers[idx].active = true;
    handlers[idx].kind = kind;
    handlers[idx].name_len = @intCast(name.len);
    @memcpy(handlers[idx].name[0..name.len], name);
    handlers[idx].js_func = c.JS_DupValue(ctx, js_func);
    // token_id is 0 until set by setTokenId
    handlers[idx].token_id = 0;

    return 0; // token_id not yet known
}

/// Set the token_id for a handler after C1 registration completes.
pub fn setTokenId(name: []const u8, token_id: u32) bool {
    lockHandlers();
    defer unlockHandlers();

    for (handlers[0..handler_count]) |*h| {
        if (h.active and h.name_len == name.len) {
            if (std.mem.eql(u8, h.name[0..name.len], name)) {
                h.token_id = token_id;
                return true;
            }
        }
    }
    return false;
}

/// Find a handler by token_id. Returns null if not found.
pub fn findHandler(token_id: u32) ?*HandlerEntry {
    // No lock: called from detour context where handler_count is stable.
    for (handlers[0..handler_count]) |*h| {
        if (h.active and h.token_id == token_id) return h;
    }
    return null;
}

/// Get the handler count.
pub fn getHandlerCount() usize {
    lockHandlers();
    defer unlockHandlers();
    return handler_count;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch an effect execution to JS. Called from custom ExecuteActual.
/// `token_id` identifies the keyword; `scope_ptr` is the CEventScope*.
/// Effects return void (no JS return value used).
pub fn dispatchEffect(token_id: u32, scope_ptr: u64) void {
    const ctx = js_ctx orelse return;
    const h = findHandler(token_id) orelse {
        std.log.warn("c2.handler: no handler for effect token_id={d}", .{token_id});
        return;
    };

    // Pass scope pointer as integer to JS.
    const scope_arg = c.JSValue.float64(@floatFromInt(scope_ptr));
    var args = [_]c.JSValue{scope_arg};

    const result = c.JS_Call(ctx, h.js_func, c.JS_UNDEFINED, 1, &args);

    if (result.isException()) {
        handleJSException(ctx, h.name[0..h.name_len]);
    } else {
        c.JS_FreeValue(ctx, result);
    }
}

/// Dispatch a trigger evaluation to JS. Called from custom ExecuteActual.
/// Returns bool: true = trigger passes, false = fails.
pub fn dispatchTrigger(token_id: u32, scope_ptr: u64) bool {
    const ctx = js_ctx orelse return false;
    const h = findHandler(token_id) orelse {
        std.log.warn("c2.handler: no handler for trigger token_id={d}", .{token_id});
        return false;
    };

    const scope_arg = c.JSValue.float64(@floatFromInt(scope_ptr));
    var args = [_]c.JSValue{scope_arg};

    const result = c.JS_Call(ctx, h.js_func, c.JS_UNDEFINED, 1, &args);

    if (result.isException()) {
        handleJSException(ctx, h.name[0..h.name_len]);
        return false;
    }

    const bool_result = c.JS_ToBool(ctx, result);
    c.JS_FreeValue(ctx, result);
    return bool_result != 0;
}

fn handleJSException(ctx: *c.JSContext, keyword_name: []const u8) void {
    const exc = c.JS_GetException(ctx);
    var len: usize = 0;
    const msg_ptr = c.JS_ToCStringLen2(ctx, &len, exc, false);
    if (msg_ptr) |msg| {
        std.log.err("c2.handler: JS exception in '{s}': {s}", .{ keyword_name, msg[0..len] });
        c.JS_FreeCString(ctx, msg);
    } else {
        std.log.err("c2.handler: JS exception in '{s}': (unknown)", .{keyword_name});
    }
    c.JS_FreeValue(ctx, exc);
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Free all handler JS references. Called during DLL cleanup.
pub fn deinit() void {
    const ctx = js_ctx orelse return;
    lockHandlers();
    defer unlockHandlers();

    for (handlers[0..handler_count]) |*h| {
        if (h.active) {
            c.JS_FreeValue(ctx, h.js_func);
            h.* = .{};
        }
    }
    handler_count = 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HandlerEntry default state" {
    const h = HandlerEntry{};
    try std.testing.expectEqual(@as(u32, 0), h.token_id);
    try std.testing.expectEqual(@as(u8, 0), h.name_len);
    try std.testing.expect(!h.active);
}

test "Kind enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Kind.effect));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Kind.trigger));
}

test "MAX_HANDLERS is 64" {
    try std.testing.expectEqual(@as(usize, 64), MAX_HANDLERS);
}

test "findHandler returns null for empty registry" {
    handler_count = 0;
    try std.testing.expectEqual(@as(?*HandlerEntry, null), findHandler(12345));
}

test "findHandler finds registered handler" {
    handler_count = 0;
    handlers[0] = .{
        .token_id = 42,
        .active = true,
        .name_len = 4,
    };
    @memcpy(handlers[0].name[0..4], "test");
    handler_count = 1;

    const h = findHandler(42);
    try std.testing.expect(h != null);
    try std.testing.expectEqual(@as(u32, 42), h.?.token_id);

    // Cleanup
    handler_count = 0;
}

test "findHandler returns null for wrong token_id" {
    handler_count = 0;
    handlers[0] = .{
        .token_id = 42,
        .active = true,
    };
    handler_count = 1;

    try std.testing.expectEqual(@as(?*HandlerEntry, null), findHandler(99));

    // Cleanup
    handler_count = 0;
}
