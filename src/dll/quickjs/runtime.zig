// runtime.zig — QuickJS runtime management.
//
// Wraps the QuickJS C API in a safe, idiomatic Zig interface.
// Provides init/deinit lifecycle, JS evaluation, and function registration.
//
// Memory model: every JSValue returned to Zig is either consumed
// (via EvalResult.deinit) or intentionally leaked (for values that
// must survive past the eval call). No double-frees, no dangling pointers.

const std = @import("std");
const c = @import("bindings.zig");

// ---------------------------------------------------------------------------
// EvalResult — tagged union for eval outcomes
// ---------------------------------------------------------------------------

pub const EvalError = struct {
    message: []const u8,

    pub fn deinit(self: *EvalError, alloc: std.mem.Allocator) void {
        alloc.free(self.message);
        self.* = undefined;
    }
};

pub const EvalResult = union(enum) {
    ok: c.JSValue,
    err: EvalError,

    /// Must be called to free the result. Releases the JS value on success
    /// or frees the error message on failure.
    pub fn deinit(self: *EvalResult, ctx: *c.JSContext, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .ok => |val| c.JS_FreeValue(ctx, val),
            .err => |*e| e.deinit(alloc),
        }
        self.* = undefined;
    }

    /// Return true if this result is an error.
    pub fn isError(self: EvalResult) bool {
        return self == .err;
    }

    /// Return true if this result is a successful value.
    pub fn isOk(self: EvalResult) bool {
        return self == .ok;
    }
};

// ---------------------------------------------------------------------------
// Value — safe wrapper for JSValue that tracks ownership
// ---------------------------------------------------------------------------

pub const Value = struct {
    raw: c.JSValue,
    is_owned: bool = true,

    /// Create a Value that owns the JSValue (must be freed).
    pub fn own(raw: c.JSValue) Value {
        return .{ .raw = raw, .is_owned = true };
    }

    /// Create a Value that does NOT own the JSValue (won't be freed).
    pub fn borrow(raw: c.JSValue) Value {
        return .{ .raw = raw, .is_owned = false };
    }

    /// Release ownership if owned.
    pub fn deinit(self: *Value, ctx: *c.JSContext) void {
        if (self.is_owned) {
            c.JS_FreeValue(ctx, self.raw);
        }
        self.* = undefined;
    }

    // Tag queries (delegate to JSValue)

    pub fn isUndefined(self: Value) bool {
        return self.raw.isUndefined();
    }

    pub fn isNull(self: Value) bool {
        return self.raw.isNull();
    }

    pub fn isBool(self: Value) bool {
        return self.raw.isBool();
    }

    pub fn isInt32(self: Value) bool {
        return self.raw.isInt32();
    }

    pub fn isFloat64(self: Value) bool {
        return self.raw.isFloat64();
    }

    pub fn isString(self: Value) bool {
        return self.raw.isString();
    }

    pub fn isObject(self: Value) bool {
        return self.raw.isObject();
    }

    pub fn isException(self: Value) bool {
        return self.raw.isException();
    }

    /// Extract int32 if the value is an integer; undefined behaviour otherwise.
    pub fn toInt32(self: Value) i32 {
        return self.raw.u.i32;
    }

    /// Extract float64 if the value is a float; undefined behaviour otherwise.
    pub fn toFloat64(self: Value) f64 {
        return self.raw.u.f64;
    }

    /// Extract the string from a JS string value.
    /// Caller must free via JS_FreeCString.
    pub fn toCString(self: Value, ctx: *c.JSContext) ?[:0]const u8 {
        var len: usize = 0;
        const ptr = c.JS_ToCStringLen2(ctx, &len, self.raw, false) orelse return null;
        // Zig slice from C pointer — does NOT own the memory.
        return ptr[0..len :0];
    }
};

// ---------------------------------------------------------------------------
// FunctionBinding — information for a registered C function
// ---------------------------------------------------------------------------

pub const FunctionBinding = struct {
    name: [:0]const u8,
    func: c.JSCFunction,
    length: c_int,
};

// ---------------------------------------------------------------------------
// Runtime — the main entry point
// ---------------------------------------------------------------------------

pub const Runtime = struct {
    rt: *c.JSRuntime,
    ctx: *c.JSContext,

    /// Default memory limits (can be overridden via configure).
    const DEFAULT_MAX_STACK_SIZE: usize = 1024 * 1024; // 1 MiB
    const DEFAULT_MEM_LIMIT: usize = 256 * 1024 * 1024; // 256 MiB

    /// Initialise the QuickJS runtime and context with default settings.
    /// Returns error.OutOfMemory if allocation fails.
    pub fn init() error{ RuntimeInitFailed, ContextInitFailed, OutOfMemory }!Runtime {
        return initWithConfig(.{});
    }

    /// Initialise with custom configuration.
    pub fn initWithConfig(config: Config) error{ RuntimeInitFailed, ContextInitFailed, OutOfMemory }!Runtime {
        const rt = c.JS_NewRuntime() orelse return error.RuntimeInitFailed;

        // Apply limits before creating context.
        c.JS_SetMaxStackSize(rt, config.max_stack_size);
        c.JS_SetMemoryLimit(rt, config.mem_limit);

        const ctx = c.JS_NewContext(rt) orelse {
            c.JS_FreeRuntime(rt);
            return error.ContextInitFailed;
        };

        return .{ .rt = rt, .ctx = ctx };
    }

    /// Free the context and runtime. Must be called exactly once.
    pub fn deinit(self: *Runtime) void {
        c.JS_FreeContext(self.ctx);
        c.JS_FreeRuntime(self.rt);
        self.* = undefined;
    }

    /// Evaluate JavaScript source code.
    /// Returns an EvalResult that must be deinitialised by the caller.
    pub fn eval(self: *Runtime, code: [:0]const u8, filename: [:0]const u8) EvalResult {
        return self.evalWithFlags(code, filename, 0);
    }

    /// Evaluate with explicit eval flags (JS_EVAL_FLAG_*).
    pub fn evalWithFlags(self: *Runtime, code: [:0]const u8, filename: [:0]const u8, flags: c_int) EvalResult {
        const result = c.JS_Eval(
            self.ctx,
            code.ptr,
            code.len,
            filename.ptr,
            flags,
        );

        if (result.isException()) {
            // Extract the error message from the pending exception.
            const exc = c.JS_GetException(self.ctx);
            const msg = self.valueToString(exc) catch "unknown error";
            // exc is consumed by GetException — no need to free it.
            return .{ .err = .{ .message = msg } };
        }

        return .{ .ok = result };
    }

    /// Register a C function on the global object.
    pub fn registerFunction(self: *Runtime, binding: FunctionBinding) void {
        const global = c.JS_GetGlobalObject(self.ctx);
        const js_func = c.JS_NewCFunction2(
            self.ctx,
            binding.func,
            binding.name.ptr,
            binding.length,
            c.JS_CFUNC_generic,
            0,
        );
        _ = c.JS_SetPropertyStr(self.ctx, global, binding.name.ptr, js_func);
        // global is borrowed from GetGlobalObject — do not free.
    }

    /// Register multiple C functions on the global object.
    pub fn registerFunctions(self: *Runtime, bindings: []const FunctionBinding) void {
        for (bindings) |binding| {
            self.registerFunction(binding);
        }
    }

    /// Extract a string from a JSValue, allocating in Zig.
    /// Caller owns the returned memory.
    fn valueToString(self: *Runtime, val: c.JSValue) error{OutOfMemory}![:0]const u8 {
        const str_val = c.JS_ToString(self.ctx, val);
        var len: usize = 0;
        const cstr = c.JS_ToCStringLen2(self.ctx, &len, str_val, false) orelse
            return error.OutOfMemory;
        // Copy into Zig-managed memory.
        const buf = std.heap.page_allocator.alloc(u8, len + 1) catch return error.OutOfMemory;
        @memcpy(buf[0..len], cstr[0..len]);
        buf[len] = 0;
        c.JS_FreeCString(self.ctx, cstr);
        c.JS_FreeValue(self.ctx, str_val);
        return @ptrCast(buf[0..len :0]);
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    test "Value tag checks" {
        // Pure Zig — no C linkage needed.
        const undef = c.JSValue{ .u = .{ .i32 = 0 }, .tag = 1 };
        try std.testing.expect(undef.isUndefined());
        try std.testing.expect(!undef.isNull());
        try std.testing.expect(!undef.isInt32());

        const num = c.JSValue{ .u = .{ .i32 = 42 }, .tag = 4 };
        try std.testing.expect(num.isInt32());
        try std.testing.expectEqual(@as(i32, 42), num.u.i32);

        const bval = c.JSValue{ .u = .{ .i32 = 1 }, .tag = 3 };
        try std.testing.expect(bval.isBool());

        const fval = c.JSValue{ .u = .{ .f64 = 3.14 }, .tag = 11 };
        try std.testing.expect(fval.isFloat64());
        try std.testing.expectApproxEqAbs(@as(f64, 3.14), fval.u.f64, 1e-10);
    }

    test "Value constructors" {
        const undef = c.JSValue.undefinedVal();
        try std.testing.expect(undef.isUndefined());

        const nval = c.JSValue.nullVal();
        try std.testing.expect(nval.isNull());

        const bval = c.JSValue.boolVal(true);
        try std.testing.expect(bval.isBool());
        try std.testing.expectEqual(@as(i32, 1), bval.u.i32);

        const ival = c.JSValue.int32(99);
        try std.testing.expect(ival.isInt32());
        try std.testing.expectEqual(@as(i32, 99), ival.u.i32);

        const fval = c.JSValue.float64(2.718);
        try std.testing.expect(fval.isFloat64());
        try std.testing.expectApproxEqAbs(@as(f64, 2.718), fval.u.f64, 1e-10);
    }

    test "Value wrapper owns/borrows correctly" {
        // We can't call JS_FreeValue here (no QuickJS linked), so we only
        // verify the ownership flag is tracked correctly.
        const v1 = Value.own(c.JSValue.int32(10));
        try std.testing.expect(v1.is_owned);

        const v2 = Value.borrow(c.JSValue.int32(20));
        try std.testing.expect(!v2.is_owned);
    }

    test "EvalResult error path" {
        // Verify EvalResult enum behaviour without C linkage.
        var ok_result = EvalResult{ .ok = c.JSValue.int32(42) };
        try std.testing.expect(ok_result.isOk());
        try std.testing.expect(!ok_result.isError());

        // Manually construct an error result.
        const alloc = std.testing.allocator;
        var err_result = EvalResult{ .err = .{ .message = try alloc.dupe(u8, "test error") } };
        try std.testing.expect(err_result.isError());
        try std.testing.expect(!err_result.isOk());

        // Clean up error message (simulates deinit without C context).
        err_result.err.deinit(alloc);
    }
};

// ---------------------------------------------------------------------------
// Config — runtime configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    max_stack_size: usize = Runtime.DEFAULT_MAX_STACK_SIZE,
    mem_limit: usize = Runtime.DEFAULT_MEM_LIMIT,
};

// ---------------------------------------------------------------------------
// Module tests (pure Zig, no QuickJS linkage)
// ---------------------------------------------------------------------------

test "Config defaults" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(usize, 1024 * 1024), cfg.max_stack_size);
    try std.testing.expectEqual(@as(usize, 256 * 1024 * 1024), cfg.mem_limit);
}

test "FunctionBinding layout" {
    // Verify the struct can be created — no C function needed.
    const binding = FunctionBinding{
        .name = "myFunc",
        .func = undefined, // Would be a real function pointer.
        .length = 2,
    };
    try std.testing.expectEqualStrings("myFunc", binding.name);
    try std.testing.expectEqual(@as(c_int, 2), binding.length);
}

test "JSValueTag fromRaw" {
    const tag = c.JSValueTag.fromRaw(4);
    try std.testing.expectEqual(c.JSValueTag.int32, tag);
}

test "JSValueTag: all known tags" {
    try std.testing.expectEqual(c.JSValueTag.none, c.JSValueTag.fromRaw(0));
    try std.testing.expectEqual(c.JSValueTag.undefined, c.JSValueTag.fromRaw(1));
    try std.testing.expectEqual(c.JSValueTag.null, c.JSValueTag.fromRaw(2));
    try std.testing.expectEqual(c.JSValueTag.bool, c.JSValueTag.fromRaw(3));
    try std.testing.expectEqual(c.JSValueTag.int32, c.JSValueTag.fromRaw(4));
    try std.testing.expectEqual(c.JSValueTag.object, c.JSValueTag.fromRaw(5));
    try std.testing.expectEqual(c.JSValueTag.string, c.JSValueTag.fromRaw(6));
    try std.testing.expectEqual(c.JSValueTag.float64, c.JSValueTag.fromRaw(11));
}

test "JSValue: isString for string tag" {
    const str_val = c.JSValue{ .u = .{ .ptr = null }, .tag = @intFromEnum(c.JSValueTag.string) };
    try std.testing.expect(str_val.isString());
    try std.testing.expect(!str_val.isInt32());
    try std.testing.expect(!str_val.isFloat64());
    try std.testing.expect(!str_val.isBool());
    try std.testing.expect(!str_val.isObject());
}

test "JSValue: isObject for object tag" {
    const obj_val = c.JSValue{ .u = .{ .ptr = null }, .tag = @intFromEnum(c.JSValueTag.object) };
    try std.testing.expect(obj_val.isObject());
    try std.testing.expect(!obj_val.isString());
    try std.testing.expect(!obj_val.isInt32());
}

test "JSValue: isException for exception tag" {
    const exc_tag: i64 = @intFromEnum(c.JSValueTag.object) | 0x80;
    const exc_val = c.JSValue{ .u = .{ .ptr = null }, .tag = exc_tag };
    try std.testing.expect(exc_val.isException());
    try std.testing.expect(!exc_val.isObject()); // Exception has special tag
}

test "JSValue: default value" {
    const default = c.JSValue{};
    try std.testing.expectEqual(@as(i64, 0), default.tag);
    try std.testing.expectEqual(@as(i32, 0), default.u.i32);
}

test "JSValueUnion: all variants" {
    var union_val = c.JSValueUnion{ .i32 = 42 };
    try std.testing.expectEqual(@as(i32, 42), union_val.i32);

    union_val = c.JSValueUnion{ .u32 = 100 };
    try std.testing.expectEqual(@as(u32, 100), union_val.u32);

    union_val = c.JSValueUnion{ .f64 = 3.14 };
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), union_val.f64, 1e-10);

    union_val = c.JSValueUnion{ .ptr = null };
    try std.testing.expectEqual(@as(?*anyopaque, null), union_val.ptr);
}

test "Value: toInt32 extracts value" {
    const val = Value.own(c.JSValue.int32(42));
    try std.testing.expectEqual(@as(i32, 42), val.toInt32());
}

test "Value: toFloat64 extracts value" {
    const val = Value.own(c.JSValue.float64(2.718));
    try std.testing.expectApproxEqAbs(@as(f64, 2.718), val.toFloat64(), 1e-10);
}

test "Value: tag queries delegate correctly" {
    const undef = Value.own(c.JSValue.undefinedVal());
    try std.testing.expect(undef.isUndefined());
    try std.testing.expect(!undef.isNull());
    try std.testing.expect(!undef.isBool());
    try std.testing.expect(!undef.isInt32());
    try std.testing.expect(!undef.isFloat64());
    try std.testing.expect(!undef.isString());
    try std.testing.expect(!undef.isObject());
    try std.testing.expect(!undef.isException());

    const nul = Value.own(c.JSValue.nullVal());
    try std.testing.expect(nul.isNull());
    try std.testing.expect(!nul.isUndefined());

    const bval = Value.own(c.JSValue.boolVal(true));
    try std.testing.expect(bval.isBool());
    try std.testing.expect(!bval.isNull());

    const ival = Value.own(c.JSValue.int32(99));
    try std.testing.expect(ival.isInt32());
    try std.testing.expect(!ival.isBool());

    const fval = Value.own(c.JSValue.float64(1.5));
    try std.testing.expect(fval.isFloat64());
    try std.testing.expect(!fval.isInt32());
}

test "EvalResult: ok result isOk and not isError" {
    var result = EvalResult{ .ok = c.JSValue.int32(42) };
    try std.testing.expect(result.isOk());
    try std.testing.expect(!result.isError());
}

test "EvalResult: err result isError and not isOk" {
    const alloc = std.testing.allocator;
    var result = EvalResult{ .err = .{ .message = try alloc.dupe(u8, "test error") } };
    try std.testing.expect(result.isError());
    try std.testing.expect(!result.isOk());
    result.err.deinit(alloc);
}

test "Config: custom values" {
    const cfg = Config{
        .max_stack_size = 2048,
        .mem_limit = 1024 * 1024,
    };
    try std.testing.expectEqual(@as(usize, 2048), cfg.max_stack_size);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), cfg.mem_limit);
}

test "FunctionBinding: with different lengths" {
    const b0 = FunctionBinding{ .name = "f0", .func = undefined, .length = 0 };
    const b1 = FunctionBinding{ .name = "f1", .func = undefined, .length = 1 };
    const b5 = FunctionBinding{ .name = "f5", .func = undefined, .length = 5 };

    try std.testing.expectEqual(@as(c_int, 0), b0.length);
    try std.testing.expectEqual(@as(c_int, 1), b1.length);
    try std.testing.expectEqual(@as(c_int, 5), b5.length);
}

test "JSValue constructors: round-trip values" {
    // bool round-trip
    const bt = c.JSValue.boolVal(true);
    try std.testing.expect(bt.isBool());
    try std.testing.expectEqual(@as(i32, 1), bt.u.i32);

    const bf = c.JSValue.boolVal(false);
    try std.testing.expect(bf.isBool());
    try std.testing.expectEqual(@as(i32, 0), bf.u.i32);

    // int32 round-trip
    const i_neg = c.JSValue.int32(-42);
    try std.testing.expect(i_neg.isInt32());
    try std.testing.expectEqual(@as(i32, -42), i_neg.u.i32);

    // float64 round-trip
    const f_neg = c.JSValue.float64(-1.5);
    try std.testing.expect(f_neg.isFloat64());
    try std.testing.expectApproxEqAbs(@as(f64, -1.5), f_neg.u.f64, 1e-10);
}
