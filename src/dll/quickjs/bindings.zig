// bindings.zig — QuickJS C API declarations.
//
// Placeholder extern declarations for the QuickJS JavaScript engine.
// These match the QuickJS 2021-03-27 / 0.x public API surface.
// When QuickJS headers are available, switch to @cImport in runtime.zig.

const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Opaque types (C forward declarations)
// ---------------------------------------------------------------------------

pub const JSRuntime = extern struct {
    _opaque: [1]u8 = undefined,
};

pub const JSContext = extern struct {
    _opaque: [1]u8 = undefined,
};

// ---------------------------------------------------------------------------
// JSValue — the universal JS value representation
// ---------------------------------------------------------------------------

pub const JSValueTag = enum(i64) {
    none = 0,
    undefined = 1,
    null = 2,
    bool = 3,
    int32 = 4,
    object = 5,
    string = 6,
    symbol = 7,
    big_int = 8,
    big_float = 9,
    big_decimal = 10,
    float64 = 11,
    _,

    pub fn fromRaw(tag: i64) JSValueTag {
        return @enumFromInt(tag);
    }
};

pub const JSValueUnion = extern union {
    i32: i32,
    u32: u32,
    f64: f64,
    ptr: ?*anyopaque,
};

pub const JSValue = extern struct {
    u: JSValueUnion = .{ .i32 = 0 },
    tag: i64 = 0,

    // --- Constructors for known tags ---

    pub fn undefinedVal() JSValue {
        return .{ .u = .{ .i32 = 0 }, .tag = @intFromEnum(JSValueTag.undefined) };
    }

    pub fn nullVal() JSValue {
        return .{ .u = .{ .i32 = 0 }, .tag = @intFromEnum(JSValueTag.null) };
    }

    pub fn boolVal(v: bool) JSValue {
        return .{ .u = .{ .i32 = @intCast(@intFromBool(v)) }, .tag = @intFromEnum(JSValueTag.bool) };
    }

    pub fn int32(v: i32) JSValue {
        return .{ .u = .{ .i32 = v }, .tag = @intFromEnum(JSValueTag.int32) };
    }

    pub fn float64(v: f64) JSValue {
        return .{ .u = .{ .f64 = v }, .tag = @intFromEnum(JSValueTag.float64) };
    }

    pub fn isException(self: JSValue) bool {
        return self.tag == (@intFromEnum(JSValueTag.object) | 0x80);
    }

    pub fn isUndefined(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.undefined);
    }

    pub fn isNull(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.null);
    }

    pub fn isBool(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.bool);
    }

    pub fn isInt32(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.int32);
    }

    pub fn isFloat64(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.float64);
    }

    pub fn isString(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.string);
    }

    pub fn isObject(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.object);
    }
};

// ---------------------------------------------------------------------------
// Eval flags
// ---------------------------------------------------------------------------

pub const JS_EVAL_FLAG_STRICT: c_int = 1 << 0;
pub const JS_EVAL_FLAG_STRIP: c_int = 1 << 1;
pub const JS_EVAL_FLAG_COMPILE_ONLY: c_int = 1 << 2;
pub const JS_EVAL_FLAG_BACKTRACE_BARRIER: c_int = 1 << 5;

// ---------------------------------------------------------------------------
// C function pointer type for JS-callable C functions
// ---------------------------------------------------------------------------

/// Signature: (ctx, this_val, argc, argv) -> JSValue
pub const JSCFunction = *const fn (ctx: ?*JSContext, this_val: JSValue, argc: c_int, argv: [*]JSValue) callconv(.c) JSValue;

/// Variable-argument variant used by JS_NewCFunction internally.
pub const JSCFunctionVar = *const fn (ctx: ?*JSContext, this_val: JSValue, argc: c_int, argv: [*]JSValue) callconv(.c) JSValue;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

pub extern fn JS_NewRuntime() ?*JSRuntime;
pub extern fn JS_NewContext(rt: ?*JSRuntime) ?*JSContext;
pub extern fn JS_FreeContext(ctx: ?*JSContext) void;
pub extern fn JS_FreeRuntime(rt: ?*JSRuntime) void;

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

pub extern fn JS_Eval(
    ctx: ?*JSContext,
    code: [*:0]const u8,
    code_len: usize,
    filename: [*:0]const u8,
    eval_flags: c_int,
) JSValue;

// ---------------------------------------------------------------------------
// Value management
// ---------------------------------------------------------------------------

pub extern fn JS_FreeValue(ctx: ?*JSContext, val: JSValue) void;
pub extern fn JS_DupValue(ctx: ?*JSContext, val: JSValue) JSValue;

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

pub extern fn JS_NewString(ctx: ?*JSContext, str: [*:0]const u8) JSValue;
pub extern fn JS_ToString(ctx: ?*JSContext, val: JSValue) JSValue;
pub extern fn JS_ToCStringLen2(ctx: ?*JSContext, len: ?*usize, val: JSValue, _ascii: bool) ?[*:0]const u8;
pub extern fn JS_FreeCString(ctx: ?*JSContext, str: [*:0]const u8) void;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

pub extern fn JS_ThrowTypeError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_GetException(ctx: ?*JSContext) JSValue;

// ---------------------------------------------------------------------------
// Function registration
// ---------------------------------------------------------------------------

pub extern fn JS_NewCFunction2(
    ctx: ?*JSContext,
    func: JSCFunction,
    name: [*:0]const u8,
    length: c_int,
    cproto: c_int,
    magic: c_int,
) JSValue;

pub extern fn JS_SetPropertyStr(
    ctx: ?*JSContext,
    this_obj: JSValue,
    prop: [*:0]const u8,
    val: JSValue,
) c_int;

// C function protocol constants
pub const JS_CFUNC_generic: c_int = 0;
pub const JS_CFUNC_generic_magic: c_int = 1;
pub const JS_CFUNC_constructor: c_int = 2;
pub const JS_CFUNC_constructor_magic: c_int = 3;
pub const JS_CFUNC_constructor_or_func: c_int = 4;

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

pub extern fn JS_SetMaxStackSize(rt: ?*JSRuntime, stack_size: usize) void;
pub extern fn JS_SetMemoryLimit(rt: ?*JSRuntime, mem_limit: usize) void;

// ---------------------------------------------------------------------------
// Global object
// ---------------------------------------------------------------------------

pub extern fn JS_GetGlobalObject(ctx: ?*JSContext) JSValue;
