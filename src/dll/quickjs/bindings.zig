// bindings.zig — QuickJS C API declarations.
//
// Zig bindings for the QuickJS JavaScript engine.
// Matches the non-NAN_BOXING, non-CONFIG_CHECK_JSVALUE layout used on
// 64-bit platforms (x86_64-windows), where JSValue = { JSValueUnion u; int64_t tag }.
//
// Static-inline functions from quickjs.h (JS_FreeValue, JS_DupValue,
// JS_NewString, etc.) are implemented as Zig pub fns that operate on
// the reference-count header directly.

const std = @import("std");

// ---------------------------------------------------------------------------
// Opaque types (C forward declarations)
// ---------------------------------------------------------------------------

pub const JSRuntime = extern struct {
    _opaque: [1]u8 = undefined,
};

pub const JSContext = extern struct {
    _opaque: [1]u8 = undefined,
};

pub const JSClass = extern struct {
    _opaque: [1]u8 = undefined,
};

pub const JSModuleDef = extern struct {
    _opaque: [1]u8 = undefined,
};

// ---------------------------------------------------------------------------
// Scalar typedefs
// ---------------------------------------------------------------------------

pub const JSAtom = u32;
pub const JSClassID = u32;

// ---------------------------------------------------------------------------
// JSValue tags — matches the C enum in quickjs.h
// ---------------------------------------------------------------------------

pub const JSValueTag = enum(i64) {
    big_int = -9,
    symbol = -8,
    string = -7,
    string_rope = -6,
    module = -3, // internal
    function_bytecode = -2, // internal
    object = -1,
    int32 = 0,
    bool = 1,
    null = 2,
    undefined = 3,
    uninitialized = 4,
    catch_offset = 5,
    exception = 6,
    short_big_int = 7,
    float64 = 8,
    _,

    pub fn fromRaw(tag: i64) JSValueTag {
        return @enumFromInt(tag);
    }
};

// ---------------------------------------------------------------------------
// JSValueUnion — matches the C union for 64-bit non-NAN_BOXING platforms
//   typedef union JSValueUnion {
//       uint64_t uint64;
//       double   float64;
//       void    *ptr;
//       int64_t  short_big_int;   // int32_t on 32-bit
//   } JSValueUnion;
//
// Fields i32/u32 are backward-compatible aliases overlaying the low 32 bits
// of uint64, matching the original placeholder layout. Existing code that
// reads val.u.i32 or val.u.f64 continues to work.
// ---------------------------------------------------------------------------

pub const JSValueUnion = extern union {
    uint64: u64,
    i32: i32,
    u32: u32,
    f64: f64, // backward-compat alias for float64
    float64: f64,
    ptr: ?*anyopaque,
    short_big_int: i64,
};

// ---------------------------------------------------------------------------
// JSValue — the universal JS value representation
//   typedef struct JSValue { JSValueUnion u; int64_t tag; } JSValue;
// ---------------------------------------------------------------------------

pub const JSValue = extern struct {
    u: JSValueUnion = .{ .uint64 = 0 },
    tag: i64 = 0,

    // --- Constructors for known tags ---
    // Matches JS_MKVAL: (JSValue){ (JSValueUnion){ .uint64 = (uint32_t)(val) }, tag }

    pub fn undefinedVal() JSValue {
        return .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.undefined) };
    }

    pub fn nullVal() JSValue {
        return .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.null) };
    }

    pub fn boolVal(v: bool) JSValue {
        return .{ .u = .{ .uint64 = if (v) 1 else 0 }, .tag = @intFromEnum(JSValueTag.bool) };
    }

    pub fn int32(v: i32) JSValue {
        return .{ .u = .{ .uint64 = @as(u32, @bitCast(v)) }, .tag = @intFromEnum(JSValueTag.int32) };
    }

    pub fn float64(v: f64) JSValue {
        return .{ .u = .{ .float64 = v }, .tag = @intFromEnum(JSValueTag.float64) };
    }

    // --- Tag queries (match quickjs.h static inline helpers) ---

    pub fn isException(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.exception);
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

    /// Matches JS_IsString: checks both JS_TAG_STRING and JS_TAG_STRING_ROPE.
    pub fn isString(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.string) or
            self.tag == @intFromEnum(JSValueTag.string_rope);
    }

    pub fn isObject(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.object);
    }

    pub fn isNumber(self: JSValue) bool {
        return self.isInt32() or self.isFloat64();
    }

    pub fn isBigInt(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.big_int) or
            self.tag == @intFromEnum(JSValueTag.short_big_int);
    }

    pub fn isSymbol(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.symbol);
    }

    pub fn isUninitialized(self: JSValue) bool {
        return self.tag == @intFromEnum(JSValueTag.uninitialized);
    }
};

// ---------------------------------------------------------------------------
// JSRefCountHeader — stored immediately before every heap object pointer
//   typedef struct JSRefCountHeader { int ref_count; } JSRefCountHeader;
// ---------------------------------------------------------------------------

pub const JSRefCountHeader = extern struct {
    ref_count: c_int,
};

// ---------------------------------------------------------------------------
// Eval flags — matches quickjs.h defines
// ---------------------------------------------------------------------------

pub const JS_EVAL_TYPE_GLOBAL: c_int = 0 << 0;
pub const JS_EVAL_TYPE_MODULE: c_int = 1 << 0;
pub const JS_EVAL_TYPE_DIRECT: c_int = 2 << 0;
pub const JS_EVAL_TYPE_INDIRECT: c_int = 3 << 0;
pub const JS_EVAL_TYPE_MASK: c_int = 3 << 0;

pub const JS_EVAL_FLAG_STRICT: c_int = 1 << 3;
pub const JS_EVAL_FLAG_COMPILE_ONLY: c_int = 1 << 5;
pub const JS_EVAL_FLAG_BACKTRACE_BARRIER: c_int = 1 << 6;
pub const JS_EVAL_FLAG_ASYNC: c_int = 1 << 7;

// ---------------------------------------------------------------------------
// C function pointer types — match quickjs.h typedefs
//
// In the 64-bit non-NAN_BOXING path, JSValueConst == JSValue (no const qualifier).
// ---------------------------------------------------------------------------

/// Matches: typedef JSValue JSCFunction(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);
pub const JSCFunction = *const fn (ctx: ?*JSContext, this_val: JSValue, argc: c_int, argv: [*]JSValue) callconv(.c) JSValue;

/// Matches: typedef JSValue JSCFunctionMagic(..., int magic);
pub const JSCFunctionMagic = *const fn (ctx: ?*JSContext, this_val: JSValue, argc: c_int, argv: [*]JSValue, magic: c_int) callconv(.c) JSValue;

/// Matches: typedef JSValue JSCFunctionData(..., int magic, JSValue *func_data);
pub const JSCFunctionData = *const fn (ctx: ?*JSContext, this_val: JSValue, argc: c_int, argv: [*]JSValue, magic: c_int, func_data: [*]JSValue) callconv(.c) JSValue;

// ---------------------------------------------------------------------------
// C function protocol enum (JS_CFUNC_*)
// ---------------------------------------------------------------------------

pub const JS_CFUNC_generic: c_int = 0;
pub const JS_CFUNC_generic_magic: c_int = 1;
pub const JS_CFUNC_constructor: c_int = 2;
pub const JS_CFUNC_constructor_magic: c_int = 3;
pub const JS_CFUNC_constructor_or_func: c_int = 4;
pub const JS_CFUNC_constructor_or_func_magic: c_int = 5;
pub const JS_CFUNC_f_f: c_int = 6;
pub const JS_CFUNC_f_f_f: c_int = 7;
pub const JS_CFUNC_getter: c_int = 8;
pub const JS_CFUNC_setter: c_int = 9;
pub const JS_CFUNC_getter_magic: c_int = 10;
pub const JS_CFUNC_setter_magic: c_int = 11;
pub const JS_CFUNC_iterator_next: c_int = 12;

// ---------------------------------------------------------------------------
// Property flags
// ---------------------------------------------------------------------------

pub const JS_PROP_CONFIGURABLE: c_int = 1 << 0;
pub const JS_PROP_WRITABLE: c_int = 1 << 1;
pub const JS_PROP_ENUMERABLE: c_int = 1 << 2;
pub const JS_PROP_C_W_E: c_int = JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE | JS_PROP_ENUMERABLE;
pub const JS_PROP_THROW: c_int = 1 << 14;
pub const JS_PROP_THROW_STRICT: c_int = 1 << 15;

// ---------------------------------------------------------------------------
// Special JSValue constants (Zig equivalents of C macros)
// ---------------------------------------------------------------------------

pub const JS_NULL: JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.null) };
pub const JS_UNDEFINED: JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.undefined) };
pub const JS_FALSE: JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.bool) };
pub const JS_TRUE: JSValue = .{ .u = .{ .uint64 = 1 }, .tag = @intFromEnum(JSValueTag.bool) };
pub const JS_EXCEPTION: JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.exception) };
pub const JS_UNINITIALIZED: JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(JSValueTag.uninitialized) };

// ---------------------------------------------------------------------------
// JS_FreeValue / JS_DupValue — static inline in C, Zig pub fns here.
//
// The C inlines check JS_VALUE_HAS_REF_COUNT(v), manipulate the
// JSRefCountHeader stored 4 bytes before the object pointer, and
// call __JS_FreeValue when refcount drops to zero.
// ---------------------------------------------------------------------------

/// JS_VALUE_HAS_REF_COUNT: true for all tags with a reference count (negative tags).
inline fn hasRefCount(v: JSValue) bool {
    return v.tag < 0;
}

/// Get the JSRefCountHeader from an object pointer (4 bytes before it).
inline fn rcHeader(ptr: *anyopaque) *JSRefCountHeader {
    return @ptrFromInt(@intFromPtr(ptr) - @sizeOf(JSRefCountHeader));
}

/// Decrement reference count; free via __JS_FreeValue when it reaches zero.
/// Matches the C static inline JS_FreeValue.
pub fn JS_FreeValue(ctx: ?*JSContext, v: JSValue) void {
    if (hasRefCount(v)) {
        const ptr = v.u.ptr orelse return;
        const rc = rcHeader(ptr);
        rc.ref_count -= 1;
        if (rc.ref_count <= 0) {
            __JS_FreeValue(ctx, v);
        }
    }
}

/// Increment reference count. Matches the C static inline JS_DupValue.
pub fn JS_DupValue(ctx: ?*JSContext, v: JSValue) JSValue {
    _ = ctx;
    if (hasRefCount(v)) {
        const ptr = v.u.ptr orelse return v;
        const rc = rcHeader(ptr);
        rc.ref_count += 1;
    }
    return v;
}

/// Matches the C static inline JS_FreeValueRT.
pub fn JS_FreeValueRT(rt: ?*JSRuntime, v: JSValue) void {
    if (hasRefCount(v)) {
        const ptr = v.u.ptr orelse return;
        const rc = rcHeader(ptr);
        rc.ref_count -= 1;
        if (rc.ref_count <= 0) {
            __JS_FreeValueRT(rt, v);
        }
    }
}

/// Matches the C static inline JS_DupValueRT.
pub fn JS_DupValueRT(rt: ?*JSRuntime, v: JSValue) JSValue {
    _ = rt;
    if (hasRefCount(v)) {
        const ptr = v.u.ptr orelse return v;
        const rc = rcHeader(ptr);
        rc.ref_count += 1;
    }
    return v;
}

// ---------------------------------------------------------------------------
// JS_NewString — static inline in C, wraps JS_NewStringLen with strlen.
// ---------------------------------------------------------------------------

/// Create a JS string from a null-terminated C string.
/// Matches the C static inline JS_NewString.
pub fn JS_NewString(ctx: ?*JSContext, str: [*:0]const u8) JSValue {
    return JS_NewStringLen(ctx, str, std.mem.span(str).len);
}

// ===========================================================================
// Extern declarations — functions exported from the QuickJS shared library.
// ===========================================================================

// ---------------------------------------------------------------------------
// Runtime lifecycle
// ---------------------------------------------------------------------------

pub extern fn JS_NewRuntime() ?*JSRuntime;
pub extern fn JS_SetRuntimeInfo(rt: ?*JSRuntime, info: [*:0]const u8) void;
pub extern fn JS_SetMemoryLimit(rt: ?*JSRuntime, limit: usize) void;
pub extern fn JS_SetGCThreshold(rt: ?*JSRuntime, gc_threshold: usize) void;
pub extern fn JS_SetMaxStackSize(rt: ?*JSRuntime, stack_size: usize) void;
pub extern fn JS_UpdateStackTop(rt: ?*JSRuntime) void;
pub extern fn JS_NewRuntime2(mf: ?*const JSMallocFunctions, user_data: ?*anyopaque) ?*JSRuntime;
pub extern fn JS_FreeRuntime(rt: ?*JSRuntime) void;
pub extern fn JS_GetRuntimeOpaque(rt: ?*JSRuntime) ?*anyopaque;
pub extern fn JS_SetRuntimeOpaque(rt: ?*JSRuntime, data: ?*anyopaque) void;
pub extern fn JS_RunGC(rt: ?*JSRuntime) void;

// ---------------------------------------------------------------------------
// Context lifecycle
// ---------------------------------------------------------------------------

pub extern fn JS_NewContext(rt: ?*JSRuntime) ?*JSContext;
pub extern fn JS_FreeContext(s: ?*JSContext) void;
pub extern fn JS_DupContext(ctx: ?*JSContext) ?*JSContext;
pub extern fn JS_GetContextOpaque(ctx: ?*JSContext) ?*anyopaque;
pub extern fn JS_SetContextOpaque(ctx: ?*JSContext, data: ?*anyopaque) void;
pub extern fn JS_GetRuntime(ctx: ?*JSContext) ?*JSRuntime;
pub extern fn JS_SetClassProto(ctx: ?*JSContext, class_id: JSClassID, obj: JSValue) void;
pub extern fn JS_GetClassProto(ctx: ?*JSContext, class_id: JSClassID) JSValue;

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

pub extern fn JS_Eval(
    ctx: ?*JSContext,
    input: [*:0]const u8,
    input_len: usize,
    filename: [*:0]const u8,
    eval_flags: c_int,
) JSValue;

pub extern fn JS_EvalThis(
    ctx: ?*JSContext,
    this_obj: JSValue,
    input: [*:0]const u8,
    input_len: usize,
    filename: [*:0]const u8,
    eval_flags: c_int,
) JSValue;

pub extern fn JS_DetectModule(input: [*:0]const u8, input_len: usize) bool;
pub extern fn JS_EvalFunction(ctx: ?*JSContext, fun_obj: JSValue) JSValue;

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

pub extern fn JS_Throw(ctx: ?*JSContext, obj: JSValue) JSValue;
pub extern fn JS_GetException(ctx: ?*JSContext) JSValue;
pub extern fn JS_HasException(ctx: ?*JSContext) bool;
pub extern fn JS_IsError(ctx: ?*JSContext, val: JSValue) bool;
pub extern fn JS_NewError(ctx: ?*JSContext) JSValue;

pub extern fn JS_ThrowSyntaxError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_ThrowTypeError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_ThrowReferenceError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_ThrowRangeError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_ThrowInternalError(ctx: ?*JSContext, fmt: [*:0]const u8, ...) JSValue;
pub extern fn JS_ThrowOutOfMemory(ctx: ?*JSContext) JSValue;

// ---------------------------------------------------------------------------
// Value conversion
// ---------------------------------------------------------------------------

pub extern fn JS_ToBool(ctx: ?*JSContext, val: JSValue) c_int;
pub extern fn JS_ToInt32(ctx: ?*JSContext, pres: ?*i32, val: JSValue) c_int;
pub extern fn JS_ToInt64(ctx: ?*JSContext, pres: ?*i64, val: JSValue) c_int;
pub extern fn JS_ToFloat64(ctx: ?*JSContext, pres: ?*f64, val: JSValue) c_int;
pub extern fn JS_ToBigInt64(ctx: ?*JSContext, pres: ?*i64, val: JSValue) c_int;
pub extern fn JS_ToIndex(ctx: ?*JSContext, plen: ?*u64, val: JSValue) c_int;

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

pub extern fn JS_NewStringLen(ctx: ?*JSContext, str: [*:0]const u8, len: usize) JSValue;
pub extern fn JS_NewAtomString(ctx: ?*JSContext, str: [*:0]const u8) JSValue;
pub extern fn JS_ToString(ctx: ?*JSContext, val: JSValue) JSValue;
pub extern fn JS_ToPropertyKey(ctx: ?*JSContext, val: JSValue) JSValue;
pub extern fn JS_ToCStringLen2(ctx: ?*JSContext, len: ?*usize, val: JSValue, cesu8: bool) ?[*:0]const u8;
pub extern fn JS_FreeCString(ctx: ?*JSContext, ptr: [*:0]const u8) void;

// ---------------------------------------------------------------------------
// Object creation
// ---------------------------------------------------------------------------

pub extern fn JS_NewObject(ctx: ?*JSContext) JSValue;
pub extern fn JS_NewObjectClass(ctx: ?*JSContext, class_id: c_int) JSValue;
pub extern fn JS_NewObjectProto(ctx: ?*JSContext, proto: JSValue) JSValue;
pub extern fn JS_NewObjectProtoClass(ctx: ?*JSContext, proto: JSValue, class_id: JSClassID) JSValue;
pub extern fn JS_NewArray(ctx: ?*JSContext) JSValue;
pub extern fn JS_NewDate(ctx: ?*JSContext, epoch_ms: f64) JSValue;

// ---------------------------------------------------------------------------
// Property access — by name (C string)
// ---------------------------------------------------------------------------

pub extern fn JS_GetPropertyStr(ctx: ?*JSContext, this_obj: JSValue, prop: [*:0]const u8) JSValue;
pub extern fn JS_SetPropertyStr(ctx: ?*JSContext, this_obj: JSValue, prop: [*:0]const u8, val: JSValue) c_int;

// ---------------------------------------------------------------------------
// Property access — by index
// ---------------------------------------------------------------------------

pub extern fn JS_GetPropertyUint32(ctx: ?*JSContext, this_obj: JSValue, idx: u32) JSValue;
pub extern fn JS_SetPropertyUint32(ctx: ?*JSContext, this_obj: JSValue, idx: u32, val: JSValue) c_int;
pub extern fn JS_SetPropertyInt64(ctx: ?*JSContext, this_obj: JSValue, idx: i64, val: JSValue) c_int;

// ---------------------------------------------------------------------------
// Property access — by atom
// ---------------------------------------------------------------------------

pub extern fn JS_HasProperty(ctx: ?*JSContext, this_obj: JSValue, atom: JSAtom) c_int;
pub extern fn JS_IsExtensible(ctx: ?*JSContext, obj: JSValue) c_int;
pub extern fn JS_PreventExtensions(ctx: ?*JSContext, obj: JSValue) c_int;
pub extern fn JS_DeleteProperty(ctx: ?*JSContext, obj: JSValue, atom: JSAtom, flags: c_int) c_int;
pub extern fn JS_GetPrototype(ctx: ?*JSContext, val: JSValue) JSValue;
pub extern fn JS_SetPrototype(ctx: ?*JSContext, obj: JSValue, proto_val: JSValue) c_int;

// ---------------------------------------------------------------------------
// Global object
// ---------------------------------------------------------------------------

pub extern fn JS_GetGlobalObject(ctx: ?*JSContext) JSValue;

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

pub extern fn JS_NewCFunctionData(
    ctx: ?*JSContext,
    func: JSCFunctionData,
    length: c_int,
    magic: c_int,
    data_len: c_int,
    data: [*]JSValue,
) JSValue;

pub extern fn JS_SetConstructor(ctx: ?*JSContext, func_obj: JSValue, proto: JSValue) c_int;

// ---------------------------------------------------------------------------
// Function calls
// ---------------------------------------------------------------------------

pub extern fn JS_Call(
    ctx: ?*JSContext,
    func_obj: JSValue,
    this_obj: JSValue,
    argc: c_int,
    argv: [*]JSValue,
) JSValue;

pub extern fn JS_Invoke(
    ctx: ?*JSContext,
    this_val: JSValue,
    atom: JSAtom,
    argc: c_int,
    argv: [*]JSValue,
) JSValue;

pub extern fn JS_CallConstructor(
    ctx: ?*JSContext,
    func_obj: JSValue,
    argc: c_int,
    argv: [*]JSValue,
) JSValue;

pub extern fn JS_CallConstructor2(
    ctx: ?*JSContext,
    func_obj: JSValue,
    new_target: JSValue,
    argc: c_int,
    argv: [*]JSValue,
) JSValue;

pub extern fn JS_IsInstanceOf(ctx: ?*JSContext, val: JSValue, obj: JSValue) c_int;
pub extern fn JS_IsFunction(ctx: ?*JSContext, val: JSValue) bool;
pub extern fn JS_IsConstructor(ctx: ?*JSContext, val: JSValue) bool;

// ---------------------------------------------------------------------------
// Strict equality
// ---------------------------------------------------------------------------

pub extern fn JS_StrictEq(ctx: ?*JSContext, op1: JSValue, op2: JSValue) bool;
pub extern fn JS_SameValue(ctx: ?*JSContext, op1: JSValue, op2: JSValue) bool;
pub extern fn JS_SameValueZero(ctx: ?*JSContext, op1: JSValue, op2: JSValue) bool;

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

pub extern fn JS_ParseJSON(ctx: ?*JSContext, buf: [*:0]const u8, buf_len: usize, filename: [*:0]const u8) JSValue;
pub extern fn JS_ParseJSON2(ctx: ?*JSContext, buf: [*:0]const u8, buf_len: usize, filename: [*:0]const u8, flags: c_int) JSValue;
pub extern fn JS_JSONStringify(ctx: ?*JSContext, obj: JSValue, replacer: JSValue, space: JSValue) JSValue;

// ---------------------------------------------------------------------------
// Jobs / promises
// ---------------------------------------------------------------------------

pub extern fn JS_EnqueueJob(ctx: ?*JSContext, job_func: *const fn (?*JSContext, c_int, [*]JSValue) callconv(.c) JSValue, argc: c_int, argv: [*]JSValue) c_int;
pub extern fn JS_IsJobPending(rt: ?*JSRuntime) bool;
pub extern fn JS_ExecutePendingJob(rt: ?*JSRuntime, pctx: ?*?*JSContext) c_int;

// ---------------------------------------------------------------------------
// Module support
// ---------------------------------------------------------------------------

pub extern fn JS_SetModuleLoaderFunc(
    rt: ?*JSRuntime,
    module_normalize: ?*const fn (?*JSContext, [*:0]const u8, [*:0]const u8, ?*anyopaque) callconv(.c) ?[*:0]const u8,
    module_loader: ?*const fn (?*JSContext, [*:0]const u8, ?*anyopaque) callconv(.c) ?*JSModuleDef,
    user_data: ?*anyopaque,
) void;

pub extern fn JS_GetImportMeta(ctx: ?*JSContext, m: ?*JSModuleDef) JSValue;
pub extern fn JS_GetModuleName(ctx: ?*JSContext, m: ?*JSModuleDef) JSAtom;
pub extern fn JS_GetModuleNamespace(ctx: ?*JSContext, m: ?*JSModuleDef) JSValue;

pub extern fn JS_NewCModule(ctx: ?*JSContext, name_str: [*:0]const u8, func: *const fn (?*JSContext, ?*JSModuleDef) callconv(.c) c_int) ?*JSModuleDef;
pub extern fn JS_AddModuleExport(ctx: ?*JSContext, m: ?*JSModuleDef, name_str: [*:0]const u8) c_int;

// ---------------------------------------------------------------------------
// Class support
// ---------------------------------------------------------------------------

pub extern fn JS_NewClassID(pclass_id: ?*JSClassID) JSClassID;
pub extern fn JS_NewClass(rt: ?*JSRuntime, class_id: JSClassID, class_def: ?*const JSClassDef) c_int;
pub extern fn JS_GetClassID(v: JSValue) JSClassID;

// ---------------------------------------------------------------------------
// Opaque data on objects
// ---------------------------------------------------------------------------

pub extern fn JS_SetOpaque(obj: JSValue, data: ?*anyopaque) void;
pub extern fn JS_GetOpaque(obj: JSValue, class_id: JSClassID) ?*anyopaque;
pub extern fn JS_GetOpaque2(ctx: ?*JSContext, obj: JSValue, class_id: JSClassID) ?*anyopaque;

// ---------------------------------------------------------------------------
// ArrayBuffer / TypedArray
// ---------------------------------------------------------------------------

pub extern fn JS_NewArrayBufferCopy(ctx: ?*JSContext, buf: [*]const u8, len: usize) JSValue;
pub extern fn JS_GetArrayBuffer(ctx: ?*JSContext, psize: ?*usize, obj: JSValue) ?[*]u8;
pub extern fn JS_DetachArrayBuffer(ctx: ?*JSContext, obj: JSValue) void;

// ---------------------------------------------------------------------------
// Serialization (bytecode read/write)
// ---------------------------------------------------------------------------

pub extern fn JS_WriteObject(ctx: ?*JSContext, psize: ?*usize, obj: JSValue, flags: c_int) ?[*]u8;
pub extern fn JS_ReadObject(ctx: ?*JSContext, buf: [*]const u8, buf_len: usize, flags: c_int) JSValue;

// ---------------------------------------------------------------------------
// Interrupt handler
// ---------------------------------------------------------------------------

pub extern fn JS_SetInterruptHandler(rt: ?*JSRuntime, cb: ?*const fn (?*JSRuntime, ?*anyopaque) callconv(.c) c_int, user_data: ?*anyopaque) void;

// ---------------------------------------------------------------------------
// Memory stats
// ---------------------------------------------------------------------------

pub extern fn JS_ComputeMemoryUsage(rt: ?*JSRuntime, s: ?*JSMemoryUsage) void;

// ---------------------------------------------------------------------------
// Reference-counted extern symbols (called by the inline wrappers above)
// ---------------------------------------------------------------------------

extern fn __JS_FreeValue(ctx: ?*JSContext, v: JSValue) void;
extern fn __JS_FreeValueRT(rt: ?*JSRuntime, v: JSValue) void;

// ===========================================================================
// Supporting structs referenced by function declarations above.
// ===========================================================================

pub const JSMallocState = extern struct {
    malloc_count: usize,
    malloc_size: usize,
    malloc_limit: usize,
    user_data: ?*anyopaque,
};

pub const JSMallocFunctions = extern struct {
    js_malloc: *const fn (s: ?*JSMallocState, size: usize) callconv(.c) ?*anyopaque,
    js_free: *const fn (s: ?*JSMallocState, ptr: ?*anyopaque) callconv(.c) void,
    js_realloc: *const fn (s: ?*JSMallocState, ptr: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque,
    js_malloc_usable_size: *const fn (ptr: ?*const anyopaque) callconv(.c) usize,
};

pub const JSClassDef = extern struct {
    class_name: [*:0]const u8,
    finalizer: ?*const fn (?*JSRuntime, JSValue) callconv(.c) void,
    gc_mark: ?*anyopaque, // JSClassGCMark — opaque to avoid complex callback type
    call: ?*anyopaque, // JSClassCall — opaque
    exotic: ?*anyopaque, // JSClassExoticMethods — opaque
};

pub const JSMemoryUsage = extern struct {
    malloc_size: i64,
    malloc_limit: i64,
    memory_used_size: i64,
    malloc_count: i64,
    memory_used_count: i64,
    atom_count: i64,
    atom_size: i64,
    str_count: i64,
    str_size: i64,
    obj_count: i64,
    obj_size: i64,
    prop_count: i64,
    prop_size: i64,
    shape_count: i64,
    shape_size: i64,
    js_func_count: i64,
    js_func_size: i64,
    js_func_code_size: i64,
    js_func_pc2line_count: i64,
    js_func_pc2line_size: i64,
    c_func_count: i64,
    array_count: i64,
    fast_array_count: i64,
    fast_array_elements: i64,
    binary_object_count: i64,
    binary_object_size: i64,
};

pub const JSSharedArrayBufferFunctions = extern struct {
    sab_alloc: ?*const fn (?*anyopaque, usize) callconv(.c) ?*anyopaque,
    sab_free: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void,
    sab_dup: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void,
    sab_user_data: ?*anyopaque,
};
