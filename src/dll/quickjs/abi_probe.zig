//! abi_probe.zig — §65 Zig-side probe: forces a real call to every extern the
//! brief names, so the compiler emits call stubs for static comparison against
//! abi_probe.c's stubs (scripts/scratch/2026-10_abi_probe/compare_stubs.py).
//!
//! NOT linked into the shipped DLL; built only by `zig build abi-probe`.
//! Stubs are never executed.
//!
//! Scope ruling (SDD ledger Task 5): the brief's "every extern" is taken as
//! its own named set (JS_NewRuntime, JS_NewRuntime2, JS_UpdateStackTop,
//! JS_Eval, JS_ToInt32, JS_Call, __JS_FreeValue); variadic JS_Throw*Error
//! bindings are excluded from both sides. `__JS_FreeValue` is file-private in
//! bindings.zig:623, so it is re-declared here with an identical signature.
const std = @import("std");
const qjs = @import("bindings.zig");

comptime {
    std.debug.assert(@sizeOf(qjs.JSValue) == 16);
    std.debug.assert(@sizeOf(qjs.JSValueUnion) == 8);
    std.debug.assert(@offsetOf(qjs.JSValue, "u") == 0);
    std.debug.assert(@offsetOf(qjs.JSValue, "tag") == 8);
}

extern fn __JS_FreeValue(ctx: ?*qjs.JSContext, v: qjs.JSValue) void;

export var rt_sink: ?*qjs.JSRuntime = null;
export var i32_sink: i32 = 0;
export var val_sink: qjs.JSValue = .{};
export var rc_sink: c_int = 0;

export fn probe_JS_NewRuntime() void {
    rt_sink = qjs.JS_NewRuntime();
}

export fn probe_JS_NewRuntime2() void {
    rt_sink = qjs.JS_NewRuntime2(null, null);
}

export fn probe_JS_UpdateStackTop(rt: ?*qjs.JSRuntime) void {
    qjs.JS_UpdateStackTop(rt);
}

const eval_src = "1\x00";
const eval_name = "<probe>\x00";

export fn probe_JS_Eval(ctx: ?*qjs.JSContext) void {
    val_sink = qjs.JS_Eval(ctx, eval_src, eval_src.len - 1, eval_name, 0);
}

export fn probe_JS_ToInt32(ctx: ?*qjs.JSContext, pres: ?*i32) void {
    const v = qjs.JSValue.int32(1);
    rc_sink = qjs.JS_ToInt32(ctx, pres, v);
}

export fn probe_JS_Call(ctx: ?*qjs.JSContext, argv: [*]qjs.JSValue) void {
    const f = qjs.JSValue.undefinedVal();
    const t = qjs.JSValue.undefinedVal();
    val_sink = qjs.JS_Call(ctx, f, t, 1, argv);
}

export fn probe___JS_FreeValue(ctx: ?*qjs.JSContext) void {
    const v: qjs.JSValue = .{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(qjs.JSValueTag.object) };
    __JS_FreeValue(ctx, v);
}
