/* abi_probe.c — §65 C-side probe: two-sided layout contract + call stubs.
 *
 * NOT linked into the shipped DLL. Built only by the non-default step
 * `zig build abi-probe` into zig-out/bin/abi_probe_c.dll.
 *
 * The contract under test: quickjs_wrapper.c does NOT include quickjs.h —
 * it hand-copies JSValueUnion/JSValue (quickjs_wrapper.c:43-53), and
 * bindings.zig:97-176 hand-copies the same layout in Zig. So the asserts
 * below fire on BOTH definitions: the real one (via quickjs.h) and a
 * hand-copied twin shaped after bindings.zig.
 *
 * Each probe_export_* function makes exactly one real call to its QuickJS
 * symbol so the compiler emits a call stub whose parameter assembly can be
 * compared against the Zig side (compare_stubs.py). Stubs are never run.
 */
#include <stddef.h>
#include <stdint.h>
#include "quickjs.h"

/* --- Contract on the REAL quickjs.h definition --- */
_Static_assert(sizeof(JSValue) == 16, "real JSValue size");
_Static_assert(__builtin_offsetof(JSValue, u) == 0, "real JSValue.u offset");
_Static_assert(__builtin_offsetof(JSValue, tag) == 8, "real JSValue.tag offset");
/* Every union member is <= 8 B, so the union itself is 8, not 16:
 * JSValue's 16 = u(8) + tag(8). */
_Static_assert(sizeof(JSValueUnion) == 8, "real JSValueUnion size");

/* --- Hand-copied twin, shaped after bindings.zig:82-89 + :97-99 --- */
typedef union ProbeJSValueUnion {
    uint64_t uint64;
    int32_t  i32;
    uint32_t u32;
    double   f64;
    double   float64;
    void    *ptr;
    int64_t  short_big_int;
} ProbeJSValueUnion;

typedef struct ProbeJSValue {
    ProbeJSValueUnion u;
    int64_t           tag;
} ProbeJSValue;

_Static_assert(sizeof(ProbeJSValueUnion) == 8, "twin JSValueUnion size");
_Static_assert(sizeof(ProbeJSValue) == 16, "twin JSValue size");
_Static_assert(__builtin_offsetof(ProbeJSValue, u) == 0, "twin u offset");
_Static_assert(__builtin_offsetof(ProbeJSValue, tag) == 8, "twin tag offset");

/* The twin must also be interchangeable with the real thing. */
_Static_assert(_Alignof(ProbeJSValue) == _Alignof(JSValue), "twin alignment");

#define EXPORT __attribute__((dllexport))

/* Pure-pointer baselines (comparison only, never a verdict): */
EXPORT JSRuntime *probe_JS_NewRuntime(void) {
    return JS_NewRuntime();
}
EXPORT JSRuntime *probe_JS_NewRuntime2(void) {
    return JS_NewRuntime2(NULL, NULL);
}
EXPORT void probe_JS_UpdateStackTop(JSRuntime *rt) {
    JS_UpdateStackTop(rt);
}

/* By-value / by-struct-return JSValue signatures — the verdict set: */
EXPORT JSValue probe_JS_Eval(JSContext *ctx) {
    static const char src[] = "1";
    static const char fname[] = "<probe>";
    return JS_Eval(ctx, src, sizeof(src) - 1, fname, 0);
}
EXPORT int probe_JS_ToInt32(JSContext *ctx, int32_t *pres) {
    JSValue v = JS_MKVAL(JS_TAG_INT, 1);
    return JS_ToInt32(ctx, pres, v);
}
EXPORT JSValue probe_JS_Call(JSContext *ctx, JSValue *argv) {
    JSValue f = JS_UNDEFINED;
    JSValue t = JS_UNDEFINED;
    return JS_Call(ctx, f, t, 1, argv);
}
EXPORT void probe___JS_FreeValue(JSContext *ctx) {
    JSValue v = JS_MKVAL(JS_TAG_OBJECT, 0);
    __JS_FreeValue(ctx, v);
}
