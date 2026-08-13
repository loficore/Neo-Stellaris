// quickjs_wrapper.c — Thin wrapper to export static-inline QuickJS functions
// as real linker symbols for Zig's extern declarations.
//
// The QuickJS header defines JS_FreeValue, JS_DupValue, JS_NewString as
// static inline functions with no exported symbols. Zig's extern declarations
// expect actual linker symbols, so we provide them here by forward-declaring
// the required types and wrapping the actual implementations.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Forward-declare QuickJS types to avoid including the header
// (which defines static inline functions that conflict with our wrappers)
typedef struct JSRuntime JSRuntime;
typedef struct JSContext JSContext;

typedef union JSValueUnion {
    int32_t i32;
    uint32_t u32;
    double f64;
    void *ptr;
} JSValueUnion;

typedef struct JSValue {
    JSValueUnion u;
    int64_t tag;
} JSValue;

typedef JSValue JSValueConst;

// Ref-count header (from quickjs internals)
typedef struct JSRefCountHeader {
    uint32_t ref_count;
} JSRefCountHeader;

// Internal macros/functions we need
#define JS_VALUE_HAS_REF_COUNT(v) (((uint32_t)((v).tag)) >= (uint32_t)7)
#define JS_VALUE_GET_PTR(v) ((v).u.ptr)
static inline JSRefCountHeader *__js_rc(void *p) {
    return &((JSRefCountHeader *)p)[-1];
}

// Actual symbols from the QuickJS library
extern void __JS_FreeValue(JSContext *ctx, JSValue v);
extern JSValue JS_NewStringLen(JSContext *ctx, const char *str1, size_t len1);

// Wrapper implementations
void JS_FreeValue(JSContext *ctx, JSValue v) {
    __JS_FreeValue(ctx, v);
}

JSValue JS_DupValue(JSContext *ctx, JSValue v) {
    if (JS_VALUE_HAS_REF_COUNT(v)) {
        JSRefCountHeader *p = __js_rc(JS_VALUE_GET_PTR(v));
        p->ref_count++;
    }
    return v;
}

JSValue JS_NewString(JSContext *ctx, const char *str) {
    return JS_NewStringLen(ctx, str, strlen(str));
}
