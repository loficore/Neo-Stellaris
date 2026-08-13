// quickjs_stubs.c — Minimal stub implementations for QuickJS C functions.
// These allow the Zig DLL to compile and link. Replace with real QuickJS library
// when available.
//
// To use real QuickJS:
// 1. Download QuickJS source from https://bellard.org/quickjs/
// 2. Build as static library
// 3. Link against it instead of these stubs

#include <stdint.h>
#include <stddef.h>

// Opaque types
typedef struct JSRuntime JSRuntime;
typedef struct JSContext JSContext;

typedef union JSValueUnion {
    int32_t i32;
    uint32_t u32;
    double f64;
    void* ptr;
} JSValueUnion;

typedef struct JSValue {
    JSValueUnion u;
    int64_t tag;
} JSValue;

// Lifecycle stubs
JSRuntime* JS_NewRuntime(void) {
    return NULL;  // Stub - returns NULL
}

JSContext* JS_NewContext(JSRuntime* rt) {
    (void)rt;
    return NULL;  // Stub - returns NULL
}

void JS_FreeContext(JSContext* ctx) {
    (void)ctx;
}

void JS_FreeRuntime(JSRuntime* rt) {
    (void)rt;
}

// Evaluation stub
JSValue JS_Eval(JSContext* ctx, const char* code, size_t code_len, const char* filename, int eval_flags) {
    (void)ctx;
    (void)code;
    (void)code_len;
    (void)filename;
    (void)eval_flags;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}

// Value management stubs
void JS_FreeValue(JSContext* ctx, JSValue val) {
    (void)ctx;
    (void)val;
}

JSValue JS_DupValue(JSContext* ctx, JSValue val) {
    (void)ctx;
    return val;
}

// String stubs
JSValue JS_NewString(JSContext* ctx, const char* str) {
    (void)ctx;
    (void)str;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}

JSValue JS_ToString(JSContext* ctx, JSValue val) {
    (void)ctx;
    (void)val;
    JSValue val2 = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val2;
}

const char* JS_ToCStringLen2(JSContext* ctx, size_t* len, JSValue val, int ascii) {
    (void)ctx;
    (void)len;
    (void)val;
    (void)ascii;
    return "";  // Stub
}

void JS_FreeCString(JSContext* ctx, const char* str) {
    (void)ctx;
    (void)str;
}

// Error stubs
JSValue JS_ThrowTypeError(JSContext* ctx, const char* fmt, ...) {
    (void)ctx;
    (void)fmt;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}

JSValue JS_GetException(JSContext* ctx) {
    (void)ctx;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}

// Function registration stubs
JSValue JS_NewCFunction2(JSContext* ctx, void* func, const char* name, int length, int cproto, int magic) {
    (void)ctx;
    (void)func;
    (void)name;
    (void)length;
    (void)cproto;
    (void)magic;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}

int JS_SetPropertyStr(JSContext* ctx, JSValue this_obj, const char* prop, JSValue val) {
    (void)ctx;
    (void)this_obj;
    (void)prop;
    (void)val;
    return 0;
}

// Runtime configuration stubs
void JS_SetMaxStackSize(JSRuntime* rt, size_t stack_size) {
    (void)rt;
    (void)stack_size;
}

void JS_SetMemoryLimit(JSRuntime* rt, size_t mem_limit) {
    (void)rt;
    (void)mem_limit;
}

// Global object stub
JSValue JS_GetGlobalObject(JSContext* ctx) {
    (void)ctx;
    JSValue val = { .u = { .i32 = 0 }, .tag = 1 };  // undefined
    return val;
}
