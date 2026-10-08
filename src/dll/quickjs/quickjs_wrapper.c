// quickjs_wrapper.c — Thin wrapper to export static-inline QuickJS functions
// as real linker symbols for Zig's extern declarations.
//
// IMPORTANT: Zig's libc malloc doesn't work in DLL injection context
// (CreateRemoteThread or even _beginthreadex). We use Windows HeapAlloc
// as the allocator for QuickJS via JS_NewRuntime2.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
/* Native (non-Windows) shims so this file — and the exact same step sequence of
 * C2DiagQuickJS/C2TestQuickJS — can be compiled and run on the Linux host as
 * part of `zig build test`. The Windows build path is byte-identical: all of
 * this is inside #ifdef _WIN32 guards. */
#include <stdlib.h>
typedef void *HANDLE;
#define GetProcessHeap() ((HANDLE)1)
static void *HeapAlloc(HANDLE heap, unsigned flags, size_t size) {
    (void)heap; (void)flags;
    return malloc(size);
}
static void HeapFree(HANDLE heap, unsigned flags, void *ptr) {
    (void)heap; (void)flags;
    free(ptr);
}
static void *HeapReAlloc(HANDLE heap, unsigned flags, void *ptr, size_t size) {
    (void)heap; (void)flags;
    return realloc(ptr, size);
}
#endif

// Forward-declare QuickJS types
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

typedef struct JSRefCountHeader {
    uint32_t ref_count;
} JSRefCountHeader;

#define JS_VALUE_HAS_REF_COUNT(v) (((uint32_t)((v).tag)) >= (uint32_t)7)
#define JS_VALUE_GET_PTR(v) ((v).u.ptr)
static inline JSRefCountHeader *__js_rc(void *p) {
    return &((JSRefCountHeader *)p)[-1];
}

// JSMallocState and JSMallocFunctions from quickjs.h
typedef struct JSMallocState {
    size_t malloc_count;
    size_t malloc_size;
    size_t malloc_limit;
    void *opaque;
} JSMallocState;

typedef struct JSMallocFunctions {
    void *(*js_malloc)(JSMallocState *s, size_t size);
    void (*js_free)(JSMallocState *s, void *ptr);
    void *(*js_realloc)(JSMallocState *s, void *ptr, size_t size);
    size_t (*js_malloc_usable_size)(const void *ptr);
} JSMallocFunctions;

// QuickJS symbols
extern void __JS_FreeValue(JSContext *ctx, JSValue v);
extern JSValue JS_NewStringLen(JSContext *ctx, const char *str1, size_t len1);
extern JSRuntime *JS_NewRuntime2(const JSMallocFunctions *mf, void *opaque);
extern JSContext *JS_NewContext(JSRuntime *rt);
extern JSContext *JS_NewContextRaw(JSRuntime *rt);
extern void JS_FreeContext(JSContext *ctx);
extern void JS_FreeRuntime(JSRuntime *rt);
extern void JS_SetMaxStackSize(JSRuntime *rt, size_t stack_size);
extern void JS_SetMemoryLimit(JSRuntime *rt, size_t limit);
extern void *JS_GetRuntimeOpaque(JSRuntime *rt);
extern void JS_SetRuntimeOpaque(JSRuntime *rt, void *opaque);
extern int JS_NewContextDiag(JSRuntime *rt, JSContext **out_ctx);

// Wrapper implementations for static-inline functions
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

// ---------------------------------------------------------------------------
// Windows Heap-based allocator for QuickJS
// ---------------------------------------------------------------------------

// Header prepended to each allocation to track size
typedef struct {
    size_t size;  // usable size (not including header)
} AllocHeader;

static void *heap_malloc(JSMallocState *s, size_t size) {
    if (size == 0) return NULL;
    if (s->malloc_size + size > s->malloc_limit) return NULL;
    
    HANDLE heap = GetProcessHeap();
    AllocHeader *h = (AllocHeader *)HeapAlloc(heap, 0, sizeof(AllocHeader) + size);
    if (!h) return NULL;
    
    h->size = size;
    s->malloc_count++;
    s->malloc_size += size;
    return (void *)(h + 1);
}

static void heap_free(JSMallocState *s, void *ptr) {
    if (!ptr) return;
    
    AllocHeader *h = ((AllocHeader *)ptr) - 1;
    /* Read the recorded size BEFORE releasing the block. After HeapFree the
       heap manager owns the block: it writes free-list links into the user
       area (and for tail blocks may decommit the pages), so reading h->size
       afterwards is a use-after-free — it fed a garbage (or unmapped) value
       into s->malloc_size, underflowing the counter to ~2^64, which made
       every subsequent heap_malloc fail its limit check (QuickJS OOM,
       JS_AddIntrinsicBaseObjects rc=2) — see evidence §33. */
    size_t freed = h->size;
    HANDLE heap = GetProcessHeap();
    HeapFree(heap, 0, h);
    
    s->malloc_count--;
    s->malloc_size -= freed;
}

static void *heap_realloc(JSMallocState *s, void *ptr, size_t size) {
    if (!ptr) return heap_malloc(s, size);
    if (size == 0) {
        heap_free(s, ptr);
        return NULL;
    }
    
    AllocHeader *h = ((AllocHeader *)ptr) - 1;
    size_t old_size = h->size;
    
    if (s->malloc_size - old_size + size > s->malloc_limit) return NULL;
    
    HANDLE heap = GetProcessHeap();
    AllocHeader *new_h = (AllocHeader *)HeapReAlloc(heap, 0, h, sizeof(AllocHeader) + size);
    if (!new_h) return NULL;
    
    new_h->size = size;
    s->malloc_size = s->malloc_size - old_size + size;
    return (void *)(new_h + 1);
}

static size_t heap_malloc_usable_size(const void *ptr) {
    if (!ptr) return 0;
    const AllocHeader *h = ((const AllocHeader *)ptr) - 1;
    return h->size;
}

static const JSMallocFunctions heap_mf = {
    heap_malloc,
    heap_free,
    heap_realloc,
    heap_malloc_usable_size,
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static JSRuntime *g_test_rt = NULL;
static JSContext *g_test_ctx = NULL;
static char g_diag_log[512];

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

// Sanity check: returns a constant that proves the new code is loaded.
int C2SanityCheck(void) {
    return 42;
}

int C2TestQuickJS(void) {
    g_test_rt = NULL;
    g_test_ctx = NULL;

    // Step 0: test heap
    HANDLE heap = GetProcessHeap();
    if (!heap) return 10;
    void *test_p = HeapAlloc(heap, 0, 256);
    if (!test_p) return 11;
    HeapFree(heap, 0, test_p);

    // Step 1: Create runtime with custom heap allocator
    g_test_rt = JS_NewRuntime2(&heap_mf, NULL);
    if (!g_test_rt) return 2;

    // Step 2: Test opaque
    JS_SetRuntimeOpaque(g_test_rt, (void *)(uintptr_t)0xDEADBEEF);
    void *opaque = JS_GetRuntimeOpaque(g_test_rt);
    if (opaque != (void *)(uintptr_t)0xDEADBEEF) return 3;

    // Step 3: Configure
    JS_SetMaxStackSize(g_test_rt, 1024 * 1024);
    JS_SetMemoryLimit(g_test_rt, 256 * 1024 * 1024);

    // Step 4: Try raw context
    JSContext *raw_ctx = JS_NewContextRaw(g_test_rt);
    if (!raw_ctx) return 4;
    JS_FreeContext(raw_ctx);

    // Step 5: Full context with diag
    int diag_rc = JS_NewContextDiag(g_test_rt, &g_test_ctx);
    return diag_rc;  // 0 = success, 1-12 = intrinsic failure
}

int C2DiagQuickJS(char *out_diag, int diag_size) {
    g_test_rt = NULL;
    g_test_ctx = NULL;
    g_diag_log[0] = '\0';
    int result = 0;
    int pos = 0;
    /* snprintf returns the WOULD-BE length, so an unguarded `pos +=` can
       overshoot 512; a later `512 - pos` would then be negative (huge size_t)
       and g_diag_log + pos would be past the end of the static. Clamp pos to
       stay within the buffer forever. (Not the crash cause for the 2026-10-08
       run — the actual log content is ~90 bytes max — but a latent overflow
       the moment more steps are logged.) */
    #define DLOG(...) do { \
        int n_ = snprintf(g_diag_log + pos, 512 - pos, __VA_ARGS__); \
        if (n_ < 0) n_ = 0; \
        pos += n_; \
        if (pos > 511) pos = 511; \
    } while(0)

    HANDLE heap = GetProcessHeap();
    if (!heap) { DLOG("no_process_heap"); result = 10; goto finish; }
    void *test_p = HeapAlloc(heap, 0, 256);
    if (!test_p) { DLOG("heap_alloc_failed"); result = 11; goto finish; }
    HeapFree(heap, 0, test_p);

    g_test_rt = JS_NewRuntime2(&heap_mf, NULL);
    if (!g_test_rt) { DLOG("runtime2_null"); result = 2; goto finish; }
    DLOG("rt=%p ", g_test_rt);

    JS_SetRuntimeOpaque(g_test_rt, (void *)(uintptr_t)0xDEADBEEF);
    void *opaque = JS_GetRuntimeOpaque(g_test_rt);
    if (opaque != (void *)(uintptr_t)0xDEADBEEF) {
        DLOG("opaque_mismatch got=%p", opaque);
        result = 3; goto finish;
    }

    JS_SetMaxStackSize(g_test_rt, 1024 * 1024);
    JS_SetMemoryLimit(g_test_rt, 256 * 1024 * 1024);

    JSContext *raw_ctx = JS_NewContextRaw(g_test_rt);
    if (!raw_ctx) { DLOG("raw_ctx_null"); result = 4; goto finish; }
    JS_FreeContext(raw_ctx);
    DLOG("raw_ok ");

    {
        int diag_rc = JS_NewContextDiag(g_test_rt, &g_test_ctx);
        DLOG("diag_rc=%d ctx=%p", diag_rc, g_test_ctx);
        result = diag_rc;
    }

finish:
    if (out_diag && diag_size > 0) {
        strncpy(out_diag, g_diag_log, diag_size - 1);
        out_diag[diag_size - 1] = '\0';
    }
    return result;
    #undef DLOG
}

void C2GetQuickJSPointers(void **out_rt, void **out_ctx) {
    *out_rt = g_test_rt;
    *out_ctx = g_test_ctx;
}

const char *C2DiagGetLog(void) {
    return g_diag_log;
}
