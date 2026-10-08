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

/* Tag constants copied from quickjs.h:77-94 — only the two this file needs.
   JS_TAG_FIRST = -9 is the boundary of the refcounted tags: quickjs.h:76 says
   "all tags with a reference count are negative", and quickjs.h:287 tests
   against JS_TAG_FIRST, NOT against any positive number. Tags 0..8
   (int/bool/null/undefined/uninitialized/catch_offset/exception/
   short_big_int/float64) carry their payload inline and are NEVER refcounted. */
#define JS_TAG_FIRST      (-9)
#define JS_TAG_EXCEPTION  6

#define JS_VALUE_GET_TAG(v) ((int32_t)(v).tag)
/* Mirrors quickjs.h:287 exactly: (unsigned)tag >= (unsigned)JS_TAG_FIRST is true
   for tags -9..-1 only (negative tags wrap above 0xFFFFFFF6, so the compare
   also rejects every positive tag). The previous `>= 7` spelling admitted
   JS_TAG_SHORT_BIG_INT (7) and JS_TAG_FLOAT64 (8), whose .u.ptr is the number's
   own bit pattern — reading it as an address made JS_DupValue write a refcount
   through a wild pointer (ruling P19, observed: quickjs_wrapper.c:104 faulted on
   a JS_TAG_FLOAT64 dup of 1.5 → address 0x3FF8000000000000 - 4). */
#define JS_VALUE_HAS_REF_COUNT(v) (((uint32_t)JS_VALUE_GET_TAG(v)) >= (uint32_t)JS_TAG_FIRST)
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
/* Mirrors quickjs.h:687-695: non-refcounted tags are a no-op, and a refcounted
   value is released by __JS_FreeValue only when the decrement takes it to zero.
   The previous unconditional `__JS_FreeValue(ctx, v)` was a second way to reach
   quickjs.c's `default: abort()` (quickjs.c:6473-6572) — __JS_FreeValueRT
   switches on the tag with cases only for the refcounted ones — so freeing the
   JS_TAG_INT result of JS_Eval("1+1"), or a JS_TAG_EXCEPTION, aborted the host
   process (ruling P19). It also ignored the refcount outright: a value held
   twice was released while a holder remained (observed natively).
   Note on `== 0` vs quickjs.h's `<= 0` (quickjs.h:691): the equivalence `<= 0`
   means `== 0` holds only of THIS file's header, whose JSRefCountHeader counts
   with uint32_t. The header this mirrors (quickjs.h:100) counts with a signed
   int ref_count, where `<= 0` and `== 0` diverge for an already non-positive
   count. The two forms agree for every well-formed value and differ only for
   an already-zero refcount, where quickjs.h would double-free and this
   releases nothing. */
void JS_FreeValue(JSContext *ctx, JSValue v) {
    if (JS_VALUE_HAS_REF_COUNT(v)) {
        JSRefCountHeader *p = __js_rc(JS_VALUE_GET_PTR(v));
        if (--p->ref_count == 0) {
            __JS_FreeValue(ctx, v);
        }
    }
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

/* Task 5 observation aid (ruling P4): write the FULL native-width pointers
 * into a caller-supplied 16-byte buffer — g_test_rt at out16+0, g_test_ctx at
 * out16+sizeof(void*) (both 8 bytes on x86-64, the only target). One argument
 * only because CreateRemoteThread passes exactly one lpParameter; the size is
 * baked into the contract, never passed. memcpy, not a void** store: the
 * caller's buffer has only byte alignment.
 *
 * The C link name is deliberately NOT the DLL's PE export name
 * `C2QuickJSPointersInto` (src/dll/exports.zig): Zig's `export fn` takes its
 * link symbol from the function identifier, and quickjs_wrapper.c is linked
 * into the same DLL — the same name twice is a duplicate-symbol link error
 * (verified). Read-only observation aids, not a permanent API (Task 5 brief). */
void C2WriteQuickJSPointersInto(unsigned char *out16) {
    void *rt = g_test_rt;
    void *ctx = g_test_ctx;
    memcpy(out16 + 0, &rt, sizeof(void *));
    memcpy(out16 + sizeof(void *), &ctx, sizeof(void *));
}

const char *C2DiagGetLog(void) {
    return g_diag_log;
}

/* ---------------------------------------------------------------------------
 * Task 6 — C2EvalProbe: the C2 acceptance gate.
 *
 * QuickJS symbols. Ruling P9: the brief's sketch names do not all exist — only
 * the genuinely-exported functions are declared here (quickjs.h:836, :730,
 * :669). `JS_IsException` (quickjs.h:641) and `JS_FreeValue` (quickjs.h:687) are
 * static inline and have NO linker symbol, so there is no `JS_IsException_` /
 * `JS_FreeValue_` to bind: the exception test below is reimplemented against the
 * tag and the free reuses THIS file's JS_FreeValue — which since the P19 fix is
 * the guarded one. No QuickJS symbol is bound on the Zig side (global
 * constraint); exports.zig externs only C2EvalProbe, our own wrapper.
 * ------------------------------------------------------------------------- */
extern JSValue JS_Eval(JSContext *ctx, const char *input, size_t input_len,
                       const char *filename, int eval_flags);
extern int JS_ToInt32(JSContext *ctx, int32_t *pres, JSValueConst val);
extern JSValue JS_GetException(JSContext *ctx);

/* Move a pending exception out of rt->current_exception and release it, so the
   moved-out exception value does not leak (quickjs.c:7406-7413; the slot would
   otherwise stay occupied until the next JS_Throw frees it). The justification
   here is leak prevention, not re-dispatchability: a second JS_Eval succeeds
   even with an exception pending. JS_FreeValue on the JS_UNINITIALIZED marker
   is a no-op under the P19 guard. */
static void c2_clear_pending_exception(JSContext *ctx) {
    JSValue exc = JS_GetException(ctx);
    JS_FreeValue(ctx, exc);
}

/* Evaluate `src` in g_test_ctx and encode the int32 result so a
 * CreateRemoteThread caller can read it back through the 32-bit thread exit
 * code:
 *      0          g_test_ctx is NULL — C2Init has not run in this module copy
 *      1          JS_Eval threw
 *      2          eval succeeded but JS_ToInt32 produced no int32
 *      n * 4 + 3  eval succeeded with int32 n; caller decodes (rc - 3) / 4
 * The ×4+3 keeps every encoded result congruent to 3 (mod 4), so no value of n
 * can be mistaken for one of the three sentinels. Ruling P20: `1+1` gives n = 2,
 * hence rc 11 — the brief's "1*4+3 = 7" was an arithmetic slip, the encoding is
 * the contract.
 *
 * Ruling P21 — the boundary this function is the first to cross: quickjs_wrapper.c
 * includes NO quickjs.h and hand-forwards JSValue (lines 43-55), and this is the
 * first code here to receive a real JSValue *by value* from QuickJS (JS_Eval's
 * result) and pass one back (JS_ToInt32's argument), in a TU compiled without the
 * header that defines the layout. It is legal only because quickjs.h:56-65 defines
 * JS_PTR64 on any platform with INTPTR_MAX >= INT64_MAX, which suppresses
 * JS_NAN_BOXING, so x86-64 uses the 16-byte {union u; int64_t tag;} struct of
 * quickjs.h:216-232 — byte-compatible with the hand-forwarded one (its union is
 * 8 bytes either way). Both the Windows DLL and the native test binary compile
 * these two TUs with the same ABI; the native e2e test asserting rc == 11 is the
 * executed proof, and a 32-bit or NaN-boxed target is where this would break.
 *
 * `src` must be NUL-terminated (Zig passes a fixed string literal; remote strings
 * are deferred to C3). eval_flags 0 == JS_EVAL_TYPE_GLOBAL (quickjs.h:332). */
int C2EvalProbe(const char *src) {
    if (!g_test_ctx) return 0;

    JSValue v = JS_Eval(g_test_ctx, src, strlen(src), "<probe>", 0);

    if (JS_VALUE_GET_TAG(v) == JS_TAG_EXCEPTION) {
        JS_FreeValue(g_test_ctx, v); /* tag 6: not refcounted, correctly a no-op */
        c2_clear_pending_exception(g_test_ctx);
        return 1;
    }

    int32_t n = 0;
    if (JS_ToInt32(g_test_ctx, &n, v) != 0) {
        JS_FreeValue(g_test_ctx, v);
        c2_clear_pending_exception(g_test_ctx);
        return 2;
    }

    /* The refcounted case (object/string result) drops the last holder here; the
       int/float/bool results are non-refcounted tags and correctly free nothing
       — which is exactly the call the pre-P19 wrapper turned into abort(). */
    JS_FreeValue(g_test_ctx, v);

    /* Modular, not signed-overflow UB: n * 4 overflows int32 for |n| >= 2^30.
       The wrap preserves the contract ((rc - 3) / 4 recovers n in two's
       complement) and is irrelevant for the fixed "1+1" probe, but C3's
       general-argument API must not reuse this encoding without a range check
       (P20 deferred minor). */
    return (int)((uint32_t)n * 4u + 3u);
}
