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
#include <unistd.h>
#include <fcntl.h>
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
/* Genuine exported QuickJS API (quickjs.h:378), bound here in C — not on the Zig
   side (global constraint; bindings.zig:345's declaration stays unused). */
extern void JS_UpdateStackTop(JSRuntime *rt);
extern void *JS_GetRuntimeOpaque(JSRuntime *rt);
extern void JS_SetRuntimeOpaque(JSRuntime *rt, void *opaque);
extern int JS_NewContextDiag(JSRuntime *rt, JSContext **out_ctx,
                             char *err_buf, int err_size);

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

/* Live-readable diagnostic buffer + write cursor, hoisted above the allocator
   callbacks so heap_malloc/free/realloc can tag themselves. g_diag_log is the
   SAME static C2CopyDiagLog reads back live (§38: the only channel that works
   while the host is dying). */
static char g_diag_log[512];
static int g_diag_pos = 0;

/* ---------------------------------------------------------------------------
 * Task 1 (C2 allocator-record discrimination plan) — bounded ring recorder
 * inside the three heap_mf callbacks. PURE OBSERVATION: the callbacks gain
 * entry/exit bookkeeping only; no control flow, accounting, size==0 handling,
 * alignment, or return value changes, and the 'M'/'m'/'!' marking plus
 * MF_TAG_CAP below are byte-for-byte untouched (every §41–§44 live reading is
 * compared against that text).
 *
 * Why: §45 pinned the crash to quickjs.c:1494 js_rc's `container_of` reading
 * `ptr - 8`, reproduced in a child process we own — but the VALUE of the
 * faulting pointer was never observed, only inferred. The ring turns that
 * inference into data: the last MF_REC_CAP allocator events, each a
 * (kind, size, ptr, malloc_state) tuple, rendered to text by C2DiagMfRecords
 * (below) and read back through exports.zig's C2DiagMfRecordsInto.
 *
 * Slot lifecycle (the plan's contract, verbatim):
 *   entry — kind/size/state written, filled = '\0', ptr = (void *)0x1 sentinel;
 *   exit  — filled = '\0' flipped to 'x', ptr = what the callback returned
 *           (heap_free records the pointer it released).
 *   A slot whose callback entered but never reached its exit keeps
 *   filled == '\0' with the 0x1 sentinel stored in ptr. The sentinel must NOT
 *   be NULL: NULL is one of the facts this plan discriminates between ("the
 *   callback returned NULL") and cannot double as the not-reached marker.
 *   Never-written slots keep the same sentinel state through the static
 *   initializer below, so "ptr == 0x1 until an exit overwrites it" holds for
 *   EVERY slot at every moment, as the interface promises.
 *   The renderer never emits the stored value for an unfilled slot: it draws
 *   '_' in the filled column and a fixed 16-dash placeholder in the ptr
 *   column, so neither the sentinel nor a fake ptr=0 crosses the text
 *   boundary — see Review Focus 2 pinned by the native tests.
 *
 * Ring: one shared cursor across the three callbacks, the 9th event overwrites
 * the 1st; the recorder is deliberately NOT reset by c2_diag_sequence — the
 * window means "the last 8 allocator events of this process", which on a
 * first-JS_NewRuntime2 death is exactly the events bracketing the death point.
 * Single-threaded by construction on the WRITE side (the callbacks run only on
 * the sequence's own thread); no locking, the same treatment as the mf_tag
 * counters above. The READ side is NOT: the next task reads the ring from a
 * SECOND thread of the child process while the first thread is still inside
 * JS_NewRuntime2 (the process aborts inside that call, so a post-call read-back
 * would never run), so C2DiagMfRecords below is written to degrade honestly
 * under a concurrent writer instead of emitting a mixture.
 * ------------------------------------------------------------------------- */
#define MF_REC_CAP 8
typedef struct {
    char kind;                  /* 'M', 'F', 'R'; '\0' = never written */
    char filled;                /* '\0' until the callback's exit writes 'x' */
    short _pad;                 /* explicit pad so the fields below keep natural alignment */
    size_t size;                /* Requested size; heap_free records the released block's own size (see mf_rec_free_size) */
    void *ptr;                  /* (void *)0x1 sentinel until exit, then the returned value */
    const JSMallocState *state; /* which malloc_state drove the call — candidate (c)'s discriminator */
} MfRecord;
/* The plan's prose says "每条记录 24 字节" while the field list above is what
 * governs (Task 1 ruling 3): on x86-64 natural alignment makes sizeof(MfRecord)
 * 32, and that is the real size. Nothing consumes this struct as raw bytes —
 * only the rendered text crosses the boundary — so the discrepancy is cosmetic
 * and recorded here rather than shaved by packing. */
#define MF_REC_EMPTY_SLOT { 0, 0, 0, 0, (void *)(uintptr_t)0x1, NULL }
static MfRecord g_mf_rec[MF_REC_CAP] = {
    MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT,
    MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT, MF_REC_EMPTY_SLOT,
};
static int g_mf_rec_pos = 0;

/* Entry half: claim the next slot, record what is knowable before the call
 * returns, hand the slot index back for the exit half to close. */
static int mf_rec_enter(char kind, size_t size, const JSMallocState *s) {
    int i = g_mf_rec_pos;
    g_mf_rec_pos = (i + 1) % MF_REC_CAP;
    g_mf_rec[i].kind = kind;
    g_mf_rec[i].filled = '\0';
    g_mf_rec[i].size = size;
    g_mf_rec[i].ptr = (void *)(uintptr_t)0x1;
    g_mf_rec[i].state = s;
    return i;
}

/* heap_free's requested size: the recorded size of the block being released,
 * read at ENTRY (the block is still ours here — it is only reads AFTER
 * HeapFree that are the §33 use-after-free). A free has no size argument, so
 * copying the block's own size is the only value that keeps the rendered
 * `size=` column honest for what it means elsewhere: a request for zero
 * bytes. The constant-0 alternative made every `Fx` row read as a captured
 * zero-size request and let the plan's Step 4 discriminator pass without any
 * such event ever having happened (observed natively 2026-10: `Fx size=0
 * ptr=2dc4e28`), so the distinction is load-bearing, not cosmetic. A free of
 * NULL records size 0 — no block was released and the pointer column says so. */
static size_t mf_rec_free_size(void *ptr) {
    if (!ptr) return 0;
    return (((const AllocHeader *)ptr) - 1)->size;
}

/* Exit half: publish how the call actually ended. */
static void mf_rec_leave(int slot, void *ptr) {
    g_mf_rec[slot].ptr = ptr;
    g_mf_rec[slot].filled = 'x';
}

/* Rate limit: a live JS_NewRuntime2 does dozens of mallocs; unbounded tagging
   would overflow the 512 buffer and push the `enter…new_rt` prefix off the end,
   so the LAST tag read would be the buffer tail, not the death point. Cap each
   callback kind, then stop appending (counting keeps going via s->malloc_count).
   NOTE: heap_malloc/free/realloc are reached ONLY via mf (the sequence's own
   alloc_ok/free_ok tags use HeapAlloc directly), so the first 'M' here proves
   JS code called back into our allocator. */
#define MF_TAG_CAP 8
static int g_mf_malloc_tagged = 0;
static int g_mf_free_tagged = 0;
static int g_mf_realloc_tagged = 0;

static void mf_tag(char c) {
    if (g_diag_pos < 511) {
        g_diag_log[g_diag_pos++] = c;
        g_diag_log[g_diag_pos] = '\0';
    }
}

/* heap_malloc leaves a matched pair of read-only markers so the LIVE witness can
   tell WHICH phase of a single allocation the host died in — the one seam §41
   could not split. 'M' = entered the callback (what §41 alone recorded); the char
   that follows is how the call ENDED:
     'm' = HeapAlloc returned a block (allocation completed)
     '!' = returned NULL (size 0 / malloc_limit reject / HeapAlloc failed)
     <dangling 'M', nothing follows> = the call never returned ⇒ death was inside
     GetProcessHeap()/HeapAlloc, not in QuickJS's own code.
   §41 only tagged entry, so `new_rt MMM` read the same for "died between two
   mallocs inside JS_NewRuntime2" and "died inside the 3rd HeapAlloc". These are
   §36's two hypotheses (engine-side vs heap/environment-side) and this decides
   them. Both markers are just writes to our OWN g_diag_log — no hook, detour,
   patchCode, or new capability, the same authorization level as §41's tags.
   g_mf_malloc_tagged increments once per CALL, so MF_TAG_CAP bounds the number
   of allocation LIFECYCLES shown (up to 2 chars each), not raw chars. */
static void *heap_malloc(JSMallocState *s, size_t size) {
    int rec_slot = mf_rec_enter('M', size, s);
    int tag_this_call = (g_mf_malloc_tagged < MF_TAG_CAP);
    if (tag_this_call) { mf_tag('M'); g_mf_malloc_tagged++; }
    if (size == 0) { if (tag_this_call) mf_tag('!'); mf_rec_leave(rec_slot, NULL); return NULL; }
    if (s->malloc_size + size > s->malloc_limit) { if (tag_this_call) mf_tag('!'); mf_rec_leave(rec_slot, NULL); return NULL; }

    HANDLE heap = GetProcessHeap();
    AllocHeader *h = (AllocHeader *)HeapAlloc(heap, 0, sizeof(AllocHeader) + size);
    if (!h) { if (tag_this_call) mf_tag('!'); mf_rec_leave(rec_slot, NULL); return NULL; }
    if (tag_this_call) mf_tag('m');

    h->size = size;
    s->malloc_count++;
    s->malloc_size += size;
    mf_rec_leave(rec_slot, (void *)(h + 1));
    return (void *)(h + 1);
}

static void heap_free(JSMallocState *s, void *ptr) {
    int rec_slot = mf_rec_enter('F', mf_rec_free_size(ptr), s);
    if (g_mf_free_tagged < MF_TAG_CAP) { mf_tag('F'); g_mf_free_tagged++; }
    if (!ptr) { mf_rec_leave(rec_slot, ptr); return; }
    
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
    /* The recorder's ptr column keeps the pointer this call released; `freed`
       above was its size, read before the block went back to the heap manager
       (the UAF the §33 comment documents must not be reintroduced here). */
    mf_rec_leave(rec_slot, ptr);
}

static void *heap_realloc(JSMallocState *s, void *ptr, size_t size) {
    int rec_slot = mf_rec_enter('R', size, s);
    if (g_mf_realloc_tagged < MF_TAG_CAP) { mf_tag('R'); g_mf_realloc_tagged++; }
    if (!ptr) {
        /* Delegation is unchanged (heap_malloc records its own slot too); the
           capture exists only so THIS slot closes with the value actually
           returned instead of dangling at the 0x1 sentinel. */
        void *delegated = heap_malloc(s, size);
        mf_rec_leave(rec_slot, delegated);
        return delegated;
    }
    if (size == 0) {
        heap_free(s, ptr);
        mf_rec_leave(rec_slot, NULL);
        return NULL;
    }
    
    AllocHeader *h = ((AllocHeader *)ptr) - 1;
    size_t old_size = h->size;
    
    if (s->malloc_size - old_size + size > s->malloc_limit) { mf_rec_leave(rec_slot, NULL); return NULL; }
    
    HANDLE heap = GetProcessHeap();
    AllocHeader *new_h = (AllocHeader *)HeapReAlloc(heap, 0, h, sizeof(AllocHeader) + size);
    if (!new_h) { mf_rec_leave(rec_slot, NULL); return NULL; }
    
    new_h->size = size;
    s->malloc_size = s->malloc_size - old_size + size;
    mf_rec_leave(rec_slot, (void *)(new_h + 1));
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

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

// Sanity check: returns a constant that proves the new code is loaded.
int C2SanityCheck(void) {
    return 42;
}

/* ---------------------------------------------------------------------------
 * §36 (2026-10-21 live) — one shared step sequence, always logged.
 *
 * Before this there were TWO copies of the sequence: C2TestQuickJS (what C2Init
 * actually dispatches) returned step codes and wrote NOTHING, while
 * C2DiagQuickJS filled g_diag_log. The live shot went through C2Init, so the rc
 * arrived with no disambiguator at all. One function now serves both, so a live
 * C2Init failure and a live C2DiagQJSInto failure are the same code path with
 * the same text.
 *
 * Return-code ranges (the other §36 defect — 2/3/4 meant two different things,
 * this file's own gates and JS_NewContextDiag's intrinsic steps shared them):
 *   0          success
 *   1..12      JS_NewContextDiag inner steps (quickjs.c): 1 = the raw-context
 *              allocation, 2..12 = the first failing intrinsic
 *   100..104   THIS file's outer gates: 100 no process heap, 101 test HeapAlloc
 *              failed, 102 JS_NewRuntime2 NULL, 103 runtime opaque mismatch,
 *              104 raw context NULL
 * The two ranges no longer intersect, so an rc is decodable on its own; the log
 * is still written because the inner codes carry the exception text.
 * ------------------------------------------------------------------------- */
#define C2_DIAG_ERR_SIZE 192

/* ---------------------------------------------------------------------------
 * The on-disk diagnostic channel.
 *
 * Why the in-process buffer is not enough: every live dispatch that has reached
 * this sequence lost the host right after the remote thread returned its exit
 * code (§32 C2DiagQJSInto, §36.3 C2Init, and the 2026-10-21 22:41 and 22:47
 * shots). The 22:47 shot is the decisive one — it used the one-shot shape, so
 * the log was already copied into the caller's remote buffer inside the same
 * thread call, and the very next ReadProcessMemory of that buffer returned
 * ERROR_PARTIAL_COPY (gle 299). The text was written; it just lived in an
 * address space that was going away. Anything that must survive has to leave
 * the process before this function returns.
 *
 * Plain kernel32 file handles (CreateFileA/WriteFile), not stdio FILE: this DLL
 * is injected, and pulling CRT stdio state into the sequence would add a new
 * variable to the very crash being measured. A failed write is silently ignored
 * — the file is a bonus channel and must never be able to change the rc.
 * ------------------------------------------------------------------------- */
#ifdef _WIN32
#define C2_DIAG_FILE_DIR "C:/temp"
#else
/* The native `zig build test` path writes here; the Windows path above is what
   the live probe deletes and reads. */
#define C2_DIAG_FILE_DIR "/tmp"
#endif

static void c2_diag_write_file(int rc, int log_len) {
    char path[64];
    char line[640];
    unsigned long pid;
#ifdef _WIN32
    pid = (unsigned long)GetCurrentProcessId();
#else
    pid = (unsigned long)getpid();
#endif
    snprintf(path, sizeof(path), C2_DIAG_FILE_DIR "/c2_diag_%lu.log", pid);

    int n = snprintf(line, sizeof(line), "rc=%d %.*s\n", rc, log_len, g_diag_log);
    if (n < 0) {
        return;
    }
    if ((size_t)n >= sizeof(line)) {
        n = (int)sizeof(line) - 1; /* truncated line is still evidence */
    }

#ifdef _WIN32
    HANDLE f = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    SetFilePointer(f, 0, NULL, FILE_END);
    DWORD written = 0;
    WriteFile(f, line, (DWORD)n, &written, NULL);
    CloseHandle(f);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    ssize_t w = write(fd, line, (size_t)n);
    (void)w;
    close(fd);
#endif
}

static int c2_diag_sequence(void) {
    g_test_rt = NULL;
    g_test_ctx = NULL;
    g_diag_log[0] = '\0';
    g_diag_pos = 0;
    g_mf_malloc_tagged = 0;
    g_mf_free_tagged = 0;
    g_mf_realloc_tagged = 0;
    int result = 0;
    char err[C2_DIAG_ERR_SIZE];
    /* snprintf returns the WOULD-BE length, so an unguarded `g_diag_pos +=` can
       overshoot 512; a later `512 - g_diag_pos` would then be negative (huge
       size_t) and g_diag_log + g_diag_pos would be past the end of the static.
       Clamp g_diag_pos to stay within the buffer forever. It is a FILE STATIC
       (not a local) so the heap_mf callbacks — which run DURING JS_NewRuntime2,
       between the `new_rt ` and `rt=` tags — share this one write cursor; that
       is exactly what mf_tag() needs. (The clamp is not the 2026-10-08 crash
       cause — real content stays well under 512 — but a latent overflow the
       moment more steps are logged.) */
    #define DLOG(...) do { \
        int n_ = snprintf(g_diag_log + g_diag_pos, 512 - g_diag_pos, __VA_ARGS__); \
        if (n_ < 0) n_ = 0; \
        g_diag_pos += n_; \
        if (g_diag_pos > 511) g_diag_pos = 511; \
    } while(0)

    HANDLE heap = GetProcessHeap();
    /* Each tag lands BEFORE the operation it precedes, so the LAST tag present in
       the static is the boundary of what actually ran. The live probe reads this
       static directly while the sequence is still running (§38: the 23:55 shot
       polled g_diag_log for 6.9 s and found it EMPTY, which a log beginning at
       `rt=` cannot distinguish from "the thread never started"). */
    DLOG("enter ");
    if (!heap) { DLOG("no_process_heap"); result = 100; goto finish; }
    DLOG("heap_ok ");
    void *test_p = HeapAlloc(heap, 0, 256);
    if (!test_p) { DLOG("heap_alloc_failed"); result = 101; goto finish; }
    DLOG("alloc_ok ");
    HeapFree(heap, 0, test_p);
    DLOG("free_ok ");

    DLOG("new_rt ");
    g_test_rt = JS_NewRuntime2(&heap_mf, NULL);
    if (!g_test_rt) { DLOG("runtime2_null"); result = 102; goto finish; }
    DLOG("rt=%p ", g_test_rt);

    JS_SetRuntimeOpaque(g_test_rt, (void *)(uintptr_t)0xDEADBEEF);
    void *opaque = JS_GetRuntimeOpaque(g_test_rt);
    if (opaque != (void *)(uintptr_t)0xDEADBEEF) {
        DLOG("opaque_mismatch got=%p", opaque);
        result = 103; goto finish;
    }
    DLOG("opaque_ok ");

    JS_SetMaxStackSize(g_test_rt, 1024 * 1024);
    JS_SetMemoryLimit(g_test_rt, 256 * 1024 * 1024);
    DLOG("limits_ok ");

    DLOG("new_raw ");
    JSContext *raw_ctx = JS_NewContextRaw(g_test_rt);
    if (!raw_ctx) { DLOG("raw_ctx_null"); result = 104; goto finish; }
    JS_FreeContext(raw_ctx);
    DLOG("raw_ok ");

    {
        err[0] = '\0';
        DLOG("new_diag ");
        int diag_rc = JS_NewContextDiag(g_test_rt, &g_test_ctx, err, C2_DIAG_ERR_SIZE);
        DLOG("diag_rc=%d ctx=%p", diag_rc, g_test_ctx);
        if (diag_rc != 0 && err[0] != '\0') DLOG(" err=[%s]", err);
        result = diag_rc;
    }

finish:
    #undef DLOG
    c2_diag_write_file(result, g_diag_pos);
    return result;
}

int C2TestQuickJS(void) {
    return c2_diag_sequence();
}

int C2DiagQuickJS(char *out_diag, int diag_size) {
    int result = c2_diag_sequence();
    if (out_diag && diag_size > 0) {
        strncpy(out_diag, g_diag_log, diag_size - 1);
        out_diag[diag_size - 1] = '\0';
    }
    return result;
}

/* Pure read of g_diag_log — NO QuickJS call, no re-init, no state change. This
 * is the live read-back path: the alternative (C2DiagQJSInto) re-runs the whole
 * init sequence, so on a host where the init dispatch is itself suspect (§36.3:
 * 2/2 of the shots that reached QuickJS init lost the process) a "read the log"
 * step would be another init in disguise.
 * `out` must be at least 512 bytes, byte-aligned (memcpy, not a pointer store);
 * the size is baked into the contract and never passed, exactly like
 * C2WriteQuickJSPointersInto below, because CreateRemoteThread passes exactly
 * one lpParameter. Returns the string length written (excluding the NUL). */
int C2CopyDiagLog(unsigned char *out) {
    size_t n = strlen(g_diag_log);
    if (n > 511) n = 511;
    memcpy(out, g_diag_log, n);
    out[n] = '\0';
    return (int)n;
}

/* Task 1 renderer: dump the heap_mf ring as TEXT into a caller buffer, one
 * fixed-shape row per slot, ordered oldest -> newest (the ring is walked from
 * the cursor g_mf_rec_pos, the slot the NEXT event will overwrite). Row shape:
 *     "<kind><filled> size=<hex> ptr=<hex> st=<low 12 hex digits>\n"
 * size/ptr are hexadecimal WITHOUT zero padding — the plan's own literal
 * assertions (" size=0 " for a captured zero-size request, and the ptr=0 vs
 * unfilled distinction) only read under this spelling; "fixed width" holds in
 * the row template, in the st= column (exactly 12 hex digits, zero padded —
 * pinned by a native test so a regression to an unpadded or full-pointer-width
 * state column cannot pass), and in the worst-case bound below.
 * filled column: 'x' = the callback reached its exit, '_' = it did not (never
 * written: kind column '_' too). An unfilled row draws its pointer column as
 * a fixed 16-dash placeholder and never emits the stored value: the 0x1
 * sentinel must not leak as a fake pointer, and must not be drawn as ptr=0
 * either — a real all-zero ptr on a COMPLETED row means "returned NULL", one
 * of the facts this recorder exists to observe (Review Focus 2).
 * Review Focus 3 bound: a row is at most MF_REC_ROW_MAX = 62 bytes (hex of a
 * 64-bit value is <= 16 digits), so the renderer's OWN bound is MF_REC_CAP
 * rows x 62 = 496 bytes — every slot is always rendered and the return value
 * can never exceed 495, whatever the caller asks; the caller's out_size is
 * still respected as a hard limit (the loop stops before writing past it,
 * leaving room for the NUL), and a buffer at the 4096-byte contract holds the
 * full ring without ever coming near that limit.
 *
 * CONCURRENT READER (the shape Task 2 actually schedules): a second thread of
 * the child process calls this while the first thread is still inside
 * JS_NewRuntime2, i.e. while mf_rec_enter/mf_rec_leave are actively rewriting
 * slots. Two torn reads were structurally possible in the obvious loop and are
 * what the three rules below close, lock-free (no mutex: taking one inside a
 * dying process is not an option, and the writer must not be able to block):
 *   1. the cursor is read ONCE before the loop, so the walk visits each slot
 *      exactly once; re-reading it per row let an advancing cursor make one
 *      slot appear twice and another disappear, producing an ordering/content
 *      that was never a ring state;
 *   2. every field is SNAPSHOT into locals first, so a row's size/ptr/state can
 *      never be a mixture of values that did not coexist in one event;
 *   3. `filled` is re-read AFTER the copy; if it no longer holds the captured
 *      value, the slot was written during the snapshot and the row is rendered
 *      in the UNFILLED form ('_' + the dash placeholder). That is deliberate:
 *      an unstable row is a RACE ARTIFACT, not allocator behaviour — it must
 *      never be printed as a completed event, because the value a mid-flight
 *      writer leaves in ptr is the 0x1 sentinel, and a sentinel escaping into
 *      the text as a CLAIMED RETURNED POINTER is exactly the false fact the
 *      sentinel clause exists to prevent (NULL and 0x1 each mean something
 *      specific to this investigation).
 * The reads go through a volatile-qualified view on purpose: without it the
 * compiler may fold the second `filled` read into the first (nothing in this
 * function writes g_mf_rec, so as far as the abstract machine goes the value
 * cannot change), which would silently un-implement rule 3.
 * Residual limit, stated rather than hidden: a writer that ENTERS and LEAVES
 * the same slot entirely between the two `filled` reads leaves both reads
 * agreeing ('x'/'x') and the row is a genuine ABA mixture. With MF_REC_CAP
 * slots and a reader that touches each slot ~8 times, that window is a handful
 * of nanoseconds against a writer whose interesting events are separated by
 * whole allocations; and Task 2 reads a *dying* process, where the writer is
 * not looping. If a row's numbers ever have to be proof, the pointer VALUE is
 * what to re-check, not the text layout. */
#define MF_REC_ROW_MAX 62
int C2DiagMfRecords(char *out, int out_size) {
    if (out == NULL || out_size <= 0) return 0;
    /* Rule 1: one cursor read, before the loop. */
    const int start = *(volatile const int *)&g_mf_rec_pos;
    int written = 0;
    for (int k = 0; k < MF_REC_CAP; k++) {
        volatile const MfRecord *slot =
            (volatile const MfRecord *)&g_mf_rec[(start + k) % MF_REC_CAP]; /* oldest first */
        /* Rule 2: snapshot the whole tuple, one read per field. */
        const char kind = slot->kind;
        const char filled = slot->filled;
        const size_t sz = slot->size;
        const void *ptr = slot->ptr;
        const JSMallocState *st = slot->state;
        /* Rule 3: re-read the marker AFTER the copy. A different value means the
           slot moved under us, so nothing in this row is a claim. */
        const int settled = (slot->filled == filled);
        const int kind_c = kind ? (int)kind : (int)'_';
        unsigned long long st_low48 =
            (unsigned long long)((uintptr_t)st & 0xFFFFFFFFFFFFULL);
        char row[MF_REC_ROW_MAX + 1];
        int n;
        if (filled == '\0' || !settled) {
            /* Unfilled, and unstable: the unfilled form is the only honest one. */
            n = snprintf(row, sizeof(row), "%c_ size=%llx ptr=---------------- st=%012llx\n",
                         kind_c, (unsigned long long)sz, st_low48);
        } else {
            n = snprintf(row, sizeof(row), "%cx size=%llx ptr=%llx st=%012llx\n",
                         kind_c, (unsigned long long)sz,
                         (unsigned long long)(uintptr_t)ptr, st_low48);
        }
        if (n < 0) continue; /* snprintf failure: skip the slot, still bound the loop by MF_REC_CAP */
        if (n >= (int)sizeof(row)) n = (int)sizeof(row) - 1; /* defensive; 62 < 63 cannot truncate */
        if (written + n > out_size - 1) break; /* keep the NUL slot; never write past out_size */
        memcpy(out + written, row, (size_t)n);
        written += n;
    }
    out[written] = '\0';
    return written;
}

/* Test-only, NOT a PE export and NOT reachable from the injection channel
 * (exports.zig declares nothing for it — the C2ProbeMallocZero shape the plan
 * blesses for Task 4: 「exports.zig 里给测试用的一行包装,它不暴露给注入通道」,
 * here even lighter: no Zig-side declaration at all, the native test binds this
 * symbol with `extern fn` the way it binds every other quickjs_wrapper.c symbol).
 *
 * Why it exists: Task 1's Step 4 wanted the recorder to be able to SEE the two
 * zero-size deviations the plan names — `malloc(state, 0)` and `realloc(state,
 * ptr, 0)` — but on this vendored build no such request can ever reach the
 * callbacks (quickjs.c serves size==0 itself; the reading is recorded on the Zig
 * test that used to assert it). Visibility of a path QuickJS never takes is
 * still what Task 3/4's discrimination needs, so it is pinned directly: this
 * function only CALLS the existing static callbacks with a caller-owned
 * JSMallocState. It changes no allocator semantics, touches no runtime, and its
 * state never escapes the frame.
 *
 * Returns the residual malloc_count after the sequence: 0 means the probe
 * released everything it allocated, which is the accounting-honesty requirement
 * (heap_malloc(s,0) allocates nothing; heap_realloc(s,p,0) frees p through
 * heap_free itself). The Zig test asserts that 0, so a future change that made
 * the probe leak cannot pass quietly. */
int C2DiagMfProbeZeroSize(void) {
    JSMallocState s;
    void *p;

    memset(&s, 0, sizeof(s));
    s.malloc_limit = 64 * 1024; /* big enough that the probe exercises the zero-size
                                   branches, not the malloc_limit rejection branch */

    /* Deviation 1: malloc asked for zero. Its own size==0 branch answers NULL. */
    heap_malloc(&s, 0);

    /* Deviation 2: realloc asked for zero WITH a live block, so the path taken is
       the size==0 branch (free the block, return NULL) and not the !ptr
       delegation to heap_malloc. The block handed in must be a real one, because
       that branch reads its header via heap_free. */
    p = heap_malloc(&s, 16);
    if (p) heap_realloc(&s, p, 0);

    return (int)s.malloc_count;
}

/* Test-only: force an intrinsic failure by starving the runtime of memory, so
 * the §36 capture path (stage + pending-exception text) is exercised natively
 * instead of only on a live game. It builds its OWN runtime and frees it, and
 * never touches g_test_rt / g_test_ctx / g_diag_log — the globals the other
 * tests observe must stay exactly as C2TestQuickJS left them.
 * Copies the captured "<stage>: <message>" into out_log (out_size bytes, NUL
 * terminated) and returns the JS_NewContextDiag step code. out_log may be NULL:
 * the capture must not be load-bearing for the numeric answer. */
int C2DiagNewContextUnderMemoryLimit(size_t mem_limit, char *out_log, int out_size) {
    JSRuntime *rt = JS_NewRuntime2(&heap_mf, NULL);
    char err[C2_DIAG_ERR_SIZE];
    JSContext *ctx = NULL;
    int rc;

    if (!rt) return 102;

    err[0] = '\0';
    JS_SetMaxStackSize(rt, 1024 * 1024);
    JS_SetMemoryLimit(rt, mem_limit);
    rc = JS_NewContextDiag(rt, &ctx, err, C2_DIAG_ERR_SIZE);
    if (ctx) JS_FreeContext(ctx);
    /* JS_FreeRuntime releases a still-pending rt->current_exception
       (quickjs.c:2410), so the failure path does not leak here. */
    JS_FreeRuntime(rt);

    if (out_log && out_size > 0) {
        strncpy(out_log, err, out_size - 1);
        out_log[out_size - 1] = '\0';
    }
    return rc;
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

    /* CONFIG_STACK_CHECK (quickjs.c:75-77) caches rt->stack_top on whichever
       thread created the runtime — JS_NewRuntime2 captures it exactly once
       (quickjs.c:2116) — and js_check_stack_overflow compares the EVALUATING
       thread's sp against stack_limit = stack_top - stack_size
       (quickjs.c:2882-2887, :2059-2064). This probe is dispatched on a
       different CreateRemoteThread than the C2Init that built the runtime, so
       the cached top belongs to a dead thread's stack and JS_Eval can throw a
       spurious stack overflow (rc 1, wrong diagnosis on the live shot).
       quickjs.h:376-378 documents exactly this: "should be called when
       changing thread". Refresh before any evaluation. */
    JS_UpdateStackTop(g_test_rt);

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

/* §50 diagnostic — fixed stress script for the allocator paths §48 un-instrumented.
 *
 * §48 removed the fallback `container_of` from eight expressions. Only `js_rc`
 * (quickjs.c:1494) was on the Task 5/6 path; the free/realloc/usable-size sites
 * (1601/1607/1645/1651/1684/1704/1711) never ran under any live probe. This
 * script drives them through ordinary JS:
 *   - `s += ...` repeatedly grows the string builder, which uses js_realloc2
 *     (quickjs.c:4146/4177) -> js_realloc_rt (__js_realloc) + js_malloc_usable_size_rt
 *     (__js_malloc_usable_size) and frees the old buffer (__js_free);
 *   - `a.push(...)` grows the property array via js_realloc2 (quickjs.c:9622);
 *   - each round drops `s`, `a` and `t`, so refcounted strings/objects/arrays are
 *     freed (__js_free) while the next round reuses the allocator.
 * The arithmetic only uses engine-stable semantics (lengths, integer digits,
 * insertion-order JSON), so the result is a deterministic int32; the expected
 * value `15904` (rc 63619) is computed with Node and pinned by the native test
 * in c2_diag_test.zig, which calls this same C symbol — the script lives here
 * once, not copied into the test.
 *
 * Not a general evaluation API: the source is fixed (the P21/C3 boundary — caller
 * JS text stays deferred). Dispatched remotely through the C2EvalStressOne PE
 * export, which reads the encoding back through the thread exit code. */
static const char c2_stress_script[] =
    "(function(){"
    "var acc=0;"
    "for(var r=0;r<8;r++){"
    "var s='';"
    "for(var i=0;i<2000;i++)s+='abcdefgh'+i;"
    "acc=(acc+s.length)&0xffff;"
    "var a=[];"
    "for(var j=0;j<4000;j++)a.push({k:j,v:'v'+j});"
    "acc=(acc+a.length+a[3999].v.length)&0xffff;"
    "var t=JSON.stringify(a);"
    "acc=(acc+t.length)&0xffff;"
    "}"
    "return acc;"
    "})()";

int C2EvalStress(void) {
    return C2EvalProbe(c2_stress_script);
}
