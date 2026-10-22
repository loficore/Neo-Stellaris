/* allocmap.c — OFFLINE (Linux host, no game) diagnostic.
 *
 * Purpose: produce the ORDERED sequence of js_malloc/js_free/js_realloc calls
 * that JS_NewRuntime2 makes through OUR malloc functions, with size + the
 * quickjs.c call site of each, so the §42 live witness `new_rt MmMmMm` (three
 * mallocs, all returned, then ~6.9s of zero allocation before death) can be
 * mapped to specific source lines.
 *
 * The mf semantics MIRROR src/dll/quickjs/quickjs_wrapper.c exactly (same
 * AllocHeader accounting, same js_malloc_usable_size = recorded size, same
 * MF_TAG_CAP + M/m/!/F/R tag stream), so this offline stream is faithful to what
 * the shipped DLL would emit — not to a libc-realloc approximation.
 *
 * Zero game involvement, zero capability change. quickjs.c is the SAME vendored
 * source the shipped DLL builds (build.zig:9).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <execinfo.h>
#include "quickjs.h"

typedef struct { size_t size; } AllocHeader;

#define MF_TAG_CAP 8
static char g_diag_log[512];
static int g_diag_pos = 0;
static int g_mf_malloc_tagged = 0;
static int g_mf_free_tagged = 0;
static int g_mf_realloc_tagged = 0;
static int g_seq = 0;   /* undecorated call index for the site dump */

static void mf_tag(char c) {
    if (g_diag_pos < 511) { g_diag_log[g_diag_pos++] = c; g_diag_log[g_diag_pos] = '\0'; }
}

static void print_site(const char *kind, size_t size, void *ptr) {
    void *bt[16];
    int n = backtrace(bt, 16);
    char **syms = backtrace_symbols(bt, n);
    fprintf(stderr, "%-4s #%-2d size=%-9zu ptr=%p  tag='%s'  log='%s'\n",
            kind, g_seq++, size, ptr, "", g_diag_log);
    int shown = 0;
    for (int i = 0; i < n && shown < 6; i++) {
        if (!syms[i]) continue;
        if (strstr(syms[i], "heap_") || strstr(syms[i], "print_site") ||
            strstr(syms[i], "mf_tag") || strstr(syms[i], "libc") ||
            strstr(syms[i], "ld-linux")) continue;
        fprintf(stderr, "        %s\n", syms[i]);
        shown++;
    }
    free(syms);
}

/* --- verbatim port of quickjs_wrapper.c's heap_malloc/free/realloc/usable --- */
static void *heap_malloc(JSMallocState *s, size_t size) {
    int tag_this_call = (g_mf_malloc_tagged < MF_TAG_CAP);
    if (tag_this_call) { mf_tag('M'); g_mf_malloc_tagged++; }
    if (size == 0) { if (tag_this_call) mf_tag('!'); return NULL; }
    if (s->malloc_size + size > s->malloc_limit) { if (tag_this_call) mf_tag('!'); return NULL; }
    AllocHeader *h = (AllocHeader *)malloc(sizeof(AllocHeader) + size);
    if (!h) { if (tag_this_call) mf_tag('!'); return NULL; }
    if (tag_this_call) mf_tag('m');
    h->size = size; s->malloc_count++; s->malloc_size += size;
    print_site("M", size, h + 1);
    return (void *)(h + 1);
}
static void heap_free(JSMallocState *s, void *ptr) {
    if (g_mf_free_tagged < MF_TAG_CAP) { mf_tag('F'); g_mf_free_tagged++; }
    if (!ptr) return;
    AllocHeader *h = ((AllocHeader *)ptr) - 1;
    size_t freed = h->size;
    print_site("F", freed, ptr);
    free(h);
    s->malloc_count--; s->malloc_size -= freed;
}
static void *heap_realloc(JSMallocState *s, void *ptr, size_t size) {
    if (g_mf_realloc_tagged < MF_TAG_CAP) { mf_tag('R'); g_mf_realloc_tagged++; }
    if (!ptr) return heap_malloc(s, size);
    if (size == 0) { heap_free(s, ptr); return NULL; }
    AllocHeader *h = ((AllocHeader *)ptr) - 1;
    size_t old_size = h->size;
    if (s->malloc_size - old_size + size > s->malloc_limit) return NULL;
    AllocHeader *new_h = (AllocHeader *)realloc(h, sizeof(AllocHeader) + size);
    if (!new_h) return NULL;
    new_h->size = size; s->malloc_size = s->malloc_size - old_size + size;
    print_site("R", size, new_h + 1);
    return (void *)(new_h + 1);
}
static size_t heap_usable(const void *ptr) {
    if (!ptr) return 0;
    const AllocHeader *h = ((const AllocHeader *)ptr) - 1;
    return h->size;
}

static const JSMallocFunctions mf = { heap_malloc, heap_free, heap_realloc, heap_usable };

int main(void) {
    fprintf(stderr, "=== JS_NewRuntime2 allocation map (offline, wrapper-faithful mf) ===\n");
    JSRuntime *rt = JS_NewRuntime2(&mf, NULL);
    fprintf(stderr, "\n=== final g_diag_log (cap %d) = '%s' ===\n", MF_TAG_CAP, g_diag_log);
    fprintf(stderr, "=== JS_NewRuntime2 returned rt=%p ===\n", (void*)rt);
    if (rt) JS_FreeRuntime(rt);
    return 0;
}
