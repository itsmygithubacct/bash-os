/* SPDX-License-Identifier: MIT */
/* Compile the production implementation with local allocation fault injection. */
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "loadables.h"

static long calls, fail_at, live;
static size_t allocated_bytes, copied_bytes, compare_calls, compare_requested_bytes;
static int fail (void) { return ++calls == fail_at; }
static void *test_malloc (size_t n)
{
    allocated_bytes += n;
    void *p = fail () ? NULL : malloc (n);
    if (p) live++;
    return p;
}
static void *test_calloc (size_t n, size_t s)
{
    allocated_bytes += n * s;
    void *p = fail () ? NULL : calloc (n, s);
    if (p) live++;
    return p;
}
static void *test_realloc (void *old, size_t n)
{
    allocated_bytes += n;
    int had_old = old != NULL;
    void *p = fail () ? NULL : realloc (old, n);
    if (p && !had_old) live++;
    return p;
}
static void test_free (void *p) { if (p) live--; free (p); }
static void *test_memcpy (void *dst, const void *src, size_t n)
{
    copied_bytes += n;
    return memcpy (dst, src, n);
}
static int test_memcmp (const void *a, const void *b, size_t n)
{
    compare_calls++;
    compare_requested_bytes += n;
    return memcmp (a, b, n);
}

#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#define free test_free
#define memcpy test_memcpy
#define memcmp test_memcmp
#define diff_builtin production_diff_builtin
#ifndef SOL_DIFF_SOURCE
#define SOL_DIFF_SOURCE "../loadables/diff.c"
#endif
#include SOL_DIFF_SOURCE
#undef diff_builtin
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef memcpy
#undef memcmp

static int fixture_builtin (WORD_LIST *list)
{
    const char *value = getenv ("BASHOS_DIFF_FAIL");
    fail_at = value ? strtol (value, NULL, 10) : 0;
    calls = 0;
    allocated_bytes = copied_bytes = compare_calls = compare_requested_bytes = 0;
    int rc = production_diff_builtin (list);
    if (live) { fprintf (stderr, "allocation leak: %ld\n", live); abort (); }
    if (getenv ("BASHOS_DIFF_REPORT")) fprintf (stderr, "allocations=%ld\n", calls);
    if (getenv ("BASHOS_DIFF_PROFILE"))
        fprintf (stderr, "{\"allocations\":%ld,\"allocated_bytes_total\":%zu,"
                 "\"memcpy_bytes\":%zu,\"memcmp_calls\":%zu,\"memcmp_requested_bytes\":%zu}\n",
                 calls, allocated_bytes, copied_bytes, compare_calls, compare_requested_bytes);
    return rc;
}

struct builtin diff_struct = {
    "diff", fixture_builtin, BUILTIN_ENABLED, diff_doc, "diff [-uqi] FILE1 FILE2", 0
};
