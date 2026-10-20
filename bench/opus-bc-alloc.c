/* SPDX-License-Identifier: MIT */
/* opus-bc-alloc.c — count heap calls made while a bc builtin runs.
 *
 * An LD_PRELOAD shim for bench/opus-bc.py --alloc: it forwards malloc,
 * calloc, realloc and free to the C library and counts every call the
 * process makes.  The harness also runs the same shell loop with `:` in
 * place of bc and subtracts that, leaving the calls bc itself made.  The
 * totals are written to the file named by OPUS_BC_ALLOC_OUT at exit.
 *
 *   cc -O2 -fPIC -shared bench/opus-bc-alloc.c -o alloc.so -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *(*real_malloc) (size_t);
static void *(*real_calloc) (size_t, size_t);
static void *(*real_realloc) (void *, size_t);
static void (*real_free) (void *);
static unsigned long long n_malloc, n_calloc, n_realloc, n_free, bytes;

/* dlsym may call calloc before real_calloc is known: serve it from here. */
static char bootstrap[4096];
static size_t bootstrap_used;

static void
resolve (void)
{
    if (real_malloc) return;
    real_calloc = dlsym (RTLD_NEXT, "calloc");
    real_malloc = dlsym (RTLD_NEXT, "malloc");
    real_realloc = dlsym (RTLD_NEXT, "realloc");
    real_free = dlsym (RTLD_NEXT, "free");
}

void *
malloc (size_t n)
{
    resolve ();
    n_malloc++;
    bytes += n;
    return real_malloc (n);
}

void *
calloc (size_t a, size_t b)
{
    if (!real_calloc) {
        if (!real_malloc && bootstrap_used + a * b + 16 <= sizeof bootstrap) {
            void *p = bootstrap + bootstrap_used;
            bootstrap_used += (a * b + 15) & ~(size_t) 15;
            return p;
        }
        resolve ();
    }
    n_calloc++;
    bytes += a * b;
    return real_calloc (a, b);
}

void *
realloc (void *p, size_t n)
{
    resolve ();
    n_realloc++;
    bytes += n;
    return real_realloc (p, n);
}

void
free (void *p)
{
    if ((char *) p >= bootstrap && (char *) p < bootstrap + sizeof bootstrap) return;
    resolve ();
    if (p) n_free++;
    real_free (p);
}

__attribute__ ((destructor)) static void
report (void)
{
    const char *path = getenv ("OPUS_BC_ALLOC_OUT");
    if (!path) return;
    FILE *f = fopen (path, "w");
    if (!f) return;
    fprintf (f, "{\"malloc\": %llu, \"calloc\": %llu, \"realloc\": %llu, \"free\": %llu, \"bytes\": %llu}\n",
             n_malloc, n_calloc, n_realloc, n_free, bytes);
    fclose (f);
}
