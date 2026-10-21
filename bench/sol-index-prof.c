/* SPDX-License-Identifier: MIT */
/* Phase timings for `index read`, over the production index reader.
 *
 * This includes loadables/_git/index.c itself, the code the builtin calls,
 * and times its parts on one index file: the read with the checksum
 * computed (cold), the read once the verified-bytes snapshot holds the file
 * (warm), the SHA-1 alone, and the path checks alone. It reports medians of
 * many repetitions in microseconds. The builtin's own formatting and output
 * are timed from the shell, not here.
 *
 *   sol-index-prof INDEX [REPEATS]
 */
#define _GNU_SOURCE 1
#include <stdarg.h>
#include <time.h>
#include "../loadables/_git/index.c"
#include "../loadables/_sha1dc/sha1.h"

void builtin_error (const char *format, ...)
{
    va_list ap;
    va_start (ap, format);
    vfprintf (stderr, format, ap);
    va_end (ap);
    fputc ('\n', stderr);
}

int
bgit_hex_to_sha (const char *hex, unsigned char *sha)
{
    (void) hex; memset (sha, 0, 20); return 0;
}

void
bgit_sha_to_hex (const unsigned char *sha, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[i * 2] = hex[sha[i] >> 4];
        out[i * 2 + 1] = hex[sha[i] & 15];
    }
    out[40] = '\0';
}

static double
now_us (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int
cmp_double (const void *a, const void *b)
{
    double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

static double
median (double *v, int n)
{
    qsort (v, n, sizeof *v, cmp_double);
    return v[n / 2];
}

int
main (int argc, char **argv)
{
    if (argc < 2) { fprintf (stderr, "usage: %s INDEX [REPEATS]\n", argv[0]); return 2; }
    const char *path = argv[1];
    int reps = argc > 2 ? atoi (argv[2]) : 51;
    if (reps < 3) reps = 3;
    double *t = calloc (reps, sizeof *t);
    bgit_index_view *views; size_t n; unsigned char *backing;

    /* cold: the snapshot dropped before every read */
    for (int r = 0; r < reps; r++) {
        bgit_index_cache_release ();
        double a = now_us ();
        if (bgit_index_read_views (path, &views, &n, &backing) < 0) return 1;
        t[r] = now_us () - a;
        free (views); free (backing);
    }
    printf ("entries %zu\n", n);
    printf ("read_views_cold_us %.1f\n", median (t, reps));

    /* warm: the same bytes as the last verified read */
    bgit_index_read_views (path, &views, &n, &backing);
    free (views); free (backing);
    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        bgit_index_read_views (path, &views, &n, &backing);
        t[r] = now_us () - a;
        free (views); free (backing);
    }
    printf ("read_views_warm_us %.1f\n", median (t, reps));

    size_t flen = 0;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        unsigned char *b2 = bgit_index_slurp (path, &flen);
        t[r] = now_us () - a;
        free (b2);
    }
    printf ("slurp_us %.1f bytes %zu\n", median (t, reps), flen);

    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        SHA1_CTX ctx; unsigned char d[20];
        SHA1DCInit (&ctx); SHA1DCSetSafeHash (&ctx, 0);
        SHA1DCUpdate (&ctx, (const char *) buf, flen - 20);
        SHA1DCFinal (d, &ctx);
        t[r] = now_us () - a;
    }
    printf ("sha1dc_us %.1f\n", median (t, reps));

    /* the same digest without collision detection */
    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        SHA1_CTX ctx; unsigned char d[20];
        SHA1DCInit (&ctx); SHA1DCSetSafeHash (&ctx, 0);
        SHA1DCSetUseDetectColl (&ctx, 0);
        SHA1DCUpdate (&ctx, (const char *) buf, flen - 20);
        SHA1DCFinal (d, &ctx);
        t[r] = now_us () - a;
    }
    printf ("sha1dc_nodetect_us %.1f\n", median (t, reps));

    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        unsigned char d[20];
        bgit_index_sha1 (buf, flen - 20, d);
        t[r] = now_us () - a;
    }
    printf ("trailer_sha1_us %.1f\n", median (t, reps));

    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        volatile int same = bgit_index_checksum_cached (buf, flen);
        (void) same;
        t[r] = now_us () - a;
    }
    printf ("snapshot_memcmp_us %.1f\n", median (t, reps));

    bgit_index_read_views (path, &views, &n, &backing);
    for (int r = 0; r < reps; r++) {
        double a = now_us ();
        volatile int ok = 0;
        for (size_t i = 0; i < n; i++) ok += bgit_index_path_valid (views[i].path);
        t[r] = now_us () - a;
    }
    printf ("path_valid_us %.1f\n", median (t, reps));
    free (views); free (backing); free (buf); free (t);
    return 0;
}
