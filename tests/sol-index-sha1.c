/* SPDX-License-Identifier: MIT */
/* The index trailer's plain SHA-1, held against FIPS 180 vectors and SHA1DC.
 *
 * loadables/_git/index.c computes the 20-byte trailer of every index it
 * reads or writes with its own SHA-1. This includes that file, checks the
 * published FIPS 180-2 digests, then compares it with the independent SHA1DC
 * implementation over every length from 0 to 4100 bytes of seeded
 * pseudo-random data, which crosses each padding boundary (55/56/63/64 mod
 * 64) many times, and over a 1 MiB buffer at every starting alignment 0-7.
 */
#define _GNU_SOURCE 1
#include <stdarg.h>
#include "../loadables/_git/index.c"
#include "../loadables/_sha1dc/sha1.h"

void builtin_error (const char *format, ...) { (void) format; }
int bgit_hex_to_sha (const char *hex, unsigned char *sha) { (void) hex; memset (sha, 0, 20); return 0; }
void bgit_sha_to_hex (const unsigned char *sha, char *out) { (void) sha; out[0] = 0; }

static void
reference (const unsigned char *p, size_t n, unsigned char d[20])
{
    /* SHA1DC loads words directly from unaligned input, which UBSan
       reports, so it is handed an aligned copy. */
    unsigned char *copy = malloc (n ? n : 1);
    memcpy (copy, p, n);
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) copy, n);
    SHA1DCFinal (d, &ctx);
    free (copy);
}

static void
hex (const unsigned char d[20], char out[41])
{
    for (int i = 0; i < 20; i++) sprintf (out + 2 * i, "%02x", d[i]);
}

int
main (void)
{
    int checks = 0, failures = 0;
    static const struct { const char *msg; size_t repeat; const char *digest; } vectors[] = {
        { "", 1, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { "abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
          "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { "a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
    };
    for (size_t v = 0; v < sizeof vectors / sizeof *vectors; v++) {
        size_t unit = strlen (vectors[v].msg), n = unit * vectors[v].repeat;
        unsigned char *m = malloc (n ? n : 1), d[20];
        char got[41];
        for (size_t i = 0; i < vectors[v].repeat; i++) memcpy (m + i * unit, vectors[v].msg, unit);
        bgit_index_sha1 (m, n, d);
        hex (d, got);
        checks++;
        if (strcmp (got, vectors[v].digest)) {
            failures++;
            fprintf (stderr, "vector %zu: %s != %s\n", v, got, vectors[v].digest);
        }
        free (m);
    }

    size_t big = (size_t) 1 << 20;
    unsigned char *data = malloc (big + 8);
    uint64_t x = 0x9E3779B97F4A7C15ull;
    for (size_t i = 0; i < big + 8; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        data[i] = (unsigned char) x;
    }
    for (size_t n = 0; n <= 4100; n++) {
        unsigned char a[20], b[20];
        bgit_index_sha1 (data + (n % 8), n, a);
        reference (data + (n % 8), n, b);
        checks++;
        if (memcmp (a, b, 20)) { failures++; fprintf (stderr, "length %zu differs\n", n); }
    }
    for (size_t align = 0; align < 8; align++) {
        unsigned char a[20], b[20];
        bgit_index_sha1 (data + align, big, a);
        reference (data + align, big, b);
        checks++;
        if (memcmp (a, b, 20)) { failures++; fprintf (stderr, "1 MiB at %zu differs\n", align); }
    }
    free (data);
    printf ("index-sha1: %d checks, %d failures\n", checks, failures);
    return failures != 0;
}
