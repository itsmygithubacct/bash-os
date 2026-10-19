/* SPDX-License-Identifier: MIT */
/* Build separately with sol-bsdgames-build.sh; execute under the bench gate.
 * Include the production implementation so the timed function cannot drift. */
#include "../loadables/bsdgames.c"
#include <assert.h>

static uint64_t ns (void)
{
    struct timespec t;
    assert (clock_gettime (CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t) t.tv_sec * 1000000000 + t.tv_nsec;
}

int main (void)
{
    const size_t n = 8 * 1024 * 1024;
    const int passes = 16;
    unsigned char *buf = malloc (n), *original = malloc (n), *rotated = malloc (n);
    unsigned char map[256];
    assert (buf && original && rotated);
    for (unsigned c = 0; c < 256; c++) {
        map[c] = c;
        if (c >= 'a' && c <= 'z') map[c] = 'a' + (c - 'a' + 13) % 26;
        if (c >= 'A' && c <= 'Z') map[c] = 'A' + (c - 'A' + 13) % 26;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned c = i % 256;
        original[i] = c;
        /* Oracle uses alphabet halves rather than the production lookup. */
        rotated[i] = ((c >= 'A' && c <= 'M') || (c >= 'a' && c <= 'm')) ? c + 13 :
                     ((c >= 'N' && c <= 'Z') || (c >= 'n' && c <= 'z')) ? c - 13 : c;
    }
    printf ("{\"bytes_per_pass\":%zu,\"passes\":%d,\"warmups\":1,\"runs_ns\":[", n, passes);
    for (int sample = -1; sample < 7; sample++) {
        uint64_t total = 0;
        memcpy (buf, original, n);
        for (int p = 0; p < passes; p++) {
            uint64_t start = ns ();
            bsdg_caesar_transform (buf, n, map);
            total += ns () - start;
            assert (memcmp (buf, p % 2 ? original : rotated, n) == 0);
        }
        if (sample >= 0) printf ("%s%llu", sample ? "," : "", (unsigned long long) total);
    }
    puts ("],\"validation\":\"every pass exact independent all-byte oracle\"}");
    free (buf); free (original); free (rotated);
    return 0;
}
