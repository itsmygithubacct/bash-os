/* SPDX-License-Identifier: MIT */
/* A .git/index from anywhere at all.
 *
 * The index is a file this build reads before nearly every command, and a
 * repository can be handed over with any bytes in it. It is read here
 * both ways it is read in earnest — as views over the file for the
 * commands that only look, and decoded into entries for the ones that
 * edit — out of a file in memory, so a run costs no disk.
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../loadables/_git/index.c"
#include "../loadables/_sha1dc/sha1.h"

void builtin_error (const char *format, ...) { (void) format; }

int
bgit_sha1 (const unsigned char *data, size_t n, unsigned char digest[20])
{
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) data, n);
    return SHA1DCFinal (digest, &ctx) == 0 ? 0 : -1;
}

int
bgit_hex_to_sha (const char *hex, unsigned char *sha)
{
    for (int i = 0; i < 20; i++) {
        unsigned value = 0;
        for (int half = 0; half < 2; half++) {
            char c = hex[i * 2 + half];
            value <<= 4;
            if (c >= '0' && c <= '9') value |= (unsigned) (c - '0');
            else if (c >= 'a' && c <= 'f') value |= (unsigned) (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value |= (unsigned) (c - 'A' + 10);
        }
        sha[i] = (unsigned char) value;
    }
    return 0;
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

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    if (size > 1 << 16) return 0;
    static int held = -1;
    if (held < 0) {
        held = memfd_create ("index", 0);
        if (held < 0) return 0;
    }
    if (ftruncate (held, 0) < 0) return 0;
    if (size && pwrite (held, data, size, 0) != (ssize_t) size) return 0;
    char path[64];
    snprintf (path, sizeof path, "/proc/self/fd/%d", held);

    bgit_index_view *views = NULL;
    unsigned char *backing = NULL;
    size_t n = 0;
    if (bgit_index_read_views (path, &views, &n, &backing) == 0) {
        for (size_t i = 0; i < n; i++) {
            const bgit_index_view *view = &views[i];
            if (!view->path || !view->disk) __builtin_trap ();
            (void) bgit_be32 (view->disk, 24);
            (void) bgit_be16 (view->disk, 60);
        }
        free (views);
        free (backing);
    }

    bgit_index_entry *entries = NULL;
    n = 0;
    if (bgit_index_read (path, &entries, &n) == 0) {
        for (size_t i = 0; i < n; i++) (void) bgit_index_racy (&entries[i]);
        bgit_index_free_entries (entries, n);
    }

    /* The extensions past the entries, which fsck and prune read as heads:
       a conflict's kept sides and the trees already worked out. */
    char (*ids)[41] = NULL;
    n = 0;
    if (bgit_index_resolve_undo (path, &ids, &n) == 0) {
        for (size_t i = 0; i < n; i++)
            if (ids[i][40] != '\0') __builtin_trap ();
        free (ids);
    }
    ids = NULL;
    n = 0;
    if (bgit_index_cache_tree (path, &ids, &n) == 0) {
        for (size_t i = 0; i < n; i++)
            if (ids[i][40] != '\0') __builtin_trap ();
        free (ids);
    }
    return 0;
}
