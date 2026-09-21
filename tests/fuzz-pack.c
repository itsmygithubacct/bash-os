/* SPDX-License-Identifier: MIT */
/* Packfiles, deltas and indexes from anywhere at all.
 *
 * A clone reads a packfile written by the other end, and an index is read
 * from disk, so both are input from outside. The first byte of each case
 * says which of them this one is, and the rest is the input itself. The
 * last case is the other direction: a delta this build writes must apply
 * back to exactly what it was made from, which is a property worth
 * holding the writer to.
 */
#include <stdarg.h>
#include "../loadables/_git/pack.c"
#include "../loadables/_sha1dc/sha1.h"

void builtin_error (const char *format, ...) { (void) format; }

/* What pack.c wants from the object store, and no more than that. */
int
bgit_sha1 (const unsigned char *data, size_t n, unsigned char digest[20])
{
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) data, n);
    return SHA1DCFinal (digest, &ctx) == 0 ? 0 : -1;
}

void
bgit_sha_to_hex (const unsigned char sha[20], char out[41])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[i * 2] = digits[sha[i] >> 4];
        out[i * 2 + 1] = digits[sha[i] & 15];
    }
    out[40] = '\0';
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    if (size < 4 || size > 1 << 16) return 0;
    unsigned char which = data[0] & 3;
    unsigned char split_at = data[1];
    size_t n = size - 2;
    size_t split = (size_t) split_at * n / 256;
    /* A pack is read out of a buffer of its own, as every caller here has
       one: a pointer into the middle of something else would have the
       hashing read across word boundaries it never reads across in
       earnest. */
    unsigned char *rest = malloc (n);
    if (!rest) return 0;
    memcpy (rest, data + 2, n);

    if (which == 0) {
        /* A delta and the base it claims to be against. */
        unsigned char *out = NULL;
        size_t out_len = 0;
        if (bgit_pack_apply_delta (rest, split, rest + split, n - split, &out,
                                   &out_len) == 0)
            free (out);
        free (rest);
        return 0;
    }
    if (which == 1) {
        /* A pack, read object by object the way indexing one reads it. */
        bgit_pack_cache_release ();
        if (n < 32) { free (rest); return 0; }
        uint64_t at = 12;
        for (int i = 0; i < 64; i++) {
            int type;
            uint64_t object_size, next;
            if (bgit_pack_read_obj_header (rest, n - 20, at, &type,
                                           &object_size, &next) < 0)
                break;
            unsigned char *out = NULL;
            size_t out_len = 0;
            if (bgit_pack_read_object_at (rest, n, NULL, 0, NULL, at, &type,
                                          &out, &out_len, 0) == 0)
                free (out);
            size_t used = 0;
            unsigned char *raw = NULL;
            size_t raw_len = 0;
            if (bgit_pack_inflate (rest + next, (size_t) (n - 20 - next),
                                   (size_t) object_size, &raw, &raw_len,
                                   &used) < 0)
                break;
            free (raw);
            at = next + used;
            if (at + 20 >= n) break;
        }
        bgit_pack_cache_release ();
        free (rest);
        return 0;
    }
    if (which == 2) {
        /* An index, checked and then asked where an object is. */
        bgit_pack_verify_idx (rest, n, NULL);
        unsigned char sha[20];
        for (int i = 0; i < 20; i++) sha[i] = rest[i % n];
        bgit_pack_lookup_offset (rest, n, sha);
        free (rest);
        return 0;
    }

    /* The other direction: what this build writes must read back. A delta
       from the first part of the input to the second, applied to the
       first, has to give the second exactly. */
    if (split < 16 || n - split < 1) { free (rest); return 0; }
    bgit_delta_index *index = bgit_delta_index_create (rest, split);
    if (!index) { free (rest); return 0; }
    unsigned char *delta = NULL;
    size_t delta_len = 0;
    if (bgit_delta_create (index, rest + split, n - split, (size_t) -1 / 2,
                           &delta, &delta_len) == 0) {
        unsigned char *back = NULL;
        size_t back_len = 0;
        if (bgit_pack_apply_delta (rest, split, delta, delta_len, &back,
                                   &back_len) != 0)
            __builtin_trap ();          /* a delta written here must apply */
        if (back_len != n - split || memcmp (back, rest + split, back_len))
            __builtin_trap ();          /* and must give back what it made */
        free (back);
        free (delta);
    }
    bgit_delta_index_free (index);
    free (rest);
    return 0;
}
