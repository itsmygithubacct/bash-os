/* SPDX-License-Identifier: MIT */
/* _git/index.c — git index (.git/index) reading and writing.
 *
 * Moved out of the index builtin so the git builtins share one
 * implementation. See index.h for the contract; the behaviour, including
 * every message, is the same as when the builtin held this code.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"

#include "index.h"
#include "odb.h"

uint32_t
bgit_be32 (const unsigned char *buf, size_t off)
{
    return ((uint32_t) buf[off] << 24) | ((uint32_t) buf[off+1] << 16) |
           ((uint32_t) buf[off+2] <<  8) | ((uint32_t) buf[off+3]);
}

uint16_t
bgit_be16 (const unsigned char *buf, size_t off)
{
    return (uint16_t) (((uint16_t) buf[off] << 8) | (uint16_t) buf[off+1]);
}

static void
bgit_put_be32 (unsigned char *buf, uint32_t v)
{
    buf[0] = (unsigned char) (v >> 24); buf[1] = (unsigned char) (v >> 16);
    buf[2] = (unsigned char) (v >> 8);  buf[3] = (unsigned char) v;
}

static void
bgit_put_be16 (unsigned char *buf, uint16_t v)
{
    buf[0] = (unsigned char) (v >> 8); buf[1] = (unsigned char) v;
}

int
bgit_index_parse_mode (const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoul (s, &end, 8);
    if (errno || !end || *end != '\0' || v > UINT32_MAX)
        return -1;
    *out = (uint32_t) v;
    return 0;
}

int
bgit_index_parse_stage (const char *s, int *out)
{
    char *end = NULL;
    long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtol (s, &end, 10);
    if (errno || !end || *end != '\0' || v < 0 || v > 3)
        return -1;
    *out = (int) v;
    return 0;
}

int
bgit_index_path_valid (const char *path)
{
    if (!path || !*path) return 0;
    for (const char *part = path; ; ) {
        const char *slash = strchr (part, '/');
        size_t len = slash ? (size_t) (slash - part) : strlen (part);
        if (!len || (len == 1 && part[0] == '.') ||
            (len == 2 && !memcmp (part, "..", 2)) ||
            (len == 4 && !strncasecmp (part, ".git", 4)))
            return 0;
        if (!slash) return 1;
        part = slash + 1;
    }
}

void
bgit_index_entry_set_stat (bgit_index_entry *e, const struct stat *st)
{
    e->ctime_sec  = (uint32_t) st->st_ctim.tv_sec;
    e->ctime_nsec = (uint32_t) st->st_ctim.tv_nsec;
    e->mtime_sec  = (uint32_t) st->st_mtim.tv_sec;
    e->mtime_nsec = (uint32_t) st->st_mtim.tv_nsec;
    e->dev = (uint32_t) st->st_dev;
    e->ino = (uint32_t) st->st_ino;
    e->mode = (uint32_t) st->st_mode;
    e->uid = (uint32_t) st->st_uid;
    e->gid = (uint32_t) st->st_gid;
    e->size = (uint32_t) st->st_size;
}

void
bgit_index_free_entries (bgit_index_entry *e, size_t n)
{
    for (size_t i = 0; i < n; i++) free (e[i].path);
    free (e);
}

/* ---- the trailer checksum ------------------------------------------------

   The last 20 bytes of an index are the SHA-1 of everything before them.
   That digest guards against a torn or corrupted file; it authenticates
   nothing, since whoever can write the index can write a matching trailer,
   and git itself does not verify it on an ordinary read. Collision
   detection buys nothing here, and SHA1DC with it on is the larger part of
   reading a big index, so the trailer is computed by plain SHA-1 (FIPS
   180-4), with the message schedule kept in a rolling 16-word window.
   Object ids, where collisions do matter, still go through SHA1DC. */

#define BGIT_ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define BGIT_SHA1_W(t) \
    (w[(t) & 15] = BGIT_ROL32 (w[((t) + 13) & 15] ^ w[((t) + 8) & 15] ^ \
                               w[((t) + 2) & 15] ^ w[(t) & 15], 1))
#define BGIT_SHA1_STEP(a, b, c, d, e, f, k, x) \
    do { e += BGIT_ROL32 (a, 5) + (f) + (k) + (x); b = BGIT_ROL32 (b, 30); } while (0)
#define BGIT_SHA1_F1(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
#define BGIT_SHA1_F2(b, c, d) ((b) ^ (c) ^ (d))
#define BGIT_SHA1_F3(b, c, d) (((b) & (c)) | ((d) & ((b) | (c))))
#define BGIT_SHA1_R0(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F1 (b, c, d), 0x5A827999u, w[t])
#define BGIT_SHA1_R1(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F1 (b, c, d), 0x5A827999u, BGIT_SHA1_W (t))
#define BGIT_SHA1_R2(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F2 (b, c, d), 0x6ED9EBA1u, BGIT_SHA1_W (t))
#define BGIT_SHA1_R3(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F3 (b, c, d), 0x8F1BBCDCu, BGIT_SHA1_W (t))
#define BGIT_SHA1_R4(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F2 (b, c, d), 0xCA62C1D6u, BGIT_SHA1_W (t))
#define BGIT_SHA1_FIVE(R, t) \
    R (a, b, c, d, e, (t));     R (e, a, b, c, d, (t) + 1); \
    R (d, e, a, b, c, (t) + 2); R (c, d, e, a, b, (t) + 3); \
    R (b, c, d, e, a, (t) + 4)

static void
bgit_index_sha1_blocks (uint32_t h[5], const unsigned char *p, size_t blocks)
{
    while (blocks--) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = bgit_be32 (p, (size_t) i * 4);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        BGIT_SHA1_FIVE (BGIT_SHA1_R0, 0);  BGIT_SHA1_FIVE (BGIT_SHA1_R0, 5);
        BGIT_SHA1_FIVE (BGIT_SHA1_R0, 10);
        BGIT_SHA1_R0 (a, b, c, d, e, 15);  BGIT_SHA1_R1 (e, a, b, c, d, 16);
        BGIT_SHA1_R1 (d, e, a, b, c, 17);  BGIT_SHA1_R1 (c, d, e, a, b, 18);
        BGIT_SHA1_R1 (b, c, d, e, a, 19);
        BGIT_SHA1_FIVE (BGIT_SHA1_R2, 20); BGIT_SHA1_FIVE (BGIT_SHA1_R2, 25);
        BGIT_SHA1_FIVE (BGIT_SHA1_R2, 30); BGIT_SHA1_FIVE (BGIT_SHA1_R2, 35);
        BGIT_SHA1_FIVE (BGIT_SHA1_R3, 40); BGIT_SHA1_FIVE (BGIT_SHA1_R3, 45);
        BGIT_SHA1_FIVE (BGIT_SHA1_R3, 50); BGIT_SHA1_FIVE (BGIT_SHA1_R3, 55);
        BGIT_SHA1_FIVE (BGIT_SHA1_R4, 60); BGIT_SHA1_FIVE (BGIT_SHA1_R4, 65);
        BGIT_SHA1_FIVE (BGIT_SHA1_R4, 70); BGIT_SHA1_FIVE (BGIT_SHA1_R4, 75);
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        p += 64;
    }
}

/* The SHA-1 of DATA[0..LEN), into DIGEST. */
static void
bgit_index_sha1 (const unsigned char *data, size_t len, unsigned char digest[20])
{
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                      0xC3D2E1F0u };
    size_t whole = len / 64;
    bgit_index_sha1_blocks (h, data, whole);
    unsigned char tail[128];
    size_t rest = len - whole * 64;
    memcpy (tail, data + whole * 64, rest);
    tail[rest] = 0x80;
    size_t tail_len = rest < 56 ? 64 : 128;
    memset (tail + rest + 1, 0, tail_len - rest - 1);
    uint64_t bits = (uint64_t) len * 8;
    for (int i = 0; i < 8; i++)
        tail[tail_len - 1 - i] = (unsigned char) (bits >> (8 * i));
    bgit_index_sha1_blocks (h, tail, tail_len / 64);
    for (int i = 0; i < 5; i++)
        bgit_put_be32 (digest + i * 4, h[i]);
}

/* Slurp file. Caller frees. A directory is refused rather than sized by
   ftell, which reports LONG_MAX for one; anything else is read to its end,
   so a file that grows or shrinks while it is read is taken as it ends. */
static unsigned char *
bgit_index_slurp (const char *path, size_t *out_len)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat (fd, &st) < 0) { int e = errno; close (fd); errno = e; return NULL; }
    if (S_ISDIR (st.st_mode)) { close (fd); errno = EISDIR; return NULL; }
    size_t cap = S_ISREG (st.st_mode) && st.st_size > 0 &&
                 (uint64_t) st.st_size < SIZE_MAX - 1 ? (size_t) st.st_size + 1 : 65536;
    size_t len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); errno = ENOMEM; return NULL; }
    for (;;) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) { free (buf); close (fd); errno = EFBIG; return NULL; }
            unsigned char *grown = realloc (buf, cap * 2);
            if (!grown) { free (buf); close (fd); errno = ENOMEM; return NULL; }
            buf = grown;
            cap *= 2;
        }
        ssize_t got = read (fd, buf + len, cap - len);
        if (got < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            free (buf); close (fd); errno = e;
            return NULL;
        }
        if (got == 0) break;
        len += (size_t) got;
    }
    close (fd);
    *out_len = len;
    return buf;
}

/* Keep one bounded, owned snapshot of successfully checksum-validated bytes.
   Every parse still reads and validates entries anew. Only exact equality of
   the entire file, including its trailer, reuses the earlier checksum result;
   no pathname, metadata, parsed entries or borrowed paths are cached. */
#define BGIT_INDEX_CHECKSUM_CACHE_LIMIT ((size_t) 8 * 1024 * 1024)
static unsigned char *bgit_index_verified_bytes;
static size_t bgit_index_verified_len;

static int
bgit_index_checksum_cached (const unsigned char *buf, size_t len)
{
    return bgit_index_verified_bytes && len == bgit_index_verified_len &&
           memcmp (buf, bgit_index_verified_bytes, len) == 0;
}

static void
bgit_index_remember_verified (const unsigned char *buf, size_t len)
{
    if (len > BGIT_INDEX_CHECKSUM_CACHE_LIMIT) return;
    int saved_errno = errno;
    if (len != bgit_index_verified_len) {
        /* Release first to retain no more than one snapshot. An optional
           allocation failure leaves ordinary checksum validation active. */
        free (bgit_index_verified_bytes);
        bgit_index_verified_bytes = NULL;
        bgit_index_verified_len = 0;
        bgit_index_verified_bytes = malloc (len);
    }
    if (bgit_index_verified_bytes) {
        memcpy (bgit_index_verified_bytes, buf, len);
        bgit_index_verified_len = len;
    }
    errno = saved_errno;
}

void
bgit_index_cache_release (void)
{
    free (bgit_index_verified_bytes);
    bgit_index_verified_bytes = NULL;
    bgit_index_verified_len = 0;
}

int
bgit_index_read_views (const char *path, bgit_index_view **out, size_t *n_out,
                       unsigned char **backing)
{
    size_t flen;
    return bgit_index_read_views_len (path, out, n_out, backing, &flen);
}

int
bgit_index_read_views_len (const char *path, bgit_index_view **out,
                           size_t *n_out, unsigned char **backing,
                           size_t *len_out)
{
    size_t flen;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    if (!buf) {
        builtin_error ("read %s: %s", path, strerror (errno));
        return -1;
    }
    if (flen < 32) {
        free (buf);
        builtin_error ("index too short (%zu bytes)", flen);
        return -1;
    }
    if (memcmp (buf, "DIRC", 4) != 0) {
        free (buf);
        builtin_error ("bad magic (not 'DIRC')");
        return -1;
    }
    uint32_t ver = bgit_be32 (buf, 4);
    if (ver != 2 && ver != 3) {
        free (buf);
        builtin_error ("unsupported index version %u (only 2,3)", ver);
        return -1;
    }
    uint32_t n_entries = bgit_be32 (buf, 8);
    if (n_entries > (flen - 32) / 64) {
        free (buf); builtin_error ("truncated index (entry count)"); return -1;
    }
    bgit_index_view *entries = calloc (n_entries ? n_entries : 1, sizeof *entries);
    if (!entries) { free (buf); return -1; }

    size_t off = 12;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (off + 62 > flen - 20) { /* -20 for trailer */
            free (buf); free (entries);
            builtin_error ("truncated index");
            return -1;
        }
        bgit_index_view *e = &entries[i];
        e->disk = buf + off;
        uint16_t flags = bgit_be16 (buf, off + 60);
        off += 62;

        /* v3+ CE_EXTENDED (0x4000) entries carry a second 16-bit flags
           field (flags2) before the path — git's create_from_disk reads it
           via get_be16(flagsp + sizeof(uint16_t)). We don't model the
           extended-flag semantics (skip-worktree / intent-to-add), but we
           MUST consume the 2 bytes or every following entry misaligns.
           extended_len feeds the 8-byte padding so the on-disk size matches
           git's ondisk_data_size(). */
        size_t extended_len = 0;
        if (ver >= 3 && (flags & 0x4000)) {
            if (off + 2 > flen - 20) {
                free (buf); free (entries);
                builtin_error ("truncated index (extended flags)");
                return -1;
            }
            off += 2;
            extended_len = 2;
        }

        size_t path_len = flags & 0xFFF;
        const unsigned char *nul = memchr (buf + off, 0, flen - 20 - off);
        if (path_len == 0xFFF && nul) path_len = (size_t) (nul - buf - off);
        if (!nul || (size_t) (nul - buf - off) != path_len) {
            free (buf); free (entries);
            builtin_error ("truncated index (path)");
            return -1;
        }
        e->path = (char *) buf + off;
        if (!bgit_index_path_valid (e->path)) {
            builtin_error ("invalid index path '%s'", e->path);
            free (buf); free (entries);
            return -1;
        }
        off += path_len;
        /* Pad to 8-byte boundary. The entry start is 12 bytes into the
           file, so total entry length so far = 62 (+2 if extended) +
           path_len. Pad to multiple of 8 with NULs (at least 1 NUL). */
        size_t entry_len = 62 + extended_len + path_len;
        size_t pad = (8 - (entry_len % 8));
        if (pad == 0) pad = 8;
        if (pad > flen - 20 - off) {
            free (buf); free (entries);
            builtin_error ("truncated index (padding)"); return -1;
        }
        for (size_t j = 0; j < pad; j++) {
            if (buf[off + j] != 0) {
                free (buf); free (entries);
                builtin_error ("invalid index padding"); return -1;
            }
        }
        off += pad;
    }

    /* Validate SHA-1 trailer: last 20 bytes = sha1 of buf[0 .. flen-21].
       Git computes the trailer over the entire index body including headers
       and all entries (everything before the trailer itself). */
    if (flen < 20) {
        free (buf); free (entries);
        builtin_error ("index too short (no trailer)");
        return -1;
    }
    if (!bgit_index_checksum_cached (buf, flen)) {
        unsigned char computed[20];
        bgit_index_sha1 (buf, flen - 20, computed);
        if (memcmp (computed, buf + flen - 20, 20) != 0) {
            free (buf); free (entries);
            builtin_error ("index checksum mismatch");
            return -1;
        }
        bgit_index_remember_verified (buf, flen);
    }

    *backing = buf;
    *out = entries;
    *n_out = n_entries;
    *len_out = flen;
    return 0;
}

/* When the index itself was last written, for the racy-entry rule. */
static uint32_t bgit_index_stamp_sec, bgit_index_stamp_nsec;
static int bgit_index_stamped;

int
bgit_index_racy (const bgit_index_entry *entry)
{
    /* An entry written in the same second as the index itself, or later,
       cannot be told from a changed one by its stat data, so only its
       content can say. git draws the line by seconds, since it compares
       timestamps by seconds. */
    if (!bgit_index_stamped || !bgit_index_stamp_sec) return 0;
    return entry->mtime_sec >= bgit_index_stamp_sec;
}

static void
bgit_index_stamp (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0) return;
    bgit_index_stamp_sec = (uint32_t) st.st_mtim.tv_sec;
    bgit_index_stamp_nsec = (uint32_t) st.st_mtim.tv_nsec;
    bgit_index_stamped = 1;
}

void
bgit_index_unstamp (void)
{
    bgit_index_stamp_sec = bgit_index_stamp_nsec = 0;
    bgit_index_stamped = 0;
}

int
bgit_index_read (const char *path, bgit_index_entry **out, size_t *n_out)
{
    bgit_index_view *views;
    size_t n;
    unsigned char *backing;
    if (bgit_index_read_views (path, &views, &n, &backing) < 0) return -1;
    return bgit_index_decode_views (path, views, n, backing, out, n_out);
}

int
bgit_index_decode_views (const char *path, bgit_index_view *views, size_t n,
                         unsigned char *backing, bgit_index_entry **out,
                         size_t *n_out)
{
    bgit_index_stamp (path);
    bgit_index_entry *entries = calloc (n ? n : 1, sizeof *entries);
    if (!entries) { free (views); free (backing); return -1; }
    for (size_t i = 0; i < n; i++) {
        const unsigned char *disk = views[i].disk;
        bgit_index_entry *e = &entries[i];
        e->ctime_sec  = bgit_be32 (disk, 0);
        e->ctime_nsec = bgit_be32 (disk, 4);
        e->mtime_sec  = bgit_be32 (disk, 8);
        e->mtime_nsec = bgit_be32 (disk, 12);
        e->dev        = bgit_be32 (disk, 16);
        e->ino        = bgit_be32 (disk, 20);
        e->mode       = bgit_be32 (disk, 24);
        e->uid        = bgit_be32 (disk, 28);
        e->gid        = bgit_be32 (disk, 32);
        e->size       = bgit_be32 (disk, 36);
        memcpy (e->sha, disk + 40, 20);
        e->flags = bgit_be16 (disk, 60);
        e->path = strdup (views[i].path);
        if (!e->path) {
            bgit_index_free_entries (entries, i);
            free (views); free (backing);
            return -1;
        }
    }
    free (views); free (backing);
    *out = entries;
    *n_out = n;
    return 0;
}

int
bgit_index_write (const char *path, bgit_index_entry *entries, size_t n)
{
    return bgit_index_write_ext (path, entries, n, NULL, 0);
}

int
bgit_index_write_ext (const char *path, bgit_index_entry *entries, size_t n,
                      const unsigned char *ext, size_t ext_len)
{
    if (n > UINT32_MAX) { builtin_error ("too many index entries"); return -1; }
    /* Build buffer in memory, then mkstemp + rename. */
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;

    /* Header */
    memcpy (buf + len, "DIRC", 4); len += 4;
    bgit_put_be32 (buf + len, 2); len += 4;
    bgit_put_be32 (buf + len, (uint32_t) n); len += 4;

    for (size_t i = 0; i < n; i++) {
        bgit_index_entry *e = &entries[i];
        if (!bgit_index_path_valid (e->path)) {
            builtin_error ("invalid index path '%s'", e->path ? e->path : "");
            free (buf);
            return -1;
        }
        size_t path_len = strlen (e->path);
        if (path_len > SIZE_MAX - 70) { free (buf); return -1; }
        size_t entry_len = 62 + path_len;
        size_t pad = (8 - (entry_len % 8));
        if (pad == 0) pad = 8;
        size_t need = entry_len + pad;
        if (need > SIZE_MAX - len - 20) { free (buf); return -1; }
        if (len + need > cap) {
            while (len + need > cap) {
                if (cap > SIZE_MAX / 2) { cap = len + need; break; }
                cap *= 2;
            }
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return -1; }
            buf = nb;
        }
        bgit_put_be32 (buf + len, e->ctime_sec);   len += 4;
        bgit_put_be32 (buf + len, e->ctime_nsec);  len += 4;
        bgit_put_be32 (buf + len, e->mtime_sec);   len += 4;
        bgit_put_be32 (buf + len, e->mtime_nsec);  len += 4;
        bgit_put_be32 (buf + len, e->dev);         len += 4;
        bgit_put_be32 (buf + len, e->ino);         len += 4;
        bgit_put_be32 (buf + len, e->mode);        len += 4;
        bgit_put_be32 (buf + len, e->uid);         len += 4;
        bgit_put_be32 (buf + len, e->gid);         len += 4;
        /* An entry racy against the index we read is written with size
           zero, as git writes it: the next process then sees the size
           disagree and reads the file rather than trusting the stat. */
        bgit_put_be32 (buf + len, bgit_index_racy (e) ? 0 : e->size);
        len += 4;
        memcpy (buf + len, e->sha, 20);            len += 20;
        /* We always emit version 2, which has no flags2 field, so
           CE_EXTENDED (0x4000) must be cleared — keep only assume-valid
           (0x8000) and the 2-bit stage (0x3000). This mirrors git's
           do_write_index, which strips CE_EXTENDED when writing v2;
           leaving it set would make git try to read a flags2 that isn't
           there. */
        uint16_t flags = (uint16_t) ((e->flags & 0xB000)
            | (path_len > 0xFFF ? 0xFFF : path_len));
        bgit_put_be16 (buf + len, flags);          len += 2;
        memcpy (buf + len, e->path, path_len);     len += path_len;
        memset (buf + len, 0, pad);                len += pad;
    }

    /* Extension records the caller has laid out, then the trailer: the
       SHA-1 of everything before it. */
    if (ext_len > SIZE_MAX - len - 20) { free (buf); return -1; }
    if (len + ext_len + 20 > cap) {
        cap = len + ext_len + 20;
        unsigned char *nb = realloc (buf, cap);
        if (!nb) { free (buf); return -1; }
        buf = nb;
    }
    if (ext_len) memcpy (buf + len, ext, ext_len);
    len += ext_len;
    unsigned char digest[20];
    bgit_index_sha1 (buf, len, digest);
    if (len + 20 > cap) {
        cap = len + 20;
        unsigned char *nb = realloc (buf, cap);
        if (!nb) { free (buf); return -1; }
        buf = nb;
    }
    memcpy (buf + len, digest, 20); len += 20;

    /* Atomic write. */
    char tmp[4096];
    if (snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path) >= (int) sizeof tmp) {
        free (buf); builtin_error ("index path too long"); return -1;
    }
    int fd = mkstemp (tmp);
    if (fd < 0) { free (buf); builtin_error ("mkstemp: %s", strerror (errno)); return -1; }
    fchmod (fd, 0644);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write (fd, buf + off, len - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            builtin_error ("write %s: %s", tmp, w < 0 ? strerror (errno) : "short write");
            close (fd); unlink (tmp); free (buf); return -1;
        }
        off += w;
    }
    int sync_rc = fdatasync (fd);
    int sync_errno = errno;
    int close_rc = close (fd);
    if (sync_rc < 0 || close_rc < 0) {
        builtin_error ("%s %s: %s", sync_rc < 0 ? "fdatasync" : "close", tmp,
                       strerror (sync_rc < 0 ? sync_errno : errno));
        unlink (tmp); free (buf); return -1;
    }
    if (rename (tmp, path) < 0) {
        unlink (tmp); free (buf);
        builtin_error ("rename: %s", strerror (errno));
        return -1;
    }
    free (buf);
    return 0;
}

int
bgit_index_line_to_entry (const char *line, const char *working_root,
                          bgit_index_entry *out)
{
    /* Split: mode sha stage path */
    char mode_s[16], sha_s[64], stage_s[16];
    int stage;
    int prefix_len = 0;
    if (sscanf (line, "%15s %63s %15s %n", mode_s, sha_s, stage_s, &prefix_len) < 3) {
        return -1;
    }
    if (bgit_index_parse_stage (stage_s, &stage) < 0)
        return -2;
    const char *path = line + prefix_len;
    /* Trim trailing newline */
    size_t pl = strlen (path);
    while (pl > 0 && (path[pl-1] == '\n' || path[pl-1] == '\r')) pl--;
    if (pl == 0) return -1;

    memset (out, 0, sizeof *out);
    if (bgit_index_parse_mode (mode_s, &out->mode) < 0) return -1;
    if (bgit_hex_to_sha (sha_s, out->sha) < 0) return -1;
    out->flags = (uint16_t) (((stage & 0x3) << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = malloc (pl + 1);
    if (!out->path) return -1;
    memcpy (out->path, path, pl);
    out->path[pl] = '\0';
    if (!bgit_index_path_valid (out->path)) {
        free (out->path);
        out->path = NULL;
        return -1;
    }

    /* If working_root + path resolves, populate stat fields. */
    if (working_root) {
        char fp[8192];
        snprintf (fp, sizeof fp, "%s/%s", working_root, out->path);
        struct stat st;
        if (stat (fp, &st) == 0) {
            bgit_index_entry_set_stat (out, &st);
        }
    }
    return 0;
}

int
bgit_index_path_cmp (const void *a, const void *b)
{
    const bgit_index_entry *ea = a, *eb = b;
    int r = strcmp (ea->path, eb->path);
    if (r != 0)
        return r;
    int sa = (ea->flags >> 12) & 0x3;
    int sb = (eb->flags >> 12) & 0x3;
    return sa - sb;
}

int
bgit_index_remove_path (bgit_index_entry **entries, size_t *n, const char *path)
{
    size_t w = 0;
    int removed = 0;

    for (size_t r = 0; r < *n; r++) {
        if (strcmp ((*entries)[r].path, path) == 0) {
            free ((*entries)[r].path);
            removed = 1;
            continue;
        }
        if (w != r)
            (*entries)[w] = (*entries)[r];
        w++;
    }
    *n = w;
    return removed;
}

int
bgit_index_info_line_to_entry (char *line, bgit_index_entry *out,
                               int *is_remove)
{
    char *tab = strchr (line, '\t');
    char *path;
    char *tok[3] = { NULL, NULL, NULL };
    int ntok = 0;
    char *save = NULL;
    uint32_t mode;
    const char *sha_s;
    int stage = 0;

    *is_remove = 0;
    if (!tab)
        return -1;
    *tab = '\0';
    path = tab + 1;
    size_t pl = strlen (path);
    while (pl > 0 && (path[pl-1] == '\n' || path[pl-1] == '\r')) {
        path[--pl] = '\0';
    }
    if (!bgit_index_path_valid (path))
        return -1;

    for (char *p = strtok_r (line, " ", &save);
         p && ntok < 3;
         p = strtok_r (NULL, " ", &save)) {
        tok[ntok++] = p;
    }
    if (strtok_r (NULL, " ", &save) != NULL)
        return -1;
    if (ntok != 2 && ntok != 3)
        return -1;
    if (bgit_index_parse_mode (tok[0], &mode) < 0)
        return -1;

    if (ntok == 2) {
        sha_s = tok[1];                 /* mode SP sha1 TAB path */
    } else if (strlen (tok[1]) == 40 &&
               bgit_index_parse_stage (tok[2], &stage) == 0) {
        sha_s = tok[1];                 /* mode SP sha1 SP stage TAB path */
    } else {
        sha_s = tok[2];                 /* mode SP type SP sha1 TAB path */
        stage = 0;
    }

    memset (out, 0, sizeof *out);
    out->mode = mode;
    if (bgit_hex_to_sha (sha_s, out->sha) < 0)
        return -1;
    if (mode == 0) {
        *is_remove = 1;
        out->path = strdup (path);
        return out->path ? 0 : -1;
    }
    if (stage < 0 || stage > 3)
        return -1;
    out->flags = (uint16_t) (((stage & 0x3) << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = strdup (path);
    return out->path ? 0 : -1;
}

/* ---- resolve-undo ------------------------------------------------------- */

/* Where an index's extensions begin, which is after its entries. The file
   is returned mapped; the caller frees it. Silent. */
static int
bgit_index_after_entries (const char *path, unsigned char **buf_out,
                          size_t *flen_out, size_t *off_out)
{
    size_t flen;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    if (!buf) return -1;
    if (flen < 32 || memcmp (buf, "DIRC", 4) != 0) { free (buf); return -1; }
    uint32_t ver = bgit_be32 (buf, 4);
    if (ver != 2 && ver != 3) { free (buf); return -1; }
    uint32_t n_entries = bgit_be32 (buf, 8);

    size_t off = 12;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (off + 62 > flen - 20) { free (buf); return -1; }
        uint16_t flags = bgit_be16 (buf, off + 60);
        off += 62;
        size_t extended_len = 0;
        if (ver >= 3 && (flags & 0x4000)) {
            if (off + 2 > flen - 20) { free (buf); return -1; }
            off += 2;
            extended_len = 2;
        }
        size_t path_len = flags & 0xFFF;
        const unsigned char *nul = memchr (buf + off, 0, flen - 20 - off);
        if (path_len == 0xFFF && nul) path_len = (size_t) (nul - buf - off);
        if (!nul || (size_t) (nul - buf - off) != path_len) {
            free (buf);
            return -1;
        }
        off += path_len;
        size_t entry_len = 62 + extended_len + path_len;
        size_t pad = 8 - (entry_len % 8);
        if (pad > flen - 20 - off) { free (buf); return -1; }
        off += pad;
    }
    *buf_out = buf;
    *flen_out = flen;
    *off_out = off;
    return 0;
}

/* Room for one more id in a growing list. Returns 0, or -1. */
static int
bgit_index_ids_room (char (**ids)[41], size_t n, size_t *cap)
{
    if (n < *cap) return 0;
    size_t next = *cap ? *cap * 2 : 16;
    char (*grown)[41] = realloc (*ids, next * sizeof *grown);
    if (!grown) return -1;
    *ids = grown;
    *cap = next;
    return 0;
}

/* The extension holds, for each path whose conflict was resolved, the three
   stage modes as octal text and one object id for every mode that is not
   zero. Nothing else here reads it; fsck counts those ids as held. */
int
bgit_index_resolve_undo (const char *path, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    unsigned char *buf = NULL;
    size_t flen = 0, off = 0;
    if (bgit_index_after_entries (path, &buf, &flen, &off) < 0) return -1;

    char (*ids)[41] = NULL;
    size_t n = 0, cap = 0;
    while (off + 8 <= flen - 20) {
        uint32_t size = bgit_be32 (buf, off + 4);
        const unsigned char *body = buf + off + 8;
        if (size > flen - 20 - off - 8) break;
        if (memcmp (buf + off, "REUC", 4) == 0) {
            size_t at = 0;
            while (at < size) {
                /* the path, then three modes, then an id per mode that is set */
                const unsigned char *end = memchr (body + at, 0, size - at);
                if (!end) break;
                at = (size_t) (end - body) + 1;
                int set[3] = { 0, 0, 0 };
                int ok = 1;
                for (int stage = 0; stage < 3 && ok; stage++) {
                    end = at < size ? memchr (body + at, 0, size - at) : NULL;
                    if (!end) { ok = 0; break; }
                    set[stage] = (end - (body + at)) > 0 && body[at] != '0';
                    at = (size_t) (end - body) + 1;
                }
                if (!ok) break;
                for (int stage = 0; stage < 3; stage++) {
                    if (!set[stage]) continue;
                    if (at + 20 > size) { ok = 0; break; }
                    if (bgit_index_ids_room (&ids, n, &cap) < 0) {
                        free (ids);
                        free (buf);
                        return -1;
                    }
                    bgit_sha_to_hex (body + at, ids[n]);
                    n++;
                    at += 20;
                }
                if (!ok) break;
            }
        }
        off += 8 + size;
    }
    free (buf);
    *out = ids;
    *n_out = n;
    return 0;
}

/* The trees an index has already worked out for the paths it holds (its
   cache-tree extension), which git counts as held even before a commit
   names them. An entry is
       <name>\0<entries> <subtrees>\n[<20-byte id>]
   laid out from the top down; a negative entry count means the tree is not
   worked out yet and no id follows. */
int
bgit_index_cache_tree (const char *path, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    unsigned char *buf = NULL;
    size_t flen = 0, off = 0;
    if (bgit_index_after_entries (path, &buf, &flen, &off) < 0) return -1;

    char (*ids)[41] = NULL;
    size_t n = 0, cap = 0;
    while (off + 8 <= flen - 20) {
        uint32_t size = bgit_be32 (buf, off + 4);
        const unsigned char *body = buf + off + 8;
        if (size > flen - 20 - off - 8) break;
        if (memcmp (buf + off, "TREE", 4) == 0) {
            size_t at = 0;
            while (at < size) {
                const unsigned char *end = memchr (body + at, 0, size - at);
                if (!end) break;
                at = (size_t) (end - body) + 1;
                /* "<entries> <subtrees>\n" */
                const unsigned char *line =
                    at < size ? memchr (body + at, '\n', size - at) : NULL;
                if (!line) break;
                char counts[64];
                size_t line_len = (size_t) (line - (body + at));
                if (line_len >= sizeof counts) break;
                memcpy (counts, body + at, line_len);
                counts[line_len] = '\0';
                at = (size_t) (line - body) + 1;
                long entries = strtol (counts, NULL, 10);
                if (entries < 0) continue;      /* not worked out yet */
                if (at + 20 > size) break;
                if (bgit_index_ids_room (&ids, n, &cap) < 0) {
                    free (ids);
                    free (buf);
                    return -1;
                }
                bgit_sha_to_hex (body + at, ids[n]);
                n++;
                at += 20;
            }
        }
        off += 8 + size;
    }
    free (buf);
    *out = ids;
    *n_out = n;
    return 0;
}
