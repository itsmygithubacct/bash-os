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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "_sha1dc_sha1.h"

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

/* Slurp file. Caller frees. */
static unsigned char *
bgit_index_slurp (const char *path, size_t *out_len)
{
    FILE *f = fopen (path, "rb");
    if (!f) return NULL;
    if (fseek (f, 0, SEEK_END) != 0) { fclose (f); return NULL; }
    long sz = ftell (f);
    if (sz < 0 || fseek (f, 0, SEEK_SET) != 0) { fclose (f); return NULL; }
    unsigned char *buf = malloc (sz ? (size_t) sz : 1);
    if (!buf) { fclose (f); return NULL; }
    if (fread (buf, 1, (size_t) sz, f) != (size_t) sz) {
        free (buf); fclose (f); return NULL;
    }
    fclose (f);
    *out_len = (size_t) sz;
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
        unsigned char stored[20];
        memcpy (stored, buf + flen - 20, 20);
        SHA1_CTX ctx;
        SHA1DCInit (&ctx);
        SHA1DCSetSafeHash (&ctx, 0);
        SHA1DCUpdate (&ctx, (const char *) buf, flen - 20);
        unsigned char computed[20];
        int collision = SHA1DCFinal (computed, &ctx);
        if (memcmp (computed, stored, 20) != 0) {
            free (buf); free (entries);
            builtin_error ("index checksum mismatch");
            return -1;
        }
        /* Retain existing acceptance behavior, but never reuse a result
           for which SHA1DC reported a collision. */
        if (!collision) bgit_index_remember_verified (buf, flen);
    }

    *backing = buf;
    *out = entries;
    *n_out = n_entries;
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

int
bgit_index_read (const char *path, bgit_index_entry **out, size_t *n_out)
{
    bgit_index_view *views;
    size_t n;
    unsigned char *backing;
    if (bgit_index_read_views (path, &views, &n, &backing) < 0) return -1;
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

    /* Trailer: SHA-1 of body via sha1dc. */
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) buf, len);
    unsigned char digest[20];
    SHA1DCFinal (digest, &ctx);  /* may detect collision; we accept anyway */
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
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; close (fd); unlink (tmp); free (buf); return -1; }
        off += w;
    }
    int sync_rc = fdatasync (fd);
    int close_rc = close (fd);
    if (sync_rc < 0 || close_rc < 0) { unlink (tmp); free (buf); return -1; }
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
    if (pl == 0)
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
