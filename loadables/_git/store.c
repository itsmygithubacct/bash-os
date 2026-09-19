/* SPDX-License-Identifier: MIT */
/* _git/store.c — one object lookup over loose objects, packs and alternates.
 *
 * obj could only read loose objects in the repository it was pointed at, so a
 * repository that had run `git gc` looked empty. This is the lookup the
 * porcelain needs: the repository's own objects directory, every alternate it
 * names, and every pack in each of them, with packs memory-mapped.
 *
 * A pack's SHA-1 trailer is not re-checked on every read — like git, which
 * verifies a pack when it is received or when asked to (`pack verify-idx`),
 * not once per object. The idx header is checked when the pack is indexed,
 * and every offset read stays inside the mapping.
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
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "loadables.h"

#include "odb.h"
#include "pack.h"
#include "repo.h"

struct bgit_pack_file {
    char *pack_path;
    unsigned char *idx;      /* mapped .idx */
    size_t idx_len;
    unsigned char *pack;     /* mapped .pack, on first use */
    size_t pack_len;
};

static void *
bgit_map_file (const char *path, size_t *len)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat (fd, &st) < 0 || st.st_size <= 0) { close (fd); return NULL; }
    void *base = mmap (NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close (fd);
    if (base == MAP_FAILED) return NULL;
    *len = (size_t) st.st_size;
    return base;
}

int
bgit_odb_open (const bgit_repo *repo, bgit_odb *odb)
{
    memset (odb, 0, sizeof *odb);
    if (bgit_repo_object_dirs (repo, &odb->object_dirs, &odb->n_object_dirs) < 0)
        return -1;
    return 0;
}

void
bgit_odb_release (bgit_odb *odb)
{
    if (!odb) return;
    for (size_t i = 0; i < odb->n_packs; i++) {
        struct bgit_pack_file *p = &odb->packs[i];
        if (p->idx) munmap (p->idx, p->idx_len);
        if (p->pack) munmap (p->pack, p->pack_len);
        free (p->pack_path);
    }
    free (odb->packs);
    bgit_repo_free_object_dirs (odb->object_dirs, odb->n_object_dirs);
    memset (odb, 0, sizeof *odb);
}

/* Index every pack in every object directory, once per store. A pack whose
   idx is not v2, or whose .pack is missing, is skipped: the object may still
   be loose or in another pack. */
static void
bgit_odb_scan_packs (bgit_odb *odb)
{
    if (odb->packs_scanned) return;
    odb->packs_scanned = 1;
    size_t cap = 0;
    for (size_t d = 0; d < odb->n_object_dirs; d++) {
        char dir[4096];
        if (snprintf (dir, sizeof dir, "%s/pack", odb->object_dirs[d]) >=
            (int) sizeof dir)
            continue;
        DIR *handle = opendir (dir);
        if (!handle) continue;
        struct dirent *entry;
        while ((entry = readdir (handle)) != NULL) {
            size_t len = strlen (entry->d_name);
            if (len < 5 || strcmp (entry->d_name + len - 4, ".idx") != 0)
                continue;
            char idx_path[4096], pack_path[4096];
            if (snprintf (idx_path, sizeof idx_path, "%s/%s", dir,
                          entry->d_name) >= (int) sizeof idx_path)
                continue;
            if (snprintf (pack_path, sizeof pack_path, "%.*s.pack",
                          (int) (strlen (idx_path) - 4), idx_path) >=
                (int) sizeof pack_path)
                continue;
            struct stat st;
            if (stat (pack_path, &st) != 0 || !S_ISREG (st.st_mode))
                continue;
            size_t idx_len = 0;
            unsigned char *idx = bgit_map_file (idx_path, &idx_len);
            if (!idx) continue;
            if (idx_len < 1032 || memcmp (idx, "\377tOc", 4) != 0 ||
                bgit_pack_be32 (idx + 4) != 2) {
                munmap (idx, idx_len);
                continue;
            }
            if (odb->n_packs == cap) {
                size_t next = cap ? cap * 2 : 4;
                struct bgit_pack_file *grown =
                    realloc (odb->packs, next * sizeof *grown);
                if (!grown) { munmap (idx, idx_len); continue; }
                odb->packs = grown;
                cap = next;
            }
            struct bgit_pack_file *p = &odb->packs[odb->n_packs];
            memset (p, 0, sizeof *p);
            p->pack_path = strdup (pack_path);
            p->idx = idx;
            p->idx_len = idx_len;
            if (!p->pack_path) { munmap (idx, idx_len); continue; }
            odb->n_packs++;
        }
        closedir (handle);
    }
}

static unsigned char *
bgit_pack_mapping (struct bgit_pack_file *p, size_t *len)
{
    if (!p->pack) {
        p->pack = bgit_map_file (p->pack_path, &p->pack_len);
        if (!p->pack) return NULL;
        if (p->pack_len < 32 || memcmp (p->pack, "PACK", 4) != 0) {
            munmap (p->pack, p->pack_len);
            p->pack = NULL;
            p->pack_len = 0;
            return NULL;
        }
    }
    *len = p->pack_len;
    return p->pack;
}

/* Every object id in a pack, for prefix matching: the idx holds them sorted,
   with a fanout by first byte. */
static int
bgit_pack_match_prefix (const struct bgit_pack_file *p, const char *prefix,
                        char full[41], int *matches)
{
    uint32_t total = bgit_pack_be32 (p->idx + 8 + 255 * 4);
    size_t sha_bytes = (size_t) total * 20;
    if (total != 0 && sha_bytes / 20 != (size_t) total) return 0;
    if (sha_bytes > p->idx_len - 1032) return 0;
    size_t plen = strlen (prefix);
    uint32_t first = 0, last = total;
    if (plen >= 2) {
        char byte[3] = { prefix[0], prefix[1], 0 };
        unsigned long value = strtoul (byte, NULL, 16);
        first = value == 0 ? 0 : bgit_pack_be32 (p->idx + 8 + (value - 1) * 4);
        last = bgit_pack_be32 (p->idx + 8 + value * 4);
        if (first > last || last > total) return 0;
    }
    for (uint32_t i = first; i < last; i++) {
        char hex[41];
        bgit_sha_to_hex (p->idx + 1032 + (size_t) i * 20, hex);
        if (strncmp (hex, prefix, plen) == 0) {
            if (*matches == 0) memcpy (full, hex, 41);
            else if (strcmp (full, hex) != 0) { (*matches)++; return 1; }
            (*matches)++;
            if (*matches > 1) return 1;
        }
    }
    return 0;
}

/* Loose objects with this prefix, in one objects directory. */
static void
bgit_loose_match_prefix (const char *objects, const char *prefix, char full[41],
                         int *matches)
{
    size_t plen = strlen (prefix);
    if (plen < 2) return;
    char dir[4096];
    if (snprintf (dir, sizeof dir, "%s/%c%c", objects, prefix[0], prefix[1]) >=
        (int) sizeof dir)
        return;
    DIR *handle = opendir (dir);
    if (!handle) return;
    struct dirent *entry;
    while ((entry = readdir (handle)) != NULL) {
        if (strlen (entry->d_name) != 38) continue;
        char hex[41];
        hex[0] = prefix[0];
        hex[1] = prefix[1];
        memcpy (hex + 2, entry->d_name, 38);
        hex[40] = '\0';
        if (strncmp (hex, prefix, plen) != 0) continue;
        if (*matches == 0) memcpy (full, hex, 41);
        else if (strcmp (full, hex) != 0) { (*matches)++; break; }
        (*matches)++;
        if (*matches > 1) break;
    }
    closedir (handle);
}

int
bgit_odb_resolve (bgit_odb *odb, const char *name, char full[41])
{
    if (!bgit_all_hex (name) || strlen (name) > 40) {
        builtin_error ("Not a valid object name %s", name ? name : "");
        return -1;
    }
    size_t len = strlen (name);
    if (len == 40) {
        memcpy (full, name, 40);
        full[40] = '\0';
        if (!bgit_odb_has (odb, full)) {
            builtin_error ("Not a valid object name %s", name);
            return -1;
        }
        return 0;
    }
    /* git's minimum abbreviation is 4 hex; shorter is rejected. */
    if (len < 4) {
        builtin_error ("Not a valid object name %s", name);
        return -1;
    }
    int matches = 0;
    char candidate[41] = "";
    for (size_t i = 0; i < odb->n_object_dirs && matches < 2; i++)
        bgit_loose_match_prefix (odb->object_dirs[i], name, candidate, &matches);
    bgit_odb_scan_packs (odb);
    for (size_t i = 0; i < odb->n_packs && matches < 2; i++)
        bgit_pack_match_prefix (&odb->packs[i], name, candidate, &matches);
    if (matches == 0) {
        builtin_error ("Not a valid object name %s", name);
        return -1;
    }
    if (matches > 1) {
        builtin_error ("ambiguous argument '%s': unknown revision or object name",
                       name);
        return -1;
    }
    memcpy (full, candidate, 41);
    return 0;
}

int
bgit_odb_has (bgit_odb *odb, const char *sha)
{
    if (!sha || strlen (sha) != 40) return 0;
    for (size_t i = 0; i < odb->n_object_dirs; i++) {
        char path[4096];
        if (snprintf (path, sizeof path, "%s/%c%c/%s", odb->object_dirs[i],
                      sha[0], sha[1], sha + 2) < (int) sizeof path &&
            access (path, R_OK) == 0)
            return 1;
    }
    unsigned char binary[20];
    if (bgit_hex_to_sha (sha, binary) < 0) return 0;
    bgit_odb_scan_packs (odb);
    for (size_t i = 0; i < odb->n_packs; i++)
        if (bgit_pack_lookup_offset (odb->packs[i].idx, odb->packs[i].idx_len,
                                     binary) != (uint64_t) -1)
            return 1;
    return 0;
}

static enum bgit_type
bgit_type_from_pack (int pack_type)
{
    switch (pack_type) {
    case BGIT_PACK_COMMIT: return BGIT_COMMIT;
    case BGIT_PACK_TREE:   return BGIT_TREE;
    case BGIT_PACK_BLOB:   return BGIT_BLOB;
    case BGIT_PACK_TAG:    return BGIT_TAG;
    default:               return BGIT_UNKNOWN;
    }
}

/* Read a loose object from whichever objects directory holds it. */
static int
bgit_odb_read_loose (bgit_odb *odb, const char *sha, enum bgit_type *type,
                     unsigned char **data, size_t *len)
{
    for (size_t i = 0; i < odb->n_object_dirs; i++) {
        unsigned char *raw = NULL;
        size_t raw_len = 0;
        if (bgit_read_loose_at (odb->object_dirs[i], sha, &raw, &raw_len) < 0)
            continue;
        size_t payload = 0;
        long off = bgit_parse_header (raw, raw_len, type, &payload);
        if (off < 0 || (size_t) off > raw_len || payload > raw_len - (size_t) off) {
            free (raw);
            builtin_error ("malformed object header for %s", sha);
            return -1;
        }
        unsigned char *content = malloc (payload ? payload : 1);
        if (!content) { free (raw); return -1; }
        memcpy (content, raw + off, payload);
        free (raw);
        *data = content;
        *len = payload;
        return 0;
    }
    return 1;   /* not loose here */
}

/* Read a packed object, resolving its delta chain. */
static int
bgit_odb_read_packed (bgit_odb *odb, const char *sha, enum bgit_type *type,
                      unsigned char **data, size_t *len)
{
    unsigned char binary[20];
    if (bgit_hex_to_sha (sha, binary) < 0) return 1;
    bgit_odb_scan_packs (odb);
    for (size_t i = 0; i < odb->n_packs; i++) {
        struct bgit_pack_file *p = &odb->packs[i];
        uint64_t off = bgit_pack_lookup_offset (p->idx, p->idx_len, binary);
        if (off == (uint64_t) -1) continue;
        size_t plen = 0;
        unsigned char *pack = bgit_pack_mapping (p, &plen);
        if (!pack) continue;
        int pack_type = 0;
        unsigned char *content = NULL;
        size_t clen = 0;
        if (bgit_pack_read_object_at (pack, plen, p->idx, p->idx_len, NULL, off,
                                      &pack_type, &content, &clen, 0) < 0) {
            builtin_error ("cannot read %s from %s", sha, p->pack_path);
            return -1;
        }
        *type = bgit_type_from_pack (pack_type);
        *data = content;
        *len = clen;
        return 0;
    }
    return 1;   /* not packed here */
}

int
bgit_odb_read (bgit_odb *odb, const char *name, enum bgit_type *type,
               unsigned char **data, size_t *len)
{
    char sha[41];
    if (bgit_odb_resolve (odb, name, sha) < 0)
        return -1;
    int rc = bgit_odb_read_loose (odb, sha, type, data, len);
    if (rc <= 0) return rc;
    rc = bgit_odb_read_packed (odb, sha, type, data, len);
    if (rc <= 0) return rc;
    builtin_error ("Not a valid object name %s", name);
    return -1;
}
