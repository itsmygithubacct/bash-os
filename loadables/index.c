/* SPDX-License-Identifier: MIT */
/* index.c — read/write `.git/index`.
 *
 * The .git/index file is git's staging area — what `git add` writes, what
 * `git commit` reads to build a tree, and what `git status` cross-references
 * for the ctime/mtime fast-path. The format itself lives in _git/index.c,
 * shared with the other git builtins; this file is the command surface.
 *
 * Verbs:
 *   index read PATH [-V VAR]
 *       Print one line per entry: "<mode> <sha> <stage> <path>".
 *       With -V, bind a bash array.
 *
 *   index write PATH (entries on stdin: "<mode> <sha> <stage> <path>")
 *       Build binary index, atomic write (mkstemp + rename). Computes
 *       SHA-1 trailer via sha1dc.
 *
 *   index --index-info PATH
 *       Import git update-index --index-info stdin forms and write PATH.
 *
 *   index add PATH BLOB_SHA WORKING_PATH [STAGE]
 *       Add/replace entry. stat() WORKING_PATH for ctime/mtime/size.
 *
 *   index remove PATH WORKING_PATH
 *       Remove entry by path. Re-writes the index.
 *
 *   index update-stat PATH WORKING_PATH
 *       Refresh stat fields for an existing entry without changing SHA.
 *
 *   index list PATH
 *       Print "<mode> <sha> <stage> <path>" lines. Synonym for read.
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
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "arrayfunc.h"

#include "_git_index.h"
#include "_git_odb.h"

/* Static builds retain the checksum snapshot until replacement or exit. */
void
index_builtin_unload (char *name)
{
    (void) name;
    bgit_index_cache_release ();
}

/* ---- verb implementations ---- */

static int
bidx_read_cmd (WORD_LIST *args)
{
    const char *path = NULL, *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("read: unknown flag %s", w); return EX_USAGE;
        } else { if (path) { builtin_error ("read: too many"); return EX_USAGE; } path = w; }
    }
    if (!path) { builtin_error ("read: PATH required"); return EX_USAGE; }
    bgit_index_view *entries; size_t n;
    unsigned char *backing;
    if (bgit_index_read_views (path, &entries, &n, &backing) < 0)
        return EXECUTION_FAILURE;

    SHELL_VAR *arr = NULL;
    if (var) {
        unbind_variable ((char *) var);
        arr = find_or_make_array_variable ((char *) var, 1);
    }
    char output[65536];
    size_t used = 0;
    int rc = EXECUTION_SUCCESS;
    for (size_t i = 0; i < n; i++) {
        char array_line[8192], octal[11];
        size_t digits = 0, len = 0;
        uint32_t mode = bgit_be32 (entries[i].disk, 24);
        uint16_t flags = bgit_be16 (entries[i].disk, 60);
        size_t pathlen = flags & 0xFFF;
        if (pathlen == 0xFFF) pathlen = strlen (entries[i].path);
        if (!arr) {
            /* At most 11 octal digits, 40 hex digits, one stage digit,
               three spaces and a newline. Reserve before formatting so
               stdout records need no intermediate line copy. */
            size_t reserve = pathlen > sizeof array_line - 56 ?
                             sizeof array_line : pathlen + 56;
            if (sizeof output - used < reserve) {
                if (fwrite (output, 1, used, stdout) != used) {
                    rc = EXECUTION_FAILURE;
                    used = 0;
                    break;
                }
                used = 0;
            }
        }
        char *line = arr ? array_line : output + used;
        do {
            octal[digits++] = '0' + (mode & 7);
            mode >>= 3;
        } while (mode);
        while (digits) line[len++] = octal[--digits];
        line[len++] = ' ';
        bgit_sha_to_hex (entries[i].disk + 40, line + len);
        len += 40;
        line[len++] = ' ';
        line[len++] = '0' + ((flags >> 12) & 0x3);
        line[len++] = ' ';
        if (pathlen > sizeof array_line - len - 1)
            pathlen = sizeof array_line - len - 1;
        memcpy (line + len, entries[i].path, pathlen);
        len += pathlen;
        line[len] = '\0';
        if (arr) {
            ARRAY *a = array_cell (arr);
            array_insert (a, (arrayind_t) i, line);
        } else {
            line[len] = '\n';
            used += len + 1;
        }
    }
    if (used && fwrite (output, 1, used, stdout) != used)
        rc = EXECUTION_FAILURE;
    free (entries);
    free (backing);
    return rc;
}

static int
bidx_write_cmd (WORD_LIST *args)
{
    const char *path = args ? args->word->word : NULL;
    if (!path) { builtin_error ("write: PATH required"); return EX_USAGE; }

    /* Read lines from stdin. */
    size_t cap = 16, n = 0;
    bgit_index_entry *entries = calloc (cap, sizeof (bgit_index_entry));
    if (!entries) return EXECUTION_FAILURE;
    char *line = NULL; size_t line_cap = 0;
    ssize_t got;
    clearerr (stdin);
    while ((got = getline (&line, &line_cap, stdin)) > 0) {
        if (n + 1 > cap) {
            if (cap > SIZE_MAX / 2 / sizeof *entries) {
                free (line); bgit_index_free_entries (entries, n); return EXECUTION_FAILURE;
            }
            cap *= 2;
            bgit_index_entry *ne = realloc (entries, cap * sizeof *entries);
            if (!ne) { free (line); bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
            entries = ne;
        }
        int parse_rc = bgit_index_line_to_entry (line, NULL, &entries[n]);
        if (parse_rc < 0) {
            if (parse_rc == -2)
                builtin_error ("write: bad stage");
            else
                builtin_error ("write: malformed line: %s", line);
            free (line);
            bgit_index_free_entries (entries, n);
            return EX_USAGE;
        }
        n++;
    }
    free (line);
    if (n > 1) qsort (entries, n, sizeof (bgit_index_entry), bgit_index_path_cmp);

    int rc = bgit_index_write (path, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_index_info_cmd (WORD_LIST *args)
{
    const char *path = args ? args->word->word : NULL;
    bgit_index_entry *entries = NULL;
    size_t n = 0, cap = 0;
    char *line = NULL;
    size_t line_cap = 0;

    if (!path) { builtin_error ("--index-info: PATH required"); return EX_USAGE; }
    if (args->next) { builtin_error ("--index-info: too many"); return EX_USAGE; }

    if (access (path, R_OK) == 0) {
        if (bgit_index_read (path, &entries, &n) < 0)
            return EXECUTION_FAILURE;
        cap = n ? n : 16;
        if (cap != n) {
            bgit_index_entry *ne = realloc (entries, cap * sizeof (bgit_index_entry));
            if (!ne) { bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
            entries = ne;
        }
    } else {
        cap = 16;
        entries = calloc (cap, sizeof (bgit_index_entry));
        if (!entries)
            return EXECUTION_FAILURE;
    }

    clearerr (stdin);
    while (getline (&line, &line_cap, stdin) > 0) {
        bgit_index_entry e;
        int is_remove = 0;
        if (bgit_index_info_line_to_entry (line, &e, &is_remove) < 0) {
            builtin_error ("--index-info: malformed line: %s", line);
            free (line);
            bgit_index_free_entries (entries, n);
            return EX_USAGE;
        }
        if (is_remove) {
            bgit_index_remove_path (&entries, &n, e.path);
            free (e.path);
            continue;
        }

        int stage = (e.flags >> 12) & 0x3;
        ssize_t found = -1;
        for (size_t i = 0; i < n; i++) {
            int cur_stage = (entries[i].flags >> 12) & 0x3;
            if (cur_stage == stage && strcmp (entries[i].path, e.path) == 0) {
                found = (ssize_t) i;
                break;
            }
        }
        if (found >= 0) {
            free (entries[found].path);
            entries[found] = e;
        } else {
            if (n + 1 > cap) {
                if (cap > SIZE_MAX / 2 / sizeof *entries) {
                    free (e.path); free (line); bgit_index_free_entries (entries, n); return EXECUTION_FAILURE;
                }
                cap *= 2;
                bgit_index_entry *ne = realloc (entries, cap * sizeof (bgit_index_entry));
                if (!ne) {
                    free (e.path);
                    free (line);
                    bgit_index_free_entries (entries, n);
                    return EXECUTION_FAILURE;
                }
                entries = ne;
            }
            entries[n++] = e;
        }
    }
    free (line);
    if (n > 1) qsort (entries, n, sizeof (bgit_index_entry), bgit_index_path_cmp);

    int rc = bgit_index_write (path, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_add_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("add: PATH BLOB_SHA WORKING_PATH [STAGE]");
        return EX_USAGE;
    }
    const char *idxpath = args->word->word;
    const char *blobsha = args->next->word->word;
    const char *workp   = args->next->next->word->word;
    int stage = 0;
    if (args->next->next->next &&
        bgit_index_parse_stage (args->next->next->next->word->word, &stage) < 0) {
        builtin_error ("bad stage");
        return EX_USAGE;
    }

    /* Stat working path. */
    struct stat st;
    if (stat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }

    bgit_index_entry *entries = NULL;
    size_t n = 0;
    /* Parse existing index if it exists. */
    if (access (idxpath, R_OK) == 0) {
        if (bgit_index_read (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;
    }
    /* Replace or append. */
    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        if (n >= SIZE_MAX / sizeof *entries - 1 || n >= INT_MAX) {
            bgit_index_free_entries (entries, n); return EXECUTION_FAILURE;
        }
        bgit_index_entry *ne = realloc (entries, (n + 1) * sizeof (bgit_index_entry));
        if (!ne) { bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
        entries = ne;
        memset (&entries[n], 0, sizeof (bgit_index_entry));
        entries[n].path = strdup (workp);
        if (!entries[n].path) { bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
        found = (int) n;
        n++;
    }
    bgit_index_entry *e = &entries[found];
    bgit_index_entry_set_stat (e, &st);
    if (bgit_hex_to_sha (blobsha, e->sha) < 0) {
        bgit_index_free_entries (entries, n);
        builtin_error ("bad blob sha"); return EX_USAGE;
    }
    e->flags = (uint16_t) (((stage & 0x3) << 12) | (strlen (e->path) > 0xFFF ? 0xFFF : strlen (e->path)));

    if (n > 1) qsort (entries, n, sizeof (bgit_index_entry), bgit_index_path_cmp);
    int rc = bgit_index_write (idxpath, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_remove_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("remove: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;
    bgit_index_entry *entries; size_t n;
    if (bgit_index_read (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;
    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        bgit_index_free_entries (entries, n);
        return EXECUTION_FAILURE;
    }
    free (entries[found].path);
    if ((size_t) (found + 1) < n) {
        memmove (entries + found, entries + found + 1, (n - found - 1) * sizeof (bgit_index_entry));
    }
    n--;
    int rc = bgit_index_write (idxpath, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_update_stat_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("update-stat: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;

    struct stat st;
    if (stat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }

    bgit_index_entry *entries; size_t n;
    if (bgit_index_read (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;

    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        bgit_index_free_entries (entries, n);
        builtin_error ("update-stat: path not in index: %s", workp);
        return EXECUTION_FAILURE;
    }

    bgit_index_entry_set_stat (&entries[found], &st);
    int rc = bgit_index_write (idxpath, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
index_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "read"))   return bidx_read_cmd (args);
    if (!strcmp (cmd, "list"))   return bidx_read_cmd (args);
    if (!strcmp (cmd, "write"))  return bidx_write_cmd (args);
    if (!strcmp (cmd, "--index-info") || !strcmp (cmd, "index-info"))
        return bidx_index_info_cmd (args);
    if (!strcmp (cmd, "add"))    return bidx_add_cmd (args);
    if (!strcmp (cmd, "remove")) return bidx_remove_cmd (args);
    if (!strcmp (cmd, "update-stat")) return bidx_update_stat_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *index_doc[] = {
    "Read/write .git/index v2 binary format.",
    "",
    "    index read PATH [-V VAR]",
    "        Print '<mode> <sha> <stage> <path>' lines.",
    "    index list PATH",
    "        Synonym for read.",
    "    index write PATH (entries on stdin)",
    "        Atomic write; computes SHA-1 trailer via sha1dc.",
    "    index --index-info PATH (git update-index --index-info stdin)",
    "        Import mode/sha/stage TAB path records; mode 0 removes a path.",
    "    index add PATH BLOB_SHA WORKING_PATH [STAGE]",
    "        Add/replace entry; stat WORKING_PATH for ctime/mtime/size.",
    "    index remove PATH WORKING_PATH",
    "        Remove entry by path.",
    "    index update-stat PATH WORKING_PATH",
    "        Refresh stat fields without changing SHA.",
    (char *)NULL
};

struct builtin index_struct = {
    "index",
    index_builtin,
    BUILTIN_ENABLED,
    index_doc,
    "index read|list|write|--index-info|add|remove|update-stat ARGS",
    0
};
