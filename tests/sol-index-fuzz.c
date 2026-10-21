/* SPDX-License-Identifier: MIT */
/* libFuzzer harness for the index command's own parsers and edits.
 *
 * tests/fuzz-index.c covers the shared reader in _git/index.c. This one
 * includes loadables/index.c itself and drives what that file adds, with
 * the first input byte choosing the case:
 *
 *   0  the bytes are an index file: the shared reader, then the command's
 *      structural checks and the decode for editing; an accepted index is
 *      written back by bgit_index_write and must read back to the same
 *      entries
 *   1  the bytes are --index-info records, applied one by one to an empty
 *      index exactly as the verb applies them; afterwards the entries must
 *      be in strict path/stage order with every path one git accepts
 *   2  the bytes are `index write` lines; a line that parses must give a
 *      canonical mode and an acceptable path
 *
 * Bash's own functions that index.c calls are stubbed; none of them is
 * reached by these cases except for messages.
 */
#define _GNU_SOURCE 1
#include <stdarg.h>
#include <sys/mman.h>
#include "../loadables/_git/index.c"
#include "../loadables/index.c"

void builtin_error (const char *format, ...) { (void) format; }
void builtin_usage (void) {}
void sh_wrerror (void) {}
int legal_identifier (const char *name) { (void) name; return 1; }
SHELL_VAR *find_variable (const char *name) { (void) name; return NULL; }
SHELL_VAR *find_variable_noref (const char *name) { (void) name; return NULL; }
int unbind_variable (const char *name) { (void) name; return 0; }
SHELL_VAR *find_or_make_array_variable (const char *name, int flags) { (void) name; (void) flags; return NULL; }
int array_insert (ARRAY *a, arrayind_t i, char *v) { (void) a; (void) i; (void) v; return 0; }
/* Not reached: no case here calls a verb that settles racy entries. */
int bgit_slurp_fd (int fd, unsigned char **out, size_t *len) { (void) fd; *out = NULL; *len = 0; return -1; }
int bgit_write_object (const char *dir, const char *type, const unsigned char *c, size_t n,
                       int w, char hex[41]) { (void) dir; (void) type; (void) c; (void) n; (void) w; hex[0] = 0; return -1; }

int
bgit_hex_to_sha (const char *hex, unsigned char *sha)
{
    if (strlen (hex) != 40) return -1;
    for (int i = 0; i < 40; i++) {
        int c = hex[i], v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (i & 1) sha[i / 2] |= (unsigned char) v;
        else sha[i / 2] = (unsigned char) (v << 4);
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

static char scratch[PATH_MAX - 16];

static void
fuzz_index_file (const uint8_t *data, size_t size)
{
    static int held = -1;
    if (held < 0 && (held = memfd_create ("index", 0)) < 0) return;
    if (ftruncate (held, 0) < 0) return;
    if (size && pwrite (held, data, size, 0) != (ssize_t) size) return;
    char path[64];
    snprintf (path, sizeof path, "/proc/self/fd/%d", held);

    bgit_index_view *views;
    unsigned char *backing;
    size_t n, flen;
    if (bgit_index_read_views_len (path, &views, &n, &backing, &flen) == 0) {
        if (flen != size) __builtin_trap ();
        (void) bidx_check (path, views, n, backing, flen, 0);
        free (views);
        free (backing);
    }

    bgit_index_entry *entries;
    bidx_undo undo, undo2;
    if (bidx_load (path, 0, &entries, &n, &undo) < 0) return;
    char out[PATH_MAX];
    snprintf (out, sizeof out, "%s/index", scratch);
    bgit_index_unstamp ();
    size_t ext_len;
    int failed = 0;
    unsigned char *ext = bidx_undo_ext (&undo, &ext_len, &failed);
    if (failed || bgit_index_write_ext (out, entries, n, ext, ext_len) < 0) __builtin_trap ();
    free (ext);
    bgit_index_entry *again;
    size_t m;
    if (bidx_load (out, 0, &again, &m, &undo2) < 0 || m != n) __builtin_trap ();
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, again[i].path) ||
            memcmp (entries[i].sha, again[i].sha, 20) ||
            entries[i].mode != again[i].mode ||
            (entries[i].flags & 0xB000) != (again[i].flags & 0xB000))
            __builtin_trap ();
    }
    if (undo.n != undo2.n) __builtin_trap ();
    for (size_t i = 0; i < undo.n; i++) {
        if (strcmp (undo.rec[i].path, undo2.rec[i].path)) __builtin_trap ();
        for (int k = 0; k < 3; k++)
            if (undo.rec[i].mode[k] != undo2.rec[i].mode[k] ||
                (undo.rec[i].mode[k] && memcmp (undo.rec[i].sha[k], undo2.rec[i].sha[k], 20)))
                __builtin_trap ();
    }
    bidx_undo_free (&undo);
    bidx_undo_free (&undo2);
    bgit_index_free_entries (entries, n);
    bgit_index_free_entries (again, m);
}

static void
fuzz_index_info (const uint8_t *data, size_t size)
{
    bidx_set set;
    bidx_undo undo = { 0 };
    bgit_index_entry *start = calloc (1, sizeof *start);
    if (!start || bidx_set_init (&set, start, 0) < 0) { free (start); return; }
    set.undo = &undo;
    int nul = size && (data[0] & 1);
    char *text = malloc (size + 1);
    memcpy (text, data, size);
    text[size] = '\0';
    char sep = nul ? '\0' : '\n';
    for (size_t at = nul ? 1 : 0; at < size; ) {
        char *line = text + at;
        char *end = memchr (line, sep, size - at);
        size_t len = end ? (size_t) (end - line) : size - at;
        line[len] = '\0';
        at += len + 1;
        if (bidx_info_apply (&set, line, nul) != EXECUTION_SUCCESS) break;
    }
    for (size_t i = 0; i < set.n; i++) {
        const bgit_index_entry *e = BIDX_AT (&set, i);
        if (!bidx_path_ok (e->path, e->mode) || e->mode == S_IFDIR ||
            bidx_canonical_mode (e->mode) != e->mode)
            __builtin_trap ();
        if (i && bidx_cmp (BIDX_AT (&set, i - 1)->path, strlen (BIDX_AT (&set, i - 1)->path),
                           BIDX_STAGE (BIDX_AT (&set, i - 1)->flags), e) >= 0)
            __builtin_trap ();
    }
    /* every removed conflict stage is noted, in path order */
    for (size_t i = 1; i < undo.n; i++)
        if (strcmp (undo.rec[i - 1].path, undo.rec[i].path) >= 0) __builtin_trap ();
    size_t ext_len;
    int failed = 0;
    unsigned char *ext = bidx_undo_ext (&undo, &ext_len, &failed);
    if (ext) {
        bidx_undo back = { 0 };
        if (bidx_undo_parse (&back, ext + 8, ext_len - 8) < 0 || back.n != undo.n) __builtin_trap ();
        bidx_undo_free (&back);
    }
    free (ext);
    bidx_undo_free (&undo);
    size_t n;
    bgit_index_entry *entries = bidx_set_take (&set, &n);
    if (entries) bgit_index_free_entries (entries, n);
    else bidx_set_free (&set);
    free (text);
}

static void
fuzz_write_lines (const uint8_t *data, size_t size)
{
    char *text = malloc (size + 1);
    memcpy (text, data, size);
    text[size] = '\0';
    for (char *line = text, *next; line && *line; line = next) {
        next = strchr (line, '\n');
        if (next) *next++ = '\0';
        bgit_index_entry e;
        if (bidx_write_line (line, &e) == 0) {
            if (!bidx_path_ok (e.path, e.mode) || bidx_canonical_mode (e.mode) != e.mode)
                __builtin_trap ();
            free (e.path);
        }
    }
    free (text);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    if (size < 1 || size > 1 << 16) return 0;
    if (!scratch[0]) {
        /* the runner makes this directory and removes it afterwards */
        const char *dir = getenv ("SOL_INDEX_FUZZ_DIR");
        if (!dir || snprintf (scratch, sizeof scratch, "%s", dir) >= (int) sizeof scratch)
            abort ();
    }
    switch (data[0] % 3) {
    case 0: fuzz_index_file (data + 1, size - 1); break;
    case 1: fuzz_index_info (data + 1, size - 1); break;
    default: fuzz_write_lines (data + 1, size - 1); break;
    }
    return 0;
}
