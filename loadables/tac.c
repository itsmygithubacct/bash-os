/* SPDX-License-Identifier: MIT */
/* tac.c — GNU-style tac(1): concatenate and print files in reverse.
 *
 *   tac [OPTION]... [FILE]...
 *
 * Write each FILE to standard output, last record first. Records default to
 * lines (separator '\n'). With no FILE, or when FILE is '-', read stdin.
 *
 * Options:
 *   -b, --before          attach the separator BEFORE each record, not after
 *   -r, --regex           treat the separator string as a GNU Emacs regex
 *   -s, --separator=SEP   use SEP as the record separator (default newline)
 *   -h, --help / -V, --version
 *
 * Seekable inputs are scanned backward; pipes use an owned temporary spool.
 * Output is batched without changing Bash's stdio state.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "loadables.h"
#include "bl-output.h"

/* Input and record sizes never determine the literal scanner's allocation.
   Keep record offsets and reread their bytes in forward order when emitting. */
#define TAC_BLOCK 65536

typedef struct {
    int fd;
    off_t end, base;
    size_t used, capacity;
    char *data;
} tac_input;

static int
tac_read_at (int fd, char *data, size_t length, off_t offset)
{
    while (length) {
        ssize_t n = pread (fd, data, length, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return -1; }
        data += n; length -= n; offset += n;
    }
    return 0;
}

/* The scan cache usually contains the entire record. A separate fixed buffer
   handles huge records without disturbing the backward search cache. */
static int
tac_output_range (tac_input *in, off_t start, off_t end, bl_output *out)
{
    char buffer[TAC_BLOCK];
    while (start < end && !out->error) {
        if (start >= in->base && start < in->base + (off_t) in->used) {
            off_t stop = in->base + (off_t) in->used;
            if (stop > end) stop = end;
            bl_output_write (out, in->data + (size_t) (start - in->base),
                             (size_t) (stop - start));
            start = stop;
        } else {
            size_t n = end - start > TAC_BLOCK ? TAC_BLOCK : (size_t) (end - start);
            if (tac_read_at (in->fd, buffer, n, start) < 0) return -1;
            bl_output_write (out, buffer, n);
            start += n;
        }
    }
    return out->error ? -1 : 0;
}

/* Rightmost separator start in [lo, hi) whose body lies in [lo, past).
   A body may extend past hi by slen-1 bytes; those bytes are still file
   bytes GNU kept from the previous window. Returns 1 and stores the
   offset, 0 if none, or -1 on a read error. */
static int
tac_find_literal (tac_input *in, const char *needle, size_t slen,
                  off_t lo, off_t hi, off_t past, off_t *found)
{
    if (hi > past) hi = past;
    while (hi > lo) {
        off_t span = hi - lo;
        off_t chunk = span > TAC_BLOCK ? (off_t) TAC_BLOCK : span;
        off_t start = hi - chunk;
        off_t read_end = hi - 1 + (off_t) slen;
        if (read_end > past) read_end = past;
        if (read_end <= start) { hi = start; continue; }
        size_t n = (size_t) (read_end - start);
        if (tac_read_at (in->fd, in->data, n, start) < 0) return -1;
        in->base = start;
        in->used = n;
        size_t limit = (size_t) (hi - start);
        if (limit > n) limit = n;
        while (limit) {
            char *match = memrchr (in->data, (unsigned char) needle[0], limit);
            if (!match) break;
            size_t pos = (size_t) (match - in->data);
            if (slen <= n && pos <= n - slen
                && (slen == 1 || !memcmp (match, needle, slen))) {
                *found = start + (off_t) pos;
                return 1;
            }
            limit = pos;
        }
        hi = start;
    }
    return 0;
}

/* GNU tac 9.7 aligns an 8192-byte window on the file (larger when the
   separator or the pending record requires it). Within a window the
   rightmost matches do not overlap. A match that begins on the window
   base is kept across the next read, so a self-overlapping separator
   one byte to its left is emitted too. *read_size survives across files
   in one invocation, as GNU's does. The search buffer stays one block
   plus the separator; record bytes are reread when printed. */
static int
tac_literal (tac_input *in, const char *sep, int before, size_t *read_size,
             bl_output *out)
{
    size_t slen = strlen (sep);
    if (!slen) slen = 1;       /* An empty argument selects NUL. */
    if (!*read_size || slen > SIZE_MAX - TAC_BLOCK) { errno = EOVERFLOW; return -1; }
    while (slen >= *read_size / 2) {
        if (*read_size > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
        *read_size *= 2;
    }
    in->capacity = TAC_BLOCK + slen;
    in->data = malloc (in->capacity);
    if (!in->data) return -1;
    if (!in->end) return 0;

    size_t rs = *read_size;
    uintmax_t rem = (uintmax_t) in->end % rs;
    off_t win_base = rem ? in->end - (off_t) rem : in->end - (off_t) rs;
    off_t win_len = in->end - win_base;
    off_t past = in->end;
    off_t match_cursor = (slen - 1 > (size_t) in->end)
        ? (off_t) -1 : in->end - (off_t) (slen - 1);
    int first = 1;

    while (!out->error) {
        off_t found = 0;
        int got = 0;
        if (match_cursor > win_base) {
            off_t hi = match_cursor;
            off_t win_end = win_base + win_len;
            if (hi > win_end) hi = win_end;
            got = tac_find_literal (in, sep, slen, win_base, hi, past, &found);
            if (got < 0) return -1;
        }
        if (!got) {
            if (win_base == 0)
                return tac_output_range (in, 0, past, out);
            if ((uintmax_t) (past - win_base) > *read_size) {
                if (*read_size > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
                *read_size *= 2;
            }
            off_t old_base = win_base;
            if ((uintmax_t) win_base >= *read_size) {
                win_base -= (off_t) *read_size;
                win_len = (off_t) *read_size;
            } else {
                *read_size = (size_t) win_base;
                win_len = win_base;
                win_base = 0;
            }
            match_cursor = old_base;
            continue;
        }
        if (!before) {
            off_t match_end = found + (off_t) slen;
            if (!(first && match_end == past)
                && tac_output_range (in, match_end, past, out) < 0)
                return -1;
            past = match_end;
            first = 0;
        } else if (tac_output_range (in, found, past, out) < 0) {
            return -1;
        } else {
            past = found;
        }
        match_cursor = (slen > (size_t) found + 1)
            ? (off_t) -1 : found - (off_t) (slen - 1);
    }
    return out->error ? -1 : 0;
}

/* A single byte atom, optionally repeated, can always match at the rightmost
   matching byte (or at the rightmost byte at all for a nullable atom). This
   scanner is also available on libcs without the GNU regex API. Complex
   patterns must go through the general matcher, never a dialect guess. */
typedef struct { unsigned char member[256]; int nullable; } tac_atom;

static int
tac_byte_atom (const char *pattern, tac_atom *atom)
{
    if (MB_CUR_MAX != 1) return 0;
    size_t end = strlen (pattern);
    atom->nullable = 0;
    if (end && strchr ("*+?", pattern[end - 1])) {
        atom->nullable = pattern[end - 1] != '+';
        end--;
    }
    memset (atom->member, 0, sizeof atom->member);
    if (end == 1 && !strchr (".[]^$\\*+?", pattern[0])) {
        atom->member[(unsigned char) pattern[0]] = 1;
        return 1;
    }
    if (end == 1 && pattern[0] == '.') {
        memset (atom->member, 1, sizeof atom->member);
        atom->member['\n'] = 0;
        return 1;
    }
    if (end >= 3 && pattern[0] == '[' && pattern[end - 1] == ']') {
        size_t first = pattern[1] == '^' ? 2 : 1;
        if (first + 1 >= end) return 0;
        for (size_t i = first; i + 1 < end; i++) {
            unsigned char c = (unsigned char) pattern[i];
            if (c == '[' || c == ']' || c == '\\' || c == '-') return 0;
            atom->member[c] = 1;
        }
        if (first == 2)
            for (size_t i = 0; i < sizeof atom->member; i++) atom->member[i] ^= 1;
        return 1;
    }
    return 0;
}

static int
tac_regex_atom (tac_input *in, const tac_atom *atom, int before, bl_output *out)
{
    in->data = malloc (TAC_BLOCK);
    if (!in->data) return -1;
    off_t search_end = in->end, record_end = in->end;
    while (search_end > 0 && !out->error) {
        in->base = search_end > TAC_BLOCK ? search_end - TAC_BLOCK : 0;
        in->used = (size_t) (search_end - in->base);
        if (tac_read_at (in->fd, in->data, in->used, in->base) < 0) return -1;
        for (size_t i = in->used; i > 0 && !out->error; ) {
            --i;
            int match = atom->member[(unsigned char) in->data[i]];
            if (!match && !atom->nullable) continue;
            off_t boundary = in->base + i + (before ? 0 : match);
            if (tac_output_range (in, boundary, record_end, out) < 0) return -1;
            record_end = boundary;
        }
        search_end = in->base;
    }
    return tac_output_range (in, 0, record_end, out);
}

#ifdef __GLIBC__
/* GNU's length-aware API preserves NULs, Emacs syntax and right-to-left
   matching. General expressions can require arbitrary context/backreferences;
   this fallback maps the file instead of copying it or indexing records.
   Its address space and the regex engine's working memory are NOT bounded. */
static int
tac_regex (tac_input *in, regex_t *re, size_t *read_size, int before, bl_output *out)
{
    if (!in->end) return 0;
    if ((uintmax_t) in->end > INT_MAX) { errno = EOVERFLOW; return -1; }
    char *mapping = mmap (NULL, (size_t) in->end, PROT_READ, MAP_PRIVATE, in->fd, 0);
    if (mapping == MAP_FAILED) return -1;
    in->data = mapping; in->used = (size_t) in->end;
    regoff_t so, eo;
    struct re_registers regs = {1, &so, &eo};
    re->regs_allocated = REGS_FIXED;
    re->not_bol = 0;
    off_t search_end = in->end, record_end = in->end;
    off_t base = ((in->end - 1) / *read_size) * *read_size;
    int rc = 0;
    while (!out->error) {
        regoff_t length = (regoff_t) (search_end - base);
        regoff_t found = length ? re_search (re, mapping + base, length,
                                            length - 1, 1 - length, &regs) : -1;
        if (found == -2) { errno = EINVAL; rc = -1; break; }
        if (found == -1) {
            if (!base) break;
            /* Preserve GNU's growing search-window geometry, including
               buffer-relative anchors and resetting the search at the
               pending record end after extending the window to the left. */
            if ((uintmax_t) (record_end - base) > *read_size) *read_size *= 2;
            if ((uintmax_t) base < *read_size) *read_size = (size_t) base;
            base -= *read_size;
            search_end = record_end;
            continue;
        }
        off_t boundary = base + (before ? so : eo);
        if (tac_output_range (in, boundary, record_end, out) < 0) { rc = -1; break; }
        record_end = boundary;
        search_end = base + so;
    }
    if (!rc) rc = tac_output_range (in, 0, record_end, out);
    in->data = NULL; in->used = 0;
    munmap (mapping, (size_t) in->end);
    return rc;
}
#endif

/* A pipe spool belongs exclusively to this call. Unlink immediately: normal
   errors, output failures and process exit cannot leave a pathname behind. */
static int
tac_spool (int fd)
{
    const char *tmpdir = getenv ("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    size_t n = strlen (tmpdir);
    if (n > SIZE_MAX - 24) { errno = EOVERFLOW; return -1; }
    char *name = malloc (n + 24);
    if (!name) return -1;
    snprintf (name, n + 24, "%s/tac.XXXXXX", tmpdir);
    int spool = mkstemp (name);
    if (spool >= 0 && unlink (name) < 0) {
        int error = errno; close (spool); spool = -1; errno = error;
    }
    free (name);
    if (spool < 0) return -1;
    if (fcntl (spool, F_SETFD, FD_CLOEXEC) < 0) goto fail;
    char buffer[TAC_BLOCK];
    for (;;) {
        ssize_t count = read (fd, buffer, sizeof buffer);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) break;
        if (!count) return spool;
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write (spool, buffer + offset, (size_t) (count - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { if (!written) errno = EIO; goto fail; }
            offset += written;
        }
    }
fail:
    { int error = errno; close (spool); errno = error; }
    return -1;
}

static int
tac_file (int fd, const char *sep, int before, int regex, regex_t *re, size_t *read_size,
          bl_output *out)
{
    int spool = -1;
    struct stat st;
    if (fstat (fd, &st) < 0) return -1;
    off_t end = lseek (fd, 0, SEEK_END);
    if (end == 0 && S_ISREG (st.st_mode)) {
        char byte;
        ssize_t n;
        do n = pread (fd, &byte, 1, 0); while (n < 0 && errno == EINTR);
        if (n <= 0) return n < 0 ? -1 : 0;
    }
    /* Zero-size special files can still supply bytes (e.g. procfs). Reading
       them into the same owned spool also catches directory/read errors. */
    if (end < 0 || !S_ISREG (st.st_mode) || !end) {
        if (end >= 0 && lseek (fd, 0, SEEK_SET) < 0) return -1;
        spool = tac_spool (fd);
        if (spool < 0) return -1;
        fd = spool;
        end = lseek (fd, 0, SEEK_END);
        if (end < 0) { int error = errno; close (fd); errno = error; return -1; }
    }
    tac_input in = { .fd = fd, .end = end };
    int rc;
    tac_atom atom;
    if (regex && tac_byte_atom (sep, &atom))
        rc = tac_regex_atom (&in, &atom, before, out);
#ifdef __GLIBC__
    else if (regex && strpbrk (sep, ".[*+?^$\\"))
        rc = tac_regex (&in, re, read_size, before, out);
#endif
    else rc = tac_literal (&in, sep, before, read_size, out);
    int error = errno;
    free (in.data);
    if (spool >= 0 && close (spool) < 0 && !rc) return -1;
    errno = error;
    return rc;
}

static void
tac_help (void)
{
    puts ("Concatenate and print files in reverse (last record first).");
    puts ("");
    puts ("    tac [OPTION]... [FILE]...");
    puts ("");
    puts ("    -b, --before          attach the separator before each record");
    puts ("    -r, --regex           the separator is a GNU Emacs regex");
    puts ("    -s, --separator=SEP   record separator (default newline)");
    puts ("    -h, --help / -V, --version");
}

int
tac_builtin (WORD_LIST *list)
{
    const char *sep = "\n";
    int before = 0, regex = 0;
    /* Collect file operands after parsing options. */
    char **files = NULL; int n_files = 0, cap_files = 0;
    int end_opts = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && !strcmp (w, "-h")) { tac_help (); free (files); return EXECUTION_SUCCESS; }
        if (!end_opts && !strcmp (w, "--help")) { tac_help (); free (files); return EXECUTION_SUCCESS; }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("tac 1.0 (bash-loadable, coreutils-compatible)"); free (files); return EXECUTION_SUCCESS;
        }
        if (!end_opts && (!strcmp (w, "-b") || !strcmp (w, "--before"))) { before = 1; continue; }
        if (!end_opts && (!strcmp (w, "-r") || !strcmp (w, "--regex"))) { regex = 1; continue; }
        if (!end_opts && (!strcmp (w, "-s") || !strcmp (w, "--separator"))) {
            if (!p->next) { builtin_error ("option requires an argument -- s"); free (files); return EX_USAGE; }
            p = p->next; sep = p->word->word; continue;
        }
        if (!end_opts && !strncmp (w, "--separator=", 12)) { sep = w + 12; continue; }
        if (!end_opts && !strncmp (w, "-s", 2) && w[2]) { sep = w + 2; continue; }
        if (!end_opts && w[0] == '-' && w[1] != '\0' && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w);
            builtin_usage (); free (files); return EX_USAGE;
        }
        /* operand */
        if (n_files == cap_files) {
            int nc = cap_files ? cap_files * 2 : 8;
            char **nf = realloc (files, (size_t) nc * sizeof *files);
            if (!nf) { builtin_error ("out of memory"); free (files); return EXECUTION_FAILURE; }
            files = nf; cap_files = nc;
        }
        files[n_files++] = (char *) w;
    }

    regex_t re;
    memset (&re, 0, sizeof re);
    if (regex) {
#ifdef __GLIBC__
        if (!*sep) { builtin_error ("separator cannot be empty"); free (files); return EXECUTION_FAILURE; }
        /* re_syntax_options belongs to the process, including Bash's own
           regex users. Restore it even when compilation fails. */
        reg_syntax_t saved = re_set_syntax (RE_SYNTAX_EMACS);
        const char *error = re_compile_pattern (sep, strlen (sep), &re);
        re_set_syntax (saved);
        if (error) {
            builtin_error ("invalid regex separator: %s", error);
            regfree (&re); free (files); return EXECUTION_FAILURE;
        }
#else
        tac_atom atom;
        if (!*sep || (strpbrk (sep, ".[*+?^$\\") && !tac_byte_atom (sep, &atom))) {
            builtin_error ("this regex separator requires the GNU regex API on this build");
            free (files); return EXECUTION_FAILURE;
        }
#endif
    }
    int rc = EXECUTION_SUCCESS;
    size_t read_size = 8192;
    bl_output out;
    bl_output_init (&out, stdout);
    /* A closed stdout must be diagnosed before open/mkstemp can reuse fd 1.
       Otherwise a pipe spool opened there would silently receive output. */
    if (!out.error) {
        int flags = fcntl (out.fd, F_GETFL);
        if (flags < 0) out.error = errno;
        else if ((flags & O_ACCMODE) == O_RDONLY) out.error = EBADF;
    }
    for (int i = 0; i < (n_files ? n_files : 1) && !out.error; i++) {
        const char *name = n_files ? files[i] : "-";
        int owned = strcmp (name, "-") != 0;
        int fd = owned ? open (name, O_RDONLY | O_CLOEXEC) : STDIN_FILENO;
        if (fd < 0) { builtin_error ("%s: %s", name, strerror (errno)); rc = EXECUTION_FAILURE; continue; }
        if (tac_file (fd, sep, before, regex, &re, &read_size, &out) < 0) {
            if (!out.error) builtin_error ("%s: %s", name, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
        if (owned && close (fd) < 0) {
            builtin_error ("%s: %s", name, strerror (errno)); rc = EXECUTION_FAILURE;
        }
    }
#ifdef __GLIBC__
    if (regex) regfree (&re);
#endif
    bl_output_flush (&out);
    if (out.error) {
        builtin_error ("write error: %s", strerror (out.error));
        rc = EXECUTION_FAILURE;
    }
    free (files);
    return rc;
}

char *tac_doc[] = {
    "Concatenate and print files in reverse (last record first).",
    "",
    "    tac [OPTION]... [FILE]...",
    "",
    "Records default to lines. With no FILE (or '-'), read standard input.",
    "",
    "Options:",
    "    -b, --before          attach the separator before each record",
    "    -r, --regex           the separator is a GNU Emacs regex",
    "    -s, --separator=SEP   record separator (default newline)",
    "    -h, --help            show this help",
    "    -V, --version         show version",
    (char *)NULL
};

struct builtin tac_struct = {
    "tac",
    tac_builtin,
    BUILTIN_ENABLED,
    tac_doc,
    "tac [OPTION]... [FILE]...",
    0
};
