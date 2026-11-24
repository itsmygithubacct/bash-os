/* SPDX-License-Identifier: MIT */
/* expand.c — POSIX expand(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Replaces tabs with the appropriate number of spaces so that the
 * column reaches the next tab stop.
 *
 *   expand [-i] [-t TABLIST] [FILE...]
 *
 *   -i           initial-only: tabs after the first non-blank are
 *                left alone
 *   -t TABLIST   tab stops; either a single number (every-N-cols) or
 *                a comma/space-separated list of column positions.
 *                Default: 8 (every 8 columns).
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
#include <ctype.h>
#include <limits.h>
#include <stdint.h>

#include "loadables.h"
#include "shim-prog-name.h"
#include "tablist.h"

/* Bash executes this builtin in one thread. Keep its input buffering, but
   avoid locking it for every byte. */
#if !HAVE_DECL_GETC_UNLOCKED
#  define getc_unlocked fgetc
#endif

typedef struct {
    bos_tabs tabs;          /* -t stops and extensions (tablist.h) */
    uintmax_t every;
    int initial_only;
} bx_opts;

static int
bx_parse_tablist (const char *s, bx_opts *o)
{
    return bos_tabs_parse (&o->tabs, s);
}

/* Return the padding, without overflowing when forming the next column. */
static uintmax_t
bx_padding (uintmax_t col, const bx_opts *o)
{
    if (o->every > 0)
        return o->every - col % o->every;
    /* Explicit list: first stop > col. */
    for (size_t i = 0; i < o->tabs.n_stops; i++)
        if ((uintmax_t) o->tabs.stops[i] > col) return o->tabs.stops[i] - col;
    /* Past the last explicit stop: /N gives multiples of N, +N gives a
       repeat every N relative to the last stop (GNU get_next_tab_column). */
    if (o->tabs.extend_size > 0)
        return o->tabs.extend_size - col % o->tabs.extend_size;
    if (o->tabs.increment_size > 0) {
        uintmax_t end_tab = o->tabs.n_stops > 0 ? o->tabs.stops[o->tabs.n_stops - 1] : 0;
        return o->tabs.increment_size - ((col - end_tab) % o->tabs.increment_size);
    }
    return 1;
}

typedef struct {
    uintmax_t col;
    int seen_nonblank;
} bx_state;

/* Buffer locally instead of changing the shell's stdout with setvbuf. Bash's
   line-buffered stdout otherwise enters libc even for each padding space. */
typedef struct {
    unsigned char data[16384];
    size_t used;
    int terminal;
    int error;
} bx_output;

static void
bx_flush (bx_output *out)
{
    if (!out->error && out->used &&
        fwrite (out->data, 1, out->used, stdout) != out->used)
        out->error = errno ? errno : EIO;
    out->used = 0;
}

static void
bx_byte (bx_output *out, unsigned char c)
{
    out->data[out->used++] = c;
    if (out->used == sizeof out->data || (out->terminal && c == '\n'))
        bx_flush (out);
}

static void
bx_spaces (bx_output *out, uintmax_t count)
{
    while (count && !out->error) {
        size_t n = sizeof out->data - out->used;
        if (count < n) n = count;
        memset (out->data + out->used, ' ', n);
        out->used += n;
        count -= n;
        if (out->used == sizeof out->data) bx_flush (out);
    }
}

static int
bx_process (FILE *f, const bx_opts *o, bx_state *state, bx_output *out)
{
    uintmax_t col = state->col;
    int seen_nonblank = state->seen_nonblank;
    int c;

    clearerr (f);
    while (!out->error && (c = getc_unlocked (f)) != EOF) {
        if (c == '\t' && (!o->initial_only || !seen_nonblank)) {
            uintmax_t padding = bx_padding (col, o);
            if (padding > UINTMAX_MAX - col) goto overflow;
            col += padding;
            bx_spaces (out, padding);
        } else if (c == '\n') {
            bx_byte (out, '\n');
            col = 0;
            seen_nonblank = 0;
        } else if (c == '\b') {
            bx_byte (out, '\b');
            if (col > 0) col--;
            seen_nonblank = 1;
        } else {
            bx_byte (out, c);
            if (c != ' ' && c != '\t') seen_nonblank = 1;
            if (col == UINTMAX_MAX) goto overflow;
            col++;
        }
    }
    state->col = col;
    state->seen_nonblank = seen_nonblank;
    if (ferror (f)) {
        builtin_error ("read error: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;

overflow:
    builtin_error ("input line is too long");
    return EXECUTION_FAILURE;
}

/* An early output failure can leave input read-ahead behind. Own the FILE
   buffer so a later shell redirection cannot expose those stale bytes. Reuse
   this stream for every '-' in one invocation; dup shares stdin's offset. */
static FILE *
bx_stdin (void)
{
    /* Do not reopen closed stdout/stderr with a writable stdin alias. */
    int fd = fcntl (STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return NULL;
    FILE *f = fdopen (fd, "r");
    if (!f) {
        int saved_errno = errno;
        close (fd);
        errno = saved_errno;
    }
    return f;
}

/* Match unambiguous GNU long-option prefixes without accepting suffixes. */
static int
bx_long_option (const char *word, const char *name, size_t length)
{
    return length && length <= strlen (name) && !strncmp (word, name, length);
}

extern char *expand_doc[];

/* Collect operands while parsing options, so options after filenames work too.
   POSIXLY_CORRECT retains the conventional stop-at-first-operand behavior. */
static int
bx_options (WORD_LIST *list, bx_opts *o, const char **files, size_t *n_files)
{
    int operands_only = 0, badc = 0;
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (operands_only || w[0] != '-' || !w[1]) {
            files[(*n_files)++] = w;
            if (getenv ("POSIXLY_CORRECT")) operands_only = 1;
            continue;
        }
        if (!strcmp (w, "--")) { operands_only = 1; continue; }
        if (w[1] == '-') {
            const char *name = w + 2, *eq = strchr (name, '=');
            size_t length = eq ? (size_t) (eq - name) : strlen (name);
            if (bx_long_option (name, "tabs", length)) {
                const char *value;
                if (eq) value = eq + 1;
                else {
                    if (!list->next) goto missing;
                    list = list->next;
                    value = list->word->word;
                }
                if (bx_parse_tablist (value, o) < 0) return -1;
            } else if (bx_long_option (name, "initial", length)) {
                if (eq) {
                    builtin_error ("option '--initial' doesn't allow an argument");
                    bos_shim_try_help ("expand");
                    return -1;
                }
                o->initial_only = 1;
            }
            else if (!eq && bx_long_option (name, "help", length)) {
                for (char **line = expand_doc; *line; line++) puts (*line);
                return 1;
            } else if (!eq && bx_long_option (name, "version", length)) {
                printf ("expand (bash-os builtin, Bash %s)\n", shell_version_string ());
                return 1;
            } else goto unknown;
            continue;
        }
        for (const char *cp = w + 1; *cp; cp++) {
            if (*cp == 'i') o->initial_only = 1;
            else if (*cp == 't') {
                const char *value = cp + 1;
                if (!*value) {
                    if (!list->next) goto missing;
                    list = list->next;
                    value = list->word->word;
                }
                if (bx_parse_tablist (value, o) < 0) return -1;
                break;
            } else if (*cp >= '0' && *cp <= '9') {
                if (bx_parse_tablist (cp, o) < 0) return -1;
                break;
            } else { badc = (unsigned char) *cp; goto unknown; }
        }
        continue;
missing:
        bos_shim_missing_arg (w[1] == '-' ? "--tabs" : w, 't', "expand");
        return -1;
unknown:
        bos_shim_bad_option (w, badc, "expand");
        return -1;
    }
    if (bos_tabs_finish (&o->tabs) < 0)
        return -1;
    if (!o->tabs.n_stops)
        o->every = o->tabs.extend_size ? o->tabs.extend_size : o->tabs.increment_size ? o->tabs.increment_size : 8;
    else if (o->tabs.n_stops == 1 && !o->tabs.extend_size && !o->tabs.increment_size)
        o->every = o->tabs.stops[0];
    return 0;
}

int
expand_builtin (WORD_LIST *list)
{
    bx_opts o = { 0 };
    size_t argc = 0, n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    const char **files = xmalloc ((argc + 1) * sizeof *files);
    int parsed = bx_options (list, &o, files, &n_files);
    if (parsed) {
        free (o.tabs.stops);
        free (files);
        if (parsed < 0) return EXECUTION_FAILURE;
        return fflush (stdout) == EOF || ferror (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    int rc = EXECUTION_SUCCESS;
    bx_state state = { 0 };
    bx_output output;
    output.used = 0;
    output.error = 0;
    output.terminal = isatty (fileno (stdout));
    FILE *input = NULL;
    if (!n_files) {
        input = bx_stdin ();
        if (input)
            rc = bx_process (input, &o, &state, &output);
        else {
            builtin_error ("stdin: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    } else {
        for (size_t i = 0; i < n_files; i++) {
            FILE *f;
            if (!strcmp (files[i], "-")) {
                if (!input) input = bx_stdin ();
                f = input;
            } else
                f = fopen (files[i], "r");
            if (!f) {
                builtin_error ("%s: %s", files[i], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (bx_process (f, &o, &state, &output) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
            if (f != input && fclose (f) == EOF) {
                builtin_error ("%s: %s", files[i], strerror (errno));
                rc = EXECUTION_FAILURE;
            }
            if (output.error) break;
        }
    }
    if (input && fclose (input) == EOF) {
        builtin_error ("stdin: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    bx_flush (&output);
    if ((fflush (stdout) == EOF || ferror (stdout)) && !output.error)
        output.error = errno ? errno : EIO;
    if (output.error) {
        builtin_error ("write error: %s", strerror (output.error));
        rc = EXECUTION_FAILURE;
    }
    free (o.tabs.stops);
    free (files);
    return rc;
}

char *expand_doc[] = {
    "Convert tabs to spaces (POSIX expand).",
    "",
    "    expand [-i] [-t TABLIST] [FILE...]",
    "",
    "    -i           leave tabs after the first non-blank alone",
    "    --initial    alias for -i",
    "    -t TABLIST   tab stops: a single number (every-N-cols) or a",
    "    --tabs=LIST  alias for -t LIST",
    "                 comma/space-separated list of column positions",
    "                 (must be strictly increasing). Default: 8.",
    "                 A trailing /N repeats stops at multiples of N; a",
    "                 trailing +N repeats every N after the last stop.",
    "    -N           shorthand for -t N; repeated options append stops",
    "    --help       display this help",
    "    --version    display builtin version information",
    "",
    "Reads stdin when no FILE or '-' is given. Output goes to stdout.",
    (char *)NULL
};

struct builtin expand_struct = {
    "expand",
    expand_builtin,
    BUILTIN_ENABLED,
    expand_doc,
    "expand [-i] [-t TABLIST] [FILE...]",
    0
};
