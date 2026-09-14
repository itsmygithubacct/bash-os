/* SPDX-License-Identifier: MIT */
/* unexpand.c — POSIX unexpand(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Replaces runs of spaces with tabs. By default only LEADING runs are
 * converted (POSIX behavior); -a converts all runs of >= 2 spaces.
 *
 *   unexpand [-a|--all] [-t TABLIST|--tabs=TABLIST] [FILE...]
 *
 *   -a, --all           convert all whitespace runs, not just leading
 *   --first-only        convert only leading whitespace runs
 *   -t, --tabs TABLIST  tab stops; same syntax as bashexpand. Default: 8.
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
#include <ctype.h>
#include <sys/stat.h>

#include "loadables.h"
#include "unwind_prot.h"
#include "bl-output.h"

#define BU_MAX_STOPS 64

typedef struct {
    int stops[BU_MAX_STOPS];
    int n_stops;
    int every;
    int all;
} bu_opts;

static int
bu_parse_tablist (const char *s, bu_opts *o)
{
    char *end;
    long n = strtol (s, &end, 10);
    if (*end == '\0') {
        if (n <= 0) { builtin_error ("invalid tab size: %s", s); return -1; }
        o->every = (int) n;
        o->n_stops = 0;
        return 0;
    }
    o->every = 0;
    o->n_stops = 0;
    int prev = 0;
    while (*s) {
        while (*s == ',' || *s == ' ' || *s == '\t') s++;
        if (!*s) break;
        char *e;
        long v = strtol (s, &e, 10);
        if (e == s || v <= prev) {
            builtin_error ("bad tab list (must be strictly increasing): %s", s);
            return -1;
        }
        if (o->n_stops >= BU_MAX_STOPS) {
            builtin_error ("too many tab stops (max %d)", BU_MAX_STOPS);
            return -1;
        }
        o->stops[o->n_stops++] = (int) v;
        prev = (int) v;
        s = e;
    }
    return o->n_stops > 0 ? 0 : (builtin_error ("empty tab list"), -1);
}

/* Next tab-stop column strictly greater than COL. With a single tab size
   (`every`) stops repeat forever. With an explicit list there is no stop past
   the last entry: *LAST_TAB is set and col+1 is returned, mirroring GNU
   unexpand's get_next_tab_column() — there conversion stops for the rest of
   the line. (No running tab_index is needed: scanning for the first stop
   strictly greater than COL is stateless and gives the same answer GNU's
   incremental index does, including after a backspace lowers the column.) */
static int
bu_next_stop (int col, const bu_opts *o, int *last_tab)
{
    *last_tab = 0;
    if (o->every > 0) {
        int offset = (o->every & (o->every - 1)) == 0
                     ? col & (o->every - 1) : col % o->every;
        return col + (o->every - offset);
    }
    for (int i = 0; i < o->n_stops; i++)
        if (o->stops[i] > col)
            return o->stops[i];
    *last_tab = 1;
    return col + 1;
}

static void
bu_output_byte (bl_output *out, unsigned char c)
{
    if (!out) {
        putc_unlocked (c, stdout);
        return;
    }
    if (out->error) return;
    out->data[out->used++] = c;
    if (out->used == sizeof out->data)
        bl_output_flush (out);
}

/* Convert one input stream, faithfully porting GNU unexpand's per-line state
   machine (coreutils unexpand.c fold_file). Blank runs are accumulated in
   `pending`; a run is replaced by a tab only when a blank lands exactly on a
   tab stop with a preceding blank, and a lone blank sitting on a stop is kept
   as a space (`one_blank_before`). `o->all` is GNU's convert_entire_line:
   when false, conversion stops after the first non-blank on each line. */
static void
bu_free_pending (void *arg)
{
    /* The pointer can change when the pending buffer grows. */
    free (*(char **) arg);
}

static int
bu_process (FILE *f, const bu_opts *o)
{
    char  *pending = NULL;       /* buffer of pending blank bytes */
    size_t pending_cap = 0;
    size_t pending_n = 0;
    int convert = 1;
    int column = 0;
    int one_blank_before = 0;
    int prev_blank = 1;          /* a line is treated as preceded by a blank */
    int out_failed = 0;
    int next_tab = 0, last_tab = 0;
    int c;
    unsigned char input[65536];
    size_t pos = 0, have = 0;
    bl_output output, *out = NULL;
    struct stat st;

    begin_unwind_frame ("unexpand pending");
    add_unwind_protect (bu_free_pending, &pending);
    clearerr (f);
    /* Full-block reads are suitable for regular files. Pipes and terminals
       keep their existing byte I/O and early output-error detection; terminal
       stdout keeps stdio's line buffering too. */
    if (fstat (fileno (f), &st) == 0 && S_ISREG (st.st_mode) &&
        !isatty (STDOUT_FILENO)) {
        bl_output_init (&output, stdout);
        out = &output;
    }
    for (;;) {
        int suppress = 0;        /* set when the current char is consumed (g.len=0) */
        if (out) {
            if (out->error) { out_failed = 1; break; }
            if (pos == have) {
                have = fread (input, 1, sizeof input, f);
                pos = 0;
                QUIT;
            }
            if (pos < have && !pending_n) {
                /* Ordinary runs need no blank/backspace/newline transition.
                   After leading-only conversion stops, everything up to the
                   next newline can be copied unchanged. */
                static const unsigned char special[256] = {
                    [' '] = 1, ['\t'] = 1, ['\b'] = 1, ['\n'] = 1
                };
                size_t end = pos;
                if (!convert) {
                    unsigned char *nl = memchr (input + pos, '\n', have - pos);
                    end = nl ? (size_t) (nl - input) : have;
                } else {
                    while (end < have && !special[input[end]]) end++;
                }
                if (end > pos) {
                    bl_output_write (out, input + pos, end - pos);
                    if (convert) {
                        column += (int) (end - pos);
                        prev_blank = 0;
                        convert = o->all;
                    }
                    pos = end;
                    continue;
                }
            }
            c = pos < have ? input[pos++] : EOF;
        } else {
            c = getc_unlocked (f);
        }

        /* EOF is processed too: like GNU, it triggers the final pending flush
           (with the pending>1 conversion) before the loop ends. */
        if (convert) {
            int blank = (c != EOF && (c == ' ' || c == '\t'));
            if (blank) {
                if (column >= next_tab) {
                    if (o->every > 0 && column == next_tab) {
                        next_tab = column + o->every;
                        last_tab = 0;
                    } else {
                        next_tab = bu_next_stop (column, o, &last_tab);
                    }
                }
                if (last_tab)
                    convert = 0;
                if (convert) {
                    if (c == '\t') {
                        column = next_tab;
                        if (pending_n) pending[0] = '\t';
                    } else { /* space (width 1) */
                        column += 1;
                        if (!(prev_blank && column == next_tab)) {
                            if (column == next_tab) one_blank_before = 1;
                            if (pending_n + 1 > pending_cap) {
                                size_t nc = pending_cap ? pending_cap * 2 : 64;
                                char *nb = realloc (pending, nc);
                                if (!nb) { run_unwind_frame ("unexpand pending"); builtin_error ("realloc"); return EXECUTION_FAILURE; }
                                pending = nb;
                                pending_cap = nc;
                            }
                            pending[pending_n++] = ' ';
                            prev_blank = 1;
                            continue;            /* hold the blank; emit nothing yet */
                        }
                        /* Replace the pending blanks by a tab (or two). */
                        bu_output_byte (out, '\t');
                        if (pending_cap == 0) {
                            pending = malloc (pending_cap = 64);
                            if (!pending) { run_unwind_frame ("unexpand pending"); builtin_error ("malloc"); return EXECUTION_FAILURE; }
                        }
                        pending[0] = '\t';
                        suppress = 1;
                    }
                    /* Discard pending, unless a single blank sat on a stop. */
                    pending_n = one_blank_before ? 1 : 0;
                }
            } else if (c == '\b') {
                if (column > 0) column--;
                next_tab = 0;
            } else if (c != '\n' && c != EOF) {
                column += 1;
            }

            if (pending_n) {
                if (pending_n > 1 && one_blank_before) pending[0] = '\t';
                if (out) bl_output_write (out, pending, pending_n);
                else fwrite (pending, 1, pending_n, stdout);
                pending_n = 0;
                one_blank_before = 0;
            }
            prev_blank = blank;
            convert = convert && (o->all || blank);
        }

        if (c == EOF)
            break;

        if (c == '\n') {
            bu_output_byte (out, '\n');
            convert = 1; column = 0;
            one_blank_before = 0; prev_blank = 1; pending_n = 0;
            next_tab = 0; last_tab = 0;
        } else if (!suppress) {
            bu_output_byte (out, (unsigned char) c);
        }
        if ((out && out->error) || ferror_unlocked (stdout)) {
            out_failed = 1;
            break;
        }
    }

    run_unwind_frame ("unexpand pending");
    if (out) bl_output_flush (out);
    if (out_failed || (out && out->error) || ferror (stdout) || fflush (stdout) == EOF) {
        int error = out && out->error ? out->error : errno;
        builtin_error ("write error: %s", strerror (error ? error : EIO));
        return EXECUTION_FAILURE;
    }
    return ferror (f) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static void
bu_help (void)
{
    puts ("unexpand [OPTION] [FILE...]");
    puts ("Convert spaces to tabs. Reads stdin if no FILE or FILE is -.");
    puts ("");
    puts ("  -a, --all          convert all blanks, not just initial blanks");
    puts ("      --first-only   convert only leading blanks");
    puts ("  -t, --tabs=LIST    tab stops (single N or comma-separated)");
    puts ("  -h, --help         show this help");
    puts ("  -V, --version      show version");
}

static void
bu_close_input (void *arg)
{
    fclose ((FILE *) arg);
}

int
unexpand_builtin (WORD_LIST *list)
{
    bu_opts o = { .every = 8 };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            bu_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("unexpand 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) { o.all = 1; list = list->next; continue; }
        if (!strcmp (w, "--first-only")) { o.all = 0; list = list->next; continue; }
        if (!strcmp (w, "-t") || !strcmp (w, "--tabs")) {
            if (!list->next) {
                builtin_error ("%s needs TABLIST", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bu_parse_tablist (list->word->word, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            /* POSIX: -t implies -a. */
            o.all = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-t", 2) && w[2]) {
            if (bu_parse_tablist (w + 2, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            o.all = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--tabs=", 7)) {
            if (bu_parse_tablist (w + 7, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            o.all = 1;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    if (!list) {
        rc = bu_process (stdin, &o);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (f != stdin) {
                begin_unwind_frame ("unexpand input");
                add_unwind_protect (bu_close_input, f);
            }
            int prc = bu_process (f, &o);
            if (f != stdin) run_unwind_frame ("unexpand input");
            if (prc != EXECUTION_SUCCESS) {
                rc = prc;
                break;
            }
        }
    }
    return rc;
}

char *unexpand_doc[] = {
    "Convert spaces to tabs (POSIX unexpand).",
    "",
    "    unexpand [OPTION] [FILE...]",
    "",
    "    -a, --all          convert all space runs of length >= 2, not just",
    "                       leading runs",
    "        --first-only   convert only leading runs",
    "    -t, --tabs=LIST    tab stops (single N or comma-separated). Default: 8.",
    "                       Specifying tabs implies --all per POSIX.",
    "    -h, --help         show help",
    "    -V, --version      show version",
    "",
    "Reads stdin when no FILE given or FILE is -. Output goes to stdout.",
    (char *)NULL
};

struct builtin unexpand_struct = {
    "unexpand",
    unexpand_builtin,
    BUILTIN_ENABLED,
    unexpand_doc,
    "unexpand [OPTION] [FILE...]",
    0
};
