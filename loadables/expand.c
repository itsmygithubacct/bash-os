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
#include <ctype.h>

#include "loadables.h"

#define BX_MAX_STOPS 64

typedef struct {
    int stops[BX_MAX_STOPS];   /* explicit stop columns; 0-terminated */
    int n_stops;
    int every;                  /* fallback "every N cols" (0 if explicit) */
    int extend_size;            /* trailing /N: multiples of N after stops */
    int increment_size;         /* trailing +N: every N after the last stop */
    int initial_only;
} bx_opts;

/* Parse TABLIST. A bare integer N → every-N stops. A comma/space list
   → explicit stops, must be strictly increasing. Returns 0 on success. */
static int
bx_parse_tablist (const char *s, bx_opts *o)
{
    /* Leading separators / empty list: a no-op (GNU uses the default
       tab width of 8 for an empty --tabs= argument). */
    while (*s == ',' || *s == ' ' || *s == '\t') s++;
    if (!*s) return 0;

    /* Single bare integer N -> every-N stops. */
    char *end;
    long n = strtol (s, &end, 10);
    if (*end == '\0') {
        if (n <= 0) { builtin_error ("invalid tab size: %s", s); return -1; }
        o->every = (int) n;
        o->n_stops = 0;
        o->extend_size = o->increment_size = 0;
        return 0;
    }

    /* Comma/space-separated list of explicit stops, optionally ending in a
       single /N (multiples of N after the stops) or +N (every N after the
       last stop). The two are mutually exclusive and must be the final
       token, matching GNU expand's get_next_tab_column semantics. */
    o->every = 0;
    o->n_stops = 0;
    o->extend_size = o->increment_size = 0;
    int prev = 0;
    while (*s) {
        while (*s == ',' || *s == ' ' || *s == '\t') s++;
        if (!*s) break;
        int multiple = 0, relative = 0;
        if (*s == '/') { multiple = 1; s++; }
        else if (*s == '+') { relative = 1; s++; }
        char *e;
        long v = strtol (s, &e, 10);
        if (e == s || v <= 0) {
            builtin_error ("invalid tab size: %s", s);
            return -1;
        }
        if (multiple || relative) {
            /* /N or +N must be the sole trailing specifier. */
            if (o->extend_size || o->increment_size) {
                builtin_error ("'/' and '+' specifiers may appear only once, at the end");
                return -1;
            }
            if (multiple) o->extend_size = (int) v;
            else          o->increment_size = (int) v;
            s = e;
            while (*s == ',' || *s == ' ' || *s == '\t') s++;
            if (*s) {
                builtin_error ("'/' or '+' specifier must be the last value");
                return -1;
            }
            break;
        }
        if (v <= prev) {
            builtin_error ("bad tab list (must be strictly increasing): %s", s);
            return -1;
        }
        if (o->n_stops >= BX_MAX_STOPS) {
            builtin_error ("too many tab stops (max %d)", BX_MAX_STOPS);
            return -1;
        }
        o->stops[o->n_stops++] = (int) v;
        prev = (int) v;
        s = e;
    }
    /* A lone /N or +N (no explicit stops) reduces to every-N. */
    if (o->n_stops == 0) {
        if (o->extend_size)         { o->every = o->extend_size;    o->extend_size = 0; }
        else if (o->increment_size) { o->every = o->increment_size; o->increment_size = 0; }
        else { builtin_error ("empty tab list"); return -1; }
    }
    return 0;
}

/* Returns the next tab-stop column strictly greater than `col`. */
static int
bx_next_stop (int col, const bx_opts *o)
{
    if (o->every > 0)
        return col + (o->every - col % o->every);
    /* Explicit list: first stop > col. */
    for (int i = 0; i < o->n_stops; i++)
        if (o->stops[i] > col) return o->stops[i];
    /* Past the last explicit stop: /N gives multiples of N, +N gives a
       repeat every N relative to the last stop (GNU get_next_tab_column). */
    if (o->extend_size > 0)
        return col + (o->extend_size - col % o->extend_size);
    if (o->increment_size > 0) {
        int end_tab = o->n_stops > 0 ? o->stops[o->n_stops - 1] : 0;
        return col + (o->increment_size - ((col - end_tab) % o->increment_size));
    }
    return col + 1;
}

static int
bx_process (FILE *f, const bx_opts *o)
{
    int col = 0;
    int seen_nonblank = 0;
    int c;

    clearerr (f);
    while ((c = fgetc (f)) != EOF) {
        if (c == '\t' && (!o->initial_only || !seen_nonblank)) {
            int target = bx_next_stop (col, o);
            while (col < target) { fputc (' ', stdout); col++; }
        } else if (c == '\n') {
            fputc ('\n', stdout);
            col = 0;
            seen_nonblank = 0;
        } else if (c == '\b') {
            fputc ('\b', stdout);
            if (col > 0) col--;
        } else {
            fputc (c, stdout);
            if (c != ' ' && c != '\t') seen_nonblank = 1;
            col++;
        }
    }
    return EXECUTION_SUCCESS;
}

int
expand_builtin (WORD_LIST *list)
{
    bx_opts o = { .every = 8 };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--initial")) {
            o.initial_only = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--tabs")) {
            if (!list->next) {
                builtin_error ("--tabs needs TABLIST");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bx_parse_tablist (list->word->word, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--tabs=", 7)) {
            if (bx_parse_tablist (w + 7, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-i")) { o.initial_only = 1; list = list->next; continue; }
        if (!strcmp (w, "-t")) {
            if (!list->next) {
                builtin_error ("-t needs TABLIST");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bx_parse_tablist (list->word->word, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-t", 2) && w[2]) {
            if (bx_parse_tablist (w + 2, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] != '-' && strchr (w + 1, 't') != NULL) {
            const char *tp = strchr (w + 1, 't');
            for (const char *cp = w + 1; cp < tp; cp++) {
                if (*cp == 'i') {
                    o.initial_only = 1;
                    continue;
                }
                builtin_error ("unknown flag: -%c", *cp);
                builtin_usage ();
                return EX_USAGE;
            }
            if (tp[1]) {
                if (bx_parse_tablist (tp + 1, &o) < 0) {
                    builtin_usage ();
                    return EX_USAGE;
                }
            } else {
                if (!list->next) {
                    builtin_error ("-t needs TABLIST");
                    builtin_usage ();
                    return EX_USAGE;
                }
                list = list->next;
                if (bx_parse_tablist (list->word->word, &o) < 0) {
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
            list = list->next;
            continue;
        }
        if (w[1] != '-') {
            int ok = 1;
            for (int i = 1; w[i]; i++) {
                if (w[i] == 'i') {
                    o.initial_only = 1;
                    continue;
                }
                ok = 0;
                break;
            }
            if (ok) {
                list = list->next;
                continue;
            }
        }
        /* POSIX shorthand: -N (digits only). */
        if (w[1] >= '0' && w[1] <= '9') {
            if (bx_parse_tablist (w + 1, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    if (!list) {
        bx_process (stdin, &o);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            bx_process (f, &o);
            if (f != stdin) fclose (f);
        }
    }
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
    "    -N           POSIX shorthand for -t N",
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
