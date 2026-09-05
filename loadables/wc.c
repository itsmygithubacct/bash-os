/* bashwc.c — POSIX wc(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. -l (lines), -w (words),
 * -c (bytes), -m (chars). Multi-file with per-file rows and a
 * `total` row. No flags = -lwc (default GNU/POSIX behavior).
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
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct {
    long long lines;
    long long words;
    long long bytes;
    long long chars;
    long long max_line;
} bwc_counts;

/* Count from an open FILE *. POSIX "word" = run of non-whitespace bytes. */
static int
bwc_count_stream (FILE *f, bwc_counts *c)
{
    int ch, in_word = 0;
    long long L = 0, W = 0, B = 0, M = 0, cur_line = 0, max_line = 0;
    mbstate_t mbs;

    setlocale (LC_CTYPE, "");
    memset (&mbs, 0, sizeof mbs);
    while ((ch = fgetc (f)) != EOF) {
        unsigned char b = (unsigned char) ch;
        wchar_t wc;
        size_t mr;
        int valid_char = 1;

        B++;

        mr = mbrtowc (&wc, (const char *) &b, 1, &mbs);
        if (mr == (size_t) -2)
            continue;
        if (mr == (size_t) -1) {
            memset (&mbs, 0, sizeof mbs);
            valid_char = 0;
        } else if (mr == 0) {
            wc = L'\0';
        }

        if (valid_char) {
            M++;
            if (wc == L'\n') {
                L++;
                if (cur_line > max_line)
                    max_line = cur_line;
                cur_line = 0;
            } else if (wc == L'\t') {
                cur_line += 8 - (cur_line % 8);
            } else if (wc == L'\r') {
                cur_line = 0;
            } else if (wc == L'\b') {
                if (cur_line > 0)
                    cur_line--;
            } else {
                int ww = wcwidth (wc);
                cur_line += ww > 0 ? ww : 0;
            }
        }
        if (valid_char && (iswspace (wc) || wc == (wchar_t) 0x00a0)) {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            W++;
        }
    }
    if (cur_line > max_line)
        max_line = cur_line;
    c->lines = L;
    c->words = W;
    c->bytes = B;
    c->chars = M;
    c->max_line = max_line;
    return 0;
}

/* Number of decimal digits needed to represent a non-negative value
 * (GNU's compute_number_width uses the running-divide form; replicate it). */
static int
bwc_digits (unsigned long long v)
{
    int width = 1;
    for (; v >= 10; v /= 10)
        width++;
    return width;
}

/* Print one row of counts according to enabled flags, right-aligning each
 * count column to field width `w` (GNU wc's number_width). Columns are
 * separated by a single space; the first column is also padded to `w`. */
static void
bwc_print (bwc_counts *c, int lflag, int wflag, int cflag, int mflag, int Lflag, int w, const char *name)
{
    int any = lflag || wflag || cflag || mflag || Lflag;
    if (!any) lflag = wflag = cflag = 1;   /* default */
    int first = 1;
    if (lflag) { printf ("%s%*lld", first ? "" : " ", w, c->lines); first = 0; }
    if (wflag) { printf ("%s%*lld", first ? "" : " ", w, c->words); first = 0; }
    if (cflag) { printf ("%s%*lld", first ? "" : " ", w, c->bytes); first = 0; }
    if (mflag) { printf ("%s%*lld", first ? "" : " ", w, c->chars); first = 0; }
    if (Lflag) { printf ("%s%*lld", first ? "" : " ", w, c->max_line); first = 0; }
    if (name) printf (" %s", name);
    putchar ('\n');
}

/* Read the entire contents of FILE (or stdin if FILE is "-") into a
 * NUL-allowing buffer, returning the byte count via *lenp. Returns the
 * malloc'd buffer (caller frees) or NULL on error. */
static char *
bwc_slurp (const char *file, size_t *lenp)
{
    FILE *f = (strcmp (file, "-") == 0) ? stdin : fopen (file, "r");
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int ch;

    if (!f) {
        builtin_error ("cannot open '%s' for reading: %s", file, strerror (errno));
        return NULL;
    }
    while ((ch = fgetc (f)) != EOF) {
        if (len >= cap) {
            size_t ncap = cap ? cap * 2 : 256;
            char *nb = realloc (buf, ncap);
            if (!nb) {
                free (buf);
                if (f != stdin) fclose (f);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        buf[len++] = (char) ch;
    }
    if (f != stdin)
        fclose (f);
    *lenp = len;
    return buf;
}

/* Compute GNU wc's number_width for the given file list and column count.
 * Mirrors get_input_fstatus + compute_number_width:
 *   - nfiles==0 (e.g. --files0-from=-), or (nfiles==1 && ncols==1): width 1.
 *   - else sum st_size of regular inputs; width = digits(sum); any
 *     non-regular input forces a minimum width of 7. */
static int
bwc_number_width (char **files, int nfiles, int ncols)
{
    if (nfiles == 0 || (nfiles == 1 && ncols == 1))
        return 1;

    struct stat st;
    int first_failed;
    if (strcmp (files[0], "-") == 0)
        first_failed = fstat (STDIN_FILENO, &st);
    else
        first_failed = stat (files[0], &st);
    if (first_failed > 0)
        return 1;

    int minimum_width = 1;
    unsigned long long regular_total = 0;
    for (int i = 0; i < nfiles; i++) {
        struct stat s;
        int failed = (strcmp (files[i], "-") == 0)
            ? fstat (STDIN_FILENO, &s)
            : stat (files[i], &s);
        if (failed)
            continue;
        if (!S_ISREG (s.st_mode))
            minimum_width = 7;
        else if (s.st_size > 0)
            regular_total += (unsigned long long) s.st_size;
    }
    int width = bwc_digits (regular_total);
    if (width < minimum_width)
        width = minimum_width;
    return width;
}

int
wc_builtin (WORD_LIST *list)
{
    int lflag = 0, wflag = 0, cflag = 0, mflag = 0, Lflag = 0;
    const char *files_from = NULL;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashwc 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--lines")) { lflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--words")) { wflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--bytes")) { cflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--chars")) { mflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--max-line-length")) { Lflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--files0-from")) {
            if (!list->next) { builtin_error ("%s needs FILE", w); return EX_USAGE; }
            list = list->next;
            files_from = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--files0-from=", 14)) {
            files_from = w + 14;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--", 2)) {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        for (const char *p = w + 1; *p; p++) {
            switch (*p) {
                case 'l': lflag = 1; break;
                case 'w': wflag = 1; break;
                case 'c': cflag = 1; break;
                case 'm': mflag = 1; break;
                case 'L': Lflag = 1; break;
                default: builtin_error ("unknown flag: -%c", *p); builtin_usage (); return EX_USAGE;
            }
        }
        list = list->next;
    }

    int ncols = lflag + wflag + cflag + mflag + Lflag;
    if (ncols == 0)
        ncols = 3;   /* default -lwc */

    bwc_counts total = {0};
    int rc = EXECUTION_SUCCESS;

    /* --files0-from: read NUL-separated filenames; counts each like an
     * operand. With files_from == "-" the list comes from stdin, and (per
     * GNU) the number_width drops to 1 (the nfiles==0 fstatus path). */
    if (files_from) {
        if (list) {
            builtin_error ("file operands cannot be combined with --files0-from");
            return EX_USAGE;
        }
        size_t blen = 0;
        char *blob = bwc_slurp (files_from, &blen);
        if (!blob)
            return EXECUTION_FAILURE;

        /* Split on NUL into a name array. */
        char **names = NULL;
        int nnames = 0, ncap = 0;
        int tokpos = 0;       /* 1-based NUL-delimited token position */
        size_t i = 0;
        while (i < blen) {
            size_t start = i;
            while (i < blen && blob[i] != '\0') i++;
            if (i == start && i < blen) {
                /* Empty (zero-length) file name. */
                tokpos++;
                builtin_error ("%s:%d: invalid zero-length file name", files_from, tokpos);
                rc = EXECUTION_FAILURE;
                i++;
                continue;
            }
            if (i >= blen && start == i)
                break;
            tokpos++;
            if (nnames >= ncap) {
                ncap = ncap ? ncap * 2 : 16;
                char **nn = realloc (names, (size_t) ncap * sizeof *nn);
                if (!nn) { free (names); free (blob); return EXECUTION_FAILURE; }
                names = nn;
            }
            blob[i] = '\0';
            names[nnames++] = blob + start;
            i++;
        }

        /* GNU wc width rule for --files0-from (coreutils 9.x):
         *   - list from a regular file (a real --files0-from=FILE, OR
         *     --files0-from=- with stdin redirected from a regular file):
         *     all names are read up front, so nfiles is known and the width
         *     is computed from the operand files' sizes (the normal path).
         *   - list from a non-regular stream (pipe/tty via --files0-from=-):
         *     names are streamed one at a time, nfiles==0, so width is 1. */
        int width;
        if (strcmp (files_from, "-") == 0) {
            struct stat lst;
            if (fstat (STDIN_FILENO, &lst) == 0 && S_ISREG (lst.st_mode))
                width = bwc_number_width (names, nnames, ncols);
            else
                width = 1;
        } else {
            width = bwc_number_width (names, nnames, ncols);
        }

        for (int k = 0; k < nnames; k++) {
            int from_stdin = strcmp (names[k], "-") == 0;
            FILE *f = from_stdin ? stdin : fopen (names[k], "r");
            if (!f) {
                builtin_error ("%s: %s", names[k], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (!from_stdin) {
                struct stat dst;
                if (fstat (fileno (f), &dst) == 0 && S_ISDIR (dst.st_mode)) {
                    /* GNU wc: diagnose + exit 1, but still emit a 0/0/0
                       count line (reading the dir fd yields 0 bytes). */
                    builtin_error ("%s: Is a directory", names[k]);
                    rc = EXECUTION_FAILURE;
                }
            }
            bwc_counts c = {0};
            bwc_count_stream (f, &c);
            if (!from_stdin)
                fclose (f);
            bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, names[k]);
            total.lines += c.lines;
            total.words += c.words;
            total.bytes += c.bytes;
            total.chars += c.chars;
            if (c.max_line > total.max_line)
                total.max_line = c.max_line;
        }
        if (nnames > 1)
            bwc_print (&total, lflag, wflag, cflag, mflag, Lflag, width, "total");
        free (names);
        free (blob);
        return rc;
    }

    if (!list) {
        int width = bwc_number_width ((char *[]){ (char *) "-" }, 1, ncols);
        bwc_counts c = {0};
        bwc_count_stream (stdin, &c);
        bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, NULL);
    } else {
        int n_files = 0;
        for (WORD_LIST *p = list; p; p = p->next) n_files++;
        char **files = malloc ((size_t) n_files * sizeof *files);
        if (!files)
            return EXECUTION_FAILURE;
        {
            int k = 0;
            for (WORD_LIST *p = list; p; p = p->next)
                files[k++] = p->word->word;
        }
        int width = bwc_number_width (files, n_files, ncols);
        free (files);

        for (WORD_LIST *p = list; p; p = p->next) {
            int from_stdin = strcmp (p->word->word, "-") == 0;
            FILE *f = from_stdin ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (!from_stdin) {
                struct stat dst;
                if (fstat (fileno (f), &dst) == 0 && S_ISDIR (dst.st_mode)) {
                    /* GNU wc: diagnose + exit 1, but still emit a 0/0/0
                       count line (reading the dir fd yields 0 bytes). */
                    builtin_error ("%s: Is a directory", p->word->word);
                    rc = EXECUTION_FAILURE;
                }
            }
            bwc_counts c = {0};
            bwc_count_stream (f, &c);
            if (!from_stdin)
                fclose (f);
            bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, p->word->word);
            total.lines += c.lines;
            total.words += c.words;
            total.bytes += c.bytes;
            total.chars += c.chars;
            if (c.max_line > total.max_line)
                total.max_line = c.max_line;
        }
        if (n_files > 1)
            bwc_print (&total, lflag, wflag, cflag, mflag, Lflag, width, "total");
    }
    return rc;
}

char *wc_doc[] = {
    "Count lines / words / bytes / chars in FILEs (or stdin).",
    "",
    "    bashwc [-lwcmL] [--lines|--words|--bytes|--chars|--max-line-length] [FILE...]",
    "    bashwc --help | --version",
    "",
    "Flags:",
    "    -l   count lines",
    "    -w   count words (whitespace-separated runs)",
    "    -c   count bytes",
    "    -m   count characters",
    "    -L   count maximum display line length",
    "    --lines, --words, --bytes, --chars, --max-line-length",
    "    --files0-from=F  read NUL-separated file names from F (- for stdin)",
    "    --help      show usage",
    "    --version   show version",
    "    (no flags) → -lwc (default)",
    "",
    "Multi-file output emits one row per file plus a `total` row.",
    (char *)NULL
};

struct builtin bashwc_struct = {
    "bashwc",
    wc_builtin,
    BUILTIN_ENABLED,
    wc_doc,
    "bashwc [-lwcmL] [--lines|--words|--bytes|--chars|--max-line-length] [FILE...]",
    0
};
