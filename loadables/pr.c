/* SPDX-License-Identifier: MIT */
/* pr.c — POSIX pr(1) paginator/formatter.
 *
 *   pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH]
 *          [-n] [-N] [-a] [-o OFFSET] [-s[SEP]] [FILE...]
 *
 *   -t          terse: no header / footer / form-feed paging
 *   -m          merge: read all FILEs in parallel, side-by-side columns
 *   -h HEADER   override the page header (default: filename)
 *   -l LINES    lines per page (default 66; header + body + footer = 66)
 *   -w WIDTH    page width for column layout (default 72)
 *   -n          number lines (1-based, 5-digit-wide column + tab)
 *   -N          (a bare digit) lay a single file out in N balanced columns
 *   -a          (--across) fill -N columns left-to-right, not top-to-bottom
 *   -o OFFSET   indent every output line by OFFSET spaces (left margin)
 *   -s[SEP]     separate columns with SEP (default TAB); no padding/truncate
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
#include <limits.h>
#include <time.h>

#include "loadables.h"

typedef struct {
    int    terse;
    int    merge;
    int    across;         /* -a: fill columns left-to-right (row-major) */
    const char *header;
    int    page_lines;     /* total lines per page including header/footer */
    int    body_lines;     /* derived: page_lines - 10 */
    int    width;
    int    number;
    int    num_width;      /* -n DIGITS: width of the line-number field (default 5) */
    char   num_sep;        /* -n SEP: char after the number (default TAB) */
    int    dbl;            /* -d: double-space (blank line after each body line) */
    int    formfeed;       /* -f / -F: form-feed page separation, no blank padding */
    int    columns;        /* -N: number of output columns (default 1) */
    int    offset;         /* -o N: left-margin indent (default 0) */
    int    sep_set;        /* -s seen */
    char   sep;            /* -s[c] column separator (default '\t' when set) */
} pr_opts;

/* Emit the -o left-margin indent (spaces) at the start of a row. */
static void
pr_offset (const pr_opts *o)
{
    int i;
    for (i = 0; i < o->offset; i++)
        putchar (' ');
}

static int
pr_parse_int_arg (const char *opt, const char *arg, int *out)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol (arg, &end, 10);
    if (end == arg || *end != '\0' || errno == ERANGE || v > INT_MAX || v < 0) {
        builtin_error ("%s: invalid number: %s", opt, arg);
        builtin_usage ();
        return EX_USAGE;
    }

    *out = (int) v;
    return EXECUTION_SUCCESS;
}

/* Header: blank, blank, DATE FILENAME PAGE, blank, blank (5 lines).
   GNU pr uses ISO-like date/minute text and centers the title between
   date and page marker within the page width. */
static void
pr_header (const pr_opts *o, const char *fname, int page_no)
{
    if (o->terse) return;
    char tbuf[64];
    char pagebuf[32];
    time_t t = time (NULL);
    struct tm tm;
    const char *title = o->header ? o->header : (fname ? fname : "");
    int title_len;
    int sep_left;
    int sep_right;
    int available;

    localtime_r (&t, &tm);
    strftime (tbuf, sizeof tbuf, "%Y-%m-%d %H:%M", &tm);
    snprintf (pagebuf, sizeof pagebuf, "Page %d", page_no);

    title_len = (int) strlen (title);
    available = o->width - (int) strlen (tbuf) - title_len - (int) strlen (pagebuf);
    sep_left = available / 2;
    sep_right = available - sep_left;
    if (sep_left < 2)
        sep_left = 2;
    if (sep_right < 2)
        sep_right = 2;

    /* The -o margin shifts the header right by OFFSET columns, exactly like
       the body rows, while the date/title/page centering stays computed
       against the unshifted page width (matches GNU pr's chars_per_margin).
       GNU also emits the margin on the first of the two leading blank lines
       (an artifact of its pad_across_to()+print_white_space() before the
       newlines); the leading "%*s" reproduces that. All "%*s" collapse to
       nothing when OFFSET is 0, so the no-offset header is byte-unchanged. */
    printf ("%*s\n\n%*s%s%*s%s%*s%s\n\n\n",
            o->offset, "",
            o->offset, "", tbuf, sep_left, "", title, sep_right, "", pagebuf);
}

static void
pr_footer (const pr_opts *o, int body_printed)
{
    if (o->terse) return;
    /* -f/-F: a single form-feed replaces the blank footer padding; the next
       page's header leading blanks follow it (so it renders as \f\n...). The
       final page's footer is just the bare \f with no trailing newline. */
    if (o->formfeed) {
        putchar ('\f');
        return;
    }
    /* Pad the body region out to body_lines (for a short final page), then the
       fixed 5-line footer. Equivalent to page_lines-5-body_printed when
       body_lines == page_lines-10, but stays correct when body_lines was
       adjusted (e.g. -d rounds it down to even). */
    int blanks = (o->body_lines - body_printed) + 5;
    if (blanks < 0)
        blanks = 0;
    while (blanks-- > 0)
        putchar ('\n');
}

static int
pr_pad_to_column (int col, int target)
{
    while (col < target) {
        int next_tab = ((col / 8) + 1) * 8;
        if (next_tab <= target) {
            putchar ('\t');
            col = next_tab;
        } else {
            putchar (' ');
            col++;
        }
    }
    return col;
}

/* Strip trailing newline / CR from a (possibly NULL) string in place. */
static size_t
pr_chomp (char *s)
{
    if (!s) return 0;
    size_t l = strlen (s);
    while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r')) s[--l] = '\0';
    return l;
}

/* GNU pr's column line-number geometry (default -n): a CHARS_PER_NUMBER-wide
   right-justified number followed by (NUMBER_WIDTH - CHARS_PER_NUMBER) spaces.
   NUMBER_WIDTH rounds the number field up to the next 8-col tab stop, matching
   GNU's `number_width = chars_per_number + TAB_WIDTH(8, chars_per_number)`.
   With -n the digit count is configurable (`o->num_width`, default 5) and the
   trailing pad is a TAB stop only when the separator is the default TAB; a
   custom -n separator (e.g. -nc3) uses exactly one separator char with no
   tab-stop rounding. */
#define PR_DEFAULT_CHARS_PER_NUMBER 5
/* chars_per_number for this run */
#define PR_CHARS_PER_NUMBER (o->num_width)
/* full number field incl. separator: TAB-rounded for the default TAB sep,
   else digits + 1 separator char. */
#define PR_NUMBER_WIDTH \
    ((o->num_sep == '\t') \
       ? (o->num_width + (8 - o->num_width % 8)) \
       : (o->num_width + 1))

/* Tab-compressing output tracker, mirroring GNU pr's tabify_output path
   (print_char buffers spaces; print_white_space flushes them as TABs to each
   8-col stop plus residual spaces). Tracks absolute output column so the
   TAB/space split matches GNU byte-for-byte. Trailing buffered spaces that are
   never followed by a glyph are dropped — that is GNU's trailing-space strip. */
typedef struct { int pos; int pending; } pr_tw;

static void
pr_tw_flush (pr_tw *w)            /* == GNU print_white_space () */
{
    int goal = w->pos + w->pending;
    int h = w->pos;
    while (goal - h > 1) {
        int next_tab = h + 8 - (h % 8);          /* POS_AFTER_TAB(8, h) */
        if (next_tab > goal) break;
        putchar ('\t');
        h = next_tab;
    }
    while (++h <= goal) putchar (' ');
    w->pos = goal;
    w->pending = 0;
}

static void
pr_tw_putc (pr_tw *w, char c)     /* == GNU print_char () under tabify_output */
{
    if (c == ' ') { w->pending++; return; }
    if (w->pending) pr_tw_flush (w);
    putchar (c);
    w->pos++;                     /* glyphs assumed width 1 */
}

/* Buffer enough spaces to reach absolute column `target`, then flush — GNU
   pads to each column's start_position as a discrete (flushed) step before
   the number begins, which is why the pad and the number's leading spaces
   tab-compress independently. */
static void
pr_tw_pad_to (pr_tw *w, int target)
{
    int cur = w->pos + w->pending;
    if (target > cur)
        w->pending += target - cur;
    pr_tw_flush (w);
}

/* Emit one row of `ncol` column strings (NULL = empty column). When a -s
   separator is set, columns are joined by that single byte with no padding
   or truncation (GNU semantics); otherwise each column is padded/truncated
   to width/ncol and tab-aligned to its column origin. The -o offset indent
   precedes everything.

   Numbering has two GNU-distinct shapes:
     - `colnums != NULL` → COLUMN mode (-N/-a with -n): each cell prints its
       OWN "%5ld\t" number field at its column origin (colnums[i]; 0 = none).
       Column origins stay at offset + i*col_w — the number sits inside the
       cell, it does not shift the grid.
     - else `lineno > 0` → MERGE / single-column: one "%5ld\t" field is
       printed once, before all columns, and reserves a 4-col extra margin
       that pushes the later column origins out. */
/* Print a single-column/merge line-number field: `num_width`-wide
   right-justified number (low-order digits kept on overflow, matching GNU),
   then the separator char (TAB default, or the custom -n separator). Returns
   the printed width of the number digits (>= num_width). */
/* Print a single-column/merge line-number field at output column `startcol`.
   COMPRESS tab-compresses the right-justified leading spaces (GNU does this in
   merge mode but NOT in single-column / -s mode — the number field there is
   emitted verbatim). Returns the printed digit width (>= num_width). */
static int
pr_print_number (const pr_opts *o, long lineno, int startcol, int compress)
{
    char nb[3 * sizeof (long) + 2];
    int nl = snprintf (nb, sizeof nb, "%*ld", o->num_width, lineno);
    const char *s = (nl > o->num_width) ? nb + (nl - o->num_width) : nb;
    int w = (int) strlen (s);
    if (o->num_sep == '\t' && compress) {
        /* GNU tabify_output: leading spaces collapse to TABs at each 8-col
           stop (matters for widths >= 8 in merge mode). */
        pr_tw tw = { .pos = startcol, .pending = 0 };
        for (const char *p = s; *p; p++) pr_tw_putc (&tw, *p);
        pr_tw_flush (&tw);
        putchar ('\t');
    } else {
        fputs (s, stdout);
        putchar (o->num_sep);
    }
    return w;
}

static void
pr_emit_row (char *const *cols, int ncol, const pr_opts *o, long lineno,
             const long *colnums)
{
    /* -s separator mode: number(s) as applicable, then columns joined by SEP,
       no padding/truncation. */
    if (o->sep_set) {
        pr_offset (o);
        if (!colnums && lineno > 0)
            pr_print_number (o, lineno, o->offset, 0);
        for (int i = 0; i < ncol; i++) {
            if (i) putchar (o->sep);
            if (colnums && colnums[i] > 0)
                pr_print_number (o, colnums[i], 0, 0);
            if (cols[i]) fputs (cols[i], stdout);
        }
        putchar ('\n');
        return;
    }

    /* Column stride (origin-to-origin). GNU reserves a 1-char separator
       between -N columns: chars_per_column = (width - (ncol-1)*1)/ncol, and
       the stride is chars_per_column + 1. At the default width 72 this equals
       width/ncol for ncol 2..6, so default-width output is unchanged; it only
       differs for non-default -w. Merge mode (parallel files) uses GNU's other
       width formula, so it keeps the naive division. */
    int col_w;
    if (ncol <= 0)
        col_w = o->width;
    else if (o->merge)
        col_w = o->width / ncol;
    else
        col_w = (o->width - (ncol - 1)) / ncol + 1;
    /* GNU floors chars_per_column (= stride - 1) at 1, i.e. stride at 2. */
    if (col_w < 2) col_w = 2;
    int text_w = col_w - 1;

    /* Per-cell column numbering (GNU -N/-a with -n): column origins stay at
       offset + i*col_w (the number lives inside the cell). Rendered through
       the tab-compressing tracker so the number's right-justified leading
       spaces and its NUMBER_WIDTH-CHARS_PER_NUMBER separator spaces collapse
       to TABs exactly as GNU does. The text field is what's left of the
       column after the number field. */
    if (colnums) {
        pr_tw w = { .pos = 0, .pending = 0 };
        /* GNU truncates a numbered column's text to chars_per_column minus
           the number field: (col_w - 1) - NUMBER_WIDTH. */
        int num_text_w = text_w - PR_NUMBER_WIDTH;
        if (num_text_w < 1) num_text_w = 1;
        pr_tw_pad_to (&w, o->offset);
        for (int i = 0; i < ncol; i++) {
            if (!o->merge) {
                int rest = 0;
                for (int j = i; j < ncol; j++)
                    if ((cols[j] && cols[j][0]) || colnums[j] > 0) { rest = 1; break; }
                if (!rest) break;
            }
            pr_tw_pad_to (&w, o->offset + i * col_w);   /* discrete flush at origin */
            if (colnums[i] > 0) {
                char nb[3 * sizeof (long) + 2];
                int nl = snprintf (nb, sizeof nb, "%*ld", PR_CHARS_PER_NUMBER, colnums[i]);
                /* GNU keeps the low-order digits when the count overflows the
                   field; otherwise nb is already right-justified to width. */
                const char *s = (nl > PR_CHARS_PER_NUMBER) ? nb + (nl - PR_CHARS_PER_NUMBER) : nb;
                for (; *s; s++) pr_tw_putc (&w, *s);
                if (o->num_sep == '\t')
                    w.pending += PR_NUMBER_WIDTH - PR_CHARS_PER_NUMBER;   /* separator spaces -> TAB */
                else
                    pr_tw_putc (&w, o->num_sep);                          /* literal separator char */
            }
            if (cols[i] && cols[i][0]) {
                int trim = (int) strlen (cols[i]);
                if (ncol > 1 && trim > num_text_w) trim = num_text_w;
                for (int k = 0; k < trim; k++) pr_tw_putc (&w, cols[i][k]);
            }
        }
        putchar ('\n');     /* trailing buffered spaces dropped (GNU strip) */
        return;
    }

    /* Once-before-all numbering (merge / single column). Column origins:
         origin(i) = offset + i*col_w + num_shift
       The -o margin shifts the whole row; the single -n field reserves a
       fixed extra margin (chars_per_number - 1 == 4 for the default 5-wide
       number) that pushes the later column origins out. */
    /* GNU reserves a fixed extra left margin for the single -n field that
       pushes the later column origins out. For the default TAB separator the
       number field is rounded up to a TAB stop and the reserved margin grows in
       4-column steps: 4 for a 1..7-wide field, 8 for 8..15, etc. — i.e.
       4*(1 + num_width/8). The default 5-wide number gives the historical 4.
       For a custom (non-TAB) separator the field is num_width+1 wide and the
       reserved margin is num_width-1. */
    int num_shift = 0;
    if (lineno > 0)
        num_shift = (o->num_sep == '\t') ? 4 * (1 + o->num_width / 8)
                                         : (o->num_width - 1);
    pr_offset (o);
    int out_col = o->offset;
    if (lineno > 0) {
        int nw = pr_print_number (o, lineno, o->offset, o->merge);
        out_col += nw;                         /* the number digits */
        if (o->num_sep == '\t')
            out_col = ((out_col / 8) + 1) * 8;  /* the trailing TAB stop */
        else
            out_col += 1;                       /* the literal separator char */
    }

    for (int i = 0; i < ncol; i++) {
        /* Column mode (-2/-3 of a single file): trailing empty columns
           produce no padding (GNU strips trailing whitespace on the final
           short page). Merge mode (-m) is different: every FILE is a live
           column, so GNU advances to each column origin and pads even when a
           file has been exhausted — do NOT strip there. */
        if (!o->merge) {
            int rest = 0;
            for (int j = i; j < ncol; j++)
                if (cols[j] && cols[j][0]) { rest = 1; break; }
            if (!rest) break;
        }
        if (i)
            out_col = pr_pad_to_column (out_col, o->offset + i * col_w + num_shift);
        if (!cols[i] || !cols[i][0])
            continue;
        int trim = (int) strlen (cols[i]);
        if (ncol > 1 && trim > text_w) trim = text_w;
        fwrite (cols[i], 1, (size_t) trim, stdout);
        out_col += trim;
    }
    putchar ('\n');
}

/* Single-file, single-column mode: paginate FILE one line per row. */
static int
pr_single (FILE *f, const char *fname, const pr_opts *o)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int line_in_page = 0;
    int page_no = 1;
    long lineno = 1;

    /* In -d mode each input line occupies two body slots (the line + a trailing
       blank), and GNU will not start a line whose blank won't also fit — so the
       break threshold is body_lines minus the per-line slot count. */
    while ((n = getline (&line, &cap, f)) != -1) {
        if (line_in_page >= o->body_lines) {
            pr_footer (o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0)
            pr_header (o, fname, page_no);
        pr_chomp (line);
        char *cols[1] = { line };
        pr_emit_row (cols, 1, o, o->number ? lineno++ : 0, NULL);
        line_in_page++;
        if (o->dbl) {           /* -d: blank line after each body line, counts as a body line */
            putchar ('\n');
            line_in_page++;
        }
    }
    if (line_in_page > 0) pr_footer (o, line_in_page);
    free (line);
    return 0;
}

/* Single-file, multi-column mode (-N): balanced columns. The file is read
   fully, then laid out. Default (column-major / "down"): column 1 gets the
   first ceil(L/N) lines, column 2 the next batch, etc. With -a ("across"):
   row-major — lines fill left-to-right across each row before the next.
   With -n the number is per-cell (each cell shows its input line number),
   matching GNU column-mode placement. */
static int
pr_columns (FILE *f, const char *fname, const pr_opts *o)
{
    char **lines = NULL;
    long nlines = 0, lcap = 0;
    char *raw = NULL;
    size_t rawcap = 0;
    ssize_t nread;

    while ((nread = getline (&raw, &rawcap, f)) != -1) {
        if (nlines == lcap) {
            long newcap = lcap ? lcap * 2 : 64;
            char **nl = realloc (lines, (size_t) newcap * sizeof *lines);
            if (!nl) break;
            lines = nl; lcap = newcap;
        }
        lines[nlines] = malloc ((size_t) nread + 1);
        if (!lines[nlines]) break;
        memcpy (lines[nlines], raw, (size_t) nread);
        lines[nlines][nread] = '\0';
        pr_chomp (lines[nlines]);
        nlines++;
    }
    free (raw);

    int ncol = o->columns;
    long per_col = (nlines + ncol - 1) / ncol;   /* ceil = number of rows */
    if (per_col < 1) per_col = 1;

    /* GNU balances "down" columns when nlines isn't a multiple of ncol: the
       first `rem` columns get base+1 lines, the rest get base (e.g. 7 in 3
       cols => heights 3,2,2, not 3,3,1). Column c then begins at line index
       start(c) = c*base + min(c, rem). "across" is unaffected (row-major). */
    long base = nlines / ncol;
    int  rem  = (int) (nlines % ncol);

    int line_in_page = 0;
    int page_no = 1;
    char **cols = calloc ((size_t) ncol, sizeof *cols);
    long *colnums = o->number ? calloc ((size_t) ncol, sizeof *colnums) : NULL;

    for (long row = 0; row < per_col; row++) {
        if (line_in_page >= o->body_lines) {
            pr_footer (o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0)
            pr_header (o, fname, page_no);
        for (int c = 0; c < ncol; c++) {
            long idx;
            if (o->across) {
                /* row-major: line fills left-to-right across each row. */
                idx = row * ncol + c;
            } else {
                /* column-major, balanced: column c holds base(+1 if c<rem)
                   lines starting at start(c); rows past its height are empty. */
                long height = base + (c < rem ? 1 : 0);
                long start  = (long) c * base + (c < rem ? c : rem);
                idx = (row < height) ? start + row : nlines; /* nlines = empty */
            }
            cols[c] = (idx < nlines) ? lines[idx] : NULL;
            if (colnums)
                colnums[c] = (idx < nlines) ? idx + 1 : 0;
        }
        pr_emit_row (cols, ncol, o, 0, colnums);
        line_in_page++;
    }
    if (line_in_page > 0) pr_footer (o, line_in_page);

    for (long j = 0; j < nlines; j++) free (lines[j]);
    free (lines); free (cols); free (colnums);
    return 0;
}

/* Merge mode: read all files line-by-line in parallel, side by side. EOF on
   one file leaves its column blank until the others finish. With -n the line
   number is emitted once per row, before all columns (GNU placement). */
static int
pr_merge (FILE **files, const char **names, int n, const pr_opts *o)
{
    (void) names;
    char **lines = calloc ((size_t) n, sizeof *lines);
    size_t *caps = calloc ((size_t) n, sizeof *caps);
    int *eof = calloc ((size_t) n, sizeof *eof);
    char **cols = calloc ((size_t) n, sizeof *cols);
    int line_in_page = 0;
    int page_no = 1;
    long lineno = 1;

    for (;;) {
        int any = 0;
        for (int i = 0; i < n; i++) {
            if (eof[i]) { cols[i] = NULL; continue; }
            if (getline (&lines[i], &caps[i], files[i]) != -1) {
                any = 1;
                pr_chomp (lines[i]);
                cols[i] = lines[i];
            } else {
                eof[i] = 1;
                cols[i] = NULL;
            }
        }
        if (!any) break;
        if (line_in_page >= o->body_lines) {
            pr_footer (o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0)
            pr_header (o, NULL, page_no);
        pr_emit_row (cols, n, o, o->number ? lineno++ : 0, NULL);
        line_in_page++;
    }
    if (line_in_page > 0) pr_footer (o, line_in_page);
    for (int i = 0; i < n; i++) free (lines[i]);
    free (lines); free (caps); free (eof); free (cols);
    return 0;
}

int
pr_builtin (WORD_LIST *list)
{
    pr_opts o = { .page_lines = 66, .width = 72, .columns = 1,
                  .num_width = PR_DEFAULT_CHARS_PER_NUMBER, .num_sep = '\t' };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("pr 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-t")) { o.terse = 1; list = list->next; continue; }
        if (!strcmp (w, "-m")) { o.merge = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--double-space")) { o.dbl = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "-F")
            || !strcmp (w, "--form-feed") || !strcmp (w, "--form-feed=")) {
            o.formfeed = 1; list = list->next; continue;
        }
        /* -n[SEP[DIGITS]]: number lines. Attached arg is GNU's only form (a
           separated token is taken as a filename). SEP = a single leading
           non-digit char (default TAB); DIGITS = the field width (default 5).
           e.g. -n => 5/TAB, -n3 => 3/TAB, -nc3 => 3/sep 'c', -n: => 5/sep ':'. */
        if (w[1] == 'n') {
            o.number = 1;
            const char *p = w + 2;
            if (*p && !(*p >= '0' && *p <= '9')) {
                o.num_sep = *p;                 /* leading non-digit = separator */
                p++;
            }
            if (*p) {                           /* remaining = digit width */
                char *end;
                long d = strtol (p, &end, 10);
                if (*end != '\0' || d < 1) {
                    builtin_error ("-n: invalid number format: %s", w);
                    builtin_usage ();
                    return EX_USAGE;
                }
                o.num_width = (int) d;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--across")) { o.across = 1; list = list->next; continue; }
        /* -N (a bare digit count) selects N output columns. */
        if (w[1] >= '1' && w[1] <= '9' && w[2] == '\0') {
            o.columns = w[1] - '0';
            list = list->next;
            continue;
        }
        /* -o OFFSET (attached -oN or separate -o N): left-margin indent. */
        if (w[1] == 'o') {
            int parsed;
            const char *arg;
            if (w[2] != '\0') {
                arg = w + 2;
            } else {
                if (!list->next) { builtin_error ("-o needs OFFSET"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                arg = list->word->word;
            }
            if (pr_parse_int_arg ("-o", arg, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            o.offset = parsed;
            list = list->next;
            continue;
        }
        /* -s[c]: column separator (default TAB). Disables width padding. */
        if (w[1] == 's' && (w[2] == '\0' || w[3] == '\0')) {
            o.sep_set = 1;
            o.sep = (w[2] != '\0') ? w[2] : '\t';
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--header")) {
            if (!list->next) { builtin_error ("--header needs HEADER"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            o.header = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--header=", 9)) {
            o.header = w + 9;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-h")) {
            if (!list->next) { builtin_error ("-h needs HEADER"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            o.header = list->word->word;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--length")) {
            int parsed;
            if (!list->next) { builtin_error ("--length needs LINES"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_parse_int_arg ("--length", list->word->word, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            o.page_lines = parsed;
            if (o.page_lines < 11) o.page_lines = 66;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--length=", 9)) {
            int parsed;
            if (pr_parse_int_arg ("--length", w + 9, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            o.page_lines = parsed;
            if (o.page_lines < 11) o.page_lines = 66;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-l")) {
            int parsed;
            if (!list->next) { builtin_error ("-l needs LINES"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_parse_int_arg ("-l", list->word->word, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            o.page_lines = parsed;
            if (o.page_lines < 11) o.page_lines = 66;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--width")) {
            int parsed;
            if (!list->next) { builtin_error ("--width needs WIDTH"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_parse_int_arg ("--width", list->word->word, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            if (parsed < 8) {
                builtin_error ("--width: invalid width: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            o.width = parsed;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--width=", 8)) {
            int parsed;
            if (pr_parse_int_arg ("--width", w + 8, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            if (parsed < 8) {
                builtin_error ("--width: invalid width: %s", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            o.width = parsed;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-w")) {
            int parsed;
            if (!list->next) { builtin_error ("-w needs WIDTH"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_parse_int_arg ("-w", list->word->word, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            if (parsed < 8) {
                builtin_error ("-w: invalid width: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            o.width = parsed;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }
    o.body_lines = o.terse ? o.page_lines : (o.page_lines - 10);
    if (o.body_lines < 1) o.body_lines = 56;
    /* -d emits each body line as a 2-line unit (line + blank); GNU rounds the
       body region down to an even number of lines so a unit never straddles a
       page boundary. */
    if (o.dbl && (o.body_lines & 1)) o.body_lines--;

    int rc = EXECUTION_SUCCESS;
    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;

    if (n_files == 0) {
        if (o.columns > 1 && !o.merge)
            pr_columns (stdin, NULL, &o);
        else
            pr_single (stdin, NULL, &o);
        return rc;
    }
    if (o.merge && n_files > 1) {
        FILE **files = calloc ((size_t) n_files, sizeof *files);
        const char **names = calloc ((size_t) n_files, sizeof *names);
        int i = 0;
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            files[i] = f;
            names[i] = p->word->word;
            i++;
        }
        pr_merge (files, names, i, &o);
        for (int j = 0; j < i; j++) if (files[j] != stdin) fclose (files[j]);
        free (files); free ((void *) names);
        return rc;
    }
    /* Single-file mode: paginate each separately. */
    for (WORD_LIST *p = list; p; p = p->next) {
        FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
        if (!f) {
            builtin_error ("%s: %s", p->word->word, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (o.columns > 1 && !o.merge)
            pr_columns (f, p->word->word, &o);
        else
            /* -m always uses a blank header title (GNU pr), even with a
               single FILE, where this would otherwise fall through to the
               filename-titled single-file path. */
            pr_single (f, o.merge ? NULL : p->word->word, &o);
        if (f != stdin) fclose (f);
    }
    return rc;
}

char *pr_doc[] = {
    "Format text for printing (POSIX pr).",
    "",
    "    pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH] [-n] [-N] [-a] [-o OFFSET] [-s[SEP]] [FILE...]",
    "",
    "    -t          terse: no header / footer paging",
    "    -m          merge mode: side-by-side columns of all FILEs",
    "    -d          double-space the output (blank line after each body line)",
    "    -f, -F      use a form-feed to separate pages (no blank padding)",
    "    -h HEADER   override page header (default: filename)",
    "    -l LINES    lines per page (default 66 — 5 hdr + 56 body + 5 ftr)",
    "    -w WIDTH    column-layout width (default 72)",
    "    -n[SEP[N]]  number body lines (N digits, default 5; SEP after, def tab)",
    "    -N          a bare digit: lay one file out in N balanced columns",
    "    -a          (--across) fill -N columns left-to-right, not top-down",
    "    -o OFFSET   indent every line by OFFSET spaces (left margin)",
    "    -s[SEP]     separate columns with SEP (default tab), no padding",
    "    --help      show this help",
    "    --version   show version",
    "",
    "Without flags: paginates with 5-line top header (date + filename +",
    "page #), 56 lines of body, 5-line footer. Reads stdin if no FILE.",
    (char *)NULL
};

struct builtin pr_struct = {
    "pr",
    pr_builtin,
    BUILTIN_ENABLED,
    pr_doc,
    "pr [--help|--version] [-tmnadfF] [-N] [-o OFFSET] [-s[SEP]] [-h HEADER] [-l LINES] [-w WIDTH] [FILE...]",
    0
};
