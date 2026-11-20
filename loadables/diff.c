/* bashdiff.c — POSIX diff(1) as a bash builtin (Myers O(ND)).
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdiff [-u|-y [-W NUM]] [-q] [-i] [-r] [--help|--version] FILE1 FILE2
 *
 *   -y   side-by-side, laid out as GNU diff (-W NUM width, default 130)
 *   -r   recursive directory comparison, with GNU's "Only in" lines
 *   -u   unified diff (with @@ hunks + 3 lines context)
 *   -q   quiet: only report whether files differ (no content)
 *   -i   ignore case
 *
 * Default output is POSIX ed-style: 1c2 / 1a1 / 2d3 with `< old`,
 * `---`, `> new` markers.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Per POSIX.
 *
 * Algorithm: Myers' O(ND) line-level diff. V-trace memoization
 * for backtrack. Live frontier O(N+M), saved active diagonals O(D^2).
 * Worst-case time and trace memory remain quadratic for unrelated inputs.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>

#include "loadables.h"
#include "bl-output.h"

typedef struct {
    int uflag, qflag, iflag, yflag, rflag;
    long width;              /* -W: side-by-side output width */
    const char *switches;    /* option words as given, for -r headers */
} bd_opts;
typedef struct { const unsigned char *data; size_t len; } bd_line;

static int
bd_is_stdin (const char *path)
{
    return path && strcmp (path, "-") == 0;
}

/* Read PATH into a buffer. "-" uses the caller's stdin descriptor, which
   this loader never opens or closes. */
static int
bd_load (const char *path, unsigned char **data, size_t *len)
{
    int fd, owned = 0;
    if (bd_is_stdin (path)) {
        fd = STDIN_FILENO;
    } else {
        fd = open (path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("%s: %s", path, strerror (errno));
            return -1;
        }
        owned = 1;
    }
    size_t cap = 4096, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) {
        builtin_error ("%s: out of memory", path);
        if (owned) close (fd);
        return -1;
    }
    for (;;) {
        if (n == cap) {
            if (cap > (size_t) -1 / 2) {
                builtin_error ("%s: out of memory", path);
                free (buf);
                if (owned) close (fd);
                return -1;
            }
            size_t ncap = cap * 2;
            unsigned char *grown = realloc (buf, ncap);
            if (!grown) {
                builtin_error ("%s: out of memory", path);
                free (buf);
                if (owned) close (fd);
                return -1;
            }
            buf = grown;
            cap = ncap;
        }
        ssize_t r = read (fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("%s: %s", path, strerror (errno));
            free (buf);
            if (owned) close (fd);
            return -1;
        }
        if (r == 0) break;
        n += (size_t) r;
    }
    if (owned) close (fd);
    *data = buf;
    *len = n;
    return 0;
}

/* Match the usual binary probe; later NULs remain part of text records. */
static int
bd_probe_binary (const unsigned char *data, size_t len)
{
    return memchr (data, '\0', len < 4096 ? len : 4096) != NULL;
}

static int
bd_files_equal (const unsigned char *a, size_t la, const unsigned char *b, size_t lb)
{
    if (la != lb) return 0;
    if (la == 0) return 1;
    return memcmp (a, b, la) == 0;
}

/* Split a loaded buffer into line views without trailing newlines. The loaded
   bytes remain owned by the caller until all views have been consumed.
   Returns NULL on error. *n_out gets line count. */
static bd_line *
bd_slurp (const unsigned char *data, size_t len, const char *path,
          int *n_out, int *no_newline)
{
    size_t cap = 256;
    bd_line *lines = malloc (cap * sizeof (*lines));
    if (!lines) {
        builtin_error ("%s: out of memory", path);
        *n_out = 0; *no_newline = 0;
        return NULL;
    }
    int n = 0;
    int last_had_nl = 0;
    size_t i = 0;
    while (i < len) {
        if (n == INT_MAX) {
            builtin_error ("%s: too many lines", path);
            goto fail;
        }
        size_t start = i;
        const unsigned char *end = memchr (data + i, '\n', len - i);
        i = end ? (size_t) (end - data) : len;
        int had_nl = (i < len && data[i] == '\n');
        size_t llen = i - start;
        if ((size_t) n >= cap) {
            if (cap > SIZE_MAX / 2 / sizeof (*lines)) {
                builtin_error ("%s: too many lines", path);
                goto fail;
            }
            bd_line *grown = realloc (lines, cap * 2 * sizeof (*lines));
            if (!grown) {
                builtin_error ("%s: out of memory", path);
                free (lines);
                *n_out = 0; *no_newline = 0;
                return NULL;
            }
            lines = grown; cap *= 2;
        }
        lines[n++] = (bd_line) { data + start, llen };
        last_had_nl = had_nl;
        if (had_nl) i++;
    }
    *n_out = n;
    *no_newline = (n > 0 && !last_had_nl);
    return lines;
fail:
    free (lines);
    *n_out = 0; *no_newline = 0;
    return NULL;
}

static int
bd_lineq (const bd_line *a, const bd_line *b, int icase)
{
    if (a->len != b->len) return 0;
    if (!icase) return memcmp (a->data, b->data, a->len) == 0;
    for (size_t i = 0; i < a->len; i++)
        if (tolower (a->data[i]) != tolower (b->data[i])) return 0;
    return 1;
}

static void
bd_text (bl_output *out, const char *text)
{
    bl_output_write (out, text, strlen (text));
}

/* Only fixed internal formats and numeric addresses use this small buffer.
   Unbounded filenames and line contents go through length-bearing writes. */
static void
bd_format (bl_output *out, const char *format, ...)
{
    char buffer[128];
    va_list args;
    va_start (args, format);
    int n = vsnprintf (buffer, sizeof buffer, format, args);
    va_end (args);
    if (n < 0 || (size_t) n >= sizeof buffer) {
        if (!out->error) out->error = EOVERFLOW;
        return;
    }
    bl_output_write (out, buffer, (size_t) n);
}

static void
bd_print_line (bl_output *out, const char *prefix, const bd_line *line)
{
    bd_text (out, prefix);
    bl_output_write (out, line->data, line->len);
    bl_output_byte (out, '\n');
}

typedef enum { BDOP_EQ, BDOP_DEL, BDOP_INS } bd_optype;
typedef struct { bd_optype op; int la; int lb; } bd_op;

/* Myers O(ND) — build edit-script ops. Returns op array (heap), sets *n_ops.
   Only d+1 diagonals of parity d are reachable at depth d. Save those rather
   than 2*(n+m)+1 cells per row. This reduces sparse-edit storage and copying;
   it does not remove quadratic worst-case time or trace memory. */
static int
bd_trace_x (const int *row, int d, int k)
{
    return row[(k + d) / 2];
}
static bd_op *
bd_myers (bd_line *A, int n, bd_line *B, int m, int icase,
          int no_newline_a, int no_newline_b, int *n_ops_out)
{
    *n_ops_out = -1;
    /* Both the diagonal index arithmetic and allocation products must fit. */
    if (n > (INT_MAX - 1) / 2 - m) {
        builtin_error ("too many lines to compare");
        return NULL;
    }
    int max = n + m;
    if (max == 0) { *n_ops_out = 0; return NULL; }
    int v_size = 2 * max + 1;
    if ((size_t) v_size > SIZE_MAX / sizeof (int) ||
        (size_t) (max + 1) > SIZE_MAX / sizeof (int *) ||
        (size_t) max > SIZE_MAX / sizeof (bd_op)) {
        builtin_error ("too many lines to compare");
        return NULL;
    }
    /* With an empty operand the only script is known; no search or saved
       frontier is needed, regardless of the amount of output. */
    if (n == 0 || m == 0) {
        bd_op *only = malloc ((size_t) max * sizeof (*only));
        if (!only) {
            builtin_error ("out of memory comparing files");
            return NULL;
        }
        for (int i = 0; i < max; i++)
            only[i] = n ? (bd_op) { BDOP_DEL, i, -1 } :
                          (bd_op) { BDOP_INS, -1, i };
        *n_ops_out = max;
        return only;
    }
    int *v = calloc ((size_t) v_size, sizeof (int));
    int **trace = calloc ((size_t) (max + 1), sizeof (int *));
    int d_done = -1;
    int rows = 0;
    bd_op *ops = NULL;
    if (!v || !trace) goto nomem;

    for (int d = 0; d <= max; d++) {
        trace[d] = malloc ((size_t) (d + 1) * sizeof (int));
        if (!trace[d]) goto nomem;
        rows++;
        for (int k = -d; k <= d; k += 2) {
            int x;
            if (k == -d || (k != d && v[k - 1 + max] < v[k + 1 + max]))
                x = v[k + 1 + max];          /* insertion */
            else
                x = v[k - 1 + max] + 1;      /* deletion */
            int y = x - k;
            while (x < n && y < m && bd_lineq (&A[x], &B[y], icase) &&
                   (x == n - 1 && no_newline_a) == (y == m - 1 && no_newline_b)) {
                x++; y++;
            }
            v[k + max] = x;
            if (x >= n && y >= m) { d_done = d; break; }
        }
        for (int k = -d; k <= d; k += 2)
            trace[d][(k + d) / 2] = v[k + max];
        if (d_done >= 0) break;
    }
    free (v);
    v = NULL;

    /* Backtrack: produce ops in reverse, then reverse. */
    /* Every operation consumes at least one input line. */
    ops = malloc ((size_t) max * sizeof (bd_op));
    if (!ops) goto nomem;
    int n_ops = 0;
    int x = n, y = m;
    for (int d = d_done; d > 0; d--) {
        int *vd = trace[d - 1];
        int k = x - y;
        int prev_k;
        if (k == -d || (k != d && bd_trace_x (vd, d - 1, k - 1) <
                                             bd_trace_x (vd, d - 1, k + 1)))
            prev_k = k + 1;
        else
            prev_k = k - 1;
        int prev_x = bd_trace_x (vd, d - 1, prev_k);
        int prev_y = prev_x - prev_k;
        /* Snake before the move (matches). */
        while (x > prev_x && y > prev_y) {
            ops[n_ops++] = (bd_op){ BDOP_EQ, x - 1, y - 1 };
            x--; y--;
        }
        if (x == prev_x) {
            ops[n_ops++] = (bd_op){ BDOP_INS, -1, y - 1 };
            y--;
        } else {
            ops[n_ops++] = (bd_op){ BDOP_DEL, x - 1, -1 };
            x--;
        }
    }
    while (x > 0 && y > 0) {
        ops[n_ops++] = (bd_op){ BDOP_EQ, x - 1, y - 1 };
        x--; y--;
    }
    /* Trim leftover (shouldn't happen but be safe). */
    while (x > 0) { ops[n_ops++] = (bd_op){ BDOP_DEL, x - 1, -1 }; x--; }
    while (y > 0) { ops[n_ops++] = (bd_op){ BDOP_INS, -1, y - 1 }; y--; }

    /* Reverse ops to forward order. */
    for (int i = 0, j = n_ops - 1; i < j; i++, j--) {
        bd_op t = ops[i]; ops[i] = ops[j]; ops[j] = t;
    }

    /* Free trace. */
    for (int d = 0; d <= d_done; d++) free (trace[d]);
    free (trace);

    *n_ops_out = n_ops;
    return ops;
nomem:
    builtin_error ("out of memory comparing files");
    free (v);
    for (int d = 0; d < rows; d++) free (trace[d]);
    free (trace);
    free (ops);
    return NULL;
}

/* Emit POSIX ed-style diff. Group consecutive ins/del into change-blocks. */
static void
bd_emit_ed (bl_output *out, bd_line *A, int n, bd_line *B, int m, bd_op *ops, int n_ops,
            int no_newline_a, int no_newline_b)
{
    (void) n; (void) m;
    int i = 0;
    while (i < n_ops) {
        if (ops[i].op == BDOP_EQ) { i++; continue; }
        /* Start of a change block. Find run of DEL/INS. */
        int j = i;
        int del0 = -1, del1 = -1, ins0 = -1, ins1 = -1;
        while (j < n_ops && ops[j].op != BDOP_EQ) {
            if (ops[j].op == BDOP_DEL) {
                if (del0 < 0) del0 = ops[j].la;
                del1 = ops[j].la;
            } else { /* INS */
                if (ins0 < 0) ins0 = ops[j].lb;
                ins1 = ops[j].lb;
            }
            j++;
        }
        /* Format header: 1-indexed inclusive ranges. */
        char header[64];
        int nd = (del0 < 0) ? 0 : (del1 - del0 + 1);
        int ni = (ins0 < 0) ? 0 : (ins1 - ins0 + 1);
        if (nd > 0 && ni > 0) {
            /* change */
            if (nd == 1)
                snprintf (header, sizeof header, "%dc", del0 + 1);
            else
                snprintf (header, sizeof header, "%d,%dc", del0 + 1, del1 + 1);
            char tail[32];
            if (ni == 1)
                snprintf (tail, sizeof tail, "%d", ins0 + 1);
            else
                snprintf (tail, sizeof tail, "%d,%d", ins0 + 1, ins1 + 1);
            bd_format (out, "%s%s\n", header, tail);
            for (int k = del0; k <= del1; k++) bd_print_line (out, "< ", &A[k]);
            if (no_newline_a && del1 == n - 1) bd_format (out, "\\ No newline at end of file\n");
            bd_format (out, "---\n");
            for (int k = ins0; k <= ins1; k++) bd_print_line (out, "> ", &B[k]);
            if (no_newline_b && ins1 == m - 1) bd_format (out, "\\ No newline at end of file\n");
        } else if (nd > 0) {
            /* delete from A; ed addressing wants index AFTER which to delete */
            int after = i > 0 ? ops[i - 1].lb + 1 : 0;
            if (nd == 1)
                bd_format (out, "%dd%d\n", del0 + 1, after);
            else
                bd_format (out, "%d,%dd%d\n", del0 + 1, del1 + 1, after);
            for (int k = del0; k <= del1; k++) bd_print_line (out, "< ", &A[k]);
            if (no_newline_a && del1 == n - 1) bd_format (out, "\\ No newline at end of file\n");
        } else { /* INS only */
            int after = i > 0 ? ops[i - 1].la + 1 : 0;
            if (ni == 1)
                bd_format (out, "%da%d\n", after, ins0 + 1);
            else
                bd_format (out, "%da%d,%d\n", after, ins0 + 1, ins1 + 1);
            for (int k = ins0; k <= ins1; k++) bd_print_line (out, "> ", &B[k]);
            if (no_newline_b && ins1 == m - 1) bd_format (out, "\\ No newline at end of file\n");
        }
        i = j;
    }
}

/* Emit unified diff (-u). 3 lines context per hunk; fuse hunks within
   6 lines of each other. */
#define BD_CTX 3
static void
bd_emit_unified (bl_output *out, bd_line *A, int n, bd_line *B, int m, bd_op *ops, int n_ops,
                 const char *fname1, const char *fname2,
                 int no_newline_a, int no_newline_b)
{
    (void) m;
    if (n_ops == 0) return;
    /* Print file headers. */
    bd_text (out, "--- "); bd_text (out, fname1); bd_text (out, "\n");
    bd_text (out, "+++ "); bd_text (out, fname2); bd_text (out, "\n");

    /* Walk ops, group into hunks bounded by ≥ 2*BD_CTX equals. */
    int i = 0;
    while (i < n_ops) {
        /* Skip leading equals; remember last BD_CTX of them. */
        while (i < n_ops && ops[i].op == BDOP_EQ) i++;
        if (i >= n_ops) break;
        /* Backtrack BD_CTX equals for context. */
        int hunk_start = i;
        int back = 0;
        while (hunk_start > 0 && back < BD_CTX && ops[hunk_start - 1].op == BDOP_EQ) {
            hunk_start--; back++;
        }
        /* Forward: extend hunk through changes + at most 2*BD_CTX equals
           (which we then trim to BD_CTX). */
        int j = i;
        while (j < n_ops) {
            if (ops[j].op != BDOP_EQ) { j++; continue; }
            /* Count run of equals from j. */
            int e0 = j;
            while (j < n_ops && ops[j].op == BDOP_EQ) j++;
            int run = j - e0;
            if (j >= n_ops) {
                /* Trailing equals — keep up to BD_CTX. */
                if (run > BD_CTX) j = e0 + BD_CTX;
                break;
            }
            if (run > 2 * BD_CTX) {
                /* Big gap — split hunk here. Trim trailing context to BD_CTX. */
                j = e0 + BD_CTX;
                break;
            }
            /* Otherwise fuse: keep going. */
        }
        int hunk_end = j;
        /* Compute line ranges over [hunk_start, hunk_end). */
        int a_start = -1, a_count = 0;
        int b_start = -1, b_count = 0;
        for (int k = hunk_start; k < hunk_end; k++) {
            if (ops[k].op == BDOP_EQ || ops[k].op == BDOP_DEL) {
                if (a_start < 0) a_start = ops[k].la;
                a_count++;
            }
            if (ops[k].op == BDOP_EQ || ops[k].op == BDOP_INS) {
                if (b_start < 0) b_start = ops[k].lb;
                b_count++;
            }
        }
        if (a_start < 0) a_start = 0;
        if (b_start < 0) b_start = 0;
        bd_format (out, "@@ -%d", a_count ? a_start + 1 : a_start);
        if (a_count != 1) bd_format (out, ",%d", a_count);
        bd_format (out, " +%d", b_count ? b_start + 1 : b_start);
        if (b_count != 1) bd_format (out, ",%d", b_count);
        bd_format (out, " @@\n");
        for (int k = hunk_start; k < hunk_end; k++) {
            switch (ops[k].op) {
            case BDOP_EQ:
                bd_print_line (out, " ", &A[ops[k].la]);
                if (no_newline_a && ops[k].la == n - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            case BDOP_DEL:
                bd_print_line (out, "-", &A[ops[k].la]);
                if (no_newline_a && ops[k].la == n - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            case BDOP_INS:
                bd_print_line (out, "+", &B[ops[k].lb]);
                if (no_newline_b && ops[k].lb == m - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            }
        }
        (void) n;
        i = hunk_end;
    }
}

/* Side-by-side output (-y), laid out as GNU diff does: two half columns,
   a marker gutter in the middle, tabs used to reach each column. Character
   widths follow the C locale: printable ASCII is one column, other bytes
   take no column. */
typedef struct { long half, col2; } bd_sbs;

static long
bd_tab_to (bl_output *out, long from, long to)
{
    long col = from;
    for (long i = col - col % 8 + 8; i <= to; i += 8) {
        bl_output_byte (out, '\t');
        col = i;
    }
    for (; col < to; col++) bl_output_byte (out, ' ');
    return col;
}

static long
bd_half_line (bl_output *out, const bd_line *line, long indent, long bound)
{
    long in = 0, outpos = 0;
    for (size_t i = 0; i < line->len; i++) {
        unsigned char c = line->data[i];
        if (c == '\t') {
            long spaces = 8 - ((in + indent) % 8);
            if (in == outpos && outpos + spaces < bound) {
                outpos += spaces;
                bl_output_byte (out, c);
            }
            in += spaces;
        } else if (c == '\r') {
            bl_output_byte (out, c);
            bd_tab_to (out, 0, indent);
            in = outpos = 0;
        } else if (c == '\b') {
            if (in != 0 && --in < outpos) bl_output_byte (out, c);
        } else if (c >= 0x20 && c < 0x7f) {
            if (++in <= bound) { outpos = in; bl_output_byte (out, c); }
        } else if (c < 0x20 && c != '\f' && c != '\v') {
            if (in <= bound) { outpos = in; bl_output_byte (out, c); }
        } else if (in < bound) {
            bl_output_byte (out, c);
        }
    }
    return outpos;
}

static void
bd_sbs_line (bl_output *out, const bd_sbs *g, const bd_line *left, int left_nl,
             char sep, const bd_line *right, int right_nl)
{
    long col = 0;
    int newline = 0;
    if (left) {
        newline |= left_nl;
        col = bd_half_line (out, left, 0, g->half);
    }
    if (sep != ' ') {
        col = bd_tab_to (out, col, (g->half + g->col2 - 1) / 2) + 1;
        if (sep == '|' && newline != right_nl) sep = newline ? '/' : '\\';
        bl_output_byte (out, sep);
    }
    if (right) {
        newline |= right_nl;
        if (right->len) {
            col = bd_tab_to (out, col, g->col2);
            bd_half_line (out, right, col, g->half);
        }
    }
    if (newline) bl_output_byte (out, '\n');
}

static void
bd_emit_side_by_side (bl_output *out, bd_line *A, int n, bd_line *B, int m,
                      bd_op *ops, int n_ops, long width,
                      int no_newline_a, int no_newline_b)
{
    bd_sbs g;
    long off = (width + 8 + 3) / 16 * 8;
    g.half = off - 3 < width - off ? off - 3 : width - off;
    if (g.half < 0) g.half = 0;
    g.col2 = g.half ? off : width;
    int i = 0;
    while (i < n_ops) {
        if (ops[i].op == BDOP_EQ) {
            int la = ops[i].la, lb = ops[i].lb;
            bd_sbs_line (out, &g, &A[la], !(no_newline_a && la == n - 1), ' ',
                         &B[lb], !(no_newline_b && lb == m - 1));
            i++;
            continue;
        }
        int j = i, nd = 0, ni = 0;
        int dels[2] = { -1, -1 }, ins[2] = { -1, -1 };
        while (j < n_ops && ops[j].op != BDOP_EQ) {
            if (ops[j].op == BDOP_DEL) { if (dels[0] < 0) dels[0] = ops[j].la; dels[1] = ops[j].la; nd++; }
            else { if (ins[0] < 0) ins[0] = ops[j].lb; ins[1] = ops[j].lb; ni++; }
            j++;
        }
        for (int k = 0; k < nd || k < ni; k++) {
            const bd_line *l = k < nd ? &A[dels[0] + k] : NULL;
            const bd_line *r = k < ni ? &B[ins[0] + k] : NULL;
            int lnl = l && !(no_newline_a && dels[0] + k == n - 1);
            int rnl = r && !(no_newline_b && ins[0] + k == m - 1);
            bd_sbs_line (out, &g, l, lnl, l && r ? '|' : l ? '<' : '>', r, rnl);
        }
        i = j;
    }
}

static int
bd_finish_output (int status)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        clearerr (stdout);
        return 2;
    }
    return status;
}

/* Compare two non-directory operands. HEADER, when set, is the
   "diff -r A B" line printed before a textual difference. */
static int
bd_compare_files (const char *p0, const char *p1, const bd_opts *o, const char *header)
{
    /* GNU diff treats these as the same input without reading it. In
       particular, do not consume a pipe or wait for EOF before returning. */
    if (bd_is_stdin (p0) && bd_is_stdin (p1))
        return EXECUTION_SUCCESS;

    /* Load distinct operands once each; a single "-" borrows stdin. */
    unsigned char *da = NULL, *db = NULL;
    size_t la = 0, lb = 0;
    if (bd_load (p0, &da, &la) < 0)
        return 2;
    if (bd_load (p1, &db, &lb) < 0) {
        free (da);
        return 2;
    }

    /* Equal bytes imply equal lines for every supported comparison mode.
       Avoid indexing lines and building an edit trace when
       the complete inputs already establish that there is no difference. */
    if (!o->yflag && bd_files_equal (da, la, db, lb)) {
        free (da);
        free (db);
        return EXECUTION_SUCCESS;
    }

    /* Byte inequality fully answers a case-sensitive quiet comparison. */
    if (o->qflag && !o->iflag) {
        printf ("Files %s and %s differ\n", p0, p1);
        free (da);
        free (db);
        return bd_finish_output (1);
    }

    /* Binary detection: NUL in the first input block. Binary inputs are compared
       bytewise: identical files exit 0 silently; differing files report the
       standard binary-differ diagnostic and exit 1. */
    int bin_a = bd_probe_binary (da, la);
    int bin_b = bd_probe_binary (db, lb);
    if (bin_a == 1 || bin_b == 1) {
        int same = bd_files_equal (da, la, db, lb);
        int rc;
        if (same)
            rc = 0;
        else {
            if (o->qflag)
                printf ("Files %s and %s differ\n", p0, p1);
            else
                printf ("Binary files %s and %s differ\n", p0, p1);
            rc = 1;
        }
        free (da);
        free (db);
        return bd_finish_output (rc);
    }

    int n, m, no_newline_a = 0, no_newline_b = 0;
    bd_line *A = bd_slurp (da, la, p0, &n, &no_newline_a);
    if (!A) {
        free (da);
        free (db);
        return 2;
    }
    bd_line *B = bd_slurp (db, lb, p1, &m, &no_newline_b);
    if (!B) {
        free (A);
        free (da);
        free (db);
        return 2;
    }
    int n_ops;
    bd_op *ops = NULL;
    int rc = 2;
    if (o->qflag) {
        int equal = n == m && no_newline_a == no_newline_b;
        for (int i = 0; equal && i < n; i++)
            equal = bd_lineq (&A[i], &B[i], o->iflag);
        if (!equal) printf ("Files %s and %s differ\n", p0, p1);
        rc = bd_finish_output (equal ? 0 : 1);
        goto cleanup;
    }
    ops = bd_myers (A, n, B, m, o->iflag, no_newline_a, no_newline_b, &n_ops);
    if (n_ops < 0) goto cleanup;

    /* Detect "differ at all" by scanning for non-EQ. */
    int differ = 0;
    for (int i = 0; i < n_ops; i++) {
        if (ops[i].op != BDOP_EQ) { differ = 1; break; }
    }
    if (no_newline_a != no_newline_b)
        differ = 1;

    rc = differ ? 1 : 0;
    if ((differ || o->yflag) && !o->qflag) {
        bl_output out;
        bl_output_init (&out, stdout);
        if (header && (differ || o->yflag)) { bd_text (&out, header); bl_output_byte (&out, '\n'); }
        if (o->yflag) bd_emit_side_by_side (&out, A, n, B, m, ops, n_ops, o->width,
                                           no_newline_a, no_newline_b);
        else if (o->uflag) bd_emit_unified (&out, A, n, B, m, ops, n_ops, p0, p1,
                                     no_newline_a, no_newline_b);
        else         bd_emit_ed (&out, A, n, B, m, ops, n_ops, no_newline_a, no_newline_b);
        bl_output_flush (&out);
        if (out.error) {
            builtin_error ("write error: %s", strerror (out.error));
            clearerr (stdout);
            rc = 2;
        }
    } else if (differ && o->qflag) {
        printf ("Files %s and %s differ\n", p0, p1);
    }

    rc = bd_finish_output (rc);
cleanup:
    free (ops);
    free (A);
    free (B);
    free (da);
    free (db);
    return rc;
}

static char *
bd_join (const char *dir, const char *name)
{
    size_t dl = strlen (dir), nl = strlen (name);
    int slash = dl && dir[dl - 1] == '/' ? 0 : 1;
    char *path = malloc (dl + slash + nl + 1);
    if (!path) { builtin_error ("out of memory"); return NULL; }
    memcpy (path, dir, dl);
    if (slash) path[dl] = '/';
    memcpy (path + dl + slash, name, nl + 1);
    return path;
}

static const char *
bd_file_type (const struct stat *st)
{
    if (S_ISREG (st->st_mode)) return st->st_size ? "regular file" : "regular empty file";
    if (S_ISDIR (st->st_mode)) return "directory";
    if (S_ISLNK (st->st_mode)) return "symbolic link";
    if (S_ISFIFO (st->st_mode)) return "fifo";
    if (S_ISSOCK (st->st_mode)) return "socket";
    if (S_ISCHR (st->st_mode)) return "character special file";
    if (S_ISBLK (st->st_mode)) return "block special file";
    return "weird file";
}

static int
bd_name_cmp (const void *a, const void *b)
{
    return strcmp (*(char *const *) a, *(char *const *) b);
}

/* Sorted entry names of DIR, without "." and "..". */
static char **
bd_list_dir (const char *dir, size_t *count)
{
    DIR *d = opendir (dir);
    if (!d) { builtin_error ("%s: %s", dir, strerror (errno)); return NULL; }
    size_t n = 0, cap = 16;
    char **names = malloc (cap * sizeof *names);
    struct dirent *de;
    while (names && (errno = 0, de = readdir (d))) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        if (n == cap) {
            char **grown = realloc (names, (cap *= 2) * sizeof *names);
            if (!grown) { for (size_t i = 0; i < n; i++) free (names[i]); free (names); names = NULL; break; }
            names = grown;
        }
        if (!(names[n] = strdup (de->d_name))) { for (size_t i = 0; i < n; i++) free (names[i]); free (names); names = NULL; break; }
        n++;
    }
    if (names && errno) {
        builtin_error ("%s: %s", dir, strerror (errno));
        for (size_t i = 0; i < n; i++) free (names[i]);
        free (names);
        names = NULL;
    } else if (!names) builtin_error ("out of memory");
    closedir (d);
    if (names) qsort (names, n, sizeof *names, bd_name_cmp);
    *count = n;
    return names;
}

static int bd_compare_paths (const char *p0, const char *p1, const bd_opts *o, int top);

/* Two directories, as GNU diff does: entries in name order, "Only in"
   for one-sided names, recursion with -r, else "Common subdirectories". */
static int
bd_compare_dirs (const char *d0, const char *d1, const bd_opts *o)
{
    size_t n0 = 0, n1 = 0;
    char **a = bd_list_dir (d0, &n0);
    if (!a) return 2;
    char **b = bd_list_dir (d1, &n1);
    if (!b) { for (size_t i = 0; i < n0; i++) free (a[i]); free (a); return 2; }
    int rc = 0;
    size_t i = 0, j = 0;
    while (i < n0 || j < n1) {
        int c = i >= n0 ? 1 : j >= n1 ? -1 : strcmp (a[i], b[j]);
        int r;
        if (c) {
            const char *dir = c < 0 ? d0 : d1, *name = c < 0 ? a[i++] : b[j++];
            fflush (stdout);
            printf ("Only in %s: %s\n", dir, name);
            r = 1;
        } else {
            char *q0 = bd_join (d0, a[i]), *q1 = q0 ? bd_join (d1, b[j]) : NULL;
            r = q1 ? bd_compare_paths (q0, q1, o, 0) : 2;
            free (q0);
            free (q1);
            i++, j++;
        }
        if (r > rc) rc = r;
    }
    for (size_t k = 0; k < n0; k++) free (a[k]);
    for (size_t k = 0; k < n1; k++) free (b[k]);
    free (a);
    free (b);
    return rc;
}

static int
bd_compare_paths (const char *p0, const char *p1, const bd_opts *o, int top)
{
    struct stat s0, s1;
    int d0 = 0, d1 = 0;
    if (!bd_is_stdin (p0)) {
        if (stat (p0, &s0) < 0) { builtin_error ("%s: %s", p0, strerror (errno)); return 2; }
        d0 = S_ISDIR (s0.st_mode);
    }
    if (!bd_is_stdin (p1)) {
        if (stat (p1, &s1) < 0) { builtin_error ("%s: %s", p1, strerror (errno)); return 2; }
        d1 = S_ISDIR (s1.st_mode);
    }
    if (d0 && d1) {
        if (top == 1 || o->rflag) return bd_compare_dirs (p0, p1, o);
        fflush (stdout);
        printf ("Common subdirectories: %s and %s\n", p0, p1);
        return bd_finish_output (0);
    }
    if (d0 != d1) {
        if (top != 1) {
            fflush (stdout);
            printf ("File %s is a %s while file %s is a %s\n", p0,
                    bd_file_type (&s0), p1, bd_file_type (&s1));
            return bd_finish_output (1);
        }
        /* DIR FILE compares DIR/basename(FILE) with FILE. */
        const char *file = d0 ? p1 : p0, *dir = d0 ? p0 : p1;
        if (bd_is_stdin (file)) { builtin_error ("cannot compare '-' to a directory"); return 2; }
        const char *base = strrchr (file, '/');
        base = base ? base + 1 : file;
        char *joined = bd_join (dir, base);
        if (!joined) return 2;
        /* Level 2: compared like a top-level pair, without a header. */
        int rc = d0 ? bd_compare_paths (joined, p1, o, 2) : bd_compare_paths (p0, joined, o, 2);
        free (joined);
        return rc;
    }
    if (top) return bd_compare_files (p0, p1, o, NULL);
    size_t len = strlen (o->switches) + strlen (p0) + strlen (p1) + 8;
    char *header = malloc (len);
    if (!header) { builtin_error ("out of memory"); return 2; }
    snprintf (header, len, "diff%s %s %s", o->switches, p0, p1);
    fflush (stdout);
    int rc = bd_compare_files (p0, p1, o, header);
    free (header);
    return rc;
}

int
diff_builtin (WORD_LIST *list)
{
    bd_opts o = {0};
    const char *paths[2] = { NULL, NULL };
    int npos = 0;
    size_t sw_len = 0;
    o.width = 130;
    /* Option words as given, for the "diff OPTIONS A B" lines of -r. */
    for (WORD_LIST *p = list; p; p = p->next)
        sw_len += strlen (p->word->word) + 1;
    char *switches = malloc (sw_len + 1);
    if (!switches) { builtin_error ("out of memory"); return 2; }
    switches[0] = '\0';
#define BD_USAGE_FAIL do { free (switches); builtin_usage (); return EX_USAGE; } while (0)
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) { free (switches); builtin_usage (); return EXECUTION_SUCCESS; }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-v") == 0) {
            free (switches);
            puts ("bashdiff 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (npos < 2) paths[npos++] = p->word->word;
                else {
                    builtin_error ("extra operand: %s", p->word->word);
                    BD_USAGE_FAIL;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] == '-') {
            const char *width = NULL;
            if (!strcmp (w, "--side-by-side")) o.yflag = 1;
            else if (!strcmp (w, "--recursive")) o.rflag = 1;
            else if (!strcmp (w, "--unified")) o.uflag = 1;
            else if (!strcmp (w, "--brief")) o.qflag = 1;
            else if (!strcmp (w, "--ignore-case")) o.iflag = 1;
            else if (!strncmp (w, "--width=", 8)) width = w + 8;
            else {
                builtin_error ("unknown option: %s", w);
                BD_USAGE_FAIL;
            }
            strcat (switches, " ");
            strcat (switches, w);
            if (width) {
                char *end;
                errno = 0;
                long v = strtol (width, &end, 10);
                if (errno || end == width || *end || v <= 0) {
                    builtin_error ("invalid width '%s'", width);
                    BD_USAGE_FAIL;
                }
                o.width = v;
            }
            continue;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            strcat (switches, " ");
            strcat (switches, w);
            for (int i = 1; w[i]; i++) {
                if (w[i] == 'W') {
                    /* -W NUM: the rest of the word, or the next word. */
                    const char *width = w[i + 1] ? &w[i + 1] : NULL;
                    if (!width) {
                        if (!p->next) {
                            builtin_error ("option requires an argument -- 'W'");
                            BD_USAGE_FAIL;
                        }
                        p = p->next;
                        width = p->word->word;
                        strcat (switches, " ");
                        strcat (switches, width);
                    }
                    char *end;
                    errno = 0;
                    long v = strtol (width, &end, 10);
                    if (errno || end == width || *end || v <= 0) {
                        builtin_error ("invalid width '%s'", width);
                        BD_USAGE_FAIL;
                    }
                    o.width = v;
                    break;
                }
                switch (w[i]) {
                case 'u': o.uflag = 1; break;
                case 'q': o.qflag = 1; break;
                case 'i': o.iflag = 1; break;
                case 'y': o.yflag = 1; break;
                case 'r': o.rflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    BD_USAGE_FAIL;
                }
            }
        } else {
            if (npos < 2) paths[npos++] = w;
            else {
                builtin_error ("extra operand: %s", w);
                BD_USAGE_FAIL;
            }
        }
    }
    if (npos != 2) BD_USAGE_FAIL;
#undef BD_USAGE_FAIL
    if (o.yflag && o.uflag) {
        free (switches);
        builtin_error ("conflicting output style options");
        builtin_usage ();
        return EX_USAGE;
    }
    o.switches = switches;
    int rc = bd_compare_paths (paths[0], paths[1], &o, 1);
    free (switches);
    return bd_finish_output (rc);
}

char *diff_doc[] = {
    "Compare two files line by line (Myers O(ND)).",
    "",
    "    bashdiff [-u|-y [-W NUM]] [-q] [-i] [-r] [--help|--version] FILE1 FILE2",
    "",
    "    -u   unified diff (3 lines context per hunk)",
    "    -y   side-by-side output; -W NUM sets the width (default 130)",
    "    -r   compare directories recursively",
    "    -q   only report whether files differ",
    "    -i   ignore case",
    "    -v, --version  show version",
    "    --help         show this help",
    "",
    "Exit 0 (same), 1 (differ), 2 (error). Default output is POSIX",
    "ed-script style: 1c2 / 1a1 / 2d3 with < and > markers.",
    (char *)NULL
};

struct builtin bashdiff_struct = {
    "bashdiff",
    diff_builtin,
    BUILTIN_ENABLED,
    diff_doc,
    "bashdiff [-uqiyr] [-W NUM] [--help|--version] FILE1 FILE2",
    0
};
