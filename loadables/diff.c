/* bashdiff.c — POSIX diff(1) as a bash builtin (Myers O(ND)).
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdiff [OPTION]... FILE1 FILE2
 *
 *   -u, -U N   unified diff, N lines of context (default 3)
 *   -c, -C N   context diff, N lines of context (default 3)
 *   -y         side-by-side, laid out as GNU diff (-W NUM width, default 130)
 *   -q / -s    report only that files differ / also that they are identical
 *   -r, -N     recursive directory comparison, with GNU's "Only in" lines;
 *              -N compares an absent file as empty (diff -ruN a b)
 *   -x / -X    exclude directory entries by pattern / patterns from a file
 *   -i -b -w -Z -B -I RE   GNU's case, white space and blank-line options
 *   -p, -F RE  show the enclosing function line in hunk headers
 *   -e         an ed script, last change first ("." lines escaped as GNU does)
 *   -t, --tabsize N  expand tabs in output; --suppress-common-lines (-y);
 *   --strip-trailing-cr; --color[=WHEN] and --palette with GNU's default
 *              colours (rs=0:hd=1:ad=32:de=31:ln=36)
 *
 * Default output is POSIX ed-style: 1c2 / 1a1 / 2d3 with `< old`,
 * `---`, `> new` markers. Unified and context output follow GNU diffutils
 * 3.10 byte for byte: headers with the file modification time, GNU's hunk
 * grouping and ranges, and GNU's shift_boundaries placement of changes.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Per POSIX.
 *
 * Algorithm: GNU diffutils' own — identical prefix and suffix skipped,
 * equivalence classes, discard_confusing_lines, gnulib's linear-space
 * compareseq (Myers O(ND) from both ends, with its TOO_EXPENSIVE cutoff)
 * and shift_boundaries — so the edit script is the one GNU diff prints.
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
#include <time.h>
#include <fnmatch.h>
#include <regex.h>
#include <locale.h>

#include "loadables.h"
#include "bl-output.h"

enum { BD_NORMAL, BD_UNIFIED, BD_CONTEXT, BD_SBS, BD_ED };
typedef struct {
    int style;               /* BD_NORMAL, -u/-U, -c/-C, -y, -e */
    int qflag, iflag, rflag, wflag, bflag, zflag;
    int nflag, sflag, blank, aflag, minimal;
    int suppress_common;     /* --suppress-common-lines */
    int strip_cr;            /* --strip-trailing-cr */
    long context;            /* -C/-U lines, -1 until set */
    const char *labels[2];
    long width;              /* -W: side-by-side output width */
    const char *switches;    /* option words as given, for -r headers */
    regex_t *ignore_re;      /* -I RE */
    regex_t *function_re;    /* -p, -F RE */
    char **excludes;         /* -x PAT, -X FILE */
    size_t nexcludes;
} bd_opts;
typedef struct { const unsigned char *data; size_t len; } bd_line;

/* Output settings of the running diff: -t, --tabsize and --color. The
   colour strings are SGR parameters, GNU's DIFF_COLORS defaults until
   --palette changes them. */
enum { BD_C_RS, BD_C_HD, BD_C_AD, BD_C_DE, BD_C_LN, BD_C_N };
static struct {
    int expand_tabs;
    long tabsize;
    int color;
    char *palette[BD_C_N];
} bd_out;
static const char *const bd_color_names[BD_C_N] = { "rs", "hd", "ad", "de", "ln" };
static const char *const bd_color_defaults[BD_C_N] = { "0", "1", "32", "31", "36" };

static int
bd_is_stdin (const char *path)
{
    return path && strcmp (path, "-") == 0;
}

/* Read PATH into a buffer. "-" uses the caller's stdin descriptor, which
   this loader never opens or closes. */
static int
bd_load (const char *path, unsigned char **data, size_t *len, struct timespec *mtime)
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
    if (mtime) {
        struct stat st;
        int rc = owned ? fstat (fd, &st) : clock_gettime (CLOCK_REALTIME, mtime);
        if (rc < 0) {
            builtin_error ("%s: %s", path, strerror (errno));
            if (owned) close (fd);
            return -1;
        }
        if (owned) *mtime = st.st_mtim;
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
          int *n_out, int *no_newline, int strip_cr)
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
        /* --strip-trailing-cr drops one CR before a newline. */
        if (strip_cr && had_nl && llen && data[i - 1] == '\r') llen--;
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

/* -b, -w and -Z also ignore a missing newline at the end of the file. */
static int
bd_ws_mode (const bd_opts *o)
{
    return o->wflag || o->bflag || o->zflag;
}

static int
bd_space (int c)
{
    return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r';
}

static int
bd_lineq (const bd_line *a, const bd_line *b, const bd_opts *o)
{
    if (o->bflag && !o->wflag) {
        /* -b: any run of white space equals any other; trailing white
           space is ignored, as with -Z. */
        size_t i = 0, j = 0;
        for (;;) {
            int sa = i < a->len && bd_space (a->data[i]);
            int sb = j < b->len && bd_space (b->data[j]);
            if (sa || sb) {
                size_t i2 = i, j2 = j;
                while (i2 < a->len && bd_space (a->data[i2])) i2++;
                while (j2 < b->len && bd_space (b->data[j2])) j2++;
                if (sa && sb) { i = i2; j = j2; continue; }
                if ((sa && i2 == a->len && j == b->len) || (sb && j2 == b->len && i == a->len)) return 1;
                return 0;
            }
            if (i == a->len || j == b->len) return i == a->len && j == b->len;
            int x = a->data[i++], y = b->data[j++];
            if ((o->iflag ? tolower (x) != tolower (y) : x != y)) return 0;
        }
    }
    if (o->zflag && !o->wflag) {
        size_t la = a->len, lb = b->len;
        while (la && bd_space (a->data[la - 1])) la--;
        while (lb && bd_space (b->data[lb - 1])) lb--;
        if (la != lb) return 0;
        if (!o->iflag) return memcmp (a->data, b->data, la) == 0;
        for (size_t i = 0; i < la; i++)
            if (tolower (a->data[i]) != tolower (b->data[i])) return 0;
        return 1;
    }
    if (o->wflag) {
        size_t i = 0, j = 0;
        for (;;) {
            while (i < a->len && isspace (a->data[i])) i++;
            while (j < b->len && isspace (b->data[j])) j++;
            if (i == a->len || j == b->len) return i == a->len && j == b->len;
            int x = a->data[i++], y = b->data[j++];
            if ((o->iflag ? tolower (x) != tolower (y) : x != y)) return 0;
        }
    }
    if (a->len != b->len) return 0;
    if (!o->iflag) return memcmp (a->data, b->data, a->len) == 0;
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

/* A line's text; with -t, tabs become spaces as GNU's output_1_line
   expands them, counting columns from the start of the text. After a
   carriage return inside the line GNU writes the line's flag again: FLAG
   is the "< ", "> " or "! " of normal and context output, NULL for the
   one-character flags of unified output and for ed scripts. */
static void
bd_write_text (bl_output *out, const bd_line *line, const char *flag)
{
    if (!bd_out.expand_tabs) {
        bl_output_write (out, line->data, line->len);
        return;
    }
    long column = 0;
    for (size_t i = 0; i < line->len; i++) {
        unsigned char c = line->data[i];
        if (c == '\t') {
            long spaces = bd_out.tabsize - column % bd_out.tabsize;
            column += spaces;
            while (spaces--) bl_output_byte (out, ' ');
            continue;
        }
        if (c == '\r') {
            bl_output_byte (out, c);
            if (flag && i + 1 < line->len) bd_text (out, flag);
            column = 0;
            continue;
        }
        if (c == '\b') {
            if (!column) continue;
            column--;
        } else column += isprint (c) != 0;
        bl_output_byte (out, c);
    }
}

static void
bd_color (bl_output *out, int which)
{
    if (!bd_out.color) return;
    bd_text (out, "\033[");
    bd_text (out, bd_out.palette[which]);
    bl_output_byte (out, 'm');
}

static void
bd_print_line (bl_output *out, const char *prefix, const bd_line *line)
{
    bd_text (out, prefix);
    bd_write_text (out, line, strlen (prefix) == 2 ? prefix : NULL);
    bl_output_byte (out, '\n');
}

/* A line in colour WHICH (-1 for none); GNU resets before the newline. */
static void
bd_print_line_c (bl_output *out, const char *prefix, const bd_line *line, int which)
{
    if (which >= 0) bd_color (out, which);
    bd_text (out, prefix);
    bd_write_text (out, line, strlen (prefix) == 2 ? prefix : NULL);
    if (which >= 0) bd_color (out, BD_C_RS);
    bl_output_byte (out, '\n');
}

typedef enum { BDOP_EQ, BDOP_DEL, BDOP_INS } bd_optype;
typedef struct { bd_optype op; int la; int lb; } bd_op;

/* One change as GNU diff's build_script makes it: DEL lines of A from LINE0
   replaced by INS lines of B from LINE1. IGNORE marks a change that -B or
   -I would hide. */
typedef struct { int line0, del, line1, ins, ignore; } bd_change;

typedef struct {
    bd_line *A, *B;
    int n, m, nonl_a, nonl_b;
    char *scratch;           /* NUL-terminated copy of a line for regexec */
} bd_files;

/* Does RE match line L? The copy gives regexec a terminated string, and
   REG_STARTEND (where the C library has it; musl does not) keeps a NUL
   inside the line from ending the match early. Without it, a line with a
   NUL is matched piece by piece. */
static int
bd_re_match (regex_t *re, const bd_files *f, const bd_line *l)
{
    memcpy (f->scratch, l->data, l->len);
    f->scratch[l->len] = '\0';
#ifdef REG_STARTEND
    regmatch_t mt[1];
    mt[0].rm_so = 0;
    mt[0].rm_eo = (regoff_t) l->len;
    return regexec (re, f->scratch, 1, mt, REG_STARTEND) == 0;
#else
    for (size_t off = 0; off <= l->len; ) {
        if (regexec (re, f->scratch + off, 0, NULL, off ? REG_NOTBOL : 0) == 0)
            return 1;
        size_t piece = strlen (f->scratch + off);
        if (off + piece >= l->len) break;
        off += piece + 1;
    }
    return 0;
#endif
}

/* Equality of two lines of the same file, as GNU's equivalence classes. */
static int
bd_same (const bd_line *L, int len, int nonl, int x, int y, const bd_opts *o)
{
    if (!bd_lineq (&L[x], &L[y], o)) return 0;
    return bd_ws_mode (o) || (nonl && x == len - 1) == (nonl && y == len - 1);
}

/* GNU's shift_boundaries: slide each run of changed lines back to merge
   with an earlier run, then forward as far as it goes, and finally back to
   line up with a run in the other file. CHANGED and OTHER have a zero
   sentinel at index -1 and at their end. */
static void
bd_shift_boundaries (char *changed, const char *other, const bd_line *L,
                     int i_end, int nonl, const bd_opts *o)
{
    int i = 0, j = 0;
    for (;;) {
        int runlength, start, corresponding;
        while (i < i_end && !changed[i]) {
            while (other[j++])
                continue;
            i++;
        }
        if (i == i_end) break;
        start = i;
        while (changed[++i])
            continue;
        while (other[j])
            j++;
        do {
            runlength = i - start;
            while (start && bd_same (L, i_end, nonl, start - 1, i - 1, o)) {
                changed[--start] = 1;
                changed[--i] = 0;
                while (changed[start - 1])
                    start--;
                while (other[--j])
                    continue;
            }
            corresponding = other[j - 1] ? i : i_end;
            while (i != i_end && bd_same (L, i_end, nonl, start, i, o)) {
                changed[start++] = 0;
                changed[i++] = 1;
                while (changed[i])
                    i++;
                while (other[++j])
                    corresponding = i;
            }
        } while (runlength != i - start);
        while (corresponding < i) {
            changed[--start] = 1;
            changed[--i] = 0;
            while (other[--j])
                continue;
        }
    }
}

/* Is a deleted or inserted line one that -B or -I lets diff ignore? */
static int
bd_trivial (const bd_files *f, const bd_line *l, const bd_opts *o)
{
    if (o->blank) {
        size_t i = 0;
        if (bd_ws_mode (o))
            while (i < l->len && (bd_space (l->data[i]) || l->data[i] == '\n')) i++;
        if (i == l->len) return 1;
    }
    return o->ignore_re && bd_re_match (o->ignore_re, f, l);
}

/* Cross-file line equality: the comparison options, and a missing final
   newline unless -b, -w or -Z ignore it. */
static int
bd_eqline (const bd_files *f, int fx, int x, int fy, int y, const bd_opts *o)
{
    const bd_line *lx = fx ? &f->B[x] : &f->A[x], *ly = fy ? &f->B[y] : &f->A[y];
    if (!bd_lineq (lx, ly, o)) return 0;
    if (bd_ws_mode (o)) return 1;
    int nx = fx ? f->nonl_b && x == f->m - 1 : f->nonl_a && x == f->n - 1;
    int ny = fy ? f->nonl_b && y == f->m - 1 : f->nonl_a && y == f->n - 1;
    return nx == ny;
}

static unsigned long
bd_hash (const bd_line *l, const bd_opts *o)
{
    unsigned long h = 5381;
    size_t len = l->len;
    if (o->wflag) {
        for (size_t i = 0; i < len; i++)
            if (!isspace (l->data[i]))
                h = h * 33 + (unsigned) (o->iflag ? tolower (l->data[i]) : l->data[i]);
        return h;
    }
    if (o->bflag || o->zflag)
        while (len && bd_space (l->data[len - 1])) len--;
    for (size_t i = 0; i < len; i++) {
        int c = l->data[i];
        if (o->bflag && bd_space (c)) {
            while (i + 1 < len && bd_space (l->data[i + 1])) i++;
            c = ' ';
        }
        h = h * 33 + (unsigned) (o->iflag ? tolower (c) : c);
    }
    return h;
}

/* GNU's diffseq (gnulib): find the midpoint of the shortest edit script
   by searching from both ends, giving up for a "good enough" split once
   the cost passes TOO_EXPENSIVE. */
typedef struct {
    const long *xv, *yv;       /* equivalence classes of undiscarded lines */
    long *fd, *bd;             /* forward and backward diagonals */
    long too_expensive;
    char *c0, *c1;             /* changed flags, by real line */
    const long *ri0, *ri1;     /* undiscarded index -> real line */
} bd_seq;

typedef struct { long xmid, ymid; int lo_minimal, hi_minimal; } bd_part;

static void
bd_diag (long xoff, long xlim, long yoff, long ylim, int find_minimal, bd_part *part, bd_seq *c)
{
    long *const fd = c->fd, *const bd = c->bd;
    const long *xv = c->xv, *yv = c->yv;
    const long dmin = xoff - ylim, dmax = xlim - yoff;
    const long fmid = xoff - yoff, bmid = xlim - ylim;
    long fmin = fmid, fmax = fmid, bmin = bmid, bmax = bmid;
    int odd = (fmid - bmid) & 1;
    fd[fmid] = xoff;
    bd[bmid] = xlim;
    for (long cost = 1;; ++cost) {
        long d;
        if (fmin > dmin) fd[--fmin - 1] = -1; else ++fmin;
        if (fmax < dmax) fd[++fmax + 1] = -1; else --fmax;
        for (d = fmax; d >= fmin; d -= 2) {
            long x, y, tlo = fd[d - 1], thi = fd[d + 1];
            long x0 = tlo < thi ? thi : tlo + 1;
            for (x = x0, y = x0 - d; x < xlim && y < ylim && xv[x] == yv[y]; x++, y++)
                continue;
            fd[d] = x;
            if (odd && bmin <= d && d <= bmax && bd[d] <= x) {
                part->xmid = x; part->ymid = y;
                part->lo_minimal = part->hi_minimal = 1;
                return;
            }
        }
        if (bmin > dmin) bd[--bmin - 1] = LONG_MAX; else ++bmin;
        if (bmax < dmax) bd[++bmax + 1] = LONG_MAX; else --bmax;
        for (d = bmax; d >= bmin; d -= 2) {
            long x, y, tlo = bd[d - 1], thi = bd[d + 1];
            long x0 = tlo < thi ? tlo : thi - 1;
            for (x = x0, y = x0 - d; xoff < x && yoff < y && xv[x - 1] == yv[y - 1]; x--, y--)
                continue;
            bd[d] = x;
            if (!odd && fmin <= d && d <= fmax && x <= fd[d]) {
                part->xmid = x; part->ymid = y;
                part->lo_minimal = part->hi_minimal = 1;
                return;
            }
        }
        if (find_minimal) continue;
        if (cost >= c->too_expensive) {
            long fxybest = -1, fxbest = 0, bxybest = LONG_MAX, bxbest = 0;
            for (d = fmax; d >= fmin; d -= 2) {
                long x = fd[d] < xlim ? fd[d] : xlim, y = x - d;
                if (ylim < y) { x = ylim + d; y = ylim; }
                if (fxybest < x + y) { fxybest = x + y; fxbest = x; }
            }
            for (d = bmax; d >= bmin; d -= 2) {
                long x = xoff > bd[d] ? xoff : bd[d], y = x - d;
                if (y < yoff) { x = yoff + d; y = yoff; }
                if (x + y < bxybest) { bxybest = x + y; bxbest = x; }
            }
            if ((xlim + ylim) - bxybest < fxybest - (xoff + yoff)) {
                part->xmid = fxbest; part->ymid = fxybest - fxbest;
                part->lo_minimal = 1; part->hi_minimal = 0;
            } else {
                part->xmid = bxbest; part->ymid = bxybest - bxbest;
                part->lo_minimal = 0; part->hi_minimal = 1;
            }
            return;
        }
    }
}

static void
bd_compareseq (long xoff, long xlim, long yoff, long ylim, int find_minimal, bd_seq *c)
{
    const long *xv = c->xv, *yv = c->yv;
    while (xoff < xlim && yoff < ylim && xv[xoff] == yv[yoff]) xoff++, yoff++;
    while (xoff < xlim && yoff < ylim && xv[xlim - 1] == yv[ylim - 1]) xlim--, ylim--;
    if (xoff == xlim)
        while (yoff < ylim) c->c1[c->ri1[yoff++]] = 1;
    else if (yoff == ylim)
        while (xoff < xlim) c->c0[c->ri0[xoff++]] = 1;
    else {
        bd_part part;
        bd_diag (xoff, xlim, yoff, ylim, find_minimal, &part, c);
        bd_compareseq (xoff, part.xmid, yoff, part.ymid, part.lo_minimal, c);
        bd_compareseq (part.xmid, xlim, part.ymid, ylim, part.hi_minimal, c);
    }
}

/* GNU's discard_confusing_lines for one file: lines with no match in the
   other file are certainly changed (1); lines with very many matches are
   provisionally discardable (2) and stay only inside runs of the first. */
static void
bd_discards (char *discards, const long *eq, const long *other_count, long end)
{
    long many = 5, tem = end / 64;
    while ((tem = tem >> 2) > 0) many *= 2;
    for (long i = 0; i < end; i++) {
        long nmatch = other_count[eq[i]];
        if (nmatch == 0) discards[i] = 1;
        else if (nmatch > many) discards[i] = 2;
    }
    for (long i = 0; i < end; i++) {
        if (discards[i] == 2) discards[i] = 0;
        else if (discards[i] != 0) {
            long j, length, provisional = 0;
            for (j = i; j < end; j++) {
                if (discards[j] == 0) break;
                if (discards[j] == 2) ++provisional;
            }
            while (j > i && discards[j - 1] == 2) discards[--j] = 0, --provisional;
            length = j - i;
            if (provisional * 4 > length) {
                while (j > i)
                    if (discards[--j] == 2) discards[j] = 0;
            } else {
                long consec, minimum = 1, t = length >> 2;
                while (0 < (t >>= 2)) minimum <<= 1;
                minimum++;
                for (j = 0, consec = 0; j < length; j++)
                    if (discards[i + j] != 2) consec = 0;
                    else if (minimum == ++consec) j -= consec;
                    else if (minimum < consec) discards[i + j] = 0;
                for (j = 0, consec = 0; j < length; j++) {
                    if (j >= 8 && discards[i + j] == 1) break;
                    if (discards[i + j] == 2) consec = 0, discards[i + j] = 0;
                    else if (discards[i + j] == 0) consec = 0;
                    else consec++;
                    if (consec == 3) break;
                }
                i += length - 1;
                for (j = 0, consec = 0; j < length; j++) {
                    if (j >= 8 && discards[i - j] == 1) break;
                    if (discards[i - j] == 2) consec = 0, discards[i - j] = 0;
                    else if (discards[i - j] == 0) consec = 0;
                    else consec++;
                    if (consec == 3) break;
                }
            }
        }
    }
}

/* Mark changed lines as GNU diff's diff_2_files does: skip the identical
   prefix and suffix (keeping HORIZON lines of each, the context), put the
   rest in equivalence classes, discard confusing lines, run compareseq. */
static int
bd_mark_changes (const bd_files *f, const bd_opts *o, char *c0, char *c1)
{
    long horizon = o->context > 0 ? o->context : 0;
    long n = f->n, m = f->m, pre = 0, suf = 0;
    while (pre < n && pre < m && f->A[pre].len == f->B[pre].len &&
           !memcmp (f->A[pre].data, f->B[pre].data, f->A[pre].len) &&
           (f->nonl_a && pre == n - 1) == (f->nonl_b && pre == m - 1))
        pre++;
    pre = pre > horizon ? pre - horizon : 0;
    if (f->nonl_a == f->nonl_b) {
        while (suf < n - pre && suf < m - pre &&
               f->A[n - 1 - suf].len == f->B[m - 1 - suf].len &&
               !memcmp (f->A[n - 1 - suf].data, f->B[m - 1 - suf].data, f->A[n - 1 - suf].len))
            suf++;
        suf = suf > horizon ? suf - horizon : 0;
    }
    long len0 = n - pre - suf, len1 = m - pre - suf;
    int rc = -1;
    long *eq0 = malloc (((size_t) (len0 + len1) + 1) * sizeof *eq0);
    size_t tsize = 16;
    while (tsize < (size_t) (len0 + len1) * 2) tsize *= 2;
    long *table = malloc (tsize * sizeof *table);     /* -1 or file*2^.. index */
    long *count = NULL, *und = NULL;
    char *disc = NULL;
    long *fdiag = NULL;
    if (!eq0 || !table) goto out;
    long *eq1 = eq0 + len0;
    for (size_t k = 0; k < tsize; k++) table[k] = -1;
    long classes = 0;
    long *rep = malloc (((size_t) (len0 + len1) + 1) * sizeof *rep);  /* class -> line code */
    if (!rep) goto out;
    for (int fi = 0; fi < 2; fi++) {
        long len = fi ? len1 : len0;
        for (long i = 0; i < len; i++) {
            const bd_line *l = fi ? &f->B[pre + i] : &f->A[pre + i];
            size_t h = bd_hash (l, o) & (tsize - 1);
            for (;;) {
                if (table[h] < 0) {
                    rep[classes] = fi ? -(pre + i) - 1 : pre + i;
                    table[h] = classes++;
                    break;
                }
                long r = rep[table[h]];
                int rf = r < 0;
                long ri = rf ? -r - 1 : r;
                if (bd_eqline (f, rf, (int) ri, fi, (int) (pre + i), o)) break;
                h = (h + 1) & (tsize - 1);
            }
            (fi ? eq1 : eq0)[i] = table[h];
        }
    }
    free (rep);
    count = calloc ((size_t) classes * 2 + 1, sizeof *count);
    disc = calloc ((size_t) (len0 + len1) + 1, 1);
    und = malloc (((size_t) (len0 + len1) + 1) * 2 * sizeof *und);
    if (!count || !disc || !und) goto out;
    long *count0 = count, *count1 = count + classes;
    for (long i = 0; i < len0; i++) count0[eq0[i]]++;
    for (long i = 0; i < len1; i++) count1[eq1[i]]++;
    char *disc0 = disc, *disc1 = disc + len0;
    bd_discards (disc0, eq0, count1, len0);
    bd_discards (disc1, eq1, count0, len1);
    long *u0 = und, *u1 = und + len0, *r0 = und + len0 + len1, *r1 = r0 + len0;
    long nd0 = 0, nd1 = 0;
    if (o->minimal) memset (disc, 0, (size_t) (len0 + len1));
    for (long i = 0; i < len0; i++)
        if (disc0[i]) c0[pre + i] = 1;
        else { u0[nd0] = eq0[i]; r0[nd0++] = pre + i; }
    for (long i = 0; i < len1; i++)
        if (disc1[i]) c1[pre + i] = 1;
        else { u1[nd1] = eq1[i]; r1[nd1++] = pre + i; }
    long diags = nd0 + nd1 + 3;
    fdiag = malloc ((size_t) diags * 2 * sizeof *fdiag);
    if (!fdiag) goto out;
    bd_seq sq;
    sq.xv = u0; sq.yv = u1;
    sq.fd = fdiag + nd1 + 1;
    sq.bd = fdiag + diags + nd1 + 1;
    long te = 1;
    for (long dg = diags; dg != 0; dg >>= 2) te <<= 1;
    sq.too_expensive = te > 4096 ? te : 4096;
    sq.c0 = c0; sq.c1 = c1; sq.ri0 = r0; sq.ri1 = r1;
    bd_compareseq (0, nd0, 0, nd1, o->minimal, &sq);
    /* shift_boundaries works on the compared region only. */
    {
        bd_files sub = { f->A + pre, f->B + pre, (int) len0, (int) len1,
                         f->nonl_a && suf == 0, f->nonl_b && suf == 0, NULL };
        char save0 = c0[pre - 1], save1 = c1[pre - 1];
        char end0 = c0[pre + len0], end1 = c1[pre + len1];
        c0[pre - 1] = c1[pre - 1] = 0;
        c0[pre + len0] = c1[pre + len1] = 0;
        bd_shift_boundaries (c0 + pre, c1 + pre, sub.A, sub.n, sub.nonl_a, o);
        bd_shift_boundaries (c1 + pre, c0 + pre, sub.B, sub.m, sub.nonl_b, o);
        c0[pre - 1] = save0; c1[pre - 1] = save1;
        c0[pre + len0] = end0; c1[pre + len1] = end1;
    }
    rc = 0;
out:
    if (rc < 0) builtin_error ("out of memory comparing files");
    free (eq0);
    free (table);
    free (count);
    free (disc);
    free (und);
    free (fdiag);
    return rc;
}

/* Turn the changed flags into GNU's change list. OPS gets the edit
   script in canonical order (deletions before insertions in each change)
   for the side-by-side writer. Returns the count, or -1 on error. */
static int
bd_changes (const bd_files *f, const bd_opts *o, bd_change **out, bd_op **ops_out, int *n_ops)
{
    *out = NULL;
    *ops_out = NULL;
    *n_ops = 0;
    char *f0 = calloc ((size_t) f->n + 2, 1), *f1 = calloc ((size_t) f->m + 2, 1);
    bd_change *ch = malloc (((size_t) f->n + f->m + 1) * sizeof *ch);
    bd_op *ops = malloc (((size_t) f->n + f->m + 1) * sizeof *ops);
    if (!f0 || !f1 || !ch || !ops) {
        free (f0); free (f1); free (ch); free (ops);
        builtin_error ("out of memory comparing files");
        return -1;
    }
    char *c0 = f0 + 1, *c1 = f1 + 1;
    if (bd_mark_changes (f, o, c0, c1) < 0) {
        free (f0); free (f1); free (ch); free (ops);
        return -1;
    }
    int count = 0;
    int i0 = 0, i1 = 0, k = 0;
    while (i0 < f->n || i1 < f->m) {
        if (c0[i0] || c1[i1]) {
            int l0 = i0, l1 = i1;
            while (c0[i0]) ops[k++] = (bd_op) { BDOP_DEL, i0++, -1 };
            while (c1[i1]) ops[k++] = (bd_op) { BDOP_INS, -1, i1++ };
            bd_change c = { l0, i0 - l0, l1, i1 - l1, 0 };
            if (o->blank || o->ignore_re) {
                c.ignore = 1;
                for (int x = l0; c.ignore && x < i0; x++) c.ignore = bd_trivial (f, &f->A[x], o);
                for (int y = l1; c.ignore && y < i1; y++) c.ignore = bd_trivial (f, &f->B[y], o);
            }
            ch[count++] = c;
        }
        if (i0 < f->n && i1 < f->m) ops[k++] = (bd_op) { BDOP_EQ, i0, i1 };
        i0++, i1++;
    }
    free (f0);
    free (f1);
    *out = ch;
    *ops_out = ops;
    *n_ops = k;
    return count;
}

static void
bd_line_nl (bl_output *out, const char *prefix, const bd_line *line, int last_nonl)
{
    bd_print_line (out, prefix, line);
    if (last_nonl) bd_text (out, "\\ No newline at end of file\n");
}

static void
bd_line_nl_c (bl_output *out, const char *prefix, const bd_line *line, int last_nonl, int which)
{
    bd_print_line_c (out, prefix, line, which);
    if (last_nonl) bd_text (out, "\\ No newline at end of file\n");
}

/* Normal output, one ed-style command per change (GNU print_normal_hunk). */
static void
bd_emit_ed (bl_output *out, const bd_files *f, const bd_change *ch, int nch)
{
    for (int c = 0; c < nch; c++) {
        const bd_change *h = &ch[c];
        if (h->ignore) continue;
        int f0 = h->line0 + 1, l0 = h->line0 + h->del, f1 = h->line1 + 1, l1 = h->line1 + h->ins;
        bd_color (out, BD_C_LN);
        if (l0 > f0) bd_format (out, "%d,%d", f0, l0); else bd_format (out, "%d", l0);
        bl_output_byte (out, h->del && h->ins ? 'c' : h->del ? 'd' : 'a');
        if (l1 > f1) bd_format (out, "%d,%d", f1, l1); else bd_format (out, "%d", l1);
        bd_color (out, BD_C_RS);
        bl_output_byte (out, '\n');
        for (int k = h->line0; k < h->line0 + h->del; k++)
            bd_line_nl_c (out, "< ", &f->A[k], f->nonl_a && k == f->n - 1, BD_C_DE);
        if (h->del && h->ins) bd_text (out, "---\n");
        for (int k = h->line1; k < h->line1 + h->ins; k++)
            bd_line_nl_c (out, "> ", &f->B[k], f->nonl_b && k == f->m - 1, BD_C_AD);
    }
}

/* -e: an ed script (GNU print_ed_hunk), each change on its own and the
   last change first so that earlier line numbers stay valid. A line that
   is just "." would end the insertion, so it is written as "..", the
   insertion is ended and "s/.//" removes the extra dot. */
static void
bd_emit_ed_script (bl_output *out, const bd_files *f, const bd_change *ch, int nch)
{
    for (int c = nch - 1; c >= 0; c--) {
        const bd_change *h = &ch[c];
        if (h->ignore) continue;
        int f0 = h->line0 + 1, l0 = h->line0 + h->del;
        if (l0 > f0) bd_format (out, "%d,%d", f0, l0); else bd_format (out, "%d", l0);
        bl_output_byte (out, h->del && h->ins ? 'c' : h->del ? 'd' : 'a');
        bl_output_byte (out, '\n');
        if (!h->ins) continue;
        int insert_mode = 1;
        for (int k = h->line1; k < h->line1 + h->ins; k++) {
            const bd_line *l = &f->B[k];
            if (!insert_mode) { bd_text (out, "a\n"); insert_mode = 1; }
            if (l->len == 1 && l->data[0] == '.') {
                bd_text (out, "..\n.\ns/.//\n");
                insert_mode = 0;
            } else
                bd_print_line (out, "", l);
        }
        if (insert_mode) bd_text (out, ".\n");
    }
}

/* GNU unified and context headers C-quote an implicit filename when it
   contains whitespace, a quote, a backslash or a byte outside printable
   ASCII, and follow it with the modification time. */
static char *
bd_cquote (const char *name)
{
    int quote = 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (*p <= ' ' || *p >= 127 || *p == '"' || *p == '\\') quote = 1;
    char *d = malloc (strlen (name) * 4 + 3), *q = d;
    if (!d) return NULL;
    if (!quote) { strcpy (d, name); return d; }
    *q++ = '"';
    for (const unsigned char *p = (const unsigned char *) name; *p; p++) {
        const char *esc = *p ? strchr ("\a\b\t\n\v\f\r", *p) : NULL;
        if (esc) {
            *q++ = '\\';
            *q++ = "abtnvfr"[*p - '\a'];
        } else if (*p < ' ' || *p >= 127) q += sprintf (q, "\\%03o", (unsigned) *p);
        else {
            if (*p == '"' || *p == '\\') *q++ = '\\';
            *q++ = (char) *p;
        }
    }
    *q++ = '"';
    *q = '\0';
    return d;
}

/* The same quoting, written straight to OUT without an allocation. */
static void
bd_header_name (bl_output *out, const char *name)
{
    int quote = 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (*p <= ' ' || *p >= 127 || *p == '"' || *p == '\\') quote = 1;
    if (!quote) { bd_text (out, name); return; }
    bl_output_byte (out, '"');
    for (const unsigned char *p = (const unsigned char *) name; *p; p++) {
        const char *esc = strchr ("\a\b\t\n\v\f\r", *p);
        if (esc) {
            bl_output_byte (out, '\\');
            bl_output_byte (out, "abtnvfr"[*p - '\a']);
        } else if (*p < ' ' || *p >= 127) bd_format (out, "\\%03o", (unsigned) *p);
        else {
            if (*p == '"' || *p == '\\') bl_output_byte (out, '\\');
            bl_output_byte (out, *p);
        }
    }
    bl_output_byte (out, '"');
}

/* Context headers keep the traditional ctime layout in the C and POSIX
   locales, as GNU does when LC_TIME is not a "hard" locale; unified
   headers, and context headers elsewhere, use the ISO form. */
static void
bd_header (bl_output *out, const char *mark, const char *label, const char *name,
           const struct timespec *mtime, int context)
{
    bd_color (out, BD_C_HD);
    bd_text (out, mark);
    if (label) bd_text (out, label);
    else {
        bd_header_name (out, name);
        char date[64], zone[32];
        struct tm tm;
        const char *lc = setlocale (LC_TIME, NULL);
        int traditional = context && (!lc || !strcmp (lc, "C") || !strcmp (lc, "POSIX"));
        tzset ();
        if (!localtime_r (&mtime->tv_sec, &tm)) ;
        else if (traditional) {
            if (strftime (date, sizeof date, "%a %b %e %H:%M:%S %Y", &tm))
                bd_format (out, "\t%s", date);
        } else if (strftime (date, sizeof date, "%Y-%m-%d %H:%M:%S", &tm) &&
                   strftime (zone, sizeof zone, "%z", &tm))
            bd_format (out, "\t%s.%09ld %s", date, mtime->tv_nsec, zone);
    }
    bd_color (out, BD_C_RS);
    bl_output_byte (out, '\n');
}

/* GNU's find_function: the last line before LINE matching the -p/-F
   expression, searching back no further than the previous search. */
typedef struct { int last_search, last_match; } bd_fn;

static const bd_line *
bd_find_function (const bd_files *f, const bd_opts *o, bd_fn *st, int line)
{
    int last = st->last_search;
    st->last_search = line;
    for (int i = line - 1; i >= last; i--) {
        if (bd_re_match (o->function_re, f, &f->A[i])) {
            st->last_match = i;
            return &f->A[i];
        }
    }
    return st->last_match >= 0 ? &f->A[st->last_match] : NULL;
}

static void
bd_function_text (bl_output *out, const bd_line *l)
{
    size_t i = 0, j;
    bl_output_byte (out, ' ');
    while (i < l->len && isspace (l->data[i])) i++;
    for (j = i; j < i + 40 && j < l->len; j++)
        continue;
    while (j > i && isspace (l->data[j - 1])) j--;
    bl_output_write (out, l->data + i, j - i);
}

/* GNU's translated ranges. FIRST and LAST are 0-based; LAST < FIRST is an
   empty range after line FIRST. */
static void
bd_unified_range (bl_output *out, int first, int last)
{
    int a = first + 1, b = last + 1;
    if (b < a) bd_format (out, "%d,0", b);
    else if (b == a) bd_format (out, "%d", b);
    else bd_format (out, "%d,%d", a, b - a + 1);
}

static void
bd_context_range (bl_output *out, int first, int last)
{
    int a = first + 1, b = last + 1;
    if (b <= a) bd_format (out, "%d", b);
    else bd_format (out, "%d,%d", a, b);
}

/* Unified (-u, -U N) and context (-c, -C N) output. Changes closer than
   2N+1 lines share a hunk (N for an ignorable change, as GNU's
   find_hunk); a hunk made only of ignorable changes is not printed. */
static void
bd_emit_hunks (bl_output *out, const bd_files *f, const bd_change *ch, int nch,
               const bd_opts *o, const char *name0, const char *name1,
               const struct timespec *t0, const struct timespec *t1)
{
    long ctx = o->context < 0 ? 3 : o->context;
    int printed = 0;
    bd_fn fn = { 0, -1 };
    int c = 0;
    while (c < nch) {
        int s = c, e = c;
        while (e + 1 < nch) {
            long top0 = ch[e].line0 + ch[e].del;
            long thresh = ch[e + 1].ignore ? ctx : 2 * ctx + 1;
            if (ch[e + 1].line0 - top0 < thresh) e++;
            else break;
        }
        c = e + 1;
        int show = 0, old = 0, new = 0;
        for (int k = s; k <= e; k++) {
            if (!ch[k].ignore) show = 1;
            if (ch[k].del) old = 1;
            if (ch[k].ins) new = 1;
        }
        if (!show) continue;
        if (!printed) {
            int uni = o->style == BD_UNIFIED;
            bd_header (out, uni ? "--- " : "*** ", o->labels[0], name0, t0, !uni);
            bd_header (out, uni ? "+++ " : "--- ", o->labels[1], name1, t1, !uni);
            printed = 1;
        }
        long first0 = ch[s].line0 - ctx, first1 = ch[s].line1 - ctx;
        long last0 = ch[e].line0 + ch[e].del - 1, last1 = ch[e].line1 + ch[e].ins - 1;
        if (first0 < 0) first0 = 0;
        if (first1 < 0) first1 = 0;
        last0 = last0 < f->n - ctx ? last0 + ctx : f->n - 1;
        last1 = last1 < f->m - ctx ? last1 + ctx : f->m - 1;
        const bd_line *func = o->function_re ? bd_find_function (f, o, &fn, (int) first0) : NULL;
        if (o->style == BD_UNIFIED) {
            bd_color (out, BD_C_LN);
            bd_text (out, "@@ -");
            bd_unified_range (out, (int) first0, (int) last0);
            bd_text (out, " +");
            bd_unified_range (out, (int) first1, (int) last1);
            bd_text (out, " @@");
            bd_color (out, BD_C_RS);
            if (func) bd_function_text (out, func);
            bl_output_byte (out, '\n');
            long i = first0, j = first1;
            int next = s;
            while (i <= last0 || j <= last1) {
                if (next > e || i < ch[next].line0) {
                    if (i <= last0) bd_line_nl (out, " ", &f->A[i], f->nonl_a && i == f->n - 1);
                    i++, j++;
                } else {
                    for (int k = 0; k < ch[next].del; k++, i++)
                        bd_line_nl_c (out, "-", &f->A[i], f->nonl_a && i == f->n - 1, BD_C_DE);
                    for (int k = 0; k < ch[next].ins; k++, j++)
                        bd_line_nl_c (out, "+", &f->B[j], f->nonl_b && j == f->m - 1, BD_C_AD);
                    next++;
                }
            }
            continue;
        }
        bd_text (out, "***************");
        if (func) bd_function_text (out, func);
        bl_output_byte (out, '\n');
        bd_color (out, BD_C_LN);
        bd_text (out, "*** ");
        bd_context_range (out, (int) first0, (int) last0);
        bd_text (out, " ****");
        bd_color (out, BD_C_RS);
        bl_output_byte (out, '\n');
        if (old) {
            int next = s;
            for (long i = first0; i <= last0; i++) {
                while (next <= e && ch[next].line0 + ch[next].del <= i) next++;
                const char *prefix = "  ";
                if (next <= e && ch[next].line0 <= i) prefix = ch[next].ins ? "! " : "- ";
                bd_line_nl_c (out, prefix, &f->A[i], f->nonl_a && i == f->n - 1, BD_C_DE);
            }
        }
        bd_color (out, BD_C_LN);
        bd_text (out, "--- ");
        bd_context_range (out, (int) first1, (int) last1);
        bd_text (out, " ----");
        bd_color (out, BD_C_RS);
        bl_output_byte (out, '\n');
        if (new) {
            int next = s;
            for (long j = first1; j <= last1; j++) {
                while (next <= e && ch[next].line1 + ch[next].ins <= j) next++;
                const char *prefix = "  ";
                if (next <= e && ch[next].line1 <= j) prefix = ch[next].del ? "! " : "+ ";
                bd_line_nl_c (out, prefix, &f->B[j], f->nonl_b && j == f->m - 1, BD_C_AD);
            }
        }
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
    long col = from, ts = bd_out.tabsize;
    if (!bd_out.expand_tabs)
        for (long i = col - col % ts + ts; i <= to; i += ts) {
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
            long spaces = bd_out.tabsize - ((in + indent) % bd_out.tabsize);
            if (in == outpos && bd_out.expand_tabs) {
                long stop = outpos + spaces < bound ? outpos + spaces : bound;
                for (; outpos < stop; outpos++) bl_output_byte (out, ' ');
            } else if (in == outpos && outpos + spaces < bound) {
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
                      int no_newline_a, int no_newline_b, int suppress_common)
{
    bd_sbs g;
    /* GNU's column layout: tab stops of 1 with -t, else the tab size. */
    long t = bd_out.expand_tabs ? 1 : bd_out.tabsize;
    long off = (width + t + 3) / (2 * t) * t;
    g.half = off - 3 < width - off ? off - 3 : width - off;
    if (g.half < 0) g.half = 0;
    g.col2 = g.half ? off : width;
    int i = 0;
    while (i < n_ops) {
        if (ops[i].op == BDOP_EQ) {
            int la = ops[i].la, lb = ops[i].lb;
            if (!suppress_common)
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
        /* GNU colours each "<" or ">" line from its start to after its
           newline. */
        for (int k = 0; k < nd || k < ni; k++) {
            const bd_line *l = k < nd ? &A[dels[0] + k] : NULL;
            const bd_line *r = k < ni ? &B[ins[0] + k] : NULL;
            int lnl = l && !(no_newline_a && dels[0] + k == n - 1);
            int rnl = r && !(no_newline_b && ins[0] + k == m - 1);
            if (!(l && r)) bd_color (out, l ? BD_C_DE : BD_C_AD);
            bd_sbs_line (out, &g, l, lnl, l && r ? '|' : l ? '<' : '>', r, rnl);
            if (!(l && r)) bd_color (out, BD_C_RS);
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
   "diff -r A B" line printed before a textual difference. MISSING has bit
   0 or 1 set for an operand that does not exist and -N treats as empty. */
static int
bd_compare_files (const char *p0, const char *p1, const bd_opts *o, const char *header,
                  int missing)
{
    /* GNU diff treats these as the same input without reading it. In
       particular, do not consume a pipe or wait for EOF before returning. */
    if (bd_is_stdin (p0) && bd_is_stdin (p1)) {
        if (o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
        return bd_finish_output (EXECUTION_SUCCESS);
    }

    /* Load distinct operands once each; a single "-" borrows stdin. */
    unsigned char *da = NULL, *db = NULL;
    size_t la = 0, lb = 0;
    struct timespec t0 = { 0, 0 }, t1 = { 0, 0 };
    int stamps = o->style == BD_UNIFIED || o->style == BD_CONTEXT;
    if (missing & 1) da = calloc (1, 1);
    else if (bd_load (p0, &da, &la, stamps ? &t0 : NULL) < 0)
        return 2;
    if (missing & 2) db = calloc (1, 1);
    else if (bd_load (p1, &db, &lb, stamps ? &t1 : NULL) < 0) {
        free (da);
        return 2;
    }
    if (!da || !db) {
        builtin_error ("out of memory");
        free (da);
        free (db);
        return 2;
    }

    const char *name0 = o->labels[0] ? o->labels[0] : p0;
    const char *name1 = o->labels[1] ? o->labels[1] : p1;
    int ignoring = o->iflag || bd_ws_mode (o) || o->blank || o->ignore_re || o->strip_cr;
    /* Equal bytes imply equal lines for every supported comparison mode.
       Avoid indexing lines and building an edit trace when
       the complete inputs already establish that there is no difference. */
    if (o->style != BD_SBS && bd_files_equal (da, la, db, lb)) {
        free (da);
        free (db);
        if (o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
        return bd_finish_output (EXECUTION_SUCCESS);
    }

    /* Byte inequality fully answers a quiet comparison without -i, -b,
       -w, -Z, -B or -I. */
    if (o->qflag && !ignoring) {
        printf ("Files %s and %s differ\n", name0, name1);
        free (da);
        free (db);
        return bd_finish_output (1);
    }

    /* Binary detection: NUL in the first input block, unless -a. Binary
       inputs are compared bytewise: identical files exit 0 silently;
       differing files report the standard binary-differ diagnostic and
       exit 1. */
    if (!o->aflag && (bd_probe_binary (da, la) || bd_probe_binary (db, lb))) {
        int same = bd_files_equal (da, la, db, lb);
        int rc;
        if (same) {
            rc = 0;
            if (o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
        } else {
            if (o->qflag)
                printf ("Files %s and %s differ\n", name0, name1);
            else
                printf ("Binary files %s and %s differ\n", name0, name1);
            rc = 1;
        }
        free (da);
        free (db);
        return bd_finish_output (rc);
    }

    bd_files f = { NULL, NULL, 0, 0, 0, 0, NULL };
    f.A = bd_slurp (da, la, p0, &f.n, &f.nonl_a, o->strip_cr);
    if (!f.A) {
        free (da);
        free (db);
        return 2;
    }
    f.B = bd_slurp (db, lb, p1, &f.m, &f.nonl_b, o->strip_cr);
    if (!f.B) {
        free (f.A);
        free (da);
        free (db);
        return 2;
    }
    int n_ops, nch = 0;
    bd_op *ops = NULL;
    bd_change *ch = NULL;
    int rc = 2;
    /* An ed script cannot express a missing newline: GNU compares such a
       last line as complete, says so for each file and exits 2. */
    int incomplete = 0;
    if (o->style == BD_ED) {
        if (f.nonl_a) { builtin_error ("%s: No newline at end of file\n", p0); incomplete = 1; }
        if (f.nonl_b) { builtin_error ("%s: No newline at end of file\n", p1); incomplete = 1; }
        f.nonl_a = f.nonl_b = 0;
    }
    if (o->ignore_re || o->function_re) {
        size_t longest = 0;
        for (int i = 0; i < f.n; i++) if (f.A[i].len > longest) longest = f.A[i].len;
        for (int i = 0; i < f.m; i++) if (f.B[i].len > longest) longest = f.B[i].len;
        f.scratch = malloc (longest + 1);
        if (!f.scratch) { builtin_error ("out of memory comparing files"); goto cleanup; }
    }
    if (o->qflag && !o->blank && !o->ignore_re) {
        int equal = f.n == f.m && (bd_ws_mode (o) || f.nonl_a == f.nonl_b);
        for (int i = 0; equal && i < f.n; i++)
            equal = bd_lineq (&f.A[i], &f.B[i], o) &&
                    (bd_ws_mode (o) || i < f.n - 1 || f.nonl_a == f.nonl_b);
        if (!equal) printf ("Files %s and %s differ\n", name0, name1);
        else if (o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
        rc = bd_finish_output (equal ? 0 : 1);
        goto cleanup;
    }
    nch = bd_changes (&f, o, &ch, &ops, &n_ops);
    if (nch < 0) goto cleanup;

    /* Only changes that -B and -I do not hide count as a difference. */
    int differ = 0;
    for (int i = 0; i < nch; i++)
        if (!ch[i].ignore) { differ = 1; break; }

    rc = differ ? 1 : 0;
    if (differ && o->qflag) {
        printf ("Files %s and %s differ\n", name0, name1);
    } else if (differ || o->style == BD_SBS) {
        bl_output out;
        bl_output_init (&out, stdout);
        if (header) { bd_text (&out, header); bl_output_byte (&out, '\n'); }
        if (o->style == BD_SBS)
            bd_emit_side_by_side (&out, f.A, f.n, f.B, f.m, ops, n_ops, o->width,
                                  f.nonl_a, f.nonl_b, o->suppress_common);
        else if (o->style == BD_NORMAL)
            bd_emit_ed (&out, &f, ch, nch);
        else if (o->style == BD_ED)
            bd_emit_ed_script (&out, &f, ch, nch);
        else
            bd_emit_hunks (&out, &f, ch, nch, o, p0, p1, &t0, &t1);
        bl_output_flush (&out);
        if (out.error) {
            builtin_error ("write error: %s", strerror (out.error));
            clearerr (stdout);
            rc = 2;
        }
    }
    if (rc == 0 && o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
    if (incomplete) rc = 2;

    rc = bd_finish_output (rc);
cleanup:
    free (f.scratch);
    free (ch);
    free (ops);
    free (f.A);
    free (f.B);
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

static int
bd_excluded (const bd_opts *o, const char *name)
{
    for (size_t i = 0; i < o->nexcludes; i++)
        if (fnmatch (o->excludes[i], name, 0) == 0) return 1;
    return 0;
}

/* Sorted entry names of DIR, without ".", ".." and -x/-X exclusions. */
static char **
bd_list_dir (const char *dir, size_t *count, const bd_opts *o)
{
    DIR *d = opendir (dir);
    if (!d) { builtin_error ("%s: %s", dir, strerror (errno)); return NULL; }
    size_t n = 0, cap = 16;
    char **names = malloc (cap * sizeof *names);
    struct dirent *de;
    while (names && (errno = 0, de = readdir (d))) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        if (bd_excluded (o, de->d_name)) continue;
        if (n == cap) {
            char **grown = realloc (names, (cap *= 2) * sizeof *names);
            if (!grown) { for (size_t i = 0; i < n; i++) free (names[i]); free (names); names = NULL; break; }
            names = grown;
        }
        size_t len = strlen (de->d_name) + 1;
        if ((names[n] = malloc (len))) memcpy (names[n], de->d_name, len);
        if (!names[n]) { for (size_t i = 0; i < n; i++) free (names[i]); free (names); names = NULL; break; }
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
   for one-sided names (compared with an empty file under -N), recursion
   with -r, else "Common subdirectories". MISSING marks a side that does
   not exist and -N treats as an empty directory. */
static int
bd_compare_dirs (const char *d0, const char *d1, const bd_opts *o, int missing)
{
    size_t n0 = 0, n1 = 0;
    char **a = (missing & 1) ? calloc (1, sizeof *a) : bd_list_dir (d0, &n0, o);
    if (!a) return 2;
    char **b = (missing & 2) ? calloc (1, sizeof *b) : bd_list_dir (d1, &n1, o);
    if (!b) { for (size_t i = 0; i < n0; i++) free (a[i]); free (a); return 2; }
    int rc = 0;
    size_t i = 0, j = 0;
    while (i < n0 || j < n1) {
        int c = i >= n0 ? 1 : j >= n1 ? -1 : strcmp (a[i], b[j]);
        int r;
        if (c && !o->nflag) {
            const char *dir = c < 0 ? d0 : d1, *name = c < 0 ? a[i++] : b[j++];
            fflush (stdout);
            printf ("Only in %s: %s\n", dir, name);
            r = 1;
        } else {
            const char *name = c <= 0 ? a[i] : b[j];
            char *q0 = bd_join (d0, name), *q1 = q0 ? bd_join (d1, name) : NULL;
            r = q1 ? bd_compare_paths (q0, q1, o, 0) : 2;
            free (q0);
            free (q1);
            if (c <= 0) i++;
            if (c >= 0) j++;
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
    int d0 = 0, d1 = 0, missing = 0;
    if (!bd_is_stdin (p0)) {
        if (stat (p0, &s0) < 0) {
            if (errno != ENOENT || !o->nflag) { builtin_error ("%s: %s", p0, strerror (errno)); return 2; }
            missing |= 1;
        } else d0 = S_ISDIR (s0.st_mode);
    }
    if (!bd_is_stdin (p1)) {
        if (stat (p1, &s1) < 0) {
            if (errno != ENOENT || !o->nflag || missing) { builtin_error ("%s: %s", missing ? p0 : p1, strerror (ENOENT)); return 2; }
            missing |= 2;
        } else d1 = S_ISDIR (s1.st_mode);
    }
    /* -N: a missing operand is an empty file, or an empty directory when
       the other side is a directory. */
    if (missing & 1) d0 = d1;
    if (missing & 2) d1 = d0;
    if (d0 && d1) {
        if (top == 1 || o->rflag) return bd_compare_dirs (p0, p1, o, missing);
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
    if (top) return bd_compare_files (p0, p1, o, NULL, missing);
    /* GNU C-quotes the names on the "diff OPTIONS A B" line. */
    char *q0 = bd_cquote (p0), *q1 = q0 ? bd_cquote (p1) : NULL;
    size_t len = strlen (o->switches) + (q1 ? strlen (q0) + strlen (q1) : 0) + 8;
    char *header = q1 ? malloc (len) : NULL;
    if (!header) { free (q0); free (q1); builtin_error ("out of memory"); return 2; }
    snprintf (header, len, "diff%s %s %s", o->switches, q0, q1);
    free (q0);
    free (q1);
    fflush (stdout);
    int rc = bd_compare_files (p0, p1, o, header, missing);
    free (header);
    return rc;
}

/* Append WORD to the "diff OPTIONS" string quoted as GNU's quotearg shell
   style: bare when safe, "..." for a word whose only special character is
   a single quote, else '...' with each ' written as '\''. */
static void
bd_switch (char *switches, const char *word)
{
    char *q = switches + strlen (switches);
    int special = !*word || *word == '#' || *word == '~', squote = 0, compat = 1;
    for (const unsigned char *p = (const unsigned char *) word; *p; p++) {
        if (*p == '\'') squote = 1;
        else if (*p < ' ' || *p == 127 || strchr (" !\"$&()*;<=>?[\\^`|", *p)) {
            special = 1;
            if (*p != ' ') compat = 0;
        } else if (*p == '#' && p != (const unsigned char *) word) compat = 0;
    }
    *q++ = ' ';
    if (squote && compat) {
        q += sprintf (q, "\"%s\"", word);
        return;
    }
    if (!special && !squote) { strcpy (q, word); return; }
    *q++ = '\'';
    for (const char *p = word; *p; p++) {
        if (*p == '\'') { memcpy (q, "'\\''", 4); q += 4; }
        else *q++ = *p;
    }
    *q++ = '\'';
    *q = '\0';
}

/* Parse a -C/-U/--context=/--unified= length as GNU does. */
static int
bd_context_arg (const char *arg, long *out)
{
    char *end;
    errno = 0;
    long v = strtol (arg, &end, 10);
    if (end == arg || *end || v < 0) {
        builtin_error ("invalid context length '%s'", arg);
        return -1;
    }
    if (errno == ERANGE || v > INT_MAX / 4) v = INT_MAX / 4;
    *out = v;
    return 0;
}

typedef struct {
    bd_opts *o;
    int style_set;
    char *ignore_pat, *function_pat;
    size_t ecap;
} bd_parse;

static int
bd_style (bd_parse *ps, int style)
{
    if (ps->style_set && ps->o->style != style) {
        builtin_error ("conflicting output style options");
        return -1;
    }
    ps->style_set = 1;
    ps->o->style = style;
    return 0;
}

static int
bd_add_exclude (bd_parse *ps, const char *pat, size_t len)
{
    bd_opts *o = ps->o;
    if (o->nexcludes == ps->ecap) {
        size_t nc = ps->ecap ? ps->ecap * 2 : 8;
        char **g = realloc (o->excludes, nc * sizeof *g);
        if (!g) { builtin_error ("out of memory"); return -1; }
        o->excludes = g;
        ps->ecap = nc;
    }
    char *d = malloc (len + 1);
    if (!d) { builtin_error ("out of memory"); return -1; }
    memcpy (d, pat, len);
    d[len] = '\0';
    o->excludes[o->nexcludes++] = d;
    return 0;
}

static int
bd_exclude_from (bd_parse *ps, const char *file)
{
    unsigned char *data;
    size_t len;
    if (bd_load (file, &data, &len, NULL) < 0) return -1;
    size_t at = 0;
    while (at < len) {
        unsigned char *nl = memchr (data + at, '\n', len - at);
        size_t l = nl ? (size_t) (nl - data - at) : len - at;
        if (bd_add_exclude (ps, (const char *) data + at, l) < 0) { free (data); return -1; }
        at += l + 1;
    }
    free (data);
    return 0;
}

/* -I RE more than once matches any of them, as GNU joins them. */
static int
bd_add_pattern (char **pat, const char *re)
{
    size_t old = *pat ? strlen (*pat) : 0, add = strlen (re);
    char *g = realloc (*pat, old + add + 3);
    if (!g) { builtin_error ("out of memory"); return -1; }
    if (old) memcpy (g + old, "\\|", 2), old += 2;
    memcpy (g + old, re, add + 1);
    *pat = g;
    return 0;
}

static regex_t *
bd_compile (const char *pat)
{
    regex_t *re = malloc (sizeof *re);
    if (!re) { builtin_error ("out of memory"); return NULL; }
    int err = regcomp (re, pat, REG_NOSUB);
    if (err) {
        char msg[256];
        regerror (err, re, msg, sizeof msg);
        builtin_error ("%s", msg);
        free (re);
        return NULL;
    }
    return re;
}

/* Options that take an argument: the rest of the word or the next one. */
#define BD_SHORT_ARG "CUxXLWIF"

/* Apply one short option C with argument ARG (NULL when it takes none). */
static int
bd_short (bd_parse *ps, int c, const char *arg, int *nlabels)
{
    bd_opts *o = ps->o;
    long v;
    switch (c) {
    case 'a': o->aflag = 1; break;
    case 'b': o->bflag = 1; break;
    case 'B': o->blank = 1; break;
    case 'c':
        if (bd_style (ps, BD_CONTEXT) < 0) return -1;
        if (o->context < 3) o->context = 3;
        break;
    case 'u':
        if (bd_style (ps, BD_UNIFIED) < 0) return -1;
        if (o->context < 3) o->context = 3;
        break;
    case 'C': case 'U':
        if (bd_context_arg (arg, &v) < 0) return -1;
        if (bd_style (ps, c == 'U' ? BD_UNIFIED : BD_CONTEXT) < 0) return -1;
        if (o->context < v) o->context = v;
        break;
    case 'd': o->minimal = 1; break;
    case 'e': return bd_style (ps, BD_ED);
    case 't': bd_out.expand_tabs = 1; break;
    case 'i': o->iflag = 1; break;
    case 'I': return bd_add_pattern (&ps->ignore_pat, arg);
    case 'F': return bd_add_pattern (&ps->function_pat, arg);
    case 'p': return bd_add_pattern (&ps->function_pat, "^[[:alpha:]$_]");
    case 'N': o->nflag = 1; break;
    case 'q': o->qflag = 1; break;
    case 'r': o->rflag = 1; break;
    case 's': o->sflag = 1; break;
    case 'w': o->wflag = 1; break;
    case 'Z': o->zflag = 1; break;
    case 'y': return bd_style (ps, BD_SBS);
    case 'x': return bd_add_exclude (ps, arg, strlen (arg));
    case 'X': return bd_exclude_from (ps, arg);
    case 'L':
        if (*nlabels == 2) { builtin_error ("too many file label options"); return -1; }
        o->labels[(*nlabels)++] = arg;
        break;
    case 'W': {
        char *end;
        errno = 0;
        v = strtol (arg, &end, 10);
        if (errno || end == arg || *end || v <= 0) {
            builtin_error ("invalid width '%s'", arg);
            return -1;
        }
        o->width = v;
        break;
    }
    default:
        builtin_error ("invalid option -- '%c'", c);
        return -1;
    }
    return 0;
}

/* GNU long options: NAME, the short option it stands for, and whether
   its argument is required (1) or optional (2). */
static const struct { const char *name; int c, arg; } bd_long[] = {
    { "text", 'a', 0 }, { "ignore-space-change", 'b', 0 },
    { "ignore-blank-lines", 'B', 0 }, { "context", 'C', 2 },
    { "minimal", 'd', 0 }, { "ignore-case", 'i', 0 },
    { "ignore-matching-lines", 'I', 1 }, { "show-function-line", 'F', 1 },
    { "show-c-function", 'p', 0 }, { "new-file", 'N', 0 },
    { "brief", 'q', 0 }, { "recursive", 'r', 0 },
    { "report-identical-files", 's', 0 }, { "unified", 'U', 2 },
    { "ignore-all-space", 'w', 0 }, { "ignore-trailing-space", 'Z', 0 },
    { "side-by-side", 'y', 0 }, { "exclude", 'x', 1 },
    { "exclude-from", 'X', 1 }, { "label", 'L', 1 }, { "width", 'W', 1 },
    { "normal", 0, 0 }, { "speed-large-files", 1, 0 },
    { "horizon-lines", 2, 1 }, { "ed", 'e', 0 }, { "expand-tabs", 't', 0 },
    { "suppress-common-lines", 3, 0 }, { "strip-trailing-cr", 4, 0 },
    { "color", 5, 2 }, { "palette", 6, 1 }, { "tabsize", 7, 1 },
};

/* --palette: GNU's DIFF_COLORS syntax, KEY=SGR pairs split by ':' for
   rs, hd, ad, de and ln. A bad palette is reported and turns colour off. */
static void
bd_palette (const char *spec)
{
    const char *p = spec;
    int bad = 0;
    while (*p && !bad) {
        const char *end = strchr (p, ':');
        size_t len = end ? (size_t) (end - p) : strlen (p);
        const char *eq = memchr (p, '=', len);
        if (len) {
            int k = -1;
            if (eq)
                for (int i = 0; i < BD_C_N; i++)
                    if ((size_t) (eq - p) == strlen (bd_color_names[i]) && !strncmp (p, bd_color_names[i], (size_t) (eq - p)))
                        k = i;
            if (!eq) bad = 1;
            else if (k < 0) {
                builtin_error ("unrecognized prefix: %.*s", (int) (eq - p), p);
                bad = 1;
            } else {
                size_t vl = len - (size_t) (eq + 1 - p);
                char *v = malloc (vl + 1);
                if (!v) { bad = 1; break; }
                memcpy (v, eq + 1, vl);
                v[vl] = '\0';
                if (bd_out.palette[k] != bd_color_defaults[k]) free (bd_out.palette[k]);
                bd_out.palette[k] = v;
            }
        }
        if (!end) break;
        p = end + 1;
    }
    if (bad) {
        builtin_error ("unparsable value for --palette");
        bd_out.color = 0;
    }
}

static void
bd_palette_free (void)
{
    for (int i = 0; i < BD_C_N; i++) {
        if (bd_out.palette[i] != bd_color_defaults[i]) free (bd_out.palette[i]);
        bd_out.palette[i] = (char *) bd_color_defaults[i];
    }
}

int
diff_builtin (WORD_LIST *list)
{
    bd_opts o = {0};
    bd_parse ps = { &o, 0, NULL, NULL, 0 };
    const char *paths[2] = { NULL, NULL };
    int npos = 0;
    size_t sw_len = 0;
    int nlabels = 0;
    int rc = EX_USAGE;
    o.width = 130;
    o.context = -1;
    o.style = BD_NORMAL;
    const char *palette = NULL;
    bd_out.expand_tabs = 0;
    bd_out.tabsize = 8;
    bd_out.color = 0;
    for (int i = 0; i < BD_C_N; i++) bd_out.palette[i] = (char *) bd_color_defaults[i];
    /* Option words as given, for the "diff OPTIONS A B" lines of -r. */
    for (WORD_LIST *p = list; p; p = p->next)
        sw_len += 4 * strlen (p->word->word) + 4;
    char *switches = malloc (sw_len + 1);
    if (!switches) { builtin_error ("out of memory"); return 2; }
    switches[0] = '\0';
#define BD_SW(word) bd_switch (switches, (word))
#define BD_USAGE_FAIL do { builtin_usage (); rc = EX_USAGE; goto done; } while (0)
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) { builtin_usage (); rc = EXECUTION_SUCCESS; goto done; }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-v") == 0) {
            puts ("bashdiff 1.0 (bash-loadable)");
            rc = EXECUTION_SUCCESS;
            goto done;
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
            const char *eq = strchr (w + 2, '=');
            size_t nl = eq ? (size_t) (eq - w - 2) : strlen (w + 2);
            int found = -1, matches = 0;
            for (size_t k = 0; k < sizeof bd_long / sizeof bd_long[0]; k++) {
                if (strncmp (bd_long[k].name, w + 2, nl)) continue;
                if (!bd_long[k].name[nl]) { found = (int) k; matches = 1; break; }
                found = (int) k;
                matches++;
            }
            if (matches != 1) {
                builtin_error ("%s option '%s'", matches ? "ambiguous" : "unrecognized", w);
                BD_USAGE_FAIL;
            }
            BD_SW (w);
            const char *arg = eq ? eq + 1 : NULL;
            if (bd_long[found].arg == 0 && arg) {
                builtin_error ("option '--%s' doesn't allow an argument", bd_long[found].name);
                BD_USAGE_FAIL;
            }
            if (bd_long[found].arg == 1 && !arg) {
                if (!p->next) {
                    builtin_error ("option '--%s' requires an argument", bd_long[found].name);
                    BD_USAGE_FAIL;
                }
                p = p->next;
                arg = p->word->word;
                BD_SW (arg);
            }
            int c = bd_long[found].c;
            if (c == 0) { if (bd_style (&ps, BD_NORMAL) < 0) BD_USAGE_FAIL; continue; }
            if (c == 1 || c == 2) continue;      /* accepted, no effect here */
            if (c == 3) { o.suppress_common = 1; continue; }
            if (c == 4) { o.strip_cr = 1; continue; }
            if (c == 5) {
                /* --color alone is auto: a terminal that is not "dumb". */
                const char *term = getenv ("TERM");
                if (!arg || !strcmp (arg, "auto"))
                    bd_out.color = isatty (STDOUT_FILENO) && term && strcmp (term, "dumb");
                else if (!strcmp (arg, "always")) bd_out.color = 1;
                else if (!strcmp (arg, "never")) bd_out.color = 0;
                else { builtin_error ("invalid color '%s'", arg); BD_USAGE_FAIL; }
                continue;
            }
            if (c == 6) { palette = arg; continue; }
            if (c == 7) {
                char *end;
                errno = 0;
                long v = strtol (arg, &end, 10);
                if (errno || end == arg || *end || v <= 0) { builtin_error ("invalid tabsize '%s'", arg); BD_USAGE_FAIL; }
                bd_out.tabsize = v;
                continue;
            }
            if (bd_long[found].arg == 2 && !arg) arg = "3";
            if (bd_short (&ps, c, arg, &nlabels) < 0) BD_USAGE_FAIL;
            continue;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            BD_SW (w);
            for (int i = 1; w[i]; i++) {
                const char *arg = NULL;
                if (strchr (BD_SHORT_ARG, w[i])) {
                    /* The rest of the word, or the next word. */
                    arg = w[i + 1] ? &w[i + 1] : NULL;
                    if (!arg) {
                        if (!p->next) {
                            builtin_error ("option requires an argument -- '%c'", w[i]);
                            BD_USAGE_FAIL;
                        }
                        p = p->next;
                        arg = p->word->word;
                        BD_SW (arg);
                    }
                }
                if (bd_short (&ps, w[i], arg, &nlabels) < 0) BD_USAGE_FAIL;
                if (arg) break;
            }
        } else {
            if (npos < 2) paths[npos++] = w;
            else {
                builtin_error ("extra operand: %s", w);
                BD_USAGE_FAIL;
            }
        }
    }
    if (npos != 2) {
        if (npos) builtin_error ("missing operand after '%s'", paths[npos - 1]);
        BD_USAGE_FAIL;
    }
    if (ps.ignore_pat && !(o.ignore_re = bd_compile (ps.ignore_pat))) { rc = 2; goto done; }
    if (ps.function_pat && !(o.function_re = bd_compile (ps.function_pat))) { rc = 2; goto done; }
#undef BD_USAGE_FAIL
#undef BD_SW
    if (palette && bd_out.color) bd_palette (palette);
    o.switches = switches;
    rc = bd_finish_output (bd_compare_paths (paths[0], paths[1], &o, 1));
done:
    free (switches);
    free (ps.ignore_pat);
    free (ps.function_pat);
    if (o.ignore_re) { regfree (o.ignore_re); free (o.ignore_re); }
    if (o.function_re) { regfree (o.function_re); free (o.function_re); }
    for (size_t i = 0; i < o.nexcludes; i++) free (o.excludes[i]);
    free (o.excludes);
    bd_palette_free ();
    bd_out.color = 0;
    return rc;
}

char *diff_doc[] = {
    "Compare two files line by line (Myers O(ND)).",
    "",
    "    diff [OPTION]... FILE1 FILE2",
    "",
    "    -u, -U NUM, --unified[=NUM]  unified diff, NUM (default 3) lines of context",
    "    -c, -C NUM, --context[=NUM]  context diff, NUM (default 3) lines of context",
    "    --normal       normal (ed-style) diff, the default",
    "    -y, --side-by-side  side-by-side output; -W NUM, --width=NUM (default 130)",
    "    -q, --brief    only report whether files differ",
    "    -s, --report-identical-files  report when two files are the same",
    "    -r, --recursive  compare directories recursively",
    "    -N, --new-file   treat absent files as empty",
    "    -x PAT, --exclude=PAT       skip directory entries that match PAT",
    "    -X FILE, --exclude-from=FILE  skip entries matching a pattern in FILE",
    "    -i, --ignore-case            ignore case differences",
    "    -b, --ignore-space-change    ignore changes in the amount of white space",
    "    -w, --ignore-all-space       ignore all white space",
    "    -Z, --ignore-trailing-space  ignore white space at line end",
    "    -B, --ignore-blank-lines     ignore changes whose lines are all blank",
    "    -I RE, --ignore-matching-lines=RE  ignore changes whose lines all match RE",
    "    -p, --show-c-function        show which C function each change is in",
    "    -e, --ed       output an ed script",
    "    -t, --expand-tabs  expand tabs to spaces in output; --tabsize=NUM (default 8)",
    "    --suppress-common-lines  do not output common lines (with -y)",
    "    --strip-trailing-cr      strip trailing carriage return on input",
    "    --color[=WHEN]  colour the output; WHEN is never, always or auto (the",
    "                    default for --color); --palette=PALETTE as DIFF_COLORS",
    "                    (default rs=0:hd=1:ad=32:de=31:ln=36)",
    "    -F RE, --show-function-line=RE  show the last line before a hunk matching RE",
    "    -a, --text     treat all files as text",
    "    -L LABEL, --label LABEL  use LABEL instead of a file name and time (up to two)",
    "    -d, --minimal  try hard to find a smaller set of changes",
    "    -v, --version  show version",
    "    --help         show this help",
    "",
    "Exit 0 (same), 1 (differ), 2 (error). Unified and context headers carry",
    "each file's modification time as GNU diff prints it.",
    (char *)NULL
};

struct builtin bashdiff_struct = {
    "bashdiff",
    diff_builtin,
    BUILTIN_ENABLED,
    diff_doc,
    "bashdiff [-abBcdeiNpqrstuwyZ] [-C NUM|-U NUM] [-x PAT] [-X FILE] [-L LABEL] [-W NUM] FILE1 FILE2",
    0
};
