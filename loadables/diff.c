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
 *   -T         a tab after each line's flag (--initial-tab)
 *   -n         an RCS script (--rcs)
 *   -D NAME    the merged file with #ifdef NAME groups (--ifdef)
 *   --old-line-format, --new-line-format, --unchanged-line-format,
 *   --line-format, --old-group-format, --new-group-format,
 *   --unchanged-group-format, --changed-group-format: output laid out by
 *              the % directives of the GNU diff manual
 *   --from-file=FILE / --to-file=FILE  compare FILE with each operand
 *   --no-dereference  compare symbolic links themselves
 *   --left-column     -y: common lines once, in the left column
 *   -d, --minimal     no shortcuts in the line matching (may be slow)
 *   --horizon-lines=NUM  lines of the common ends kept in the comparison
 *
 * Default output is POSIX ed-style: 1c2 / 1a1 / 2d3 with `< old`,
 * `---`, `> new` markers. Unified and context output follow GNU diffutils
 * 3.10's layout: headers with the file modification time, its hunk
 * grouping and ranges.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Per POSIX.
 *
 * Algorithm: Myers' O(ND) difference algorithm in its linear-space form
 * (from the 1986 paper), with run placement after the GNU diff manual;
 * see "Line matching" below.
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

enum { BD_NORMAL, BD_UNIFIED, BD_CONTEXT, BD_SBS, BD_ED, BD_IFDEF, BD_RCS };
/* The formats of the line and group format options, and -D. */
enum { BD_F_OLD_LINE, BD_F_NEW_LINE, BD_F_UNCHANGED_LINE, BD_F_OLD_GROUP,
       BD_F_NEW_GROUP, BD_F_UNCHANGED_GROUP, BD_F_CHANGED_GROUP, BD_F_N };
typedef struct {
    int style;               /* BD_NORMAL, -u/-U, -c/-C, -y, -e */
    int qflag, iflag, rflag, wflag, bflag, zflag;
    int nflag, sflag, blank, aflag, minimal;
    int suppress_common;     /* --suppress-common-lines */
    int strip_cr;            /* --strip-trailing-cr */
    int no_deref;            /* --no-dereference */
    int left_column;         /* --left-column */
    char *formats[BD_F_N];   /* format options as given; NULL for the default */
    long context;            /* -C/-U lines, -1 until set */
    long horizon;            /* --horizon-lines */
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
    int initial_tab;         /* -T */
    long tabsize;
    int color;
    char *palette[BD_C_N];
} bd_out;
static const char *const bd_color_names[BD_C_N] = { "rs", "hd", "ad", "de", "ln" };
static const char *const bd_color_defaults[BD_C_N] = { "0", "1", "32", "31", "36" };
/* Set by a comparison that ends the whole run (-D with two directories). */
static int bd_fatal;

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

/* A line's flag. With -T the blank after a two-character flag becomes a
   tab, a one-character unified flag gets a tab after it, and the lone
   ' ' of an unchanged unified line is replaced by the tab. */
static void
bd_prefix (bl_output *out, const char *prefix)
{
    size_t len = strlen (prefix);
    if (!bd_out.initial_tab || !len) {
        bl_output_write (out, prefix, len);
        return;
    }
    if (len != 1 || prefix[0] != ' ') bl_output_byte (out, prefix[0]);
    bl_output_byte (out, '\t');
}

/* A line's text; with -t, tabs become spaces, counting columns from the
   start of the text. After a carriage return inside the line GNU writes
   the line's flag again: FLAG is the "< ", "> " or "! " of normal and
   context output, NULL for the one-character flags of unified output and
   for ed scripts. */
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
            if (flag && i + 1 < line->len) bd_prefix (out, flag);
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
    bd_prefix (out, prefix);
    bd_write_text (out, line, strlen (prefix) == 2 ? prefix : NULL);
    bl_output_byte (out, '\n');
}

/* A line in colour WHICH (-1 for none); GNU resets before the newline. */
static void
bd_print_line_c (bl_output *out, const char *prefix, const bd_line *line, int which)
{
    if (which >= 0) bd_color (out, which);
    bd_prefix (out, prefix);
    bd_write_text (out, line, strlen (prefix) == 2 ? prefix : NULL);
    if (which >= 0) bd_color (out, BD_C_RS);
    bl_output_byte (out, '\n');
}

/* ------------------------------------------------------------------
   Line matching and change placement.

   Written for bash-os from E. Myers, "An O(ND) Difference Algorithm and
   Its Variations" (Algorithmica 1, 1986), section 4b, and from the
   behaviour the GNU diff manual documents, checked by running GNU diff
   on sample inputs; no other diff program's source was used.

   1. Each line gets an equivalence class: two lines are equal when
      bd_lineq says so (it honours -i, -b, -w and -Z) and, without those
      white space options, an incomplete last line equals only another
      incomplete last line.
   2. The common prefix and suffix are matched as they stand (with
      --horizon-lines, or the context of -c and -u, some of their lines
      join the rest).
   3. Without -d, a line between them whose class does not occur between
      them in the other file can never be matched. Such lines are marked
      changed at once and left out of the search, which then runs on
      shorter sequences (two unrelated files take linear time) without
      changing the number of lines the script changes.
   4. The search is the paper's linear-space refinement: D-paths grow
      from both corners of the edit graph at once until a forward path
      meets a reverse one; the snake where they meet lies on an optimal
      path, so it is matched and the parts before and after it are
      solved the same way. Each part strips its own common ends first.
      Diagonals are scanned from the highest (most deletions) down, so
      the first meeting found decides between equally short scripts.
      Without -d, a part whose cost passes a limit stops growing paths
      and is split at the point that has come furthest instead; that
      keeps the time near linear on large, very different inputs and may
      give a longer script than -d.
   5. Where a run of changed lines can slide over identical lines without
      changing what the script does, it is placed as the manual describes:
      joined with an adjacent run where it can be, otherwise facing a run
      of changed lines in the other file, otherwise as far towards the end
      of the file as it goes (never into the common prefix or suffix).

   Time is O((N+M)D) for the search (bounded further by the limit
   without -d) and space is linear. */

/* One change, from the walk over the change flags: DEL lines of A from
   LINE0 replaced by INS lines of B from LINE1. IGNORE marks a change
   that -B or -I would hide. */
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

/* A hash that agrees with bd_lineq: the bytes it compares, folded the
   same way. */
static unsigned long
bd_line_key (const bd_line *l, const bd_opts *o)
{
    unsigned long h = 5381;
    size_t len = l->len;
    const unsigned char *p = l->data;
#define BD_MIX(c) (h = h * 33u ^ (unsigned char) (o->iflag ? tolower (c) : (c)))
    if (o->wflag) {
        for (size_t i = 0; i < len; i++)
            if (!isspace (p[i])) BD_MIX (p[i]);
    } else if (o->bflag) {
        for (size_t i = 0; i < len; ) {
            if (bd_space (p[i])) {
                size_t j = i;
                while (j < len && bd_space (p[j])) j++;
                if (j < len) BD_MIX (' ');
                i = j;
            } else {
                BD_MIX (p[i]);
                i++;
            }
        }
    } else {
        if (o->zflag)
            while (len && bd_space (p[len - 1])) len--;
        for (size_t i = 0; i < len; i++) BD_MIX (p[i]);
    }
#undef BD_MIX
    return h;
}

/* Is line I of file X (0 for A) the incomplete last line, for equality? */
static int
bd_tail (const bd_files *f, const bd_opts *o, int x, long i)
{
    if (bd_ws_mode (o)) return 0;
    return x ? f->nonl_b && i == f->m - 1 : f->nonl_a && i == f->n - 1;
}

/* Number the classes of equal lines: CLS[0..n) for A, CLS[n..n+m) for B.
   Returns the number of classes, or -1 when out of memory. */
static int
bd_classify (const bd_files *f, const bd_opts *o, int *cls)
{
    long total = (long) f->n + f->m;
    size_t size = 16;
    while (size < (size_t) total * 2) size *= 2;
    long *table = calloc (size, sizeof *table);   /* line index + 1, or 0 */
    if (!table) return -1;
    int classes = 0;
    for (long g = 0; g < total; g++) {
        int x = g >= f->n;
        long i = x ? g - f->n : g;
        const bd_line *l = x ? &f->B[i] : &f->A[i];
        int tail = bd_tail (f, o, x, i);
        unsigned long h = bd_line_key (l, o) * 2 + (unsigned long) tail;
        size_t at = h & (size - 1);
        for (;;) {
            long e = table[at];
            if (!e) {
                table[at] = g + 1;
                cls[g] = classes++;
                break;
            }
            long r = e - 1;
            int rx = r >= f->n;
            long ri = rx ? r - f->n : r;
            if (bd_tail (f, o, rx, ri) == tail &&
                bd_lineq (rx ? &f->B[ri] : &f->A[ri], l, o)) {
                cls[g] = cls[r];
                break;
            }
            at = (at + 1) & (size - 1);
        }
    }
    free (table);
    return classes;
}

/* The search state: class sequences A and B with their change flags, and
   the furthest point reached on each diagonal by forward and reverse
   paths. Diagonal K holds the points with x - y == K. */
typedef struct {
    const int *a, *b;
    char *ca, *cb;
    long *fv, *bv;           /* indexed by diagonal + the length of B + 1 */
    long limit;              /* cost at which a search gives up */
} bd_search;

#define BD_NONE (-1L)        /* no path reaches this diagonal */

/* Find where an optimal path through [xl,xh) x [yl,yh) crosses its
   middle (the paper's "middle snake"), or, past the cost limit, a point
   to split at. On return the part [*x0,*x1) of A matches [*y0,*y1) of B. */
static void
bd_middle (bd_search *s, long xl, long xh, long yl, long yh,
           long *x0, long *y0, long *x1, long *y1)
{
    const int *a = s->a, *b = s->b;
    long *fv = s->fv, *bv = s->bv;
    long fk = xl - yl, bk = xh - yh, kmin = xl - yh, kmax = xh - yl;
    int odd = (bk - fk) & 1;
    long flo = fk, fhi = fk, blo = bk, bhi = bk;
    long x, y;

    /* D = 0: the snakes from each corner. */
    for (x = xl, y = yl; x < xh && y < yh && a[x] == b[y]; x++, y++)
        ;
    fv[fk] = x;
    for (x = xh, y = yh; x > xl && y > yl && a[x - 1] == b[y - 1]; x--, y--)
        ;
    bv[bk] = x;

    for (long d = 1; ; d++) {
        if (d > s->limit) {
            /* Give up: split at the reached point furthest from its corner. */
            long best = -1, bx = 0, by = 0;
            for (long k = flo; k <= fhi; k += 2) {
                if (fv[k] == BD_NONE) continue;
                long px = fv[k], py = px - k;
                if ((px - xl) + (py - yl) > best) { best = (px - xl) + (py - yl); bx = px; by = py; }
            }
            for (long k = blo; k <= bhi; k += 2) {
                if (bv[k] == BD_NONE) continue;
                long px = bv[k], py = px - k;
                if ((xh - px) + (yh - py) > best) { best = (xh - px) + (yh - py); bx = px; by = py; }
            }
            *x0 = *x1 = bx;
            *y0 = *y1 = by;
            return;
        }

        /* Forward paths of cost D. */
        long lo = fk - d < kmin ? kmin + ((kmin - (fk - d)) & 1) : fk - d;
        long hi = fk + d > kmax ? kmax - (((fk + d) - kmax) & 1) : fk + d;
        for (long k = hi; k >= lo; k -= 2) {
            long right = BD_NONE, down = BD_NONE;
            if (k - 1 >= flo && k - 1 <= fhi && fv[k - 1] != BD_NONE && fv[k - 1] < xh)
                right = fv[k - 1] + 1;
            if (k + 1 >= flo && k + 1 <= fhi && fv[k + 1] != BD_NONE && fv[k + 1] - k <= yh)
                down = fv[k + 1];
            x = right > down ? right : down;
            if (x == BD_NONE) { fv[k] = BD_NONE; continue; }
            y = x - k;
            long sx = x, sy = y;
            while (x < xh && y < yh && a[x] == b[y]) x++, y++;
            fv[k] = x;
            if (odd && k >= blo && k <= bhi && bv[k] != BD_NONE && x >= bv[k]) {
                *x0 = sx; *y0 = sy; *x1 = x; *y1 = y;
                return;
            }
        }
        flo = lo; fhi = hi;

        /* Reverse paths of cost D. */
        lo = bk - d < kmin ? kmin + ((kmin - (bk - d)) & 1) : bk - d;
        hi = bk + d > kmax ? kmax - (((bk + d) - kmax) & 1) : bk + d;
        for (long k = hi; k >= lo; k -= 2) {
            long up = BD_NONE, left = BD_NONE;
            if (k - 1 >= blo && k - 1 <= bhi && bv[k - 1] != BD_NONE && bv[k - 1] - k >= yl)
                up = bv[k - 1];
            if (k + 1 >= blo && k + 1 <= bhi && bv[k + 1] != BD_NONE && bv[k + 1] > xl)
                left = bv[k + 1] - 1;
            if (up == BD_NONE) x = left;
            else if (left == BD_NONE) x = up;
            else x = up < left ? up : left;
            if (x == BD_NONE) { bv[k] = BD_NONE; continue; }
            y = x - k;
            long ex = x, ey = y;
            while (x > xl && y > yl && a[x - 1] == b[y - 1]) x--, y--;
            bv[k] = x;
            if (!odd && k >= flo && k <= fhi && fv[k] != BD_NONE && x <= fv[k]) {
                *x0 = x; *y0 = y; *x1 = ex; *y1 = ey;
                return;
            }
        }
        blo = lo; bhi = hi;
    }
}

/* Mark the changed lines of [xl,xh) x [yl,yh). The smaller part left by
   each split is solved by recursion and the larger in the loop, so the
   recursion is no deeper than log2 of the input size. */
static void
bd_solve (bd_search *s, long xl, long xh, long yl, long yh)
{
    for (;;) {
        while (xl < xh && yl < yh && s->a[xl] == s->b[yl]) xl++, yl++;
        while (xl < xh && yl < yh && s->a[xh - 1] == s->b[yh - 1]) xh--, yh--;
        if (xl == xh) { while (yl < yh) s->cb[yl++] = 1; return; }
        if (yl == yh) { while (xl < xh) s->ca[xl++] = 1; return; }
        long x0, y0, x1, y1;
        bd_middle (s, xl, xh, yl, yh, &x0, &y0, &x1, &y1);
        if ((x0 - xl) + (y0 - yl) <= (xh - x1) + (yh - y1)) {
            bd_solve (s, xl, x0, yl, y0);
            xl = x1; yl = y1;
        } else {
            bd_solve (s, x1, xh, y1, yh);
            xh = x0; yh = y0;
        }
    }
}

/* Slide the runs of changed lines of one file X (classes CLS, flags CX,
   N lines) over identical lines. CY are the other file's flags (M lines)
   and UY[u] the index of its u-th unchanged line: the u-th unchanged
   lines of the two files are matched. Runs stay within [LO, HI), the part
   outside the common prefix and suffix.

   A run that meets another run while sliding is joined with it, and the
   joined run can slide further, so each run first goes up and down as far
   as it can until it stops growing. It then rests at the lowest place
   where it faces changed lines of the other file (so the two make one
   change rather than a deletion and an insertion), or at the bottom when
   there is no such place. */
static void
bd_slide (const int *cls, char *cx, long n, const char *cy, long m,
          const long *uy, long lo, long hi)
{
    long i = 0, u = 0;           /* u: unchanged lines of X before i */
#define BD_FACING(u) ((u) > 0 ? uy[(u) - 1] + 1 < m && cy[uy[(u) - 1] + 1] \
                              : m > 0 && cy[0])
    while (i < n) {
        if (!cx[i]) { i++; u++; continue; }
        long st = i, en = i, len;
        while (en < n && cx[en]) en++;
        do {
            len = en - st;
            while (st > lo && cls[st - 1] == cls[en - 1]) {
                cx[--st] = 1;
                cx[--en] = 0;
                u--;
                while (st > 0 && cx[st - 1]) st--;
            }
            while (en < hi && cls[st] == cls[en]) {
                cx[st++] = 0;
                cx[en++] = 1;
                u++;
                while (en < n && cx[en]) en++;
            }
        } while (en - st != len);
        long bottom = st;
        while (!BD_FACING (u) && st > lo && cls[st - 1] == cls[en - 1]) {
            cx[--st] = 1;
            cx[--en] = 0;
            u--;
        }
        if (!BD_FACING (u))
            while (st < bottom) {
                cx[st++] = 0;
                cx[en++] = 1;
                u++;
            }
        i = en;
    }
#undef BD_FACING
}

/* Index of each unchanged line of a file with flags C and N lines. */
static void
bd_unchanged (const char *c, long n, long *u)
{
    long k = 0;
    for (long i = 0; i < n; i++)
        if (!c[i]) u[k++] = i;
}

/* Would -B or -I hide this line? */
static int
bd_trivial (const bd_files *f, const bd_line *l, const bd_opts *o)
{
    if (o->blank) {
        size_t i = 0;
        if (bd_ws_mode (o))
            while (i < l->len && isspace (l->data[i])) i++;
        if (i == l->len) return 1;
    }
    return o->ignore_re && bd_re_match (o->ignore_re, f, l);
}

/* Are line I of A and line J of B the same bytes, newline included? */
static int
bd_bytes_equal (const bd_files *f, long i, long j)
{
    const bd_line *a = &f->A[i], *b = &f->B[j];
    return a->len == b->len && !memcmp (a->data, b->data, a->len) &&
           (f->nonl_a && i == f->n - 1) == (f->nonl_b && j == f->m - 1);
}

typedef enum { BDOP_EQ, BDOP_DEL, BDOP_INS } bd_optype;
typedef struct { bd_optype op; int la; int lb; } bd_op;

/* Compare the files: the list of changes (returned count, -1 when out of
   memory) and the line-by-line operations that -y lays out. */
static int
bd_changes (const bd_files *f, const bd_opts *o, bd_change **out, bd_op **ops_out, int *n_ops)
{
    long n = f->n, m = f->m;
    int *cls = malloc (((size_t) n + m + 1) * sizeof *cls);
    int *count = NULL, *ra = NULL;
    long *ia = NULL, *vec = NULL, *uy = NULL;
    char *ca = calloc ((size_t) n + m + 2, 1);
    bd_change *ch = NULL;
    bd_op *ops = NULL;
    int nch = -1;
    if (!cls || !ca) goto oom;
    char *cb = ca + n + 1;
    int classes = bd_classify (f, o, cls);
    if (classes < 0) goto oom;
    const int *ea = cls, *eb = cls + n;

    /* The common prefix and suffix of byte-identical lines (lines that
       are only equal under -i, -b, -w or -Z do not count here; GNU diff
       behaves the same), less the lines --horizon-lines (or the context
       of -c and -u, as in GNU diff) keeps next to the rest: those lines
       count when judging which lines have no counterpart, and runs may
       slide into them. Lines equal under the options are matched by the
       search, which strips equal ends of each part it is given. */
    long pre = 0, suf = 0;
    while (pre < n && pre < m && bd_bytes_equal (f, pre, pre)) pre++;
    while (suf < n - pre && suf < m - pre && bd_bytes_equal (f, n - 1 - suf, m - 1 - suf)) suf++;
    long keep = o->horizon;
    if ((o->style == BD_UNIFIED || o->style == BD_CONTEXT) &&
        (o->context < 0 ? 3 : o->context) > keep)
        keep = o->context < 0 ? 3 : o->context;
    pre = pre > keep ? pre - keep : 0;
    suf = suf > keep ? suf - keep : 0;
    long xn = n - pre - suf, yn = m - pre - suf;

    /* Without -d, a line of the part between them whose class does not
       occur in the other file's part is changed and left out of the
       search. RA/RB hold the classes of the lines searched, IA/IB their
       line numbers. COUNT has two flags per class: occurs in A's part,
       occurs in B's. */
    ra = malloc (((size_t) xn + yn + 1) * sizeof *ra);
    ia = malloc (((size_t) xn + yn + 1) * sizeof *ia);
    if (!ra || !ia) goto oom;
    if (!o->minimal) {
        count = calloc ((size_t) classes * 2 + 2, sizeof *count);
        if (!count) goto oom;
        for (long i = pre; i < n - suf; i++) count[ea[i] * 2] = 1;
        for (long j = pre; j < m - suf; j++) count[eb[j] * 2 + 1] = 1;
    }
    long rn = 0, rm = 0;
    for (long i = pre; i < n - suf; i++) {
        if (!count || count[ea[i] * 2 + 1]) { ra[rn] = ea[i]; ia[rn++] = i; }
        else ca[i] = 1;
    }
    int *rb = ra + rn;
    long *ib = ia + rn;
    for (long j = pre; j < m - suf; j++) {
        if (!count || count[eb[j] * 2]) { rb[rm] = eb[j]; ib[rm++] = j; }
        else cb[j] = 1;
    }
    free (count);
    count = NULL;

    if (rn && rm) {
        char *rc = calloc ((size_t) rn + rm, 1);
        vec = malloc (((size_t) rn + rm + 3) * 2 * sizeof *vec);
        if (!rc || !vec) { free (rc); goto oom; }
        bd_search s;
        s.a = ra;
        s.b = rb;
        s.ca = rc;
        s.cb = rc + rn;
        s.fv = vec + rm + 1;
        s.bv = vec + (rn + rm + 3) + rm + 1;
        if (o->minimal) s.limit = LONG_MAX;
        else {
            /* 4096, or the square root of the input when that is larger:
               edits of thousands of lines still get a minimal script,
               while two shuffled copies of a 100000-line file take about
               as long as GNU diff takes. */
            long t = rn + rm, r = 1;
            while (r * r < t) r++;
            s.limit = r > 4096 ? r : 4096;
        }
        bd_solve (&s, 0, rn, 0, rm);
        for (long i = 0; i < rn; i++) if (rc[i]) ca[ia[i]] = 1;
        for (long j = 0; j < rm; j++) if (rc[rn + j]) cb[ib[j]] = 1;
        free (rc);
    } else {
        for (long i = 0; i < rn; i++) ca[ia[i]] = 1;
        for (long j = 0; j < rm; j++) cb[ib[j]] = 1;
    }
    free (vec);
    vec = NULL;
    free (ra);
    ra = NULL;
    free (ia);
    ia = NULL;

    /* Place the runs: A against B's flags, then B against A's. */
    uy = malloc (((size_t) (n > m ? n : m) + 1) * sizeof *uy);
    if (!uy) goto oom;
    bd_unchanged (cb, m, uy);
    bd_slide (ea, ca, n, cb, m, uy, pre, n - suf);
    bd_unchanged (ca, n, uy);
    bd_slide (eb, cb, m, ca, n, uy, pre, m - suf);
    free (uy);
    uy = NULL;

    /* Walk both files: matched lines in step, each stretch of changed
       lines between them one change. */
    long count_ch = 0, i = 0, j = 0;
    while (i < n || j < m) {
        if (i < n && j < m && !ca[i] && !cb[j]) { i++; j++; continue; }
        while (i < n && ca[i]) i++;
        while (j < m && cb[j]) j++;
        count_ch++;
    }
    ch = malloc (((size_t) count_ch + 1) * sizeof *ch);
    ops = malloc (((size_t) n + m + 1) * sizeof *ops);
    if (!ch || !ops) goto oom;
    int k = 0, c = 0;
    i = j = 0;
    while (i < n || j < m) {
        if (i < n && j < m && !ca[i] && !cb[j]) {
            ops[k++] = (bd_op) { BDOP_EQ, (int) i, (int) j };
            i++; j++;
            continue;
        }
        bd_change *h = &ch[c++];
        h->line0 = (int) i;
        h->line1 = (int) j;
        h->ignore = o->blank || o->ignore_re != NULL;
        for (; i < n && ca[i]; i++) {
            ops[k++] = (bd_op) { BDOP_DEL, (int) i, (int) j };
            if (h->ignore && !bd_trivial (f, &f->A[i], o)) h->ignore = 0;
        }
        for (; j < m && cb[j]; j++) {
            ops[k++] = (bd_op) { BDOP_INS, (int) i, (int) j };
            if (h->ignore && !bd_trivial (f, &f->B[j], o)) h->ignore = 0;
        }
        h->del = (int) i - h->line0;
        h->ins = (int) j - h->line1;
    }
    nch = c;
    *out = ch;
    *ops_out = ops;
    *n_ops = k;
    free (cls);
    free (ca);
    return nch;

oom:
    builtin_error ("out of memory comparing files");
    free (cls);
    free (count);
    free (ra);
    free (ia);
    free (vec);
    free (uy);
    free (ca);
    free (ch);
    free (ops);
    return -1;
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

/* -n: an RCS script, first change first. "dL N" deletes N lines from
   old line L; "aL N" adds the N lines that follow it after old line L.
   An incomplete last line is written as it is. */
static void
bd_emit_rcs (bl_output *out, const bd_files *f, const bd_change *ch, int nch)
{
    for (int c = 0; c < nch; c++) {
        const bd_change *h = &ch[c];
        if (h->ignore) continue;
        if (h->del) bd_format (out, "d%d %d\n", h->line0 + 1, h->del);
        if (!h->ins) continue;
        bd_format (out, "a%d %d\n", h->line0 + h->del, h->ins);
        for (int k = h->line1; k < h->line1 + h->ins; k++) {
            bd_write_text (out, &f->B[k], NULL);
            if (!(f->nonl_b && k == f->m - 1)) bl_output_byte (out, '\n');
        }
    }
}

/* Output laid out by the line and group formats (and -D, which is a set
   of group formats). The file is cut into groups: runs of unchanged
   lines, and changes that delete lines (old), insert lines (new) or both
   (changed). Each group is written by its group format; there %< writes
   the group's old lines, %> its new lines and %= its old lines again,
   each line by its line format. A change that -B or -I hides belongs to
   the unchanged run around it.

   A format is text with % directives. Group formats have %<, %>, %=,
   %(A=B?THEN:ELSE), and numbers of the group's lines; line formats have
   %l (the text), %L (the text and its newline, if it has one) and the
   line's number. Both have %% and %c'C' (C a character or \OOO). A
   number is printf-like: %[-'0][WIDTH][.PREC] then d, o, x or X, then a
   letter: n in a line format; e f l m n (old file) or E F L M N (new
   file) in a group format, for the line before the group, its first and
   last lines, the line after it, and its length. A '%' that starts none
   of these is written as it is and the text after it read on. */
typedef struct {
    bl_output *out;
    const bd_files *f;
    const bd_opts *o;
    int is_line;             /* a line format, else a group format */
    long lo[2], hi[2];       /* group: lines [lo, hi) of each file */
    int file;                /* line: which file, and its index there */
    long line;
} bd_fmt;

static const char *bd_fmt_walk (bd_fmt *x, const char *p, int stop, int emit);

static const char *
bd_fmt_default (const bd_opts *o, int slot)
{
    const char *fmt = o->formats[slot];
    if (fmt) return fmt;
    switch (slot) {
    case BD_F_OLD_GROUP:
        return o->formats[BD_F_CHANGED_GROUP] ? o->formats[BD_F_CHANGED_GROUP] : "%<";
    case BD_F_NEW_GROUP:
        return o->formats[BD_F_CHANGED_GROUP] ? o->formats[BD_F_CHANGED_GROUP] : "%>";
    case BD_F_UNCHANGED_GROUP:
        return "%=";
    default:
        return "%l\n";
    }
}

/* Value of a number letter, 0 when the letter does not belong here. */
static int
bd_fmt_letter (const bd_fmt *x, int letter, intmax_t *v)
{
    if (x->is_line) {
        if (letter != 'n') return 0;
        *v = x->line + 1;
        return 1;
    }
    if (!letter || !strchr ("eflmnEFLMN", letter)) return 0;
    int side = letter >= 'A' && letter <= 'Z';
    long lo = x->lo[side], hi = x->hi[side];
    switch (letter | 0x20) {
    case 'e': *v = lo; break;
    case 'f': *v = lo + 1; break;
    case 'l': *v = hi; break;
    case 'm': *v = hi + 1; break;
    default: *v = hi - lo; break;
    }
    return 1;
}

/* Write the lines [lo, hi) of FILE by the line format in SLOT. */
static void
bd_fmt_lines (const bd_fmt *x, int file, int slot)
{
    const char *fmt = bd_fmt_default (x->o, slot);
    bd_fmt lx = *x;
    lx.is_line = 1;
    lx.file = file;
    for (long i = x->lo[file]; i < x->hi[file]; i++) {
        lx.line = i;
        bd_fmt_walk (&lx, fmt, 0, 1);
    }
}

/* A conditional operand: a number letter or a decimal number. */
static const char *
bd_fmt_operand (const bd_fmt *x, const char *p, intmax_t *v)
{
    if (bd_fmt_letter (x, (unsigned char) *p, v)) return p + 1;
    if (!isdigit ((unsigned char) *p)) return NULL;
    intmax_t n = 0;
    for (; isdigit ((unsigned char) *p); p++) {
        int d = *p - '0';
        if (n > (INTMAX_MAX - d) / 10) return NULL;
        n = n * 10 + d;
    }
    *v = n;
    return p;
}

/* %(A=B?THEN:ELSE) from after the '('. THEN runs to a ':' (a ')' there is
   text), ELSE to a ')'; either may run to the end of the format. */
static const char *
bd_fmt_cond (bd_fmt *x, const char *p, int emit)
{
    intmax_t a, b;
    if (!(p = bd_fmt_operand (x, p, &a)) || *p != '=') return NULL;
    if (!(p = bd_fmt_operand (x, p + 1, &b)) || *p != '?') return NULL;
    p = bd_fmt_walk (x, p + 1, ':', emit && a == b);
    if (*p == ':') {
        p = bd_fmt_walk (x, p + 1, ')', emit && a != b);
        if (*p == ')') p++;
    }
    return p;
}

/* %c'C' or %c'\OOO' from after the 'c'. */
static const char *
bd_fmt_char (bd_fmt *x, const char *p, int emit)
{
    unsigned value = 0;
    if (*p++ != '\'') return NULL;
    if (*p == '\\') {
        int digits = 0;
        for (p++; digits < 3 && *p >= '0' && *p <= '7'; p++, digits++)
            value = value * 8 + (unsigned) (*p - '0');
        if (!digits) return NULL;
    } else if (*p && *p != '\'') value = (unsigned char) *p++;
    else return NULL;
    if (*p != '\'') return NULL;
    if (emit) bl_output_byte (x->out, (unsigned char) value);
    return p + 1;
}

/* One directive from after its '%'; NULL when it is not one. */
static const char *
bd_fmt_directive (bd_fmt *x, const char *p, int emit)
{
    const char *spec = p;
    while (*p == '-' || *p == '\'' || *p == '0') p++;
    while (isdigit ((unsigned char) *p)) p++;
    if (*p == '.')
        for (p++; isdigit ((unsigned char) *p); p++)
            continue;
    if (p == spec) {
        switch (*p) {
        case '%':
            if (emit) bl_output_byte (x->out, '%');
            return p + 1;
        case '<': case '>': case '=':
            if (x->is_line) return NULL;
            if (emit)
                bd_fmt_lines (x, *p == '>', *p == '<' ? BD_F_OLD_LINE
                              : *p == '>' ? BD_F_NEW_LINE : BD_F_UNCHANGED_LINE);
            return p + 1;
        case 'l': case 'L':
            if (!x->is_line) return NULL;
            if (emit) {
                const bd_line *l = x->file ? &x->f->B[x->line] : &x->f->A[x->line];
                int nonl = x->file ? x->f->nonl_b && x->line == x->f->m - 1
                                   : x->f->nonl_a && x->line == x->f->n - 1;
                bd_write_text (x->out, l, NULL);
                if (*p == 'L' && !nonl) bl_output_byte (x->out, '\n');
            }
            return p + 1;
        case '(':
            return x->is_line ? NULL : bd_fmt_cond (x, p + 1, emit);
        }
    }
    if (*p == 'c') return bd_fmt_char (x, p + 1, emit);
    intmax_t v;
    if (!*p || !strchr ("doxX", *p) || !bd_fmt_letter (x, (unsigned char) p[1], &v))
        return NULL;
    if (emit) {
        /* "%" SPEC "j" CONVERSION, for snprintf. */
        size_t sl = (size_t) (p - spec);
        char *cf = malloc (sl + 4);
        if (!cf) { if (!x->out->error) x->out->error = ENOMEM; return p + 2; }
        cf[0] = '%';
        memcpy (cf + 1, spec, sl);
        cf[sl + 1] = 'j';
        cf[sl + 2] = *p;
        cf[sl + 3] = '\0';
        int n = *p == 'd' ? snprintf (NULL, 0, cf, v) : snprintf (NULL, 0, cf, (uintmax_t) v);
        char *buf = n >= 0 ? malloc ((size_t) n + 1) : NULL;
        if (n < 0) { free (cf); return NULL; }
        if (!buf) { free (cf); if (!x->out->error) x->out->error = ENOMEM; return p + 2; }
        if (*p == 'd') snprintf (buf, (size_t) n + 1, cf, v);
        else snprintf (buf, (size_t) n + 1, cf, (uintmax_t) v);
        bl_output_write (x->out, buf, (size_t) n);
        free (buf);
        free (cf);
    }
    return p + 2;
}

/* Run the format at P up to its end or to an unconsumed STOP character,
   writing only when EMIT; returns where it stopped. */
static const char *
bd_fmt_walk (bd_fmt *x, const char *p, int stop, int emit)
{
    while (*p && *p != stop) {
        const char *next = *p == '%' ? bd_fmt_directive (x, p + 1, emit) : NULL;
        if (next) {
            p = next;
            continue;
        }
        if (emit) bl_output_byte (x->out, (unsigned char) *p);
        p++;
    }
    return p;
}

static void
bd_fmt_group (bd_fmt *x, int slot, long lo0, long hi0, long lo1, long hi1)
{
    x->is_line = 0;
    x->lo[0] = lo0; x->hi[0] = hi0;
    x->lo[1] = lo1; x->hi[1] = hi1;
    if (slot == BD_F_CHANGED_GROUP && !x->o->formats[BD_F_CHANGED_GROUP]) {
        /* By default a change is its old group and then its new group. */
        bd_fmt_walk (x, bd_fmt_default (x->o, BD_F_OLD_GROUP), 0, 1);
        bd_fmt_walk (x, bd_fmt_default (x->o, BD_F_NEW_GROUP), 0, 1);
        return;
    }
    bd_fmt_walk (x, bd_fmt_default (x->o, slot), 0, 1);
}

static void
bd_emit_formats (bl_output *out, const bd_files *f, const bd_change *ch, int nch,
                 const bd_opts *o)
{
    bd_fmt x;
    memset (&x, 0, sizeof x);
    x.out = out;
    x.f = f;
    x.o = o;
    long u0 = 0, u1 = 0;
    for (int c = 0; c <= nch; c++) {
        if (c < nch && ch[c].ignore) continue;
        long e0 = c < nch ? ch[c].line0 : f->n, e1 = c < nch ? ch[c].line1 : f->m;
        if (e0 > u0 || e1 > u1) bd_fmt_group (&x, BD_F_UNCHANGED_GROUP, u0, e0, u1, e1);
        if (c == nch) break;
        const bd_change *h = &ch[c];
        int slot = h->del && h->ins ? BD_F_CHANGED_GROUP : h->del ? BD_F_OLD_GROUP : BD_F_NEW_GROUP;
        bd_fmt_group (&x, slot, h->line0, h->line0 + h->del, h->line1, h->line1 + h->ins);
        u0 = h->line0 + h->del;
        u1 = h->line1 + h->ins;
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
   take no column. With -t a tab in either column is expanded from the
   start of that column; without it, real tabs keep the page's tab stops.
   --left-column writes a common line once, with "(" in the gutter. */
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
            long at = bd_out.expand_tabs ? in : in + indent;
            long spaces = bd_out.tabsize - (at % bd_out.tabsize);
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
    if (sep == '(') right = NULL, newline |= right_nl;
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
                      int no_newline_a, int no_newline_b, int suppress_common,
                      int left_column)
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
                bd_sbs_line (out, &g, &A[la], !(no_newline_a && la == n - 1),
                             left_column ? '(' : ' ',
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
    /* Side-by-side and format output write the common lines too. */
    if (o->style != BD_SBS && o->style != BD_IFDEF && bd_files_equal (da, la, db, lb)) {
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
    } else if (differ || o->style == BD_SBS || o->style == BD_IFDEF) {
        bl_output out;
        bl_output_init (&out, stdout);
        if (header) { bd_text (&out, header); bl_output_byte (&out, '\n'); }
        if (o->style == BD_SBS)
            bd_emit_side_by_side (&out, f.A, f.n, f.B, f.m, ops, n_ops, o->width,
                                  f.nonl_a, f.nonl_b, o->suppress_common,
                                  o->left_column);
        else if (o->style == BD_NORMAL)
            bd_emit_ed (&out, &f, ch, nch);
        else if (o->style == BD_ED)
            bd_emit_ed_script (&out, &f, ch, nch);
        else if (o->style == BD_RCS)
            bd_emit_rcs (&out, &f, ch, nch);
        else if (o->style == BD_IFDEF)
            bd_emit_formats (&out, &f, ch, nch, o);
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

/* The target of symbolic link PATH, allocated; NULL after an error. */
static char *
bd_readlink (const char *path, const struct stat *st)
{
    size_t cap = st->st_size > 0 ? (size_t) st->st_size + 1 : 64;
    for (;;) {
        char *buf = malloc (cap);
        if (!buf) { builtin_error ("out of memory"); return NULL; }
        ssize_t n = readlink (path, buf, cap);
        if (n < 0) {
            builtin_error ("%s: %s", path, strerror (errno));
            free (buf);
            return NULL;
        }
        if ((size_t) n < cap) { buf[n] = '\0'; return buf; }
        free (buf);
        if (cap > SIZE_MAX / 2) { builtin_error ("out of memory"); return NULL; }
        cap *= 2;
    }
}

/* --no-dereference with a symbolic link on either side: two links are
   the same when their targets are; a link and another kind of file
   always differ. */
static int
bd_compare_links (const char *p0, const struct stat *s0, const char *p1,
                  const struct stat *s1, const bd_opts *o)
{
    int rc;
    fflush (stdout);
    if (S_ISLNK (s0->st_mode) && S_ISLNK (s1->st_mode)) {
        char *t0 = bd_readlink (p0, s0), *t1 = t0 ? bd_readlink (p1, s1) : NULL;
        if (!t1) { free (t0); return 2; }
        rc = strcmp (t0, t1) != 0;
        free (t0);
        free (t1);
        if (rc) printf ("Symbolic links %s and %s differ\n", p0, p1);
        else if (o->sflag) printf ("Files %s and %s are identical\n", p0, p1);
    } else {
        printf ("File %s is a %s while file %s is a %s\n", p0, bd_file_type (s0),
                p1, bd_file_type (s1));
        rc = 1;
    }
    return bd_finish_output (rc);
}

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
    int (*stat_fn) (const char *, struct stat *) = o->no_deref ? lstat : stat;
    if (!bd_is_stdin (p0)) {
        if (stat_fn (p0, &s0) < 0) {
            if (errno != ENOENT || !o->nflag) { builtin_error ("%s: %s", p0, strerror (errno)); return 2; }
            missing |= 1;
        } else d0 = S_ISDIR (s0.st_mode);
    }
    if (!bd_is_stdin (p1)) {
        if (stat_fn (p1, &s1) < 0) {
            if (errno != ENOENT || !o->nflag || missing) { builtin_error ("%s: %s", missing ? p0 : p1, strerror (ENOENT)); return 2; }
            missing |= 2;
        } else d1 = S_ISDIR (s1.st_mode);
    }
    /* -N: a missing operand is an empty file, or an empty directory when
       the other side is a directory. */
    if (missing & 1) d0 = d1;
    if (missing & 2) d1 = d0;
    if (d0 && d1) {
        if (o->style == BD_IFDEF) {
            builtin_error ("-D option not supported with directories");
            bd_fatal = 1;
            return 2;
        }
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
    if (o->no_deref && !missing && !bd_is_stdin (p0) && !bd_is_stdin (p1) &&
        (S_ISLNK (s0.st_mode) || S_ISLNK (s1.st_mode)))
        return bd_compare_links (p0, &s0, p1, &s1, o);
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

/* Put VALUE in format SLOT; OPTION names the option for a conflict, a
   second value that differs from the first. */
static int
bd_set_format (bd_parse *ps, int slot, const char *value, const char *option)
{
    bd_opts *o = ps->o;
    if (o->formats[slot]) {
        if (strcmp (o->formats[slot], value) == 0) return 0;
        builtin_error ("conflicting %s option value '%s'", option, value);
        return -1;
    }
    size_t len = strlen (value) + 1;
    if (!(o->formats[slot] = malloc (len))) { builtin_error ("out of memory"); return -1; }
    memcpy (o->formats[slot], value, len);
    return 0;
}

/* The format options in bd_long order (codes 12 to 19); --line-format
   sets all three line formats. */
static const struct { const char *option; int slot; } bd_format_opts[] = {
    { "--old-line-format", BD_F_OLD_LINE }, { "--new-line-format", BD_F_NEW_LINE },
    { "--unchanged-line-format", BD_F_UNCHANGED_LINE }, { "--line-format", -1 },
    { "--old-group-format", BD_F_OLD_GROUP }, { "--new-group-format", BD_F_NEW_GROUP },
    { "--unchanged-group-format", BD_F_UNCHANGED_GROUP },
    { "--changed-group-format", BD_F_CHANGED_GROUP },
};

static int
bd_format_option (bd_parse *ps, int which, const char *value)
{
    if (bd_style (ps, BD_IFDEF) < 0) return -1;
    const char *option = bd_format_opts[which].option;
    if (bd_format_opts[which].slot >= 0)
        return bd_set_format (ps, bd_format_opts[which].slot, value, option);
    for (int slot = BD_F_OLD_LINE; slot <= BD_F_UNCHANGED_LINE; slot++)
        if (bd_set_format (ps, slot, value, option) < 0) return -1;
    return 0;
}

/* -D NAME: the group formats of the manual's #ifndef/#ifdef/#else/#endif
   layout, NAME taken literally. */
static int
bd_ifdef (bd_parse *ps, const char *name)
{
    static const char *const shapes[4] = {
        "#ifndef %s\n%%<#endif /* ! %s */\n",
        "#ifdef %s\n%%>#endif /* %s */\n",
        "%%=",
        "#ifndef %s\n%%<#else /* %s */\n%%>#endif /* %s */\n",
    };
    static const int slots[4] = {
        BD_F_OLD_GROUP, BD_F_NEW_GROUP, BD_F_UNCHANGED_GROUP, BD_F_CHANGED_GROUP
    };
    if (bd_style (ps, BD_IFDEF) < 0) return -1;
    size_t len = 0;
    for (const char *c = name; *c; c++) len += *c == '%' ? 2 : 1;
    char *esc = malloc (len + 1);
    if (!esc) { builtin_error ("out of memory"); return -1; }
    char *q = esc;
    for (const char *c = name; *c; c++) {
        if (*c == '%') *q++ = '%';
        *q++ = *c;
    }
    *q = '\0';
    int rc = 0;
    for (int i = 0; i < 4 && rc == 0; i++) {
        size_t size = strlen (shapes[i]) + 3 * len + 1;
        char *fmt = malloc (size);
        if (!fmt) { builtin_error ("out of memory"); rc = -1; break; }
        snprintf (fmt, size, shapes[i], esc, esc, esc);
        rc = bd_set_format (ps, slots[i], fmt, "-D");
        free (fmt);
    }
    free (esc);
    return rc;
}

/* Options that take an argument: the rest of the word or the next one. */
#define BD_SHORT_ARG "CUxXLWIFD"

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
    case 'D': return bd_ifdef (ps, arg);
    case 'e': return bd_style (ps, BD_ED);
    case 'n': return bd_style (ps, BD_RCS);
    case 't': bd_out.expand_tabs = 1; break;
    case 'T': bd_out.initial_tab = 1; break;
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
    { "initial-tab", 'T', 0 }, { "ifdef", 'D', 1 }, { "rcs", 'n', 0 },
    { "from-file", 8, 1 }, { "to-file", 9, 1 }, { "no-dereference", 10, 0 },
    { "left-column", 11, 0 },
    { "old-line-format", 12, 1 }, { "new-line-format", 13, 1 },
    { "unchanged-line-format", 14, 1 }, { "line-format", 15, 1 },
    { "old-group-format", 16, 1 }, { "new-group-format", 17, 1 },
    { "unchanged-group-format", 18, 1 }, { "changed-group-format", 19, 1 },
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
    const char **paths = NULL;
    const char *from_file = NULL, *to_file = NULL;
    int npos = 0;
    size_t sw_len = 0;
    int nlabels = 0;
    int rc = EX_USAGE;
    o.width = 130;
    o.context = -1;
    o.style = BD_NORMAL;
    const char *palette = NULL;
    bd_out.expand_tabs = 0;
    bd_out.initial_tab = 0;
    bd_out.tabsize = 8;
    bd_fatal = 0;
    bd_out.color = 0;
    for (int i = 0; i < BD_C_N; i++) bd_out.palette[i] = (char *) bd_color_defaults[i];
    /* Option words as given, for the "diff OPTIONS A B" lines of -r. */
    size_t nwords = 0;
    for (WORD_LIST *p = list; p; p = p->next, nwords++)
        sw_len += 4 * strlen (p->word->word) + 4;
    char *switches = malloc (sw_len + 1);
    paths = malloc ((nwords + 1) * sizeof *paths);
    if (!switches || !paths) {
        builtin_error ("out of memory");
        free (switches);
        free (paths);
        return 2;
    }
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
            for (p = p->next; p; p = p->next) paths[npos++] = p->word->word;
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
            if (c == 1) continue;      /* --speed-large-files: accepted, no effect */
            if (c == 2) {
                /* GNU takes an empty value as 0. */
                char *end;
                errno = 0;
                long v = *arg ? strtol (arg, &end, 10) : 0;
                if (*arg && (end == arg || *end || v < 0)) {
                    builtin_error ("invalid horizon length '%s'", arg);
                    BD_USAGE_FAIL;
                }
                o.horizon = errno == ERANGE || v > INT_MAX ? INT_MAX : v;
                continue;
            }
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
            if (c == 8 || c == 9) {
                const char **file = c == 8 ? &from_file : &to_file;
                if (*file && strcmp (*file, arg)) {
                    builtin_error ("conflicting %s option value '%s'",
                                   c == 8 ? "--from-file" : "--to-file", arg);
                    BD_USAGE_FAIL;
                }
                *file = arg;
                continue;
            }
            if (c == 10) { o.no_deref = 1; continue; }
            if (c == 11) { o.left_column = 1; continue; }
            if (c >= 12 && c <= 19) {
                if (bd_format_option (&ps, c - 12, arg) < 0) BD_USAGE_FAIL;
                continue;
            }
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
        } else paths[npos++] = w;
    }
    if (from_file && to_file) {
        builtin_error ("--from-file and --to-file both specified");
        BD_USAGE_FAIL;
    }
    /* --from-file and --to-file take any number of operands. */
    if (!from_file && !to_file && npos > 2) {
        builtin_error ("extra operand: %s", paths[2]);
        BD_USAGE_FAIL;
    }
    if (!from_file && !to_file && npos != 2) {
        if (npos) builtin_error ("missing operand after '%s'", paths[npos - 1]);
        BD_USAGE_FAIL;
    }
    if (ps.ignore_pat && !(o.ignore_re = bd_compile (ps.ignore_pat))) { rc = 2; goto done; }
    if (ps.function_pat && !(o.function_re = bd_compile (ps.function_pat))) { rc = 2; goto done; }
#undef BD_USAGE_FAIL
#undef BD_SW
    if (palette && bd_out.color) bd_palette (palette);
    o.switches = switches;
    if (from_file || to_file) {
        /* Each operand against the one file, in order; the worst status
           wins. */
        rc = 0;
        for (int i = 0; i < npos && !bd_fatal; i++) {
            int r = from_file ? bd_compare_paths (from_file, paths[i], &o, 1)
                              : bd_compare_paths (paths[i], to_file, &o, 1);
            if (r > rc) rc = r;
        }
        rc = bd_finish_output (rc);
    } else rc = bd_finish_output (bd_compare_paths (paths[0], paths[1], &o, 1));
done:
    free (switches);
    free (paths);
    for (int i = 0; i < BD_F_N; i++) free (o.formats[i]);
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
    "    diff [OPTION]... --from-file=FILE1 FILE2...",
    "    diff [OPTION]... --to-file=FILE2 FILE1...",
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
    "    -n, --rcs      output an RCS format diff",
    "    -D NAME, --ifdef=NAME  output the merged file with #ifdef NAME groups",
    "    --GTYPE-group-format=GFMT  format GTYPE (old, new, unchanged or changed)",
    "                   groups with GFMT: %< %> %= lines, %(A=B?T:E), %c'C',",
    "                   printf-style %[-'0][W][.P]{doxX} of e f l m n (old file)",
    "                   or E F L M N (new file)",
    "    --LTYPE-line-format=LFMT  format LTYPE (old, new or unchanged) lines with",
    "                   LFMT: %l %L text, %c'C', %%, printf-style line number n;",
    "                   --line-format=LFMT sets all three",
    "    -T, --initial-tab  make tabs line up by starting lines with a tab",
    "    --left-column  output only the left column of common lines (with -y)",
    "    --from-file=FILE  compare FILE to each operand (FILE may be a directory)",
    "    --to-file=FILE    compare each operand to FILE",
    "    --no-dereference  do not follow symbolic links",
    "    -t, --expand-tabs  expand tabs to spaces in output; --tabsize=NUM (default 8)",
    "    --suppress-common-lines  do not output common lines (with -y)",
    "    --strip-trailing-cr      strip trailing carriage return on input",
    "    --color[=WHEN]  colour the output; WHEN is never, always or auto (the",
    "                    default for --color); --palette=PALETTE as DIFF_COLORS",
    "                    (default rs=0:hd=1:ad=32:de=31:ln=36)",
    "    -F RE, --show-function-line=RE  show the last line before a hunk matching RE",
    "    -a, --text     treat all files as text",
    "    -L LABEL, --label LABEL  use LABEL instead of a file name and time (up to two)",
    "    -d, --minimal  try hard to find a smaller set of changes: no shortcut",
    "                   for lines found in only one file, and no cost limit",
    "    --horizon-lines=NUM  keep NUM lines of the common prefix and suffix",
    "                   in the comparison (-c and -u keep their context)",
    "    --speed-large-files  accepted; the cost limit is always on without -d",
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
    "bashdiff [-abBcdeinNpqrstTuwyZ] [-C NUM|-U NUM|-D NAME] [-x PAT] [-X FILE] [-L LABEL] [-W NUM] FILE1 FILE2",
    0
};
