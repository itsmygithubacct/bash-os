/* SPDX-License-Identifier: MIT */
/* ptx.c — GNU-style ptx(1): produce a permuted index of file contents.
 *
 *   ptx [OPTION]... [INPUT]...     (GNU extensions, the default)
 *   ptx -G [OPTION]... [INPUT [OUTPUT]]
 *
 * Every word of the input becomes a keyword line: the text before it, a
 * gap, then the keyword and what follows, each part fitted to its half of
 * the line. Text that does not fit on its own side wraps to the other one
 * (the "tail" goes left of the before-context, the "head" right of the
 * keyword-and-after field); cut text is flagged with the truncation string.
 * Contexts are sentences in GNU mode, lines with -G or -r. Lines are sorted
 * by keyword (bytewise, or folded to upper case with -f), then by position.
 *
 * Options, as the coreutils manual documents them:
 *   -A, --auto-reference          FILE:LINE references
 *   -G, --traditional             System V ptx behaviour (roff output, a
 *                                 word is any run of non-blanks, an
 *                                 optional OUTPUT operand)
 *   -F, --flag-truncation=STRING  truncation flag (default "/")
 *   -M, --macro-name=STRING       roff/TeX macro name (default "xx")
 *   -O, --format=roff             roff output;  -T, --format=tex  TeX output
 *   -R, --right-side-refs         references after the right context
 *   -S, --sentence-regexp=REGEXP  end of a context (Emacs regex syntax)
 *   -W, --word-regexp=REGEXP      what a keyword is (Emacs regex syntax)
 *   -b, --break-file=FILE         the characters in FILE separate words
 *   -f, --ignore-case             fold to upper case when sorting/matching
 *   -g, --gap-size=NUMBER         columns between the fields (default 3)
 *   -i, --ignore-file=FILE        words (one per line) that are never keys
 *   -o, --only-file=FILE          only these words are keys
 *   -r, --references              the first field of each line is its ref
 *   -t, --typeset-mode            accepted; not implemented, as in GNU
 *   -w, --width=NUMBER            output width, references excluded (72)
 *
 * Regexes are GNU Emacs syntax translated to POSIX extended syntax, matched
 * with regexec under REG_NEWLINE (so ^ and $ also match at line breaks).
 * Equal keywords sort by position; from different files, in file order (GNU
 * compares the addresses of its file buffers, so its order there follows the
 * heap layout). Written for bash-os from the coreutils manual and observed
 * GNU behaviour.
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
#include <ctype.h>
#include <fcntl.h>
#include <regex.h>
#include <stdint.h>
#include <limits.h>

#include "loadables.h"
#include "gnu-longopt.h"

typedef struct { long s, e; } px_span;

typedef struct {
    int file;           /* index into px_state.text */
    long key, len;      /* keyword offset and length */
    long left, right;   /* context bounds, relative to key (left <= 0) */
    long ref;           /* auto: line count; -r: reference offset vs key */
} px_occ;

typedef struct { char *buf; long len; } px_text;

typedef struct { char **w; size_t n; } px_words;

enum { PX_DUMB, PX_ROFF, PX_TEX };

typedef struct {
    int gnu, auto_ref, input_ref, right_ref, fold, format;
    long width, gap;
    const char *trunc, *macro;
    size_t trunc_len;
    regex_t word_re, ctx_re;
    int have_word_re, have_ctx_re;
    unsigned char fastmap[256];   /* word constituents without -W */
    unsigned char edited[256];    /* characters print_field rewrites */
    px_words ignore, only;
    int have_ignore, have_only;
    px_text *text; char **names; int ntext;
    long *line_count;             /* cumulative line count at each file end */
    px_occ *occ; size_t nocc, cap;
    long max_word, total_lines, ref_width;
    long half, before_max, keyafter_max;
    FILE *out;
} px_state;

/* ---- character classes and cursor moves ---------------------------------- */

static int px_space (unsigned char c) { return isspace (c) != 0; }

static void
px_skip_white (const char *b, long *cp, long limit)
{
    while (*cp < limit && px_space ((unsigned char) b[*cp])) (*cp)++;
}

static void
px_skip_white_back (const char *b, long *cp, long start)
{
    while (*cp > start && px_space ((unsigned char) b[*cp - 1])) (*cp)--;
}

static void
px_skip_nonwhite (const char *b, long *cp, long limit)
{
    while (*cp < limit && !px_space ((unsigned char) b[*cp])) (*cp)++;
}

/* Match RE against [at, limit) of B, which must be writable and have room
   for the temporary terminator. Returns the match offsets via SO and EO
   relative to AT, or 0 when there is none. */
static int
px_search (regex_t *re, char *b, long at, long limit, long *so, long *eo)
{
    char saved = b[limit];
    regmatch_t m;
    int r;

    b[limit] = '\0';
    r = regexec (re, b + at, 1, &m, 0);
    b[limit] = saved;
    if (r != 0) return 0;
    *so = m.rm_so; *eo = m.rm_eo;
    return 1;
}

/* Advance over one word, or one character that is not part of a word. */
static void
px_skip_something (px_state *st, char *b, long *cp, long limit)
{
    if (*cp >= limit) { (*cp)++; return; }
    if (st->have_word_re) {
        long so, eo;
        if (px_search (&st->word_re, b, *cp, limit, &so, &eo) && so == 0 && eo > 0)
            *cp += eo;
        else
            (*cp)++;
    } else if (st->fastmap[(unsigned char) b[*cp]]) {
        while (*cp < limit && st->fastmap[(unsigned char) b[*cp]]) (*cp)++;
    } else
        (*cp)++;
}

/* ---- Emacs regex syntax -> POSIX ERE ------------------------------------- */

/* Emacs syntax: \( \) \| group and alternate, bare ( ) | { } are literal,
   * + ? are operators, \w \W are word classes, \` \' anchor the subject,
   \< \> \b \B are word boundaries. ERE has no \< \> \b \B equivalents in
   POSIX; they are dropped (a boundary always holds where the words of
   ptx's default word set meet). Brackets are copied as they are. */
static char *
px_emacs_to_ere (const char *re)
{
    size_t n = strlen (re), o = 0;
    char *out = malloc (n * 12 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        char c = re[i];
        if (c == '[') {
            size_t j = i + 1;
            if (j < n && re[j] == '^') j++;
            if (j < n && re[j] == ']') j++;
            while (j < n && re[j] != ']') {
                if (re[j] == '[' && j + 1 < n && (re[j+1] == ':' || re[j+1] == '.' || re[j+1] == '=')) {
                    char close = re[j+1];
                    j += 2;
                    while (j + 1 < n && !(re[j] == close && re[j+1] == ']')) j++;
                    j += 2;
                } else
                    j++;
            }
            if (j >= n) { out[o++] = '['; continue; }   /* regcomp reports it */
            memcpy (out + o, re + i, j - i + 1); o += j - i + 1; i = j;
            continue;
        }
        if (c == '\\' && i + 1 < n) {
            char d = re[++i];
            switch (d) {
            case '(': out[o++] = '('; break;
            case ')': out[o++] = ')'; break;
            case '|': out[o++] = '|'; break;
            case '{': out[o++] = '{'; break;
            case '}': out[o++] = '}'; break;
            case 'w': memcpy (out + o, "[[:alnum:]_]", 12); o += 12; break;
            case 'W': memcpy (out + o, "[^[:alnum:]_]", 13); o += 13; break;
            case '`': out[o++] = '^'; break;
            case '\'': out[o++] = '$'; break;
            case '<': case '>': case 'b': case 'B': break;
            case 'n': out[o++] = '\n'; break;
            case 't': out[o++] = '\t'; break;
            default:
                if (d >= '1' && d <= '9') { out[o++] = '\\'; out[o++] = d; }
                else if (isalnum ((unsigned char) d)) out[o++] = d;
                else { out[o++] = '\\'; out[o++] = d; }
            }
            continue;
        }
        switch (c) {
        case '(': case ')': case '|': case '{': case '}':
            out[o++] = '\\'; out[o++] = c; break;
        default:
            out[o++] = c;
        }
    }
    out[o] = '\0';
    return out;
}

static int
px_compile (px_state *st, regex_t *re, const char *emacs)
{
    char *ere = px_emacs_to_ere (emacs);
    int r;
    if (!ere) { builtin_error ("memory exhausted"); return -1; }
    r = regcomp (re, ere, REG_EXTENDED | REG_NEWLINE | (st->fold ? REG_ICASE : 0));
    free (ere);
    if (r != 0) {
        char msg[256];
        regerror (r, re, msg, sizeof msg);
        builtin_error ("%s (for regexp '%s')", msg, emacs);
        return -1;
    }
    return 0;
}

/* ---- input --------------------------------------------------------------- */

/* Read FILE ("-" or NULL = stdin) into a buffer with one spare byte. */
static int
px_slurp (const char *file, px_text *t)
{
    int fd = (!file || !strcmp (file, "-")) ? 0 : open (file, O_RDONLY);
    size_t cap = 8192, len = 0;
    char *buf;

    if (fd < 0) { builtin_error ("%s: %s", file, strerror (errno)); return -1; }
    buf = malloc (cap + 1);
    if (!buf) { if (fd) close (fd); builtin_error ("memory exhausted"); return -1; }
    for (;;) {
        ssize_t r;
        if (len == cap) {
            char *nb = realloc (buf, cap * 2 + 1);
            if (!nb) { free (buf); if (fd) close (fd); builtin_error ("memory exhausted"); return -1; }
            buf = nb; cap *= 2;
        }
        r = read (fd, buf + len, cap - len);
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("%s: %s", file && strcmp (file, "-") ? file : "-", strerror (errno));
            free (buf); if (fd) close (fd); return -1;
        }
        if (r == 0) break;
        len += (size_t) r;
    }
    if (fd) close (fd);
    buf[len] = '\0';
    t->buf = buf; t->len = (long) len;
    return 0;
}

static int
px_cmp_bytes (const px_state *st, const char *a, long al, const char *b, long bl)
{
    long n = al < bl ? al : bl;
    for (long i = 0; i < n; i++) {
        int x = (unsigned char) a[i], y = (unsigned char) b[i];
        if (st->fold) { x = toupper (x); y = toupper (y); }
        if (x != y) return x - y;
    }
    return (al > bl) - (al < bl);
}

static const px_state *px_sort_state;

static int
px_cmp_word_ptrs (const void *a, const void *b)
{
    const char *x = *(char *const *) a, *y = *(char *const *) b;
    return px_cmp_bytes (px_sort_state, x, (long) strlen (x), y, (long) strlen (y));
}

/* A word list: one word per line; empty lines are skipped. */
static int
px_read_words (px_state *st, const char *file, px_words *w)
{
    px_text t;
    if (px_slurp (file, &t) < 0) return -1;
    w->w = NULL; w->n = 0;
    for (long i = 0; i < t.len; ) {
        long s = i;
        while (i < t.len && t.buf[i] != '\n') i++;
        if (i > s) {
            char **nw = realloc (w->w, (w->n + 1) * sizeof *nw);
            if (!nw) { free (t.buf); builtin_error ("memory exhausted"); return -1; }
            w->w = nw;
            w->w[w->n] = strndup (t.buf + s, (size_t) (i - s));
            if (!w->w[w->n]) { free (t.buf); builtin_error ("memory exhausted"); return -1; }
            w->n++;
        }
        if (i < t.len) i++;
    }
    free (t.buf);
    px_sort_state = st;
    qsort (w->w, w->n, sizeof *w->w, px_cmp_word_ptrs);
    return 0;
}

static int
px_in_words (const px_state *st, const px_words *w, const char *s, long len)
{
    size_t lo = 0, hi = w->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = px_cmp_bytes (st, s, len, w->w[mid], (long) strlen (w->w[mid]));
        if (c == 0) return 1;
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return 0;
}

static void
px_free_words (px_words *w)
{
    for (size_t i = 0; i < w->n; i++) free (w->w[i]);
    free (w->w);
    w->w = NULL; w->n = 0;
}

/* The characters of FILE (and, in traditional mode, blanks) end words. */
static int
px_read_breaks (px_state *st, const char *file)
{
    px_text t;
    if (px_slurp (file, &t) < 0) return -1;
    memset (st->fastmap, 1, sizeof st->fastmap);
    for (long i = 0; i < t.len; i++) st->fastmap[(unsigned char) t.buf[i]] = 0;
    if (!st->gnu) st->fastmap[' '] = st->fastmap['\t'] = st->fastmap['\n'] = 0;
    free (t.buf);
    return 0;
}

/* ---- finding the keywords -------------------------------------------------- */

static int
px_add (px_state *st, px_occ *o)
{
    if (st->nocc == st->cap) {
        size_t nc = st->cap ? st->cap * 2 : 256;
        px_occ *n = realloc (st->occ, nc * sizeof *n);
        if (!n) { builtin_error ("memory exhausted"); return -1; }
        st->occ = n; st->cap = nc;
    }
    st->occ[st->nocc++] = *o;
    return 0;
}

static int
px_scan (px_state *st, int fi)
{
    char *b = st->text[fi].buf;
    long end = st->text[fi].len;
    long line_start = 0, line_scan = 0, ref_len = 0, next;

    if (st->input_ref) {
        px_skip_nonwhite (b, &line_scan, end);
        ref_len = line_scan - line_start;
    }
    for (long cursor = 0; cursor < end; cursor = next) {
        long ctx_start = cursor, ctx_end;
        next = end;
        if (st->have_ctx_re) {
            long so, eo;
            if (px_search (&st->ctx_re, b, cursor, end, &so, &eo)) {
                if (eo == 0) {
                    builtin_error ("error: regular expression has a match of length zero");
                    return -1;
                }
                next = cursor + eo;
            }
        }
        ctx_end = next;
        px_skip_white_back (b, &ctx_end, ctx_start);

        for (;;) {
            long ws, we;
            if (st->have_word_re) {
                long so, eo;
                if (cursor >= ctx_end || !px_search (&st->word_re, b, cursor, ctx_end, &so, &eo))
                    break;
                ws = cursor + so; we = cursor + eo;
            } else {
                long sc = cursor;
                while (sc < ctx_end && !st->fastmap[(unsigned char) b[sc]]) sc++;
                if (sc >= ctx_end) break;
                ws = sc;
                while (sc < ctx_end && st->fastmap[(unsigned char) b[sc]]) sc++;
                we = sc;
            }
            cursor = ws;
            if (we == ws) { cursor++; continue; }
            cursor = we;
            if (we - ws > st->max_word) st->max_word = we - ws;

            if (st->input_ref) {
                while (line_scan < ws) {
                    if (b[line_scan] == '\n') {
                        st->total_lines++;
                        line_start = ++line_scan;
                        px_skip_nonwhite (b, &line_scan, end);
                        ref_len = line_scan - line_start;
                    } else
                        line_scan++;
                }
                if (line_scan > ws) continue;   /* the word is the reference */
            }
            if (st->have_ignore && px_in_words (st, &st->ignore, b + ws, we - ws)) continue;
            if (st->have_only && !px_in_words (st, &st->only, b + ws, we - ws)) continue;

            px_occ o = { fi, ws, we - ws, 0, 0, 0 };
            if (st->auto_ref) {
                while (line_scan < ws) {
                    if (b[line_scan] == '\n') {
                        st->total_lines++;
                        line_start = ++line_scan;
                        px_skip_nonwhite (b, &line_scan, end);
                    } else
                        line_scan++;
                }
                o.ref = st->total_lines;
            } else if (st->input_ref) {
                o.ref = line_start - ws;
                if (ref_len > st->ref_width) st->ref_width = ref_len;
            }
            if (st->input_ref && line_start == ctx_start) {
                px_skip_nonwhite (b, &ctx_start, ctx_end);
                px_skip_white (b, &ctx_start, ctx_end);
            }
            o.left = ctx_start - ws;
            o.right = ctx_end - ws;
            if (px_add (st, &o) < 0) return -1;
        }
    }
    return 0;
}

static int
px_cmp_occ (const void *a, const void *b)
{
    const px_occ *x = a, *y = b;
    const px_state *st = px_sort_state;
    int c = px_cmp_bytes (st, st->text[x->file].buf + x->key, x->len,
                          st->text[y->file].buf + y->key, y->len);
    if (c) return c;
    if (x->file != y->file) return x->file < y->file ? -1 : 1;
    return (x->key > y->key) - (x->key < y->key);
}

/* ---- output ---------------------------------------------------------------- */

static void
px_spaces (px_state *st, long n)
{
    while (n-- > 0) putc (' ', st->out);
}

static void
px_field (px_state *st, const char *b, px_span f)
{
    for (long i = f.s; i < f.e; i++) {
        unsigned char c = (unsigned char) b[i];
        if (!st->edited[c]) { putc (c, st->out); continue; }
        switch (c) {
        case '"': fputs ("\"\"", st->out); break;
        case '$': case '%': case '&': case '#': case '_':
            putc ('\\', st->out); putc (c, st->out); break;
        case '{': case '}': fprintf (st->out, "$\\%c$", c); break;
        case '\\': fputs ("\\backslash{}", st->out); break;
        default: putc (' ', st->out);
        }
    }
}

static void
px_flag (px_state *st, int on)
{
    if (on) fputs (st->trunc, st->out);
}

static void
px_line (px_state *st, const px_occ *o)
{
    char *b = st->text[o->file].buf;
    long tlen = st->text[o->file].len, ks = o->key;
    long lcs = ks + o->left, rce = ks + o->right, cur, lfs;
    long tl = (long) st->trunc_len;
    px_span ka, before, tail = { 0, 0 }, head = { 0, 0 }, ref = { 0, 0 };
    int ka_t, b_t, t_t = 0, h_t = 0, have_ref = st->auto_ref || st->input_ref;
    char refbuf[PATH_MAX + 32];
    int use_refbuf = 0;

    ka.s = ks; ka.e = ks + o->len;
    cur = ka.e;
    while (cur < rce && cur <= ks + st->keyafter_max) {
        ka.e = cur;
        px_skip_something (st, b, &cur, rce);
    }
    if (cur <= ks + st->keyafter_max) ka.e = cur;
    ka_t = st->trunc && ka.e < rce;
    px_skip_white_back (b, &ka.e, ka.s);

    if (-o->left > st->half + st->max_word) {
        lfs = ks - (st->half + st->max_word);
        px_skip_something (st, b, &lfs, ks);
    } else
        lfs = lcs;

    before.s = lfs; before.e = ks;
    px_skip_white_back (b, &before.e, before.s);
    while (before.s + st->before_max < before.e)
        px_skip_something (st, b, &before.s, before.e);
    if (st->trunc) {
        long c = before.s;
        px_skip_white_back (b, &c, 0);
        b_t = c > lcs;
    } else
        b_t = 0;
    px_skip_white (b, &before.s, tlen);

    long tail_max = st->before_max - (before.e - before.s) - st->gap;
    if (tail_max > 0) {
        tail.s = ka.e;
        px_skip_white (b, &tail.s, tlen);
        tail.e = tail.s; cur = tail.e;
        while (cur < rce && cur < tail.s + tail_max) {
            tail.e = cur;
            px_skip_something (st, b, &cur, rce);
        }
        if (cur < tail.s + tail_max) tail.e = cur;
        if (tail.e > tail.s) {
            ka_t = 0;
            t_t = st->trunc && tail.e < rce;
        }
        px_skip_white_back (b, &tail.e, tail.s);
    }

    long head_max = st->keyafter_max - (ka.e - ka.s) - st->gap;
    if (head_max > 0) {
        head.e = before.s;
        px_skip_white_back (b, &head.e, 0);
        head.s = lfs;
        while (head.s + head_max < head.e)
            px_skip_something (st, b, &head.s, head.e);
        if (head.e > head.s) {
            b_t = 0;
            h_t = st->trunc && head.s > lcs;
        }
        px_skip_white (b, &head.s, head.e);
    }

    if (st->auto_ref) {
        long ordinal = o->ref + 1 - (o->file > 0 ? st->line_count[o->file - 1] : 0);
        snprintf (refbuf, sizeof refbuf, "%s:%ld", st->names[o->file] ? st->names[o->file] : "", ordinal);
        use_refbuf = 1;
    } else if (st->input_ref) {
        ref.s = ks + o->ref; ref.e = ref.s;
        px_skip_nonwhite (b, &ref.e, rce);
    }
    long reflen = use_refbuf ? (long) strlen (refbuf) : ref.e - ref.s;
#define PX_REF() (use_refbuf ? (void) fputs (refbuf, st->out) : px_field (st, b, ref))

    long tlen_ = tail.e > tail.s ? tail.e - tail.s : 0;
    long hlen_ = head.e > head.s ? head.e - head.s : 0;
    if (tail.e < tail.s) tail.e = tail.s;
    if (head.e < head.s) head.e = head.s;

    if (st->format == PX_ROFF) {
        fprintf (st->out, ".%s \"", st->macro);
        px_field (st, b, tail); px_flag (st, t_t);
        fputs ("\" \"", st->out);
        px_flag (st, b_t); px_field (st, b, before);
        fputs ("\" \"", st->out);
        px_field (st, b, ka); px_flag (st, ka_t);
        fputs ("\" \"", st->out);
        px_flag (st, h_t); px_field (st, b, head);
        putc ('"', st->out);
        if (have_ref) { fputs (" \"", st->out); PX_REF (); putc ('"', st->out); }
        putc ('\n', st->out);
        return;
    }
    if (st->format == PX_TEX) {
        px_span key = ka, after = ka;
        long c = ka.s;
        px_skip_something (st, b, &c, ka.e);
        if (c > ka.e) c = ka.e;
        key.e = c; after.s = c;
        fprintf (st->out, "\\%s {", st->macro);
        px_field (st, b, tail); fputs ("}{", st->out);
        px_field (st, b, before); fputs ("}{", st->out);
        px_field (st, b, key); fputs ("}{", st->out);
        px_field (st, b, after); fputs ("}{", st->out);
        px_field (st, b, head); putc ('}', st->out);
        if (have_ref) { putc ('{', st->out); PX_REF (); putc ('}', st->out); }
        putc ('\n', st->out);
        return;
    }

    /* Without -R the reference column and its gap come first, even when
       there are no references (then it is just the gap). */
    if (!st->right_ref) {
        PX_REF ();
        if (st->auto_ref) {
            putc (':', st->out);
            px_spaces (st, st->ref_width + st->gap - reflen - 1);
        } else
            px_spaces (st, st->ref_width + st->gap - reflen);
    }
    if (tlen_ > 0) {
        px_field (st, b, tail); px_flag (st, t_t);
        px_spaces (st, st->half - st->gap - (before.e - before.s) - (b_t ? tl : 0)
                       - tlen_ - (t_t ? tl : 0));
    } else
        px_spaces (st, st->half - st->gap - (before.e - before.s) - (b_t ? tl : 0));
    px_flag (st, b_t); px_field (st, b, before);
    px_spaces (st, st->gap);
    px_field (st, b, ka); px_flag (st, ka_t);
    if (hlen_ > 0) {
        px_spaces (st, st->half - (ka.e - ka.s) - (ka_t ? tl : 0) - hlen_ - (h_t ? tl : 0));
        px_flag (st, h_t); px_field (st, b, head);
    } else if (have_ref && st->right_ref)
        px_spaces (st, st->half - (ka.e - ka.s) - (ka_t ? tl : 0));
    if (have_ref && st->right_ref) {
        px_spaces (st, st->gap);
        PX_REF ();
    }
    putc ('\n', st->out);
#undef PX_REF
}

/* ---- the builtin ----------------------------------------------------------- */

static int
px_number (const char *what, const char *v, long *out)
{
    char *end;
    long n;
    errno = 0;
    n = strtol (v, &end, 10);
    if (!*v || *end || errno || n < 0) {
        builtin_error ("invalid %s: '%s'", what, v);
        return -1;
    }
    *out = n;
    return 0;
}

enum { PX_OPT_FORMAT = BOS_OPT_FIRST };

int
ptx_builtin (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "auto-reference", BOS_NO_ARG, 'A' },
        { "traditional", BOS_NO_ARG, 'G' },
        { "flag-truncation", BOS_REQ_ARG, 'F' },
        { "macro-name", BOS_REQ_ARG, 'M' },
        { "format", BOS_REQ_ARG, PX_OPT_FORMAT },
        { "right-side-refs", BOS_NO_ARG, 'R' },
        { "sentence-regexp", BOS_REQ_ARG, 'S' },
        { "word-regexp", BOS_REQ_ARG, 'W' },
        { "break-file", BOS_REQ_ARG, 'b' },
        { "ignore-case", BOS_NO_ARG, 'f' },
        { "gap-size", BOS_REQ_ARG, 'g' },
        { "ignore-file", BOS_REQ_ARG, 'i' },
        { "only-file", BOS_REQ_ARG, 'o' },
        { "references", BOS_NO_ARG, 'r' },
        { "typeset-mode", BOS_NO_ARG, 't' },
        { "width", BOS_REQ_ARG, 'w' },
        { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    px_state st;
    const char *word_re = NULL, *ctx_re = NULL, *break_file = NULL;
    const char *ignore_file = NULL, *only_file = NULL;
    int format = -1, c, rc = EXECUTION_FAILURE;
    bos_getopt g;

    memset (&st, 0, sizeof st);
    st.gnu = 1; st.width = 72; st.gap = 3; st.trunc = "/"; st.macro = "xx";
    st.out = stdout;

    bos_getopt_init (&g, "ptx", "AF:GM:ORS:TW:b:fg:i:o:rtw:", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
        case 'A': st.auto_ref = 1; break;
        case 'G': st.gnu = 0; break;
        case 'F': st.trunc = g.optarg; break;
        case 'M': st.macro = g.optarg; break;
        case 'O': format = PX_ROFF; break;
        case 'T': format = PX_TEX; break;
        case PX_OPT_FORMAT:
            if (!strcmp (g.optarg, "roff")) format = PX_ROFF;
            else if (!strcmp (g.optarg, "tex")) format = PX_TEX;
            else {
                builtin_error ("invalid argument '%s' for '--format'", g.optarg);
                fputs ("Valid arguments are:\n  - 'roff'\n  - 'tex'\n", stderr);
                bos_try_help ("ptx");
                goto done;
            }
            break;
        case 'R': st.right_ref = 1; break;
        case 'S': ctx_re = g.optarg; break;
        case 'W': word_re = g.optarg; break;
        case 'b': break_file = g.optarg; break;
        case 'f': st.fold = 1; break;
        case 'g':
            if (px_number ("gap width", g.optarg, &st.gap) < 0 || st.gap == 0) {
                if (st.gap == 0) builtin_error ("invalid gap width: '%s'", g.optarg);
                goto done;
            }
            break;
        case 'i': ignore_file = g.optarg; break;
        case 'o': only_file = g.optarg; break;
        case 'r': st.input_ref = 1; break;
        case 't': break;
        case 'w':
            if (px_number ("line width", g.optarg, &st.width) < 0 || st.width == 0) {
                if (st.width == 0) builtin_error ("invalid line width: '%s'", g.optarg);
                goto done;
            }
            break;
        case BOS_OPT_HELP:
            builtin_help ();
            rc = EXECUTION_SUCCESS;
            goto done;
        case BOS_OPT_VERSION:
            printf ("ptx (bash-os builtin, Bash %s)\n", dist_version);
            rc = EXECUTION_SUCCESS;
            goto done;
        default:
            goto done;
        }
    }

    st.format = format >= 0 ? format : st.gnu ? PX_DUMB : PX_ROFF;
    /* Traditional mode: the second operand is the output file (even "-",
       which names a file), which GNU opens, creating it, before it looks
       at any further operand. */
    if (!st.gnu && g.noperands >= 2) {
        st.out = fopen (g.operands[1], "w");
        if (!st.out) { builtin_error ("%s: %s", g.operands[1], strerror (errno)); st.out = stdout; goto done; }
    }
    if (!st.gnu && g.noperands > 2) {
        builtin_error ("extra operand '%s'", g.operands[2]);
        bos_try_help ("ptx");
        goto done;
    }

    /* Word lists and the break file are read before the input. */
    if (break_file && px_read_breaks (&st, break_file) < 0) goto done;
    if (ignore_file) {
        if (px_read_words (&st, ignore_file, &st.ignore) < 0) goto done;
        st.have_ignore = 1;
    }
    if (only_file) {
        if (px_read_words (&st, only_file, &st.only) < 0) goto done;
        st.have_only = 1;
    }

    if (ctx_re) {
        if (*ctx_re) {
            if (px_compile (&st, &st.ctx_re, ctx_re) < 0) goto done;
            st.have_ctx_re = 1;
        }
    } else {
        if (px_compile (&st, &st.ctx_re, st.gnu && !st.input_ref
                        ? "[.?!][]\"')}]*\\($\\|\t\\|  \\)[ \t\n]*" : "\n") < 0)
            goto done;
        st.have_ctx_re = 1;
    }
    if (word_re && *word_re) {
        if (px_compile (&st, &st.word_re, word_re) < 0) goto done;
        st.have_word_re = 1;
    } else if (!break_file) {
        for (int ch = 0; ch < 256; ch++)
            st.fastmap[ch] = st.gnu ? (isalpha (ch) != 0) : 1;
        if (!st.gnu) st.fastmap[' '] = st.fastmap['\t'] = st.fastmap['\n'] = 0;
    }

    /* Inputs: every operand in GNU mode; in traditional mode the first is
       the input and the second the output. */
    int nin = st.gnu ? g.noperands : (g.noperands > 0 ? 1 : 0);
    if (nin == 0) nin = 1;
    st.text = calloc ((size_t) nin, sizeof *st.text);
    st.names = calloc ((size_t) nin, sizeof *st.names);
    st.line_count = calloc ((size_t) nin, sizeof *st.line_count);
    if (!st.text || !st.names || !st.line_count) { builtin_error ("memory exhausted"); goto done; }
    for (int i = 0; i < nin; i++) {
        const char *name = g.noperands ? g.operands[i] : NULL;
        if (name && !strcmp (name, "-")) name = NULL;
        st.names[i] = (char *) name;
        if (px_slurp (name, &st.text[i]) < 0) goto done;
        st.ntext = i + 1;
        if (px_scan (&st, i) < 0) goto done;
        st.total_lines++;
        st.line_count[i] = st.total_lines;
    }

    px_sort_state = &st;
    qsort (st.occ, st.nocc, sizeof *st.occ, px_cmp_occ);

    /* Field widths. */
    if (st.auto_ref) {
        st.ref_width = 0;
        for (int i = 0; i < st.ntext; i++) {
            long ord = st.line_count[i] + 1 - (i > 0 ? st.line_count[i - 1] : 0);
            long w = snprintf (NULL, 0, ":%ld", ord) + (st.names[i] ? (long) strlen (st.names[i]) : 0);
            if (w > st.ref_width) st.ref_width = w;
        }
    }
    long width = st.width;
    if ((st.auto_ref || st.input_ref) && !st.right_ref)
        width -= st.ref_width + st.gap;
    if (width < 0) width = 0;
    st.half = width / 2;
    st.before_max = st.half - st.gap;
    st.keyafter_max = st.half;
    if (st.trunc && *st.trunc) st.trunc_len = strlen (st.trunc);
    else st.trunc = NULL;
    if (st.gnu) {
        st.before_max -= 2 * (long) st.trunc_len;
        if (st.before_max < 0) st.before_max = 0;
        st.keyafter_max -= 2 * (long) st.trunc_len;
    } else
        st.keyafter_max -= 2 * (long) st.trunc_len + 1;

    for (int ch = 0; ch < 256; ch++) st.edited[ch] = isspace (ch) != 0;
    st.edited['\f'] = 1;
    if (st.format == PX_ROFF) st.edited['"'] = 1;
    else if (st.format == PX_TEX)
        for (const char *p = "$%&#_{}\\"; *p; p++) st.edited[(unsigned char) *p] = 1;

    for (size_t i = 0; i < st.nocc; i++) {
        px_line (&st, &st.occ[i]);
        QUIT;
    }
    rc = EXECUTION_SUCCESS;
    if (fflush (st.out) == EOF || ferror (st.out)) {
        builtin_error ("write error");
        rc = EXECUTION_FAILURE;
    }

done:
    if (st.out && st.out != stdout) fclose (st.out);
    else clearerr (stdout);
    if (st.have_word_re) regfree (&st.word_re);
    if (st.have_ctx_re) regfree (&st.ctx_re);
    px_free_words (&st.ignore);
    px_free_words (&st.only);
    for (int i = 0; i < st.ntext; i++) free (st.text[i].buf);
    free (st.text); free (st.names); free (st.line_count); free (st.occ);
    bos_getopt_free (&g);
    return rc;
}

char *ptx_doc[] = {
    "Produce a permuted index of file contents.",
    "",
    "    ptx [OPTION]... [INPUT]...   (without -G)",
    "    ptx -G [OPTION]... [INPUT [OUTPUT]]",
    "",
    "Output a permuted index, including context, of the words in the input",
    "files. With no INPUT, or when INPUT is -, read standard input.",
    "",
    "Options:",
    "    -A, --auto-reference           output automatically generated references",
    "    -G, --traditional              behave more like System V 'ptx'",
    "    -F, --flag-truncation=STRING   use STRING for flagging line truncations",
    "    -M, --macro-name=STRING        macro name to use instead of 'xx'",
    "    -O, --format=roff              generate output as roff directives",
    "    -R, --right-side-refs          put references at right, not counted in -w",
    "    -S, --sentence-regexp=REGEXP   for end of lines or end of sentences",
    "    -T, --format=tex               generate output as TeX directives",
    "    -W, --word-regexp=REGEXP       use REGEXP to match each keyword",
    "    -b, --break-file=FILE          word break characters in this FILE",
    "    -f, --ignore-case              fold lower case to upper case for sorting",
    "    -g, --gap-size=NUMBER          gap size in columns between output fields",
    "    -i, --ignore-file=FILE         read ignore word list from FILE",
    "    -o, --only-file=FILE           read only word list from this FILE",
    "    -r, --references               first field of each line is a reference",
    "    -t, --typeset-mode             - not implemented -",
    "    -w, --width=NUMBER             output width in columns, reference excluded",
    "        --help, --version",
    (char *)NULL
};

struct builtin ptx_struct = {
    "ptx",
    ptx_builtin,
    BUILTIN_ENABLED,
    ptx_doc,
    "ptx [OPTION]... [INPUT]...",
    0
};
