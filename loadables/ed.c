/* SPDX-License-Identifier: MIT */
/* ed.c — the standard line editor, with GNU ed's commands and messages.
 *
 *   ed [-EGlqrsv] [-p PROMPT] [--strip-trailing-cr] [FILE | !COMMAND]
 *
 * Written from the POSIX ed specification and the behaviour of GNU ed
 * 1.21.1 (compared black-box, command by command; no GNU source or
 * manual text is used). Addresses:
 * N, ., $, +N, -N, + and - (repeatable), an address followed by blanks and
 * a number (added), /RE/ and ?RE? (wrapping searches; // and ?? reuse the
 * last expression), 'x marks, ',' or '%' (1,$), ';' (.,$, and A;B makes A
 * current before B is read); more than two addresses keep the last two.
 *
 * Commands: (.)a (.,.)c (.,.)d e E f (1,$)g/RE/LIST (1,$)G/RE/ h H (.)i
 * (.,.+1)j (.)kx (.,.)l (.,.)m(.) (.,.)n (.,.)p P q Q ($)r (.,.)s (.,.)t(.)
 * u (1,$)v (1,$)V (1,$)w (1,$)wq (1,$)W (.)x (.,.)y (.+1)zN ($)= !CMD #
 * and a bare address (print). l, n and p may follow most commands.
 * s/RE/REPL/ takes g, a count N, p, l and n; REPL may use & and \1..\9,
 * \ followed by a newline splits the line, a lone % is the previous
 * replacement and a missing final delimiter prints the line. s alone
 * repeats the last substitution (g and p toggle, r uses the last search,
 * N picks the Nth match). g/v run a command list (lines continued with
 * \) on each matching line, G/V read one command per matching line, &
 * repeating the previous one. u undoes (and redoes) the last command,
 * a whole g included; x puts the lines that d, c, j, s or y last saved.
 *
 * Errors print "?" on standard output; h shows the reason and H (or -v)
 * shows each one. File errors also go to standard error, and a FILE that
 * cannot be read is reported there instead of with "?". q, e or the end
 * of input on a modified buffer warn once. When standard input is a
 * regular file (a script), the first error ends ed, messages name the
 * script line, and a FILE that cannot be loaded runs nothing (status 2).
 * The exit status is 0, 1 after any failed command (-l keeps 0) or an
 * unreadable FILE, and 2 when the end of input found unsaved changes. Shell commands run with /bin/sh -c; -r refuses them
 * and names with a slash. Lines may hold NUL bytes. On non-glibc C
 * libraries regular expressions use sed's copy of the GNU engine, so \+,
 * \?, \| and \< mean what they mean in GNU ed.
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
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
/* GNU ed uses glibc's engine and its BRE extensions. Non-glibc C libraries
   (musl) lack those; such builds use sed's private copy of the GNU regex
   engine. BASHED_PORTABLE_REGEX selects that engine on glibc too, so the
   same path can be checked on the host. */
#if defined (__GLIBC__) && !defined (BASHED_PORTABLE_REGEX)
#  include <regex.h>
#else
#  include "sed-regex.h"
#endif

#include "loadables.h"
#include "child-wait.h"

#define ED_OK     0
#define ED_QUIT   1
#define ED_ERR   -1     /* errmsg says why */
#define ED_EMOD  -2     /* "Warning: buffer modified" */

#define PF_P 1
#define PF_L 2
#define PF_N 4

typedef struct ed_line {
    struct ed_line *prev, *next;
    char *text;                 /* NUL-terminated; may also hold NUL bytes */
    size_t len;
    unsigned char live;         /* linked into the buffer */
    unsigned char active;       /* selected by the running g, v, G or V */
    unsigned char doomed;       /* collected for freeing */
} ed_line;

/* One change made by a command: COUNT lines linked after line ADDR
   (INSERTED) or unlinked from after it. Undo applies the inverse ops. */
typedef struct {
    int inserted;
    long addr;
    ed_line **v;
    long count, cap;
} ed_op;

typedef struct { char *s; size_t len, cap; } ed_str;

/* Where command lines and input text come from: standard input, or the
   command list of a global command. */
typedef struct { const char *buf; size_t len, pos; } ed_src;

typedef struct { regex_t re; int refs; } ed_regex;

typedef struct {
    ed_line head;               /* head.next is line 1, head.prev is $ */
    long last, cur;
    long cache_n;               /* a line whose node is known */
    ed_line *cache_p;
    long hint_n;                /* another, kept by g at its current line */
    ed_line *hint_p;
    ed_line *marks[26];
    int modified;
    char *filename;

    ed_op *ops;                 /* the last command's changes */
    size_t nops, capops;
    long undo_cur;
    int undo_modified;

    ed_str *cut;                /* lines saved for x */
    size_t ncut;

    ed_regex *last_re;          /* the last expression used */
    ed_regex *sub_re;           /* the last substitution's */
    char *repl;
    size_t repl_len;
    int have_sub, sub_global, sub_flags, sub_print;
    long sub_count;                 /* sub_flags is the print mode, sub_print turns it on */

    int silent, verbose, loose, extended, restricted, quiet, strip_cr;
    const char *prompt;
    int prompt_on;
    int tty;

    const char *errmsg;
    char errbuf[256];
    int status;
    int warned;                 /* q and e already warned of these changes */
    int just_warned;            /* the last command was that warning */
    unsigned long changes;      /* counts edits, to see if a command made any */
    int in_global;
    unsigned long generation;   /* bumped when e replaces the buffer */
    long window;                /* lines z prints */
    long columns;               /* l wraps at this width */
    char *shell_last;           /* for !! */
    char *gcmd_last;            /* for & in G and V */

    char *in;                   /* standard input, read ahead */
    size_t in_len, in_pos;
    size_t in_unit;             /* bytes per read: 1 unless it can seek back */
    int in_eof;
    int script;                 /* standard input is a regular file */
    long in_lines;              /* lines read from it */

    char *tbuf;                 /* a line with NUL bytes made matchable */
    size_t tbuf_cap;
} ed_state;

static volatile sig_atomic_t ed_sigint;

static void
ed_on_sigint (int sig)
{
    (void) sig;
    ed_sigint = 1;
}

static int
ed_fail (ed_state *e, const char *msg)
{
    e->errmsg = msg;
    return ED_ERR;
}

/* --- strings --- */

static void
str_reserve (ed_str *s, size_t extra)
{
    if (s->len + extra + 1 > s->cap) {
        size_t nc = s->cap ? s->cap : 64;
        while (nc < s->len + extra + 1) nc *= 2;
        s->s = xrealloc (s->s, nc);
        s->cap = nc;
    }
}

static void
str_add (ed_str *s, const char *p, size_t n)
{
    str_reserve (s, n);
    memcpy (s->s + s->len, p, n);
    s->len += n;
    s->s[s->len] = '\0';
}

static void
str_addc (ed_str *s, int c)
{
    char ch = (char) c;
    str_add (s, &ch, 1);
}

static void
str_clear (ed_str *s)
{
    s->len = 0;
    str_reserve (s, 0);
    s->s[0] = '\0';
}

static char *
ed_strndup (const char *p, size_t n)
{
    char *s = xmalloc (n + 1);
    memcpy (s, p, n);
    s[n] = '\0';
    return s;
}

/* --- lines and the buffer --- */

static ed_line *
ed_newline (const char *text, size_t len)
{
    ed_line *l = xmalloc (sizeof *l);
    memset (l, 0, sizeof *l);
    l->text = ed_strndup (text, len);
    l->len = len;
    return l;
}

static void
ed_freeline (ed_state *e, ed_line *l)
{
    for (int i = 0; i < 26; i++)
        if (e->marks[i] == l) e->marks[i] = NULL;
    free (l->text);
    free (l);
}

/* The node of line N (0 is the head), walking from the nearest known node. */
static ed_line *
ed_node (ed_state *e, long n)
{
    long from = e->cache_n;
    ed_line *p = e->cache_p;
    long best = n > from ? n - from : from - n;
    long dh = n > e->hint_n ? n - e->hint_n : e->hint_n - n;
    if (dh < best) { best = dh; p = e->hint_p; from = e->hint_n; }
    if (n < best) { best = n; p = &e->head; from = 0; }
    if (e->last - n < best) { p = e->head.prev; from = e->last; }
    while (from < n) { p = p->next; from++; }
    while (from > n) { p = p->prev; from--; }
    e->cache_n = n;
    e->cache_p = p;
    return p;
}

/* The line number of node L, or -1 when it is not in the buffer. The walk
   starts at the hint g keeps (the next selected line is usually just
   after it), which is near in sequential use. */
static long
ed_index (ed_state *e, const ed_line *l)
{
    if (!l || !l->live) return -1;
    ed_line *f = e->hint_p, *b = e->hint_p;
    long nf = e->hint_n, nb = e->hint_n;
    for (;;) {
        if (f == l) { e->cache_n = nf; e->cache_p = f; return nf; }
        if (b == l) { e->cache_n = nb; e->cache_p = b; return nb; }
        int moved = 0;
        if (nf < e->last) { f = f->next; nf++; moved = 1; }
        if (nb > 0) { b = b->prev; nb--; moved = 1; }
        if (!moved) return -1;
    }
}

static void
ed_link (ed_state *e, long n, ed_line **v, long count)
{
    if (count <= 0) return;
    ed_line *at = ed_node (e, n), *after = at->next;
    for (long i = 0; i < count; i++) {
        v[i]->prev = i ? v[i - 1] : at;
        v[i]->next = i + 1 < count ? v[i + 1] : after;
        v[i]->live = 1;
    }
    at->next = v[0];
    after->prev = v[count - 1];
    if (e->hint_n > n) e->hint_n += count;
    e->last += count;
    e->modified = 1;
    e->changes++;
}

/* Unlink lines A..B into V (COUNT = B-A+1 slots). DELETING also drops them
   from a running global command. */
static void
ed_unlink (ed_state *e, long a, long b, ed_line **v, int deleting)
{
    ed_line *first = ed_node (e, a), *p = first;
    ed_line *before = first->prev;
    for (long i = 0; i < b - a + 1; i++) {
        v[i] = p;
        p = p->next;
        v[i]->live = 0;
        if (deleting) v[i]->active = 0;
    }
    before->next = p;
    p->prev = before;
    if (e->hint_n > b) e->hint_n -= b - a + 1;
    else if (e->hint_n >= a) { e->hint_n = a - 1; e->hint_p = before; }
    e->last -= b - a + 1;
    e->cache_n = a - 1;
    e->cache_p = before;
    e->modified = 1;
    e->changes++;
}

static void
ed_log (ed_state *e, int inserted, long addr, ed_line **v, long count)
{
    if (count <= 0) return;
    if (e->nops) {
        /* Consecutive lines appended one by one are one op. */
        ed_op *o = &e->ops[e->nops - 1];
        if (inserted && o->inserted && o->addr + o->count == addr) {
            if (o->count + count > o->cap) {
                while (o->count + count > o->cap) o->cap *= 2;
                o->v = xrealloc (o->v, o->cap * sizeof *o->v);
            }
            memcpy (o->v + o->count, v, count * sizeof *v);
            o->count += count;
            return;
        }
    }
    if (e->nops == e->capops) {
        e->capops = e->capops ? e->capops * 2 : 16;
        e->ops = xrealloc (e->ops, e->capops * sizeof *e->ops);
    }
    ed_op *o = &e->ops[e->nops++];
    o->inserted = inserted;
    o->addr = addr;
    o->count = o->cap = count;
    o->v = xmalloc (count * sizeof *v);
    memcpy (o->v, v, count * sizeof *v);
}

/* Insert copies of TEXTS after line N, logged for undo. */
static void
ed_insert (ed_state *e, long n, ed_line **v, long count)
{
    ed_link (e, n, v, count);
    ed_log (e, 1, n, v, count);
}

static void
ed_delete (ed_state *e, long a, long b)
{
    long count = b - a + 1;
    ed_line **v = xmalloc (count * sizeof *v);
    ed_unlink (e, a, b, v, 1);
    ed_log (e, 0, a - 1, v, count);
    free (v);
}

/* Forget the previous command's changes; this command starts a new log. */
static void
ed_undo_clear (ed_state *e)
{
    ed_line *dead = NULL;
    for (size_t i = 0; i < e->nops; i++) {
        ed_op *o = &e->ops[i];
        for (long j = 0; j < o->count; j++) {
            ed_line *l = o->v[j];
            if (!l->live && !l->doomed) {
                l->doomed = 1;
                l->prev = dead;     /* no longer needed for anything else */
                dead = l;
            }
        }
        free (o->v);
    }
    e->nops = 0;
    while (dead) {
        ed_line *next = dead->prev;
        ed_freeline (e, dead);
        dead = next;
    }
    e->undo_cur = e->cur;
    e->undo_modified = e->modified;
}

static void
ed_begin_change (ed_state *e)
{
    if (!e->in_global) ed_undo_clear (e);
}

static int
ed_undo (ed_state *e)
{
    if (!e->nops) return ed_fail (e, "Nothing to undo");
    int modified = e->modified;
    long cur = e->cur;
    ed_op *inv = xmalloc (e->nops * sizeof *inv);
    for (size_t i = 0; i < e->nops; i++) {
        ed_op *o = &e->ops[e->nops - 1 - i];
        if (o->inserted) ed_unlink (e, o->addr + 1, o->addr + o->count, o->v, 0);
        else ed_link (e, o->addr, o->v, o->count);
        inv[i] = *o;
        inv[i].inserted = !o->inserted;
    }
    free (e->ops);
    e->ops = inv;
    e->capops = e->nops;
    e->cur = e->undo_cur;
    e->undo_cur = cur;
    e->modified = e->undo_modified;
    e->undo_modified = modified;
    if (e->cur > e->last) e->cur = e->last;
    return ED_OK;
}

static void
ed_cut_clear (ed_state *e)
{
    for (size_t i = 0; i < e->ncut; i++) free (e->cut[i].s);
    free (e->cut);
    e->cut = NULL;
    e->ncut = 0;
}

static void
ed_cut_lines (ed_state *e, long a, long b)
{
    ed_cut_clear (e);
    e->ncut = (size_t) (b - a + 1);
    e->cut = xmalloc (e->ncut * sizeof *e->cut);
    ed_line *l = ed_node (e, a);
    for (size_t i = 0; i < e->ncut; i++, l = l->next) {
        e->cut[i].s = ed_strndup (l->text, l->len);
        e->cut[i].len = e->cut[i].cap = l->len;
    }
}

static void
ed_clear_buffer (ed_state *e)
{
    ed_undo_clear (e);
    ed_line *l = e->head.next;
    while (l != &e->head) {
        ed_line *n = l->next;
        ed_freeline (e, l);
        l = n;
    }
    e->head.next = e->head.prev = &e->head;
    e->last = e->cur = 0;
    e->cache_n = e->hint_n = 0;
    e->cache_p = e->hint_p = &e->head;
    memset (e->marks, 0, sizeof e->marks);
}

/* --- regular expressions --- */

static void
ed_re_drop (ed_regex *r)
{
    if (r && --r->refs == 0) {
        regfree (&r->re);
        free (r);
    }
}

static void
ed_re_set (ed_regex **slot, ed_regex *r)
{
    if (r) r->refs++;
    ed_re_drop (*slot);
    *slot = r;
}

static ed_regex *
ed_compile (ed_state *e, const char *pat)
{
    ed_regex *r = xmalloc (sizeof *r);
    int rc = regcomp (&r->re, pat, e->extended ? REG_EXTENDED : 0);
    if (rc) {
        regerror (rc, &r->re, e->errbuf, sizeof e->errbuf);
        free (r);
        e->errmsg = e->errbuf;
        return NULL;
    }
    r->refs = 0;
    return r;
}

/* The text regexec sees for L: NUL bytes become newlines, which no line
   otherwise holds. */
static const char *
ed_subject (ed_state *e, const ed_line *l)
{
    if (!memchr (l->text, '\0', l->len)) return l->text;
    if (l->len + 1 > e->tbuf_cap) {
        e->tbuf_cap = l->len + 1;
        e->tbuf = xrealloc (e->tbuf, e->tbuf_cap);
    }
    for (size_t i = 0; i < l->len; i++) e->tbuf[i] = l->text[i] ? l->text[i] : '\n';
    e->tbuf[l->len] = '\0';
    return e->tbuf;
}

static int
ed_line_matches (ed_state *e, ed_regex *r, const ed_line *l)
{
    return regexec (&r->re, ed_subject (e, l), 0, NULL, 0) == 0;
}

/* Copy a pattern from *PP up to DELIM or END. \DELIM stands for DELIM;
   a bracket expression may hold DELIM. */
static int
ed_scan_pattern (ed_state *e, const char **pp, const char *end, int delim, ed_str *out)
{
    const char *p = *pp;
    str_clear (out);
    while (p < end && *p != delim) {
        if (*p == '[') {
            const char *q = p + 1;
            if (q < end && *q == '^') q++;
            if (q < end && *q == ']') q++;
            while (q < end && *q != ']') {
                if (*q == '[' && q + 1 < end && (q[1] == ':' || q[1] == '.' || q[1] == '=')) {
                    char kind = q[1];
                    q += 2;
                    while (q + 1 < end && !(q[0] == kind && q[1] == ']')) q++;
                    if (q + 1 >= end) return ed_fail (e, "Unbalanced brackets ([])");
                    q += 2;
                    continue;
                }
                q++;
            }
            if (q >= end) return ed_fail (e, "Unbalanced brackets ([])");
            str_add (out, p, (size_t) (q - p + 1));
            p = q + 1;
            continue;
        }
        if (*p == '\\' && p + 1 < end) {
            if (p[1] == delim) str_addc (out, delim);
            else str_add (out, p, 2);
            p += 2;
            continue;
        }
        str_addc (out, *p++);
    }
    *pp = p;
    return ED_OK;
}

/* The expression for a pattern just scanned: empty means the last one. */
static ed_regex *
ed_pattern_re (ed_state *e, const ed_str *pat)
{
    if (!pat->len) {
        if (!e->last_re) { e->errmsg = "No previous pattern"; return NULL; }
        return e->last_re;
    }
    ed_regex *r = ed_compile (e, pat->s);
    if (r) ed_re_set (&e->last_re, r);
    return r;
}

/* --- standard input --- */

/* One line of standard input, without its newline: 1, 0 at the end of
   input, or -1 when interrupted. A last line without a newline counts. */
/* The reason for the last error, as h prints it: a script read from a
   file names the line it had got to. */
static void
ed_explain (const ed_state *e)
{
    if (e->script) printf ("script, line %ld: %s\n", e->in_lines, e->errmsg);
    else printf ("%s\n", e->errmsg);
}

static int
ed_read_stdin (ed_state *e, ed_str *out)
{
    str_clear (out);
    for (;;) {
        if (e->in_pos < e->in_len) {
            char *start = e->in + e->in_pos;
            char *nl = memchr (start, '\n', e->in_len - e->in_pos);
            size_t n = nl ? (size_t) (nl - start) : e->in_len - e->in_pos;
            str_add (out, start, n);
            e->in_pos += n + (nl ? 1 : 0);
            if (nl) { e->in_lines++; return 1; }
            continue;
        }
        if (e->in_eof) {
            if (!out->len) return 0;
            e->in_lines++;
            return 1;
        }
        ssize_t r = read (STDIN_FILENO, e->in, e->in_unit);
        if (r < 0 && errno == EINTR) {
            if (ed_sigint) {
                ed_sigint = 0;
                e->in_pos = e->in_len = 0;
                str_clear (out);
                return -1;
            }
            continue;
        }
        if (r <= 0) {
            e->in_eof = 1;
            continue;
        }
        e->in_len = (size_t) r;
        e->in_pos = 0;
    }
}

static int
ed_getline (ed_state *e, ed_src *src, ed_str *out)
{
    if (!src->buf) return ed_read_stdin (e, out);
    str_clear (out);
    if (src->pos >= src->len) return 0;
    const char *p = src->buf + src->pos;
    const char *nl = memchr (p, '\n', src->len - src->pos);
    size_t n = nl ? (size_t) (nl - p) : src->len - src->pos;
    str_add (out, p, n);
    src->pos += n + (nl ? 1 : 0);
    return 1;
}

/* True when S ends with an odd number of backslashes: an escaped newline. */
static int
ed_continued (const char *s, size_t len)
{
    size_t n = 0;
    while (n < len && s[len - 1 - n] == '\\') n++;
    return n % 2 == 1;
}

/* --- output --- */

/* l: escapes, $ at the end, and lines folded with \ at the width. COL
   is where the text starts (after an n prefix). */
static void
ed_put_l (ed_state *e, const ed_line *l, long col)
{
    for (size_t i = 0; i < l->len; i++) {
        unsigned char c = (unsigned char) l->text[i];
        char tmp[8];
        const char *esc = NULL;
        switch (c) {
        case '\\': esc = "\\\\"; break;
        case '\a': esc = "\\a"; break;
        case '\b': esc = "\\b"; break;
        case '\f': esc = "\\f"; break;
        case '\r': esc = "\\r"; break;
        case '\t': esc = "\\t"; break;
        case '\v': esc = "\\v"; break;
        default:
            if (c < 32 || c >= 127) {
                snprintf (tmp, sizeof tmp, "\\%03o", c);
                esc = tmp;
            }
        }
        if (esc) { fputs (esc, stdout); col += (long) strlen (esc); }
        else { putchar (c); col++; }
        if (col >= e->columns && i + 1 < l->len) {
            fputs ("\\\n", stdout);
            col = 0;
        }
    }
    fputs ("$\n", stdout);
}

static void
ed_print (ed_state *e, long n, int flags)
{
    ed_line *l = ed_node (e, n);
    long col = 0;
    if (flags & PF_N) col = (printf ("%ld\t", n) + 7) / 8 * 8;
    if (flags & PF_L) ed_put_l (e, l, col);
    else {
        fwrite (l->text, 1, l->len, stdout);
        putchar ('\n');
    }
}

static int
ed_print_range (ed_state *e, long a, long b, int flags)
{
    for (long n = a; n <= b; n++) {
        ed_print (e, n, flags);
        if (ed_sigint) { ed_sigint = 0; return ed_fail (e, "Interrupt"); }
    }
    e->cur = b;
    return ED_OK;
}

/* --- shell commands and files --- */

static pid_t
ed_spawn (const char *cmd, int dir, int *fd, bos_child_wait *cw)
{
    int pfd[2] = { -1, -1 };
    fflush (stdout);
    fflush (stderr);
    if (bos_child_wait_begin (cw) < 0) return -1;
    if (dir && pipe (pfd) < 0) { bos_child_wait_end (cw); return -1; }
    pid_t pid = fork ();
    if (pid < 0) {
        int saved = errno;
        if (dir) { close (pfd[0]); close (pfd[1]); }
        bos_child_wait_end (cw);
        errno = saved;
        return -1;
    }
    if (pid == 0) {
        static const int sigs[] = { SIGINT, SIGQUIT, SIGPIPE, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU };
        for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) signal (sigs[i], SIG_DFL);
        bos_child_wait_child (cw);
        if (dir == 'r') { dup2 (pfd[1], STDOUT_FILENO); close (pfd[0]); close (pfd[1]); }
        else if (dir == 'w') { dup2 (pfd[0], STDIN_FILENO); close (pfd[0]); close (pfd[1]); }
        execl ("/bin/sh", "sh", "-c", cmd, (char *) NULL);
        _exit (127);
    }
    if (dir == 'r') { close (pfd[1]); *fd = pfd[0]; }
    else if (dir == 'w') { close (pfd[0]); *fd = pfd[1]; }
    if (dir) fcntl (*fd, F_SETFD, FD_CLOEXEC);
    return pid;
}

static void
ed_reap (pid_t pid, bos_child_wait *cw)
{
    int st;
    while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
        ;
    bos_child_wait_end (cw);
}

static int
ed_slurp (int fd, ed_str *data)
{
    str_clear (data);
    for (;;) {
        str_reserve (data, 65536);
        ssize_t r = read (fd, data->s + data->len, 65536);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) return 0;
        data->len += (size_t) r;
        data->s[data->len] = '\0';
    }
}

/* Read NAME (a file, or !COMMAND's output) after line N. */
static int
ed_read_file (ed_state *e, const char *name, long n, int *missing)
{
    ed_str data = { 0 };
    int fd = -1, rc = 0;
    pid_t pid = -1;
    bos_child_wait cw;
    if (missing) *missing = 0;
    if (name[0] == '!') {
        pid = ed_spawn (name + 1, 'r', &fd, &cw);
        if (pid < 0) return ed_fail (e, "Cannot open input file");
    } else if ((fd = open (name, O_RDONLY | O_CLOEXEC)) < 0) {
        if (missing) *missing = 1;
        if (!e->quiet) fprintf (stderr, "%s: %s\n", name, strerror (errno));
        return ed_fail (e, "Cannot open input file");
    }
    if (ed_slurp (fd, &data) < 0) {
        if (!e->quiet) fprintf (stderr, "%s: %s\n", name, strerror (errno));
        rc = ed_fail (e, "Cannot read input file");
    }
    close (fd);
    if (pid > 0) ed_reap (pid, &cw);
    if (rc) { free (data.s); return rc; }

    long bytes = (long) data.len, count = 0, cap = 0;
    ed_line **v = NULL;
    size_t at = 0;
    if (data.len && data.s[data.len - 1] != '\n') {
        if (!e->silent) puts ("Newline appended");
        bytes++;
    }
    while (at < data.len) {
        char *nl = memchr (data.s + at, '\n', data.len - at);
        size_t len = nl ? (size_t) (nl - data.s - at) : data.len - at;
        size_t keep = len;
        if (e->strip_cr && keep && data.s[at + keep - 1] == '\r') { keep--; bytes--; }
        if (count == cap) {
            cap = cap ? cap * 2 : 256;
            v = xrealloc (v, cap * sizeof *v);
        }
        v[count++] = ed_newline (data.s + at, keep);
        at += len + 1;
    }
    free (data.s);
    if (count) {
        ed_insert (e, n, v, count);
        e->cur = n + count;
    }
    free (v);
    if (!e->silent) printf ("%ld\n", bytes);
    return ED_OK;
}

static int
ed_write_file (ed_state *e, const char *name, int append, long a, long b)
{
    int fd;
    pid_t pid = -1;
    bos_child_wait cw;
    if (name[0] == '!') {
        pid = ed_spawn (name + 1, 'w', &fd, &cw);
        if (pid < 0) return ed_fail (e, "Cannot open output file");
    } else {
        fd = open (name, O_WRONLY | O_CREAT | O_CLOEXEC | (append ? O_APPEND : O_TRUNC), 0666);
        if (fd < 0) {
            if (!e->quiet) fprintf (stderr, "%s: %s\n", name, strerror (errno));
            return ed_fail (e, "Cannot open output file");
        }
    }
    struct sigaction ign, old;
    memset (&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset (&ign.sa_mask);
    sigaction (SIGPIPE, &ign, &old);
    FILE *fp = fdopen (fd, "w");
    long bytes = 0;
    int bad = !fp;
    if (fp) {
        ed_line *l = a > 0 ? ed_node (e, a) : NULL;
        for (long n = a; n > 0 && n <= b; n++, l = l->next) {
            fwrite (l->text, 1, l->len, fp);
            putc ('\n', fp);
            bytes += (long) l->len + 1;
        }
        if (ferror (fp)) bad = 1;
        if (fclose (fp) == EOF) bad = 1;
    } else close (fd);
    if (pid > 0) ed_reap (pid, &cw);
    sigaction (SIGPIPE, &old, NULL);
    if (bad && pid < 0) {
        if (!e->quiet) fprintf (stderr, "%s: %s\n", name, strerror (errno));
        return ed_fail (e, "Cannot write file");
    }
    if (!e->silent) printf ("%ld\n", bytes);
    return ED_OK;
}

/* A file name after e, E, f, r, w or W: blanks, then the rest of the line.
   None means the current file name. */
static int
ed_filename (ed_state *e, const char **pp, const char *end, char **name, int need)
{
    const char *p = *pp;
    *name = NULL;
    if (p < end && *p != ' ' && *p != '\t') return ed_fail (e, "Unexpected command suffix");
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p < end) {
        if (memchr (p, '\0', (size_t) (end - p))) return ed_fail (e, "Invalid filename");
        if (e->restricted) {
            if (*p == '!') return ed_fail (e, "Shell access restricted");
            if (memchr (p, '/', (size_t) (end - p))) return ed_fail (e, "Directory access restricted");
        }
        *name = ed_strndup (p, (size_t) (end - p));
    } else if (need) {
        if (!e->filename) return ed_fail (e, "No current filename");
        *name = ed_strndup (e->filename, strlen (e->filename));
    }
    *pp = end;
    return ED_OK;
}

/* The command after r !, w !, e ! or !: a leading ! is the previous
   command, % the current file name (\% a plain %). An expanded command is
   shown before it runs. */
static int
ed_shell_text (ed_state *e, const char *p, const char *end, char **out)
{
    ed_str cmd = { 0 };
    int expanded = 0;
    str_clear (&cmd);
    if (p < end && *p == '!') {
        if (!e->shell_last) { free (cmd.s); return ed_fail (e, "No previous command"); }
        str_add (&cmd, e->shell_last, strlen (e->shell_last));
        p++;
        expanded = 1;
    }
    for (; p < end; p++) {
        if (*p == '\\' && p + 1 < end) {
            if (p[1] == '%') str_addc (&cmd, '%');
            else str_add (&cmd, p, 2);
            p++;
        } else if (*p == '%') {
            if (!e->filename) { free (cmd.s); return ed_fail (e, "No current filename"); }
            str_add (&cmd, e->filename, strlen (e->filename));
            expanded = 1;
        } else str_addc (&cmd, *p);
    }
    free (e->shell_last);
    e->shell_last = ed_strndup (cmd.s, cmd.len);
    if (expanded) printf ("%s\n", cmd.s);
    *out = cmd.s;
    return ED_OK;
}

/* NAME as given to r, w or e: a !COMMAND gets its expansion. */
static int
ed_redirect (ed_state *e, char **name)
{
    if ((*name)[0] != '!') return ED_OK;
    char *cmd;
    const char *p = *name + 1;
    int rc = ed_shell_text (e, p, p + strlen (p), &cmd);
    if (rc) return rc;
    size_t n = strlen (cmd);
    char *full = xmalloc (n + 2);
    full[0] = '!';
    memcpy (full + 1, cmd, n + 1);
    free (cmd);
    free (*name);
    *name = full;
    return ED_OK;
}

static void
ed_set_filename (ed_state *e, const char *name)
{
    char *copy = ed_strndup (name, strlen (name));
    free (e->filename);
    e->filename = copy;
}

/* --- addresses --- */

static void
ed_skip_blanks (const char **pp, const char *end)
{
    while (*pp < end && (**pp == ' ' || **pp == '\t')) (*pp)++;
}

static int
ed_number (ed_state *e, const char **pp, const char *end, long *out)
{
    long v = 0;
    const char *p = *pp;
    while (p < end && isdigit ((unsigned char) *p)) {
        if (v > (LONG_MAX - 9) / 10) return ed_fail (e, "Number out of range");
        v = v * 10 + (*p++ - '0');
    }
    *pp = p;
    *out = v;
    return ED_OK;
}

static int
ed_search (ed_state *e, ed_regex *r, int back, long *out)
{
    long n = e->cur;
    for (long i = 0; i < e->last; i++) {
        if (back) n = n > 1 ? n - 1 : e->last;
        else n = n < e->last ? n + 1 : 1;
        if (ed_line_matches (e, r, ed_node (e, n))) {
            *out = n;
            return ED_OK;
        }
        if (ed_sigint) { ed_sigint = 0; return ed_fail (e, "Interrupt"); }
    }
    return ed_fail (e, "No match");
}

/* One address and its offsets: 1 when there is one, 0 when not, -1 on an
   error. */
static int
ed_address (ed_state *e, const char **pp, const char *end, long *out)
{
    const char *p = *pp;
    long v = e->cur;
    int have = 0;
    if (p < end) {
        unsigned char c = (unsigned char) *p;
        if (isdigit (c)) {
            if (ed_number (e, &p, end, &v)) return -1;
            have = 1;
        } else if (c == '.' || c == '$') {
            v = c == '.' ? e->cur : e->last;
            p++;
            have = 1;
        } else if (c == '\'') {
            p++;
            if (p >= end || !islower ((unsigned char) *p)) return ed_fail (e, "Invalid mark character");
            v = ed_index (e, e->marks[*p - 'a']);
            p++;
            if (v < 0) return ed_fail (e, "Invalid address");
            have = 1;
        } else if (c == '/' || c == '?') {
            ed_str pat = { 0 };
            ed_regex *r = NULL;
            p++;
            int rc = ed_scan_pattern (e, &p, end, c, &pat);
            if (!rc) {
                if (p < end) p++;
                r = ed_pattern_re (e, &pat);
                rc = r ? ed_search (e, r, c == '?', &v) : ED_ERR;
            }
            free (pat.s);
            if (rc) return -1;
            have = 1;
        }
        /* Two addresses with nothing between them ("..", "$.") */
        if (have && p < end && strchr (".$'/?", *p) && *p) return ed_fail (e, "Invalid address");
    }
    for (;;) {
        const char *q = p;
        ed_skip_blanks (&q, end);
        if (q < end && (*q == '+' || *q == '-')) {
            long sign = *q == '+' ? 1 : -1, n = 1;
            q++;
            if (q < end && isdigit ((unsigned char) *q) && ed_number (e, &q, end, &n)) return -1;
            v += sign * n;
            have = 1;
            p = q;
        } else if (have && q > p && q < end && isdigit ((unsigned char) *q)) {
            long n;
            if (ed_number (e, &q, end, &n)) return -1;
            v += n;
            p = q;
        } else break;
    }
    *pp = p;
    if (!have) return 0;
    if (v < 0 || v > e->last) return ed_fail (e, "Invalid address");
    *out = v;
    return 1;
}

/* The address list before a command. CNT is how many were given (at most
   2 kept); with one, *A2 holds it. */
static int
ed_addresses (ed_state *e, const char **pp, const char *end, int *cnt, long *a1, long *a2)
{
    const char *p = *pp;
    int have_prev = 0;
    long v;
    *cnt = 0;
    *a1 = *a2 = e->cur;
#define ED_PUSH(x) do { *a1 = *a2; *a2 = (x); (*cnt)++; } while (0)
    for (;;) {
        ed_skip_blanks (&p, end);
        int r = ed_address (e, &p, end, &v);
        if (r < 0) return ED_ERR;
        if (r) { ED_PUSH (v); have_prev = 1; }
        ed_skip_blanks (&p, end);
        if (p >= end) break;
        char c = *p;
        if (c != ',' && c != ';' && c != '%') break;
        p++;
        if (c == '%') c = ',';
        int lone = !r && !have_prev;
        if (lone) ED_PUSH (c == ';' ? e->cur : 1);
        if (c == ';') e->cur = *a2;
        ed_skip_blanks (&p, end);
        r = ed_address (e, &p, end, &v);
        if (r < 0) return ED_ERR;
        if (r) ED_PUSH (v);
        else ED_PUSH (lone ? e->last : *a2);
        have_prev = 1;
    }
#undef ED_PUSH
    if (*cnt > 2) *cnt = 2;
    *pp = p;
    return ED_OK;
}

/* Fill in the default addresses and check them; LOW is 0 when line 0 is
   allowed. */
static int
ed_range (ed_state *e, int cnt, long *a1, long *a2, long d1, long d2, long low)
{
    if (cnt == 0) { *a1 = d1; *a2 = d2; }
    else if (cnt == 1) *a1 = *a2;
    if (*a1 < low || *a1 > *a2 || *a2 > e->last) return ed_fail (e, "Invalid address");
    return ED_OK;
}

static int
ed_suffix (ed_state *e, const char *p, const char *end, int *flags)
{
    for (; p < end; p++) {
        if (*p == 'p') *flags |= PF_P;
        else if (*p == 'l') *flags |= PF_L;
        else if (*p == 'n') *flags |= PF_N;
        else return ed_fail (e, "Invalid command suffix");
    }
    return ED_OK;
}

/* --- commands --- */

/* Text lines up to "." (or the end of input), inserted after line AFTER. */
static int
ed_append (ed_state *e, ed_src *src, long after, long *count)
{
    ed_str t = { 0 };
    long n = after;
    int rc = ED_OK;
    *count = 0;
    for (;;) {
        int got = ed_getline (e, src, &t);
        if (got < 0) { rc = ed_fail (e, "Interrupt"); break; }
        if (got && src->buf && ed_continued (t.s, t.len)) t.s[--t.len] = '\0';
        if (got == 0 || (t.len == 1 && t.s[0] == '.')) break;
        ed_line *l = ed_newline (t.s, t.len);
        ed_insert (e, n, &l, 1);
        e->cur = ++n;
        (*count)++;
    }
    free (t.s);
    return rc;
}

static void
ed_join (ed_state *e, long a, long b)
{
    ed_str s = { 0 };
    str_clear (&s);
    ed_line *l = ed_node (e, a);
    for (long n = a; n <= b; n++, l = l->next) str_add (&s, l->text, l->len);
    ed_line *joined = ed_newline (s.s, s.len);
    free (s.s);
    ed_delete (e, a, b);
    ed_insert (e, a - 1, &joined, 1);
    e->cur = a;
}

static ed_line **
ed_copies (ed_state *e, long a, long b)
{
    ed_line **v = xmalloc ((size_t) (b - a + 1) * sizeof *v);
    ed_line *l = ed_node (e, a);
    for (long i = 0; i < b - a + 1; i++, l = l->next) v[i] = ed_newline (l->text, l->len);
    return v;
}

static void
ed_expand (ed_str *out, const char *repl, size_t rlen, const char *text, size_t base,
           const regmatch_t *m, size_t nsub)
{
    for (size_t i = 0; i < rlen; i++) {
        char c = repl[i];
        if (c == '&') str_add (out, text + base + m[0].rm_so, (size_t) (m[0].rm_eo - m[0].rm_so));
        else if (c == '\\' && i + 1 < rlen) {
            char d = repl[++i];
            if (d >= '1' && d <= '9' && (size_t) (d - '0') <= nsub) {
                const regmatch_t *g = &m[d - '0'];
                if (g->rm_so >= 0) str_add (out, text + base + g->rm_so, (size_t) (g->rm_eo - g->rm_so));
            } else str_addc (out, d);
        } else str_addc (out, c);
    }
}

/* Substitute in lines A..B. A match that is empty where the previous one
   was makes a global substitution loop forever, as GNU reports. */
static int
ed_substitute (ed_state *e, ed_regex *r, const char *repl, size_t rlen, int global, long count,
               long a, long b)
{
    regmatch_t m[10];
    ed_str out = { 0 };
    long changed = 0;
    int rc = ED_OK;
    size_t nsub = r->re.re_nsub;
    for (long n = a; n <= b && rc == ED_OK; n++) {
        ed_line *l = ed_node (e, n);
        const char *subj = ed_subject (e, l);
        size_t len = l->len, pos = 0;
        long nth = 0, prev_empty = -1;
        int first = 1, did = 0;
        str_clear (&out);
        for (;;) {
            if (!first && pos >= len) break;
            if (regexec (&r->re, subj + pos, 10, m, first ? 0 : REG_NOTBOL)) break;
            size_t so = pos + (size_t) m[0].rm_so, eo = pos + (size_t) m[0].rm_eo;
            if (global && so == eo && (long) so == prev_empty) {
                rc = ed_fail (e, "Infinite substitution loop");
                break;
            }
            nth++;
            if (global || nth == count) {
                str_add (&out, l->text + pos, so - pos);
                ed_expand (&out, repl, rlen, l->text, pos, m, nsub);
                did = 1;
            } else str_add (&out, l->text + pos, eo - pos);
            prev_empty = so == eo ? (long) so : -1;
            pos = eo;
            first = 0;
            if (!global && nth == count) break;
            if (so == eo && eo >= len) break;
        }
        if (rc || !did) continue;
        str_add (&out, l->text + pos, len - pos);

        long k = 0, cap = 4;
        ed_line **v = xmalloc ((size_t) cap * sizeof *v);
        size_t at = 0;
        for (;;) {
            char *nl = memchr (out.s + at, '\n', out.len - at);
            size_t piece = nl ? (size_t) (nl - out.s - at) : out.len - at;
            if (k == cap) { cap *= 2; v = xrealloc (v, (size_t) cap * sizeof *v); }
            v[k++] = ed_newline (out.s + at, piece);
            if (!nl) break;
            at += piece + 1;
        }
        /* x puts back the last line the substitution replaced. */
        ed_cut_lines (e, n, n);
        ed_delete (e, n, n);
        ed_insert (e, n - 1, v, k);
        free (v);
        n += k - 1;
        b += k - 1;
        e->cur = n;
        changed++;
    }
    free (out.s);
    if (rc) return rc;
    if (!changed && !e->in_global) return ed_fail (e, "No match");
    return ED_OK;
}

static int
ed_cmd_s (ed_state *e, ed_src *src, const char *p, const char *end, int esc_nl, int cnt, long a1, long a2)
{
    ed_str pat = { 0 }, repl = { 0 }, cont = { 0 };
    int global = 0, flags = 0, rc = ED_OK, use_search = 0, repeat = 0;
    long count = 1;
    ed_regex *r = NULL;
    const char *rtext;
    size_t rlen;

    if (p >= end || (*p && strchr ("gpr0123456789", *p))) {
        if (!e->have_sub) return ed_fail (e, "No previous substitution");
        repeat = 1;
        /* The suffixes change the remembered substitution: g toggles and
           a count replaces g as they are read (an error later on keeps
           them); p toggles printing once all of them are valid. A count
           comes once, does not start with 0 and does not go with g; g, p
           and r come once each. */
        int saw_count = 0, saw_g = 0, toggle_print = 0;
        while (p < end) {
            if (*p == 'g' && !saw_count && !saw_g) { e->sub_global = !e->sub_global; saw_g = 1; p++; }
            else if (*p == 'p' && !toggle_print) { toggle_print = 1; p++; }
            else if (*p == 'r' && !use_search) { use_search = 1; p++; }
            else if (isdigit ((unsigned char) *p) && *p != '0' && !saw_count && !saw_g) {
                if (ed_number (e, &p, end, &count)) return ED_ERR;
                e->sub_count = count;
                e->sub_global = 0;
                saw_count = 1;
            } else return ed_fail (e, "Invalid command suffix");
        }
        if (toggle_print) e->sub_print = !e->sub_print;
        global = e->sub_global;
        count = e->sub_count;
        if (e->sub_print && !e->sub_flags) e->sub_flags = PF_P;
        flags = e->sub_print ? e->sub_flags : 0;
        r = use_search ? e->last_re : e->sub_re;
        if (!r) return ed_fail (e, "No previous pattern");
        rtext = e->repl;
        rlen = e->repl_len;
    } else {
        int delim = (unsigned char) *p++;
        if (delim == ' ' || delim == '\n' || delim == '\\') return ed_fail (e, "Invalid pattern delimiter");
        if ((rc = ed_scan_pattern (e, &p, end, delim, &pat))) goto out;
        if (p >= end) { rc = ed_fail (e, "Missing pattern delimiter"); goto out; }
        p++;
        str_clear (&repl);
        for (;;) {
            if (p < end && *p == delim) break;
            if (p < end && *p == '\\' && p + 1 < end) {
                str_add (&repl, p, 2);
                p += 2;
            } else if ((p < end && *p == '\\') || (p == end && esc_nl)) {
                /* An escaped newline: the replacement goes on. */
                str_add (&repl, "\\\n", 2);
                int got = ed_getline (e, src, &cont);
                if (got < 0) { rc = ed_fail (e, "Interrupt"); goto out; }
                if (got == 0) { p = end; esc_nl = 0; break; }
                p = cont.s;
                end = cont.s + cont.len;
                esc_nl = src->buf && ed_continued (cont.s, cont.len);
                if (esc_nl) end--;
            } else if (p < end) str_addc (&repl, *p++);
            else break;
        }
        if (p >= end) flags |= PF_P;
        else {
            p++;
            int saw_count = 0;
            while (p < end) {
                if (*p == 'g' && !saw_count && !global) { global = 1; p++; }
                else if (*p == 'p') { flags |= PF_P; p++; }
                else if (*p == 'l') { flags |= PF_L; p++; }
                else if (*p == 'n') { flags |= PF_N; p++; }
                else if (isdigit ((unsigned char) *p) && !saw_count && !global) {
                    if (ed_number (e, &p, end, &count)) { rc = ED_ERR; goto out; }
                    if (count == 0) { rc = ed_fail (e, "Invalid command suffix"); goto out; }
                    saw_count = 1;
                } else { rc = ed_fail (e, "Invalid command suffix"); goto out; }
            }
        }
        if (repl.len == 1 && repl.s[0] == '%') {
            if (!e->have_sub) { rc = ed_fail (e, "No previous substitution"); goto out; }
        } else {
            free (e->repl);
            e->repl = ed_strndup (repl.s, repl.len);
            e->repl_len = repl.len;
        }
        if (!(r = ed_pattern_re (e, &pat))) { rc = ED_ERR; goto out; }
        ed_re_set (&e->sub_re, r);
        e->have_sub = 1;
        e->sub_global = global;
        e->sub_flags = flags;
        e->sub_print = flags != 0;
        e->sub_count = count;
        rtext = e->repl;
        rlen = e->repl_len;
    }
    if ((rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1))) goto out;
    ed_begin_change (e);
    r->refs++;
    rc = ed_substitute (e, r, rtext, rlen, global, count, a1, a2);
    ed_re_drop (r);
    if (!rc && flags) ed_print (e, e->cur, flags);
    /* In a command list the newline after a repeated substitution is
       left as an empty command, which prints the current line. */
    if (!rc && repeat && src->buf) ed_print (e, e->cur, PF_P);
out:
    free (pat.s);
    free (repl.s);
    free (cont.s);
    return rc;
}

static int ed_exec (ed_state *e, ed_src *src, ed_str *cmd);

static int
ed_run_list (ed_state *e, const char *buf, size_t len)
{
    ed_src src = { buf, len, 0 };
    ed_str line = { 0 };
    int rc = ED_OK;
    while (rc == ED_OK && ed_getline (e, &src, &line) > 0) rc = ed_exec (e, &src, &line);
    free (line.s);
    return rc;
}

/* The rest of a command list: lines ending in an escaped newline go on. */
static int
ed_more_lines (ed_state *e, ed_src *src, ed_str *list)
{
    ed_str more = { 0 };
    int rc = ED_OK;
    /* The backslashes stay: s reads one as an escaped newline in its
       replacement, other commands drop it. */
    while (list->len && ed_continued (list->s, list->len)) {
        str_addc (list, '\n');
        int got = ed_getline (e, src, &more);
        if (got < 0) { rc = ed_fail (e, "Interrupt"); break; }
        if (got == 0) break;
        str_add (list, more.s, more.len);
    }
    free (more.s);
    return rc;
}

static int
ed_cmd_global (ed_state *e, ed_src *src, int c, const char *p, const char *end, int cnt, long a1, long a2)
{
    int invert = c == 'v' || c == 'V', inter = c == 'G' || c == 'V';
    ed_str pat = { 0 }, list = { 0 }, more = { 0 };
    int rc, gflags = 0;
    if (e->in_global) return ed_fail (e, "Cannot nest global commands");
    if (p >= end || *p == ' ' || *p == '\n') return ed_fail (e, "Invalid pattern delimiter");
    if ((rc = ed_range (e, cnt, &a1, &a2, 1, e->last, 1))) return rc;
    int delim = (unsigned char) *p++;
    if ((rc = ed_scan_pattern (e, &p, end, delim, &pat))) goto out;
    if (p < end) p++;
    ed_regex *r = ed_pattern_re (e, &pat);
    if (!r) { rc = ED_ERR; goto out; }
    str_clear (&list);
    if (inter) {
        if ((rc = ed_suffix (e, p, end, &gflags))) goto out;
        if (!gflags) gflags = PF_P;
    } else {
        str_add (&list, p, (size_t) (end - p));
        if ((rc = ed_more_lines (e, src, &list))) goto out;
        if (!list.len) str_add (&list, "p", 1);
        str_addc (&list, '\n');
    }

    long nact = 0;
    ed_line **act = xmalloc ((size_t) (a2 - a1 + 1) * sizeof *act);
    ed_line *l = ed_node (e, a1);
    for (long n = a1; n <= a2; n++, l = l->next)
        if (ed_line_matches (e, r, l) != invert) {
            l->active = 1;
            act[nact++] = l;
        }
    ed_undo_clear (e);
    e->in_global = 1;
    unsigned long gen = e->generation;
    for (long i = 0; i < nact && rc == ED_OK && gen == e->generation; i++) {
        l = act[i];
        if (!l->active) continue;
        l->active = 0;
        long n = ed_index (e, l);
        if (n < 0) continue;
        e->cur = n;
        e->hint_n = n;
        e->hint_p = l;
        if (ed_sigint) { ed_sigint = 0; rc = ed_fail (e, "Interrupt"); break; }
        if (inter) {
            ed_print (e, n, gflags);
            fflush (stdout);
            int got = ed_read_stdin (e, &more);
            if (got < 0) { rc = ed_fail (e, "Interrupt"); break; }
            if (got == 0) break;
            if (!more.len) continue;
            str_clear (&list);
            if (more.len == 1 && more.s[0] == '&') {
                if (!e->gcmd_last) { rc = ed_fail (e, "No previous command"); break; }
                str_add (&list, e->gcmd_last, strlen (e->gcmd_last));
            } else {
                ed_src in = { NULL, 0, 0 };
                str_add (&list, more.s, more.len);
                if ((rc = ed_more_lines (e, &in, &list))) break;
                str_addc (&list, '\n');
                free (e->gcmd_last);
                e->gcmd_last = ed_strndup (list.s, list.len);
            }
        }
        rc = ed_run_list (e, list.s, list.len);
    }
    if (gen == e->generation)
        for (long i = 0; i < nact; i++) act[i]->active = 0;
    e->in_global = 0;
    free (act);
out:
    free (pat.s);
    free (list.s);
    free (more.s);
    return rc;
}

static int
ed_edit (ed_state *e, char *name)
{
    ed_clear_buffer (e);
    e->generation++;
    if (name[0] != '!') ed_set_filename (e, name);
    int rc = ed_read_file (e, name, 0, NULL);
    ed_undo_clear (e);
    e->modified = 0;
    e->undo_modified = 0;
    e->cur = e->last;
    return rc;
}

static int
ed_exec (ed_state *e, ed_src *src, ed_str *cmd)
{
    const char *p = cmd->s, *end = cmd->s + cmd->len;
    int cnt, flags = 0, rc = ED_OK;
    long a1, a2, count;
    char *name = NULL;
    ed_line **v;
    int esc_nl = 0;

    /* In a command list, a line ending in an escaped newline goes on. */
    if (src->buf && ed_continued (cmd->s, cmd->len)) { end--; esc_nl = 1; }
    if (ed_addresses (e, &p, end, &cnt, &a1, &a2)) return ED_ERR;
    ed_skip_blanks (&p, end);
    int c = p < end ? (unsigned char) *p++ : '\n';
    switch (c) {
    case 'a':
    case 'i':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 0)))
            return rc;
        ed_begin_change (e);
        rc = ed_append (e, src, c == 'i' && a2 > 0 ? a2 - 1 : a2, &count);
        if (!count) e->cur = a2;
        break;
    case 'c':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        ed_begin_change (e);
        ed_cut_lines (e, a1, a2);
        ed_delete (e, a1, a2);
        e->cur = a1 <= e->last ? a1 : e->last;
        rc = ed_append (e, src, a1 - 1, &count);
        break;
    case 'd':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        ed_begin_change (e);
        ed_cut_lines (e, a1, a2);
        ed_delete (e, a1, a2);
        e->cur = a1 <= e->last ? a1 : e->last;
        break;
    case 'e':
    case 'E':
        if (cnt) return ed_fail (e, "Unexpected address");
        if ((rc = ed_filename (e, &p, end, &name, 1))) return rc;
        if (c == 'e' && e->modified && !e->warned) { free (name); return ED_EMOD; }
        if (!(rc = ed_redirect (e, &name))) rc = ed_edit (e, name);
        break;
    case 'f':
        if (cnt) return ed_fail (e, "Unexpected address");
        if ((rc = ed_filename (e, &p, end, &name, 0))) return rc;
        if (name) {
            if (name[0] == '!') { free (name); return ed_fail (e, "Invalid redirection"); }
            ed_set_filename (e, name);
        }
        if (!e->filename) rc = ed_fail (e, "No current filename");
        else printf ("%s\n", e->filename);
        free (name);
        return rc;
    case 'g':
    case 'v':
    case 'G':
    case 'V':
        return ed_cmd_global (e, src, c, p, end, cnt, a1, a2);
    case 'h':
    case 'H':
        if (cnt) return ed_fail (e, "Unexpected address");
        if (p < end) return ed_fail (e, "Invalid command suffix");
        if (c == 'H') e->verbose = !e->verbose;
        if ((c == 'h' || e->verbose) && e->errmsg) ed_explain (e);
        return ED_OK;
    case 'j':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur + 1, 1)))
            return rc;
        if (a1 < a2) {
            ed_begin_change (e);
            ed_cut_lines (e, a1, a2);
            ed_join (e, a1, a2);
        }
        break;
    case 'k': {
        if (p >= end) return ed_fail (e, "Invalid command suffix");
        if (!islower ((unsigned char) *p)) return ed_fail (e, "Invalid mark character");
        int mark = *p++ - 'a';
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        e->marks[mark] = ed_node (e, a2);
        break;
    }
    case 'l':
    case 'n':
    case 'p':
        flags = c == 'l' ? PF_L : c == 'n' ? PF_N : PF_P;
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        return ed_print_range (e, a1, a2, flags);
    case 'm':
    case 't': {
        long dest = e->cur;
        ed_skip_blanks (&p, end);
        int r = ed_address (e, &p, end, &dest);
        if (r < 0) return ED_ERR;
        if (!r) dest = e->cur;
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        count = a2 - a1 + 1;
        if (c == 'm') {
            if (dest >= a1 && dest < a2) return ed_fail (e, "Invalid destination");
            ed_begin_change (e);
            if (dest == a1 - 1 || dest == a2) { e->cur = a2; break; }
            v = xmalloc ((size_t) count * sizeof *v);
            ed_unlink (e, a1, a2, v, 0);
            ed_log (e, 0, a1 - 1, v, count);
            if (dest > a2) dest -= count;
            ed_insert (e, dest, v, count);
        } else {
            v = ed_copies (e, a1, a2);
            ed_begin_change (e);
            ed_insert (e, dest, v, count);
        }
        free (v);
        e->cur = dest + count;
        break;
    }
    case 'P':
        if (cnt) return ed_fail (e, "Unexpected address");
        if ((rc = ed_suffix (e, p, end, &flags))) return rc;
        e->prompt_on = !e->prompt_on;
        break;
    case 'q':
    case 'Q':
        if (cnt) return ed_fail (e, "Unexpected address");
        if (p < end) return ed_fail (e, "Invalid command suffix");
        if (c == 'q' && e->modified && !e->warned) return ED_EMOD;
        return ED_QUIT;
    case 'r':
        if ((rc = ed_range (e, cnt, &a1, &a2, e->last, e->last, 0))) return rc;
        if ((rc = ed_filename (e, &p, end, &name, 1))) return rc;
        if ((rc = ed_redirect (e, &name))) break;
        if (!e->filename && name[0] != '!') ed_set_filename (e, name);
        ed_begin_change (e);
        rc = ed_read_file (e, name, a2, NULL);
        break;
    case 's':
        return ed_cmd_s (e, src, p, end, esc_nl, cnt, a1, a2);
    case 'u':
        if (cnt) return ed_fail (e, "Unexpected address");
        if ((rc = ed_suffix (e, p, end, &flags))) return rc;
        rc = ed_undo (e);
        break;
    case 'w':
    case 'W': {
        int quit = 0;
        if (c == 'w' && p < end && *p == 'q') { quit = 1; p++; }
        if (cnt == 0 && e->last == 0) a1 = a2 = 0;
        else if ((rc = ed_range (e, cnt, &a1, &a2, 1, e->last, 1))) return rc;
        if ((rc = ed_filename (e, &p, end, &name, 1))) return rc;
        if ((rc = ed_redirect (e, &name))) break;
        if (!e->filename && name[0] != '!') ed_set_filename (e, name);
        rc = ed_write_file (e, name, c == 'W', a1, a2);
        if (!rc && name[0] != '!' && (e->last == 0 || (a1 == 1 && a2 == e->last))) e->modified = 0;
        if (!rc && quit) rc = ED_QUIT;
        break;
    }
    case 'x':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 0)))
            return rc;
        if (!e->ncut) return ed_fail (e, "Nothing to put");
        v = xmalloc (e->ncut * sizeof *v);
        for (size_t i = 0; i < e->ncut; i++) v[i] = ed_newline (e->cut[i].s, e->cut[i].len);
        ed_begin_change (e);
        ed_insert (e, a2, v, (long) e->ncut);
        free (v);
        e->cur = a2 + (long) e->ncut;
        break;
    case 'y':
        if ((rc = ed_suffix (e, p, end, &flags)) || (rc = ed_range (e, cnt, &a1, &a2, e->cur, e->cur, 1)))
            return rc;
        ed_cut_lines (e, a1, a2);
        break;
    case 'z':
        if (cnt == 0) a2 = e->cur + !e->in_global;
        if (a2 < 1 || a2 > e->last) return ed_fail (e, "Invalid address");
        if (p < end && isdigit ((unsigned char) *p)) {
            long w;
            if (ed_number (e, &p, end, &w)) return ED_ERR;
            if (w > 0) e->window = w;
        }
        if ((rc = ed_suffix (e, p, end, &flags))) return rc;
        a1 = a2;
        a2 = a1 + e->window - 1 < e->last ? a1 + e->window - 1 : e->last;
        return ed_print_range (e, a1, a2, flags ? flags : PF_P);
    case '=':
        if ((rc = ed_suffix (e, p, end, &flags))) return rc;
        printf ("%ld\n", cnt ? a2 : e->last);
        break;
    case '!': {
        char *text;
        if (cnt) return ed_fail (e, "Unexpected address");
        if (e->restricted) return ed_fail (e, "Shell access restricted");
        if ((rc = ed_shell_text (e, p, end, &text))) return rc;
        bos_child_wait cw;
        pid_t pid = ed_spawn (text, 0, NULL, &cw);
        free (text);
        if (pid < 0) return ed_fail (e, "Cannot fork");
        ed_reap (pid, &cw);
        if (!e->silent) puts ("!");
        return ED_OK;
    }
    case '#':
        return ED_OK;
    case '\n':
        if (cnt == 0) a2 = e->cur + !e->in_global;
        if (a2 < 1 || a2 > e->last) return ed_fail (e, "Invalid address");
        ed_print (e, a2, PF_P);
        e->cur = a2;
        return ED_OK;
    default:
        return ed_fail (e, "Unknown command");
    }
    free (name);
    if (rc) return rc;
    if (flags && e->cur > 0) ed_print (e, e->cur, flags);
    return ED_OK;
}

/* --- the program --- */

static void
ed_loop (ed_state *e)
{
    ed_src in = { NULL, 0, 0 };
    ed_str line = { 0 };
    for (;;) {
        int st;
        if (e->prompt_on) fputs (e->prompt, stdout);
        fflush (stdout);
        int got = ed_read_stdin (e, &line);
        if (got < 0) {
            e->errmsg = "Interrupt";
            fputs ("\n?\n", stdout);
            if (e->verbose) ed_explain (e);
            e->warned = e->just_warned = 0;
            continue;
        }
        unsigned long changes = e->changes;
        if (got == 0) {
            if (e->tty) e->in_eof = 0;
            if (!e->modified || e->just_warned) break;
            st = ED_EMOD;
            if (!e->loose) e->status = 2;
        } else st = ed_exec (e, &in, &line);
        /* GNU ed 1.21: after the warning, q or e goes ahead
           unless a command failed or edited in between; the end of input
           only right after it. */
        e->just_warned = st == ED_EMOD;
        if (st == ED_EMOD) e->warned = 1;
        else if (st < 0 || e->changes != changes) e->warned = 0;
        if (st == ED_QUIT) break;
        if (st < 0) {
            if (st == ED_EMOD) e->errmsg = "Warning: buffer modified";
            int intr = !strcmp (e->errmsg, "Interrupt");
            fputs (intr ? "\n?\n" : "?\n", stdout);
            if (e->verbose) ed_explain (e);
            if (!e->loose && !e->status && !intr) e->status = 1;
            /* A script read from a file stops at its first error. */
            if (e->script && !intr) break;
        }
    }
    free (line.s);
}

static void
ed_usage_error (const char *fmt, const char *arg)
{
    fputs ("ed: ", stderr);
    fprintf (stderr, fmt, arg);
    fputs ("\nTry 'ed --help' for more information.\n", stderr);
}

static void
ed_help (void)
{
    fputs ("Usage: ed [options] [file]\n"
           "Edit FILE, or the output of !COMMAND, with the standard line editor.\n\n"
           "  -E, --extended-regexp      extended regular expressions\n"
           "  -G, --traditional          accepted for compatibility\n"
           "  -h, --help                 show this help\n"
           "  -l, --loose-exit-status    exit 0 even when a command failed\n"
           "  -p, --prompt=STRING        prompt with STRING (P toggles it)\n"
           "  -q, --quiet, --silent      no file diagnostics on standard error\n"
           "  -r, --restricted           no shell commands or names with a slash\n"
           "  -s, --script               no byte counts and no '!' after shell commands\n"
           "  -v, --verbose              explain each error, as H does\n"
           "  -V, --version              show the version\n"
           "      --strip-trailing-cr    drop a carriage return before each newline read\n\n"
           "Exit status: 0, 1 after an error, 2 when input ended with unsaved changes.\n",
           stdout);
}

int
ed_builtin (WORD_LIST *list)
{
    static const char *const longs[] = {
        "--extended-regexp", "--traditional", "--help", "--loose-exit-status", "--prompt",
        "--quiet", "--silent", "--restricted", "--script", "--verbose", "--version",
        "--strip-trailing-cr", NULL
    };
    ed_state st, *e = &st;
    const char *file = NULL;
    int end_opts = 0;

    memset (e, 0, sizeof *e);
    e->head.next = e->head.prev = &e->head;
    e->cache_p = e->hint_p = &e->head;
    e->window = 22;
    e->columns = 76;
    e->sub_count = 1;
    e->prompt = "*";

    for (WORD_LIST *w = list; w; w = w->next) {
        const char *a = w->word->word;
        if (end_opts || a[0] != '-' || !a[1]) {
            if (!end_opts && !strcmp (a, "-")) e->silent = 1;
            else if (!file) file = a;
            continue;
        }
        if (!strcmp (a, "--")) { end_opts = 1; continue; }
        if (a[1] == '-') {
            const char *eq = strchr (a, '=');
            size_t n = eq ? (size_t) (eq - a) : strlen (a);
            int hit = -1, hits = 0;
            for (int i = 0; longs[i]; i++)
                if (!strncmp (longs[i], a, n)) {
                    if (strlen (longs[i]) == n) { hit = i; hits = 1; break; }
                    hit = i;
                    hits++;
                }
            if (hits == 0) { ed_usage_error ("unrecognized option '%s'", a); return EXECUTION_FAILURE; }
            if (hits > 1) { ed_usage_error ("option '%s' is ambiguous", a); return EXECUTION_FAILURE; }
            const char *name = longs[hit];
            if (!strcmp (name, "--prompt")) {
                const char *val = eq ? eq + 1 : NULL;
                if (!val) {
                    if (!w->next) { ed_usage_error ("option '%s' requires an argument", name); return EXECUTION_FAILURE; }
                    w = w->next;
                    val = w->word->word;
                }
                e->prompt = val;
                e->prompt_on = 1;
                continue;
            }
            if (eq) { ed_usage_error ("option '%s' doesn't allow an argument", name); return EXECUTION_FAILURE; }
            if (!strcmp (name, "--extended-regexp")) e->extended = 1;
            else if (!strcmp (name, "--traditional")) ;
            else if (!strcmp (name, "--help")) { ed_help (); return EXECUTION_SUCCESS; }
            else if (!strcmp (name, "--loose-exit-status")) e->loose = 1;
            else if (!strcmp (name, "--quiet") || !strcmp (name, "--silent")) e->quiet = 1;
            else if (!strcmp (name, "--restricted")) e->restricted = 1;
            else if (!strcmp (name, "--script")) e->silent = 1;
            else if (!strcmp (name, "--verbose")) e->verbose = 1;
            else if (!strcmp (name, "--version")) { puts ("ed (bash-os) 0.1.5"); return EXECUTION_SUCCESS; }
            else e->strip_cr = 1;
            continue;
        }
        for (int i = 1; a[i]; i++) {
            switch (a[i]) {
            case 'E': e->extended = 1; break;
            case 'G': break;
            case 'h': ed_help (); return EXECUTION_SUCCESS;
            case 'l': e->loose = 1; break;
            case 'q': e->quiet = 1; break;
            case 'r': e->restricted = 1; break;
            case 's': e->silent = 1; break;
            case 'v': e->verbose = 1; break;
            case 'V': puts ("ed (bash-os) 0.1.5"); return EXECUTION_SUCCESS;
            case 'p':
                if (a[i + 1]) e->prompt = a + i + 1;
                else if (w->next) { w = w->next; e->prompt = w->word->word; }
                else {
                    char opt[2] = { 'p', 0 };
                    ed_usage_error ("option requires an argument -- '%s'", opt);
                    return EXECUTION_FAILURE;
                }
                e->prompt_on = 1;
                i = (int) strlen (a) - 1;
                break;
            default: {
                char opt[2] = { a[i], 0 };
                ed_usage_error ("invalid option -- '%s'", opt);
                return EXECUTION_FAILURE;
            }
            }
        }
    }

    e->tty = isatty (STDIN_FILENO);
    struct stat in_st;
    e->script = !e->tty && fstat (STDIN_FILENO, &in_st) == 0 && S_ISREG (in_st.st_mode);
    struct winsize ws;
    if (isatty (STDOUT_FILENO) && ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row > 2) e->window = ws.ws_row - 2;
        if (ws.ws_col > 8) e->columns = ws.ws_col - 4;
    }
    /* Input that cannot be sought back over (a pipe, a terminal) is read a
       byte at a time, as GNU ed does, so what follows q stays for the next
       reader and a shell command run by ! reads the lines after it. */
    e->in_unit = lseek (STDIN_FILENO, 0, SEEK_CUR) < 0 ? 1 : 65536;
    e->in = xmalloc (65536);

    struct sigaction sa, old_int;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = ed_on_sigint;
    sigemptyset (&sa.sa_mask);
    ed_sigint = 0;
    sigaction (SIGINT, &sa, &old_int);

    if (file) {
        int missing = 0;
        char *name = ed_strndup (file, strlen (file));
        int rc = ED_OK;
        if (e->restricted && (name[0] == '!' || strchr (name, '/')))
            rc = ed_fail (e, name[0] == '!' ? "Shell access restricted" : "Directory access restricted");
        else {
            if (name[0] != '!') ed_set_filename (e, name);
            else rc = ed_redirect (e, &name);
            if (!rc) rc = ed_read_file (e, name, 0, &missing);
        }
        free (name);
        ed_undo_clear (e);
        e->modified = e->undo_modified = 0;
        e->cur = e->last;
        /* A file named on the command line that cannot be opened is only
           reported (as a new file would be); one that cannot be read is
           reported on standard error, not with "?", and sets status 1
           even under -l. A script read from a file is not run at all. */
        if (rc && e->script) e->status = 2;     /* a script needs its file */
        else if (rc && !missing) {
            fprintf (stderr, "%s: %s\n", file, e->errmsg);
            e->status = 1;
        }
    }
    if (e->status != 2) ed_loop (e);

    fflush (stdout);
    if (e->in_pos < e->in_len)
        lseek (STDIN_FILENO, -(off_t) (e->in_len - e->in_pos), SEEK_CUR);
    sigaction (SIGINT, &old_int, NULL);
    ed_sigint = 0;
    ed_clear_buffer (e);
    free (e->ops);
    ed_cut_clear (e);
    ed_re_set (&e->last_re, NULL);
    ed_re_set (&e->sub_re, NULL);
    free (e->repl);
    free (e->filename);
    free (e->shell_last);
    free (e->gcmd_last);
    free (e->in);
    free (e->tbuf);
    return e->status;
}

char *ed_doc[] = {
    "Edit text with the standard line editor.",
    "",
    "    ed [-EGlqrsv] [-p PROMPT] [--strip-trailing-cr] [FILE | !COMMAND]",
    "",
    "Commands are read from standard input, as GNU ed reads them: addresses",
    "N . $ +N -N /RE/ ?RE? 'x , ; and the commands a c d e E f g G h H i j k",
    "l m n p P q Q r s t u v V w W wq x y z = ! # and newline. s/RE/REPL/",
    "takes g, N, p, l and n; REPL may use & and \\1..\\9. g/RE/LIST and",
    "v/RE/LIST run a command list on each (non-)matching line; G and V ask",
    "for one. u undoes the last command, a whole g included. Errors print",
    "'?'; h explains the last one and H (or -v) explains each. When standard",
    "input is a file, the first error ends ed. -s drops byte counts and",
    "notes, -p sets a prompt, -E uses extended expressions, -l exits 0 after",
    "failed commands, -r refuses shell commands and paths. Exit status: 0, 1",
    "after a failed command or an unreadable FILE, 2 when input ended with",
    "unsaved changes or a script file could not load FILE.",
    (char *) NULL
};

struct builtin ed_struct = {
    "ed",
    ed_builtin,
    BUILTIN_ENABLED,
    ed_doc,
    "ed [-EGlqrsv] [-p PROMPT] [--strip-trailing-cr] [FILE | !COMMAND]",
    0
};
