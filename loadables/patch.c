/* SPDX-License-Identifier: MIT */
/* patch.c — apply unified and normal diffs, as GNU patch 2.8 does.
 *
 *   patch [-bEfNRst] [-p N] [-F N] [-i PATCHFILE] [-o OUT] [-r REJ] [-d DIR]
 *         [-z SUFFIX] [--dry-run] [ORIGFILE [PATCHFILE]]
 *
 * The patch is read whole from -i, the second operand or standard input (a
 * pipe works). Each file's hunks are located the way GNU's locate_hunk does:
 * at the expected line plus the offset earlier hunks needed, then nearer
 * lines first, after or before; with fuzz 1 and 2 the outer context lines
 * may differ. A hunk at the start or end of a file, shown by its shorter
 * context there, must stay there.
 *
 * Messages match GNU's on standard output: "patching file F", "Hunk #N
 * succeeded at L with fuzz F (offset K lines).", "Hunk #N FAILED at L." and
 * "N out of M hunks FAILED -- saving rejects to file F.rej". Failed hunks go
 * to F.rej in unified form, and a file that did not match exactly is first
 * kept as F.orig. The questions GNU asks on a terminal (a reversed patch, a
 * file that cannot be found, a creation over an existing file) are answered
 * with their defaults, as GNU answers them without a terminal; -N skips
 * reversed patches and -t applies them reversed. -p absent means the base
 * name. Context diffs (diff -c) are not supported. Fuzz never exceeds a
 * hunk's context, so deleted lines always match exactly. A header time at
 * the Epoch (diff -N) marks a file absent: created, or removed once empty.
 *
 * Exit status: 0 when everything applied, 1 when a hunk failed or was
 * skipped, 2 on a malformed patch or another error.
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
#include <stdarg.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct { char *text; size_t len; char kind; int nonl; } bp_line;

typedef struct {
    long old_start, old_count, new_start, new_count;
    long first, newfirst;      /* where the hunk applies, GNU's p_first */
    bp_line *lines;
    size_t n;
    char *function;            /* text after the closing @@ */
    long input_line;           /* line of the @@ (or command) in the patch */
} bp_hunk;

typedef struct {
    char *old_name, *new_name;     /* as written, NULL for /dev/null */
    char *old_time, *new_time;     /* from the tab on, or NULL */
    int old_null, new_null, git_new, git_delete, normal;
    bp_hunk *hunks;
    size_t nh;
    size_t lead_start, lead_end;   /* the text leading up to the first hunk */
} bp_file;

typedef struct {
    int strip, reverse, forward, force, batch, silent, remove_empty, backup;
    int backup_mismatch, dry_run, maxfuzz;
    const char *output, *reject, *suffix, *origfile;
    const char *text;              /* the whole patch */
    size_t text_len;
} bp_opts;

typedef struct { char *text; size_t len; int nl; } bp_fline;

static void bp_say (const bp_opts *o, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

static void
bp_say (const bp_opts *o, const char *fmt, ...)
{
    if (o->silent) return;
    va_list ap;
    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
}

static void
bp_free_files (bp_file *files, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < files[i].nh; j++) {
            for (size_t k = 0; k < files[i].hunks[j].n; k++) free (files[i].hunks[j].lines[k].text);
            free (files[i].hunks[j].lines);
            free (files[i].hunks[j].function);
        }
        free (files[i].hunks);
        free (files[i].old_name); free (files[i].new_name);
        free (files[i].old_time); free (files[i].new_time);
    }
    free (files);
}

/* Line iterator over the patch text. */
typedef struct { const char *s; size_t len, at; long number; } bp_reader;

static int
bp_next (bp_reader *r, const char **line, size_t *len, size_t *start)
{
    if (r->at >= r->len) return 0;
    const char *p = r->s + r->at;
    const char *nl = memchr (p, '\n', r->len - r->at);
    *line = p;
    *len = nl ? (size_t) (nl - p) : r->len - r->at;
    if (start) *start = r->at;
    r->at += *len + (nl ? 1 : 0);
    r->number++;
    return 1;
}

static int
bp_peek (const bp_reader *r, int skip, const char **line, size_t *len)
{
    bp_reader copy = *r;
    for (int i = 0; i <= skip; i++)
        if (!bp_next (&copy, line, len, NULL)) return 0;
    return 1;
}

static char *
bp_dup (const char *s, size_t n)
{
    char *d = malloc (n + 1);
    if (!d) return NULL;
    memcpy (d, s, n);
    d[n] = '\0';
    return d;
}

/* "--- NAME\tTIME": the name runs to a tab, or to the end of the line. */
static int
bp_header_name (const char *line, size_t len, char **name, char **time, int *is_null)
{
    const char *p = line + 4, *end = line + len;
    while (end > p && (end[-1] == '\r')) end--;
    const char *tab = memchr (p, '\t', (size_t) (end - p));
    const char *name_end = tab ? tab : end;
    if (!tab) while (name_end > p && name_end[-1] == ' ') name_end--;
    *name = bp_dup (p, (size_t) (name_end - p));
    *time = tab ? bp_dup (tab, (size_t) (end - tab)) : NULL;
    if (!*name || (tab && !*time)) return -1;
    *is_null = !strcmp (*name, "/dev/null");
    return 0;
}

static int
bp_parse_range (const char **p, long *start, long *count)
{
    char *end;
    errno = 0;
    *start = strtol (*p, &end, 10);
    if (end == *p || errno) return -1;
    *count = 1;
    if (*end == ',') {
        const char *q = end + 1;
        *count = strtol (q, &end, 10);
        if (end == q || errno) return -1;
    }
    *p = end;
    return 0;
}

static int
bp_add_line (bp_hunk *h, size_t *cap, char kind, const char *text, size_t len)
{
    if (h->n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        bp_line *g = realloc (h->lines, nc * sizeof *g);
        if (!g) return -1;
        h->lines = g;
        *cap = nc;
    }
    bp_line *l = &h->lines[h->n];
    l->text = bp_dup (text, len);
    if (!l->text) return -1;
    l->len = len;
    l->kind = kind;
    l->nonl = 0;
    h->n++;
    return 0;
}

/* Does LINE start a normal-diff command such as 5c5 or 3,4d2? */
static int
bp_normal_cmd (const char *line, size_t len, long *l1, long *l2, char *cmd, long *r1, long *r2)
{
    char buf[128];
    if (!len || len >= sizeof buf || !isdigit ((unsigned char) line[0])) return 0;
    memcpy (buf, line, len);
    buf[len] = '\0';
    const char *p = buf;
    long c1, c2;
    if (bp_parse_range (&p, l1, &c1) < 0) return 0;
    /* bp_parse_range reads "a,b" as start a, count b; in a normal diff the
       second number is the last line. */
    *l2 = memchr (buf, ',', (size_t) (p - buf)) ? c1 : *l1;
    if (*p != 'a' && *p != 'c' && *p != 'd') return 0;
    *cmd = *p++;
    const char *q = p;
    if (bp_parse_range (&p, r1, &c2) < 0 || *p) return 0;
    *r2 = memchr (q, ',', (size_t) (p - q)) ? c2 : *r1;
    return *l2 >= *l1 && *r2 >= *r1;
}

/* Parse the patch into files and hunks. Returns 0, or 2 after a message. */
static int
bp_parse (const bp_opts *o, bp_file **out, size_t *n_out)
{
    bp_reader r = { o->text, o->text_len, 0, 0 };
    bp_file *files = NULL;
    size_t n = 0, cap = 0, lead = 0;
    int git_new = 0, git_delete = 0;
    const char *line, *next, *next2;
    size_t len, next_len, next2_len, start;

    while (bp_next (&r, &line, &len, &start)) {
        if (len >= 11 && !strncmp (line, "diff --git ", 11)) { git_new = git_delete = 0; continue; }
        if (len >= 13 && !strncmp (line, "new file mode", 13)) { git_new = 1; continue; }
        if (len >= 17 && !strncmp (line, "deleted file mode", 17)) { git_delete = 1; continue; }
        if (len >= 4 && !strncmp (line, "*** ", 4) && bp_peek (&r, 0, &next, &next_len)
            && next_len >= 15 && !strncmp (next, "***************", 15)) {
            builtin_error ("**** context diffs are not supported; use a unified diff (diff -u)");
            bp_free_files (files, n);
            return 2;
        }
        long l1, l2, r1, r2;
        char cmd;
        int unified = len >= 4 && !strncmp (line, "--- ", 4)
            && bp_peek (&r, 0, &next, &next_len) && next_len >= 4 && !strncmp (next, "+++ ", 4)
            && bp_peek (&r, 1, &next2, &next2_len) && next2_len >= 4 && !strncmp (next2, "@@ -", 4);
        int normal = !unified && bp_normal_cmd (line, len, &l1, &l2, &cmd, &r1, &r2);
        if (!unified && !normal) continue;

        if (n == cap) {
            size_t nc = cap ? cap * 2 : 4;
            bp_file *g = realloc (files, nc * sizeof *g);
            if (!g) goto oom;
            files = g;
            cap = nc;
        }
        bp_file *f = &files[n++];
        memset (f, 0, sizeof *f);
        f->git_new = git_new;
        f->git_delete = git_delete;
        git_new = git_delete = 0;
        f->lead_start = lead;
        if (unified) {
            if (bp_header_name (line, len, &f->old_name, &f->old_time, &f->old_null) < 0) goto oom;
            bp_next (&r, &line, &len, NULL);
            if (bp_header_name (line, len, &f->new_name, &f->new_time, &f->new_null) < 0) goto oom;
            f->lead_end = r.at;
        } else {
            f->normal = 1;
            f->lead_end = start;
            r.at = start;   /* reread the command line below */
            r.number--;
        }
        size_t hcap = 0;
        for (;;) {
            if (!bp_peek (&r, 0, &line, &len)) break;
            int is_unified = f->normal ? 0 : len >= 4 && !strncmp (line, "@@ -", 4);
            int is_normal = f->normal && bp_normal_cmd (line, len, &l1, &l2, &cmd, &r1, &r2);
            if (!is_unified && !is_normal) break;
            bp_next (&r, &line, &len, NULL);
            if (f->nh == hcap) {
                size_t nc = hcap ? hcap * 2 : 4;
                bp_hunk *g = realloc (f->hunks, nc * sizeof *g);
                if (!g) goto oom;
                f->hunks = g;
                hcap = nc;
            }
            bp_hunk *h = &f->hunks[f->nh++];
            memset (h, 0, sizeof *h);
            h->input_line = r.number;
            size_t lcap = 0;
            if (is_unified) {
                char *hdr = bp_dup (line, len);
                if (!hdr) goto oom;
                const char *p = hdr + 4;
                int bad = bp_parse_range (&p, &h->old_start, &h->old_count) < 0;
                if (!bad && !strncmp (p, " +", 2)) { p += 2; bad = bp_parse_range (&p, &h->new_start, &h->new_count) < 0; }
                else bad = 1;
                if (!bad && strncmp (p, " @@", 3)) bad = 1;
                if (bad) {
                    builtin_error ("**** malformed patch at line %ld: %s", r.number, hdr);
                    free (hdr);
                    bp_free_files (files, n);
                    return 2;
                }
                h->function = strdup (p + 3);
                free (hdr);
                if (!h->function) goto oom;
                long old_left = h->old_count, new_left = h->new_count;
                while (old_left > 0 || new_left > 0) {
                    if (!bp_next (&r, &line, &len, NULL)) {
                        builtin_error ("**** unexpected end of file in patch");
                        bp_free_files (files, n);
                        return 2;
                    }
                    char k = len ? line[0] : ' ';
                    if (k == '\\') { if (h->n) h->lines[h->n - 1].nonl = 1; continue; }
                    if (k != ' ' && k != '-' && k != '+') {
                        char *shown = bp_dup (line, len);
                        builtin_error ("**** malformed patch at line %ld: %s", r.number, shown ? shown : "");
                        free (shown);
                        bp_free_files (files, n);
                        return 2;
                    }
                    if (bp_add_line (h, &lcap, k, len ? line + 1 : line, len ? len - 1 : 0) < 0) goto oom;
                    if (k != '+') old_left--;
                    if (k != '-') new_left--;
                    if (old_left < 0 || new_left < 0) {
                        builtin_error ("**** malformed patch at line %ld: %s", r.number, "hunk is longer than its header");
                        bp_free_files (files, n);
                        return 2;
                    }
                }
            } else {
                h->old_start = l1;
                h->old_count = cmd == 'a' ? 0 : l2 - l1 + 1;
                h->new_start = r1;
                h->new_count = cmd == 'd' ? 0 : r2 - r1 + 1;
                h->function = strdup ("");
                if (!h->function) goto oom;
                for (int side = 0; side < 2; side++) {
                    long want = side ? h->new_count : h->old_count;
                    if (side && cmd == 'c') {
                        if (!bp_next (&r, &line, &len, NULL) || len != 3 || strncmp (line, "---", 3)) {
                            builtin_error ("**** malformed patch at line %ld: %s", r.number, "expected ---");
                            bp_free_files (files, n);
                            return 2;
                        }
                    }
                    for (long i = 0; i < want; i++) {
                        if (!bp_next (&r, &line, &len, NULL) || len < 2 || line[0] != (side ? '>' : '<') || line[1] != ' ') {
                            builtin_error ("**** malformed patch at line %ld: %s", r.number, "bad normal diff line");
                            bp_free_files (files, n);
                            return 2;
                        }
                        if (bp_add_line (h, &lcap, side ? '+' : '-', line + 2, len - 2) < 0) goto oom;
                        if (bp_peek (&r, 0, &next, &next_len) && next_len && next[0] == '\\') {
                            bp_next (&r, &line, &len, NULL);
                            h->lines[h->n - 1].nonl = 1;
                        }
                    }
                }
            }
            /* A trailing "\ No newline" after the counts ran out. */
            if (bp_peek (&r, 0, &line, &len) && len && line[0] == '\\') {
                bp_next (&r, &line, &len, NULL);
                if (h->n) h->lines[h->n - 1].nonl = 1;
            }
        }
        lead = r.at;
    }
    *out = files;
    *n_out = n;
    return 0;
oom:
    builtin_error ("out of memory");
    bp_free_files (files, n);
    return 2;
}

/* -R: swap the sides of every hunk. */
static void
bp_reverse_hunk (bp_hunk *h)
{
    long t = h->old_start; h->old_start = h->new_start; h->new_start = t;
    t = h->old_count; h->old_count = h->new_count; h->new_count = t;
    /* Keep removed lines ahead of added ones within each change, as diff
       writes them, so a reversed hunk reads like a forward one. */
    size_t i = 0;
    while (i < h->n) {
        if (h->lines[i].kind == ' ') { i++; continue; }
        size_t j = i;
        while (j < h->n && h->lines[j].kind != ' ') j++;
        bp_line *tmp = malloc ((j - i) * sizeof *tmp);
        if (tmp) {
            size_t k = 0;
            for (size_t m = i; m < j; m++) if (h->lines[m].kind == '+') { tmp[k] = h->lines[m]; tmp[k++].kind = '-'; }
            for (size_t m = i; m < j; m++) if (h->lines[m].kind == '-') { tmp[k] = h->lines[m]; tmp[k++].kind = '+'; }
            memcpy (h->lines + i, tmp, (j - i) * sizeof *tmp);
            free (tmp);
        } else
            for (size_t m = i; m < j; m++) h->lines[m].kind = h->lines[m].kind == '+' ? '-' : '+';
        i = j;
    }
}

static void
bp_reverse_file (bp_file *f)
{
    char *t = f->old_name; f->old_name = f->new_name; f->new_name = t;
    t = f->old_time; f->old_time = f->new_time; f->new_time = t;
    int x = f->old_null; f->old_null = f->new_null; f->new_null = x;
    x = f->git_new; f->git_new = f->git_delete; f->git_delete = x;
    for (size_t i = 0; i < f->nh; i++) bp_reverse_hunk (&f->hunks[i]);
}

static void
bp_set_first (bp_hunk *h)
{
    h->first = h->old_start + (h->old_count == 0);
    h->newfirst = h->new_start + (h->new_count == 0);
}

/* -pN on a name; N < 0 (no -p) keeps the base name. */
static char *
bp_strip (const char *name, int strip)
{
    if (!name) return NULL;
    const char *at = name;
    if (strip < 0) {
        const char *slash = strrchr (name, '/');
        at = slash ? slash + 1 : name;
    } else
        for (int i = 0; i < strip; i++) {
            const char *slash = strchr (at, '/');
            if (!slash) break;
            at = slash + 1;
            while (*at == '/') at++;
        }
    return strdup (at);
}

static int
bp_exists (const char *name)
{
    struct stat st;
    return name && *name && stat (name, &st) == 0 && S_ISREG (st.st_mode);
}

/* GNU's best name: fewest components, then the shorter base, then shorter. */
static int
bp_better (const char *a, const char *b)
{
    size_t ca = 0, cb = 0;
    for (const char *p = a; *p; p++) ca += *p == '/';
    for (const char *p = b; *p; p++) cb += *p == '/';
    if (ca != cb) return ca < cb;
    const char *ba = strrchr (a, '/'), *bb = strrchr (b, '/');
    size_t la = strlen (ba ? ba + 1 : a), lb = strlen (bb ? bb + 1 : b);
    if (la != lb) return la < lb;
    return strlen (a) <= strlen (b);
}

/* Read a file into lines. */
static int
bp_load (const char *name, bp_fline **out, size_t *n_out, mode_t *mode)
{
    *out = NULL;
    *n_out = 0;
    int fd = open (name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat (fd, &st) < 0) { close (fd); return -1; }
    *mode = st.st_mode & 07777;
    size_t cap = (size_t) st.st_size + 1, len = 0;
    char *buf = malloc (cap);
    if (!buf) { close (fd); return -1; }
    for (;;) {
        if (len == cap) {
            char *g = realloc (buf, cap * 2);
            if (!g) { free (buf); close (fd); return -1; }
            buf = g;
            cap *= 2;
        }
        ssize_t r = read (fd, buf + len, cap - len);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { free (buf); close (fd); return -1; }
        if (!r) break;
        len += (size_t) r;
    }
    close (fd);
    size_t count = 0;
    for (size_t i = 0; i < len; i++) count += buf[i] == '\n';
    if (len && buf[len - 1] != '\n') count++;
    bp_fline *lines = calloc (count + 1, sizeof *lines);
    if (!lines) { free (buf); return -1; }
    size_t k = 0, at = 0;
    while (at < len) {
        char *nl = memchr (buf + at, '\n', len - at);
        size_t l = nl ? (size_t) (nl - buf - at) : len - at;
        lines[k].text = bp_dup (buf + at, l);
        if (!lines[k].text) { for (size_t i = 0; i < k; i++) free (lines[i].text); free (lines); free (buf); return -1; }
        lines[k].len = l;
        lines[k].nl = nl != NULL;
        k++;
        at += l + (nl ? 1 : 0);
    }
    free (buf);
    *out = lines;
    *n_out = k;
    return 0;
}

typedef struct {
    bp_fline *in;
    size_t nin;
    long frozen;       /* input lines already copied to the output */
    long in_offset;
} bp_target;

static long
bp_pattern (const bp_hunk *h, const bp_line **pat, long *prefix, long *suffix)
{
    long m = 0;
    for (size_t i = 0; i < h->n; i++) if (h->lines[i].kind != '+') pat[m++] = &h->lines[i];
    *prefix = 0;
    for (size_t i = 0; i < h->n && h->lines[i].kind == ' '; i++) (*prefix)++;
    *suffix = 0;
    for (size_t i = h->n; i > 0 && h->lines[i - 1].kind == ' '; i--) (*suffix)++;
    if (*prefix == (long) h->n) *suffix = 0;   /* all context */
    return m;
}

static int
bp_match (const bp_target *t, const bp_line **pat, long m, long base, long pf, long sf)
{
    for (long i = pf; i < m - sf; i++) {
        long line = base + i;            /* 1-based */
        if (line < 1 || line > (long) t->nin) return 0;
        const bp_fline *fl = &t->in[line - 1];
        if (fl->len != pat[i]->len || memcmp (fl->text, pat[i]->text, fl->len)) return 0;
    }
    return 1;
}

/* GNU's locate_hunk. Returns the 1-based line, or 0. */
static long
bp_locate (bp_target *t, const bp_hunk *h, long fuzz)
{
    const bp_line **pat = malloc ((h->n + 1) * sizeof *pat);
    if (!pat) return 0;
    long prefix, suffix, m = bp_pattern (h, pat, &prefix, &suffix);
    long first_guess = h->first + t->in_offset;
    long context = prefix < suffix ? suffix : prefix;
    long pf = fuzz + prefix - context, sf = fuzz + suffix - context;
    long input = (long) t->nin;
    long max_where = input - (m - sf) + 1;
    long min_where = t->frozen + 1 - (prefix - pf);
    long max_pos = max_where - first_guess, max_neg = first_guess - min_where;
    long max_offset = max_pos < max_neg ? max_neg : max_pos;
    long where = 0;

    if (!m) { where = first_guess; goto done; }
    if (first_guess <= max_neg) max_neg = first_guess - 1;
    if (pf < 0 && h->first <= 1) {
        if (sf < 0 && (m != input || prefix < t->frozen)) goto done;
        long offset = 1 - first_guess;
        if (t->frozen <= prefix && offset <= max_pos && bp_match (t, pat, m, first_guess + offset, 0, sf < 0 ? 0 : sf)) {
            t->in_offset += offset;
            where = first_guess + offset;
        }
        goto done;
    } else if (pf < 0)
        pf = 0;
    if (sf < 0) {
        long offset = first_guess - (input - m + 1);
        if (offset <= max_neg && bp_match (t, pat, m, first_guess - offset, pf, 0)) {
            t->in_offset -= offset;
            where = first_guess - offset;
        }
        goto done;
    }
    for (long offset = 0; offset <= max_offset; offset++) {
        if (offset <= max_pos && bp_match (t, pat, m, first_guess + offset, pf, sf)) {
            t->in_offset += offset;
            where = first_guess + offset;
            goto done;
        }
        if (offset <= max_neg && bp_match (t, pat, m, first_guess - offset, pf, sf)) {
            t->in_offset -= offset;
            where = first_guess - offset;
            goto done;
        }
    }
done:
    free (pat);
    return where;
}

typedef struct { bp_fline *lines; size_t n, cap; } bp_outbuf;

static int
bp_emit (bp_outbuf *o, const char *text, size_t len, int nl)
{
    if (o->n == o->cap) {
        size_t nc = o->cap ? o->cap * 2 : 64;
        bp_fline *g = realloc (o->lines, nc * sizeof *g);
        if (!g) return -1;
        o->lines = g;
        o->cap = nc;
    }
    o->lines[o->n].text = (char *) text;   /* borrowed */
    o->lines[o->n].len = len;
    o->lines[o->n].nl = nl;
    o->n++;
    return 0;
}

static int
bp_copy_to (bp_outbuf *o, bp_target *t, long upto)
{
    while (t->frozen < upto && t->frozen < (long) t->nin) {
        const bp_fline *fl = &t->in[t->frozen++];
        if (bp_emit (o, fl->text, fl->len, fl->nl) < 0) return -1;
    }
    return 0;
}

/* Apply hunk H at WHERE: context comes from the file, '+' lines from the
   hunk. */
static int
bp_apply (bp_outbuf *o, bp_target *t, const bp_hunk *h, long where)
{
    if (bp_copy_to (o, t, where - 1) < 0) return -1;
    for (size_t i = 0; i < h->n; i++) {
        const bp_line *l = &h->lines[i];
        if (l->kind == '+') {
            if (bp_emit (o, l->text, l->len, !l->nonl) < 0) return -1;
        } else if (l->kind == ' ') {
            if (t->frozen < (long) t->nin) {
                const bp_fline *fl = &t->in[t->frozen++];
                if (bp_emit (o, fl->text, fl->len, l->nonl ? fl->nl : 1) < 0) return -1;
            }
        } else if (t->frozen < (long) t->nin)
            t->frozen++;
    }
    return 0;
}

static void
bp_range (FILE *fp, long start, long count)
{
    if (count == 0) fprintf (fp, "%ld,0", start - 1);
    else if (count == 1) fprintf (fp, "%ld", start);
    else fprintf (fp, "%ld,%ld", start, count);
}

static void
bp_reject_line (FILE *fp, char kind, const bp_line *l)
{
    fputc (kind, fp);
    fwrite (l->text, 1, l->len, fp);
    fputc ('\n', fp);
    if (l->nonl) fputs ("\\ No newline at end of file\n", fp);
}

static void
bp_reject_hunk (FILE *fp, const bp_hunk *h, long out_offset)
{
    fputs ("@@ -", fp);
    bp_range (fp, h->first + out_offset, h->old_count);
    fputs (" +", fp);
    bp_range (fp, h->newfirst + out_offset, h->new_count);
    fprintf (fp, " @@%s\n", h->function ? h->function : "");
    /* Removed lines of a change ahead of the added ones, as GNU writes. */
    size_t i = 0;
    while (i < h->n) {
        if (h->lines[i].kind == ' ') { bp_reject_line (fp, ' ', &h->lines[i]); i++; continue; }
        size_t j = i;
        while (j < h->n && h->lines[j].kind != ' ') j++;
        for (size_t k = i; k < j; k++) if (h->lines[k].kind == '-') bp_reject_line (fp, '-', &h->lines[k]);
        for (size_t k = i; k < j; k++) if (h->lines[k].kind == '+') bp_reject_line (fp, '+', &h->lines[k]);
        i = j;
    }
}

static int
bp_mkdirs (const char *path)
{
    char *copy = strdup (path);
    if (!copy) return -1;
    for (char *p = copy + 1; *p; p++)
        if (*p == '/') {
            *p = '\0';
            if (mkdir (copy, 0777) < 0 && errno != EEXIST) { free (copy); return -1; }
            *p = '/';
        }
    free (copy);
    return 0;
}

static int
bp_write_file (const char *name, const bp_outbuf *o, mode_t mode)
{
    if (bp_mkdirs (name) < 0) return -1;
    size_t nlen = strlen (name);
    char *tmp = malloc (nlen + 16);
    if (!tmp) return -1;
    const char *slash = strrchr (name, '/');
    size_t dir = slash ? (size_t) (slash - name + 1) : 0;
    snprintf (tmp, nlen + 16, "%.*s.patchXXXXXX", (int) dir, name);
    int fd = mkstemp (tmp);
    if (fd < 0) { free (tmp); return -1; }
    FILE *fp = fdopen (fd, "w");
    if (!fp) { close (fd); unlink (tmp); free (tmp); return -1; }
    for (size_t i = 0; i < o->n; i++) {
        fwrite (o->lines[i].text, 1, o->lines[i].len, fp);
        if (o->lines[i].nl || i + 1 < o->n) fputc ('\n', fp);
    }
    int bad = ferror (fp);
    if (fchmod (fileno (fp), mode) < 0) bad = 1;
    if (fclose (fp) == EOF) bad = 1;
    if (bad || rename (tmp, name) < 0) { int e = errno; unlink (tmp); free (tmp); errno = e; return -1; }
    free (tmp);
    return 0;
}

static int
bp_backup (const bp_opts *o, const char *name)
{
    const char *suffix = o->suffix ? o->suffix : ".orig";
    size_t n = strlen (name) + strlen (suffix) + 1;
    char *bak = malloc (n);
    if (!bak) return -1;
    snprintf (bak, n, "%s%s", name, suffix);
    unlink (bak);
    int rc = link (name, bak);
    if (rc < 0) {
        /* No hard links here: copy instead. */
        bp_fline *lines;
        size_t count;
        mode_t mode;
        if (bp_load (name, &lines, &count, &mode) == 0) {
            bp_outbuf out = { lines, count, count };
            rc = bp_write_file (bak, &out, mode);
            for (size_t i = 0; i < count; i++) free (lines[i].text);
            free (lines);
        }
    }
    free (bak);
    return rc;
}

static void
bp_show_lead (const bp_opts *o, const bp_file *f)
{
    printf ("--------------------------\n");
    const char *p = o->text + f->lead_start, *end = o->text + f->lead_end;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t l = nl ? (size_t) (nl - p) : (size_t) (end - p);
        printf ("|%.*s\n", (int) l, p);
        p += l + (nl ? 1 : 0);
    }
    printf ("--------------------------\n");
}

static const char *
bp_hunks_word (size_t n)
{
    return n == 1 ? "hunk" : "hunks";
}

/* Does a header time (from the tab on) name the Epoch? diff -N writes a
   missing side as "1970-01-01 00:00:00.000000000 +0000" (in its time zone),
   and GNU patch then treats that file as absent: created, or removed when
   the patch leaves it empty. */
static int
bp_is_epoch (const char *t)
{
    if (!t) return 0;
    while (*t == '\t' || *t == ' ') t++;
    int y, mo, d, h, mi, sec, n = 0;
    if (sscanf (t, "%4d-%2d-%2d %2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &sec, &n) != 6) return 0;
    t += n;
    if (*t == '.') { t++; while (*t == '0') t++; if (isdigit ((unsigned char) *t)) return 0; }
    long zone = 0;
    while (*t == ' ') t++;
    if (*t == '+' || *t == '-') {
        int sign = *t == '-' ? -1 : 1, hh, mm;
        if (sscanf (t + 1, "%2d%2d", &hh, &mm) != 2) return 0;
        zone = sign * (hh * 3600L + mm * 60L);
    }
    /* Days from the civil date (proleptic Gregorian). */
    long yy = y - (mo <= 2), era = (yy >= 0 ? yy : yy - 399) / 400;
    long yoe = yy - era * 400, doy = (153L * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    return days * 86400 + h * 3600L + mi * 60L + sec - zone == 0;
}

/* Patch one file. Returns 0, 1 (hunks failed or skipped) or 2. */
static int
bp_patch_file (const bp_opts *o, bp_file *f)
{
    char *old = f->old_null ? NULL : bp_strip (f->old_name, o->strip);
    char *new = f->new_null ? NULL : bp_strip (f->new_name, o->strip);
    const char *name = NULL;
    int creating = 0, rc = 0;
    for (size_t i = 0; i < f->nh; i++) bp_set_first (&f->hunks[i]);

    int all_empty_old = 1;
    for (size_t i = 0; i < f->nh; i++) if (f->hunks[i].old_count) all_empty_old = 0;
    if (o->origfile) name = o->origfile;
    else if (f->old_null || f->git_new) { name = new ? new : old; creating = 1; }
    else if (f->new_null || f->git_delete) name = old ? old : new;
    else if (bp_is_epoch (f->old_time) && !bp_exists (new) && !bp_exists (old)) { name = new ? new : old; creating = 1; }
    else {
        int oe = bp_exists (old), ne = bp_exists (new);
        if (oe && ne) name = bp_better (old, new) ? old : new;
        else if (oe) name = old;
        else if (ne) name = new;
        else if (all_empty_old) { name = new ? new : old; creating = 1; }
    }
    if (!name || !*name || (!creating && !bp_exists (name))) {
        long at = f->nh ? f->hunks[0].input_line : 0;
        printf ("can't find file to patch at input line %ld\n", at);
        printf ("Perhaps you %s -p or --strip option?\n", o->strip < 0 ? "should have used the" : "used the wrong");
        printf ("The text leading up to this was:\n");
        bp_show_lead (o, f);
        printf ("File to patch: \nSkip this patch? [y] \nSkipping patch.\n");
        printf ("%zu out of %zu %s ignored\n", f->nh, f->nh, bp_hunks_word (f->nh));
        free (old); free (new);
        return 1;
    }

    bp_target t = { NULL, 0, 0, 0 };
    mode_t mode = 0666 & ~0022;
    {
        mode_t mask = umask (0);
        umask (mask);
        mode = 0666 & ~mask;
    }
    int existed = bp_exists (name);
    if (existed && bp_load (name, &t.in, &t.nin, &mode) < 0) {
        builtin_error ("**** Can't open file %s : %s", name, strerror (errno));
        free (old); free (new);
        return 2;
    }
    const char *dest = o->output ? o->output : name;
    if (creating && existed && t.nin && !o->force && !o->batch) {
        bp_say (o, "The next patch would create the file %s,\nwhich already exists!  ", name);
        if (o->forward) bp_say (o, "Skipping patch.\n");
        else bp_say (o, "Assume -R? [n] \nApply anyway? [n] \nSkipping patch.\n");
        printf ("%zu out of %zu %s ignored\n", f->nh, f->nh, bp_hunks_word (f->nh));
        rc = 1;
        goto out_noreject;
    }
    if (o->output && strcmp (o->output, name))
        bp_say (o, "%s file %s (read from %s)\n", o->dry_run ? "checking" : "patching", dest, name);
    else
        bp_say (o, "%s file %s\n", o->dry_run ? "checking" : "patching", dest);

    int skip = 0, reversed_now = 0;

    bp_outbuf out = { NULL, 0, 0 };
    size_t failed = 0;
    int mismatch = 0;
    long out_offset = 0;
    char *rejname = NULL;
    FILE *rej = NULL;
    for (size_t hi = 0; hi < f->nh; hi++) {
        bp_hunk *h = &f->hunks[hi];
        long where = 0, fuzz = 0;
        /* GNU caps the fuzz at the hunk's context (pch_context): fuzz only
           drops context lines, never the lines a hunk deletes or changes. */
        long mymaxfuzz = o->maxfuzz, hprefix = 0, hsuffix = 0;
        for (size_t k = 0; k < h->n && h->lines[k].kind == ' '; k++) hprefix++;
        for (size_t k = h->n; k > 0 && h->lines[k - 1].kind == ' '; k--) hsuffix++;
        if (hprefix == (long) h->n) hsuffix = 0;
        if (mymaxfuzz > (hprefix > hsuffix ? hprefix : hsuffix))
            mymaxfuzz = hprefix > hsuffix ? hprefix : hsuffix;
        if (!skip) {
            do {
                where = bp_locate (&t, h, fuzz);
                if (hi == 0 && !where && !o->force && !reversed_now) {
                    bp_reverse_hunk (h);
                    bp_set_first (h);
                    long saved = t.in_offset;
                    long rwhere = bp_locate (&t, h, fuzz);
                    if (rwhere) {
                        const char *what = o->reverse ? "Unreversed patch detected!" : "Reversed (or previously applied) patch detected!";
                        if (o->batch) {
                            bp_say (o, "%s  Assuming -R.\n", what);
                            reversed_now = 1;
                            mismatch = 1;   /* the forward try failed */
                            where = rwhere;
                            for (size_t k = 1; k < f->nh; k++) { bp_reverse_hunk (&f->hunks[k]); bp_set_first (&f->hunks[k]); }
                            break;
                        }
                        t.in_offset = saved;
                        bp_reverse_hunk (h);
                        bp_set_first (h);
                        if (o->forward) bp_say (o, "%s  Skipping patch.\n", what);
                        else bp_say (o, "%s  %s -R? [n] \nApply anyway? [n] \nSkipping patch.\n", what, o->reverse ? "Ignore" : "Assume");
                        skip = 1;
                        break;
                    }
                    t.in_offset = saved;
                    bp_reverse_hunk (h);
                    bp_set_first (h);
                }
            } while (!where && ++fuzz <= mymaxfuzz);
        }
        if (!where || skip) {
            failed++;
            mismatch = 1;
            if (!skip) bp_say (o, "Hunk #%zu FAILED at %ld.\n", hi + 1, h->newfirst + t.in_offset);
            if (!o->dry_run && !rej && !(o->reject && !strcmp (o->reject, "-"))) {
                if (o->reject) rejname = strdup (o->reject);
                else {
                    size_t n = strlen (dest) + 5;
                    rejname = malloc (n);
                    if (rejname) snprintf (rejname, n, "%s.rej", dest);
                }
                rej = rejname ? fopen (rejname, "w") : NULL;
                if (rej) {
                    char *ro = bp_strip (f->old_name, o->strip), *rn = bp_strip (f->new_name, o->strip);
                    fprintf (rej, "--- %s%s\n", f->old_null ? "/dev/null" : ro ? ro : "", f->old_time ? f->old_time : "");
                    fprintf (rej, "+++ %s%s\n", f->new_null ? "/dev/null" : rn ? rn : "", f->new_time ? f->new_time : "");
                    free (ro); free (rn);
                }
            }
            if (rej) bp_reject_hunk (rej, h, out_offset);
            continue;
        }
        if (fuzz || t.in_offset) mismatch = 1;
        if (fuzz || t.in_offset) {
            bp_say (o, "Hunk #%zu succeeded at %ld", hi + 1, h->newfirst + t.in_offset);
            if (fuzz) bp_say (o, " with fuzz %ld", fuzz);
            if (t.in_offset) bp_say (o, " (offset %ld line%s)", t.in_offset, t.in_offset == 1 ? "" : "s");
            bp_say (o, ".\n");
        }
        if (bp_apply (&out, &t, h, where) < 0) { builtin_error ("out of memory"); rc = 2; goto out; }
        out_offset = t.in_offset + (long) out.n - t.frozen;
    }
    if (failed) {
        rc = 1;
        printf ("%zu out of %zu %s %s", failed, f->nh, bp_hunks_word (f->nh), skip ? "ignored" : "FAILED");
        if (rej) printf (" -- saving rejects to file %s", rejname);
        printf ("\n");
    }
    if (!skip && !o->dry_run) {
        if (bp_copy_to (&out, &t, (long) t.nin) < 0) { builtin_error ("out of memory"); rc = 2; goto out; }
        int remove = !out.n && (o->remove_empty || f->new_null || f->git_delete || bp_is_epoch (f->new_time)) && !o->output;
        if (existed && (o->backup || (mismatch && o->backup_mismatch)) && !o->output) {
            if (bp_backup (o, name) < 0) { builtin_error ("**** Can't back up %s : %s", name, strerror (errno)); rc = 2; goto out; }
        }
        if (remove) {
            if (existed && unlink (name) < 0) { builtin_error ("**** Can't remove %s : %s", name, strerror (errno)); rc = 2; }
        } else if (bp_write_file (dest, &out, mode) < 0) {
            builtin_error ("**** Can't create file %s : %s", dest, strerror (errno));
            rc = 2;
        }
    }
out:
    if (rej && fclose (rej) == EOF) rc = 2;
    free (rejname);
    free (out.lines);
out_noreject:
    for (size_t i = 0; i < t.nin; i++) free (t.in[i].text);
    free (t.in);
    free (old); free (new);
    return rc;
}

static int
bp_slurp_fd (int fd, char **out, size_t *len)
{
    size_t cap = 65536, n = 0;
    char *buf = malloc (cap);
    if (!buf) return -1;
    for (;;) {
        if (n == cap) {
            char *g = realloc (buf, cap * 2);
            if (!g) { free (buf); return -1; }
            buf = g;
            cap *= 2;
        }
        ssize_t r = read (fd, buf + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { free (buf); return -1; }
        if (!r) break;
        n += (size_t) r;
    }
    *out = buf;
    *len = n;
    return 0;
}

static int
bp_number (const char *s, int *out)
{
    char *end;
    errno = 0;
    long v = strtol (s, &end, 10);
    if (!*s || *end || errno || v < 0 || v > INT_MAX) return -1;
    *out = (int) v;
    return 0;
}

int
patch_builtin (WORD_LIST *list)
{
    bp_opts o;
    memset (&o, 0, sizeof o);
    o.strip = -1;
    o.backup_mismatch = 1;
    o.maxfuzz = 2;
    const char *input = NULL, *dir = NULL, *operands[2] = { NULL, NULL };
    int nops = 0, end_options = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_options && !strcmp (w, "--")) { end_options = 1; continue; }
        if (!end_options && w[0] == '-' && w[1] == '-') {
            const char *eq = strchr (w, '=');
            size_t nl = eq ? (size_t) (eq - w) : strlen (w);
            const char *val = eq ? eq + 1 : NULL;
            static const char *const with_arg[] = { "--strip", "--input", "--output", "--reject-file",
                                                    "--directory", "--fuzz", "--suffix", NULL };
            int takes = 0;
            for (int i = 0; with_arg[i]; i++) if (strlen (with_arg[i]) == nl && !strncmp (w, with_arg[i], nl)) takes = 1;
            if (takes && !val) {
                if (!p->next) { builtin_error ("option '%s' requires an argument", w); return 2; }
                p = p->next;
                val = p->word->word;
            }
#define BP_IS(s) (strlen (s) == nl && !strncmp (w, s, nl))
            if (BP_IS ("--strip")) { if (bp_number (val, &o.strip) < 0) { builtin_error ("strip count %s is not a number", val); return 2; } }
            else if (BP_IS ("--input")) input = val;
            else if (BP_IS ("--output")) o.output = val;
            else if (BP_IS ("--reject-file")) o.reject = val;
            else if (BP_IS ("--directory")) dir = val;
            else if (BP_IS ("--suffix")) o.suffix = val;
            else if (BP_IS ("--fuzz")) { if (bp_number (val, &o.maxfuzz) < 0) { builtin_error ("fuzz factor %s is not a number", val); return 2; } }
            else if (BP_IS ("--reverse")) o.reverse = 1;
            else if (BP_IS ("--forward")) o.forward = 1;
            else if (BP_IS ("--force")) o.force = 1;
            else if (BP_IS ("--batch")) o.batch = 1;
            else if (BP_IS ("--silent") || BP_IS ("--quiet")) o.silent = 1;
            else if (BP_IS ("--remove-empty-files")) o.remove_empty = 1;
            else if (BP_IS ("--backup")) o.backup = 1;
            else if (BP_IS ("--backup-if-mismatch")) o.backup_mismatch = 1;
            else if (BP_IS ("--no-backup-if-mismatch")) o.backup_mismatch = 0;
            else if (BP_IS ("--dry-run")) o.dry_run = 1;
            else if (BP_IS ("--unified") || BP_IS ("--normal") || BP_IS ("--binary") || BP_IS ("--verbose")) ;
            else if (BP_IS ("--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
            else if (BP_IS ("--version")) { puts ("patch (bash-os) 0.1.5"); return EXECUTION_SUCCESS; }
            else { builtin_error ("unrecognized option '%s'", w); builtin_error ("Try 'patch --help' for more information."); return 2; }
#undef BP_IS
            continue;
        }
        if (!end_options && w[0] == '-' && w[1]) {
            for (int i = 1; w[i]; i++) {
                char c = w[i];
                if (strchr ("pioFrdz", c)) {
                    const char *val = w[i + 1] ? &w[i + 1] : NULL;
                    if (!val) {
                        if (!p->next) { builtin_error ("option requires an argument -- '%c'", c); return 2; }
                        p = p->next;
                        val = p->word->word;
                    }
                    if (c == 'p') { if (bp_number (val, &o.strip) < 0) { builtin_error ("strip count %s is not a number", val); return 2; } }
                    else if (c == 'F') { if (bp_number (val, &o.maxfuzz) < 0) { builtin_error ("fuzz factor %s is not a number", val); return 2; } }
                    else if (c == 'i') input = val;
                    else if (c == 'o') o.output = val;
                    else if (c == 'r') o.reject = val;
                    else if (c == 'd') dir = val;
                    else o.suffix = val;
                    break;
                }
                switch (c) {
                case 'R': o.reverse = 1; break;
                case 'N': o.forward = 1; break;
                case 'f': o.force = 1; break;
                case 't': o.batch = 1; break;
                case 's': o.silent = 1; break;
                case 'E': o.remove_empty = 1; break;
                case 'b': o.backup = 1; break;
                case 'u': case 'n': case 'l': break;
                default:
                    builtin_error ("invalid option -- '%c'", c);
                    builtin_error ("Try 'patch --help' for more information.");
                    return 2;
                }
            }
            continue;
        }
        if (nops >= 2) { builtin_error ("**** Only one file and one patch can be given"); return 2; }
        operands[nops++] = w;
    }
    o.origfile = operands[0];
    if (operands[1]) input = operands[1];

    int saved_cwd = -1;
    if (dir) {
        saved_cwd = open (".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (saved_cwd < 0 || chdir (dir) < 0) {
            builtin_error ("**** Can't change to directory %s : %s", dir, strerror (errno));
            if (saved_cwd >= 0) close (saved_cwd);
            return 2;
        }
    }
    int rc = 0;
    char *text = NULL;
    size_t text_len = 0;
    int fd = input && strcmp (input, "-") ? open (input, O_RDONLY | O_CLOEXEC) : STDIN_FILENO;
    if (fd < 0 || bp_slurp_fd (fd, &text, &text_len) < 0) {
        builtin_error ("**** Can't open patch file %s : %s", input ? input : "-", strerror (errno));
        if (fd > STDIN_FILENO) close (fd);
        rc = 2;
        goto done;
    }
    if (fd != STDIN_FILENO) close (fd);
    o.text = text;
    o.text_len = text_len;

    bp_file *files = NULL;
    size_t nfiles = 0;
    rc = bp_parse (&o, &files, &nfiles);
    if (rc) goto done;
    if (!nfiles) {
        fflush (stdout);
        builtin_error ("**** Only garbage was found in the patch input.");
        rc = 2;
        goto done;
    }
    for (size_t i = 0; i < nfiles; i++) {
        if (o.reverse) bp_reverse_file (&files[i]);
        int r = bp_patch_file (&o, &files[i]);
        if (r > rc) rc = r;
        if (r == 2) break;
    }
    bp_free_files (files, nfiles);
done:
    free (text);
    if (fflush (stdout) == EOF || ferror (stdout)) { clearerr (stdout); if (!rc) rc = 2; }
    if (saved_cwd >= 0) {
        if (fchdir (saved_cwd) < 0) { builtin_error ("cannot return to the previous directory: %s", strerror (errno)); rc = 2; }
        close (saved_cwd);
    }
    return rc;
}

char *patch_doc[] = {
    "Apply a unified or normal diff to files.",
    "",
    "    patch [-bEfNRst] [-p N] [-F N] [-i PATCHFILE] [-o OUT] [-r REJ]",
    "          [-d DIR] [-z SUFFIX] [--dry-run] [ORIGFILE [PATCHFILE]]",
    "",
    "The patch comes from -i, PATCHFILE or standard input. Hunks are found",
    "with offsets and up to -F (default 2) lines of fuzz; failed hunks go to",
    "FILE.rej, and a file that did not match exactly is kept as FILE.orig",
    "(--no-backup-if-mismatch turns that off, -b always backs up). -p N",
    "strips N leading path parts; without -p the base name is used. -R",
    "reverses, -N skips reversed patches, -t applies them reversed, -f",
    "does not check, -E removes files left empty, -s is quiet. Questions",
    "GNU patch asks on a terminal get their default answers. Context diffs",
    "are not supported.",
    (char *)NULL
};

struct builtin patch_struct = {
    "patch",
    patch_builtin,
    BUILTIN_ENABLED,
    patch_doc,
    "patch [-bEfNRst] [-p N] [-F N] [-i PATCH] [-o OUT] [-d DIR] [FILE [PATCH]]",
    0
};
