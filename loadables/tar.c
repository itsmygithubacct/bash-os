/* SPDX-License-Identifier: MIT */
/* GNU-style tar interface to bash-os's ustar/PAX archive engine. */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1   /* fopencookie */
#endif
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include "loadables.h"
#include "pax-stream.h"
#include "gzip-stream.h"
#include "date-parse.h"

struct tar_arg { const char *text; int directory; };

#define TAR_TRY "Try 'tar --help' or 'tar --usage' for more information.\n"

/* ---- -N/--newer/--after-date DATE and --newer-mtime DATE ------------------ */
struct tar_newer {
    int set, mtime_only, from_file, unknown;
    time_t sec;
    long nsec;
    const char *text, *option;
};

/* DATE as GNU tar reads it: a name starting with '/' or '.' is a file whose
   modification time is used; anything else is a date string (date -d's
   grammar). An unknown date is GNU's "Substituting" the earliest time.
   Returns 0, or -1 after GNU's diagnostics (exit 2). */
static int tar_newer_date(struct tar_newer *n, const char *option, const char *value, int mtime_only)
{
    n->set = 1; n->option = option; n->text = value; n->from_file = n->unknown = 0;
    n->mtime_only = mtime_only;
    if (*value == '/' || *value == '.') {
        struct stat st;
        if (stat(value, &st) < 0) {
            builtin_error("%s: Cannot stat: %s", value, strerror(errno));
            builtin_error("Date sample file not found");
            fputs(TAR_TRY, stderr);
            return -1;
        }
        n->sec = st.st_mtim.tv_sec; n->nsec = st.st_mtim.tv_nsec; n->from_file = 1;
        return 0;
    }
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    time_t t; long ns;
    if (bd_parse_date(value, &now, &t, &ns, 0) < 0) {
        builtin_error("Substituting %lld for unknown date format '%s'", LLONG_MIN + 1, value);
        n->sec = (time_t)(LLONG_MIN + 1); n->nsec = 0; n->unknown = 1;
        return 0;
    }
    n->sec = t; n->nsec = ns;
    return 0;
}

/* GNU tar's note (with -v, and when listing) of how a date was read,
   unless it was written that way already. */
static void tar_newer_note(const struct tar_newer *n)
{
    if (!n->set || n->from_file || n->unknown) return;
    struct tm tm; time_t t = n->sec; char when[80];
    if (!localtime_r(&t, &tm) || !strftime(when, 64, "%Y-%m-%d %H:%M:%S", &tm)) return;
    if (n->nsec) {
        char frac[16]; snprintf(frac, sizeof frac, ".%09ld", n->nsec);
        size_t l = strlen(frac);
        while (l > 1 && frac[l-1] == '0') frac[--l] = 0;
        strcat(when, frac);
    }
    if (strcmp(when, n->text)) builtin_error("Option %s: Treating date '%s' as %s", n->option, n->text, when);
}

/* ---- -g/--listed-incremental and -G/--incremental on create -------------- */
/* A directory of the snapshot file (format 2, as GNU tar 1.35 writes it):
   "GNU tar-VERSION-2\n", the dump's start "SEC\0NSEC\0", then per directory
   "NFS\0MTIME-SEC\0MTIME-NSEC\0DEV\0INO\0NAME\0" and its contents as
   "Cname\0" records (Y dumped, N not dumped, D directory) and "\0\0". */
struct tar_snapdir { char *name; unsigned long long dev, ino; };
struct tar_ent { char *name; char code; };
struct tar_node {
    char *path;              /* the walked path: the snapshot's name */
    struct stat st;
    struct tar_ent *e;
    size_t n;
    char *ren;               /* R/T/X records */
    size_t rlen, rcap;
    long parent;
    const char *old;         /* renamed from this snapshot name */
    int all;                 /* every entry is stored */
};
struct tar_incr {
    int listed, old, verbose, level_set;
    long level;
    const char *snapshot;
    struct timespec start;
    int have_prev;
    struct timespec prev;
    struct tar_snapdir *dirs;
    size_t ndirs;
    char *out;               /* this dump's directory records */
    size_t olen, ocap;
};

static int tar_buf(char **b, size_t *len, size_t *cap, const char *s, size_t n)
{
    if (*len + n + 1 > *cap) {
        size_t nc = *cap ? *cap * 2 : 256;
        while (nc < *len + n + 1) nc *= 2;
        char *p = realloc(*b, nc);
        if (!p) return -1;
        *b = p; *cap = nc;
    }
    memcpy(*b + *len, s, n); *len += n; (*b)[*len] = 0;
    return 0;
}

/* The next NUL-terminated field of [*P, END), or NULL at the end. */
static const char *tar_field(const char **p, const char *end)
{
    if (*p >= end) return NULL;
    const char *z = memchr(*p, '\0', (size_t)(end - *p));
    if (!z) return NULL;
    const char *f = *p; *p = z + 1;
    return f;
}

static int tar_number(const char *s, unsigned long long *v)
{
    char *e; errno = 0;
    if (!s || !*s || *s == '-') return -1;
    *v = strtoull(s, &e, 10);
    return errno || *e ? -1 : 0;
}

static void tar_incr_free(struct tar_incr *in)
{
    for (size_t i = 0; i < in->ndirs; i++) free(in->dirs[i].name);
    free(in->dirs); free(in->out);
    in->dirs = NULL; in->ndirs = 0; in->out = NULL;
}

/* Read the snapshot file of the previous dump. A missing or empty file is a
   level-0 dump. Returns 0, or -1 after a fatal diagnostic. */
static int tar_snapshot_read(struct tar_incr *in)
{
    FILE *f = fopen(in->snapshot, "rb");
    if (!f) {
        if (errno == ENOENT || errno == ENOTDIR) return 0;
        builtin_error("%s: Cannot open: %s", in->snapshot, strerror(errno));
        return -1;
    }
    char *buf = NULL; size_t len = 0, cap = 0, got; char chunk[16384];
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0)
        if (tar_buf(&buf, &len, &cap, chunk, got) < 0) { fclose(f); free(buf); builtin_error("out of memory"); return -1; }
    int bad = ferror(f);
    fclose(f);
    if (bad) { builtin_error("%s: Read error: %s", in->snapshot, strerror(errno)); free(buf); return -1; }
    if (!len) { free(buf); return 0; }
    const char *end = buf + len, *nl = memchr(buf, '\n', len);
    if (!nl || len < 8 || strncmp(buf, "GNU tar-", 8)) {
        builtin_error("%s:1: Invalid time stamp: Invalid argument", in->snapshot);
        free(buf); return -1;
    }
    const char *dash = nl;
    while (dash > buf && dash[-1] != '-') dash--;
    long format = dash > buf + 8 ? strtol(dash, NULL, 10) : -1;
    if (format != 2) {
        builtin_error("%s: Unsupported incremental format version: %ld", in->snapshot, format);
        free(buf); return -1;
    }
    const char *p = nl + 1;
    unsigned long long sec, nsec;
    if (tar_number(tar_field(&p, end), &sec) < 0 || tar_number(tar_field(&p, end), &nsec) < 0 || nsec > 999999999ULL) {
        builtin_error("%s:2: Invalid time stamp", in->snapshot);
        free(buf); return -1;
    }
    in->prev.tv_sec = (time_t)sec; in->prev.tv_nsec = (long)nsec; in->have_prev = 1;
    while (p < end) {
        const char *nfs = tar_field(&p, end), *ms = tar_field(&p, end), *mn = tar_field(&p, end),
                   *dv = tar_field(&p, end), *ino = tar_field(&p, end), *name = tar_field(&p, end);
        unsigned long long v[4];
        if (!nfs || !name || tar_number(ms, &v[0]) < 0 || tar_number(mn, &v[1]) < 0 ||
            tar_number(dv, &v[2]) < 0 || tar_number(ino, &v[3]) < 0) {
            builtin_error("%s: Unexpected EOF in snapshot file", in->snapshot);
            free(buf); return -1;
        }
        const char *e;
        while ((e = tar_field(&p, end)) && *e) ;
        if (p < end && !*p) p++;
        struct tar_snapdir *g = realloc(in->dirs, (in->ndirs + 1) * sizeof *g);
        if (!g) { free(buf); builtin_error("out of memory"); return -1; }
        in->dirs = g;
        if (!(g[in->ndirs].name = strdup(name))) { free(buf); builtin_error("out of memory"); return -1; }
        g[in->ndirs].dev = v[2]; g[in->ndirs].ino = v[3];
        in->ndirs++;
    }
    free(buf);
    return 0;
}

/* The dump's start, on the clock file times come from (the kernel's coarse
   clock), once it has moved on: a file changed before has an older time, one
   changed while the dump runs this time or a later one. So the next level
   neither misses a change made just after the start (as a start read from
   the fine clock can) nor stores again one made just before it. */
static void tar_dump_start(struct timespec *start)
{
#ifdef CLOCK_REALTIME_COARSE
    struct timespec first, now;
    if (clock_gettime(CLOCK_REALTIME_COARSE, &first) == 0) {
        now = first;
        for (int i = 0; i < 200 && now.tv_sec == first.tv_sec && now.tv_nsec == first.tv_nsec; i++) {
            struct timespec ms = { 0, 1000000 };
            nanosleep(&ms, NULL);
            if (clock_gettime(CLOCK_REALTIME_COARSE, &now)) break;
        }
        *start = now;
        return;
    }
#endif
    clock_gettime(CLOCK_REALTIME, start);
}

static int tar_snapshot_write(struct tar_incr *in)
{
    FILE *f = fopen(in->snapshot, "wb");
    if (!f) { builtin_error("%s: Cannot open: %s", in->snapshot, strerror(errno)); return -1; }
    fprintf(f, "GNU tar-1.35-2\n%lld", (long long)in->start.tv_sec); fputc(0, f);
    fprintf(f, "%ld", in->start.tv_nsec); fputc(0, f);
    if (in->olen) fwrite(in->out, 1, in->olen, f);
    int bad = ferror(f);
    if (fclose(f) || bad) { builtin_error("%s: Cannot write: %s", in->snapshot, strerror(errno)); return -1; }
    return 0;
}

/* Changed since the previous dump: data or status at or after its start. */
static int tar_changed(const struct stat *st, const struct timespec *t)
{
    return st->st_mtim.tv_sec > t->tv_sec || (st->st_mtim.tv_sec == t->tv_sec && st->st_mtim.tv_nsec >= t->tv_nsec) ||
           st->st_ctim.tv_sec > t->tv_sec || (st->st_ctim.tv_sec == t->tv_sec && st->st_ctim.tv_nsec >= t->tv_nsec);
}

static int tar_ent_cmp(const void *a, const void *b)
{
    return strcmp(((const struct tar_ent *)a)->name, ((const struct tar_ent *)b)->name);
}

struct tar_tree { struct tar_node *v; size_t n, cap; const char *root; };

static char *tar_join(const char *dir, const char *name)
{
    size_t n = strlen(dir) + strlen(name) + 2;
    char *p = malloc(n);
    if (p) snprintf(p, n, "%s%s%s", dir, dir[strlen(dir)-1] == '/' ? "" : "/", name);
    return p;
}

/* Where snapshot name OLD is after the renames FROM[i] -> TO[i] (i < N),
   each moving its whole tree: the longest one that OLD lies in applies. */
static char *tar_current(const char *old, const char *const *from, const char *const *to, size_t n)
{
    size_t best = 0; const char *dest = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!from[i] || !to[i]) continue;
        size_t l = strlen(from[i]);
        if (l > best && !strncmp(old, from[i], l) && (old[l] == 0 || old[l] == '/')) { best = l; dest = to[i]; }
    }
    if (!dest) return strdup(old);
    size_t len = strlen(dest) + strlen(old + best) + 1;
    char *p = malloc(len);
    if (p) snprintf(p, len, "%s%s", dest, old + best);
    return p;
}

/* Add directory PATH and, depth first in name order, the directories below
   it, deciding for each entry whether this dump stores it. As GNU tar does:
   a new directory, everything below one, and a directory that only moved
   with a renamed parent have all of their entries stored; a renamed
   directory (the same device and inode under another name, in this
   operand's tree) keeps the time rule and gets an R/T record. */
static int tar_walk(struct tar_tree *t, const char *path, const struct stat *st, long parent,
                    struct tar_incr *in, struct bashos_pax_write_context *w)
{
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 32;
        struct tar_node *v = realloc(t->v, nc * sizeof *v);
        if (!v) { builtin_error("out of memory"); return 1; }
        t->v = v; t->cap = nc;
    }
    size_t me = t->n++;
    struct tar_node *node = &t->v[me];
    memset(node, 0, sizeof *node);
    node->parent = parent; node->st = *st;
    if (!(node->path = strdup(path))) { builtin_error("out of memory"); return 1; }
    int fresh = 1, all = parent >= 0 && t->v[parent].all;
    const char *old = NULL;
    size_t rl = strlen(t->root);
    for (size_t i = 0; in->have_prev && i < in->ndirs; i++) {
        if (in->dirs[i].dev != (unsigned long long)st->st_dev || in->dirs[i].ino != (unsigned long long)st->st_ino) continue;
        if (!strcmp(in->dirs[i].name, path)) { fresh = 0; old = NULL; break; }
        const char *o = in->dirs[i].name;
        if (parent >= 0 && !old && !strncmp(o, t->root, rl) && o[rl] == '/') { old = o; fresh = 0; }
    }
    if (old) {
        /* Renamed, or only carried along by a renamed directory above. */
        const char **from = calloc(me + 1, sizeof *from), **to = calloc(me + 1, sizeof *to);
        if (!from || !to) { free(from); free(to); builtin_error("out of memory"); return 1; }
        for (size_t i = 0; i < me; i++) { from[i] = t->v[i].old; to[i] = t->v[i].path; }
        char *now = tar_current(old, from, to, me);
        free(from); free(to);
        if (!now) { builtin_error("out of memory"); return 1; }
        if (!strcmp(now, path)) { all = 1; old = NULL; }
        free(now);
    }
    node = &t->v[me];
    node->old = old;
    node->all = all || fresh;
    if (in->verbose && fresh) builtin_error("%s: Directory is new", path);
    if (in->verbose && old) builtin_error("%s: Directory has been renamed from '%s'", path, old);
    DIR *d = opendir(path);
    if (!d) { builtin_error("%s: Cannot open: %s", path, strerror(errno)); return 1; }
    struct dirent *de;
    struct tar_ent *e = NULL; size_t n = 0, cap = 0;
    int rc = 0;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (n == cap) {
            struct tar_ent *g = realloc(e, (cap = cap ? cap * 2 : 32) * sizeof *g);
            if (!g) { rc = 1; break; }
            e = g;
        }
        if (!(e[n].name = strdup(de->d_name))) { rc = 1; break; }
        e[n++].code = 0;
    }
    closedir(d);
    if (rc) { builtin_error("out of memory"); for (size_t i = 0; i < n; i++) free(e[i].name); free(e); return 1; }
    if (n) qsort(e, n, sizeof *e, tar_ent_cmp);
    node->e = e; node->n = n;
    int store_all = node->all;
    for (size_t i = 0; i < n; i++) {
        char *child = tar_join(path, e[i].name);
        if (!child) { builtin_error("out of memory"); return 1; }
        struct stat cs;
        /* An excluded entry is listed as not dumped, so that extraction
           keeps it. */
        if (bashos_pax_excluded(w, child)) e[i].code = 'N';
        else if ((w->dereference ? stat : lstat)(child, &cs) < 0) {
            builtin_error("%s: Cannot stat: %s", child, strerror(errno)); rc = 1; e[i].code = 'N';
        } else if (S_ISDIR(cs.st_mode)) {
            e[i].code = 'D';
            rc |= tar_walk(t, child, &cs, (long)me, in, w);
        } else if (S_ISSOCK(cs.st_mode)) {
            builtin_error("%s: socket ignored", child); e[i].code = 'N';
        } else e[i].code = store_all || tar_changed(&cs, &in->prev) ? 'Y' : 'N';
        free(child);
    }
    return rc;
}

static int tar_rec(struct tar_node *node, char code, const char *name, struct bashos_pax_write_context *w)
{
    char *arc = *name ? bashos_pax_member_name(w, name) : strdup("");
    if (!arc) return -1;
    int bad = tar_buf(&node->ren, &node->rlen, &node->rcap, &code, 1) < 0 ||
              tar_buf(&node->ren, &node->rlen, &node->rcap, arc, strlen(arc) + 1) < 0;
    free(arc);
    return bad ? -1 : 0;
}

static int tar_inside(const char *path, const char *dir)
{
    size_t l = strlen(dir);
    return !strncmp(path, dir, l) && path[l] == '/';
}

/* The R/T records of every renamed directory of the tree, in the top
   directory's dumpdir (as GNU tar places them, so that they all happen
   before any directory below is cleaned), in an order that can be
   replayed: tree order, except that a rename waits until its target is
   free and its target's parent is in place; a cycle goes through a
   temporary name (X DIR, R SOURCE, T "", ..., R "", T TARGET). */
static int tar_renames(struct tar_tree *t, struct bashos_pax_write_context *w)
{
    size_t np = 0;
    for (size_t j = 0; j < t->n; j++) if (t->v[j].old) np++;
    if (!np) return 0;
    const char **old = calloc(np, sizeof *old), **to = calloc(np, sizeof *to),
               **doneold = calloc(np, sizeof *doneold), **doneto = calloc(np, sizeof *doneto);
    char **from = calloc(np, sizeof *from);
    int rc = !old || !to || !doneold || !doneto || !from ? -1 : 0;
    size_t k = 0, ndone = 0, left = np;
    for (size_t j = 0; j < t->n && !rc; j++) if (t->v[j].old) { old[k] = t->v[j].old; to[k] = t->v[j].path; k++; }
    long temp = -1;
    int xdone = 0;
    struct tar_node *top = &t->v[0];
    while (left && !rc) {
        /* Where each pending source is now. */
        for (size_t a = 0; a < np && !rc; a++) {
            free(from[a]); from[a] = NULL;
            if (to[a] && (long)a != temp && !(from[a] = tar_current(old[a], doneold, doneto, ndone))) rc = -1;
        }
        size_t pick = np;
        for (size_t a = 0; a < np && pick == np && !rc; a++) {
            if (!to[a]) continue;
            int wait = 0;
            for (size_t b = 0; b < np && !wait; b++)
                wait = b != a && to[b] && ((from[b] && !strcmp(from[b], to[a])) || tar_inside(to[a], to[b]));
            if (!wait) pick = a;
        }
        if (rc) break;
        if (pick < np) {
            rc |= tar_rec(top, 'R', (long)pick == temp ? "" : from[pick], w) | tar_rec(top, 'T', to[pick], w);
            if ((long)pick == temp) temp = -1;
            doneold[ndone] = old[pick]; doneto[ndone++] = to[pick];
            to[pick] = NULL; left--;
            continue;
        }
        /* Only cycles remain: move one source to the temporary name (one
           at a time; should that ever not be enough, keep tree order). */
        size_t a = 0;
        while (a < np && (!to[a] || (long)a == temp)) a++;
        if (a == np || temp >= 0) {
            for (a = 0; !to[a]; a++) ;
            rc |= tar_rec(top, 'R', (long)a == temp ? "" : from[a], w) | tar_rec(top, 'T', to[a], w);
            if ((long)a == temp) temp = -1;
            doneold[ndone] = old[a]; doneto[ndone++] = to[a];
            to[a] = NULL; left--;
            continue;
        }
        if (!xdone++) rc |= tar_rec(top, 'X', top->path, w);
        rc |= tar_rec(top, 'R', from[a], w) | tar_rec(top, 'T', "", w);
        temp = (long)a;
    }
    for (size_t a = 0; from && a < np; a++) free(from[a]);
    free(old); free(to); free(doneold); free(doneto); free(from);
    if (rc) builtin_error("out of memory");
    return rc ? 1 : 0;
}

/* One -g/-G operand: a directory tree as dumpdir members first, then the
   entries this dump stores; a file only when it changed since the previous
   dump. Appends the directories to the new snapshot. */
static int tar_incr_operand(FILE *out, const char *operand, struct tar_incr *in, struct bashos_pax_write_context *w)
{
    char *path = strdup(operand);
    if (!path) { builtin_error("out of memory"); return 1; }
    size_t pl = strlen(path);
    while (pl > 1 && path[pl-1] == '/') path[--pl] = 0;
    struct stat st;
    int rc = 0;
    if (bashos_pax_excluded(w, path)) { free(path); return 0; }
    if ((w->dereference || w->dereference_operands ? stat : lstat)(path, &st) < 0) {
        builtin_error("%s: Cannot stat: %s", path, strerror(errno)); free(path); return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (!in->have_prev || tar_changed(&st, &in->prev)) rc = bashos_pax_write_member_context(out, path, w);
        free(path); return rc ? 1 : 0;
    }
    struct tar_tree t = { .root = path };
    rc = tar_walk(&t, path, &st, -1, in, w);
    if (!rc) rc = tar_renames(&t, w);
    for (size_t i = 0; i < t.n && !rc; i++) {
        struct tar_node *node = &t.v[i];
        char *dd = NULL; size_t dl = 0, dc = 0;
        int bad = tar_buf(&dd, &dl, &dc, "", 0) < 0;
        for (size_t j = 0; j < node->n && !bad; j++)
            bad = tar_buf(&dd, &dl, &dc, &node->e[j].code, 1) < 0 ||
                  tar_buf(&dd, &dl, &dc, node->e[j].name, strlen(node->e[j].name) + 1) < 0;
        /* The snapshot keeps the contents without the renames. */
        char num[128];
        snprintf(num, sizeof num, "0%c%lld%c%ld%c%llu%c%llu%c", 0, (long long)node->st.st_mtim.tv_sec, 0,
                 node->st.st_mtim.tv_nsec, 0, (unsigned long long)node->st.st_dev, 0,
                 (unsigned long long)node->st.st_ino, 0);
        size_t numlen = 0;
        for (int z = 0; z < 5; numlen++) if (!num[numlen]) z++;
        bad = bad || tar_buf(&in->out, &in->olen, &in->ocap, num, numlen) < 0 ||
              tar_buf(&in->out, &in->olen, &in->ocap, node->path, strlen(node->path) + 1) < 0 ||
              (dl && tar_buf(&in->out, &in->olen, &in->ocap, dd, dl) < 0) ||
              tar_buf(&in->out, &in->olen, &in->ocap, "\0", 2) < 0;
        bad = bad || (node->rlen && tar_buf(&dd, &dl, &dc, node->ren, node->rlen) < 0) ||
              tar_buf(&dd, &dl, &dc, "\0", 1) < 0;
        if (bad) { builtin_error("out of memory"); rc = 1; }
        else rc = bashos_pax_write_dumpdir(out, node->path, &node->st, dd, dl, w);
        free(dd);
    }
    int saved_no_recurse = w->no_recurse;
    w->no_recurse = 1;
    for (size_t i = 0; i < t.n && !rc; i++)
        for (size_t j = 0; j < t.v[i].n; j++) {
            if (t.v[i].e[j].code != 'Y') continue;
            char *child = tar_join(t.v[i].path, t.v[i].e[j].name);
            if (!child) { builtin_error("out of memory"); rc = 1; break; }
            if (bashos_pax_write_member_context(out, child, w)) rc = 1;
            free(child);
        }
    w->no_recurse = saved_no_recurse;
    for (size_t i = 0; i < t.n; i++) {
        for (size_t j = 0; j < t.v[i].n; j++) free(t.v[i].e[j].name);
        free(t.v[i].e); free(t.v[i].path); free(t.v[i].ren);
    }
    free(t.v); free(path);
    return rc;
}

/* --owner=NAME[:UID] / --group=NAME[:GID] on create: the archived owner. */
static int tar_set_owner(struct bashos_pax_write_context *w, const char *v, int group)
{
    char name[64] = ""; const char *id = NULL;
    const char *colon = strchr(v, ':');
    if (colon) { snprintf(name, sizeof name, "%.*s", (int)(colon - v), v); id = colon + 1; }
    else if (*v && strspn(v + (*v == '+'), "0123456789") == strlen(v + (*v == '+')) && v[*v == '+']) id = v + (*v == '+');
    else snprintf(name, sizeof name, "%s", v);
    unsigned long long n = 0;
    if (id) {
        if (tar_number(id, &n) < 0) goto bad;
        if (!colon) {
            if (group) { struct group *gr = getgrgid((gid_t)n); if (gr) snprintf(name, sizeof name, "%s", gr->gr_name); }
            else { struct passwd *pw = getpwuid((uid_t)n); if (pw) snprintf(name, sizeof name, "%s", pw->pw_name); }
        }
    } else if (group) { struct group *gr = getgrnam(name); if (!gr) goto bad; n = gr->gr_gid; }
    else { struct passwd *pw = getpwnam(name); if (!pw) goto bad; n = pw->pw_uid; }
    if (group) { w->override_gid = 1; w->gid = (unsigned long)n; w->set_gname = 1; snprintf(w->gname, sizeof w->gname, "%s", name); }
    else { w->override_uid = 1; w->uid = (unsigned long)n; w->set_uname = 1; snprintf(w->uname, sizeof w->uname, "%s", name); }
    return 0;
bad:
    builtin_error("%s: Invalid %s", v, group ? "group" : "owner");
    return -1;
}

/* --format=FORMAT / -H FORMAT, with GNU tar's diagnostic for a bad name. */
static const char *tar_format_name;
static int tar_set_format(struct bashos_pax_write_context *writer, const char *name)
{
    int format = bashos_pax_format(name);
    if (format < 0) {
        builtin_error("%s: Invalid archive format", name);
        fputs(TAR_TRY, stderr);
        return -1;
    }
    writer->format = format;
    tar_format_name = name;
    return 0;
}

/* -b N (blocks of 512 bytes) or --record-size=BYTES (BYTES_FORM): the
   archive's record size, as GNU tar checks it. */
static int tar_set_record(size_t *record, const char *value, int bytes_form)
{
    char *end; errno = 0;
    unsigned long long n = strtoull(value, &end, 10);
    int ok = *value >= '0' && *value <= '9' && !*end && !errno;
    if (bytes_form) {
        if (!ok || n == 0) { builtin_error("%s: Invalid record size", value); fputs(TAR_TRY, stderr); return -1; }
        if (n % 512) { builtin_error("Record size must be a multiple of 512."); fputs(TAR_TRY, stderr); return -1; }
        n /= 512;
    }
    if (!ok || n == 0 || n > (SIZE_MAX / 512) || n > 0x7fffffffULL / 512) {
        builtin_error("%s: Invalid blocking factor", value); fputs(TAR_TRY, stderr); return -1;
    }
    *record = (size_t) n * 512;
    return 0;
}

/* A write-only stream that counts the bytes it passes on. */
struct tar_count { FILE *out; unsigned long long bytes; };
static ssize_t tar_count_write(void *cookie, const char *buf, size_t n)
{
    struct tar_count *c = cookie;
    size_t w = fwrite(buf, 1, n, c->out);
    c->bytes += w;
    return w == n ? (ssize_t) n : w ? (ssize_t) w : -1;
}

int tar_builtin(WORD_LIST *list)
{
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    struct tar_arg *args = calloc(count + 1, sizeof *args);
    const char **members = calloc(count + 1, sizeof *members);
    const char **excludes = calloc(count + 1, sizeof *excludes);
    if (!args || !members || !excludes) { free(args); free(members); free(excludes); builtin_error("out of memory"); return 2; }
    size_t exclude_count = 0;
    int absolute_names = 0;
    struct bashos_pax_xform *xforms = NULL;
    size_t used = 0, member_count = 0;
    int mode = 0, zip = 0, verbose = 0, end_options = 0, first = 1, no_recurse = 0;
    int saved = -1, rc = 0, zip_warning = 0;
    const char *archive = "-";
    FILE *stream = NULL, *temporary = NULL, *counter = NULL;
    struct bashos_pax_write_context writer = {0};
    struct bashos_pax_read_options read_options = { .tar_mode = 1 };
    /* -1: GNU tar's default, on for root and off for other users. */
    int same_owner = -1, same_permissions = -1, numeric_owner = 0;
    struct tar_newer newer = {0};
    struct tar_incr incr = {0};
    const char *bad = NULL;
    char bad_char = 0;
    size_t record = 10240;       /* GNU tar's default: 20 blocks of 512 bytes */
    writer.tar_words = 1;
    tar_format_name = NULL;
    for (; list; list = list->next) {
        const char *w = list->word->word, *opts = NULL, *value = NULL;
        char value_option = 0;
        int old_style = first && *w && w[0] != '-';
        first = 0;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: tar -c|-t|-x|-d|--delete [-zvhPSG] [-H FORMAT] [-f ARCHIVE] [-C DIR] [-g SNAPSHOT] [-N DATE] [FILE...]\nCreate, list, extract or compare (-d, --diff) ustar/PAX archives. '-' means stdin/stdout.\n-h follows symbolic links; --format=FORMAT (-H) writes gnu, oldgnu, v7, ustar, posix.\n-O extracts to stdout; --strip-components=N removes leading path components.\n-p preserves permissions; --no-recursion archives only directory entries.\n--same-owner/--no-same-owner restore the archived owner (default for root);\n--numeric-owner uses archived ids rather than names.\n--exclude=PATTERN skips members; --wildcards makes member operands patterns.\n--transform=s/RE/REPL/FLAGS rewrites member names; -P keeps a leading '/'.\n-S stores files with holes as sparse members; --acls stores and restores ACLs.\n--delete removes the named members from ARCHIVE; --to-command=CMD pipes each\nregular member to CMD with GNU's TAR_* variables.\n-g, --listed-incremental=SNAPSHOT makes a level-0 dump when SNAPSHOT does not exist,\nthen dumps what changed since (GNU snapshot format 2); --level=0 forces a full dump.\n-G, --incremental makes a dump with directory contents; -G or -g on -x deletes what\nthe dumped directories no longer held, and -tvv -G lists their contents.\n-N, --newer, --after-date=DATE stores files changed (mtime or ctime) since DATE;\n--newer-mtime=DATE looks at mtime only; a DATE starting with / or . names a file.\n--owner=NAME[:UID], --group=NAME[:GID], --sort=name apply on create.\n-b N, --blocking-factor=N, --record-size=BYTES set the record size (default\n20 blocks of 512 bytes); a created archive fills its last record with zeros."); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("tar (bash-os) 0.1.1"); goto done; }
        if (!end_options && !strcmp(w, "--create")) opts = "c";
        else if (!end_options && !strcmp(w, "--extract")) opts = "x";
        else if (!end_options && !strcmp(w, "--get")) opts = "x";
        else if (!end_options && !strcmp(w, "--list")) opts = "t";
        else if (!end_options && (!strcmp(w, "--diff") || !strcmp(w, "--compare"))) opts = "d";
        else if (!end_options && !strcmp(w, "--dereference")) opts = "h";
        else if (!end_options && !strcmp(w, "--posix")) { writer.format = BASHOS_PAX_FMT_DEFAULT; tar_format_name = "posix"; continue; }
        else if (!end_options && (!strcmp(w, "--old-archive") || !strcmp(w, "--portability"))) { writer.format = BASHOS_PAX_FMT_V7; tar_format_name = "v7"; continue; }
        else if (!end_options && (!strcmp(w, "--listed-incremental") || !strncmp(w, "--listed-incremental=", 21))) {
            if (w[20] == '=') value = w + 21;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            incr.listed = 1; incr.snapshot = value; continue;
        }
        else if (!end_options && !strcmp(w, "--incremental")) { incr.old = 1; continue; }
        else if (!end_options && (!strcmp(w, "--level") || !strncmp(w, "--level=", 8))) {
            if (w[7] == '=') value = w + 8;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            const char *digits = value + (*value == '-' || *value == '+');
            if (strspn(digits, "0123456789") != strlen(digits)) {
                builtin_error("Invalid incremental level value"); fputs(TAR_TRY, stderr); rc = 2; goto done;
            }
            incr.level_set = 1; incr.level = strtol(value, NULL, 10); continue;
        }
        else if (!end_options && (!strcmp(w, "--newer") || !strncmp(w, "--newer=", 8) ||
                                  !strcmp(w, "--after-date") || !strncmp(w, "--after-date=", 13) ||
                                  !strcmp(w, "--newer-mtime") || !strncmp(w, "--newer-mtime=", 14))) {
            const char *eq = strchr(w, '=');
            if (eq) value = eq + 1;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            int mtime_only = !strncmp(w, "--newer-mtime", 13);
            if (tar_newer_date(&newer, mtime_only ? "--newer-mtime" : "--after-date", value, mtime_only) < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && (!strcmp(w, "--owner") || !strncmp(w, "--owner=", 8) ||
                                  !strcmp(w, "--group") || !strncmp(w, "--group=", 8))) {
            const char *eq = strchr(w, '=');
            if (eq) value = eq + 1;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            if (tar_set_owner(&writer, value, w[2] == 'g') < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && !strncmp(w, "--sort=", 7)) {
            if (!strcmp(w + 7, "name")) writer.sort_names = 1;
            else if (!strcmp(w + 7, "none") || !strcmp(w + 7, "inode")) writer.sort_names = 0;
            else {
                builtin_error("invalid argument '%s' for '--sort'", w + 7);
                fputs("Valid arguments are:\n  - 'none'\n  - 'name'\n  - 'inode'\n", stderr);
                rc = 2; goto done;
            }
            continue;
        }
        else if (!end_options && (!strcmp(w, "--format") || !strncmp(w, "--format=", 9))) {
            if (w[8] == '=') value = w + 9;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            if (tar_set_format(&writer, value) < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && (!strcmp(w, "--gzip") || !strcmp(w, "--gunzip"))) opts = "z";
        else if (!end_options && !strcmp(w, "--verbose")) opts = "v";
        else if (!end_options && !strcmp(w, "--to-stdout")) opts = "O";
        else if (!end_options && (!strcmp(w, "--same-permissions") || !strcmp(w, "--preserve-permissions"))) opts = "p";
        else if (!end_options && !strcmp(w, "--no-same-permissions")) { same_permissions = 0; continue; }
        else if (!end_options && !strcmp(w, "--same-owner")) { same_owner = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-same-owner")) { same_owner = 0; continue; }
        else if (!end_options && !strcmp(w, "--numeric-owner")) { read_options.numeric_owner = numeric_owner = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-recursion")) { no_recurse = 1; continue; }
        else if (!end_options && (!strcmp(w, "--to-command") || !strncmp(w, "--to-command=", 13))) {
            if (w[12] == '=') value = w + 13;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            read_options.to_command = value; continue;
        }
        else if (!end_options && !strcmp(w, "--wildcards")) { read_options.wildcards = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-wildcards")) { read_options.wildcards = 0; continue; }
        else if (!end_options && !strcmp(w, "--absolute-names")) opts = "P";
        else if (!end_options && !strcmp(w, "--sparse")) opts = "S";
        else if (!end_options && !strcmp(w, "--acls")) { read_options.acls = writer.acls = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-acls")) { read_options.acls = writer.acls = 0; continue; }
        else if (!end_options && !strcmp(w, "--delete")) {
            if (mode && mode != 'D') goto conflict;
            mode = 'D'; continue;
        }
        else if (!end_options && (!strcmp(w, "--exclude") || !strncmp(w, "--exclude=", 10))) {
            if (w[9] == '=') value = w + 10;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            excludes[exclude_count++] = value; continue;
        }
        else if (!end_options && (!strcmp(w, "--transform") || !strcmp(w, "--xform") ||
                                  !strncmp(w, "--transform=", 12) || !strncmp(w, "--xform=", 8))) {
            const char *eq = strchr(w, '=');
            if (eq) value = eq + 1;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            if (bashos_pax_xform_add(&xforms, value) < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && (!strcmp(w, "--mtime") || !strncmp(w, "--mtime=", 8))) {
            if (w[7] == '=') value = w + 8;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            if (*value != '@' || bashos_pax_set_mtime(&writer, value + 1) < 0) goto invalid;
            continue;
        }
        else if (!end_options && !strcmp(w, "--file")) opts = "f";
        else if (!end_options && !strcmp(w, "--directory")) opts = "C";
        else if (!end_options && !strncmp(w, "--file=", 7)) { value_option = 'f'; value = w + 7; }
        else if (!end_options && !strncmp(w, "--directory=", 12)) { value_option = 'C'; value = w + 12; }
        else if (!end_options && (!strcmp(w, "--strip-components") || !strncmp(w, "--strip-components=", 19))) {
            value = w + 18;
            if (*value == '=') value++;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            char *end; errno = 0;
            unsigned long n = strtoul(value, &end, 10);
            if (!*value || *value == '-' || *end || errno || n > UINT_MAX) {
                builtin_error("%s: Invalid number of elements", value); fputs(TAR_TRY, stderr); rc = 2; goto done;
            }
            read_options.strip = (unsigned)n; continue;
        }
        else if (!end_options && (!strcmp(w, "--blocking-factor") || !strncmp(w, "--blocking-factor=", 18) ||
                                  !strcmp(w, "--record-size") || !strncmp(w, "--record-size=", 14))) {
            const char *eq = strchr(w, '=');
            if (eq) value = eq + 1;
            else { if (!(list = list->next)) { bad = w; goto missing_long; } value = list->word->word; }
            if (tar_set_record(&record, value, w[2] == 'r') < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && w[0] == '-' && w[1] == '-') {
            /* A known option given an argument it does not take. */
            const char *eq = strchr(w, '=');
            static const char *const plain[] = {
                "--create", "--extract", "--get", "--list", "--diff", "--compare", "--dereference",
                "--posix", "--old-archive", "--portability", "--incremental", "--gzip", "--gunzip",
                "--verbose", "--to-stdout", "--same-permissions", "--preserve-permissions",
                "--no-same-permissions", "--same-owner", "--no-same-owner", "--numeric-owner",
                "--no-recursion", "--wildcards", "--no-wildcards", "--absolute-names", "--sparse",
                "--acls", "--no-acls", "--delete", "--help", "--version", NULL };
            for (int i = 0; eq && plain[i]; i++)
                if (strlen(plain[i]) == (size_t)(eq - w) && !strncmp(plain[i], w, (size_t)(eq - w))) {
                    builtin_error("option '%.*s' doesn't allow an argument", (int)(eq - w), w);
                    fputs(TAR_TRY, stderr); rc = 64; goto done;
                }
            bad = w; goto unknown_long;
        }
        else if (!end_options && w[0] == '-' && w[1]) opts = w + 1;
        else if (!end_options && old_style) opts = w;
        if (opts) {
            for (; *opts; opts++) {
                if (*opts == 'c' || *opts == 't' || *opts == 'x' || *opts == 'd') {
                    if (mode && mode != *opts) goto conflict;
                    mode = *opts;
                } else if (*opts == 'z') zip = 1;
                else if (*opts == 'v') verbose++;
                else if (*opts == 'G') incr.old = 1;
                else if (*opts == 'O') read_options.to_stdout = 1;
                else if (*opts == 'p') same_permissions = 1;
                else if (*opts == 'P') absolute_names = 1;
                else if (*opts == 'S') writer.sparse = 1;
                else if (*opts == 'h') writer.dereference = read_options.dereference = 1;
                else if (*opts == 'f' || *opts == 'C' || *opts == 'H' || *opts == 'g' || *opts == 'N' || *opts == 'b') {
                    char option = *opts;
                    if (!old_style && opts[1]) { value = opts + 1; opts += strlen(opts) - 1; }
                    else if (!(list = list->next)) {
                        if (old_style) {
                            builtin_error("Old option '%c' requires an argument.", option);
                            fputs(TAR_TRY, stderr); rc = 2; goto done;
                        }
                        bad = w; bad_char = option; goto missing_short;
                    } else value = list->word->word;
                    if (option == 'f') archive = value;
                    else if (option == 'b') { if (tar_set_record(&record, value, 0) < 0) { rc = 2; goto done; } }
                    else if (option == 'g') { incr.listed = 1; incr.snapshot = value; }
                    else if (option == 'N') { if (tar_newer_date(&newer, "--after-date", value, 0) < 0) { rc = 2; goto done; } }
                    else if (option == 'H') { if (tar_set_format(&writer, value) < 0) { rc = 2; goto done; } }
                    else args[used++] = (struct tar_arg){value, 1};
                } else { bad = w; bad_char = *opts; goto invalid_short; }
            }
        } else if (value_option == 'f') archive = value;
        else if (value_option == 'C') args[used++] = (struct tar_arg){value, 1};
        else { args[used++] = (struct tar_arg){w, 0}; members[member_count++] = w; }
    }
    if (!mode) {
        builtin_error("You must specify one of the '-Acdtrux', '--delete' or '--test-label' options");
        fputs(TAR_TRY, stderr); rc = 2; goto done;
    }
    if (mode == 'c' && !member_count) {
        builtin_error("Cowardly refusing to create an empty archive");
        fputs(TAR_TRY, stderr); rc = 2; goto done;
    }
    if (writer.override_mtime && mode != 'c') goto invalid;
    /* -g, -G and -N as GNU tar checks them. */
    if (incr.listed && newer.set) {
        builtin_error("'--listed-incremental' cannot be used with '--newer'"); fputs(TAR_TRY, stderr); rc = 2; goto done;
    }
    int incremental_create = mode == 'c' && (incr.listed || incr.old);
    if (incremental_create && tar_format_name &&
        (!strcmp(tar_format_name, "ustar") || !strcmp(tar_format_name, "v7"))) {
        builtin_error("GNU features wanted on incompatible archive format"); fputs(TAR_TRY, stderr); rc = 2; goto done;
    }
    if (incr.level_set && !incr.listed) builtin_error("--level is meaningless without --listed-incremental");
    if (verbose || mode == 't') tar_newer_note(&newer);
    read_options.incremental = incr.listed || incr.old;
    if (newer.set && mode != 'c') {
        read_options.newer_set = 1; read_options.newer_sec = newer.sec; read_options.newer_nsec = newer.nsec;
    }
    if (incremental_create) {
        /* GNU tar's own format unless --format names one; a dumpdir needs
           the gnu or posix format. -N does not apply inside new directories. */
        if (!tar_format_name) writer.format = BASHOS_PAX_FMT_GNU;
        writer.incremental = 1;
        incr.verbose = verbose;
    } else if (newer.set && mode == 'c') {
        writer.newer_set = 1; writer.newer_ctime = !newer.mtime_only;
        writer.newer_sec = newer.sec; writer.newer_nsec = newer.nsec;
    }
    if (numeric_owner && mode == 'c') { writer.set_uname = writer.set_gname = 1; writer.uname[0] = writer.gname[0] = 0; }
    if (mode == 'D' && (zip || read_options.to_stdout || read_options.strip)) goto invalid;
    if (mode == 'd' && (read_options.to_stdout || read_options.to_command)) goto invalid;
    if (read_options.to_command && (mode != 'x' || read_options.to_stdout)) goto invalid;
    read_options.archive = archive;
    read_options.excludes = excludes; read_options.nexcludes = exclude_count;
    read_options.absolute_names = absolute_names;
    read_options.xforms = xforms;
    writer.excludes = excludes; writer.nexcludes = exclude_count;
    writer.xforms = xforms;
    writer.strip_slash = !absolute_names;
    read_options.same_owner = same_owner < 0 ? geteuid() == 0 : same_owner;
    read_options.preserve = same_permissions < 0 ? geteuid() == 0 : same_permissions;
    saved = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved < 0) { builtin_error("save working directory: %s", strerror(errno)); rc = 2; goto done; }
    /* Open the archive before -C affects member paths. */
    if (!strcmp(archive, "-")) {
        int fd = dup(mode == 'c' ? 1 : 0);
        stream = fd < 0 ? NULL : fdopen(fd, mode == 'c' ? "wb" : "rb");
        if (!stream && fd >= 0) close(fd);
    } else stream = fopen(archive, mode == 'c' ? "wb" : mode == 'D' ? "r+b" : "rb");
    if (!stream) {
        builtin_error("%s: Cannot open: %s", archive, strerror(errno));
        builtin_error("Error is not recoverable: exiting now"); rc = 2; goto done;
    }
    FILE *payload = stream;
    if (zip) {
        temporary = tmpfile();
        if (!temporary) { builtin_error("temporary archive: %s", strerror(errno)); rc = 2; goto done; }
        payload = temporary;
        if (mode != 'c') {
            int z = bgz_decode(fileno(stream), fileno(temporary), NULL);
            /* As GNU tar does when gzip warns: the archive is still read,
               then tar fails. */
            if (z == BGZ_TRAILING_GARBAGE) { builtin_error("decompression OK, trailing garbage ignored"); zip_warning = 1; }
            else if (z && z != BGZ_TRAILING_ZEROS) { builtin_error("Error is not recoverable: exiting now"); rc = 2; goto done; }
            if (fseek(temporary, 0, SEEK_SET)) { rc = 2; goto done; }
        }
    }
    if (mode == 'D') {
        /* Rewrite the archive without the named members, in place. */
        FILE *copy = tmpfile();
        if (!copy) { builtin_error("temporary archive: %s", strerror(errno)); rc = 2; goto done; }
        read_options.members = members; read_options.count = member_count;
        int drc = bashos_pax_delete(stream, copy, &read_options);
        if (drc != 2 && strcmp(archive, "-")) {
            char buf[16384]; size_t n;
            if (fflush(copy) || fseek(copy, 0, SEEK_SET) || fseek(stream, 0, SEEK_SET)) drc = 2;
            while (drc != 2 && (n = fread(buf, 1, sizeof buf, copy)) > 0)
                if (fwrite(buf, 1, n, stream) != n) drc = 2;
            if (drc != 2 && (fflush(stream) || ftruncate(fileno(stream), ftello(stream)) < 0)) drc = 2;
        } else if (drc != 2) {
            char buf[16384]; size_t n;
            if (fflush(copy) || fseek(copy, 0, SEEK_SET)) drc = 2;
            while (drc != 2 && (n = fread(buf, 1, sizeof buf, copy)) > 0)
                if (fwrite(buf, 1, n, stdout) != n) drc = 2;
        }
        fclose(copy);
        if (drc) { if (drc == 1) builtin_error("Exiting with failure status due to previous errors"); rc = 2; }
        goto done;
    }
    struct tar_count tally = { stream, 0 };
    int counted = 0;
    if (mode == 'c' && !zip) {
        /* Count what goes to an archive that may not be seekable (a pipe),
           to fill its last record. */
        cookie_io_functions_t io = { NULL, tar_count_write, NULL, NULL };
        FILE *wrapped = fopencookie(&tally, "wb", io);
        if (!wrapped) { builtin_error("archive: %s", strerror(errno)); rc = 2; goto done; }
        payload = counter = wrapped; counted = 1;
    }
    if (mode == 'c') {
        writer.no_recurse = no_recurse;
        writer.verbose_out = verbose ? (!strcmp(archive, "-") ? stderr : stdout) : NULL;
        int warned = 0, member_failed = 0;
        if (incremental_create) {
            if (incr.listed) tar_dump_start(&incr.start);
            /* --level=0 makes a full dump whatever the snapshot holds. */
            if (incr.listed && !(incr.level_set && incr.level == 0) && tar_snapshot_read(&incr) < 0) {
                builtin_error("Error is not recoverable: exiting now"); rc = 2; goto done;
            }
        }
        for (size_t i = 0; i < used; i++) {
            if (args[i].directory) {
                if (chdir(args[i].text)) {
                    builtin_error("%s: Cannot open: %s", args[i].text, strerror(errno));
                    builtin_error("Error is not recoverable: exiting now"); rc = 2; break;
                }
            } else {
                if (args[i].text[0] == '/' && !absolute_names && !xforms && !warned++)
                    builtin_error("Removing leading `/' from member names");
                if (incremental_create ? tar_incr_operand(payload, args[i].text, &incr, &writer) :
                    bashos_pax_write_member_context(payload, args[i].text, &writer)) rc = member_failed = 2;
            }
        }
        /* The new snapshot, named from where tar started. */
        if (incr.listed && !(rc == 2 && !member_failed)) {
            if (fchdir(saved) || tar_snapshot_write(&incr) < 0) rc = member_failed = 2;
        }
        if (member_failed) builtin_error("Exiting with failure status due to previous errors");
        unsigned char zero[1024] = {0};
        if (fwrite(zero, 1, sizeof zero, payload) != sizeof zero) rc = 2;
        /* GNU tar writes whole records: zero-fill the last one. */
        if (fflush(payload)) rc = 2;
        off_t written = counted ? (off_t) tally.bytes : ftello(payload);
        if (written >= 0) {
            size_t pad = (record - (size_t) (written % (off_t) record)) % record;
            char *fill = pad ? calloc(1, pad) : NULL;
            if (pad && (!fill || fwrite(fill, 1, pad, payload) != pad)) rc = 2;
            free(fill);
        }
        if (fflush(payload)) rc = 2;
        if (!rc && zip) {
            if (fseek(payload, 0, SEEK_SET) || bgz_encode(fileno(payload), fileno(stream), 6, NULL, 0)) rc = 2;
        }
    } else {
        for (size_t i = 0; i < used; i++) if (args[i].directory && chdir(args[i].text)) {
            builtin_error("%s: Cannot open: %s", args[i].text, strerror(errno));
            builtin_error("Error is not recoverable: exiting now"); rc = 2; goto done;
        }
        read_options.extract = mode == 'x'; read_options.verbose = verbose;
        read_options.members = members; read_options.count = member_count;
        int member_errors = 0, differences = 0;
        read_options.member_errors = &member_errors;
        /* -d: GNU tar exits 1 when files differ, 2 on trouble. */
        read_options.compare = mode == 'd';
        read_options.differences = &differences;
        if (bashos_pax_read(payload, &read_options)) rc = 2;
        if (member_errors) builtin_error("Exiting with failure status due to previous errors");
        else if (!rc && differences) rc = 1;
    }
    goto done;
invalid:
    builtin_error("unsupported option, missing argument, or conflicting operation; try tar --help"); rc = 2;
    goto done;
conflict:
    builtin_error("You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option");
    fputs(TAR_TRY, stderr); rc = 2; goto done;
unknown_long:
    builtin_error("unrecognized option '%s'", bad); fputs(TAR_TRY, stderr); rc = 64; goto done;
invalid_short:
    builtin_error("invalid option -- '%c'", bad_char); fputs(TAR_TRY, stderr); rc = 64; goto done;
missing_short:
    if (bad[0] == '-' && bad[1] == '-') { bad_char = 0; goto missing_long; }
    builtin_error("option requires an argument -- '%c'", bad_char); fputs(TAR_TRY, stderr); rc = 64; goto done;
missing_long:
    builtin_error("option '%.*s' requires an argument", (int)strcspn(bad, "="), bad); fputs(TAR_TRY, stderr); rc = 64;
done:
    tar_incr_free(&incr);
    bashos_pax_write_clear(&writer);
    bashos_pax_xform_free(&xforms);
    free(excludes);
    if (counter && fclose(counter)) rc = 2;
    if (temporary && fclose(temporary)) rc = 2;
    if (stream && fclose(stream)) rc = 2;
    if (saved >= 0) {
        if (fchdir(saved)) { builtin_error("restore working directory: %s", strerror(errno)); rc = 2; }
        close(saved);
    }
    free(args); free(members);
    if (fflush(stdout) || ferror(stdout)) { clearerr(stdout); rc = 2; }
    if (zip_warning && !rc) { builtin_error("Child returned status 2"); rc = 2; }
    return rc;
}

char *tar_doc[] = {
    "Create (-c), list (-t), extract (-x) or compare (-d, --diff, --compare) ustar/PAX",
    "archives; -f selects the archive. -d reports what differs on disk as GNU tar does",
    "(\"NAME: Mod time differs\", ...; exit 1 when anything differs, 2 on errors).",
    "-h/--dereference archives (and compares) what symbolic links point to.",
    "--format=FORMAT or -H FORMAT: gnu, oldgnu, v7 as GNU tar writes them; ustar, posix",
    "and pax write ustar with pax headers only when needed. v7 archives are read too.",
    "Supports -C directory, -z gzip, -v, -O stdout, -p permissions, --strip-components.",
    "Extraction restores the archived owner and modes when run as root, as GNU tar does;",
    "--same-owner/--no-same-owner, -p/--no-same-permissions and --numeric-owner override.",
    "Creation accepts --mtime=@EPOCH_SECONDS to normalize all archived timestamps.",
    "--exclude=PATTERN, --wildcards, --transform=s/RE/REPL/FLAGS, -P/--absolute-names,",
    "-S/--sparse (GNU PAX 1.0 sparse members) and --acls (SCHILY.acl.* records) as in GNU tar;",
    "a leading '/' is removed from member names unless -P. --delete removes members;",
    "--to-command=CMD pipes each regular member to CMD (TAR_FILENAME, TAR_SIZE, ...).",
    "Uses the pax engine. Unsupported options fail instead of being ignored.",
    "Preserves regular-file hardlinks with nonconflicting member names; supports FIFOs and devices.",
    "No append/update or automatic compression detection (the tar command adds those).",
    "-g/--listed-incremental=SNAPSHOT: a level-0 dump when SNAPSHOT does not exist, then",
    "dumps of what changed, in GNU's incremental format (dumpdir 'D' members, snapshot",
    "format 2, renamed directories); --level=0 forces a full dump. -G/--incremental makes",
    "a dump with directory contents. Extracting with -G (or -g /dev/null) applies renames and",
    "deletes files the dumped directories no longer held; -tvv -G lists directory contents.",
    "-N/--newer/--after-date=DATE (mtime or ctime), --newer-mtime=DATE: only files changed",
    "since DATE (a DATE starting with '/' or '.' is a file whose mtime is used); on -t/-x,",
    "only members not older than DATE. --owner, --group, --sort=name apply on create.",
    "-b N, --blocking-factor=N or --record-size=BYTES sets the record size (default 20",
    "blocks, 10240 bytes); as in GNU tar a created archive fills its last record with zeros.",
    "Option errors use GNU tar's wording; getopt errors exit 64, others 2.", NULL
};
struct builtin tar_struct = {
    "tar", tar_builtin, BUILTIN_ENABLED, tar_doc, "tar -c|-t|-x|-d|--delete [-zvhPSG] [-H FORMAT] [-f ARCHIVE] [-C DIR] [-g SNAPSHOT] [-N DATE] [FILE...]", 0
};
