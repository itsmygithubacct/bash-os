/* SPDX-License-Identifier: MIT
 * Compile the production fstrim.c against a closed filesystem fixture.
 *
 * stat, access, statfs, realpath, open, close and ioctl are redirected to a
 * table of fake nodes declared with the fstrim_fixture builtin. Paths below
 * the fixture directory (mount tables, fake sysfs and /dev/disk links) are
 * real private files; every other path is ENOENT. No call reaches a real
 * mountpoint or a device, and FITRIM is answered from the fixture plan.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include "loadables.h"

static int fx_stat (const char *, struct stat *);
static int fx_access (const char *, int);
static int fx_statfs (const char *, struct statfs *);
static char *fx_realpath (const char *, char *);
static int fx_open (const char *, int, ...);
static int fx_close (int);
static int fx_ioctl (int, unsigned long, ...);
static const char *fx_path (int which);

#define stat(p, s) fx_stat (p, s)
#define statfs(p, s) fx_statfs (p, s)
#define access fx_access
#define realpath fx_realpath
#define open fx_open
#define close fx_close
#define ioctl fx_ioctl
#define FSTRIM_MOUNTINFO_PATH fx_path (0)
#define FSTRIM_FSTAB_PATH fx_path (1)
#define FSTRIM_CMDLINE_PATH fx_path (2)
#define FSTRIM_SYSFS_ROOT fx_path (3)
#define FSTRIM_DEVDISK_ROOT fx_path (4)
#ifndef FSTRIM_SOURCE
#define FSTRIM_SOURCE "../loadables/fstrim.c"
#endif
#include FSTRIM_SOURCE
#undef stat
#undef statfs
#undef access
#undef realpath
#undef open
#undef close
#undef ioctl

#define NODES 64

struct node {
    char path[PATH_MAX];
    char kind;              /* d, f or b */
    dev_t dev, rdev;
    int werr, serr, oerr, rerr;
    long magic;
    int planned, plan_err;
    unsigned long long plan_len;
    int live;
};

static struct node nodes[NODES];
static int count, opens, closes, trims, live, bad;
static char root[PATH_MAX];
static char paths[5][PATH_MAX];
static char fx_trace[1 << 16];
static size_t used;

static void
event (const char *fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (fx_trace + used, sizeof fx_trace - used, fmt, ap);
    va_end (ap);
    if (n < 0 || (size_t) n >= sizeof fx_trace - used) {
        bad++;
        return;
    }
    used += n;
}

static const char *
fx_path (int which)
{
    static const char *const leaf[] = { "mountinfo", "fstab", "cmdline", "sys", "disk" };
    snprintf (paths[which], sizeof paths[which], "%s/%s", root, leaf[which]);
    return paths[which];
}

/* collapse repeated '/', drop "." components and trailing '/' */
static void
norm (const char *in, char *out, size_t sz)
{
    size_t w = 0;
    const char *p = in;
    int abs = *p == '/';

    if (abs)
        out[w++] = '/';
    while (*p) {
        while (*p == '/')
            p++;
        const char *e = p;
        while (*e && *e != '/')
            e++;
        size_t l = (size_t) (e - p);
        if (l == 1 && *p == '.') {
            p = e;
            continue;
        }
        if (l) {
            if (w > (size_t) abs && w + 1 < sz)
                out[w++] = '/';
            if (w + l >= sz)
                l = sz - w - 1;
            memcpy (out + w, p, l);
            w += l;
        }
        p = e;
    }
    out[w] = '\0';
}

static int
private_path (const char *p)
{
    size_t n = strlen (root);
    return n && !strncmp (p, root, n) && (p[n] == '/' || p[n] == '\0');
}

static struct node *
find (const char *path)
{
    char n[PATH_MAX];
    norm (path, n, sizeof n);
    for (int i = 0; i < count; i++)
        if (!strcmp (nodes[i].path, n))
            return &nodes[i];
    return NULL;
}

static int
ancestor (const char *path)
{
    char n[PATH_MAX];
    norm (path, n, sizeof n);
    if (!strcmp (n, "/"))
        return 1;
    size_t l = strlen (n);
    if (!l || n[0] != '/')
        return 0;
    for (int i = 0; i < count; i++)
        if (!strncmp (nodes[i].path, n, l) && nodes[i].path[l] == '/')
            return 1;
    return 0;
}

static int
fx_stat (const char *path, struct stat *st)
{
    if (private_path (path))
        return stat (path, st);
    struct node *nd = find (path);
    memset (st, 0, sizeof *st);
    if (nd) {
        st->st_mode = nd->kind == 'd' ? S_IFDIR | 0755 : nd->kind == 'b' ? S_IFBLK | 0660 : S_IFREG | 0644;
        st->st_dev = nd->dev;
        st->st_rdev = nd->rdev;
        return 0;
    }
    if (ancestor (path)) {
        st->st_mode = S_IFDIR | 0755;
        st->st_dev = makedev (1, 1);
        return 0;
    }
    errno = ENOENT;
    return -1;
}

static int
fx_access (const char *path, int mode)
{
    if (private_path (path))
        return access (path, mode);
    struct node *nd = find (path);
    if (nd) {
        if ((mode & W_OK) && nd->werr) {
            errno = nd->werr;
            return -1;
        }
        return 0;
    }
    if (ancestor (path))
        return 0;
    errno = ENOENT;
    return -1;
}

static int
fx_statfs (const char *path, struct statfs *s)
{
    memset (s, 0, sizeof *s);
    struct node *nd = find (path);
    if (nd && nd->serr) {
        errno = nd->serr;
        return -1;
    }
    if (nd || ancestor (path)) {
        s->f_type = nd && nd->magic ? nd->magic : 0xEF53;
        return 0;
    }
    errno = ENOENT;
    return -1;
}

static char *
fx_realpath (const char *path, char *resolved)
{
    char n[PATH_MAX];
    if (resolved) {
        bad++;
        errno = EINVAL;
        return NULL;
    }
    if (private_path (path)) {
        char link[PATH_MAX];
        ssize_t l = readlink (path, link, sizeof link - 1);
        if (l > 0 && link[0] == '/') {
            link[l] = '\0';
            if (!private_path (link))
                return fx_realpath (link, NULL);
        }
        return realpath (path, NULL);
    }
    struct node *nd = find (path);
    if (nd && nd->rerr) {
        errno = nd->rerr;
        return NULL;
    }
    if (nd || ancestor (path)) {
        norm (path, n, sizeof n);
        return strdup (n);
    }
    errno = ENOENT;
    return NULL;
}

static int
fx_open (const char *path, int flags, ...)
{
    opens++;
    event ("open %s\n", path);
    if (flags != (O_RDONLY | O_CLOEXEC))
        bad++;
    struct node *nd = find (path);
    if (!nd) {
        errno = ancestor (path) ? EACCES : ENOENT;
        return -1;
    }
    if (nd->oerr) {
        errno = nd->oerr;
        return -1;
    }
    if (nd->live) {
        bad++;
        errno = EMFILE;
        return -1;
    }
    nd->live = 1;
    live++;
    return 100 + (int) (nd - nodes);
}

static struct node *
by_fd (int fd)
{
    if (fd < 100 || fd >= 100 + count || !nodes[fd - 100].live) {
        bad++;
        return NULL;
    }
    return &nodes[fd - 100];
}

static int
fx_ioctl (int fd, unsigned long request, ...)
{
    va_list ap;
    va_start (ap, request);
    struct fstrim_range *r = va_arg (ap, struct fstrim_range *);
    va_end (ap);
    struct node *nd = by_fd (fd);
    if (!nd || request != FITRIM || !r) {
        bad++;
        errno = EBADF;
        return -1;
    }
    trims++;
    event ("FITRIM %s %llu %llu %llu\n", nd->path, (unsigned long long) r->start,
           (unsigned long long) r->len, (unsigned long long) r->minlen);
    if (!nd->planned) {
        errno = ENOTTY;
        return -1;
    }
    if (nd->plan_err) {
        errno = nd->plan_err;
        return -1;
    }
    r->len = nd->plan_len;
    return 0;
}

static int
fx_close (int fd)
{
    closes++;
    struct node *nd = by_fd (fd);
    if (!nd) {
        errno = EBADF;
        return -1;
    }
    event ("close %s\n", nd->path);
    nd->live = 0;
    live--;
    return 0;
}

static int
parse_dev (const char *s, dev_t *d)
{
    unsigned ma, mi;
    if (sscanf (s, "%u:%u", &ma, &mi) != 2)
        return -1;
    *d = makedev (ma, mi);
    return 0;
}

int
fstrim_fixture_builtin (WORD_LIST *list)
{
    const char *a[12];
    int n = 0;
    for (; list && n < 12; list = list->next)
        a[n++] = list->word->word;
    if (list || !n)
        return 2;
    if (!strcmp (a[0], "reset") && n == 2) {
        memset (nodes, 0, sizeof nodes);
        count = opens = closes = trims = live = bad = 0;
        used = 0;
        fx_trace[0] = '\0';
        snprintf (root, sizeof root, "%s", a[1]);
    } else if (!strcmp (a[0], "node") && n >= 4 && count < NODES) {
        struct node *nd = &nodes[count];
        memset (nd, 0, sizeof *nd);
        norm (a[1], nd->path, sizeof nd->path);
        if (strlen (a[2]) != 1 || !strchr ("dfb", a[2][0]))
            return 2;
        nd->kind = a[2][0];
        if (parse_dev (a[3], &nd->dev))
            return 2;
        for (int i = 4; i < n; i++) {
            const char *k = a[i];
            if (!strncmp (k, "rdev=", 5)) {
                if (parse_dev (k + 5, &nd->rdev))
                    return 2;
            } else if (!strncmp (k, "w=", 2))
                nd->werr = atoi (k + 2);
            else if (!strncmp (k, "statfs=", 7))
                nd->serr = atoi (k + 7);
            else if (!strncmp (k, "magic=", 6))
                nd->magic = strtol (k + 6, NULL, 0);
            else if (!strncmp (k, "open=", 5))
                nd->oerr = atoi (k + 5);
            else if (!strncmp (k, "realpath=", 9))
                nd->rerr = atoi (k + 9);
            else if (!strncmp (k, "len=", 4)) {
                nd->planned = 1;
                nd->plan_len = strtoull (k + 4, NULL, 10);
            } else if (!strncmp (k, "err=", 4)) {
                nd->planned = 1;
                nd->plan_err = atoi (k + 4);
            } else
                return 2;
        }
        count++;
    } else if (!strcmp (a[0], "trace") && n == 1) {
        fputs (fx_trace, stdout);
        used = 0;
        fx_trace[0] = '\0';
        if (live || bad)
            return 96;
    } else if (!strcmp (a[0], "stats") && n == 1)
        printf ("stats opens=%d closes=%d trims=%d live=%d bad=%d\n", opens, closes, trims, live, bad);
    else
        return 2;
    return 0;
}

static char *fixture_doc[] = { "Private fstrim filesystem fixture control.", NULL };
struct builtin fstrim_fixture_struct = {
    "fstrim_fixture", fstrim_fixture_builtin, BUILTIN_ENABLED,
    fixture_doc, "fstrim_fixture reset DIR|node PATH KIND DEV [k=v...]|trace|stats", 0
};
