/* SPDX-License-Identifier: MIT */
/* ramdisk.c — RAM-backed storage for bash-os, as a bash builtin.
 *
 *   ramdisk [list] [-b|-h] [PATH...]
 *   ramdisk setup [-n|--dry-run] [--tmp] [--no-run] [--root DIR]
 *   ramdisk create [-s SIZE] [-m MODE] [-u UID] [-g GID] [-i INODES]
 *                  [-o OPTS] [-f|--force] PATH
 *   ramdisk resize PATH SIZE
 *   ramdisk remove [-l|--lazy] [--rmdir] PATH...
 *   ramdisk zram [--root DIR] add SIZE [-a ALGO] | remove N...
 *
 * list    the RAM-backed mounts (tmpfs, ramfs, mqueue, devtmpfs, hugetlbfs
 *         and filesystems on /dev/zramN) from /proc/self/mountinfo, sized
 *         with statfs(2).
 * setup   the standard set an init needs, idempotently: /run, /run/lock,
 *         /dev/shm, /dev/mqueue and (--tmp) /tmp. Anything already mounted
 *         is left alone; missing mount points are created.
 * create  a tmpfs at PATH with the tmpfs(5) size/mode/uid/gid/nr_inodes
 *         options.
 * resize  a tmpfs's size limit, by mount(2) MS_REMOUNT, keeping the
 *         mount's own flags (a remount without them would clear them).
 * remove  umount2(2) of a RAM-backed mount, optionally rmdir(2) after.
 * zram    the kernel's zram-control interface in sysfs (hot_add,
 *         comp_algorithm, disksize, reset, hot_remove).
 *
 * Written for bash-os from the Linux man pages (mount(2), umount(2),
 * statfs(2), tmpfs(5), mq_overview(7), shm_overview(7),
 * proc_pid_mountinfo(5)), the kernel's zram documentation and the
 * observed behaviour of the kernel. Modelled on bashmount.c and mkswap.c.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-longopt.h"

#define RD_PROG     "ramdisk"
#define RD_VERSION  "ramdisk (bash-os) 0.1.5"
#define RD_LINE_MAX 8192
#define RD_DATA_MAX 1024

#ifndef MS_LAZYTIME
#  define MS_LAZYTIME (1<<25)
#endif
#ifndef MNT_DETACH
#  define MNT_DETACH 2
#endif

enum { RD_OPT_TMP = BOS_OPT_FIRST, RD_OPT_NO_RUN, RD_OPT_ROOT, RD_OPT_RMDIR };

/* ---------------- help -------------------------------------------------- */

extern char *ramdisk_doc[];

static int
rd_help (void)
{
    for (char **lp = ramdisk_doc; *lp; lp++)
        puts (*lp);
    return sh_chkwrite (EXECUTION_SUCCESS);
}

static int
rd_version (void)
{
    puts (RD_VERSION);
    return sh_chkwrite (EXECUTION_SUCCESS);
}

/* A usage error that is not an option error: the message, then the Try
   line; status 1 as for the option errors. */
static int
rd_usage_error (const char *fmt, const char *arg)
{
    builtin_error (fmt, arg);
    bos_try_help (RD_PROG);
    return EXECUTION_FAILURE;
}

/* ---------------- /proc/self/mountinfo --------------------------------- */

typedef struct {
    char *mnt;                 /* mount point, \NNN decoded               */
    char *type;                /* filesystem type                         */
    char *src;                 /* mount source, decoded                   */
    dev_t dev;                 /* makedev (major, minor) of field 3       */
} rd_mount;

typedef struct {
    rd_mount *v;
    size_t n, cap;
} rd_table;

/* mountinfo encodes space, tab, newline and backslash as \NNN octal. */
static void
rd_unescape (char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' && r[2] >= '0' && r[2] <= '7'
            && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) ((r[1] - '0') * 64 + (r[2] - '0') * 8 + (r[3] - '0'));
            r += 4;
        } else
            *w++ = *r++;
    }
    *w = '\0';
}

static void
rd_table_free (rd_table *t)
{
    for (size_t i = 0; i < t->n; i++) {
        free (t->v[i].mnt);
        free (t->v[i].type);
        free (t->v[i].src);
    }
    free (t->v);
    t->v = NULL;
    t->n = t->cap = 0;
}

/* Fields: id parent maj:min root mountpoint opts [optional...] - type src
   superopts (proc_pid_mountinfo(5)). 0, or -1 after a diagnostic. */
static int
rd_table_load (rd_table *t)
{
    FILE *f = fopen ("/proc/self/mountinfo", "r");
    char line[RD_LINE_MAX];

    memset (t, 0, sizeof *t);
    if (!f) {
        builtin_error ("/proc/self/mountinfo: %s", strerror (errno));
        return -1;
    }
    while (fgets (line, sizeof line, f)) {
        char *field[6] = { 0 }, *save = NULL, *tok, *type = NULL, *src = NULL;
        unsigned maj = 0, min = 0;
        int n = 0, dash = 0;

        line[strcspn (line, "\n")] = '\0';
        for (tok = strtok_r (line, " ", &save); tok; tok = strtok_r (NULL, " ", &save)) {
            if (n < 6) {
                field[n++] = tok;
                continue;
            }
            if (!dash) {
                dash = strcmp (tok, "-") == 0;
                continue;
            }
            if (!type)
                type = tok;
            else {
                src = tok;
                break;
            }
        }
        if (n < 6 || !type || !src || sscanf (field[2], "%u:%u", &maj, &min) != 2)
            continue;
        if (t->n == t->cap) {
            size_t cap = t->cap ? t->cap * 2 : 64;
            rd_mount *v = realloc (t->v, cap * sizeof *v);
            if (!v) {
                builtin_error ("memory exhausted");
                fclose (f);
                rd_table_free (t);
                return -1;
            }
            t->v = v;
            t->cap = cap;
        }
        rd_unescape (field[4]);
        rd_unescape (src);
        rd_mount *m = &t->v[t->n];
        m->mnt = strdup (field[4]);
        m->type = strdup (type);
        m->src = strdup (src);
        m->dev = makedev (maj, min);
        if (!m->mnt || !m->type || !m->src) {
            free (m->mnt); free (m->type); free (m->src);
            builtin_error ("memory exhausted");
            fclose (f);
            rd_table_free (t);
            return -1;
        }
        t->n++;
    }
    fclose (f);
    return 0;
}

/* RAM-backed: the in-memory filesystem types, or any filesystem on a zram
   block device. */
static int
rd_is_zram_source (const char *src)
{
    if (strncmp (src, "/dev/zram", 9) != 0 || !src[9])
        return 0;
    for (const char *p = src + 9; *p; p++)
        if (!isdigit ((unsigned char) *p))
            return 0;
    return 1;
}

static int
rd_is_ram (const rd_mount *m)
{
    static const char *const types[] = { "tmpfs", "ramfs", "mqueue", "devtmpfs", "hugetlbfs", NULL };
    for (int i = 0; types[i]; i++)
        if (strcmp (m->type, types[i]) == 0)
            return 1;
    return rd_is_zram_source (m->src);
}

/* The topmost mount whose mount point is CANON, or -1. */
static long
rd_find_at (const rd_table *t, const char *canon)
{
    long found = -1;
    for (size_t i = 0; i < t->n; i++)
        if (strcmp (t->v[i].mnt, canon) == 0)
            found = (long) i;
    return found;
}

/* The mount holding CANON: the longest mount point that is CANON or one of
   its ancestors, preferring entries with CANON's device, the last of equal
   length (it is on top). */
static long
rd_find_containing (const rd_table *t, const char *canon, dev_t dev)
{
    long best = -1, best_dev = -1;
    size_t best_len = 0, best_dev_len = 0;
    for (size_t i = 0; i < t->n; i++) {
        const char *m = t->v[i].mnt;
        size_t len = strlen (m);
        int under = strcmp (m, "/") == 0
                    || (strncmp (canon, m, len) == 0 && (canon[len] == '\0' || canon[len] == '/'));
        if (!under)
            continue;
        if (len >= best_len) { best = (long) i; best_len = len; }
        if (t->v[i].dev == dev && len >= best_dev_len) {
            best_dev = (long) i;
            best_dev_len = len;
        }
    }
    return best_dev >= 0 ? best_dev : best;
}

/* Is PATH (resolved) a mount point now? 1 yes, 0 no or missing, -1 error. */
static int
rd_is_mountpoint (const char *path)
{
    rd_table t;
    char *canon = realpath (path, NULL);
    int rc;

    if (!canon)
        return 0;
    if (rd_table_load (&t) < 0) {
        free (canon);
        return -1;
    }
    rc = rd_find_at (&t, canon) >= 0;
    rd_table_free (&t);
    free (canon);
    return rc;
}

/* ---------------- sizes ------------------------------------------------- */

/* Digits with an optional k, m or g (binary multiples, either case) or,
   when PCT_OK, a % suffix, as tmpfs(5) takes them. *BYTES gets the byte
   count (0 for a percentage) and *PCT the percentage (0 otherwise). */
static int
rd_parse_size (const char *s, int pct_ok, uint64_t *bytes, unsigned *pct)
{
    const char *p = s;
    uint64_t v = 0;
    int shift = 0;

    *bytes = 0;
    *pct = 0;
    if (!isdigit ((unsigned char) *p))
        return -1;
    for (; isdigit ((unsigned char) *p); p++) {
        if (v > (UINT64_MAX - 9) / 10)
            return -1;
        v = v * 10 + (uint64_t) (*p - '0');
    }
    switch (*p) {
    case '\0': break;
    case 'k': case 'K': shift = 10; p++; break;
    case 'm': case 'M': shift = 20; p++; break;
    case 'g': case 'G': shift = 30; p++; break;
    case '%':
        if (!pct_ok || p[1] || v == 0 || v > 100000)
            return -1;
        *pct = (unsigned) v;
        return 0;
    default:
        return -1;
    }
    if (*p || (shift && v > (UINT64_MAX >> shift)))
        return -1;
    *bytes = v << shift;
    return 0;
}

/* df -h style: powers of 1024, rounded up, one decimal below 10. */
static void
rd_human (uint64_t v, char *buf, size_t n)
{
    static const char units[] = "KMGTPE";
    uint64_t base = 1024, q, r;
    int i = 0;

    if (v < 1024) {
        snprintf (buf, n, "%llu", (unsigned long long) v);
        return;
    }
    while (i < 5 && v / base >= 1024) {
        base *= 1024;
        i++;
    }
    q = v / base;
    r = v % base;
    if (q < 10) {
        uint64_t tenths = q * 10 + (r * 10 + base - 1) / base;
        if (tenths < 100) {
            snprintf (buf, n, "%llu.%llu%c", (unsigned long long) (tenths / 10),
                      (unsigned long long) (tenths % 10), units[i]);
            return;
        }
        q = 10;
    } else if (r)
        q++;
    if (q >= 1024 && i < 5)
        snprintf (buf, n, "1.0%c", units[i + 1]);
    else
        snprintf (buf, n, "%llu%c", (unsigned long long) q, units[i]);
}

static void
rd_number (uint64_t v, int bytes, char *buf, size_t n)
{
    if (bytes)
        snprintf (buf, n, "%llu", (unsigned long long) v);
    else
        rd_human (v, buf, n);
}

typedef struct {
    uint64_t size, used, avail;
    unsigned long flags;       /* statfs f_flags (ST_*)                   */
} rd_usage;

static int
rd_statfs (const char *path, rd_usage *u)
{
    struct statfs s;
    uint64_t unit;

    if (statfs (path, &s) < 0)
        return -1;
    unit = s.f_frsize ? (uint64_t) s.f_frsize : (uint64_t) s.f_bsize;
    u->size = (uint64_t) s.f_blocks * unit;
    u->used = (uint64_t) (s.f_blocks - s.f_bfree) * unit;
    u->avail = (uint64_t) s.f_bavail * unit;
    u->flags = (unsigned long) s.f_flags;
    return 0;
}

/* ---------------- paths ------------------------------------------------- */

/* mkdir -p PATH (mode 0755 for what it makes). *MADE, when not NULL, gets
   the length of the prefix that already existed (strlen (PATH) when the
   whole path existed), so a failed caller can remove what it made. 0, or
   -1 with errno set. */
static int
rd_mkdir_p (const char *path, size_t *made)
{
    char *buf = strdup (path);
    size_t len, existed;
    struct stat st;

    if (!buf)
        return -1;
    len = strlen (buf);
    while (len > 1 && buf[len - 1] == '/')
        buf[--len] = '\0';
    existed = len;
    if (made)
        *made = len;
    for (size_t i = 1; i <= len; i++) {
        if (buf[i] != '/' && buf[i] != '\0')
            continue;
        char saved = buf[i];
        buf[i] = '\0';
        if (mkdir (buf, 0755) == 0) {
            if (existed == len) {   /* the first one made: its parent existed */
                char *slash = strrchr (buf, '/');
                existed = slash ? (size_t) (slash - buf) : 0;
            }
        } else if (errno != EEXIST || stat (buf, &st) < 0 || !S_ISDIR (st.st_mode)) {
            int e = errno == EEXIST ? ENOTDIR : errno;
            free (buf);
            errno = e;
            return -1;
        }
        buf[i] = saved;
    }
    if (made)
        *made = existed;
    free (buf);
    return 0;
}

/* Undo rd_mkdir_p: remove the directories below the first MADE bytes. */
static void
rd_unmake (const char *path, size_t made)
{
    char *buf = strdup (path);
    size_t len;

    if (!buf)
        return;
    len = strlen (buf);
    while (len > 1 && buf[len - 1] == '/')
        buf[--len] = '\0';
    while (len > made) {
        if (rmdir (buf) < 0)
            break;
        char *slash = strrchr (buf, '/');
        if (!slash || slash == buf)
            break;
        *slash = '\0';
        len = (size_t) (slash - buf);
    }
    free (buf);
}

/* Does PATH, or its deepest existing ancestor, resolve inside ROOT (a
   canonical directory)? A symlink such as DIR/dev -> /dev must not lead a
   --root setup onto the running system. */
static int
rd_inside_root (const char *path, const char *root)
{
    char *buf = strdup (path), *canon = NULL;
    size_t rlen = strlen (root);
    int inside = 0;

    if (!buf)
        return 0;
    for (;;) {
        canon = realpath (buf, NULL);
        if (canon || errno != ENOENT)
            break;
        char *slash = strrchr (buf, '/');
        if (!slash || slash == buf)
            break;
        *slash = '\0';
    }
    if (canon)
        inside = strcmp (root, "/") == 0
                 || (strncmp (canon, root, rlen) == 0 && (canon[rlen] == '\0' || canon[rlen] == '/'));
    free (canon);
    free (buf);
    return inside;
}

/* ---------------- -o flags ---------------------------------------------- */

typedef struct {
    const char *name;
    unsigned long bit;
    int clears;
} rd_flag_row;

static const rd_flag_row rd_flag_table[] = {
    { "ro",          MS_RDONLY,      0 }, { "rw",          MS_RDONLY,      1 },
    { "nosuid",      MS_NOSUID,      0 }, { "suid",        MS_NOSUID,      1 },
    { "nodev",       MS_NODEV,       0 }, { "dev",         MS_NODEV,       1 },
    { "noexec",      MS_NOEXEC,      0 }, { "exec",        MS_NOEXEC,      1 },
    { "noatime",     MS_NOATIME,     0 }, { "atime",       MS_NOATIME,     1 },
    { "nodiratime",  MS_NODIRATIME,  0 }, { "diratime",    MS_NODIRATIME,  1 },
    { "relatime",    MS_RELATIME,    0 }, { "norelatime",  MS_RELATIME,    1 },
    { "strictatime", MS_STRICTATIME, 0 }, { "lazytime",    MS_LAZYTIME,    0 },
    { "sync",        MS_SYNCHRONOUS, 0 }, { "async",       MS_SYNCHRONOUS, 1 },
    { "dirsync",     MS_DIRSYNC,     0 },
    { NULL, 0, 0 }
};

/* Append "TOKEN" to the comma-separated DATA. */
static int
rd_data_add (char *data, const char *fmt, const char *value)
{
    size_t len = strlen (data);
    int n = snprintf (data + len, RD_DATA_MAX - len, "%s", len ? "," : "");
    if (n < 0 || (size_t) n >= RD_DATA_MAX - len)
        return -1;
    len += (size_t) n;
    n = snprintf (data + len, RD_DATA_MAX - len, fmt, value);
    if (n < 0 || (size_t) n >= RD_DATA_MAX - len)
        return -1;
    return 0;
}

/* Fold OPTS into *FLAGS and DATA: the mount(2) flag names set or clear
   bits; anything else is tmpfs data, passed on for the kernel to judge. */
static int
rd_parse_opts (const char *opts, unsigned long *flags, char *data)
{
    char *buf = strdup (opts), *save = NULL;
    int rc = 0;

    if (!buf) {
        builtin_error ("memory exhausted");
        return -1;
    }
    for (char *tok = strtok_r (buf, ",", &save); tok && rc == 0; tok = strtok_r (NULL, ",", &save)) {
        const rd_flag_row *r;
        for (r = rd_flag_table; r->name; r++)
            if (strcmp (tok, r->name) == 0)
                break;
        if (r->name) {
            if (r->clears) *flags &= ~r->bit;
            else           *flags |= r->bit;
        } else if (rd_data_add (data, "%s", tok) < 0) {
            builtin_error ("-o: options too long");
            rc = -1;
        }
    }
    free (buf);
    return rc;
}

/* The per-mount flags a remount must repeat, from statfs f_flags. */
static unsigned long
rd_remount_flags (unsigned long st)
{
    unsigned long fl = 0;
    if (st & ST_RDONLY)      fl |= MS_RDONLY;
    if (st & ST_NOSUID)      fl |= MS_NOSUID;
#ifdef ST_NODEV
    if (st & ST_NODEV)       fl |= MS_NODEV;
#endif
#ifdef ST_NOEXEC
    if (st & ST_NOEXEC)      fl |= MS_NOEXEC;
#endif
#ifdef ST_SYNCHRONOUS
    if (st & ST_SYNCHRONOUS) fl |= MS_SYNCHRONOUS;
#endif
#ifdef ST_NOATIME
    if (st & ST_NOATIME)     fl |= MS_NOATIME;
#endif
#ifdef ST_NODIRATIME
    if (st & ST_NODIRATIME)  fl |= MS_NODIRATIME;
#endif
#ifdef ST_RELATIME
    if (st & ST_RELATIME)    fl |= MS_RELATIME;
    if (!(fl & (MS_NOATIME | MS_RELATIME)))
        fl |= MS_STRICTATIME;
#endif
    return fl;
}

/* ---------------- list -------------------------------------------------- */

#define RD_COLS 7

typedef struct {
    char *cell[RD_COLS];
} rd_row;

static int
rd_row_add (rd_row **rows, size_t *n, const rd_mount *m, int bytes)
{
    char buf[RD_COLS][64];
    rd_usage u;
    struct stat st;
    rd_row *v = realloc (*rows, (*n + 1) * sizeof *v);

    if (!v) {
        builtin_error ("memory exhausted");
        return -1;
    }
    *rows = v;
    if (rd_is_zram_source (m->src) && strcmp (m->type, "swap") != 0)
        snprintf (buf[0], sizeof buf[0], "zram:%s", m->type);
    else
        snprintf (buf[0], sizeof buf[0], "%s", m->type);
    if (rd_statfs (m->mnt, &u) == 0) {
        rd_number (u.size, bytes, buf[1], sizeof buf[1]);
        rd_number (u.used, bytes, buf[2], sizeof buf[2]);
        rd_number (u.avail, bytes, buf[3], sizeof buf[3]);
        uint64_t used = u.used, total = u.used + u.avail;
        while (used > UINT64_MAX / 100) { used >>= 10; total >>= 10; }
        if (total)
            snprintf (buf[4], sizeof buf[4], "%llu%%",
                      (unsigned long long) ((used * 100 + total - 1) / total));
        else
            snprintf (buf[4], sizeof buf[4], "-");
    } else
        for (int c = 1; c <= 4; c++)
            snprintf (buf[c], sizeof buf[c], "-");
    if (stat (m->mnt, &st) == 0)
        snprintf (buf[5], sizeof buf[5], "%o", (unsigned) (st.st_mode & 07777));
    else
        snprintf (buf[5], sizeof buf[5], "-");
    rd_row *r = &v[*n];
    for (int c = 0; c < RD_COLS - 1; c++)
        r->cell[c] = strdup (buf[c]);
    r->cell[RD_COLS - 1] = strdup (m->mnt);
    (*n)++;
    for (int c = 0; c < RD_COLS; c++)
        if (!r->cell[c]) {
            builtin_error ("memory exhausted");
            return -1;
        }
    return 0;
}

static void
rd_rows_print (rd_row *rows, size_t n)
{
    static const char *const head[RD_COLS] = { "TYPE", "SIZE", "USED", "AVAIL", "USE%", "MODE", "MOUNTPOINT" };
    size_t w[RD_COLS];

    for (int c = 0; c < RD_COLS; c++)
        w[c] = strlen (head[c]);
    for (size_t i = 0; i < n; i++)
        for (int c = 0; c < RD_COLS - 1; c++)
            if (strlen (rows[i].cell[c]) > w[c])
                w[c] = strlen (rows[i].cell[c]);
    for (size_t i = 0; i <= n; i++) {
        const char *const *cell = i == 0 ? head : (const char *const *) rows[i - 1].cell;
        printf ("%-*s %*s %*s %*s %*s %-*s %s\n",
                (int) w[0], cell[0], (int) w[1], cell[1], (int) w[2], cell[2],
                (int) w[3], cell[3], (int) w[4], cell[4], (int) w[5], cell[5], cell[6]);
    }
}

static void
rd_rows_free (rd_row *rows, size_t n)
{
    for (size_t i = 0; i < n; i++)
        for (int c = 0; c < RD_COLS; c++)
            free (rows[i].cell[c]);
    free (rows);
}

static int
rd_list (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "bytes",          BOS_NO_ARG, 'b' },
        { "human-readable", BOS_NO_ARG, 'h' },
        { "help",           BOS_NO_ARG, BOS_OPT_HELP },
        { "version",        BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c, bytes = 0, rc = EXECUTION_SUCCESS;
    rd_table t;
    rd_row *rows = NULL;
    size_t nrows = 0;

    bos_getopt_init (&g, RD_PROG, "bh", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case 'b': bytes = 1; break;
        case 'h': bytes = 0; break;
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (rd_table_load (&t) < 0) {
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (g.noperands == 0) {
        for (size_t i = 0; i < t.n && rc == EXECUTION_SUCCESS; i++) {
            if (!rd_is_ram (&t.v[i]))
                continue;
            /* A mount hidden under a later one at the same place would be
               sized by statfs as the one on top: show only the top. */
            if (rd_find_at (&t, t.v[i].mnt) != (long) i)
                continue;
            if (rd_row_add (&rows, &nrows, &t.v[i], bytes) < 0)
                rc = EXECUTION_FAILURE;
        }
    } else
        for (int i = 0; i < g.noperands; i++) {
            const char *path = g.operands[i];
            struct stat st;
            char *canon = realpath (path, NULL);
            if (!canon || stat (canon, &st) < 0) {
                builtin_error ("%s: %s", path, strerror (errno));
                free (canon);
                rc = EXECUTION_FAILURE;
                continue;
            }
            long at = rd_find_containing (&t, canon, st.st_dev);
            if (at < 0 || !rd_is_ram (&t.v[at])) {
                builtin_error ("%s: not on a RAM-backed filesystem%s%s%s", path,
                               at < 0 ? "" : " (", at < 0 ? "" : t.v[at].type, at < 0 ? "" : ")");
                rc = EXECUTION_FAILURE;
            } else if (rd_row_add (&rows, &nrows, &t.v[at], bytes) < 0)
                rc = EXECUTION_FAILURE;
            free (canon);
        }
    rd_rows_print (rows, nrows);
    rd_rows_free (rows, nrows);
    rd_table_free (&t);
    bos_getopt_free (&g);
    return sh_chkwrite (rc);
}

/* ---------------- setup ------------------------------------------------- */

typedef struct {
    const char *path;          /* below the root                          */
    const char *type;
    unsigned long flags;
    const char *data;          /* mount(2) data                            */
    const char *shown;         /* ", mode 1777" style detail for messages  */
} rd_item;

static int
rd_kernel_has (const char *fstype)
{
    FILE *f = fopen ("/proc/filesystems", "r");
    char line[128];
    int found = 0;

    if (!f)
        return 0;
    while (!found && fgets (line, sizeof line, f)) {
        char *name = strrchr (line, '\t');
        name = name ? name + 1 : line;
        name[strcspn (name, " \n")] = '\0';
        found = strcmp (name, fstype) == 0;
    }
    fclose (f);
    return found;
}

static int
rd_setup (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "dry-run", BOS_NO_ARG,  'n' },
        { "tmp",     BOS_NO_ARG,  RD_OPT_TMP },
        { "no-run",  BOS_NO_ARG,  RD_OPT_NO_RUN },
        { "root",    BOS_REQ_ARG, RD_OPT_ROOT },
        { "help",    BOS_NO_ARG,  BOS_OPT_HELP },
        { "version", BOS_NO_ARG,  BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    static const rd_item items[] = {
        { "/run",        "tmpfs",  MS_NOSUID | MS_NODEV,              "mode=755",         ", mode 755" },
        { "/run/lock",   "tmpfs",  MS_NOSUID | MS_NODEV | MS_NOEXEC,  "mode=1777,size=5m", ", mode 1777, size 5m" },
        { "/dev/shm",    "tmpfs",  MS_NOSUID | MS_NODEV,              "mode=1777",        ", mode 1777" },
        { "/dev/mqueue", "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC,  NULL,               "" },
        { "/tmp",        "tmpfs",  MS_NOSUID | MS_NODEV,              "mode=1777",        ", mode 1777" },
    };
    bos_getopt g;
    int c, dry = 0, want_tmp = 0, no_run = 0, rc = EXECUTION_SUCCESS, run_fresh = 0;
    const char *root = NULL;
    char *root_canon = NULL, *root_shown = NULL;

    bos_getopt_init (&g, RD_PROG, "n", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case 'n':           dry = 1; break;
        case RD_OPT_TMP:    want_tmp = 1; break;
        case RD_OPT_NO_RUN: no_run = 1; break;
        case RD_OPT_ROOT:   root = g.optarg; break;
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (g.noperands) {
        rc = rd_usage_error ("setup: extra operand '%s'", g.operands[0]);
        bos_getopt_free (&g);
        return rc;
    }
    bos_getopt_free (&g);

    if (root) {
        struct stat st;
        size_t len;
        root_canon = realpath (root, NULL);
        if (!root_canon || stat (root_canon, &st) < 0 || !S_ISDIR (st.st_mode)) {
            builtin_error ("setup: %s: %s", root, root_canon ? strerror (ENOTDIR) : strerror (errno));
            free (root_canon);
            return EXECUTION_FAILURE;
        }
        root_shown = strdup (root);
        if (!root_shown) {
            free (root_canon);
            builtin_error ("memory exhausted");
            return EXECUTION_FAILURE;
        }
        len = strlen (root_shown);
        while (len > 0 && root_shown[len - 1] == '/')
            root_shown[--len] = '\0';
    }

    for (size_t i = 0; i < sizeof items / sizeof items[0]; i++) {
        const rd_item *it = &items[i];
        int is_run = strncmp (it->path, "/run", 4) == 0;
        char target[PATH_MAX];
        struct stat st;
        size_t made;

        if ((is_run && no_run) || (strcmp (it->path, "/tmp") == 0 && !want_tmp))
            continue;
        if (snprintf (target, sizeof target, "%s%s", root_shown ? root_shown : "", it->path)
            >= (int) sizeof target) {
            builtin_error ("setup: %s: %s", it->path, strerror (ENAMETOOLONG));
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (strcmp (it->type, "mqueue") == 0 && !rd_kernel_has ("mqueue")) {
            printf ("%s skipped: mqueue is not supported by this kernel\n", target);
            continue;
        }
        if (root_canon && !rd_inside_root (target, root_canon)) {
            builtin_error ("setup: %s resolves outside %s; not mounting it", target, root_shown);
            rc = EXECUTION_FAILURE;
            continue;
        }
        /* Under a /run that this run mounts (or, dry, would mount), nothing
           is mounted yet whatever the old directory held. */
        int fresh = dry && run_fresh && strcmp (it->path, "/run/lock") == 0;
        int mounted = fresh ? 0 : rd_is_mountpoint (target);
        if (mounted < 0) {
            rc = EXECUTION_FAILURE;
            break;
        }
        if (mounted) {
            printf ("%s already mounted\n", target);
            continue;
        }
        if (strcmp (it->path, "/run") == 0)
            run_fresh = 1;
        if (dry) {
            if (fresh || stat (target, &st) < 0)
                printf ("would create %s\n", target);
            printf ("would mount %s (%s%s)\n", target, it->type, it->shown);
            continue;
        }
        int existed = stat (target, &st) == 0;
        if (rd_mkdir_p (target, &made) < 0) {
            builtin_error ("setup: cannot create %s: %s", target, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (root_canon && !rd_inside_root (target, root_canon)) {
            builtin_error ("setup: %s resolves outside %s; not mounting it", target, root_shown);
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (!existed)
            printf ("created %s\n", target);
        if (mount (it->type, target, it->type, it->flags, it->data) < 0) {
            builtin_error ("setup: cannot mount %s (%s): %s", target, it->type, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        printf ("mounted %s (%s%s)\n", target, it->type, it->shown);
    }
    free (root_canon);
    free (root_shown);
    return sh_chkwrite (rc);
}

/* ---------------- create ------------------------------------------------ */

static int
rd_parse_id (const char *s, unsigned long *out)
{
    char *end;
    if (!isdigit ((unsigned char) *s))
        return -1;
    errno = 0;
    unsigned long long v = strtoull (s, &end, 10);
    if (errno || *end || v >= 0xffffffffULL)
        return -1;
    *out = (unsigned long) v;
    return 0;
}

static int
rd_create (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "size",      BOS_REQ_ARG, 's' },
        { "mode",      BOS_REQ_ARG, 'm' },
        { "uid",       BOS_REQ_ARG, 'u' },
        { "gid",       BOS_REQ_ARG, 'g' },
        { "nr-inodes", BOS_REQ_ARG, 'i' },
        { "options",   BOS_REQ_ARG, 'o' },
        { "force",     BOS_NO_ARG,  'f' },
        { "help",      BOS_NO_ARG,  BOS_OPT_HELP },
        { "version",   BOS_NO_ARG,  BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c, force = 0, rc = EXECUTION_FAILURE;
    const char *size = NULL, *mode = NULL, *uid = NULL, *gid = NULL, *inodes = NULL, *opts = NULL;
    unsigned long flags = MS_NOSUID | MS_NODEV, id;
    char data[RD_DATA_MAX] = "";
    uint64_t bytes;
    unsigned pct;
    size_t made;

    bos_getopt_init (&g, RD_PROG, "s:m:u:g:i:o:f", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case 's': size = g.optarg; break;
        case 'm': mode = g.optarg; break;
        case 'u': uid = g.optarg; break;
        case 'g': gid = g.optarg; break;
        case 'i': inodes = g.optarg; break;
        case 'o': opts = g.optarg; break;
        case 'f': force = 1; break;
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (g.noperands == 0) {
        bos_getopt_free (&g);
        return rd_usage_error ("create: missing PATH operand%s", "");
    }
    if (g.noperands > 1) {
        rc = rd_usage_error ("create: extra operand '%s'", g.operands[1]);
        bos_getopt_free (&g);
        return rc;
    }
    const char *path = g.operands[0];

    if (size && rd_parse_size (size, 1, &bytes, &pct) < 0) {
        builtin_error ("create: invalid size '%s'", size);
        goto out;
    }
    if (inodes && rd_parse_size (inodes, 0, &bytes, &pct) < 0) {
        builtin_error ("create: invalid inode count '%s'", inodes);
        goto out;
    }
    if (mode) {
        char *end;
        unsigned long m = strtoul (mode, &end, 8);
        if (!*mode || *end || strspn (mode, "01234567") != strlen (mode) || m > 07777) {
            builtin_error ("create: invalid mode '%s'", mode);
            goto out;
        }
    }
    if (uid && rd_parse_id (uid, &id) < 0) {
        builtin_error ("create: invalid user ID '%s'", uid);
        goto out;
    }
    if (gid && rd_parse_id (gid, &id) < 0) {
        builtin_error ("create: invalid group ID '%s'", gid);
        goto out;
    }
    if ((size && rd_data_add (data, "size=%s", size) < 0)
        || (inodes && rd_data_add (data, "nr_inodes=%s", inodes) < 0)
        || (mode && rd_data_add (data, "mode=%s", mode) < 0)
        || (uid && rd_data_add (data, "uid=%s", uid) < 0)
        || (gid && rd_data_add (data, "gid=%s", gid) < 0)) {
        builtin_error ("create: options too long");
        goto out;
    }
    if (opts && rd_parse_opts (opts, &flags, data) < 0)
        goto out;

    int mounted = rd_is_mountpoint (path);
    if (mounted < 0)
        goto out;
    if (mounted && !force) {
        builtin_error ("create: %s is already a mount point (--force mounts over it)", path);
        goto out;
    }
    if (rd_mkdir_p (path, &made) < 0) {
        builtin_error ("create: cannot create %s: %s", path, strerror (errno));
        goto out;
    }
    if (mount ("tmpfs", path, "tmpfs", flags, data[0] ? data : NULL) < 0) {
        int e = errno;
        rd_unmake (path, made);
        builtin_error ("create: cannot mount tmpfs on %s: %s", path, strerror (e));
        goto out;
    }
    printf ("mounted %s (tmpfs%s%s)\n", path, data[0] ? ", " : "", data);
    rc = sh_chkwrite (EXECUTION_SUCCESS);
out:
    bos_getopt_free (&g);
    return rc;
}

/* ---------------- resize / remove --------------------------------------- */

/* Resolve PATH to the mount on top at exactly that place: *T is loaded and
   the index returned, or -1 after a diagnostic naming VERB. */
static long
rd_mount_at (const char *verb, const char *path, rd_table *t, char **canon)
{
    long at;

    *canon = realpath (path, NULL);
    if (!*canon) {
        builtin_error ("%s: %s: %s", verb, path, strerror (errno));
        return -1;
    }
    if (rd_table_load (t) < 0) {
        free (*canon);
        *canon = NULL;
        return -1;
    }
    at = rd_find_at (t, *canon);
    if (at < 0) {
        builtin_error ("%s: %s is not a mount point", verb, path);
        rd_table_free (t);
        free (*canon);
        *canon = NULL;
    }
    return at;
}

static int
rd_resize (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "help",    BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c, rc = EXECUTION_FAILURE;
    rd_table t;
    char *canon = NULL, data[RD_DATA_MAX] = "", shown[64];
    uint64_t bytes;
    unsigned pct;
    rd_usage u;
    long at;

    bos_getopt_init (&g, RD_PROG, "", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (g.noperands < 2) {
        rc = rd_usage_error (g.noperands ? "resize: missing SIZE operand%s"
                                         : "resize: missing PATH and SIZE operands%s", "");
        bos_getopt_free (&g);
        return rc;
    }
    if (g.noperands > 2) {
        rc = rd_usage_error ("resize: extra operand '%s'", g.operands[2]);
        bos_getopt_free (&g);
        return rc;
    }
    const char *path = g.operands[0], *size = g.operands[1];
    if (rd_parse_size (size, 1, &bytes, &pct) < 0) {
        builtin_error ("resize: invalid size '%s'", size);
        goto out;
    }
    if ((at = rd_mount_at ("resize", path, &t, &canon)) < 0)
        goto out;
    if (strcmp (t.v[at].type, "tmpfs") != 0) {
        builtin_error ("resize: %s is a %s mount, not tmpfs", path, t.v[at].type);
        goto out_table;
    }
    if (rd_statfs (canon, &u) < 0) {
        builtin_error ("resize: %s: %s", path, strerror (errno));
        goto out_table;
    }
    rd_data_add (data, "size=%s", size);
    /* MS_REMOUNT replaces the per-mount flags with those given: repeat the
       mount's own, or nosuid/nodev/noexec would be dropped. */
    if (mount (t.v[at].src, canon, NULL, MS_REMOUNT | rd_remount_flags (u.flags), data) < 0) {
        int e = errno;
        if (pct) {
            struct sysinfo si;
            bytes = sysinfo (&si) == 0 ? (uint64_t) si.totalram * si.mem_unit / 100 * pct : 0;
        }
        if (e == EINVAL && bytes && bytes < u.used) {
            rd_human (u.used, shown, sizeof shown);
            builtin_error ("resize: cannot shrink %s to %s: %s is in use: %s", path, size, shown, strerror (e));
        } else if (e == EINVAL && u.size == 0 && (bytes || pct))
            /* Observed: the kernel will not limit a tmpfs mounted without one. */
            builtin_error ("resize: cannot limit %s to %s: it has no size limit, and the kernel cannot add one: %s",
                           path, size, strerror (e));
        else
            builtin_error ("resize: cannot remount %s with size=%s: %s", path, size, strerror (e));
        goto out_table;
    }
    if (rd_statfs (canon, &u) < 0) {
        builtin_error ("resize: %s: %s", path, strerror (errno));
        goto out_table;
    }
    if (u.size)
        rd_human (u.size, shown, sizeof shown);
    else
        snprintf (shown, sizeof shown, "no limit");
    printf ("resized %s to %s\n", path, shown);
    rc = sh_chkwrite (EXECUTION_SUCCESS);
out_table:
    rd_table_free (&t);
    free (canon);
out:
    bos_getopt_free (&g);
    return rc;
}

static int
rd_remove (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "lazy",    BOS_NO_ARG, 'l' },
        { "rmdir",   BOS_NO_ARG, RD_OPT_RMDIR },
        { "help",    BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c, lazy = 0, remove_dir = 0, rc = EXECUTION_SUCCESS;

    bos_getopt_init (&g, RD_PROG, "l", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case 'l':          lazy = 1; break;
        case RD_OPT_RMDIR: remove_dir = 1; break;
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (g.noperands == 0) {
        bos_getopt_free (&g);
        return rd_usage_error ("remove: missing PATH operand%s", "");
    }
    for (int i = 0; i < g.noperands; i++) {
        const char *path = g.operands[i];
        rd_table t;
        char *canon;
        long at = rd_mount_at ("remove", path, &t, &canon);

        if (at < 0) {
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (!rd_is_ram (&t.v[at])) {
            builtin_error ("remove: %s is not a RAM-backed mount (%s)", path, t.v[at].type);
            rc = EXECUTION_FAILURE;
        } else if (umount2 (canon, lazy ? MNT_DETACH : 0) < 0) {
            builtin_error ("remove: cannot unmount %s: %s", path, strerror (errno));
            rc = EXECUTION_FAILURE;
        } else {
            printf ("unmounted %s\n", path);
            if (remove_dir) {
                int still = rd_is_mountpoint (canon);
                if (still) {
                    if (still > 0)
                        builtin_error ("remove: %s is still a mount point; not removing it", path);
                    rc = EXECUTION_FAILURE;
                } else if (rmdir (canon) < 0) {
                    builtin_error ("remove: cannot remove %s: %s", path, strerror (errno));
                    rc = EXECUTION_FAILURE;
                } else
                    printf ("removed %s\n", path);
            }
        }
        rd_table_free (&t);
        free (canon);
    }
    bos_getopt_free (&g);
    return sh_chkwrite (rc);
}

/* ---------------- zram -------------------------------------------------- */

/* The zram sysfs interface (the kernel's zram documentation): reading
   /sys/class/zram-control/hot_add makes a device and returns its number;
   /sys/block/zramN/comp_algorithm and then disksize configure it; writing
   1 to reset releases its memory and the number to hot_remove deletes it. */

static int
rd_write_file (const char *path, const char *text)
{
    int fd = open (path, O_WRONLY | O_CLOEXEC);
    size_t len = strlen (text);

    if (fd < 0)
        return -1;
    ssize_t n = write (fd, text, len);
    int e = errno;
    if (close (fd) < 0 && n == (ssize_t) len)
        return -1;
    if (n != (ssize_t) len) {
        errno = n < 0 ? e : EIO;
        return -1;
    }
    return 0;
}

/* "N", "zramN" or "/dev/zramN" to N; -1 if none of those. */
static long
rd_zram_number (const char *s)
{
    char *end;
    if (strncmp (s, "/dev/", 5) == 0)
        s += 5;
    if (strncmp (s, "zram", 4) == 0)
        s += 4;
    if (!isdigit ((unsigned char) *s))
        return -1;
    errno = 0;
    long n = strtol (s, &end, 10);
    return errno || *end || n > 1000000 ? -1 : n;
}

static int
rd_zram (WORD_LIST *list)
{
    static const struct bos_longopt longopts[] = {
        { "algorithm", BOS_REQ_ARG, 'a' },
        { "root",      BOS_REQ_ARG, RD_OPT_ROOT },
        { "help",      BOS_NO_ARG,  BOS_OPT_HELP },
        { "version",   BOS_NO_ARG,  BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c, rc = EXECUTION_FAILURE, add;
    const char *algo = NULL, *root = "";
    char ctl[PATH_MAX], file[PATH_MAX + 64], buf[32];
    struct stat st;
    uint64_t bytes;
    unsigned pct;

    bos_getopt_init (&g, RD_PROG, "a:", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
        switch (c) {
        case 'a':         algo = g.optarg; break;
        case RD_OPT_ROOT: root = g.optarg; break;
        case BOS_OPT_HELP:    bos_getopt_free (&g); return rd_help ();
        case BOS_OPT_VERSION: bos_getopt_free (&g); return rd_version ();
        default:              bos_getopt_free (&g); return EXECUTION_FAILURE;
        }
    if (g.noperands == 0) {
        bos_getopt_free (&g);
        return rd_usage_error ("zram: missing command (add or remove)%s", "");
    }
    add = strcmp (g.operands[0], "add") == 0;
    if (!add && strcmp (g.operands[0], "remove") != 0) {
        rc = rd_usage_error ("zram: unknown command '%s'", g.operands[0]);
        goto out;
    }
    if (add && g.noperands != 2) {
        rc = rd_usage_error (g.noperands < 2 ? "zram add: missing SIZE operand%s"
                                             : "zram add: extra operand '%s'",
                             g.noperands < 2 ? "" : g.operands[2]);
        goto out;
    }
    if (!add && g.noperands < 2) {
        rc = rd_usage_error ("zram remove: missing device operand%s", "");
        goto out;
    }
    if (!add && algo) {
        rc = rd_usage_error ("zram remove: -a only applies to zram add%s", "");
        goto out;
    }
    if (add && (rd_parse_size (g.operands[1], 0, &bytes, &pct) < 0 || bytes == 0)) {
        builtin_error ("zram add: invalid size '%s'", g.operands[1]);
        goto out;
    }
    if (algo && (!*algo || strpbrk (algo, "/\n "))) {
        builtin_error ("zram add: invalid algorithm '%s'", algo);
        goto out;
    }

    size_t rlen = strlen (root);
    while (rlen > 0 && root[rlen - 1] == '/')
        rlen--;
    if (rlen > PATH_MAX - 128) {
        builtin_error ("zram: %s: %s", root, strerror (ENAMETOOLONG));
        goto out;
    }
    snprintf (ctl, sizeof ctl, "%.*s/sys/class/zram-control", (int) rlen, root);
    if (stat (ctl, &st) < 0 || !S_ISDIR (st.st_mode)) {
        builtin_error ("zram not available in this kernel (no %s)", ctl);
        goto out;
    }

    if (add) {
        snprintf (file, sizeof file, "%s/hot_add", ctl);
        int fd = open (file, O_RDONLY | O_CLOEXEC);
        ssize_t n = fd < 0 ? -1 : read (fd, buf, sizeof buf - 1);
        int e = errno;
        if (fd >= 0)
            close (fd);
        if (n <= 0) {
            builtin_error ("zram add: %s: %s", file, n < 0 ? strerror (e) : "no device number");
            goto out;
        }
        buf[n] = '\0';
        buf[strcspn (buf, "\n")] = '\0';
        long num = rd_zram_number (buf);
        if (num < 0) {
            builtin_error ("zram add: %s: unexpected reply '%s'", file, buf);
            goto out;
        }
        const char *step = NULL, *value = NULL;
        if (algo) {
            snprintf (file, sizeof file, "%.*s/sys/block/zram%ld/comp_algorithm", (int) rlen, root, num);
            if (rd_write_file (file, algo) < 0) {
                step = "cannot set compression algorithm";
                value = algo;
            }
        }
        if (!step) {
            snprintf (file, sizeof file, "%.*s/sys/block/zram%ld/disksize", (int) rlen, root, num);
            if (rd_write_file (file, g.operands[1]) < 0) {
                step = "cannot set disk size";
                value = g.operands[1];
            }
        }
        if (step) {
            int e2 = errno;
            snprintf (buf, sizeof buf, "%ld", num);
            snprintf (file, sizeof file, "%s/hot_remove", ctl);
            rd_write_file (file, buf);
            builtin_error ("zram add: %s %s on zram%ld: %s", step, value, num, strerror (e2));
            goto out;
        }
        printf ("/dev/zram%ld\n", num);
        rc = sh_chkwrite (EXECUTION_SUCCESS);
        goto out;
    }

    rc = EXECUTION_SUCCESS;
    for (int i = 1; i < g.noperands; i++) {
        long num = rd_zram_number (g.operands[i]);
        if (num < 0) {
            builtin_error ("zram remove: invalid device '%s'", g.operands[i]);
            rc = EXECUTION_FAILURE;
            continue;
        }
        snprintf (file, sizeof file, "%.*s/sys/block/zram%ld", (int) rlen, root, num);
        if (stat (file, &st) < 0) {
            builtin_error ("zram remove: no such device: zram%ld", num);
            rc = EXECUTION_FAILURE;
            continue;
        }
        snprintf (file, sizeof file, "%.*s/sys/block/zram%ld/reset", (int) rlen, root, num);
        if (rd_write_file (file, "1") < 0) {
            builtin_error ("zram remove: cannot reset zram%ld: %s%s", num, strerror (errno),
                           errno == EBUSY ? " (mounted or in use as swap?)" : "");
            rc = EXECUTION_FAILURE;
            continue;
        }
        snprintf (buf, sizeof buf, "%ld", num);
        snprintf (file, sizeof file, "%s/hot_remove", ctl);
        if (rd_write_file (file, buf) < 0) {
            builtin_error ("zram remove: cannot remove zram%ld: %s", num, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        printf ("removed /dev/zram%ld\n", num);
    }
    rc = sh_chkwrite (rc);
out:
    bos_getopt_free (&g);
    return rc;
}

/* ---------------- dispatch ---------------------------------------------- */

int
ramdisk_builtin (WORD_LIST *list)
{
    static const struct {
        const char *name;
        int (*fn) (WORD_LIST *);
    } verbs[] = {
        { "list", rd_list }, { "setup", rd_setup }, { "create", rd_create },
        { "resize", rd_resize }, { "remove", rd_remove }, { "zram", rd_zram },
        { NULL, NULL }
    };
    const char *w;

    if (!list)
        return rd_list (NULL);
    w = list->word->word;
    if (w[0] == '-')
        return rd_list (list);  /* list's options, --help, --version */
    for (int i = 0; verbs[i].name; i++)
        if (strcmp (w, verbs[i].name) == 0)
            return verbs[i].fn (list->next);
    return rd_usage_error ("unknown command '%s'", w);
}

char *ramdisk_doc[] = {
    "Manage RAM-backed filesystems: tmpfs, ramfs, mqueue and zram.",
    "",
    "    ramdisk [list] [-b|-h] [PATH...]",
    "    ramdisk setup [-n|--dry-run] [--tmp] [--no-run] [--root DIR]",
    "    ramdisk create [-s SIZE] [-m MODE] [-u UID] [-g GID] [-i INODES]",
    "                   [-o OPTS] [-f|--force] PATH",
    "    ramdisk resize PATH SIZE",
    "    ramdisk remove [-l|--lazy] [--rmdir] PATH...",
    "    ramdisk zram [--root DIR] add SIZE [-a ALGO] | remove N...",
    "",
    "list    Show the RAM-backed mounts (tmpfs, ramfs, mqueue, devtmpfs,",
    "        hugetlbfs, zram) as TYPE SIZE USED AVAIL USE% MODE MOUNTPOINT,",
    "        in human-readable sizes (-h, the default) or bytes (-b). With",
    "        PATHs, show the RAM-backed mount holding each one.",
    "setup   Mount the standard set, leaving whatever is already mounted:",
    "        /run       tmpfs nosuid,nodev, mode 755",
    "        /run/lock  tmpfs nosuid,nodev,noexec, mode 1777, size 5m",
    "        /dev/shm   tmpfs nosuid,nodev, mode 1777",
    "        /dev/mqueue  mqueue nosuid,nodev,noexec, if the kernel has it",
    "        /tmp       tmpfs nosuid,nodev, mode 1777, only with --tmp",
    "        --no-run skips /run and /run/lock; -n/--dry-run reports what it",
    "        would do; --root DIR sets up the tree at DIR. Missing mount",
    "        points are created.",
    "create  Mount a tmpfs at PATH, making PATH as mkdir -p does. SIZE is",
    "        bytes with an optional k, m or g suffix, or N% of RAM; 0 is no",
    "        limit. MODE is octal; UID, GID and INODES are numbers (INODES may",
    "        take k, m or g). The mount is nosuid,nodev unless -o says suid or",
    "        dev; other -o OPTS are mount flags or tmpfs options. A PATH that",
    "        is already a mount point is refused unless -f/--force.",
    "resize  Change a tmpfs's size limit in place, keeping its contents and",
    "        mount flags. The kernel refuses a size below the current use, and",
    "        a limit for a tmpfs that has none (size 0).",
    "remove  Unmount a RAM-backed mount (-l/--lazy detaches it now and",
    "        frees it when no longer busy); --rmdir also removes PATH.",
    "zram    Add a compressed RAM block device of SIZE (k, m or g), with",
    "        compression ALGO, and print its /dev/zramN; or remove devices.",
    "        Needs the kernel's zram module (/sys/class/zram-control).",
    "",
    "Exit Status: 0 on success; 1 for a usage error or if anything could not",
    "be listed, mounted, resized or removed.",
    (char *) NULL
};

struct builtin ramdisk_struct = {
    "ramdisk",
    ramdisk_builtin,
    BUILTIN_ENABLED,
    ramdisk_doc,
    "ramdisk [list|setup|create|resize|remove|zram] [OPTION]... [ARG]...",
    0
};
