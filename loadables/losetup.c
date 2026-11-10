/* SPDX-License-Identifier: MIT */
/* losetup.c — set up and control loop devices, as a bash builtin.
 *
 *   losetup [-l|-a] [-n] [-O COLS|--output-all] [--raw|-J]   list used loops
 *   losetup [-l] LOOPDEV                       show one loop device
 *   losetup -j FILE [-o OFF]                   list loops backed by FILE
 *   losetup -f                                 print the first free loop device
 *   losetup [-r] [-P] [-o N] [--sizelimit N] [-b N] [--show] -f|LOOPDEV FILE
 *   losetup -d LOOPDEV...   |   losetup -D     detach
 *   losetup -c LOOPDEV                         refresh the device size
 *
 * Command-line, listing and diagnostic behaviour follows util-linux 2.41
 * losetup(8): GNU getopt_long parsing with permutation, its mutually
 * exclusive option groups, its size syntax, the -a line format, the
 * libsmartcols table, and the used-device scan (/sys/block, or
 * /proc/partitions without sysfs, with every entry verified against the
 * loop device node). Device attributes come from /sys/dev/block/MAJ:MIN,
 * falling back to LOOP_GET_STATUS64. Attach uses LOOP_CONFIGURE, falling back
 * to LOOP_SET_FD + LOOP_SET_STATUS64 and clearing a half-made association.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <linux/loop.h>

#include "loadables.h"

/* bash's builtins/getopt.h shadows the system header on the loadable include
   path; declare the libc getopt_long(3) interface directly (as ls.c does). */
struct option
{
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#define bl_no_arg   0
#define bl_req_arg  1
#define bl_opt_arg  2
extern int getopt_long (int, char *const *, const char *,
                        const struct option *, int *);

#ifndef LOOP_CTL_GET_FREE
#  define LOOP_CTL_GET_FREE 0x4C82
#endif
#ifndef LOOP_CTL_ADD
#  define LOOP_CTL_ADD 0x4C80
#endif
#ifndef LOOP_SET_CAPACITY
#  define LOOP_SET_CAPACITY 0x4C07
#endif
#ifndef LOOP_SET_DIRECT_IO
#  define LOOP_SET_DIRECT_IO 0x4C08
#endif
#ifndef LOOP_SET_BLOCK_SIZE
#  define LOOP_SET_BLOCK_SIZE 0x4C09
#endif
#define BL_LOOP_CONFIGURE 0x4C0A
#ifndef LO_FLAGS_AUTOCLEAR
#  define LO_FLAGS_AUTOCLEAR 4
#endif
#ifndef LO_FLAGS_PARTSCAN
#  define LO_FLAGS_PARTSCAN 8
#endif
#ifndef LO_FLAGS_DIRECT_IO
#  define LO_FLAGS_DIRECT_IO 16
#endif

/* struct loop_config (Linux 5.8), declared locally for older headers. */
struct bl_loop_config
{
    uint32_t fd;
    uint32_t block_size;
    struct loop_info64 info;
    uint64_t reserved[8];
};

#define BL_LOOP_MAJOR   7
#define BL_EAGAIN_TRIES 64

/* util-linux option values beyond the short-option range */
enum { OPT_SIZELIMIT = 256, OPT_SHOW, OPT_RAW, OPT_DIO, OPT_OUTPUT_ALL, OPT_REF };

static const struct option bl_longopts[] = {
    { "all",          bl_no_arg,  NULL, 'a' },
    { "set-capacity", bl_req_arg, NULL, 'c' },
    { "detach",       bl_req_arg, NULL, 'd' },
    { "detach-all",   bl_no_arg,  NULL, 'D' },
    { "find",         bl_no_arg,  NULL, 'f' },
    { "nooverlap",    bl_no_arg,  NULL, 'L' },
    { "help",         bl_no_arg,  NULL, 'h' },
    { "associated",   bl_req_arg, NULL, 'j' },
    { "json",         bl_no_arg,  NULL, 'J' },
    { "list",         bl_no_arg,  NULL, 'l' },
    { "sector-size",  bl_req_arg, NULL, 'b' },
    { "noheadings",   bl_no_arg,  NULL, 'n' },
    { "offset",       bl_req_arg, NULL, 'o' },
    { "output",       bl_req_arg, NULL, 'O' },
    { "output-all",   bl_no_arg,  NULL, OPT_OUTPUT_ALL },
    { "sizelimit",    bl_req_arg, NULL, OPT_SIZELIMIT },
    { "partscan",     bl_no_arg,  NULL, 'P' },
    { "read-only",    bl_no_arg,  NULL, 'r' },
    { "direct-io",    bl_opt_arg, NULL, OPT_DIO },
    { "raw",          bl_no_arg,  NULL, OPT_RAW },
    { "loop-ref",     bl_req_arg, NULL, OPT_REF },
    { "show",         bl_no_arg,  NULL, OPT_SHOW },
    { "verbose",      bl_no_arg,  NULL, 'v' },
    { "version",      bl_no_arg,  NULL, 'V' },
    { NULL, 0, NULL, 0 }
};

/* Mutually exclusive groups, each in ascending option-value order. */
static const int bl_excl[][7] = {
    { 'D', 'a', 'c', 'd', 'f', 'j', 0 },
    { 'D', 'c', 'd', 'f', 'l', 0 },
    { 'D', 'O', 'c', 'd', 'f', 0 },
    { 'J', OPT_RAW, 0 },
};
#define BL_NEXCL ((int) (sizeof bl_excl / sizeof bl_excl[0]))

/* ------------------------------------------------------------------ */
/* loop device context (util-linux loopdev_cxt subset)                */

typedef struct
{
    char device[PATH_MAX];
    int fd;
    int rdwr;
    int devno_state;            /* 0 unknown, 1 known, -1 unavailable */
    dev_t devno;
    int info_state;             /* 0 unread, 1 read, -1 failed */
    struct loop_info64 info;
} bl_lc;

static void
lc_reset (bl_lc *lc)
{
    if (lc->fd >= 0)
        close (lc->fd);
    memset (lc, 0, sizeof *lc);
    lc->fd = -1;
}

/* A name without a leading '/' or '.' is taken relative to /dev. */
static void
lc_set (bl_lc *lc, const char *name)
{
    lc_reset (lc);
    if (*name != '/' && *name != '.')
        snprintf (lc->device, sizeof lc->device, "/dev/%s", name);
    else
        snprintf (lc->device, sizeof lc->device, "%s", name);
}

static int
lc_fd (bl_lc *lc)
{
    if (lc->fd < 0)
        lc->fd = open (lc->device, (lc->rdwr ? O_RDWR : O_RDONLY) | O_CLOEXEC);
    return lc->fd;
}

static int
read_line (const char *path, char *buf, size_t n)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t r = read (fd, buf, n - 1);
    int saved = errno;
    close (fd);
    if (r < 0) {
        errno = saved;
        return -1;
    }
    buf[r] = '\0';
    size_t l = strlen (buf);
    while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r'))
        buf[--l] = '\0';
    return 0;
}

static int
lc_devno (bl_lc *lc, dev_t *out)
{
    if (!lc->devno_state) {
        struct stat st;
        lc->devno_state = -1;
        if (stat (lc->device, &st) == 0 && S_ISBLK (st.st_mode)) {
            lc->devno = st.st_rdev;
            lc->devno_state = 1;
        } else {
            /* A node missing from /dev can still be found by name in sysfs. */
            const char *base = strrchr (lc->device, '/');
            char path[PATH_MAX], buf[64];
            unsigned int ma, mi;
            base = base ? base + 1 : lc->device;
            if (!strncmp (base, "loop", 4)
                && snprintf (path, sizeof path, "/sys/block/%s/dev", base) < (int) sizeof path
                && read_line (path, buf, sizeof buf) == 0
                && sscanf (buf, "%u:%u", &ma, &mi) == 2) {
                lc->devno = makedev (ma, mi);
                lc->devno_state = 1;
            }
        }
    }
    if (lc->devno_state < 0)
        return -1;
    *out = lc->devno;
    return 0;
}

static int
lc_sysfs (bl_lc *lc, const char *attr, char *buf, size_t n)
{
    dev_t d;
    char path[128];
    if (lc_devno (lc, &d) < 0)
        return -1;
    snprintf (path, sizeof path, "/sys/dev/block/%u:%u/%s", major (d), minor (d), attr);
    return read_line (path, buf, n);
}

static int
lc_sysfs_u64 (bl_lc *lc, const char *attr, uint64_t *out)
{
    char buf[64], *end;
    if (lc_sysfs (lc, attr, buf, sizeof buf) < 0 || !isdigit ((unsigned char) buf[0]))
        return -1;
    errno = 0;
    unsigned long long v = strtoull (buf, &end, 10);
    if (errno || *end)
        return -1;
    if (out)
        *out = v;
    return 0;
}

/* LOOP_GET_STATUS64, read once; a failure is remembered (as EINVAL). */
static struct loop_info64 *
lc_info (bl_lc *lc)
{
    if (lc->info_state > 0)
        return &lc->info;
    if (lc->info_state < 0) {
        errno = EINVAL;
        return NULL;
    }
    int fd = lc_fd (lc);
    if (fd < 0)
        return NULL;
    if (ioctl (fd, LOOP_GET_STATUS64, &lc->info) == 0) {
        lc->info_state = 1;
        return &lc->info;
    }
    lc->info_state = -1;
    return NULL;
}

static int
lc_offset (bl_lc *lc, uint64_t *out)
{
    if (lc_sysfs_u64 (lc, "loop/offset", out) == 0)
        return 0;
    struct loop_info64 *lo = lc_info (lc);
    if (!lo)
        return -1;
    if (out)
        *out = lo->lo_offset;
    return 0;
}

static int
lc_sizelimit (bl_lc *lc, uint64_t *out)
{
    if (lc_sysfs_u64 (lc, "loop/sizelimit", out) == 0)
        return 0;
    struct loop_info64 *lo = lc_info (lc);
    if (!lo)
        return -1;
    *out = lo->lo_sizelimit;
    return 0;
}

/* sysfs keeps the whole path; loop_info64 keeps 63 bytes, marked by '*'. */
static char *
lc_backing_file (bl_lc *lc)
{
    char buf[PATH_MAX + 1];
    if (lc_sysfs (lc, "loop/backing_file", buf, sizeof buf) == 0)
        return savestring (buf);
    struct loop_info64 *lo = lc_info (lc);
    if (!lo)
        return NULL;
    lo->lo_file_name[LO_NAME_SIZE - 2] = '*';
    lo->lo_file_name[LO_NAME_SIZE - 1] = '\0';
    return savestring ((char *) lo->lo_file_name);
}

/* Flag attributes: sysfs, then loop_info64 flags, else unset. util-linux
   2.41 reports a failed info lookup as a set partscan flag. */
static int
lc_flag (bl_lc *lc, const char *attr, uint32_t bit)
{
    uint64_t v;
    if (lc_sysfs_u64 (lc, attr, &v) == 0)
        return v != 0;
    struct loop_info64 *lo = lc_info (lc);
    if (lo)
        return (lo->lo_flags & bit) != 0;
    return bit == LO_FLAGS_PARTSCAN;
}

static int
lc_blocksize (bl_lc *lc, uint64_t *out)
{
    if (lc_sysfs_u64 (lc, "queue/logical_block_size", out) == 0)
        return 0;
    int fd = lc_fd (lc), sz = 0;
    if (fd < 0 || ioctl (fd, BLKSSZGET, &sz) < 0)
        return -1;
    *out = (uint64_t) sz;
    return 0;
}

static int
lc_used (bl_lc *lc)
{
    return lc_offset (lc, NULL) == 0;
}

static int
bl_is_loopdev (const char *path)
{
    struct stat st;
    if (stat (path, &st) != 0 || !S_ISBLK (st.st_mode)) {
        errno = ENODEV;
        return 0;
    }
    if (major (st.st_rdev) == BL_LOOP_MAJOR)
        return 1;
    char link[64], target[PATH_MAX];
    snprintf (link, sizeof link, "/sys/dev/block/%u:%u", major (st.st_rdev), minor (st.st_rdev));
    ssize_t n = readlink (link, target, sizeof target - 1);
    if (n > 0) {
        target[n] = '\0';
        const char *base = strrchr (target, '/');
        if (!strncmp (base ? base + 1 : target, "loop", 4))
            return 1;
    }
    errno = ENODEV;
    return 0;
}

/* ------------------------------------------------------------------ */
/* used-device scan                                                   */

typedef struct
{
    char **names;
    size_t n, cap;
} bl_names;

static void
names_add (bl_names *v, const char *name)
{
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 16;
        v->names = xrealloc (v->names, v->cap * sizeof *v->names);
    }
    v->names[v->n++] = savestring (name);
}

static void
names_free (bl_names *v)
{
    for (size_t i = 0; i < v->n; i++)
        free (v->names[i]);
    free (v->names);
    memset (v, 0, sizeof *v);
}

/* Names of loop entries with a backing file, in /sys/block directory order,
   or loop-major entries of /proc/partitions when sysfs is absent. */
static void
used_candidates (bl_names *v)
{
    if (access ("/sys/block", F_OK) == 0 && access ("/sys/dev/block", F_OK) == 0) {
        DIR *d = opendir ("/sys/block");
        if (!d)
            return;
        struct dirent *de;
        while ((de = readdir (d))) {
            struct stat st;
            char rel[NAME_MAX + 32];
            if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")
                || strncmp (de->d_name, "loop", 4))
                continue;
            snprintf (rel, sizeof rel, "%s/loop/backing_file", de->d_name);
            if (fstatat (dirfd (d), rel, &st, 0) != 0)
                continue;
            names_add (v, de->d_name);
        }
        closedir (d);
        return;
    }
    FILE *f = fopen ("/proc/partitions", "re");
    if (!f)
        return;
    char buf[BUFSIZ], name[129];
    unsigned int m;
    while (fgets (buf, sizeof buf, f))
        if (sscanf (buf, " %u %*s %*s %128[^\n ]", &m, name) == 2 && m == BL_LOOP_MAJOR)
            names_add (v, name);
    fclose (f);
}

/* Select the used loop named NAME into LC; 0 when it qualifies. */
static int
used_select (bl_lc *lc, const char *name)
{
    lc_set (lc, name);
    if (!bl_is_loopdev (lc->device))
        return -1;
    return lc_used (lc) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* free device                                                        */

static int
cmp_int (const void *a, const void *b)
{
    int x = *(const int *) a, y = *(const int *) b;
    return (x > y) - (x < y);
}

/* LOOP_CTL_GET_FREE, else the first of loop0..loop7 and then the /dev/loopN
   nodes that is not in use. *control_ok reports loop-control success. */
static int
find_unused (bl_lc *lc, int *control_ok)
{
    char name[32];
    int ctl = open ("/dev/loop-control", O_RDWR | O_CLOEXEC), rc = -1;
    if (ctl >= 0) {
        rc = ioctl (ctl, LOOP_CTL_GET_FREE);
        close (ctl);
    }
    *control_ok = ctl >= 0 && rc >= 0;
    if (rc >= 0) {
        snprintf (name, sizeof name, "loop%d", rc);
        lc_set (lc, name);
        return 0;
    }
    for (int i = 0; i < 8; i++) {
        snprintf (name, sizeof name, "loop%d", i);
        lc_set (lc, name);
        if (!lc_used (lc))
            return 0;
    }
    DIR *d = opendir ("/dev");
    int *minors = NULL;
    size_t n = 0, cap = 0;
    if (d) {
        struct dirent *de;
        while ((de = readdir (d))) {
            const char *p = de->d_name;
            if (strncmp (p, "loop", 4) || !isdigit ((unsigned char) p[4]))
                continue;
            char *end;
            long v = strtol (p + 4, &end, 10);
            if (*end || v < 0 || v > INT_MAX)
                continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                minors = xrealloc (minors, cap * sizeof *minors);
            }
            minors[n++] = (int) v;
        }
        closedir (d);
    }
    if (n)
        qsort (minors, n, sizeof *minors, cmp_int);
    for (size_t i = 0; i < n; i++) {
        snprintf (name, sizeof name, "loop%d", minors[i]);
        lc_set (lc, name);
        if (!lc_used (lc)) {
            free (minors);
            return 0;
        }
    }
    free (minors);
    lc_reset (lc);
    errno = ENOENT;
    return -1;
}

/* The kernel knows the device but /dev has no node for it. */
static int
lc_is_lost (bl_lc *lc)
{
    struct stat st;
    const char *base = strrchr (lc->device, '/');
    char path[PATH_MAX];
    if (stat (lc->device, &st) == 0 || !base)
        return 0;
    snprintf (path, sizeof path, "/sys/block/%s", base + 1);
    return access (path, F_OK) == 0;
}

/* ------------------------------------------------------------------ */
/* util-linux size syntax: base-0 integer, optional fraction, K..Y with
   optional "iB" (1024) or "B" (1000). */

static int
bl_scale (uintmax_t *x, unsigned base, int pwr)
{
    while (pwr--) {
        if (*x > UINTMAX_MAX / base)
            return -ERANGE;
        *x *= base;
    }
    return 0;
}

static int
bl_parse_size (const char *str, uint64_t *out)
{
    static const char suf[] = "KMGTPEZY", suf2[] = "kmgtpezy";
    const char *p = str;
    char *end = NULL;
    uintmax_t x, frac = 0;
    unsigned base = 1024;
    int pwr = 0, frac_zeros = 0;

    if (!str || !*str)
        return -EINVAL;
    while (isspace ((unsigned char) *p))
        p++;
    if (*p == '-')
        return -EINVAL;
    errno = 0;
    x = strtoumax (str, &end, 0);
    if (end == str || (errno != 0 && (x == UINTMAX_MAX || x == 0)))
        return errno ? -errno : -EINVAL;
    if (!end || !*end)
        goto done;
    p = end;
check_suffix:
    if (*p && p[1] == 'i' && (p[2] == 'B' || p[2] == 'b') && !p[3])
        base = 1024;
    else if (*p && (p[1] == 'B' || p[1] == 'b') && !p[2])
        base = 1000;
    else if (*p && p[1]) {
        if (frac == 0 && *p == '.') {
            const char *f = p + 1;
            for (; *f == '0'; f++)
                frac_zeros++;
            p = f;
            if (isdigit ((unsigned char) *f)) {
                errno = 0;
                frac = strtoumax (f, &end, 0);
                if (end == f || (errno != 0 && (frac == UINTMAX_MAX || frac == 0)))
                    return errno ? -errno : -EINVAL;
                p = end;
            }
            if (!*p)
                return -EINVAL;
            goto check_suffix;
        }
        return -EINVAL;
    }
    {
        const char *sp = *p ? strchr (suf, *p) : NULL;
        if (sp)
            pwr = (int) (sp - suf) + 1;
        else if (*p && (sp = strchr (suf2, *p)))
            pwr = (int) (sp - suf2) + 1;
        else
            return -EINVAL;
    }
    if (bl_scale (&x, base, pwr) < 0)
        return -ERANGE;
    if (frac && pwr) {
        uintmax_t frac_div = 10, frac_poz = 1, frac_base = 1;
        bl_scale (&frac_base, base, pwr);
        while (frac_div < frac) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        for (int i = 0; i < frac_zeros; i++) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        do {
            unsigned seg = (unsigned) (frac % 10);
            uintmax_t seg_div = frac_div / frac_poz;
            frac /= 10;
            frac_poz *= 10;
            if (seg && seg_div / seg)
                x += frac_base / (seg_div / seg);
        } while (frac);
    }
done:
    if (x > UINT64_MAX)
        return -ERANGE;
    *out = (uint64_t) x;
    return 0;
}

/* ------------------------------------------------------------------ */
/* output                                                             */

enum {
    C_NAME, C_AUTOCLR, C_BACK_FILE, C_BACK_INO, C_BACK_MAJMIN, C_BACK_MAJ,
    C_BACK_MIN, C_MAJMIN, C_MAJ, C_MIN, C_OFFSET, C_PARTSCAN, C_REF, C_RO,
    C_SIZELIMIT, C_DIO, C_LOGSEC, C_COUNT
};
enum { J_STR, J_NUM, J_BOOL };

static const struct { const char *name; int right, json; } bl_cols[C_COUNT] = {
    [C_NAME]        = { "NAME",         0, J_STR },
    [C_AUTOCLR]     = { "AUTOCLEAR",    1, J_BOOL },
    [C_BACK_FILE]   = { "BACK-FILE",    0, J_STR },
    [C_BACK_INO]    = { "BACK-INO",     1, J_NUM },
    [C_BACK_MAJMIN] = { "BACK-MAJ:MIN", 0, J_STR },
    [C_BACK_MAJ]    = { "BACK-MAJ",     1, J_NUM },
    [C_BACK_MIN]    = { "BACK-MIN",     1, J_NUM },
    [C_MAJMIN]      = { "MAJ:MIN",      0, J_STR },
    [C_MAJ]         = { "MAJ",          1, J_NUM },
    [C_MIN]         = { "MIN",          1, J_NUM },
    [C_OFFSET]      = { "OFFSET",       1, J_NUM },
    [C_PARTSCAN]    = { "PARTSCAN",     1, J_BOOL },
    [C_REF]         = { "REF",          0, J_STR },
    [C_RO]          = { "RO",           1, J_BOOL },
    [C_SIZELIMIT]   = { "SIZELIMIT",    1, J_NUM },
    [C_DIO]         = { "DIO",          1, J_BOOL },
    [C_LOGSEC]      = { "LOG-SEC",      1, J_NUM },
};

#define BL_MAXCOLS (C_COUNT * 2)

typedef struct
{
    int cols[BL_MAXCOLS];
    int ncols;
    int raw, json, noheadings;
    char **cells;               /* nrows * ncols */
    size_t nrows, cap;
} bl_table;

static char *
fmt_u64 (uint64_t v)
{
    char buf[32];
    snprintf (buf, sizeof buf, "%" PRIu64, v);
    return savestring (buf);
}

static char *
cell_value (bl_lc *lc, int col, int compact)
{
    uint64_t x;
    char buf[64];
    struct loop_info64 *lo;
    struct stat st;

    switch (col) {
    case C_NAME:
        return savestring (lc->device);
    case C_BACK_FILE:
        return lc_backing_file (lc);
    case C_OFFSET:
        return lc_offset (lc, &x) == 0 ? fmt_u64 (x) : NULL;
    case C_SIZELIMIT:
        return lc_sizelimit (lc, &x) == 0 ? fmt_u64 (x) : NULL;
    case C_BACK_INO:
        return (lo = lc_info (lc)) ? fmt_u64 (lo->lo_inode) : NULL;
    case C_BACK_MAJMIN: case C_BACK_MAJ: case C_BACK_MIN:
        if (!(lo = lc_info (lc)) || !lo->lo_device)
            return NULL;
        if (col == C_BACK_MAJ)
            snprintf (buf, sizeof buf, "%u", major (lo->lo_device));
        else if (col == C_BACK_MIN)
            snprintf (buf, sizeof buf, "%u", minor (lo->lo_device));
        else
            snprintf (buf, sizeof buf, compact ? "%u:%u" : "%8u:%-3u",
                      major (lo->lo_device), minor (lo->lo_device));
        return savestring (buf);
    case C_MAJMIN: case C_MAJ: case C_MIN:
        if (stat (lc->device, &st) != 0 || !S_ISBLK (st.st_mode)
            || major (st.st_rdev) != BL_LOOP_MAJOR)
            return NULL;
        if (col == C_MAJ)
            snprintf (buf, sizeof buf, "%u", major (st.st_rdev));
        else if (col == C_MIN)
            snprintf (buf, sizeof buf, "%u", minor (st.st_rdev));
        else
            snprintf (buf, sizeof buf, compact ? "%u:%u" : "%3u:%-3u",
                      major (st.st_rdev), minor (st.st_rdev));
        return savestring (buf);
    case C_AUTOCLR:
        return savestring (lc_flag (lc, "loop/autoclear", LO_FLAGS_AUTOCLEAR) ? "1" : "0");
    case C_RO:
        return savestring (lc_flag (lc, "ro", LO_FLAGS_READ_ONLY) ? "1" : "0");
    case C_DIO:
        return savestring (lc_flag (lc, "loop/dio", LO_FLAGS_DIRECT_IO) ? "1" : "0");
    case C_PARTSCAN:
        return savestring (lc_flag (lc, "loop/partscan", LO_FLAGS_PARTSCAN) ? "1" : "0");
    case C_LOGSEC:
        return lc_blocksize (lc, &x) == 0 ? fmt_u64 (x) : NULL;
    case C_REF:
        if (!(lo = lc_info (lc)))
            return NULL;
        lo->lo_file_name[LO_NAME_SIZE - 1] = '\0';
        return savestring ((char *) lo->lo_file_name);
    }
    return NULL;
}

static void
table_add (bl_table *t, bl_lc *lc)
{
    if (t->nrows == t->cap) {
        t->cap = t->cap ? t->cap * 2 : 8;
        t->cells = xrealloc (t->cells, t->cap * t->ncols * sizeof *t->cells);
    }
    for (int i = 0; i < t->ncols; i++)
        t->cells[t->nrows * t->ncols + i] = cell_value (lc, t->cols[i], t->raw || t->json);
    t->nrows++;
}

static void
put_raw (const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char) *s;
        if (c <= ' ' || c == '\\' || c == 0x7f)
            printf ("\\x%02x", c);
        else
            putchar (c);
    }
}

static void
put_json_string (const char *s)
{
    putchar ('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char) *s;
        if (c == '"' || c == '\\')
            printf ("\\%c", c);
        else if (c < 0x20 || c == 0x7f)
            printf ("\\u%04x", c);
        else
            putchar (c);
    }
    putchar ('"');
}

static void
table_print (bl_table *t)
{
    if (t->json) {
        fputs ("{\n   \"loopdevices\": [\n", stdout);
        for (size_t r = 0; r < t->nrows; r++) {
            fputs (r ? "      },{\n" : "      {\n", stdout);
            for (int i = 0; i < t->ncols; i++) {
                const char *v = t->cells[r * t->ncols + i];
                fputs ("         \"", stdout);
                for (const char *n = bl_cols[t->cols[i]].name; *n; n++)
                    putchar (tolower ((unsigned char) *n));
                fputs ("\": ", stdout);
                switch (bl_cols[t->cols[i]].json) {
                case J_BOOL:
                    fputs (v && *v && *v != '0' ? "true" : "false", stdout);
                    break;
                case J_NUM:
                    fputs (v && *v ? v : "null", stdout);
                    break;
                default:
                    if (v && *v)
                        put_json_string (v);
                    else
                        fputs ("null", stdout);
                }
                fputs (i + 1 < t->ncols ? ",\n" : "\n", stdout);
            }
        }
        fputs (t->nrows ? "      }\n" : "\n", stdout);
        fputs ("   ]\n}\n", stdout);
        return;
    }
    if (!t->nrows)
        return;                 /* libsmartcols prints nothing for no lines */
    if (t->raw) {
        if (!t->noheadings) {
            for (int i = 0; i < t->ncols; i++) {
                if (i)
                    putchar (' ');
                put_raw (bl_cols[t->cols[i]].name);
            }
            putchar ('\n');
        }
        for (size_t r = 0; r < t->nrows; r++) {
            for (int i = 0; i < t->ncols; i++) {
                const char *v = t->cells[r * t->ncols + i];
                if (i)
                    putchar (' ');
                put_raw (v ? v : "");
            }
            putchar ('\n');
        }
        return;
    }
    size_t width[BL_MAXCOLS];
    for (int i = 0; i < t->ncols; i++) {
        width[i] = t->noheadings ? 0 : strlen (bl_cols[t->cols[i]].name);
        for (size_t r = 0; r < t->nrows; r++) {
            const char *v = t->cells[r * t->ncols + i];
            if (v && strlen (v) > width[i])
                width[i] = strlen (v);
        }
    }
    for (size_t r = t->noheadings ? 1 : 0; r <= t->nrows; r++) {
        for (int i = 0; i < t->ncols; i++) {
            const char *v = r ? t->cells[(r - 1) * t->ncols + i] : bl_cols[t->cols[i]].name;
            int last = i + 1 == t->ncols;
            if (!v)
                v = "";
            if (i)
                putchar (' ');
            if (last && !*v)
                break;
            if (bl_cols[t->cols[i]].right)
                printf ("%*s", (int) width[i], v);
            else if (last)
                fputs (v, stdout);
            else
                printf ("%-*s", (int) width[i], v);
        }
        putchar ('\n');
    }
}

static void
table_free (bl_table *t)
{
    for (size_t i = 0; i < t->nrows * t->ncols; i++)
        free (t->cells[i]);
    free (t->cells);
    t->cells = NULL;
    t->nrows = t->cap = 0;
}

/* Backing-file match: device and inode when both are known, else name. */
static int
lc_backed_by (bl_lc *lc, struct stat *st, const char *file, uint64_t offset, int use_offset)
{
    struct loop_info64 *lo = st ? lc_info (lc) : NULL;
    int found = 0;
    if (lo)
        found = lo->lo_inode == st->st_ino && lo->lo_device == st->st_dev;
    else if (file) {
        char *name = lc_backing_file (lc);
        found = name && !strcmp (name, file);
        free (name);
    }
    if (found && use_offset) {
        uint64_t off = 0;
        found = lc_offset (lc, &off) == 0 && off == offset;
    }
    return found;
}

/* "-a" line: "/dev/loopN: [DEV]:INO (FILE), offset N, sizelimit N". */
static int
print_loopdev (bl_lc *lc)
{
    uint64_t x;
    char *fname = lc_backing_file (lc);
    if (!fname)
        return -1;
    struct loop_info64 *lo = lc_info (lc);
    uint64_t dev = lo ? lo->lo_device : 0, ino = lo ? lo->lo_inode : 0;
    if (!dev && !ino)
        printf ("%s: []: (%s)", lc->device, fname);
    else
        printf ("%s: [%04" PRIu64 "]:%" PRIu64 " (%s)", lc->device, dev, ino, fname);
    if (lc_offset (lc, &x) == 0 && x)
        printf (", offset %" PRIu64, x);
    if (lc_sizelimit (lc, &x) == 0 && x)
        printf (", sizelimit %" PRIu64, x);
    if ((dev || ino) && (lo = lc_info (lc)) && lo->lo_encrypt_type) {
        lo->lo_crypt_name[LO_NAME_SIZE - 1] = '\0';
        const char *e = (const char *) lo->lo_crypt_name;
        if (!*e && lo->lo_encrypt_type == 1)
            e = "XOR";
        if (*e)
            printf (", encryption %s (type %u)", e, lo->lo_encrypt_type);
    }
    putchar ('\n');
    free (fname);
    return 0;
}

/* -a / -j / listing over every used device. */
static void
show_used (bl_table *t, const char *file, uint64_t offset, int use_offset)
{
    bl_names v = { 0 };
    struct stat sbuf, *st = &sbuf;
    char *canon = NULL;
    bl_lc lc;

    lc.fd = -1;
    lc_reset (&lc);
    if (!file || stat (file, st))
        st = NULL;
    used_candidates (&v);
    for (size_t i = 0; i < v.n; i++) {
        if (used_select (&lc, v.names[i]) < 0)
            continue;
        if (file) {
            int used = lc_backed_by (&lc, st, canon ? canon : file, offset, use_offset);
            if (!used && !canon) {
                canon = realpath (file, NULL);
                if (!canon)
                    canon = savestring (file);
                used = lc_backed_by (&lc, st, canon, offset, use_offset);
            }
            if (!used)
                continue;
        }
        if (t)
            table_add (t, &lc);
        else
            print_loopdev (&lc);
    }
    lc_reset (&lc);
    names_free (&v);
    free (canon);
}

/* ------------------------------------------------------------------ */
/* setup                                                              */

static int
ioctl_retry (int fd, unsigned long req, void *arg)
{
    for (int tries = 0;; tries++) {
        errno = 0;
        if (ioctl (fd, req, arg) == 0)
            return 0;
        if (errno != EAGAIN || tries >= BL_EAGAIN_TRIES)
            return -1;
        struct timespec ts = { 0, 250000000 };
        nanosleep (&ts, NULL);
    }
}

typedef struct
{
    uint64_t offset, sizelimit, blocksize;
    int set_offset, set_sizelimit;
    uint32_t lo_flags;
    const char *refname;
} bl_setup_opts;

/* Attach FILE to LC's device; on failure errno holds the cause and *opened
   says whether the device itself was opened. */
static int
setup_device (bl_lc *lc, const char *file, const bl_setup_opts *o, int control_ok, int *opened)
{
    struct bl_loop_config cfg;
    int mode = (o->lo_flags & LO_FLAGS_READ_ONLY) ? O_RDONLY : O_RDWR;
    int file_fd, dev_fd, errsv = 0, bound = 0;
    char *canon = realpath (file, NULL);

    *opened = 0;
    memset (&cfg, 0, sizeof cfg);
    if (!canon)
        canon = savestring (file);
    cfg.info.lo_offset = o->set_offset ? o->offset : 0;
    cfg.info.lo_sizelimit = o->set_sizelimit ? o->sizelimit : 0;
    cfg.info.lo_flags = o->lo_flags;
    strncpy ((char *) cfg.info.lo_file_name, o->refname ? o->refname : canon, LO_NAME_SIZE - 1);

    file_fd = open (canon, mode | O_CLOEXEC);
    if (file_fd < 0 && mode != O_RDONLY && (errno == EROFS || errno == EACCES))
        file_fd = open (canon, (mode = O_RDONLY) | O_CLOEXEC);
    errsv = errno;
    free (canon);
    if (file_fd < 0) {
        errno = errsv;
        return -1;
    }
    if (mode == O_RDONLY)
        cfg.info.lo_flags |= LO_FLAGS_READ_ONLY;
    else
        cfg.info.lo_flags &= ~LO_FLAGS_READ_ONLY;
    if (lc->fd >= 0 && lc->rdwr != (mode == O_RDWR)) {
        close (lc->fd);
        lc->fd = -1;
    }
    lc->rdwr = mode == O_RDWR;

    /* udev may not have applied the node's ownership yet. */
    for (int cnt = 0;; cnt++) {
        errno = 0;
        dev_fd = lc_fd (lc);
        if (dev_fd >= 0 || !control_ok || (errno != EACCES && errno != ENOENT) || cnt >= 16)
            break;
        struct timespec ts = { 0, 25000000 };
        nanosleep (&ts, NULL);
    }
    if (dev_fd < 0) {
        errsv = errno;
        close (file_fd);
        errno = errsv;
        return -1;
    }
    *opened = 1;

    cfg.fd = (uint32_t) file_fd;
    cfg.block_size = (uint32_t) o->blocksize;
    if (ioctl_retry (dev_fd, BL_LOOP_CONFIGURE, &cfg) == 0)
        bound = 1;
    else if (errno != EINVAL && errno != ENOTTY && errno != ENOSYS) {
        errsv = errno;
        goto fail;
    } else {
        if (ioctl (dev_fd, LOOP_SET_FD, file_fd) < 0) {
            errsv = errno;
            goto fail;
        }
        bound = 1;
        if (o->blocksize
            && ioctl_retry (dev_fd, LOOP_SET_BLOCK_SIZE, (void *) (uintptr_t) o->blocksize) < 0) {
            errsv = errno;
            goto fail;
        }
        if (ioctl_retry (dev_fd, LOOP_SET_STATUS64, &cfg.info) < 0) {
            errsv = errno;
            goto fail;
        }
    }
    close (file_fd);
    lc->info_state = 0;
    return 0;

fail:
    close (file_fd);
    /* Clear only an association this call made; a busy device is someone
       else's. A failing rollback is not reported, as in util-linux. */
    if (bound && errsv != EBUSY)
        ioctl (dev_fd, LOOP_CLR_FD, 0);
    errno = errsv;
    return -1;
}

/* LOOP_CTL_ADD for a named device that does not exist yet; 1 on success. */
static int
add_device (bl_lc *lc)
{
    const char *p = strrchr (lc->device, '/');
    int nr = -1, rc = -1;
    if (!p || (sscanf (p, "/loop%d", &nr) != 1 && sscanf (p, "/%d", &nr) != 1) || nr < 0)
        return 0;
    int ctl = open ("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl >= 0) {
        rc = ioctl (ctl, LOOP_CTL_ADD, nr);
        close (ctl);
    }
    return rc >= 0;
}

/* -L: 2 for an identical association of FILE (left selected in LC),
   1 for an overlapping one, else 0. */
static int
find_overlap (bl_lc *lc, const char *file, const bl_setup_opts *o)
{
    bl_names v = { 0 };
    struct stat st;
    int rc = 0;
    if (stat (file, &st) != 0)
        return 0;
    uint64_t lim = o->set_sizelimit ? o->sizelimit : 0;
    uint64_t start = o->set_offset ? o->offset : 0;
    uint64_t end = lim ? start + lim
                       : (st.st_size > (off_t) start ? (uint64_t) st.st_size : start);
    used_candidates (&v);
    for (size_t i = 0; i < v.n && !rc; i++) {
        uint64_t off = 0, sz = 0;
        if (used_select (lc, v.names[i]) < 0 || !lc_backed_by (lc, &st, file, 0, 0))
            continue;
        if (lc_offset (lc, &off) < 0 || lc_sizelimit (lc, &sz) < 0)
            continue;
        uint64_t oend = sz ? off + sz : (uint64_t) st.st_size;
        if (off == start && sz == lim)
            rc = 2;
        else if (start < oend && off < end)
            rc = 1;
    }
    names_free (&v);
    if (rc != 2)
        lc_reset (lc);
    return rc;
}

static void
warn_size (const char *file, uint64_t size, uint64_t offset, int set_offset)
{
    struct stat st;
    if (!size) {
        if (stat (file, &st) || S_ISBLK (st.st_mode))
            return;
        size = (uint64_t) st.st_size;
        if (set_offset)
            size -= offset;
    }
    if (size < 512)
        builtin_error ("%s: Warning: file is smaller than 512 bytes; the loop device "
                       "may be useless or invisible for system tools.", file);
    else if (size % 512)
        builtin_error ("%s: Warning: file does not end on a 512-byte sector boundary; "
                       "the remaining end of the file will be ignored.", file);
}

static int
create_loop (bl_lc *lc, int hasdev, int nooverlap, const char *file, const bl_setup_opts *o)
{
    int control_ok = 0, opened = 0;

    if (!hasdev && nooverlap) {
        switch (find_overlap (lc, file, o)) {
        case 0:
            break;
        case 1:
            builtin_error ("%s: overlapping loop device exists", file);
            return -1;
        default: {
            struct loop_info64 *lo = lc_info (lc);
            if (lc_flag (lc, "ro", LO_FLAGS_READ_ONLY) && !(o->lo_flags & LO_FLAGS_READ_ONLY)) {
                builtin_error ("%s: overlapping read-only loop device exists", file);
                return -1;
            }
            if (lo && lo->lo_encrypt_type) {
                builtin_error ("%s: overlapping encrypted loop device exists", file);
                return -1;
            }
            if (lo) {
                lo->lo_flags &= ~LO_FLAGS_AUTOCLEAR;
                if (ioctl_retry (lc_fd (lc), LOOP_SET_STATUS64, lo) == 0)
                    return 0;
            }
            builtin_error ("%s: failed to re-use loop device", file);
            return -1;
        }
        }
    }
    if (hasdev && !bl_is_loopdev (lc->device))
        control_ok = add_device (lc);
    for (int ntries = 0;; ntries++) {
        if (!hasdev && find_unused (lc, &control_ok) < 0) {
            builtin_error ("cannot find an unused loop device");
            return -1;
        }
        if (setup_device (lc, file, o, control_ok, &opened) == 0)
            return 0;
        if ((errno == EBUSY || errno == EAGAIN) && !hasdev && ntries < 64) {
            struct timespec ts = { 0, 200000000 };
            nanosleep (&ts, NULL);
            continue;
        }
        int e = errno;
        builtin_error ("%s: failed to set up loop device: %s",
                       hasdev && !opened ? lc->device : file, strerror (e));
        return -1;
    }
}

static int
delete_loop (bl_lc *lc)
{
    int fd = lc_fd (lc);
    if (fd >= 0 && ioctl (fd, LOOP_CLR_FD, 0) == 0)
        return 0;
    builtin_error ("%s: detach failed: %s", lc->device, strerror (errno));
    return -1;
}

static int
lc_simple_ioctl (bl_lc *lc, unsigned long req, unsigned long arg)
{
    int fd = lc_fd (lc);
    if (fd < 0)
        return -1;
    return ioctl_retry (fd, req, (void *) (uintptr_t) arg);
}

/* ------------------------------------------------------------------ */
/* command line                                                       */

static void
try_help (void)
{
    fprintf (stderr, "Try 'losetup --help' for more information.\n");
}

/* util-linux err_exclusive_options(): 1 when C conflicts with an earlier option. */
static int
check_exclusive (int c, int *status)
{
    for (int e = 0; e < BL_NEXCL; e++)
        for (const int *op = bl_excl[e]; *op; op++) {
            if (*op != c)
                continue;
            if (!status[e])
                status[e] = c;
            else if (status[e] != c) {
                char msg[512];
                size_t len = 0;
                msg[0] = '\0';
                for (const int *p = bl_excl[e]; *p && len < sizeof msg; p++) {
                    const struct option *lo = bl_longopts;
                    while (lo->name && lo->val != *p)
                        lo++;
                    if (lo->name)
                        len += snprintf (msg + len, sizeof msg - len, " --%s", lo->name);
                    else
                        len += snprintf (msg + len, sizeof msg - len, " -%c", *p);
                }
                builtin_error ("mutually exclusive arguments:%s", msg);
                return 1;
            }
            break;
        }
    return 0;
}

/* -O list; "+" appends to the columns already chosen. */
static int
parse_columns (const char *arg, bl_table *t)
{
    const char *p = arg;
    if (*p == '+')
        p++;
    else
        t->ncols = 0;
    if (!*p)
        return -1;
    for (;;) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen (p);
        int id = -1;
        if (!len)
            return -1;
        for (int i = 0; i < C_COUNT; i++)
            if (strlen (bl_cols[i].name) == len && !strncasecmp (bl_cols[i].name, p, len))
                id = i;
        if (id < 0) {
            builtin_error ("unknown column: %.*s", (int) len, p);
            return -1;
        }
        if (t->ncols >= BL_MAXCOLS)
            return -1;
        t->cols[t->ncols++] = id;
        if (!comma)
            return 0;
        p = comma + 1;
    }
}

enum { A_NONE, A_CREATE, A_DELETE, A_DELETE_ALL, A_FIND_FREE, A_SHOW, A_SHOW_ONE,
       A_SET_CAPACITY, A_SET_DIRECT_IO, A_SET_BLOCKSIZE };

static int
losetup_run (WORD_LIST *list)
{
    bl_lc lc;
    bl_table tb;
    bl_setup_opts so;
    int act = A_NONE, list_mode = 0, showdev = 0, nooverlap = 0;
    int set_dio = 0, use_dio = 0, set_blocksize = 0, output_all = 0;
    int excl_status[BL_NEXCL] = { 0 };
    const char *file = NULL, *outarg = NULL;
    int res = 0, fail = 0, done = 0;

    memset (&tb, 0, sizeof tb);
    memset (&so, 0, sizeof so);
    lc.fd = -1;
    lc_reset (&lc);

    int argc = 1;
    for (WORD_LIST *w = list; w; w = w->next)
        argc++;
    char **argv = xmalloc (((size_t) argc + 1) * sizeof *argv);
    argv[0] = (char *) "losetup";
    {
        int i = 1;
        for (WORD_LIST *w = list; w; w = w->next)
            argv[i++] = w->word->word;
        argv[i] = NULL;
    }

    /* libc getopt state is shared with bash and sibling loadables. */
    int save_optind = optind, save_opterr = opterr, save_optopt = optopt;
    char *save_optarg = optarg;
    optind = 0;
    opterr = 1;

    int c;
    while (!fail && !done
           && (c = getopt_long (argc, argv, "ab:c:d:Dfhj:JlLno:O:PrvV", bl_longopts, NULL)) != -1) {
        int r;
        if (check_exclusive (c, excl_status)) {
            fail = 1;
            break;
        }
        switch (c) {
        case 'a':
            act = A_SHOW;
            break;
        case 'b':
            set_blocksize = 1;
            if ((r = bl_parse_size (optarg, &so.blocksize)) < 0) {
                builtin_error ("failed to parse logical block size: '%s': %s", optarg, strerror (-r));
                fail = 1;
            }
            break;
        case 'c':
            act = A_SET_CAPACITY;
            lc_set (&lc, optarg);
            break;
        case 'r':
            so.lo_flags |= LO_FLAGS_READ_ONLY;
            break;
        case 'd':
            act = A_DELETE;
            lc_set (&lc, optarg);
            break;
        case 'D':
            act = A_DELETE_ALL;
            break;
        case 'f':
            act = A_FIND_FREE;
            break;
        case 'J':
            tb.json = 1;
            break;
        case 'j':
            act = A_SHOW;
            file = optarg;
            break;
        case 'l':
            list_mode = 1;
            break;
        case 'L':
            nooverlap = 1;
            break;
        case 'n':
            tb.noheadings = 1;
            break;
        case OPT_RAW:
            tb.raw = 1;
            break;
        case 'o':
            if ((r = bl_parse_size (optarg, &so.offset)) < 0) {
                builtin_error ("failed to parse offset: '%s': %s", optarg, strerror (-r));
                fail = 1;
            }
            so.set_offset = 1;
            break;
        case 'O':
            outarg = optarg;
            list_mode = 1;
            break;
        case OPT_OUTPUT_ALL:
            list_mode = 1;
            output_all = 1;
            break;
        case 'P':
            so.lo_flags |= LO_FLAGS_PARTSCAN;
            break;
        case OPT_REF:
            so.refname = optarg;
            break;
        case OPT_SHOW:
            showdev = 1;
            break;
        case OPT_DIO:
            use_dio = set_dio = 1;
            if (optarg) {
                if (!strcmp (optarg, "on"))
                    use_dio = 1;
                else if (!strcmp (optarg, "off"))
                    use_dio = 0;
                else {
                    builtin_error ("argument error: '%s'", optarg);
                    fail = 1;
                }
            }
            break;
        case 'v':
            break;
        case OPT_SIZELIMIT:
            if ((r = bl_parse_size (optarg, &so.sizelimit)) < 0) {
                builtin_error ("failed to parse size: '%s': %s", optarg, strerror (-r));
                fail = 1;
            }
            so.set_sizelimit = 1;
            break;
        case 'h': {
            extern char *losetup_doc[];
            for (char **lp = losetup_doc; *lp; lp++)
                puts (*lp);
            done = 1;
            break;
        }
        case 'V':
            puts ("losetup (bash-os loadable)");
            done = 1;
            break;
        default:
            try_help ();
            fail = 1;
        }
    }
    int ai = optind;
    optind = save_optind;
    opterr = save_opterr;
    optopt = save_optopt;
    optarg = save_optarg;
    if (fail || done)
        goto out;

    /* "losetup" alone, or with only --json/--raw, is --list --all. */
    if (argc == 1 || (argc == 2 && (tb.json || tb.raw))) {
        act = A_SHOW;
        list_mode = 1;
    }
    if (act == A_FIND_FREE && ai < argc) {
        act = A_CREATE;
        file = argv[ai++];
        if (ai < argc) {
            builtin_error ("unexpected arguments");
            fail = 1;
            goto out;
        }
    }
    if (list_mode && act == A_NONE && ai == argc)
        act = A_SHOW;
    if (act == A_NONE && ai + 1 == argc) {
        act = set_dio ? A_SET_DIRECT_IO : set_blocksize ? A_SET_BLOCKSIZE : A_SHOW_ONE;
        lc_set (&lc, argv[ai++]);
    }
    if (act == A_NONE) {
        act = A_CREATE;
        if (ai >= argc) {
            builtin_error ("no loop device specified");
            fail = 1;
            goto out;
        }
        lc_set (&lc, argv[ai++]);
        if (ai >= argc) {
            builtin_error ("no file specified");
            fail = 1;
            goto out;
        }
        file = argv[ai++];
    }
    if (act != A_CREATE && (so.sizelimit || so.lo_flags || showdev)) {
        builtin_error ("the options %s are allowed during loop device setup only",
                       "--{sizelimit,partscan,read-only,show}");
        fail = 1;
        goto out;
    }
    if (so.set_offset && act != A_CREATE && (act != A_SHOW || !file)) {
        builtin_error ("the option --offset is not allowed in this context");
        fail = 1;
        goto out;
    }
    if (output_all) {
        for (int i = 0; i < C_COUNT; i++)
            tb.cols[i] = i;
        tb.ncols = C_COUNT;
    } else if (list_mode && (!outarg || *outarg == '+')) {
        static const int defaults[] = { C_NAME, C_SIZELIMIT, C_OFFSET, C_AUTOCLR, C_RO,
                                        C_BACK_FILE, C_DIO, C_LOGSEC };
        for (size_t i = 0; i < sizeof defaults / sizeof defaults[0]; i++)
            tb.cols[i] = defaults[i];
        tb.ncols = (int) (sizeof defaults / sizeof defaults[0]);
    }
    if (outarg && parse_columns (outarg, &tb) < 0) {
        fail = 1;
        goto out;
    }

    switch (act) {
    case A_CREATE:
        res = create_loop (&lc, lc.device[0] != '\0', nooverlap, file, &so);
        if (res == 0) {
            if (showdev)
                printf ("%s\n", lc.device);
            warn_size (file, so.sizelimit, so.offset, so.set_offset);
            if (set_dio && lc_simple_ioctl (&lc, LOOP_SET_DIRECT_IO, (unsigned long) use_dio) < 0) {
                builtin_error ("%s: set direct io failed: %s", lc.device, strerror (errno));
                res = -1;
            }
        }
        break;
    case A_DELETE:
        res = delete_loop (&lc);
        while (ai < argc) {
            lc_set (&lc, argv[ai++]);
            res += delete_loop (&lc);
        }
        break;
    case A_DELETE_ALL: {
        bl_names v = { 0 };
        used_candidates (&v);
        for (size_t i = 0; i < v.n; i++)
            if (used_select (&lc, v.names[i]) == 0)
                res += delete_loop (&lc);
        names_free (&v);
        break;
    }
    case A_FIND_FREE: {
        int control_ok;
        if (find_unused (&lc, &control_ok) < 0) {
            int errsv = errno;
            if (!(access ("/dev/loop-control", F_OK) == 0 && access ("/dev/loop-control", W_OK) != 0))
                errno = errsv;
            builtin_error ("cannot find an unused loop device: %s", strerror (errno));
            res = -1;
        } else
            printf ("%s%s\n", lc.device, lc_is_lost (&lc) ? " (lost)" : "");
        break;
    }
    case A_SHOW:
        show_used (list_mode ? &tb : NULL, file, so.offset, so.set_offset);
        if (list_mode)
            table_print (&tb);
        break;
    case A_SHOW_ONE:
        if (list_mode) {
            table_add (&tb, &lc);
            table_print (&tb);
        } else if (print_loopdev (&lc) < 0) {
            builtin_error ("%s: %s", lc.device, strerror (errno));
            res = -1;
        }
        break;
    case A_SET_CAPACITY:
        if (lc_simple_ioctl (&lc, LOOP_SET_CAPACITY, 0) < 0) {
            builtin_error ("%s: set capacity failed: %s", lc.device, strerror (errno));
            res = -1;
        }
        break;
    case A_SET_DIRECT_IO:
        if (lc_simple_ioctl (&lc, LOOP_SET_DIRECT_IO, (unsigned long) use_dio) < 0) {
            builtin_error ("%s: set direct io failed: %s", lc.device, strerror (errno));
            res = -1;
        }
        break;
    case A_SET_BLOCKSIZE:
        if (lc_simple_ioctl (&lc, LOOP_SET_BLOCK_SIZE, (unsigned long) so.blocksize) < 0) {
            builtin_error ("%s: set logical block size failed: %s", lc.device, strerror (errno));
            res = -1;
        }
        break;
    }
    if (res)
        fail = 1;
out:
    table_free (&tb);
    lc_reset (&lc);
    free (argv);
    return fail ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
losetup_builtin (WORD_LIST *list)
{
    /* stdio error indicators survive calls in the same shell. */
    clearerr (stdout);
    int rc = losetup_run (list);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return rc;
}

char *losetup_doc[] = {
    "Set up and control loop devices.",
    "",
    "    losetup [-l|-a] [-n] [-O COLS|--output-all] [--raw|-J]   list used loops",
    "    losetup [-l] LOOPDEV                   show one loop device",
    "    losetup -j FILE [-o OFF]               list loops backed by FILE",
    "    losetup -f                             print the first free loop device",
    "    losetup [-r] [-P] [-o N] [--sizelimit N] [-b N] [--show] -f|LOOPDEV FILE",
    "    losetup -d LOOPDEV...  |  losetup -D   detach",
    "    losetup -c LOOPDEV                     refresh the device size",
    "",
    "Columns: NAME AUTOCLEAR BACK-FILE BACK-INO BACK-MAJ:MIN BACK-MAJ BACK-MIN",
    "MAJ:MIN MAJ MIN OFFSET PARTSCAN REF RO SIZELIMIT DIO LOG-SEC.",
    "Attach/detach require suitable permissions.",
    (char *) NULL
};

struct builtin losetup_struct = {
    "losetup",
    losetup_builtin,
    BUILTIN_ENABLED,
    losetup_doc,
    "losetup [-adDfjlLnOPrv] [-o N] [--sizelimit N] [--show] [loopdev] [file]",
    0
};
