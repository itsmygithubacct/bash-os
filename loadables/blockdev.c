/* SPDX-License-Identifier: MIT */
/* blockdev.c — call block-device ioctls, as a bash builtin.
 *
 *   blockdev [actions...] device [device...]
 *
 *   --getsz        size in 512-byte sectors
 *   --getsize64    size in bytes
 *   --getsize      size in 512-byte sectors (32-bit, deprecated)
 *   --getss        logical sector size (bytes)
 *   --getbsz       block size (bytes)
 *   --getro        1 if read-only, else 0
 *   --setro        set read-only
 *   --setrw        set read-write
 *   --flushbufs    flush buffers
 *   --rereadpt     re-read the partition table
 *   --report       one table row per device (every device when none is named)
 *
 * Actions are applied in order to each device argument.
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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "loadables.h"

extern char *blockdev_doc[];

#include <sys/stat.h>
#include <sys/sysmacros.h>

/* One row per action, in util-linux's terms: the ioctl it issues, the name
   that ioctl has in a diagnostic, and how its argument is passed and shown. */
enum { T_NONE, T_INT, T_UINT, T_LONG, T_ULONG, T_U64, T_SECTORS, T_BYTES, T_SETRO, T_SETRW, T_USHORT };

static const struct action {
    const char *option;
    const char *iocname;
    unsigned long request;
    int type;
} actions[] = {
    { "--getsz",        "BLKGETSIZE64", BLKGETSIZE64, T_SECTORS },
    { "--getsize64",    "BLKGETSIZE64", BLKGETSIZE64, T_BYTES },
    { "--getsize",      "BLKGETSIZE",   BLKGETSIZE,   T_ULONG },
    { "--getss",        "BLKSSZGET",    BLKSSZGET,    T_INT },
    { "--getpbsz",      "BLKPBSZGET",   BLKPBSZGET,   T_UINT },
    { "--getbsz",       "BLKBSZGET",    BLKBSZGET,    T_INT },
    { "--getro",        "BLKROGET",     BLKROGET,     T_INT },
    { "--getra",        "BLKRAGET",     BLKRAGET,     T_LONG },
    { "--getfra",       "BLKFRAGET",    BLKFRAGET,    T_LONG },
    { "--getiomin",     "BLKIOMIN",     BLKIOMIN,     T_UINT },
    { "--getioopt",     "BLKIOOPT",     BLKIOOPT,     T_UINT },
    { "--getalignoff",  "BLKALIGNOFF",  BLKALIGNOFF,  T_INT },
    { "--getmaxsect",   "BLKSECTGET",   BLKSECTGET,   T_USHORT },
    { "--getdiscardzeroes", "BLKDISCARDZEROES", BLKDISCARDZEROES, T_UINT },
    { "--setro",        "BLKROSET",     BLKROSET,     T_SETRO },
    { "--setrw",        "BLKROSET",     BLKROSET,     T_SETRW },
    { "--flushbufs",    "BLKFLSBUF",    BLKFLSBUF,    T_NONE },
    { "--rereadpt",     "BLKRRPART",    BLKRRPART,    T_NONE },
};

/* A failed ioctl is named as util-linux names it. */
static int
run_action (int fd, const struct action *act)
{
    int res;
    switch (act->type) {
        case T_SECTORS: case T_BYTES: case T_U64: {
            uint64_t v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0)
                printf ("%llu\n", (unsigned long long) (act->type == T_SECTORS ? v / 512 : v));
            break;
        }
        case T_ULONG: {
            unsigned long v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0) printf ("%lu\n", v);
            break;
        }
        case T_LONG: {
            long v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0) printf ("%ld\n", v);
            break;
        }
        case T_INT: {
            int v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0) printf ("%d\n", v);
            break;
        }
        case T_UINT: {
            unsigned int v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0) printf ("%u\n", v);
            break;
        }
        case T_USHORT: {
            unsigned short v = 0;
            if ((res = ioctl (fd, act->request, &v)) == 0) printf ("%hu\n", v);
            break;
        }
        case T_SETRO: case T_SETRW: {
            int v = act->type == T_SETRO;
            res = ioctl (fd, act->request, &v);
            break;
        }
        default:
            res = ioctl (fd, act->request, 0);
            break;
    }
    if (res < 0) {
        builtin_error ("ioctl error on %s: %s", act->iocname, strerror (errno));
        return -1;
    }
    return 0;
}

static const struct action *
find_action (const char *word)
{
    for (size_t i = 0; i < sizeof actions / sizeof actions[0]; i++)
        if (!strcmp (word, actions[i].option)) return &actions[i];
    return NULL;
}

static int
finish_output (int rc)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        clearerr (stdout);
        return EXECUTION_FAILURE;
    }
    return rc;
}

/* First sector of a partition, from sysfs; zero for a whole device. */
static unsigned long long
start_sector (int fd)
{
    struct stat st;
    char path[96], text[64];
    unsigned long long start = 0;
    if (fstat (fd, &st) < 0 || !S_ISBLK (st.st_mode)) return 0;
    snprintf (path, sizeof path, "/sys/dev/block/%u:%u/start", major (st.st_rdev), minor (st.st_rdev));
    int sfd = open (path, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return 0;
    ssize_t n = read (sfd, text, sizeof text - 1);
    close (sfd);
    if (n > 0) { text[n] = 0; start = strtoull (text, NULL, 10); }
    return start;
}

static int
blockdev_try (void)
{
    fprintf (stderr, "Try 'blockdev --help' for more information.\n");
    return EXECUTION_FAILURE;
}

static int
report_device (const char *dev, int quiet)
{
    int fd = open (dev, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (!quiet) builtin_error ("cannot open %s: %s", dev, strerror (errno));
        return quiet ? 0 : -1;
    }
    int ro = 0, ssz = 0, bsz = 0, rc = 0;
    long ra = 0;
    uint64_t bytes = 0;
    if (ioctl (fd, BLKROGET, &ro) == 0 && ioctl (fd, BLKRAGET, &ra) == 0
        && ioctl (fd, BLKSSZGET, &ssz) == 0 && ioctl (fd, BLKBSZGET, &bsz) == 0
        && ioctl (fd, BLKGETSIZE64, &bytes) == 0)
        printf ("%s %5ld %5d %5d %15llu %15lld   %s\n", ro ? "ro" : "rw", ra, ssz, bsz,
                start_sector (fd), (long long) bytes, dev);
    else if (!quiet) {
        builtin_error ("ioctl error on %s", dev);
        rc = -1;
    }
    close (fd);
    return rc;
}

static int
report (WORD_LIST *devices)
{
    int rc = EXECUTION_SUCCESS;
    puts ("RO    RA   SSZ   BSZ        StartSec            Size   Device");
    if (devices) {
        for (WORD_LIST *p = devices; p && rc == EXECUTION_SUCCESS; p = p->next)
            if (report_device (p->word->word, 0) < 0) rc = EXECUTION_FAILURE;
        return finish_output (rc);
    }
    /* No device named: every block device the kernel lists. */
    FILE *f = fopen ("/proc/partitions", "re");
    if (!f) {
        builtin_error ("cannot open %s: %s", "/proc/partitions", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[256], name[200], path[216];
    while (fgets (line, sizeof line, f)) {
        if (sscanf (line, " %*d %*d %*u %199[^\n ]", name) != 1) continue;
        snprintf (path, sizeof path, "/dev/%s", name);
        report_device (path, 1);
    }
    fclose (f);
    return finish_output (rc);
}

int
blockdev_builtin (WORD_LIST *list)
{
    WORD_LIST *first_action = list;
    size_t nact = 0;
    int want_report = 0;

    if (!list) { builtin_error ("not enough arguments"); return blockdev_try (); }
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        else if (!strcmp (w, "--help")) { for (char **lp = blockdev_doc; *lp; lp++) puts (*lp); return finish_output (EXECUTION_SUCCESS); }
        else if (!strcmp (w, "--version")) { puts ("blockdev 1.0 (bash-loadable)"); return finish_output (EXECUTION_SUCCESS); }
        else if (!strcmp (w, "--report")) { want_report = 1; list = list->next; continue; }
        else if (!find_action (w)) {
            builtin_error ("Unknown command: %s", w);
            return blockdev_try ();
        }
        nact++;
        list = list->next;
    }

    if (want_report) {
        if (nact) { builtin_error ("--report cannot be combined with other actions"); return blockdev_try (); }
        return report (list);
    }
    if (!list) { builtin_error ("no device specified"); return blockdev_try (); }

    /* The first device that cannot be opened, or the first ioctl that fails,
       ends the command, as in util-linux. */
    int rc = EXECUTION_SUCCESS, stop = 0;
    for (WORD_LIST *p = list; p && !stop; p = p->next) {
        const char *dev = p->word->word;
        int fd = open (dev, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("cannot open %s: %s", dev, strerror (errno));
            rc = EXECUTION_FAILURE;
            break;
        }
        WORD_LIST *action = first_action;
        for (size_t i = 0; i < nact; i++, action = action->next)
            if (run_action (fd, find_action (action->word->word)) < 0) {
                rc = EXECUTION_FAILURE;
                stop = 1;
                break;
            }
        if (close (fd) < 0) {
            builtin_error ("%s: close: %s", dev, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    }
    return finish_output (rc);
}

char *blockdev_doc[] = {
    "Call block-device ioctls from the command line.",
    "",
    "    blockdev [actions...] device [device...]",
    "",
    "    --getsz       size in 512-byte sectors      --getsize64  size in bytes",
    "    --getsize     size in 512-byte sectors (legacy ioctl)",
    "    --getss       logical sector size            --getbsz     block size",
    "    --getro       read-only flag (1/0)            --setro/--setrw  set ro/rw",
    "    --flushbufs   flush buffers                   --rereadpt   re-read partitions",
    "    --getra/--getfra  readahead     --getpbsz  physical block size",
    "    --getiomin/--getioopt/--getalignoff/--getmaxsect/--getdiscardzeroes",
    "    --report      table of RO RA SSZ BSZ StartSec Size Device",
    "",
    "Actions are applied in order to each device.",
    (char *) NULL
};

struct builtin blockdev_struct = {
    "blockdev",
    blockdev_builtin,
    BUILTIN_ENABLED,
    blockdev_doc,
    "blockdev [--report] [--getsz|--getsize64|--getsize|--getss|--getbsz|--getro|--setro|--setrw|--flushbufs|--rereadpt] [device...]",
    0
};
