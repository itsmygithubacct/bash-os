/* SPDX-License-Identifier: MIT
 * Compile the actual loadable with a closed syscall boundary. No shim function
 * opens a path or calls a device ioctl, even for unrecognized operands.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include "loadables.h"

static int fixture_open (const char *, int, ...);
static int fixture_ioctl (int, unsigned long, ...);
static int fixture_close (int);
#define open fixture_open
#define ioctl fixture_ioctl
#define close fixture_close
#ifndef BLOCKDEV_SOURCE
#define BLOCKDEV_SOURCE "../loadables/blockdev.c"
#endif
#include BLOCKDEV_SOURCE
#undef open
#undef ioctl
#undef close

struct device {
    char name[128];
    uint64_t bytes;
    unsigned long sectors;
    int ss, bsz, ro, active;
};
static struct device devices[8];
static int count, opens, closes, calls, live, bad, quiet;
static int fail_open, fail_close, fail_errno;
static char fail_request[32], fail_device[128];
static char fixture_trace[65536];
static size_t used;

static void event (const char *format, ...)
{
    if (quiet) return;
    va_list ap;
    va_start (ap, format);
    int n = vsnprintf (fixture_trace + used, sizeof fixture_trace - used, format, ap);
    va_end (ap);
    if (n < 0 || (size_t)n >= sizeof fixture_trace - used) { bad++; return; }
    used += n;
}

static const char *request_name (unsigned long r)
{
    switch (r) {
    case BLKGETSIZE64: return "BLKGETSIZE64";
    case BLKGETSIZE: return "BLKGETSIZE";
    case BLKSSZGET: return "BLKSSZGET";
    case BLKBSZGET: return "BLKBSZGET";
    case BLKROGET: return "BLKROGET";
    case BLKROSET: return "BLKROSET";
    case BLKFLSBUF: return "BLKFLSBUF";
    case BLKRRPART: return "BLKRRPART";
    default: return "UNKNOWN";
    }
}

static int fixture_open (const char *name, int flags, ...)
{
    opens++;
    event ("open %s %s\n", name, (flags & O_ACCMODE) == O_RDWR ? "rw" : "ro");
    /* Baseline lacks CLOEXEC; the Python suite separately checks the fix. */
    if (flags & ~(O_ACCMODE | O_CLOEXEC)) bad++;
    if (!strcmp (name, fail_device) && fail_open &&
        (fail_open != EACCES || (flags & O_ACCMODE) != O_RDWR)) {
        errno = fail_open; return -1;
    }
    for (int i = 0; i < count; i++) if (!strcmp (name, devices[i].name)) {
        if (devices[i].active) { bad++; errno = EMFILE; return -1; }
        devices[i].active = 1; live++; return 100 + i;
    }
    errno = ENOENT; return -1;
}

static int fixture_ioctl (int fd, unsigned long request, ...)
{
    calls++;
    if (fd < 100 || fd >= 100 + count || !devices[fd-100].active) {
        bad++; errno = EBADF; return -1;
    }
    struct device *d = &devices[fd-100];
    va_list ap;
    va_start (ap, request);
    /* Pointer requests and no-argument requests have different vararg types. */
    void *arg = NULL;
    if (request == BLKFLSBUF || request == BLKRRPART) {
        if (va_arg (ap, int) != 0) bad++;
    } else arg = va_arg (ap, void *);
    va_end (ap);
    event ("ioctl %s %s", d->name, request_name (request));
    if (request == BLKROSET && arg) event (" %d", *(int *)arg);
    event ("\n");
    if (!strcmp (d->name, fail_device) && !strcmp (request_name (request), fail_request)) {
        errno = fail_errno; return -1;
    }
    switch (request) {
    case BLKGETSIZE64: *(uint64_t *)arg = d->bytes; break;
    case BLKGETSIZE: *(unsigned long *)arg = d->sectors; break;
    case BLKSSZGET: *(int *)arg = d->ss; break;
    case BLKBSZGET: *(int *)arg = d->bsz; break;
    case BLKROGET: *(int *)arg = d->ro; break;
    case BLKROSET:
        if (*(int *)arg != 0 && *(int *)arg != 1) bad++;
        d->ro = *(int *)arg; break;
    case BLKFLSBUF: case BLKRRPART: break;
    default: bad++; errno = EINVAL; return -1;
    }
    return 0;
}

static int fixture_close (int fd)
{
    closes++;
    if (fd < 100 || fd >= 100 + count || !devices[fd-100].active) {
        bad++; errno = EBADF; return -1;
    }
    struct device *d = &devices[fd-100];
    event ("close %s\n", d->name);
    d->active = 0; live--;
    if (fail_close && !strcmp (d->name, fail_device)) { errno = EIO; return -1; }
    return 0;
}

int blockdev_fixture_builtin (WORD_LIST *list)
{
    const char *args[10]; int n = 0;
    for (; list && n < 10; list = list->next) args[n++] = list->word->word;
    if (list || !n) return 2;
    if (!strcmp (args[0], "reset") && n == 1) {
        memset (devices, 0, sizeof devices);
        count = opens = closes = calls = live = bad = quiet = 0;
        fail_open = fail_close = fail_errno = 0;
        fail_request[0] = fail_device[0] = 0;
        used = 0; fixture_trace[0] = 0;
    } else if (!strcmp (args[0], "device") && n == 8 && count < 8) {
        struct device *d = &devices[count++];
        snprintf (d->name, sizeof d->name, "%s", args[1]);
        d->bytes = strtoull (args[2], NULL, 10);
        d->sectors = strtoul (args[3], NULL, 10);
        d->ss = atoi (args[4]); d->bsz = atoi (args[5]); d->ro = atoi (args[6]);
        /* An explicit eighth argument confirms the metadata format version. */
        if (strcmp (args[7], "v1")) return 2;
    } else if (!strcmp (args[0], "fail") && n == 4) {
        snprintf (fail_device, sizeof fail_device, "%s", args[1]);
        fail_errno = atoi (args[3]);
        if (!strcmp (args[2], "open")) fail_open = fail_errno;
        else if (!strcmp (args[2], "close")) fail_close = 1;
        else snprintf (fail_request, sizeof fail_request, "%s", args[2]);
    } else if (!strcmp (args[0], "quiet") && n == 1) quiet = 1;
    else if (!strcmp (args[0], "trace") && n == 1) {
        if (live || bad) return 96;
        fputs (fixture_trace, stdout);
    }
    else if (!strcmp (args[0], "stats") && n == 1) {
        printf ("stats %d %d %d %d %d\n", opens, closes, calls, live, bad);
        for (int i = 0; i < count; i++) printf ("ro %s %d\n", devices[i].name, devices[i].ro);
    } else return 2;
    return 0;
}
static char *fixture_doc[] = { "Private blockdev syscall fixture control.", NULL };
struct builtin blockdev_fixture_struct = {
    "blockdev_fixture", blockdev_fixture_builtin, BUILTIN_ENABLED,
    fixture_doc, "blockdev_fixture reset|device|fail|quiet|trace|stats", 0
};
