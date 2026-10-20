/* SPDX-License-Identifier: MIT
 * LD_PRELOAD interposer for the fstrim oracle: every FITRIM request is
 * answered here and never reaches the kernel. Other ioctls pass through.
 *
 * OPUS_FSTRIM_PLAN  "NAME=len:N;NAME=err:E;..." keyed by the basename of the
 *                   descriptor's path; unlisted targets get ENOTTY.
 * OPUS_FSTRIM_LOG   file receiving "FITRIM NAME start len minlen" records.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

static void
record (const char *fmt, ...)
{
    const char *log = getenv ("OPUS_FSTRIM_LOG");
    if (!log)
        return;
    int fd = open (log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    char buf[1024];
    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (buf, sizeof buf, fmt, ap);
    va_end (ap);
    if (n > 0)
        (void) !write (fd, buf, (size_t) n < sizeof buf ? (size_t) n : sizeof buf - 1);
    close (fd);
}

static int
answer (int fd, struct fstrim_range *r)
{
    char link[64], path[4096];
    snprintf (link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink (link, path, sizeof path - 1);
    if (n < 0)
        n = 0;
    path[n] = '\0';
    const char *name = strrchr (path, '/');
    name = name ? name + 1 : path;
    record ("FITRIM %s %llu %llu %llu\n", name, (unsigned long long) r->start,
            (unsigned long long) r->len, (unsigned long long) r->minlen);

    const char *plan = getenv ("OPUS_FSTRIM_PLAN");
    size_t nl = strlen (name);
    for (const char *p = plan; p && *p;) {
        const char *e = strchr (p, ';');
        size_t l = e ? (size_t) (e - p) : strlen (p);
        if (l > nl + 1 && !strncmp (p, name, nl) && p[nl] == '=') {
            const char *v = p + nl + 1;
            if (!strncmp (v, "len:", 4)) {
                r->len = strtoull (v + 4, NULL, 10);
                return 0;
            }
            if (!strncmp (v, "err:", 4)) {
                errno = atoi (v + 4);
                return -1;
            }
        }
        p = e ? e + 1 : NULL;
    }
    errno = ENOTTY;
    return -1;
}

int
ioctl (int fd, unsigned long request, ...)
{
    va_list ap;
    va_start (ap, request);
    void *arg = va_arg (ap, void *);
    va_end (ap);
    if (request == FITRIM)
        return answer (fd, arg);
    static int (*next) (int, unsigned long, ...);
    if (!next)
        next = (int (*) (int, unsigned long, ...)) dlsym (RTLD_NEXT, "ioctl");
    if (!next) {
        errno = ENOSYS;
        return -1;
    }
    return next (fd, request, arg);
}
