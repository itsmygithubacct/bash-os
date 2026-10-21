/* SPDX-License-Identifier: MIT */
/* Injected failures for the index writer, as an LD_PRELOAD library.
 *
 * SOL_INDEX_FAULT=OP:MATCH makes one kind of call fail when the file it
 * concerns has MATCH in its path, and leaves every other call alone:
 *
 *   write:MATCH       write(2) to such a file fails with ENOSPC
 *   short:MATCH       write(2) to such a file returns 0 bytes written
 *   fdatasync:MATCH   fdatasync(2) on such a file fails with EIO
 *   close:MATCH       close(2) of such a file closes it, then fails with EIO
 *   rename:MATCH      rename(2) whose target has MATCH fails with EXDEV
 *
 * The file behind a descriptor is found through /proc/self/fd. Each call
 * made to fail appends "OP PATH" to $SOL_INDEX_FAULT_LOG, so a test can
 * tell an injected failure from one that never happened.
 */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ssize_t (*real_write) (int, const void *, size_t);
static int (*real_fdatasync) (int);
static int (*real_close) (int);
static int (*real_rename) (const char *, const char *);

static void
fault_init (void)
{
    if (real_write) return;
    real_write = (ssize_t (*) (int, const void *, size_t)) dlsym (RTLD_NEXT, "write");
    real_fdatasync = (int (*) (int)) dlsym (RTLD_NEXT, "fdatasync");
    real_close = (int (*) (int)) dlsym (RTLD_NEXT, "close");
    real_rename = (int (*) (const char *, const char *)) dlsym (RTLD_NEXT, "rename");
}

static int
fault_matches (const char *op, const char *path)
{
    const char *spec = getenv ("SOL_INDEX_FAULT");
    size_t oplen = strlen (op);
    if (!spec || !path || strncmp (spec, op, oplen) != 0 || spec[oplen] != ':')
        return 0;
    return strstr (path, spec + oplen + 1) != NULL;
}

static int
fault_fd_path (int fd, char *out, size_t size)
{
    char link[64];
    snprintf (link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink (link, out, size - 1);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
}

static void
fault_note (const char *op, const char *path)
{
    const char *log = getenv ("SOL_INDEX_FAULT_LOG");
    if (!log) return;
    int saved = errno;
    int fd = open (log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        char line[4200];
        int n = snprintf (line, sizeof line, "%s %s\n", op, path);
        if (n > 0) real_write (fd, line, (size_t) n < sizeof line ? (size_t) n : sizeof line - 1);
        real_close (fd);
    }
    errno = saved;
}

/* Whether a call on FD should fail as OP, noting it if so. */
static int
fault_fd (const char *op, int fd)
{
    const char *spec = getenv ("SOL_INDEX_FAULT");
    char path[4096];
    if (!spec || strncmp (spec, op, strlen (op)) != 0) return 0;
    if (fault_fd_path (fd, path, sizeof path) < 0 || !fault_matches (op, path))
        return 0;
    fault_note (op, path);
    return 1;
}

ssize_t
write (int fd, const void *buf, size_t n)
{
    fault_init ();
    if (fault_fd ("write", fd)) { errno = ENOSPC; return -1; }
    if (fault_fd ("short", fd)) return 0;
    return real_write (fd, buf, n);
}

int
fdatasync (int fd)
{
    fault_init ();
    if (fault_fd ("fdatasync", fd)) { errno = EIO; return -1; }
    return real_fdatasync (fd);
}

int
close (int fd)
{
    fault_init ();
    if (fault_fd ("close", fd)) {
        real_close (fd);
        errno = EIO;
        return -1;
    }
    return real_close (fd);
}

int
rename (const char *from, const char *to)
{
    fault_init ();
    if (fault_matches ("rename", to)) {
        fault_note ("rename", to);
        errno = EXDEV;
        return -1;
    }
    return real_rename (from, to);
}
