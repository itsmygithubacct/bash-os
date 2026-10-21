/* SPDX-License-Identifier: MIT */
/* Test-only proc adapter and fail-closed signal sink. There is deliberately
   no path to the real kill syscall. Native tests preload this; the sanitizer
   harness substitutes only these three production calls at compile time. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
sol_path(const char *path, char buffer[PATH_MAX])
{
    const char *root = getenv("SOL_PKILL_PROC_ROOT");
    if (root && (!strcmp(path, "/proc") || !strncmp(path, "/proc/", 6))) {
        int n = snprintf(buffer, PATH_MAX, "%s%s", root, path + 5);
        if (n < 0 || n >= PATH_MAX) abort();
        return buffer;
    }
    return path;
}

#ifdef SOL_PKILL_LINKED
#define SOL_OPEN sol_open
#define SOL_OPENDIR sol_opendir
#define SOL_KILL sol_kill
#else
#define SOL_OPEN open
#define SOL_OPENDIR opendir
#define SOL_KILL kill
#endif

int SOL_OPEN(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    char buffer[PATH_MAX];
#ifdef SOL_PKILL_LINKED
    return open(sol_path(path, buffer), flags, mode);
#else
    static int (*real_open)(const char *, int, ...);
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    return real_open(sol_path(path, buffer), flags, mode);
#endif
}

#ifndef SOL_PKILL_LINKED
/* Bash configurations using large-file entry points must read the same tree. */
extern __typeof(open) open64 __attribute__((alias("open")));
#endif

DIR *SOL_OPENDIR(const char *path)
{
    char buffer[PATH_MAX];
#ifdef SOL_PKILL_LINKED
    return opendir(sol_path(path, buffer));
#else
    static DIR *(*real_opendir)(const char *);
    if (!real_opendir) real_opendir = dlsym(RTLD_NEXT, "opendir");
    return real_opendir(sol_path(path, buffer));
#endif
}

int SOL_KILL(pid_t pid, int sig)
{
    const char *log = getenv("SOL_PKILL_LOG");
    const char *fail = getenv("SOL_PKILL_FAIL");
    /* Comma-separated PID:errno injection. Zero means successful delivery. */
    int error = 0;
    while (fail && *fail) {
        long fail_pid;
        int fail_errno;
        if (sscanf(fail, "%ld:%d", &fail_pid, &fail_errno) != 2) abort();
        if (fail_pid == pid) error = fail_errno;
        fail = strchr(fail, ',');
        if (fail) fail++;
    }
    if (!log || pid <= 0 || sig < 0 || sig >= NSIG) abort();
    FILE *out = fopen(log, "a");
    if (!out) abort();
    if (fprintf(out, "%ld %d %d\n", (long)pid, sig, error) < 0) abort();
    if (fclose(out)) abort();
    errno = error;
    return error ? -1 : 0;
}
