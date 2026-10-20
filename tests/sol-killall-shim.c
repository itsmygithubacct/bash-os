/* SPDX-License-Identifier: MIT */
/* Test-only /proc redirection and fail-closed signal interception. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *redirect(const char *path, char *buf, size_t cap)
{
    const char *root = getenv("SOL_KILLALL_PROC");
    if (root && (!strcmp(path, "/proc") || !strncmp(path, "/proc/", 6))) {
        if (snprintf(buf, cap, "%s%s", root, path + 5) >= (int)cap) {
            errno = ENAMETOOLONG;
            return NULL;
        }
        return buf;
    }
    return path;
}

DIR *opendir(const char *path)
{
    char buf[8192];
    const char *p = redirect(path, buf, sizeof buf);
    DIR *(*real_fn)(const char *) = dlsym(RTLD_NEXT, "opendir");
    return p ? real_fn(p) : NULL;
}

int open(const char *path, int flags, ...)
{
    char buf[8192];
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    const char *vanish = getenv("SOL_KILLALL_VANISH");
    if (vanish && !strncmp(path, "/proc/", 6)) {
        char *end;
        long pid = strtol(path + 6, &end, 10);
        if (*end == '/' && pid == strtol(vanish, NULL, 10)) {
            errno = ENOENT;
            return -1;
        }
    }
    const char *p = redirect(path, buf, sizeof buf);
    int (*real_fn)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    return p ? real_fn(p, flags, mode) : -1;
}

/* Real forwarding requires one exact positive PID, its independently supplied
   comm, and parent/uid checks against the kernel immediately before kill. */
int kill(pid_t pid, int sig)
{
    const char *owned = getenv("SOL_KILLALL_OWNED_PID");
    int err = 0;
    unsigned long long delivery_ns = 0;
    if (owned) {
        char path[80], buf[1024], comm[64];
        FILE *fp;
        long ppid = -1, uid = -1;
        snprintf(path, sizeof path, "/proc/%d/status", pid);
        fp = fopen(path, "r");
        if (fp) {
            while (fgets(buf, sizeof buf, fp)) {
                if (!strncmp(buf, "PPid:", 5)) ppid = strtol(buf + 5, NULL, 10);
                if (!strncmp(buf, "Uid:", 4)) uid = strtol(buf + 4, NULL, 10);
            }
            fclose(fp);
        }
        snprintf(path, sizeof path, "/proc/%d/comm", pid);
        fp = fopen(path, "r");
        comm[0] = 0;
        if (fp) { if (fgets(comm, sizeof comm, fp)) comm[strcspn(comm, "\n")] = 0; fclose(fp); }
        const char *parent = getenv("SOL_KILLALL_PARENT");
        const char *name = getenv("SOL_KILLALL_OWNED_COMM");
        if (pid <= 0 || pid != strtol(owned, NULL, 10) || !parent || !name ||
            ppid != strtol(parent, NULL, 10) || uid != getuid() || strcmp(name, comm))
            err = EPERM;
        else {
            struct timespec before, after;
            clock_gettime(CLOCK_MONOTONIC, &before);
            if (syscall(SYS_kill, pid, sig) < 0) err = errno;
            clock_gettime(CLOCK_MONOTONIC, &after);
            delivery_ns = (after.tv_sec - before.tv_sec) * 1000000000ULL
                          + after.tv_nsec - before.tv_nsec;
        }
    } else {
        const char *fail = getenv("SOL_KILLALL_FAIL_PID");
        if (fail && pid == strtol(fail, NULL, 10)) {
            const char *kind = getenv("SOL_KILLALL_FAIL_ERRNO");
            err = kind ? atoi(kind) : ESRCH;
        }
    }
    const char *log = getenv("SOL_KILLALL_LOG");
    if (log) {
        int fd = syscall(SYS_openat, AT_FDCWD, log, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
        if (fd >= 0) {
            char line[128];
            int n = snprintf(line, sizeof line, "%d %d %d\n", pid, sig, err);
            if (syscall(SYS_write, fd, line, n) != n) err = EIO;
            syscall(SYS_close, fd);
        } else err = EIO;
    }
    const char *timing = getenv("SOL_KILLALL_DELIVERY_NS");
    if (timing && owned && !err) {
        int fd = syscall(SYS_openat, AT_FDCWD, timing, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
        if (fd < 0) err = EIO;
        else {
            char line[64];
            int n = snprintf(line, sizeof line, "%llu\n", delivery_ns);
            if (syscall(SYS_write, fd, line, n) != n) err = EIO;
            syscall(SYS_close, fd);
        }
    }
    if (err) { errno = err; return -1; }
    return 0;
}
