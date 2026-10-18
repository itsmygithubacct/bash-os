/* SPDX-License-Identifier: MIT */
/* Inject one syscall failure class for one exact private fixture path.
   Real close/closedir calls still release their descriptor before failing. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static int
descriptor_path (int fd, char path[PATH_MAX])
{
    char proc[64];
    snprintf (proc, sizeof proc, "/proc/self/fd/%d", fd);
    ssize_t n = readlink (proc, path, PATH_MAX - 1);
    if (n < 0) return 0;
    path[n] = '\0';
    return 1;
}

static int
watched (int fd, const char *path)
{
    const char *target = getenv ("BASHOS_IO_FAULT_PATH");
    char resolved[PATH_MAX], parent[PATH_MAX];
    if (!target) return 0;
    if (!path || !*path)
        return descriptor_path (fd, resolved) && !strcmp (resolved, target);
    if (*path == '/') return !strcmp (path, target);
    if (fd == AT_FDCWD) {
        if (!getcwd (parent, sizeof parent)) return 0;
    } else if (!descriptor_path (fd, parent)) return 0;
    int n = snprintf (resolved, sizeof resolved, "%s/%s", parent, path);
    return n >= 0 && (size_t) n < sizeof resolved && !strcmp (resolved, target);
}

static int
inject (const char *operation, int fd, const char *path)
{
    if (!watched (fd, path)) return 0;
    const char *log = getenv ("BASHOS_IO_FAULT_LOG");
    if (log) {
        int logfd = open (log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            syscall (SYS_write, logfd, operation, strlen (operation));
            syscall (SYS_write, logfd, "\n", 1);
            syscall (SYS_close, logfd);
        }
    }
    /* Deterministically change a private source after the destination tree
       was populated, just before its final timestamp is applied. */
    const char *from = getenv ("BASHOS_IO_RENAME_FROM");
    const char *to = getenv ("BASHOS_IO_RENAME_TO");
    if (from && to && !strcmp (operation, "utimensat") && rename (from, to) < 0)
        return 1;
    const char *selected = getenv ("BASHOS_IO_FAULT");
    /* Exercise the legacy timestamp fallback's own error path. */
    if (selected && !strcmp (selected, "utimes") && !strcmp (operation, "utimensat")) {
        errno = ENOSYS;
        return 1;
    }
    if (!selected || strcmp (operation, selected)) return 0;
    static unsigned matched;
    const char *skip = getenv ("BASHOS_IO_FAULT_SKIP");
    if (skip && matched++ < strtoul (skip, NULL, 10)) return 0;
    const char *error = getenv ("BASHOS_IO_FAULT_ERRNO");
    int number = error ? atoi (error) : EIO;
    if (!number) return 0;
    errno = number;
    return 1;
}

int
close (int fd)
{
    int (*real) (int) = dlsym (RTLD_NEXT, "close");
    int fail = inject ("close", fd, NULL), error = errno;
    int result = real (fd);
    if (fail && result == 0) { errno = error; return -1; }
    return result;
}

int
closedir (DIR *dir)
{
    int (*real) (DIR *) = dlsym (RTLD_NEXT, "closedir");
    int fail = inject ("closedir", dirfd (dir), NULL), error = errno;
    int result = real (dir);
    if (fail && result == 0) { errno = error; return -1; }
    return result;
}

struct dirent *
readdir (DIR *dir)
{
    struct dirent *(*real) (DIR *) = dlsym (RTLD_NEXT, "readdir");
    if (inject ("readdir", dirfd (dir), NULL)) return NULL;
    return real (dir);
}

int
chown (const char *path, uid_t uid, gid_t gid)
{
    int (*real) (const char *, uid_t, gid_t) = dlsym (RTLD_NEXT, "chown");
    if (inject ("chown", AT_FDCWD, path)) return -1;
    return real (path, uid, gid);
}

int
lchown (const char *path, uid_t uid, gid_t gid)
{
    int (*real) (const char *, uid_t, gid_t) = dlsym (RTLD_NEXT, "lchown");
    if (inject ("lchown", AT_FDCWD, path)) return -1;
    return real (path, uid, gid);
}

int
fchown (int fd, uid_t uid, gid_t gid)
{
    int (*real) (int, uid_t, gid_t) = dlsym (RTLD_NEXT, "fchown");
    if (inject ("chown", fd, NULL)) return -1;
    return real (fd, uid, gid);
}

int
fchownat (int fd, const char *path, uid_t uid, gid_t gid, int flags)
{
    int (*real) (int, const char *, uid_t, gid_t, int) = dlsym (RTLD_NEXT, "fchownat");
    if (inject (flags & AT_SYMLINK_NOFOLLOW ? "lchown" : "chown", fd, path)) return -1;
    return real (fd, path, uid, gid, flags);
}

int
chmod (const char *path, mode_t mode)
{
    int (*real) (const char *, mode_t) = dlsym (RTLD_NEXT, "chmod");
    if (inject ("chmod", AT_FDCWD, path)) return -1;
    return real (path, mode);
}

int
fchmod (int fd, mode_t mode)
{
    int (*real) (int, mode_t) = dlsym (RTLD_NEXT, "fchmod");
    if (inject ("chmod", fd, NULL)) return -1;
    return real (fd, mode);
}

int
fchmodat (int fd, const char *path, mode_t mode, int flags)
{
    int (*real) (int, const char *, mode_t, int) = dlsym (RTLD_NEXT, "fchmodat");
    if (inject ("chmod", fd, path)) return -1;
    return real (fd, path, mode, flags);
}

int
utimensat (int fd, const char *path, const struct timespec times[2], int flags)
{
    int (*real) (int, const char *, const struct timespec *, int) = dlsym (RTLD_NEXT, "utimensat");
    if (inject ("utimensat", fd, path)) return -1;
    return real (fd, path, times, flags);
}

int
futimens (int fd, const struct timespec times[2])
{
    int (*real) (int, const struct timespec *) = dlsym (RTLD_NEXT, "futimens");
    if (inject ("utimensat", fd, NULL)) return -1;
    return real (fd, times);
}

int
utimes (const char *path, const struct timeval times[2])
{
    int (*real) (const char *, const struct timeval *) = dlsym (RTLD_NEXT, "utimes");
    if (inject ("utimes", AT_FDCWD, path)) return -1;
    return real (path, times);
}
