/* Injected directory identity for sed -i.
   BS_INPLACE_PARENT is the absolute directory, BS_INPLACE_FILE its final
   component, and BS_INPLACE_MODE is rename-parent or swap-entry.
   rename-parent moves the directory aside after it is opened and leaves a
   decoy behind. swap-entry replaces the directory entry after the file is
   opened. Both run once. Other paths call through. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int (*real_open) (const char *, int, ...);
static int (*real_open64) (const char *, int, ...);
static int (*real_openat) (int, const char *, int, ...);
static int (*real_openat64) (int, const char *, int, ...);
static int (*real_rename) (const char *, const char *);
static int in_init;

static int raw_openat (int fd, const char *path, int flags, mode_t mode)
{
    return (int) syscall (SYS_openat, fd, path, flags, mode);
}

static void init (void)
{
    if (real_openat || in_init) return;
    in_init = 1;
    real_open = dlsym (RTLD_NEXT, "open");
    real_open64 = dlsym (RTLD_NEXT, "open64");
    real_openat = dlsym (RTLD_NEXT, "openat");
    real_openat64 = dlsym (RTLD_NEXT, "openat64");
    real_rename = dlsym (RTLD_NEXT, "rename");
    in_init = 0;
}

static int armed (void)
{
    return !in_init && getenv ("BS_INPLACE_PARENT") && getenv ("BS_INPLACE_FILE")
        && getenv ("BS_INPLACE_MODE");
}

static void rewrite (const char *full, const char *bytes, size_t n)
{
    init ();
    int fd = real_open (full, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) { ssize_t w = write (fd, bytes, n); (void) w; close (fd); }
}

static void attack (int dirfd, const char *path)
{
    if (!armed () || !path) return;
    const char *parent = getenv ("BS_INPLACE_PARENT");
    const char *file = getenv ("BS_INPLACE_FILE");
    const char *mode = getenv ("BS_INPLACE_MODE");
    const char *base = strrchr (parent, '/');
    base = base ? base + 1 : parent;
    static int done;
    if (done) return;

    int parent_open = strcmp (path, parent) == 0 || strcmp (path, base) == 0;
    char full[4096];
    int nw = snprintf (full, sizeof full, "%s/%s", parent, file);
    if (nw < 0 || (size_t) nw >= sizeof full) return;
    int file_open = strcmp (path, full) == 0 || strcmp (path, file) == 0;
    if (file_open && path[0] != '/' && dirfd != AT_FDCWD) {
        char link[64], got[4096];
        snprintf (link, sizeof link, "/proc/self/fd/%d", dirfd);
        ssize_t n = readlink (link, got, sizeof got - 1);
        if (n < 0) return;
        got[n] = 0;
        if (strcmp (got, parent) != 0) file_open = 0;
    }
    if (!parent_open && !file_open) return;
    if (!strcmp (mode, "rename-parent") && (parent_open || file_open)) {
        done = 1;
        char moved[4096];
        snprintf (moved, sizeof moved, "%s.moved", parent);
        init ();
        if (real_rename (parent, moved) != 0) return;
        mkdir (parent, 0755);
        rewrite (full, "DECOY\n", 6);
    } else if (!strcmp (mode, "swap-entry") && file_open) {
        done = 1;
        unlink (full);
        rewrite (full, "SAFE\n", 5);
    }
}

static int call_open (int (*fn) (const char *, int, ...), const char *path, int flags, mode_t mode)
{
    if (!fn) { init (); }
    int fd = fn ? fn (path, flags, mode) : raw_openat (AT_FDCWD, path, flags, mode);
    if (fd >= 0) attack (AT_FDCWD, path);
    return fd;
}

static int call_openat (int (*fn) (int, const char *, int, ...), int dirfd, const char *path,
                        int flags, mode_t mode)
{
    if (!fn) init ();
    int fd = fn ? fn (dirfd, path, flags, mode) : raw_openat (dirfd, path, flags, mode);
    if (fd >= 0) attack (dirfd, path);
    return fd;
}

int open (const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start (ap, flags); mode = va_arg (ap, mode_t); va_end (ap); }
    init ();
    if (in_init) return raw_openat (AT_FDCWD, path, flags, mode);
    return call_open (real_open, path, flags, mode);
}

int open64 (const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start (ap, flags); mode = va_arg (ap, mode_t); va_end (ap); }
    init ();
    if (in_init) return raw_openat (AT_FDCWD, path, flags, mode);
    return call_open (real_open64 ? real_open64 : real_open, path, flags, mode);
}

int openat (int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start (ap, flags); mode = va_arg (ap, mode_t); va_end (ap); }
    init ();
    if (in_init) return raw_openat (dirfd, path, flags, mode);
    return call_openat (real_openat, dirfd, path, flags, mode);
}

int openat64 (int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start (ap, flags); mode = va_arg (ap, mode_t); va_end (ap); }
    init ();
    if (in_init) return raw_openat (dirfd, path, flags, mode);
    return call_openat (real_openat64 ? real_openat64 : real_openat, dirfd, path, flags, mode);
}
