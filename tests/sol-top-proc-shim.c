/* SPDX-License-Identifier: MIT
 * Test-only proc redirection. Never linked into the production binary.
 * Every /proc lookup is redirected; mutation requests are recorded, never sent.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static unsigned sample;
static unsigned frame;
static const char *redirect(const char *path, char *buf, size_t size)
{
    const char *root = getenv("TOP_FIXTURE");
    if (!root || strncmp(path, "/proc", 5) || (path[5] && path[5] != '/'))
        return path;
    const char *mode = getenv("TOP_FIXTURE_MODE");
    if (mode && !strcmp(mode, "pair")) {
        if (!strcmp(path, "/proc/stat")) frame = sample++ % 2;
        snprintf(buf, size, "%s/%u%s", root, frame, path + 5);
    } else {
        snprintf(buf, size, "%s/current%s", root, path + 5);
    }
    return buf;
}
int open(const char *path, int flags, ...)
{
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    char buf[4096];
    return real_open(redirect(path, buf, sizeof buf), flags, mode);
}
DIR *opendir(const char *path)
{
    DIR *(*real_opendir)(const char *) = dlsym(RTLD_NEXT, "opendir");
    char buf[4096];
    return real_opendir(redirect(path, buf, sizeof buf));
}
static void record(const char *kind, int a, int b)
{
    const char *log = getenv("TOP_MUTATION_LOG");
    if (!log) _exit(99);  /* Never silently permit a mutation in these tests. */
    FILE *f = fopen(log, "a");
    if (!f) _exit(98);
    fprintf(f, "%s %d %d\n", kind, a, b);
    fclose(f);
}
int kill(pid_t pid, int sig) { record("kill", pid, sig); return 0; }
int getpriority(__priority_which_t which, id_t who)
{
    record("getpriority", which, who); errno = 0; return 5;
}
int setpriority(__priority_which_t which, id_t who, int value)
{
    (void)which; record("setpriority", who, value); return 0;
}
