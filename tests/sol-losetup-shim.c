/* SPDX-License-Identifier: MIT
 * Compile the actual production implementation behind closed boundaries.
 * Every open/stat/opendir is confined to the private fixture root. Device
 * ioctls never reach the kernel, including unknown operands and requests.
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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include "loadables.h"
static int fixture_open(const char *, int, ...);
static int fixture_close(int);
static int fixture_ioctl(int, unsigned long, ...);
static int fixture_stat(const char *, struct stat *);
static DIR *fixture_opendir(const char *);
static int fixture_closedir(DIR *);
#define open fixture_open
#define close fixture_close
#define ioctl fixture_ioctl
#define stat(path, buf) fixture_stat(path, buf)
#define opendir fixture_opendir
#define closedir fixture_closedir
#include "../loadables/losetup.c"
#undef open
#undef close
#undef ioctl
#undef stat
#undef opendir
#undef closedir

#define NDEV 8
#define NFDS 4096
static char root[1024], names[NFDS][2048], fixture_trace[65536];
static int kinds[NFDS], modes[NFDS], live, dirs, bad, opens, closes, calls, quiet;
static size_t used;
struct state { int attached; struct loop_info64 info; char file[1024]; };
static struct state state[NDEV];
static int failures[8];
/* fail slots: control open, control ioctl, backing rw, backing ro,
 * device open, SET_FD, SET_STATUS64, CLR_FD. */
static void event(const char *fmt, ...)
{
    if (quiet) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(fixture_trace + used, sizeof fixture_trace - used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof fixture_trace - used) { bad++; return; }
    used += n;
}
static int fail(int slot)
{
    if (!failures[slot]) return 0;
    errno = failures[slot]; return 1;
}
static int confined(const char *p)
{
    return root[0] && !strncmp(p, root, strlen(root)) && p[strlen(root)] == '/' &&
           !strstr(p, "/../");
}
static int device_index(const char *p)
{
    if (strncmp(p, "/dev/loop", 9) || strlen(p) != 10 || p[9] < '0' || p[9] >= '0' + NDEV)
        return -1;
    return p[9] - '0';
}
static int fixture_open(const char *p, int flags, ...)
{
    char mapped[2048]; int kind = 1, idx = device_index(p);
    opens++;
    event("open %s %s\n", p, (flags & O_ACCMODE) == O_RDWR ? "rw" : "ro");
    if (!(flags & O_CLOEXEC) || (flags & ~(O_ACCMODE | O_CLOEXEC))) bad++;
    if (!strcmp(p, "/dev/loop-control")) {
        if (fail(0)) return -1;
        kind = 2; snprintf(mapped, sizeof mapped, "%s/dev/loop-control", root);
    } else if (idx >= 0) {
        if (fail(4)) return -1;
        kind = 10 + idx; snprintf(mapped, sizeof mapped, "%s/dev/loop%d", root, idx);
    } else if (!strncmp(p, "/sys/block/", 11)) {
        snprintf(mapped, sizeof mapped, "%s/sys/%s", root, p + 11);
    } else if (confined(p)) {
        if (fail((flags & O_ACCMODE) == O_RDWR ? 2 : 3)) return -1;
        snprintf(mapped, sizeof mapped, "%s", p);
    } else { errno = ENOENT; return -1; }
    if (!confined(mapped)) { bad++; errno = EPERM; return -1; }
    int fd = open(mapped, flags);
    if (fd >= NFDS) { close(fd); bad++; errno = EMFILE; return -1; }
    if (fd >= 0) {
        if (kinds[fd]) bad++;
        kinds[fd] = kind; modes[fd] = flags & O_ACCMODE; live++;
        snprintf(names[fd], sizeof names[fd], "%s", p);
    }
    return fd;
}
static int fixture_close(int fd)
{
    if (fd < 0 || fd >= NFDS || !kinds[fd]) { bad++; errno = EBADF; return -1; }
    closes++; live--; kinds[fd] = 0;
    event("close %s\n", names[fd]);
    int rc = close(fd);
    /* Deliberately clobber errno to exercise preservation on failed ioctls. */
    errno = EBADF;
    return rc;
}
static int fixture_stat(const char *p, struct stat *st)
{
    if (!confined(p)) { errno = ENOENT; return -1; }
    return stat(p, st);
}
static DIR *fixture_opendir(const char *p)
{
    if (!root[0] || strcmp(p, "/sys/block")) { bad++; errno = EPERM; return NULL; }
    char path[2048]; snprintf(path, sizeof path, "%s/sys", root);
    DIR *d = opendir(path); if (d) dirs++;
    return d;
}
static int fixture_closedir(DIR *d) { dirs--; return closedir(d); }
static int fixture_ioctl(int fd, unsigned long req, ...)
{
    calls++;
    if (fd < 0 || fd >= NFDS || !kinds[fd]) { bad++; errno = EBADF; return -1; }
    if (req == LOOP_CTL_GET_FREE) {
        event("GET_FREE\n");
        if (kinds[fd] != 2) bad++;
        if (fail(1)) return -1;
        for (int i = 0; i < NDEV; i++) if (!state[i].attached) return i;
        errno = ENOSPC; return -1;
    }
    int idx = kinds[fd] - 10;
    if (idx < 0 || idx >= NDEV) { bad++; errno = ENOTTY; return -1; }
    struct state *d = &state[idx];
    va_list ap; va_start(ap, req);
    int arg = -1; struct loop_info64 *info = NULL;
    if (req == LOOP_SET_FD || req == LOOP_CLR_FD) arg = va_arg(ap, int);
    else if (req == LOOP_SET_STATUS64) info = va_arg(ap, struct loop_info64 *);
    else bad++;
    va_end(ap);
    if (req == LOOP_SET_FD) {
        event("SET_FD loop%d\n", idx);
        if (fail(5)) return -1;
        if (d->attached) { errno = EBUSY; return -1; }
        if (arg < 0 || arg >= NFDS || kinds[arg] != 1 || !confined(names[arg])) {
            bad++; errno = EBADF; return -1;
        }
        d->attached = 1;
        snprintf(d->file, sizeof d->file, "%s", names[arg]);
        memset(&d->info, 0, sizeof d->info);
        if (modes[arg] == O_RDONLY || modes[fd] == O_RDONLY) d->info.lo_flags = LO_FLAGS_READ_ONLY;
    } else if (req == LOOP_SET_STATUS64) {
        event("SET_STATUS loop%d offset=%llu size=%llu flags=%u name=%s\n", idx,
              (unsigned long long)info->lo_offset, (unsigned long long)info->lo_sizelimit,
              info->lo_flags, info->lo_file_name);
        if (info->lo_device || info->lo_inode || info->lo_rdevice || info->lo_number ||
            info->lo_encrypt_type || info->lo_encrypt_key_size ||
            info->lo_init[0] || info->lo_init[1] ||
            (info->lo_flags & ~(LO_FLAGS_READ_ONLY | LO_FLAGS_PARTSCAN))) bad++;
        if (fail(6)) return -1;
        if (!d->attached) { bad++; errno = ENXIO; return -1; }
        d->info = *info;
    } else if (req == LOOP_CLR_FD) {
        event("CLR_FD loop%d\n", idx);
        if (arg != 0) bad++;
        if (fail(7)) return -1;
        if (!d->attached) { errno = ENXIO; return -1; }
        memset(d, 0, sizeof *d);
    } else { errno = ENOTTY; return -1; }
    return 0;
}
int losetup_fixture_builtin(WORD_LIST *list)
{
    const char *a[8]; int n = 0;
    for (; list && n < 8; list = list->next) a[n++] = list->word->word;
    if (list || !n) return 2;
    if (!strcmp(a[0], "reset") && n == 2 && a[1][0] == '/') {
        if (live || dirs) return 95;
        snprintf(root, sizeof root, "%s", a[1]);
        memset(state, 0, sizeof state); memset(failures, 0, sizeof failures);
        opens = closes = calls = live = dirs = bad = quiet = 0;
        used = 0; fixture_trace[0] = 0;
        /* A pre-existing association belongs to someone else. */
        state[0].attached = 1; strcpy(state[0].file, "foreign");
    } else if (!strcmp(a[0], "fail") && n == 3) {
        int slot = atoi(a[1]); if (slot < 0 || slot >= 8) return 2;
        failures[slot] = atoi(a[2]);
    } else if (!strcmp(a[0], "expect") && n == 6) {
        int idx = atoi(a[1]);
        if (idx < 0 || idx >= NDEV) return 2;
        struct state *d = &state[idx];
        if (!d->attached || d->info.lo_offset != strtoull(a[2], NULL, 10) ||
            d->info.lo_sizelimit != strtoull(a[3], NULL, 10) ||
            d->info.lo_flags != strtoul(a[4], NULL, 10) || strcmp(d->file, a[5])) return 97;
    } else if (!strcmp(a[0], "quiet") && n == 1) quiet = 1;
    else if (!strcmp(a[0], "trace") && n == 1) fputs(fixture_trace, stdout);
    else if (!strcmp(a[0], "state") && n == 1) {
        printf("audit live=%d dirs=%d bad=%d\n", live, dirs, bad);
        for (int i = 0; i < NDEV; i++) if (state[i].attached)
            printf("loop%d %s %llu %llu %u\n", i, state[i].file,
                   (unsigned long long)state[i].info.lo_offset,
                   (unsigned long long)state[i].info.lo_sizelimit, state[i].info.lo_flags);
    } else if (!strcmp(a[0], "counts") && n == 1)
        printf("counts %d %d %d\n", opens, closes, calls);
    else if (!strcmp(a[0], "assert") && n == 1) {
        if (live || dirs || bad || !state[0].attached || strcmp(state[0].file, "foreign")) return 96;
    } else return 2;
    return 0;
}
static char *fixture_doc[] = {"Private losetup boundary controller.", NULL};
struct builtin losetup_fixture_struct = {
    "losetup_fixture", losetup_fixture_builtin, BUILTIN_ENABLED, fixture_doc,
    "losetup_fixture reset|fail|expect|quiet|trace|state|counts|assert", 0
};
