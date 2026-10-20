/* SPDX-License-Identifier: MIT */
/* Include the production implementation, replacing only its syscall boundary.
 * No ioctl in this module can reach the kernel. Only /dev/null is opened. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "loadables.h"

static char scenario[40] = "success", fixture_trace[256], stat_path[64];
static unsigned long stats, opens, freezes, thaws, closes, bad;
static int active_fd = -1, verbose = 1, expect_freeze = 1;

static void event(const char *s)
{
    if (verbose && strlen(fixture_trace) + strlen(s) + 1 < sizeof(fixture_trace))
        strcat(fixture_trace, s);
}

static int injected_errno(const char *prefix)
{
    struct { const char *name; int value; } errors[] = {
        {"ENOENT", ENOENT}, {"EACCES", EACCES}, {"EPERM", EPERM},
        {"ENOTDIR", ENOTDIR}, {"ENOTTY", ENOTTY},
        {"EOPNOTSUPP", EOPNOTSUPP}, {"EBUSY", EBUSY},
        {"EINVAL", EINVAL}, {"EINTR", EINTR}, {"EMFILE", EMFILE},
        {NULL, 0}
    };
    size_t n = strlen(prefix);
    if (strncmp(scenario, prefix, n)) return 0;
    for (int i = 0; errors[i].name; i++)
        if (!strcmp(scenario + n, errors[i].name)) return errors[i].value;
    bad++;
    return EIO;
}

static int fixture_stat(const char *path, struct stat *st)
{
    int e;
    stats++;
    event("stat,");
    if (strcmp(path, "/fixture/mount") && strcmp(path, "/fixture/with space") &&
        strcmp(path, "-mount")) {
        bad++;
        errno = ENOENT;
        return -1;
    }
    strcpy(stat_path, path);
    if ((e = injected_errno("stat-"))) { errno = e; return -1; }
    memset(st, 0, sizeof(*st));
    st->st_mode = !strcmp(scenario, "regular") ? S_IFREG | 0600 :
                  !strcmp(scenario, "block") ? S_IFBLK | 0600 : S_IFDIR | 0700;
    return 0;
}

static int fixture_open(const char *path, int flags, ...)
{
    int e;
    if (strcmp(path, stat_path)) bad++;
    opens++;
    event("open,");
    if (flags != (O_RDONLY | O_DIRECTORY | O_CLOEXEC)) bad++;
    if ((e = injected_errno("open-"))) { errno = e; return -1; }
    if (active_fd != -1) { bad++; errno = EMFILE; return -1; }
    active_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (active_fd < 0) bad++;
    return active_fd;
}

static int fixture_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    int arg, e;
    va_start(ap, request);
    arg = va_arg(ap, int);
    va_end(ap);
    if (fd != active_fd || active_fd < 0 || arg != 0) bad++;
    /* Quiet batches have an independent alternating freeze/thaw oracle for
     * every request, not only matching aggregate totals. */
    if (!verbose) {
        if (request != (expect_freeze ? _IOWR('X', 119, int) : _IOWR('X', 120, int))) bad++;
        expect_freeze = !expect_freeze;
    }
    /* Linux UAPI constants, independently specified rather than reused from
     * the included implementation's fallback definitions. */
    if (request == _IOWR('X', 119, int)) { freezes++; event("freeze,"); }
    else if (request == _IOWR('X', 120, int)) { thaws++; event("thaw,"); }
    else { bad++; errno = EINVAL; return -1; }
    if ((e = injected_errno("ioctl-"))) { errno = e; return -1; }
    return 0;
}

static int fixture_close(int fd)
{
    int rc;
    closes++;
    event("close,");
    if (fd != active_fd || active_fd < 0) { bad++; errno = EBADF; return -1; }
    rc = close(fd);
    if (rc) bad++;
    active_fd = -1;
    /* Clobber errno even on successful close to test saved ioctl errors. */
    errno = EBADF;
    return rc;
}

#define stat(...) fixture_stat(__VA_ARGS__)
#define open(...) fixture_open(__VA_ARGS__)
#define ioctl(...) fixture_ioctl(__VA_ARGS__)
#define close(...) fixture_close(__VA_ARGS__)
#ifndef FSFREEZE_SOURCE
#define FSFREEZE_SOURCE "../loadables/fsfreeze.c"
#endif
#include FSFREEZE_SOURCE
#undef stat
#undef open
#undef ioctl
#undef close

static int fsfreeze_fixture_builtin(WORD_LIST *list)
{
    if (!list) return EX_USAGE;
    if (!strcmp(list->word->word, "reset")) {
        if (active_fd != -1) return EXECUTION_FAILURE;
        list = list->next;
        if (!list || strlen(list->word->word) >= sizeof(scenario)) return EX_USAGE;
        strcpy(scenario, list->word->word);
        verbose = !(list->next && !strcmp(list->next->word->word, "quiet"));
        stats = opens = freezes = thaws = closes = bad = 0;
        fixture_trace[0] = stat_path[0] = 0;
        expect_freeze = 1;
        return EXECUTION_SUCCESS;
    }
    if (!strcmp(list->word->word, "dump")) {
        printf("stat=%lu open=%lu freeze=%lu thaw=%lu close=%lu live=%d bad=%lu trace=%s\n",
               stats, opens, freezes, thaws, closes, active_fd != -1, bad, fixture_trace);
        return EXECUTION_SUCCESS;
    }
    return EX_USAGE;
}
static char *fixture_doc[] = { "Private fsfreeze syscall fixture: reset SCENARIO [quiet], dump.", NULL };
struct builtin fsfreeze_fixture_struct = {
    "fsfreeze_fixture", fsfreeze_fixture_builtin, BUILTIN_ENABLED,
    fixture_doc, "fsfreeze_fixture reset|dump", 0
};
