/* SPDX-License-Identifier: MIT */
/* LD_PRELOAD fixture: intercept production requests; NEVER call setpriority. */
#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
setpriority (__priority_which_t which, id_t who, int priority)
{
    const char *path = getenv ("SOL_RENICE_AUDIT");
    FILE *f = path ? fopen (path, "a") : NULL;
    if (!f) { errno = EIO; return -1; }
    fprintf (f, "%d %lu %d\n", which, (unsigned long) who, priority);
    if (fclose (f)) { errno = EIO; return -1; }
    if (who == 404404) { errno = ESRCH; return -1; }
    if (priority < 0) { errno = EACCES; return -1; }
    return 0;
}

struct passwd *
getpwnam (const char *name)
{
    static struct passwd user = {
        .pw_name = "renice-fixture-user", .pw_passwd = "x",
        .pw_uid = 4242, .pw_gid = 4242, .pw_gecos = "",
        .pw_dir = "/", .pw_shell = "/bin/sh"
    };
    if (strcmp (name, "renice-fixture-user")) return NULL;
    return &user;
}
