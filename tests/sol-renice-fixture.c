/* SPDX-License-Identifier: MIT */
/* LD_PRELOAD fixture: intercept production requests.
   Never call the real getpriority or setpriority. An unseen id reports
   old priority 10. A successful set is remembered and later reads are
   clamped to the Linux nice range -20..19. */
#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RENICE_SLOTS 64
#define RENICE_OLD 10

struct renice_slot { int used, which, prio; unsigned long who; };
static struct renice_slot slots[RENICE_SLOTS];

static int
renice_clamp (int priority)
{
    if (priority > 19) return 19;
    if (priority < -20) return -20;
    return priority;
}

static struct renice_slot *
renice_slot (int which, unsigned long who, int create)
{
    struct renice_slot *free_slot = NULL;
    int i;

    for (i = 0; i < RENICE_SLOTS; i++) {
        if (slots[i].used && slots[i].which == which && slots[i].who == who)
            return &slots[i];
        if (!slots[i].used && !free_slot)
            free_slot = &slots[i];
    }
    if (!create || !free_slot)
        return NULL;
    free_slot->used = 1;
    free_slot->which = which;
    free_slot->who = who;
    free_slot->prio = RENICE_OLD;
    return free_slot;
}

int
getpriority (__priority_which_t which, id_t who)
{
    struct renice_slot *slot = renice_slot ((int) which, (unsigned long) who, 0);
    errno = 0;
    return slot ? renice_clamp (slot->prio) : RENICE_OLD;
}

int
setpriority (__priority_which_t which, id_t who, int priority)
{
    const char *path = getenv ("SOL_RENICE_AUDIT");
    FILE *f = path ? fopen (path, "a") : NULL;
    struct renice_slot *slot;
    if (!f) { errno = EIO; return -1; }
    fprintf (f, "%d %lu %d\n", which, (unsigned long) who, priority);
    if (fclose (f)) { errno = EIO; return -1; }
    if (who == 404404) { errno = ESRCH; return -1; }
    if (priority < 0) { errno = EACCES; return -1; }
    slot = renice_slot ((int) which, (unsigned long) who, 1);
    if (!slot) { errno = ENOMEM; return -1; }
    slot->prio = priority;
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
