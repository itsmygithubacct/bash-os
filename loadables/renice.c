/* SPDX-License-Identifier: MIT */
/* renice.c — POSIX renice(1) as a bash builtin.
 *
 *   renice [-n] PRIORITY [-g|-p|-u] ID...
 *
 * Sets niceness on already-running processes (-p PID), process groups
 * (-g PGID), or all processes owned by user (-u USER). Default target
 * type is -p. Closes a POSIX-2024 medium-impact gap.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/resource.h>

#include "loadables.h"

static int
brenice_priority (const char *s, int *out)
{
    char *end;
    errno = 0;
    long value = strtol (s, &end, 10);
    if (errno || end == s || *end || value < INT_MIN || value > INT_MAX) {
        builtin_error ("invalid priority: %s", s);
        return -1;
    }
    *out = (int) value;
    return 0;
}

int
renice_builtin (WORD_LIST *list)
{
    int which = PRIO_PROCESS;
    int have_prio = 0;
    int prio = 0;

    /* Optional leading -n is POSIX-allowed but the priority can also be
       the bare first non-flag argument. Flags -p/-g/-u change the target
       type for everything that follows. */
    int rc = EXECUTION_SUCCESS;
    int target_count = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-n") && p->next) {
            p = p->next;
            if (brenice_priority (p->word->word, &prio) < 0) return EX_USAGE;
            have_prio = 1;
            continue;
        }
        if (!strcmp (w, "-p")) { which = PRIO_PROCESS; continue; }
        if (!strcmp (w, "-g")) { which = PRIO_PGRP;    continue; }
        if (!strcmp (w, "-u")) { which = PRIO_USER;    continue; }
        if (!have_prio) {
            /* First non-flag argument is the priority. */
            if (brenice_priority (w, &prio) < 0) return EX_USAGE;
            have_prio = 1;
            continue;
        }
        /* This is a target ID — interpret per the current `which`. */
        id_t id;
        if (which == PRIO_USER) {
            /* Numeric uid? Else look up by name. */
            char *end;
            errno = 0;
            unsigned long n = strtoul (w, &end, 10);
            if (!*w || *w == '-' || isspace ((unsigned char) *w) ||
                (end != w && !*end && (errno || n >= (id_t) -1))) {
                builtin_error ("invalid user ID: %s", w);
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (end != w && *end == '\0') {
                id = (id_t) n;
            } else {
                struct passwd *pw = getpwnam (w);
                if (!pw) {
                    builtin_error ("unknown user: %s", w);
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                id = pw->pw_uid;
            }
        } else {
            char *end;
            errno = 0;
            long n = strtol (w, &end, 10);
            if (errno || end == w || *end || n < 0 || n > INT_MAX) {
                builtin_error ("invalid process ID: %s", w);
                rc = EXECUTION_FAILURE;
                continue;
            }
            id = (id_t) n;
        }
        if (setpriority (which, id, prio) < 0) {
            builtin_error ("setpriority(%d, %lu, %d): %s",
                           which, (unsigned long) id, prio, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
        target_count++;
    }

    if (!have_prio || target_count == 0) {
        builtin_error ("usage: renice [-n] PRIORITY [-g|-p|-u] ID...");
        return EX_USAGE;
    }
    return rc;
}

char *renice_doc[] = {
    "Change the niceness of running processes (POSIX renice).",
    "",
    "    renice [-n] PRIORITY [-p|-g|-u] ID...",
    "",
    "    -p   IDs are PIDs (default)",
    "    -g   IDs are process group IDs",
    "    -u   IDs are usernames or UIDs (every process owned)",
    "",
    "Set the niceness to PRIORITY (an absolute value, NOT an increment",
    "— that's nice's job). Negative values require CAP_SYS_NICE.",
    (char *)NULL
};

struct builtin renice_struct = {
    "renice",
    renice_builtin,
    BUILTIN_ENABLED,
    renice_doc,
    "renice [-n] PRIORITY [-p|-g|-u] ID...",
    0
};
