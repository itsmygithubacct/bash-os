/* SPDX-License-Identifier: MIT */
/* renice.c — util-linux 2.41.5 renice(1) as a bash builtin.
 *
 *   renice [-n|--priority|--relative] PRIORITY [-p|--pid|-g|--pgrp|-u|--user] ID...
 *
 * The first argument is the priority. -n is absolute unless POSIXLY_CORRECT
 * is set, when it is added to the current priority. --priority is always
 * absolute. --relative is always an increment. Later selectors apply to the
 * ids that follow. Process id 0 is applied in a short-lived child so the
 * shell's niceness stays unchanged, matching an external renice.
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
#include <stdarg.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pwd.h>

#include "loadables.h"
#include "child-wait.h"

static const char *
renice_kind (int which)
{
    if (which == PRIO_PGRP) return "process group ID";
    if (which == PRIO_USER) return "user ID";
    return "process ID";
}

/* util-linux 2.41.5 keeps the low 32 bits of strtol and ignores ERANGE. */
static int
renice_bits (uint32_t bits)
{
    int32_t narrowed;
    memcpy (&narrowed, &bits, sizeof narrowed);
    return (int) narrowed;
}

static int
renice_i32 (const char *text, char **end)
{
    return renice_bits ((uint32_t) (unsigned long) strtol (text, end, 10));
}

static int
renice_i32_uid (unsigned long uid)
{
    return renice_bits ((uint32_t) uid);
}

static void
renice_warnx (const char *fmt, ...)
{
    va_list args;
    fprintf (stderr, "renice: ");
    va_start (args, fmt);
    vfprintf (stderr, fmt, args);
    va_end (args);
    fputc ('\n', stderr);
}

static void
renice_warn (const char *fmt, ...)
{
    int saved = errno;
    va_list args;
    fprintf (stderr, "renice: ");
    va_start (args, fmt);
    vfprintf (stderr, fmt, args);
    va_end (args);
    fprintf (stderr, ": %s\n", strerror (saved));
}

static void
renice_tryhelp (void)
{
    fputs ("Try 'renice --help' for more information.\n", stderr);
}

static void
renice_help (void)
{
    fputs ("\nUsage:\n"
           " renice [-n|--priority|--relative] <priority> [-p|--pid] <pid>...\n"
           " renice [-n|--priority|--relative] <priority>  -g|--pgrp <pgid>...\n"
           " renice [-n|--priority|--relative] <priority>  -u|--user <user>...\n"
           "\n"
           "Alter the priority of running processes.\n"
           "\nOptions:\n"
           " -n <num>               specify the nice value;\n"
           "                          if POSIXLY_CORRECT flag is set in environment,\n"
           "                          then the priority is 'relative' to current\n"
           "                          process priority; otherwise it is 'absolute'\n"
           " --priority <num>       specify the 'absolute' nice value\n"
           " --relative <num>       specify the 'relative' nice value\n"
           " -p, --pid              interpret arguments as process ID (default)\n"
           " -g, --pgrp             interpret arguments as process group ID\n"
           " -u, --user             interpret arguments as username or user ID\n"
           "\n", stdout);
    printf ("%-24s%s\n%-24s%s\n",
            " -h, --help", "display this help",
            " -V, --version", "display version");
    fputs ("\nFor more details see renice(1).\n", stdout);
}

static int
renice_getprio (int which, int who, int *prio)
{
    errno = 0;
    *prio = getpriority (which, who);
    if (*prio == -1 && errno) {
        renice_warn ("failed to get priority for %d (%s)", who, renice_kind (which));
        return -1;
    }
    return 0;
}

static int
renice_donice (int which, int who, int prio, int relative, int *write_error)
{
    int oldprio, newprio;

    if (renice_getprio (which, who, &oldprio) != 0)
        return 1;
    newprio = relative
        ? renice_bits ((uint32_t) ((unsigned) oldprio + (unsigned) prio))
        : prio;
    if (setpriority (which, who, newprio) < 0) {
        renice_warn ("failed to set priority for %d (%s)", who, renice_kind (which));
        return 1;
    }
    if (renice_getprio (which, who, &newprio) != 0)
        return 1;
    if (printf ("%d (%s) old priority %d, new priority %d\n",
                who, renice_kind (which), oldprio, newprio) < 0
        && errno != EPIPE && *write_error == 0)
        *write_error = errno;
    return 0;
}

/* who 0 and PRIO_PROCESS means the calling process. External renice changes
   only itself. Apply that in a child so the shell is left alone. */
static int
renice_donice_self (int prio, int relative)
{
    bos_child_wait child_wait;
    pid_t pid, waited;
    int status, rc, write_error = 0;

    if (bos_child_wait_begin (&child_wait) < 0) {
        renice_warn ("cannot block SIGCHLD");
        return 1;
    }
    fflush (stdout);
    fflush (stderr);
    pid = fork ();
    if (pid < 0) {
        int saved = errno;
        bos_child_wait_end (&child_wait);
        errno = saved;
        renice_warn ("fork");
        return 1;
    }
    if (pid == 0) {
        bos_child_wait_child (&child_wait);
        rc = renice_donice (PRIO_PROCESS, 0, prio, relative, &write_error);
        if (fflush (stdout) == EOF && errno != EPIPE && write_error == 0)
            write_error = errno;
        if (write_error) {
            errno = write_error;
            renice_warn ("write error");
            rc = 1;
        }
        fflush (stdout);
        fflush (stderr);
        _exit (rc ? 1 : 0);
    }
    while ((waited = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
        ;
    if (waited < 0) {
        int saved = errno;
        bos_child_wait_end (&child_wait);
        errno = saved;
        renice_warn ("waitpid");
        return 1;
    }
    bos_child_wait_end (&child_wait);
    if (!WIFEXITED (status) || WEXITSTATUS (status) != 0)
        return 1;
    return 0;
}

static int
renice_finish (int status, int write_error)
{
    if (fflush (stdout) == EOF && errno != EPIPE && write_error == 0)
        write_error = errno;
    if (write_error) {
        errno = write_error;
        renice_warn ("write error");
        status = EXECUTION_FAILURE;
    }
    fflush (stderr);
    clearerr (stdout);
    clearerr (stderr);
    return status;
}

int
renice_builtin (WORD_LIST *list)
{
    int which = PRIO_PROCESS;
    int relative = 0;
    int prio = 0;
    int errs = 0;
    int write_error = 0;
    char *endptr = NULL;
    const char *text;

    if (list && !list->next) {
        text = list->word->word;
        if (!strcmp (text, "-h") || !strcmp (text, "--help")) {
            renice_help ();
            return renice_finish (EXECUTION_SUCCESS, 0);
        }
        if (!strcmp (text, "-v") || !strcmp (text, "-V") || !strcmp (text, "--version")) {
            printf ("renice from util-linux 2.41.5\n");
            return renice_finish (EXECUTION_SUCCESS, 0);
        }
    }

    if (list) {
        text = list->word->word;
        if (!strcmp (text, "-n")) {
            relative = getenv ("POSIXLY_CORRECT") != NULL;
            list = list->next;
        } else if (!strcmp (text, "--relative")) {
            relative = 1;
            list = list->next;
        } else if (!strcmp (text, "--priority")) {
            list = list->next;
        }
    }

    /* A priority and at least one following argument are required. Selectors
       with no id still count as that following argument. */
    if (!list || !list->next) {
        renice_warnx ("not enough arguments");
        renice_tryhelp ();
        return renice_finish (EXECUTION_FAILURE, 0);
    }

    text = list->word->word;
    prio = renice_i32 (text, &endptr);
    if (!endptr || *endptr) {
        renice_warnx ("invalid priority '%s'", text);
        renice_tryhelp ();
        return renice_finish (EXECUTION_FAILURE, 0);
    }
    list = list->next;

    for (; list; list = list->next) {
        int who;
        text = list->word->word;
        if (!strcmp (text, "-g") || !strcmp (text, "--pgrp")) {
            which = PRIO_PGRP;
            continue;
        }
        if (!strcmp (text, "-u") || !strcmp (text, "--user")) {
            which = PRIO_USER;
            continue;
        }
        if (!strcmp (text, "-p") || !strcmp (text, "--pid")) {
            which = PRIO_PROCESS;
            continue;
        }
        if (which == PRIO_USER) {
            struct passwd *pw = getpwnam (text);
            if (pw)
                who = renice_i32_uid (pw->pw_uid);
            else
                who = renice_i32 (text, &endptr);
            /* endptr is left unchanged when getpwnam succeeds, matching
               util-linux 2.41.5. A previous failed numeric parse can make
               the next resolved name fail this check. */
            if (who < 0 || !endptr || *endptr) {
                renice_warnx ("unknown user %s", text);
                errs = 1;
                continue;
            }
        } else {
            who = renice_i32 (text, &endptr);
            if (who < 0 || !endptr || *endptr) {
                renice_warnx ("bad %s value: %s", renice_kind (which), text);
                errs = 1;
                continue;
            }
        }
        if (which == PRIO_PROCESS && who == 0)
            errs |= renice_donice_self (prio, relative);
        else
            errs |= renice_donice (which, who, prio, relative, &write_error);
    }
    return renice_finish (errs ? EXECUTION_FAILURE : EXECUTION_SUCCESS, write_error);
}

char *renice_doc[] = {
    "Alter the priority of running processes.",
    "",
    "    renice [-n|--priority|--relative] PRIORITY [-p|--pid|-g|--pgrp|-u|--user] ID...",
    "",
    "The first argument is the priority. -n is absolute unless POSIXLY_CORRECT",
    "is set, when it is added to the current priority. --priority is always",
    "absolute and --relative is always an increment. Later -p, -g, and -u",
    "select process IDs (the default), process groups, or users.",
    "",
    "Success prints \"ID (kind) old priority OLD, new priority NEW\". Linux",
    "clamps the nice value to -20 through 19. A bad priority or a missing",
    "target fails before any change. A bad id or a syscall error is reported",
    "and later ids are still attempted. Process id 0 changes a short-lived",
    "child, not the shell. -h/--help and -V/--version need exactly one argument.",
    (char *)NULL
};

struct builtin renice_struct = {
    "renice",
    renice_builtin,
    BUILTIN_ENABLED,
    renice_doc,
    "renice [-n|--priority|--relative] PRIORITY [-p|--pid|-g|--pgrp|-u|--user] ID...",
    0
};
