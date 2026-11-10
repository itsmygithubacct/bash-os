/* SPDX-License-Identifier: MIT */
/* ionice.c — get/set I/O scheduling class & priority, as a bash builtin.
 *
 *   ionice [-c CLASS] [-n LEVEL] -p PID...     # set (or, with no -c/-n, get)
 *   ionice [-c CLASS] [-n LEVEL] command [args] # set for a new process
 *   ionice -p PID                               # print PID's class/priority
 *
 *   -c CLASS  none|0, realtime|rt|1, best-effort|be|2, idle|3
 *   -n LEVEL  priority within the class, 0 (highest) .. 7 (lowest)
 *   -p PID    act on an existing process (repeatable)
 *   -t        ignore failures when setting
 *
 * Uses the ioprio_get/ioprio_set syscalls directly (no libc wrappers).
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "loadables.h"
#include "child-wait.h"

extern char *ionice_doc[];

#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_PRIO_MASK   ((1u << IOPRIO_CLASS_SHIFT) - 1)
#define IOPRIO_PRIO_CLASS(v) ((v) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(v)  ((v) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(c, d) (((c) << IOPRIO_CLASS_SHIFT) | (d))

enum { IOPRIO_CLASS_NONE = 0, IOPRIO_CLASS_RT = 1, IOPRIO_CLASS_BE = 2, IOPRIO_CLASS_IDLE = 3 };
enum { IOPRIO_WHO_PROCESS = 1 };

static const char *class_names[] = { "none", "realtime", "best-effort", "idle" };

static int
ioprio_get_p (int pid)
{
    return (int) syscall (SYS_ioprio_get, IOPRIO_WHO_PROCESS, pid);
}
static int
ioprio_set_p (int pid, int class, int data)
{
    return (int) syscall (SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid,
                          IOPRIO_PRIO_VALUE (class, data));
}

static int
parse_class (const char *s, int *out)
{
    if (!strcmp (s, "none") || !strcmp (s, "0")) { *out = IOPRIO_CLASS_NONE; return 0; }
    if (!strcmp (s, "realtime") || !strcmp (s, "rt") || !strcmp (s, "1")) { *out = IOPRIO_CLASS_RT; return 0; }
    if (!strcmp (s, "best-effort") || !strcmp (s, "be") || !strcmp (s, "2")) { *out = IOPRIO_CLASS_BE; return 0; }
    if (!strcmp (s, "idle") || !strcmp (s, "3")) { *out = IOPRIO_CLASS_IDLE; return 0; }
    return -1;
}

/* util-linux strtos32_or_err: status 1, no 0..7 pre-check. The kernel
   rejects class data outside 0..7 when a set is actually attempted. */
static int
ion_s32 (const char *s, int *out, const char *what)
{
    char *end = NULL;
    long long v;
    errno = 0;
    if (!s)
        s = "";
    v = strtoll (s, &end, 10);
    if (end == s || *end) {
        fprintf (stderr, "ionice: %s: '%s'\n", what, s);
        return -1;
    }
    if (errno == ERANGE || v < (long long) INT32_MIN || v > (long long) INT32_MAX) {
        fprintf (stderr, "ionice: %s: '%s': Numerical result out of range\n", what, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

static int
ion_tryhelp (void)
{
    fprintf (stderr, "Try 'ionice --help' for more information.\n");
    return EXECUTION_FAILURE;
}

static int
ion_add_id (int **ids, int *n, int *cap, int id)
{
    if (*n == *cap) {
        int next = *cap ? *cap * 2 : 16;
        int *grown = realloc (*ids, (size_t) next * sizeof **ids);
        if (!grown) {
            fprintf (stderr, "ionice: realloc: %s\n", strerror (errno));
            return -1;
        }
        *ids = grown;
        *cap = next;
    }
    (*ids)[(*n)++] = id;
    return 0;
}

static int
print_ioprio (int pid)
{
    int v = ioprio_get_p (pid);
    if (v < 0) {
        /* util-linux err(EXIT_FAILURE, "ioprio_get failed"). Callers keep
           walking the rest of the id list (continue-on-failure). */
        fprintf (stderr, "ionice: ioprio_get failed: %s\n", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int cls = IOPRIO_PRIO_CLASS (v);
    int data = IOPRIO_PRIO_DATA (v);
    if (cls < 0 || cls > 3) cls = 0;
    /* util-linux prints the bare class name only for idle; every other class,
       none included, carries its priority ("none: prio 0"). */
    if (cls == IOPRIO_CLASS_IDLE)
        printf ("%s\n", class_names[cls]);
    else
        printf ("%s: prio %d\n", class_names[cls], data);
    return EXECUTION_SUCCESS;
}

int
ionice_builtin (WORD_LIST *list)
{
    /* Defaults match util-linux: best-effort class, class data 4. */
    int klass = IOPRIO_CLASS_BE, level = 4, ignore_fail = 0;
    int class_set = 0, data_set = 0;
    int *pids = NULL;
    int npid = 0, pcap = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        char *w = list->word->word;
        const char *val = NULL;
        const char *longname = NULL;
        char opt = 0;

        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            for (char **lp = ionice_doc; *lp; lp++) puts (*lp);
            free (pids);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("ionice 1.0 (bash-loadable)");
            free (pids);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-t") || !strcmp (w, "--ignore")) {
            ignore_fail = 1; list = list->next; continue;
        }
        if (!strncmp (w, "--class=", 8)) { opt = 'c'; val = w + 8; }
        else if (!strcmp (w, "--class")) { opt = 'c'; longname = "class"; }
        else if (!strncmp (w, "--classdata=", 12)) { opt = 'n'; val = w + 12; }
        else if (!strcmp (w, "--classdata")) { opt = 'n'; longname = "classdata"; }
        else if (!strncmp (w, "--pid=", 6)) { opt = 'p'; val = w + 6; }
        else if (!strcmp (w, "--pid")) { opt = 'p'; longname = "pid"; }
        else if (w[1] == 'c' || w[1] == 'n' || w[1] == 'p') {
            opt = w[1];
            if (w[2]) val = w + 2;
        } else {
            if (w[1] == '-')
                fprintf (stderr, "ionice: unrecognized option '%s'\n", w);
            else
                fprintf (stderr, "ionice: invalid option -- '%c'\n", w[1]);
            free (pids);
            return ion_tryhelp ();
        }
        if (!val) {
            if (!list->next) {
                if (longname)
                    fprintf (stderr, "ionice: option '--%s' requires an argument\n", longname);
                else
                    fprintf (stderr, "ionice: option requires an argument -- '%c'\n", opt);
                free (pids);
                return ion_tryhelp ();
            }
            list = list->next;
            val = list->word->word;
        }
        if (opt == 'c') {
            if (isdigit ((unsigned char) val[0])) {
                if (ion_s32 (val, &klass, "invalid class argument") < 0) {
                    free (pids); return EXECUTION_FAILURE;
                }
            } else if (parse_class (val, &klass) < 0) {
                fprintf (stderr, "ionice: unknown scheduling class: '%s'\n", val);
                free (pids);
                return EXECUTION_FAILURE;
            }
            class_set = 1;
        } else if (opt == 'n') {
            if (ion_s32 (val, &level, "invalid class data argument") < 0) {
                free (pids); return EXECUTION_FAILURE;
            }
            data_set = 1;
        } else {
            int id;
            if (ion_s32 (val, &id, "invalid PID argument") < 0
                || ion_add_id (&pids, &npid, &pcap, id) < 0) {
                free (pids);
                return EXECUTION_FAILURE;
            }
        }
        list = list->next;
    }

    if (class_set && (klass < IOPRIO_CLASS_NONE || klass > IOPRIO_CLASS_IDLE) && !ignore_fail)
        fprintf (stderr, "ionice: unknown prio class %d\n", klass);
    if (klass == IOPRIO_CLASS_NONE || klass == IOPRIO_CLASS_IDLE) {
        if (data_set && !ignore_fail)
            fprintf (stderr, "ionice: ignoring given class data for %s class\n",
                     klass == IOPRIO_CLASS_IDLE ? "idle" : "none");
        level = (klass == IOPRIO_CLASS_IDLE) ? 7 : 0;
    }

    /* Ids after a -p are more targets (util-linux) as well as repeated -p.
       There is no 256-id cap; every id is attempted. */
    if (npid > 0) {
        while (list) {
            int id;
            if (ion_s32 (list->word->word, &id, "invalid PID argument") < 0
                || ion_add_id (&pids, &npid, &pcap, id) < 0) {
                free (pids);
                return EXECUTION_FAILURE;
            }
            list = list->next;
        }
    }

    if (npid > 0) {
        int set_mode = class_set || data_set;
        int rc = EXECUTION_SUCCESS;
        for (int i = 0; i < npid; i++) {
            if (set_mode) {
                if (ioprio_set_p (pids[i], klass, level) < 0 && !ignore_fail) {
                    fprintf (stderr, "ionice: ioprio_set failed: %s\n", strerror (errno));
                    rc = EXECUTION_FAILURE;
                }
            } else if (print_ioprio (pids[i]) != EXECUTION_SUCCESS) {
                rc = EXECUTION_FAILURE;
            }
        }
        free (pids);
        return rc;
    }
    free (pids);
    pids = NULL;

    if (!list) {
        if (class_set || data_set) {
            fprintf (stderr, "ionice: bad usage\n");
            return ion_tryhelp ();
        }
        return print_ioprio (0);
    }

    /* Command form: set our intended class, then fork+exec it. */
    int argc = 0; for (WORD_LIST *p = list; p; p = p->next) argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) { builtin_error ("calloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int i = 0; for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    bos_child_wait child_wait;
    if (bos_child_wait_begin (&child_wait) < 0) {
        builtin_error ("SIGCHLD setup: %s", strerror (errno));
        free (argv); return EXECUTION_FAILURE;
    }

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) { builtin_error ("fork: %s", strerror (errno)); bos_child_wait_end (&child_wait); free (argv); return EXECUTION_FAILURE; }
    if (pid == 0) {
        bos_child_wait_child (&child_wait);
        if (ioprio_set_p (0, klass, level) < 0 && !ignore_fail) {
            fprintf (stderr, "ionice: ioprio_set failed: %s\n", strerror (errno));
            _exit (EXECUTION_FAILURE);
        }
        execvp (argv[0], argv);
        int saved = errno;
        fprintf (stderr, "ionice: %s: %s\n", argv[0], strerror (saved));
        _exit (saved == ENOENT ? 127 : 126);
    }
    free (argv);
    int wst = 0, status = EXECUTION_SUCCESS; pid_t w;
    while ((w = waitpid (pid, &wst, 0)) < 0 && errno == EINTR) ;
    bos_child_wait_end (&child_wait);
    if (w < 0) { builtin_error ("waitpid: %s", strerror (errno)); return EXECUTION_FAILURE; }
    if (WIFEXITED (wst)) status = WEXITSTATUS (wst);
    else if (WIFSIGNALED (wst)) status = 128 + WTERMSIG (wst);
    return status;
}

char *ionice_doc[] = {
    "Get or set the I/O scheduling class and priority of a process.",
    "",
    "    ionice [-c CLASS] [-n LEVEL] -p PID...      set (or get) for PIDs",
    "    ionice [-c CLASS] [-n LEVEL] command [args] set for a new process",
    "    ionice -p PID                               print PID's class/priority",
    "",
    "    -c CLASS  none|0, realtime|rt|1, best-effort|be|2, idle|3",
    "    -n LEVEL  0 (highest) .. 7 (lowest); default 4",
    "    -p PID    operate on an existing process (repeatable)",
    "    -t        ignore set failures",
    (char *) NULL
};

struct builtin ionice_struct = {
    "ionice",
    ionice_builtin,
    BUILTIN_ENABLED,
    ionice_doc,
    "ionice [-c CLASS] [-n LEVEL] [-t] {-p PID... | command [args]}",
    0
};
