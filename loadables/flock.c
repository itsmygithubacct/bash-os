/* SPDX-License-Identifier: MIT */
/* flock.c — flock(2) advisory file locking as a bash builtin.
 *
 *   flock [options] FD                          # lock an open fd
 *   flock [options] FILE|DIR command [args...]  # lock FILE, run command
 *   flock [options] FILE|DIR -c "shell command"
 *
 * The fd form is the reason this is a builtin rather than a forked tool:
 * because it runs IN the calling shell, `flock -x 9` locks the descriptor
 * the shell opened with `exec 9>lockfile`, and the lock persists after the
 * builtin returns (it lives on the open file description, not the process).
 * That makes the canonical idiom
 *
 *     exec 9>/var/lock/mine
 *     flock -n 9 || { echo "busy"; exit 1; }
 *     ... critical section ...
 *
 * work with no fork and no external binary.
 *
 * Options (util-linux flock(1) compatible, from its manual and observed
 * behaviour):
 *   -s, --shared        take a shared lock
 *   -x, -e, --exclusive take an exclusive lock (default)
 *   -u, --unlock        drop a held lock
 *   -n, --nb, --nonblock fail (do not wait) if the lock is held
 *   -w, --wait, --timeout SECONDS  wait at most SECONDS (fractional ok)
 *   -E, --conflict-exit-code N  exit code when -n/-w fails to lock (default 1)
 *   -o, --close         close the fd before running command (file form)
 *   -c, --command CMD   (after FILE) run CMD via $SHELL -c, else /bin/sh -c
 *   -F, --no-fork       the command itself holds the lock; no waiting
 *                       flock process keeps a copy of the descriptor
 *       --fcntl         use fcntl(F_OFD_SETLK) instead of flock(2)
 *       --verbose       report the time taken to get the lock and the
 *                       command run (on stdout, as util-linux does)
 *
 * util-linux's -F replaces the flock process with the command. Here the
 * flock "process" is the calling shell, which must survive: the command
 * runs in a child that holds the only copy of the locked descriptor, and
 * the shell waits for it. Only when the builtin is the whole job of a child
 * bash (`flock -F L cmd &`, a pipeline element) does the command replace
 * that process directly.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <limits.h>
#include <math.h>

#include "loadables.h"
#include "child-wait.h"
#include "command-run.h"
#include "gnu-longopt.h"
#include "shim-prog-name.h"

extern char *flock_doc[];

/* util-linux uses sysexits values, distinct from Bash's EX_USAGE (2). */
enum { FLOCK_USAGE = 64, FLOCK_DATAERR = 65, FLOCK_NOINPUT = 66,
       FLOCK_UNAVAILABLE = 69, FLOCK_OSERR = 71 };

enum { FLOCK_OPT_FCNTL = BOS_OPT_FIRST, FLOCK_OPT_VERBOSE };

static const struct bos_longopt flock_longopts[] = {
    { "shared",             BOS_NO_ARG,  's' },
    { "exclusive",          BOS_NO_ARG,  'x' },
    { "unlock",             BOS_NO_ARG,  'u' },
    { "nonblocking",        BOS_NO_ARG,  'n' },
    { "nb",                 BOS_NO_ARG,  'n' },
    { "no-fork",            BOS_NO_ARG,  'F' },
    { "timeout",            BOS_REQ_ARG, 'w' },
    { "wait",               BOS_REQ_ARG, 'w' },
    { "conflict-exit-code", BOS_REQ_ARG, 'E' },
    { "close",              BOS_NO_ARG,  'o' },
    { "fcntl",              BOS_NO_ARG,  FLOCK_OPT_FCNTL },
    { "verbose",            BOS_NO_ARG,  FLOCK_OPT_VERBOSE },
    { "help",               BOS_NO_ARG,  'h' },
    { "version",            BOS_NO_ARG,  'V' },
    { NULL, 0, 0 }
};

static int
flock_contended_errno (int e)
{
    return e == EWOULDBLOCK || e == EAGAIN || e == EACCES;
}

static double
flock_monotonic_seconds (void)
{
    struct timespec ts;
    if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
        return 0.0;
    return (double) ts.tv_sec + ((double) ts.tv_nsec / 1000000000.0);
}

static void
flock_sleep_until_retry (double deadline)
{
    double now = flock_monotonic_seconds ();
    double remaining = deadline - now;
    if (remaining <= 0.0)
        return;

    if (remaining > 0.01)
        remaining = 0.01;

    struct timespec req;
    req.tv_sec = (time_t) remaining;
    req.tv_nsec = (long) ((remaining - (double) req.tv_sec) * 1000000000.0);
    if (req.tv_sec == 0 && req.tv_nsec <= 0)
        req.tv_nsec = 1;

    while (nanosleep (&req, &req) < 0 && errno == EINTR) {
        if (flock_monotonic_seconds () >= deadline)
            break;
    }
}

/* One lock attempt with flock(2) or an open-file-description fcntl lock.
   LOCKTYPE is LOCK_SH, LOCK_EX or LOCK_UN. */
static int
flock_try (int fd, int locktype, int nonblock, int use_fcntl)
{
    if (!use_fcntl)
        return flock (fd, locktype | (nonblock ? LOCK_NB : 0));

    struct flock fl;
    memset (&fl, 0, sizeof fl);
    fl.l_type = locktype == LOCK_SH ? F_RDLCK : locktype == LOCK_UN ? F_UNLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    return fcntl (fd, nonblock ? F_OFD_SETLK : F_OFD_SETLKW, &fl);
}

/* Take LOCKTYPE on FD. timeout < 0 means block forever, timeout == 0 one
   non-blocking attempt. Returns 0 on success, 1 if the lock is contended
   (would block / timed out), -1 on a real error (errno set). */
static int
flock_apply (int fd, int locktype, double timeout, int use_fcntl)
{
    if (timeout < 0) {
        /* Retry after a signal the shell does not act on (SIGCHLD from a
           background job, say); give up on SIGINT or a terminating one. */
        while (flock_try (fd, locktype, 0, use_fcntl) != 0) {
            if (errno != EINTR || interrupt_state || terminating_signal)
                return -1;
        }
        return 0;
    }

    /* Timed wait: avoid SIGALRM in the Bash process. Poll with a
       non-blocking attempt until the monotonic deadline so -w cannot wedge
       in a restarted blocking flock(2) inside a loadable builtin. */
    double deadline = flock_monotonic_seconds () + timeout;
    for (;;) {
        if (flock_try (fd, locktype, 1, use_fcntl) == 0)
            return 0;

        int saved_errno = errno;
        if (!flock_contended_errno (saved_errno)) {
            errno = saved_errno;
            return -1;
        }

        if (timeout <= 0.0 || flock_monotonic_seconds () >= deadline) {
            errno = saved_errno;
            return 1;
        }

        flock_sleep_until_retry (deadline);
    }
}

static int
flock_all_digits (const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit ((unsigned char) *p))
            return 0;
    return 1;
}

static int
flock_parse_exit (const char *s, int *out)
{
    char *end;
    errno = 0;
    long value = strtol (s, &end, 10);
    if (end == s || *end) {
        builtin_error ("invalid exit code: '%s'", s);
        return -1;
    }
    if (errno) {
        builtin_error ("invalid exit code: '%s': %s", s, strerror (errno));
        return -1;
    }
    if (value < 0 || value > 255) {
        builtin_error ("exit code out of range (expected 0 to 255)");
        return -1;
    }
    *out = (int) value;
    return 0;
}

static int
flock_parse_timeout (const char *s, double *out)
{
    char *end = NULL;
    errno = 0;
    double value = strtod (s, &end);
    if (end == s || *end) {
        builtin_error ("invalid timeout value: '%s'", s);
        return -1;
    }
    *out = value;
    return 0;
}

static void
flock_help (void)
{
    for (char **lp = flock_doc; *lp; lp++)
        puts (*lp);
}

/* The program -c runs: an exported non-empty SHELL, else /bin/sh. */
static const char *
flock_shell (void)
{
    SHELL_VAR *v = find_variable ("SHELL");
    const char *s = v && exported_p (v) && !array_p (v) && !assoc_p (v) ? value_cell (v) : NULL;
    return s && *s ? s : "/bin/sh";
}

/* Child side of the file form: run ARGV (PROGRAM is argv[0] or the shell
   for -c). Never returns. */
static void
flock_exec_child (char **argv, int is_shell_cmd)
{
    if (!is_shell_cmd)
        bos_run_builtin (argv[0], argv, NULL);
    if (is_shell_cmd)
        execv (argv[0], argv);
    else
        execvp (argv[0], argv);
    int saved = errno;
    fprintf (stderr, "flock: failed to execute %s: %s\n", argv[0], strerror (saved));
    fflush (stderr);
    _exit (FLOCK_UNAVAILABLE);
}

int
flock_builtin (WORD_LIST *list)
{
    int locktype = LOCK_EX;          /* default exclusive */
    int nonblock = 0;
    int do_unlock = 0;
    int close_before_exec = 0;
    int no_fork = 0;
    int use_fcntl = 0;
    int verbose = 0;
    int conflict_exit = 1;
    int timeout_given = 0;
    double timeout = -1.0;           /* <0 = block forever */
    const char *prog = bos_shim_prog_name ("flock");
    bos_getopt g;
    int c;

    if (!list) {
        builtin_error ("not enough arguments");
        bos_try_help (prog);
        return FLOCK_USAGE;
    }

    /* util-linux stops at the first operand: everything after FILE is the
       command, and -c/--command is recognised only right after FILE. */
    bos_getopt_init (&g, prog, "sxeunoFw:E:hV", flock_longopts, list);
    g.posix = 1;
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
            case 's': locktype = LOCK_SH; break;
            case 'x': case 'e': locktype = LOCK_EX; break;
            case 'u': do_unlock = 1; break;
            case 'n': nonblock = 1; break;
            case 'o': close_before_exec = 1; break;
            case 'F': no_fork = 1; break;
            case FLOCK_OPT_FCNTL: use_fcntl = 1; break;
            case FLOCK_OPT_VERBOSE: verbose = 1; break;
            case 'w':
                if (flock_parse_timeout (g.optarg, &timeout) < 0) {
                    bos_getopt_free (&g);
                    return FLOCK_USAGE;
                }
                timeout_given = 1;
                break;
            case 'E':
                if (flock_parse_exit (g.optarg, &conflict_exit) < 0) {
                    bos_getopt_free (&g);
                    return FLOCK_USAGE;
                }
                break;
            case 'h':
                bos_getopt_free (&g);
                flock_help ();
                return sh_chkwrite (EXECUTION_SUCCESS);
            case 'V':
                bos_getopt_free (&g);
                puts ("flock 1.0 (bash-loadable, util-linux compatible subset)");
                return sh_chkwrite (EXECUTION_SUCCESS);
            default:
                bos_getopt_free (&g);
                return FLOCK_USAGE;
        }
    }

    if (no_fork && close_before_exec) {
        builtin_error ("the --no-fork and --close options are incompatible");
        bos_getopt_free (&g);
        return FLOCK_USAGE;
    }
    if (g.noperands == 0) {
        builtin_error ("requires file descriptor, file or directory");
        bos_getopt_free (&g);
        return FLOCK_USAGE;
    }

    char *operand = g.operands[0];
    char **cmd = g.operands + 1;      /* command argv (file form) */
    int ncmd = g.noperands - 1;
    char *shell_argv[4] = { NULL, NULL, NULL, NULL };
    int is_shell_cmd = 0;

    if (ncmd > 0 && (!strcmp (cmd[0], "-c") || !strcmp (cmd[0], "--command"))) {
        if (ncmd != 2) {
            builtin_error ("-c requires exactly one command argument");
            bos_getopt_free (&g);
            return FLOCK_USAGE;
        }
        shell_argv[0] = (char *) flock_shell ();
        shell_argv[1] = "-c";
        shell_argv[2] = cmd[1];
        cmd = shell_argv;
        ncmd = 3;
        is_shell_cmd = 1;
    }

    /* A single operand is a descriptor; with a command it is a pathname,
       including when the pathname consists only of digits. */
    int is_fd = ncmd == 0;
    int fd, opened = 0;

    if (is_fd) {
        if (!flock_all_digits (operand)) {
            builtin_error ("bad file descriptor: '%s'", operand);
            bos_getopt_free (&g);
            return FLOCK_USAGE;
        }
        errno = 0;
        long number = strtol (operand, NULL, 10);
        if (errno || number > INT_MAX) {
            builtin_error ("bad file descriptor: '%s': %s", operand, strerror (ERANGE));
            bos_getopt_free (&g);
            return FLOCK_USAGE;
        }
        fd = (int) number;
    } else {
        /* An exclusive fcntl lock needs a writable descriptor; flock(2)
           and shared locks work on a read-only one, as on a directory. */
        int mode = use_fcntl && !do_unlock && locktype == LOCK_EX ? O_WRONLY : O_RDONLY;
        fd = open (operand, mode | O_CREAT | O_NOCTTY | O_CLOEXEC, 0666);
        if (fd < 0 && errno == EISDIR)
            fd = open (operand, O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("cannot open lock file %s: %s", operand, strerror (errno));
            bos_getopt_free (&g);
            return FLOCK_NOINPUT;
        }
        opened = 1;
    }

    /* Match util-linux's timer-setup failure for a negative or non-finite
       wait. Do this after pathname opening and before locking, without
       installing a process-wide timer or signal handler in the shell. */
    if (timeout_given && (timeout < 0.0 || !isfinite (timeout))) {
        builtin_error ("cannot set up timer: %s", strerror (EINVAL));
        if (opened) close (fd);
        bos_getopt_free (&g);
        return FLOCK_OSERR;
    }

    /* Apply the lock (or unlock). -n, and a zero wait, try once. */
    double started = flock_monotonic_seconds ();
    int once = nonblock || (timeout_given && timeout == 0.0);
    int lrc = flock_apply (fd, do_unlock ? LOCK_UN : locktype,
                           once ? 0.0 : timeout, use_fcntl);
    if (lrc == 1) {
        if (verbose)
            builtin_error (once ? "failed to get lock" : "timeout while waiting to get lock");
        if (opened) close (fd);
        bos_getopt_free (&g);
        return conflict_exit;          /* contended / timed out */
    }
    if (lrc < 0) {
        int saved = errno;
        builtin_error ("%s: %s", operand, strerror (saved));
        if (opened) close (fd);
        bos_getopt_free (&g);
        return saved == EBADF ? FLOCK_DATAERR : EXECUTION_FAILURE;
    }

    /* util-linux writes its verbose report to stdout through stdio, so a
       terminal sees it at once and a pipe or file at exit, after the
       command's own output; with -F the exec discards it unless stdout is
       a terminal. */
    char report[PATH_MAX + 128];
    report[0] = '\0';
    if (verbose) {
        double took = flock_monotonic_seconds () - started;
        int n = snprintf (report, sizeof report, "flock: getting lock took %.6f seconds\n",
                          took < 0 ? 0.0 : took);
        if (!is_fd && n > 0 && (size_t) n < sizeof report)
            snprintf (report + n, sizeof report - (size_t) n, "flock: executing %s\n", cmd[0]);
    }
    int report_now = report[0] && isatty (STDOUT_FILENO);
    if (report_now) {
        fputs (report, stdout);
        fflush (stdout);
    }

    /* Fd form: done. The descriptor (and thus the lock, for the lock case)
       stays exactly as the caller left it. */
    if (is_fd) {
        bos_getopt_free (&g);
        if (report[0] && !report_now)
            fputs (report, stdout);
        return sh_chkwrite (EXECUTION_SUCCESS);
    }

    /* File form: run the command while holding the lock, then release. */
    int status = EXECUTION_SUCCESS;
    char **argv = calloc ((size_t) ncmd + 1, sizeof *argv);
    if (!argv) {
        builtin_error ("calloc: %s", strerror (errno));
        close (fd);
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    for (int i = 0; i < ncmd; i++)
        argv[i] = cmd[i];
    argv[ncmd] = NULL;
    bos_getopt_free (&g);

    bos_child_wait child_wait;
    if (bos_child_wait_begin (&child_wait) < 0) {
        builtin_error ("SIGCHLD setup: %s", strerror (errno));
        close (fd);
        free (argv);
        return EXECUTION_FAILURE;
    }

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);

    /* -F in a child bash forked just for this builtin: the command replaces
       that process, as util-linux execs it in place of flock. Otherwise
       fork; the calling shell always survives. */
    pid_t pid = no_fork && bos_owns_process () ? 0 : fork ();
    if (pid < 0) {
        builtin_error ("fork: %s", strerror (errno));
        bos_child_wait_end (&child_wait);
        close (fd);
        free (argv);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bos_prepare_child ();
        bos_child_wait_child (&child_wait);
        if (close_before_exec) {
            close (fd);
        } else {
            /* The command inherits the locked descriptor, as it does from
               util-linux flock. */
            int flags = fcntl (fd, F_GETFD);
            if (flags >= 0)
                fcntl (fd, F_SETFD, flags & ~FD_CLOEXEC);
        }
        flock_exec_child (argv, is_shell_cmd);
    }

    /* -F: the command holds the only copy of the locked descriptor, so the
       lock ends with the command (or with whatever it passed the
       descriptor to), not with this shell's wait. */
    if (no_fork)
        close (fd);
    free (argv);

    int wstatus = 0;
    pid_t w;
    while ((w = waitpid (pid, &wstatus, 0)) < 0 && errno == EINTR) ;
    bos_child_wait_end (&child_wait);
    if (w < 0) {
        builtin_error ("waitpid: %s", strerror (errno));
        if (!no_fork) close (fd);
        return EXECUTION_FAILURE;
    }
    if (WIFEXITED (wstatus))        status = WEXITSTATUS (wstatus);
    else if (WIFSIGNALED (wstatus)) status = 128 + WTERMSIG (wstatus);

    if (!no_fork) close (fd);          /* releases the lock */
    if (report[0] && !report_now && !no_fork) {
        fputs (report, stdout);
        fflush (stdout);
    }
    return status;
}

char *flock_doc[] = {
    "Manage advisory file locks via flock(2).",
    "",
    "    flock [-sxun] [-w SECONDS] FD",
    "    flock [-sxun] [-w SECONDS] FILE command [args...]",
    "    flock [-sxun] [-w SECONDS] FILE -c \"shell command\"",
    "",
    "    -s, --shared        shared lock",
    "    -x, -e, --exclusive exclusive lock (default)",
    "    -u, --unlock        release a lock",
    "    -n, --nb, --nonblock fail instead of waiting if the lock is held",
    "    -w, --wait, --timeout SECONDS  wait at most SECONDS for the lock",
    "    -E N, --conflict-exit-code N  exit code on -n/-w failure (default 1)",
    "    -o, --close         close the descriptor before running the command",
    "    -F, --no-fork       the command holds the lock; flock keeps no copy",
    "    -c, --command CMD   after FILE: run CMD with $SHELL -c (or /bin/sh)",
    "        --fcntl         use fcntl(F_OFD_SETLK) rather than flock(2)",
    "        --verbose       report the lock wait and the command on stdout",
    "    -h, --help          display this help",
    "    -V, --version       display version",
    "",
    "The FD form runs in the current shell, so `flock -x 9` locks a descriptor",
    "opened with `exec 9>file` and the lock persists after flock returns.",
    "Options end at FILE or FD. A command in the file form runs in a child",
    "process; with -F that child holds the only copy of the locked descriptor",
    "and the calling shell waits for it and continues. The command may be an",
    "enabled builtin. A command that cannot be run exits with status 69.",
    "On a non-blocking or timed-out conflict, flock exits with the conflict",
    "exit code (default 1) and prints nothing.",
    (char *) NULL
};

struct builtin flock_struct = {
    "flock",
    flock_builtin,
    BUILTIN_ENABLED,
    flock_doc,
    "flock [-sxun] [-w SECONDS] [-E N] FD | FILE [command [args] | -c CMD]",
    0
};
