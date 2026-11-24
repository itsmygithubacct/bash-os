/* SPDX-License-Identifier: MIT */
/* timeout.c — POSIX timeout(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   timeout [--help|--version] [-s SIG] [-k DUR] DURATION CMD [ARG...]
 *
 *   -s SIG    initial signal to send (name or number; default TERM).
 *   -k DUR    if CMD doesn't exit within DUR after the initial signal,
 *             escalate to SIGKILL.
 *
 *   DURATION  a number with optional suffix s/m/h/d (default seconds).
 *             Floating-point allowed.
 *
 * Exit codes:
 *   0..N     CMD's exit status if it exited normally before timeout.
 *   124      CMD timed out (we sent the signal).
 *   125      timeout itself (us) failed.
 *   126      CMD was found but not executable.
 *   127      CMD not found.
 *   128+N    CMD killed by signal N (after timeout, this becomes 124,
 *            except 137 when the timed-out CMD died from SIGKILL).
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <math.h>
#include <langinfo.h>

#include "loadables.h"
#include "command-run.h"
#include "shim-prog-name.h"
#include "gnu-longopt.h"

/* Parse "30", "30s", "1.5m", "2h" → seconds (double). */
static int
bto_parse_duration (const char *s, double *out)
{
    char *end;
    double v = strtod (s, &end);
    if (end == s || v < 0 || isnan (v)) return -1;
    if (*end == '\0') { *out = v; return 0; }
    if (end[1] != '\0') return -1;
    switch (*end) {
    case 's': *out = v; return 0;
    case 'm': *out = v * 60.0; return 0;
    case 'h': *out = v * 3600.0; return 0;
    case 'd': *out = v * 86400.0; return 0;
    default: return -1;
    }
}

/* Symbolic signal name → number. Caller passes "TERM", "INT", "9", etc. */
static int
bto_parse_signal (const char *s)
{
    if (!s || !*s) return -1;
    /* Numeric form: "9" or "SIG9". */
    const char *p = s;
    if (strncasecmp (p, "SIG", 3) == 0) p += 3;
    if (*p >= '0' && *p <= '9') {
        char *end;
        errno = 0;
        long n = strtol (p, &end, 10);
        if (errno || *end != '\0' || n < 0 || n >= NSIG) return -1;
        return (int) n;
    }
    if (strncasecmp (p, "RTMIN", 5) == 0) {
        long off = 0;
        const char *tail = p + 5;
        if (*tail == '+') {
            char *end;
            errno = 0;
            off = strtol (tail + 1, &end, 10);
            if (errno || end == tail + 1 || *end != '\0' || off < 0)
                return -1;
        } else if (*tail != '\0') {
            return -1;
        }
        if (off > SIGRTMAX - SIGRTMIN) return -1;
        long v = (long) SIGRTMIN + off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? (int) v : -1;
    }
    if (strncasecmp (p, "RTMAX", 5) == 0) {
        long off = 0;
        const char *tail = p + 5;
        if (*tail == '-') {
            char *end;
            errno = 0;
            off = strtol (tail + 1, &end, 10);
            if (errno || end == tail + 1 || *end != '\0' || off < 0)
                return -1;
        } else if (*tail != '\0') {
            return -1;
        }
        if (off > SIGRTMAX - SIGRTMIN) return -1;
        long v = (long) SIGRTMAX - off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? (int) v : -1;
    }
    /* Common names. */
    static const struct { const char *name; int sig; } map[] = {
        {"HUP",SIGHUP}, {"INT",SIGINT}, {"QUIT",SIGQUIT}, {"ILL",SIGILL},
        {"ABRT",SIGABRT}, {"FPE",SIGFPE}, {"KILL",SIGKILL}, {"USR1",SIGUSR1},
        {"SEGV",SIGSEGV}, {"USR2",SIGUSR2}, {"PIPE",SIGPIPE}, {"ALRM",SIGALRM},
        {"TERM",SIGTERM}, {"STOP",SIGSTOP}, {"TSTP",SIGTSTP}, {"CONT",SIGCONT},
        {"CHLD",SIGCHLD}, {"WINCH",SIGWINCH}, {"PWR", SIGPWR}, {NULL,0}
    };
    for (int i = 0; map[i].name; i++) {
        if (strcasecmp (p, map[i].name) == 0) return map[i].sig;
    }
    return -1;
}

extern char *timeout_doc[];

/* Reverse signal-number → short name lookup (no SIG prefix). NULL
   if outside the common set; caller falls back to numeric. */
static const char *
bto_signal_name (int s)
{
    static char rtbuf[16];

    switch (s) {
    case SIGHUP:  return "HUP";
    case SIGINT:  return "INT";
    case SIGQUIT: return "QUIT";
    case SIGILL:  return "ILL";
    case SIGABRT: return "ABRT";
    case SIGFPE:  return "FPE";
    case SIGKILL: return "KILL";
    case SIGUSR1: return "USR1";
    case SIGSEGV: return "SEGV";
    case SIGUSR2: return "USR2";
    case SIGPIPE: return "PIPE";
    case SIGALRM: return "ALRM";
    case SIGTERM: return "TERM";
    case SIGSTOP: return "STOP";
    case SIGTSTP: return "TSTP";
    case SIGCONT: return "CONT";
    case SIGCHLD: return "CHLD";
    case SIGWINCH:return "WINCH";
#ifdef SIGPWR
    case SIGPWR:  return "PWR";
#endif
    default:
        if (s >= SIGRTMIN && s <= SIGRTMAX) {
            if (s == SIGRTMIN)
                return "RTMIN";
            if (s == SIGRTMAX)
                return "RTMAX";
            snprintf (rtbuf, sizeof rtbuf, "RTMIN+%d", s - SIGRTMIN);
            return rtbuf;
        }
        return NULL;
    }
}

/* GNU timeout(1)-compatible verbose diagnostic, written to stderr.
   Format mirrors coreutils: "timeout: sending signal NAME to
   command 'CMD'". Falls back to a numeric signal when the name
   is unknown (RT signals etc). */
static void
bto_verbose_signal (int sig, const char *cmd)
{
    const char *nm = bto_signal_name (sig);
    const char *codeset = nl_langinfo (CODESET);
    int utf8 = codeset && (strcasecmp (codeset, "UTF-8") == 0
                           || strcasecmp (codeset, "UTF8") == 0);
    const char *open_quote = utf8 ? "\342\200\230" : "'";
    const char *close_quote = utf8 ? "\342\200\231" : "'";
    if (nm)
        fprintf (stderr, "timeout: sending signal %s to command %s%s%s\n",
                 nm, open_quote, cmd ? cmd : "<unknown>", close_quote);
    else
        fprintf (stderr, "timeout: sending signal %d to command %s%s%s\n",
                 sig, open_quote, cmd ? cmd : "<unknown>", close_quote);
    fflush (stderr);
}

/* Signal only the child in foreground mode; otherwise target its process
   group, falling back to the child if the group does not exist. */
static void
bto_signal_child (pid_t child, int sig, int foreground)
{
    if (foreground)
        kill (child, sig);
    else if (kill (-child, sig) < 0 && errno == ESRCH)
        kill (child, sig);
}

/* A termination signal received while timeout is the whole job of its
   process (`timeout D CMD &`): forwarded to CMD as GNU timeout does, after
   which timeout keeps waiting and reports CMD's status. In the calling
   shell's own process the shell keeps its usual dispositions. */
static volatile sig_atomic_t bto_forward_sig;

static void
bto_forward_handler (int sig)
{
    bto_forward_sig = sig;
}

static const int bto_forwarded[] = { SIGTERM, SIGINT, SIGHUP, SIGQUIT };

/* Close the child's pidfd (if any) and restore the caller's mask.
   SIGCHLD stays pending: we never dequeue it, so Bash still reaps
   any background job that exited while we ran. */
static void
bto_restore (const sigset_t *prev, int pidfd)
{
    int saved = errno;
    if (pidfd >= 0)
        close (pidfd);
    sigprocmask (SIG_SETMASK, prev, NULL);
    errno = saved;
}

/* Sleep until the child exits or remain elapses. pidfd+ppoll wakes
   on our child without consuming SIGCHLD. Without a pidfd, cap each sleep
   so waitpid can notice an early exit while SIGCHLD remains blocked. */
static void
bto_wait_remain (int pidfd, const struct timespec *remain)
{
    if (pidfd >= 0) {
        struct pollfd pfd;
        pfd.fd = pidfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (ppoll (&pfd, 1, remain, NULL) < 0 && errno != EINTR)
            return;
        return;
    }
    {
        struct timespec interval = *remain;
        if (interval.tv_sec > 0 || interval.tv_nsec > 50000000L) {
            interval.tv_sec = 0;
            interval.tv_nsec = 50000000L;
        }
        int rc = clock_nanosleep (CLOCK_MONOTONIC, 0, &interval, NULL);
        (void) rc;
    }
}

int
timeout_builtin (WORD_LIST *list)
{
    int sig = SIGTERM;
    double kill_after = -1;
    double duration = -1;
    WORD_LIST *cmd_list = NULL;

    int preserve_status = 0;
    int foreground = 0;
    int verbose = 0;

    /* glibc getopt_long in "+" mode, as GNU timeout: options up to the
       first operand (DURATION), clusters such as -vs9, abbreviations,
       "--". Option arguments are checked as they are read; then a missing
       operand gets only the Try line, as GNU's. */
    static const struct bos_longopt timeout_longopts[] = {
        { "kill-after", BOS_REQ_ARG, 'k' },
        { "signal", BOS_REQ_ARG, 's' },
        { "verbose", BOS_NO_ARG, 'v' },
        { "foreground", BOS_NO_ARG, BOS_OPT_FIRST },
        { "preserve-status", BOS_NO_ARG, BOS_OPT_FIRST + 1 },
        { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    const char *prog = bos_shim_prog_name ("timeout");
    bos_getopt g;
    int c, nwords = 0;
    char *quoted;

    bos_getopt_init (&g, prog, "k:s:v", timeout_longopts, list);
    g.posix = 1;
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
        case 'k':
            if (bto_parse_duration (g.optarg, &kill_after) < 0) {
                quoted = bos_quote (g.optarg);
                builtin_error ("invalid time interval %s", quoted ? quoted : g.optarg);
                free (quoted);
                bos_shim_try_help ("timeout");
                bos_getopt_free (&g);
                return 125;
            }
            break;
        case 's':
            sig = bto_parse_signal (g.optarg);
            if (sig < 0) {
                quoted = bos_quote (g.optarg);
                builtin_error ("%s: invalid signal", quoted ? quoted : g.optarg);
                free (quoted);
                bos_shim_try_help ("timeout");
                bos_getopt_free (&g);
                return 125;
            }
            break;
        case 'v': verbose = 1; break;
        case BOS_OPT_FIRST: foreground = 1; break;
        case BOS_OPT_FIRST + 1: preserve_status = 1; break;
        case BOS_OPT_HELP: {
            char **d;
            bos_getopt_free (&g);
            for (d = timeout_doc; *d; d++) puts (*d);
            return EXECUTION_SUCCESS;
        }
        case BOS_OPT_VERSION:
            bos_getopt_free (&g);
            puts ("timeout 1.0 (bash-loadable, coreutils-compatible)");
            return EXECUTION_SUCCESS;
        default:
            bos_getopt_free (&g);
            return 125;
        }
    }
    if (g.noperands < 2) {
        bos_getopt_free (&g);
        bos_shim_try_help ("timeout");
        return 125;
    }
    if (bto_parse_duration (g.operands[0], &duration) < 0) {
        quoted = bos_quote (g.operands[0]);
        builtin_error ("invalid time interval %s", quoted ? quoted : g.operands[0]);
        free (quoted);
        bos_shim_try_help ("timeout");
        bos_getopt_free (&g);
        return 125;
    }
    /* In "+" mode the operands are the list's tail: DURATION, CMD, ARGs. */
    for (WORD_LIST *w = list; w; w = w->next) nwords++;
    cmd_list = list;
    for (int skip = nwords - g.noperands + 1; skip > 0; skip--) cmd_list = cmd_list->next;
    bos_getopt_free (&g);

    /* Build argv. */
    int argc = 0;
    for (WORD_LIST *q = cmd_list; q; q = q->next) argc++;
    char **argv = (char **) malloc ((argc + 1) * sizeof (char *));
    if (!argv) { builtin_error ("malloc: %s", strerror (errno)); return 125; }
    int i = 0;
    for (WORD_LIST *q = cmd_list; q; q = q->next) argv[i++] = q->word->word;
    argv[argc] = NULL;

    /* Preserve the command name for any verbose diagnostics — argv
       is freed before the wait loop, but cmd_list points into the
       bash-managed WORD_LIST so the underlying string outlives us. */
    const char *cmd_name = cmd_list->word->word;

    /* Block SIGCHLD so bash's SIGCHLD handler doesn't reap our forked
       child out from under us. Bash's main loop calls waitpid(-1, ...)
       on SIGCHLD; without blocking, our subsequent waitpid(child, ...)
       returns ECHILD because bash already collected the status. */
    sigset_t chld_set, prev_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_set);

    /* Decide before forking: the command child must not inherit the handler
       or the sole-child mark. */
    int forward = bos_owns_process ();

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t child = fork ();
    if (child < 0) {
        free (argv);
        sigprocmask (SIG_SETMASK, &prev_set, NULL);
        builtin_error ("fork: %s", strerror (errno));
        return 125;
    }
    if (child == 0) {
        bos_prepare_child ();
        /* Restore signal mask in child so it sees signals normally. */
        sigprocmask (SIG_SETMASK, &prev_set, NULL);
        if (!foreground)
            setpgid (0, 0);  /* own process group — subprocess coverage on kill */
        /* Optional pgid probe for tests: write the post-setpgid pgid to
           the path named by BASHTIMEOUT_PGID_PROBE. Lets the test observe
           --foreground (caller pgid retained) vs default (new pgrp). */
        const char *pgid_probe = getenv ("BASHTIMEOUT_PGID_PROBE");
        if (pgid_probe && *pgid_probe) {
            int pfd = open (pgid_probe, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (pfd >= 0) {
                char pline[64];
                int pn = snprintf (pline, sizeof pline, "%ld\n",
                                   (long) getpgid (0));
                if (pn > 0) {
                    ssize_t wn = write (pfd, pline, (size_t) pn);
                    (void) wn;  /* best-effort */
                }
                close (pfd);
            }
        }
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        /* Preserve execvp's error across diagnostic formatting and flushing. */
        int exec_error = errno;
        fprintf (stderr, "timeout: failed to run command '%s': %s\n",
                 argv[0], strerror (exec_error));
        fflush (stderr);
        _exit (exec_error == ENOENT ? 127 : 126);
    }
    if (!foreground)
        setpgid (child, child);  /* close parent/child process-group setup race */
    free (argv);
    if (forward) {
        bto_forward_sig = 0;
        struct sigaction fa = {0};
        fa.sa_handler = bto_forward_handler;
        sigemptyset (&fa.sa_mask);
        for (size_t k = 0; k < sizeof bto_forwarded / sizeof *bto_forwarded; k++)
            sigaction (bto_forwarded[k], &fa, NULL);
    }

    /* Parent: SIGCHLD stays blocked so Bash cannot steal this child, but
       we must not dequeue it (sigtimedwait would). pidfd+ppoll wakes when
       this child exits; leftover SIGCHLD still reaches Bash after restore.
       SIGALRM is Bash's (TMOUT / read -t). */
    int pidfd = -1;
#ifdef SYS_pidfd_open
    pidfd = (int) syscall (SYS_pidfd_open, child, 0);
#endif
    struct timespec start, now;
    clock_gettime (CLOCK_MONOTONIC, &start);

    int status;
    int timed_out = 0;
    int killed_hard = 0;
    double elapsed_at_signal = 0;
    for (;;) {
        if (forward && bto_forward_sig) {
            int fs = bto_forward_sig;
            bto_forward_sig = 0;
            bto_signal_child (child, fs, foreground);
            if (fs != SIGKILL && fs != SIGCONT)
                bto_signal_child (child, SIGCONT, foreground);
        }
        pid_t r = waitpid (child, &status, WNOHANG);
        if (r == child) break;
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) {
            builtin_error ("waitpid: %s", strerror (errno));
            bto_restore (&prev_set, pidfd);
            return 125;
        }
        clock_gettime (CLOCK_MONOTONIC, &now);
        double elapsed = (double)(now.tv_sec - start.tv_sec)
                       + (double)(now.tv_nsec - start.tv_nsec) / 1e9;
        /* DURATION of 0 disables the timeout (run CMD to completion), matching
           timeout(1): "A duration of 0 disables the associated timeout." */
        double deadline = -1;
        if (!timed_out && duration > 0)
            deadline = duration;
        else if (timed_out && !killed_hard && kill_after > 0)
            deadline = elapsed_at_signal + kill_after;
        if (deadline >= 0 && elapsed >= deadline) {
            if (!timed_out) {
                if (verbose) bto_verbose_signal (sig, cmd_name);
                bto_signal_child (child, sig, foreground);
                /* A stopped command cannot act on a pending termination
                   signal until continued (e.g. after a tty SIGTTIN). */
                if (sig != SIGKILL && sig != SIGCONT)
                    bto_signal_child (child, SIGCONT, foreground);
                timed_out = 1;
                elapsed_at_signal = elapsed;
            } else {
                if (verbose) bto_verbose_signal (SIGKILL, cmd_name);
                bto_signal_child (child, SIGKILL, foreground);
                killed_hard = 1;
            }
            continue;
        }
        if (killed_hard || deadline < 0) {
            r = waitpid (child, &status, 0);
            if (r == child) break;
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) {
                builtin_error ("waitpid: %s", strerror (errno));
                bto_restore (&prev_set, pidfd);
                return 125;
            }
            continue;
        }
        double remain = deadline - elapsed;
        /* GNU accepts infinite and very large durations. Wait in bounded
           chunks rather than converting an unrepresentable double to time_t.
           pidfd still wakes immediately when the command exits. */
        if (remain > 86400.0) remain = 86400.0;
        struct timespec wait_ts;
        wait_ts.tv_sec = (time_t) remain;
        wait_ts.tv_nsec = (long) ((remain - (double) wait_ts.tv_sec) * 1e9);
        if (wait_ts.tv_nsec < 0) wait_ts.tv_nsec = 0;
        if (wait_ts.tv_nsec >= 1000000000L) {
            wait_ts.tv_sec += 1;
            wait_ts.tv_nsec -= 1000000000L;
        }
        bto_wait_remain (pidfd, &wait_ts);
    }

    bto_restore (&prev_set, pidfd);

    if (timed_out) {
        /* GNU's non-foreground monitor belongs to the group it kills and
           therefore dies from SIGKILL during escalation.  Our monitor is
           the calling shell, so report the equivalent status without
           killing that shell.  A timed-out command that died from SIGKILL
           (escalation, -s KILL, or its own doing) is also 128+9 in every
           mode, so callers can tell it was forcibly killed. */
        if (killed_hard && !foreground)
            return 128 + SIGKILL;
        if (WIFSIGNALED (status) && WTERMSIG (status) == SIGKILL)
            return 128 + SIGKILL;
        if (preserve_status) {
            if (WIFEXITED (status)) return WEXITSTATUS (status);
            if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
        }
        return 124;
    }
    if (WIFEXITED (status)) return WEXITSTATUS (status);
    if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
    return 125;
}

char *timeout_doc[] = {
    "Run a command with a time limit.",
    "",
    "    timeout [--help|--version] [--preserve-status] [--foreground] [-v|--verbose]",
    "                [-s SIG] [-k DUR] DURATION CMD [ARG...]",
    "",
    "    --help              show this help",
    "    --version           show version",
    "    -s SIG              initial signal (name, RTMIN[+N], RTMAX[-N], or number; default TERM)",
    "    -k DUR              send SIGKILL if still alive DUR after the initial signal",
    "    --preserve-status   return CMD's actual exit status even on timeout",
    "    -v, --verbose       diagnose to stderr any signal sent upon timeout",
    "                        (format: \"timeout: sending signal NAME to command 'CMD'\")",
    "    DURATION            <number>[s|m|h|d]  (default seconds; 0 disables the timeout)",
    "",
    "Exit 124 on timeout, 125 on internal error, 126 if CMD found but",
    "not executable, 127 if not found, 128+N if killed by signal N,",
    "otherwise CMD's own exit status.  With --preserve-status, returns",
    "CMD's exit status (128+N) instead of 124 when timeout occurs.",
    (char *)NULL
};

struct builtin timeout_struct = {
    "timeout",
    timeout_builtin,
    BUILTIN_ENABLED,
    timeout_doc,
    "timeout [--help|--version] [--preserve-status] [--foreground] [-v|--verbose] [-s SIG] [-k DUR] DURATION CMD [ARG...]",
    0
};
