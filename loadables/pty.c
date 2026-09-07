/* SPDX-License-Identifier: MIT */
/* pty.c — TTY / session management for bash-os getty + login.
 *
 * Bash can drive a terminal via /dev/ttyXXX redirection but can't
 * issue setsid / TIOCSCTTY / tcsetpgrp — those are syscalls that
 * make a TTY into a controlling terminal for a session. pty
 * exposes the minimum surface needed for getty.sh / login login
 * to run real login sessions on a console without forking to /sbin/
 * agetty or /bin/login.
 *
 * Subcommands:
 *
 *   pty setsid
 *       setsid(2). The calling process becomes a new session
 *       leader with no controlling terminal. Required before
 *       open-tty (TIOCSCTTY only works on a session leader with
 *       no current ctty).
 *
 *   pty open-tty PATH [FDVAR]
 *       open(PATH, O_RDWR|O_NOCTTY), then ioctl(fd, TIOCSCTTY)
 *       to install it as the session's controlling terminal.
 *       By default also dup2's the new fd into stdin/stdout/stderr
 *       so subsequent reads/writes go to the tty without further
 *       redirection. With FDVAR, just bind $FDVAR to the fd and
 *       leave 0/1/2 alone.
 *
 *   pty isatty FD
 *       Exit 0 if FD is a terminal.
 *
 *   pty tty-name FD
 *       Print the filesystem path of the TTY backing FD (e.g.,
 *       /dev/pts/3 or /dev/ttyS0).
 *
 *   pty foreground PGRP [FD]
 *       tcsetpgrp(FD, PGRP). FD defaults to stdin (0). Used after
 *       fork+exec to give a child shell the foreground process
 *       group on the controlling tty.
 *
 *   pty close FD
 *       close(FD). Convenience.
 *
 *   pty spawn FDVAR PIDVAR CMD [ARG ...]
 *       Allocate a pty, fork a child, and exec CMD with the slave
 *       end as its controlling tty (stdin/stdout/stderr all wired
 *       to slave). Parent retains the master fd; reading the master
 *       gives the child's output, writing the master sends to its
 *       stdin. The master fd is bound to $FDVAR, the child pid to
 *       $PIDVAR. Use bash redirection to read/write — e.g.
 *           read -u "$FDVAR" -N 1 -t 5 ch     # read with timeout
 *           printf '%s\n' "$pw" >&"$FDVAR"    # send a line
 *       After EOF, `exec {FDVAR}<&-; wait $PIDVAR` cleans up.
 *       This is the spawn primitive for /bash-os/expect.sh.
 *
 * Refuses TIOCSCTTY if not the session leader — the calling script
 * is responsible for setsid before open-tty.
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
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

struct bp_child_guard {
  struct sigaction old_chld;
  sigset_t oldmask;
};

static int
bp_child_guard_begin (struct bp_child_guard *g)
{
  struct sigaction dfl;
  sigset_t block;
  memset (&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset (&dfl.sa_mask);
  if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
    return -1;
  sigemptyset (&block);
  sigaddset (&block, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0)
    {
      sigaction (SIGCHLD, &g->old_chld, NULL);
      return -1;
    }
  return 0;
}

static void
bp_child_guard_parent_end (struct bp_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
  sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
bp_child_guard_child_end (struct bp_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static int
bp_setsid_cmd (WORD_LIST *args)
{
  (void) args;
  pid_t s = setsid ();
  if (s < 0)
    {
      builtin_error ("setsid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bp_open_tty_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("open-tty needs PATH [FDVAR]"); return EX_USAGE; }
  const char *path = args->word->word;
  const char *fdvar = (args->next) ? args->next->word->word : NULL;

  /* O_NOCTTY: don't let open() implicitly grab the tty. We do that
     explicitly with TIOCSCTTY below, after verifying we're a session
     leader. O_RDWR for bidirectional. */
  int fd = open (path, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("open %s: %s", path, strerror (errno));
      return EXECUTION_FAILURE;
    }

  /* Acquire the controlling terminal. Fails if we already have one
     (caller should setsid first to start with no ctty) or if we're
     not a session leader. Pass 0 to TIOCSCTTY (don't force-steal). */
  if (ioctl (fd, TIOCSCTTY, 0) < 0)
    {
      /* Note: this can fail with EPERM if we already have a ctty —
         common in interactive / dev sessions. Don't fail hard; the
         tty is still usable for reads/writes, just not "controlling". */
      builtin_error ("TIOCSCTTY %s: %s (continuing without controlling)",
                     path, strerror (errno));
      /* Fall through — keep the fd; warn was enough. */
    }

  if (fdvar)
    {
      /* Caller wants the fd via variable; don't touch 0/1/2. */
      char buf[32];
      snprintf (buf, sizeof buf, "%d", fd);
      builtin_bind_variable ((char *) fdvar, buf, 0);
      return EXECUTION_SUCCESS;
    }

  /* Default: dup2 over stdin/stdout/stderr so the calling shell now
     reads/writes the tty. This is what getty wants. */
  if (dup2 (fd, 0) < 0 || dup2 (fd, 1) < 0 || dup2 (fd, 2) < 0)
    {
      builtin_error ("dup2: %s", strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  /* Close the original (CLOEXEC isn't enough — the dup2'd copies
     don't carry it). */
  if (fd > 2) close (fd);
  return EXECUTION_SUCCESS;
}

static int
bp_isatty_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("isatty needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  return isatty (fd) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bp_ttyname_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("tty-name needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  char buf[256];
  if (ttyname_r (fd, buf, sizeof buf) != 0)
    {
      builtin_error ("ttyname: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  printf ("%s\n", buf);
  return EXECUTION_SUCCESS;
}

static int
bp_foreground_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("foreground needs PGRP [FD]"); return EX_USAGE; }
  pid_t pgrp = (pid_t) atoi (args->word->word);
  int fd = (args->next) ? atoi (args->next->word->word) : 0;
  if (tcsetpgrp (fd, pgrp) < 0)
    {
      int saved = errno;
      if (saved == ENOTTY)
        {
          pid_t current = -1;
          if (ioctl (fd, TIOCGPGRP, &current) == 0 && current == pgrp)
            return EXECUTION_SUCCESS;
          char slave_path[256];
          if (ptsname_r (fd, slave_path, sizeof slave_path) == 0)
            {
              int slave = open (slave_path, O_RDWR | O_NOCTTY);
              if (slave >= 0)
                {
                  int rc = tcsetpgrp (slave, pgrp);
                  saved = errno;
                  close (slave);
                  if (rc == 0)
                    return EXECUTION_SUCCESS;
                }
            }
        }
      errno = saved;
      builtin_error ("tcsetpgrp: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bp_close_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("close needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  if (close (fd) < 0)
    {
      builtin_error ("close: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* Single-slot stash for the spawn → waitpid handoff. Keyed by the
   target child's PID (the pty-spawn user-visible PID, NOT the
   intermediate). pipe_fd holds the read end of the status pipe whose
   write end is closed when the intermediate exits. */
static struct {
  pid_t target_pid;
  int   pipe_fd;
} bp_stash = { 0, -1 };

static void
bp_stash_intermediate (pid_t target, int pipe_rd)
{
  /* If a previous stash wasn't drained (caller forgot waitpid),
     close its pipe to free resources. The caller's exit status for
     that prior child is permanently lost — that's their bug. */
  if (bp_stash.pipe_fd >= 0) close (bp_stash.pipe_fd);
  bp_stash.target_pid = target;
  bp_stash.pipe_fd = pipe_rd;
}

/* spawn: allocate pty, fork, exec child with slave as ctty.
 *
 * The pattern (POSIX): posix_openpt → grantpt → unlockpt → ptsname →
 * fork → child opens slave by path, makes it ctty, dup2 to 0/1/2,
 * exec; parent keeps master.
 *
 * We pre-grant in the parent so the child doesn't need root for
 * grantpt (which can chown the slave). Slave is opened by path AFTER
 * setsid in the child — Linux uses "first tty opened by a session
 * leader without O_NOCTTY becomes the ctty" which the open() does
 * implicitly, but we also issue an explicit TIOCSCTTY for portability.
 *
 * Errors before fork: cleaned up; errors after fork in child:
 * _exit(126) for setup, _exit(127) for exec — same convention as
 * shells use for "command not found" and "command not executable",
 * so the parent's wait status is informative.
 */
static int
bp_spawn_cmd (WORD_LIST *args)
{
  if (!args || !args->next || !args->next->next)
    {
      builtin_error ("spawn needs FDVAR PIDVAR CMD [ARG ...]");
      return EX_USAGE;
    }
  const char *fdvar = args->word->word;
  const char *pidvar = args->next->word->word;
  WORD_LIST *cmd_list = args->next->next;

  /* Build child argv. */
  int argc = 0;
  for (WORD_LIST *p = cmd_list; p; p = p->next) argc++;
  char **argv = (char **) malloc ((argc + 1) * sizeof (char *));
  if (!argv)
    { builtin_error ("argv malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int i = 0;
  for (WORD_LIST *p = cmd_list; p; p = p->next) argv[i++] = p->word->word;
  argv[argc] = NULL;

  /* Allocate master pty. O_CLOEXEC so master doesn't leak into child. */
  int master = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0)
    { free (argv); builtin_error ("posix_openpt: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (grantpt (master) < 0)
    { close (master); free (argv); builtin_error ("grantpt: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (unlockpt (master) < 0)
    { close (master); free (argv); builtin_error ("unlockpt: %s", strerror (errno)); return EXECUTION_FAILURE; }

  char slave_path[256];
  if (ptsname_r (master, slave_path, sizeof slave_path) != 0)
    { close (master); free (argv); builtin_error ("ptsname: %s", strerror (errno)); return EXECUTION_FAILURE; }

  /* Status pipe: intermediate writes the target's PID, then later
     its encoded exit status, into pipefd[1]; pty waitpid (running
     in the original bash) reads from pipefd[0]. This sidesteps the
     SIGCHLD race — bash's signal handler reaps the INTERMEDIATE
     child eagerly (which is fine, intermediate exits 0 immediately
     after writing), but the TARGET is a child of the intermediate,
     not bash, so bash never sees it and our exit status is preserved
     in the pipe. */
  int statpipe[2];
  if (pipe (statpipe) < 0)
    { close (master); free (argv); builtin_error ("pipe: %s", strerror (errno)); return EXECUTION_FAILURE; }
  /* CLOEXEC on the parent's read end so it doesn't leak into other
     spawn'd children. The intermediate dups statpipe[1] before
     close-on-exec doesn't apply (no exec in intermediate). */
  fcntl (statpipe[0], F_SETFD, FD_CLOEXEC);

  struct bp_child_guard guard;
  if (bp_child_guard_begin (&guard) < 0)
    { close (master); close (statpipe[0]); close (statpipe[1]); free (argv);
      builtin_error ("SIGCHLD guard: %s", strerror (errno)); return EXECUTION_FAILURE; }

  pid_t intermediate = fork ();
  if (intermediate < 0)
    { bp_child_guard_parent_end (&guard); close (master); close (statpipe[0]); close (statpipe[1]); free (argv);
      builtin_error ("fork: %s", strerror (errno)); return EXECUTION_FAILURE; }

  if (intermediate == 0)
    {
      bp_child_guard_child_end (&guard);
      /* Intermediate: forks the actual target, waits, writes status. */
      close (master);
      close (statpipe[0]);
      struct bp_child_guard target_guard;
      if (bp_child_guard_begin (&target_guard) < 0)
        {
          dprintf (2, "pty spawn intermediate: SIGCHLD guard: %s\n", strerror (errno));
          _exit (126);
        }
      pid_t target = fork ();
      if (target < 0)
        {
          bp_child_guard_parent_end (&target_guard);
          dprintf (2, "pty spawn intermediate: fork: %s\n", strerror (errno));
          _exit (126);
        }
      if (target == 0)
        {
          bp_child_guard_child_end (&target_guard);
          /* Target: set up pty + exec. Errors before dup2 go to
             original stderr (visible to user); errors after (exec
             failure) go to the slave → master → caller's EXP_BUF. */
          close (statpipe[1]);
          if (setsid () < 0)
            { dprintf (2, "pty spawn child: setsid: %s\n", strerror (errno)); _exit (126); }
          int slave = open (slave_path, O_RDWR);
          if (slave < 0)
            { dprintf (2, "pty spawn child: open(%s): %s\n", slave_path, strerror (errno)); _exit (126); }
          if (ioctl (slave, TIOCSCTTY, 0) < 0)
            { dprintf (2, "pty spawn child: TIOCSCTTY: %s\n", strerror (errno)); _exit (126); }
          if (dup2 (slave, 0) < 0 || dup2 (slave, 1) < 0 || dup2 (slave, 2) < 0)
            { dprintf (2, "pty spawn child: dup2: %s\n", strerror (errno)); _exit (126); }
          if (slave > 2) close (slave);
          bos_prepare_child ();
          bos_run_builtin (argv[0], argv, NULL);
          execvp (argv[0], argv);
          dprintf (2, "pty spawn child: execvp(%s): %s\n", argv[0], strerror (errno));
          _exit (127);
        }
      /* Intermediate waits for target. Send target PID first so the
         caller can identify the actual process for kill / proc lookups,
         then send the encoded exit code. */
      ssize_t w = write (statpipe[1], &target, sizeof target);
      (void) w;
      int status = 0;
      pid_t waited;
      while ((waited = waitpid (target, &status, 0)) < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      bp_child_guard_parent_end (&target_guard);
      int exit_code = waited == target && WIFEXITED (status) ? WEXITSTATUS (status)
                    : WIFSIGNALED (status) ? 128 + WTERMSIG (status)
                    : 1;
      w = write (statpipe[1], &exit_code, sizeof exit_code);
      (void) w;
      close (statpipe[1]);
      _exit (0);
    }

  /* Original bash. Read the target's PID from the pipe; status comes
     later (when caller invokes pty waitpid). Stash the read fd in
     the static slot keyed off target PID. */
  free (argv);
  close (statpipe[1]);
  pid_t target_pid;
  if (read (statpipe[0], &target_pid, sizeof target_pid) != (ssize_t) sizeof target_pid)
    {
      bp_child_guard_parent_end (&guard);
      close (master); close (statpipe[0]);
      builtin_error ("spawn: short read from intermediate (target PID lost)");
      return EXECUTION_FAILURE;
    }
  bp_child_guard_parent_end (&guard);
  /* Stash <intermediate_pid, statpipe[0]> for the matching waitpid call.
     Since expect-style use is single-child-at-a-time per shell, a
     single-slot stash is enough. If you need parallel spawns, extend
     to a small array. */
  bp_stash_intermediate (target_pid, statpipe[0]);

  char buf[32];
  snprintf (buf, sizeof buf, "%d", master);
  builtin_bind_variable ((char *) fdvar, buf, 0);
  snprintf (buf, sizeof buf, "%d", (int) target_pid);
  builtin_bind_variable ((char *) pidvar, buf, 0);
  return EXECUTION_SUCCESS;
}

/* waitpid: read the target's exit status from the pipe stashed by
 * the matching `pty spawn`. Direct waitpid(2) doesn't work
 * because bash's interactive SIGCHLD handler reaps spawn'd children
 * eagerly — by the time userspace gets a chance to call waitpid,
 * ECHILD. The double-fork in spawn moves the actual target one level
 * down (parented by an intermediate that bash CAN reap), and pipes
 * the status back here.
 *
 * Exit status convention matches the shell: 0..255 for clean exit,
 * 128 + signum for signal death.
 */
static int
bp_waitpid_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("waitpid needs PID [STATUSVAR]"); return EX_USAGE; }
  pid_t pid = (pid_t) atoi (args->word->word);
  const char *statusvar = (args->next) ? args->next->word->word : NULL;

  if (bp_stash.pipe_fd < 0 || bp_stash.target_pid != pid)
    {
      builtin_error ("waitpid %d: no stashed status (was this PID spawn'd?)",
                     (int) pid);
      return EXECUTION_FAILURE;
    }

  int exit_code;
  ssize_t r = read (bp_stash.pipe_fd, &exit_code, sizeof exit_code);
  close (bp_stash.pipe_fd);
  bp_stash.pipe_fd = -1;
  bp_stash.target_pid = 0;

  if (r != (ssize_t) sizeof exit_code)
    {
      builtin_error ("waitpid %d: short read from status pipe (rc=%zd)",
                     (int) pid, r);
      return EXECUTION_FAILURE;
    }

  if (statusvar)
    {
      char buf[32];
      snprintf (buf, sizeof buf, "%d", exit_code);
      builtin_bind_variable ((char *) statusvar, buf, 0);
    }
  return exit_code;
}

/* echo FD on|off — toggle ECHO/ECHOE/ECHOK/ECHONL on the line
   discipline backing FD (master pty fd works on Linux because both
   ends share line-discipline state). Used by expect.sh for password
   prompts. */
static int
bp_echo_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("echo needs FD on|off"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  const char *mode = args->next->word->word;
  int on;
  if      (strcmp (mode, "on")  == 0 || strcmp (mode, "1") == 0) on = 1;
  else if (strcmp (mode, "off") == 0 || strcmp (mode, "0") == 0) on = 0;
  else { builtin_error ("echo: mode must be on|off (got '%s')", mode); return EX_USAGE; }

  struct termios tio;
  if (tcgetattr (fd, &tio) < 0)
    { builtin_error ("tcgetattr: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (on)
    tio.c_lflag |=  (ECHO | ECHOE | ECHOK | ECHONL);
  else
    tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  if (tcsetattr (fd, TCSANOW, &tio) < 0)
    { builtin_error ("tcsetattr: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* resize FD -W cols -H rows — set winsize on master fd; kernel
   delivers SIGWINCH to the foreground process group on the slave.
   Also accepts positional FD COLS ROWS form for terseness. */
static int
bp_resize_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("resize needs FD -W COLS -H ROWS (or FD COLS ROWS)"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  int cols = -1, rows = -1;
  WORD_LIST *p = args->next;

  /* Try positional first: FD COLS ROWS */
  if (p && p->next && p->word->word[0] != '-')
    {
      cols = atoi (p->word->word);
      rows = atoi (p->next->word->word);
    }
  else
    {
      for (; p; p = p->next)
        {
          const char *w = p->word->word;
          if      ((!strcmp (w, "-W") || !strcmp (w, "--cols")) && p->next)
            { cols = atoi (p->next->word->word); p = p->next; }
          else if ((!strcmp (w, "-H") || !strcmp (w, "--rows")) && p->next)
            { rows = atoi (p->next->word->word); p = p->next; }
          else
            { builtin_error ("resize: unknown arg '%s'", w); return EX_USAGE; }
        }
    }
  if (cols <= 0 || rows <= 0)
    { builtin_error ("resize: cols and rows must be > 0 (got %d %d)", cols, rows); return EX_USAGE; }

  struct winsize ws = { .ws_row = (unsigned short) rows,
                        .ws_col = (unsigned short) cols,
                        .ws_xpixel = 0, .ws_ypixel = 0 };
  if (ioctl (fd, TIOCSWINSZ, &ws) < 0)
    { builtin_error ("TIOCSWINSZ: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static WORD_LIST *
bp_arg_at (WORD_LIST *args, int index)
{
  WORD_LIST *p = args;
  for (int i = 0; p && i < index; i++)
    p = p->next;
  return p;
}

static int
bp_parse_int_arg (const char *s, const char *what, int *out)
{
  char *end = NULL;
  long v;
  errno = 0;
  v = strtol (s, &end, 0);
  if (errno || end == s || *end != '\0')
    {
      builtin_error ("set-ldisc: invalid %s: %s", what, s);
      return -1;
    }
  *out = (int) v;
  return 0;
}

static int
bp_parse_ulong_arg (const char *s, const char *what, unsigned long *out)
{
  char *end = NULL;
  unsigned long v;
  errno = 0;
  v = strtoul (s, &end, 0);
  if (errno || end == s || *end != '\0')
    {
      builtin_error ("set-ldisc: invalid %s: %s", what, s);
      return -1;
    }
  *out = v;
  return 0;
}

static int
bp_speed_constant (int speed, speed_t *out)
{
  switch (speed)
    {
    case 0: *out = B0; return 0;
#ifdef B50
    case 50: *out = B50; return 0;
#endif
#ifdef B75
    case 75: *out = B75; return 0;
#endif
#ifdef B110
    case 110: *out = B110; return 0;
#endif
#ifdef B134
    case 134: *out = B134; return 0;
#endif
#ifdef B150
    case 150: *out = B150; return 0;
#endif
#ifdef B200
    case 200: *out = B200; return 0;
#endif
#ifdef B300
    case 300: *out = B300; return 0;
#endif
#ifdef B600
    case 600: *out = B600; return 0;
#endif
#ifdef B1200
    case 1200: *out = B1200; return 0;
#endif
#ifdef B1800
    case 1800: *out = B1800; return 0;
#endif
#ifdef B2400
    case 2400: *out = B2400; return 0;
#endif
#ifdef B4800
    case 4800: *out = B4800; return 0;
#endif
#ifdef B9600
    case 9600: *out = B9600; return 0;
#endif
#ifdef B19200
    case 19200: *out = B19200; return 0;
#endif
#ifdef B38400
    case 38400: *out = B38400; return 0;
#endif
#ifdef B57600
    case 57600: *out = B57600; return 0;
#endif
#ifdef B115200
    case 115200: *out = B115200; return 0;
#endif
#ifdef B230400
    case 230400: *out = B230400; return 0;
#endif
#ifdef B460800
    case 460800: *out = B460800; return 0;
#endif
#ifdef B500000
    case 500000: *out = B500000; return 0;
#endif
#ifdef B576000
    case 576000: *out = B576000; return 0;
#endif
#ifdef B921600
    case 921600: *out = B921600; return 0;
#endif
#ifdef B1000000
    case 1000000: *out = B1000000; return 0;
#endif
#ifdef B1152000
    case 1152000: *out = B1152000; return 0;
#endif
#ifdef B1500000
    case 1500000: *out = B1500000; return 0;
#endif
#ifdef B2000000
    case 2000000: *out = B2000000; return 0;
#endif
#ifdef B2500000
    case 2500000: *out = B2500000; return 0;
#endif
#ifdef B3000000
    case 3000000: *out = B3000000; return 0;
#endif
#ifdef B3500000
    case 3500000: *out = B3500000; return 0;
#endif
#ifdef B4000000
    case 4000000: *out = B4000000; return 0;
#endif
    default:
      return -1;
    }
}

static int
bp_have_cap_sys_admin (void)
{
  FILE *fp = fopen ("/proc/self/status", "r");
  if (!fp)
    return 0;

  char line[256];
  int have = 0;
  while (fgets (line, sizeof line, fp))
    {
      if (strncmp (line, "CapEff:", 7) == 0)
        {
          char *p = line + 7;
          while (*p == ' ' || *p == '\t') p++;
          errno = 0;
          unsigned long long caps = strtoull (p, NULL, 16);
          if (!errno && (caps & (1ULL << 21)) != 0)
            have = 1;
          break;
        }
    }
  fclose (fp);
  return have;
}

static int
bp_set_ldisc_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    {
      builtin_error ("set-ldisc needs LDISC DEVICE [SPEED|-] [CSIZE|-] [PARITY|-] [STOPBITS|-] [IFLAG_SET|-] [IFLAG_CLEAR|-]");
      return EX_USAGE;
    }

  int ldisc = 0;
  if (bp_parse_int_arg (args->word->word, "line discipline", &ldisc) < 0)
    return EX_USAGE;
  const char *device = args->next->word->word;

  const char *speed_s = bp_arg_at (args, 2) ? bp_arg_at (args, 2)->word->word : "-";
  const char *csize_s = bp_arg_at (args, 3) ? bp_arg_at (args, 3)->word->word : "-";
  const char *parity_s = bp_arg_at (args, 4) ? bp_arg_at (args, 4)->word->word : "-";
  const char *stop_s = bp_arg_at (args, 5) ? bp_arg_at (args, 5)->word->word : "-";
  const char *iflag_set_s = bp_arg_at (args, 6) ? bp_arg_at (args, 6)->word->word : "-";
  const char *iflag_clear_s = bp_arg_at (args, 7) ? bp_arg_at (args, 7)->word->word : "-";

  int fd = open (device, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("set-ldisc: open %s: %s", device, strerror (errno));
      return EXECUTION_FAILURE;
    }

  struct stat st;
  if (fstat (fd, &st) < 0)
    {
      builtin_error ("set-ldisc: fstat %s: %s", device, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  if (!S_ISCHR (st.st_mode) || !isatty (fd))
    {
      builtin_error ("set-ldisc: %s is not a serial line", device);
      close (fd);
      return EXECUTION_FAILURE;
    }

  if (!bp_have_cap_sys_admin ())
    {
      builtin_error ("set-ldisc: cannot set line discipline: Operation not permitted");
      close (fd);
      return EXECUTION_FAILURE;
    }

  int need_termios = 0;
  int speed = -1, csize = 0, stopbits = 0;
  unsigned long iflag_set = 0, iflag_clear = 0;
  speed_t speed_const = 0;

  if (speed_s && strcmp (speed_s, "-") != 0)
    {
      if (bp_parse_int_arg (speed_s, "speed", &speed) < 0)
        { close (fd); return EX_USAGE; }
      if (bp_speed_constant (speed, &speed_const) < 0)
        {
          builtin_error ("set-ldisc: unsupported speed: %d", speed);
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (csize_s && strcmp (csize_s, "-") != 0)
    {
      if (bp_parse_int_arg (csize_s, "character size", &csize) < 0)
        { close (fd); return EX_USAGE; }
      if (csize != 7 && csize != 8)
        {
          builtin_error ("set-ldisc: character size must be 7 or 8");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (parity_s && strcmp (parity_s, "-") != 0)
    {
      if (strcmp (parity_s, "none") != 0 && strcmp (parity_s, "even") != 0
          && strcmp (parity_s, "odd") != 0)
        {
          builtin_error ("set-ldisc: parity must be none|even|odd");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (stop_s && strcmp (stop_s, "-") != 0)
    {
      if (bp_parse_int_arg (stop_s, "stop bits", &stopbits) < 0)
        { close (fd); return EX_USAGE; }
      if (stopbits != 1 && stopbits != 2)
        {
          builtin_error ("set-ldisc: stop bits must be 1 or 2");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (iflag_set_s && strcmp (iflag_set_s, "-") != 0)
    {
      if (bp_parse_ulong_arg (iflag_set_s, "iflag set mask", &iflag_set) < 0)
        { close (fd); return EX_USAGE; }
      need_termios = 1;
    }
  if (iflag_clear_s && strcmp (iflag_clear_s, "-") != 0)
    {
      if (bp_parse_ulong_arg (iflag_clear_s, "iflag clear mask", &iflag_clear) < 0)
        { close (fd); return EX_USAGE; }
      need_termios = 1;
    }

  if (need_termios)
    {
      struct termios tio;
      if (tcgetattr (fd, &tio) < 0)
        {
          builtin_error ("set-ldisc: tcgetattr %s: %s", device, strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
      if (speed >= 0)
        {
          if (cfsetispeed (&tio, speed_const) < 0 || cfsetospeed (&tio, speed_const) < 0)
            {
              builtin_error ("set-ldisc: cfsetspeed %d: %s", speed, strerror (errno));
              close (fd);
              return EXECUTION_FAILURE;
            }
        }
      if (csize)
        {
          tio.c_cflag &= ~CSIZE;
          tio.c_cflag |= (csize == 7) ? CS7 : CS8;
        }
      if (parity_s && strcmp (parity_s, "-") != 0)
        {
          if (strcmp (parity_s, "none") == 0)
            tio.c_cflag &= ~(PARENB | PARODD);
          else if (strcmp (parity_s, "even") == 0)
            {
              tio.c_cflag |= PARENB;
              tio.c_cflag &= ~PARODD;
            }
          else
            tio.c_cflag |= (PARENB | PARODD);
        }
      if (stopbits)
        {
          if (stopbits == 2)
            tio.c_cflag |= CSTOPB;
          else
            tio.c_cflag &= ~CSTOPB;
        }
      tio.c_iflag |= (tcflag_t) iflag_set;
      tio.c_iflag &= ~((tcflag_t) iflag_clear);
      if (tcsetattr (fd, TCSANOW, &tio) < 0)
        {
          builtin_error ("set-ldisc: tcsetattr %s: %s", device, strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
    }

  if (ioctl (fd, TIOCSETD, &ldisc) < 0)
    {
      builtin_error ("set-ldisc: TIOCSETD %s: %s", device, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }

  close (fd);
  return EXECUTION_SUCCESS;
}

int
pty_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "setsid")     == 0) return bp_setsid_cmd (args);
  if (strcmp (cmd, "open-tty")   == 0) return bp_open_tty_cmd (args);
  if (strcmp (cmd, "isatty")     == 0) return bp_isatty_cmd (args);
  if (strcmp (cmd, "tty-name")   == 0) return bp_ttyname_cmd (args);
  if (strcmp (cmd, "foreground") == 0) return bp_foreground_cmd (args);
  if (strcmp (cmd, "close")      == 0) return bp_close_cmd (args);
  if (strcmp (cmd, "spawn")      == 0) return bp_spawn_cmd (args);
  if (strcmp (cmd, "waitpid")    == 0) return bp_waitpid_cmd (args);
  if (strcmp (cmd, "echo")       == 0) return bp_echo_cmd (args);
  if (strcmp (cmd, "resize")     == 0) return bp_resize_cmd (args);
  if (strcmp (cmd, "set-ldisc")  == 0) return bp_set_ldisc_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *pty_doc[] = {
  "TTY + session management primitives for bash-os getty / login.",
  "",
  "    pty setsid",
  "        Become a new session leader (no controlling tty).",
  "    pty open-tty PATH [FDVAR]",
  "        Open PATH (a /dev/tty*) and install as controlling tty.",
  "        Default: dup2 to 0/1/2. With FDVAR: bind $FDVAR, leave",
  "        stdio alone.",
  "    pty isatty FD",
  "        Exit 0 if FD is a terminal.",
  "    pty tty-name FD",
  "        Print the device path of the tty backing FD.",
  "    pty foreground PGRP [FD]",
  "        tcsetpgrp — give PGRP the foreground (FD defaults to 0).",
  "    pty close FD",
  "        close(2) wrapper.",
  "    pty spawn FDVAR PIDVAR CMD [ARG ...]",
  "        Fork+exec CMD on a fresh pty. Master fd → $FDVAR,",
  "        child pid → $PIDVAR. Used by /bash-os/expect.sh.",
  "    pty waitpid PID [STATUSVAR]",
  "        Blocking waitpid(2) on PID; sets $? (and $STATUSVAR) to",
  "        the child's exit status. Use this for spawn'd children —",
  "        bash's `wait` builtin doesn't see them.",
  "    pty echo FD on|off",
  "        Toggle ECHO/ECHOE/ECHOK/ECHONL on FD's line discipline.",
  "        On a spawn'd master fd, this affects what the child sees",
  "        (echo on / off for password prompts).",
  "    pty resize FD -W COLS -H ROWS",
  "        TIOCSWINSZ on FD. Kernel sends SIGWINCH to the slave's",
  "        foreground process group. Also accepts FD COLS ROWS positional.",
  "    pty set-ldisc LDISC DEVICE [SPEED|-] [CSIZE|-] [PARITY|-]",
  "        [STOPBITS|-] [IFLAG_SET|-] [IFLAG_CLEAR|-]",
  "        Gated TIOCSETD + optional termios setup for ldattach.",
  "",
  "Typical getty flow:",
  "    ( pty setsid; pty open-tty /dev/ttyS0; exec login ) &",
  (char *)NULL
};

struct builtin pty_struct = {
  "pty",
  pty_builtin,
  BUILTIN_ENABLED,
  pty_doc,
  "pty setsid|open-tty|isatty|tty-name|foreground|close|spawn|waitpid|echo|resize|set-ldisc ARGS...",
  0
};
