/* SPDX-License-Identifier: MIT */
/* sudo fixture. The production doas.c/sudo.c parser, dispatcher, request
 * construction and digest, credential helper, child setup, external fallback
 * and sudoedit orchestration are included verbatim, as are the shared
 * sudoedit safe-open and atomic-copyback helpers. Only the account files,
 * credential syscalls, the authority device, isatty and exec are substituted,
 * at compile time. Requests are recorded in shared memory, so requests made by
 * forked production children are checked by the parent. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "_bashos_auth_uapi.h"
#include "_bashauth/sudoedit.h"

static int checks;
#define CHECK(x) do { if (!(x)) { fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); abort (); } checks++; } while (0)

#define MAXREQ 40
#define MAXFD 16
typedef struct {
  unsigned long op;
  pid_t pid;
  struct bashos_auth_privcmd p;		/* AUTHZ request as received */
  struct bashos_auth_exec_verify_req v;
  struct bashos_auth_exec_handoff_req h;
  unsigned char argv[4096];
  unsigned argv_bytes;
  unsigned char env[4096];
  unsigned env_bytes;
  int fd_cloexec;
  unsigned nfds;
  int fd_rdonly[MAXFD];
  char fd_data[MAXFD][64];
} req_t;

typedef struct {
  int nreq;
  req_t req[MAXREQ];
  int authz_calls;
  /* root-path execve capture */
  int execs;
  char path[256];
  int argc;
  char argv[16][256];
  int envc;
  char env[48][256];
  char cwd[PATH_MAX];
  int open_fds, sigusr1_blocked, sigterm_dfl, nnp;
  char cred_order[8];
  gid_t groups[64];
  int ngroups;
  uid_t uid;
  gid_t gid;
  /* execvp capture: editor or external delegate */
  int spawns;
  int spawn_argc;
  char spawn_argv[24][256];
  int spawn_open_fds;
  /* SUDO_COMMAND can be 4096 argument bytes plus a short prefix. */
  char sudo_command[8192];
  int sudo_command_len;
  int argv_words_ok;
  int argv1_len;
} shared_t;
static shared_t *S;

typedef struct { unsigned decision; int nohandle; const char *reason; int err; } reply_t;
static reply_t R[8];
static int nR;
static int root_route, tty_mode, auth_absent, verify_fail, cred_fail;
static int handoff_err, handoff_approval, handoff_exit;
static int open_mode, copyback_drift, exec_real, capture_exit;
static char scratch[PATH_MAX], passwd_path[PATH_MAX], group_path[PATH_MAX];
static char last_error[1024];
static int quiet;
static int io_read_fail, io_write_fail, io_read_eintr, io_write_eintr;
static int big_expect_on, big_expect_argc;
static const char *big_expect_word;
static const char *caller_shell = "/bin/sh";

/* Account rows are real private files parsed by the production readers. */
static FILE *
fixture_fopen (const char *path, const char *mode)
{
  if (!strcmp (path, "/etc/passwd")) return fopen (passwd_path, mode);
  if (!strcmp (path, "/etc/group")) return fopen (group_path, mode);
  return fopen (path, mode);
}
static uid_t fixture_geteuid (void) { return root_route ? 0 : getuid (); }
static void
cred_step (char c)
{
  size_t n = strlen (S->cred_order);
  if (n + 1 < sizeof S->cred_order) { S->cred_order[n] = c; S->cred_order[n + 1] = 0; }
}
static int
fixture_setgroups (size_t n, const gid_t *g)
{
  cred_step ('G');
  if (cred_fail == 1) { errno = EPERM; return -1; }
  CHECK (n <= 64);
  S->ngroups = (int) n;
  memcpy (S->groups, g, n * sizeof *g);
  return 0;
}
static int
fixture_setresgid (gid_t r, gid_t e, gid_t s)
{
  cred_step ('g');
  if (cred_fail == 2) { errno = EPERM; return -1; }
  CHECK (r == e && e == s);
  S->gid = r;
  return 0;
}
static int
fixture_setresuid (uid_t r, uid_t e, uid_t s)
{
  cred_step ('u');
  if (cred_fail == 3) { errno = EPERM; return -1; }
  CHECK (r == e && e == s);
  S->uid = r;
  return 0;
}
static int fixture_getresuid (uid_t *r, uid_t *e, uid_t *s) { *r = *e = *s = S->uid + (cred_fail == 4); return 0; }
static int fixture_getresgid (gid_t *r, gid_t *e, gid_t *s) { *r = *e = *s = S->gid; return 0; }
#define fopen fixture_fopen
#define geteuid fixture_geteuid
#define setgroups fixture_setgroups
#define setresuid fixture_setresuid
#define setresgid fixture_setresgid
#define getresuid fixture_getresuid
#define getresgid fixture_getresgid
#include "common/bashcred_privdrop.h"
#undef setgroups
#undef setresuid
#undef setresgid
#undef getresuid
#undef getresgid

static int count_open_fds (void)
{
  int n = 0;
  for (int fd = 3; fd < 1024; fd++)
    if (fcntl (fd, F_GETFD) >= 0) n++;
  return n;
}

static int
fixture_open (const char *p, int flags, ...)
{
  if (!strcmp (p, "/dev/bashos-auth"))
    {
      if (auth_absent) { errno = ENOENT; return -1; }
      return open ("/dev/null", flags);
    }
  return open (p, flags);
}
static int fixture_isatty (int fd) { (void) fd; return tty_mode; }

static void
capture_strings (char dst[][256], int max, int *countp, char *const *src)
{
  int n = 0;
  for (; src && src[n]; n++)
    {
      CHECK (n < max);
      CHECK (strlen (src[n]) < 256);
      strcpy (dst[n], src[n]);
    }
  *countp = n;
}

static ssize_t
fixture_status_read (int fd, void *buf, size_t n)
{
  if (io_read_eintr > 0)
    {
      io_read_eintr--;
      errno = EINTR;
      return -1;
    }
  if (io_read_fail > 0)
    {
      char sink;
      io_read_fail--;
      /* Let the child deliver its byte before the failure is reported, so
         closing the pipe afterwards cannot SIGPIPE the writer. */
      for (;;)
        {
          ssize_t nread = read (fd, &sink, 1);
          if (nread < 0 && errno == EINTR)
            continue;
          break;
        }
      errno = EIO;
      return -1;
    }
  return read (fd, buf, n);
}
static ssize_t
fixture_status_write (int fd, const void *buf, size_t n)
{
  if (io_write_eintr > 0)
    {
      io_write_eintr--;
      errno = EINTR;
      return -1;
    }
  if (io_write_fail > 0)
    {
      io_write_fail--;
      errno = EIO;
      return -1;
    }
  return write (fd, buf, n);
}

static int
fixture_execve (const char *p, char *const *a, char *const *e)
{
  sigset_t mask;
  struct sigaction sa;
  int stored = 0;
  S->execs++;
  CHECK (strlen (p) < sizeof S->path);
  strcpy (S->path, p);
  /* Keep every short slot the older assertions read, and also record a long
     argv and SUDO_COMMAND without aborting. */
  S->argc = 0;
  S->argv1_len = 0;
  S->argv_words_ok = 1;
  S->sudo_command_len = -1;
  for (int n = 0; a && a[n]; n++)
    {
      size_t L = strlen (a[n]);
      if (n == 1)
        S->argv1_len = (int) L;
      if (big_expect_on)
        {
          const char *want = n == 0 ? "/bin/true" : big_expect_word;
          if (!want || strcmp (a[n], want) != 0)
            S->argv_words_ok = 0;
        }
      if (n < 16 && L < 256)
        memcpy (S->argv[n], a[n], L + 1);
      S->argc++;
    }
  if (big_expect_on && S->argc != big_expect_argc)
    S->argv_words_ok = 0;
  for (int n = 0; e && e[n]; n++)
    {
      size_t L = strlen (e[n]);
      if (L >= 13 && strncmp (e[n], "SUDO_COMMAND=", 13) == 0)
        {
          size_t vl = L - 13;
          size_t copy = vl < sizeof S->sudo_command - 1 ? vl : sizeof S->sudo_command - 1;
          S->sudo_command_len = (int) vl;
          memcpy (S->sudo_command, e[n] + 13, copy);
          S->sudo_command[copy] = 0;
        }
      if (stored < 48 && L < 256)
        memcpy (S->env[stored++], e[n], L + 1);
    }
  S->envc = stored;
  if (!getcwd (S->cwd, sizeof S->cwd)) S->cwd[0] = 0;
  S->open_fds = count_open_fds ();
  S->sigusr1_blocked = sigprocmask (SIG_SETMASK, NULL, &mask) == 0 && sigismember (&mask, SIGUSR1);
  S->sigterm_dfl = sigaction (SIGTERM, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL;
  S->nnp = prctl (PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  if (exec_real)
    return execve (p, a, e);
  _exit (capture_exit);
}

static int
fixture_execvp (const char *file, char *const *args)
{
  S->spawns++;
  capture_strings (S->spawn_argv, 24, &S->spawn_argc, args);
  S->spawn_open_fds = count_open_fds ();
  if (!strcmp (file, "/bin/vi"))
    _exit (0);			/* never start an interactive editor */
  return execvp (file, args);
}

static req_t *
record (unsigned long op)
{
  CHECK (S->nreq < MAXREQ);
  req_t *q = &S->req[S->nreq++];
  memset (q, 0, sizeof *q);
  q->op = op;
  q->pid = getpid ();
  return q;
}
static void
copy_blob (unsigned char *dst, unsigned *bytesp, unsigned long long ptr, unsigned bytes, size_t cap)
{
  CHECK (bytes <= cap);
  CHECK (!bytes || ptr);
  if (bytes) memcpy (dst, (void *) (uintptr_t) ptr, bytes);
  *bytesp = bytes;
}

/* sudoedit OPEN/COPYBACK use the shared safe-open and atomic-copyback helpers
   on the real private originals; only root mediation is simulated. */
static bashos_sudoedit_identity open_ids[16];
static char open_targets[16][PATH_MAX], temp_paths[16][PATH_MAX];
static int open_n;

static int
fixture_sudoedit_open (struct bashos_auth_exec_handoff_req *h)
{
  char *out = (char *) (uintptr_t) h->sudoedit_temp_paths_user_ptr;
  const char *a = (const char *) (uintptr_t) h->argv_user_ptr;
  size_t bytes = 0;
  if (open_mode == 6) { errno = ENOSYS; return -1; }
  if (open_mode == 7) { h->approval_status = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED; h->reject_stage = 4; return 0; }
  open_n = (int) h->argc;
  for (int i = 0; i < open_n; i++, a += strlen (a) + 1)
    {
      int fd, t;
      char buf[4096];
      ssize_t n;
      CHECK (strlen (a) < PATH_MAX);
      strcpy (open_targets[i], a);
      if (bashos_sudoedit_safe_open (a, &fd, &open_ids[i]) != BASHOS_SE_OK)
        { h->approval_status = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED; h->reject_stage = 10 + i; return 0; }
      snprintf (temp_paths[i], sizeof temp_paths[i], "%s/temp%d", scratch, i);
      t = open (temp_paths[i], O_CREAT | O_EXCL | O_WRONLY, 0600);
      CHECK (t >= 0);
      while ((n = read (fd, buf, sizeof buf)) > 0) CHECK (write (t, buf, (size_t) n) == n);
      close (t);
      close (fd);
      size_t len = strlen (temp_paths[i]) + 1;
      CHECK (bytes + len <= h->sudoedit_temp_paths_cap);
      memcpy (out + bytes, temp_paths[i], len);
      bytes += len;
    }
  h->sudoedit_temp_paths_bytes = (unsigned) bytes;
  h->sudoedit_temp_count = (unsigned) open_n;
  h->approval_status = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;
  if (open_mode == 1) h->sudoedit_temp_count = (unsigned) open_n + 1;
  if (open_mode == 2) h->sudoedit_temp_paths_bytes = 0;
  if (open_mode == 3) h->sudoedit_temp_paths_bytes = h->sudoedit_temp_paths_cap + 1;
  if (open_mode == 4) h->sudoedit_temp_paths_bytes = (unsigned) bytes - 1;	/* unterminated */
  if (open_mode == 5) out[0] = 0;						/* empty first path */
  return 0;
}

static int
fixture_sudoedit_copyback (struct bashos_auth_exec_handoff_req *h, req_t *q)
{
  unsigned *fds = (unsigned *) (uintptr_t) h->sudoedit_temp_fds_user_ptr;
  CHECK (h->sudoedit_temp_fds_count == (unsigned) open_n && h->sudoedit_temp_fds_count <= MAXFD);
  q->nfds = h->sudoedit_temp_fds_count;
  for (unsigned i = 0; i < q->nfds; i++)
    {
      int fl = fcntl ((int) fds[i], F_GETFL);
      q->fd_rdonly[i] = fl >= 0 && (fl & O_ACCMODE) == O_RDONLY;
      ssize_t n = pread ((int) fds[i], q->fd_data[i], sizeof q->fd_data[i] - 1, 0);
      CHECK (n >= 0);
    }
  if (copyback_drift < 0) { errno = ENOSYS; return -1; }
  for (unsigned i = 0; i < q->nfds; i++)
    if (bashos_sudoedit_atomic_copyback (open_targets[i], (int) fds[i], &open_ids[i]) != BASHOS_SE_OK)
      {
        h->approval_status = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED;
        h->reject_stage = 100 + i;	/* earlier targets stay committed */
        return 0;
      }
  h->approval_status = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;
  return 0;
}

static int
fixture_ioctl (int fd, unsigned long op, ...)
{
  va_list ap;
  va_start (ap, op);
  void *v = va_arg (ap, void *);
  va_end (ap);
  if (op == BASHOS_AUTH_IOC_VERSION)
    {
      struct bashos_auth_version *r = v;
      r->abi_major = BASHOS_AUTH_ABI_MAJOR;
      r->abi_minor = BASHOS_AUTH_ABI_MINOR;
      r->features = BASHOS_AUTH_FEAT_PRIVCMD;
      return 0;
    }
  req_t *q = record (op);
  q->fd_cloexec = (fcntl (fd, F_GETFD) & FD_CLOEXEC) != 0;
  if (op == BASHOS_AUTH_IOC_PRIVCMD_AUTHZ)
    {
      struct bashos_auth_privcmd *r = v;
      q->p = *r;
      copy_blob (q->argv, &q->argv_bytes, r->argv_user_ptr, r->argv_bytes, sizeof q->argv);
      copy_blob (q->env, &q->env_bytes, r->env_user_ptr, r->env_bytes, sizeof q->env);
      int call = S->authz_calls++;
      reply_t *rep = &R[call < nR ? call : nR - 1];
      if (rep->err) { errno = rep->err; return -1; }
      r->decision = rep->decision;
      r->handle_id = rep->nohandle ? 0 : 100 + call;
      r->policy_generation = 7;
      r->timestamp_timeout = 300;
      r->audit_id = 900 + call;
      if (rep->reason) snprintf (r->reason, sizeof r->reason, "%s", rep->reason);
      return 0;
    }
  if (op == BASHOS_AUTH_IOC_EXEC_VERIFY)
    {
      q->v = *(struct bashos_auth_exec_verify_req *) v;
      if (verify_fail) { errno = EACCES; return -1; }
      return 0;
    }
  if (op == BASHOS_AUTH_IOC_EXEC_INTERACTIVE)
    {
      struct bashos_auth_exec_handoff_req *h = v;
      q->h = *h;
      copy_blob (q->argv, &q->argv_bytes, h->argv_user_ptr, h->argv_bytes, sizeof q->argv);
      if (handoff_err) { h->reject_stage = 3; errno = EACCES; return -1; }
      _exit (handoff_exit);		/* the kernel replaces the owned child */
    }
  if (op == BASHOS_AUTH_IOC_EXEC_HANDOFF)
    {
      struct bashos_auth_exec_handoff_req *h = v;
      int rc = 0;
      copy_blob (q->argv, &q->argv_bytes, h->argv_user_ptr, h->argv_bytes, sizeof q->argv);
      if (h->flags == BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN)
        rc = fixture_sudoedit_open (h);
      else if (h->flags == BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_COPYBACK)
        rc = fixture_sudoedit_copyback (h, q);
      else if (handoff_err) { errno = EACCES; rc = -1; }
      else { h->approval_status = handoff_approval; h->exit_code = handoff_exit; }
      q->h = *h;
      return rc;
    }
  CHECK (0);
  return -1;
}

#define open fixture_open
#define ioctl fixture_ioctl
#define isatty fixture_isatty
#define execve fixture_execve
#define execvp fixture_execvp
#define read fixture_status_read
#define write fixture_status_write
static int fixture_nnp (char *err, size_t len)
{
  if (cred_fail == 5) { snprintf (err, len, "injected"); errno = EPERM; return -1; }
  return bc_no_new_privs (err, len);
}
#define bc_no_new_privs fixture_nnp
#include DOAS_SOURCE
#undef open
#undef ioctl
#undef isatty
#undef execve
#undef execvp
#undef read
#undef write
#undef fopen
#undef geteuid
#undef bc_no_new_privs
#include "../loadables/sudo.c"
#include SUDOEDIT_SOURCE

char **export_env;
void maybe_make_export_env (void) { }
void
builtin_error (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vsnprintf (last_error, sizeof last_error, fmt, ap);
  va_end (ap);
  if (!quiet) fprintf (stderr, "sudo-fixture: %s\n", last_error);
}

/* ---- harness ----------------------------------------------------------- */

static int
dispatchv (int sudo, char **args)
{
  int n = 0;
  while (args[n]) n++;
  WORD_LIST *list = calloc ((size_t) n + 1, sizeof *list);
  WORD_DESC *words = calloc ((size_t) n + 1, sizeof *words);
  CHECK (list && words);
  for (int i = 0; i < n; i++)
    {
      words[i].word = args[i];
      list[i].word = &words[i];
      list[i].next = i + 1 < n ? &list[i + 1] : NULL;
    }
  last_error[0] = 0;
  int rc = sudo ? sudo_builtin (n ? list : NULL) : doas_builtin (n ? list : NULL);
  free (list);
  free (words);
  return rc;
}
#define SUDO(...) dispatchv (1, (char *[]) { __VA_ARGS__, NULL })
#define DOAS(...) dispatchv (0, (char *[]) { __VA_ARGS__, NULL })

static void
reset_state (void)
{
  memset (S, 0, sizeof *S);
  memset (R, 0, sizeof R);
  R[0].decision = BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC;
  nR = 1;
  root_route = tty_mode = auth_absent = verify_fail = cred_fail = 0;
  handoff_err = open_mode = copyback_drift = exec_real = 0;
  handoff_approval = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;
  handoff_exit = 37;
  capture_exit = 41;
  open_n = 0;
  io_read_fail = io_write_fail = io_read_eintr = io_write_eintr = 0;
  big_expect_on = big_expect_argc = 0;
  big_expect_word = NULL;
}
static void
script (int n, ...)
{
  va_list ap;
  va_start (ap, n);
  for (int i = 0; i < n; i++) { memset (&R[i], 0, sizeof R[i]); R[i].decision = va_arg (ap, unsigned); }
  va_end (ap);
  nR = n;
}
static int
count_op (unsigned long op)
{
  int n = 0;
  for (int i = 0; i < S->nreq; i++) n += S->req[i].op == op;
  return n;
}
static req_t *
nth_op (unsigned long op, int k)
{
  for (int i = 0; i < S->nreq; i++)
    if (S->req[i].op == op && k-- == 0) return &S->req[i];
  CHECK (0);
  return NULL;
}
#define AUTHZ(k) nth_op (BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, k)
#define HANDOFF(k) nth_op (BASHOS_AUTH_IOC_EXEC_HANDOFF, k)
static int
blob_is (const unsigned char *b, unsigned bytes, ...)
{
  unsigned char want[4096];
  size_t n = 0;
  va_list ap;
  va_start (ap, bytes);
  for (const char *s; (s = va_arg (ap, const char *)); )
    {
      size_t l = strlen (s) + 1;
      CHECK (n + l <= sizeof want);
      memcpy (want + n, s, l);
      n += l;
    }
  va_end (ap);
  return n == bytes && !memcmp (want, b, n);
}
static int
blob_has (const unsigned char *b, unsigned bytes, const char *entry)
{
  for (unsigned off = 0; off < bytes; off += (unsigned) strlen ((const char *) b + off) + 1)
    if (!strcmp ((const char *) b + off, entry)) return 1;
  return 0;
}
static const char *
env_of (const char *name)
{
  size_t n = strlen (name);
  const char *found = NULL;
  int count = 0;
  for (int i = 0; i < S->envc; i++)
    if (!strncmp (S->env[i], name, n) && S->env[i][n] == '=') { found = S->env[i] + n + 1; count++; }
  CHECK (count <= 1);		/* never a duplicate name */
  return found;
}
static void
write_file (const char *path, const char *text)
{
  FILE *f = fopen (path, "w");
  CHECK (f);
  CHECK (fputs (text, f) >= 0);
  CHECK (fclose (f) == 0);
}
static int
file_is (const char *path, const char *text)
{
  char buf[256] = { 0 };
  int fd = open (path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) return 0;
  ssize_t n = read (fd, buf, sizeof buf - 1);
  close (fd);
  return n >= 0 && !strcmp (buf, text);
}
static int
proc_fds (void)
{
  DIR *d = opendir ("/proc/self/fd");
  CHECK (d);
  int n = 0;
  while (readdir (d)) n++;
  closedir (d);
  return n;
}
static int
temps_gone (void)
{
  for (int i = 0; i < open_n; i++)
    if (access (temp_paths[i], F_OK) == 0) return 0;
  return 1;
}

static char home_dir[PATH_MAX];
static void
accounts (void)
{
  char rows[2048];
  snprintf (home_dir, sizeof home_dir, "%s/home", scratch);
  (void) mkdir (home_dir, 0700);
  snprintf (rows, sizeof rows,
            "# comment\n"
            "root:x:0:0:root:/root:/bin/sh\n"
            "short:x:5000:5000:Short:/tmp\n"
            "fixture:x:4242:4343:Fixture:%s:/bin/sh\n"
            "relshell:x:4300:4300:Rel:/tmp:sh\n"
            "caller:x:%u:%u:Caller:%s:%s\n",
            home_dir, (unsigned) getuid (), (unsigned) getgid (), scratch, caller_shell);
  write_file (passwd_path, rows);
  write_file (group_path,
              "cho:x:1:\n"
              "chosenx:x:2:\n"
              "chosen:x\n"
              "chosen:x:4545:fixture\n"
              "extra:x:4444:other,fixture\n"
              "fixture:x:4343:\n"
              "huge:x:4294967296:\n"
              "neg:x:-1:\n");
}

/* ---- options ----------------------------------------------------------- */

static void
option_tests (void)
{
  /* Bundled and attached short options, long forms, '#uid'. */
  const char *forms[][4] = {
    { "-nu", "fixture", NULL }, { "-nufixture", NULL }, { "-n", "-ufixture", NULL },
    { "-n", "--user", "fixture", NULL }, { "-n", "--user=fixture", NULL },
    { "--non-interactive", "-u", "#4242", NULL }, { "-Hnu", "fixture", NULL },
    { "-Bn", "--user=#4242", NULL },
  };
  for (size_t f = 0; f < sizeof forms / sizeof forms[0]; f++)
    {
      char *args[8];
      int n = 0;
      for (; forms[f][n]; n++) args[n] = (char *) forms[f][n];
      args[n++] = "/bin/true";
      args[n++] = "x";
      args[n] = NULL;
      reset_state ();
      CHECK (dispatchv (1, args) == 37);
      CHECK (S->nreq == 2 && count_op (BASHOS_AUTH_IOC_EXEC_HANDOFF) == 1);
      req_t *a = AUTHZ (0);
      CHECK (a->p.non_interactive == 1 && a->p.target_uid == 4242 && a->p.target_gid == 4343);
      CHECK (!strcmp (a->p.target_user, "fixture") && a->p.mode == BASHOS_AUTH_PRIVCMD_MODE_EXEC);
      CHECK (blob_is (a->argv, a->argv_bytes, "/bin/true", "x", NULL));
    }

  /* -iu: login mode without a command synthesizes [shell, -l]. */
  reset_state ();
  CHECK (SUDO ("-niu", "fixture") == 37);
  CHECK (AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_LOGIN);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", "-l", NULL));
  reset_state ();
  CHECK (SUDO ("-nsu", "fixture") == 37);
  CHECK (AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_SHELL);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", NULL));
  reset_state ();
  CHECK (SUDO ("-n", "-s", "-s", "-u", "fixture") == 37);	/* a repeated mode is one mode */
  reset_state ();
  CHECK (SUDO ("-n", "-i", "-u", "relshell") == 1 && S->nreq == 0);
  CHECK (strstr (last_error, "no valid login shell"));

  /* Usage errors: no authority request is made. */
  const char *usage[][6] = {
    { "-s", "-i", NULL }, { "-is", NULL }, { "--login", "--shell", NULL },
    { "-e", "-s", "/tmp/x", NULL }, { "-v", "-e", "/tmp/x", NULL }, { "-K", "-v", NULL },
    { "-l", "-s", NULL }, { "-e", "-i", "/tmp/x", NULL }, { "-K", "-e", "/tmp/x", NULL },
    { "-K", "/bin/true", NULL }, { "-v", "/bin/true", NULL }, { "-v", "A=1", NULL },
    { "-K", "A=1", NULL }, { "A=1", NULL }, { "-k", "A=1", NULL }, { "-n", "B=2", NULL },
    { "-u", NULL }, { "-nu", NULL }, { "--user", NULL }, { "-g", NULL }, { "--group", NULL },
    { "-E", "/bin/true", NULL }, { "-nE", "/bin/true", NULL }, { "-S", "/bin/true", NULL },
    { "-A", "/bin/true", NULL }, { "-p", "x", "/bin/true", NULL }, { "-b", "/bin/true", NULL },
    { "-P", "/bin/true", NULL }, { "-C", "4", "/bin/true", NULL }, { "-U", "x", "-l", NULL },
    { "-nh", NULL }, { "-nV", NULL }, { "--preserve-env", "/bin/true", NULL },
    { "--preserve-env=PATH", "/bin/true", NULL }, { "--prompt=x", "/bin/true", NULL },
    { "--non", "/bin/true", NULL }, { "--login=x", NULL }, { "--chdir=/", "/bin/true", NULL },
    { "-l", NULL }, { "-ll", NULL }, { "--list", NULL },
  };
  for (size_t u = 0; u < sizeof usage / sizeof usage[0]; u++)
    {
      char *args[8];
      int n = 0;
      for (; usage[u][n]; n++) args[n] = (char *) usage[u][n];
      args[n] = NULL;
      for (int route = 0; route < 2; route++)
        {
          reset_state ();
          root_route = route;
          int rc = dispatchv (1, args);
          if (rc != 2) fprintf (stderr, "usage case %zu route %d rc %d\n", u, route, rc);
          CHECK (rc == 2 && S->nreq == 0 && S->execs == 0 && S->spawns == 0);
        }
    }
  reset_state ();
  CHECK (SUDO ("-s", "-i") == 2 && strstr (last_error, "only one of"));
  reset_state ();
  CHECK (SUDO ("-K", "/bin/true") == 2 && strstr (last_error, "-K cannot be used with a command"));
  reset_state ();
  CHECK (SUDO ("-nE", "/bin/true") == 2 && strstr (last_error, "-E is not supported"));

  /* Assignments precede the command; options end at the first operand. */
  reset_state ();
  CHECK (SUDO ("-n", "-u", "fixture", "A=1", "B_2=two words", "/bin/true", "C=3") == 37);
  req_t *a = AUTHZ (0);
  CHECK (blob_is (a->argv, a->argv_bytes, "/bin/true", "C=3", NULL));
  CHECK (blob_has (a->env, a->env_bytes, "BASHOS_INLINE_A=1"));
  CHECK (blob_has (a->env, a->env_bytes, "BASHOS_INLINE_B_2=two words"));
  CHECK (!blob_has (a->env, a->env_bytes, "BASHOS_INLINE_C=3"));
  CHECK (a->p.envc == 5);	/* three caller exports + two assignments */
  reset_state ();
  CHECK (SUDO ("-u", "fixture", "A=1", "-n", "/bin/true") == 127 && S->nreq == 0);
  CHECK (strstr (last_error, "command not found in secure path: -n"));
  reset_state ();
  CHECK (SUDO ("--", "-n") == 127 && S->nreq == 0);
  reset_state ();
  CHECK (SUDO ("-n", "-u", "fixture", "--", "/bin/echo", "-u", "--", "") == 37);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/echo", "-u", "--", "", NULL));
  reset_state ();
  CHECK (SUDO ("-n", "-u", "fixture", "echo", "relative") == 37);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/echo", "relative", NULL));
  /* -u takes the next word even when it looks like an option. */
  reset_state ();
  CHECK (SUDO ("-u", "-n", "/bin/true") == 1 && S->nreq == 0 && strstr (last_error, "unknown user: -n"));

  /* Help and version remain first-word forms with checked output. */
  for (int sudo = 0; sudo < 2; sudo++)
    {
      fflush (stdout);
      int saved = dup (STDOUT_FILENO), full = open ("/dev/full", O_WRONLY);
      CHECK (saved >= 0 && full >= 0);
      CHECK (dup2 (full, STDOUT_FILENO) == STDOUT_FILENO);
      CHECK (dispatchv (sudo, (char *[]) { "--version", NULL }) == 1);
      CHECK (dispatchv (sudo, (char *[]) { "-h", NULL }) == 1);
      CHECK (dup2 (saved, STDOUT_FILENO) == STDOUT_FILENO);
      close (saved);
      close (full);
      clearerr (stdout);
      CHECK (dispatchv (sudo, (char *[]) { "--version", NULL }) == 0);
    }
}

/* ---- target lookup and groups ------------------------------------------ */

static void
lookup_tests (void)
{
  const char *bad_users[] = { "missing", "short", "4294967296", "4294967295", "", "fixture:", NULL };
  for (int i = 0; bad_users[i]; i++)
    for (int route = 0; route < 2; route++)
      {
        reset_state ();
        root_route = route;
        CHECK (SUDO ("-n", "-u", (char *) bad_users[i], "/bin/true") == 1);
        CHECK (S->nreq == 0 && S->execs == 0 && strstr (last_error, "unknown user"));
      }
  /* Names match whole rows; malformed earlier rows are skipped. */
  const char *groups[][2] = { { "chosen", "4545" }, { "#4545", "4545" }, { "extra", "4444" }, { "cho", "1" }, { "#0", "0" } };
  for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++)
    {
      reset_state ();
      CHECK (SUDO ("-n", "-u", "fixture", "-g", (char *) groups[i][0], "/bin/true") == 37);
      req_t *a = AUTHZ (0);
      CHECK (a->p.target_uid == 4242 && a->p.target_gid == (unsigned) atoi (groups[i][1]));
      CHECK (a->p.flags == BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP);
    }
  reset_state ();
  CHECK (SUDO ("-nufixture", "-gchosen", "/bin/true") == 37 && AUTHZ (0)->p.target_gid == 4545);
  reset_state ();
  CHECK (SUDO ("-n", "-u", "fixture", "--group=chosen", "/bin/true") == 37 && AUTHZ (0)->p.target_gid == 4545);
  const char *bad_groups[] = { "chose", "huge", "neg", "missing", "", "#", "#-1", "#+1", "#4294967295", "#4294967296", NULL };
  for (int i = 0; bad_groups[i]; i++)
    for (int route = 0; route < 2; route++)
      {
        reset_state ();
        root_route = route;
        CHECK (SUDO ("-n", "-u", "fixture", "-g", (char *) bad_groups[i], "/bin/true") == 1);
        CHECK (S->nreq == 0 && S->execs == 0 && strstr (last_error, "unknown group"));
      }
  /* -g without -u runs as the invoking user with the chosen group. */
  reset_state ();
  CHECK (SUDO ("-n", "-g", "chosen", "/bin/true") == 37);
  CHECK (AUTHZ (0)->p.target_uid == getuid () && AUTHZ (0)->p.target_gid == 4545);
  CHECK (!strcmp (AUTHZ (0)->p.target_user, "caller"));
  reset_state ();
  CHECK (SUDO ("-n", "/bin/true") == 37 && AUTHZ (0)->p.target_uid == 0 && AUTHZ (0)->p.flags == 0);
  /* doas keeps its own default target. */
  reset_state ();
  CHECK (DOAS ("-n", "-g", "chosen", "/bin/true") == 37 && AUTHZ (0)->p.target_uid == 0);
}

/* ---- authority policy and authentication -------------------------------- */

static void
authority_tests (void)
{
  int before = proc_fds ();
  for (int i = 0; i < 3; i++)
    {
      reset_state ();
      CHECK (SUDO ("-n", "-u", "fixture", "/bin/true", "literal ' ; $(no)\n", "") == 37);
      req_t *a = AUTHZ (0), *h = HANDOFF (0);
      CHECK (a->fd_cloexec && a->p.size == sizeof a->p && a->p.caller_uid == getuid ());
      CHECK (a->p.decision == 0 && a->p.handle_id == 0);
      CHECK (blob_is (a->argv, a->argv_bytes, "/bin/true", "literal ' ; $(no)\n", "", NULL));
      CHECK (blob_is (a->env, a->env_bytes, "BASHOS_CALLER_SAFE=caller", "BASHOS_CALLER_LD_PRELOAD=caller",
                      "BASHOS_CALLER_BASH_ENV=caller", NULL));
      CHECK (h->h.handle.handle_id == 100 && h->h.mode == BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE);
      CHECK (blob_is (h->argv, h->argv_bytes, "/bin/true", "literal ' ; $(no)\n", "", NULL));
      CHECK (proc_fds () == before);
    }
  /* Command status, including a forced UMH handoff. */
  reset_state ();
  handoff_exit = 0;
  handoff_approval = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_FORCED_UMH;
  CHECK (SUDO ("-n", "/bin/true") == 0);
  reset_state ();
  handoff_exit = 143;
  CHECK (SUDO ("-n", "/bin/true") == 143);

  /* Denials never hand off. */
  struct { unsigned decision; int nohandle, err, tty; } deny[] = {
    { BASHOS_AUTH_PRIVCMD_DECISION_DENY, 0, 0, 0 },
    { BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC, 1, 0, 0 },
    { BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 0 },
    { BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK, 0, 0, 0 },
    { BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK, 0, 0, 0 },
    { 999, 0, 0, 0 },
    { 0, 0, EACCES, 0 },
  };
  for (size_t i = 0; i < sizeof deny / sizeof deny[0]; i++)
    {
      reset_state ();
      R[0].decision = deny[i].decision;
      R[0].nohandle = deny[i].nohandle;
      R[0].err = deny[i].err;
      R[0].reason = "rule 3";
      CHECK (SUDO ("-n", "-u", "fixture", "/bin/true") == 1);
      CHECK (S->nreq == 1 && count_op (BASHOS_AUTH_IOC_EXEC_HANDOFF) == 0);
    }
  reset_state ();
  R[0].decision = BASHOS_AUTH_PRIVCMD_DECISION_DENY;
  R[0].reason = "rule 3";
  CHECK (SUDO ("-n", "/bin/true") == 1 && strstr (last_error, "audit_id=900") && strstr (last_error, "reason=rule 3"));
  reset_state ();
  handoff_approval = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED;
  CHECK (SUDO ("-n", "/bin/true") == 1);
  reset_state ();
  handoff_err = 1;
  CHECK (SUDO ("-n", "/bin/true") == 1);

  /* Non-interactive denial: -n, or no terminal, never starts the verifier. */
  for (int variant = 0; variant < 3; variant++)
    {
      reset_state ();
      script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
      tty_mode = variant == 2;
      int rc = variant == 1 ? SUDO ("/bin/true") : SUDO ("-n", "/bin/true");
      CHECK (rc == 1 && S->nreq == 1 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 0);
      CHECK (strstr (last_error, "requires authentication"));
    }
  for (int variant = 0; variant < 2; variant++)
    {
      reset_state ();
      script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
      tty_mode = variant;
      CHECK (SUDO ("-n", "-v") == 1 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 0);
    }

  /* Interactive: AUTHZ, verify, AUTHZ again, then the kernel exec. */
  reset_state ();
  tty_mode = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("-u", "fixture", "/bin/true", "a") == 37);
  CHECK (count_op (BASHOS_AUTH_IOC_PRIVCMD_AUTHZ) == 2 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1 && count_op (BASHOS_AUTH_IOC_EXEC_HANDOFF) == 0);
  req_t *v = nth_op (BASHOS_AUTH_IOC_EXEC_VERIFY, 0), *x = nth_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE, 0);
  CHECK (!memcmp (v->v.request_digest, AUTHZ (0)->p.request_digest, 32));
  CHECK (!memcmp (AUTHZ (0)->p.request_digest, AUTHZ (1)->p.request_digest, 32));
  CHECK (v->v.target_uid == 4242 && v->v.policy_generation == 7 && v->v.timeout_sec == 300);
  CHECK (v->pid != getpid () && x->pid != getpid ());
  CHECK (x->h.handle.handle_id == 101 && blob_is (x->argv, x->argv_bytes, "/bin/true", "a", NULL));
  /* A failed verification never execs. */
  reset_state ();
  tty_mode = 1;
  verify_fail = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("/bin/true") == 126 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0 && count_op (BASHOS_AUTH_IOC_PRIVCMD_AUTHZ) == 1);
  /* Still AUTH_REQUIRED after one verification: failure, not success. */
  reset_state ();
  tty_mode = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
  CHECK (SUDO ("/bin/true") == 1 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 2 && strstr (last_error, "still requires authentication"));
  reset_state ();
  tty_mode = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_DENY);
  CHECK (SUDO ("/bin/true") == 125 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0);
  reset_state ();
  tty_mode = 1;
  handoff_err = 1;
  CHECK (SUDO ("/bin/true") == 126);

  /* -v, -k, -K. */
  reset_state ();
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK);
  CHECK (SUDO ("-v") == 0 && AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE);
  CHECK (AUTHZ (0)->p.argc == 0 && AUTHZ (0)->p.argv_user_ptr == 0 && AUTHZ (0)->p.envc == 0 && AUTHZ (0)->p.env_user_ptr == 0);
  reset_state ();
  tty_mode = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK);
  CHECK (SUDO ("-v") == 0 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1 && count_op (BASHOS_AUTH_IOC_PRIVCMD_AUTHZ) == 2);
  reset_state ();
  tty_mode = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_DENY);
  CHECK (SUDO ("-v") == 1);
  reset_state ();
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK);
  CHECK (SUDO ("-k") == 0 && S->nreq == 1 && AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP && AUTHZ (0)->p.flags == 0);
  reset_state ();
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK);
  CHECK (SUDO ("-K") == 0 && AUTHZ (0)->p.flags == BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL);
  reset_state ();
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK);
  CHECK (SUDO ("-k") == 1);
  /* -k with a command: reset, then authorize and run the command. */
  reset_state ();
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("-nk", "-u", "fixture", "A=1", "/bin/true") == 37);
  CHECK (S->nreq == 3 && AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP);
  CHECK (AUTHZ (0)->p.argc == 0 && AUTHZ (0)->p.envc == 0 && AUTHZ (0)->p.target_uid == 4242);
  CHECK (AUTHZ (1)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_EXEC && blob_is (AUTHZ (1)->argv, AUTHZ (1)->argv_bytes, "/bin/true", NULL));
  CHECK (blob_has (AUTHZ (1)->env, AUTHZ (1)->env_bytes, "BASHOS_INLINE_A=1"));
  CHECK (HANDOFF (0)->h.handle.handle_id == 101);
  reset_state ();
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_DENY, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("-k", "-n", "/bin/true") == 1 && S->nreq == 1);
  reset_state ();
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK, BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK);
  CHECK (SUDO ("-kv") == 0 && S->nreq == 2 && AUTHZ (1)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE);
  reset_state ();
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("-k", "-n", "-i", "-u", "fixture") == 37 && AUTHZ (1)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_LOGIN);
  CHECK (proc_fds () == before);

  /* Without the authority, an explicit delegate gets the original words. */
  reset_state ();
  auth_absent = 1;
  setenv ("BASHSUDO_EXTERNAL", "/bin/true", 1);
  setenv ("BASHDOAS_EXTERNAL", "/bin/false", 1);
  CHECK (SUDO ("-nk", "A=1", "/bin/echo", "x") == 0 && S->nreq == 0);
  CHECK (S->spawns == 1 && S->spawn_argc == 5 && !strcmp (S->spawn_argv[0], "/bin/true"));
  CHECK (!strcmp (S->spawn_argv[1], "-nk") && !strcmp (S->spawn_argv[2], "A=1") && S->spawn_open_fds == 0);
  reset_state ();
  auth_absent = 1;
  CHECK (DOAS ("-n", "/bin/true") == 1 && !strcmp (S->spawn_argv[0], "/bin/false"));
  unsetenv ("BASHSUDO_EXTERNAL");
  reset_state ();
  auth_absent = 1;
  CHECK (SUDO ("-n", "/bin/true") == 1 && !strcmp (S->spawn_argv[0], "/bin/false"));
  unsetenv ("BASHDOAS_EXTERNAL");
}

/* ---- default doas delegate translation --------------------------------- */

static void
translation_tests (void)
{
  /* With PATH empty the default delegate is absent: 127, after translation. */
  struct { const char *args[8]; const char *want[10]; } ok[] = {
    { { "-nu", "fixture", "/bin/echo", "-x", "" }, { "doas", "-n", "-u", "fixture", "--", "/bin/echo", "-x", "" } },
    { { "/bin/true" }, { "doas", "-u", "root", "--", "/bin/true" } },
    { { "-u", "#4242", "-s" }, { "doas", "-u", "4242", "-s" } },
    { { "-k" }, { "doas", "-L" } },
    { { "-K" }, { "doas", "-L" } },
  };
  for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
    {
      char *args[8] = { 0 };
      for (int k = 0; ok[i].args[k]; k++) args[k] = (char *) ok[i].args[k];
      reset_state ();
      auth_absent = 1;
      CHECK (dispatchv (1, args) == 127 && S->spawns == 1 && S->spawn_open_fds == 0);
      int n = 0;
      for (; ok[i].want[n]; n++) CHECK (!strcmp (S->spawn_argv[n], ok[i].want[n]));
      CHECK (S->spawn_argc == n);
    }
  const char *refuse[][4] = {
    { "-i", NULL }, { "-e", "/tmp/x", NULL }, { "-v", NULL }, { "-g", "chosen", "/bin/true" },
    { "-k", "/bin/true", NULL }, { "A=1", "/bin/true", NULL }, { "-s", "/bin/true", NULL },
  };
  for (size_t i = 0; i < sizeof refuse / sizeof refuse[0]; i++)
    {
      char *args[5] = { 0 };
      for (int k = 0; k < 4 && refuse[i][k]; k++) args[k] = (char *) refuse[i][k];
      reset_state ();
      auth_absent = 1;
      CHECK (dispatchv (1, args) == 1 && S->spawns == 0 && strstr (last_error, "requires the bash-os authority"));
    }
  reset_state ();
  auth_absent = 1;
  CHECK (DOAS ("-n", "-s") == 127 && S->spawn_argc == 3 && !strcmp (S->spawn_argv[1], "-n") && !strcmp (S->spawn_argv[2], "-s"));
}

/* ---- root caller ------------------------------------------------------- */

static void
root_tests (void)
{
  setenv ("USER", "spoofed", 1);
  setenv ("UNSAFE", "caller", 1);
  setenv ("BASH_ENV", "evil", 1);
  setenv ("TERM", "fixture-term", 1);
  int inherited = open ("/dev/null", O_RDONLY);
  CHECK (inherited >= 3 && dup2 (inherited, 200) == 200);
  signal (SIGTERM, SIG_IGN);
  sigset_t mask, old;
  sigemptyset (&mask);
  sigaddset (&mask, SIGUSR1);
  CHECK (sigprocmask (SIG_BLOCK, &mask, &old) == 0);
  for (int i = 0; i < 3; i++)
    {
      reset_state ();
      root_route = 1;
      CHECK (SUDO ("-u", "fixture", "-g", "chosen", "HOME=/override", "SAFE=one", "SAFE=two", "LD_PRELOAD=x",
                   "PS4=x", "BASH_FUNC_x=y", "/usr/bin/printf", "%s", "literal ' ; $(no)") == 41);
      CHECK (S->execs == 1 && !strcmp (S->path, "/usr/bin/printf") && S->argc == 3);
      CHECK (!strcmp (S->argv[1], "%s") && !strcmp (S->argv[2], "literal ' ; $(no)"));
      CHECK (!strcmp (S->cred_order, "Ggu") && S->uid == 4242 && S->gid == 4545);
      /* chosen primary group, the passwd primary group, and memberships */
      CHECK (S->ngroups == 3 && S->groups[0] == 4545 && S->groups[1] == 4444 && S->groups[2] == 4343);
      CHECK (!strcmp (env_of ("HOME"), "/override") && !strcmp (env_of ("SAFE"), "two"));
      CHECK (!strcmp (env_of ("USER"), "fixture") && !strcmp (env_of ("LOGNAME"), "fixture"));
      CHECK (!strcmp (env_of ("SHELL"), "/bin/sh") && !strcmp (env_of ("PATH"), "/bin:/bash-os:/usr/bin"));
      CHECK (!strcmp (env_of ("TERM"), "fixture-term"));
      CHECK (!strcmp (env_of ("SUDO_COMMAND"), "/usr/bin/printf %s literal ' ; $(no)"));
      /* SUDO_USER names the invoking account, not $USER. */
      CHECK (!strcmp (env_of ("SUDO_USER"), "caller"));
      char id[32];
      snprintf (id, sizeof id, "%u", (unsigned) getuid ());
      CHECK (!strcmp (env_of ("SUDO_UID"), id));
      snprintf (id, sizeof id, "%u", (unsigned) getgid ());
      CHECK (!strcmp (env_of ("SUDO_GID"), id));
      const char *never[] = { "LD_PRELOAD", "PS4", "BASH_FUNC_x", "BASH_ENV", "UNSAFE", NULL };
      for (int k = 0; never[k]; k++) CHECK (!env_of (never[k]));
      CHECK (S->open_fds == 0 && !S->sigusr1_blocked && S->sigterm_dfl && S->nnp == 1);
      CHECK (fcntl (200, F_GETFD) >= 0);
    }
  CHECK (sigprocmask (SIG_SETMASK, &old, NULL) == 0);
  signal (SIGTERM, SIG_DFL);
  close (200);
  close (inherited);

  /* Without -g the passwd group is primary and appears once. */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-u", "fixture", "/bin/true") == 41);
  CHECK (S->gid == 4343 && S->ngroups == 3 && S->groups[0] == 4545 && S->groups[1] == 4444 && S->groups[2] == 4343);
  /* -g alone: the invoking user (here the caller row) with the chosen group. */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-g", "chosen", "/bin/true") == 41 && S->uid == getuid () && S->gid == 4545);
  /* Assignments are applied after sudo's own variables. */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-u", "fixture", "SUDO_COMMAND=mine", "SUDO_USER=named", "/bin/true") == 41);
  CHECK (!strcmp (env_of ("SUDO_COMMAND"), "mine") && !strcmp (env_of ("SUDO_USER"), "named"));
  /* doas does not export SUDO_COMMAND. */
  reset_state ();
  root_route = 1;
  CHECK (DOAS ("-u", "fixture", "/bin/true") == 41 && !env_of ("SUDO_COMMAND") && env_of ("SUDO_USER"));

  /* -i: "-" + shell basename, target home, login flag. */
  char cwd[PATH_MAX];
  CHECK (getcwd (cwd, sizeof cwd));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-i", "-u", "fixture") == 41);
  CHECK (!strcmp (S->path, "/bin/sh") && S->argc == 2 && !strcmp (S->argv[0], "-sh") && !strcmp (S->argv[1], "-l"));
  CHECK (!strcmp (S->cwd, home_dir) && !strcmp (env_of ("SUDO_COMMAND"), "/bin/sh"));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-i", "-u", "fixture", "echo", "it's") == 41);
  CHECK (S->argc == 4 && !strcmp (S->argv[0], "-sh") && !strcmp (S->argv[2], "-c") && !strcmp (S->argv[3], "echo it\\'s"));
  CHECK (!strcmp (env_of ("SUDO_COMMAND"), "/bin/sh -c echo it\\'s"));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture") == 41 && S->argc == 1 && !strcmp (S->argv[0], "/bin/sh") && !strcmp (S->cwd, cwd));
  /* A missing home is reported; the shell still starts. */
  CHECK (rmdir (home_dir) == 0);
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-i", "-u", "fixture") == 41 && !strcmp (S->cwd, cwd));
  CHECK (mkdir (home_dir, 0700) == 0);
  CHECK (getcwd (cwd, sizeof cwd) && !strcmp (cwd, S->cwd));	/* the parent never moved */

  /* -k/-K/-v need no credential for root. */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-k", "-u", "fixture", "/bin/true") == 41 && S->execs == 1);
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-K") == 0 && SUDO ("-v") == 0 && SUDO ("-k") == 0 && S->execs == 0);

  /* Credential failures stop before exec. */
  for (int step = 1; step <= 5; step++)
    {
      reset_state ();
      root_route = 1;
      cred_fail = step;
      CHECK (SUDO ("-u", "fixture", "/bin/true") == 126 && S->execs == 0);
    }

  /* Real execs: status, signal, not found, not executable, literal argv. */
  struct { const char *cmd[7]; int rc; } real[] = {
    { { "sh", "-c", "exit 23" }, 23 },
    { { "/bin/sh", "-c", "kill -TERM $$" }, 143 },
    { { "/not/a/command" }, 127 },
    { { "not-a-command-anywhere" }, 127 },
    { { "/dev/null" }, 126 },
    { { "/bin/sh", "-c", "test \"$1\" = \"a b\" && test -z \"$2\" && test $# = 2", "zero", "a b", "" }, 0 },
  };
  for (size_t i = 0; i < sizeof real / sizeof real[0]; i++)
    {
      char *args[12] = { "-u", "fixture" };
      for (int k = 0; real[i].cmd[k]; k++) args[2 + k] = (char *) real[i].cmd[k];
      reset_state ();
      root_route = 1;
      exec_real = 1;
      CHECK (dispatchv (1, args) == real[i].rc);
    }

  /* Root sudoedit runs the split editor on the files themselves. */
  char file[PATH_MAX], editor[PATH_MAX], cmd[PATH_MAX * 2];
  snprintf (file, sizeof file, "%s/root-edit", scratch);
  snprintf (editor, sizeof editor, "%s/editor", scratch);
  write_file (file, "old");
  snprintf (cmd, sizeof cmd, "%s --append", editor);
  setenv ("SUDO_EDITOR", cmd, 1);
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-e", file) == 0 && S->spawns == 1 && S->spawn_argc == 3);
  CHECK (!strcmp (S->spawn_argv[1], "--append") && !strcmp (S->spawn_argv[2], file) && file_is (file, "old+edited"));
  CHECK (unlink (file) == 0);
}

/* ---- sudoedit through the authority ------------------------------------- */

static char originals[17][PATH_MAX];
static void
make_originals (int n)
{
  for (int i = 0; i < n; i++)
    {
      char text[32];
      snprintf (originals[i], sizeof originals[i], "%s/original%d", scratch, i);
      unlink (originals[i]);
      snprintf (text, sizeof text, "orig%d", i);
      write_file (originals[i], text);
      CHECK (chmod (originals[i], 0600) == 0);
    }
}
static int
edit_n (int n)
{
  char *args[24] = { "-u", "fixture", "-e" };
  for (int i = 0; i < n; i++) args[3 + i] = originals[i];
  args[3 + n] = NULL;
  return dispatchv (1, args);
}
static char moved[PATH_MAX];
static void
edit_reset (void)
{
  snprintf (moved, sizeof moved, "%s/moved", scratch);
  unlink (moved);
  reset_state ();
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT);
  make_originals (2);
}

static void
edit_tests (void)
{
  char editor[PATH_MAX], value[PATH_MAX * 2];
  snprintf (editor, sizeof editor, "%s/editor", scratch);
  snprintf (value, sizeof value, "  %s\t--append  ", editor);
  setenv ("SUDO_EDITOR", value, 1);
  unsetenv ("EDITOR_EXIT");
  unsetenv ("EDITOR_ACTION");
  int before = proc_fds ();

  /* Success: open, one editor run as the caller, fresh authorization,
     read-only descriptors of the edited copies, protected copyback. */
  for (int round = 0; round < 2; round++)
    {
      edit_reset ();
      CHECK (edit_n (2) == 0);
      CHECK (S->nreq == 4 && AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT && AUTHZ (1)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT);
      CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, originals[0], originals[1], NULL));
      CHECK (!memcmp (AUTHZ (0)->p.request_digest, AUTHZ (1)->p.request_digest, 32));
      req_t *o = HANDOFF (0), *c = HANDOFF (1);
      CHECK (o->h.flags == BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN && o->h.handle.handle_id == 100);
      CHECK (c->h.flags == BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_COPYBACK && c->h.handle.handle_id == 101);
      CHECK (blob_is (c->argv, c->argv_bytes, originals[0], originals[1], NULL));
      CHECK (c->nfds == 2 && c->fd_rdonly[0] && c->fd_rdonly[1]);
      CHECK (!strcmp (c->fd_data[0], "orig0+edited") && !strcmp (c->fd_data[1], "orig1+edited"));
      CHECK (S->spawns == 1 && S->spawn_argc == 4 && !strcmp (S->spawn_argv[0], editor) && !strcmp (S->spawn_argv[1], "--append"));
      CHECK (!strcmp (S->spawn_argv[2], temp_paths[0]) && !strcmp (S->spawn_argv[3], temp_paths[1]) && S->spawn_open_fds == 0);
      CHECK (file_is (originals[0], "orig0+edited") && file_is (originals[1], "orig1+edited"));
      CHECK (temps_gone () && proc_fds () == before);
    }

  /* Each rejection leaves both originals untouched and removes the copies. */
  struct { int open_mode, editor_exit, tty, verify_fail, drift; unsigned second, third; int nohandle, rc, opens, copybacks, spawns; const char *action; } bad[] = {
    { 1, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* count mismatch */
    { 2, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* zero bytes */
    { 3, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* bytes > cap */
    { 4, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* unterminated */
    { 5, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* empty path */
    { 6, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* gate off */
    { 7, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 0, NULL },	/* open denied */
    { 0, 3, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 1, NULL },	/* editor failed */
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_DENY, 0, 0, 1, 1, 0, 1, NULL },		/* policy drift */
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, 0, 0, 1, 1, 0, 1, NULL },	/* expired, no tty */
    { 0, 0, 1, 1, 0, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, 0, 0, 1, 1, 0, 1, NULL },	/* verify failed */
    { 0, 0, 1, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_DENY, 0, 1, 1, 0, 1, NULL },
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 1, 1, 1, 0, 1, NULL },	/* fresh handle missing */
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC, 0, 0, 1, 1, 0, 1, NULL },	/* wrong decision */
    { 0, 0, 0, 0, -1, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 1, 1, NULL },	/* copyback gate off */
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 0, 1, "temp-symlink" },
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 1, 1, "symlink" },
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 1, 1, "hardlink" },
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 1, 1, "replace" },
    { 0, 0, 0, 0, 0, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, 0, 0, 1, 1, 1, 1, "chmod" },
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      edit_reset ();
      open_mode = bad[i].open_mode;
      tty_mode = bad[i].tty;
      verify_fail = bad[i].verify_fail;
      copyback_drift = bad[i].drift;
      R[1].decision = bad[i].second;
      R[1].nohandle = bad[i].nohandle;
      if (bad[i].third) { R[2].decision = bad[i].third; nR = 3; }
      char code[8];
      snprintf (code, sizeof code, "%d", bad[i].editor_exit);
      setenv ("EDITOR_EXIT", code, 1);
      if (bad[i].action) setenv ("EDITOR_ACTION", bad[i].action, 1);
      int rc = edit_n (2);
      unsetenv ("EDITOR_ACTION");
      if (rc != bad[i].rc) fprintf (stderr, "edit case %zu rc %d\n", i, rc);
      CHECK (rc == bad[i].rc);
      int opens = 0, copybacks = 0;
      for (int k = 0; k < S->nreq; k++)
        if (S->req[k].op == BASHOS_AUTH_IOC_EXEC_HANDOFF)
          {
            if (S->req[k].h.flags == BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN) opens++;
            else copybacks++;
          }
      CHECK (opens == bad[i].opens && copybacks == bad[i].copybacks && S->spawns == bad[i].spawns);
      CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == bad[i].tty);
      CHECK (file_is (originals[1], "orig1"));
      /* A moved original keeps its content; a swapped-in path is never written. */
      if (bad[i].action && (!strcmp (bad[i].action, "symlink") || !strcmp (bad[i].action, "replace")))
        CHECK (file_is (moved, "orig0"));
      if (!bad[i].action || strcmp (bad[i].action, "symlink"))
        CHECK (file_is (originals[0], "orig0"));
      /* A malformed OPEN reply is not trusted for cleanup; drop the copies. */
      if (open_mode >= 1 && open_mode <= 5)
        for (int k = 0; k < open_n; k++) unlink (temp_paths[k]);
      CHECK (temps_gone () && proc_fds () == before);
    }

  /* An expired timestamp re-verifies once on a terminal, then copies back. */
  edit_reset ();
  setenv ("EDITOR_EXIT", "0", 1);
  tty_mode = 1;
  script (3, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT);
  CHECK (edit_n (2) == 0 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1 && HANDOFF (1)->h.handle.handle_id == 102);
  CHECK (!memcmp (nth_op (BASHOS_AUTH_IOC_EXEC_VERIFY, 0)->v.request_digest, AUTHZ (0)->p.request_digest, 32));
  CHECK (file_is (originals[0], "orig0+edited") && file_is (originals[1], "orig1+edited"));

  /* Second target drifted: the first is committed (documented residual). */
  edit_reset ();
  setenv ("EDITOR_ACTION", "drift-second", 1);
  CHECK (edit_n (2) == 1 && HANDOFF (1)->h.reject_stage == 101);
  CHECK (file_is (originals[0], "orig0+edited") && strstr (last_error, "partial multi-target"));
  unsetenv ("EDITOR_ACTION");

  /* Bounds: 16 targets work; 0, 17 and relative paths make no request. */
  reset_state ();
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT);
  make_originals (16);
  CHECK (edit_n (16) == 0 && S->spawn_argc == 18);
  for (int i = 0; i < 16; i++)
    {
      char text[32];
      snprintf (text, sizeof text, "orig%d+edited", i);
      CHECK (file_is (originals[i], text));
    }
  make_originals (17);
  reset_state ();
  CHECK (edit_n (17) == 2 && S->nreq == 0);
  reset_state ();
  CHECK (edit_n (0) == 2 && S->nreq == 0);
  reset_state ();
  CHECK (SUDO ("-e", "relative") == 2 && S->nreq == 0);
  reset_state ();
  CHECK (SUDO ("-e", "A=1") == 2 && S->nreq == 0);	/* operands are files */
  for (int i = 0; i < 17; i++) unlink (originals[i]);

  /* Editor selection: blank SUDO_EDITOR falls through to VISUAL. */
  edit_reset ();
  setenv ("SUDO_EDITOR", " \t", 1);
  setenv ("VISUAL", editor, 1);
  CHECK (edit_n (2) == 0 && S->spawn_argc == 3 && !strcmp (S->spawn_argv[0], editor));
  edit_reset ();
  unsetenv ("SUDO_EDITOR");
  unsetenv ("VISUAL");
  unsetenv ("EDITOR");
  /* /bin/vi is recorded, not started: the unchanged copies are copied back. */
  CHECK (edit_n (2) == 0 && S->spawn_argc == 3 && !strcmp (S->spawn_argv[0], "/bin/vi"));
  CHECK (file_is (originals[0], "orig0") && file_is (originals[1], "orig1"));
  for (int i = 0; i < 2; i++) unlink (originals[i]);
  CHECK (proc_fds () == before);
}

/* ---- shared protected-copyback helper ----------------------------------- */

/* Appends to the copy; given a path, also changes that original's mode. */
static int helper_edit (const char *temp, void *ud)
{
  int fd = open (temp, O_WRONLY | O_APPEND);
  if (fd < 0) return -1;
  int ok = write (fd, "+helper", 7) == 7;
  close (fd);
  if (ud) CHECK (chmod ((const char *) ud, 0644) == 0);
  return ok ? 0 : -1;
}
/* Policy holds for the first FAIL_AT-1 checks. */
typedef struct { int calls, fail_at; } drift_t;
static int helper_drift (const bashos_sudoedit_target *t, void *ud)
{
  drift_t *d = ud;
  (void) t;
  return ++d->calls == d->fail_at ? -1 : 0;
}

static void
helper_tests (void)
{
  char path[PATH_MAX], other[PATH_MAX];
  int fd;
  bashos_sudoedit_identity id;
  snprintf (path, sizeof path, "%s/helper", scratch);
  snprintf (other, sizeof other, "%s/helper-other", scratch);
  int before = proc_fds ();
  /* safe_open rejects every unsafe kind of target. */
  write_file (path, "x");
  CHECK (bashos_sudoedit_safe_open (path, &fd, &id) == BASHOS_SE_OK && fd >= 0 && id.valid);
  close (fd);
  CHECK (symlink (path, other) == 0);
  CHECK (bashos_sudoedit_safe_open (other, &fd, &id) == BASHOS_SE_REJECT_SYMLINK && fd == -1);
  CHECK (unlink (other) == 0 && link (path, other) == 0);
  CHECK (bashos_sudoedit_safe_open (path, &fd, &id) == BASHOS_SE_REJECT_HARDLINK);
  CHECK (unlink (other) == 0 && chmod (path, 04600) == 0);
  CHECK (bashos_sudoedit_safe_open (path, &fd, &id) == BASHOS_SE_REJECT_UNSAFE_MODE);
  CHECK (chmod (path, 02600) == 0);
  CHECK (bashos_sudoedit_safe_open (path, &fd, &id) == BASHOS_SE_REJECT_UNSAFE_MODE);
  CHECK (chmod (path, 0600) == 0 && mkfifo (other, 0600) == 0);
  CHECK (bashos_sudoedit_safe_open (other, &fd, &id) == BASHOS_SE_REJECT_NOT_REGULAR);
  CHECK (unlink (other) == 0);
  CHECK (bashos_sudoedit_safe_open (scratch, &fd, &id) == BASHOS_SE_REJECT_NOT_REGULAR);
  CHECK (bashos_sudoedit_safe_open (other, &fd, &id) == BASHOS_SE_REJECT_OPEN);
  CHECK (bashos_sudoedit_safe_open ("", &fd, &id) == BASHOS_SE_REJECT_PARAM);
  CHECK (proc_fds () == before);

  /* The ordered run: success, missing editor, policy drift after the edit,
     missing edit token, and original identity drift during the edit. */
  for (int k = 0; k < 5; k++)
    {
      unlink (path);
      write_file (path, "orig");
      CHECK (chmod (path, 0600) == 0);
      drift_t drift = { 0, k == 2 ? 2 : 0 };
      bashos_sudoedit_target t = { .path = path, .orig_fd = -1, .temp_fd = -1 };
      bashos_sudoedit_ctx c = { .target = &t, .caller_uid = getuid (), .caller_gid = getgid (), .tmpdir = scratch,
                                .editor_fn = k == 1 ? NULL : helper_edit, .editor_ud = k == 4 ? path : NULL,
                                .policy_fn = helper_drift, .policy_ud = &drift,
                                .require_edit_token = k == 3, .edit_token_valid = 0 };
      bashos_sudoedit_plan plan;
      int rc = bashos_sudoedit_run (&c, &plan);
      CHECK ((rc == 0) == (k == 0));
      CHECK (file_is (path, k == 0 ? "orig+helper" : "orig"));
      CHECK (k == 0 ? plan.reached_copyback : !plan.reached_copyback);
      if (k == 1) CHECK (plan.failed_step == BASHOS_SE_STEP_EDIT_AS_CALLER && t.reject == BASHOS_SE_REJECT_EDITOR);
      if (k == 2) CHECK (plan.failed_step == BASHOS_SE_STEP_REVALIDATE && t.reject == BASHOS_SE_REJECT_POLICY_DRIFT);
      if (k == 3) CHECK (plan.failed_step == BASHOS_SE_STEP_POLICY_CHECK && t.reject == BASHOS_SE_REJECT_TOKEN);
      if (k == 4) CHECK (plan.failed_step == BASHOS_SE_STEP_REVALIDATE && t.reject == BASHOS_SE_REJECT_RACE);
      CHECK (t.temp_path == NULL && t.temp_fd == -1 && t.orig_fd == -1);
      CHECK (proc_fds () == before);
    }
  CHECK (unlink (path) == 0);
  DIR *d = opendir (scratch);
  CHECK (d);
  for (struct dirent *e; (e = readdir (d)); )
    CHECK (strncmp (e->d_name, ".sudoedit.", 10) != 0);
  closedir (d);
}

/* ---- request dump for the independent digest oracle ------------------- */

static void
hex (const unsigned char *b, size_t n)
{
  for (size_t i = 0; i < n; i++) printf ("%02x", b[i]);
}
static void
dump_request (void)
{
  reset_state ();
  quiet = 1;
  CHECK (SUDO ("-n", "-u", "fixture", "-g", "chosen", "Z=1", "/bin/echo", "x y", "") == 37);
  req_t *a = AUTHZ (0);
  printf ("{\"mode\":%u,\"flags\":%u,\"non_interactive\":%u,\"caller_uid\":%u,\"caller_gid\":%u,"
          "\"target_uid\":%u,\"target_gid\":%u,\"argc\":%u,\"envc\":%u,\"caller_user\":\"%s\","
          "\"target_user\":\"%s\",\"cwd\":\"%s\",\"argv\":\"",
          a->p.mode, a->p.flags, a->p.non_interactive, a->p.caller_uid, a->p.caller_gid,
          a->p.target_uid, a->p.target_gid, a->p.argc, a->p.envc, a->p.caller_user,
          a->p.target_user, a->p.cwd);
  hex (a->argv, a->argv_bytes);
  printf ("\",\"env\":\"");
  hex (a->env, a->env_bytes);
  printf ("\",\"digest\":\"");
  hex (a->p.request_digest, 32);
  printf ("\"}\n");
}

/* ---- measured work units ------------------------------------------------ */

static void
work (const char *phase, int n)
{
  quiet = 1;
  char editor[PATH_MAX];
  snprintf (editor, sizeof editor, "%s/editor", scratch);
  setenv ("SUDO_EDITOR", editor, 1);
  unsetenv ("EDITOR_EXIT");
  unsetenv ("EDITOR_ACTION");
  for (int i = 0; i < n; i++)
    {
      reset_state ();
      if (!strcmp (phase, "policy"))
        {
          CHECK (SUDO ("-n", "-u", "fixture", "A=1", "/bin/true", "x") == 37);
          CHECK (S->nreq == 2 && AUTHZ (0)->p.envc == 4 && HANDOFF (0)->h.handle.handle_id == 100);
        }
      else if (!strcmp (phase, "reset"))
        {
          script (2, BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
          CHECK (SUDO ("-nk", "-u", "fixture", "/bin/true") == 37);
          CHECK (S->nreq == 3 && AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP);
        }
      else if (!strcmp (phase, "verify"))
        {
          tty_mode = 1;
          script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
          CHECK (SUDO ("-u", "fixture", "/bin/true") == 37);
          CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1);
        }
      else if (!strcmp (phase, "edit"))
        {
          script (2, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT);
          make_originals (2);
          CHECK (edit_n (2) == 0 && S->nreq == 4);
          CHECK (file_is (originals[0], "orig0+edited") && file_is (originals[1], "orig1+edited") && temps_gone ());
        }
      else if (!strcmp (phase, "child"))
        {
          root_route = 1;
          exec_real = 1;
          CHECK (SUDO ("-u", "fixture", "-g", "chosen", "/bin/true") == 0);
          CHECK (S->execs == 1 && S->uid == 4242 && S->gid == 4545 && S->ngroups == 3 && S->open_fds == 0);
        }
      else
        CHECK (0);
    }
  if (!strcmp (phase, "edit"))
    for (int i = 0; i < 2; i++) CHECK (unlink (originals[i]) == 0);
  printf ("validated %s %d\n", phase, n);
}

/* sudo(8) keeps the command prefix, one separating space, and at most 4096
   bytes of the joined arguments. The cut may land inside a word. */
static void
reference_sudo_command (const char *prefix, char **words, int nwords,
                        char *out, size_t cap, int *lenp)
{
  size_t plen = strlen (prefix);
  size_t n = plen;
  CHECK (plen + 2 < cap);
  memcpy (out, prefix, plen);
  if (nwords > 0)
    {
      out[n++] = ' ';
      for (int i = 0; i < nwords; i++)
        {
          size_t wlen = strlen (words[i]);
          if (i)
            {
              CHECK (n + 1 < cap);
              out[n++] = ' ';
            }
          CHECK (n + wlen < cap);
          memcpy (out + n, words[i], wlen);
          n += wlen;
        }
      if (n - plen - 1 > 4096)
        n = plen + 1 + 4096;
    }
  out[n] = 0;
  *lenp = (int) n;
}

static void
fill_words (char *storage, size_t stride, int n, int wlen, char ch,
            char **args, int at)
{
  for (int i = 0; i < n; i++)
    {
      char *w = storage + (size_t) i * stride;
      memset (w, ch, (size_t) wlen);
      w[wlen] = 0;
      args[at + i] = w;
    }
  args[at + n] = NULL;
}

static void
command_tests (void)
{
  enum { MANY = 300, WORD = 16, ONES = 2049, HUGE = 5000 };
  char *storage = malloc ((size_t) MANY * (WORD + 1) + (size_t) ONES * 2 + HUGE + 1);
  char **args = calloc ((size_t) ONES + 8, sizeof *args);
  char expect[8192];
  int expect_len = 0;
  CHECK (storage && args);
  unsetenv ("SHELL");

  /* More than 4096 bytes of joined arguments. The argv stays intact. */
  args[0] = "-u";
  args[1] = "fixture";
  args[2] = "/bin/true";
  fill_words (storage, WORD + 1, MANY, WORD, 'a', args, 3);
  reference_sudo_command ("/bin/true", args + 3, MANY, expect, sizeof expect, &expect_len);
  CHECK (expect_len == 4106 && expect[4105] == 'a');
  reset_state ();
  root_route = 1;
  big_expect_on = 1;
  big_expect_word = args[3];
  big_expect_argc = MANY + 1;
  CHECK (dispatchv (1, args) == 41);
  if (S->sudo_command_len != expect_len || !S->argv_words_ok || S->argc != MANY + 1)
    fprintf (stderr, "long SUDO_COMMAND len %d want %d argc %d words_ok %d\n",
             S->sudo_command_len, expect_len, S->argc, S->argv_words_ok);
  CHECK (S->sudo_command_len == expect_len && S->argv_words_ok && S->argc == MANY + 1);
  CHECK (!memcmp (S->sudo_command, expect, (size_t) expect_len));

  /* A single argument longer than 4096 is cut mid-word. */
  args[3] = storage;
  memset (storage, 'b', HUGE);
  storage[HUGE] = 0;
  args[4] = NULL;
  reference_sudo_command ("/bin/true", args + 3, 1, expect, sizeof expect, &expect_len);
  CHECK (expect_len == 4106 && expect[4105] == 'b');
  reset_state ();
  root_route = 1;
  big_expect_on = 1;
  big_expect_word = args[3];
  big_expect_argc = 2;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->sudo_command_len == expect_len && S->argc == 2 && S->argv1_len == HUGE);
  CHECK (!memcmp (S->sudo_command, expect, (size_t) expect_len));

  /* The 4096th argument byte may be the space before the next word. */
  fill_words (storage, 2, ONES, 1, 'a', args, 3);
  reference_sudo_command ("/bin/true", args + 3, ONES, expect, sizeof expect, &expect_len);
  CHECK (expect_len == 4106 && expect[4105] == ' ');
  reset_state ();
  root_route = 1;
  big_expect_on = 1;
  big_expect_word = args[3];
  big_expect_argc = ONES + 1;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->sudo_command_len == expect_len && S->argv_words_ok && S->argc == ONES + 1);
  CHECK (!memcmp (S->sudo_command, expect, (size_t) expect_len));

  /* Exactly 4096 argument bytes are kept whole (241 words of 16 plus spaces). */
  fill_words (storage, WORD + 1, 241, WORD, 'a', args, 3);
  reference_sudo_command ("/bin/true", args + 3, 241, expect, sizeof expect, &expect_len);
  CHECK (expect_len == 4106);
  reset_state ();
  root_route = 1;
  big_expect_on = 1;
  big_expect_word = args[3];
  big_expect_argc = 242;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->sudo_command_len == expect_len && S->argv_words_ok);
  CHECK (!memcmp (S->sudo_command, expect, (size_t) expect_len));

  /* An explicit assignment wins and is not truncated to fit the diagnostic. */
  args[0] = "-u";
  args[1] = "fixture";
  args[2] = "SUDO_COMMAND=preserved-literal";
  args[3] = "/bin/true";
  fill_words (storage, WORD + 1, MANY, WORD, 'c', args, 4);
  reset_state ();
  root_route = 1;
  big_expect_on = 1;
  big_expect_word = args[4];
  big_expect_argc = MANY + 1;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->argv_words_ok && S->argc == MANY + 1);
  CHECK (S->sudo_command_len == (int) strlen ("preserved-literal"));
  CHECK (!strcmp (S->sudo_command, "preserved-literal"));
  CHECK (!strcmp (env_of ("SUDO_COMMAND"), "preserved-literal"));

  free (storage);
  free (args);
}

static int
groups_hold (gid_t passwd_gid, gid_t selected)
{
  int have_pw = 0, have_sel = 0;
  if (S->ngroups <= 0 || S->ngroups > 64)
    return 0;
  for (int i = 0; i < S->ngroups; i++)
    {
      if (S->groups[i] == passwd_gid)
        have_pw = 1;
      if (S->groups[i] == selected)
        have_sel = 1;
    }
  return have_pw && have_sel;
}

static void
write_memberships (int n, int include_required)
{
  FILE *f = fopen (group_path, "w");
  CHECK (f);
  for (int i = 0; i < n; i++)
    {
      unsigned g = 8000u + (unsigned) i;
      if (include_required && i == 0)
        g = 4343;
      if (include_required && i == 1)
        g = 7000;
      CHECK (fprintf (f, "g%d:x:%u:fixture\n", i, g) > 0);
    }
  CHECK (fclose (f) == 0);
}

static void
group_tests (void)
{
  char *args[] = { "-u", "fixture", "-g", "#7000", "/bin/true", NULL };
  unsetenv ("SHELL");
  /* 64 memberships omit both required gids. */
  write_memberships (64, 0);
  for (int sudo = 0; sudo < 2; sudo++)
    {
      reset_state ();
      root_route = 1;
      CHECK (dispatchv (sudo, args) == 41);
      if (!groups_hold (4343, 7000))
        fprintf (stderr, "full vector sudo=%d ngroups=%d gid=%u first=%u last=%u\n",
                 sudo, S->ngroups, (unsigned) S->gid,
                 S->ngroups ? (unsigned) S->groups[0] : 0,
                 S->ngroups ? (unsigned) S->groups[S->ngroups - 1] : 0);
      CHECK (S->gid == 7000 && groups_hold (4343, 7000));
    }
  /* 63 memberships used to accept the passwd gid and drop -g from the vector. */
  write_memberships (63, 0);
  reset_state ();
  root_route = 1;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->gid == 7000 && groups_hold (4343, 7000));
  reset_state ();
  root_route = 1;
  CHECK (dispatchv (0, args) == 41);
  CHECK (S->gid == 7000 && groups_hold (4343, 7000));
  /* Both required gids already in the 64 stay there, once each. */
  write_memberships (64, 1);
  reset_state ();
  root_route = 1;
  CHECK (dispatchv (1, args) == 41);
  CHECK (S->ngroups == 64 && S->gid == 7000 && groups_hold (4343, 7000));
  accounts ();
}

static void
status_reaped (void)
{
  int st = 0;
  sigset_t mask;
  pid_t w = waitpid (-1, &st, WNOHANG);
  /* The owned child is gone. SIGCHLD was only blocked for the wait, and the
     SIGUSR1 block this test installed is still the caller's mask. */
  CHECK (w == -1 && errno == ECHILD);
  CHECK (sigprocmask (SIG_SETMASK, NULL, &mask) == 0);
  CHECK (!sigismember (&mask, SIGCHLD));
  CHECK (sigismember (&mask, SIGUSR1));
}

static void
status_tests (void)
{
  sigset_t block;
  unsetenv ("SHELL");
  sigemptyset (&block);
  sigaddset (&block, SIGUSR1);
  CHECK (sigprocmask (SIG_BLOCK, &block, NULL) == 0);

  /* A failed status read must not treat a verify-only exit 0 as success. */
  reset_state ();
  tty_mode = 1;
  io_read_fail = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
  CHECK (SUDO ("/bin/true") == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0);
  CHECK (count_op (BASHOS_AUTH_IOC_PRIVCMD_AUTHZ) == 1);
  CHECK (strstr (last_error, "v2 authority status"));
  status_reaped ();
  reset_state ();
  tty_mode = 1;
  io_read_fail = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
  CHECK (DOAS ("/bin/true") == 1 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0);
  status_reaped ();

  /* EINTR is retried; the marker still starts the real command. */
  reset_state ();
  tty_mode = 1;
  io_read_eintr = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("/bin/true") == 37);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1);
  status_reaped ();
  reset_state ();
  tty_mode = 1;
  io_read_eintr = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (DOAS ("/bin/true") == 37 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1);
  status_reaped ();

  /* A failed marker write never reaches the verifier. */
  reset_state ();
  tty_mode = 1;
  io_write_fail = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
  CHECK (SUDO ("/bin/true") == 125);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 0);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 0);
  status_reaped ();
  reset_state ();
  tty_mode = 1;
  io_write_fail = 1;
  script (1, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED);
  CHECK (DOAS ("/bin/true") == 125 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 0);
  status_reaped ();

  /* One interrupted write is retried and the command still runs. */
  reset_state ();
  tty_mode = 1;
  io_write_eintr = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (SUDO ("/bin/true") == 37 && count_op (BASHOS_AUTH_IOC_EXEC_VERIFY) == 1);
  CHECK (count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1);
  status_reaped ();
  reset_state ();
  tty_mode = 1;
  io_write_eintr = 1;
  script (2, BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED, BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
  CHECK (DOAS ("/bin/true") == 37 && count_op (BASHOS_AUTH_IOC_EXEC_INTERACTIVE) == 1);
  status_reaped ();

  CHECK (sigprocmask (SIG_UNBLOCK, &block, NULL) == 0);
}

static int
has_backslash_newline (const char *s)
{
  for (; s[0]; s++)
    if (s[0] == '\\' && s[1] == '\n')
      return 1;
  return 0;
}

static void
shell_tests (void)
{
  unsetenv ("SHELL");
  setenv ("SHELL", "/usr/bin/env", 1);
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture") == 41);
  CHECK (S->argc == 1 && !strcmp (S->argv[0], "/usr/bin/env") && !strcmp (S->path, "/usr/bin/env"));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-i", "-u", "fixture") == 41);
  CHECK (!strcmp (S->argv[0], "-sh") && !strcmp (S->path, "/bin/sh"));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture", "echo", "it's") == 41);
  CHECK (!strcmp (S->path, "/usr/bin/env") && S->argc == 3 && !strcmp (S->argv[0], "/usr/bin/env"));
  CHECK (!strcmp (S->argv[1], "-c") && !strcmp (S->argv[2], "echo it\\'s"));
  /* sudo(8) escape class. Empty is '' and a newline stays inside quotes.
     The string is one shell command: $HOME expands, $(id) does not run. */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture", "printf", "a b", "it's", "$HOME", "a\\b", "x;y", "", "a\nb") == 41);
  CHECK (S->argc == 3 && !strcmp (S->argv[1], "-c"));
  CHECK (!strcmp (S->argv[2], "printf a\\ b it\\'s $HOME a\\\\b x\\;y '' 'a\nb'"));
  CHECK (!has_backslash_newline (S->argv[2]));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture", "printf", "$(id)") == 41);
  CHECK (!strcmp (S->argv[2], "printf $\\(id\\)"));
  /* doas keeps the target shell and the single-quoted command string. */
  reset_state ();
  root_route = 1;
  CHECK (DOAS ("-s", "-u", "fixture") == 41);
  CHECK (!strcmp (S->argv[0], "/bin/sh") && !strcmp (S->path, "/bin/sh"));
  reset_state ();
  root_route = 1;
  CHECK (DOAS ("-s", "-u", "fixture", "echo", "it's") == 41);
  CHECK (!strcmp (S->path, "/bin/sh") && S->argc == 3 && !strcmp (S->argv[1], "-c"));
  CHECK (!strcmp (S->argv[2], "'echo' 'it'\\''s'"));

  unsetenv ("SHELL");
  reset_state ();
  CHECK (SUDO ("-n", "-i", "-u", "fixture", "echo", "it's") == 37);
  CHECK (AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_LOGIN);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", "-l", "-c", "echo it\\'s", NULL));
  setenv ("SHELL", "/bin/sh", 1);
  reset_state ();
  CHECK (SUDO ("-n", "-s", "-u", "fixture", "not-a-path", "x y") == 37);
  CHECK (AUTHZ (0)->p.mode == BASHOS_AUTH_PRIVCMD_MODE_SHELL);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", "-c", "not-a-path x\\ y", NULL));
  reset_state ();
  CHECK (SUDO ("-n", "-s", "-u", "fixture", "printf", "a b", "it's", "$HOME", "a\\b", "x;y", "", "a\nb") == 37);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", "-c",
                  "printf a\\ b it\\'s $HOME a\\\\b x\\;y '' 'a\nb'", NULL));
  reset_state ();
  CHECK (SUDO ("-n", "-s", "-u", "fixture", "printf", "$(id)") == 37);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/sh", "-c", "printf $\\(id\\)", NULL));
  unsetenv ("SHELL");
  reset_state ();
  CHECK (DOAS ("-n", "-u", "fixture", "-s", "/bin/true") == 37);
  CHECK (blob_is (AUTHZ (0)->argv, AUTHZ (0)->argv_bytes, "/bin/true", NULL));

  /* The target shell is /bin/sh. $HOME expands. An empty word and a
     newline survive. A naive backslash would drop both. */
  setenv ("SHELL", "/bin/sh", 1);
  reset_state ();
  root_route = 1;
  exec_real = 1;
  CHECK (SUDO ("-s", "-u", "fixture", "test", "$HOME", "=", home_dir) == 0);
  reset_state ();
  root_route = 1;
  exec_real = 1;
  CHECK (SUDO ("-s", "-u", "fixture", "test", "-z", "", "-a", "-z", "") == 0);
  {
    const char *nl_script = "nl='\n'\ntest \"$1\" = \"a${nl}b\"\n";
    reset_state ();
    root_route = 1;
    exec_real = 1;
    CHECK (SUDO ("-s", "-u", "fixture", "sh", "-c", (char *) nl_script, "_", "a\nb") == 0);
  }
  unsetenv ("SHELL");

  /* With $SHELL unset, sudo -s uses the invoking account's shell. */
  caller_shell = "/bin/bash";
  accounts ();
  unsetenv ("SHELL");
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture") == 41);
  CHECK (!strcmp (S->argv[0], "/bin/bash") && !strcmp (S->path, "/bin/bash"));
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-i", "-u", "fixture") == 41 && !strcmp (S->argv[0], "-sh"));
  setenv ("SHELL", "bash", 1);		/* relative: not used */
  reset_state ();
  root_route = 1;
  CHECK (SUDO ("-s", "-u", "fixture") == 41 && !strcmp (S->argv[0], "/bin/bash"));
  caller_shell = "/bin/sh";
  accounts ();
  unsetenv ("SHELL");
}

int
main (int argc, char **argv)
{
  S = mmap (NULL, sizeof *S, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  CHECK (S != MAP_FAILED);
  const char *base = getenv ("SOL_SUDO_TMPDIR") ? getenv ("SOL_SUDO_TMPDIR") : "/tmp";
  snprintf (scratch, sizeof scratch, "%s/sol-sudo-XXXXXX", base);
  CHECK (mkdtemp (scratch));
  snprintf (passwd_path, sizeof passwd_path, "%s/passwd", scratch);
  snprintf (group_path, sizeof group_path, "%s/group", scratch);
  accounts ();
  /* The editor: appends to each file, honours EDITOR_EXIT, and can attack
     the originals or its copies between open and copyback. */
  char editor[PATH_MAX], text[4096];
  snprintf (editor, sizeof editor, "%s/editor", scratch);
  snprintf (text, sizeof text,
            "#!/bin/sh\n"
            "PATH=/usr/bin:/bin\n"
            "[ \"$1\" = --append ] && shift\n"
            "for f; do printf +edited >> \"$f\" || exit 9; done\n"
            "d=%s\n"
            "case \"$EDITOR_ACTION\" in\n"
            "temp-symlink) rm -f \"$1\" && ln -s \"$d/original1\" \"$1\" ;;\n"
            "symlink) mv \"$d/original0\" \"$d/moved\" && ln -s \"$d/moved\" \"$d/original0\" ;;\n"
            "hardlink) ln \"$d/original0\" \"$d/moved\" ;;\n"
            "replace) mv \"$d/original0\" \"$d/moved\" && printf orig0 > \"$d/original0\" ;;\n"
            "chmod) chmod 0644 \"$d/original0\" ;;\n"
            "drift-second) chmod 0644 \"$d/original1\" ;;\n"
            "esac\n"
            "exit ${EDITOR_EXIT:-0}\n", scratch);
  write_file (editor, text);
  CHECK (chmod (editor, 0700) == 0);
  setenv ("PATH", "", 1);
  unsetenv ("SHELL");
  char *exports[] = { "SAFE=caller", "LD_PRELOAD=caller", "BASH_ENV=caller", NULL };
  export_env = exports;

  int rc = 0;
  if (argc == 2 && !strcmp (argv[1], "--dump-request"))
    dump_request ();
  else if (argc == 3)
    work (argv[1], atoi (argv[2]));
  else
    {
      const char *groups[] = { "options", "lookup", "authority", "translation", "root", "edit", "helper",
                               "command", "groups", "status", "shell", NULL };
      for (int g = 0; groups[g]; g++)
        {
          if (argc == 2 && strcmp (argv[1], groups[g])) continue;
          int start = checks;
          if (!strcmp (groups[g], "options")) option_tests ();
          if (!strcmp (groups[g], "lookup")) lookup_tests ();
          if (!strcmp (groups[g], "authority")) authority_tests ();
          if (!strcmp (groups[g], "translation")) translation_tests ();
          if (!strcmp (groups[g], "root")) root_tests ();
          if (!strcmp (groups[g], "edit")) edit_tests ();
          if (!strcmp (groups[g], "helper")) helper_tests ();
          if (!strcmp (groups[g], "command")) command_tests ();
          if (!strcmp (groups[g], "groups")) group_tests ();
          if (!strcmp (groups[g], "status")) status_tests ();
          if (!strcmp (groups[g], "shell")) shell_tests ();
          printf ("group %s: %d assertions passed\n", groups[g], checks - start);
          rc = 1;
        }
      CHECK (rc == 1);
      rc = 0;
      printf ("sol-sudo: %d assertions passed; no skipped fixtures\n", checks);
    }
  /* Remove only what this process created. */
  const char *mine[] = { "passwd", "group", "editor", "moved", NULL };
  for (int i = 0; mine[i]; i++)
    {
      char p[PATH_MAX];
      snprintf (p, sizeof p, "%s/%s", scratch, mine[i]);
      unlink (p);
    }
  (void) rmdir (home_dir);
  CHECK (rmdir (scratch) == 0);
  return rc;
}
