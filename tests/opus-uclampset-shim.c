/* SPDX-License-Identifier: MIT */
/* LD_PRELOAD interposer for uclampset tests. Intercepts syscall(2) for
   SYS_sched_setattr and SYS_sched_getattr only, records every request the
   production loadable builds, and either passes it to the kernel, fails it
   with an injected errno, or emulates a CONFIG_UCLAMP_TASK kernel's clamp
   bookkeeping. Everything else goes straight to libc.

   UCLAMP_SHIM_DIR  state directory; unset means pure pass-through
   UCLAMP_SHIM_SET  real | emulate | errno:N        (default real)
   UCLAMP_SHIM_GET  real | errno:N                   (default real)
   UCLAMP_SHIM_FAIL_WRITE  basename whose write-mode open fails with EIO

   Write-mode opens of sched_util_clamp_* files are logged in order too,
   which is how the system setter's write ordering and rollback are observed.

   With SET=emulate a sched_getattr result is the kernel's real answer with
   util_min/util_max replaced by the emulated values (0/1024 until set), so
   policy, nice and priority still come from the kernel. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct shim_attr {
  uint32_t size, policy;
  uint64_t flags;
  int32_t nice;
  uint32_t prio;
  uint64_t runtime, deadline, period;
  uint32_t util_min, util_max;
};

#define F_RESET_ON_FORK 0x01ULL
#define F_RECLAIM       0x02ULL
#define F_DL_OVERRUN    0x04ULL
#define F_KEEP_POLICY   0x08ULL
#define F_KEEP_PARAMS   0x10ULL
#define F_UTIL_MIN      0x20ULL
#define F_UTIL_MAX      0x40ULL
#define F_ALL           0x7fULL

typedef long (*syscall_fn) (long, ...);

static syscall_fn
real_syscall (void)
{
  static syscall_fn fn;
  if (!fn)
    fn = (syscall_fn) dlsym (RTLD_NEXT, "syscall");
  return fn;
}

static int
injected_errno (const char *mode)
{
  if (mode && strncmp (mode, "errno:", 6) == 0)
    return atoi (mode + 6);
  return 0;
}

static void
state_path (char *buf, size_t sz, const char *dir, long pid)
{
  snprintf (buf, sz, "%s/state-%ld", dir, pid);
}

static int
load_state (const char *dir, long pid, uint32_t *mn, uint32_t *mx)
{
  char path[4096];
  unsigned a, b;
  state_path (path, sizeof path, dir, pid);
  FILE *fp = fopen (path, "r");
  if (!fp)
    return -1;
  int ok = fscanf (fp, "%u %u", &a, &b) == 2;
  fclose (fp);
  if (!ok)
    return -1;
  *mn = a;
  *mx = b;
  return 0;
}

static void
save_state (const char *dir, long pid, uint32_t mn, uint32_t mx)
{
  char path[4096];
  state_path (path, sizeof path, dir, pid);
  FILE *fp = fopen (path, "w");
  if (fp)
    {
      fprintf (fp, "%u %u\n", mn, mx);
      fclose (fp);
    }
}

static void
log_line (const char *dir, const char *line)
{
  char path[4096];
  snprintf (path, sizeof path, "%s/log", dir);
  int fd = open (path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (fd < 0)
    return;
  ssize_t ignored = write (fd, line, strlen (line));
  (void) ignored;
  close (fd);
}

static long
emulate_set (const char *dir, long pid, const struct shim_attr *a)
{
  if (a->size < 56 || (a->flags & ~F_ALL))
    return -EINVAL;
  uint32_t cur_min = 0, cur_max = 1024;
  load_state (dir, pid, &cur_min, &cur_max);
  int64_t mn = cur_min, mx = cur_max;
  if (a->flags & F_UTIL_MIN)
    {
      if (a->util_min + 1U > 1024U + 1U)
        return -EINVAL;
      mn = (int32_t) a->util_min;
    }
  if (a->flags & F_UTIL_MAX)
    {
      if (a->util_max + 1U > 1024U + 1U)
        return -EINVAL;
      mx = (int32_t) a->util_max;
    }
  if (mn != -1 && mx != -1 && mn > mx)
    return -EINVAL;
  if (a->flags & F_UTIL_MIN)
    cur_min = mn == -1 ? 0 : (uint32_t) mn;
  if (a->flags & F_UTIL_MAX)
    cur_max = mx == -1 ? 1024 : (uint32_t) mx;
  save_state (dir, pid, cur_min, cur_max);
  return 0;
}

/* sched_getattr's 0/0 is ambiguous on a kernel without CONFIG_UCLAMP_TASK.
   Emulate the read-only support probe too, including a supported 0/0 task.
   This does not redirect any real system files or permit writes to them. */
int
access (const char *path, int mode)
{
  typedef int (*access_fn) (const char *, int);
  static access_fn fn;
  if (!fn)
    fn = (access_fn) dlsym (RTLD_NEXT, "access");
  const char *dir = getenv ("UCLAMP_SHIM_DIR");
  const char *set_mode = getenv ("UCLAMP_SHIM_SET");
  if (dir && set_mode && strcmp (set_mode, "emulate") == 0
      && mode == F_OK
      && strcmp (path, "/proc/sys/kernel/sched_util_clamp_min") == 0)
    return 0;
  return fn (path, mode);
}

typedef int (*open_fn) (const char *, int, ...);

static int
shim_open (const char *sym, const char *path, int flags, mode_t mode)
{
  static open_fn fns[2];
  int idx = strcmp (sym, "open") != 0;
  if (!fns[idx])
    fns[idx] = (open_fn) dlsym (RTLD_NEXT, sym);
  const char *dir = getenv ("UCLAMP_SHIM_DIR");
  const char *base = strrchr (path, '/');
  base = base ? base + 1 : path;
  if (!dir || (flags & O_ACCMODE) == O_RDONLY
      || strncmp (base, "sched_util_clamp_", 17) != 0)
    return fns[idx] (path, flags, mode);
  const char *fail = getenv ("UCLAMP_SHIM_FAIL_WRITE");
  int fd, err;
  if (fail && strcmp (fail, base) == 0)
    {
      fd = -1;
      err = EIO;
    }
  else
    {
      fd = fns[idx] (path, flags, mode);
      err = fd < 0 ? errno : 0;
    }
  char line[512];
  snprintf (line, sizeof line, "write path=%s result=%d\n", base, err);
  log_line (dir, line);
  errno = err;
  return fd;
}

int
open (const char *path, int flags, ...)
{
  mode_t mode = 0;
  if (flags & (O_CREAT | O_TMPFILE))
    {
      va_list ap;
      va_start (ap, flags);
      mode = va_arg (ap, mode_t);
      va_end (ap);
    }
  return shim_open ("open", path, flags, mode);
}

int
open64 (const char *path, int flags, ...)
{
  mode_t mode = 0;
  if (flags & (O_CREAT | O_TMPFILE))
    {
      va_list ap;
      va_start (ap, flags);
      mode = va_arg (ap, mode_t);
      va_end (ap);
    }
  return shim_open ("open64", path, flags, mode);
}

long
syscall (long nr, ...)
{
  va_list ap;
  long a[6];
  va_start (ap, nr);
  for (int i = 0; i < 6; i++)
    a[i] = va_arg (ap, long);
  va_end (ap);

  const char *dir = getenv ("UCLAMP_SHIM_DIR");
  if (!dir || (nr != SYS_sched_setattr && nr != SYS_sched_getattr))
    return real_syscall () (nr, a[0], a[1], a[2], a[3], a[4], a[5]);

  long target = a[0] == 0 ? (long) getpid () : a[0];
  const char *set_mode = getenv ("UCLAMP_SHIM_SET");
  const char *get_mode = getenv ("UCLAMP_SHIM_GET");
  int emulate = set_mode && strcmp (set_mode, "emulate") == 0;
  char line[512];
  long rc;
  int err = 0;

  if (nr == SYS_sched_getattr)
    {
      if ((err = injected_errno (get_mode)))
        rc = -1;
      else
        {
          rc = real_syscall () (nr, a[0], a[1], a[2], a[3], a[4], a[5]);
          err = rc < 0 ? errno : 0;
          if (rc == 0 && emulate)
            {
              struct shim_attr *out = (struct shim_attr *) a[1];
              uint32_t mn = 0, mx = 1024;
              load_state (dir, target, &mn, &mx);
              out->util_min = mn;
              out->util_max = mx;
            }
        }
      snprintf (line, sizeof line, "get caller=%ld pid=%ld result=%d\n",
                (long) getpid (), a[0], err);
      log_line (dir, line);
      errno = err;
      return err ? -1 : rc;
    }

  const struct shim_attr *req = (const struct shim_attr *) a[1];
  if ((err = injected_errno (set_mode)))
    rc = -1;
  else if (emulate)
    {
      /* The kernel still decides whether the target exists. */
      struct shim_attr probe;
      memset (&probe, 0, sizeof probe);
      if (real_syscall () (SYS_sched_getattr, a[0], &probe, sizeof probe, 0) < 0)
        err = errno;
      else
        {
          long e = emulate_set (dir, target, req);
          err = e < 0 ? (int) -e : 0;
        }
      rc = err ? -1 : 0;
    }
  else
    {
      rc = real_syscall () (nr, a[0], a[1], a[2], a[3], a[4], a[5]);
      err = rc < 0 ? errno : 0;
    }
  snprintf (line, sizeof line,
            "set caller=%ld pid=%ld size=%u policy=%u flags=0x%llx nice=%d prio=%u "
            "runtime=%llu deadline=%llu period=%llu min=%d max=%d uflags=%ld result=%d\n",
            (long) getpid (), a[0], req->size, req->policy,
            (unsigned long long) req->flags, req->nice, req->prio,
            (unsigned long long) req->runtime, (unsigned long long) req->deadline,
            (unsigned long long) req->period, (int32_t) req->util_min,
            (int32_t) req->util_max, a[2], err);
  log_line (dir, line);
  errno = err;
  return err ? -1 : rc;
}
