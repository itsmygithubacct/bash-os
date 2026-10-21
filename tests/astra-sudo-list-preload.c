/* SPDX-License-Identifier: MIT */
/* Private policy/metadata interfaces for native sudo list tests. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../loadables/common/_bashos_auth_uapi.h"
#include "../loadables/_mbedtls/sha256.h"
static int authority_fd = -1;
static unsigned infos;
static const char *policy (void) { return getenv ("SUDO_LIST_TEST_POLICY"); }
int open (const char *path, int flags, ...)
{
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
    { va_list ap; va_start (ap, flags); mode = va_arg (ap, int); va_end (ap); }
  if (!strcmp (path, "/dev/bashos-auth"))
    {
      if (!policy ()) { errno = ENOENT; return -1; }
      infos = 0;
      authority_fd = syscall (SYS_openat, AT_FDCWD, policy (), O_RDONLY | O_CLOEXEC, 0);
      return authority_fd;
    }
  return syscall (SYS_openat, AT_FDCWD, path, flags, mode);
}
int open64 (const char *path, int flags, ...)
{
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
    { va_list ap; va_start (ap, flags); mode = va_arg (ap, int); va_end (ap); }
  return open (path, flags, mode);
}
FILE *fopen (const char *path, const char *mode)
{
  FILE *(*real_fopen)(const char *, const char *) = dlsym (RTLD_NEXT, "fopen");
  const char *passwd = getenv ("SUDO_LIST_TEST_PASSWD");
  if (!strcmp (path, "/etc/passwd") && passwd) path = passwd;
  return real_fopen (path, mode);
}
FILE *fopen64 (const char *path, const char *mode) { return fopen (path, mode); }
int fstat (int fd, struct stat *st)
{
  int rc = syscall (SYS_fstat, fd, st);
  struct stat p;
  if (rc == 0 && policy () && stat (policy (), &p) == 0 &&
      st->st_dev == p.st_dev && st->st_ino == p.st_ino) st->st_uid = 0;
  return rc;
}
int ioctl (int fd, unsigned long op, ...)
{
  va_list ap; va_start (ap, op); void *v = va_arg (ap, void *); va_end (ap);
  if (fd != authority_fd) return syscall (SYS_ioctl, fd, op, v);
  if (op == BASHOS_AUTH_IOC_VERSION)
    {
      struct bashos_auth_version *p = v;
      p->abi_major = BASHOS_AUTH_ABI_MAJOR; p->abi_minor = BASHOS_AUTH_ABI_MINOR;
      p->features = BASHOS_AUTH_FEAT_PRIVCMD; return 0;
    }
  if (op == BASHOS_AUTH_IOC_POLICY_INFO)
    {
      struct bashos_auth_policy_info *p = v;
      struct stat st;
      if (stat (policy (), &st)) return -1;
      p->status = BASHOS_AUTH_POLICY_STATUS_OK; p->uid = 0; p->gid = st.st_gid;
      p->mode = st.st_mode; p->ino = st.st_ino; p->size_bytes = st.st_size;
      p->mtime_sec = st.st_mtime; p->ctime_sec = st.st_ctime;
      p->generation = 7;
      snprintf (p->path, sizeof p->path, "%s", policy ());
      FILE *f = fopen (policy (), "r");
      if (!f) return -1;
      mbedtls_sha256_context sha; unsigned char buf[1024]; size_t n;
      mbedtls_sha256_init (&sha); mbedtls_sha256_starts (&sha, 0);
      while ((n = fread (buf, 1, sizeof buf, f))) mbedtls_sha256_update (&sha, buf, n);
      int error = ferror (f); fclose (f);
      mbedtls_sha256_finish (&sha, p->policy_digest); mbedtls_sha256_free (&sha);
      if (error) { errno = EIO; return -1; }
      const char *fault = getenv ("SUDO_LIST_TEST_FAULT");
      if (fault && !strcmp (fault, "digest")) p->policy_digest[0] ^= 1;
      if (fault && !strcmp (fault, "drift") && infos) p->generation++;
      infos++;
      return 0;
    }
  /* Any attempted authorization or credential operation is a test failure. */
  _exit (98);
}
