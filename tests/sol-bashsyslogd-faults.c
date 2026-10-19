/* SPDX-License-Identifier: MIT
 * Task-private syscall fixtures; never loaded by a production build.
 * With BASHSYSLOGD_TEST_BLOCK set to an existing private marker, UDP
 * sendto fails with EAGAIN. Removing it restores real loopback sends.
 * BASHSYSLOGD_TEST_CLOCK fixes only the file timestamp for exact bytes.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

time_t time(time_t *out)
{
  static time_t (*real_time)(time_t *);
  time_t value;
  if (getenv("BASHSYSLOGD_TEST_CLOCK"))
    {
      value = 1700000000;
      if (out) *out = value;
      return value;
    }
  if (!real_time) real_time = dlsym(RTLD_NEXT, "time");
  return real_time(out);
}

ssize_t sendto(int fd, const void *buf, size_t size, int flags,
               const struct sockaddr *addr, socklen_t addrlen)
{
  static ssize_t (*real_sendto)(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
  const char *marker = getenv("BASHSYSLOGD_TEST_BLOCK");
  if (marker && access(marker, F_OK) == 0)
    {
      errno = EAGAIN;
      return -1;
    }
  if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
  return real_sendto(fd, buf, size, flags, addr, addrlen);
}

int mkstemp(char *name)
{
  static int (*real_mkstemp)(char *);
  const char *marker = getenv("BASHSYSLOGD_TEST_REWRITE_BLOCK");
  if (marker && access(marker, F_OK) == 0)
    { errno = EACCES; return -1; }
  if (!real_mkstemp) real_mkstemp = dlsym(RTLD_NEXT, "mkstemp");
  return real_mkstemp(name);
}
