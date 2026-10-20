/* SPDX-License-Identifier: MIT */
/* Fault injection for production timestamp framing; only the named private log. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t n)
{
  char link[64], path[1024];
  const char *target = getenv("SV_TEST_WRITE_TARGET");
  if (target && n)
    {
      snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
      ssize_t len = readlink(link, path, sizeof path - 1);
      if (len >= 0)
        {
          path[len] = 0;
          if (strcmp(path, target) == 0)
            {
              static unsigned calls;
              ++calls;
              if (calls % 3 == 1) { errno = EINTR; return -1; }
              if (n > 7) n = 7;
            }
        }
    }
  return syscall(SYS_write, fd, buf, n);
}
