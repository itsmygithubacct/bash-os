/* SPDX-License-Identifier: MIT
 * Test-only barrier: pause a private FIFO's writer open until the test
 * has closed the matching reader. Not part of lpr.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int openat(int directory, const char *path, int flags, ...)
{
  int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  int fd = real_openat(directory, path, flags, mode);
  const char *target = getenv("LPR_REVIEW_CTL");
  const char *ready = getenv("LPR_REVIEW_READY");
  const char *go = getenv("LPR_REVIEW_GO");
  if (fd >= 0 && target && ready && go && !strcmp(path, target)
      && (flags & O_ACCMODE) == O_WRONLY) {
    int marker = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker < 0) { close(fd); return -1; }
    close(marker);
    struct timespec pause = {0, 1000000};
    for (int i = 0; i < 10000; i++) {
      if (access(go, F_OK) == 0) return fd;
      nanosleep(&pause, NULL);
    }
    close(fd); errno = ETIMEDOUT; return -1;
  }
  return fd;
}
