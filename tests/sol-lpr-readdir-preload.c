/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Fail readdir only for the directory named by BASHLPR_READDIR_FAIL_DIR.
 * Every other directory, including those bash opens while starting, is read
 * through the real libc function. */
static struct dirent *
hooked_readdir (DIR *dirp)
{
  static struct dirent *(*real_readdir) (DIR *) = 0;
  if (!real_readdir)
    real_readdir = (struct dirent *(*) (DIR *)) dlsym (RTLD_NEXT, "readdir");
  const char *want = getenv ("BASHLPR_READDIR_FAIL_DIR");
  if (want && *want && dirp) {
    int fd = dirfd (dirp);
    char link[64];
    char path[PATH_MAX];
    if (fd >= 0 && snprintf (link, sizeof link, "/proc/self/fd/%d", fd) < (int) sizeof link) {
      ssize_t n = readlink (link, path, sizeof path - 1);
      if (n >= 0) {
        path[n] = '\0';
        if (strcmp (path, want) == 0) {
          errno = EIO;
          return 0;
        }
      }
    }
  }
  return real_readdir (dirp);
}

struct dirent *readdir (DIR *dirp) { return hooked_readdir (dirp); }
