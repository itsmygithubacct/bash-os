/* SPDX-License-Identifier: MIT */
/* Test-only fopen link wrapper: exercise production entropy reads using an
   owned regular-file fixture. Linked only into the sanitizer test module. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern FILE *__real_fopen (const char *, const char *);
FILE *
__wrap_fopen (const char *path, const char *mode)
{
  const char *fixture = getenv ("SOL_COREUTILS_RANDOM_FIXTURE");
  if (fixture && strcmp (path, "/dev/urandom") == 0)
    return __real_fopen (fixture, mode);
  return __real_fopen (path, mode);
}
