/* Fail the Nth realloc of 128 bytes.
 *
 * el_end is an int plus a flag, 8 bytes with the ABI padding this tree
 * uses. The end list grows 8, 16, 32, ... so the first growth past the
 * initial block asks for 16 * 8 == 128 bytes. Failing that realloc is
 * how the old el_ends_add wrote before the buffer. Startup of an
 * expr-only shell does not realloc 128 bytes; the two such calls are
 * inside the matcher.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static int seen128;

void *
realloc (void *p, size_t sz)
{
  static void *(*real) (void *, size_t);
  if (!real)
    real = dlsym (RTLD_NEXT, "realloc");
  if (sz == 128)
    {
      int at = getenv ("FAIL_N") ? atoi (getenv ("FAIL_N")) : 0;
      seen128++;
      if (at && seen128 == at)
        {
          fprintf (stderr, "FAIL128 %d\n", seen128);
          return NULL;
        }
    }
  return real (p, sz);
}
