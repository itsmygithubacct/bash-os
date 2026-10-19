/* SPDX-License-Identifier: MIT
 * Compile the production daemon with a narrowly injected allocation failure.
 * The marker and the deliberately distinct queued payload size belong to tests.
 */
#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

static void *queue_fixture_malloc(size_t size)
{
  const char *marker = getenv("BASHSYSLOGD_TEST_ALLOC_BLOCK");
  if (size == 7199 && marker && access(marker, F_OK) == 0)
    { errno = ENOMEM; return NULL; }
  return malloc(size);
}
#define malloc queue_fixture_malloc
#include "../loadables/bashsyslogd.c"
