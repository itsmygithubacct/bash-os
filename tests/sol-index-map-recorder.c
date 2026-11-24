/* SPDX-License-Identifier: MIT */
/* Linked into the indexcheck sanitizer shell only, by
 * tests/sol-index-sanitize.sh. At start-up, before main, every process of
 * that executable copies its own /proc/self/cmdline and /proc/self/maps
 * into EXE.maps/PID-N.cmdline and EXE.maps/PID-N.maps, where EXE is the
 * resolved /proc/self/exe, if that directory exists and is writable. The
 * script then proves from inside each process, as the module stages do with
 * their loader, that every process of the binary mapped libasan; no outside
 * /proc watcher can miss a short-lived process. Without the directory it
 * does nothing. errno is preserved and no descriptor stays open.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Lets the script confirm a prebuilt SOL_INDEX_ASAN_BASH carries this. */
__attribute__ ((used))
const char bos_index_map_recorder_marker[] = "bash-os index sanitizer map recorder v1";

static void
bos_copy (const char *from, int out)
{
  char buf[8192];
  ssize_t n;
  int in = open (from, O_RDONLY | O_CLOEXEC);

  if (in < 0)
    return;
  while ((n = read (in, buf, sizeof buf)) > 0)
    if (write (out, buf, (size_t) n) != n)
      break;
  close (in);
}

__attribute__ ((constructor))
static void
bos_index_map_record (void)
{
  int saved = errno;
  char dir[4096], path[4200];
  ssize_t n = readlink ("/proc/self/exe", dir, sizeof dir - sizeof ".maps");

  if (n > 0)
    {
      memcpy (dir + n, ".maps", sizeof ".maps");
      if (access (dir, W_OK) == 0)
        /* PID-N: a PID reused within one stage still gets its own record. */
        for (int k = 0; k < 1000; k++)
          {
            int out;
            snprintf (path, sizeof path, "%s/%ld-%d.cmdline", dir, (long) getpid (), k);
            out = open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (out < 0)
              {
                if (errno == EEXIST)
                  continue;
                break;
              }
            bos_copy ("/proc/self/cmdline", out);
            close (out);
            snprintf (path, sizeof path, "%s/%ld-%d.maps", dir, (long) getpid (), k);
            out = open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (out >= 0)
              {
                bos_copy ("/proc/self/maps", out);
                close (out);
              }
            break;
          }
    }
  errno = saved;
}
