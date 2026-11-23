/* SPDX-License-Identifier: MIT */
/* sync.c — the sync(1) command as a bash loadable builtin.
 *
 *   sync [-d|-f] [FILE]...
 *
 * Written for bash-os from the coreutils manual, POSIX and the observed
 * behaviour of GNU coreutils 9.7 sync (its messages, exit status and
 * system-call sequence, seen from outside the program).
 *
 * With no FILE, flush every filesystem with sync(2). With FILEs, each one
 * is opened read-only (write-only when reading is refused), without
 * blocking on FIFOs or devices, and flushed with fsync(2), with
 * fdatasync(2) under -d/--data, or through syncfs(2) of its filesystem
 * under -f/--file-system. A FILE that cannot be opened or flushed is
 * reported and the rest are still processed; the status is then 1.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "gnu-longopt.h"

enum { SYNC_EVERYTHING, SYNC_FILE, SYNC_DATA, SYNC_FILESYSTEM };

/* Report one failure about FILE: "WHAT 'FILE': ERROR". */
static void
sync_fail (const char *what, const char *file, int error)
{
  char *q = bos_quoteaf (file);
  builtin_error ("%s %s: %s", what, q ? q : file, strerror (error));
  free (q);
}

/* Flush one named FILE the way MODE asks; 0 on success, -1 after a
   diagnostic. */
static int
sync_one (const char *file, int mode)
{
  int fd = open (file, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      /* A file the caller may write but not read can still be flushed. */
      int first = errno;
      fd = open (file, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
      if (fd < 0)
        {
          sync_fail ("error opening", file, first);
          return -1;
        }
    }

  int rc = 0;
  /* O_NONBLOCK only kept the open from waiting on a FIFO or a device. */
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags & ~O_NONBLOCK) < 0)
    {
      sync_fail ("couldn't reset non-blocking mode", file, errno);
      rc = -1;
    }
  else
    {
      int r;
      if (mode == SYNC_DATA)
        r = fdatasync (fd);
      else if (mode == SYNC_FILESYSTEM)
        {
#if defined (__linux__)
          r = syncfs (fd);
#else
          sync ();
          r = 0;
#endif
        }
      else
        r = fsync (fd);
      if (r < 0)
        {
          sync_fail ("error syncing", file, errno);
          rc = -1;
        }
    }

  if (close (fd) < 0 && rc == 0)
    {
      sync_fail ("failed to close", file, errno);
      rc = -1;
    }
  return rc;
}

static void
sync_usage (void)
{
  printf ("Usage: sync [OPTION] [FILE]...\n"
          "Synchronize cached writes to persistent storage\n"
          "\n"
          "If one or more files are specified, sync only them,\n"
          "or their containing file systems.\n"
          "\n"
          "  -d, --data             sync only file data, no unneeded metadata\n"
          "  -f, --file-system      sync the file systems that contain the files\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n");
}

int
sync_builtin (WORD_LIST *list)
{
  static const struct bos_longopt longopts[] = {
    { "data",        BOS_NO_ARG, 'd' },
    { "file-system", BOS_NO_ARG, 'f' },
    { "help",        BOS_NO_ARG, BOS_OPT_HELP },
    { "version",     BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
  };
  bos_getopt g;
  int c, data = 0, filesystem = 0;

  bos_getopt_init (&g, "sync", "df", longopts, list);
  while ((c = bos_getopt_next (&g)) != -1)
    switch (c)
      {
      case 'd':
        data = 1;
        break;
      case 'f':
        filesystem = 1;
        break;
      case BOS_OPT_HELP:
        bos_getopt_free (&g);
        sync_usage ();
        return sh_chkwrite (EXECUTION_SUCCESS);
      case BOS_OPT_VERSION:
        bos_getopt_free (&g);
        printf ("sync (bash-os)\n");
        return sh_chkwrite (EXECUTION_SUCCESS);
      default:
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
      }

  int rc = EXECUTION_SUCCESS;
  if (data && filesystem)
    {
      builtin_error ("cannot specify both --data and --file-system");
      rc = EXECUTION_FAILURE;
    }
  else if (data && g.noperands == 0)
    {
      builtin_error ("--data needs at least one argument");
      rc = EXECUTION_FAILURE;
    }
  else if (g.noperands == 0)
    sync ();
  else
    {
      int mode = data ? SYNC_DATA : filesystem ? SYNC_FILESYSTEM : SYNC_FILE;
      for (int i = 0; i < g.noperands; i++)
        {
          QUIT;
          if (sync_one (g.operands[i], mode) < 0)
            rc = EXECUTION_FAILURE;
        }
    }
  bos_getopt_free (&g);
  return rc;
}

char *sync_doc[] = {
  "Sync disks or specified files.",
  "",
  "If one or more FILEs is supplied, force completion of pending writes",
  "to those files. Otherwise, force completion of any pending disk",
  "writes.",
  "",
  "  -d, --data         sync only file data, no unneeded metadata",
  "  -f, --file-system  sync the file systems that contain the files",
  "",
  "Exit Status: zero unless any FILE could not be synced.",
  (char *) NULL
};

struct builtin sync_struct = {
  "sync",
  sync_builtin,
  BUILTIN_ENABLED,
  sync_doc,
  "sync",
  0
};
