/* SPDX-License-Identifier: MIT */
/* rmdir.c — the rmdir(1) command as a bash loadable builtin.
 *
 *   rmdir [OPTION]... DIRECTORY...
 *
 * Written for bash-os from the coreutils manual, POSIX and the observed
 * behaviour of GNU coreutils 9.7 rmdir (its messages, exit status and
 * system-call sequence, seen from outside the program).
 *
 *   --ignore-fail-on-non-empty   do not report a directory that could not
 *                                be removed because it is not empty
 *   -p, --parents                then remove each ancestor named in the
 *                                operand, stopping at the first failure
 *   -v, --verbose                report each directory as it is removed
 *
 * Each operand is removed with rmdir(2) exactly as written. With -p, the
 * last component (and the slashes around it) is cut off repeatedly and
 * each remaining prefix is removed in turn; a failure there is reported
 * as "failed to remove directory". A failure of any operand makes the
 * status 1; the remaining operands are still processed.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "gnu-longopt.h"

enum { RMDIR_OPT_IGNORE = BOS_OPT_FIRST };

typedef struct
{
  int ignore_nonempty;
  int parents;
  int verbose;
} rmdir_opts;

/* Whether DIR could be read and holds something besides "." and "..". */
static int
rmdir_has_entries (const char *dir)
{
  int fd = open (dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  DIR *d;
  struct dirent *e;
  int found = 0;

  if (fd < 0)
    return 0;
  d = fdopendir (fd);
  if (d == NULL)
    {
      close (fd);
      return 0;
    }
  while ((e = readdir (d)) != NULL)
    if (strcmp (e->d_name, ".") && strcmp (e->d_name, ".."))
      {
        found = 1;
        break;
      }
  closedir (d);
  return found;
}

/* Whether the failure ERROR to remove DIR is one that
   --ignore-fail-on-non-empty hides. */
static int
rmdir_ignorable (const char *dir, int error)
{
  if (error == ENOTEMPTY || error == EEXIST)
    return 1;
  /* Permission and busy errors can hide a non-empty directory. */
  if (error == EACCES || error == EPERM || error == EBUSY || error == EROFS)
    return rmdir_has_entries (dir);
  return 0;
}

/* NAME ends in a slash and, without it, names a symbolic link. */
static int
rmdir_slash_symlink (const char *name)
{
  size_t len = strlen (name);
  struct stat st;
  char *bare;
  int r;

  if (len < 2 || name[len - 1] != '/')
    return 0;
  if (stat (name, &st) != 0 && errno == ENOTDIR)
    return 0;
  while (len > 1 && name[len - 1] == '/')
    len--;
  bare = strndup (name, len);
  if (bare == NULL)
    return 0;
  r = lstat (bare, &st) == 0 && S_ISLNK (st.st_mode);
  free (bare);
  return r;
}

static void
rmdir_fail (const char *dir, int ancestor, int error)
{
  char *q = bos_quoteaf (dir);
  const char *shown = q ? q : dir;

  fflush (stdout);
  if (!ancestor && error == ENOTDIR && rmdir_slash_symlink (dir))
    builtin_error ("failed to remove %s: Symbolic link not followed", shown);
  else if (ancestor && error != ENOTDIR)
    builtin_error ("failed to remove directory %s: %s", shown, strerror (error));
  else
    builtin_error ("failed to remove %s: %s", shown, strerror (error));
  free (q);
}

/* Remove DIR. Returns 0 when it is gone, 1 when a failure was ignored
   (nothing further should be tried), -1 after reporting a failure. */
static int
rmdir_one (const char *dir, int ancestor, const rmdir_opts *o)
{
  int error;

  if (o->verbose)
    {
      char *q = bos_quoteaf (dir);
      printf ("rmdir: removing directory, %s\n", q ? q : dir);
      fflush (stdout);
      free (q);
    }
  if (rmdir (dir) == 0)
    return 0;
  error = errno;
  if (o->ignore_nonempty && rmdir_ignorable (dir, error))
    return 1;
  rmdir_fail (dir, ancestor, error);
  return -1;
}

/* Remove the operand ARG and, under -p, its ancestors. */
static int
rmdir_operand (const char *arg, const rmdir_opts *o)
{
  char *path;
  size_t len;
  int r = rmdir_one (arg, 0, o);

  if (r != 0)
    return r < 0;
  if (!o->parents)
    return 0;

  path = strdup (arg);
  if (path == NULL)
    {
      builtin_error ("memory exhausted");
      return 1;
    }
  len = strlen (path);
  while (!interrupt_state && !terminating_signal)
    {
      /* Drop trailing slashes, then the last component, then the slashes
         before it; a name of slashes alone has no parent. */
      while (len > 0 && path[len - 1] == '/')
        len--;
      if (len == 0)
        break;
      while (len > 0 && path[len - 1] != '/')
        len--;
      if (len == 0)
        break;
      while (len > 1 && path[len - 1] == '/')
        len--;
      path[len] = '\0';
      r = rmdir_one (path, 1, o);
      if (r != 0)
        {
          free (path);
          return r < 0;
        }
    }
  free (path);
  return 0;
}

static void
rmdir_usage (void)
{
  fputs ("Usage: rmdir [OPTION]... DIRECTORY...\n"
         "Remove the DIRECTORY(ies), if they are empty.\n"
         "\n"
         "      --ignore-fail-on-non-empty\n"
         "                    ignore each failure to remove a non-empty directory\n"
         "  -p, --parents     remove DIRECTORY and its ancestors;\n"
         "                    e.g., 'rmdir -p a/b' is similar to 'rmdir a/b a'\n"
         "\n"
         "  -v, --verbose     output a diagnostic for every directory processed\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n",
         stdout);
}

int
rmdir_builtin (WORD_LIST *list)
{
  static const struct bos_longopt longopts[] = {
    { "ignore-fail-on-non-empty", BOS_NO_ARG, RMDIR_OPT_IGNORE },
    { "parents",                  BOS_NO_ARG, 'p' },
    { "verbose",                  BOS_NO_ARG, 'v' },
    { "help",                     BOS_NO_ARG, BOS_OPT_HELP },
    { "version",                  BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
  };
  rmdir_opts o;
  bos_getopt g;
  int c, i, failed = 0;

  memset (&o, 0, sizeof o);
  bos_getopt_init (&g, "rmdir", "pv", longopts, list);
  while ((c = bos_getopt_next (&g)) != -1)
    {
      switch (c)
        {
        case RMDIR_OPT_IGNORE:
          o.ignore_nonempty = 1;
          break;
        case 'p':
          o.parents = 1;
          break;
        case 'v':
          o.verbose = 1;
          break;
        case BOS_OPT_HELP:
          bos_getopt_free (&g);
          rmdir_usage ();
          return sh_chkwrite (EXECUTION_SUCCESS);
        case BOS_OPT_VERSION:
          bos_getopt_free (&g);
          printf ("rmdir (bash-os)\n");
          return sh_chkwrite (EXECUTION_SUCCESS);
        default:
          bos_getopt_free (&g);
          return EXECUTION_FAILURE;
        }
    }

  if (g.noperands == 0)
    {
      bos_getopt_free (&g);
      builtin_error ("missing operand");
      bos_try_help ("rmdir");
      return EXECUTION_FAILURE;
    }

  for (i = 0; i < g.noperands; i++)
    {
      QUIT;
      failed |= rmdir_operand (g.operands[i], &o);
    }
  bos_getopt_free (&g);
  return sh_chkwrite (failed ? EXECUTION_FAILURE : EXECUTION_SUCCESS);
}

char *rmdir_doc[] = {
  "Remove empty directories.",
  "",
  "Remove each DIRECTORY, if it is empty.",
  "",
  "    --ignore-fail-on-non-empty",
  "                    ignore each failure to remove a non-empty directory",
  "    -p, --parents   remove DIRECTORY and its ancestors; e.g., 'rmdir -p a/b'",
  "                    is similar to 'rmdir a/b a'",
  "    -v, --verbose   output a diagnostic for every directory processed",
  "",
  "The exit status is 0 unless a directory could not be removed.",
  (char *)NULL
};

struct builtin rmdir_struct = {
  "rmdir",
  rmdir_builtin,
  BUILTIN_ENABLED,
  rmdir_doc,
  "rmdir [-pv] [--ignore-fail-on-non-empty] DIRECTORY...",
  0
};
