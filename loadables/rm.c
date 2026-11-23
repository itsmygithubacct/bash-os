/* SPDX-License-Identifier: MIT */
/* rm.c — the rm(1) command as a bash loadable builtin.
 *
 *   rm [OPTION]... [FILE]...
 *
 * Written for bash-os from the coreutils manual, POSIX and the observed
 * behaviour of GNU coreutils 9.7 rm (its messages, prompts, exit status
 * and system-call sequence, seen from outside the program).
 *
 *   -f, --force            ignore missing files and operands, never prompt
 *   -i                     prompt before every removal
 *   -I                     prompt once before removing more than three
 *                          files, or when removing recursively
 *   --interactive[=WHEN]   never, once (-I) or always (-i, the default)
 *   --one-file-system      skip directories on other file systems
 *   --no-preserve-root     do not treat '/' specially
 *   --preserve-root[=all]  refuse '/' (default); with 'all', also refuse
 *                          operands on another device than their parent
 *   -r, -R, --recursive    remove directories and their contents
 *   -d, --dir              remove empty directories
 *   -v, --verbose          report each removal
 *
 * Answers to prompts are read from standard input one line at a time, a
 * byte at a time, so a later command still sees the unread answers. A
 * declined file leaves its directory to be prompted for (and to fail as
 * non-empty); a declined descent, a declined empty directory and any
 * error leave every enclosing directory silently in place. Declining is
 * not an error; any failure makes the status 1.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "gnu-longopt.h"

/* Directories deeper than this give up their parent's descriptor while
   they are processed and reopen it through "..", so a deep tree does not
   exhaust the descriptor table. */
#define RM_FD_KEEP 8

/* Verbose output is held back like a fully buffered stdout: it is written
   when an error is reported, when a block fills, and at the end, so it
   interleaves with prompts and diagnostics the way the GNU tool's does. */
#define RM_OUT_BLOCK 4096

enum { RM_ASK_DEFAULT, RM_ASK_NEVER, RM_ASK_ONCE, RM_ASK_ALWAYS };

/* What became of one file: removed, declined in a way that still lets its
   directory be tried, or failed/declined so that every directory above it
   is left alone. */
enum { RM_DONE, RM_KEPT, RM_BLOCKED };

enum
{
  RM_OPT_INTERACTIVE = BOS_OPT_FIRST,
  RM_OPT_ONE_FS,
  RM_OPT_NO_PRESERVE,
  RM_OPT_PRESERVE,
  RM_OPT_TTY
};

typedef struct
{
  int ask;              /* RM_ASK_* */
  int ignore_missing;   /* -f */
  int recursive;        /* -r */
  int dirs;             /* -d */
  int verbose;          /* -v */
  int one_fs;           /* --one-file-system */
  int keep_root;        /* --preserve-root */
  int keep_mounts;      /* --preserve-root=all */
  int tty;              /* standard input is a terminal */
  int status;
  int stopped;          /* interrupted: unwind without further work */
  int root_known;
  struct stat root;     /* "/" */
  dev_t top_dev;        /* device of the current operand */
  char *out;
  size_t out_len, out_cap;
  int out_tty;
  int out_failed;
} rm_state;

/* ---- output ---------------------------------------------------------- */

static void
rm_flush (rm_state *s)
{
  if (s->out_len)
    {
      if (fwrite (s->out, 1, s->out_len, stdout) != s->out_len)
        s->out_failed = 1;
      s->out_len = 0;
    }
  if (fflush (stdout) != 0)
    s->out_failed = 1;
}

static void
rm_put (rm_state *s, const char *text)
{
  size_t n = strlen (text);

  if (s->out_len + n > s->out_cap)
    {
      size_t cap = s->out_cap ? s->out_cap : RM_OUT_BLOCK * 2;
      char *p;

      while (cap < s->out_len + n)
        cap *= 2;
      p = realloc (s->out, cap);
      if (p == NULL)
        {
          rm_flush (s);
          fputs (text, stdout);
          return;
        }
      s->out = p;
      s->out_cap = cap;
    }
  memcpy (s->out + s->out_len, text, n);
  s->out_len += n;
  if (s->out_tty)
    rm_flush (s);
  else if (s->out_len >= RM_OUT_BLOCK)
    {
      size_t whole = s->out_len - s->out_len % RM_OUT_BLOCK;

      if (fwrite (s->out, 1, whole, stdout) != whole)
        s->out_failed = 1;
      if (fflush (stdout) != 0)
        s->out_failed = 1;
      memmove (s->out, s->out + whole, s->out_len - whole);
      s->out_len -= whole;
    }
}

static void
rm_report (rm_state *s, const char *what, const char *path)
{
  char *q;
  char *line;

  if (!s->verbose)
    return;
  q = bos_quoteaf (path);
  if (q == NULL)
    return;
  line = malloc (strlen (what) + strlen (q) + 3);
  if (line)
    {
      sprintf (line, "%s %s\n", what, q);
      rm_put (s, line);
      free (line);
    }
  free (q);
}

/* A diagnostic: earlier verbose output first, as GNU does. */
static void
rm_say (rm_state *s, const char *fmt, ...)
{
  char buf[1024];
  char *text = buf;
  va_list ap;
  int n;

  rm_flush (s);
  va_start (ap, fmt);
  n = vsnprintf (buf, sizeof buf, fmt, ap);
  va_end (ap);
  if (n >= (int) sizeof buf)
    {
      text = malloc ((size_t) n + 1);
      if (text == NULL)
        text = buf;
      else
        {
          va_start (ap, fmt);
          vsnprintf (text, (size_t) n + 1, fmt, ap);
          va_end (ap);
        }
    }
  builtin_error ("%s", text);
  if (text != buf)
    free (text);
}

/* "cannot remove 'PATH': ERROR", and a failing status. */
static void
rm_fail (rm_state *s, const char *path, int error)
{
  char *q = bos_quoteaf (path);

  rm_say (s, "cannot remove %s: %s", q ? q : path, strerror (error));
  free (q);
  s->status = EXECUTION_FAILURE;
}

/* ---- prompts --------------------------------------------------------- */

static int
rm_interrupted (rm_state *s)
{
  if (interrupt_state || terminating_signal)
    s->stopped = 1;
  return s->stopped;
}

/* Read one answer line from standard input; nonzero when it is
   affirmative in the current locale. End of input is a refusal. */
static int
rm_answer (rm_state *s)
{
  char line[256];
  size_t len = 0;
  int got = 0;
  regex_t re;
  const char *yes;
  int ok;

  for (;;)
    {
      char c;
      ssize_t r = read (0, &c, 1);

      if (r < 0 && errno == EINTR)
        {
          if (rm_interrupted (s))
            return 0;
          continue;
        }
      if (r <= 0)
        break;
      got = 1;
      if (c == '\n')
        break;
      if (len < sizeof line - 1)
        line[len++] = c;
    }
  line[len] = '\0';
  if (!got)
    return 0;

  yes = nl_langinfo (YESEXPR);
  if (yes && *yes && regcomp (&re, yes, REG_EXTENDED | REG_NOSUB) == 0)
    {
      ok = regexec (&re, line, 0, NULL, 0) == 0;
      regfree (&re);
      return ok;
    }
  return line[0] == 'y' || line[0] == 'Y';
}

/* Print "rm: " and the question, then read the answer. */
static int
rm_ask (rm_state *s, const char *fmt, ...)
{
  va_list ap;

  if (rm_interrupted (s))
    return 0;
  fputs ("rm: ", stderr);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fflush (stderr);
  return rm_answer (s);
}

static const char *
rm_kind (const struct stat *st)
{
  if (S_ISREG (st->st_mode))
    return st->st_size == 0 ? "regular empty file" : "regular file";
  if (S_ISDIR (st->st_mode))
    return "directory";
  if (S_ISLNK (st->st_mode))
    return "symbolic link";
  if (S_ISFIFO (st->st_mode))
    return "fifo";
  if (S_ISSOCK (st->st_mode))
    return "socket";
  if (S_ISCHR (st->st_mode))
    return "character special file";
  if (S_ISBLK (st->st_mode))
    return "block special file";
  return "weird file";
}

/* Whether removing NAME (in DIRFD) calls for a question; *PROTECTED says
   whether it is write-protected. Symbolic links are never protected. */
static int
rm_should_ask (rm_state *s, int dirfd, const char *name,
               const struct stat *st, int *protected)
{
  *protected = 0;
  if (s->ask == RM_ASK_NEVER)
    return 0;
  if (s->ask != RM_ASK_ALWAYS && !s->tty)
    return 0;
  if (!S_ISLNK (st->st_mode)
      && faccessat (dirfd, name, W_OK, AT_EACCESS) != 0 && errno == EACCES)
    *protected = 1;
  return s->ask == RM_ASK_ALWAYS || *protected;
}

/* ---- helpers --------------------------------------------------------- */

/* 1 if directory NAME in DIRFD is empty, 0 if not, -1 (with *ERROR) if it
   cannot be read. */
static int
rm_is_empty (int dirfd, const char *name, int *error)
{
  int fd = openat (dirfd, name,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  DIR *d;
  struct dirent *e;
  int empty = 1;

  if (fd < 0)
    {
      *error = errno;
      return -1;
    }
  d = fdopendir (fd);
  if (d == NULL)
    {
      *error = errno;
      close (fd);
      return -1;
    }
  while ((e = readdir (d)) != NULL)
    if (strcmp (e->d_name, ".") && strcmp (e->d_name, ".."))
      {
        empty = 0;
        break;
      }
  closedir (d);
  return empty;
}

/* Whether the last component of NAME is "." or "..". */
static int
rm_is_dot (const char *name)
{
  size_t len = strlen (name), start;

  while (len > 0 && name[len - 1] == '/')
    len--;
  if (len == 0)
    return 0;
  start = len;
  while (start > 0 && name[start - 1] != '/')
    start--;
  return (len - start == 1 && name[start] == '.')
         || (len - start == 2 && name[start] == '.' && name[start + 1] == '.');
}

/* PATH/NAME, without doubling a slash PATH already ends with. */
static char *
rm_join (const char *path, const char *name)
{
  size_t pl = strlen (path), nl = strlen (name);
  int slash = pl > 0 && path[pl - 1] != '/';
  char *r = malloc (pl + slash + nl + 1);

  if (r == NULL)
    return NULL;
  memcpy (r, path, pl);
  if (slash)
    r[pl] = '/';
  memcpy (r + pl + slash, name, nl + 1);
  return r;
}

/* The entries of the open directory FD other than "." and "..", as a
   NULL-terminated malloc'd array (each name malloc'd); NULL with *ERROR
   on failure. FD stays open. */
static char **
rm_list (int fd, int *error)
{
  int copy = dup (fd);
  DIR *d;
  struct dirent *e;
  char **v = NULL;
  size_t n = 0, cap = 0;

  if (copy < 0)
    {
      *error = errno;
      return NULL;
    }
  d = fdopendir (copy);
  if (d == NULL)
    {
      *error = errno;
      close (copy);
      return NULL;
    }
  for (;;)
    {
      errno = 0;
      e = readdir (d);
      if (e == NULL)
        break;
      if (!strcmp (e->d_name, ".") || !strcmp (e->d_name, ".."))
        continue;
      if (n + 2 > cap)
        {
          size_t nc = cap ? cap * 2 : 32;
          char **nv = realloc (v, nc * sizeof *nv);
          if (nv == NULL)
            {
              errno = ENOMEM;
              e = NULL;
              break;
            }
          v = nv;
          cap = nc;
        }
      v[n] = strdup (e->d_name);
      if (v[n] == NULL)
        {
          errno = ENOMEM;
          break;
        }
      n++;
    }
  if (errno != 0)
    {
      *error = errno;
      closedir (d);
      while (n > 0)
        free (v[--n]);
      free (v);
      return NULL;
    }
  closedir (d);
  if (v == NULL)
    {
      v = malloc (sizeof *v);
      if (v == NULL)
        {
          *error = ENOMEM;
          return NULL;
        }
    }
  v[n] = NULL;
  return v;
}

static void
rm_free_list (char **v)
{
  size_t i;

  for (i = 0; v[i]; i++)
    free (v[i]);
  free (v);
}

/* ---- removal --------------------------------------------------------- */

/* Remove the non-directory NAME of DIRFD, shown as PATH. */
static int
rm_file (rm_state *s, int dirfd, const char *name, const char *path,
         const struct stat *st)
{
  int protected;

  if (rm_should_ask (s, dirfd, name, st, &protected))
    {
      char *q = bos_quoteaf (path);
      int yes = rm_ask (s, "remove %s%s %s? ", protected ? "write-protected " : "",
                        rm_kind (st), q ? q : path);
      free (q);
      if (!yes)
        return RM_KEPT;
    }
  if (unlinkat (dirfd, name, 0) != 0)
    {
      if (s->ignore_missing && errno == ENOENT)
        return RM_DONE;
      rm_fail (s, path, errno);
      return RM_BLOCKED;
    }
  rm_report (s, "removed", path);
  return RM_DONE;
}

static int rm_entry (rm_state *s, int *dirfd, const struct stat *dirst,
                     const char *name, const char *path, int depth);

/* Remove directory NAME of *PARENT (whose status is PARENT_ST) and all it
   holds; PATH is its displayed name and ST its status. */
static int
rm_tree (rm_state *s, int *parent, const struct stat *parent_st,
         const char *name, const char *path, const struct stat *st, int depth)
{
  int protected, fd, error = 0, blocked = 0;
  struct stat self;
  char **names;
  size_t i;


  if (rm_should_ask (s, *parent, name, st, &protected))
    {
      int empty = rm_is_empty (*parent, name, &error);
      char *q;
      int yes;

      if (empty < 0)
        {
          rm_fail (s, path, error);
          return RM_BLOCKED;
        }
      q = bos_quoteaf (path);
      yes = rm_ask (s, empty ? "remove %sdirectory %s? " : "descend into %sdirectory %s? ",
                    protected ? "write-protected " : "", q ? q : path);
      free (q);
      if (!yes)
        return RM_BLOCKED;
      if (empty)
        {
          if (unlinkat (*parent, name, AT_REMOVEDIR) != 0)
            {
              if (s->ignore_missing && errno == ENOENT)
                return RM_DONE;
              rm_fail (s, path, errno);
              return RM_BLOCKED;
            }
          rm_report (s, "removed directory", path);
          return RM_DONE;
        }
    }

  /* Checked after the question, as GNU does. */
  if (depth > 0 && s->one_fs && st->st_dev != s->top_dev)
    {
      char *q = bos_quoteaf (path);
      rm_say (s, "skipping %s, since it's on a different device", q ? q : path);
      free (q);
      s->status = EXECUTION_FAILURE;
      return RM_BLOCKED;
    }

  fd = openat (*parent, name,
               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      error = errno;
      if (s->ignore_missing && error == ENOENT)
        return RM_DONE;
      /* An unreadable directory may still be empty. */
      if (unlinkat (*parent, name, AT_REMOVEDIR) == 0)
        {
          rm_report (s, "removed directory", path);
          return RM_DONE;
        }
      rm_fail (s, path, error);
      return RM_BLOCKED;
    }
  if (fstat (fd, &self) != 0)
    {
      rm_fail (s, path, errno);
      close (fd);
      return RM_BLOCKED;
    }
  names = rm_list (fd, &error);
  if (names == NULL)
    {
      rm_fail (s, path, error);
      close (fd);
      return RM_BLOCKED;
    }

  if (depth >= RM_FD_KEEP && *parent >= 0)
    {
      close (*parent);
      *parent = -1;
    }

  for (i = 0; names[i]; i++)
    {
      char *child;

      if (rm_interrupted (s))
        break;
      child = rm_join (path, names[i]);
      if (child == NULL)
        {
          rm_fail (s, path, ENOMEM);
          blocked = 1;
          break;
        }
      if (rm_entry (s, &fd, &self, names[i], child, depth + 1) == RM_BLOCKED)
        blocked = 1;
      free (child);
      if (fd < 0)
        {
          /* The child could not get back to this directory. */
          blocked = 1;
          break;
        }
    }
  rm_free_list (names);

  if (*parent == -1)
    {
      struct stat back;
      int up = -1;

      if (fd < 0)
        return RM_BLOCKED;      /* already reported below us */
      up = openat (fd, "..", O_RDONLY | O_DIRECTORY | O_NOCTTY | O_CLOEXEC);
      if (up < 0 || fstat (up, &back) != 0
          || back.st_dev != parent_st->st_dev || back.st_ino != parent_st->st_ino)
        {
          char *q = bos_quoteaf (path);
          if (up >= 0)
            close (up);
          rm_say (s, "failed to return to the directory above %s", q ? q : path);
          free (q);
          s->status = EXECUTION_FAILURE;
          s->stopped = 1;
          close (fd);
          return RM_BLOCKED;
        }
      *parent = up;
    }
  if (fd >= 0)
    close (fd);

  if (blocked || s->stopped)
    return RM_BLOCKED;

  if (rm_should_ask (s, *parent, name, st, &protected))
    {
      char *q = bos_quoteaf (path);
      int yes = rm_ask (s, "remove %sdirectory %s? ", protected ? "write-protected " : "",
                        q ? q : path);
      free (q);
      if (!yes)
        return RM_KEPT;
    }
  if (unlinkat (*parent, name, AT_REMOVEDIR) != 0)
    {
      if (s->ignore_missing && errno == ENOENT)
        return RM_DONE;
      rm_fail (s, path, errno);
      return RM_BLOCKED;
    }
  rm_report (s, "removed directory", path);
  return RM_DONE;
}

/* One entry found inside a directory being removed recursively. */
static int
rm_entry (rm_state *s, int *dirfd, const struct stat *dirst,
          const char *name, const char *path, int depth)
{
  struct stat st;

  if (fstatat (*dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
    {
      if (s->ignore_missing && errno == ENOENT)
        return RM_DONE;
      rm_fail (s, path, errno);
      return RM_BLOCKED;
    }
  if (S_ISDIR (st.st_mode))
    return rm_tree (s, dirfd, dirst, name, path, &st, depth);
  return rm_file (s, *dirfd, name, path, &st);
}

/* A command-line operand. */
static void
rm_operand (rm_state *s, const char *name)
{
  struct stat st;

  if (lstat (name, &st) != 0)
    {
      if (s->ignore_missing && (errno == ENOENT || errno == ENOTDIR))
        return;
      rm_fail (s, name, errno);
      return;
    }
  if (!S_ISDIR (st.st_mode))
    {
      rm_file (s, AT_FDCWD, name, name, &st);
      return;
    }

  if (s->recursive)
    {
      int cwd = AT_FDCWD;
      char *q;

      if (rm_is_dot (name))
        {
          q = bos_quoteaf (name);
          rm_say (s, "refusing to remove '.' or '..' directory: skipping %s", q ? q : name);
          free (q);
          s->status = EXECUTION_FAILURE;
          return;
        }
      if (s->keep_root && s->root_known
          && st.st_dev == s->root.st_dev && st.st_ino == s->root.st_ino)
        {
          q = bos_quoteaf (name);
          if (strcmp (name, "/") == 0)
            rm_say (s, "it is dangerous to operate recursively on %s", q ? q : name);
          else
            rm_say (s, "it is dangerous to operate recursively on %s (same as '/')", q ? q : name);
          free (q);
          rm_say (s, "use --no-preserve-root to override this failsafe");
          s->status = EXECUTION_FAILURE;
          return;
        }
      if (s->keep_mounts)
        {
          char *up = rm_join (name, "..");
          struct stat pst;

          if (up && stat (up, &pst) == 0 && pst.st_dev != st.st_dev)
            {
              free (up);
              q = bos_quoteaf (name);
              rm_say (s, "skipping %s, since it's on a different device", q ? q : name);
              free (q);
              rm_say (s, "and --preserve-root=all is in effect");
              s->status = EXECUTION_FAILURE;
              return;
            }
          free (up);
        }
      s->top_dev = st.st_dev;
      rm_tree (s, &cwd, NULL, name, name, &st, 0);
      return;
    }

  if (s->dirs)
    {
      int error = 0, protected;
      int empty = rm_is_empty (AT_FDCWD, name, &error);

      if (empty == 0)
        {
          rm_fail (s, name, ENOTEMPTY);
          return;
        }
      if (rm_is_dot (name))
        {
          char *q = bos_quoteaf (name);
          rm_say (s, "refusing to remove '.' or '..' directory: skipping %s", q ? q : name);
          free (q);
          s->status = EXECUTION_FAILURE;
          return;
        }
      if (rm_should_ask (s, AT_FDCWD, name, &st, &protected))
        {
          char *q = bos_quoteaf (name);
          int yes;

          if (empty < 0)
            yes = rm_ask (s, "attempt removal of inaccessible directory %s? ", q ? q : name);
          else
            yes = rm_ask (s, "remove %sdirectory %s? ", protected ? "write-protected " : "",
                          q ? q : name);
          free (q);
          if (!yes)
            return;
        }
      if (unlinkat (AT_FDCWD, name, AT_REMOVEDIR) != 0)
        {
          int e = errno;
          if (s->ignore_missing && e == ENOENT)
            return;
          rm_fail (s, name, empty < 0 ? error : e);
          return;
        }
      rm_report (s, "removed directory", name);
      return;
    }

  rm_fail (s, name, EISDIR);
}

/* The operand as it is processed and shown: a run of trailing slashes is
   cut to one (a name of exactly two slashes is kept). */
static char *
rm_tidy (const char *arg)
{
  size_t len = strlen (arg);
  char *r;

  if (len > 2 && arg[len - 1] == '/')
    while (len > 1 && arg[len - 2] == '/')
      len--;
  r = malloc (len + 1);
  if (r == NULL)
    return NULL;
  memcpy (r, arg, len);
  r[len] = '\0';
  return r;
}

/* NAME as a shell word: unchanged when no character in it is special to
   the shell, else quoted. */
static char *
rm_shell_word (const char *name)
{
  size_t len = strlen (name), i;
  mbstate_t state;
  int plain = len > 0;

  memset (&state, 0, sizeof state);
  for (i = 0; plain && i < len;)
    {
      int printable;
      size_t n = bos_quote_next (name + i, len - i, &state, &printable);

      if (!printable || (n == 1 && strchr (" !\"$&'()*;<=>?[\\^`|", name[i])))
        plain = 0;
      i += n;
    }
  return plain ? strdup (name) : bos_quoteaf (name);
}

/* After a usage error: point at an operand that looks like an option but
   names an existing file. */
static void
rm_dash_hint (WORD_LIST *list)
{
  struct stat st;

  for (; list; list = list->next)
    {
      const char *w = list->word->word;

      if (w[0] == '-' && w[1] != '\0' && lstat (w, &st) == 0)
        {
          char *word = rm_shell_word (w);
          char *q = bos_quoteaf (w);
          if (word && q)
            {
              fflush (stdout);
              fprintf (stderr, "Try 'rm ./%s' to remove the file %s.\n", word, q);
            }
          free (word);
          free (q);
          return;
        }
    }
}

static void
rm_usage (void)
{
  fputs ("Usage: rm [OPTION]... [FILE]...\n"
         "Remove (unlink) the FILE(s).\n"
         "\n"
         "  -f, --force           ignore nonexistent files and arguments, never prompt\n"
         "  -i                    prompt before every removal\n"
         "  -I                    prompt once before removing more than three files, or\n"
         "                          when removing recursively; less intrusive than -i,\n"
         "                          while still giving protection against most mistakes\n"
         "      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or\n"
         "                          always (-i); without WHEN, prompt always\n"
         "      --one-file-system  when removing a hierarchy recursively, skip any\n"
         "                          directory that is on a file system different from\n"
         "                          that of the corresponding command line argument\n"
         "      --no-preserve-root  do not treat '/' specially\n"
         "      --preserve-root[=all]  do not remove '/' (default);\n"
         "                              with 'all', reject any command line argument\n"
         "                              on a separate device from its parent\n"
         "  -r, -R, --recursive   remove directories and their contents recursively\n"
         "  -d, --dir             remove empty directories\n"
         "  -v, --verbose         explain what is being done\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n"
         "\n"
         "By default, rm does not remove directories.  Use the --recursive (-r or -R)\n"
         "option to remove each listed directory, too, along with all of its contents.\n"
         "\n"
         "Any attempt to remove a file whose last file name component is '.' or '..'\n"
         "is rejected with a diagnostic.\n"
         "\n"
         "To remove a file whose name starts with a '-', for example '-foo',\n"
         "use one of these commands:\n"
         "  rm -- -foo\n"
         "\n"
         "  rm ./-foo\n"
         "\n"
         "If you use rm to remove a file, it might be possible to recover\n"
         "some of its contents, given sufficient expertise and/or time.  For greater\n"
         "assurance that the contents are unrecoverable, consider using shred(1).\n",
         stdout);
}

int
rm_builtin (WORD_LIST *list)
{
  static const struct bos_longopt longopts[] = {
    { "dir",                BOS_NO_ARG,  'd' },
    { "force",              BOS_NO_ARG,  'f' },
    { "interactive",        BOS_OPT_ARG, RM_OPT_INTERACTIVE },
    { "one-file-system",    BOS_NO_ARG,  RM_OPT_ONE_FS },
    { "no-preserve-root",   BOS_NO_ARG,  RM_OPT_NO_PRESERVE },
    { "preserve-root",      BOS_OPT_ARG, RM_OPT_PRESERVE },
    { "-presume-input-tty", BOS_NO_ARG,  RM_OPT_TTY },
    { "recursive",          BOS_NO_ARG,  'r' },
    { "verbose",            BOS_NO_ARG,  'v' },
    { "help",               BOS_NO_ARG,  BOS_OPT_HELP },
    { "version",            BOS_NO_ARG,  BOS_OPT_VERSION },
    { NULL, 0, 0 }
  };
  static const char *const when_names[] = {
    "never", "no", "none", "once", "always", "yes", NULL
  };
  static const int when_vals[] = {
    RM_ASK_NEVER, RM_ASK_NEVER, RM_ASK_NEVER, RM_ASK_ONCE, RM_ASK_ALWAYS, RM_ASK_ALWAYS
  };
  rm_state s;
  bos_getopt g;
  int c, i, presume_tty = 0;

  memset (&s, 0, sizeof s);
  s.ask = RM_ASK_DEFAULT;
  s.keep_root = 1;

  bos_getopt_init (&g, "rm", "dfiIrRv", longopts, list);
  g.no_hint = 1;
  while ((c = bos_getopt_next (&g)) != -1)
    {
      switch (c)
        {
        case 'd':
          s.dirs = 1;
          break;
        case 'f':
          s.ask = RM_ASK_NEVER;
          s.ignore_missing = 1;
          break;
        case 'i':
          s.ask = RM_ASK_ALWAYS;
          s.ignore_missing = 0;
          break;
        case 'I':
          s.ask = RM_ASK_ONCE;
          s.ignore_missing = 0;
          break;
        case 'r':
        case 'R':
          s.recursive = 1;
          break;
        case 'v':
          s.verbose = 1;
          break;
        case RM_OPT_INTERACTIVE:
          if (g.optarg == NULL)
            s.ask = RM_ASK_ALWAYS;
          else
            {
              int v = bos_argmatch ("rm", "--interactive", g.optarg, when_names, when_vals);
              if (v < 0)
                {
                  bos_getopt_free (&g);
                  return EXECUTION_FAILURE;
                }
              s.ask = v;
            }
          if (s.ask != RM_ASK_NEVER)
            s.ignore_missing = 0;
          break;
        case RM_OPT_ONE_FS:
          s.one_fs = 1;
          break;
        case RM_OPT_NO_PRESERVE:
          if (strcmp (g.word, "--no-preserve-root") != 0)
            {
              builtin_error ("you may not abbreviate the --no-preserve-root option");
              bos_getopt_free (&g);
              return EXECUTION_FAILURE;
            }
          s.keep_root = 0;
          break;
        case RM_OPT_PRESERVE:
          if (g.optarg)
            {
              if (strcmp (g.optarg, "all") != 0)
                {
                  char *q = bos_quoteaf (g.optarg);
                  builtin_error ("unrecognized --preserve-root argument: %s", q ? q : g.optarg);
                  free (q);
                  bos_getopt_free (&g);
                  return EXECUTION_FAILURE;
                }
              s.keep_mounts = 1;
            }
          s.keep_root = 1;
          break;
        case RM_OPT_TTY:
          presume_tty = 1;
          break;
        case BOS_OPT_HELP:
          bos_getopt_free (&g);
          rm_usage ();
          return sh_chkwrite (EXECUTION_SUCCESS);
        case BOS_OPT_VERSION:
          bos_getopt_free (&g);
          printf ("rm (bash-os)\n");
          return sh_chkwrite (EXECUTION_SUCCESS);
        default:
          rm_dash_hint (list);
          bos_try_help ("rm");
          bos_getopt_free (&g);
          return EXECUTION_FAILURE;
        }
    }

  if (g.noperands == 0)
    {
      bos_getopt_free (&g);
      if (s.ignore_missing)
        return EXECUTION_SUCCESS;
      builtin_error ("missing operand");
      bos_try_help ("rm");
      return EXECUTION_FAILURE;
    }

  s.tty = presume_tty || isatty (0);
  s.out_tty = isatty (1);
  if (s.recursive && s.keep_root)
    s.root_known = lstat ("/", &s.root) == 0;

  if (s.ask == RM_ASK_ONCE && (g.noperands > 3 || s.recursive))
    {
      if (!rm_ask (&s, "remove %d argument%s%s? ", g.noperands,
                   g.noperands == 1 ? "" : "s", s.recursive ? " recursively" : ""))
        {
          bos_getopt_free (&g);
          QUIT;
          return EXECUTION_SUCCESS;
        }
    }

  for (i = 0; i < g.noperands && !rm_interrupted (&s); i++)
    {
      char *name = rm_tidy (g.operands[i]);

      if (name == NULL)
        {
          rm_say (&s, "memory exhausted");
          s.status = EXECUTION_FAILURE;
          break;
        }
      rm_operand (&s, name);
      free (name);
    }

  rm_flush (&s);
  free (s.out);
  bos_getopt_free (&g);
  QUIT;
  return sh_chkwrite (s.status);
}

char *rm_doc[] = {
  "Remove files.",
  "",
  "Remove (unlink) each FILE. Directories are removed only with -r (with",
  "their contents) or -d (when empty). Any operand whose last component is",
  "'.' or '..' is refused, and so is '/' under -r unless --no-preserve-root.",
  "",
  "    -f, --force         ignore nonexistent files and arguments, never prompt",
  "    -i                  prompt before every removal",
  "    -I                  prompt once before removing more than three files,",
  "                        or when removing recursively",
  "    --interactive[=WHEN]  prompt never, once (-I) or always (-i, default)",
  "    --one-file-system   skip directories on other file systems under -r",
  "    --no-preserve-root  do not treat '/' specially",
  "    --preserve-root[=all]  refuse '/' (default); with 'all', also refuse",
  "                        operands on a different device than their parent",
  "    -r, -R, --recursive remove directories and their contents recursively",
  "    -d, --dir           remove empty directories",
  "    -v, --verbose       explain what is being done",
  "",
  "Answers to prompts are read from standard input. The exit status is 0",
  "unless a file could not be removed or an operand was invalid.",
  (char *)NULL
};

struct builtin rm_struct = {
  "rm",
  rm_builtin,
  BUILTIN_ENABLED,
  rm_doc,
  "rm [-dfiIrRv] [--interactive[=WHEN]] [--one-file-system] [--preserve-root[=all]] [--no-preserve-root] [FILE]...",
  0
};
