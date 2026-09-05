/* stat - load up an associative array with stat information about a file */

/* See Makefile for compilation details. */

/*
   Copyright (C) 2016,2022-2023 Free Software Foundation, Inc.

   This file is part of GNU Bash.
   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>

#include <sys/types.h>
#include "posixstat.h"
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include "posixtime.h"

#include "bashansi.h"
#include "shell.h"
#include "builtins.h"
#include "common.h"
#include <pwd.h>
#include <grp.h>

#include "bashgetopt.h"

#ifndef errno
extern int	errno;
#endif

#if defined (ARRAY_VARS)

#define ST_NAME		0
#define ST_DEV		1
#define ST_INO		2
#define ST_MODE		3
#define ST_NLINK	4
#define ST_UID		5
#define ST_GID		6
#define ST_RDEV		7
#define ST_SIZE		8
#define ST_ATIME	9
#define ST_MTIME	10
#define ST_CTIME	11
#define ST_BLKSIZE	12
#define ST_BLOCKS	13
#define ST_CHASELINK	14
#define ST_PERMS	15

#define ST_END		16

static char *arraysubs[] =
  {
    "name", "device", "inode", "type", "nlink", "uid", "gid", "rdev",
    "size", "atime", "mtime", "ctime", "blksize", "blocks", "link", "perms",
    0
  };

#define DEFTIMEFMT	"%a %b %e %k:%M:%S %Z %Y"
#ifndef TIMELEN_MAX
#  define TIMELEN_MAX 128
#endif

static char *stattime (time_t, const char *);

static int
getstat (const char *fname, int flags, struct stat *sp)
{
  intmax_t lfd;
  int fd, r;

  if (strncmp (fname, "/dev/fd/", 8) == 0)
    {
      if ((valid_number(fname + 8, &lfd) == 0) || (int)lfd != lfd)
	{
	  errno = EINVAL;
	  return -1;
	}
      fd = lfd;
      r = fstat(fd, sp);
    }
#ifdef HAVE_LSTAT
  else if (flags & 1)
    r = lstat(fname, sp);
#endif
  else
    r = stat(fname, sp);

  return r;
}

static char *
statlink (char *fname, struct stat *sp)
{
#if defined (HAVE_READLINK)
  char linkbuf[PATH_MAX];
  int n;

  /* Leave room for the terminator: readlink does not NUL-terminate, and asking
     for the full PATH_MAX lets a target of exactly that length return n ==
     PATH_MAX, so linkbuf[n] wrote one byte past the end of the buffer. */
  if (fname && S_ISLNK (sp->st_mode) &&
      (n = readlink (fname, linkbuf, sizeof (linkbuf) - 1)) > 0)
    {
      linkbuf[n] = '\0';
      return (savestring (linkbuf));
    }
  else
#endif
    return (savestring (fname));
}

static char *
octalperms (int m)
{
  int operms;
  char *ret;

  operms = 0;

  if (m & S_IRUSR)
    operms |= 0400;
  if (m & S_IWUSR)
    operms |= 0200;
  if (m & S_IXUSR)
    operms |= 0100;

  if (m & S_IRGRP)
    operms |= 0040;
  if (m & S_IWGRP)
    operms |= 0020;
  if (m & S_IXGRP)
    operms |= 0010;

  if (m & S_IROTH)
    operms |= 0004;
  if (m & S_IWOTH)
    operms |= 0002;
  if (m & S_IXOTH)
    operms |= 0001;

  if (m & S_ISUID)
    operms |= 04000;
  if (m & S_ISGID)
    operms |= 02000;
  if (m & S_ISVTX)
    operms |= 01000;

  ret = (char *)xmalloc (16);
  snprintf (ret, 16, "%04o", operms);
  return ret;
}

/* Apply a setuid/setgid/sticky marker to a densely-packed permission string:
   replace a trailing execute bit with `lower`, else append `upper`. */
static void
statperms_special (char *bits, size_t cap, int has_exec, char lower, char upper)
{
  size_t n = strlen (bits);
  if (has_exec && n > 0 && bits[n - 1] == 'x')
    bits[n - 1] = lower;
  else if (n + 1 < cap)
    {
      bits[n] = upper;
      bits[n + 1] = '\0';
    }
}

static char *
statperms (int m)
{
  char ubits[5], gbits[5], obits[5];	/* u=rwx,g=rwx,o=rwx (+ s/S/t/T) */
  int i;
  char *ret;

  i = 0;
  if (m & S_IRUSR)
    ubits[i++] = 'r';
  if (m & S_IWUSR)
    ubits[i++] = 'w';
  if (m & S_IXUSR)
    ubits[i++] = 'x';
  ubits[i] = '\0';

  i = 0;
  if (m & S_IRGRP)
    gbits[i++] = 'r';
  if (m & S_IWGRP)
    gbits[i++] = 'w';
  if (m & S_IXGRP)
    gbits[i++] = 'x';
  gbits[i] = '\0';

  i = 0;
  if (m & S_IROTH)
    obits[i++] = 'r';
  if (m & S_IWOTH)
    obits[i++] = 'w';
  if (m & S_IXOTH)
    obits[i++] = 'x';
  obits[i] = '\0';

  /* setuid/setgid/sticky. These used to be written to a FIXED index 2, but the
     bits above are packed densely (only the permissions that are set), so
     index 2 is past the terminator for every mode without all of r, w and x —
     and the special bit was then silently dropped from the output, hiding a
     setuid file from anyone reading this. Replace a trailing 'x' (s/t), or
     append the capital form (S/T) when there is no execute bit. */
  if (m & S_ISUID)
    statperms_special (ubits, sizeof ubits, (m & S_IXUSR) != 0, 's', 'S');
  if (m & S_ISGID)
    statperms_special (gbits, sizeof gbits, (m & S_IXGRP) != 0, 's', 'S');
  if (m & S_ISVTX)
    statperms_special (obits, sizeof obits, (m & S_IXOTH) != 0, 't', 'T');

  ret = (char *)xmalloc (32);
  snprintf (ret, 32, "u=%s,g=%s,o=%s", ubits, gbits, obits);
  return ret;
}

static char *
statmode(int mode)
{
  char *modestr, *m;

  modestr = m = (char *)xmalloc (8);
  if (S_ISBLK (mode))
    *m++ = 'b';
  if (S_ISCHR (mode))
    *m++ = 'c';
  if (S_ISDIR (mode))
    *m++ = 'd';
  if (S_ISREG(mode))
    *m++ = '-';
  if (S_ISFIFO(mode))
    *m++ = 'p';
  if (S_ISLNK(mode))
    *m++ = 'l';
  if (S_ISSOCK(mode))
    *m++ = 's';

#ifdef S_ISDOOR
  if (S_ISDOOR (mode))
    *m++ = 'D';
#endif
#ifdef S_ISWHT
  if (S_ISWHT(mode))
    *m++ = 'W';
#endif
#ifdef S_ISNWK
  if (S_ISNWK(mode))
    *m++ = 'n';
#endif
#ifdef S_ISMPC
  if (S_ISMPC (mode))
    *m++ = 'm';
#endif

  *m = '\0';
  return (modestr);
}

static char *
stattime (time_t t, const char *timefmt)
{
  char *tbuf, *ret;
  const char *fmt;
  size_t tlen;
  struct tm *tm;

  fmt = timefmt ? timefmt : DEFTIMEFMT;
  tm = localtime (&t);
  if (tm == 0)
    return (itos (t));

  ret = xmalloc (TIMELEN_MAX);

  tlen = strftime (ret, TIMELEN_MAX, fmt, tm);
  if (tlen == 0)
    tlen = strftime (ret, TIMELEN_MAX, DEFTIMEFMT, tm);

  return ret;
}

static char *
statval (int which, char *fname, int flags, char *fmt, struct stat *sp)
{
  int temp;

  switch (which)
    {
    case ST_NAME:
      return savestring (fname);
    case ST_DEV:
      return itos (sp->st_dev);
    case ST_INO:
      return itos (sp->st_ino);
    case ST_MODE:
      return (statmode (sp->st_mode));
    case ST_NLINK:
      return itos (sp->st_nlink);
    case ST_UID:
      return itos (sp->st_uid);
    case ST_GID:
      return itos (sp->st_gid);
    case ST_RDEV:
      return itos (sp->st_rdev);
    case ST_SIZE:
      return itos (sp->st_size);
    case ST_ATIME:
      return ((flags & 2) ? stattime (sp->st_atime, fmt) : itos (sp->st_atime));
    case ST_MTIME:
      return ((flags & 2) ? stattime (sp->st_mtime, fmt) : itos (sp->st_mtime));
    case ST_CTIME:
      return ((flags & 2) ? stattime (sp->st_ctime, fmt) : itos (sp->st_ctime));
    case ST_BLKSIZE:
      return itos (sp->st_blksize);
    case ST_BLOCKS:
      return itos (sp->st_blocks);
    case ST_CHASELINK:
      return (statlink (fname, sp));
    case ST_PERMS:
      temp = sp->st_mode & (S_IRWXU|S_IRWXG|S_IRWXO|S_ISUID|S_ISGID);
      return (flags & 2) ? statperms (temp) : octalperms (temp);
    default:
      return savestring ("42");
    }
}

static int
loadstat (char *vname, SHELL_VAR *var, char *fname, int flags, char *fmt, struct stat *sp)
{
  int i;
  char *key, *value;
  SHELL_VAR *v;

  for (i = 0; arraysubs[i]; i++)
    {
      key = savestring (arraysubs[i]);
      value = statval (i, fname, flags, fmt, sp);
      v = bind_assoc_variable (var, vname, key, value, ASS_FORCE);
      free (value);
    }
  return 0;
}
#endif

/* --- bash-os: GNU coreutils `stat -c FORMAT` support ------------
 * Expand a format string against `sp` and print it. Covers the directives the
 * appliance scripts use; unknown %X is emitted verbatim, like GNU stat. flags
 * bit 2 selects strftime output for the human time directives. */
static char *
symbolic_perms (mode_t m)
{
  char *r = (char *)xmalloc (11);
  char *t = statmode (m);		/* type char in r[0] */
  r[0] = t[0] ? t[0] : '?'; free (t);
  r[1] = (m & S_IRUSR) ? 'r' : '-';
  r[2] = (m & S_IWUSR) ? 'w' : '-';
  r[3] = (m & S_ISUID) ? ((m & S_IXUSR) ? 's' : 'S') : ((m & S_IXUSR) ? 'x' : '-');
  r[4] = (m & S_IRGRP) ? 'r' : '-';
  r[5] = (m & S_IWGRP) ? 'w' : '-';
  r[6] = (m & S_ISGID) ? ((m & S_IXGRP) ? 's' : 'S') : ((m & S_IXGRP) ? 'x' : '-');
  r[7] = (m & S_IROTH) ? 'r' : '-';
  r[8] = (m & S_IWOTH) ? 'w' : '-';
  r[9] = (m & S_ISVTX) ? ((m & S_IXOTH) ? 't' : 'T') : ((m & S_IXOTH) ? 'x' : '-');
  r[10] = '\0';
  return r;
}

static const char *
ftype_word (mode_t m)
{
  if (S_ISREG (m))  return "regular file";
  if (S_ISDIR (m))  return "directory";
  if (S_ISLNK (m))  return "symbolic link";
  if (S_ISCHR (m))  return "character special file";
  if (S_ISBLK (m))  return "block special file";
  if (S_ISFIFO (m)) return "fifo";
#ifdef S_ISSOCK
  if (S_ISSOCK (m)) return "socket";
#endif
  return "unknown";
}

/* %U/%G resolve a uid/gid to a name; on musl each call reopens and scans
 * /etc/passwd or /etc/group, so `stat -c %U *` was one scan per file. Memoise
 * the last resolved id, which collapses the common "everything owned by root"
 * case to a single lookup. */
static uid_t g_uid_memo = (uid_t)-1; static char g_uname_memo[64];
static gid_t g_gid_memo = (gid_t)-1; static char g_gname_memo[64];

static void
format_stat (const char *fmt, const char *fname, struct stat *sp)
{
  const char *f;
  char *tmp;

  for (f = fmt; *f; f++)
    {
      if (*f == '\\')			/* backslash escapes */
	{
	  switch (*++f)
	    {
	    case 'n': putchar ('\n'); break;
	    case 't': putchar ('\t'); break;
	    case '\\': putchar ('\\'); break;
	    case '"': putchar ('"'); break;
	    case '\0': putchar ('\\'); f--; break;
	    default:  putchar ('\\'); putchar (*f); break;
	    }
	  continue;
	}
      if (*f != '%')
	{
	  putchar (*f);
	  continue;
	}
      switch (*++f)		/* directive */
	{
	case '%': putchar ('%'); break;
	case 'n': fputs (fname, stdout); break;
	case 's': printf ("%ld", (long) sp->st_size); break;
	case 'b': printf ("%ld", (long) sp->st_blocks); break;
	case 'B': case 'o': printf ("%ld", (long) sp->st_blksize); break;
	case 'i': printf ("%lu", (unsigned long) sp->st_ino); break;
	case 'h': printf ("%lu", (unsigned long) sp->st_nlink); break;
	case 'd': printf ("%lu", (unsigned long) sp->st_dev); break;
	case 'D': printf ("%lx", (unsigned long) sp->st_dev); break;
	case 'u': printf ("%lu", (unsigned long) sp->st_uid); break;
	case 'g': printf ("%lu", (unsigned long) sp->st_gid); break;
	case 'f': printf ("%lx", (unsigned long) sp->st_mode); break;
	case 'a':				/* octal perms */
	  tmp = octalperms (sp->st_mode & (S_IRWXU|S_IRWXG|S_IRWXO|S_ISUID|S_ISGID));
	  fputs (tmp, stdout); free (tmp); break;
	case 'A':				/* -rwxr-xr-x symbolic perms */
	  tmp = symbolic_perms (sp->st_mode); fputs (tmp, stdout); free (tmp); break;
	case 'F': fputs (ftype_word (sp->st_mode), stdout); break;
	case 'U':
	  if (sp->st_uid == g_uid_memo && g_uname_memo[0]) { fputs (g_uname_memo, stdout); break; }
	  { struct passwd *pw = getpwuid (sp->st_uid);
	    if (pw) { fputs (pw->pw_name, stdout);
		      g_uid_memo = sp->st_uid; strncpy (g_uname_memo, pw->pw_name, sizeof g_uname_memo - 1); g_uname_memo[sizeof g_uname_memo - 1] = 0; }
	    else printf ("%lu", (unsigned long) sp->st_uid); }
	  break;
	case 'G':
	  if (sp->st_gid == g_gid_memo && g_gname_memo[0]) { fputs (g_gname_memo, stdout); break; }
	  { struct group *gr = getgrgid (sp->st_gid);
	    if (gr) { fputs (gr->gr_name, stdout);
		      g_gid_memo = sp->st_gid; strncpy (g_gname_memo, gr->gr_name, sizeof g_gname_memo - 1); g_gname_memo[sizeof g_gname_memo - 1] = 0; }
	    else printf ("%lu", (unsigned long) sp->st_gid); }
	  break;
	case 'X': printf ("%ld", (long) sp->st_atime); break;
	case 'Y': printf ("%ld", (long) sp->st_mtime); break;
	case 'Z': printf ("%ld", (long) sp->st_ctime); break;
	case 'x': tmp = stattime (sp->st_atime, 0); fputs (tmp, stdout); free (tmp); break;
	case 'y': tmp = stattime (sp->st_mtime, 0); fputs (tmp, stdout); free (tmp); break;
	case 'z': tmp = stattime (sp->st_ctime, 0); fputs (tmp, stdout); free (tmp); break;
	case '\0': putchar ('%'); f--; break;
	default:  putchar ('%'); putchar (*f); break;	/* unknown: verbatim */
	}
    }
}

int
stat_builtin (WORD_LIST *list)
{
#if defined (ARRAY_VARS)
  int opt, flags;
  char *aname, *fname, *timefmt, *cfmt;
  struct stat st;
  SHELL_VAR *v;

  aname = "STAT";
  flags = 0;
  timefmt = 0;
  cfmt = 0;

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "A:F:Llc:")) != -1)
    {
      switch (opt)
	{
	case 'A':
	  aname = list_optarg;
	  break;
	case 'L':
	  flags |= 1;		/* operate on links rather than resolving them */
	  break;
	case 'l':
	  flags |= 2;
	  break;
	case 'F':
	  timefmt = list_optarg;
	  break;
	case 'c':
	  cfmt = list_optarg;	/* GNU-style format; print, do not fill an array */
	  break;
	CASE_HELPOPT;
	default:
	  builtin_usage ();
	  return (EX_USAGE);
	}
    }

  list = loptend;
  if (list == 0)
    {
      builtin_usage ();
      return (EX_USAGE);
    }

  if (cfmt)			/* GNU coreutils-style: stat -c FMT FILE... */
    {
      int rc = EXECUTION_SUCCESS;
      WORD_LIST *l;
      for (l = list; l; l = l->next)
	{
	  if (getstat (l->word->word, flags, &st) < 0)
	    {
	      builtin_error ("%s: cannot stat: %s", l->word->word, strerror (errno));
	      rc = EXECUTION_FAILURE;
	      continue;
	    }
	  format_stat (cfmt, l->word->word, &st);
	  putchar ('\n');
	}
      return (rc);
    }

  if (valid_identifier (aname) == 0)
    {
      sh_invalidid (aname);
      return (EXECUTION_FAILURE);
    }


#if 0
  unbind_variable (aname);
#endif
  fname = list->word->word;

  if (getstat (fname, flags, &st) < 0)
    {
      builtin_error ("%s: cannot stat: %s", fname, strerror (errno));
      return (EXECUTION_FAILURE);
    }

  v = find_or_make_array_variable (aname, 3);
  if (v == 0)
    {
      builtin_error ("%s: cannot create variable", aname);
      return (EXECUTION_FAILURE);
    }
  if (loadstat (aname, v, fname, flags, timefmt, &st) < 0)
    {
      builtin_error ("%s: cannot assign file status information", aname);
      unbind_variable (aname);
      return (EXECUTION_FAILURE);
    }

  return (EXECUTION_SUCCESS);
#else
  builtin_error ("arrays not available");
  return (EXECUTION_FAILURE);
#endif
}

/* An array of strings forming the `long' documentation for a builtin xxx,
   which is printed by `help xxx'.  It must end with a NULL.  By convention,
   the first line is a short description. */
char *stat_doc[] = {
	"Load an associative array with file status information, or print",
	"a format string with -c (GNU coreutils compatible).",
	"",
	"Take a filename and load the status information returned by a",
	"stat(2) call on that file into the associative array specified",
	"by the -A option.  The default array name is STAT.",
	"",
	"If the -L option is supplied, stat does not resolve symbolic links",
	"and reports information about the link itself.  The -l option results",
	"in longer-form listings for some of the fields. When -l is used,",
	"the -F option supplies a format string passed to strftime(3) to",
	"display the file time information.",
	"",
	"With -c FORMAT, print FORMAT for each file, expanding %n name,",
	"%s size, %F type, %a octal / %A symbolic perms, %U user, %G group,",
	"%u/%g id, %i inode, %h links, %X/%Y/%Z a/m/ctime epoch, %x/%y/%z time,",
	"%d device, %f raw mode hex, %b blocks, %B block size, %% literal.",
	"",
	"The exit status is 0 unless the stat fails or assigning the array",
	"is unsuccessful.",
	(char *)NULL
};

/* The standard structure describing a builtin command.  bash keeps an array
   of these structures.  The flags must include BUILTIN_ENABLED so the
   builtin can be used. */
struct builtin stat_struct = {
	"stat",			/* builtin name */
	stat_builtin,		/* function implementing the builtin */
	BUILTIN_ENABLED,	/* initial flags for builtin */
	stat_doc,		/* array of long documentation strings. */
	"stat [-lL] [-c format] [-A aname] file...",	/* usage synopsis; becomes short_doc */
	0			/* reserved for internal use */
};
