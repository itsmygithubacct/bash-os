/* SPDX-License-Identifier: MIT */
/* coreutils.c — 13 small POSIX coreutils as a single bash loadable.
 *
 * Phase MISSING_LOADABLES T3 of bash-os. Bundles thirteen short
 * coreutils that each lack a dedicated bash builtin:
 *
 *   coreutils tac    [FILE...]                  reverse lines
 *   coreutils shuf   [-erz] [-i LO-HI] [-n COUNT] [-o FILE] [FILE|ARG...]
 *   coreutils factor [-h] [NUMBER...]           prime factorize (any size)
 *   coreutils yes    [STRING...]                infinite repeat
 *   coreutils fmt    [-cstu] [-w N] [-p S] [FILE...]  GNU fmt
 *   coreutils tsort  [FILE]                     topological sort
 *   coreutils printf FORMAT [ARG...]            GNU printf (env/xargs/find use it)
 *   coreutils nproc                             sched_getaffinity count; --all is configured
 *   coreutils numfmt [OPTION]... [NUMBER]...    GNU numfmt options
 *   coreutils shred  [-n N] [-u] [-z] FILE...   overwrite + unlink
 *   coreutils groups [USER]                     list user groups
 *   coreutils install [-bCcDdpsTvZ] [-m MODE] [-o OWNER] [-g GROUP] [-S SUFFIX] [-t DIR] SRC... DST | -d DIR...
 *   coreutils mknod  PATH {b|c|p} [MAJ MIN]     create device/fifo
 *
 * Thirteen verbs, one .c file, single struct builtin dispatched via
 * the leading word. Each verb keeps its own static helpers under a
 * `bcu_<verb>_` prefix; the public entry points are `bcu_<verb>_cmd`
 * (taking a WORD_LIST). The bottom of the file holds the dispatch
 * table + the bash builtin glue.
 *
 * POSIX wrappers in rootfs/bash-os/<verb>.sh exec the verb directly so
 * external fork-exec callers (Node child_process, scripts that use
 * /usr/bin/<verb>) get a real PATH entry. The wrappers all `exec
 * coreutils <verb> "$@"` so the loadable runs in-process.
 *
 * shuf, fmt, tsort, printf, install and factor are clean-room: written
 * from the coreutils manual, POSIX, published algorithms and observed
 * coreutils 9.7 behaviour, not from GNU source.
 *
 * Source counterparts named for the other verbs:
 *   research/refs/coreutils/src/{tac,yes,nproc,numfmt,shred,
 *     groups,mknod}.c (GNU canonical)
 *   research/refs/sbase/{tac,yes,nproc,shred}.c (minimal)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <fcntl.h>
#include <float.h>
#include <stdarg.h>
#include <langinfo.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <sched.h>
#if defined (__linux__)
#  include <sys/syscall.h>
#endif

#include "loadables.h"
#include "error.h"
#include "bl-output.h"
#include "gnu-quote.h"
#include <limits.h>

static void *bcu_calloc (size_t n, size_t size)
{
  if (size && n > SIZE_MAX / size) { fatal_error ("coreutils: allocation too large"); abort (); }
  size_t total = n * size;
  void *p = xmalloc (total ? total : 1);
  memset (p, 0, total);
  return p;
}
static char *bcu_strdup (const char *s)
{
  size_t n = strlen (s) + 1;
  char *p = xmalloc (n);
  memcpy (p, s, n);
  return p;
}
/* Temporary argument lists borrow words from Bash, owning only their nodes.
   Cleanup also runs when option parsing returns early. */
static void bcu_free_nodes (WORD_LIST **head)
{
  while (*head) { WORD_LIST *next = (*head)->next; free (*head); *head = next; }
}

#ifndef BUFSZ
#  define BUFSZ 8192
#endif

/* ===================================================================
 * Shared helpers — file I/O, parsing.
 * =================================================================== */

static FILE *
bcu_open_input (const char *path)
{
  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    return stdin;
  FILE *fp = fopen (path, "r");
  if (!fp)
    builtin_error ("%s: %s", path, strerror (errno));
  return fp;
}

/* Slurp a stream into a malloc'd buffer; returns -1 on error. *out is
 * freshly malloc'd with one extra byte for the caller's convenience
 * (callers may NUL-terminate themselves). */
static ssize_t
bcu_slurp (FILE *fp, char **out)
{
  size_t cap = 4096, len = 0;
  char *buf = xmalloc (cap);
  if (!buf) { *out = NULL; return -1; }
  for (;;)
    {
      if (len + 1 >= cap)
        {
          size_t ncap = cap * 2;
          char *nbuf = xrealloc (buf, ncap);
          if (!nbuf) { free (buf); *out = NULL; return -1; }
          buf = nbuf; cap = ncap;
        }
      size_t n = fread (buf + len, 1, cap - len - 1, fp);
      len += n;
      if (n == 0) break;
    }
  if (ferror (fp))
    {
      free (buf);
      *out = NULL;
      return -1;
    }
  buf[len] = '\0';
  *out = buf;
  return (ssize_t) len;
}

/* strtoll wrapper that returns 1 on success, 0 on failure. */
static int
bcu_parse_ll (const char *s, long long *out)
{
  if (!s || !*s) return 0;
  errno = 0;
  char *end = NULL;
  long long v = strtoll (s, &end, 10);
  if (errno || !end || *end != '\0') return 0;
  *out = v;
  return 1;
}

static void
bcu_usage (const char *verb)
{
  if (strcmp (verb, "tac") == 0)
    builtin_error ("usage: coreutils tac [FILE...]");
  else if (strcmp (verb, "shuf") == 0)
    builtin_error ("usage: coreutils shuf [-erz] [-i LO-HI] [-n COUNT] [-o FILE] [--random-source=FILE] [FILE | ARG...]");
  else if (strcmp (verb, "factor") == 0)
    builtin_error ("usage: coreutils factor [-h|--exponents] [NUMBER...]");
  else if (strcmp (verb, "yes") == 0)
    builtin_error ("usage: coreutils yes [STRING...]");
  else if (strcmp (verb, "fmt") == 0)
    builtin_error ("usage: coreutils fmt [-WIDTH] [-cstu] [-w WIDTH] [-g GOAL] [-p PREFIX] [FILE...]");
  else if (strcmp (verb, "tsort") == 0)
    builtin_error ("usage: coreutils tsort [FILE]");
  else if (strcmp (verb, "printf") == 0)
    builtin_error ("usage: coreutils printf FORMAT [ARGUMENT]...");
  else if (strcmp (verb, "nproc") == 0)
    builtin_error ("usage: coreutils nproc [--all] [--ignore=N]");
  else if (strcmp (verb, "numfmt") == 0)
    builtin_error ("usage: coreutils numfmt [OPTION]... [NUMBER]...");
  else if (strcmp (verb, "shred") == 0)
    builtin_error ("usage: coreutils shred [-fuvxz] [-n N] [-s SIZE] [--remove[=HOW]] FILE...");
  else if (strcmp (verb, "groups") == 0)
    builtin_error ("usage: coreutils groups [USER...]");
  else if (strcmp (verb, "install") == 0)
    builtin_error ("usage: coreutils install [-bCcDdpsTvZ] [-g GROUP] [-m MODE] [-o OWNER] [-S SUFFIX] [-t DIR] SOURCE... DEST | -d DIR...");
  else if (strcmp (verb, "mknod") == 0)
    builtin_error ("usage: coreutils mknod [-m MODE] PATH {b|c|p} [MAJ MIN]");
  else
    builtin_usage ();
}

/* ===================================================================
 * tac — reverse lines.
 * =================================================================== */

/* Coalesce small records while retaining stdio ordering with other Bash
   builtins. A large record goes directly to stdout without another copy. */
typedef struct {
  char bytes[65536];
  size_t used;
  int failed;
} BCU_OUTPUT;

static void
bcu_output_flush (BCU_OUTPUT *out)
{
  if (!out->failed && out->used &&
      fwrite (out->bytes, 1, out->used, stdout) != out->used)
    out->failed = 1;
  out->used = 0;
}

static void
bcu_output_append (BCU_OUTPUT *out, const char *bytes, size_t len)
{
  if (out->failed || !len) return;
  if (len > sizeof out->bytes - out->used) bcu_output_flush (out);
  if (out->failed) return;
  if (len >= sizeof out->bytes)
    {
      if (fwrite (bytes, 1, len, stdout) != len) out->failed = 1;
    }
  else
    {
      memcpy (out->bytes + out->used, bytes, len);
      out->used += len;
    }
}

/* Read the descriptor rather than Bash's persistent stdin FILE: its EOF
   indicator and read-ahead buffer can survive shell redirections. */
static ssize_t
bcu_tac_slurp (int fd, char **out)
{
  size_t cap = 65536, len = 0;
  char *buf = xmalloc (cap);
  for (;;)
    {
      if (len == cap)
        {
          if (cap > (size_t) SSIZE_MAX / 2)
            { free (buf); errno = EOVERFLOW; return -1; }
          cap *= 2;
          buf = xrealloc (buf, cap);
        }
      ssize_t n = read (fd, buf + len, cap - len);
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) { int e = errno; free (buf); errno = e; return -1; }
      if (!n) break;
      len += (size_t) n;
    }
  *out = buf;
  return (ssize_t) len;
}

static int
bcu_tac_stream (FILE *fp, const char *sep, bl_output *out)
{
  char *buf = NULL;
  ssize_t len = bcu_tac_slurp (fileno (fp), &buf);
  if (len < 0)
    { builtin_error ("tac: read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  /* GNU selects NUL for an empty separator. Search from the right so
     overlapping literal separators consume the rightmost match first.
     Emit each record immediately, avoiding a per-record offset array. */
  size_t seplen = strlen (sep);
  if (!seplen) seplen = 1;
  size_t search_end = (size_t) len, record_end = (size_t) len;
  while (search_end >= seplen && !out->error)
    {
      size_t limit = search_end - seplen + 1;
      const char *found = NULL;
      while (limit)
        {
          found = memrchr (buf, (unsigned char) sep[0], limit);
          if (!found || seplen == 1 || memcmp (found, sep, seplen) == 0) break;
          limit = (size_t) (found - buf);
          found = NULL;
        }
      if (!found) break;
      size_t start = (size_t) (found - buf), boundary = start + seplen;
      bl_output_write (out, buf + boundary, record_end - boundary);
      record_end = boundary;
      search_end = start;
    }
  if (record_end) bl_output_write (out, buf, record_end);
  free (buf);
  return out->error ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bcu_tac_cmd (WORD_LIST *list)
{
  const char *sep = "\n";
  /* Parse -s SEP / -sSEP / --separator=SEP (GNU tac). -r/-b out of scope. */
  while (list && list->word->word[0] == '-' && list->word->word[1])
    {
      const char *w = list->word->word;
      if (!strcmp (w, "--")) { list = list->next; break; }
      if (!strcmp (w, "-s") || !strcmp (w, "--separator"))
        {
          if (!list->next) { builtin_error ("tac: option requires an argument -- 's'"); return EX_USAGE; }
          list = list->next; sep = list->word->word; list = list->next; continue;
        }
      if (!strncmp (w, "-s", 2))            { sep = w + 2; list = list->next; continue; }
      if (!strncmp (w, "--separator=", 12)) { sep = w + 12; list = list->next; continue; }
      builtin_error ("tac: unknown option: %s", w);
      return EX_USAGE;
    }
  bl_output out;
  bl_output_init (&out, stdout);
  int rc = EXECUTION_SUCCESS;
  if (!list)
    rc = bcu_tac_stream (stdin, sep, &out);
  for (WORD_LIST *w = list; w && !out.error; w = w->next)
    {
      FILE *fp = bcu_open_input (w->word->word);
      if (!fp) { rc = EXECUTION_FAILURE; continue; }
      if (bcu_tac_stream (fp, sep, &out) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
      if (fp != stdin) fclose (fp);
    }
  bl_output_flush (&out);
  if (out.error)
    { builtin_error ("tac: write: %s", strerror (out.error)); rc = EXECUTION_FAILURE; }
  return rc;
}

/* ===================================================================
 * Helpers shared by shuf, tsort, fmt and printf: GNU-style option
 * scanning, diagnostics and quoting. Written for bash-os from the
 * coreutils manual, POSIX and observed behaviour of coreutils 9.7.
 * =================================================================== */

/* "PROG: message" on stderr. Standard output is flushed first so the
   two streams interleave as a stdio program's would. */
static void bcu_err (const char *prog, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));
static void
bcu_err (const char *prog, const char *fmt, ...)
{
  va_list ap;
  fflush (stdout);
  fprintf (stderr, "%s: ", prog);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fputc ('\n', stderr);
  fflush (stderr);
}

static void
bcu_try_help (const char *prog)
{
  fflush (stdout);
  fprintf (stderr, "Try '%s --help' for more information.\n", prog);
  fflush (stderr);
}

/* TEXT in the locale's quotation marks; always returns allocated text. */
static char *
bcu_quote (const char *text)
{
  char *q = bos_quote (text);
  return q ? q : bcu_strdup (text);
}

/* Shell quoting as `ls --quoting-style=shell-escape` and printf %q show
   it: words made only of safe characters stay bare; a word whose only
   unsafe characters are apostrophes and spaces goes in double quotes;
   anything else in single quotes, with an apostrophe written '\'' and
   unprintable bytes in $'...' sections. */
static char *
bcu_shell_quote (const char *s)
{
  size_t len = strlen (s), at = 0;
  int needs = len == 0, apostrophe = 0, single = 0;
  mbstate_t st;

  memset (&st, 0, sizeof st);
  for (size_t i = 0; i < len;)
    {
      unsigned char c = (unsigned char) s[i];
      int printable;
      size_t n = bos_quote_next (s + i, len - i, &st, &printable);
      if (!printable)
        needs = single = 1;
      else if (c == '\'')
        needs = apostrophe = 1;
      else if (c == ' ')
        needs = 1;
      else if (c < 0x80 && strchr ("!\"$&()*;<=>?[\\^`|", c))
        needs = single = 1;
      else if (c == '#' || c == '~')
        {
          single = 1;
          if (i == 0)
            needs = 1;
        }
      else if (c == '{' || c == '}')
        {
          single = 1;
          if (len == 1)
            needs = 1;
        }
      i += n;
    }
  if (!needs)
    return bcu_strdup (s);

  char *out = xmalloc (len * 8 + 8);
  if (apostrophe && !single)
    {
      out[at++] = '"';
      memcpy (out + at, s, len);
      at += len;
      out[at++] = '"';
      out[at] = '\0';
      return out;
    }
  int dollar = 0;
  memset (&st, 0, sizeof st);
  out[at++] = '\'';
  for (size_t i = 0; i < len;)
    {
      unsigned char c = (unsigned char) s[i];
      int printable;
      size_t n = bos_quote_next (s + i, len - i, &st, &printable);
      if (c == '\'')
        {
          memcpy (out + at, "'\\''", 4);
          at += 4;
          dollar = 0;
        }
      else if (!printable)
        {
          if (!dollar)
            {
              memcpy (out + at, "'$'", 3);
              at += 3;
              dollar = 1;
            }
          for (size_t k = 0; k < n; k++)
            {
              unsigned char b = (unsigned char) s[i + k];
              char letter = bos_quote_letter (b);
              out[at++] = '\\';
              if (letter)
                out[at++] = letter;
              else
                {
                  out[at++] = (char) ('0' + (b >> 6));
                  out[at++] = (char) ('0' + ((b >> 3) & 7));
                  out[at++] = (char) ('0' + (b & 7));
                }
            }
        }
      else
        {
          if (dollar)
            {
              out[at++] = '\'';
              out[at++] = '\'';
              dollar = 0;
            }
          memcpy (out + at, s + i, n);
          at += n;
        }
      i += n;
    }
  out[at++] = '\'';
  out[at] = '\0';
  return out;
}

/* A file name in a diagnostic: bare when that is unambiguous. */
#define bcu_quotef bcu_shell_quote

/* Option scanning in the manner of glibc getopt_long: short clusters,
   "-oARG" and "-o ARG", long options as "--name=ARG" or "--name ARG",
   unambiguous prefixes, operands collected in order with options after
   them still recognised unless POSIXLY_CORRECT is set, and "--". */
enum { BCU_NOARG, BCU_REQARG };
enum { BCU_OPT_HELP = 0x100, BCU_OPT_VERSION, BCU_OPT_FIRST };

struct bcu_lopt
{
  const char *name;
  int has_arg;
  int val;
};

typedef struct
{
  const char *prog;
  const char *shortopts;
  const struct bcu_lopt *longopts;
  WORD_LIST *next;
  const char *cluster;
  const char *optarg;
  int ended, posix;
  char **ops;
  int nops, cap;
} bcu_opts;

static void
bcu_opts_init (bcu_opts *g, const char *prog, const char *shortopts,
               const struct bcu_lopt *longopts, WORD_LIST *list)
{
  memset (g, 0, sizeof *g);
  g->prog = prog;
  g->shortopts = shortopts;
  g->longopts = longopts;
  g->next = list;
  g->posix = getenv ("POSIXLY_CORRECT") != NULL;
  g->ops = xmalloc (sizeof (char *));
  g->ops[0] = NULL;
}

static void
bcu_opts_free (bcu_opts *g)
{
  free (g->ops);
  g->ops = NULL;
}

static int
bcu_opts_long (bcu_opts *g, const char *word)
{
  const char *name = word + 2, *eq = strchr (name, '=');
  size_t len = eq ? (size_t) (eq - name) : strlen (name);
  const struct bcu_lopt *found = NULL, *o;
  int ambiguous = 0;

  for (o = g->longopts; o && o->name; o++)
    if (!strncmp (o->name, name, len))
      {
        if (strlen (o->name) == len)
          {
            found = o;
            ambiguous = 0;
            break;
          }
        if (!found)
          found = o;
        else if (found->has_arg != o->has_arg || found->val != o->val)
          ambiguous = 1;
      }
  if (ambiguous)
    {
      fflush (stdout);
      fprintf (stderr, "%s: option '%.*s' is ambiguous; possibilities:",
               g->prog, (int) (len + 2), word);
      for (o = g->longopts; o->name; o++)
        if (!strncmp (o->name, name, len))
          fprintf (stderr, " '--%s'", o->name);
      fputc ('\n', stderr);
      bcu_try_help (g->prog);
      return '?';
    }
  if (!found)
    {
      bcu_err (g->prog, "unrecognized option '%s'", word);
      bcu_try_help (g->prog);
      return '?';
    }
  g->optarg = NULL;
  if (eq)
    {
      if (found->has_arg == BCU_NOARG)
        {
          bcu_err (g->prog, "option '--%s' doesn't allow an argument", found->name);
          bcu_try_help (g->prog);
          return '?';
        }
      g->optarg = eq + 1;
    }
  else if (found->has_arg == BCU_REQARG)
    {
      if (!g->next)
        {
          bcu_err (g->prog, "option '--%s' requires an argument", found->name);
          bcu_try_help (g->prog);
          return '?';
        }
      g->optarg = g->next->word->word;
      g->next = g->next->next;
    }
  return found->val;
}

/* The next option, -1 when the words are used up (operands are then in
   g->ops), or '?' after a diagnostic. */
static int
bcu_opts_next (bcu_opts *g)
{
  g->optarg = NULL;
  while (!g->cluster || !*g->cluster)
    {
      g->cluster = NULL;
      if (!g->next)
        return -1;
      char *w = g->next->word->word;
      g->next = g->next->next;
      if (g->ended || w[0] != '-' || !w[1])
        {
          if (g->nops + 2 > g->cap)
            {
              g->cap = g->cap ? g->cap * 2 : 8;
              g->ops = xrealloc (g->ops, (size_t) g->cap * sizeof (char *));
            }
          g->ops[g->nops++] = w;
          g->ops[g->nops] = NULL;
          if (g->posix)
            g->ended = 1;
          continue;
        }
      if (w[1] == '-')
        {
          if (!w[2])
            {
              g->ended = 1;
              continue;
            }
          return bcu_opts_long (g, w);
        }
      g->cluster = w + 1;
    }
  int c = (unsigned char) *g->cluster++;
  const char *spec = c == ':' ? NULL : strchr (g->shortopts, c);
  if (!spec)
    {
      bcu_err (g->prog, "invalid option -- '%c'", c);
      bcu_try_help (g->prog);
      return '?';
    }
  if (spec[1] == ':')
    {
      if (*g->cluster)
        g->optarg = g->cluster;
      else if (g->next)
        {
          g->optarg = g->next->word->word;
          g->next = g->next->next;
        }
      else
        {
          bcu_err (g->prog, "option requires an argument -- '%c'", c);
          bcu_try_help (g->prog);
          return '?';
        }
      g->cluster = NULL;
    }
  return c;
}

/* Buffered output to a descriptor, for verbs that may write to a file. */
typedef struct
{
  int fd;
  int error;
  size_t used;
  char buf[65536];
} bcu_wbuf;

static void
bcu_wbuf_flush (bcu_wbuf *w)
{
  size_t off = 0;
  while (off < w->used && !w->error)
    {
      ssize_t n = write (w->fd, w->buf + off, w->used - off);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        w->error = errno;
      else
        off += (size_t) n;
    }
  w->used = 0;
}

static void
bcu_wbuf_put (bcu_wbuf *w, const char *p, size_t n)
{
  while (n && !w->error)
    {
      size_t room = sizeof w->buf - w->used;
      size_t k = n < room ? n : room;
      memcpy (w->buf + w->used, p, k);
      w->used += k;
      p += k;
      n -= k;
      if (w->used == sizeof w->buf)
        bcu_wbuf_flush (w);
    }
}

/* Unsigned decimal as coreutils reads counts and ranges: optional
   leading blanks and '+', digits, nothing after. 1 on success, 0 when
   malformed, -1 on overflow. */
static int
bcu_parse_uint (const char *s, uintmax_t *out)
{
  while (*s == ' ' || (*s >= '\t' && *s <= '\r'))
    s++;
  if (*s == '+')
    s++;
  if (*s < '0' || *s > '9')
    return 0;
  uintmax_t v = 0;
  int over = 0;
  for (; *s >= '0' && *s <= '9'; s++)
    {
      unsigned d = (unsigned) (*s - '0');
      if (v > (UINTMAX_MAX - d) / 10)
        over = 1;
      else
        v = v * 10 + d;
    }
  if (*s)
    return 0;
  *out = over ? UINTMAX_MAX : v;
  return over ? -1 : 1;
}

/* ===================================================================
 * shuf — random permutation of input lines, operands or a range.
 *
 *   -e, --echo                 each operand is an input line
 *   -i, --input-range=LO-HI    the numbers LO..HI are the input lines
 *   -n, --head-count=COUNT     output at most COUNT lines (smallest wins)
 *   -o, --output=FILE          write to FILE, opened after the input is read
 *   --random-source=FILE       take random bytes from FILE
 *   -r, --repeat               draw with replacement (forever without -n)
 *   -z, --zero-terminated      lines end in NUL, not newline
 * Plain `shuf` (or `shuf FILE`) reads lines from stdin/FILE.
 * Written from the coreutils manual and observed coreutils 9.7 behaviour;
 * the permutation itself is this file's own (see the parity exclusion).
 * =================================================================== */

typedef struct
{
  const char *source;   /* --random-source, or NULL for the kernel */
  int fd;
  unsigned char buf[512];
  size_t have, pos;
  int failed;
} bcu_rand;

/* Next random byte; 0 with r->failed set after a diagnostic. */
static int
bcu_rand_byte (bcu_rand *r, unsigned char *b)
{
  if (r->pos == r->have)
    {
      ssize_t n;
      r->pos = r->have = 0;
      if (r->fd < 0)
        {
#if defined (__linux__) && defined (SYS_getrandom)
          do
            n = syscall (SYS_getrandom, r->buf, sizeof r->buf, 0);
          while (n < 0 && errno == EINTR);
          if (n <= 0)
#endif
            {
              r->fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
              if (r->fd < 0)
                {
                  bcu_err ("shuf", "/dev/urandom: %s", strerror (errno));
                  r->failed = 1;
                  return 0;
                }
              return bcu_rand_byte (r, b);
            }
#if defined (__linux__) && defined (SYS_getrandom)
          r->have = (size_t) n;
#endif
        }
      else
        {
          do
            n = read (r->fd, r->buf, sizeof r->buf);
          while (n < 0 && errno == EINTR);
          if (n <= 0)
            {
              char *q = bcu_quote (r->source ? r->source : "/dev/urandom");
              if (n == 0)
                bcu_err ("shuf", "%s: end of file", q);
              else
                bcu_err ("shuf", "%s: read error: %s", q, strerror (errno));
              free (q);
              r->failed = 1;
              return 0;
            }
          r->have = (size_t) n;
        }
    }
  *b = r->buf[r->pos++];
  return 1;
}

/* Uniform value in [0, N): N <= 1 needs no randomness. Big-endian bytes
   masked to the bit length of N - 1, redrawn when too large, so a source
   of zero bytes always yields 0. */
static uintmax_t
bcu_rand_below (bcu_rand *r, uintmax_t n)
{
  if (n <= 1 || r->failed)
    return 0;
  uintmax_t max = n - 1, mask = max;
  int bytes = 0;
  for (uintmax_t m = max; m; m >>= 8)
    bytes++;
  for (int s = 1; s < 64; s <<= 1)
    mask |= mask >> s;
  for (;;)
    {
      uintmax_t v = 0;
      for (int i = 0; i < bytes; i++)
        {
          unsigned char b;
          if (!bcu_rand_byte (r, &b))
            return 0;
          v = (v << 8) | b;
        }
      v &= mask;
      if (v <= max)
        return v;
    }
}

/* Sparse map of swapped positions for a partial shuffle of a range too
   large to hold: open addressing over uintmax_t keys. */
typedef struct
{
  uintmax_t *keys, *vals;
  unsigned char *used;
  size_t cap, count;
} bcu_umap;

static size_t
bcu_umap_slot (const bcu_umap *m, uintmax_t key)
{
  uint64_t h = (uint64_t) key * 0x9E3779B97F4A7C15ULL;
  size_t i = (size_t) (h ^ (h >> 29)) & (m->cap - 1);
  while (m->used[i] && m->keys[i] != key)
    i = (i + 1) & (m->cap - 1);
  return i;
}

static void
bcu_umap_put (bcu_umap *m, uintmax_t key, uintmax_t val)
{
  if ((m->count + 1) * 2 > m->cap)
    {
      bcu_umap old = *m;
      m->cap = old.cap ? old.cap * 2 : 64;
      m->keys = xmalloc (m->cap * sizeof *m->keys);
      m->vals = xmalloc (m->cap * sizeof *m->vals);
      m->used = bcu_calloc (m->cap, 1);
      m->count = 0;
      for (size_t i = 0; i < old.cap; i++)
        if (old.used[i])
          bcu_umap_put (m, old.keys[i], old.vals[i]);
      free (old.keys);
      free (old.vals);
      free (old.used);
    }
  size_t i = bcu_umap_slot (m, key);
  if (!m->used[i])
    {
      m->used[i] = 1;
      m->keys[i] = key;
      m->count++;
    }
  m->vals[i] = val;
}

static uintmax_t
bcu_umap_get (const bcu_umap *m, uintmax_t key)
{
  if (!m->cap)
    return key;
  size_t i = bcu_umap_slot (m, key);
  return m->used[i] ? m->vals[i] : key;
}

static void
bcu_shuf_usage (void)
{
  fputs ("Usage: shuf [OPTION]... [FILE]\n"
         "  or:  shuf -e [OPTION]... [ARG]...\n"
         "  or:  shuf -i LO-HI [OPTION]...\n"
         "Print the input lines in a random order.\n"
         "\n"
         "With no FILE, or when FILE is -, read standard input.\n"
         "\n"
         "Mandatory arguments to long options are mandatory for short options too.\n"
         "  -e, --echo                each ARG is an input line\n"
         "  -i, --input-range=LO-HI   the numbers LO to HI are the input lines\n"
         "  -n, --head-count=COUNT    print no more than COUNT lines\n"
         "  -o, --output=FILE         write to FILE, not standard output\n"
         "      --random-source=FILE  read random bytes from FILE\n"
         "  -r, --repeat              a line may be printed more than once\n"
         "  -z, --zero-terminated     lines end in NUL, not newline\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n",
         stdout);
}

static int
bcu_shuf_cmd (WORD_LIST *list)
{
  enum { OPT_RANDOM_SOURCE = BCU_OPT_FIRST };
  static const struct bcu_lopt longopts[] = {
    { "echo",            BCU_NOARG,  'e' },
    { "input-range",     BCU_REQARG, 'i' },
    { "head-count",      BCU_REQARG, 'n' },
    { "output",          BCU_REQARG, 'o' },
    { "random-source",   BCU_REQARG, OPT_RANDOM_SOURCE },
    { "repeat",          BCU_NOARG,  'r' },
    { "zero-terminated", BCU_NOARG,  'z' },
    { "help",            BCU_NOARG,  BCU_OPT_HELP },
    { "version",         BCU_NOARG,  BCU_OPT_VERSION },
    { NULL, 0, 0 }
  };
  bcu_opts g;
  int c, echo = 0, have_range = 0, repeat = 0, rc = EXECUTION_FAILURE;
  char delim = '\n';
  uintmax_t lo = 0, hi = 0, head = UINTMAX_MAX;
  const char *outfile = NULL, *source = NULL;
  char *data = NULL;
  char **lines = NULL;
  size_t nlines = 0, *loff = NULL, *llen = NULL;
  bcu_rand rnd;
  bcu_umap map;
  int outfd = -1;

  memset (&rnd, 0, sizeof rnd);
  rnd.fd = -1;
  memset (&map, 0, sizeof map);
  bcu_opts_init (&g, "shuf", "ei:n:o:rz", longopts, list);
  while ((c = bcu_opts_next (&g)) != -1)
    {
      switch (c)
        {
        case 'e':
          echo = 1;
          break;
        case 'i':
          {
            if (have_range)
              {
                bcu_err ("shuf", "multiple -i options specified");
                goto out;
              }
            const char *a = g.optarg, *dash = strchr (a, '-');
            int ok = 0, over = 0;
            if (dash)
              {
                char *left = bcu_strdup (a);
                left[dash - a] = '\0';
                int l = bcu_parse_uint (left, &lo);
                int h = bcu_parse_uint (dash + 1, &hi);
                free (left);
                over = l < 0 || h < 0;
                ok = l == 1 && h == 1 && !(lo == 0 && hi == UINTMAX_MAX)
                     && (hi >= lo || hi + 1 == lo);
              }
            if (!ok)
              {
                char *q = bcu_quote (a);
                if (over)
                  bcu_err ("shuf", "invalid input range: %s: %s", q, strerror (EOVERFLOW));
                else
                  bcu_err ("shuf", "invalid input range: %s", q);
                free (q);
                goto out;
              }
            have_range = 1;
            break;
          }
        case 'n':
          {
            uintmax_t v;
            if (!bcu_parse_uint (g.optarg, &v))
              {
                char *q = bcu_quote (g.optarg);
                bcu_err ("shuf", "invalid line count: %s", q);
                free (q);
                goto out;
              }
            if (v < head)
              head = v;
            break;
          }
        case 'o':
          if (outfile && strcmp (outfile, g.optarg))
            {
              bcu_err ("shuf", "multiple output files specified");
              goto out;
            }
          outfile = g.optarg;
          break;
        case OPT_RANDOM_SOURCE:
          if (source && strcmp (source, g.optarg))
            {
              bcu_err ("shuf", "multiple random sources specified");
              goto out;
            }
          source = g.optarg;
          break;
        case 'r':
          repeat = 1;
          break;
        case 'z':
          delim = '\0';
          break;
        case BCU_OPT_HELP:
          bcu_shuf_usage ();
          rc = EXECUTION_SUCCESS;
          goto out;
        case BCU_OPT_VERSION:
          puts ("shuf (bash-os coreutils)");
          rc = EXECUTION_SUCCESS;
          goto out;
        default:
          goto out;
        }
    }

  if (echo && have_range)
    {
      bcu_err ("shuf", "cannot combine -e and -i options");
      bcu_try_help ("shuf");
      goto out;
    }
  if (!echo && g.nops > (have_range ? 0 : 1))
    {
      char *q = bcu_quote (g.ops[have_range ? 0 : 1]);
      bcu_err ("shuf", "extra operand %s", q);
      free (q);
      bcu_try_help ("shuf");
      goto out;
    }

  if (source)
    {
      rnd.source = source;
      rnd.fd = open (source, O_RDONLY | O_CLOEXEC);
      if (rnd.fd < 0)
        {
          char *q = bcu_quotef (source);
          bcu_err ("shuf", "%s: %s", q, strerror (errno));
          free (q);
          goto out;
        }
    }

  /* Gather the input lines (a range stays implicit). */
  uintmax_t total;
  if (have_range)
    total = hi + 1 - lo;
  else if (echo)
    {
      lines = g.ops;
      nlines = (size_t) g.nops;
      total = nlines;
    }
  else
    {
      const char *name = g.nops ? g.ops[0] : "-";
      int fd = 0;
      if (strcmp (name, "-"))
        {
          fd = open (name, O_RDONLY | O_CLOEXEC);
          if (fd < 0)
            {
              char *q = bcu_quotef (name);
              bcu_err ("shuf", "%s: %s", q, strerror (errno));
              free (q);
              goto out;
            }
        }
      ssize_t len = bcu_tac_slurp (fd, &data);
      int e = errno;
      if (fd)
        close (fd);
      if (len < 0)
        {
          char *q = bcu_quotef (name);
          bcu_err ("shuf", "%s: read error: %s", q, strerror (e));
          free (q);
          goto out;
        }
      size_t cap = 0;
      for (size_t at = 0; at < (size_t) len;)
        {
          char *end = memchr (data + at, delim, (size_t) len - at);
          size_t stop = end ? (size_t) (end - data) : (size_t) len;
          if (nlines == cap)
            {
              cap = cap ? cap * 2 : 64;
              loff = xrealloc (loff, cap * sizeof *loff);
              llen = xrealloc (llen, cap * sizeof *llen);
            }
          loff[nlines] = at;
          llen[nlines++] = stop - at;
          at = stop + 1;
        }
      total = nlines;
    }

  if (repeat && total == 0 && head)
    {
      bcu_err ("shuf", "no lines to repeat");
      goto out;
    }

  if (outfile)
    {
      outfd = open (outfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
      if (outfd < 0)
        {
          char *q = bcu_quotef (outfile);
          bcu_err ("shuf", "%s: %s", q, strerror (errno));
          free (q);
          goto out;
        }
    }
  else
    fflush (stdout);

  bcu_wbuf *w = xmalloc (sizeof *w);
  w->fd = outfd >= 0 ? outfd : 1;
  w->error = 0;
  w->used = 0;
  uintmax_t count = repeat ? head : (head < total ? head : total);
  char num[32];
  for (uintmax_t k = 0; (repeat ? (head == UINTMAX_MAX || k < count) : k < count)
         && !w->error && !rnd.failed; k++)
    {
      uintmax_t pick;
      if (repeat)
        pick = bcu_rand_below (&rnd, total);
      else
        {
          /* Forward Fisher-Yates: position k takes a random one of the
             positions k..total-1. */
          uintmax_t j = k + bcu_rand_below (&rnd, total - k);
          pick = bcu_umap_get (&map, j);
          if (j != k)
            bcu_umap_put (&map, j, bcu_umap_get (&map, k));
        }
      if (rnd.failed)
        break;
      if (have_range)
        {
          int n = snprintf (num, sizeof num, "%ju", lo + pick);
          bcu_wbuf_put (w, num, (size_t) n);
        }
      else
        {
          if (echo)
            bcu_wbuf_put (w, lines[pick], strlen (lines[pick]));
          else
            bcu_wbuf_put (w, data + loff[pick], llen[pick]);
        }
      bcu_wbuf_put (w, &delim, 1);
    }
  if (!w->error && !rnd.failed)
    bcu_wbuf_flush (w);
  if (w->error)
    {
      if (outfile)
        {
          char *q = bcu_quotef (outfile);
          bcu_err ("shuf", "%s: %s", q, strerror (w->error));
          free (q);
        }
      else
        bcu_err ("shuf", "write error: %s", strerror (w->error));
    }
  else if (!rnd.failed)
    rc = EXECUTION_SUCCESS;
  free (w);
  if (outfd >= 0 && close (outfd) < 0 && rc == EXECUTION_SUCCESS)
    {
      char *q = bcu_quotef (outfile);
      bcu_err ("shuf", "%s: %s", q, strerror (errno));
      free (q);
      rc = EXECUTION_FAILURE;
    }
  outfd = -1;

out:
  if (outfd >= 0)
    close (outfd);
  if (rnd.fd >= 0)
    close (rnd.fd);
  free (map.keys);
  free (map.vals);
  free (map.used);
  free (loff);
  free (llen);
  free (data);
  bcu_opts_free (&g);
  return rc;
}

/* ===================================================================
 * factor — prime factorization of integers of any size, as GNU factor.
 *
 *   coreutils factor [-h|--exponents] [NUMBER]...
 *
 * Written from published algorithms, not from any factor source:
 *   - trial division by the primes below BCU_FACTOR_TRIAL;
 *   - Miller-Rabin (Miller 1976, Rabin 1980), deterministic below 2^64
 *     with the first twelve prime bases (Sorenson and Webster 2015);
 *   - above 2^64, Baillie-PSW: Miller-Rabin to base 2 and the strong
 *     Lucas test with Selfridge's parameters (Baillie and Wagstaff 1980);
 *   - Pollard's rho method with Brent's cycle finding and batched gcds
 *     (Pollard 1975, Brent 1980);
 *   - Montgomery multiplication (Montgomery 1985) for big moduli and for
 *     rho below 2^64;
 *   - a perfect square is split by its square root (digit-by-digit).
 * Big numbers are little-endian arrays of 64-bit limbs (32-bit without
 * 128-bit integers), every one of a token's values the same length (the
 * input's limbs plus one). Above 2^64 a prime is a Baillie-PSW probable
 * prime (no composite is known to pass); GNU proves primality instead,
 * which can take it far longer on large primes. Rho needs about sqrt(p)
 * steps for the second-largest prime factor p: a factor near 10^17 takes
 * minutes, as it does with GNU's.
 * =================================================================== */

#define BCU_FACTOR_TRIAL 4096u
#define BCU_FACTOR_BATCH 128

/* Limbs are 64 bits wide where the compiler has 128-bit integers for the
   double-width products, 32 bits otherwise. */
#if defined (__SIZEOF_INT128__)
typedef uint64_t bf_limb;
typedef unsigned __int128 bf_dlimb;
#  define BF_BITS 64
#else
typedef uint32_t bf_limb;
typedef uint64_t bf_dlimb;
#  define BF_BITS 32
#endif

static int bcu_factor_stop;   /* an interrupt arrived: unwind and QUIT */

static int
bf_interrupted (void)
{
  if (interrupt_state || terminating_signal)
    bcu_factor_stop = 1;
  return bcu_factor_stop;
}

/* --- fixed-length limb arithmetic (L limbs each) ------------------- */

static int
bf_is_zero (const bf_limb *a, size_t L)
{
  for (size_t i = 0; i < L; i++)
    if (a[i]) return 0;
  return 1;
}

static int
bf_is_one (const bf_limb *a, size_t L)
{
  if (a[0] != 1) return 0;
  for (size_t i = 1; i < L; i++)
    if (a[i]) return 0;
  return 1;
}

static int
bf_cmp (const bf_limb *a, const bf_limb *b, size_t L)
{
  for (size_t i = L; i-- > 0;)
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

static void
bf_set_u64 (bf_limb *a, size_t L, uint64_t v)
{
  memset (a, 0, L * sizeof *a);
  a[0] = (bf_limb) v;
#if BF_BITS == 32
  if (L > 1) a[1] = (bf_limb) (v >> 32);
#endif
}

/* Significant limbs (0 for zero). */
static size_t
bf_len (const bf_limb *a, size_t L)
{
  while (L && a[L - 1] == 0) L--;
  return L;
}

static int
bf_fits_u64 (const bf_limb *a, size_t L)
{
  return bf_len (a, L) <= 64 / BF_BITS;
}

static uint64_t
bf_get_u64 (const bf_limb *a, size_t L)
{
#if BF_BITS == 32
  return (uint64_t) a[0] | (L > 1 ? (uint64_t) a[1] << 32 : 0);
#else
  (void) L;
  return a[0];
#endif
}

static size_t
bf_bits (const bf_limb *a, size_t L)
{
  size_t n = bf_len (a, L);
  if (!n) return 0;
  size_t bits = (n - 1) * BF_BITS;
  for (bf_limb top = a[n - 1]; top; top >>= 1) bits++;
  return bits;
}

static int
bf_bit (const bf_limb *a, size_t i)
{
  return (a[i / BF_BITS] >> (i % BF_BITS)) & 1;
}

static bf_limb
bf_add (bf_limb *r, const bf_limb *a, const bf_limb *b, size_t L)
{
  bf_dlimb c = 0;
  for (size_t i = 0; i < L; i++)
    {
      c += (bf_dlimb) a[i] + b[i];
      r[i] = (bf_limb) c;
      c >>= BF_BITS;
    }
  return (bf_limb) c;
}

static bf_limb
bf_sub (bf_limb *r, const bf_limb *a, const bf_limb *b, size_t L)
{
  bf_dlimb borrow = 0;
  for (size_t i = 0; i < L; i++)
    {
      bf_dlimb d = (bf_dlimb) a[i] - b[i] - borrow;
      r[i] = (bf_limb) d;
      borrow = (d >> BF_BITS) & 1;
    }
  return (bf_limb) borrow;
}

static void
bf_shr1 (bf_limb *a, size_t L, bf_limb top)
{
  for (size_t i = 0; i < L; i++)
    a[i] = (a[i] >> 1) | ((i + 1 < L ? a[i + 1] : top) << (BF_BITS - 1));
}

static void
bf_shr (bf_limb *a, size_t L, size_t k)
{
  size_t w = k / BF_BITS, b = k % BF_BITS;
  for (size_t i = 0; i < L; i++)
    {
      bf_limb lo = i + w < L ? a[i + w] : 0;
      bf_limb hi = i + w + 1 < L ? a[i + w + 1] : 0;
      a[i] = b ? (lo >> b) | (hi << (BF_BITS - b)) : lo;
    }
}

static bf_limb
bf_shl1 (bf_limb *a, size_t L)
{
  bf_limb carry = 0;
  for (size_t i = 0; i < L; i++)
    {
      bf_limb next = a[i] >> (BF_BITS - 1);
      a[i] = (a[i] << 1) | carry;
      carry = next;
    }
  return carry;
}

static size_t
bf_ctz (const bf_limb *a, size_t L)
{
  size_t k = 0;
  for (size_t i = 0; i < L; i++)
    {
      if (a[i])
        {
          bf_limb v = a[i];
          while (!(v & 1)) { v >>= 1; k++; }
          return k;
        }
      k += BF_BITS;
    }
  return k;
}

/* A /= d; returns A mod d. */
static bf_limb
bf_divmod_1 (bf_limb *a, size_t L, bf_limb d)
{
  bf_dlimb r = 0;
  for (size_t i = L; i-- > 0;)
    {
      bf_dlimb cur = (r << BF_BITS) | a[i];
      a[i] = (bf_limb) (cur / d);
      r = cur % d;
    }
  return (bf_limb) r;
}

static bf_limb
bf_mod_1 (const bf_limb *a, size_t L, bf_limb d)
{
  bf_dlimb r = 0;
  for (size_t i = L; i-- > 0;)
    r = ((r << BF_BITS) | a[i]) % d;
  return (bf_limb) r;
}

/* A = A * m + add; returns the carry out. */
static bf_limb
bf_mul_1_add (bf_limb *a, size_t L, bf_limb m, bf_limb add)
{
  bf_dlimb c = add;
  for (size_t i = 0; i < L; i++)
    {
      c += (bf_dlimb) a[i] * m;
      a[i] = (bf_limb) c;
      c >>= BF_BITS;
    }
  return (bf_limb) c;
}

/* Q = A / B, exactly or not (shift-subtract long division). T is L
   limbs of scratch. B is nonzero. */
static void
bf_div (bf_limb *q, const bf_limb *a, const bf_limb *b, bf_limb *t, size_t L)
{
  memset (q, 0, L * sizeof *q);
  memset (t, 0, L * sizeof *t);
  for (size_t i = bf_bits (a, L); i-- > 0;)
    {
      bf_limb out = bf_shl1 (t, L);
      t[0] |= (bf_limb) bf_bit (a, i);
      if (out || bf_cmp (t, b, L) >= 0)
        {
          bf_sub (t, t, b, L);
          q[i / BF_BITS] |= (bf_limb) 1 << (i % BF_BITS);
        }
    }
}

/* G = gcd (A, B) by the binary method; A and B are consumed. */
static void
bf_gcd (bf_limb *g, bf_limb *a, bf_limb *b, size_t L)
{
  if (bf_is_zero (a, L)) { memcpy (g, b, L * sizeof *g); return; }
  if (bf_is_zero (b, L)) { memcpy (g, a, L * sizeof *g); return; }
  size_t za = bf_ctz (a, L), zb = bf_ctz (b, L), k = za < zb ? za : zb;
  bf_shr (a, L, za);
  bf_shr (b, L, zb);
  for (;;)
    {
      int c = bf_cmp (a, b, L);
      if (c == 0) break;
      if (c < 0) { bf_limb *t = a; a = b; b = t; }
      bf_sub (a, a, b, L);
      bf_shr (a, L, bf_ctz (a, L));
    }
  memcpy (g, a, L * sizeof *g);
  /* gcd * 2^k; k is 0 here, since every caller passes an odd number. */
  for (size_t i = 0; i < k; i++) bf_shl1 (g, L);
}

/* Digit-by-digit square root: is A a perfect square? Its root goes to
   ROOT when ROOT is not NULL. */
static int
bf_square_root (const bf_limb *a, size_t L, bf_limb *root)
{
  size_t sz = L * sizeof (bf_limb);
  bf_limb *num = xmalloc (sz), *res = xmalloc (sz), *bit = xmalloc (sz), *t = xmalloc (sz);
  memcpy (num, a, sz);
  memset (res, 0, sz);
  memset (bit, 0, sz);
  size_t top = bf_bits (a, L);
  top = top ? (top - 1) & ~(size_t) 1 : 0;
  bit[top / BF_BITS] = (bf_limb) 1 << (top % BF_BITS);
  while (!bf_is_zero (bit, L))
    {
      bf_add (t, res, bit, L);
      if (bf_cmp (num, t, L) >= 0)
        {
          bf_sub (num, num, t, L);
          bf_shr1 (res, L, 0);
          bf_add (res, res, bit, L);
        }
      else
        bf_shr1 (res, L, 0);
      bf_shr (bit, L, 2);
    }
  int sq = bf_is_zero (num, L);
  if (root)
    memcpy (root, res, sz);
  free (num); free (res); free (bit); free (t);
  return sq;
}

static int
bf_is_square (const bf_limb *a, size_t L)
{
  return bf_square_root (a, L, NULL);
}

/* --- Montgomery arithmetic modulo an odd N of k limbs ---------------- */

typedef struct {
  size_t k;          /* limbs of n */
  bf_limb *n;        /* the modulus, k limbs */
  bf_limb ninv;      /* -n^-1 mod 2^BF_BITS */
  bf_limb *one;      /* R mod n (Montgomery 1) */
  bf_limb *r2;       /* R^2 mod n */
  bf_limb *t;        /* k + 2 limbs of scratch */
} bf_mont;

/* R = A * B / 2^(BF_BITS k) mod N; A, B < N; R may alias A or B. */
static void
bf_mont_mul (bf_limb *r, const bf_limb *a, const bf_limb *b, const bf_mont *m)
{
  size_t k = m->k;
  bf_limb *t = m->t;
  memset (t, 0, (k + 2) * sizeof *t);
  for (size_t i = 0; i < k; i++)
    {
      bf_dlimb c = 0, bi = b[i];
      for (size_t j = 0; j < k; j++)
        {
          c += (bf_dlimb) t[j] + a[j] * bi;
          t[j] = (bf_limb) c;
          c >>= BF_BITS;
        }
      c += t[k];
      t[k] = (bf_limb) c;
      t[k + 1] = (bf_limb) (c >> BF_BITS);
      bf_dlimb q = (bf_limb) (t[0] * m->ninv);
      c = ((bf_dlimb) t[0] + q * m->n[0]) >> BF_BITS;
      for (size_t j = 1; j < k; j++)
        {
          c += (bf_dlimb) t[j] + q * m->n[j];
          t[j - 1] = (bf_limb) c;
          c >>= BF_BITS;
        }
      c += t[k];
      t[k - 1] = (bf_limb) c;
      t[k] = t[k + 1] + (bf_limb) (c >> BF_BITS);
    }
  if (t[k] || bf_cmp (t, m->n, k) >= 0)
    bf_sub (t, t, m->n, k);
  memcpy (r, t, k * sizeof *r);
}

static void
bf_mont_add (bf_limb *r, const bf_limb *a, const bf_limb *b, const bf_mont *m)
{
  bf_limb c = bf_add (r, a, b, m->k);
  if (c || bf_cmp (r, m->n, m->k) >= 0)
    bf_sub (r, r, m->n, m->k);
}

static void
bf_mont_sub (bf_limb *r, const bf_limb *a, const bf_limb *b, const bf_mont *m)
{
  if (bf_sub (r, a, b, m->k))
    bf_add (r, r, m->n, m->k);
}

/* R = A / 2 mod N. */
static void
bf_mont_half (bf_limb *r, const bf_limb *a, const bf_mont *m)
{
  bf_limb top = 0;
  if (r != a) memcpy (r, a, m->k * sizeof *r);
  if (r[0] & 1)
    top = bf_add (r, r, m->n, m->k);
  bf_shr1 (r, m->k, top);
}

/* N (L limbs, odd, more than one) into a Montgomery context of its own
   significant length. */
static void
bf_mont_init (bf_mont *m, const bf_limb *n, size_t L)
{
  size_t k = bf_len (n, L);
  m->k = k;
  m->n = xmalloc (k * sizeof *m->n);
  m->one = xmalloc (k * sizeof *m->one);
  m->r2 = xmalloc (k * sizeof *m->r2);
  m->t = xmalloc ((k + 2) * sizeof *m->t);
  memcpy (m->n, n, k * sizeof *m->n);
  bf_limb inv = m->n[0];            /* Newton: correct to 3, 6, 12, 24, 48, 96 bits */
  for (int i = 0; i < 5; i++)
    inv *= 2 - m->n[0] * inv;
  m->ninv = (bf_limb) (0 - inv);
  /* R^2 mod n by doubling 1 a total of 64k times. */
  memset (m->r2, 0, k * sizeof *m->r2);
  m->r2[0] = 1;
  for (size_t i = 0; i < 2 * BF_BITS * k; i++)
    {
      bf_limb out = bf_shl1 (m->r2, k);
      if (out || bf_cmp (m->r2, m->n, k) >= 0)
        bf_sub (m->r2, m->r2, m->n, k);
    }
  memset (m->one, 0, k * sizeof *m->one);
  m->one[0] = 1;
  bf_mont_mul (m->one, m->one, m->r2, m);
}

static void
bf_mont_free (bf_mont *m)
{
  free (m->n); free (m->one); free (m->r2); free (m->t);
}

/* Montgomery form of the small value V (V < n). */
static void
bf_mont_small (bf_limb *r, uint64_t v, const bf_mont *m)
{
  bf_set_u64 (r, m->k, v);
  if (m->k == 1)
    r[0] = (bf_limb) (v % m->n[0]);
  bf_mont_mul (r, r, m->r2, m);
}

/* R = B^E mod n, all in Montgomery form; E is a plain L-limb number. */
static void
bf_mont_pow (bf_limb *r, const bf_limb *b, const bf_limb *e, size_t L, const bf_mont *m)
{
  bf_limb *acc = xmalloc (m->k * sizeof *acc);
  memcpy (acc, m->one, m->k * sizeof *acc);
  for (size_t i = bf_bits (e, L); i-- > 0;)
    {
      bf_mont_mul (acc, acc, acc, m);
      if (bf_bit (e, i))
        bf_mont_mul (acc, acc, b, m);
    }
  memcpy (r, acc, m->k * sizeof *r);
  free (acc);
}

/* --- primality above 2^64: Baillie-PSW -------------------------------- */

/* Jacobi symbol (a / n) for a small and n odd. */
static int
bf_jacobi_small (uint64_t a, uint64_t n)
{
  int s = 1;
  a %= n;
  while (a)
    {
      while (!(a & 1))
        {
          a >>= 1;
          if ((n & 7) == 3 || (n & 7) == 5) s = -s;
        }
      uint64_t t = a; a = n; n = t;
      if ((a & 3) == 3 && (n & 3) == 3) s = -s;
      a %= n;
    }
  return n == 1 ? s : 0;
}

/* (D / n) for a small odd |D| and a big odd n. */
static int
bf_jacobi (long d, const bf_limb *n, size_t L)
{
  uint64_t ad = d < 0 ? (uint64_t) -d : (uint64_t) d;
  int s = 1;
  if (d < 0 && (n[0] & 3) == 3) s = -s;           /* (-1 / n) */
  /* Reciprocity for odd ad: (ad / n) = (n / ad) * (-1)^((ad-1)/2 (n-1)/2). */
  if ((ad & 3) == 3 && (n[0] & 3) == 3) s = -s;
  return s * bf_jacobi_small (bf_mod_1 (n, L, (bf_limb) ad), ad);
}

static int
bf_miller_rabin (const bf_limb *n, size_t L, const bf_mont *m, uint64_t base)
{
  size_t k = m->k, sz = L * sizeof (bf_limb);
  bf_limb *d = xmalloc (sz), *x = xmalloc (k * sizeof *x), *b = xmalloc (k * sizeof *b),
          *nm1 = xmalloc (k * sizeof *nm1);
  int prime = 0;
  memcpy (d, n, sz);
  d[0] &= ~(bf_limb) 1;                             /* n - 1, n odd */
  size_t s = bf_ctz (d, L);
  bf_shr (d, L, s);
  bf_mont_small (b, base, m);
  bf_mont_pow (x, b, d, L, m);
  bf_mont_sub (nm1, m->n, m->one, m);               /* -1 = n - R mod n */
  if (bf_cmp (x, m->one, k) == 0 || bf_cmp (x, nm1, k) == 0)
    prime = 1;
  for (size_t r = 1; r < s && !prime; r++)
    {
      bf_mont_mul (x, x, x, m);
      if (bf_cmp (x, nm1, k) == 0) prime = 1;
      else if (bf_cmp (x, m->one, k) == 0) break;
    }
  free (d); free (x); free (b); free (nm1);
  return prime;
}

/* Strong Lucas probable prime with Selfridge's method A: the first D of
   5, -7, 9, -11, ... with (D / n) = -1, P = 1, Q = (1 - D) / 4. */
static int
bf_strong_lucas (const bf_limb *n, size_t L, const bf_mont *m)
{
  long d = 5;
  for (int tries = 0;; tries++, d = d > 0 ? -(d + 2) : -d + 2)
    {
      int j = bf_jacobi (d, n, L);
      if (j == -1) break;
      if (j == 0) return 0;              /* |D| < n shares a factor with n */
      if (tries == 20 && bf_is_square (n, L)) return 0;
    }
  long q = (1 - d) / 4;
  size_t k = m->k, sz = L * sizeof (bf_limb), ks = k * sizeof (bf_limb);
  bf_limb *e = xmalloc (sz), *U = xmalloc (ks), *V = xmalloc (ks), *Qk = xmalloc (ks),
          *Qm = xmalloc (ks), *Dm = xmalloc (ks), *t = xmalloc (ks), *u = xmalloc (ks),
          *z = xmalloc (ks);
  int prime = 0;

  /* n + 1 = e * 2^s with e odd; n has at most L - 1 limbs. */
  memcpy (e, n, sz);
  {
    bf_dlimb c = 1;
    for (size_t i = 0; i < L && c; i++) { c += e[i]; e[i] = (bf_limb) c; c >>= BF_BITS; }
  }
  size_t s = bf_ctz (e, L);
  bf_shr (e, L, s);

  /* Small signed constants in Montgomery form. */
  memset (z, 0, ks);
  bf_mont_small (Qm, (uint64_t) (q < 0 ? -q : q), m);
  if (q < 0)
    bf_mont_sub (Qm, z, Qm, m);
  bf_mont_small (Dm, (uint64_t) (d < 0 ? -d : d), m);
  if (d < 0)
    bf_mont_sub (Dm, z, Dm, m);

  memcpy (U, m->one, ks);               /* U_1 = 1 */
  memcpy (V, m->one, ks);               /* V_1 = P = 1 */
  memcpy (Qk, Qm, ks);                  /* Q^1 */
  for (size_t i = bf_bits (e, L) - 1; i-- > 0;)
    {
      bf_mont_mul (U, U, V, m);                          /* U_2k = U_k V_k */
      bf_mont_mul (V, V, V, m);
      bf_mont_add (t, Qk, Qk, m);
      bf_mont_sub (V, V, t, m);                          /* V_2k = V_k^2 - 2Q^k */
      bf_mont_mul (Qk, Qk, Qk, m);
      if (bf_bit (e, i))
        {
          bf_mont_add (t, U, V, m);                      /* (P U + V) / 2 */
          bf_mont_mul (u, Dm, U, m);
          bf_mont_add (u, u, V, m);                      /* (D U + P V) / 2 */
          bf_mont_half (U, t, m);
          bf_mont_half (V, u, m);
          bf_mont_mul (Qk, Qk, Qm, m);
        }
    }
  if (bf_is_zero (U, k) || bf_is_zero (V, k))
    prime = 1;
  for (size_t r = 1; r < s && !prime; r++)
    {
      bf_mont_mul (V, V, V, m);
      bf_mont_add (t, Qk, Qk, m);
      bf_mont_sub (V, V, t, m);
      bf_mont_mul (Qk, Qk, Qk, m);
      if (bf_is_zero (V, k)) prime = 1;
    }
  free (e); free (U); free (V); free (Qk); free (Qm); free (Dm); free (t); free (u); free (z);
  return prime;
}

/* N above 2^64 with no factor below BCU_FACTOR_TRIAL. */
static int
bf_is_prime (const bf_limb *n, size_t L)
{
  bf_mont m;
  bf_mont_init (&m, n, L);
  int prime = bf_miller_rabin (n, L, &m, 2) && bf_strong_lucas (n, L, &m);
  bf_mont_free (&m);
  return prime;
}

/* Pollard-Brent rho: a nontrivial factor of the odd composite N into F;
   0 on success, -1 when interrupted. */
static int
bf_rho (bf_limb *f, const bf_limb *n, size_t L)
{
  bf_mont m;
  bf_mont_init (&m, n, L);
  size_t k = m.k, ks = k * sizeof (bf_limb), sz = L * sizeof (bf_limb);
  bf_limb *x = xmalloc (ks), *y = xmalloc (ks), *ys = xmalloc (ks), *q = xmalloc (ks),
          *c = xmalloc (ks), *diff = xmalloc (ks);
  bf_limb *ga = xmalloc (sz), *gb = xmalloc (sz), *g = xmalloc (sz);
  int rc = -1;

  for (uint64_t cv = 1;; cv++)
    {
      int found = 0;
      bf_mont_small (c, cv, &m);
      bf_mont_small (y, 2, &m);
      memcpy (q, m.one, ks);
      for (size_t r = 1; !found; r *= 2)
        {
          memcpy (x, y, ks);
          for (size_t i = 0; i < r; i++)
            {
              bf_mont_mul (y, y, y, &m);
              bf_mont_add (y, y, c, &m);
            }
          for (size_t done = 0; done < r && !found; done += BCU_FACTOR_BATCH)
            {
              if (bf_interrupted ()) goto out;
              memcpy (ys, y, ks);
              size_t lim = r - done < BCU_FACTOR_BATCH ? r - done : BCU_FACTOR_BATCH;
              for (size_t i = 0; i < lim; i++)
                {
                  bf_mont_mul (y, y, y, &m);
                  bf_mont_add (y, y, c, &m);
                  bf_mont_sub (diff, x, y, &m);
                  bf_mont_mul (q, q, diff, &m);
                }
              memset (ga, 0, sz); memcpy (ga, q, ks);
              memset (gb, 0, sz); memcpy (gb, n, ks);
              bf_gcd (g, ga, gb, L);
              if (!bf_is_one (g, L))
                found = 1;
            }
        }
      if (bf_cmp (g, n, L) == 0)
        {
          /* The batch overshot: step again from its start, one gcd each. */
          do
            {
              if (bf_interrupted ()) goto out;
              bf_mont_mul (ys, ys, ys, &m);
              bf_mont_add (ys, ys, c, &m);
              bf_mont_sub (diff, x, ys, &m);
              memset (ga, 0, sz); memcpy (ga, diff, ks);
              memset (gb, 0, sz); memcpy (gb, n, ks);
              bf_gcd (g, ga, gb, L);
            }
          while (bf_is_one (g, L));
        }
      if (bf_cmp (g, n, L) != 0)
        {
          memcpy (f, g, sz);
          rc = 0;
          break;
        }
    }
out:
  free (x); free (y); free (ys); free (q); free (c); free (diff);
  free (ga); free (gb); free (g);
  bf_mont_free (&m);
  return rc;
}

/* --- 64-bit arithmetic ------------------------------------------------ */

static uint64_t
bf_mulmod64 (uint64_t a, uint64_t b, uint64_t n)
{
#if defined (__SIZEOF_INT128__)
  return (uint64_t) (((unsigned __int128) a * b) % n);
#else
  uint64_t r = 0;
  a %= n;
  while (b)
    {
      if (b & 1) r = r >= n - a ? r - (n - a) : r + a;
      a = a >= n - a ? a - (n - a) : a + a;
      b >>= 1;
    }
  return r;
#endif
}

static uint64_t
bf_powmod64 (uint64_t b, uint64_t e, uint64_t n)
{
  uint64_t r = 1 % n;
  b %= n;
  while (e)
    {
      if (e & 1) r = bf_mulmod64 (r, b, n);
      b = bf_mulmod64 (b, b, n);
      e >>= 1;
    }
  return r;
}

/* N odd, above BCU_FACTOR_TRIAL^2 or known to have no small factor. */
static int
bf_is_prime64 (uint64_t n)
{
  static const uint64_t bases[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
  uint64_t d = n - 1;
  int s = 0;
  while (!(d & 1)) { d >>= 1; s++; }
  for (size_t i = 0; i < sizeof bases / sizeof *bases; i++)
    {
      uint64_t a = bases[i] % n;
      if (a == 0) continue;
      uint64_t x = bf_powmod64 (a, d, n);
      if (x == 1 || x == n - 1) continue;
      int r;
      for (r = 1; r < s; r++)
        {
          x = bf_mulmod64 (x, x, n);
          if (x == n - 1) break;
        }
      if (r == s) return 0;
    }
  return 1;
}

static uint64_t
bf_gcd64 (uint64_t a, uint64_t b)
{
  while (b) { uint64_t t = a % b; a = b; b = t; }
  return a;
}

/* The rho iteration's product mod n. With 128-bit integers it is a
   Montgomery product (a b / 2^64 mod n): the map y -> y^2 / 2^64 + c is
   conjugate to y -> y^2 + c' modulo every prime factor, which is all rho
   needs, and gcd (q, n) is unchanged by the 2^64 factors. */
typedef struct {
  uint64_t n, ninv;
} bf_rho64_mod;

static uint64_t
bf_rho64_mul (uint64_t a, uint64_t b, const bf_rho64_mod *m)
{
#if defined (__SIZEOF_INT128__)
  unsigned __int128 t = (unsigned __int128) a * b;
  uint64_t lo = (uint64_t) t, hi = (uint64_t) (t >> 64);
  uint64_t q = lo * m->ninv;
  unsigned __int128 qn = (unsigned __int128) q * m->n;
  /* lo + low (qn) is 0 mod 2^64; it carries unless lo is 0. */
  uint64_t qhi = (uint64_t) (qn >> 64), carry = lo != 0;
  uint64_t r = hi + qhi;
  int over = r < hi;
  r += carry;
  over |= r < carry;
  if (over || r >= m->n)
    r -= m->n;
  return r;
#else
  return bf_mulmod64 (a, b, m->n);
#endif
}

/* y^2 + c mod n, for c < n. */
static uint64_t
bf_rho64_step (uint64_t y, uint64_t c, const bf_rho64_mod *m)
{
  uint64_t t = bf_rho64_mul (y, y, m);
  return t >= m->n - c ? t - (m->n - c) : t + c;
}

/* A nontrivial factor of the odd composite N, or 0 when interrupted. */
static uint64_t
bf_rho64 (uint64_t n)
{
  bf_rho64_mod m;
  uint64_t inv = n;                 /* Newton: 3, 6, 12, 24, 48, 96 bits */
  for (int i = 0; i < 5; i++)
    inv *= 2 - n * inv;
  m.n = n;
  m.ninv = 0 - inv;
  for (uint64_t c = 1;; c++)
    {
      uint64_t y = 2, x = 2, ys = 2, q = 1, g = 1;
      for (uint64_t r = 1; g == 1; r *= 2)
        {
          x = y;
          for (uint64_t i = 0; i < r; i++)
            y = bf_rho64_step (y, c, &m);
          for (uint64_t done = 0; done < r && g == 1; done += BCU_FACTOR_BATCH)
            {
              if (bf_interrupted ()) return 0;
              ys = y;
              uint64_t lim = r - done < BCU_FACTOR_BATCH ? r - done : BCU_FACTOR_BATCH;
              for (uint64_t i = 0; i < lim; i++)
                {
                  y = bf_rho64_step (y, c, &m);
                  q = bf_rho64_mul (q, x > y ? x - y : y - x, &m);
                }
              g = bf_gcd64 (q, n);
            }
        }
      if (g == n)
        do
          {
            ys = bf_rho64_step (ys, c, &m);
            g = bf_gcd64 (x > ys ? x - ys : ys - x, n);
          }
        while (g == 1);
      if (g != n)
        return g;
    }
}

/* --- the factor list -------------------------------------------------- */

typedef struct {
  size_t L;
  bf_limb **p;       /* each L limbs */
  size_t n, cap;
} bf_list;

static void
bf_list_add (bf_list *fl, const bf_limb *v)
{
  if (fl->n == fl->cap)
    {
      fl->cap = fl->cap ? fl->cap * 2 : 16;
      fl->p = xrealloc (fl->p, fl->cap * sizeof *fl->p);
    }
  fl->p[fl->n] = xmalloc (fl->L * sizeof (bf_limb));
  memcpy (fl->p[fl->n++], v, fl->L * sizeof (bf_limb));
}

static void
bf_list_add_u64 (bf_list *fl, uint64_t v)
{
  bf_limb *t = xmalloc (fl->L * sizeof *t);
  bf_set_u64 (t, fl->L, v);
  bf_list_add (fl, t);
  free (t);
}

static int
bf_factor64 (uint64_t n, bf_list *fl)
{
  if (n < 2) return 0;
  if (n < (uint64_t) BCU_FACTOR_TRIAL * BCU_FACTOR_TRIAL || bf_is_prime64 (n))
    {
      bf_list_add_u64 (fl, n);
      return 0;
    }
  uint64_t d = bf_rho64 (n);
  if (!d) return -1;
  return bf_factor64 (d, fl) < 0 ? -1 : bf_factor64 (n / d, fl);
}

/* N (L limbs, odd, no factor below BCU_FACTOR_TRIAL). */
static int
bf_factor_big (const bf_limb *n, bf_list *fl)
{
  size_t L = fl->L;
  if (bf_fits_u64 (n, L))
    return bf_factor64 (bf_get_u64 (n, L), fl);
  if (bf_is_prime (n, L))
    {
      bf_list_add (fl, n);
      return 0;
    }
  size_t sz = L * sizeof (bf_limb);
  bf_limb *d = xmalloc (sz), *co = xmalloc (sz), *t = xmalloc (sz);
  int rc;
  /* Rho needs about sqrt(p) steps for p^2 too; a square root is cheap. */
  if (bf_square_root (n, L, d))
    {
      rc = bf_factor_big (d, fl);
      if (rc == 0)
        rc = bf_factor_big (d, fl);
      free (d); free (co); free (t);
      return rc;
    }
  rc = bf_rho (d, n, L);
  if (rc == 0)
    {
      bf_div (co, n, d, t, L);
      rc = bf_factor_big (d, fl);
      if (rc == 0)
        rc = bf_factor_big (co, fl);
    }
  free (d); free (co); free (t);
  return rc;
}

/* The primes below BCU_FACTOR_TRIAL, sieved once. */
static uint16_t bf_primes[600];
static size_t bf_nprimes;

static void
bf_init_primes (void)
{
  static unsigned char sieve[BCU_FACTOR_TRIAL];
  if (bf_nprimes) return;
  for (unsigned i = 2; i < BCU_FACTOR_TRIAL; i++)
    {
      if (sieve[i]) continue;
      bf_primes[bf_nprimes++] = (uint16_t) i;
      for (unsigned j = i * i; j < BCU_FACTOR_TRIAL; j += i)
        sieve[j] = 1;
    }
}

/* Every prime factor of N (consumed) into FL, smallest first. */
static int
bf_factor (bf_limb *n, bf_list *fl)
{
  size_t L = fl->L;
  int rc = 0;
  bf_init_primes ();
  if (bf_fits_u64 (n, L))
    {
      uint64_t v = bf_get_u64 (n, L);
      if (v < 2)
        return 0;
      for (size_t i = 0; i < bf_nprimes; i++)
        {
          uint64_t p = bf_primes[i];
          if (p * p > v) break;
          while (v % p == 0)
            {
              v /= p;
              bf_list_add_u64 (fl, p);
            }
        }
      if (v > 1)
        rc = bf_factor64 (v, fl);
    }
  else
    {
      for (size_t i = 0; i < bf_nprimes; i++)
        {
          bf_limb p = bf_primes[i];
          while (bf_mod_1 (n, L, p) == 0)
            {
              bf_divmod_1 (n, L, p);
              bf_list_add_u64 (fl, p);
            }
        }
      if (!bf_is_one (n, L))
        rc = bf_factor_big (n, fl);
    }
  /* Insertion sort: the lists are short. */
  for (size_t i = 1; i < fl->n; i++)
    for (size_t j = i; j > 0 && bf_cmp (fl->p[j - 1], fl->p[j], L) > 0; j--)
      {
        bf_limb *t = fl->p[j]; fl->p[j] = fl->p[j - 1]; fl->p[j - 1] = t;
      }
  return rc;
}

/* Decimal digits of A (consumed) into a new string. */
static char *
bf_to_dec (bf_limb *a, size_t L)
{
  size_t cap = L * (BF_BITS == 64 ? 20 : 10) + 2, at = cap;
  char *buf = xmalloc (cap);
  buf[--at] = '\0';
  do
    {
      bf_limb r = bf_divmod_1 (a, L, 1000000000u);
      int last = bf_is_zero (a, L);
      for (int i = 0; i < 9 && (!last || r); i++)
        {
          buf[--at] = (char) ('0' + r % 10);
          r /= 10;
        }
    }
  while (!bf_is_zero (a, L));
  if (buf[at] == '\0')
    buf[--at] = '0';
  memmove (buf, buf + at, cap - at);
  return buf;
}

static char *
bf_dec (const bf_limb *a, size_t L)
{
  bf_limb *t = xmalloc (L * sizeof *t);
  memcpy (t, a, L * sizeof *t);
  char *s = bf_to_dec (t, L);
  free (t);
  return s;
}

static void
bcu_factor_bad (const char *tok)
{
  char *q = bos_quote (tok);
  fflush (stdout);
  fprintf (stderr, "factor: %s is not a valid positive integer\n", q ? q : tok);
  free (q);
}

/* Factor and print one token; 0, 1 for an invalid token, -1 when an
   interrupt stopped the work. GNU's syntax: leading spaces, an optional
   '+', then decimal digits and nothing else. */
static int
bcu_factor_one (const char *tok, int exponents)
{
  const char *p = tok;
  while (*p == ' ') p++;
  if (*p == '+') p++;
  const char *digits = p;
  while (*p >= '0' && *p <= '9') p++;
  if (p == digits || *p)
    {
      bcu_factor_bad (tok);
      return 1;
    }
  while (*digits == '0' && digits + 1 < p) digits++;
  size_t nd = (size_t) (p - digits);
  size_t L = nd / (BF_BITS == 64 ? 19 : 9) + 2;
  bf_limb *n = xmalloc (L * sizeof *n);
  memset (n, 0, L * sizeof *n);
  for (const char *c = digits; c < p; c++)
    bf_mul_1_add (n, L, 10, (bf_limb) (*c - '0'));

  char *ns = bf_dec (n, L);
  bf_list fl = { L, NULL, 0, 0 };
  int rc = bf_factor (n, &fl);
  if (rc == 0)
    {
      printf ("%s:", ns);
      for (size_t i = 0; i < fl.n;)
        {
          size_t j = i + 1;
          if (exponents)
            while (j < fl.n && bf_cmp (fl.p[i], fl.p[j], L) == 0) j++;
          char *f = bf_dec (fl.p[i], L);
          if (j - i > 1)
            printf (" %s^%zu", f, j - i);
          else
            printf (" %s", f);
          free (f);
          i = j;
        }
      putchar ('\n');
    }
  for (size_t i = 0; i < fl.n; i++) free (fl.p[i]);
  free (fl.p);
  free (ns);
  free (n);
  return rc;
}

static void
bcu_factor_try (void)
{
  fprintf (stderr, "Try 'factor --help' for more information.\n");
}

static int
bcu_factor_cmd (WORD_LIST *list)
{
  int exponents = 0, status = EXECUTION_SUCCESS, nops = 0, ended = 0;
  WORD_LIST *w;

  /* Options anywhere, as getopt_long permutes them; "--" ends them. */
  for (w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (ended || a[0] != '-' || a[1] == '\0')
        { nops++; continue; }
      if (strcmp (a, "--") == 0)
        { ended = 1; continue; }
      if (a[1] == '-')
        {
          const char *eq = strchr (a, '=');
          size_t len = eq ? (size_t) (eq - a) : strlen (a);
          static const char *const longs[] = { "--exponents", "--help", "--version" };
          int hit = -1;
          for (int i = 0; i < 3; i++)
            if (strncmp (longs[i], a, len) == 0)
              hit = i;          /* the three share no prefix past "--" */
          if (hit < 0)
            {
              fprintf (stderr, "factor: unrecognized option '%s'\n", a);
              bcu_factor_try ();
              return EXECUTION_FAILURE;
            }
          if (eq)
            {
              fprintf (stderr, "factor: option '%s' doesn't allow an argument\n", longs[hit]);
              bcu_factor_try ();
              return EXECUTION_FAILURE;
            }
          if (hit == 0)
            exponents = 1;
          else if (hit == 1)
            {
              printf ("Usage: factor [OPTION] [NUMBER]...\n"
                      "Print the prime factors of each specified integer NUMBER.  If none\n"
                      "are specified on the command line, read them from standard input.\n"
                      "\n"
                      "  -h, --exponents   print repeated factors in form p^e unless e is 1\n"
                      "      --help        display this help and exit\n"
                      "      --version     output version information and exit\n");
              return fflush (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
            }
          else
            {
              printf ("factor (bash-os) %s\n", dist_version);
              return fflush (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
            }
          continue;
        }
      for (const char *c = a + 1; *c; c++)
        {
          if (*c != 'h')
            {
              fprintf (stderr, "factor: invalid option -- '%c'\n", *c);
              bcu_factor_try ();
              return EXECUTION_FAILURE;
            }
          exponents = 1;
        }
    }

  bcu_factor_stop = 0;
  if (nops)
    {
      ended = 0;
      for (w = list; w; w = w->next)
        {
          const char *a = w->word->word;
          if (!ended && strcmp (a, "--") == 0) { ended = 1; continue; }
          if (!ended && a[0] == '-' && a[1]) continue;
          int r = bcu_factor_one (a, exponents);
          if (r < 0) break;
          if (r) status = EXECUTION_FAILURE;
        }
    }
  else
    {
      /* Tokens of standard input, split at spaces, tabs and newlines. */
      char *tok = NULL;
      size_t len = 0, cap = 0;
      int ch;
      for (;;)
        {
          ch = getchar ();
          if (ch == EOF || ch == ' ' || ch == '\t' || ch == '\n')
            {
              if (len)
                {
                  tok[len] = '\0';
                  len = 0;
                  int r = bcu_factor_one (tok, exponents);
                  if (r < 0) break;
                  if (r) status = EXECUTION_FAILURE;
                }
              if (ch == EOF) break;
              continue;
            }
          if (len + 2 > cap)
            {
              cap = cap ? cap * 2 : 64;
              tok = xrealloc (tok, cap);
            }
          tok[len++] = (char) ch;
        }
      free (tok);
      if (ferror (stdin))
        {
          fflush (stdout);
          fprintf (stderr, "factor: read error: %s\n", strerror (errno));
          status = EXECUTION_FAILURE;
        }
    }
  if (fflush (stdout) == EOF)
    status = EXECUTION_FAILURE;
  if (bcu_factor_stop)
    {
      bcu_factor_stop = 0;
      QUIT;
      return 130;
    }
  return status;
}

/* ===================================================================
 * yes — repeat STRING (default "y") forever, one per line.
 * =================================================================== */

static int
bcu_yes_cmd (WORD_LIST *list)
{
  /* Assemble the line once; loop tight on fwrite. SIGPIPE from
   * `yes | head -3` terminates us cleanly. */
  char *line = NULL;
  size_t llen = 0;
  if (!list)
    {
      line = bcu_strdup ("y\n");
      llen = 2;
    }
  else
    {
      size_t total = 0;
      for (WORD_LIST *w = list; w; w = w->next)
        total += strlen (w->word->word) + 1;
      line = xmalloc (total + 1);
      if (!line) { builtin_error ("oom"); return EXECUTION_FAILURE; }
      char *p = line;
      for (WORD_LIST *w = list; w; w = w->next)
        {
          size_t n = strlen (w->word->word);
          memcpy (p, w->word->word, n); p += n;
          *p++ = w->next ? ' ' : '\n';
        }
      *p = '\0';
      llen = (size_t) (p - line);
    }
  while (fwrite (line, 1, llen, stdout) == llen)
    ;
  free (line);
  return EXECUTION_FAILURE;
}

/* ===================================================================
 * fmt — refill paragraphs.
 *
 * Written for bash-os from the coreutils manual and from measurements of
 * coreutils 9.7 output (no GNU source was consulted). Model:
 *
 *   Lines. A line holding only blanks is printed empty and ends the
 *   paragraph. With -p, a line is a text line only when its leading
 *   blanks reach the prefix's own leading blanks, the prefix's visible
 *   part follows and the text then starts no earlier than the prefix's
 *   trailing blanks would end; a line that is just the prefix (plus
 *   blanks) prints as lead + prefix. Any other line is copied as is
 *   apart from its leading blanks, which are rebuilt like indentation.
 *   Columns expand tabs to multiples of 8.
 *
 *   Paragraphs. Consecutive text lines with the same lead column join
 *   when their text columns agree: all equal by default; with -c the
 *   second line may differ from the first and the rest follow the
 *   second; -t is -c where the second line must differ (a lone tagged
 *   line wraps to the previous paragraph's second-line column, or when
 *   that equals its own, to column 3, or 0 if it was indented). -s never
 *   joins. Each FILE is formatted separately.
 *
 *   Words. Space, tab and newline separate words. A word ending in . ? or
 *   ! (closing ) ] " ' ignored) ends a sentence when two or more columns
 *   or the end of the line follow it, and the last word of a paragraph
 *   always does. Between words the input spacing is kept (in columns);
 *   a line end becomes one space, two after a sentence end; -u always
 *   uses one, or two after a sentence end.
 *
 *   Breaking. Lines stay within WIDTH - 1 columns unless a single word is
 *   longer, and aim at GOAL (default WIDTH * 187 / 200). The break points
 *   minimise, from the end of the paragraph backwards, for each line but
 *   the last: (GOAL - length)^2 + 49, half the squared difference from the
 *   following line's length unless that one is the last, and a cost for
 *   the break: -25 after a sentence end, +3600 after any other word ending
 *   in . ? or !, -16 after other punctuation, +400/(length+2) after the
 *   first word of a sentence; then -16 before a word opening with ( [ " '
 *   or `, otherwise +225/(length+2) before the last word of a sentence.
 *   Ties go to the shorter line. A paragraph is refilled in windows of
 *   about 5000 bytes of words: each full window prints all but its last
 *   line, which starts the next window.
 *
 *   Output. Lead, prefix and indentation are rebuilt in columns; once any
 *   line read so far held a tab, runs of blanks that reach a tab stop at
 *   least two columns away use tabs.
 * =================================================================== */

#define BCU_FMT_WINDOW 5000
#define BCU_FMT_MAXWORDS 1000

typedef struct
{
  size_t off, len;      /* bytes in the paragraph arena */
  long gap;             /* columns after the word when not at a line end */
  int final, endp, at_eol;
} bcu_fmt_word;

typedef struct
{
  /* options */
  long width, goal;
  int crown, tagged, split, uniform;
  int has_prefix;
  const char *core;     /* visible part of the prefix */
  size_t core_len;
  long pre_lead;        /* columns of the prefix's leading blanks */
  long pre_trail;       /* columns of its trailing blanks */
  /* state */
  int tabs;
  BCU_OUTPUT *out;
  /* paragraph */
  int open;             /* a paragraph is being collected */
  int lines;            /* text lines in it */
  int first_done;       /* its first output line has been printed */
  long last_other;      /* other indentation of the previous paragraph */
  long lead, tc1, tc2;  /* lead column, first and other text columns */
  char *arena;
  size_t alen, acap;
  bcu_fmt_word *w;
  size_t nw, wcap;
  size_t wbytes;
} bcu_fmt_ctx;

static long
bcu_fmt_advance (long col, unsigned char ch)
{
  return ch == '\t' ? (col / 8 + 1) * 8 : col + 1;
}

static void
bcu_fmt_space (bcu_fmt_ctx *f, long col, long target)
{
  if (target <= col)
    return;
  if (f->tabs)
    {
      long stop = target / 8 * 8;
      if (stop - col >= 2)
        while (col < stop)
          {
            bcu_output_append (f->out, "\t", 1);
            col = (col / 8 + 1) * 8;
          }
    }
  while (col < target)
    {
      bcu_output_append (f->out, " ", 1);
      col++;
    }
}

/* Lead, prefix and indentation of an output line; returns the column. */
static long
bcu_fmt_head (bcu_fmt_ctx *f, long tc)
{
  long col = 0;
  if (f->has_prefix)
    {
      bcu_fmt_space (f, 0, f->lead);
      bcu_output_append (f->out, f->core, f->core_len);
      col = f->lead;
      for (size_t i = 0; i < f->core_len; i++)
        col = bcu_fmt_advance (col, (unsigned char) f->core[i]);
    }
  bcu_fmt_space (f, col, tc);
  return tc > col ? tc : col;
}

/* Costs are integers in hundredths so that equal choices tie exactly. */
#define BCU_FMT_UNIT 100

static long long
bcu_fmt_break_cost (const bcu_fmt_ctx *f, size_t i)
{
  const bcu_fmt_word *a = &f->w[i], *b = &f->w[i + 1];
  unsigned char last = (unsigned char) f->arena[a->off + a->len - 1];
  unsigned char next = (unsigned char) f->arena[b->off];
  long long c = 0;
  if (a->final)
    c -= 25 * BCU_FMT_UNIT;
  else if (a->endp)
    c += 3600 * BCU_FMT_UNIT;
  else if (ispunct (last))
    c -= 16 * BCU_FMT_UNIT;
  else if (i > 0 && f->w[i - 1].final)
    c += 400 * BCU_FMT_UNIT / (long long) (a->len + 2);
  if (next == '(' || next == '[' || next == '"' || next == '\'' || next == '`')
    c -= 16 * BCU_FMT_UNIT;
  else if (b->final)
    c += 225 * BCU_FMT_UNIT / (long long) (b->len + 2);
  return c;
}

static long
bcu_fmt_spacing (const bcu_fmt_ctx *f, const bcu_fmt_word *x)
{
  if (f->uniform || x->at_eol)
    return x->final ? 2 : 1;
  return x->gap;
}

/* Print the lines chosen for words [0, n); with KEEP_LAST the words of
   the final line stay in the paragraph. */
static void
bcu_fmt_emit (bcu_fmt_ctx *f, size_t n, int keep_last)
{
  if (!n)
    return;
  int saved_final = f->w[n - 1].final;
  f->w[n - 1].final = 1;
  long maxl = f->width - 1, goal = f->goal;
  long long *best = xmalloc ((n + 1) * sizeof *best);
  size_t *next = xmalloc ((n + 1) * sizeof *next);
  long *flen = xmalloc ((n + 1) * sizeof *flen);
  long long *bk = xmalloc ((n ? n : 1) * sizeof *bk);
  for (size_t i = 0; i + 1 < n; i++)
    bk[i] = bcu_fmt_break_cost (f, i);
  best[n] = 0;
  next[n] = n;
  flen[n] = 0;
  for (size_t a = n; a-- > 0;)
    {
      long len = (a == 0 && !f->first_done ? f->tc1 : f->tc2) + (long) f->w[a].len;
      long long bc = 0;
      size_t bb = n;
      long bl = len;
      int have = 0;
      for (size_t b = a + 1; b <= n; b++)
        {
          if (b > a + 1)
            len += bcu_fmt_spacing (f, &f->w[b - 2]) + (long) f->w[b - 1].len;
          if (len > maxl && b > a + 1)
            break;
          long long c;
          if (b == n)
            c = 0;
          else
            {
              long long d = goal - len;
              c = (d * d + 49) * BCU_FMT_UNIT + best[b] + bk[b - 1];
              if (next[b] != n)
                {
                  long long r = len - flen[b];
                  c += r * r * BCU_FMT_UNIT / 2;
                }
            }
          if (!have || c < bc)
            {
              have = 1;
              bc = c;
              bb = b;
              bl = len;
            }
        }
      best[a] = bc;
      next[a] = bb;
      flen[a] = bl;
    }

  size_t a = 0;
  while (a < n)
    {
      size_t b = next[a];
      if (keep_last && b == n)
        break;
      long col = bcu_fmt_head (f, f->first_done ? f->tc2 : f->tc1);
      for (size_t j = a; j < b; j++)
        {
          bcu_output_append (f->out, f->arena + f->w[j].off, f->w[j].len);
          col += (long) f->w[j].len;
          if (j + 1 < b)
            {
              long s = bcu_fmt_spacing (f, &f->w[j]);
              bcu_fmt_space (f, col, col + s);
              col += s;
            }
        }
      bcu_output_append (f->out, "\n", 1);
      f->first_done = 1;
      a = b;
    }
  free (best);
  free (next);
  free (flen);
  free (bk);
  f->w[n - 1].final = saved_final;

  /* Keep words [a, n) for the next window. */
  if (a && a < n)
    {
      size_t base = f->w[a].off, bytes = 0;
      memmove (f->arena, f->arena + base, f->alen - base);
      f->alen -= base;
      for (size_t j = a; j < n; j++)
        {
          f->w[j - a] = f->w[j];
          f->w[j - a].off -= base;
          bytes += f->w[j].len;
        }
      f->nw = n - a;
      f->wbytes = bytes;
    }
  else if (a >= n)
    {
      f->nw = 0;
      f->alen = 0;
      f->wbytes = 0;
    }
}

static void
bcu_fmt_flush (bcu_fmt_ctx *f)
{
  if (!f->open)
    return;
  if (f->lines == 1 && !f->split)
    {
      /* No second line decided the other indentation. */
      if (f->tagged)
        {
          long min = 0;
          if (f->has_prefix)
            {
              min = f->lead;
              for (size_t i = 0; i < f->core_len; i++)
                min = bcu_fmt_advance (min, (unsigned char) f->core[i]);
            }
          f->tc2 = f->last_other;
          if (f->tc2 == f->tc1)
            f->tc2 = f->tc1 == 0 ? 3 : 0;
          if (f->tc2 < min)
            f->tc2 = min;
        }
      else
        f->tc2 = f->tc1;
    }
  bcu_fmt_emit (f, f->nw, 0);
  f->last_other = f->tc2;
  f->open = 0;
  f->nw = f->alen = f->wbytes = 0;
}

/* Add the words of a text line starting at byte P, column COL. */
static void
bcu_fmt_add_words (bcu_fmt_ctx *f, const char *s, size_t len, size_t p, long col)
{
  while (p < len)
    {
      size_t start = p;
      long scol = col;
      while (p < len && s[p] != ' ' && s[p] != '\t')
        {
          p++;
          col++;
        }
      size_t wl = p - start;
      long ecol = col;
      while (p < len && (s[p] == ' ' || s[p] == '\t'))
        col = bcu_fmt_advance (col, (unsigned char) s[p++]);
      (void) scol;
      if (f->nw == f->wcap)
        {
          f->wcap = f->wcap ? f->wcap * 2 : 256;
          f->w = xrealloc (f->w, f->wcap * sizeof *f->w);
        }
      if (f->alen + wl > f->acap)
        {
          while (f->alen + wl > f->acap)
            f->acap = f->acap ? f->acap * 2 : 4096;
          f->arena = xrealloc (f->arena, f->acap);
        }
      memcpy (f->arena + f->alen, s + start, wl);
      bcu_fmt_word *x = &f->w[f->nw++];
      x->off = f->alen;
      x->len = wl;
      f->alen += wl;
      f->wbytes += wl;
      x->at_eol = p >= len;
      x->gap = col - ecol;
      size_t k = wl;
      while (k && strchr (")]\"'", s[start + k - 1]))
        k--;
      x->endp = k && (s[start + k - 1] == '.' || s[start + k - 1] == '?'
                      || s[start + k - 1] == '!');
      x->final = x->endp && (x->at_eol || x->gap >= 2);
    }
}

static void
bcu_fmt_line (bcu_fmt_ctx *f, const char *s, size_t len, int nl)
{
  if (memchr (s, '\t', len))
    f->tabs = 1;

  size_t p = 0;
  long col = 0;
  while (p < len && (s[p] == ' ' || s[p] == '\t'))
    col = bcu_fmt_advance (col, (unsigned char) s[p++]);
  if (p == len)
    {
      bcu_fmt_flush (f);
      bcu_output_append (f->out, "\n", 1);
      return;
    }

  long lead = 0, tc = col;
  if (f->has_prefix)
    {
      lead = col;
      size_t skip = p;
      int ok = lead >= f->pre_lead && len - p >= f->core_len
               && !memcmp (s + p, f->core, f->core_len);
      long after = 0;
      if (ok)
        {
          p += f->core_len;
          col = lead;
          for (size_t i = 0; i < f->core_len; i++)
            col = bcu_fmt_advance (col, (unsigned char) f->core[i]);
          after = col;
          while (p < len && (s[p] == ' ' || s[p] == '\t'))
            col = bcu_fmt_advance (col, (unsigned char) s[p++]);
          if (p == len)
            {
              bcu_fmt_flush (f);
              bcu_fmt_space (f, 0, lead);
              bcu_output_append (f->out, f->core, f->core_len);
              bcu_output_append (f->out, "\n", 1);
              return;
            }
          ok = col - after >= f->pre_trail;
        }
      if (!ok)
        {
          /* Not for refilling: the indentation is rebuilt, the rest is
             copied. */
          bcu_fmt_flush (f);
          bcu_fmt_space (f, 0, lead);
          bcu_output_append (f->out, s + skip, len - skip);
          if (nl)
            bcu_output_append (f->out, "\n", 1);
          return;
        }
      tc = col;
    }

  int join = 0;
  if (f->open && !f->split && lead == f->lead)
    {
      if (f->lines == 1 && (f->crown || f->tagged))
        join = !f->tagged || tc != f->tc1;
      else if (f->lines == 1)
        join = tc == f->tc1;
      else
        join = tc == f->tc2;
    }
  if (!join)
    {
      bcu_fmt_flush (f);
      f->open = 1;
      f->lines = 0;
      f->first_done = 0;
      f->lead = lead;
      f->tc1 = f->tc2 = tc;
    }
  else if (f->lines == 1)
    f->tc2 = tc;
  f->lines++;
  bcu_fmt_add_words (f, s, len, p, col);

  if (f->wbytes >= BCU_FMT_WINDOW || f->nw >= BCU_FMT_MAXWORDS)
    {
      if (f->lines == 1 && !f->split)
        {
          f->tc2 = f->tc1;
          if (f->tagged)
            {
              f->tc2 = f->last_other;
              if (f->tc2 == f->tc1)
                f->tc2 = f->tc1 == 0 ? 3 : 0;
            }
        }
      bcu_fmt_emit (f, f->nw, 1);
    }
}

/* Width as fmt reads it: blanks and '+' allowed, decimal, at most MAX. */
static int
bcu_fmt_width (const char *arg, long max, long *out)
{
  uintmax_t v;
  int r = bcu_parse_uint (arg, &v);
  if (r == 0)
    {
      char *q = bcu_quote (arg);
      bcu_err ("fmt", "invalid width: %s", q);
      free (q);
      return 0;
    }
  if (r < 0 || (max >= 0 && v > (uintmax_t) max) || v > LONG_MAX / 4)
    {
      char *q = bcu_quote (arg);
      bcu_err ("fmt", "invalid width: %s: %s", q,
               strerror (max >= 0 ? ERANGE : EOVERFLOW));
      free (q);
      return 0;
    }
  *out = (long) v;
  return 1;
}

static void
bcu_fmt_usage (void)
{
  fputs ("Usage: fmt [-WIDTH] [OPTION]... [FILE]...\n"
         "Refill the paragraphs of each FILE and write them to standard output.\n"
         "A leading -WIDTH is short for --width=WIDTH.\n"
         "\n"
         "With no FILE, or when FILE is -, read standard input.\n"
         "\n"
         "  -c, --crown-margin        keep the indentation of the first two lines\n"
         "  -p, --prefix=STRING       refill only lines starting with STRING and put\n"
         "                              STRING back in front of the refilled lines\n"
         "  -s, --split-only          break long lines without joining short ones\n"
         "  -t, --tagged-paragraph    the first line is indented unlike the second\n"
         "  -u, --uniform-spacing     one space between words, two after sentences\n"
         "  -w, --width=WIDTH         widest line allowed (75 columns by default)\n"
         "  -g, --goal=WIDTH          preferred line width (93% of the width by default)\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n",
         stdout);
}

static int
bcu_fmt_cmd (WORD_LIST *list)
{
  static const struct bcu_lopt longopts[] = {
    { "crown-margin",     BCU_NOARG,  'c' },
    { "prefix",           BCU_REQARG, 'p' },
    { "split-only",       BCU_NOARG,  's' },
    { "tagged-paragraph", BCU_NOARG,  't' },
    { "uniform-spacing",  BCU_NOARG,  'u' },
    { "width",            BCU_REQARG, 'w' },
    { "goal",             BCU_REQARG, 'g' },
    { "help",             BCU_NOARG,  BCU_OPT_HELP },
    { "version",          BCU_NOARG,  BCU_OPT_VERSION },
    { NULL, 0, 0 }
  };
  bcu_fmt_ctx f;
  memset (&f, 0, sizeof f);
  int have_w = 0, have_g = 0, rc = EXECUTION_SUCCESS;
  const char *goal_arg = NULL, *prefix = NULL;
  long width = 75, goal = 0;

  if (list && list->word->word[0] == '-'
      && list->word->word[1] >= '0' && list->word->word[1] <= '9')
    {
      if (!bcu_fmt_width (list->word->word + 1, 2500, &width))
        return EXECUTION_FAILURE;
      have_w = 1;
      list = list->next;
    }

  bcu_opts o;
  int c;
  bcu_opts_init (&o, "fmt", "0123456789cp:stuw:g:", longopts, list);
  while ((c = bcu_opts_next (&o)) != -1)
    switch (c)
      {
      case 'c': f.crown = 1; break;
      case 's': f.split = 1; break;
      case 't': f.tagged = 1; break;
      case 'u': f.uniform = 1; break;
      case 'p': prefix = o.optarg; break;
      case 'w':
        if (!bcu_fmt_width (o.optarg, 2500, &width))
          goto fail;
        have_w = 1;
        break;
      case 'g':
        if (!bcu_fmt_width (o.optarg, -1, &goal))
          goto fail;
        goal_arg = o.optarg;
        have_g = 1;
        break;
      case BCU_OPT_HELP:
        bcu_fmt_usage ();
        bcu_opts_free (&o);
        return EXECUTION_SUCCESS;
      case BCU_OPT_VERSION:
        puts ("fmt (bash-os coreutils)");
        bcu_opts_free (&o);
        return EXECUTION_SUCCESS;
      default:
        if (c >= '0' && c <= '9')
          {
            fflush (stdout);
            fprintf (stderr, "fmt: invalid option -- %c; -WIDTH is recognized only when it is the first\n"
                     "option; use -w N instead\n", c);
            bcu_try_help ("fmt");
          }
        goto fail;
      }

  if (have_g)
    {
      if (goal > width)
        {
          char *q = bcu_quote (goal_arg);
          bcu_err ("fmt", "invalid width: %s: %s", q, strerror (EOVERFLOW));
          free (q);
          goto fail;
        }
      if (!have_w)
        width = goal + 10;
    }
  else
    goal = width * 187 / 200;
  f.width = width;
  f.goal = goal;

  if (prefix)
    {
      const char *s = prefix, *e;
      long col = 0;
      while (*s == ' ' || *s == '\t')
        col = bcu_fmt_advance (col, (unsigned char) *s++);
      e = s + strlen (s);
      while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
        e--;
      f.pre_lead = col;
      f.core = s;
      f.core_len = (size_t) (e - s);
      long cc = 0, tc = 0;
      for (const char *t = s; t < e; t++)
        cc = bcu_fmt_advance (cc, (unsigned char) *t);
      tc = cc;
      for (const char *t = e; *t; t++)
        tc = bcu_fmt_advance (tc, (unsigned char) *t);
      f.pre_trail = tc - cc;
      f.has_prefix = col > 0 || f.core_len > 0;
    }

  BCU_OUTPUT out;
  out.used = 0;
  out.failed = 0;
  f.out = &out;

  char *dash[] = { (char *) "-", NULL };
  char **files = o.nops ? o.ops : dash;
  int nfiles = o.nops ? o.nops : 1;
  char *buf = NULL;
  size_t cap = 0;
  for (int i = 0; i < nfiles; i++)
    {
      const char *name = files[i];
      int fd = 0;
      if (strcmp (name, "-"))
        {
          fd = open (name, O_RDONLY | O_CLOEXEC);
          if (fd < 0)
            {
              int e = errno;
              char *q = bcu_shell_quote (name);
              int quoted = q[0] == '\'' || q[0] == '"' || !strncmp (q, "$'", 2);
              bcu_output_flush (&out);
              bcu_err ("fmt", quoted ? "cannot open %s for reading: %s"
                                     : "cannot open '%s' for reading: %s",
                       q, strerror (e));
              free (q);
              rc = EXECUTION_FAILURE;
              continue;
            }
        }
      size_t used = 0, start = 0;
      int eof = 0, err = 0;
      for (;;)
        {
          char *nlp = used > start ? memchr (buf + start, '\n', used - start)
                                   : NULL;
          if (!nlp && !eof)
            {
              if (start)
                {
                  memmove (buf, buf + start, used - start);
                  used -= start;
                  start = 0;
                }
              if (used == cap)
                {
                  cap = cap ? cap * 2 : 65536;
                  buf = xrealloc (buf, cap);
                }
              ssize_t n = read (fd, buf + used, cap - used);
              if (n < 0 && errno == EINTR)
                continue;
              if (n < 0)
                {
                  err = 1;
                  eof = 1;
                }
              else if (n == 0)
                eof = 1;
              else
                used += (size_t) n;
              continue;
            }
          if (!nlp && start == used)
            break;
          size_t end = nlp ? (size_t) (nlp - buf) : used;
          bcu_fmt_line (&f, buf + start, end - start, nlp != NULL);
          start = nlp ? end + 1 : used;
        }
      bcu_fmt_flush (&f);
      if (fd)
        close (fd);
      if (err)
        {
          bcu_output_flush (&out);
          bcu_err ("fmt", "read error");
          rc = EXECUTION_FAILURE;
        }
    }
  bcu_output_flush (&out);
  if (out.failed)
    rc = EXECUTION_FAILURE;
  free (buf);
  free (f.arena);
  free (f.w);
  bcu_opts_free (&o);
  return rc;

fail:
  bcu_opts_free (&o);
  return EXECUTION_FAILURE;
}

/* ===================================================================
 * tsort — topological sort of whitespace-separated pairs ("A B" is an
 *         edge A -> B; "A A" only names A). Tokens are separated by
 *         space, tab and newline.
 *
 * Order, as observed from coreutils 9.7: the items with no
 * predecessor go first in byte order; then breadth first, each item
 * releasing its successors newest edge first. When every remaining item
 * waits on another there is a loop: "tsort: FILE: input contains a
 * loop:" and its members, one "tsort: ITEM" line each, go to stderr,
 * one edge of the loop is dropped, sorting resumes and the status
 * becomes 1. The loop reported is found by following, from the first
 * remaining item in byte order, each item's chosen predecessor: the
 * first one in byte order that sorts after the item itself, otherwise
 * the first one. The members print in edge order, starting at the
 * loop's entry when the walk started on the loop and ending there
 * otherwise; the dropped edge is the one into the first member printed.
 * An odd number of tokens is "input contains an odd number of tokens"
 * with no output and status 1.
 * =================================================================== */

typedef struct
{
  const char *name;
  size_t first_edge;    /* newest outgoing edge, or SIZE_MAX */
  size_t count;         /* live incoming edges */
  size_t rank;          /* position in byte order */
  int done;
} bcu_tnode;

typedef struct
{
  size_t to, next;
  int dead;
} bcu_tedge;

typedef struct
{
  bcu_tnode *nodes;
  size_t n, cap;
  bcu_tedge *edges;
  size_t ne, ecap;
  size_t *table;        /* hash slots: node index + 1, 0 when empty */
  size_t tcap;
} bcu_tgraph;

static size_t
bcu_tsort_hash (const char *s)
{
  size_t h = 1469598103934665603ULL & SIZE_MAX;
  for (; *s; s++)
    h = (h ^ (unsigned char) *s) * (1099511628211ULL & SIZE_MAX);
  return h;
}

static size_t
bcu_tsort_node (bcu_tgraph *g, const char *name)
{
  if ((g->n + 1) * 2 > g->tcap)
    {
      free (g->table);
      g->tcap = g->tcap ? g->tcap * 2 : 1024;
      g->table = bcu_calloc (g->tcap, sizeof *g->table);
      for (size_t i = 0; i < g->n; i++)
        {
          size_t h = bcu_tsort_hash (g->nodes[i].name) & (g->tcap - 1);
          while (g->table[h])
            h = (h + 1) & (g->tcap - 1);
          g->table[h] = i + 1;
        }
    }
  size_t h = bcu_tsort_hash (name) & (g->tcap - 1);
  while (g->table[h])
    {
      if (!strcmp (g->nodes[g->table[h] - 1].name, name))
        return g->table[h] - 1;
      h = (h + 1) & (g->tcap - 1);
    }
  if (g->n == g->cap)
    {
      g->cap = g->cap ? g->cap * 2 : 256;
      g->nodes = xrealloc (g->nodes, g->cap * sizeof *g->nodes);
    }
  bcu_tnode *t = &g->nodes[g->n];
  t->name = name;
  t->first_edge = SIZE_MAX;
  t->count = 0;
  t->rank = 0;
  t->done = 0;
  g->table[h] = g->n + 1;
  return g->n++;
}

static const bcu_tnode *bcu_tsort_sort_base;

static int
bcu_tsort_cmp (const void *a, const void *b)
{
  return strcmp (bcu_tsort_sort_base[*(const size_t *) a].name,
                 bcu_tsort_sort_base[*(const size_t *) b].name);
}

static void
bcu_tsort_usage (void)
{
  fputs ("Usage: tsort [OPTION] [FILE]\n"
         "Print the items of FILE, read as pairs \"BEFORE AFTER\", in an order that\n"
         "puts every BEFORE ahead of its AFTER.\n"
         "\n"
         "With no FILE, or when FILE is -, read standard input.\n"
         "\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n",
         stdout);
}

static int
bcu_tsort_cmd (WORD_LIST *list)
{
  static const struct bcu_lopt longopts[] = {
    { "help",    BCU_NOARG, BCU_OPT_HELP },
    { "version", BCU_NOARG, BCU_OPT_VERSION },
    { NULL, 0, 0 }
  };
  bcu_opts o;
  int c, rc = EXECUTION_FAILURE;
  bcu_opts_init (&o, "tsort", "", longopts, list);
  while ((c = bcu_opts_next (&o)) != -1)
    {
      if (c == BCU_OPT_HELP)
        {
          bcu_tsort_usage ();
          bcu_opts_free (&o);
          return EXECUTION_SUCCESS;
        }
      if (c == BCU_OPT_VERSION)
        {
          puts ("tsort (bash-os coreutils)");
          bcu_opts_free (&o);
          return EXECUTION_SUCCESS;
        }
      bcu_opts_free (&o);
      return EXECUTION_FAILURE;
    }
  if (o.nops > 1)
    {
      char *q = bcu_quote (o.ops[1]);
      bcu_err ("tsort", "extra operand %s", q);
      free (q);
      bcu_try_help ("tsort");
      bcu_opts_free (&o);
      return EXECUTION_FAILURE;
    }
  const char *file = o.nops ? o.ops[0] : "-";
  char *qfile = bcu_quotef (file);
  bcu_opts_free (&o);

  int fd = 0;
  if (strcmp (file, "-"))
    {
      fd = open (file, O_RDONLY | O_CLOEXEC);
      if (fd < 0)
        {
          bcu_err ("tsort", "%s: %s", qfile, strerror (errno));
          free (qfile);
          return EXECUTION_FAILURE;
        }
    }
  char *buf = NULL;
  ssize_t len = bcu_tac_slurp (fd, &buf);
  int e = errno;
  if (fd)
    close (fd);
  if (len < 0)
    {
      bcu_err ("tsort", "%s: read error: %s", qfile, strerror (e));
      free (qfile);
      return EXECUTION_FAILURE;
    }
  buf = xrealloc (buf, (size_t) len + 1);
  buf[len] = '\0';

  bcu_tgraph g;
  memset (&g, 0, sizeof g);
  size_t pending = SIZE_MAX, ntok = 0;
  for (size_t at = 0; at < (size_t) len;)
    {
      char ch = buf[at];
      if (ch == ' ' || ch == '\t' || ch == '\n')
        {
          at++;
          continue;
        }
      size_t start = at;
      while (at < (size_t) len && buf[at] != ' ' && buf[at] != '\t' && buf[at] != '\n')
        at++;
      buf[at++] = '\0';
      size_t k = bcu_tsort_node (&g, buf + start);
      ntok++;
      if (pending == SIZE_MAX)
        {
          pending = k;
          continue;
        }
      if (pending != k)
        {
          if (g.ne == g.ecap)
            {
              g.ecap = g.ecap ? g.ecap * 2 : 256;
              g.edges = xrealloc (g.edges, g.ecap * sizeof *g.edges);
            }
          g.edges[g.ne].to = k;
          g.edges[g.ne].next = g.nodes[pending].first_edge;
          g.edges[g.ne].dead = 0;
          g.nodes[pending].first_edge = g.ne++;
          g.nodes[k].count++;
        }
      pending = SIZE_MAX;
    }
  if (ntok % 2)
    {
      bcu_err ("tsort", "%s: input contains an odd number of tokens", qfile);
      goto done;
    }

  size_t n = g.n;
  size_t *order = xmalloc ((n ? n : 1) * sizeof *order);
  size_t *queue = xmalloc ((n ? n : 1) * sizeof *queue);
  size_t *link = xmalloc ((n ? n : 1) * sizeof *link);
  size_t *above = xmalloc ((n ? n : 1) * sizeof *above);
  size_t *seen = xmalloc ((n ? n : 1) * sizeof *seen);
  size_t *path = xmalloc ((n ? n : 1) * sizeof *path);
  for (size_t i = 0; i < n; i++)
    order[i] = i;
  bcu_tsort_sort_base = g.nodes;
  qsort (order, n, sizeof *order, bcu_tsort_cmp);
  for (size_t i = 0; i < n; i++)
    g.nodes[order[i]].rank = i;

  size_t head = 0, tail = 0, left = n, first = 0;
  rc = EXECUTION_SUCCESS;
  for (size_t i = 0; i < n; i++)
    if (!g.nodes[order[i]].count)
      queue[tail++] = order[i];
  for (;;)
    {
      while (head < tail)
        {
          bcu_tnode *t = &g.nodes[queue[head++]];
          t->done = 1;
          left--;
          fputs (t->name, stdout);
          putchar ('\n');
          for (size_t ed = t->first_edge; ed != SIZE_MAX; ed = g.edges[ed].next)
            if (!g.edges[ed].dead && !--g.nodes[g.edges[ed].to].count)
              queue[tail++] = g.edges[ed].to;
        }
      if (!left)
        break;

      /* Every remaining item has a predecessor: choose one for each. */
      for (size_t i = 0; i < n; i++)
        link[i] = above[i] = SIZE_MAX;
      for (size_t r = 0; r < n; r++)
        {
          size_t k = order[r];
          if (g.nodes[k].done)
            continue;
          for (size_t ed = g.nodes[k].first_edge; ed != SIZE_MAX; ed = g.edges[ed].next)
            {
              size_t j = g.edges[ed].to;
              if (g.edges[ed].dead || g.nodes[j].done)
                continue;
              if (link[j] == SIZE_MAX)
                link[j] = k;
              if (above[j] == SIZE_MAX && r > g.nodes[j].rank)
                above[j] = k;
            }
        }
      while (g.nodes[order[first]].done)
        first++;
      size_t start = order[first], cur = start, steps = 0;
      for (size_t i = 0; i < n; i++)
        seen[i] = SIZE_MAX;
      while (seen[cur] == SIZE_MAX)
        {
          seen[cur] = steps;
          path[steps++] = cur;
          cur = above[cur] != SIZE_MAX ? above[cur] : link[cur];
        }
      size_t from = seen[cur], members = steps - from;
      /* Members in edge order into the reused LINK array. */
      size_t *loop = link;
      if (cur == start)
        {
          loop[0] = cur;
          for (size_t i = 1; i < members; i++)
            loop[i] = path[steps - i];
        }
      else
        for (size_t i = 0; i < members; i++)
          loop[i] = path[steps - 1 - i];
      fflush (stdout);
      fprintf (stderr, "tsort: %s: input contains a loop:\n", qfile);
      for (size_t i = 0; i < members; i++)
        fprintf (stderr, "tsort: %s\n", g.nodes[loop[i]].name);
      fflush (stderr);
      rc = EXECUTION_FAILURE;

      /* Drop the edge from the last member printed into the first. */
      size_t into = loop[0], src = loop[members - 1];
      for (size_t ed = g.nodes[src].first_edge; ed != SIZE_MAX; ed = g.edges[ed].next)
        if (!g.edges[ed].dead && g.edges[ed].to == into)
          {
            g.edges[ed].dead = 1;
            if (!--g.nodes[into].count)
              queue[tail++] = into;
            break;
          }
    }
  free (order);
  free (queue);
  free (link);
  free (above);
  free (seen);
  free (path);

done:
  free (g.nodes);
  free (g.edges);
  free (g.table);
  free (buf);
  free (qfile);
  return rc;
}

/* ===================================================================
 * printf — coreutils printf: `coreutils printf FORMAT [ARGUMENT]...`.
 *
 * This is the external printf that env, nice, nohup, xargs and find run
 * (common/command-run.h routes an enabled printf here), so it follows
 * coreutils rather than Bash's builtin: there is no -v, %q quotes as
 * `ls --quoting-style=shell-escape` does ('a b'), "--" is skipped only
 * as the first argument, --help/--version only as the sole argument.
 * FORMAT is reused while arguments remain; missing arguments read as ""
 * or 0. %b expands escapes in its argument, \c stops all output.
 * Numeric arguments take a leading ' or " for a character's value and
 * C's base prefixes; bad ones are diagnosed, printed as far as they
 * converted, and make the status 1. A bad directive or escape is fatal.
 * %N$ picks argument N of the current round. Written from the coreutils
 * manual, POSIX and observed coreutils 9.7 behaviour.
 * =================================================================== */

typedef struct
{
  char **argv;          /* arguments of the current round */
  int argc;
  int seq;              /* next sequential argument */
  int maxpos;           /* highest %N$ used */
  int status;
  int stop;             /* \c seen: no more output at all */
  int fatal;            /* fatal diagnostic printed */
} bcu_pf;

static void
bcu_pf_fatal (bcu_pf *p, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
static void
bcu_pf_fatal (bcu_pf *p, const char *fmt, ...)
{
  va_list ap;
  fflush (stdout);
  fputs ("printf: ", stderr);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fputc ('\n', stderr);
  p->fatal = 1;
  p->status = EXECUTION_FAILURE;
}

/* Write code point CP for a \u or \U escape: the locale's encoding of
   it, or the escape itself (\uXXXX, \UXXXXXXXX) when the locale cannot
   represent it. Surrogates are an error. */
static void
bcu_pf_unicode (bcu_pf *p, unsigned long cp, char letter, const char *digits, int ndigits)
{
  if (cp >= 0xD800 && cp <= 0xDFFF)
    {
      bcu_pf_fatal (p, "invalid universal character name \\%c%.*s", letter, ndigits, digits);
      return;
    }
  if (cp < 0x80)
    {
      putchar ((int) cp);
      return;
    }
  if (cp <= 0x10FFFF)
    {
      char mb[MB_LEN_MAX];
      mbstate_t st;
      memset (&st, 0, sizeof st);
      size_t n = wcrtomb (mb, (wchar_t) cp, &st);
      if (n != (size_t) -1)
        {
          fwrite (mb, 1, n, stdout);
          return;
        }
    }
  if (cp <= 0xFFFF)
    printf ("\\u%04lX", cp);
  else
    printf ("\\U%08lX", cp);
}

/* Interpret the escape at S (just after the backslash); returns the
   number of characters used. In %b arguments (BARG) octal is \0NNN or
   \NNN; in the format it is \NNN. */
static size_t
bcu_pf_escape (bcu_pf *p, const char *s, int barg)
{
  const char *start = s;
  int c = (unsigned char) *s;
  switch (c)
    {
    case '\\': putchar ('\\'); return 1;
    case '"':  putchar ('"'); return 1;
    case 'a':  putchar ('\a'); return 1;
    case 'b':  putchar ('\b'); return 1;
    case 'e':  putchar (0x1b); return 1;
    case 'f':  putchar ('\f'); return 1;
    case 'n':  putchar ('\n'); return 1;
    case 'r':  putchar ('\r'); return 1;
    case 't':  putchar ('\t'); return 1;
    case 'v':  putchar ('\v'); return 1;
    case 'c':  p->stop = 1; return 1;
    case 'x':
      {
        unsigned v = 0;
        int n = 0;
        for (s++; n < 2 && isxdigit ((unsigned char) *s); s++, n++)
          v = v * 16 + (unsigned) (isdigit ((unsigned char) *s) ? *s - '0'
                                   : (tolower ((unsigned char) *s) - 'a' + 10));
        if (!n)
          {
            bcu_pf_fatal (p, "missing hexadecimal number in escape");
            return (size_t) (s - start);
          }
        putchar ((int) v);
        return (size_t) (s - start);
      }
    case 'u':
    case 'U':
      {
        int want = c == 'u' ? 4 : 8, n = 0;
        unsigned long v = 0;
        const char *digits = s + 1;
        for (s++; n < want && isxdigit ((unsigned char) *s); s++, n++)
          v = v * 16 + (unsigned long) (isdigit ((unsigned char) *s) ? *s - '0'
                                        : (tolower ((unsigned char) *s) - 'a' + 10));
        if (n < want)
          {
            bcu_pf_fatal (p, "missing hexadecimal number in escape");
            return (size_t) (s - start);
          }
        bcu_pf_unicode (p, v, (char) c, digits, want);
        return (size_t) (s - start);
      }
    default:
      break;
    }
  if (c >= '0' && c <= '7' && (!barg || c != '0'))
    {
      unsigned v = 0;
      int n = 0;
      for (; n < 3 && *s >= '0' && *s <= '7'; s++, n++)
        v = v * 8 + (unsigned) (*s - '0');
      putchar ((int) (v & 0xff));
      return (size_t) (s - start);
    }
  if (barg && c == '0')
    {
      unsigned v = 0;
      int n = 0;
      for (s++; n < 3 && *s >= '0' && *s <= '7'; s++, n++)
        v = v * 8 + (unsigned) (*s - '0');
      putchar ((int) (v & 0xff));
      return (size_t) (s - start);
    }
  /* Unknown escape, or a backslash at the end: both print as written. */
  putchar ('\\');
  if (c)
    {
      putchar (c);
      return 1;
    }
  return 0;
}

/* %b: ARG with escapes expanded. */
static void
bcu_pf_bstring (bcu_pf *p, const char *arg)
{
  while (*arg && !p->stop && !p->fatal)
    {
      if (*arg == '\\')
        arg += 1 + bcu_pf_escape (p, arg + 1, 1);
      else
        putchar (*arg++);
    }
}

/* Argument for %N$ (POS > 0) or the next sequential one; NULL when the
   round has no such argument. */
static const char *
bcu_pf_arg (bcu_pf *p, int pos)
{
  if (pos > 0)
    {
      if (pos > p->maxpos)
        p->maxpos = pos;
      return pos <= p->argc ? p->argv[pos - 1] : NULL;
    }
  p->seq++;
  return p->seq <= p->argc ? p->argv[p->seq - 1] : NULL;
}

static void
bcu_pf_numeric_error (bcu_pf *p, const char *arg, const char *msg)
{
  char *q = bcu_quote (arg);
  fflush (stdout);
  fprintf (stderr, "printf: %s: %s\n", q, msg);
  free (q);
  p->status = EXECUTION_FAILURE;
}

/* A leading ' or " gives the value of the following character (a
   multibyte one in its locale's encoding, else the byte); text after it
   is ignored with a warning. Returns 1 when ARG had that form. */
static int
bcu_pf_charconst (bcu_pf *p, const char *arg, uintmax_t *v)
{
  if ((arg[0] != '\'' && arg[0] != '"') || !arg[1])
    return 0;
  const char *s = arg + 1;
  size_t len = strlen (s), n = 1;
  mbstate_t st;
  wchar_t wc;
  memset (&st, 0, sizeof st);
  size_t r = mbrtowc (&wc, s, len, &st);
  if (r != (size_t) -1 && r != (size_t) -2 && r > 0 && (unsigned char) *s >= 0x80)
    {
      *v = (uintmax_t) wc;
      n = r;
    }
  else
    *v = (unsigned char) *s;
  if (s[n])
    {
      fflush (stdout);
      fprintf (stderr, "printf: warning: %s: character(s) following character constant have been ignored\n", s + n);
    }
  return 1;
}

/* Check a converted number: diagnose it (not fatally) as coreutils does. */
static void
bcu_pf_check (bcu_pf *p, const char *arg, const char *end, int err)
{
  if (end == arg)
    bcu_pf_numeric_error (p, arg, "expected a numeric value");
  else if (err == ERANGE)
    bcu_pf_numeric_error (p, arg, strerror (ERANGE));
  else if (*end)
    bcu_pf_numeric_error (p, arg, "value not completely converted");
}

static intmax_t
bcu_pf_signed (bcu_pf *p, const char *arg)
{
  uintmax_t c;
  if (!arg)
    return 0;
  if (bcu_pf_charconst (p, arg, &c))
    return (intmax_t) c;
  char *end;
  errno = 0;
  intmax_t v = strtoimax (arg, &end, 0);
  bcu_pf_check (p, arg, end, errno);
  return v;
}

static uintmax_t
bcu_pf_unsigned (bcu_pf *p, const char *arg)
{
  uintmax_t c;
  if (!arg)
    return 0;
  if (bcu_pf_charconst (p, arg, &c))
    return c;
  char *end;
  errno = 0;
  uintmax_t v = strtoumax (arg, &end, 0);
  bcu_pf_check (p, arg, end, errno);
  return v;
}

static long double
bcu_pf_float (bcu_pf *p, const char *arg)
{
  uintmax_t c;
  if (!arg)
    return 0;
  if (bcu_pf_charconst (p, arg, &c))
    return (long double) c;
  char *end;
  errno = 0;
  long double v = strtold (arg, &end);
  bcu_pf_check (p, arg, end, errno);
  return v;
}

/* Pad TEXT[0..LEN) to WIDTH bytes (negative: none), left-justified with
   MINUS; PREC (>= 0) first truncates it. */
static void
bcu_pf_pad (const char *text, size_t len, int minus, long width, long prec)
{
  if (prec >= 0 && (size_t) prec < len)
    len = (size_t) prec;
  size_t pad = width > 0 && (size_t) width > len ? (size_t) width - len : 0;
  if (!minus)
    for (; pad; pad--)
      putchar (' ');
  fwrite (text, 1, len, stdout);
  for (; pad; pad--)
    putchar (' ');
}

/* Width or precision taken from an argument ('*'). Returns 0 after a
   fatal diagnostic. */
static int
bcu_pf_star (bcu_pf *p, int pos, int is_width, long *out)
{
  const char *arg = bcu_pf_arg (p, pos);
  intmax_t v = bcu_pf_signed (p, arg);
  if (is_width ? (v < -INT_MAX || v > INT_MAX) : v > INT_MAX)
    {
      char *q = bcu_quote (arg ? arg : "");
      bcu_pf_fatal (p, "invalid %s: %s", is_width ? "field width" : "precision", q);
      free (q);
      return 0;
    }
  *out = v < INT_MIN ? -1 : (long) v;
  return 1;
}

/* Read "N$" at *S; returns N (> 0), 0 when absent, -1 when it is "0$". */
static int
bcu_pf_position (const char **s)
{
  const char *t = *s;
  long n = 0;
  if (*t < '0' || *t > '9')
    return 0;
  for (; *t >= '0' && *t <= '9'; t++)
    n = n < INT_MAX / 10 ? n * 10 + (*t - '0') : INT_MAX;
  if (*t != '$')
    return 0;
  *s = t + 1;
  return n ? (int) n : -1;
}

/* One directive at FMT (the '%'); returns the characters consumed. */
static size_t
bcu_pf_directive (bcu_pf *p, const char *fmt)
{
  const char *s = fmt + 1;
  if (*s == '%')
    {
      putchar ('%');
      return 2;
    }
  int pos = bcu_pf_position (&s);
  if (pos < 0)
    goto invalid;
  char flags[16];
  int nflags = 0, minus = 0, have_width = 0, have_prec = 0, have_len = 0;
  int width_star = 0, prec_star = 0, width_pos = 0, prec_pos = 0, width_over = 0;
  long width = -1, prec = -1;
  static const char flagchars[] = "-+ #0'I";
  unsigned seen = 0;    /* bit per flag: - + space # 0 ' I */
  for (;; s++)
    {
      const char *f = *s ? strchr (flagchars, *s) : NULL;
      if (!f)
        break;
      seen |= 1u << (f - flagchars);
      if (*s == '-')
        minus = 1;
      if (nflags < (int) sizeof flags - 1)
        flags[nflags++] = *s;
    }
  flags[nflags] = '\0';
  if (*s == '*')
    {
      have_width = width_star = 1;
      s++;
      width_pos = bcu_pf_position (&s);
      if (width_pos < 0)
        goto invalid;
    }
  else if (*s >= '0' && *s <= '9')
    {
      have_width = 1;
      width = 0;
      for (; *s >= '0' && *s <= '9'; s++)
        {
          if (width > (INT_MAX - (*s - '0')) / 10)
            width_over = 1;
          else
            width = width * 10 + (*s - '0');
        }
    }
  if (*s == '.')
    {
      have_prec = 1;
      s++;
      if (*s == '*')
        {
          prec_star = 1;
          s++;
          prec_pos = bcu_pf_position (&s);
          if (prec_pos < 0)
            goto invalid;
        }
      else
        {
          int over = 0;
          prec = 0;
          for (; *s >= '0' && *s <= '9'; s++)
            {
              if (prec > (INT_MAX - (*s - '0')) / 10)
                over = 1;
              else
                prec = prec * 10 + (*s - '0');
            }
          if (over)
            prec = -1;
        }
    }
  while (*s && strchr ("hlLjzt", *s))
    {
      have_len = 1;
      s++;
    }
  if (!*s)
    goto invalid;
  int conv = (unsigned char) *s++;
  /* Which flags each conversion takes, as coreutils accepts them:
     bit order - + space # 0 ' I. */
  unsigned allowed;
  int w_ok = 1, p_ok = 1, l_ok = 1;
  switch (conv)
    {
    case 's':                     allowed = 0x07; break;
    case 'c':                     allowed = 0x07; p_ok = 0; break;
    case 'b': case 'q':           allowed = 0; w_ok = p_ok = l_ok = 0; break;
    case 'd': case 'i': case 'u': allowed = 0x77; break;
    case 'o': case 'x': case 'X': allowed = 0x1f; break;
    case 'f': case 'F': case 'g': case 'G': allowed = 0x7f; break;
    case 'e': case 'E': case 'a': case 'A': allowed = 0x1f; break;
    default: goto invalid;
    }
  if ((seen & ~allowed) || (have_width && !w_ok) || (have_prec && !p_ok)
      || (have_len && !l_ok))
    goto invalid;

  if (width_star && !bcu_pf_star (p, width_pos, 1, &width))
    return (size_t) (s - fmt);
  if (width_star && width < 0)
    {
      minus = 1;
      width = -width;
    }
  if (prec_star && !bcu_pf_star (p, prec_pos, 0, &prec))
    return (size_t) (s - fmt);
  if (width_over)
    {
      bcu_pf_fatal (p, "write error");
      return (size_t) (s - fmt);
    }

  const char *arg = bcu_pf_arg (p, pos);
  char spec[48];
  int k = 0;
  spec[k++] = '%';
  for (const char *f = flags; *f; f++)
    if (k < 20)
      spec[k++] = *f;
  if (minus && !strchr (flags, '-'))
    spec[k++] = '-';
  if (width >= 0 || width_star)
    k += snprintf (spec + k, sizeof spec - (size_t) k, "%ld", width < 0 ? 0 : width);
  if (prec >= 0)
    k += snprintf (spec + k, sizeof spec - (size_t) k, ".%ld", prec);
  switch (conv)
    {
    case 'd': case 'i':
      {
        intmax_t v = bcu_pf_signed (p, arg);
        snprintf (spec + k, sizeof spec - (size_t) k, "j%c", conv);
        printf (spec, v);
        break;
      }
    case 'o': case 'u': case 'x': case 'X':
      {
        uintmax_t v = bcu_pf_unsigned (p, arg);
        snprintf (spec + k, sizeof spec - (size_t) k, "j%c", conv);
        printf (spec, v);
        break;
      }
    case 'f': case 'F': case 'g': case 'G': case 'e': case 'E': case 'a': case 'A':
      {
        long double v = bcu_pf_float (p, arg);
        snprintf (spec + k, sizeof spec - (size_t) k, "L%c", conv);
        printf (spec, v);
        break;
      }
    case 'c':
      {
        char ch = arg ? arg[0] : '\0';
        bcu_pf_pad (&ch, 1, minus, width, -1);
        break;
      }
    case 's':
      bcu_pf_pad (arg ? arg : "", arg ? strlen (arg) : 0, minus, width, prec);
      break;
    case 'b':
      if (arg)
        bcu_pf_bstring (p, arg);
      break;
    case 'q':
      {
        char *q = bcu_shell_quote (arg ? arg : "");
        fputs (q, stdout);
        free (q);
        break;
      }
    }
  return (size_t) (s - fmt);

invalid:
  bcu_pf_fatal (p, "%.*s: invalid conversion specification", (int) (s - fmt), fmt);
  return (size_t) (s - fmt);
}

static void
bcu_printf_usage (void)
{
  fputs ("Usage: printf FORMAT [ARGUMENT]...\n"
         "  or:  printf OPTION\n"
         "Print ARGUMENT(s) under control of FORMAT, reusing FORMAT while\n"
         "arguments remain.\n"
         "\n"
         "      --help     display this help and exit\n"
         "      --version  output version information and exit\n"
         "\n"
         "FORMAT is printed as written except for these escapes:\n"
         "  \\\"  \\\\  \\a  \\b  \\c (no further output)  \\e  \\f  \\n  \\r  \\t  \\v\n"
         "  \\NNN (octal byte, 1 to 3 digits)  \\xHH (hexadecimal byte, 1 or 2 digits)\n"
         "  \\uHHHH  \\UHHHHHHHH (Unicode character)\n"
         "and directives as in C printf (d i o u x X f F e E g G a A c s), plus:\n"
         "  %%      a percent sign\n"
         "  %b      ARGUMENT with backslash escapes expanded (octal is \\0NNN)\n"
         "  %q      ARGUMENT quoted for reuse as shell input\n"
         "A numeric ARGUMENT may be a character with a leading ' or \"; its value\n"
         "is that character's code.\n",
         stdout);
}

static int
bcu_printf_cmd (WORD_LIST *list)
{
  if (list && !list->next)
    {
      if (!strcmp (list->word->word, "--help"))
        {
          bcu_printf_usage ();
          return EXECUTION_SUCCESS;
        }
      if (!strcmp (list->word->word, "--version"))
        {
          puts ("printf (bash-os coreutils)");
          return EXECUTION_SUCCESS;
        }
    }
  if (list && !strcmp (list->word->word, "--"))
    list = list->next;
  if (!list)
    {
      bcu_err ("printf", "missing operand");
      bcu_try_help ("printf");
      return EXECUTION_FAILURE;
    }
  const char *format = list->word->word;
  int argc = 0;
  for (WORD_LIST *w = list->next; w; w = w->next)
    argc++;
  char **argv = xmalloc ((size_t) (argc + 1) * sizeof *argv);
  argc = 0;
  for (WORD_LIST *w = list->next; w; w = w->next)
    argv[argc++] = w->word->word;
  argv[argc] = NULL;

  bcu_pf p;
  memset (&p, 0, sizeof p);
  int done = 0;
  for (;;)
    {
      p.argv = argv + done;
      p.argc = argc - done;
      p.seq = p.maxpos = 0;
      for (const char *f = format; *f && !p.stop && !p.fatal;)
        {
          if (*f == '%')
            f += bcu_pf_directive (&p, f);
          else if (*f == '\\')
            f += 1 + bcu_pf_escape (&p, f + 1, 0);
          else
            putchar (*f++);
        }
      if (p.stop || p.fatal)
        break;
      int used = p.seq > p.maxpos ? p.seq : p.maxpos;
      if (used > p.argc)
        used = p.argc;
      done += used;
      if (done >= argc)
        break;
      if (!used)
        {
          char *q = bcu_quote (argv[done]);
          fflush (stdout);
          fprintf (stderr, "printf: warning: ignoring excess arguments, starting with %s\n", q);
          free (q);
          break;
        }
    }
  free (argv);
  return p.status;
}

/* ===================================================================
 * nproc — processors available to this process; --all is every configured one
 * =================================================================== */

/* Count the current affinity mask; zero requests a sysconf fallback. */
static unsigned long
bcu_nproc_available (void)
{
  cpu_set_t set;
  if (sched_getaffinity (0, sizeof set, &set) != 0) return 0;
  return CPU_COUNT (&set);
}

/* OpenMP permits surrounding whitespace and lists of nesting levels.
   Only the first level affects nproc. Invalid/zero values are ignored;
   strtoul saturation matches GNU for values larger than ULONG_MAX. */
static unsigned long
bcu_nproc_omp (const char *value)
{
  if (!value) return 0;
  while (isspace ((unsigned char) *value)) value++;
  if (*value < '0' || *value > '9') return 0;
  char *end;
  unsigned long n = strtoul (value, &end, 10);
  while (isspace ((unsigned char) *end)) end++;
  return !*end || *end == ',' ? n : 0;
}

static int
bcu_nproc_cmd (WORD_LIST *list)
{
  unsigned long ignore = 0;
  int use_all = 0;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word, *value = NULL;
      if (!strcmp (a, "--all")) { use_all = 1; continue; }
      if (!strcmp (a, "--") && !w->next) break;
      if (!strncmp (a, "--ignore=", 9)) value = a + 9;
      else if (!strcmp (a, "--ignore") && w->next)
        { w = w->next; value = w->word->word; }
      if (value)
        {
          while (isspace ((unsigned char) *value)) value++;
          char *end;
          errno = 0;
          ignore = strtoul (value, &end, 10);
          if (*value && *value != '-' && end != value && !*end)
            continue;
          builtin_error ("nproc: invalid number: %s", value);
          return EXECUTION_FAILURE;
        }
      builtin_error ("nproc: unknown flag: %s", a);
      bcu_usage ("nproc");
      return EX_USAGE;
    }
  unsigned long n = 0, limit = ULONG_MAX;
  if (!use_all)
    {
      n = bcu_nproc_omp (getenv ("OMP_NUM_THREADS"));
      unsigned long v = bcu_nproc_omp (getenv ("OMP_THREAD_LIMIT"));
      if (v) limit = v;
      if (!n) n = bcu_nproc_available ();
    }
  if (!n)
    {
      long configured = sysconf (use_all ? _SC_NPROCESSORS_CONF : _SC_NPROCESSORS_ONLN);
      n = configured > 0 ? (unsigned long) configured : 1;
    }
  if (n > limit) n = limit;
  n = ignore < n ? n - ignore : 1;
  printf ("%lu\n", n);
  return EXECUTION_SUCCESS;
}

/* ===================================================================
 * numfmt — reformat numbers to and from human-readable scales.
 *
 * The GNU numfmt(1) surface: --from/--to (none, auto, si, iec, iec-i),
 * --from-unit/--to-unit, --round, --suffix, --padding, --grouping,
 * --format, --field, -d/--delimiter, --header[=N], --invalid, -z and
 * --debug (accepted; no extra warnings). Operands and stdin lines are
 * split into fields; only the selected fields (default 1) are converted.
 * Conversion errors exit 2, stopping at the first one unless --invalid
 * selects fail/warn/ignore; option errors exit 1.
 * =================================================================== */

extern char *this_command_name;

typedef enum { BCU_SCALE_NONE, BCU_SCALE_AUTO, BCU_SCALE_SI, BCU_SCALE_IEC, BCU_SCALE_IEC_I } bcu_scale_t;
typedef enum { BCU_ROUND_UP, BCU_ROUND_DOWN, BCU_ROUND_FROM_ZERO, BCU_ROUND_TO_ZERO, BCU_ROUND_NEAREST } bcu_round_t;
typedef enum { BCU_INVAL_ABORT, BCU_INVAL_FAIL, BCU_INVAL_WARN, BCU_INVAL_IGNORE } bcu_inval_t;
typedef enum { BCU_NF_OK, BCU_NF_OVERFLOW, BCU_NF_INVALID, BCU_NF_FORBIDDEN,
               BCU_NF_BAD_SUFFIX, BCU_NF_MISSING_I, BCU_NF_TRAILING } bcu_nf_err;

/* Digits a long double prints without loss (LDBL_DIG), and 999Q. */
#define BCU_NF_UNSCALED_DIGITS 18
#define BCU_NF_MAX_DIGITS      33

typedef struct { uintmax_t lo, hi; } bcu_nf_range;

typedef struct {
  bcu_scale_t from, to;
  bcu_round_t round;
  bcu_inval_t inval;
  const char *suffix;
  uintmax_t from_unit, to_unit;
  int grouping;
  intmax_t padding;          /* >0 right-align, <0 left-align, 0 none */
  int zero_width;            /* width of a %0Nf format */
  long precision;            /* precision of a %.Nf format, or -1 */
  char *fmt_prefix, *fmt_suffix;
  int auto_padding;
  int delimiter;             /* -1: blanks separate fields */
  int line_delim;
  bcu_nf_range *fields;      /* NULL: only field 1 */
  size_t nfields;
  const char *radix;
  size_t radix_len;
  int stop;                  /* an abort-mode conversion error was reported */
} bcu_numfmt_t;

static const char *const bcu_nf_from_names[] = { "none", "auto", "si", "iec", "iec-i", NULL };
static const bcu_scale_t bcu_nf_from_types[] = { BCU_SCALE_NONE, BCU_SCALE_AUTO, BCU_SCALE_SI, BCU_SCALE_IEC, BCU_SCALE_IEC_I };
static const char *const bcu_nf_to_names[] = { "none", "si", "iec", "iec-i", NULL };
static const bcu_scale_t bcu_nf_to_types[] = { BCU_SCALE_NONE, BCU_SCALE_SI, BCU_SCALE_IEC, BCU_SCALE_IEC_I };
static const char *const bcu_nf_round_names[] = { "up", "down", "from-zero", "towards-zero", "nearest", NULL };
static const char *const bcu_nf_inval_names[] = { "abort", "fail", "warn", "ignore", NULL };

static int
bcu_nf_try (void)
{
  fprintf (stderr, "Try 'numfmt --help' for more information.\n");
  return EXECUTION_FAILURE;
}

/* An exact name or a unique abbreviation, as GNU argmatch accepts. */
static int
bcu_nf_argmatch (const char *opt, const char *arg, const char *const *names)
{
  size_t len = strlen (arg);
  int found = -1, ambiguous = 0;
  for (int i = 0; names[i]; i++)
    {
      if (strcmp (names[i], arg) == 0)
        return i;
      if (len && strncmp (names[i], arg, len) == 0)
        {
          if (found >= 0) ambiguous = 1;
          else found = i;
        }
    }
  if (found >= 0 && !ambiguous)
    return found;
  char *q = bos_quote (arg);
  builtin_error ("%s argument %s for '%s'", ambiguous ? "ambiguous" : "invalid",
                 q ? q : arg, opt);
  free (q);
  fprintf (stderr, "Valid arguments are:\n");
  for (int i = 0; names[i]; i++)
    {
      q = bos_quote (names[i]);
      fprintf (stderr, "  - %s\n", q ? q : names[i]);
      free (q);
    }
  bcu_nf_try ();
  return -1;
}

static void
bcu_nf_error_quoted (const char *fmt, const char *arg)
{
  char *q = bos_quote (arg);
  builtin_error (fmt, q ? q : arg);
  free (q);
}

static long double
bcu_nf_abs (long double v)
{
  return v < 0 ? -v : v;
}

static long double
bcu_nf_pow (long double base, long n)
{
  long double r = 1;
  while (n-- > 0) r *= base;
  return r;
}

/* Round to an integer without libm. Magnitudes this large already have
   no fractional bits worth keeping in a long double. */
static long double
bcu_nf_round (long double v, bcu_round_t mode)
{
  if (v >= 9.2e18L || v <= -9.2e18L)
    return v;
  intmax_t i = (intmax_t) v;              /* truncates towards zero */
  switch (mode)
    {
    case BCU_ROUND_UP:        if ((long double) i < v) i++; break;
    case BCU_ROUND_DOWN:      if ((long double) i > v) i--; break;
    case BCU_ROUND_FROM_ZERO:
      if (v < 0 && (long double) i > v) i--;
      else if (v > 0 && (long double) i < v) i++;
      break;
    case BCU_ROUND_TO_ZERO:   break;
    case BCU_ROUND_NEAREST:   i = (intmax_t) (v < 0 ? v - 0.5L : v + 0.5L); break;
    }
  return (long double) i;
}

/* --from-unit/--to-unit: N, NK (K=1000) or NKi (Ki=1024), nonzero. */
static int
bcu_nf_unit_size (const char *s, uintmax_t *out)
{
  const char *units = "KMGTPEZYRQ";
  char *end = NULL;
  uintmax_t n = 0;
  if (!isdigit ((unsigned char) *s)) goto bad;
  errno = 0;
  n = strtoumax (s, &end, 10);
  if (errno) goto bad;
  if (*end)
    {
      char unit = *end == 'k' ? 'K' : *end;
      const char *pos = strchr (units, unit);
      if (!pos) goto bad;
      int power = (int) (pos - units) + 1;
      uintmax_t base = 1000;
      end++;
      if (*end == 'i') { base = 1024; end++; }
      if (*end) goto bad;
      while (power--)
        {
          if (n > UINTMAX_MAX / base) goto bad;
          n *= base;
        }
    }
  if (n == 0) goto bad;
  *out = n;
  return 0;
bad:
  bcu_nf_error_quoted ("invalid unit size: %s", s);
  return -1;
}

static int
bcu_nf_add_range (bcu_numfmt_t *nf, uintmax_t lo, uintmax_t hi)
{
  bcu_nf_range *grown = realloc (nf->fields, (nf->nfields + 1) * sizeof *grown);
  if (!grown) { builtin_error ("out of memory"); return -1; }
  nf->fields = grown;
  nf->fields[nf->nfields].lo = lo;
  nf->fields[nf->nfields].hi = hi;
  nf->nfields++;
  return 0;
}

/* cut(1)-style field list: N, N-, N-M, -M and a lone '-', separated by
   commas or blanks. */
static int
bcu_nf_parse_fields (bcu_numfmt_t *nf, const char *spec)
{
  const char *p = strcmp (spec, "-") == 0 ? "1-" : spec;
  for (;;)
    {
      uintmax_t lo = 0, hi = 0;
      int have_lo = 0, have_hi = 0, dash = 0;
      while (isdigit ((unsigned char) *p))
        {
          if (lo > (UINTMAX_MAX - 1) / 10) goto too_large;
          lo = lo * 10 + (uintmax_t) (*p++ - '0');
          have_lo = 1;
        }
      if (*p == '-')
        {
          dash = 1;
          p++;
          if (have_lo && lo == 0) goto from_one;
          while (isdigit ((unsigned char) *p))
            {
              if (hi > (UINTMAX_MAX - 1) / 10) goto too_large;
              hi = hi * 10 + (uintmax_t) (*p++ - '0');
              have_hi = 1;
            }
          if (*p == '-')
            {
              builtin_error ("invalid field range");
              return bcu_nf_try ();
            }
        }
      if (*p && *p != ',' && !isblank ((unsigned char) *p))
        {
          bcu_nf_error_quoted ("invalid field value %s", p);
          return bcu_nf_try ();
        }
      if (dash)
        {
          uintmax_t first = have_lo ? lo : 1;
          if (!have_hi)
            hi = UINTMAX_MAX;
          else if (hi < first)
            {
              builtin_error ("invalid decreasing range");
              return bcu_nf_try ();
            }
          if (bcu_nf_add_range (nf, first, hi) < 0) return EXECUTION_FAILURE;
        }
      else
        {
          if (lo == 0) goto from_one;
          if (bcu_nf_add_range (nf, lo, lo) < 0) return EXECUTION_FAILURE;
        }
      if (!*p) break;
      p++;
    }
  return EXECUTION_SUCCESS;
from_one:
  builtin_error ("fields are numbered from 1");
  return bcu_nf_try ();
too_large:
  builtin_error ("field number is too large");
  return bcu_nf_try ();
}

/* --format: one %[0]['][-][N][.N]f directive, with literal text around
   it. As in GNU numfmt, the prefix keeps the first bytes of the text,
   one per character or %% pair, and both sides are printed verbatim. */
static int
bcu_nf_parse_format (bcu_numfmt_t *nf, const char *fmt)
{
  size_t i = 0, prefix_len = 0;
  char *q;
  while (!(fmt[i] == '%' && fmt[i + 1] != '%'))
    {
      if (!fmt[i])
        {
          q = bos_quote (fmt);
          builtin_error ("format %s has no %% directive", q ? q : fmt);
          free (q);
          return EXECUTION_FAILURE;
        }
      prefix_len++;
      i += (fmt[i] == '%') + 1;
    }
  i++;
  int zero = 0;
  for (;;)
    {
      size_t skip = strspn (fmt + i, " ");
      i += skip;
      if (fmt[i] == '\'') { nf->grouping = 1; i++; }
      else if (fmt[i] == '0') { zero = 1; i++; }
      else if (!skip) break;
    }
  char *end = NULL;
  errno = 0;
  intmax_t pad = strtoimax (fmt + i, &end, 10);
  if (pad < 0)
    nf->padding = pad;
  else if (pad > 0)
    {
      if (zero) nf->zero_width = pad > INT_MAX ? INT_MAX : (int) pad;
      else nf->padding = pad;
    }
  i = (size_t) (end - fmt);
  if (!fmt[i])
    {
      q = bos_quote (fmt);
      builtin_error ("format %s ends in %%", q ? q : fmt);
      free (q);
      return EXECUTION_FAILURE;
    }
  if (fmt[i] == '.')
    {
      i++;
      errno = 0;
      long prec = strtol (fmt + i, &end, 10);
      if (errno == ERANGE || prec < 0 || isblank ((unsigned char) fmt[i]) || fmt[i] == '+')
        {
          q = bos_quote (fmt);
          builtin_error ("invalid precision in format %s", q ? q : fmt);
          free (q);
          return EXECUTION_FAILURE;
        }
      nf->precision = prec;
      i = (size_t) (end - fmt);
    }
  if (fmt[i] != 'f')
    {
      q = bos_quote (fmt);
      builtin_error ("invalid format %s, directive must be %%[0]['][-][N][.][N]f", q ? q : fmt);
      free (q);
      return EXECUTION_FAILURE;
    }
  i++;
  size_t suffix_pos = i;
  for (; fmt[i]; i += (fmt[i] == '%') + 1)
    if (fmt[i] == '%' && fmt[i + 1] != '%')
      {
        q = bos_quote (fmt);
        builtin_error ("format %s has too many %% directives", q ? q : fmt);
        free (q);
        return EXECUTION_FAILURE;
      }
  if (prefix_len)
    {
      nf->fmt_prefix = bcu_calloc (1, prefix_len + 1);
      memcpy (nf->fmt_prefix, fmt, prefix_len);
    }
  if (fmt[suffix_pos])
    nf->fmt_suffix = bcu_strdup (fmt + suffix_pos);
  return EXECUTION_SUCCESS;
}

/* Parse [-]DIGITS[.DIGITS][blanks][SUFFIX[i]]. PRECISION is the number of
   fraction digits, or 0 once a scale suffix was applied. */
static bcu_nf_err
bcu_nf_parse_number (const bcu_numfmt_t *nf, const char *s, long double *out,
                     size_t *precision, const char **rest)
{
  const char *p = s;
  long double v = 0;
  int negative = 0, digits = 0, any = 0;
  *precision = 0;
  *rest = s;
  if (*p == '-') { negative = 1; p++; }
  for (; isdigit ((unsigned char) *p); p++)
    {
      int d = *p - '0';
      any = 1;
      if (v != 0 || d) digits++;
      if (digits > BCU_NF_MAX_DIGITS) return BCU_NF_OVERFLOW;
      v = v * 10 + d;
    }
  int radix = strncmp (p, nf->radix, nf->radix_len) == 0;
  if (!any && !radix) return BCU_NF_INVALID;
  if (radix)
    {
      p += nf->radix_len;
      const char *start = p;
      long double frac = 0;
      int fdigits = 0;
      for (; isdigit ((unsigned char) *p); p++)
        {
          int d = *p - '0';
          if (frac != 0 || d) fdigits++;
          if (fdigits > BCU_NF_MAX_DIGITS) return BCU_NF_OVERFLOW;
          frac = frac * 10 + d;
        }
      if (p == start) return BCU_NF_INVALID;
      *precision = (size_t) (p - start);
      v += frac / bcu_nf_pow (10, (long) *precision);
    }
  if (negative) v = -v;
  if (*p)
    {
      while (isblank ((unsigned char) *p)) p++;
      if (*p && !strchr ("KkMGTPEZYRQ", *p)) return BCU_NF_BAD_SUFFIX;
      if (nf->from == BCU_SCALE_NONE) return BCU_NF_FORBIDDEN;
      if (!*p)
        {
          /* Blanks after the number but no suffix letter. */
          *rest = p;
          return BCU_NF_TRAILING;
        }
      long power = (long) (strchr ("KMGTPEZYRQ", *p == 'k' ? 'K' : *p) - "KMGTPEZYRQ") + 1;
      long double base = (nf->from == BCU_SCALE_IEC || nf->from == BCU_SCALE_IEC_I) ? 1024 : 1000;
      p++;
      if (nf->from == BCU_SCALE_AUTO && *p == 'i')
        { base = 1024; p++; }
      else if (nf->from == BCU_SCALE_IEC_I)
        {
          if (*p != 'i') return BCU_NF_MISSING_I;
          p++;
        }
      *precision = 0;
      v *= bcu_nf_pow (base, power);
    }
  *out = v;
  *rest = p;
  return *p ? BCU_NF_TRAILING : BCU_NF_OK;
}

static void
bcu_nf_report (const bcu_numfmt_t *nf, bcu_nf_err e, const char *text, const char *rest)
{
  if (nf->inval == BCU_INVAL_IGNORE)
    return;
  switch (e)
    {
    case BCU_NF_OVERFLOW: bcu_nf_error_quoted ("value too large to be converted: %s", text); break;
    case BCU_NF_INVALID: bcu_nf_error_quoted ("invalid number: %s", text); break;
    case BCU_NF_FORBIDDEN: bcu_nf_error_quoted ("rejecting suffix in input: %s (consider using --from)", text); break;
    case BCU_NF_BAD_SUFFIX: bcu_nf_error_quoted ("invalid suffix in input: %s", text); break;
    case BCU_NF_MISSING_I: bcu_nf_error_quoted ("missing 'i' suffix in input: %s (e.g Ki/Mi/Gi)", text); break;
    case BCU_NF_TRAILING:
      {
        char *a = bos_quote (text), *b = bos_quote (rest);
        builtin_error ("invalid suffix in input %s: %s", a ? a : text, b ? b : rest);
        free (a);
        free (b);
        break;
      }
    case BCU_NF_OK: break;
    }
}

static char *
bcu_nf_printf (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  int n = vsnprintf (NULL, 0, fmt, ap);
  va_end (ap);
  if (n < 0) return NULL;
  char *out = malloc ((size_t) n + 1);
  if (!out) return NULL;
  va_start (ap, fmt);
  vsnprintf (out, (size_t) n + 1, fmt, ap);
  va_end (ap);
  return out;
}

/* Render VAL with the output scale, rounding and suffix. */
static char *
bcu_nf_render (const bcu_numfmt_t *nf, long double val, size_t precision)
{
  char fmt[64], *f = fmt;
  const char *suffix = nf->suffix ? nf->suffix : "";
  *f++ = '%';
  if (nf->grouping) *f++ = '\'';
  if (nf->zero_width) f += sprintf (f, "0%d", nf->zero_width);
  if (nf->to == BCU_SCALE_NONE)
    {
      long double scale = bcu_nf_pow (10, (long) precision);
      val = bcu_nf_round (val * scale, nf->round) / scale;
      strcpy (f, ".*Lf%s");
      return bcu_nf_printf (fmt, (int) precision, val, suffix);
    }
  long double base = nf->to == BCU_SCALE_SI ? 1000 : 1024;
  int power = 0;
  if (val >= -LDBL_MAX && val <= LDBL_MAX)
    while (bcu_nf_abs (val) >= base) { val /= base; power++; }
  long adjust = 0;
  if (nf->precision != -1)
    adjust = power * 3 < nf->precision ? power * 3 : nf->precision;
  else if (bcu_nf_abs (val) < 10)
    adjust = 1;           /* one decimal digit below 10 */
  long double scale = bcu_nf_pow (10, adjust);
  val = bcu_nf_round (val * scale, nf->round) / scale;
  if (bcu_nf_abs (val) >= base) { val /= base; power++; }
  int show_decimal = val != 0 && bcu_nf_abs (val) < 10 && power > 0;
  int prec = nf->precision == -1 ? show_decimal : (int) nf->precision;
  static const char *const units[] = { "", "K", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q" };
  const char *unit = power == 1 && nf->to == BCU_SCALE_SI ? "k" : power <= 10 ? units[power] : "(error)";
  strcpy (f, ".*Lf%s%s%s");
  return bcu_nf_printf (fmt, prec, val, unit,
                        nf->to == BCU_SCALE_IEC_I && power > 0 ? "i" : "", suffix);
}

/* Display width of a rendered number: its character count. */
static int
bcu_nf_width (const char *s)
{
  size_t n = mbstowcs (NULL, s, 0);
  return n == (size_t) -1 ? (int) strlen (s) : (int) n;
}

static int
bcu_nf_included (const bcu_numfmt_t *nf, uintmax_t field)
{
  if (!nf->fields) return field == 1;
  for (size_t i = 0; i < nf->nfields; i++)
    if (nf->fields[i].lo <= field && field <= nf->fields[i].hi)
      return 1;
  return 0;
}

/* Convert one field in place. Returns 1 when it converted (or was not
   selected), 0 when it was invalid. */
static int
bcu_nf_field (bcu_numfmt_t *nf, char *text, uintmax_t field)
{
  if (!bcu_nf_included (nf, field))
    {
      fputs (text, stdout);
      return 1;
    }
  if (nf->suffix)
    {
      size_t tl = strlen (text), sl = strlen (nf->suffix);
      if (tl > sl && strcmp (text + tl - sl, nf->suffix) == 0)
        text[tl - sl] = '\0';
    }
  char *p = text;
  while (*p && isblank ((unsigned char) *p)) p++;
  intmax_t padding = nf->padding;
  if (nf->auto_padding)
    padding = (text < p || field > 1) ? (intmax_t) strlen (text) : 0;

  long double val = 0;
  size_t precision = 0;
  const char *rest = p;
  bcu_nf_err e = bcu_nf_parse_number (nf, p, &val, &precision, &rest);
  if (e != BCU_NF_OK)
    {
      bcu_nf_report (nf, e, p, rest);
      goto invalid;
    }
  if (nf->from_unit != 1 || nf->to_unit != 1)
    val = val * nf->from_unit / nf->to_unit;

  size_t used = nf->precision == -1 ? precision : (size_t) nf->precision;
  int exponent = 0;
  if (val >= -LDBL_MAX && val <= LDBL_MAX)
    for (long double t = bcu_nf_abs (val); t >= 10; t /= 10) exponent++;
  if (nf->to == BCU_SCALE_NONE && (size_t) exponent + used > BCU_NF_UNSCALED_DIGITS)
    {
      if (nf->inval != BCU_INVAL_IGNORE)
        {
          if (used)
            builtin_error ("value/precision too large to be printed: '%Lg/%zu' (consider using --to)", val, used);
          else
            builtin_error ("value too large to be printed: '%Lg' (consider using --to)", val);
        }
      goto invalid;
    }
  if (exponent > BCU_NF_MAX_DIGITS - 1)
    {
      if (nf->inval != BCU_INVAL_IGNORE)
        builtin_error ("value too large to be printed: '%Lg' (cannot handle values > 999Q)", val);
      goto invalid;
    }
  char *out = bcu_nf_render (nf, val, used);
  if (!out)
    {
      builtin_error ("failed to prepare value '%Lf' for printing", val);
      nf->stop = 1;
      return 0;
    }
  intmax_t pad = 0;
  if (padding)
    {
      intmax_t width = bcu_nf_width (out);
      if (padding < 0 && padding < -width) pad = padding + width;
      else if (padding > 0 && width < padding) pad = padding - width;
    }
  if (nf->fmt_prefix) fputs (nf->fmt_prefix, stdout);
  for (intmax_t i = pad; i > 0; i--) putchar (' ');
  fputs (out, stdout);
  for (intmax_t i = pad; i < 0; i++) putchar (' ');
  if (nf->fmt_suffix) fputs (nf->fmt_suffix, stdout);
  free (out);
  return 1;

invalid:
  if (nf->inval == BCU_INVAL_ABORT)
    nf->stop = 1;
  else
    fputs (text, stdout);
  return 0;
}

/* Split LINE into fields (blank-separated, or on the -d character),
   convert the selected ones and print the result. */
static int
bcu_nf_line (bcu_numfmt_t *nf, char *line, int newline)
{
  uintmax_t field = 0;
  int valid = 1;
  for (;;)
    {
      char *start = line, *end = line;
      field++;
      if (nf->delimiter >= 0)
        {
          if (*start != (char) nf->delimiter)
            while (*end && *end != (char) nf->delimiter) end++;
        }
      else
        {
          while (*end && (isblank ((unsigned char) *end) || *end == '\n')) end++;
          while (*end && !isblank ((unsigned char) *end) && *end != '\n') end++;
        }
      int last = *end == '\0';
      *end = '\0';
      if (!bcu_nf_field (nf, start, field)) valid = 0;
      if (nf->stop) return 0;
      if (last) break;
      putchar (nf->delimiter >= 0 ? nf->delimiter : ' ');
      line = end + 1;
    }
  if (newline) putchar (nf->line_delim);
  return valid;
}

/* Long options; an unambiguous prefix selects one, as getopt_long does. */
enum { BCU_NF_ARG_NONE, BCU_NF_ARG_REQUIRED, BCU_NF_ARG_OPTIONAL };
static const struct { const char *name; int arg; } bcu_nf_longopts[] = {
  { "from", BCU_NF_ARG_REQUIRED }, { "from-unit", BCU_NF_ARG_REQUIRED },
  { "to", BCU_NF_ARG_REQUIRED }, { "to-unit", BCU_NF_ARG_REQUIRED },
  { "round", BCU_NF_ARG_REQUIRED }, { "padding", BCU_NF_ARG_REQUIRED },
  { "suffix", BCU_NF_ARG_REQUIRED }, { "grouping", BCU_NF_ARG_NONE },
  { "delimiter", BCU_NF_ARG_REQUIRED }, { "field", BCU_NF_ARG_REQUIRED },
  { "debug", BCU_NF_ARG_NONE }, { "header", BCU_NF_ARG_OPTIONAL },
  { "format", BCU_NF_ARG_REQUIRED }, { "invalid", BCU_NF_ARG_REQUIRED },
  { "zero-terminated", BCU_NF_ARG_NONE }, { "help", BCU_NF_ARG_NONE },
  { "version", BCU_NF_ARG_NONE }, { NULL, 0 }
};

static int
bcu_nf_option (bcu_numfmt_t *nf, const char *name, const char *arg,
               const char **format, uintmax_t *header, int *field_seen)
{
  int k;
  if (!strcmp (name, "from"))
    {
      if ((k = bcu_nf_argmatch ("--from", arg, bcu_nf_from_names)) < 0) return EXECUTION_FAILURE;
      nf->from = bcu_nf_from_types[k];
    }
  else if (!strcmp (name, "to"))
    {
      if ((k = bcu_nf_argmatch ("--to", arg, bcu_nf_to_names)) < 0) return EXECUTION_FAILURE;
      nf->to = bcu_nf_to_types[k];
    }
  else if (!strcmp (name, "from-unit"))
    { if (bcu_nf_unit_size (arg, &nf->from_unit) < 0) return EXECUTION_FAILURE; }
  else if (!strcmp (name, "to-unit"))
    { if (bcu_nf_unit_size (arg, &nf->to_unit) < 0) return EXECUTION_FAILURE; }
  else if (!strcmp (name, "round"))
    {
      if ((k = bcu_nf_argmatch ("--round", arg, bcu_nf_round_names)) < 0) return EXECUTION_FAILURE;
      nf->round = (bcu_round_t) k;
    }
  else if (!strcmp (name, "invalid"))
    {
      if ((k = bcu_nf_argmatch ("--invalid", arg, bcu_nf_inval_names)) < 0) return EXECUTION_FAILURE;
      nf->inval = (bcu_inval_t) k;
    }
  else if (!strcmp (name, "padding"))
    {
      char *end = NULL;
      errno = 0;
      intmax_t v = strtoimax (arg, &end, 10);
      if (end == arg || *end || v == 0)
        {
          bcu_nf_error_quoted ("invalid padding value %s", arg);
          return EXECUTION_FAILURE;
        }
      nf->padding = v;
    }
  else if (!strcmp (name, "suffix"))
    nf->suffix = arg;
  else if (!strcmp (name, "grouping"))
    nf->grouping = 1;
  else if (!strcmp (name, "delimiter"))
    {
      if (arg[0] && arg[1])
        {
          builtin_error ("the delimiter must be a single character");
          return EXECUTION_FAILURE;
        }
      nf->delimiter = (unsigned char) arg[0];
    }
  else if (!strcmp (name, "field"))
    {
      if (*field_seen)
        {
          builtin_error ("multiple field specifications");
          return EXECUTION_FAILURE;
        }
      *field_seen = 1;
      return bcu_nf_parse_fields (nf, arg);
    }
  else if (!strcmp (name, "header"))
    {
      if (!arg)
        *header = 1;
      else
        {
          char *end = NULL;
          errno = 0;
          uintmax_t v = strtoumax (arg, &end, 10);
          if (!isdigit ((unsigned char) *arg) || errno || *end || v == 0)
            {
              bcu_nf_error_quoted ("invalid header value %s", arg);
              return EXECUTION_FAILURE;
            }
          *header = v;
        }
    }
  else if (!strcmp (name, "format"))
    *format = arg;
  else if (!strcmp (name, "zero-terminated"))
    nf->line_delim = '\0';
  else if (!strcmp (name, "debug"))
    ;
  else if (!strcmp (name, "help") || !strcmp (name, "version"))
    {
      printf ("Usage: numfmt [OPTION]... [NUMBER]...\n");
      return -1;
    }
  return EXECUTION_SUCCESS;
}

static int
bcu_numfmt_run (WORD_LIST *list, bcu_numfmt_t *nf)
{
  WORD_LIST *values __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *values_tail = NULL;
  const char *format = NULL;
  uintmax_t header = 0;
  int field_seen = 0, rc, ended = 0;

  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (!ended && a[0] == '-' && a[1] == '-' && a[2] == '\0')
        { ended = 1; continue; }
      if (!ended && a[0] == '-' && a[1] == '-')
        {
          const char *name = a + 2, *eq = strchr (name, '=');
          size_t len = eq ? (size_t) (eq - name) : strlen (name);
          int found = -1, matches = 0;
          for (int i = 0; bcu_nf_longopts[i].name; i++)
            {
              if (strncmp (bcu_nf_longopts[i].name, name, len)) continue;
              if (strlen (bcu_nf_longopts[i].name) == len) { found = i; matches = 1; break; }
              if (found < 0) found = i;
              matches++;
            }
          if (matches > 1)
            {
              char list[512];
              size_t at = 0;
              list[0] = '\0';
              for (int i = 0; bcu_nf_longopts[i].name && at < sizeof list - 40; i++)
                if (!strncmp (bcu_nf_longopts[i].name, name, len))
                  at += (size_t) snprintf (list + at, sizeof list - at, " '--%s'",
                                           bcu_nf_longopts[i].name);
              builtin_error ("option '%s' is ambiguous; possibilities:%s", a, list);
              return bcu_nf_try ();
            }
          if (found < 0)
            {
              builtin_error ("unrecognized option '%s'", a);
              return bcu_nf_try ();
            }
          const char *optname = bcu_nf_longopts[found].name, *arg = eq ? eq + 1 : NULL;
          if (bcu_nf_longopts[found].arg == BCU_NF_ARG_NONE && eq)
            {
              builtin_error ("option '--%s' doesn't allow an argument", optname);
              return bcu_nf_try ();
            }
          if (bcu_nf_longopts[found].arg == BCU_NF_ARG_REQUIRED && !eq)
            {
              if (!w->next)
                {
                  builtin_error ("option '--%s' requires an argument", optname);
                  return bcu_nf_try ();
                }
              w = w->next;
              arg = w->word->word;
            }
          rc = bcu_nf_option (nf, optname, arg, &format, &header, &field_seen);
          if (rc < 0) return EXECUTION_SUCCESS;
          if (rc != EXECUTION_SUCCESS) return rc;
          continue;
        }
      if (!ended && a[0] == '-' && a[1])
        {
          for (const char *c = a + 1; *c; c++)
            {
              if (*c == 'z') { nf->line_delim = '\0'; continue; }
              if (*c == 'd')
                {
                  const char *arg = c[1] ? c + 1 : NULL;
                  if (!arg)
                    {
                      if (!w->next)
                        {
                          builtin_error ("option requires an argument -- 'd'");
                          return bcu_nf_try ();
                        }
                      w = w->next;
                      arg = w->word->word;
                    }
                  rc = bcu_nf_option (nf, "delimiter", arg, &format, &header, &field_seen);
                  if (rc != EXECUTION_SUCCESS) return rc;
                  break;
                }
              builtin_error ("invalid option -- '%c'", *c);
              return bcu_nf_try ();
            }
          continue;
        }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!values) values = nw; else values_tail->next = nw;
      values_tail = nw;
    }

  if (format && nf->grouping)
    {
      builtin_error ("--grouping cannot be combined with --format");
      return EXECUTION_FAILURE;
    }
  if (format && bcu_nf_parse_format (nf, format) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  if (nf->grouping && nf->to != BCU_SCALE_NONE)
    {
      builtin_error ("grouping cannot be combined with --to");
      return EXECUTION_FAILURE;
    }
  nf->auto_padding = nf->padding == 0 && nf->delimiter < 0;

  int valid = 1;
  if (values)
    for (WORD_LIST *w = values; w && !nf->stop; w = w->next)
      {
        char *copy = bcu_strdup (w->word->word);
        valid &= bcu_nf_line (nf, copy, 1);
        free (copy);
      }
  else
    {
      int fd = dup (STDIN_FILENO);
      FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
      if (!in)
        {
          if (fd >= 0) close (fd);
          builtin_error ("stdin: %s", strerror (errno));
          return EXECUTION_FAILURE;
        }
      char *line = NULL;
      size_t cap = 0;
      ssize_t len;
      while (header && getdelim (&line, &cap, nf->line_delim, in) > 0)
        {
          fputs (line, stdout);
          header--;
        }
      while (!nf->stop && (len = getdelim (&line, &cap, nf->line_delim, in)) > 0)
        {
          int newline = line[len - 1] == (char) nf->line_delim;
          if (newline) line[len - 1] = '\0';
          valid &= bcu_nf_line (nf, line, newline);
        }
      int read_error = ferror (in);
      free (line);
      fclose (in);
      if (read_error)
        {
          builtin_error ("error reading input");
          return EXECUTION_FAILURE;
        }
    }
  if (nf->stop) return 2;
  if (!valid && (nf->inval == BCU_INVAL_ABORT || nf->inval == BCU_INVAL_FAIL)) return 2;
  return EXECUTION_SUCCESS;
}

/* Diagnostics carry the program name GNU numfmt prints. */
static int
bcu_numfmt_cmd (WORD_LIST *list)
{
  bcu_numfmt_t nf;
  memset (&nf, 0, sizeof nf);
  nf.from = nf.to = BCU_SCALE_NONE;
  nf.round = BCU_ROUND_FROM_ZERO;
  nf.inval = BCU_INVAL_ABORT;
  nf.from_unit = nf.to_unit = 1;
  nf.precision = -1;
  nf.delimiter = -1;
  nf.line_delim = '\n';
  nf.radix = nl_langinfo (RADIXCHAR);
  if (!nf.radix || !*nf.radix) nf.radix = ".";
  nf.radix_len = strlen (nf.radix);

  char *saved = this_command_name;
  this_command_name = (char *) "numfmt";
  int rc = bcu_numfmt_run (list, &nf);
  this_command_name = saved;
  free (nf.fields);
  free (nf.fmt_prefix);
  free (nf.fmt_suffix);
  return rc;
}

/* ===================================================================
 * shred — overwrite a file N times with random bytes, optionally
 *         unlink. Defaults: 3 passes, no zero-pass, no unlink.
 *
 * Flags (GNU shred spellings):
 *   -n N, --iterations=N   pass count (default 3)
 *   -z, --zero             add a final zero-fill pass
 *   -u                     remove after writing (as --remove=wipesync)
 *   --remove[=HOW]         remove; HOW is unlink, wipe or wipesync
 *                          (wipe renames the name to shorter all-'0'
 *                          names before the unlink; wipesync also syncs
 *                          the directory after each rename)
 *   -v, --verbose          report each pass and removal step on stderr
 *   -f, --force            make the file writable first if needed
 *   -x, --exact            exact size (also the default)
 *   -s SZ, --size=SZ       treat file as SZ bytes long
 * =================================================================== */

enum { BCU_RM_NONE, BCU_RM_UNLINK, BCU_RM_WIPE, BCU_RM_WIPESYNC };

/* GNU wipename: rename PATH through ever shorter names made of '0' (the
   first free name of each length), then unlink it. */
static int
bcu_shred_remove (const char *path, int how, int verbose)
{
  if (verbose) fprintf (stderr, "shred: %s: removing\n", path);
  char *old = savestring (path);
  if (how != BCU_RM_UNLINK)
    {
      char *slash = strrchr (old, '/');
      size_t dirlen = slash ? (size_t) (slash - old) + 1 : 0;
      char *dir = slash ? savestring (old) : NULL;
      int dfd = -1;
      if (dir) dir[dirlen] = '\0';
      if (how == BCU_RM_WIPESYNC)
        dfd = open (dir ? dir : ".", O_RDONLY | O_DIRECTORY);
      size_t len = strlen (old + dirlen);
      char *nw = xmalloc (dirlen + len + 1);
      memcpy (nw, old, dirlen);
      static const char nameset[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.";
      for (; len; len--)
        {
          char *base = nw + dirlen;
          memset (base, nameset[0], len);
          base[len] = '\0';
          int ok = 0;
          for (;;)
            {
              struct stat st;
              if (lstat (nw, &st) < 0 && errno == ENOENT)
                { ok = rename (old, nw) == 0; break; }
              /* Next name of this length (odometer over nameset). */
              size_t i = len;
              while (i--)
                {
                  const char *at = strchr (nameset, base[i]);
                  if (at[1]) { base[i] = at[1]; break; }
                  base[i] = nameset[0];
                }
              if (i == (size_t) -1) break;
            }
          if (ok)
            {
              if (dfd >= 0) fsync (dfd);
              if (verbose) fprintf (stderr, "shred: %s: renamed to %s\n", old, nw);
              strcpy (old + dirlen, base);
            }
        }
      free (nw);
      free (dir);
      if (dfd >= 0) close (dfd);
    }
  int rc = EXECUTION_SUCCESS;
  if (unlink (old) < 0)
    {
      builtin_error ("shred: %s: failed to remove: %s", path, strerror (errno));
      rc = EXECUTION_FAILURE;
    }
  else if (verbose)
    fprintf (stderr, "shred: %s: removed\n", path);
  free (old);
  return rc;
}

static int
bcu_shred_one (const char *path, int passes, int zero_pass, int remove_how,
               long long fixed_size, int verbose, int force)
{
  int fd = open (path, O_WRONLY);
  if (fd < 0 && force && errno == EACCES)
    {
      struct stat st;
      if (stat (path, &st) == 0 && chmod (path, st.st_mode | S_IWUSR) == 0)
        fd = open (path, O_WRONLY);
      else
        errno = EACCES;
    }
  if (fd < 0) { builtin_error ("shred: %s: failed to open for writing: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  off_t sz;
  if (fixed_size >= 0) sz = (off_t) fixed_size;
  else
    {
      struct stat st;
      if (fstat (fd, &st) < 0) { close (fd); builtin_error ("shred: fstat: %s", strerror (errno)); return EXECUTION_FAILURE; }
      sz = st.st_size;
    }
  unsigned char *buf = xmalloc (BUFSZ);
  if (!buf) { close (fd); return EXECUTION_FAILURE; }

  int error = 0;
  int total = passes + (zero_pass ? 1 : 0);
  FILE *rnd = passes ? fopen ("/dev/urandom", "rb") : NULL;
  if (passes && !rnd) error = errno;
  for (int pass = 0; !error && pass < total; pass++)
    {
      if (lseek (fd, 0, SEEK_SET) < 0) { error = errno; break; }
      int is_zero_pass = (pass == passes);
      if (verbose)
        fprintf (stderr, "shred: %s: pass %d/%d (%s)...\n", path, pass + 1, total,
                 is_zero_pass ? "000000" : "random");
      off_t remaining = sz;
      while (remaining > 0 && !error)
        {
          size_t chunk = remaining < BUFSZ ? (size_t) remaining : (size_t) BUFSZ;
          if (is_zero_pass) memset (buf, 0, chunk);
          else if (fread (buf, 1, chunk, rnd) != chunk)
            { error = errno ? errno : EIO; break; }
          size_t written = 0;
          while (written < chunk)
            {
              ssize_t n = write (fd, buf + written, chunk - written);
              if (n < 0 && errno == EINTR) continue;
              if (n <= 0) { error = n < 0 ? errno : EIO; break; }
              written += (size_t) n;
            }
          remaining -= (off_t) written;
        }
      if (!error && fsync (fd) < 0) error = errno;
    }
  if (rnd) fclose (rnd);
  free (buf);
  if (close (fd) < 0 && !error) error = errno;
  /* Never unlink a file after an unsuccessful overwrite. */
  if (error)
    { builtin_error ("shred: %s: %s", path, strerror (error)); return EXECUTION_FAILURE; }
  if (remove_how != BCU_RM_NONE)
    return bcu_shred_remove (path, remove_how, verbose);
  return EXECUTION_SUCCESS;
}

static int
bcu_shred_cmd (WORD_LIST *list)
{
  int passes = 3, zero_pass = 0, remove_how = BCU_RM_NONE, verbose = 0, force = 0;
  int options_done = 0;
  long long fixed_size = -1;
  WORD_LIST *files __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *files_tail = NULL;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      const char *val = NULL;
      if (!options_done && strcmp (a, "--") == 0) { options_done = 1; continue; }
      if (options_done || a[0] != '-' || a[1] == '\0')
        {
          WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
          nw->word = w->word;
          if (!files) files = nw; else files_tail->next = nw;
          files_tail = nw;
          continue;
        }
      if (a[1] == '-')
        {
          const char *eq = strchr (a, '=');
          size_t n = eq ? (size_t) (eq - a) : strlen (a);
          if (!eq && strcmp (a, "--help") == 0)
            {
              puts ("Usage: shred [-fuvxz] [-n N] [-s SIZE] [--remove[=HOW]] FILE...");
              puts ("Overwrite FILEs (3 random passes by default); -z adds a zero pass;");
              puts ("-u or --remove[=unlink|wipe|wipesync] removes them; -v reports progress.");
              return EXECUTION_SUCCESS;
            }
          if (!eq && strcmp (a, "--exact") == 0) continue;
          if (!eq && strcmp (a, "--zero") == 0) { zero_pass = 1; continue; }
          if (!eq && strcmp (a, "--verbose") == 0) { verbose = 1; continue; }
          if (!eq && strcmp (a, "--force") == 0) { force = 1; continue; }
          if (n == 8 && strncmp (a, "--remove", n) == 0)
            {
              const char *how = eq ? eq + 1 : "wipesync";
              if (strcmp (how, "unlink") == 0) remove_how = BCU_RM_UNLINK;
              else if (strcmp (how, "wipe") == 0) remove_how = BCU_RM_WIPE;
              else if (strcmp (how, "wipesync") == 0) remove_how = BCU_RM_WIPESYNC;
              else
                {
                  builtin_error ("shred: invalid argument '%s' for '--remove'", how);
                  builtin_error ("shred: valid arguments are: 'unlink', 'wipe', 'wipesync'");
                  return EX_USAGE;
                }
              continue;
            }
          char opt = 0;
          if (n == 12 && strncmp (a, "--iterations", n) == 0) opt = 'n';
          else if (n == 6 && strncmp (a, "--size", n) == 0) opt = 's';
          if (!opt) { builtin_error ("shred: unknown flag: %s", a); bcu_usage ("shred"); return EX_USAGE; }
          if (eq) val = eq + 1;
          else if (w->next) { w = w->next; val = w->word->word; }
          else { builtin_error ("shred: option '%s' requires an argument", a); bcu_usage ("shred"); return EX_USAGE; }
          if (opt == 'n') goto iterations;
          goto size;
        }
      /* Clustered short options: -vuz, -n3, -s 10. */
      for (const char *p = a + 1; *p; p++)
        {
          switch (*p)
            {
            case 'x': continue;
            case 'z': zero_pass = 1; continue;
            case 'u': remove_how = BCU_RM_WIPESYNC; continue;
            case 'v': verbose = 1; continue;
            case 'f': force = 1; continue;
            case 'n': case 's':
              if (p[1]) val = p + 1;
              else if (w->next) { w = w->next; val = w->word->word; }
              else { builtin_error ("shred: option requires an argument -- '%c'", *p); bcu_usage ("shred"); return EX_USAGE; }
              if (*p == 'n') goto iterations;
              goto size;
            default:
              builtin_error ("shred: unknown flag: %s", a); bcu_usage ("shred"); return EX_USAGE;
            }
        }
      continue;
    iterations:
      {
        long long v;
        if (!bcu_parse_ll (val, &v) || v < 0 || v >= INT_MAX) { builtin_error ("shred: bad -n"); bcu_usage ("shred"); return EX_USAGE; }
        passes = (int) v;
        continue;
      }
    size:
      if (!bcu_parse_ll (val, &fixed_size) || fixed_size < 0) { builtin_error ("shred: bad -s"); bcu_usage ("shred"); return EX_USAGE; }
    }

  if (!files) { builtin_error ("shred: missing FILE"); bcu_usage ("shred"); return EX_USAGE; }

  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *w = files; w; w = w->next)
    if (bcu_shred_one (w->word->word, passes, zero_pass, remove_how, fixed_size, verbose, force) != EXECUTION_SUCCESS)
      rc = EXECUTION_FAILURE;

  return rc;
}

/* ===================================================================
 * groups — print groups a user belongs to.
 * =================================================================== */

static int
bcu_groups_print (const char *user)
{
  struct passwd *pw = getpwnam (user);
  if (!pw) { builtin_error ("groups: no such user: %s", user); return EXECUTION_FAILURE; }
  int ngroups = 0;
  /* First call: ask glibc how many slots we need. */
  getgrouplist (pw->pw_name, pw->pw_gid, NULL, &ngroups);
  if (ngroups <= 0) ngroups = 16;
  gid_t *gids = xmalloc ((size_t) ngroups * sizeof (gid_t));
  if (!gids) { builtin_error ("groups: oom"); return EXECUTION_FAILURE; }
  if (getgrouplist (pw->pw_name, pw->pw_gid, gids, &ngroups) < 0)
    { free (gids); builtin_error ("groups: getgrouplist failed"); return EXECUTION_FAILURE; }
  for (int i = 0; i < ngroups; i++)
    {
      struct group *gr = getgrgid (gids[i]);
      if (i) putchar (' ');
      if (gr) fputs (gr->gr_name, stdout);
      else    printf ("%u", (unsigned) gids[i]);
    }
  putchar ('\n');
  free (gids);
  return EXECUTION_SUCCESS;
}

static int
bcu_groups_cmd (WORD_LIST *list)
{
  if (!list)
    {
      /* No operand: print the CURRENT PROCESS's groups via getgroups(),
         exactly like GNU `groups`. (Deriving them from getpwuid()+
         getgrouplist() recomputes from /etc/group and yields a different
         order — and aliases libc's static passwd buffer.) */
      int ng = getgroups (0, NULL);
      if (ng < 0) ng = 0;
      gid_t *gids = xmalloc ((size_t) (ng ? ng : 1) * sizeof (gid_t));
      if (!gids) { builtin_error ("groups: oom"); return EXECUTION_FAILURE; }
      ng = getgroups (ng, gids);
      if (ng < 0) { free (gids); builtin_error ("groups: getgroups failed"); return EXECUTION_FAILURE; }
      /* GNU prints the effective gid's group FIRST, then the remaining
         supplementary groups (in getgroups() order) skipping the egid. */
      gid_t egid = getegid ();
      struct group *eg = getgrgid (egid);
      if (eg) fputs (eg->gr_name, stdout);
      else    printf ("%u", (unsigned) egid);
      for (int i = 0; i < ng; i++)
        {
          if (gids[i] == egid) continue;
          putchar (' ');
          struct group *gr = getgrgid (gids[i]);
          if (gr) fputs (gr->gr_name, stdout);
          else    printf ("%u", (unsigned) gids[i]);
        }
      putchar ('\n');
      free (gids);
      return EXECUTION_SUCCESS;
    }
  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      printf ("%s : ", w->word->word);
      if (bcu_groups_print (w->word->word) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
    }
  return rc;
}

/* ===================================================================
 * install — like `cp` with explicit -m mode and -d/-D for directories.
 *
 *   install [OPTION]... [-T] SOURCE DEST
 *   install [OPTION]... SOURCE... DIRECTORY
 *   install [OPTION]... -t DIRECTORY SOURCE...
 *   install [OPTION]... -d DIRECTORY...
 *
 * Written for bash-os from the coreutils manual, POSIX and the observed
 * behaviour of GNU coreutils 9.7 install (messages, the order of its
 * checks, exit status and system calls, all seen from outside).
 *
 * Each SOURCE goes to a fresh file that takes DEST's name: an existing
 * DEST is backed up (-b, --backup, -S) or removed, the copy is created
 * exclusively, then optionally stripped (-s), given the source's times
 * (-p), the requested owner and group (-o/-g, names or numbers) and last
 * the mode (-m, octal or symbolic, computed as for a new file; default
 * rwxr-xr-x). -C leaves a destination whose content, owner, group and
 * mode already match untouched. -d creates each DIRECTORY with all its
 * missing parents, then applies -m to it as chmod would; -D creates DEST's
 * missing parents, or all of the -t directory. Parents are made
 * rwxr-xr-x whatever the umask. -v reports each step on stdout. Any
 * failure gives status 1; diagnostics read "install: ...".
 * =================================================================== */

#include "gnu-longopt.h"
#include "gnu-mode.h"
#include "child-wait.h"
#include "findcmd.h"
#include "trap.h"
#include <sys/wait.h>
#if defined (__linux__)
#  include <sys/ioctl.h>
#  ifndef FICLONE
#    define FICLONE _IOW (0x94, 9, int)
#  endif
#endif

extern char *this_command_name;

typedef struct
{
  int dir_arg, parents, compare, preserve_times, strip, verbose, debug;
  int backup_kind;                      /* BOS_BACKUP_NONE: remove DEST */
  const char *suffix;                   /* resolved simple-backup suffix */
  const char *strip_program;            /* NULL: strip */
  struct bos_mode_change *mode_change;  /* NULL: the default rwxr-xr-x */
  mode_t file_mode, dir_mode;           /* what a new file / directory gets */
  uid_t uid;                            /* (uid_t) -1: leave alone */
  gid_t gid;
} bcu_inst;

/* "BEFORE 'NAME'AFTER[: ERROR]" with NAME in GNU's file-name quoting. */
static void
bcu_inst_fail (const char *before, const char *name, const char *after, int error)
{
  char *q = bos_quoteaf (name);
  builtin_error ("%s%s%s%s%s", before, q ? q : name, after,
                 error ? ": " : "", error ? strerror (error) : "");
  free (q);
}

/* Print "install: creating directory 'NAME'" for -v. */
static void
bcu_inst_said_mkdir (const bcu_inst *o, const char *name)
{
  if (!o->verbose)
    return;
  char *q = bos_quoteaf (name);
  printf ("install: creating directory %s\n", q ? q : name);
  free (q);
}

static int
bcu_inst_mkdir (const char *path, mode_t mode)
{
  /* Exact permissions, as install's own umask of 0 gives. mkdir itself
     still lets a set-group-ID parent pass that bit on. */
  mode_t mask = umask (0);
  int rc = mkdir (path, mode);
  int error = errno;
  umask (mask);
  errno = error;
  return rc;
}

/* Create the missing directories along PATH, each rwxr-xr-x, reporting
   each new one under -v. The last component is included only when
   WITH_LAST is set. A component that exists must be a directory that can
   be searched. Returns 0, or -1 after "cannot create directory". */
static int
bcu_inst_mkdirs (const bcu_inst *o, const char *path, int with_last)
{
  size_t len = strlen (path), i = 0;
  char *prefix = xmalloc (len + 1);
  while (path[i] == '/')
    i++;
  while (path[i])
    {
      while (path[i] && path[i] != '/')
        i++;
      size_t end = i;
      while (path[i] == '/')
        i++;
      int last = path[i] == '\0';
      if (last && !with_last)
        break;
      const char *name = path;
      if (!last)
        {
          memcpy (prefix, path, end);
          prefix[end] = '\0';
          name = prefix;
        }
      if (bcu_inst_mkdir (name, 0755) == 0)
        {
          bcu_inst_said_mkdir (o, name);
          continue;
        }
      int error = errno;
      struct stat st;
      if (stat (name, &st) == 0)
        {
          if (S_ISDIR (st.st_mode) && access (name, X_OK) == 0)
            continue;
          error = S_ISDIR (st.st_mode) ? errno : ENOTDIR;
        }
      else if (error == EEXIST)
        error = errno;
      bcu_inst_fail ("cannot create directory ", name, "", error);
      free (prefix);
      return -1;
    }
  free (prefix);
  return 0;
}

/* install -d: PATH and its missing parents, then owner, group and mode on
   PATH itself (an existing directory too). */
static int
bcu_inst_make_dir (const bcu_inst *o, const char *path)
{
  if (bcu_inst_mkdirs (o, path, 0) < 0)
    return -1;
  int made = bcu_inst_mkdir (path, o->dir_mode) == 0;
  int error = errno;
  struct stat st;
  if (made)
    bcu_inst_said_mkdir (o, path);
  if (stat (path, &st) < 0)
    {
      int stat_error = errno;
      if (made || error == ENOENT || error == ENOTDIR)
        bcu_inst_fail ("cannot create directory ", path, "", made ? stat_error : error);
      else
        bcu_inst_fail ("cannot change permissions of ", path, "", stat_error);
      return -1;
    }
  if (!S_ISDIR (st.st_mode))
    {
      bcu_inst_fail ("cannot create directory ", path, "", made ? ENOTDIR : error);
      return -1;
    }
  if (o->uid != (uid_t) -1 || o->gid != (gid_t) -1)
    {
      if (lchown (path, o->uid, o->gid) < 0)
        {
          bcu_inst_fail ("cannot change owner and permissions of ", path, "", errno);
          return -1;
        }
      if (stat (path, &st) < 0)
        {
          bcu_inst_fail ("cannot change permissions of ", path, "", errno);
          return -1;
        }
    }
  /* A -m mode works on the directory as chmod would (so a directory keeps
     set-ID bits that octal modes leave alone); the default mode is exact. */
  mode_t want = o->mode_change
    ? bos_mode_adjust (st.st_mode & BOS_MODE_BITS, 1, 0, o->mode_change, NULL) & BOS_MODE_BITS
    : 0755;
  if ((st.st_mode & BOS_MODE_BITS) != want && chmod (path, want) < 0)
    {
      bcu_inst_fail ("cannot change permissions of ", path, "", errno);
      return -1;
    }
  return 0;
}

/* Whether two paths name one directory entry: the same last component in
   the same parent directory, however either path is spelled. An answer that
   cannot be established counts as the same entry, so the caller refuses
   instead of removing the source's only name. */
static int
bcu_install_same_entry (const char *a, const char *b)
{
  const char *paths[2] = { a, b };
  char parents[2][PATH_MAX];
  struct stat dirs[2];
  const char *sa = strrchr (a, '/'), *sb = strrchr (b, '/');
  if (strcmp (sa ? sa + 1 : a, sb ? sb + 1 : b))
    return 0;
  for (int i = 0; i < 2; i++)
    {
      const char *slash = strrchr (paths[i], '/');
      size_t len = slash ? (size_t) (slash - paths[i]) : 0;
      if (len >= PATH_MAX)
        return 1;
      if (!slash)
        strcpy (parents[i], ".");
      else if (len == 0)
        strcpy (parents[i], "/");
      else
        {
          memcpy (parents[i], paths[i], len);
          parents[i][len] = '\0';
        }
      if (stat (parents[i], &dirs[i]) < 0)
        return 1;
    }
  return dirs[0].st_dev == dirs[1].st_dev && dirs[0].st_ino == dirs[1].st_ino;
}

static void
bcu_inst_same_file (const char *src, const char *dst)
{
  char *qs = bos_quoteaf (src), *qd = bos_quoteaf (dst);
  builtin_error ("%s and %s are the same file", qs ? qs : src, qd ? qd : dst);
  free (qs);
  free (qd);
}

/* Refuse a destination that is the source as GNU install does: the same
   directory entry, or a source that reaches the destination through a
   symbolic link. Another hard link or a symbolic link to the source is
   fine: it is replaced by a fresh file and the source keeps its data.
   Returns -1 after reporting a refusal. */
static int
bcu_install_same_file (const char *src, const char *dst, const struct stat *src_st)
{
  struct stat st;
  if (stat (dst, &st) < 0 || st.st_dev != src_st->st_dev || st.st_ino != src_st->st_ino)
    return 0;
  if (lstat (dst, &st) == 0 && S_ISLNK (st.st_mode))
    return 0;
  if ((lstat (src, &st) == 0 && S_ISLNK (st.st_mode)) || bcu_install_same_entry (src, dst))
    {
      bcu_inst_same_file (src, dst);
      return -1;
    }
  return 0;
}

/* -C/--compare: whether DST must be (re)written. It may be skipped only
   when both are regular files without special mode bits, DST already has
   MODE and the owner and group the copy would get (the caller's real IDs
   unless -o/-g name them), and the contents are identical. */
static int
bcu_install_need_copy (const char *src, const char *dst, mode_t mode, uid_t uid, gid_t gid)
{
  const mode_t extra = (mode_t) ~(S_IRWXU | S_IRWXG | S_IRWXO | S_IFMT);
  struct stat ss, ds;
  if ((mode & extra) || stat (src, &ss) < 0 || lstat (dst, &ds) < 0)
    return 1;
  if (!S_ISREG (ss.st_mode) || !S_ISREG (ds.st_mode)
      || (ss.st_mode & extra) || (ds.st_mode & extra)
      || ss.st_size != ds.st_size || (ds.st_mode & 07777) != mode)
    return 1;
  if (ds.st_uid != (uid == (uid_t) -1 ? getuid () : uid)
      || ds.st_gid != (gid == (gid_t) -1 ? getgid () : gid))
    return 1;
  int a = open (src, O_RDONLY), b = a < 0 ? -1 : open (dst, O_RDONLY);
  int differ = a < 0 || b < 0;
  static char ba[65536], bb[65536];
  while (!differ)
    {
      ssize_t na = read (a, ba, sizeof ba);
      if (na < 0 && errno == EINTR) continue;
      if (na <= 0) { differ = na < 0; if (!differ) differ = read (b, bb, 1) != 0; break; }
      ssize_t got = 0;
      while (got < na)
        {
          ssize_t nb = read (b, bb + got, (size_t) (na - got));
          if (nb < 0 && errno == EINTR) continue;
          if (nb <= 0) break;
          got += nb;
        }
      differ = got != na || memcmp (ba, bb, (size_t) na) != 0;
    }
  if (a >= 0) close (a);
  if (b >= 0) close (b);
  return differ;
}

/* Copy RFD to WFD. Returns 0, or the errno of a failed read (*READING set)
   or write. *OFFLOAD and *REFLINK describe the method for --debug. */
static int
bcu_inst_copy_data (int rfd, int wfd, const struct stat *src_st, int *reading,
                    const char **offload, const char **reflink)
{
  struct stat dst_st;
  int regular = S_ISREG (src_st->st_mode) && fstat (wfd, &dst_st) == 0
                && S_ISREG (dst_st.st_mode);
  *reading = 0;
  *offload = "unsupported";
  *reflink = "unsupported";
#if defined (__linux__)
  if (regular && ioctl (wfd, FICLONE, rfd) == 0)
    {
      *reflink = "yes";
      *offload = "avoided";
      return 0;
    }
#  if defined (SYS_copy_file_range)
  /* An unsupported filesystem (or a short kernel copy) continues through
     read/write at the descriptors' current offsets. */
  if (regular)
    {
      ssize_t n = syscall (SYS_copy_file_range, rfd, NULL, wfd, NULL,
                           (size_t) 1024 * 1024 * 1024, 0);
      if (n > 0)
        {
          *offload = "yes";
          while ((n = syscall (SYS_copy_file_range, rfd, NULL, wfd, NULL,
                               (size_t) 1024 * 1024 * 1024, 0)) > 0)
            ;
        }
      else if (n == 0)
        *offload = "unknown";
    }
#  endif
#endif
  /* Always finish with read, including after a zero return: some virtual
     regular files report zero size yet still yield data when read. */
  static char buf[128 * 1024];
  for (;;)
    {
      ssize_t n = read (rfd, buf, sizeof buf);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        {
          *reading = 1;
          return errno;
        }
      if (n == 0)
        return 0;
      for (ssize_t off = 0; off < n;)
        {
          ssize_t w = write (wfd, buf + off, (size_t) (n - off));
          if (w < 0 && errno == EINTR)
            continue;
          if (w <= 0)
            return w < 0 ? errno : EIO;
          off += w;
        }
    }
}

/* Run the strip program on DST. Returns 0, or -1 after a diagnostic. */
static int
bcu_inst_strip (const bcu_inst *o, const char *dst)
{
  const char *program = o->strip_program ? o->strip_program : "strip";
  char *path = strchr (program, '/') ? savestring (program) : find_user_command (program);
  /* An operand that starts with '-' must not read as an option. */
  char *operand = NULL;
  if (dst[0] == '-')
    {
      operand = xmalloc (strlen (dst) + 3);
      strcpy (operand, "./");
      strcat (operand, dst);
    }
  char *argv[3] = { (char *) program, operand ? operand : (char *) dst, NULL };
  int rc = -1;
  bos_child_wait wait_state;
  if (bos_child_wait_begin (&wait_state) < 0)
    builtin_error ("cannot fork: %s", strerror (errno));
  else
    {
      maybe_make_export_env ();
      fflush (stdout);
      fflush (stderr);
      pid_t pid = fork ();
      if (pid == 0)
        {
          bos_child_wait_child (&wait_state);
          restore_original_signals ();
          if (path)
            execve (path, argv, export_env);
          else
            errno = ENOENT;
          bcu_inst_fail ("cannot run ", program, "", errno);
          fflush (stderr);
          _exit (EXIT_FAILURE);
        }
      int status = 0;
      if (pid < 0)
        builtin_error ("cannot fork: %s", strerror (errno));
      else
        {
          pid_t w;
          while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
            ;
          if (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0)
            rc = 0;
        }
      bos_child_wait_end (&wait_state);
      if (rc < 0)
        builtin_error ("strip process terminated abnormally");
    }
  free (operand);
  free (path);
  return rc;
}

/* Install the file SRC as DST. Returns 0, or -1 after a diagnostic. */
static int
bcu_inst_file (const bcu_inst *o, const char *src, const char *dst)
{
  struct stat ss, ds;
  if (stat (src, &ss) < 0)
    {
      bcu_inst_fail ("cannot stat ", src, "", errno);
      return -1;
    }
  if (S_ISDIR (ss.st_mode))
    {
      bcu_inst_fail ("omitting directory ", src, "", 0);
      return -1;
    }
  int exists = lstat (dst, &ds) == 0;
  if (!exists && *dst && errno != ENOENT)
    {
      bcu_inst_fail ("cannot stat ", dst, "", errno);
      return -1;
    }
  if (!*dst || (exists && S_ISDIR (ds.st_mode)))
    {
      if (*dst && o->backup_kind != BOS_BACKUP_NONE)
        bcu_inst_fail ("cannot create regular file ", dst, "", EISDIR);
      else
        {
          char *qd = bos_quoteaf (dst), *qs = bos_quoteaf (src);
          builtin_error ("cannot overwrite directory %s with non-directory %s",
                         qd ? qd : dst, qs ? qs : src);
          free (qd);
          free (qs);
        }
      return -1;
    }
  if (o->compare && !bcu_install_need_copy (src, dst, o->file_mode, o->uid, o->gid))
    return 0;
  if (bcu_install_same_file (src, dst, &ss) < 0)
    return -1;

  /* Free DST's name: back it up, or remove it, so other hard links keep
     their contents and a symbolic link is replaced rather than followed. */
  char *backup = NULL;
  if (exists)
    {
      if (o->backup_kind != BOS_BACKUP_NONE)
        {
          backup = bos_backup_name (dst, o->backup_kind, o->suffix);
          if (!backup || rename (dst, backup) < 0)
            {
              bcu_inst_fail ("cannot backup ", dst, "", errno);
              free (backup);
              return -1;
            }
        }
      else if (unlink (dst) < 0)
        {
          if (errno != ENOENT)
            {
              bcu_inst_fail ("cannot remove ", dst, "", errno);
              return -1;
            }
        }
      else if (o->verbose)
        {
          char *q = bos_quoteaf (dst);
          printf ("removed %s\n", q ? q : dst);
          free (q);
        }
    }
  if (o->verbose)
    {
      char *qs = bos_quoteaf (src), *qd = bos_quoteaf (dst);
      printf ("%s -> %s", qs ? qs : src, qd ? qd : dst);
      if (backup)
        {
          char *qb = bos_quoteaf (backup);
          printf (" (backup: %s)", qb ? qb : backup);
          free (qb);
        }
      putchar ('\n');
      free (qs);
      free (qd);
    }
  free (backup);

  int rfd = open (src, O_RDONLY);
  if (rfd < 0)
    {
      bcu_inst_fail ("cannot open ", src, " for reading", errno);
      return -1;
    }
  if (fstat (rfd, &ss) < 0)
    {
      bcu_inst_fail ("cannot fstat ", src, "", errno);
      close (rfd);
      return -1;
    }
  int wfd = open (dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (wfd < 0)
    {
      int error = errno;
      size_t n = strlen (dst);
      /* A name with a trailing slash can only be a directory. */
      if (error == EISDIR && n && dst[n - 1] == '/')
        error = ENOTDIR;
      bcu_inst_fail ("cannot create regular file ", dst, "", error);
      close (rfd);
      return -1;
    }
  if (fstat (wfd, &ds) == 0 && ds.st_dev == ss.st_dev && ds.st_ino == ss.st_ino)
    {
      bcu_inst_same_file (src, dst);
      close (rfd);
      close (wfd);
      return -1;
    }
  int reading;
  const char *offload, *reflink;
  int error = bcu_inst_copy_data (rfd, wfd, &ss, &reading, &offload, &reflink);
  close (rfd);
  if (error)
    {
      bcu_inst_fail (reading ? "error reading " : "error writing ",
                     reading ? src : dst, "", error);
      close (wfd);
      return -1;
    }
  if (o->debug)
    printf ("copy offload: %s, reflink: %s, sparse detection: no\n", offload, reflink);
  struct timespec times[2] = { ss.st_atim, ss.st_mtim };
  if (o->preserve_times && futimens (wfd, times) < 0)
    {
      bcu_inst_fail ("cannot set timestamps for ", dst, "", errno);
      close (wfd);
      return -1;
    }
  if (close (wfd) < 0)
    {
      bcu_inst_fail ("error writing ", dst, "", errno);
      return -1;
    }
  if (o->strip)
    {
      if (bcu_inst_strip (o, dst) < 0)
        {
          unlink (dst);
          return -1;
        }
      /* The strip program rewrote the file, so its times are new again. */
      if (o->preserve_times && utimensat (AT_FDCWD, dst, times, 0) < 0)
        {
          bcu_inst_fail ("cannot set timestamps for ", dst, "", errno);
          return -1;
        }
    }
  if ((o->uid != (uid_t) -1 || o->gid != (gid_t) -1) && lchown (dst, o->uid, o->gid) < 0)
    {
      bcu_inst_fail ("cannot change ownership of ", dst, "", errno);
      return -1;
    }
  /* Ownership changes may clear set-ID bits: the mode comes last. */
  if (chmod (dst, o->file_mode) < 0)
    {
      bcu_inst_fail ("cannot change permissions of ", dst, "", errno);
      return -1;
    }
  return 0;
}

/* DIR/NAME's last component, as installing NAME into DIR names it. */
static char *
bcu_inst_join (const char *dir, const char *name)
{
  size_t dl = strlen (dir);
  while (dl > 1 && dir[dl - 1] == '/')
    dl--;
  const char *base = strrchr (name, '/');
  base = base ? base + 1 : name;
  char *out = xmalloc (dl + strlen (base) + 2);
  memcpy (out, dir, dl);
  if (!dl || dir[dl - 1] != '/')
    out[dl++] = '/';
  strcpy (out + dl, base);
  return out;
}

/* The directory part of FILE (trailing slashes dropped), or NULL when it
   has none or it is the root. */
static char *
bcu_inst_parent (const char *file)
{
  size_t n = strlen (file);
  while (n > 1 && file[n - 1] == '/')
    n--;
  while (n > 0 && file[n - 1] != '/')
    n--;
  while (n > 0 && file[n - 1] == '/')
    n--;
  if (n == 0)
    return NULL;
  char *out = xmalloc (n + 1);
  memcpy (out, file, n);
  out[n] = '\0';
  return out;
}

/* Resolve an -o/-g operand: a known name, else a number (C base rules,
   as GNU install accepts "0x3e8" and "01750") that fits the ID type. */
static int
bcu_install_id (const char *name, int group, uintmax_t *id)
{
#if defined (BASHOS_STATIC) && defined (__GLIBC__)
  /* Static glibc cannot safely load arbitrary host NSS modules. Restrict
     named install identities to the local account files in this build. */
  FILE *accounts = fopen (group ? "/etc/group" : "/etc/passwd", "r");
  if (accounts)
    {
      int found = 0;
      if (group)
        {
          struct group *gr;
          while ((gr = fgetgrent (accounts)) != NULL)
            if (!strcmp (gr->gr_name, name)) { *id = gr->gr_gid; found = 1; break; }
        }
      else
        {
          struct passwd *pw;
          while ((pw = fgetpwent (accounts)) != NULL)
            if (!strcmp (pw->pw_name, name)) { *id = pw->pw_uid; found = 1; break; }
        }
      fclose (accounts);
      if (found) return 0;
    }
#else
  if (group)
    {
      struct group *gr = getgrnam (name);
      if (gr) { *id = gr->gr_gid; return 0; }
    }
  else
    {
      struct passwd *pw = getpwnam (name);
      if (pw) { *id = pw->pw_uid; return 0; }
    }
#endif
  const char *number = name;
  while (isspace ((unsigned char) *number)) number++;
  char *end;
  errno = 0;
  uintmax_t value = strtoumax (number, &end, 0);
  if (*number == '-' || end == number || *end || errno == ERANGE ||
      (group ? (uintmax_t) (gid_t) value : (uintmax_t) (uid_t) value) != value)
    {
      bcu_inst_fail (group ? "invalid group " : "invalid user ", name, "", 0);
      return -1;
    }
  *id = value;
  return 0;
}

static void
bcu_install_help (void)
{
  fputs ("Usage: install [OPTION]... [-T] SOURCE DEST\n"
         "  or:  install [OPTION]... SOURCE... DIRECTORY\n"
         "  or:  install [OPTION]... -t DIRECTORY SOURCE...\n"
         "  or:  install [OPTION]... -d DIRECTORY...\n"
         "\n"
         "In the first three forms, copy SOURCE to DEST or multiple SOURCE(s) to\n"
         "the existing DIRECTORY, while setting permission modes and owner/group.\n"
         "In the 4th form, create all components of the given DIRECTORY(ies).\n"
         "\n"
         "Mandatory arguments to long options are mandatory for short options too.\n"
         "      --backup[=CONTROL]  make a backup of each existing destination file\n"
         "  -b                  like --backup but does not accept an argument\n"
         "  -c                  (ignored)\n"
         "  -C, --compare       compare content of source and destination files, and\n"
         "                        if no change to content, ownership, and permissions,\n"
         "                        do not modify the destination at all\n"
         "  -d, --directory     treat all arguments as directory names; create all\n"
         "                        components of the specified directories\n"
         "  -D                  create all leading components of DEST except the last,\n"
         "                        or all components of --target-directory,\n"
         "                        then copy SOURCE to DEST\n"
         "      --debug         explain how a file is copied.  Implies -v\n"
         "  -g, --group=GROUP   set group ownership, instead of process' current group\n"
         "  -m, --mode=MODE     set permission mode (as in chmod), instead of rwxr-xr-x\n"
         "  -o, --owner=OWNER   set ownership (super-user only)\n"
         "  -p, --preserve-timestamps   apply access/modification times of SOURCE files\n"
         "                        to corresponding destination files\n"
         "  -s, --strip         strip symbol tables\n"
         "      --strip-program=PROGRAM  program used to strip binaries\n"
         "  -S, --suffix=SUFFIX  override the usual backup suffix\n"
         "  -t, --target-directory=DIRECTORY  copy all SOURCE arguments into DIRECTORY\n"
         "  -T, --no-target-directory  treat DEST as a normal file\n"
         "  -v, --verbose       print the name of each created file or directory\n"
         "      --preserve-context  preserve SELinux security context\n"
         "  -Z                      set SELinux security context of destination\n"
         "                            file and each created directory to default type\n"
         "      --context[=CTX]     like -Z, or if CTX is specified then set the\n"
         "                            SELinux or SMACK security context to CTX\n"
         "      --help        display this help and exit\n"
         "      --version     output version information and exit\n"
         "\n"
         "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX.\n"
         "The version control method may be selected via the --backup option or through\n"
         "the VERSION_CONTROL environment variable.  Here are the values:\n"
         "\n"
         "  none, off       never make backups (even if --backup is given)\n"
         "  numbered, t     make numbered backups\n"
         "  existing, nil   numbered if numbered backups exist, simple otherwise\n"
         "  simple, never   always make simple backups\n"
         "\n"
         "This build has no SELinux support: -Z and --context set no context.\n",
         stdout);
}

static int
bcu_install_run (WORD_LIST *list)
{
  enum { OPT_BACKUP = BOS_OPT_FIRST, OPT_DEBUG, OPT_STRIP_PROGRAM,
         OPT_PRESERVE_CONTEXT, OPT_CONTEXT };
  /* Table order decides the order of an ambiguity report's candidates. */
  static const struct bos_longopt longopts[] = {
    { "backup",              BOS_OPT_ARG, OPT_BACKUP },
    { "compare",             BOS_NO_ARG,  'C' },
    { "context",             BOS_OPT_ARG, OPT_CONTEXT },
    { "debug",               BOS_NO_ARG,  OPT_DEBUG },
    { "directory",           BOS_NO_ARG,  'd' },
    { "group",               BOS_REQ_ARG, 'g' },
    { "mode",                BOS_REQ_ARG, 'm' },
    { "no-target-directory", BOS_NO_ARG,  'T' },
    { "owner",               BOS_REQ_ARG, 'o' },
    { "preserve-timestamps", BOS_NO_ARG,  'p' },
    { "preserve-context",    BOS_NO_ARG,  OPT_PRESERVE_CONTEXT },
    { "strip",               BOS_NO_ARG,  's' },
    { "strip-program",       BOS_REQ_ARG, OPT_STRIP_PROGRAM },
    { "suffix",              BOS_REQ_ARG, 'S' },
    { "target-directory",    BOS_REQ_ARG, 't' },
    { "verbose",             BOS_NO_ARG,  'v' },
    { "version",             BOS_NO_ARG,  BOS_OPT_VERSION },
    { "help",                BOS_NO_ARG,  BOS_OPT_HELP },
    { NULL, 0, 0 }
  };
  bcu_inst o;
  bos_getopt g;
  int c, rc = EXECUTION_FAILURE, make_backups = 0, no_target = 0;
  const char *control = NULL, *suffix = NULL, *target = NULL;
  const char *mode_text = NULL, *owner = NULL, *group = NULL;
  char **ops = NULL;
  int n = 0, make_target = 0;
  const char *into = NULL;

  memset (&o, 0, sizeof o);
  o.uid = (uid_t) -1;
  o.gid = (gid_t) -1;
  o.file_mode = o.dir_mode = 0755;
  o.backup_kind = BOS_BACKUP_NONE;

  bos_getopt_init (&g, "install", "bcCdDg:m:o:psS:t:TvZ", longopts, list);
  while ((c = bos_getopt_next (&g)) != -1)
    switch (c)
      {
      case 'b': make_backups = 1; break;
      case OPT_BACKUP:
        make_backups = 1;
        if (g.optarg)
          control = g.optarg;
        break;
      case 'c': break;
      case 'C': o.compare = 1; break;
      case 'd': o.dir_arg = 1; break;
      case 'D': o.parents = 1; break;
      case 'g': group = g.optarg; break;
      case 'm': mode_text = g.optarg; break;
      case 'o': owner = g.optarg; break;
      case 'p': o.preserve_times = 1; break;
      case 's': o.strip = 1; break;
      case OPT_STRIP_PROGRAM: o.strip_program = g.optarg; break;
      case 'S': make_backups = 1; suffix = g.optarg; break;
      case 't':
        if (target)
          {
            builtin_error ("multiple target directories specified");
            goto done;
          }
        target = g.optarg;
        break;
      case 'T': no_target = 1; break;
      case 'v': o.verbose = 1; break;
      case OPT_DEBUG: o.debug = o.verbose = 1; break;
      case 'Z': break;
      case OPT_PRESERVE_CONTEXT:
        builtin_error ("WARNING: ignoring --preserve-context; this kernel is not SELinux-enabled");
        break;
      case OPT_CONTEXT:
        if (g.optarg)
          builtin_error ("warning: ignoring --context; it requires an SELinux-enabled kernel");
        break;
      case BOS_OPT_HELP:
        bcu_install_help ();
        rc = sh_chkwrite (EXECUTION_SUCCESS);
        goto done;
      case BOS_OPT_VERSION:
        puts ("install (bash-os coreutils)");
        rc = sh_chkwrite (EXECUTION_SUCCESS);
        goto done;
      default:
        goto done;
      }

  ops = g.operands;
  n = g.noperands;

  if (make_backups)
    {
      o.backup_kind = bos_backup_kind ("install", control);
      if (o.backup_kind < 0)
        goto done;
      o.suffix = bos_backup_suffix (suffix);
    }
  if (o.dir_arg && o.strip)
    {
      builtin_error ("the strip option may not be used when installing a directory");
      goto done;
    }
  if (o.dir_arg && target)
    {
      builtin_error ("target directory not allowed when installing a directory");
      goto done;
    }
  if (n < (o.dir_arg || target ? 1 : 2))
    {
      if (n == 0)
        builtin_error ("missing file operand");
      else
        bcu_inst_fail ("missing destination file operand after ", ops[0], "", 0);
      bos_try_help ("install");
      goto done;
    }
  if (no_target)
    {
      if (target)
        {
          builtin_error ("cannot combine --target-directory (-t) and --no-target-directory (-T)");
          goto done;
        }
      if (n > 2)
        {
          bcu_inst_fail ("extra operand ", ops[2], "", 0);
          bos_try_help ("install");
          goto done;
        }
    }

  /* Where the files go: the -t directory (made later under -D when it is
     missing), a last operand that is a directory, or the one DEST. */
  if (!o.dir_arg)
    {
      struct stat st;
      if (target)
        {
          int error = stat (target, &st) < 0 ? errno : S_ISDIR (st.st_mode) ? 0 : ENOTDIR;
          into = target;
          if (error)
            {
              if (!(o.parents && error == ENOENT))
                {
                  bcu_inst_fail ("failed to access ", target, "", error);
                  goto done;
                }
              make_target = 1;
            }
        }
      else if (!no_target)
        {
          const char *last = ops[n - 1];
          if (stat (last, &st) == 0 && S_ISDIR (st.st_mode))
            {
              into = last;
              n--;
            }
          else if (n > 2)
            {
              bcu_inst_fail ("target ", last, "", stat (last, &st) == 0 ? ENOTDIR : errno);
              goto done;
            }
        }
    }

  if (o.strip_program && !o.strip)
    builtin_error ("WARNING: ignoring --strip-program option as -s option was not specified");
  if (o.compare && (o.preserve_times || o.strip))
    {
      builtin_error ("options --compare (-C) and --%s are mutually exclusive",
                     o.preserve_times ? "preserve-timestamps" : "strip");
      bos_try_help ("install");
      goto done;
    }
  if (mode_text)
    {
      int nomem = 0;
      o.mode_change = bos_mode_compile (mode_text, &nomem);
      if (!o.mode_change)
        {
          if (nomem)
            builtin_error ("memory exhausted");
          else
            {
              char *q = bos_quote (mode_text);
              builtin_error ("invalid mode %s", q ? q : mode_text);
              free (q);
            }
          goto done;
        }
      o.file_mode = bos_mode_adjust (0, 0, 0, o.mode_change, NULL) & BOS_MODE_BITS;
      o.dir_mode = bos_mode_adjust (0, 1, 0, o.mode_change, NULL) & BOS_MODE_BITS;
    }
  if (o.compare && (o.file_mode & ~BOS_MODE_RWX))
    {
      builtin_error ("the --compare (-C) option is ignored when you specify a mode with non-permission bits");
      o.compare = 0;
    }
  if (owner)
    {
      uintmax_t id;
      if (bcu_install_id (owner, 0, &id) < 0)
        goto done;
      o.uid = (uid_t) id;
    }
  if (group)
    {
      uintmax_t id;
      if (bcu_install_id (group, 1, &id) < 0)
        goto done;
      o.gid = (gid_t) id;
    }

  rc = EXECUTION_SUCCESS;
  if (o.dir_arg)
    {
      for (int i = 0; i < n; i++)
        {
          QUIT;
          if (bcu_inst_make_dir (&o, ops[i]) < 0)
            rc = EXECUTION_FAILURE;
        }
    }
  else if (into)
    {
      if (make_target)
        {
          struct stat st;
          if (bcu_inst_mkdirs (&o, target, 1) < 0)
            {
              rc = EXECUTION_FAILURE;
              goto done;
            }
          int error = stat (target, &st) < 0 ? errno : S_ISDIR (st.st_mode) ? 0 : ENOTDIR;
          if (error)
            {
              bcu_inst_fail ("failed to access ", target, "", error);
              rc = EXECUTION_FAILURE;
              goto done;
            }
        }
      for (int i = 0; i < n; i++)
        {
          QUIT;
          char *dst = bcu_inst_join (into, ops[i]);
          if (bcu_inst_file (&o, ops[i], dst) < 0)
            rc = EXECUTION_FAILURE;
          free (dst);
        }
    }
  else
    {
      char *parent = o.parents ? bcu_inst_parent (ops[1]) : NULL;
      if (parent && bcu_inst_mkdirs (&o, parent, 1) < 0)
        rc = EXECUTION_FAILURE;
      else if (bcu_inst_file (&o, ops[0], ops[1]) < 0)
        rc = EXECUTION_FAILURE;
      free (parent);
    }

done:
  free (o.mode_change);
  bos_getopt_free (&g);
  return rc;
}

static int
bcu_install_cmd (WORD_LIST *list)
{
  char *saved = this_command_name;
  this_command_name = (char *) "install";
  int rc = bcu_install_run (list);
  this_command_name = saved;
  return rc;
}

/* ===================================================================
 * mknod — create device or fifo.
 *
 *   mknod PATH p              named pipe (any uid; matches mkfifo)
 *   mknod PATH b MAJ MIN      block device (root only)
 *   mknod PATH c MAJ MIN      character device (root only)
 * =================================================================== */

extern char *this_command_name;

static int
bcu_mknod_try (void)
{
  fprintf (stderr, "Try 'mknod --help' for more information.\n");
  return EXECUTION_FAILURE;
}

/* GNU's parser: an octal permission mode only. */
static int
bcu_mknod_mode (const char *text, mode_t *mode)
{
  char *end = NULL;
  unsigned long m = strtoul (text, &end, 8);
  if (!*text || end == text || *end != '\0' || m > 07777)
    { builtin_error ("invalid mode"); return -1; }
  if (m & ~0777UL)
    { builtin_error ("mode must specify only file permission bits"); return -1; }
  *mode = (mode_t) m;
  return 0;
}

static int
bcu_mknod_number (const char *text, unsigned long long *value)
{
  char *end = NULL;
  if (!isdigit ((unsigned char) *text))
    return -1;
  errno = 0;
  *value = strtoull (text, &end, 0);
  return (errno || end == text || *end != '\0') ? -1 : 0;
}

static int
bcu_mknod_run (WORD_LIST *list)
{
  mode_t mode = 0666;
  int explicit_mode = 0, options = 1;
  const char *pos[5];
  int npos = 0;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      const char *value = NULL;
      if (!options || a[0] != '-' || a[1] == '\0')
        {
          if (npos < 5) pos[npos] = a;
          npos++;
          continue;
        }
      if (strcmp (a, "--") == 0) { options = 0; continue; }
      if (strncmp (a, "--mode=", 7) == 0)
        value = a + 7;
      else if (strcmp (a, "--mode") == 0 || strcmp (a, "-m") == 0)
        {
          if (!w->next)
            {
              if (a[1] == '-') builtin_error ("option '--mode' requires an argument");
              else builtin_error ("option requires an argument -- 'm'");
              return bcu_mknod_try ();
            }
          w = w->next;
          value = w->word->word;
        }
      else if (a[1] == 'm')
        value = a + 2;
      else
        {
          if (a[1] == '-') builtin_error ("unrecognized option '%s'", a);
          else builtin_error ("invalid option -- '%c'", a[1]);
          return bcu_mknod_try ();
        }
      if (bcu_mknod_mode (value, &mode) < 0)
        return EXECUTION_FAILURE;
      explicit_mode = 1;
    }

  /* A FIFO takes NAME and TYPE; every other type also MAJOR and MINOR. */
  int expected = (npos > 1 && pos[1][0] == 'p') ? 2 : 4;
  if (npos < expected)
    {
      if (npos == 0)
        builtin_error ("missing operand");
      else
        {
          char *q = bos_quote (pos[npos - 1]);
          builtin_error ("missing operand after %s", q ? q : pos[npos - 1]);
          free (q);
        }
      if (expected == 4 && npos == 2)
        fprintf (stderr, "Special files require major and minor device numbers.\n");
      return bcu_mknod_try ();
    }
  if (npos > expected)
    {
      char *q = bos_quote (pos[expected]);
      builtin_error ("extra operand %s", q ? q : pos[expected]);
      free (q);
      if (expected == 2 && npos == 4)
        fprintf (stderr, "Fifos do not have major and minor device numbers.\n");
      return bcu_mknod_try ();
    }

  const char *path = pos[0];
  mode_t kind;
  dev_t device = 0;
  switch (pos[1][0])
    {
    case 'b': kind = S_IFBLK; break;
    case 'c': case 'u': kind = S_IFCHR; break;
    case 'p': kind = S_IFIFO; break;
    default:
      {
        char *q = bos_quote (pos[1]);
        builtin_error ("invalid device type %s", q ? q : pos[1]);
        free (q);
        return bcu_mknod_try ();
      }
    }
  if (kind != S_IFIFO)
    {
      unsigned long long maj, min_;
      if (bcu_mknod_number (pos[2], &maj) < 0 || maj > UINT_MAX)
        {
          char *q = bos_quote (pos[2]);
          builtin_error ("invalid major device number %s", q ? q : pos[2]);
          free (q);
          return EXECUTION_FAILURE;
        }
      if (bcu_mknod_number (pos[3], &min_) < 0 || min_ > UINT_MAX)
        {
          char *q = bos_quote (pos[3]);
          builtin_error ("invalid minor device number %s", q ? q : pos[3]);
          free (q);
          return EXECUTION_FAILURE;
        }
      device = makedev ((unsigned) maj, (unsigned) min_);
      if (major (device) != (unsigned) maj || minor (device) != (unsigned) min_)
        {
          builtin_error ("invalid device %s %s", pos[2], pos[3]);
          return EXECUTION_FAILURE;
        }
    }

  /* An explicit mode is independent of the caller's umask. Apply it at
     creation, without chmod on a pathname that may already exist. */
  mode_t saved_mask = explicit_mode ? umask (0) : 0;
  int result = kind == S_IFIFO ? mkfifo (path, mode) : mknod (path, mode | kind, device);
  int saved_errno = errno;
  if (explicit_mode) umask (saved_mask);
  if (result < 0)
    {
      builtin_error ("%s: %s", path, strerror (saved_errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* Diagnostics carry the program name GNU mknod prints. */
static int
bcu_mknod_cmd (WORD_LIST *list)
{
  char *saved = this_command_name;
  this_command_name = (char *) "mknod";
  int rc = bcu_mknod_run (list);
  this_command_name = saved;
  return rc;
}

/* ===================================================================
 * Bash builtin dispatch.
 * =================================================================== */

static int
bcu_dispatch (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *verb = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (verb, "tac")     == 0) return bcu_tac_cmd     (args);
  if (strcmp (verb, "shuf")    == 0) return bcu_shuf_cmd    (args);
  if (strcmp (verb, "factor")  == 0) return bcu_factor_cmd  (args);
  if (strcmp (verb, "yes")     == 0) return bcu_yes_cmd     (args);
  if (strcmp (verb, "fmt")     == 0) return bcu_fmt_cmd     (args);
  if (strcmp (verb, "tsort")   == 0) return bcu_tsort_cmd   (args);
  if (strcmp (verb, "printf")  == 0) return bcu_printf_cmd  (args);
  if (strcmp (verb, "nproc")   == 0) return bcu_nproc_cmd   (args);
  if (strcmp (verb, "numfmt")  == 0) return bcu_numfmt_cmd  (args);
  if (strcmp (verb, "shred")   == 0) return bcu_shred_cmd   (args);
  if (strcmp (verb, "groups")  == 0) return bcu_groups_cmd  (args);
  if (strcmp (verb, "install") == 0) return bcu_install_cmd (args);
  if (strcmp (verb, "mknod")   == 0) return bcu_mknod_cmd   (args);
  builtin_error ("coreutils: unknown verb: %s", verb);
  builtin_error ("usage: coreutils {tac|shuf|factor|yes|fmt|tsort|printf|nproc|numfmt|shred|groups|install|mknod} ARGS");
  return EX_USAGE;
}

int
coreutils_builtin (WORD_LIST *list)
{
  int rc = bcu_dispatch (list);
  if (fflush (stdout) == EOF || ferror (stdout))
    {
      builtin_error ("write: %s", strerror (errno ? errno : EIO));
      clearerr (stdout);
      rc = EXECUTION_FAILURE;
    }
  return rc;
}

char *coreutils_doc[] = {
  "Bundle of 13 small POSIX coreutils as a single bash loadable.",
  "",
  "    coreutils tac    [FILE...]",
  "    coreutils shuf   [-erz] [-i LO-HI] [-n COUNT] [-o FILE] [--random-source=FILE]",
  "                     [FILE | ARG...]",
  "        GNU shuf: -e/--echo, -i/--input-range, -n/--head-count, -o/--output,",
  "        -r/--repeat, -z/--zero-terminated; long-option prefixes.",
  "    coreutils factor [-h|--exponents] [NUMBER]...",
  "        GNU factor: integers of any size (trial division, Pollard-Brent rho,",
  "        Miller-Rabin and Baillie-PSW); numbers from standard input when none",
  "        are given; -h prints p^e.",
  "    coreutils yes    [STRING...]",
  "    coreutils fmt    [-WIDTH] [-cstu] [-w WIDTH] [-g GOAL] [-p PREFIX] [FILE...]",
  "        GNU fmt: -c crown margin, -s split only, -t tagged paragraph,",
  "        -u uniform spacing, -p reformat only lines starting with PREFIX.",
  "    coreutils tsort  [FILE]",
  "        GNU tsort: a loop is reported on stderr, sorting goes on, status 1.",
  "    coreutils printf FORMAT [ARGUMENT]...",
  "        GNU printf: \\ escapes, %b, %q, %N$ positions, * widths; reuses FORMAT",
  "        until the arguments are used up.",
  "    coreutils nproc  [--all] [--ignore=N]",
  "    coreutils numfmt [--from=UNIT] [--to=UNIT] [--from-unit=N] [--to-unit=N]",
  "                     [--round=METHOD] [--suffix=S] [--padding=N] [--grouping]",
  "                     [--format=FMT] [--field=FIELDS] [-d X] [--header[=N]]",
  "                     [--invalid=MODE] [-z] [NUMBER...]",
  "        UNIT none|auto|si|iec|iec-i; METHOD up|down|from-zero|towards-zero|nearest;",
  "        MODE abort|fail|warn|ignore. Conversion errors exit 2.",
  "    coreutils shred  [-fuvxz] [-n N] [-s SIZE] [--remove[=HOW]] FILE...",
  "    coreutils groups [USER...]",
  "    coreutils install [OPTION]... [-T] SOURCE DEST | SOURCE... DIRECTORY",
  "    coreutils install [OPTION]... -t DIRECTORY SOURCE... | -d DIRECTORY...",
  "        GNU install: -b, --backup[=CONTROL], -S/--suffix, -c, -C/--compare,",
  "        -d/--directory, -D, -g/--group, -m/--mode (octal or symbolic), -o/--owner,",
  "        -p/--preserve-timestamps, -s/--strip, --strip-program, -t/--target-directory,",
  "        -T, -v/--verbose, --debug, -Z/--context (no SELinux here); long-option",
  "        prefixes; diagnostics read \"install: ...\"; see coreutils install --help.",
  "    coreutils mknod  [-m MODE] PATH {b|c|p} [MAJ MIN]",
  "",
  "POSIX cmd-name wrappers in /bash-os/<verb>.sh exec the verb directly.",
  (char *)NULL
};

struct builtin coreutils_struct = {
  "coreutils",
  coreutils_builtin,
  BUILTIN_ENABLED,
  coreutils_doc,
  "coreutils VERB [ARGS...]",
  0
};
