/* SPDX-License-Identifier: MIT */
/* column.c — bundled column(1) / col(1) / colrm(1) bash loadable.
 *
 * Phase MISSING_LOADABLES T2 of bash-os (ML-T2-11).
 *
 * Three small text utilities, one .c, three exported builtins so each
 * registered name (column, col, colrm) dispatches to its
 * own argv handler via the builtin lookup table. Sibling .c files
 * (col.c, colrm.c) are empty stubs — they exist only so the
 * patch-bash-loadables.sh `cp examples/loadables/${name}.c` step has
 * a file at the expected path; the actual struct/_builtin/_doc
 * symbols are exported from this translation unit.
 *
 *   column [-t] [-s SEPSTR] [-o OUTSTR] [FILE...]
 *      Aligned table mode. SEPSTR (default " \t") names the set of
 *      bytes that separate input fields. Without -s, runs of those
 *      bytes collapse into one separator; with -s, each char in
 *      SEPSTR splits, so consecutive separators produce empty
 *      fields (matching `column -s : -t /etc/passwd`). OUTSTR
 *      (default "  ") joins output columns. Missing fields are padded
 *      through the final table column, which is not right-padded.
 *      Option parsing follows getopt shape for the implemented
 *      options, so `-ts :`, `-s:`, and `-o::` are accepted.
 *      Non-table mode supports `-S N` / `--use-spaces=N` as the
 *      util-linux no-tabs layout knob.
 *      Cells are padded by display width: wcwidth(3) under a multibyte
 *      locale (an invalid byte counts one column), bytes under C.
 *      -N NAMES / --table-columns=NAMES (comma-separated) prints a header
 *      row. -J / --json prints the table as util-linux JSON instead: keys
 *      are the -N names in ASCII lower case, the array is -n NAME /
 *      --table-name=NAME (default "table"), empty or missing cells are
 *      null, and a row with more fields than names is an error.
 *      -l N / --table-columns-limit=N makes the N-th field the rest of the
 *      line. -R / --table-right, -H / --table-hide and -O / --table-order
 *      take util-linux column lists (names, numbers, ranges, 0, -1, and
 *      '-' for -H) to right-align, hide and reorder columns.
 *
 *   col [-b] [FILE...]
 *      Preserve CTL-H (backspace) overstrike sequences by default. With
 *      -b the backspace and the preceding character are both removed.
 *      Escape pairs, including ESC-7 (reverse linefeed), are dropped by
 *      this focused filter. Invalid
 *      multibyte bytes are escaped as \xNN; decoded C1 controls are dropped.
 *
 *   colrm [START [END]]
 *      Remove display columns START..END (1-based, inclusive). Tabs advance
 *      to eight-column stops, backspaces retreat one column, and multibyte
 *      characters use their locale display widths. Partially removed tabs
 *      and wide characters leave spaces for the surviving cells. A zero
 *      START passes input through; END zero means through end-of-line.
 *
 * Source counterparts (read for spec shape, not vendored):
 *   research/refs/util-linux/text-utils/column.c
 *   research/refs/util-linux/text-utils/col.c
 *   research/refs/util-linux/text-utils/colrm.c
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c / bashfold.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <wchar.h>

#include "loadables.h"

#ifndef BCOL_MAX_FILES
#  define BCOL_MAX_FILES 256
#endif

/* ===================================================================
 * Shared helpers — stream slurp and getline-style read.
 * =================================================================== */

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF and read-ahead across redirections. Repeated '-' operands share
   this stream. Never fclose stdin. */
static FILE *
bcol_open_stdin (void)
{
  int fd = dup (STDIN_FILENO);
  FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
  if (!in)
    {
      int error = errno;
      if (fd >= 0)
        close (fd);
      builtin_error ("stdin: %s", strerror (error));
    }
  return in;
}

static FILE *
bcol_open (const char *path, FILE **in_stdin)
{
  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    {
      if (*in_stdin == NULL)
        *in_stdin = bcol_open_stdin ();
      return *in_stdin;
    }
  FILE *fp = fopen (path, "r");
  if (!fp)
    builtin_error ("%s: %s", path, strerror (errno));
  return fp;
}

/* Read one line including its newline (if any) into *out (malloc'd or
 * realloc'd; caller frees). Returns the byte length (0 = EOF with no
 * data, -1 = ferror). The trailing '\n' is included in the count when
 * present; callers strip it themselves. */
static ssize_t
bcol_getline (FILE *fp, char **out, size_t *cap)
{
  if (*out == NULL || *cap == 0)
    {
      *cap = 256;
      *out = malloc (*cap);
      if (!*out)
        return -1;
    }
  size_t len = 0;
  int c;
  while ((c = fgetc (fp)) != EOF)
    {
      if (len + 1 >= *cap)
        {
          size_t ncap = *cap * 2;
          char *nb = realloc (*out, ncap);
          if (!nb)
            return -1;
          *out = nb;
          *cap = ncap;
        }
      (*out)[len++] = (char) c;
      if (c == '\n')
        break;
    }
  if (ferror (fp))
    return -1;
  return (ssize_t) len;
}

/* column ignores whitespace-only records in both layout modes. */
static int
bcol_blank (const char *line, size_t len)
{
  for (size_t i = 0; i < len; i++)
    if (!isspace ((unsigned char) line[i]))
      return 0;
  return 1;
}

/* ===================================================================
 * column verb.
 * =================================================================== */

typedef struct
{
  char **fields;    /* malloc'd field strings */
  int n;            /* count */
  int cap;          /* capacity */
} bcol_row;

static void
bcol_row_free (bcol_row *r)
{
  for (int i = 0; i < r->n; i++)
    free (r->fields[i]);
  free (r->fields);
  r->fields = NULL;
  r->n = 0;
  r->cap = 0;
}

static int
bcol_row_push (bcol_row *r, const char *s, size_t len)
{
  if (r->n >= r->cap)
    {
      int ncap = r->cap ? r->cap * 2 : 8;
      char **nf = realloc (r->fields, (size_t) ncap * sizeof (*nf));
      if (!nf)
        return -1;
      r->fields = nf;
      r->cap = ncap;
    }
  char *copy = malloc (len + 1);
  if (!copy)
    return -1;
  memcpy (copy, s, len);
  copy[len] = '\0';
  r->fields[r->n++] = copy;
  return 0;
}

/* Split LINE into fields using SEPS. If sflag is 0 (no -s given) runs
 * of any byte in SEPS collapse into one separator and leading runs are
 * skipped. If sflag is 1 each separator byte makes one cut, so
 * consecutive separators yield empty fields. With LIMIT (-l) the
 * LIMIT-th field is the rest of the line, separators and all. */
static int
bcol_split (const char *line, size_t len, const char *seps, int sflag,
            long limit, bcol_row *out)
{
  size_t i = 0;
  if (!sflag)
    {
      while (i < len && strchr (seps, line[i]))
        i++;
      while (i < len)
        {
          if (limit && out->n == limit - 1)
            return bcol_row_push (out, line + i, len - i);
          size_t j = i;
          while (j < len && !strchr (seps, line[j]))
            j++;
          if (bcol_row_push (out, line + i, j - i) != 0)
            return -1;
          while (j < len && strchr (seps, line[j]))
            j++;
          i = j;
        }
      return 0;
    }
  /* sflag: split on every separator byte. */
  size_t start = 0;
  for (i = 0; i < len && !(limit && out->n == limit - 1); i++)
    {
      if (strchr (seps, line[i]))
        {
          if (bcol_row_push (out, line + start, i - start) != 0)
            return -1;
          start = i + 1;
        }
    }
  if (bcol_row_push (out, line + start, len - start) != 0)
    return -1;
  return 0;
}

static size_t bcol_character (const char *s, size_t len, wchar_t *wc, int *valid);

/* Display width of a cell: wcwidth under a multibyte locale, where an
   invalid byte occupies one column and nonprinting characters none; byte
   count under a single-byte locale such as C. */
static size_t
bcol_width (const char *s)
{
  size_t len = strlen (s), width = 0;
  if (MB_CUR_MAX == 1)
    return len;
  for (size_t i = 0; i < len;)
    {
      wchar_t wc;
      int valid;
      i += bcol_character (s + i, len - i, &wc, &valid);
      int w = valid ? wcwidth (wc) : 1;
      if (w > 0)
        width += (size_t) w;
    }
  return width;
}

/* util-linux JSON string: quote and backslash escaped, C0 controls as \b
   \f \n \r \t or \u00XX, DEL dropped, and a byte that is not a valid
   character in the locale written as the text \\xNN. Names (LOWER) are
   folded to ASCII lower case. */
static void
bcol_json_string (const char *s, int lower)
{
  size_t len = strlen (s);
  putchar ('"');
  for (size_t i = 0; i < len;)
    {
      unsigned char c = (unsigned char) s[i];
      if (c < 0x80 || lower)
        {
          if (c == '"' || c == '\\')
            { putchar ('\\'); putchar (c); }
          else if (c < 0x20)
            {
              const char *named = strchr ("\bb\ff\nn\rr\tt", c);
              if (named)
                printf ("\\%c", named[1]);
              else
                printf ("\\u%04x", c);
            }
          else if (c != 0x7f)
            putchar (lower && c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
          i++;
          continue;
        }
      wchar_t wc;
      int valid = 0;
      size_t n = MB_CUR_MAX > 1 ? bcol_character (s + i, len - i, &wc, &valid) : 1;
      if (valid)
        fwrite (s + i, 1, n, stdout);
      else
        printf ("\\\\x%02x", c);
      i += n;
    }
  putchar ('"');
}

/* Split -N NAMES at commas; empty names are skipped (util-linux). */
static int
bcol_names (const char *spec, bcol_row *names)
{
  const char *p = spec;
  while (*p)
    {
      const char *end = strchr (p, ',');
      size_t len = end ? (size_t) (end - p) : strlen (p);
      if (len && bcol_row_push (names, p, len) != 0)
        return -1;
      p += len;
      if (*p == ',')
        p++;
    }
  return 0;
}

/* -R, -H and -O name columns by -N name, by number from 1, by a range
   of numbers (A-B), as 0 for all of them, '-' for every column without a
   name, or -1 for the last one not hidden. Each
   column named in SPEC gets FLAG; ORDER (for -O, where only names,
   numbers and -1 count) instead gets the columns appended in turn. A
   column named twice in -O is placed once (util-linux 2.41 then drops
   another column, which is not copied here).
   Returns -1, after util-linux's message, for an unknown name. */
static int
bcol_columns (const char *spec, const bcol_row *names, int n_cols,
              const char *hidden, char *flag, int *order, int *n_order)
{
  const char *p = spec;
  while (*p)
    {
      const char *end = strchr (p, ',');
      size_t len = end ? (size_t) (end - p) : strlen (p);
      int from = -1, to = -2;
      for (int k = 0; k < names->n && from < 0; k++)
        if (strlen (names->fields[k]) == len && !strncmp (names->fields[k], p, len))
          from = to = k;
      size_t digits = strspn (p, "0123456789");
      if (from >= 0)
        ;
      else if (len == 2 && !strncmp (p, "-1", 2))
        {
          for (int k = n_cols - 1; k >= 0 && from < 0; k--)
            if (!hidden || !hidden[k])
              from = to = k;
        }
      else if (!order && len == 1 && *p == '-')
        from = names->n, to = n_cols - 1;
      else if (digits && digits == len)
        {
          long v = strtol (p, NULL, 10);
          if (v == 0 && !order)
            from = 0, to = n_cols - 1;
          else if (v >= 1 && v <= n_cols)
            from = to = (int) v - 1;
        }
      else if (!order && digits && digits < len && p[digits] == '-'
               && strspn (p + digits + 1, "0123456789") == len - digits - 1
               && len > digits + 1)
        {
          long a = strtol (p, NULL, 10), b = strtol (p + digits + 1, NULL, 10);
          from = a < 1 ? 0 : (int) (a - 1);
          to = b > n_cols ? n_cols - 1 : (int) (b - 1);
          if (from > to)
            from = 0, to = -1;
        }
      if (from < 0 && len)
        {
          builtin_error ("undefined column name '%.*s'", (int) len, p);
          return -1;
        }
      for (int k = from; k <= to && k >= 0; k++)
        {
          if (!order)
            flag[k] = 1;
          else if (!flag[k])
            {
              flag[k] = 1;
              order[(*n_order)++] = k;
            }
        }
      p += len;
      if (*p == ',')
        p++;
    }
  return 0;
}

static void
bcol_json (bcol_row *rows, int n_rows, const bcol_row *names, const char *tname,
           const int *vis, int n_vis)
{
  if (n_rows == 0)
    return;
  int last = -1;
  for (int i = 0; i < n_vis; i++)
    if (vis[i] < names->n)
      last = i;
  fputs ("{\n   ", stdout);
  bcol_json_string (tname, 1);
  fputs (": [\n", stdout);
  for (int r = 0; r < n_rows; r++)
    {
      fputs (r ? "      },{\n" : "      {\n", stdout);
      if (last < 0)
        putchar ('\n');
      for (int i = 0; i <= last; i++)
        {
          int k = vis[i];
          if (k >= names->n)
            continue;
          fputs ("         ", stdout);
          bcol_json_string (names->fields[k], 1);
          fputs (": ", stdout);
          if (k < rows[r].n && rows[r].fields[k][0])
            bcol_json_string (rows[r].fields[k], 0);
          else
            fputs ("null", stdout);
          fputs (i < last ? ",\n" : "\n", stdout);
        }
    }
  fputs ("      }\n   ]\n}\n", stdout);
}

/* -l NUMBER: util-linux's strtou32 check and messages. */
static int
bcol_limit (const char *arg, long *limit)
{
  const char *p = arg;
  char *end;
  while (isspace ((unsigned char) *p))
    p++;
  errno = 0;
  unsigned long long v = *p == '-' ? 0 : strtoull (p, &end, 10);
  if (*p == '-' || (!errno && v > 0xffffffffULL))
    errno = ERANGE;
  else if (!errno && (end == p || *end))
    {
      builtin_error ("invalid columns limit argument: '%s'", arg);
      return -1;
    }
  if (errno)
    {
      builtin_error ("invalid columns limit argument: '%s': %s", arg, strerror (errno));
      return -1;
    }
  if (v == 0)
    {
      builtin_error ("columns limit must be greater than zero");
      return -1;
    }
  *limit = (long) v;
  return 0;
}

/* The table options that take a column list or a number, long and short. */
static const struct { const char *name; char c; } bcol_table_opts[] = {
  { "table-right", 'R' }, { "table-hide", 'H' }, { "table-order", 'O' },
  { "table-columns-limit", 'l' },
};

int
column_builtin (WORD_LIST *list)
{
  const char *seps = " \t";
  const char *outsep = "  ";
  int sflag = 0;
  int tflag = 0;
  int xflag = 0;
  long output_width = 80;
  long use_spaces = -1;
  const char *files[BCOL_MAX_FILES];
  int n_files = 0;
  int jflag = 0;
  const char *colnames = NULL;      /* -N NAMES */
  const char *tname = NULL;         /* -n NAME */
  const char *table_spec[3] = { NULL, NULL, NULL };   /* -R, -H, -O */
  long limit = 0;                   /* -l NUMBER */

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            if (n_files < BCOL_MAX_FILES)
              files[n_files++] = p->word->word;
          break;
        }
      if (strcmp (w, "--help") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("column 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--table") == 0)
        { tflag = 1; continue; }
      if (strcmp (w, "--fillrows") == 0)
        { xflag = 1; continue; }
      if (strcmp (w, "--json") == 0)
        { jflag = 1; continue; }
      if (strncmp (w, "--table-columns=", 16) == 0)
        { colnames = w + 16; continue; }
      if (strncmp (w, "--table-name=", 13) == 0)
        { tname = w + 13; continue; }
      if (strcmp (w, "--table-columns") == 0 || strcmp (w, "--table-name") == 0)
        {
          if (!p->next)
            {
              builtin_error ("option '%s' requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          if (w[8] == 'c')
            colnames = p->next->word->word;
          else
            tname = p->next->word->word;
          p = p->next;
          continue;
        }
      {
        const char *arg = NULL;
        int which = -1;
        for (size_t k = 0; k < sizeof bcol_table_opts / sizeof bcol_table_opts[0]; k++)
          {
            size_t nl = strlen (bcol_table_opts[k].name);
            if (strncmp (w, "--", 2) || strncmp (w + 2, bcol_table_opts[k].name, nl))
              continue;
            if (w[2 + nl] == '=')
              arg = w + 3 + nl;
            else if (w[2 + nl])
              continue;
            which = (int) k;
            break;
          }
        if (which >= 0)
          {
            if (!arg)
              {
                if (!p->next)
                  {
                    builtin_error ("option '%s' requires an argument", w);
                    return EXECUTION_FAILURE;
                  }
                p = p->next;
                arg = p->word->word;
              }
            if (bcol_table_opts[which].c == 'l')
              {
                if (bcol_limit (arg, &limit) < 0)
                  return EXECUTION_FAILURE;
              }
            else
              table_spec[which] = arg;
            continue;
          }
      }
      if (strcmp (w, "--output-width") == 0)
        {
          char *endp = NULL;
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          errno = 0;
          output_width = strtol (p->next->word->word, &endp, 10);
          if (errno || endp == p->next->word->word || !endp || *endp || output_width < 0)
            {
              builtin_error ("column: bad output width: %s", p->next->word->word);
              builtin_usage ();
              return EXECUTION_FAILURE;
            }
          p = p->next;
          continue;
        }
      if (strncmp (w, "--output-width=", 15) == 0)
        {
          char *endp = NULL;
          errno = 0;
          output_width = strtol (w + 15, &endp, 10);
          if (errno || endp == w + 15 || !endp || *endp || output_width < 0)
            {
              builtin_error ("column: bad output width: %s", w + 15);
              builtin_usage ();
              return EXECUTION_FAILURE;
            }
          continue;
        }
      if (strcmp (w, "--use-spaces") == 0)
        {
          char *endp = NULL;
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          use_spaces = strtol (p->next->word->word, &endp, 10);
          if (!endp || *endp || use_spaces < 1)
            {
              builtin_error ("column: bad use-spaces value: %s", p->next->word->word);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next;
          continue;
        }
      if (strncmp (w, "--use-spaces=", 13) == 0)
        {
          char *endp = NULL;
          use_spaces = strtol (w + 13, &endp, 10);
          if (!endp || *endp || use_spaces < 1)
            {
              builtin_error ("column: bad use-spaces value: %s", w + 13);
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }
      if (strcmp (w, "--separator") == 0
          || strcmp (w, "--input-separator") == 0)
        {
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          seps = p->next->word->word;
          sflag = 1;
          p = p->next;
          continue;
        }
      if (strncmp (w, "--separator=", 12) == 0)
        { seps = w + 12; sflag = 1; continue; }
      if (strncmp (w, "--input-separator=", 18) == 0)
        { seps = w + 18; sflag = 1; continue; }
      if (strcmp (w, "--output-separator") == 0)
        {
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          outsep = p->next->word->word;
          p = p->next;
          continue;
        }
      if (strncmp (w, "--output-separator=", 19) == 0)
        { outsep = w + 19; continue; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          for (const char *q = w + 1; *q; q++)
            {
              if (*q == 't')
                { tflag = 1; continue; }
              if (*q == 'x')
                { xflag = 1; continue; }
              if (*q == 'J')
                { jflag = 1; continue; }
              if (*q == 'c')
                {
                  char *endp = NULL;
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  errno = 0;
                  output_width = strtol (arg, &endp, 10);
                  if (errno || endp == arg || !endp || *endp || output_width < 0)
                    {
                      builtin_error ("column: bad output width: %s", arg);
                      builtin_usage ();
                      return EXECUTION_FAILURE;
                    }
                  break;
                }
              if (*q == 'S')
                {
                  char *endp = NULL;
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  use_spaces = strtol (arg, &endp, 10);
                  if (!endp || *endp || use_spaces < 1)
                    {
                      builtin_error ("column: bad use-spaces value: %s", arg);
                      builtin_usage ();
                      return EX_USAGE;
                    }
                  break;
                }
              if (*q == 'R' || *q == 'H' || *q == 'O' || *q == 'l')
                {
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("option requires an argument -- '%c'", *q);
                          return EXECUTION_FAILURE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  if (*q == 'l')
                    {
                      if (bcol_limit (arg, &limit) < 0)
                        return EXECUTION_FAILURE;
                    }
                  else
                    table_spec[*q == 'R' ? 0 : *q == 'H' ? 1 : 2] = arg;
                  break;
                }
              if (*q == 's' || *q == 'o' || *q == 'N' || *q == 'n')
                {
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  if (*q == 's')
                    { seps = arg; sflag = 1; }
                  else if (*q == 'N')
                    colnames = arg;
                  else if (*q == 'n')
                    tname = arg;
                  else
                    outsep = arg;
                  break;
                }
              builtin_error ("column: unknown flag: -%c", *q);
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }
      if (n_files < BCOL_MAX_FILES)
        files[n_files++] = w;
    }

  /* util-linux: the --table-* options need table or JSON output, and JSON
     needs the column names. */
  if ((colnames || tname || table_spec[0] || table_spec[1] || table_spec[2])
      && !tflag && !jflag)
    {
      builtin_error ("option --table required for all --table-*");
      return EXECUTION_FAILURE;
    }
  if (jflag && !colnames)
    {
      builtin_error ("option --table-columns or --table-column required for --json");
      return EXECUTION_FAILURE;
    }
  if (jflag)
    tflag = 1;

  if (!tflag)
    {
      char **items = NULL;
      int n_items = 0, cap_items = 0;
      size_t maxw = 0;
      int rc = EXECUTION_SUCCESS;
      int n_streams = n_files ? n_files : 1;
      FILE *in_stdin = NULL;

      for (int fi = 0; fi < n_streams; fi++)
        {
          FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
          if (!fp)
            { rc = EXECUTION_FAILURE; continue; }
          char *line = NULL;
          size_t cap = 0;
          ssize_t got;
          while ((got = bcol_getline (fp, &line, &cap)) > 0)
            {
              if (line[got - 1] == '\n')
                got--;
              if (bcol_blank (line, (size_t) got))
                continue;
              if (n_items >= cap_items)
                {
                  int nc = cap_items ? cap_items * 2 : 16;
                  char **ni = realloc (items, (size_t) nc * sizeof (*ni));
                  if (!ni) { rc = EXECUTION_FAILURE; free (line); goto columnar_cleanup; }
                  items = ni;
                  cap_items = nc;
                }
              char *copy = malloc ((size_t) got + 1);
              if (!copy) { rc = EXECUTION_FAILURE; free (line); goto columnar_cleanup; }
              memcpy (copy, line, (size_t) got);
              copy[got] = '\0';
              items[n_items++] = copy;
              if ((size_t) got > maxw)
                maxw = (size_t) got;
            }
          if (got < 0)
            { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
          free (line);
          if (fp != in_stdin) fclose (fp);
        }

      if (n_items > 0)
        {
          size_t colstep;
          if (use_spaces > 0)
            colstep = maxw + (size_t) use_spaces;
          else
            colstep = maxw ? ((maxw + 8) & ~(size_t) 7) : 8;
          int n_cols = (int) ((size_t) output_width / colstep);
          if (n_cols < 1) n_cols = 1;
          if (n_cols > n_items) n_cols = n_items;
          int n_rows = (n_items + n_cols - 1) / n_cols;

          for (int r = 0; r < n_rows; r++)
            {
              int printed = 0;
              for (int c = 0; c < n_cols; c++)
                {
                  int idx = xflag ? (r * n_cols + c) : (c * n_rows + r);
                  if (idx >= n_items)
                    continue;
                  if (printed && use_spaces <= 0)
                    putchar ('\t');
                  fputs (items[idx], stdout);
                  if (use_spaces > 0)
                    {
                      int more = 0;
                      for (int nc = c + 1; nc < n_cols; nc++)
                        {
                          int nidx = xflag ? (r * n_cols + nc) : (nc * n_rows + r);
                          if (nidx < n_items)
                            { more = 1; break; }
                        }
                      if (more)
                        {
                          size_t pad = colstep - strlen (items[idx]);
                          for (size_t sp = 0; sp < pad; sp++)
                            putchar (' ');
                        }
                    }
                  printed = 1;
                }
              putchar ('\n');
            }
        }

columnar_cleanup:
      if (in_stdin)
        fclose (in_stdin);
      for (int i = 0; i < n_items; i++)
        free (items[i]);
      free (items);
      return rc;
    }

  bcol_row *rows = NULL;
  int n_rows = 0, cap_rows = 0;
  size_t *colw = NULL;
  int n_cols = 0, cap_cols = 0;
  int rc = EXECUTION_SUCCESS;
  bcol_row names = { 0 };
  long lineno = 0;
  char *hidden = NULL, *right = NULL, *seen = NULL;
  int *vis = NULL, n_vis = 0;
  int n_streams = n_files ? n_files : 1;
  FILE *in_stdin = NULL;

  if (colnames && bcol_names (colnames, &names) != 0)
    { rc = EXECUTION_FAILURE; goto cleanup; }
  /* -N in table output: the names form a header row, measured like data
     and padded through every column; there is one even when NAMES is
     empty, but none without a data row (util-linux). */
  int header = colnames && !jflag;

  for (int fi = 0; fi < n_streams; fi++)
    {
      FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
      if (!fp)
        { rc = EXECUTION_FAILURE; continue; }
      char *line = NULL;
      size_t cap = 0;
      ssize_t got = 0;
      while (header || (got = bcol_getline (fp, &line, &cap)) > 0)
        {
          if (!header)
            {
              lineno++;
              if (line[got - 1] == '\n')
                got--;
              if (bcol_blank (line, (size_t) got))
                continue;
            }
          if (n_rows >= cap_rows)
            {
              int nc = cap_rows ? cap_rows * 2 : 16;
              bcol_row *nr = realloc (rows, (size_t) nc * sizeof (*nr));
              if (!nr) { rc = EXECUTION_FAILURE; goto cleanup; }
              rows = nr;
              cap_rows = nc;
            }
          rows[n_rows].fields = NULL;
          rows[n_rows].n = 0;
          rows[n_rows].cap = 0;
          if (header)
            {
              header = 0;
              for (int k = 0; k < names.n; k++)
                if (bcol_row_push (&rows[n_rows], names.fields[k], strlen (names.fields[k])) != 0)
                  { n_rows++; rc = EXECUTION_FAILURE; goto cleanup; }
            }
          else if (bcol_split (line, (size_t) got, seps, sflag, limit, &rows[n_rows]) != 0)
            { n_rows++; rc = EXECUTION_FAILURE; goto cleanup; }
          /* util-linux numbers the line one past the input line. */
          if (jflag && rows[n_rows].n > names.n)
            {
              builtin_error ("line %ld: for JSON the name of the column %d is required",
                             lineno + 1, names.n + 1);
              n_rows++;
              rc = EXECUTION_FAILURE;
              free (line);
              if (fp != in_stdin) fclose (fp);
              goto cleanup;
            }
          if (rows[n_rows].n > n_cols)
            {
              int newn = rows[n_rows].n;
              if (newn > cap_cols)
                {
                  int nc = cap_cols ? cap_cols * 2 : 8;
                  while (nc < newn) nc *= 2;
                  size_t *nw = realloc (colw, (size_t) nc * sizeof (*nw));
                  if (!nw) { rc = EXECUTION_FAILURE; goto cleanup; }
                  for (int k = cap_cols; k < nc; k++) nw[k] = 0;
                  colw = nw;
                  cap_cols = nc;
                }
              n_cols = newn;
            }
          for (int k = 0; k < rows[n_rows].n; k++)
            {
              size_t w = bcol_width (rows[n_rows].fields[k]);
              if (w > colw[k])
                colw[k] = w;
            }
          n_rows++;
        }
      if (got < 0)
        { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
      free (line);
      if (fp != in_stdin) fclose (fp);
    }

  /* -H, -O and -R name the columns the input made (and the -N names):
     the hidden ones are left out, -O's come first and the rest follow in
     input order, and -R's are padded on the left. As util-linux, an empty
     last cell is not padded even when right-aligned. */
  /* Without a data row util-linux prints no header either. */
  if (colnames && !jflag && n_rows == 1)
    {
      bcol_row_free (&rows[0]);
      n_rows = 0;
    }
  int total = n_cols > names.n ? n_cols : names.n;
  hidden = calloc ((size_t) total + 1, 1);
  right = calloc ((size_t) total + 1, 1);
  seen = calloc ((size_t) total + 1, 1);
  vis = malloc (((size_t) total + 1) * sizeof (*vis));
  if (!hidden || !right || !seen || !vis)
    {
      builtin_error ("out of memory");
      rc = EXECUTION_FAILURE;
      goto cleanup;
    }
  if (n_rows > 0
      && ((table_spec[1] && bcol_columns (table_spec[1], &names, total, NULL, hidden, NULL, NULL) < 0)
          || (table_spec[2] && bcol_columns (table_spec[2], &names, total, hidden, seen, vis, &n_vis) < 0)
          || (table_spec[0] && bcol_columns (table_spec[0], &names, total, hidden, right, NULL, NULL) < 0)))
    {
      rc = EXECUTION_FAILURE;
      goto cleanup;
    }
  for (int k = 0; k < total; k++)
    if (!seen[k])
      vis[n_vis++] = k;
  {
    int kept = 0;
    for (int i = 0; i < n_vis; i++)
      if (!hidden[vis[i]])
        vis[kept++] = vis[i];
    n_vis = kept;
  }

  if (jflag)
    {
      if (rc == EXECUTION_SUCCESS)
        bcol_json (rows, n_rows, &names, tname ? tname : "table", vis, n_vis);
      n_vis = 0;
    }
  for (int r = 0; r < n_rows && !jflag; r++)
    {
      for (int i = 0; i < n_vis; i++)
        {
          int k = vis[i];
          const char *field = k < rows[r].n ? rows[r].fields[k] : "";
          int last = i + 1 == n_vis;
          size_t pad = colw[k] - bcol_width (field);
          if (right[k] && (*field || !last))
            for (size_t p = 0; p < pad; p++) putchar (' ');
          fputs (field, stdout);
          if (!last)
            {
              if (!right[k])
                for (size_t p = 0; p < pad; p++) putchar (' ');
              fputs (outsep, stdout);
            }
        }
      putchar ('\n');
    }

cleanup:
  free (hidden);
  free (right);
  free (seen);
  free (vis);
  if (in_stdin)
    fclose (in_stdin);
  bcol_row_free (&names);
  for (int r = 0; r < n_rows; r++)
    bcol_row_free (&rows[r]);
  free (rows);
  free (colw);
  return rc;
}

/* Decode one character without changing the bytes used for output. Invalid
   bytes consume one position so the next character can still be decoded. */
static size_t
bcol_character (const char *s, size_t len, wchar_t *wc, int *valid)
{
  mbstate_t state = {0};
  size_t n = mbrtowc (wc, s, len, &state);
  *valid = n != (size_t) -1 && n != (size_t) -2;
  if (!*valid)
    { *wc = (unsigned char) *s; return 1; }
  return n ? n : 1;
}

/* ===================================================================
 * col verb.
 * =================================================================== */

int
col_builtin (WORD_LIST *list)
{
  int bflag = 0;
  const char *files[BCOL_MAX_FILES];
  int n_files = 0;

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            if (n_files < BCOL_MAX_FILES)
              files[n_files++] = p->word->word;
          break;
        }
      if (strcmp (w, "--help") == 0 || strcmp (w, "-H") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("col 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-b") == 0) { bflag = 1; continue; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          builtin_error ("col: unknown flag: %s", w);
          builtin_usage ();
          return EXECUTION_FAILURE;
        }
      if (n_files < BCOL_MAX_FILES)
        files[n_files++] = w;
    }

  int rc = EXECUTION_SUCCESS;
  int n_streams = n_files ? n_files : 1;
  FILE *in_stdin = NULL;
  /* util-linux col terminates its output: an input whose last line has no
     newline still gets one. Track the last byte written across every stream so
     the newline is added once, after the final operand, and not at all for
     empty input -- where util-linux writes nothing. */
  int last = -1;
  for (int fi = 0; fi < n_streams; fi++)
    {
      FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
      if (!fp) { rc = EXECUTION_FAILURE; continue; }
      /* Hold the last printable character for the simple -b overstrike
         contract. Decode before filtering so a UTF-8 continuation byte is
         never mistaken for a raw C1 control. */
      char pending[MB_LEN_MAX];
      size_t pending_len = 0;
      int in_esc = 0;
      char *line = NULL;
      size_t cap = 0;
      ssize_t got;
      while ((got = bcol_getline (fp, &line, &cap)) > 0)
        for (size_t pos = 0; pos < (size_t) got; )
          {
            wchar_t wc;
            int valid;
            size_t n = bcol_character (line + pos, (size_t) got - pos,
                                       &wc, &valid);
            const char *text = line + pos;
            pos += n;
            if (in_esc) { in_esc = 0; continue; }
            if (valid && wc == 0x1b) { in_esc = 1; continue; }
            if (valid && wc >= 0x80 && wc <= 0x9f)
              continue;
            if (valid && wc == '\b')
              {
                if (bflag)
                  pending_len = 0;
                else
                  {
                    if (pending_len)
                      fwrite (pending, 1, pending_len, stdout);
                    pending_len = 0;
                    putchar ('\b');
                    last = '\b';
                  }
                continue;
              }
            if (pending_len)
              {
                fwrite (pending, 1, pending_len, stdout);
                last = (unsigned char) pending[pending_len - 1];
                pending_len = 0;
              }
            if (!valid)
              {
                /* Invalid input is displayed as four printable ASCII cells.
                   Keep the last cell pending so -b can overstrike it. */
                char escaped[5];
                snprintf (escaped, sizeof escaped, "\\x%02x",
                          (unsigned char) *text);
                fwrite (escaped, 1, 3, stdout);
                last = (unsigned char) escaped[2];
                pending[0] = escaped[3];
                pending_len = 1;
              }
            else
              {
                memcpy (pending, text, n);
                pending_len = n;
              }
          }
      free (line);
      if (pending_len)
        {
          fwrite (pending, 1, pending_len, stdout);
          last = (unsigned char) pending[pending_len - 1];
        }
      if (got < 0)
        { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
      if (fp != in_stdin) fclose (fp);
    }
  if (last != -1 && last != '\n')
    putchar ('\n');
  if (in_stdin)
    fclose (in_stdin);
  return rc;
}

/* ===================================================================
 * colrm verb.
 * =================================================================== */

int
colrm_builtin (WORD_LIST *list)
{
  long start = 0, end = 0;
  int n_pos = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("colrm 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          builtin_error ("colrm: unknown flag: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      char *e = NULL;
      errno = 0;
      long v = strtol (w, &e, 10);
      if (errno || e == w || !e || *e != '\0' || v < 0)
        {
          builtin_error ("colrm: bad column: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      if (n_pos == 0) start = v;
      else if (n_pos == 1) end = v;
      else
        {
          builtin_error ("colrm: too many operands");
          builtin_usage ();
          return EX_USAGE;
        }
      n_pos++;
    }
  if (n_pos == 1) end = 0;          /* 0 == "to end-of-line" */

  char *line = NULL;
  size_t cap = 0;
  ssize_t got;
  int rc = EXECUTION_SUCCESS;
  FILE *in = bcol_open_stdin ();
  if (!in)
    return EXECUTION_FAILURE;
  while ((got = bcol_getline (in, &line, &cap)) > 0)
    {
      if (start == 0)
        {
          fwrite (line, 1, (size_t) got, stdout);
          continue;
        }
      long column = 0, trailing_pad = 0;
      int removing = 0, tail = 0;
      for (size_t pos = 0; pos < (size_t) got; )
        {
          wchar_t wc;
          int valid;
          size_t n = bcol_character (line + pos, (size_t) got - pos,
                                     &wc, &valid);
          const char *text = line + pos;
          pos += n;
          if (wc == '\n')
            { putchar ('\n'); column = trailing_pad = 0; removing = tail = 0; continue; }
          if (tail)
            {
              for (long cell = 0; cell < trailing_pad; cell++)
                putchar (' ');
              trailing_pad = 0;
              fwrite (text, 1, n, stdout);
              continue;
            }
          long previous = column;
          int width = valid ? wcwidth (wc) : 1;
          if (wc == '\b')
            { if (column > 0) column--; }
          else if (wc == '\t')
            column += 8 - column % 8;
          else if (width > 0)
            column += width;
          if (!removing && column < start)
            { fwrite (text, 1, n, stdout); continue; }
          if (!removing)
            {
              /* Retain the part before START of a tab or wide glyph. */
              for (long cell = previous; cell < start - 1; cell++)
                putchar (' ');
              removing = 1;
            }
          if (end && column >= end)
            {
              /* Right-side cells matter only when more text follows on
                 this line. Do not materialize padding at newline or EOF.
                 This also retains historical reversed-range padding. */
              trailing_pad = column - end;
              tail = 1;
            }
        }
    }
  if (got < 0)
    { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
  free (line);
  fclose (in);
  return rc;
}

/* ===================================================================
 * Bash builtin registration — three names, three structs, all from
 * this translation unit. The sibling stub files col.c and
 * colrm.c contain no code; they exist so patch-bash-loadables.sh's
 * `cp examples/loadables/${name}.c` step has a file at the expected
 * path. The struct + _builtin + _doc symbols below are picked up via
 * the extern declarations inject-loadables-to-builtins-c.sh appends
 * to builtins/builtext.h.
 * =================================================================== */

char *column_doc[] = {
  "Aligned-column formatter (util-linux column subset).",
  "",
  "    column [-x] [-c WIDTH] [FILE...]",
  "    column -t [-s SEPSTR] [-o OUTSTR] [-N NAMES] [-l NUM] [-R COLS] [-H COLS]",
  "              [-O COLS] [FILE...]",
  "    column -J -N NAMES [-n NAME] [-s SEPSTR] [FILE...]",
  "    column --help | --version",
  "",
  "  -t          table mode",
  "  -x          fill rows before columns in non-table mode",
  "  -c WIDTH    output width for non-table mode (default 80)",
  "  -S NUM      use NUM spaces between non-table columns, no tabs",
  "  -s SEPSTR   each byte in SEPSTR splits input fields (preserves",
  "              empty fields between consecutive separators)",
  "  -o OUTSTR   column join string (default '  ')",
  "              getopt-style -ts:, -s:, and -o:: forms are accepted",
  "  -N NAMES, --table-columns=NAMES",
  "              comma-separated column names: a header row with -t,",
  "              the keys (in lower case) with -J",
  "  -J, --json  print the table as JSON; empty cells are null",
  "  -n NAME, --table-name=NAME",
  "              JSON table name (default table)",
  "  -l NUM, --table-columns-limit=NUM",
  "              at most NUM input columns; the last holds the rest of the line",
  "  -R COLS, --table-right=COLS   right-align these columns",
  "  -H COLS, --table-hide=COLS    do not print these columns ('-': unnamed ones)",
  "  -O COLS, --table-order=COLS   print these columns first, in this order",
  "              COLS is a comma-separated list of -N names, numbers from 1,",
  "              ranges such as 1-3 (not -O), 0 for all (not -O) and -1 for",
  "              the last visible column",
  "  --help      show usage",
  "  --version   show version",
  "",
  "Non-table mode formats each input line as one item.",
  "In table mode without -s, runs of whitespace collapse into one separator.",
  "Cells are padded by display width (wcwidth) in a UTF-8 locale, bytes in C.",
  (char *) NULL
};

struct builtin column_struct = {
  "column",
  column_builtin,
  BUILTIN_ENABLED,
  column_doc,
  "column [-x] [-c WIDTH] [-t [-s SEPSTR] [-o OUTSTR] [-N NAMES] [-l NUM] [-R|-H|-O COLS]] [-J -N NAMES [-n NAME]] [FILE...]",
  0
};

char *col_doc[] = {
  "Filter CTL-H overstrike sequences (util-linux col).",
  "",
  "    col [-b] [FILE...]",
  "    col --help | --version",
  "",
  "  -b   drop backspace and the character it overstrikes (no overprint)",
  "  -H, --help     show usage",
  "  -V, --version  show version",
  "",
  "Without -b, backspace overstrike bytes are preserved. Escape pairs and decoded C1 controls are dropped.",
  "Invalid multibyte bytes are displayed as \\xNN.",
  (char *) NULL
};

struct builtin col_struct = {
  "col",
  col_builtin,
  BUILTIN_ENABLED,
  col_doc,
  "col [-b] [FILE...]",
  0
};

char *colrm_doc[] = {
  "Remove display columns from each stdin line (util-linux colrm).",
  "",
  "    colrm [START [END]]",
  "    colrm --help | --version",
  "",
  "  START      1-based first column to remove",
  "  END        1-based last column to remove (omit = to end-of-line)",
  "  -h, --help     show usage",
  "  -V, --version  show version",
  "",
  "Tabs use eight-column stops; backspaces retreat one display column.",
  "Multibyte characters use locale display widths; partially removed cells become spaces.",
  "START zero passes input through; END zero removes through end-of-line.",
  (char *) NULL
};

struct builtin colrm_struct = {
  "colrm",
  colrm_builtin,
  BUILTIN_ENABLED,
  colrm_doc,
  "colrm [START [END]]",
  0
};
