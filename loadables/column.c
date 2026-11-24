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
 *      '-' for -H) to right-align, hide and reorder columns. -T, -W and -E
 *      name the columns that give way when the table is wider than the
 *      output (-c, the terminal, COLUMNS, 80): truncated, wrapped, or
 *      shrunk with the longer cells ending their line. The split of the
 *      excess between several such columns models util-linux 2.41 as
 *      observed (exact for single-row tables, close otherwise). -d hides
 *      the -N header, -e repeats it every LINES rows, -L keeps blank lines,
 *      and -r/-i/-p draw a tree from child and parent ID columns.
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
#include <langinfo.h>
#include <sys/ioctl.h>

#include "loadables.h"
#include "shim-prog-name.h"

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

/* One JSON array level: the objects from START along NEXT, at INDENT,
   each followed by a "children" array when FIRST names a child. */
static void
bcol_json_level (bcol_row *rows, int start, int indent, const bcol_row *names,
                 const int *vis, int n_vis, int last, const int *first,
                 const int *next)
{
  for (int r = start, k = 0; r >= 0; r = next[r], k++)
    {
      printf ("%*s%s\n", indent, "", k ? "},{" : "{");
      if (last < 0)
        putchar ('\n');
      int kids = first && first[r] >= 0;
      for (int i = 0; i <= last; i++)
        {
          int c = vis[i];
          if (c >= names->n)
            continue;
          printf ("%*s", indent + 3, "");
          bcol_json_string (names->fields[c], 1);
          fputs (": ", stdout);
          if (c < rows[r].n && rows[r].fields[c][0])
            bcol_json_string (rows[r].fields[c], 0);
          else
            fputs ("null", stdout);
          fputs (i < last || kids ? ",\n" : "\n", stdout);
        }
      if (kids)
        {
          printf ("%*s\"children\": [\n", indent + 3, "");
          bcol_json_level (rows, first[r], indent + 6, names, vis, n_vis, last, first, next);
          printf ("%*s]\n", indent + 3, "");
        }
    }
  printf ("%*s}\n", indent, "");
}

/* util-linux JSON: the rows from ROOT along NEXT, and with --tree each
   row's children (FIRST) nested in a "children" array. */
static void
bcol_json (bcol_row *rows, int n_rows, const bcol_row *names, const char *tname,
           const int *vis, int n_vis, int root, const int *first, const int *next)
{
  if (n_rows == 0 || root < 0)
    return;
  int last = -1;
  for (int i = 0; i < n_vis; i++)
    if (vis[i] < names->n)
      last = i;
  fputs ("{\n   ", stdout);
  bcol_json_string (tname, 1);
  fputs (": [\n", stdout);
  bcol_json_level (rows, root, 6, names, vis, n_vis, last, first, next);
  fputs ("   ]\n}\n", stdout);
}

/* Terminal size the util-linux way: the width of a terminal on stdout,
   else COLUMNS, else 80; the height from LINES, else from a terminal on
   stdout, stderr or stdin, else 24. */
static long
bcol_term_size (int lines)
{
  struct winsize ws;
  if (!lines && isatty (STDOUT_FILENO)
      && ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    return ws.ws_col;
  const char *env = getenv (lines ? "LINES" : "COLUMNS");
  if (env && *env)
    {
      char *end;
      errno = 0;
      long v = strtol (env, &end, 10);
      if (!errno && !*end && v > 0 && v <= INT_MAX)
        return v;
    }
  if (lines)
    {
      static const int fds[] = { STDOUT_FILENO, STDERR_FILENO, STDIN_FILENO };
      for (int i = 0; i < 3; i++)
        if (isatty (fds[i]) && ioctl (fds[i], TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
          return ws.ws_row;
      return 24;
    }
  return 80;
}

/* Bytes of S (LEN) that fit in MAXW display columns; *WIDTH gets their
   width. At least one character is taken when ATLEAST is set, so that a
   wrapped cell always advances. */
static size_t
bcol_cut (const char *s, size_t len, size_t maxw, size_t *width, int atleast)
{
  size_t i = 0, used = 0;
  while (i < len)
    {
      size_t n = 1, cw = 1;
      if (MB_CUR_MAX > 1)
        {
          wchar_t wc;
          int valid;
          n = bcol_character (s + i, len - i, &wc, &valid);
          int x = valid ? wcwidth (wc) : 1;
          cw = x > 0 ? (size_t) x : 0;
        }
      if (used + cw > maxw && !(atleast && i == 0))
        break;
      used += cw;
      i += n;
    }
  *width = used;
  return i;
}

/* -r/-i/-p name one column: a -N name, a number from 1, or -1 for the
   last visible column. Returns its index, or -1 after util-linux's
   message. */
static int
bcol_column1 (const char *spec, const bcol_row *names, int n_cols, const char *hidden)
{
  for (int k = 0; k < names->n; k++)
    if (!strcmp (names->fields[k], spec))
      return k;
  if (!strcmp (spec, "-1"))
    for (int k = n_cols - 1; k >= 0; k--)
      if (!hidden[k])
        return k;
  size_t digits = strspn (spec, "0123456789");
  if (digits && !spec[digits])
    {
      long v = strtol (spec, NULL, 10);
      if (v >= 1 && v <= n_cols)
        return (int) v - 1;
    }
  builtin_error ("undefined column name '%s'", spec);
  return -1;
}

/* Rows sorted by their parent field, for --tree. */
static const bcol_row *bcol_sort_rows;
static int bcol_sort_col;

static const char *
bcol_field (const bcol_row *r, int c)
{
  return c < r->n ? r->fields[c] : "";
}

static int
bcol_by_parent (const void *a, const void *b)
{
  int x = *(const int *) a, y = *(const int *) b;
  int d = strcmp (bcol_field (&bcol_sort_rows[x], bcol_sort_col),
                  bcol_field (&bcol_sort_rows[y], bcol_sort_col));
  return d ? d : (x > y) - (x < y);
}

/* Shrink the visible columns (widths W, minimums MINW, N of them) until
   the table fits in WIDTH. This is an empirical model of util-linux 2.41
   observed on single-row tables: each round takes up to three columns from
   the widest column (ties: the later one) when it may be truncated,
   wrapped or have extremes ignored (checking the fit after each one only
   when it ignores extremes or is the last column), then one from each
   other such column, last first, checking after each. RED marks the
   columns that may shrink and NOEXT those that ignore extremes. */
static void
bcol_fit (size_t *w, const size_t *minw, const size_t *natural, int n, size_t seplen,
          size_t width, const char *red, const char *noext)
{
  if (n == 0)
    return;
  size_t total = seplen * (size_t) (n - 1);
  int prim = 0;
  for (int i = 0; i < n; i++)
    {
      total += w[i];
      if (natural[i] >= natural[prim])
        prim = i;
    }
  while (total > width)
    {
      int progressed = 0;
      if (red[prim])
        {
          int checked = noext[prim] || prim == n - 1;
          for (int k = 0; k < 3; k++)
            if (w[prim] > minw[prim])
              {
                w[prim]--, total--, progressed = 1;
                if (checked && total <= width)
                  break;
              }
          if (total <= width)
            break;
        }
      for (int i = n - 1; i >= 0; i--)
        if (i != prim && red[i] && w[i] > minw[i])
          {
            w[i]--, total--, progressed = 1;
            if (total <= width)
              break;
          }
      if (!progressed)
        break;
    }
}

/* Print one table row: trunc cells (-T) are cut to the column width, wrap
   cells (-W) continue on following lines, and any other cell wider than
   its column ends the line, the rest of the row continuing below at its
   own column (util-linux). */
static void
bcol_print_row (const bcol_row *row, const int *vis, int n_vis, const size_t *w,
                const char *right, const char *trunc, const char *wrap,
                const char *outsep)
{
  size_t seplen = strlen (outsep);
  size_t off[n_vis ? n_vis : 1];
  for (int i = 0; i < n_vis; i++)
    off[i] = 0;
  for (int line = 0, more = 1; more; line++)
    {
      more = 0;
      size_t pos = 0;
      for (int i = 0; i < n_vis; i++)
        {
          int k = vis[i];
          const char *field = bcol_field (row, k);
          size_t len = strlen (field), cellw = bcol_width (field);
          int last = i + 1 == n_vis;
          const char *seg = "";
          size_t seglen = 0, segw = 0;
          if (wrap[k] && cellw > w[i])
            {
              if (off[i] < len)
                {
                  seg = field + off[i];
                  seglen = bcol_cut (seg, len - off[i], w[i], &segw, 1);
                  off[i] += seglen;
                  if (off[i] < len)
                    more = 1;
                }
            }
          else if (line == 0)
            {
              seg = field;
              if (trunc[k] && cellw > w[i])
                seglen = bcol_cut (field, len, w[i], &segw, 0);
              else
                seglen = len, segw = cellw;
            }
          size_t pad = segw < w[i] ? w[i] - segw : 0;
          if (right[k] && (seglen || !last))
            for (size_t p = 0; p < pad; p++) putchar (' ');
          fwrite (seg, 1, seglen, stdout);
          pos += w[i] + seplen;
          if (last)
            break;
          if (segw > w[i])
            {
              putchar ('\n');
              for (size_t p = 0; p < pos; p++) putchar (' ');
              continue;
            }
          if (!right[k])
            for (size_t p = 0; p < pad; p++) putchar (' ');
          fputs (outsep, stdout);
        }
      putchar ('\n');
    }
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
  { "table-columns-limit", 'l' }, { "table-truncate", 'T' },
  { "table-noextreme", 'E' }, { "table-wrap", 'W' }, { "tree", 'r' },
  { "tree-id", 'i' }, { "tree-parent", 'p' },
};
#define BCOL_N_TABLE_OPTS ((int) (sizeof bcol_table_opts / sizeof bcol_table_opts[0]))
enum { BCOL_R, BCOL_H, BCOL_O, BCOL_L, BCOL_T, BCOL_E, BCOL_W, BCOL_TREE,
       BCOL_TREE_ID, BCOL_TREE_PARENT };

/* util-linux's getopt diagnostics end with the --help hint. */
static void
bcol_try_help (void)
{
  fputs ("Try 'column --help' for more information.\n", stderr);
}

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
  const char *table_spec[BCOL_N_TABLE_OPTS] = { NULL };  /* by BCOL_* */
  long limit = 0;                   /* -l NUMBER */
  int width_given = 0;              /* -c WIDTH */
  int noheadings = 0;               /* -d */
  int header_repeat = 0;            /* -e */
  int keep_empty = 0;               /* -L */

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
      if (strcmp (w, "--table-noheadings") == 0)
        { noheadings = 1; continue; }
      if (strcmp (w, "--table-header-repeat") == 0)
        { header_repeat = 1; continue; }
      if (strcmp (w, "--keep-empty-lines") == 0
          || strcmp (w, "--table-empty-lines") == 0)
        { keep_empty = 1; continue; }
      if (strncmp (w, "--table-columns=", 16) == 0)
        { colnames = w + 16; continue; }
      if (strncmp (w, "--table-name=", 13) == 0)
        { tname = w + 13; continue; }
      if (strcmp (w, "--table-columns") == 0 || strcmp (w, "--table-name") == 0)
        {
          if (!p->next)
            {
              bos_shim_missing_arg (w, 0, "column");
              return EXECUTION_FAILURE;
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
                    bcol_try_help ();
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
              bos_shim_missing_arg (w, w[1], "column");
              return EXECUTION_FAILURE;
            }
          errno = 0;
          width_given = 1;
          if (strcmp (p->next->word->word, "unlimited") == 0)
            output_width = 0, endp = (char *) "";
          else
            output_width = strtol (p->next->word->word, &endp, 10);
          if (errno || endp == p->next->word->word || !endp || *endp || output_width < 0)
            {
              builtin_error ("bad output width: %s", p->next->word->word);
              bos_shim_try_help ("column");
              return EXECUTION_FAILURE;
            }
          p = p->next;
          continue;
        }
      if (strncmp (w, "--output-width=", 15) == 0)
        {
          char *endp = NULL;
          errno = 0;
          width_given = 1;
          if (strcmp (w + 15, "unlimited") == 0)
            output_width = 0, endp = (char *) "";
          else
            output_width = strtol (w + 15, &endp, 10);
          if (errno || endp == w + 15 || !endp || *endp || output_width < 0)
            {
              builtin_error ("bad output width: %s", w + 15);
              bos_shim_try_help ("column");
              return EXECUTION_FAILURE;
            }
          continue;
        }
      if (strcmp (w, "--use-spaces") == 0)
        {
          char *endp = NULL;
          if (!p->next)
            {
              bos_shim_missing_arg (w, w[1], "column");
              return EXECUTION_FAILURE;
            }
          use_spaces = strtol (p->next->word->word, &endp, 10);
          if (!endp || *endp || use_spaces < 1)
            {
              builtin_error ("bad use-spaces value: %s", p->next->word->word);
              bos_shim_try_help ("column");
              return EXECUTION_FAILURE;
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
              builtin_error ("bad use-spaces value: %s", w + 13);
              bos_shim_try_help ("column");
              return EXECUTION_FAILURE;
            }
          continue;
        }
      if (strcmp (w, "--separator") == 0
          || strcmp (w, "--input-separator") == 0)
        {
          if (!p->next)
            {
              bos_shim_missing_arg (w, w[1], "column");
              return EXECUTION_FAILURE;
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
              bos_shim_missing_arg (w, w[1], "column");
              return EXECUTION_FAILURE;
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
              if (*q == 'd')
                { noheadings = 1; continue; }
              if (*q == 'e')
                { header_repeat = 1; continue; }
              if (*q == 'L')
                { keep_empty = 1; continue; }
              if (*q == 'c')
                {
                  char *endp = NULL;
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          bos_shim_missing_arg ("-", *q, "column");
                          return EXECUTION_FAILURE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  errno = 0;
                  width_given = 1;
                  if (strcmp (arg, "unlimited") == 0)
                    output_width = 0, endp = (char *) "";
                  else
                    output_width = strtol (arg, &endp, 10);
                  if (errno || endp == arg || !endp || *endp || output_width < 0)
                    {
                      builtin_error ("bad output width: %s", arg);
                      bos_shim_try_help ("column");
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
                          bos_shim_missing_arg ("-", *q, "column");
                          return EXECUTION_FAILURE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  use_spaces = strtol (arg, &endp, 10);
                  if (!endp || *endp || use_spaces < 1)
                    {
                      builtin_error ("bad use-spaces value: %s", arg);
                      bos_shim_try_help ("column");
                      return EXECUTION_FAILURE;
                    }
                  break;
                }
              if (strchr ("RHOlTEWrip", *q))
                {
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("option requires an argument -- '%c'", *q);
                          bcol_try_help ();
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
                    for (int k = 0; k < BCOL_N_TABLE_OPTS; k++)
                      if (bcol_table_opts[k].c == *q)
                        table_spec[k] = arg;
                  break;
                }
              if (*q == 's' || *q == 'o' || *q == 'N' || *q == 'n')
                {
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          bos_shim_missing_arg ("-", *q, "column");
                          return EXECUTION_FAILURE;
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
              bos_shim_bad_option (w, w[1] == '-' ? 0 : *q, "column");
              return EXECUTION_FAILURE;
            }
          continue;
        }
      if (n_files < BCOL_MAX_FILES)
        files[n_files++] = w;
    }

  /* util-linux: the --table-* options need table or JSON output, and JSON
     needs the column names. */
  /* -r (--tree) implies table output and needs -i and -p. */
  if (table_spec[BCOL_TREE])
    {
      if (!table_spec[BCOL_TREE_ID] || !table_spec[BCOL_TREE_PARENT])
        {
          builtin_error ("options --tree-id and --tree-parent are required for tree formatting");
          return EXECUTION_FAILURE;
        }
      tflag = 1;
    }
  if ((colnames || tname || table_spec[BCOL_R] || table_spec[BCOL_H] || table_spec[BCOL_O]
       || table_spec[BCOL_T] || table_spec[BCOL_E] || table_spec[BCOL_W])
      && !tflag && !jflag)
    {
      builtin_error ("option --table required for all --table-*");
      return EXECUTION_FAILURE;
    }
  /* Without -c: the terminal's width when stdout is one, else COLUMNS,
     else 80 (util-linux). */
  if (!width_given)
    output_width = bcol_term_size (0);
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
                {
                  /* -L keeps it, as an empty item. */
                  if (!keep_empty)
                    continue;
                  got = 0;
                }
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
  int n_cols = 0;
  int rc = EXECUTION_SUCCESS;
  bcol_row names = { 0 };
  long lineno = 0;
  char *hidden = NULL, *right = NULL, *seen = NULL, *trunc = NULL, *wrap = NULL;
  char *noext = NULL, *red = NULL;
  int *vis = NULL, n_vis = 0;
  int *first = NULL, *next = NULL, *up = NULL, *tail = NULL, *byparent = NULL;
  size_t *colw = NULL, *w = NULL, *minw = NULL, *natural = NULL;
  char *prefix = NULL;
  int n_streams = n_files ? n_files : 1;
  FILE *in_stdin = NULL;

  if (colnames && bcol_names (colnames, &names) != 0)
    { rc = EXECUTION_FAILURE; goto cleanup; }
  /* -N in table output: the names form a header row, measured like data
     and padded through every column; there is one even when NAMES is
     empty, but none without a data row (util-linux). -d keeps the names
     for addressing columns but prints no header. */
  int header = colnames && !jflag && !noheadings;
  int hdr = header;     /* rows[0] is the header */

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
          int blank = 0;
          if (!header)
            {
              lineno++;
              if (line[got - 1] == '\n')
                got--;
              /* -L keeps a whitespace-only line as a row without cells. */
              blank = bcol_blank (line, (size_t) got);
              if (blank && !keep_empty)
                continue;
            }
          if (n_rows >= cap_rows)
            {
              int nc = cap_rows ? cap_rows * 2 : 16;
              bcol_row *nr = realloc (rows, (size_t) nc * sizeof (*nr));
              if (!nr) { rc = EXECUTION_FAILURE; free (line); goto cleanup; }
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
                  { n_rows++; rc = EXECUTION_FAILURE; free (line); goto cleanup; }
            }
          else if (!blank
                   && bcol_split (line, (size_t) got, seps, sflag, limit, &rows[n_rows]) != 0)
            { n_rows++; rc = EXECUTION_FAILURE; free (line); goto cleanup; }
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
            n_cols = rows[n_rows].n;
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
  if (hdr && n_rows == 1)
    {
      bcol_row_free (&rows[0]);
      n_rows = 0;
    }
  int n_data = n_rows - hdr;
  int total = n_cols > names.n ? n_cols : names.n;
  size_t slots = (size_t) total + 1;
  hidden = calloc (slots, 1);
  right = calloc (slots, 1);
  seen = calloc (slots, 1);
  trunc = calloc (slots, 1);
  wrap = calloc (slots, 1);
  noext = calloc (slots, 1);
  red = calloc (slots, 1);
  vis = malloc (slots * sizeof (*vis));
  first = malloc (((size_t) n_rows + 1) * sizeof (*first));
  next = malloc (((size_t) n_rows + 1) * sizeof (*next));
  if (!hidden || !right || !seen || !trunc || !wrap || !noext || !red || !vis || !first || !next)
    {
      builtin_error ("out of memory");
      rc = EXECUTION_FAILURE;
      goto cleanup;
    }
  if (n_rows > 0
      && ((table_spec[BCOL_H] && bcol_columns (table_spec[BCOL_H], &names, total, NULL, hidden, NULL, NULL) < 0)
          || (table_spec[BCOL_O] && bcol_columns (table_spec[BCOL_O], &names, total, hidden, seen, vis, &n_vis) < 0)
          || (table_spec[BCOL_R] && bcol_columns (table_spec[BCOL_R], &names, total, hidden, right, NULL, NULL) < 0)
          || (table_spec[BCOL_T] && bcol_columns (table_spec[BCOL_T], &names, total, hidden, trunc, NULL, NULL) < 0)
          || (table_spec[BCOL_W] && bcol_columns (table_spec[BCOL_W], &names, total, hidden, wrap, NULL, NULL) < 0)
          || (table_spec[BCOL_E] && bcol_columns (table_spec[BCOL_E], &names, total, hidden, noext, NULL, NULL) < 0)))
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

  /* Data rows as a list (NEXT) or, with -r, as a forest: the row whose -i
     cell matches another row's -p cell adopts it, in input order, unless
     that would make a cycle; a later row with the same ID takes the child
     over. Children print below their parent, the -r column prefixed by the
     tree lines. */
  int root = n_data > 0 ? 0 : -1;
  for (int r = 0; r < n_data; r++)
    first[r] = -1, next[r] = r + 1 < n_data ? r + 1 : -1;
  if (table_spec[BCOL_TREE] && n_data > 0)
    {
      bcol_row *data = rows + hdr;
      int tc = bcol_column1 (table_spec[BCOL_TREE], &names, total, hidden);
      int ic = tc < 0 ? -1 : bcol_column1 (table_spec[BCOL_TREE_ID], &names, total, hidden);
      int pc = ic < 0 ? -1 : bcol_column1 (table_spec[BCOL_TREE_PARENT], &names, total, hidden);
      up = malloc ((size_t) n_data * sizeof (*up));
      tail = malloc ((size_t) n_data * sizeof (*tail));
      byparent = malloc ((size_t) n_data * sizeof (*byparent));
      if (pc < 0 || !up || !tail || !byparent)
        {
          if (pc >= 0)
            builtin_error ("out of memory");
          rc = EXECUTION_FAILURE;
          goto cleanup;
        }
      for (int r = 0; r < n_data; r++)
        first[r] = next[r] = up[r] = tail[r] = -1, byparent[r] = r;
      bcol_sort_rows = data;
      bcol_sort_col = pc;
      qsort (byparent, (size_t) n_data, sizeof (*byparent), bcol_by_parent);
      for (int r = 0; r < n_data; r++)
        {
          const char *id = bcol_field (&data[r], ic);
          if (!*id)
            continue;
          int lo = 0, hi = n_data;
          while (lo < hi)
            {
              int mid = (lo + hi) / 2;
              if (strcmp (bcol_field (&data[byparent[mid]], pc), id) < 0)
                lo = mid + 1;
              else
                hi = mid;
            }
          for (; lo < n_data && !strcmp (bcol_field (&data[byparent[lo]], pc), id); lo++)
            {
              int c = byparent[lo], a;
              for (a = r; a >= 0 && a != c; a = up[a])
                ;
              if (a == c)
                continue;
              if (up[c] >= 0)
                {
                  int *link = &first[up[c]], prev = -1;
                  while (*link != c)
                    prev = *link, link = &next[*link];
                  *link = next[c];
                  if (tail[up[c]] == c)
                    tail[up[c]] = prev;
                }
              next[c] = -1;
              if (tail[r] >= 0)
                next[tail[r]] = c;
              else
                first[r] = c;
              tail[r] = c;
              up[c] = r;
            }
        }
      /* Roots stay in input order. */
      root = -1;
      for (int r = n_data - 1; r >= 0; r--)
        if (up[r] < 0)
          next[r] = root, root = r;
      if (!jflag)
        {
          /* Pre-order walk: give each row its tree lines, then reorder. */
          int utf8 = !strcmp (nl_langinfo (CODESET), "UTF-8");
          const char *vert = utf8 ? "\xe2\x94\x82 " : "| ";
          const char *branch = utf8 ? "\xe2\x94\x9c\xe2\x94\x80" : "|-";
          const char *lastbr = utf8 ? "\xe2\x94\x94\xe2\x94\x80" : "`-";
          bcol_row *sorted = malloc (((size_t) n_rows) * sizeof (*sorted));
          int *stack = malloc ((size_t) n_data * sizeof (*stack));
          if (!sorted || !stack)
            {
              free (sorted);
              free (stack);
              builtin_error ("out of memory");
              rc = EXECUTION_FAILURE;
              goto cleanup;
            }
          if (hdr)
            sorted[0] = rows[0];
          int out = hdr, sp = 0;
          for (int r = root; r >= 0; r = next[r])
            {
              stack[sp++] = r;
              while (sp)
                {
                  int x = stack[--sp];
                  size_t plen = 0, depth = 0;
                  for (int a = x; up[a] >= 0; a = up[a])
                    depth++;
                  if (depth)
                    {
                      free (prefix);
                      prefix = malloc (depth * 6 + 1);
                      if (!prefix)
                        {
                          free (sorted);
                          free (stack);
                          builtin_error ("out of memory");
                          rc = EXECUTION_FAILURE;
                          goto cleanup;
                        }
                      /* Right to left: this row's branch, then one
                         segment per ancestor below the root. */
                      size_t at = depth * 6;
                      prefix[at] = 0;
                      int a = x;
                      for (size_t d = 0; d < depth; d++, a = up[a])
                        {
                          const char *piece = d == 0 ? (next[a] >= 0 ? branch : lastbr)
                                                     : (next[a] >= 0 ? vert : "  ");
                          size_t n = strlen (piece);
                          at -= n;
                          memcpy (prefix + at, piece, n);
                        }
                      plen = depth * 6 - at;
                      memmove (prefix, prefix + at, plen + 1);
                      while (data[x].n <= tc)
                        if (bcol_row_push (&data[x], "", 0) != 0)
                          break;
                      if (data[x].n > tc)
                        {
                          size_t olen = strlen (data[x].fields[tc]);
                          char *cell = malloc (plen + olen + 1);
                          if (cell)
                            {
                              memcpy (cell, prefix, plen);
                              memcpy (cell + plen, data[x].fields[tc], olen + 1);
                              free (data[x].fields[tc]);
                              data[x].fields[tc] = cell;
                            }
                        }
                    }
                  sorted[out++] = data[x];
                  /* Children in order: push them last first. */
                  int nk = 0;
                  for (int c = first[x]; c >= 0; c = next[c])
                    nk++;
                  sp += nk;
                  int at = sp;
                  for (int c = first[x]; c >= 0; c = next[c])
                    stack[--at] = c;
                }
            }
          free (stack);
          free (rows);
          rows = sorted;
          cap_rows = n_rows;
        }
    }

  if (jflag)
    {
      if (rc == EXECUTION_SUCCESS)
        bcol_json (rows, n_rows, &names, tname ? tname : "table", vis, n_vis,
                   root, table_spec[BCOL_TREE] ? first : NULL, next);
      goto cleanup;
    }
  /* -L rows without a single cell: util-linux prints nothing and fails. */
  if (total == 0)
    {
      if (n_rows > 0)
        rc = EXECUTION_FAILURE;
      goto cleanup;
    }

  /* Widths: the widest cell of each visible column, header included. When
     the table is wider than the output, the -T, -W and -E columns (and,
     without -E, the last column, whose cells are never padded) give way,
     but never below the header or one column. */
  colw = calloc (slots, sizeof (*colw));
  w = calloc (slots, sizeof (*w));
  minw = calloc (slots, sizeof (*minw));
  natural = calloc (slots, sizeof (*natural));
  if (!colw || !w || !minw || !natural)
    {
      builtin_error ("out of memory");
      rc = EXECUTION_FAILURE;
      goto cleanup;
    }
  for (int r = 0; r < n_rows; r++)
    for (int k = 0; k < rows[r].n; k++)
      {
        size_t cw = bcol_width (rows[r].fields[k]);
        if (cw > colw[k])
          colw[k] = cw;
      }
  int any_noext = 0;
  for (int i = 0; i < n_vis; i++)
    any_noext |= noext[vis[i]];
  char *noext_vis = seen;   /* reused: per visible position */
  for (int i = 0; i < n_vis; i++)
    {
      int k = vis[i];
      natural[i] = w[i] = colw[k];
      minw[i] = hdr ? bcol_width (bcol_field (&rows[0], k)) : 0;
      if (minw[i] < 1)
        minw[i] = 1;
      noext_vis[i] = any_noext ? noext[k] : i + 1 == n_vis;
      red[i] = trunc[k] || wrap[k] || noext_vis[i];
    }
  if (output_width > 0)
    bcol_fit (w, minw, natural, n_vis, strlen (outsep), (size_t) output_width, red, noext_vis);

  long page = header_repeat && hdr ? bcol_term_size (1) : 0;
  for (int r = 0; r < n_rows; r++)
    {
      int d = r - hdr;
      if (page && d > 0 && d % page == 0)
        bcol_print_row (&rows[0], vis, n_vis, w, right, trunc, wrap, outsep);
      bcol_print_row (&rows[r], vis, n_vis, w, right, trunc, wrap, outsep);
    }

cleanup:
  free (hidden);
  free (right);
  free (seen);
  free (trunc);
  free (wrap);
  free (noext);
  free (red);
  free (vis);
  free (first);
  free (next);
  free (up);
  free (tail);
  free (byparent);
  free (w);
  free (minw);
  free (natural);
  free (prefix);
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
          bos_shim_bad_option (w, w[1], "col");
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
          bos_shim_bad_option (w, w[1], "colrm");
          return EXECUTION_FAILURE;
        }
      char *e = NULL;
      errno = 0;
      long v = strtol (w, &e, 10);
      if (errno || e == w || !e || *e != '\0' || v < 0)
        {
          builtin_error ("bad column: %s", w);
          bos_shim_try_help ("colrm");
          return EXECUTION_FAILURE;
        }
      if (n_pos == 0) start = v;
      else if (n_pos == 1) end = v;
      else
        {
          builtin_error ("too many operands");
          bos_shim_try_help ("colrm");
          return EXECUTION_FAILURE;
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
  "    column [-x] [-L] [-c WIDTH] [FILE...]",
  "    column -t [-s SEPSTR] [-o OUTSTR] [-N NAMES] [-dLe] [-l NUM] [-R COLS]",
  "              [-H COLS] [-O COLS] [-T COLS] [-W COLS] [-E COLS]",
  "              [-r COL -i COL -p COL] [-c WIDTH] [FILE...]",
  "    column -J -N NAMES [-n NAME] [-s SEPSTR] [FILE...]",
  "    column --help | --version",
  "",
  "  -t          table mode",
  "  -x          fill rows before columns in non-table mode",
  "  -c WIDTH    output width (default: the terminal's, else COLUMNS, else",
  "              80); 0 or 'unlimited' never shrinks a table",
  "  -S NUM      use NUM spaces between non-table columns, no tabs",
  "  -s SEPSTR   each byte in SEPSTR splits input fields (preserves",
  "              empty fields between consecutive separators)",
  "  -o OUTSTR   column join string (default '  ')",
  "              getopt-style -ts:, -s:, and -o:: forms are accepted",
  "  -N NAMES, --table-columns=NAMES",
  "              comma-separated column names: a header row with -t,",
  "              the keys (in lower case) with -J",
  "  -d, --table-noheadings        keep -N names but print no header",
  "  -e, --table-header-repeat     repeat the header every LINES rows",
  "              (LINES, else the terminal height, else 24)",
  "  -L, --keep-empty-lines        keep whitespace-only lines (empty rows)",
  "  -J, --json  print the table as JSON; empty cells are null",
  "  -n NAME, --table-name=NAME",
  "              JSON table name (default table)",
  "  -l NUM, --table-columns-limit=NUM",
  "              at most NUM input columns; the last holds the rest of the line",
  "  -R COLS, --table-right=COLS   right-align these columns",
  "  -H COLS, --table-hide=COLS    do not print these columns ('-': unnamed ones)",
  "  -O COLS, --table-order=COLS   print these columns first, in this order",
  "  -T COLS, --table-truncate=COLS   truncate these columns when the table",
  "              is wider than the output",
  "  -W COLS, --table-wrap=COLS    wrap these columns onto more lines instead",
  "  -E COLS, --table-noextreme=COLS  these columns may give up width; a",
  "              longer cell then ends its line (default: the last column)",
  "              COLS is a comma-separated list of -N names, numbers from 1,",
  "              ranges such as 1-3 (not -O), 0 for all (not -O) and -1 for",
  "              the last visible column",
  "  -r COL, --tree=COL            draw COL as a tree of the rows: each row",
  "  -i COL, --tree-id=COL         whose -i cell is another row's -p cell is",
  "  -p COL, --tree-parent=COL     that row's parent (needs -i and -p)",
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
  "column [-xL] [-c WIDTH] [-t [-s SEPSTR] [-o OUTSTR] [-N NAMES] [-dLe] [-l NUM] [-R|-H|-O|-T|-W|-E COLS] [-r COL -i COL -p COL]] [-J -N NAMES [-n NAME]] [FILE...]",
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
