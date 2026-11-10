/* SPDX-License-Identifier: MIT */
/* uudecode.c — decode traditional uuencode (`begin MODE NAME`) and
 *                   base64-uuencode (`begin-base64 MODE NAME`) streams.
 *
 *   uudecode [-m] [-o OUT] [FILE...]
 *
 * Written independently. Header rules, statuses and partial output follow
 * GNU sharutils uudecode as black-box runs of it show them: the first line
 * starting "begin" must be a valid header, malformed input stops with
 * status 2 and keeps what was already decoded, an unreadable FILE gives
 * status 4 after the others are decoded, and an output failure stops with
 * status 8. A zero-length base64 line is malformed input and stays status
 * 2. GNU sharutils exits 8 for that line, because fwrite of a zero-length
 * buffer fails its check; that status is not copied. -m is a no-op.
 *
 * FILE = "-" or omitted reads stdin. -o "-" or "/dev/stdout" writes to
 * stdout (does not chmod). Otherwise the output path defaults to the
 * filename baked into the begin line, with its mode's permission bits.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "loadables.h"

#define BU_INVALID   2		/* malformed input: stops the run */
#define BU_NO_INPUT  4		/* a FILE cannot be opened: the rest still run */
#define BU_NO_OUTPUT 8		/* the output cannot be opened or written: stops */

#define BU_LINE 16384

static int
b64val (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

/* Find the header. The first line starting "begin" decides: it is
   "begin " or "begin-base64 ", an octal mode as scanf reads one (sign and
   leading blanks allowed, it ends at the first non-octal digit), then a
   non-empty name running to the newline with trailing blanks dropped.
   A header cut off before its newline is not one. */
static int
bu_header (FILE *in, const char *src, int *is_b64, unsigned *mode,
	   char *name)
{
  char line[BU_LINE];
  const char *p;
  size_t len;
  unsigned long v = 0;
  int neg = 0, digits = 0;

  do
    if (!fgets (line, sizeof line, in))
      goto bad;
  while (strncmp (line, "begin", 5));

  if (!strncmp (line, "begin-base64 ", 13))
    *is_b64 = 1, p = line + 13;
  else if (!strncmp (line, "begin ", 6))
    *is_b64 = 0, p = line + 6;
  else
    goto bad;
  len = strlen (line);
  if (line[len - 1] != '\n')
    goto bad;

  while (isspace ((unsigned char) *p)) p++;
  if (*p == '+' || *p == '-')
    neg = *p++ == '-';
  for (; *p >= '0' && *p <= '7'; p++, digits++)
    v = v * 8 + (unsigned) (*p - '0');
  if (!digits)
    goto bad;
  *mode = (unsigned) (neg ? -v : v) & 0777;

  while (isspace ((unsigned char) *p)) p++;
  len = strlen (p);
  while (len && isspace ((unsigned char) p[len - 1])) len--;
  if (!len)
    goto bad;
  memcpy (name, p, len);
  name[len] = 0;
  return 0;

bad:
  builtin_error ("%s: invalid or missing begin line", src);
  return BU_INVALID;
}

/* Traditional uuencode. The first byte of a line gives its decoded length;
   a zero length ends the data, and the next line must be "end". As with
   GNU, the length alone counts: a line shorter than it says decodes the
   bytes after it in the line buffer, which are its newline, the NUL fgets
   stores, and whatever earlier, longer lines left there (zero at first). */
#define UU_DEC(c) (((unsigned) (c) - ' ') & 077)

static int
bu_body_uu (FILE *in, FILE *out, const char *src)
{
  char buf[BU_LINE];
  int n;

  memset (buf, 0, sizeof buf);
  for (;;)
    {
      const unsigned char *p = (const unsigned char *) buf + 1;
      if (!fgets (buf, sizeof buf, in))
	{
	  builtin_error ("%s: short file", src);
	  return BU_INVALID;
	}
      if ((n = UU_DEC (buf[0])) == 0)
	break;
      for (; n > 0; p += 4, n -= 3)
	{
	  unsigned a = UU_DEC (p[0]), b = UU_DEC (p[1]);
	  unsigned c = UU_DEC (p[2]), d = UU_DEC (p[3]);
	  putc ((a << 2 | b >> 4) & 0xff, out);
	  if (n > 1)
	    putc ((b << 4 | c >> 2) & 0xff, out);
	  if (n > 2)
	    putc ((c << 6 | d) & 0xff, out);
	}
    }
  if (!fgets (buf, sizeof buf, in)
      || (strcmp (buf, "end\n") && strcmp (buf, "end\r\n")))
    {
      builtin_error ("%s: no end line", src);
      return BU_INVALID;
    }
  return 0;
}

/* One four-character base64 group into OUT: the byte count, or -1. */
static int
bu_quantum (const unsigned char *q, unsigned char *out)
{
  int a = b64val (q[0]), b = b64val (q[1]), c, d;

  if (a < 0 || b < 0)
    return -1;
  out[0] = (unsigned char) (a << 2 | b >> 4);
  if (q[2] == '=')
    return q[3] == '=' ? 1 : -1;
  if ((c = b64val (q[2])) < 0)
    return -1;
  out[1] = (unsigned char) (b << 4 | c >> 2);
  if (q[3] == '=')
    return 2;
  if ((d = b64val (q[3])) < 0)
    return -1;
  out[2] = (unsigned char) (c << 6 | d);
  return 3;
}

/* Base64 lines up to one starting "====". Newlines are not data; every
   other byte joins a four-character group, which may span lines, and a group
   left incomplete at the terminator is dropped. A line with no base64
   characters is invalid input (status 2): GNU sharutils exits 8 there.
   A line with a bad group writes nothing, so the output keeps only the
   lines before it. */
static int
bu_body_b64 (FILE *in, FILE *out, const char *src)
{
  char buf[BU_LINE];
  unsigned char group[4], obuf[BU_LINE];
  int held = 0;

  for (;;)
    {
      size_t len, made = 0;
      if (!fgets (buf, sizeof buf, in))
	{
	  builtin_error ("%s: short file", src);
	  return BU_INVALID;
	}
      if (!strncmp (buf, "====", 4))
	return 0;
      len = strlen (buf);
      int payload = 0;
      for (size_t i = 0; i < len; i++)
	{
	  int k;
	  if (buf[i] == '\n')
	    continue;
	  payload = 1;
	  group[held++] = (unsigned char) buf[i];
	  if (held < 4)
	    continue;
	  held = 0;
	  if ((k = bu_quantum (group, obuf + made)) < 0)
	    {
	      builtin_error ("%s: invalid base64 input", src);
	      return BU_INVALID;
	    }
	  made += (size_t) k;
	}
      /* A line with no base64 characters is invalid input (status 2).
         GNU sharutils fwrite's that empty decode with nmemb 1 and exits 8.
         Do not copy that. */
      if (!payload)
	{
	  builtin_error ("%s: invalid base64 input", src);
	  return BU_INVALID;
	}
      if (made && fwrite (obuf, 1, made, out) != made)
	return -1;
    }
}

/* Decode the first stream in IN: 0, or the status that ends the run. */
static int
bu_decode (FILE *in, const char *src, const char *override)
{
  char name[BU_LINE];
  unsigned mode = 0;
  int is_b64, rc, to_stdout;
  const char *outpath;
  FILE *out;

  if ((rc = bu_header (in, src, &is_b64, &mode, name)) != 0)
    return rc;

  /* Output: -o overrides; "-" or "/dev/stdout" goes to stdout untouched. */
  outpath = override ? override : name;
  to_stdout = !strcmp (outpath, "-") || !strcmp (outpath, "/dev/stdout");
  out = to_stdout ? stdout : fopen (outpath, "wb");
  if (!out || (!to_stdout && fchmod (fileno (out), mode) < 0))
    {
      builtin_error ("%s: %s", outpath, strerror (errno));
      if (out)
	fclose (out);
      return BU_NO_OUTPUT;
    }

  rc = is_b64 ? bu_body_b64 (in, out, src) : bu_body_uu (in, out, src);
  if (to_stdout ? fflush (out) != 0 || ferror (out) : fclose (out) != 0)
    rc = -1;
  if (rc < 0)
    {
      builtin_error ("%s: %s", outpath, strerror (errno));
      rc = BU_NO_OUTPUT;
    }
  return rc;
}

int
uudecode_builtin (WORD_LIST *list)
{
  const char *override = NULL;
  int status = EXECUTION_SUCCESS;

  /* Argv parse: accept -m (a no-op) and -o OUT before the FILEs. */
  while (list && list->word->word[0] == '-' && list->word->word[1])
    {
      const char *w = list->word->word;
      if (!strcmp (w, "-m"))
	{ list = list->next; continue; }
      if (!strcmp (w, "-o"))
	{
	  if (!list->next)
	    { builtin_error ("-o requires output"); return EX_USAGE; }
	  override = list->next->word->word;
	  list = list->next->next;
	  continue;
	}
      if (!strcmp (w, "--"))
	{ list = list->next; break; }
      builtin_error ("invalid option: %s", w);
      builtin_usage ();
      return EX_USAGE;
    }

  if (!list)
    return bu_decode (stdin, "stdin", override);
  for (; list; list = list->next)
    {
      const char *src = list->word->word;
      int is_stdin = !strcmp (src, "-"), rc;
      FILE *in = is_stdin ? stdin : fopen (src, "r");
      if (!in)
	{
	  builtin_error ("%s: %s", src, strerror (errno));
	  status = BU_NO_INPUT;
	  continue;
	}
      rc = bu_decode (in, is_stdin ? "stdin" : src, override);
      if (!is_stdin)
	fclose (in);
      if (rc)
	return rc;
    }
  return status;
}

char *uudecode_doc[] = {
  "Decode traditional uuencode and base64-uuencode streams.",
  "",
  "    uudecode [-m] [-o OUT] [FILE...]",
  "",
  "Each FILE ('-' or none for stdin) is searched for its first line",
  "starting 'begin': 'begin MODE NAME' starts uuencoded lines ending with",
  "a zero-length line and 'end', 'begin-base64 MODE NAME' base64 lines",
  "ending with '===='. Output goes to NAME, or OUT with -o, with the",
  "permission bits of MODE; '-' and '/dev/stdout' write to stdout. -m is",
  "accepted as a no-op.",
  "",
  "Exit status is 2 for malformed input and 8 when the output cannot be",
  "written, both stopping at once and keeping what was decoded; 4 when a",
  "FILE cannot be opened, after decoding the others; otherwise 0.",
  "A zero-length base64 line stays status 2. GNU sharutils exits 8 for",
  "that line because fwrite of a zero-length buffer fails its check;",
  "that status-8 result is not copied.",
  (char *) NULL
};

struct builtin uudecode_struct = {
  "uudecode", uudecode_builtin, BUILTIN_ENABLED, uudecode_doc,
  "uudecode [-m] [-o OUT] [FILE...]", 0
};
