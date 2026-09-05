/* bashfold.c — POSIX fold(1) as a bash builtin.
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashfold [-bs] [-w WIDTH] [FILE...]
 *
 *   -w WIDTH   wrap at WIDTH columns (default 80)
 *   -b         count bytes, not display columns (treat each byte as 1)
 *   -s         break at last whitespace ≤ WIDTH (word-wrap), if any
 *
 * No FILE or "-" reads stdin. Default mode counts display columns,
 * with TAB advancing to next multiple of 8, BS rewinding by one,
 * CR resetting to column 0.
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
#include <fcntl.h>
#include <ctype.h>
#include <wchar.h>

#include "loadables.h"

typedef struct { int width; int bflag; int sflag; int cflag; } bf_opts;

/* Decode one logical unit from BYTES[0..avail-1] into *cp, returning its
 * byte length (1..4). Mirrors the three counting modes of GNU coreutils
 * fold (which reads whole characters via mbbuf/mcel):
 *
 *   -b (COUNT_BYTES):   the unit is a single byte — fold may split a
 *                       multibyte sequence at a byte boundary.
 *   else (CHARACTERS / COLUMNS): the unit is a whole UTF-8 character, so
 *                       a wrap never falls inside a multibyte sequence.
 *
 * An incomplete or malformed sequence decodes as its lead byte alone
 * (length 1), which the width logic then treats as a width-1 character —
 * matching fold's "default to width 1 on an invalid character". */
static int
bf_decode (const unsigned char *bytes, size_t avail, const bf_opts *o,
           unsigned int *cp)
{
    unsigned int c = bytes[0];
    *cp = c;
    if (o->bflag || c < 0x80)
        return 1;
    int need;
    unsigned int code;
    if (c >= 0xC0 && c < 0xE0)      { need = 1; code = c & 0x1F; }
    else if (c >= 0xE0 && c < 0xF0) { need = 2; code = c & 0x0F; }
    else if (c >= 0xF0 && c < 0xF8) { need = 3; code = c & 0x07; }
    else                            return 1;   /* stray continuation / 5+ byte */
    if (avail < (size_t) need + 1)
        return 1;                               /* truncated: lead byte alone */
    for (int k = 1; k <= need; k++) {
        if ((bytes[k] & 0xC0) != 0x80)
            return 1;                           /* not a continuation */
        code = (code << 6) | (bytes[k] & 0x3F);
    }
    *cp = code;
    return need + 1;
}

/* Column reached after consuming the unit (codepoint CP, byte length LEN)
 * starting from COL. *LAST_W carries the width of the most recent
 * non-control character so '\b' can rewind by the right amount, exactly
 * as fold's adjust_column() uses last_character_width. */
static int
bf_advance (int col, unsigned int cp, int len, int *last_w, const bf_opts *o)
{
    if (o->bflag)
        return col + len;                       /* bytes: TAB/CR/BS not special */
    if (cp == '\b')
        return col > *last_w ? col - *last_w : 0;
    if (cp == '\r')
        return 0;
    if (cp == '\t')
        return col + (8 - (col % 8));
    if (o->cflag) {
        *last_w = 1;                            /* characters: one per char */
        return col + 1;
    }
    int w = wcwidth ((wchar_t) cp);             /* columns: display width */
    if (w < 0)
        w = 1;                                  /* invalid char defaults to 1 */
    *last_w = w;
    return col + w;
}

typedef struct {
    const char **v;
    int n;
    int cap;
} bf_files;

static int
bf_files_add (bf_files *files, const char *path)
{
    if (files->n == files->cap) {
        int new_cap = files->cap ? files->cap * 2 : 16;
        const char **nv = realloc (files->v, (size_t) new_cap * sizeof (*files->v));
        if (!nv) {
            builtin_error ("realloc: %s", strerror (errno));
            return -1;
        }
        files->v = nv;
        files->cap = new_cap;
    }
    files->v[files->n++] = path;
    return 0;
}

static int
bf_parse_width (const char *arg, int *width)
{
    char *end = NULL;
    long n;

    errno = 0;
    n = strtol (arg, &end, 10);
    if (errno || end == arg || *end != '\0' || n < 1 || n > 2147483647L)
        return 0;
    *width = (int) n;
    return 1;
}

/* Process one input stream. Wraps at o.width columns; emits to stdout.
 * Input is consumed a whole character at a time (a single byte under -b)
 * via a small refillable lookahead so a multibyte sequence is never
 * split across a stream-buffer boundary or a wrap. */
static int
bf_fold_stream (FILE *in, const bf_opts *o, const char *name)
{
    /* buf holds the current pending output line, flushed when a unit
       would push the column past the width (or on newline). */
    size_t cap = (size_t) o->width + 64;
    char *buf = (char *) malloc (cap);
    if (!buf) {
        builtin_error ("malloc: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    size_t len = 0;       /* bytes in buf */
    int col = 0;          /* current column position */
    int last_space = -1;  /* byte index of last blank in buf, for -s */
    int last_w = 1;       /* width of last non-control char, for '\b' */

    unsigned char ib[8192];     /* input lookahead */
    size_t ipos = 0, iend = 0;
    int eof = 0;

    for (;;) {
        /* Keep >=4 bytes available so a full UTF-8 unit is decodable. */
        if (!eof && iend - ipos < 4) {
            if (ipos > 0) { memmove (ib, ib + ipos, iend - ipos); iend -= ipos; ipos = 0; }
            size_t got = fread (ib + iend, 1, sizeof ib - iend, in);
            if (got == 0) eof = 1;
            iend += got;
        }
        if (ipos >= iend) break;

        unsigned int cp;
        int clen = bf_decode (ib + ipos, iend - ipos, o, &cp);

        if (cp == '\n' && clen == 1) {
            fwrite (buf, 1, len, stdout);
            putchar ('\n');
            len = 0; col = 0; last_space = -1; last_w = 1;
            ipos += 1;
            continue;
        }

        int new_col = bf_advance (col, cp, clen, &last_w, o);
        /* While this unit would exceed the width, flush the line and
           re-evaluate the unit against the (now shorter) remainder. This
           loop mirrors GNU fold's `goto rescan`: a single flush is not
           always enough — e.g. under -s, after breaking at an earlier blank
           the remainder may still be too narrow for the incoming unit and
           must itself be flushed (so a TAB lands on its own line rather than
           gluing to the word before it). A unit wider than the whole width
           is emitted alone once the buffer drains (len == 0). */
        while (new_col > o->width && len > 0) {
            int break_at = (int) len;              /* default: flush whole line */
            if (o->sflag && last_space >= 0)
                break_at = last_space + 1;         /* -s: break after the blank */
            fwrite (buf, 1, (size_t) break_at, stdout);
            putchar ('\n');
            /* Shift remainder to start of buf. */
            size_t rem = len - (size_t) break_at;
            if (rem > 0) memmove (buf, buf + break_at, rem);
            len = rem;
            /* Recompute col/last_space/last_w over the remainder. */
            col = 0; last_space = -1; last_w = 1;
            for (size_t i = 0; i < len; ) {
                unsigned int cp2;
                int l2 = bf_decode ((unsigned char *) buf + i, len - i, o, &cp2);
                col = bf_advance (col, cp2, l2, &last_w, o);
                if (cp2 == ' ' || cp2 == '\t') last_space = (int) i;
                i += (size_t) l2;
            }
            new_col = bf_advance (col, cp, clen, &last_w, o);
        }

        if (len + (size_t) clen > cap) {
            while (len + (size_t) clen > cap) cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) { free (buf); builtin_error ("realloc"); return EXECUTION_FAILURE; }
            buf = nb;
        }
        if (cp == ' ' || cp == '\t') last_space = (int) len;   /* blank at this offset */
        memcpy (buf + len, ib + ipos, (size_t) clen);
        len += (size_t) clen;
        col = new_col;
        ipos += (size_t) clen;
    }

    if (len > 0) fwrite (buf, 1, len, stdout);
    free (buf);
    if (ferror (in)) {
        builtin_error ("read %s: %s", name ? name : "stdin", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

int
fold_builtin (WORD_LIST *list)
{
    bf_opts o = { .width = 80, .bflag = 0, .sflag = 0, .cflag = 0 };
    bf_files files = {0};

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            free (files.v);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashfold 1.0 (bash-loadable)");
            free (files.v);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bf_files_add (&files, p->word->word) < 0) {
                    free (files.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (strcmp (w, "--width") == 0) {
            if (!p->next) {
                builtin_error ("--width needs WIDTH");
                builtin_usage ();
                return EX_USAGE;
            }
            if (!bf_parse_width (p->next->word->word, &o.width)) {
                builtin_error ("invalid width: %s", p->next->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            p = p->next;
            continue;
        }
        if (strncmp (w, "--width=", 8) == 0) {
            if (!bf_parse_width (w + 8, &o.width)) {
                builtin_error ("invalid width: %s", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (strcmp (w, "--bytes") == 0) {
            o.bflag = 1; o.cflag = 0;   /* counting mode: last one wins */
            continue;
        }
        if (strcmp (w, "--characters") == 0) {
            o.cflag = 1; o.bflag = 0;
            continue;
        }
        if (strcmp (w, "--spaces") == 0) {
            o.sflag = 1;
            continue;
        }
        /* -NN shorthand for -w NN (POSIX historical). */
        if (w[0] == '-' && w[1] >= '0' && w[1] <= '9') {
            if (!bf_parse_width (w + 1, &o.width)) {
                builtin_error ("invalid width: %s", w);
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            /* Reject long-option-style --foo as unknown flag. */
            if (w[1] == '-' && w[2] != '\0') {
                builtin_error ("unknown flag: %s", w);
                builtin_usage ();
                return EX_USAGE;
            }
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'b': o.bflag = 1; o.cflag = 0; break;  /* last mode wins */
                case 'c': o.cflag = 1; o.bflag = 0; break;
                case 's': o.sflag = 1; break;
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                    if (!bf_parse_width (w + i, &o.width)) {
                        builtin_error ("invalid width: %s", w + i);
                        builtin_usage ();
                        free (files.v);
                        return EX_USAGE;
                    }
                    i = (int) strlen (w) - 1;
                    break;
                case 'w':
                    if (w[i + 1]) {
                        if (!bf_parse_width (w + i + 1, &o.width)) {
                            builtin_error ("invalid width: %s", w + i + 1);
                            builtin_usage ();
                            free (files.v);
                            return EX_USAGE;
                        }
                    } else {
                        if (!p->next) {
                            builtin_error ("-w needs WIDTH");
                            builtin_usage ();
                            free (files.v);
                            return EX_USAGE;
                        }
                        if (!bf_parse_width (p->next->word->word, &o.width)) {
                            builtin_error ("invalid width: %s", p->next->word->word);
                            builtin_usage ();
                            free (files.v);
                            return EX_USAGE;
                        }
                        p = p->next;
                    }
                    i = (int) strlen (w) - 1;
                    break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    free (files.v);
                    return EX_USAGE;
                }
            }
        } else {
            if (bf_files_add (&files, w) < 0) {
                free (files.v);
                return EXECUTION_FAILURE;
            }
        }
    }

    int rc = EXECUTION_SUCCESS;
    if (files.n == 0) {
        if (bf_fold_stream (stdin, &o, NULL) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
    } else {
        for (int i = 0; i < files.n; i++) {
            FILE *fp = (strcmp (files.v[i], "-") == 0) ? stdin : fopen (files.v[i], "r");
            if (!fp) {
                builtin_error ("%s: %s", files.v[i], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (bf_fold_stream (fp, &o, files.v[i]) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
            if (fp != stdin) fclose (fp);
        }
    }
    free (files.v);
    return rc;
}

char *fold_doc[] = {
    "POSIX fold — wrap each input line to fit a column width.",
    "",
    "    bashfold [-bcs] [-w WIDTH] [FILE...]",
    "    bashfold --help | --version",
    "",
    "    -w WIDTH   wrap at WIDTH columns (default 80)",
    "    -b         count bytes, not display columns",
    "    -c         count characters: a UTF-8 char is one unit and a",
    "               wrap never splits a multibyte sequence",
    "    -s         break at last whitespace ≤ WIDTH (word-wrap)",
    "    --help | --version",
    "               show usage or version",
    "",
    "TAB → next multiple of 8; BS rewinds; CR resets column to 0",
    "(unless -b is set). -b and -c are mutually exclusive (last wins).",
    "No FILE or '-' reads stdin.",
    (char *)NULL
};

struct builtin bashfold_struct = {
    "bashfold",
    fold_builtin,
    BUILTIN_ENABLED,
    fold_doc,
    "bashfold [-bcs] [-w WIDTH] [FILE...]",
    0
};
