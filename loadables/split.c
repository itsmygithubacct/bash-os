/* SPDX-License-Identifier: MIT */
/* split.c — POSIX split(1) as a bash builtin.
 *
 *   split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]
 *
 * Splits INPUT (or stdin) into pieces named PREFIX{aa,ab,ac,...}.
 * Default: -l 1000 lines per piece, -a 2 (suffix length), PREFIX=x.
 *
 * SIZE accepts GNU byte units: b (512), K..Q (powers of 1024),
 * KB..QB (powers of 1000), and KiB..QiB (powers of 1024).
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "loadables.h"

static long long
bs_parse_count (const char *s)
{
    char *end;
    errno = 0;
    long long n = strtoll (s, &end, 10);
    if (errno == ERANGE || end == s || n <= 0) return -1;
    return *end == '\0' ? n : -1;
}

static int
bs_parse_size (const char *s, uintmax_t *size)
{
    const char *number = s;
    char *end;
    while (isspace ((unsigned char) *number)) number++;
    if (*number == '-') return -1;
    errno = 0;
    uintmax_t n = strtoumax (s, &end, 10);
    if (end == s) {
        /* A unit by itself means one; whitespace/signs still need digits. */
        if (!*s || !strchr ("bkmKMGTPEZYRQ", *s)) return -1;
        n = 1;
    } else if (errno && errno != ERANGE) {
        return -1;
    }
    if (!n) return -1;

    unsigned int power = 0;
    uintmax_t base = 1024;
    if (*end == 'b' && end[1] == '\0') {
        base = 512;
        power = 1;
    } else if (*end) {
        const char *units = "KMGTPEZYRQ";
        int unit = *end == 'k' ? 'K' : *end == 'm' ? 'M' : *end;
        const char *position = strchr (units, unit);
        if (!position) return -1;
        power = (unsigned int) (position - units) + 1;
        end++;
        if (!strcmp (end, "B")) base = 1000;
        else if (*end && strcmp (end, "iB")) return -1;
    }
    /* GNU accepts overflowing sizes as an unbounded chunk. Saturation keeps
       the streaming counters unsigned and never wraps a large size to zero. */
    while (power--) n = n > UINTMAX_MAX / base ? UINTMAX_MAX : n * base;
    *size = n;
    return 0;
}

/* Compose PREFIX + a fixed-width suffix from `index`, using lowercase
   letters or decimal digits. Returns -1 if index exceeds capacity. */
static int
bs_make_name (char *out, size_t cap, const char *prefix, int suflen, long index,
              int numeric)
{
    size_t plen = strlen (prefix);
    if (plen + (size_t) suflen + 1 > cap) return -1;
    memcpy (out, prefix, plen);
    long max = 1;
    int base = numeric ? 10 : 26;
    for (int i = 0; i < suflen; i++) max *= base;
    if (index >= max) return -1;
    for (int i = suflen - 1; i >= 0; i--) {
        out[plen + i] = (numeric ? '0' : 'a') + (char) (index % base);
        index /= base;
    }
    out[plen + suflen] = '\0';
    return 0;
}

/* stdin's FILE belongs to the persistent shell. A private stream so a later
   redirection is not stuck at EOF from this invocation. */
static FILE *
bs_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
    if (!in) {
        int error = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (error));
    }
    return in;
}

/* Open without truncation until we know this is not the input, including
   a hard link or a symlink to it. fdopen("w") does not truncate the fd. */
static FILE *
bs_open_output (const char *name, const struct stat *input)
{
    int fd = open (name, O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        builtin_error ("create %s: %s", name, strerror (errno));
        return NULL;
    }
    struct stat output;
    if (fstat (fd, &output) < 0) {
        builtin_error ("stat %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    if (output.st_dev == input->st_dev && output.st_ino == input->st_ino) {
        builtin_error ("%s would overwrite the input", name);
        close (fd);
        return NULL;
    }
    if (S_ISREG (output.st_mode) && ftruncate (fd, 0) < 0) {
        builtin_error ("truncate %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    FILE *out = fdopen (fd, "w");
    if (!out) {
        builtin_error ("open %s: %s", name, strerror (errno));
        close (fd);
    }
    return out;
}

static int
bs_close_output (FILE *out, const char *name)
{
    if (fclose (out) == EOF) {
        builtin_error ("write %s: %s", name, strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

int
split_builtin (WORD_LIST *list)
{
    long line_chunk = 1000;     /* -l N default */
    uintmax_t byte_chunk = 0;   /* -b SIZE; 0 = use lines */
    int suflen = 2;             /* -a */
    int numeric = 0;
    long start = 0;
    const char *prefix = "x";
    const char *input = NULL;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strncmp (w, "--numeric-suffixes=", 19)) {
            const char *p = w + 19;
            long value = 0;
            /* GNU treats an explicitly empty starting value as zero. */
            for (; *p; p++) {
                if (*p < '0' || *p > '9' || value > (LONG_MAX - (*p - '0')) / 10)
                    goto invalid_start;
                value = value * 10 + (*p - '0');
            }
            numeric = 1;
            start = value;
            list = list->next;
            continue;
invalid_start:
            builtin_error ("invalid start value for numerical suffix: %s", w + 19);
            return EXECUTION_FAILURE;
        }
        if (!strcmp (w, "-l") || !strncmp (w, "-l", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-l needs N"); builtin_usage (); return EXECUTION_FAILURE; }
            long long value = bs_parse_count (v);
            if (value <= 0 || value > LONG_MAX) {
                builtin_error ("-l: invalid line count: %s", v);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            line_chunk = (long) value;
            byte_chunk = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-b") || !strncmp (w, "-b", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-b needs SIZE"); builtin_usage (); return EXECUTION_FAILURE; }
            if (bs_parse_size (v, &byte_chunk) < 0) { builtin_error ("-b: bad SIZE: %s", v); builtin_usage (); return EXECUTION_FAILURE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-a") || !strncmp (w, "-a", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-a needs SUFLEN"); builtin_usage (); return EXECUTION_FAILURE; }
            long long value = bs_parse_count (v);
            if (value < 1 || value > 6) { builtin_error ("-a: SUFLEN must be in 1..6"); builtin_usage (); return EXECUTION_FAILURE; }
            suflen = (int) value;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (list) { input = list->word->word; list = list->next; }
    if (list) { prefix = list->word->word; list = list->next; }
    if (list) { builtin_error ("split: extra argument: %s", list->word->word); builtin_usage (); return EXECUTION_FAILURE; }

    if (numeric) {
        long capacity = 1;
        for (int i = 0; i < suflen; i++) capacity *= 10;
        if (start >= capacity) {
            builtin_error ("numerical suffix start value is too large for the suffix length");
            return EXECUTION_FAILURE;
        }
    }

    int from_stdin = !input || !strcmp (input, "-");
    FILE *fin = from_stdin ? bs_open_stdin () : fopen (input, "r");
    if (!fin) {
        if (!from_stdin) builtin_error ("%s: %s", input, strerror (errno));
        return EXECUTION_FAILURE;
    }

    struct stat input_stat;
    if (fstat (fileno (fin), &input_stat) < 0) {
        builtin_error ("stat input: %s", strerror (errno));
        fclose (fin);
        return EXECUTION_FAILURE;
    }
    size_t namecap = strlen (prefix) + (size_t) suflen + 1;
    char *namebuf = malloc (namecap);
    if (!namebuf) {
        builtin_error ("out of memory");
        fclose (fin);
        return EXECUTION_FAILURE;
    }
    long idx = start;
    int rc = EXECUTION_SUCCESS;

    if (byte_chunk > 0) {
        /* Byte-based splitting. */
        unsigned char buf[8192];
        uintmax_t left_in_chunk = 0;
        FILE *fout = NULL;
        for (;;) {
            /* Read BEFORE opening the next output file. GNU split never
               creates an empty trailing piece: a file is opened only once we
               have a byte to put in it, so an empty input (or an input whose
               size is an exact multiple of the chunk) produces no spurious
               zero-length file. */
            uintmax_t cap_chunk = (left_in_chunk > 0) ? left_in_chunk : byte_chunk;
            size_t want = sizeof buf > cap_chunk ? (size_t) cap_chunk : sizeof buf;
            size_t r = fread (buf, 1, want, fin);
            if (r == 0) break;
            if (fout == NULL) {
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
                    rc = EXECUTION_FAILURE;
                    break;
                }
                left_in_chunk = byte_chunk;
            }
            if (fwrite (buf, 1, r, fout) != r) {
                builtin_error ("write %s: %s", namebuf, strerror (errno));
                rc = EXECUTION_FAILURE;
                break;
            }
            left_in_chunk -= r;
            if (left_in_chunk == 0) {
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
    } else {
        /* Line-based splitting. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        long lines_in_chunk = 0;
        FILE *fout = NULL;
        while ((n = getline (&line, &cap, fin)) != -1) {
            if (lines_in_chunk == 0) {
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
                    rc = EXECUTION_FAILURE;
                    break;
                }
            }
            if (fwrite (line, 1, (size_t) n, fout) != (size_t) n) {
                builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
                rc = EXECUTION_FAILURE;
                break;
            }
            lines_in_chunk++;
            if (lines_in_chunk >= line_chunk) {
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                lines_in_chunk = 0;
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
        free (line);
    }

    if (ferror (fin)) {
        builtin_error ("read %s: %s", input ? input : "stdin", strerror (errno ? errno : EIO));
        rc = EXECUTION_FAILURE;
    }
    if (fclose (fin) == EOF) {
        builtin_error ("close input: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    free (namebuf);
    return rc;
}

char *split_doc[] = {
    "Split a file into pieces (POSIX split).",
    "",
    "    split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]",
    "",
    "    -l N        N lines per piece (default 1000)",
    "    -b SIZE     SIZE bytes per piece; b=512, K=1024, KB=1000, KiB=1024",
    "                Units K, M, G, T, P, E, Z, Y, R, Q; k/m also accepted",
    "    -a SUFLEN   suffix length (default 2 → aa..zz, max 26^2 = 676)",
    "    --numeric-suffixes=FROM  use fixed-width decimal suffixes from FROM",
    "",
    "INPUT defaults to stdin (or `-`). Output files are named",
    "PREFIXaa, PREFIXab, ... where PREFIX defaults to `x`.",
    (char *)NULL
};

struct builtin split_struct = {
    "split",
    split_builtin,
    BUILTIN_ENABLED,
    split_doc,
    "split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]",
    0
};
