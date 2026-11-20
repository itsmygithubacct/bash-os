/* SPDX-License-Identifier: MIT */
/* split.c — POSIX split(1) as a bash builtin.
 *
 *   split [-l N | -b SIZE | -n CHUNKS] [-a SUFLEN] [INPUT [PREFIX]]
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

/* Whole input in memory: -n needs the total size before writing. */
static unsigned char *
bs_slurp (FILE *in, size_t *size)
{
    size_t cap = 65536, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { builtin_error ("out of memory"); return NULL; }
    for (;;) {
        if (len == cap) {
            unsigned char *grown = cap > SIZE_MAX / 2 ? NULL : realloc (buf, cap * 2);
            if (!grown) { free (buf); builtin_error ("out of memory"); return NULL; }
            buf = grown;
            cap *= 2;
        }
        size_t r = fread (buf + len, 1, cap - len, in);
        len += r;
        if (r == 0) break;
    }
    *size = len;
    return buf;
}

/* Write one -n piece. Index IDX names the file; with K set, only piece K
   goes to standard output and nothing is created. */
static int
bs_put_piece (const unsigned char *data, size_t n, int to_stdout,
              char *namebuf, size_t namecap, const char *prefix, int suflen,
              long idx, int numeric, const struct stat *input_stat, FILE **open_out,
              int append)
{
    if (to_stdout) {
        if (n && fwrite (data, 1, n, stdout) != n) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            return -1;
        }
        return 0;
    }
    if (!append || !*open_out) {
        if (*open_out && bs_close_output (*open_out, namebuf) < 0) { *open_out = NULL; return -1; }
        *open_out = NULL;
        if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
            builtin_error ("split: suffix exhausted (try larger -a)");
            return -1;
        }
        *open_out = bs_open_output (namebuf, input_stat);
        if (!*open_out) return -1;
    }
    if (n && fwrite (data, 1, n, *open_out) != n) {
        builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

/* GNU split -n CHUNKS: N, K/N, l/N, l/K/N, r/N, r/K/N. */
static int
bs_split_chunks (FILE *fin, int mode, uintmax_t k, uintmax_t n, char *namebuf,
                 size_t namecap, const char *prefix, int suflen, long start,
                 int numeric, const struct stat *input_stat)
{
    size_t size;
    unsigned char *data = bs_slurp (fin, &size);
    if (!data) return -1;
    if (ferror (fin)) { free (data); return 0; }   /* reported by the caller */
    FILE *out = NULL;
    int rc = 0;
    if (mode == 'b') {
        uintmax_t base = size / n, rem = size % n;
        for (uintmax_t c = 1; c <= n && rc == 0; c++) {
            uintmax_t from = (c - 1) * base + (c - 1 < rem ? c - 1 : rem);
            uintmax_t to = c * base + (c < rem ? c : rem);
            if (k && c != k) continue;
            rc = bs_put_piece (data + from, (size_t) (to - from), k != 0, namebuf, namecap,
                               prefix, suflen, start + (long) (c - 1), numeric,
                               input_stat, &out, 0);
        }
    } else if (mode == 'l') {
        /* GNU's lines_chunk_split: piece C ends at the first newline at or
           after its byte boundary (the boundaries of plain -n N), so a long
           line can leave later pieces empty; the last piece takes the rest. */
        uintmax_t base = size / n, rem = size % n, chunk_no = 1;
        uintmax_t chunk_end = base + (rem ? 1 : 0);   /* one past the boundary byte */
        size_t pos = 0;
        if (!k) rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                                   start, numeric, input_stat, &out, 0);
        while (rc == 0 && pos < size) {
            size_t look = chunk_end > pos + 1 ? (size_t) chunk_end - 1 : pos;
            if (chunk_no == n) look = size;
            const unsigned char *nl = look < size ? memchr (data + look, '\n', size - look) : NULL;
            size_t stop = nl ? (size_t) (nl - data) + 1 : size;
            if (!k || k == chunk_no)
                rc = bs_put_piece (data + pos, stop - pos, k != 0, namebuf, namecap, prefix,
                                   suflen, start + (long) (chunk_no - 1), numeric,
                                   input_stat, &out, 1);
            pos = stop;
            if (rc || pos >= size) break;
            /* Advance to the piece the next line starts in, creating any
               piece a long line skipped over. */
            do {
                chunk_no++;
                if (k && chunk_no > k) goto done;
                chunk_end = chunk_no == n ? size
                    : chunk_no * base + (chunk_no < rem ? chunk_no : rem);
                if (!k)
                    rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                                       start + (long) (chunk_no - 1), numeric,
                                       input_stat, &out, 0);
            } while (rc == 0 && chunk_end <= pos && chunk_no < n);
        }
        while (rc == 0 && !k && chunk_no < n) {
            chunk_no++;
            rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                               start + (long) (chunk_no - 1), numeric, input_stat, &out, 0);
        }
    } else {
        /* Round robin: line I goes to piece I mod N. All N files exist. */
        FILE **outs = NULL;
        char **names = NULL;
        if (!k) {
            outs = calloc ((size_t) n, sizeof *outs);
            names = calloc ((size_t) n, sizeof *names);
            if (!outs || !names) { builtin_error ("out of memory"); rc = -1; }
            for (uintmax_t c = 0; rc == 0 && c < n; c++) {
                names[c] = malloc (namecap);
                if (!names[c]) { builtin_error ("out of memory"); rc = -1; break; }
                if (bs_make_name (names[c], namecap, prefix, suflen, start + (long) c, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = -1;
                    break;
                }
                outs[c] = bs_open_output (names[c], input_stat);
                if (!outs[c]) rc = -1;
            }
        }
        size_t pos = 0;
        uintmax_t line = 0;
        while (rc == 0 && pos < size) {
            const unsigned char *nl = memchr (data + pos, '\n', size - pos);
            size_t stop = nl ? (size_t) (nl - data) + 1 : size;
            uintmax_t c = line++ % n;
            FILE *dst = k ? (c + 1 == k ? stdout : NULL) : outs[c];
            if (dst && fwrite (data + pos, 1, stop - pos, dst) != stop - pos) {
                builtin_error ("write %s: %s", k ? "error" : names[c], strerror (errno ? errno : EIO));
                rc = -1;
            }
            pos = stop;
        }
        for (uintmax_t c = 0; outs && c < n; c++)
            if (outs[c] && bs_close_output (outs[c], names[c]) < 0) rc = -1;
        for (uintmax_t c = 0; names && c < n; c++) free (names[c]);
        free (outs);
        free (names);
    }
done:
    if (out && bs_close_output (out, namebuf) < 0) rc = -1;
    if (k && fflush (stdout) == EOF) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        rc = -1;
    }
    free (data);
    return rc;
}

/* Parse -n CHUNKS. Returns 0 and the mode ('b', 'l' or 'r'), K and N. */
static int
bs_parse_chunks (const char *v, int *mode, uintmax_t *k, uintmax_t *n)
{
    *mode = 'b';
    *k = 0;
    if ((v[0] == 'l' || v[0] == 'r') && v[1] == '/') { *mode = v[0]; v += 2; }
    const char *slash = strchr (v, '/');
    char *end;
    if (slash) {
        if (*v < '0' || *v > '9') return -1;
        errno = 0;
        *k = strtoumax (v, &end, 10);
        if (errno || end != slash) return -1;
        if (*k == 0) return -2;
        v = slash + 1;
    }
    if (*v < '0' || *v > '9') return -1;
    errno = 0;
    *n = strtoumax (v, &end, 10);
    if (errno || *end || *n == 0 || *n > 100000000) return -1;
    if (*k > *n) return -2;
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
    const char *chunks = NULL;

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
        if (!strncmp (w, "-n", 2) || !strncmp (w, "--number=", 9)) {
            const char *v = w[1] == '-' ? w + 9
                : w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("option requires an argument -- 'n'"); builtin_usage (); return EXECUTION_FAILURE; }
            chunks = v;
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

    if (chunks) {
        int mode;
        uintmax_t k, n;
        int bad = bs_parse_chunks (chunks, &mode, &k, &n);
        if (bad == -2) {
            builtin_error ("invalid chunk number: '%ju'", k);
            rc = EXECUTION_FAILURE;
        } else if (bad < 0) {
            const char *num = chunks;
            if ((num[0] == 'l' || num[0] == 'r') && num[1] == '/') num += 2;
            const char *slash = strrchr (num, '/');
            builtin_error ("invalid number of chunks: '%s'", slash ? slash + 1 : num);
            rc = EXECUTION_FAILURE;
        } else if (bs_split_chunks (fin, mode, k, n, namebuf, namecap, prefix, suflen,
                                    start, numeric, &input_stat) < 0)
            rc = EXECUTION_FAILURE;
    } else if (byte_chunk > 0) {
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
    "    split [-l N | -b SIZE | -n CHUNKS] [-a SUFLEN] [INPUT [PREFIX]]",
    "",
    "    -l N        N lines per piece (default 1000)",
    "    -b SIZE     SIZE bytes per piece; b=512, K=1024, KB=1000, KiB=1024",
    "                Units K, M, G, T, P, E, Z, Y, R, Q; k/m also accepted",
    "    -n CHUNKS   N, K/N, l/N, l/K/N, r/N or r/K/N pieces, as GNU split;",
    "                with K, piece K goes to standard output",
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
    "split [-l N | -b SIZE | -n CHUNKS] [-a SUFLEN] [INPUT [PREFIX]]",
    0
};
