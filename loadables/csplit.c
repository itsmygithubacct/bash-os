/* SPDX-License-Identifier: MIT */
/* csplit.c — POSIX csplit(1) context split.
 *
 *   csplit [-k] [-s] [--help|--version] [-n DIGITS] [-f PREFIX]
 *              [-b SUFFIX-FORMAT] FILE PATTERN [PATTERN...]
 *
 *   -k            keep output files even if a pattern fails (default:
 *                 unlink them on error)
 *   --suppress-matched  omit the line matching PATTERN from the output
 *   -s            silent — don't print byte counts of each output file
 *   -n DIGITS     suffix length (default 2 → xx00, xx01, ..., xx99)
 *   -f PREFIX     output filename prefix (default: xx)
 *   -b FORMAT     printf-style suffix format (e.g. %03d.txt); overrides -n
 *
 * PATTERNs (read in order):
 *   /REGEX/[+OFF|-OFF] split before the line containing REGEX, offset by
 *                    OFF lines (negative offsets split before an earlier
 *                    line — the whole input is buffered to allow this)
 *   %REGEX%[+OFF|-OFF] skip pattern: discard input until REGEX matches,
 *                    don't create an output file
 *   N                split before line number N (1-based, absolute)
 *   {N}              repeat the previous pattern N more times
 *   {*}              repeat the previous pattern as long as it matches
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
#include <regex.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "shim-prog-name.h"

typedef enum { CS_NONE, CS_REGEX, CS_SKIP, CS_LINENO } cs_kind;

typedef struct {
    cs_kind kind;
    regex_t re;
    int     re_compiled;
    long    lineno;        /* absolute/interval target line (CS_LINENO) */
    long    offset;        /* +OFF / -OFF after a regex (may be negative) */
    long    repeat;        /* {N}; -1 for {*}; 0 = no repeat */
    const char *word;      /* original pattern token, for GNU-style errors */
} cs_pat;

typedef struct {
    char  *buf;          /* line content (with newline if any) */
    size_t len;          /* byte length */
} cs_line;

/* Build the output filename for chunk `idx`. With a printf-style
   suffix-format (-b), the format owns the numeric field and `digits` is
   ignored; otherwise the classic zero-padded field is used. Returns a
   malloc'd string (caller frees), or NULL on allocation failure. */
static char *
cs_chunk_name (const char *prefix, int idx, int digits, const char *sfmt)
{
    char tail[256];
    if (sfmt)
        snprintf (tail, sizeof tail, sfmt, idx);
    else
        snprintf (tail, sizeof tail, "%0*d", digits, idx);
    size_t plen = strlen (prefix);
    size_t tlen = strlen (tail);
    char *out = malloc (plen + tlen + 1);
    if (!out) return NULL;
    memcpy (out, prefix, plen);
    memcpy (out + plen, tail, tlen + 1);
    return out;
}

static void
cs_print_size (FILE *f, int silent)
{
    if (silent) return;
    long pos = ftell (f);
    if (pos < 0) pos = 0;
    printf ("%ld\n", pos);
}

/* Validate a -b suffix-format: GNU requires exactly one printf integer
   conversion specification (% ... d/i/o/u/x/X) and rejects others. We do a
   light check: there must be a '%' that is not '%%', and the conversion
   letter must be an integer conversion. Returns 0 on success, -1 on error. */
static int
cs_check_suffix_format (const char *fmt)
{
    int conversions = 0;
    const char *p = fmt;
    while ((p = strchr (p, '%')) != NULL) {
        if (p[1] == '%') { p += 2; continue; }
        /* Skip flags, width, precision up to the conversion letter. */
        const char *q = p + 1;
        while (*q && (strchr ("-+ #0", *q) != NULL)) q++;
        while (*q >= '0' && *q <= '9') q++;
        if (*q == '.') { q++; while (*q >= '0' && *q <= '9') q++; }
        if (*q == '\0') return -1;
        if (strchr ("diouxX", *q) == NULL) return -1;
        conversions++;
        p = q + 1;
    }
    if (conversions != 1) return -1;
    return 0;
}

static int
cs_parse_digits (const char *v, int *out)
{
    char *end = NULL;
    long n;
    if (!v || !*v)
        return -1;
    errno = 0;
    n = strtol (v, &end, 10);
    if (errno || !end || *end || n < 1 || n > 8)
        return -1;
    *out = (int)n;
    return 0;
}

static int
cs_regex_matches_line (regex_t *re, const char *line, ssize_t n)
{
    char *buf;
    size_t len;
    int rc;

    if (n < 0)
        return 0;
    len = (size_t)n;
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len > 0 && line[len - 1] == '\r')
        len--;

    buf = malloc (len + 1);
    if (!buf)
        return 0;
    memcpy (buf, line, len);
    buf[len] = '\0';
    rc = regexec (re, buf, 0, NULL, 0);
    free (buf);
    return rc == 0;
}

/* GNU csplit error helpers. GNU quotes the original pattern token in the
   locale's quotation marks (bos_quote: '/SEP/' in the C locale, U+2018
   and U+2019 under UTF-8) and appends "on repetition N" only when the
   failure is on a repeat (applied > 0). The base application (applied ==
   0) omits the suffix. `applied` is the number of repeats attempted so far
   (the failing attempt included); the base pattern is not counted. */
static void
cs_err_pattern (const char *pat, const char *what, long applied)
{
    char *q = bos_quote (pat);
    if (applied > 0)
        builtin_error ("%s: %s on repetition %ld", q ? q : pat, what, applied);
    else
        builtin_error ("%s: %s", q ? q : pat, what);
    free (q);
}

static void
cs_err_out_of_range (const char *pat, long applied)
{
    cs_err_pattern (pat, "line number out of range", applied);
}

static void
cs_err_no_match (const char *pat, long applied)
{
    cs_err_pattern (pat, "match not found", applied);
}

/* stdin's FILE belongs to the persistent shell. A private stream so a later
   redirection is not stuck at EOF from this invocation. */
static FILE *
cs_open_stdin (void)
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

/* GNU csplit: "'PATTERN': invalid pattern". */
static void
cs_bad_pattern (const char *w)
{
    char *q = bos_quote (w);
    builtin_error ("%s: invalid pattern", q ? q : w);
    free (q);
}

int
csplit_builtin (WORD_LIST *list)
{
    int silent = 0;
    int keep   = 0;
    int digits = 2;
    int suppress = 0;          /* --suppress-matched: drop the split-point line */
    int elide = 0;             /* -z/--elide-empty-files: drop 0-byte chunks */
    const char *prefix = "xx";
    const char *sfmt = NULL;   /* -b / --suffix-format printf template */

    /* Options before the operands; short ones cluster ("-sk", "-n3"),
       and errors are GNU csplit's (status 1). */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        const char *val = NULL;
        int opt = 0;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (w[1] == '-') {
            if (!strcmp (w, "--help")) {
                builtin_help ();
                return EXECUTION_SUCCESS;
            }
            if (!strcmp (w, "--version")) {
                puts ("csplit 1.0 (bash-loadable)");
                return EXECUTION_SUCCESS;
            }
            if (!strcmp (w, "--elide-empty-files")) elide = 1;
            else if (!strcmp (w, "--keep-files")) keep = 1;
            else if (!strcmp (w, "--silent") || !strcmp (w, "--quiet")) silent = 1;
            else if (!strcmp (w, "--suppress-matched")) suppress = 1;
            else if (!strcmp (w, "--digits") || !strcmp (w, "--prefix") || !strcmp (w, "--suffix-format")) {
                if (!list->next) { bos_shim_missing_arg (w, 0, "csplit"); return EXECUTION_FAILURE; }
                opt = w[2] == 'd' ? 'n' : w[2] == 'p' ? 'f' : 'b';
                list = list->next;
                val = list->word->word;
            } else if (!strncmp (w, "--digits=", 9)) { opt = 'n'; val = w + 9; }
            else if (!strncmp (w, "--prefix=", 9)) { opt = 'f'; val = w + 9; }
            else if (!strncmp (w, "--suffix-format=", 16)) { opt = 'b'; val = w + 16; }
            else { bos_shim_bad_option (w, 0, "csplit"); return EXECUTION_FAILURE; }
        } else {
            for (const char *c = w + 1; *c && !opt; c++) {
                switch (*c) {
                case 'z': elide = 1; break;
                case 'k': keep = 1; break;
                case 's': case 'q': silent = 1; break;
                case 'n': case 'f': case 'b':
                    opt = *c;
                    if (c[1]) val = c + 1;
                    else if (list->next) { list = list->next; val = list->word->word; }
                    else { bos_shim_missing_arg ("-", *c, "csplit"); return EXECUTION_FAILURE; }
                    break;
                default:
                    bos_shim_bad_option (w, *c, "csplit");
                    return EXECUTION_FAILURE;
                }
            }
        }
        if (opt == 'n') {
            if (cs_parse_digits (val, &digits) < 0) {
                char *q = bos_quote (val);
                builtin_error ("invalid number: %s", q ? q : val);
                free (q);
                return EXECUTION_FAILURE;
            }
        } else if (opt == 'f')
            prefix = val;
        else if (opt == 'b') {
            sfmt = val;
            if (cs_check_suffix_format (sfmt) != 0)
                { builtin_error ("invalid suffix format: %s", sfmt); return EXECUTION_FAILURE; }
        }
        list = list->next;
    }
    if (!list || !list->next) {
        char *q = list ? bos_quote (list->word->word) : NULL;
        if (list)
            builtin_error ("missing operand after %s", q ? q : list->word->word);
        else
            builtin_error ("missing operand");
        free (q);
        bos_shim_try_help ("csplit");
        return EXECUTION_FAILURE;
    }
    const char *fname = list->word->word;
    list = list->next;

    /* Parse the pattern list (each token from the WORD_LIST). */
    int n_pat = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_pat++;
    cs_pat *pats = calloc ((size_t) (n_pat + 1), sizeof *pats);
    if (!pats) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        cs_pat *cp = &pats[i];
        cp->repeat = 0;
        cp->word = w;        /* original token — used verbatim in GNU errors */
        if (w[0] == '{' && (w[1] == '*' || (w[1] >= '0' && w[1] <= '9'))) {
            /* repeat directive — modifies the PREVIOUS pattern. */
            if (i == 0) { cs_bad_pattern (w); free (pats); return EXECUTION_FAILURE; }
            if (w[1] == '*') pats[i - 1].repeat = -1;
            else             pats[i - 1].repeat = atol (w + 1);
            n_pat--;
            continue;
        }
        if (w[0] == '/' || w[0] == '%') {
            const char *end = strrchr (w + 1, w[0]);
            if (!end || end == w) { builtin_error ("%s: closing delimiter '%c' missing", w, w[0]); free (pats); return EXECUTION_FAILURE; }
            size_t rl = (size_t) (end - w - 1);
            char *re_buf = malloc (rl + 1);
            if (!re_buf) { builtin_error ("out of memory"); free (pats); return EXECUTION_FAILURE; }
            memcpy (re_buf, w + 1, rl);
            re_buf[rl] = '\0';
            int rc = regcomp (&cp->re, re_buf, REG_EXTENDED);
            free (re_buf);
            if (rc != 0) {
                char why[256], *q = bos_quote (w);
                regerror (rc, &cp->re, why, sizeof why);
                builtin_error ("%s: invalid regular expression: %s", q ? q : w, why);
                free (q);
                free (pats);
                return EXECUTION_FAILURE;
            }
            cp->re_compiled = 1;
            cp->kind = (w[0] == '/') ? CS_REGEX : CS_SKIP;
            /* Trailing [+OFF] or [-OFF] after the closing delimiter. */
            if (end[1] == '+')      cp->offset =  atol (end + 2);
            else if (end[1] == '-') cp->offset = -atol (end + 2);
            i++;
            continue;
        }
        if (w[0] >= '0' && w[0] <= '9') {
            cp->kind = CS_LINENO;
            cp->lineno = atol (w);
            i++;
            continue;
        }
        cs_bad_pattern (w);
        free (pats);
        return EXECUTION_FAILURE;
    }

    int from_stdin = !strcmp (fname, "-");
    FILE *fin = from_stdin ? cs_open_stdin () : fopen (fname, "r");
    if (!fin) {
        if (!from_stdin) builtin_error ("%s: %s", fname, strerror (errno));
        free (pats);
        return EXECUTION_FAILURE;
    }

    /* Slurp the whole input into a line array. csplit needs random access
       both for negative regex offsets (split *before* an earlier line) and
       for the per-pattern repeat intervals — neither is expressible in a
       pure forward stream. GNU csplit buffers identically. */
    cs_line *lines = NULL;
    long nlines = 0, lcap = 0;
    {
        char *raw = NULL;
        size_t rawcap = 0;
        ssize_t nread;
        while ((nread = getline (&raw, &rawcap, fin)) != -1) {
            if (nlines == lcap) {
                long newcap = lcap ? lcap * 2 : 64;
                cs_line *nl = realloc (lines, (size_t) newcap * sizeof *lines);
                if (!nl) { free (raw); free (lines); fclose (fin);
                           builtin_error ("out of memory"); return EXECUTION_FAILURE; }
                lines = nl; lcap = newcap;
            }
            lines[nlines].buf = malloc ((size_t) nread);
            if (!lines[nlines].buf) { free (raw); fclose (fin);
                                      builtin_error ("out of memory"); return EXECUTION_FAILURE; }
            memcpy (lines[nlines].buf, raw, (size_t) nread);
            lines[nlines].len = (size_t) nread;
            nlines++;
        }
        free (raw);
    }
    fclose (fin);

    int err = 0;
    int chunk_idx = 0;
    char **created_names = calloc (1024, sizeof *created_names);

    /* `cur` is the 1-based number of the first line not yet written.
       Each split emits lines [cur, split) to a new chunk; `split` is the
       1-based number of the first line of the NEXT chunk. */
    long cur = 1;

    /* Emit lines [from, to) (1-based, half-open) to a freshly numbered
       chunk file. Returns -1 on create/IO failure. */
#define EMIT_CHUNK(from, to) do { \
        if (elide && (to) <= (from)) break; /* -z: suppress empty chunk, no idx bump */ \
        char *nm = cs_chunk_name (prefix, chunk_idx, digits, sfmt); \
        if (!nm) { err = 1; goto finish; } \
        FILE *cf = fopen (nm, "w"); \
        if (!cf) { builtin_error ("create %s: %s", nm, strerror (errno)); \
                   free (nm); err = 1; goto finish; } \
        if (chunk_idx < 1024) created_names[chunk_idx] = nm; else free (nm); \
        long _li; \
        for (_li = (from); _li < (to); _li++) \
            fwrite (lines[_li - 1].buf, 1, lines[_li - 1].len, cf); \
        cs_print_size (cf, silent); \
        fclose (cf); \
        chunk_idx++; \
    } while (0)

    /* When a skip pattern's repeat runs out of matches, GNU consumes the rest
       of the input as part of that skip and writes NO trailing chunk. This flag
       suppresses the leftover EMIT_CHUNK below for that case. */
    int skip_ate_remainder = 0;

    for (int pi = 0; pi < n_pat && !err; pi++) {
        cs_pat *cp = &pats[pi];
        /* Once the input is exhausted (a skip or split reached EOF), GNU stops
           processing: any remaining patterns produce nothing and raise no
           error. */
        if (cur > nlines)
            break;
        /* reps = number of times to apply this pattern: 1 + repeat count,
           or "until it stops" for {*} (rep == -1). */
        long reps = (cp->repeat >= 0) ? (cp->repeat + 1) : -1;
        long applied = 0;
        long search_from = cur;       /* 1-based line to begin a regex scan */
        long interval_base = 0;       /* previous CS_LINENO target */

        for (;;) {
            if (reps >= 0 && applied >= reps) break;

            long split = 0;       /* 1-based first line of next chunk */
            int matched = 0;

            if (cp->kind == CS_LINENO) {
                /* First application: absolute line. Repeats: add the
                   interval (the literal value) to the previous target. */
                split = (applied == 0) ? cp->lineno : interval_base + cp->lineno;
                interval_base = split;
                /* Out of range: the target must be a real line boundary in the
                   buffered input. GNU treats N > nlines as out of range (a
                   split before a non-existent line); the leftover chunk picks
                   up the final line otherwise. A repeat ({k} or {*}) that
                   overshoots is a hard error in GNU — it is NOT a graceful
                   stop. The error names the repetition number (= number of
                   repeats attempted, base not counted) when applied > 0. */
                if (split < cur || split > nlines) {
                    cs_err_out_of_range (cp->word, applied);
                    err = 1;
                    break;
                }
                matched = 1;
            } else {
                /* CS_REGEX / CS_SKIP: scan forward from search_from. */
                long m = 0;
                for (long ln = search_from; ln <= nlines; ln++) {
                    if (cs_regex_matches_line (&cp->re,
                            lines[ln - 1].buf, (ssize_t) lines[ln - 1].len)) {
                        m = ln;
                        break;
                    }
                }
                if (m == 0) {
                    /* No (further) match. For a skip pattern, GNU treats the
                       unmatched tail as consumed by the skip — the remainder is
                       discarded and no trailing chunk is produced. This holds
                       for both {*} (graceful stop) and {k} (which still errors
                       but has the same file effect). */
                    if (cp->kind == CS_SKIP) {
                        cur = nlines + 1;
                        skip_ate_remainder = 1;
                    }
                    if (reps < 0)
                        break;          /* {*}: graceful stop */
                    cs_err_no_match (cp->word, applied);
                    err = 1;
                    break;
                }
                /* Next scan starts after this match. */
                search_from = m + 1;
                split = m + cp->offset;
                if (split < cur || split > nlines + 1) {
                    cs_err_out_of_range (cp->word, applied);
                    err = 1;
                    break;
                }
                matched = 1;
            }

            if (!matched) break;

            if (cp->kind == CS_SKIP) {
                /* Discard [cur, split) without creating a file. With
                   --suppress-matched the matched line itself is also dropped. */
                cur = suppress ? split + 1 : split;
            } else {
                EMIT_CHUNK (cur, split);
                /* --suppress-matched drops the split-point line (the first
                   line of what would be the next chunk) from the output. */
                cur = suppress ? split + 1 : split;
            }
            applied++;
        }
    }

    /* Trailing chunk: everything left over. GNU writes this in-progress
       chunk even when a pattern ultimately fails (no-match / out-of-range)
       — the partial file is then unlinked unless -k is given (handled
       below). It is skipped only if a create/IO error already jumped to
       `finish`, or if a skip {*} already consumed the remainder. */
    if (!skip_ate_remainder && cur <= nlines + 1)
        EMIT_CHUNK (cur, nlines + 1);

finish:
    for (int j = 0; j <= n_pat; j++)
        if (pats[j].re_compiled) regfree (&pats[j].re);
    free (pats);

    if (err && !keep) {
        for (int j = 0; j < chunk_idx && j < 1024; j++)
            if (created_names[j]) unlink (created_names[j]);
    }
    for (int j = 0; j < 1024; j++) free (created_names[j]);
    free (created_names);
    for (long j = 0; j < nlines; j++) free (lines[j].buf);
    free (lines);
#undef EMIT_CHUNK
    return err ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *csplit_doc[] = {
    "Context-split a file (POSIX csplit).",
    "",
    "    csplit [-k] [-s] [--help|--version] [-n DIGITS] [-f PREFIX] [-b FMT] FILE PATTERN [PATTERN...]",
    "",
    "    -k, --keep-files       keep partial output on error (default: unlink)",
    "    -s, -q, --silent       silent — don't print per-chunk byte counts",
    "    -z, --elide-empty-files  do not create empty (0-byte) output files",
    "    --suppress-matched     omit the line matching PATTERN from the output",
    "    -n, --digits DIGITS    suffix length (default 2)",
    "    -f, --prefix PREFIX    filename prefix (default xx; → xx00 xx01 ...)",
    "    -b, --suffix-format FMT  printf-style suffix (e.g. %03d.txt); overrides -n",
    "    --help                 show this help",
    "    --version              show version",
    "",
    "Patterns (in order):",
    "    /REGEX/[+OFF|-OFF]  split before line matching REGEX, offset OFF lines",
    "    %REGEX%[+OFF|-OFF]  skip pattern: discard until REGEX, no output file",
    "    N               split before line number N (absolute)",
    "    {N}             repeat previous pattern N times",
    "    {*}             repeat previous pattern as long as it matches",
    "",
    "Use `-` for FILE to read stdin.",
    (char *)NULL
};

struct builtin csplit_struct = {
    "csplit",
    csplit_builtin,
    BUILTIN_ENABLED,
    csplit_doc,
    "csplit [-k] [-s] [--help|--version] [-n DIGITS] [-f PREFIX] [-b FMT] FILE PATTERN [PATTERN...]",
    0
};
