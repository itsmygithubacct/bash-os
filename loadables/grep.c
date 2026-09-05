/* bashgrep.c — POSIX-shape grep(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. Line-by-line POSIX regex
 * (REG_EXTENDED engine; the default dialect applies GNU-grep BRE paren
 * compat — unescaped `(` `)` literal, `\(` `\)` grouping, see
 * bg_bre_paren_compat — while explicit -E selects raw ERE), -F
 * fixed-string mode via memmem(3), and a bounded
 * PCRE2-backed -P mode. Recursive mode (-r) walks via opendir/readdir.
 *
 * Flags supported:
 *   -E   raw extended regex (default differs only for parens: GNU BRE)
 *   -F   fixed string (memmem)
 *   -P   Perl-compatible regex (PCRE2)
 *   -i   case-insensitive
 *   -v   invert match
 *   -c   only print count of matches per file
 *   -l   list filenames with at least one match
 *   -L   inverse of -l
 *   -n   prefix line numbers
 *   -o   only matching part
 *   -r   recurse directories
 *   -H   always prefix filename
 *   -h   never prefix filename
 *   -q   quiet (exit status only)
 *   -s   suppress file diagnostics
 *   -w   require word-boundary match
 *   -x   require whole-line match
 *   -m N stop after N matches per file
 *   -a   treat binary files as text
 *   -I   skip binary files
 *   -Z   NUL-separate filename output
 *   -e PAT / -f FILE  add OR-combined patterns
 *   -A N  print N lines after each match
 *   -B N  print N lines before each match
 *   -C N  -A N -B N
 *   --include/--exclude/--exclude-dir for recursive filtering
 *
 * Out of scope: --color output (no color in bash-os Phase A by design;
 * --color[=WHEN] is accepted as a no-op), basic-regex `-G`.
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
#include <regex.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef BASHGREP_PCRE2
#define BASHGREP_PCRE2 0   /* set 1 to enable `grep -P`; needs libpcre2. Off: POSIX regex only. */
#endif
#if BASHGREP_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
/* No PCRE2 in this build. Stub the opaque types and the few functions used
   outside the (guarded) helper block; -P then fails cleanly at run time. */
typedef void pcre2_code;
typedef void pcre2_match_data;
typedef void pcre2_match_context;
#ifndef PCRE2_NOTBOL
#define PCRE2_NOTBOL 0u
#endif
#define pcre2_match_data_create_from_pattern(a,b) ((pcre2_match_data *)0)
#define pcre2_code_free(a)        ((void)0)
#define pcre2_match_data_free(a)  ((void)0)
#endif

#include "loadables.h"

typedef struct {
    int    iflag;
    int    vflag;
    int    cflag;
    int    lflag;
    int    Lflag;
    int    nflag;
    int    bflag;        /* -b / --byte-offset */
    int    oflag;
    int    rflag;
    int    Hflag;        /* force filename prefix */
    int    hflag;        /* suppress filename prefix */
    int    Fflag;        /* fixed string */
    int    Gflag;        /* basic regex */
    int    Eflag;        /* explicit -E: raw ERE, skip BRE paren compat */
    int    Pflag;        /* Perl-compatible regex via PCRE2 */
    int    qflag;        /* -q: quiet (exit-status-only; suppress all output) */
    int    sflag;        /* -s: silent (suppress error messages) */
    int    wflag;        /* -w: word-boundary match */
    int    xflag;        /* -x: whole-line match */
    int    mflag;        /* -m N: stop after N matches per file (0 = unlimited unless set) */
    int    mflag_set;    /* distinguish default unlimited from GNU-compatible -m 0 */
    int    Zflag;        /* -Z / --null: NUL-separated filename output */
    int    zdflag;       /* -z / --null-data: NUL-separated input+output records */
    int    aflag;        /* -a: treat binary files as text */
    int    Iflag;        /* -I: skip binary files entirely */
    /* --include/--exclude/--exclude-dir glob lists. */
    char **incl_globs;  int n_incl;
    char **excl_globs;  int n_excl;
    char **excl_dir_globs; int n_excl_dir;
    int    A, B;         /* context lines after / before */
    char  *pattern;
    /* Multi-pattern collection. -e PATTERN can repeat; -f FILE adds
       each line. They get OR-combined into the single pattern above
       at compile time. */
    char **patterns;
    int    n_patterns;
    int    cap_patterns;
    regex_t re;
    int    re_compiled;
    pcre2_code *pcre;
    pcre2_match_data *pcre_md;
} bg_opts;

#define BG_PCRE_DEFAULT_MATCH_LIMIT 1000000u
#define BG_PCRE_DEFAULT_DEPTH_LIMIT 10000u

static int
bg_parse_count (const char *s, int *out)
{
    char *end = NULL;
    long n;
    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n < 0 || n > 1000000)
        return -1;
    *out = (int) n;
    return 0;
}

#if BASHGREP_PCRE2
static pcre2_match_context *
bg_pcre_match_ctx (void)
{
    static pcre2_match_context *ctx = NULL;
    if (!ctx)
    {
        ctx = pcre2_match_context_create (NULL);
        if (!ctx)
            return NULL;
    }
    uint32_t mlim = BG_PCRE_DEFAULT_MATCH_LIMIT;
    uint32_t dlim = BG_PCRE_DEFAULT_DEPTH_LIMIT;
    const char *e;
    if ((e = getenv ("BASHPCRE_MATCH_LIMIT")) && *e)
    {
        unsigned long v = strtoul (e, NULL, 10);
        if (v) mlim = (uint32_t) v;
    }
    if ((e = getenv ("BASHPCRE_DEPTH_LIMIT")) && *e)
    {
        unsigned long v = strtoul (e, NULL, 10);
        if (v) dlim = (uint32_t) v;
    }
    pcre2_set_match_limit (ctx, mlim);
    pcre2_set_depth_limit (ctx, dlim);
    return ctx;
}

static pcre2_code *
bg_pcre_compile (const char *pattern, int iflag)
{
    uint32_t flags = PCRE2_UTF | PCRE2_UCP;
    if (iflag)
        flags |= PCRE2_CASELESS;

    int errcode;
    PCRE2_SIZE erroffset;
    pcre2_code *code = pcre2_compile ((PCRE2_SPTR) pattern,
                                      PCRE2_ZERO_TERMINATED,
                                      flags, &errcode, &erroffset, NULL);
    if (!code)
    {
        char buf[256];
        pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
        builtin_error ("bad PCRE regex at offset %zu: %s",
                       (size_t) erroffset, buf);
    }
    return code;
}

static int
bg_pcre_exec (const bg_opts *o, const char *line, size_t llen,
              size_t start, uint32_t match_opts, regmatch_t *m)
{
    int rc = pcre2_match (o->pcre, (PCRE2_SPTR) line, llen, start,
                          match_opts, o->pcre_md, bg_pcre_match_ctx ());
    if (rc == PCRE2_ERROR_NOMATCH)
        return 0;
    if (rc < 0)
    {
        char buf[128];
        pcre2_get_error_message (rc, (PCRE2_UCHAR *) buf, sizeof buf);
        builtin_error ("PCRE match error: %s", buf);
        return -1;
    }
    PCRE2_SIZE *ovec = pcre2_get_ovector_pointer (o->pcre_md);
    m->rm_so = (regoff_t) ovec[0];
    m->rm_eo = (regoff_t) ovec[1];
    return 1;
}
#else /* !BASHGREP_PCRE2 : POSIX-only build */
static pcre2_code *
bg_pcre_compile (const char *pattern, int iflag)
{
    (void) pattern; (void) iflag;
    builtin_error ("grep: -P (Perl regex) not supported in this build");
    return (pcre2_code *) 0;
}
static int
bg_pcre_exec (const bg_opts *o, const char *line, size_t llen,
              size_t start, uint32_t match_opts, regmatch_t *m)
{
    (void) o; (void) line; (void) llen; (void) start; (void) match_opts; (void) m;
    return -1;
}
#endif /* BASHGREP_PCRE2 */

/* Escape every literal `{` and `}` in PATTERN, preserving existing
   `\X` escapes verbatim. Used as a permissive-ERE retry path when
   `regcomp` rejects the user's pattern with REG_BADBR/REG_BADRPT/
   REG_EBRACE — e.g. the standalone `^{` shape that `tests/bash-os/
   204-bench-runner.sh` emits to count JSON records. POSIX ERE calls
   stray `{`/`}` undefined; GNU and BSD `grep` are lenient and treat
   them as literal, which the retry below mirrors. Returns a freshly
   allocated string (caller frees) or NULL on OOM. */
static char *
bg_escape_braces (const char *pattern)
{
    size_t plen = strlen (pattern);
    char *out = malloc (plen * 2 + 1);
    if (!out) return NULL;
    size_t op = 0;
    for (size_t i = 0; i < plen; i++)
    {
        if (pattern[i] == '\\' && i + 1 < plen)
        {
            out[op++] = pattern[i];
            out[op++] = pattern[i + 1];
            i++;
            continue;
        }
        if (pattern[i] == '{' || pattern[i] == '}')
            out[op++] = '\\';
        out[op++] = pattern[i];
    }
    out[op] = '\0';
    return out;
}

/* GNU-grep BRE paren parity for the default (no -E/-F/-P/-G) dialect:
   in BRE, unescaped `(` / `)` are literal characters and `\(` / `\)`
   are the grouping operators — the exact inverse of the REG_EXTENDED
   engine we compile with. Swap the escapedness of parens so the ERE
   compile sees BRE-faithful parens: `a(b)c` matches the literal string
   and `\(foo\)` groups, matching grep(1)'s default. Other escapes
   (`\.`, `\+`, ...) pass through verbatim, as do bracket expressions
   (`[()]`, `[[:alpha:]]`) where parens are already literal members.
   Runs per pattern arm, before the OR-combiner below wraps arms in
   its own (meta) ERE parens. Returns a freshly allocated string
   (caller frees) or NULL on OOM. */
static char *
bg_bre_paren_compat (const char *pattern)
{
    size_t plen = strlen (pattern);
    char *out = malloc (plen * 2 + 1);
    if (!out) return NULL;
    size_t op = 0;
    for (size_t i = 0; i < plen; i++)
    {
        if (pattern[i] == '\\' && i + 1 < plen)
        {
            if (pattern[i + 1] == '(' || pattern[i + 1] == ')')
                out[op++] = pattern[i + 1];      /* \( -> ( : BRE group */
            else
            {
                out[op++] = pattern[i];
                out[op++] = pattern[i + 1];
            }
            i++;
            continue;
        }
        if (pattern[i] == '[')
        {
            /* Copy a bracket expression verbatim: `]` is a member when
               first (after optional `^`), and `[: :]` / `[. .]` /
               `[= =]` sequences may themselves contain `]`. */
            size_t j = i + 1;
            if (j < plen && pattern[j] == '^') j++;
            if (j < plen && pattern[j] == ']') j++;
            while (j < plen && pattern[j] != ']')
            {
                if (pattern[j] == '[' && j + 1 < plen
                    && (pattern[j + 1] == ':' || pattern[j + 1] == '.'
                        || pattern[j + 1] == '='))
                {
                    char delim = pattern[j + 1];
                    j += 2;
                    while (j + 1 < plen
                           && !(pattern[j] == delim && pattern[j + 1] == ']'))
                        j++;
                    if (j + 1 < plen) j += 2;
                }
                else
                    j++;
            }
            if (j < plen) j++;                   /* include closing `]` */
            memcpy (out + op, pattern + i, j - i);
            op += j - i;
            i = j - 1;
            continue;
        }
        if (pattern[i] == '(' || pattern[i] == ')')
            out[op++] = '\\';                    /* ( -> \( : BRE literal */
        out[op++] = pattern[i];
    }
    out[op] = '\0';
    return out;
}

/* Print a single matched line with optional prefixes. */
static void
bg_print_impl (const bg_opts *o, const char *fname, int n_files, int from_recursion,
               long lineno, long byte_off, const char *line, size_t llen,
               regmatch_t *match, int context_line)
{
    if (o->qflag) return;        /* -q: exit-status only */
    /* Filename prefix when >1 file is searched, when this file was reached via
       directory recursion, or with -H. A single explicit file (even with -r)
       gets no prefix — matching GNU. */
    int prefix_fname = o->Hflag || (!o->hflag && (n_files > 1 || from_recursion));
    int sep = context_line ? '-' : ':';
    if (prefix_fname && fname) printf ("%s%c", fname, sep);
    if (o->nflag) printf ("%ld%c", lineno, sep);
    /* -b: byte offset of the match (with -o) or of the line start. GNU prints
       it after any filename/line-number prefix. */
    if (o->bflag) {
        long bo = (o->oflag && match) ? byte_off + match->rm_so : byte_off;
        printf ("%ld%c", bo, sep);
    }
    /* -z: records are separated by NUL on output as well as input. */
    char rsep = o->zdflag ? '\0' : '\n';
    if (o->oflag && match)
    {
        size_t mlen = (size_t) (match->rm_eo - match->rm_so);
        fwrite (line + match->rm_so, 1, mlen, stdout);
        putchar (rsep);
    }
    else
    {
        fwrite (line, 1, llen, stdout);
        if (llen == 0 || line[llen - 1] != rsep) putchar (rsep);
    }
}

static void
bg_print (const bg_opts *o, const char *fname, int n_files, int from_recursion,
          long lineno, long byte_off, const char *line, size_t llen,
          regmatch_t *match)
{
    bg_print_impl (o, fname, n_files, from_recursion, lineno, byte_off, line, llen, match, 0);
}

static void
bg_print_context (const bg_opts *o, const char *fname, int n_files, int from_recursion,
                  long lineno, long byte_off, const char *line, size_t llen)
{
    bg_print_impl (o, fname, n_files, from_recursion, lineno, byte_off, line, llen, NULL, 1);
}

static void
bg_context_separator (const bg_opts *o, long lineno,
                      int *printed_any, long *last_printed)
{
    if ((o->A > 0 || o->B > 0) && *printed_any
        && lineno > *last_printed + 1)
        puts ("--");
}

static void
bg_context_mark (long lineno, int *printed_any, long *last_printed)
{
    *printed_any = 1;
    *last_printed = lineno;
}

/* Find first match of fixed-string needle in haystack[len], with
   optional case-insensitivity. Returns offset or -1. */
static long
bg_fixed_find (const char *hay, size_t hlen, const char *needle, int icase)
{
    size_t nlen = strlen (needle);
    if (nlen == 0) return 0;
    if (nlen > hlen) return -1;
    if (!icase)
    {
        const char *p = memmem (hay, hlen, needle, nlen);
        return p ? (long) (p - hay) : -1;
    }
    /* case-insensitive: byte-wise lower-compare */
    for (size_t i = 0; i + nlen <= hlen; i++)
    {
        int eq = 1;
        for (size_t j = 0; j < nlen; j++)
        {
            char hc = hay[i + j], nc = needle[j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) { eq = 0; break; }
        }
        if (eq) return (long) i;
    }
    return -1;
}

/* Find the earliest fixed-string match across the active pattern set. */
static long
bg_fixed_find_any (const bg_opts *o, const char *hay, size_t hlen, size_t *mlen)
{
    long best = -1;
    size_t best_len = 0;

    for (int i = 0; i < o->n_patterns; i++)
    {
        long off = bg_fixed_find (hay, hlen, o->patterns[i], o->iflag);
        if (off >= 0 && (best < 0 || off < best))
        {
            best = off;
            best_len = strlen (o->patterns[i]);
        }
    }
    if (o->pattern)
    {
        long off = bg_fixed_find (hay, hlen, o->pattern, o->iflag);
        if (off >= 0 && (best < 0 || off < best))
        {
            best = off;
            best_len = strlen (o->pattern);
        }
    }

    if (mlen)
        *mlen = best_len;
    return best;
}

/* Process one file (or stdin if path is NULL). Returns number of
   matches. */
static long
bg_grep_file (const bg_opts *o, const char *path, int n_files, int from_recursion)
{
    FILE *f = path ? fopen (path, "r") : stdin;
    if (!f) {
        if (!o->sflag) builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }

    /* Binary file detection: scan first 4096 bytes for NUL. */
    int is_binary = 0;
    if (path && (o->Iflag || !o->aflag)) {
        unsigned char probe[4096];
        size_t probe_n = fread (probe, 1, sizeof probe, f);
        for (size_t i = 0; i < probe_n; i++) if (probe[i] == 0) { is_binary = 1; break; }
        fseek (f, 0, SEEK_SET);
    }
    if (is_binary && o->Iflag) {
        fclose (f);
        return 0;   /* skip binary */
    }
    /* For default behavior on binary (no -a): scan for a match, but
       report "Binary file FOO matches" instead of dumping binary bytes. */

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    long lineno = 0;
    long match_count = 0;
    long byte_off = 0;          /* running byte offset of the current line start */

    /* Context-buffer ring (for -B). */
    int Bcap = o->B;
    char **bbuf = NULL;
    size_t *blen = NULL;
    long *bln = NULL;
    long *boff = NULL;          /* byte offset of each buffered context line */
    int btop = 0, bsize = 0;
    if (Bcap > 0)
    {
        bbuf = calloc ((size_t) Bcap, sizeof *bbuf);
        blen = calloc ((size_t) Bcap, sizeof *blen);
        bln  = calloc ((size_t) Bcap, sizeof *bln);
        boff = calloc ((size_t) Bcap, sizeof *boff);
    }
    int after_left = 0;
    int printed_any = 0;
    long last_printed = 0;

    /* -z: input records are NUL-delimited (e.g. `find -print0 | grep -z`). */
    int rec_delim = o->zdflag ? '\0' : '\n';
    while ((n = getdelim (&line, &cap, rec_delim, f)) != -1)
    {
        lineno++;
        long cur_off = byte_off;     /* byte offset of this record's first byte */
        byte_off += n;               /* advance past the whole record incl. delimiter */
        size_t llen = (size_t) n;
        if (llen > 0 && line[llen - 1] == rec_delim) llen--;

        /* Match. */
        regmatch_t m = {0};
        int matched;
        if (o->Fflag)
        {
            size_t mlen = 0;
            long off = bg_fixed_find_any (o, line, llen, &mlen);
            matched = (off >= 0);
            if (matched)
            {
                m.rm_so = off;
                m.rm_eo = off + (regoff_t) mlen;
                if (o->xflag && (m.rm_so != 0 || (size_t) m.rm_eo != llen))
                    matched = 0;
            }
        }
        else if (o->Pflag)
        {
            int prc = bg_pcre_exec (o, line, llen, 0, 0, &m);
            if (prc < 0)
            {
                free (line);
                if (Bcap > 0)
                {
                    for (int i = 0; i < Bcap; i++) free (bbuf[i]);
                    free (bbuf); free (blen); free (bln); free (boff);
                }
                if (path) fclose (f);
                return -1;
            }
            matched = (prc > 0);
            if (matched && o->xflag && (m.rm_so != 0 || (size_t) m.rm_eo != llen))
                matched = 0;
        }
        else
        {
            /* In -a and default binary-report mode, replace embedded NULs
               with '.' so regexec can see the full line. NUL bytes are not
               valid in C strings and would truncate the match. */
            if (o->aflag || is_binary) {
                for (size_t i = 0; i < llen; i++)
                    if (line[i] == '\0') line[i] = '.';
            }
            char saved = line[llen];
            line[llen] = '\0';
            int rrc = regexec (&o->re, line, 1, &m, 0);
            line[llen] = saved;
            matched = (rrc == 0);
        }
        /* -w: word-boundary scan-forward.  Match in `m` (first hit from
           regexec/bg_fixed_find above) is checked against the word-
           boundary rule (no alnum or `_` abutting).  If it fails, we
           walk subsequent non-overlapping matches on the same line
           until either a -w-passing candidate is found (update `m`) or
           the line is exhausted (matched=0).  This gives GNU grep -w
           parity on lines where the first regex/-F hit lies inside a
           longer word but a later same-line hit is word-bounded —
           e.g. `foobar foo foobar` / `foo` emits the middle `foo`
           under both -w (whole line) and -wo (just the substring).
           Reuses the same REG_NOTBOL + zero-width-guard primitives as
           the -o multi-match emit loop below so the two stay aligned. */
        if (matched && o->wflag) {
            char saved = line[llen];
            line[llen] = '\0';
            #define _IS_WC(ch) (((ch) >= 'a' && (ch) <= 'z') || \
                                ((ch) >= 'A' && (ch) <= 'Z') || \
                                ((ch) >= '0' && (ch) <= '9') || (ch) == '_')
            while (1) {
                int s = (int) m.rm_so, e = (int) m.rm_eo;
                int left_ok  = (s == 0)
                               || !_IS_WC ((unsigned char) line[s-1]);
                int right_ok = (e == (int) llen)
                               || !_IS_WC ((unsigned char) line[e]);
                if (left_ok && right_ok)
                    break;     /* m is the first -w-passing match. */
                /* Advance past current candidate with zero-width-match
                   guard (m.rm_eo == m.rm_so → step exactly one byte
                   to avoid infinite loop). */
                size_t step = (m.rm_eo > m.rm_so)
                              ? (size_t) m.rm_eo
                              : (size_t) m.rm_eo + 1;
                if (step >= llen) { matched = 0; break; }
                /* Find the next non-overlapping match.  REG_NOTBOL so
                   `^` cannot re-match mid-line. */
                regmatch_t sub;
                int hit;
                if (o->Fflag) {
                    size_t mlen = 0;
                    long off = bg_fixed_find_any (o, line + step,
                                                  llen - step, &mlen);
                    hit = (off >= 0);
                    if (hit) {
                        sub.rm_so = (regoff_t) off;
                        sub.rm_eo = sub.rm_so + (regoff_t) mlen;
                    }
                } else if (o->Pflag) {
                    int prc = bg_pcre_exec (o, line, llen, step,
                                            PCRE2_NOTBOL, &sub);
                    if (prc < 0) { matched = -1; break; }
                    hit = (prc > 0);
                } else {
                    hit = (regexec (&o->re, line + step, 1, &sub, REG_NOTBOL) == 0);
                }
                if (!hit) { matched = 0; break; }
                if (o->Pflag) {
                    m = sub;
                } else {
                    m.rm_so = (regoff_t) (step + (size_t) sub.rm_so);
                    m.rm_eo = (regoff_t) (step + (size_t) sub.rm_eo);
                }
            }
            #undef _IS_WC
            line[llen] = saved;
        }
        if (matched < 0)
        {
            free (line);
            if (Bcap > 0)
            {
                for (int i = 0; i < Bcap; i++) free (bbuf[i]);
                free (bbuf); free (blen); free (bln); free (boff);
            }
            if (path) fclose (f);
            return -1;
        }
        if (o->vflag) matched = !matched;

        if (matched)
        {
            match_count++;
            /* -m N: stop after N matches per file. */
            if (o->mflag > 0 && match_count > o->mflag) { match_count--; break; }
            /* -q: short-circuit on first match. */
            if (o->qflag) break;
            /* -l: print filename once, stop scanning this file. */
            if (o->lflag) break;
            if (o->cflag) continue;
            if (o->Lflag) { /* will skip whole-file print at end */ continue; }
            if (is_binary && !o->aflag)
            {
                if (path)
                    printf ("Binary file %s matches\n", path);
                else
                    printf ("Binary file (standard input) matches\n");
                break;
            }
            /* Flush context-before. Bcap > 0 here (else bsize == 0). */
            if (bsize > 0)
            {
                int idx = (btop - bsize + Bcap) % Bcap;
                for (int i = 0; i < bsize; i++)
                {
                    if (bbuf[idx] && bln[idx] > last_printed)
                    {
                        bg_context_separator (o, bln[idx], &printed_any, &last_printed);
                        bg_print_context (o, path, n_files, from_recursion, bln[idx], boff[idx], bbuf[idx], blen[idx]);
                        bg_context_mark (bln[idx], &printed_any, &last_printed);
                    }
                    idx = (idx + 1) % Bcap;
                }
                bsize = 0;
            }
            /* Print matches.  Under -o, GNU grep emits every non-
               overlapping match on a line as its own output line; we
               loop over the remainder of the line (regexec for regex,
               bg_fixed_find for -F) until exhausted.  A zero-width
               match (rm_so == rm_eo) advances by exactly one byte to
               avoid an infinite loop, matching GNU grep's behavior.
               Outside -o, the line is emitted once via bg_print's
               full-line arm (the pre-existing single-call path). */
            if (o->oflag)
            {
                char saved = line[llen];
                line[llen] = '\0';
                /* First match already in `m` (passed -w if -w was set
                   in the pre-loop check above).  Emit it unless it's
                   zero-width — GNU grep -o suppresses empty matches
                   to avoid spamming one empty line per byte. */
                if (m.rm_eo > m.rm_so)
                {
                    bg_context_separator (o, lineno, &printed_any, &last_printed);
                    bg_print (o, path, n_files, from_recursion, lineno, cur_off, line, llen, &m);
                    bg_context_mark (lineno, &printed_any, &last_printed);
                }
                size_t pos = (m.rm_eo > m.rm_so)
                             ? (size_t) m.rm_eo
                             : (size_t) m.rm_eo + 1;
                while (pos < llen)
                {
                    regmatch_t cur;
                    if (o->Fflag)
                    {
                        size_t mlen = 0;
                        long off = bg_fixed_find_any (o, line + pos,
                                                      llen - pos, &mlen);
                        if (off < 0) break;
                        cur.rm_so = (regoff_t) (pos + (size_t) off);
                        cur.rm_eo = cur.rm_so + (regoff_t) mlen;
                    }
                    else if (o->Pflag)
                    {
                        int prc = bg_pcre_exec (o, line, llen, pos,
                                                pos ? PCRE2_NOTBOL : 0, &cur);
                        if (prc < 0)
                        {
                            line[llen] = saved;
                            free (line);
                            if (Bcap > 0)
                            {
                                for (int i = 0; i < Bcap; i++) free (bbuf[i]);
                                free (bbuf); free (blen); free (bln); free (boff);
                            }
                            if (path) fclose (f);
                            return -1;
                        }
                        if (prc == 0) break;
                    }
                    else
                    {
                        regmatch_t sub;
                        /* REG_NOTBOL: line + pos is not the start of
                           a logical line, so `^` must not match. */
                        if (regexec (&o->re, line + pos, 1, &sub, REG_NOTBOL) != 0)
                            break;
                        cur.rm_so = (regoff_t) (pos + (size_t) sub.rm_so);
                        cur.rm_eo = (regoff_t) (pos + (size_t) sub.rm_eo);
                    }
                    /* -w post-filter on each subsequent match (the
                       first was already filtered before we got here). */
                    int wpass = 1;
                    if (o->wflag)
                    {
                        int s = (int) cur.rm_so;
                        int e = (int) cur.rm_eo;
                        #define _IS_WC(ch) (((ch) >= 'a' && (ch) <= 'z') || \
                                            ((ch) >= 'A' && (ch) <= 'Z') || \
                                            ((ch) >= '0' && (ch) <= '9') || (ch) == '_')
                        int left_ok  = (s == 0)
                                       || !_IS_WC ((unsigned char) line[s-1]);
                        int right_ok = (e == (int) llen)
                                       || !_IS_WC ((unsigned char) line[e]);
                        if (!left_ok || !right_ok) wpass = 0;
                        #undef _IS_WC
                    }
                    /* Suppress emission for zero-width matches (GNU
                       grep -o parity).  We still advance below. */
                    if (wpass && cur.rm_eo > cur.rm_so)
                    {
                        bg_context_separator (o, lineno, &printed_any, &last_printed);
                        bg_print (o, path, n_files, from_recursion, lineno, cur_off, line, llen, &cur);
                        bg_context_mark (lineno, &printed_any, &last_printed);
                    }
                    /* Advance with zero-width-match guard.  step is
                       absolute; cur.rm_eo > cur.rm_so on non-empty
                       matches, otherwise step past one byte. */
                    size_t step = (cur.rm_eo > cur.rm_so)
                                  ? (size_t) cur.rm_eo
                                  : (size_t) cur.rm_eo + 1;
                    if (step <= pos) step = pos + 1;   /* defensive */
                    pos = step;
                }
                line[llen] = saved;
            }
            else
            {
                bg_context_separator (o, lineno, &printed_any, &last_printed);
                bg_print (o, path, n_files, from_recursion, lineno, cur_off, line, llen,
                          o->Fflag ? NULL : &m);
                bg_context_mark (lineno, &printed_any, &last_printed);
            }
            after_left = o->A;
        }
        else if (after_left > 0)
        {
            /* Print as -A context. */
            if (lineno > last_printed)
            {
                bg_context_separator (o, lineno, &printed_any, &last_printed);
                bg_print_context (o, path, n_files, from_recursion, lineno, cur_off, line, llen);
                bg_context_mark (lineno, &printed_any, &last_printed);
            }
            after_left--;
        }
        else if (Bcap > 0)
        {
            /* Save into ring. */
            free (bbuf[btop]);
            bbuf[btop] = strndup (line, llen);
            if (!bbuf[btop])
            {
                builtin_error ("bashgrep: strndup: %s", strerror (errno));
                blen[btop] = 0;  /* defensive: don't reference NULL on flush */
            }
            else
                blen[btop] = llen;
            bln[btop]  = lineno;
            boff[btop] = cur_off;
            btop = (btop + 1) % Bcap;
            if (bsize < Bcap) bsize++;
        }
    }
    free (line);
    if (Bcap > 0)
    {
        for (int i = 0; i < Bcap; i++) free (bbuf[i]);
        free (bbuf); free (blen); free (bln); free (boff);
    }
    if (path) fclose (f);

    if (o->qflag) {
        /* -q: no output regardless of other flags. */
    }
    else if (o->cflag)
    {
        int prefix_fname = o->Hflag || (!o->hflag && (n_files > 1 || from_recursion));
        if (prefix_fname && path) printf ("%s:%ld\n", path, match_count);
        else                       printf ("%ld\n", match_count);
    }
    else if (o->lflag && match_count > 0 && path)
    {
        fputs (path, stdout);
        putchar (o->Zflag ? '\0' : '\n');
    }
    else if (o->Lflag && match_count == 0 && path)
    {
        fputs (path, stdout);
        putchar (o->Zflag ? '\0' : '\n');
    }
    return match_count;
}

/* Match a path against one of the glob lists (returns 1 if it matches
   any glob in the list). */
static int
bg_glob_any (char **globs, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (fnmatch (globs[i], name, 0) == 0) return 1;
    return 0;
}

/* Recursive walker for -r. */
static long
bg_grep_recursive (const bg_opts *o, const char *path, int from_recursion)
{
    struct stat st;
    if (lstat (path, &st) != 0)
        {
            if (!o->sflag) builtin_error ("%s: %s", path, strerror (errno));
            return -1;
        }
    if (S_ISREG (st.st_mode)) {
        /* Apply --include / --exclude to leaf basename. */
        const char *bn = strrchr (path, '/');
        bn = bn ? bn + 1 : path;
        if (o->n_incl > 0 && !bg_glob_any (o->incl_globs, o->n_incl, bn)) return 0;
        if (o->n_excl > 0 && bg_glob_any (o->excl_globs, o->n_excl, bn)) return 0;
        /* Filename prefix during recursion is driven by o->rflag in bg_print. */
        return bg_grep_file (o, path, 1, from_recursion);
    }
    if (!S_ISDIR (st.st_mode)) return 0;
    /* --exclude-dir applied to the directory's basename. */
    if (o->n_excl_dir > 0) {
        const char *bn = strrchr (path, '/');
        bn = bn ? bn + 1 : path;
        if (bg_glob_any (o->excl_dir_globs, o->n_excl_dir, bn)) return 0;
    }

    DIR *d = opendir (path);
    if (!d) {
        if (!o->sflag) builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    long total = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL)
    {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        size_t pl = strlen (path), nl = strlen (de->d_name);
        int slash = (pl > 0 && path[pl - 1] != '/') ? 1 : 0;
        char *child = malloc (pl + slash + nl + 1);
        if (!child) continue;
        memcpy (child, path, pl);
        if (slash) child[pl] = '/';
        memcpy (child + pl + slash, de->d_name, nl + 1);
        long rc = bg_grep_recursive (o, child, 1);
        if (rc > 0) total += rc;
        free (child);
    }
    closedir (d);
    return total;
}

static void
bg_print_help (void)
{
    puts ("bashgrep [FLAGS] [-e PATTERN]... [-f FILE]... [PATTERN] [FILE ...]");
    puts ("  -E, --extended-regexp       raw extended regex (default: GNU BRE parens)");
    puts ("  -F, --fixed-strings         fixed string");
    puts ("  -P, --perl-regexp           Perl-compatible regex (PCRE2)");
    puts ("  -i, --ignore-case           case-insensitive");
    puts ("  -v, --invert-match          invert match");
    puts ("  -c, --count                 only count per file");
    puts ("  -l, --files-with-matches    list filenames with matches");
    puts ("  -L, --files-without-match   list filenames without matches");
    puts ("  -n, --line-number           prefix line numbers");
    puts ("  -b, --byte-offset           prefix the byte offset of the match");
    puts ("  -o, --only-matching         only matching text");
    puts ("  -m, --max-count=NUM         stop after NUM matches");
    puts ("  -r, -R, --recursive         recurse directories");
    puts ("  -q, --quiet, --silent       quiet, exit on first match");
    puts ("  -s, --no-messages           suppress file error messages");
    puts ("  -H, --with-filename         always prefix filename");
    puts ("  -h, --no-filename           never prefix filename");
    puts ("  -w, --word-regexp           word-boundary match");
    puts ("  -x, --line-regexp           whole-line match");
    puts ("  -a, --text                  treat binary files as text");
    puts ("  -I                          skip binary files");
    puts ("  -Z, --null                  NUL-separate filename output");
    puts ("  -z, --null-data             NUL-separated input and output records");
    puts ("      --include=GLOB --exclude=GLOB --exclude-dir=GLOB");
    puts ("      --                      end option parsing");
}

static void
bg_print_version (void)
{
    puts ("grep (bash-os bashgrep) 3.11-compatible");
}

int
grep_builtin (WORD_LIST *list)
{
    bg_opts o = {0};
    int parsed_pattern = 0;
    int n_files = 0;
    int paths_cap = 8;
    const char **paths = malloc (paths_cap * sizeof *paths);
    if (!paths) { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }

    int end_options = 0;
    WORD_LIST *p = list;
    while (p)
    {
        const char *w = p->word->word;
        if (!end_options && !strcmp (w, "--"))
        {
            end_options = 1;
            p = p->next;
            continue;
        }
        /* Long-options: GNU-compatible aliases for the short options
           documented by grep.txt, plus recursive include/exclude globs. */
        if (!end_options && w[0] == '-' && w[1] == '-')
        {
            if (!strcmp (w, "--help")) {
                bg_print_help ();
                free (paths);
                return EXECUTION_SUCCESS;
            }
            if (!strcmp (w, "--version")) {
                bg_print_version ();
                free (paths);
                return EXECUTION_SUCCESS;
            }
            if (!strcmp (w, "--extended-regexp")) { o.Eflag = 1; o.Fflag = 0; o.Gflag = 0; o.Pflag = 0; }
            else if (!strcmp (w, "--basic-regexp")) { o.Eflag = 0; o.Fflag = 0; o.Gflag = 1; o.Pflag = 0; }
            else if (!strcmp (w, "--fixed-strings")) { o.Eflag = 0; o.Fflag = 1; o.Gflag = 0; o.Pflag = 0; }
            else if (!strcmp (w, "--perl-regexp")) { o.Eflag = 0; o.Pflag = 1; o.Fflag = 0; o.Gflag = 0; }
            else if (!strcmp (w, "--ignore-case")) o.iflag = 1;
            else if (!strcmp (w, "--invert-match")) o.vflag = 1;
            else if (!strcmp (w, "--count")) o.cflag = 1;
            else if (!strcmp (w, "--files-with-matches")) o.lflag = 1;
            else if (!strcmp (w, "--files-without-match")) o.Lflag = 1;
            else if (!strcmp (w, "--line-number")) o.nflag = 1;
            else if (!strcmp (w, "--byte-offset")) o.bflag = 1;
            else if (!strcmp (w, "--null-data")) o.zdflag = 1;
            /* --color[=WHEN] / --colour[=WHEN]: accepted as a no-op. bash-os
               grep never emits color (Phase A design), which matches GNU's
               --color=never/auto when stdout is not a tty (the common piped
               case). Accepting the flag unblocks the ubiquitous scripted
               `grep --color=auto` idiom instead of erroring. */
            else if (!strncmp (w, "--color", 7)
                     && (w[7] == '\0' || w[7] == '=')) { /* no-op */ }
            else if (!strncmp (w, "--colour", 8)
                     && (w[8] == '\0' || w[8] == '=')) { /* no-op */ }
            else if (!strcmp (w, "--only-matching")) o.oflag = 1;
            else if (!strcmp (w, "--recursive")) o.rflag = 1;
            else if (!strcmp (w, "--quiet") || !strcmp (w, "--silent")) o.qflag = 1;
            else if (!strcmp (w, "--no-messages")) o.sflag = 1;
            else if (!strcmp (w, "--with-filename")) o.Hflag = 1;
            else if (!strcmp (w, "--no-filename")) o.hflag = 1;
            else if (!strcmp (w, "--word-regexp")) o.wflag = 1;
            else if (!strcmp (w, "--line-regexp")) o.xflag = 1;
            else if (!strcmp (w, "--text")) o.aflag = 1;
            else if (!strcmp (w, "--null")) o.Zflag = 1;
            else if (!strncmp (w, "--max-count=", 12)) {
                int n;
                if (bg_parse_count (w + 12, &n) < 0) {
                    builtin_error ("--max-count: invalid count: %s", w + 12);
                    free (paths); return EX_USAGE;
                }
                o.mflag = n; o.mflag_set = 1;
            }
            else if (!strcmp (w, "--max-count")) {
                if (!p->next) { builtin_error ("--max-count needs N"); free (paths); return EX_USAGE; }
                p = p->next;
                int n;
                if (bg_parse_count (p->word->word, &n) < 0) {
                    builtin_error ("--max-count: invalid count: %s", p->word->word);
                    free (paths); return EX_USAGE;
                }
                o.mflag = n; o.mflag_set = 1;
            }
            else if (!strncmp (w, "--include=", 10) || !strncmp (w, "--exclude=", 10) ||
                     !strncmp (w, "--exclude-dir=", 14)) {
                char ***list_ptr = NULL;
                int *count_ptr = NULL;
                const char *glob = NULL;
                if (!strncmp (w, "--include=", 10)) {
                    list_ptr = &o.incl_globs; count_ptr = &o.n_incl; glob = w + 10;
                } else if (!strncmp (w, "--exclude=", 10)) {
                    list_ptr = &o.excl_globs; count_ptr = &o.n_excl; glob = w + 10;
                } else {
                    list_ptr = &o.excl_dir_globs; count_ptr = &o.n_excl_dir; glob = w + 14;
                }
                *list_ptr = realloc (*list_ptr, (size_t) (*count_ptr + 1) * sizeof **list_ptr);
                if (!*list_ptr) {
                    builtin_error ("realloc: %s", strerror (errno));
                    free (paths);
                    return EXECUTION_FAILURE;
                }
                (*list_ptr)[(*count_ptr)++] = strdup (glob);
            } else {
                builtin_error ("unknown option: %s", w);
                free (paths);
                return EX_USAGE;
            }
            p = p->next;
            continue;
        }
        /* Flags may appear anywhere (POSIX/GNU) — don't gate on
           parsed_pattern, otherwise repeated `-e PAT` after the first
           is misclassified as a file. The first non-flag word becomes
           the implicit pattern (only when no -e/-f set one). */
        if (!end_options && w[0] == '-' && w[1] != '\0')
        {
            for (const char *c = w + 1; *c; c++)
            {
                switch (*c)
                {
                    case 'E': o.Eflag = 1; o.Fflag = 0; o.Gflag = 0; o.Pflag = 0; break;
                    case 'G': o.Eflag = 0; o.Fflag = 0; o.Gflag = 1; o.Pflag = 0; break;
                    case 'F': o.Eflag = 0; o.Fflag = 1; o.Gflag = 0; o.Pflag = 0; break;
                    case 'P': o.Eflag = 0; o.Pflag = 1; o.Fflag = 0; o.Gflag = 0; break;
                    case 'i': o.iflag = 1; break;
                    case 'v': o.vflag = 1; break;
                    case 'c': o.cflag = 1; break;
                    case 'l': o.lflag = 1; break;
                    case 'L': o.Lflag = 1; break;
                    case 'n': o.nflag = 1; break;
                    case 'b': o.bflag = 1; break;
                    case 'z': o.zdflag = 1; break;
                    case 'o': o.oflag = 1; break;
                    case 'r': o.rflag = 1; break;
                    case 'H': o.Hflag = 1; break;
                    case 'h': o.hflag = 1; break;
                    case 'q': o.qflag = 1; break;
                    case 's': o.sflag = 1; break;
                    case 'w': o.wflag = 1; break;
                    case 'Z': o.Zflag = 1; break;
                    case 'a': o.aflag = 1; break;
                    case 'I': o.Iflag = 1; break;
                    case 'R': o.rflag = 1; break;   /* -R alias for -r */
                    case 'x': o.xflag = 1; break;
                    case 'm':
                    {
                        /* GNU grep accepts both the attached form (-m2) and
                           the separated form (-m 2), like -e/-f above. */
                        const char *cnt = NULL;
                        if (c[1] != '\0') {
                            cnt = c + 1;
                        } else {
                            if (!p->next) { builtin_error ("-m needs N"); free (paths); return EX_USAGE; }
                            p = p->next;
                            cnt = p->word->word;
                        }
                        int n;
                        if (bg_parse_count (cnt, &n) < 0)
                        {
                            builtin_error ("-m: invalid count: %s", cnt);
                            free (paths); return EX_USAGE;
                        }
                        o.mflag = n;
                        o.mflag_set = 1;
                        goto next_word;
                    }
                    case 'e':
                    {
                        const char *pat = NULL;
                        if (c[1] != '\0') {
                            pat = c + 1;
                        } else {
                            if (!p->next) { builtin_error ("-e needs PATTERN"); free (paths); return EX_USAGE; }
                            p = p->next;
                            pat = p->word->word;
                        }
                        if (o.n_patterns >= o.cap_patterns) {
                            int nc = o.cap_patterns ? o.cap_patterns * 2 : 8;
                            char **np = realloc (o.patterns, (size_t) nc * sizeof *np);
                            if (!np) { free (paths); return EXECUTION_FAILURE; }
                            o.patterns = np; o.cap_patterns = nc;
                        }
                        o.patterns[o.n_patterns++] = strdup (pat);
                        parsed_pattern = 1;
                        goto next_word;
                    }
                    case 'f':
                    {
                        if (!p->next) { builtin_error ("-f needs FILE"); free (paths); return EX_USAGE; }
                        p = p->next;
                        FILE *pf = fopen (p->word->word, "r");
                        if (!pf) {
                            if (!o.sflag) builtin_error ("-f %s: %s", p->word->word, strerror (errno));
                            free (paths); return EXECUTION_FAILURE;
                        }
                        char *line = NULL; size_t cap = 0; ssize_t rd;
                        while ((rd = getline (&line, &cap, pf)) != -1) {
                            if (rd > 0 && line[rd - 1] == '\n') line[rd - 1] = '\0';
                            if (o.n_patterns >= o.cap_patterns) {
                                int nc = o.cap_patterns ? o.cap_patterns * 2 : 8;
                                char **np = realloc (o.patterns, (size_t) nc * sizeof *np);
                                if (!np) { free (line); fclose (pf); free (paths); return EXECUTION_FAILURE; }
                                o.patterns = np; o.cap_patterns = nc;
                            }
                            o.patterns[o.n_patterns++] = strdup (line);
                        }
                        free (line); fclose (pf);
                        parsed_pattern = 1;
                        goto next_word;
                    }
                    case 'A':
                    case 'B':
                    case 'C':
                    {
                        char which = *c;
                        const char *cnt;
                        /* Attached form -A1/-B2/-C3 (GNU grep): the count is
                           the rest of this word; otherwise it is the next
                           argument (-A 1). */
                        if (c[1]) {
                            cnt = c + 1;
                        } else {
                            if (!p->next) { builtin_error ("-%c needs N", which); free (paths); return EX_USAGE; }
                            p = p->next;
                            cnt = p->word->word;
                        }
                        int n;
                        if (bg_parse_count (cnt, &n) < 0)
                        {
                            builtin_error ("-%c: invalid count: %s", which, cnt);
                            free (paths); return EX_USAGE;
                        }
                        if (which == 'A' || which == 'C') o.A = n;
                        if (which == 'B' || which == 'C') o.B = n;
                        goto next_word;
                    }
                    default:
                        builtin_error ("unknown flag: -%c", *c);
                        builtin_usage ();
                        free (paths);
                        return EX_USAGE;
                }
            }
        }
        else if (!parsed_pattern)
        {
            o.pattern = (char *) w;
            parsed_pattern = 1;
        }
        else
        {
            if (n_files == paths_cap) {
                paths_cap *= 2;
                const char **bigger = realloc (paths, paths_cap * sizeof *paths);
                if (!bigger) { free (paths); return EXECUTION_FAILURE; }
                paths = bigger;
            }
            paths[n_files++] = w;
        }
    next_word:
        p = p->next;
    }

    if (!parsed_pattern)
    {
        free (paths);
        builtin_error ("usage: bashgrep [-EFiloncrvHhwx] [-A N] [-B N] [-C N] [-m N] [-e PAT]... [-f FILE]... [PATTERN] [FILE...]");
        return EX_USAGE;
    }

    if (o.mflag_set && o.mflag == 0)
    {
        free (paths);
        if (o.patterns) {
            for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
            free (o.patterns);
        }
        return 1;
    }

    if (o.Pflag && o.zdflag)
    {
        free (paths);
        if (o.patterns) {
            for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
            free (o.patterns);
        }
        builtin_error ("-P with -z is not supported in this bashgrep slice");
        return EX_USAGE;
    }
    if (o.Pflag && o.wflag)
    {
        free (paths);
        if (o.patterns) {
            for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
            free (o.patterns);
        }
        builtin_error ("-P with -w is not supported in this bashgrep slice");
        return EX_USAGE;
    }

    /* Default dialect: GNU grep is BRE when no -E/-F/-P is given, where
       unescaped `(` `)` are literal and `\(` `\)` group. The engine stays
       REG_EXTENDED, so swap the escapedness of parens per arm before the
       ERE combiner below adds its own meta parens. Explicit -E keeps raw
       ERE; -G compiles plain regcomp BRE further down. */
    char *pat_compat = NULL;    /* compat copy of the positional pattern */
    if (!o.Eflag && !o.Gflag && !o.Fflag && !o.Pflag) {
        for (int i = 0; i < o.n_patterns; i++) {
            char *t = bg_bre_paren_compat (o.patterns[i]);
            if (!t) { free (paths); return EXECUTION_FAILURE; }
            free (o.patterns[i]);
            o.patterns[i] = t;
        }
        if (o.pattern) {
            pat_compat = bg_bre_paren_compat (o.pattern);
            if (!pat_compat) { free (paths); return EXECUTION_FAILURE; }
            o.pattern = pat_compat;
        }
    }

    /* Combine multi-patterns from -e / -f / first positional into a single
       OR-pattern: (p1)|(p2)|(p3). For -x, additionally anchor with ^...$.
       For -F (fixed string), skip regex combining; fixed-string matching
       walks the pattern vector directly. */
    char *combined = NULL;
    if (o.Fflag) {
        /* Empty -f FILE leaves no active pattern, so the base match set is
           empty; -v inverts that later to emit every line. */
    } else if (o.Gflag && o.n_patterns == 0 && o.pattern && !o.xflag) {
        /* Keep single basic-regex patterns literal. The ERE combiner below
           wraps arms in () and joins with |, both of which alter BRE syntax. */
    } else if (o.n_patterns > 0 || o.pattern) {
        size_t total = 1;
        for (int i = 0; i < o.n_patterns; i++)
            total += strlen (o.patterns[i]) + 4;
        if (o.pattern) total += strlen (o.pattern) + 4;
        if (o.xflag) total += 2;   /* ^ + $ */
        combined = malloc (total);
        if (!combined) { free (paths); return EXECUTION_FAILURE; }
        size_t op = 0;
        if (o.xflag) combined[op++] = '^';
        if (o.xflag) combined[op++] = '(';   /* group all alternatives */
        int first = 1;
        for (int i = 0; i < o.n_patterns; i++) {
            if (!first) { combined[op++] = '|'; }
            combined[op++] = '(';
            size_t l = strlen (o.patterns[i]);
            memcpy (combined + op, o.patterns[i], l); op += l;
            combined[op++] = ')';
            first = 0;
        }
        if (o.pattern) {
            if (!first) { combined[op++] = '|'; }
            combined[op++] = '(';
            size_t l = strlen (o.pattern);
            memcpy (combined + op, o.pattern, l); op += l;
            combined[op++] = ')';
        }
        if (o.xflag) { combined[op++] = ')'; combined[op++] = '$'; }
        combined[op] = '\0';
        o.pattern = combined;
    } else {
        /* Empty -f FILE: grep's base match result is "no line matches".
           A regex that cannot match any POSIX line preserves -v behavior. */
        o.pattern = "a^";
    }
    /* A live pat_compat always went through the combiner above (the -G
       carve-out and -F skip paths never set it), so o.pattern now points
       at `combined` and the per-arm compat copy is dead. */
    free (pat_compat);

    /* Compile regex unless -F. */
    if (o.Pflag)
    {
        o.pcre = bg_pcre_compile (o.pattern, o.iflag);
        if (!o.pcre)
        {
            free (paths);
            free (combined);
            if (o.patterns) {
                for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
                free (o.patterns);
            }
            return EX_USAGE;
        }
        o.pcre_md = pcre2_match_data_create_from_pattern (o.pcre, NULL);
        if (!o.pcre_md)
        {
            builtin_error ("pcre2 match_data allocation failed");
            pcre2_code_free (o.pcre);
            free (paths);
            free (combined);
            if (o.patterns) {
                for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
                free (o.patterns);
            }
            return EXECUTION_FAILURE;
        }
    }
    else if (!o.Fflag)
    {
        int flags = REG_NEWLINE;
        if (!o.Gflag) flags |= REG_EXTENDED;
        if (o.iflag) flags |= REG_ICASE;
        int rrc = regcomp (&o.re, o.pattern, flags);
        /* Permissive-ERE retry: on stray-brace errors, escape every
           literal `{`/`}` and recompile. Matches GNU/BSD grep, which
           accept patterns like `^{` that POSIX ERE rejects. */
        if (rrc == REG_BADBR || rrc == REG_BADRPT
#ifdef REG_EBRACE
            || rrc == REG_EBRACE
#endif
            )
        {
            char *retry = bg_escape_braces (o.pattern);
            if (retry)
            {
                regex_t re2;
                int rrc2 = regcomp (&re2, retry, flags);
                if (rrc2 == 0)
                {
                    o.re = re2;
                    rrc = 0;
                }
                free (retry);
            }
        }
        if (rrc != 0)
        {
            char ebuf[256];
            regerror (rrc, &o.re, ebuf, sizeof ebuf);
            builtin_error ("bad regex: %s", ebuf);
            free (paths);
            return EX_USAGE;
        }
        o.re_compiled = 1;
    }

    long total = 0;
    int rc = EXECUTION_SUCCESS;
    if (n_files == 0)
    {
        long c = bg_grep_file (&o, NULL, 1, 0);
        if (c < 0) rc = EXECUTION_FAILURE;
        else total += c;
    }
    else
    {
        for (int i = 0; i < n_files; i++)
        {
            long c = o.rflag ? bg_grep_recursive (&o, paths[i], 0)
                             : bg_grep_file (&o, paths[i], n_files, 0);
            if (c < 0) rc = EXECUTION_FAILURE;
            else total += c;
        }
    }

    if (o.re_compiled) regfree (&o.re);
    if (o.pcre_md) pcre2_match_data_free (o.pcre_md);
    if (o.pcre) pcre2_code_free (o.pcre);
    free (paths);
    free (combined);
    if (o.patterns) {
        for (int i = 0; i < o.n_patterns; i++) free (o.patterns[i]);
        free (o.patterns);
    }
    /* grep convention: 0 if any matches, 1 if none, 2 if error. */
    if (rc != EXECUTION_SUCCESS) return 2;
    return total > 0 ? 0 : 1;
}

char *grep_doc[] = {
    "POSIX-shape grep(1) — line matching with regex or fixed strings.",
    "",
    "    bashgrep [FLAGS] [-e PATTERN]... [-f FILE]... [PATTERN] [FILE ...]",
    "",
    "Flags:",
    "    -E   raw extended regex (default treats unescaped ( ) as literal,",
    "         \\( \\) as groups — GNU-grep BRE paren behavior)",
    "    -F   fixed string (memmem)",
    "    -P   Perl-compatible regex (PCRE2)",
    "    -i   case-insensitive",
    "    -v   invert match",
    "    -c   only count per file",
    "    -l   list filenames with matches",
    "    -L   inverse of -l",
    "    -n   prefix line numbers",
    "    -o   only matching part",
    "    -r   recurse directories",
    "    -q   quiet — exit 0 on first match, no output",
    "    -s   suppress error messages on missing/unreadable files",
    "    -H   always prefix filename",
    "    -h   never prefix filename",
    "    -w   word-boundary match (anchor with \\<...\\>)",
    "    -x   whole-line match (anchor with ^...$)",
    "    -m N stop after N matches per file",
    "    -e PATTERN   add PATTERN to the pattern set; can repeat",
    "    -f FILE      add patterns from FILE (one per line); can repeat",
    "    -a   treat binary files as text",
    "    -I   skip binary files entirely",
    "    -Z / --null  NUL-separate filenames in output",
    "    -A N -B N -C N   context lines",
    "    --include=GLOB  / --exclude=GLOB  / --exclude-dir=GLOB",
    "",
    "Multi-pattern: -e PATTERNs and -f FILE patterns are OR-combined",
    "(GNU semantics). The bare PATTERN positional is also accepted",
    "when no -e/-f is given.",
    "",
    "Exit: 0 if matches found, 1 if none, 2 on error.",
    (char *)NULL
};

struct builtin bashgrep_struct = {
    "bashgrep",
    grep_builtin,
    BUILTIN_ENABLED,
    grep_doc,
    "bashgrep [-EFPiloncrvqsHhwxaIZ] [-m N] [-e PAT]... [-f FILE]... [-A N] [-B N] [-C N] [PATTERN] [FILE ...]",
    0
};
