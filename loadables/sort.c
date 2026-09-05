/* bashsort.c — POSIX sort(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. Reads all input lines into
 * memory, qsort()s with a flag-driven comparator, emits.
 *
 *   bashsort [-zRVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [FILE...]
 *
 *   -n   numeric (atof) compare
 *   -g   general numeric compare (strtold)
 *   -h   human numeric compare (SI suffix order)
 *   -V   version/natural compare
 *   -R   random compare (shuffle, grouping equal keys)
 *        --random-source=FILE seed random ordering from FILE bytes
 *   -M   month compare (Jan..Dec; unknown names sort before Jan)
 *   -m   merge already-sorted inputs
 *   -b   ignore leading blanks in comparison keys
 *   -d   dictionary order: compare only blanks and alphanumeric bytes
 *   -r   reverse
 *   -u   suppress duplicate adjacent lines (post-sort dedup)
 *   -f   ignore case
 *   -c   check sorted (exit 0 if sorted, 1 otherwise)
 *   -i   ignore non-printable
 *   -s   stable: preserve input order for equal keys
 *   -t SEP   field separator (default: whitespace runs)
 *   -k KEYDEF which field to compare (simple FIELD[.C][,FIELD[.C]][bdfirnghVM] subset)
 *   -o FILE  write result to FILE
 *   -z, --zero-terminated  use NUL as the record delimiter
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
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <time.h>

#include "loadables.h"

typedef struct {
    int field;        /* 1-based; 0 = disabled */
    int start_char;   /* 1-based; 0 = field start */
    int end_field;    /* 1-based; 0 = same as field */
    int end_char;     /* 1-based inclusive; 0 = field end */
    int numeric;
    int general_numeric;
    int human_numeric;
    int version;
    int month;
    int reverse;
    int ignore_leading_blanks;
    int dictionary_order;
    int ignore_case;
    int ignore_nonprinting;
} bs_keydef;

typedef struct {
    int nflag, gflag, hflag, vflag, Rflag, bflag, dflag, rflag, uflag, fflag, cflag, Cflag, iflag, sflag, mflag, mergeflag, zflag;
    int check_quiet;
    char tsep;
    int  has_tsep;
    int  kfield;       /* 1-based; 0 = whole line */
    bs_keydef keys[8];
    int nkeys;
} bs_opts;

typedef struct {
    char *buf;
    size_t len;
    size_t index;
    uint64_t random_rank;
} bs_line;

typedef struct {
    size_t start;
    size_t end;
    size_t pos;
    const char *name;   /* source file name for diagnostics; "-" for stdin */
} bs_run;

static bs_opts *bs_cmp_opts;

static uint64_t bs_random_state;

static uint64_t
bs_random_next (void)
{
    uint64_t x = bs_random_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    bs_random_state = x ? x : 0x9e3779b97f4a7c15ULL;
    return bs_random_state;
}

static int
bs_random_seed (const char *random_source)
{
    uint64_t seed = 1469598103934665603ULL;

    if (random_source) {
        FILE *f = fopen (random_source, "rb");
        int ch;
        size_t nread = 0;

        if (!f) {
            builtin_error ("%s: %s", random_source, strerror (errno));
            return -1;
        }
        while ((ch = fgetc (f)) != EOF) {
            seed ^= (unsigned char) ch;
            seed *= 1099511628211ULL;
            nread++;
        }
        if (ferror (f)) {
            builtin_error ("%s: %s", random_source, strerror (errno));
            fclose (f);
            return -1;
        }
        if (fclose (f) != 0) {
            builtin_error ("%s: %s", random_source, strerror (errno));
            return -1;
        }
        if (nread == 0) {
            builtin_error ("%s: end of file", random_source);
            return -1;
        }
        bs_random_state = seed ? seed : 0x9e3779b97f4a7c15ULL;
        return 0;
    }

    seed ^= (uint64_t) time (NULL);
#if defined (HAVE_GETPID) || defined (_POSIX_VERSION)
    seed ^= ((uint64_t) getpid ()) << 32;
#endif
    seed ^= (uint64_t) (uintptr_t) &seed;
    bs_random_state = seed ? seed : 0x9e3779b97f4a7c15ULL;
    return 0;
}

static int
bs_parse_keydef (const char *s, bs_keydef *key)
{
    char *end = NULL;
    unsigned long field;
    unsigned long start_char = 0;
    unsigned long end_field = 0;
    unsigned long end_char = 0;

    if (!s || !*s)
        return -1;
    errno = 0;
    field = strtoul (s, &end, 10);
    if (errno || field == 0 || field > 2147483647UL)
        return -1;
    key->field = (int) field;
    key->start_char = 0;
    key->end_field = 0;
    key->end_char = 0;
    key->numeric = 0;
    key->general_numeric = 0;
    key->human_numeric = 0;
    key->version = 0;
    key->month = 0;
    key->reverse = 0;
    key->ignore_leading_blanks = 0;
    key->dictionary_order = 0;
    key->ignore_case = 0;
    key->ignore_nonprinting = 0;

    if (*end == '.') {
        end++;
        if (!isdigit ((unsigned char) *end))
            return -1;
        errno = 0;
        start_char = strtoul (end, &end, 10);
        if (errno || start_char == 0 || start_char > 2147483647UL)
            return -1;
        key->start_char = (int) start_char;
    }
    if (*end == ',') {
        end++;
        if (!isdigit ((unsigned char) *end))
            return -1;
        errno = 0;
        end_field = strtoul (end, &end, 10);
        if (errno || end_field == 0 || end_field > 2147483647UL || end_field < field)
            return -1;
        key->end_field = (int) end_field;
        if (*end == '.') {
            end++;
            if (!isdigit ((unsigned char) *end))
                return -1;
            errno = 0;
            end_char = strtoul (end, &end, 10);
            if (errno || end_char == 0 || end_char > 2147483647UL)
                return -1;
            key->end_char = (int) end_char;
        }
        if (key->end_field == key->field && key->end_char && key->start_char &&
            key->end_char < key->start_char)
            return -1;
    }
    while (*end) {
        switch (*end) {
            case 'n':
                key->numeric = 1;
                break;
            case 'g':
                key->general_numeric = 1;
                break;
            case 'h':
                key->human_numeric = 1;
                break;
            case 'V':
                key->version = 1;
                break;
            case 'M':
                key->month = 1;
                break;
            case 'r':
                key->reverse = 1;
                break;
            case 'b':
                key->ignore_leading_blanks = 1;
                break;
            case 'd':
                key->dictionary_order = 1;
                break;
            case 'f':
                key->ignore_case = 1;
                break;
            case 'i':
                key->ignore_nonprinting = 1;
                break;
            default:
                return -1;
        }
        end++;
    }
    return 0;
}

static int
bs_version_cmp (const char *a, const char *b)
{
    const unsigned char *pa = (const unsigned char *) a;
    const unsigned char *pb = (const unsigned char *) b;

    while (*pa || *pb) {
        if (isdigit (*pa) && isdigit (*pb)) {
            const unsigned char *za = pa;
            const unsigned char *zb = pb;
            while (*za == '0')
                za++;
            while (*zb == '0')
                zb++;

            const unsigned char *ea = za;
            const unsigned char *eb = zb;
            while (isdigit (*ea))
                ea++;
            while (isdigit (*eb))
                eb++;

            size_t la = (size_t) (ea - za);
            size_t lb = (size_t) (eb - zb);
            if (la != lb)
                return (la < lb) ? -1 : 1;
            for (size_t i = 0; i < la; i++) {
                if (za[i] != zb[i])
                    return (za[i] < zb[i]) ? -1 : 1;
            }

            /* Equal numeric value. Prefer fewer leading zeroes. */
            size_t lza = (size_t) (za - pa);
            size_t lzb = (size_t) (zb - pb);
            if (lza != lzb)
                return (lza < lzb) ? -1 : 1;

            pa = ea;
            pb = eb;
            continue;
        }
        if (*pa != *pb)
            return (*pa < *pb) ? -1 : 1;
        if (*pa)
            pa++;
        if (*pb)
            pb++;
    }
    return 0;
}

static int
bs_general_numcmp (const char *a, const char *b)
{
    char *ea = NULL;
    char *eb = NULL;
    long double na = strtold (a, &ea);
    long double nb = strtold (b, &eb);

    if (ea == a)
        return (eb == b) ? 0 : -1;
    if (eb == b)
        return 1;

    if (na < nb)
        return -1;
    if (na > nb)
        return 1;
    if (na == nb)
        return 0;
    if (isnan (na) && isnan (nb))
        return 0;
    if (isnan (na))
        return -1;
    return 1;
}

static int
bs_human_unit_order (const char *number)
{
    int negative = 0;
    char *end = NULL;
    long double value;
    int order = 0;

    while (*number == ' ' || *number == '\t')
        number++;
    if (*number == '-')
        negative = 1;

    value = strtold (number, &end);
    if (end == number || value == 0.0L)
        return 0;

    switch ((unsigned char) *end) {
        case 'k':
        case 'K': order = 1; break;
        case 'M': order = 2; break;
        case 'G': order = 3; break;
        case 'T': order = 4; break;
        case 'P': order = 5; break;
        case 'E': order = 6; break;
        case 'Z': order = 7; break;
        case 'Y': order = 8; break;
        case 'R': order = 9; break;
        case 'Q': order = 10; break;
        default: order = 0; break;
    }
    return negative ? -order : order;
}

static int
bs_human_numcmp (const char *a, const char *b)
{
    int oa = bs_human_unit_order (a);
    int ob = bs_human_unit_order (b);

    if (oa != ob)
        return oa - ob;
    return bs_general_numcmp (a, b);
}

static int
bs_month_value (const char *s)
{
    static const char *months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"
    };
    char key[4];

    while (*s == ' ' || *s == '\t')
        s++;
    for (int i = 0; i < 3; i++) {
        if (!s[i])
            return 0;
        key[i] = (char) tolower ((unsigned char) s[i]);
    }
    key[3] = '\0';
    for (int i = 0; i < 12; i++) {
        if (strcmp (key, months[i]) == 0)
            return i + 1;
    }
    return 0;
}

static int
bs_add_keydef (bs_opts *o, const char *s)
{
    if (o->nkeys >= (int) (sizeof o->keys / sizeof o->keys[0])) {
        builtin_error ("too many -k keys");
        return -1;
    }
    if (bs_parse_keydef (s, &o->keys[o->nkeys]) < 0) {
        builtin_error ("invalid key: %s", s);
        return -1;
    }
    o->kfield = o->keys[0].field;
    o->nkeys++;
    return 0;
}

static int
bs_add_line (bs_line **linesp, size_t *np, size_t *capp, const char *line, size_t len, int delim)
{
    bs_line *lines = *linesp;
    size_t n = *np;
    size_t cap = *capp;
    size_t out_len = len;

    /* Normalize: every stored record ends with the record delimiter, so a
       final line that lacks one (no trailing newline / NUL at EOF) does not
       run into the next record on output. GNU sort appends the delimiter to
       such a last line. */
    if (out_len == 0 || (unsigned char) line[out_len - 1] != (unsigned char) delim)
        out_len++;

    if (n >= cap) {
        cap = cap ? cap * 2 : 64;
        bs_line *nb = realloc (lines, cap * sizeof *nb);
        if (!nb)
            return -1;
        lines = nb;
        *linesp = lines;
        *capp = cap;
    }
    lines[n].buf = malloc (out_len + 1);
    if (!lines[n].buf)
        return -1;
    memcpy (lines[n].buf, line, len);
    if (out_len > len)
        lines[n].buf[len] = (char) delim;
    lines[n].buf[out_len] = '\0';
    lines[n].len = out_len;
    lines[n].index = n;
    lines[n].random_rank = 0;
    *np = n + 1;
    return 0;
}

static void
bs_free_lines (bs_line *lines, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free (lines[i].buf);
    free (lines);
}

static void
bs_field_bounds (const char *line, bs_opts *o, int target, const char **startp, const char **endp)
{
    int field = 0;
    const char *p = line;

    *startp = "";
    *endp = "";
    if (target <= 0)
        return;
    if (o->has_tsep) {
        for (int f = 1; f < target; f++) {
            while (*p && *p != o->tsep) p++;
            if (*p) p++;
            else return;
        }
        *startp = p;
        while (*p && *p != o->tsep) p++;
        *endp = p;
        return;
    }

    while (*p && (*p == ' ' || *p == '\t')) p++;
    while (field < target - 1 && *p) {
        while (*p && *p != ' ' && *p != '\t') p++;
        while (*p == ' ' || *p == '\t') p++;
        field++;
    }
    if (!*p)
        return;
    *startp = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    *endp = p;
}

/* Extract the comparison key from a line per the -t/-k options. */
static const char *
bs_key (const char *line, char *scratch, size_t scratch_sz, bs_opts *o, const bs_keydef *key)
{
    int start_field = key ? key->field : o->kfield;
    int start_char = key ? key->start_char : 0;
    int end_field = key && key->end_field ? key->end_field : start_field;
    int end_char = key ? key->end_char : 0;
    const char *s, *se, *e, *ee, *fs, *fe;
    size_t l;

    if (start_field <= 0)
        return line;
    bs_field_bounds (line, o, start_field, &s, &se);
    if (!*s)
        return "";
    if ((key && key->ignore_leading_blanks) || o->bflag) {
        while (s < se && (*s == ' ' || *s == '\t'))
            s++;
    }
    fs = s;
    bs_field_bounds (line, o, end_field, &e, &ee);
    if (!*e)
        e = ee = se;
    fe = e;

    if (start_char > 1) {
        const char *limit = se;
        int skip = start_char - 1;
        while (skip-- > 0 && s < limit)
            s++;
    }
    if (end_char > 0) {
        const char *limit = ee;
        e = (end_field == start_field) ? fs : fe;
        while (end_char-- > 0 && e < limit)
            e++;
    } else {
        e = ee;
    }
    if (e < s)
        e = s;
    l = (size_t) (e - s);
    if (l >= scratch_sz) l = scratch_sz - 1;
    memcpy (scratch, s, l);
    scratch[l] = '\0';
    return scratch;
}

static int
bs_dictionary_byte (unsigned char ch)
{
    return isalnum (ch) || ch == ' ' || ch == '\t';
}

static int
bs_cmp_str (const char *a, const char *b, int icase, int ignore_nonprint, int dictionary_order)
{
    for (;;) {
        while (ignore_nonprint && *a && !isprint ((unsigned char) *a))
            a++;
        while (ignore_nonprint && *b && !isprint ((unsigned char) *b))
            b++;
        while (dictionary_order && *a && !bs_dictionary_byte ((unsigned char) *a))
            a++;
        while (dictionary_order && *b && !bs_dictionary_byte ((unsigned char) *b))
            b++;
        if (!*a || !*b)
            return (unsigned char) *a - (unsigned char) *b;
        int ca = (unsigned char) *a;
        int cb = (unsigned char) *b;
        if (icase) {
            ca = tolower (ca);
            cb = tolower (cb);
        }
        if (ca != cb) return ca - cb;
        a++; b++;
    }
}

static int
bs_cmp_bytes (const bs_line *a, const bs_line *b, int icase, int ignore_nonprint, int dictionary_order)
{
    size_t ia = 0, ib = 0;

    while (ia < a->len || ib < b->len) {
        while (ignore_nonprint && ia < a->len && !isprint ((unsigned char) a->buf[ia]))
            ia++;
        while (ignore_nonprint && ib < b->len && !isprint ((unsigned char) b->buf[ib]))
            ib++;
        while (dictionary_order && ia < a->len && !bs_dictionary_byte ((unsigned char) a->buf[ia]))
            ia++;
        while (dictionary_order && ib < b->len && !bs_dictionary_byte ((unsigned char) b->buf[ib]))
            ib++;
        if (ia >= a->len || ib >= b->len)
            break;
        int ca = (unsigned char) a->buf[ia];
        int cb = (unsigned char) b->buf[ib];
        if (icase) {
            ca = tolower (ca);
            cb = tolower (cb);
        }
        if (ca != cb)
            return ca - cb;
        ia++;
        ib++;
    }
    if (ia >= a->len && ib >= b->len)
        return 0;
    if (ia >= a->len)
        return -1;
    return 1;
}

static int
bs_cmp_bytes_key (const bs_line *a, const bs_line *b, int icase, int ignore_nonprint, int ignore_leading_blanks, int dictionary_order)
{
    size_t ia = 0, ib = 0;
    bs_line ka = *a;
    bs_line kb = *b;

    if (ignore_leading_blanks) {
        while (ia < a->len && (a->buf[ia] == ' ' || a->buf[ia] == '\t'))
            ia++;
        while (ib < b->len && (b->buf[ib] == ' ' || b->buf[ib] == '\t'))
            ib++;
    }
    ka.buf = a->buf + ia;
    ka.len = a->len - ia;
    kb.buf = b->buf + ib;
    kb.len = b->len - ib;
    return bs_cmp_bytes (&ka, &kb, icase, ignore_nonprint, dictionary_order);
}

static int
bs_compare_line (const bs_line *la, const bs_line *lb, bs_opts *o, int apply_reverse)
{
    int cmp;

    if (o->nkeys > 0) {
        for (int i = 0; i < o->nkeys; i++) {
            char ka[256], kb[256];
            bs_opts ko = *o;
            ko.kfield = o->keys[i].field;
            const char *ax = bs_key (la->buf, ka, sizeof ka, &ko, &o->keys[i]);
            const char *bx = bs_key (lb->buf, kb, sizeof kb, &ko, &o->keys[i]);

            if (o->keys[i].month || o->mflag) {
                int ma = bs_month_value (ax);
                int mb = bs_month_value (bx);
                cmp = ma - mb;
            } else if (o->keys[i].version || o->vflag) {
                cmp = bs_version_cmp (ax, bx);
            } else if (o->keys[i].human_numeric || o->hflag) {
                cmp = bs_human_numcmp (ax, bx);
            } else if (o->keys[i].general_numeric || o->gflag) {
                cmp = bs_general_numcmp (ax, bx);
            } else if (o->keys[i].numeric || o->nflag) {
                double na = strtod (ax, NULL);
                double nb = strtod (bx, NULL);
                cmp = (na < nb) ? -1 : (na > nb) ? 1 : 0;
            } else {
                cmp = bs_cmp_str (ax, bx, o->keys[i].ignore_case || o->fflag, o->keys[i].ignore_nonprinting || o->iflag, o->keys[i].dictionary_order || o->dflag);
            }
            if (cmp != 0 && o->keys[i].reverse)
                cmp = -cmp;
            if (cmp != 0)
                goto done;
        }
        cmp = 0;
    } else if (o->kfield <= 0 && !o->nflag && !o->gflag && !o->hflag && !o->vflag && !o->mflag) {
        cmp = bs_cmp_bytes_key (la, lb, o->fflag, o->iflag, o->bflag, o->dflag);
    } else {
        char ka[256], kb[256];
        const char *ax = bs_key (la->buf, ka, sizeof ka, o, NULL);
        const char *bx = bs_key (lb->buf, kb, sizeof kb, o, NULL);
        if (o->bflag) {
            while (*ax == ' ' || *ax == '\t')
                ax++;
            while (*bx == ' ' || *bx == '\t')
                bx++;
        }
        if (o->mflag) {
            int ma = bs_month_value (ax);
            int mb = bs_month_value (bx);
            cmp = ma - mb;
        } else if (o->vflag) {
            cmp = bs_version_cmp (ax, bx);
        } else if (o->hflag) {
            cmp = bs_human_numcmp (ax, bx);
        } else if (o->gflag) {
            cmp = bs_general_numcmp (ax, bx);
        } else if (o->nflag) {
            double na = strtod (ax, NULL);
            double nb = strtod (bx, NULL);
            cmp = (na < nb) ? -1 : (na > nb) ? 1 : 0;
        } else {
            cmp = bs_cmp_str (ax, bx, o->fflag, o->iflag, o->dflag);
        }
    }
done:
    if (apply_reverse && o->rflag)
        cmp = -cmp;
    return cmp;
}

static int
bs_compare_line_keys (const bs_line *la, const bs_line *lb, bs_opts *o)
{
    bs_opts ko = *o;

    ko.Rflag = 0;
    ko.rflag = 0;
    return bs_compare_line (la, lb, &ko, 0);
}

static int
bs_compare (const void *va, const void *vb)
{
    const bs_line *la = (const bs_line *) va;
    const bs_line *lb = (const bs_line *) vb;
    int cmp;

    if (bs_cmp_opts->Rflag) {
        if (la->random_rank < lb->random_rank)
            cmp = -1;
        else if (la->random_rank > lb->random_rank)
            cmp = 1;
        else
            cmp = bs_compare_line_keys (la, lb, bs_cmp_opts);
        if (bs_cmp_opts->rflag)
            cmp = -cmp;
    } else {
        cmp = bs_compare_line (la, lb, bs_cmp_opts, 1);
    }

    if (cmp == 0) {
        if (bs_cmp_opts->sflag) {
            /* -s (stable): preserve input order, no last-resort compare. */
            if (la->index < lb->index)
                return -1;
            if (la->index > lb->index)
                return 1;
        } else if (!bs_cmp_opts->Rflag) {
            /* GNU default last-resort: when the specified keys compare equal,
               compare the entire records bytewise (LC_COLLATE=C), excluding
               the trailing record delimiter. Subject to global -r. -R has its
               own random tiebreak above, so it is excluded here. */
            size_t na = la->len, nb = lb->len;
            if (na && (la->buf[na - 1] == '\n' || la->buf[na - 1] == '\0')) na--;
            if (nb && (lb->buf[nb - 1] == '\n' || lb->buf[nb - 1] == '\0')) nb--;
            size_t m = na < nb ? na : nb;
            int c = m ? memcmp (la->buf, lb->buf, m) : 0;
            if (c == 0)
                c = (na > nb) - (na < nb);
            if (bs_cmp_opts->rflag)
                c = -c;
            if (c)
                return c;
        }
    }
    return cmp;
}

static void
bs_emit_lines (FILE *out, bs_line *lines, size_t n, const bs_opts *o)
{
    for (size_t i = 0; i < n; i++) {
        if (o->uflag && i > 0) {
            int eq = (bs_compare_line_keys (&lines[i - 1], &lines[i], (bs_opts *) o) == 0);
            if (eq)
                continue;
        }
        fwrite (lines[i].buf, 1, lines[i].len, out);
    }
}

static void
bs_emit_merged (FILE *out, bs_line *lines, bs_run *runs, size_t nruns, const bs_opts *o)
{
    bs_line *last = NULL;

    for (;;) {
        size_t best = (size_t) -1;
        for (size_t r = 0; r < nruns; r++) {
            if (runs[r].pos >= runs[r].end)
                continue;
            if (best == (size_t) -1
                || bs_compare_line (&lines[runs[r].pos], &lines[runs[best].pos], (bs_opts *) o, 1) < 0)
                best = r;
        }
        if (best == (size_t) -1)
            break;
        bs_line *cur = &lines[runs[best].pos++];
        if (o->uflag && last && bs_compare_line_keys (last, cur, (bs_opts *) o) == 0)
            continue;
        fwrite (cur->buf, 1, cur->len, out);
        last = cur;
    }
}

int
sort_builtin (WORD_LIST *list)
{
    bs_opts o = {0};
    const char *output_file = NULL;
    const char *random_source = NULL;
    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashsort 1.0 (bash-os)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--numeric-sort")) { o.nflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--sort=numeric")) { o.nflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--general-numeric-sort") || !strcmp (w, "--sort=general-numeric")) {
            o.gflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--human-numeric-sort") || !strcmp (w, "--sort=human-numeric")) {
            o.hflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--version-sort") || !strcmp (w, "--sort=version")) {
            o.vflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--random-sort") || !strcmp (w, "--sort=random")) {
            o.Rflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--random-source")) {
            if (!list->next) { builtin_error ("%s needs FILE", w); return EX_USAGE; }
            list = list->next;
            if (random_source && strcmp (random_source, list->word->word) != 0) {
                builtin_error ("multiple random sources specified");
                return EX_USAGE;
            }
            random_source = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--random-source=", 16)) {
            if (random_source && strcmp (random_source, w + 16) != 0) {
                builtin_error ("multiple random sources specified");
                return EX_USAGE;
            }
            random_source = w + 16;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--month-sort") || !strcmp (w, "--sort=month")) { o.mflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--merge")) { o.mergeflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--ignore-leading-blanks")) { o.bflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--dictionary-order")) { o.dflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--reverse")) { o.rflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--unique")) { o.uflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--ignore-case")) { o.fflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--ignore-nonprinting")) { o.iflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--stable")) { o.sflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--zero-terminated")) { o.zflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--check") || !strncmp (w, "--check=", 8)) {
            o.cflag = 1;
            if (!strcmp (w, "--check=quiet") || !strcmp (w, "--check=silent"))
                o.check_quiet = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-t") || !strcmp (w, "--field-separator")) {
            if (!list->next) { builtin_error ("%s needs SEP", w); return EX_USAGE; }
            list = list->next;
            if (list->word->word[0] == '\0') {
                builtin_error ("%s needs a non-empty SEP", w);
                return EX_USAGE;
            }
            o.tsep = list->word->word[0];
            o.has_tsep = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--field-separator=", 18)) {
            if (w[18] == '\0') {
                builtin_error ("--field-separator needs a non-empty SEP");
                return EX_USAGE;
            }
            o.tsep = w[18];
            o.has_tsep = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-k") || !strcmp (w, "--key")) {
            if (!list->next) { builtin_error ("%s needs FIELD", w); return EX_USAGE; }
            list = list->next;
            if (bs_add_keydef (&o, list->word->word) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--key=", 6)) {
            if (bs_add_keydef (&o, w + 6) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-o") || !strcmp (w, "--output")) {
            if (!list->next) { builtin_error ("%s needs FILE", w); return EX_USAGE; }
            list = list->next;
            output_file = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--output=", 9)) {
            output_file = w + 9;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-k", 2) && w[2] >= '0' && w[2] <= '9') {
            if (bs_add_keydef (&o, w + 2) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (w[1] == '-') {
            builtin_error ("unknown option: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        for (const char *p = w + 1; *p; p++) {
            switch (*p) {
                case 'n': o.nflag = 1; break;
                case 'g': o.gflag = 1; break;
                case 'h': o.hflag = 1; break;
                case 'V': o.vflag = 1; break;
                case 'R': o.Rflag = 1; break;
                case 'M': o.mflag = 1; break;
                case 'm': o.mergeflag = 1; break;
                case 'b': o.bflag = 1; break;
                case 'd': o.dflag = 1; break;
                case 'r': o.rflag = 1; break;
                case 'u': o.uflag = 1; break;
                case 'f': o.fflag = 1; break;
                case 'c': o.cflag = 1; break;
                case 'C': o.cflag = 1; o.Cflag = 1; o.check_quiet = 1; break;
                case 'i': o.iflag = 1; break;
                case 's': o.sflag = 1; break;
                case 'z': o.zflag = 1; break;
                case 't':
                    /* Field separator: glued (-t:) or as the next argument (-t :). */
                    if (p[1]) {
                        o.tsep = p[1];
                        o.has_tsep = 1;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("-t needs SEP"); return EX_USAGE; }
                        list = list->next;
                        if (list->word->word[0] == '\0') {
                            builtin_error ("-t needs a non-empty SEP");
                            return EX_USAGE;
                        }
                        o.tsep = list->word->word[0];
                        o.has_tsep = 1;
                    }
                    break;
                case 'k':
                    /* Key definition: glued (-k2) or as the next argument (-k 2). */
                    if (p[1]) {
                        if (bs_add_keydef (&o, p + 1) < 0)
                            return EX_USAGE;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("-k needs FIELD"); return EX_USAGE; }
                        list = list->next;
                        if (bs_add_keydef (&o, list->word->word) < 0)
                            return EX_USAGE;
                    }
                    break;
                case 'o':
                    if (p[1]) {
                        output_file = p + 1;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("-o needs FILE"); return EX_USAGE; }
                        list = list->next;
                        output_file = list->word->word;
                    }
                    break;
                default:  builtin_error ("unknown flag: -%c", *p); builtin_usage (); return EX_USAGE;
            }
        }
        list = list->next;
    }

    /* Read input lines. */
    bs_line *lines = NULL;
    size_t n = 0, cap = 0;
    char *line = NULL; size_t lcap = 0; ssize_t rd;

    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;
    bs_run *runs = calloc ((size_t) (n_files > 0 ? n_files : 1), sizeof *runs);
    size_t nruns = 0;
    if (!runs)
        return EXECUTION_FAILURE;
    int bs_rc = EXECUTION_SUCCESS;

    clearerr (stdin);

    int record_delim = o.zflag ? '\0' : '\n';

    if (n_files == 0) {
        size_t start = n;
        while ((rd = getdelim (&line, &lcap, record_delim, stdin)) != -1) {
            if (bs_add_line (&lines, &n, &cap, line, (size_t) rd, record_delim) < 0) {
                free (line);
                free (runs);
                bs_free_lines (lines, n);
                return EXECUTION_FAILURE;
            }
        }
        runs[nruns++] = (bs_run) { start, n, start, "-" };
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = stdin;
            size_t start = n;
            if (strcmp (p->word->word, "-") != 0)
                f = fopen (p->word->word, "r");
            else
                clearerr (stdin);
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                bs_rc = EXECUTION_FAILURE;
                continue;
            }
            while ((rd = getdelim (&line, &lcap, record_delim, f)) != -1) {
                if (bs_add_line (&lines, &n, &cap, line, (size_t) rd, record_delim) < 0) {
                    free (line);
                    if (f != stdin) fclose (f);
                    free (runs);
                    bs_free_lines (lines, n);
                    return EXECUTION_FAILURE;
                }
            }
            if (f != stdin)
                fclose (f);
            runs[nruns++] = (bs_run) { start, n, start, p->word->word };
        }
    }
    free (line);

    bs_cmp_opts = &o;

    if (o.Rflag) {
        if (bs_random_seed (random_source) < 0) {
            bs_free_lines (lines, n);
            free (runs);
            return EXECUTION_FAILURE;
        }
        for (size_t i = 0; i < n; i++) {
            int found = 0;
            for (size_t j = 0; j < i; j++) {
                if (bs_compare_line_keys (&lines[i], &lines[j], &o) == 0) {
                    lines[i].random_rank = lines[j].random_rank;
                    found = 1;
                    break;
                }
            }
            if (!found)
                lines[i].random_rank = bs_random_next ();
        }
    }

    if (o.cflag) {
        /* -c / -C: check if input is already sorted.
         * -C (Cflag) is silent; -c emits a GNU-style disorder diagnostic
         *   "bashsort: <file>:<line>: disorder: <line-content>"
         * where <file> is the source file name ("-" for stdin), <line> is
         * the 1-based line number within that file, and <line-content> is
         * the offending record with its trailing record delimiter stripped. */
        for (size_t i = 1; i < n; i++) {
            if (bs_compare_line (&lines[i - 1], &lines[i], &o, 1) > 0) {
                if (!o.check_quiet) {
                    const char *fname = "-";
                    size_t rel_line = i + 1;
                    for (size_t r = 0; r < nruns; r++) {
                        if (i >= runs[r].start && i < runs[r].end) {
                            fname = runs[r].name ? runs[r].name : "-";
                            rel_line = (i - runs[r].start) + 1;
                            break;
                        }
                    }
                    /* Strip the trailing record delimiter from the content. */
                    size_t clen = lines[i].len;
                    if (clen > 0 && lines[i].buf[clen - 1] == record_delim)
                        clen--;
                    fprintf (stderr, "bashsort: %s:%zu: disorder: ", fname, rel_line);
                    fwrite (lines[i].buf, 1, clen, stderr);
                    fputc ('\n', stderr);
                }
                bs_free_lines (lines, n);
                free (runs);
                return EXECUTION_FAILURE;
            }
        }
        bs_free_lines (lines, n);
        free (runs);
        return bs_rc;
    }

    if (!o.mergeflag)
        qsort (lines, n, sizeof *lines, bs_compare);

    FILE *out = stdout;
    if (output_file && strcmp (output_file, "-") != 0) {
        out = fopen (output_file, "w");
        if (!out) {
            builtin_error ("%s: %s", output_file, strerror (errno));
            free (runs);
            bs_free_lines (lines, n);
            return EXECUTION_FAILURE;
        }
    } else {
        clearerr (stdout);
    }

    if (o.mergeflag)
        bs_emit_merged (out, lines, runs, nruns, &o);
    else
        bs_emit_lines (out, lines, n, &o);
    free (runs);
    bs_free_lines (lines, n);
    if (out != stdout && fclose (out) != 0) {
        builtin_error ("%s: %s", output_file, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return bs_rc;
}

char *sort_doc[] = {
    "Sort lines in FILEs (or stdin).",
    "",
    "    bashsort [-zRVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [FILE...]",
    "",
    "    -n   numeric compare (strtod-driven)",
    "    -g   general numeric compare (strtold; supports +, exponent, inf, NaN)",
    "    -h   human numeric compare (SI suffix order)",
    "    -V   version/natural compare",
    "    -R   random compare (shuffle, grouping equal keys)",
    "         --random-source=FILE  seed random ordering from FILE bytes",
    "    -M   month compare (Jan..Dec; unknown names sort before Jan)",
    "    -m, --merge  merge already-sorted inputs",
    "    -b   ignore leading blanks in comparison keys",
    "    -d   dictionary order: compare only blanks and alphanumeric bytes",
    "    -r   reverse",
    "    -u   unique (post-sort, key-aware)",
    "    -f   case-insensitive",
    "    -c   check-only: exit 0 if sorted, 1 otherwise (GNU-style disorder diagnostic)",
    "    -C   check-only, silent: exit 0 if sorted, 1 otherwise (no diagnostic)",
    "    -i   ignore non-printable characters in keys",
    "    -s   stable: preserve input order for equal keys",
    "    -z, --zero-terminated  use NUL as the record delimiter",
    "    -t SEP    field separator (default whitespace runs)",
    "    -k KEYDEF  1-based key; simple FIELD[.C][,FIELD[.C]][bdfirnghVM] subset",
    "    -o FILE   write result to FILE",
    (char *)NULL
};

struct builtin bashsort_struct = {
    "bashsort",
    sort_builtin,
    BUILTIN_ENABLED,
    sort_doc,
    "bashsort [-RVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [FILE...]",
    0
};
