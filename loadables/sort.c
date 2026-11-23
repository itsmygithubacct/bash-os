/* bashsort.c — POSIX sort(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. Reads every input whole, computes
 * each line's comparison keys once (the -k/-t spans and, for -n, the parsed
 * number), sorts a compact array of key prefixes with a flag-driven
 * comparator, emits.
 *
 *   bashsort [-zRVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [FILE...]
 *
 *   -n   numeric compare, GNU sort's rules: leading blanks, an optional '-',
 *        digits and one decimal point; anything else compares as zero
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
 *   -k KEYDEF which field to compare: FIELD[.CHAR][OPTS][,FIELD[.CHAR][OPTS]],
 *            read as GNU sort reads it (a key with letters of its own takes
 *            no global ordering option; one without takes them all)
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
#include <pthread.h>
#include <signal.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>
#include <inttypes.h>

#include "loadables.h"

typedef struct {
    int field;            /* 1-based start field; 0 = the whole line */
    int start_char;       /* 1-based; 0 = field start */
    int end_field;        /* 1-based; 0 = the end of the line */
    int end_char;         /* 1-based; 0 = the end of the end field */
    int numeric;
    int general_numeric;
    int human_numeric;
    int version;
    int month;
    int reverse;
    int skip_start_blanks;
    int skip_end_blanks;
    int dictionary_order;
    int ignore_case;
    int ignore_nonprinting;
    int has_ordering;     /* a letter was given on the key itself */
} bs_keydef;

typedef struct {
    int nflag, gflag, hflag, vflag, Rflag, bflag, dflag, rflag, uflag, fflag, cflag, Cflag, iflag, sflag, mflag, mergeflag, zflag;
    int check_quiet;
    char tsep;
    int  has_tsep;
    bs_keydef keys[8];
    int nkeys;            /* after bs_resolve_keys: at least 1 */
} bs_opts;

/* One comparison key of a line, computed once before sorting: the key's
   text within the line and, for a numeric key, its decomposition. */
typedef struct {
    const char *s;      /* key text (no copy, no length limit) */
    size_t len;
    const char *ip;     /* -n: integer digits, leading zeros stripped */
    size_t ilen;
    const char *fp;     /* -n: fraction digits, trailing zeros stripped */
    size_t flen;
    int sign;           /* -n: -1, 0 or 1; 0 for zero and for a non-number */
} bs_keyval;

typedef struct {
    char *buf;          /* the record, ending in the record delimiter */
    size_t len;
    size_t index;       /* input order */
    uint64_t random_rank;
    bs_keyval *keys;    /* one per key */
} bs_line;

/* What the sort permutes: an order-preserving prefix of the first key and
   the line. 16 bytes, so most comparisons never leave this array. */
typedef struct {
    uint64_t pre;
    bs_line *ln;
} bs_elem;

typedef struct {
    size_t start;
    size_t end;
    size_t pos;
    const char *name;   /* source file name for diagnostics; "-" for stdin */
} bs_run;

/* GNU sort's exit status for trouble; 1 is reserved for -c disorder. */
#define BS_TROUBLE 2

static const bs_opts *bs_cmp_opts;

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

/* -k FIELD[.CHAR][OPTS][,FIELD[.CHAR][OPTS]], as GNU sort reads it. A
   letter before the comma orders the key, and a b there skips the blanks at
   its start; a letter after the comma orders the key too, and a b there
   skips the blanks at its end. Fields and start chars count from 1; an end
   char of 0 means the end of that field. */
static int
bs_parse_count (const char **sp, unsigned long *out)
{
    const char *s = *sp;
    char *end = NULL;

    if (!isdigit ((unsigned char) *s))
        return -1;
    errno = 0;
    *out = strtoul (s, &end, 10);
    if (errno || *out > 2147483647UL)
        return -1;
    *sp = end;
    return 0;
}

static int
bs_parse_letters (const char **sp, bs_keydef *key, int at_end)
{
    const char *s = *sp;

    for (; *s && *s != ','; s++) {
        switch (*s) {
            case 'b': if (at_end) key->skip_end_blanks = 1; else key->skip_start_blanks = 1; break;
            case 'd': key->dictionary_order = 1; break;
            case 'f': key->ignore_case = 1; break;
            case 'g': key->general_numeric = 1; break;
            case 'h': key->human_numeric = 1; break;
            case 'i': key->ignore_nonprinting = 1; break;
            case 'M': key->month = 1; break;
            case 'n': key->numeric = 1; break;
            case 'r': key->reverse = 1; break;
            case 'V': key->version = 1; break;
            default: return -1;
        }
        key->has_ordering = 1;
    }
    *sp = s;
    return 0;
}

static int
bs_parse_keydef (const char *s, bs_keydef *key)
{
    unsigned long v;

    memset (key, 0, sizeof *key);
    if (!s || bs_parse_count (&s, &v) < 0 || v == 0)
        return -1;
    key->field = (int) v;
    if (*s == '.') {
        s++;
        if (bs_parse_count (&s, &v) < 0 || v == 0)
            return -1;
        key->start_char = (int) v;
    }
    if (bs_parse_letters (&s, key, 0) < 0)
        return -1;
    if (*s == ',') {
        s++;
        if (bs_parse_count (&s, &v) < 0 || v == 0)
            return -1;
        key->end_field = (int) v;
        if (*s == '.') {
            s++;
            if (bs_parse_count (&s, &v) < 0)
                return -1;
            key->end_char = (int) v;
        }
        if (bs_parse_letters (&s, key, 1) < 0)
            return -1;
    }
    return *s ? -1 : 0;
}


/* In a version's nonnumeric segment, tilde precedes even end-of-string,
   letters precede punctuation, and a digit starts the numeric segment. */
static int
bs_version_order (unsigned char c)
{
    if (c == '~') return -1;
    if (!c || (c >= '0' && c <= '9')) return 0;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return c;
    return c + 256;
}

static int
bs_version_part (const char *a, size_t na, const char *b, size_t nb)
{
    const unsigned char *pa = (const unsigned char *) a, *ea = pa + na;
    const unsigned char *pb = (const unsigned char *) b, *eb = pb + nb;
    while (pa < ea || pb < eb) {
        while ((pa < ea && !isdigit (*pa)) || (pb < eb && !isdigit (*pb))) {
            int order_a = bs_version_order (pa < ea ? *pa : 0);
            int order_b = bs_version_order (pb < eb ? *pb : 0);
            if (order_a != order_b) return order_a < order_b ? -1 : 1;
            if (pa < ea) pa++;
            if (pb < eb) pb++;
        }
        /* Zero-padded numeric keys are equal; -s/-u retain input order. */
        while (pa < ea && *pa == '0') pa++;
        while (pb < eb && *pb == '0') pb++;
        const unsigned char *da = pa, *db = pb;
        while (da < ea && isdigit (*da)) da++;
        while (db < eb && isdigit (*db)) db++;
        size_t la = (size_t) (da - pa), lb = (size_t) (db - pb);
        if (la != lb) return la < lb ? -1 : 1;
        for (size_t i = 0; i < la; i++)
            if (pa[i] != pb[i]) return pa[i] < pb[i] ? -1 : 1;
        pa = da;
        pb = db;
    }
    return 0;
}

static int
bs_version_letter (unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~';
}

/* Compare the name before trailing .letter[letter-or-digit]* suffixes
   first, then the full name. This keeps archive extensions after releases
   but before a later version, including chains such as .tar.gz. */
static size_t
bs_version_prefix (const char *s, size_t n)
{
    size_t end = n;
    while (end) {
        size_t i = end;
        while (i && (bs_version_letter ((unsigned char) s[i-1]) ||
                     (s[i-1] >= '0' && s[i-1] <= '9'))) i--;
        if (i <= 1 || i == end || s[i-1] != '.' ||
            !bs_version_letter ((unsigned char) s[i])) break;
        end = i - 1;
    }
    return end;
}

static int
bs_version_class (const char *s)
{
    if (!*s) return 0;
    if (!strcmp (s, ".")) return 1;
    if (!strcmp (s, "..")) return 2;
    return *s == '.' ? 3 : 4;
}

static int
bs_version_cmp (const char *a, const char *b)
{
    int ca = bs_version_class (a), cb = bs_version_class (b);
    if (ca != cb) return ca < cb ? -1 : 1;
    size_t na = strlen (a), nb = strlen (b);
    size_t pa = bs_version_prefix (a, na), pb = bs_version_prefix (b, nb);
    int cmp = bs_version_part (a, pa, b, pb);
    if (cmp || (pa == na && pb == nb)) return cmp;
    return bs_version_part (a, na, b, nb);
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
    o->nkeys++;
    return 0;
}

/* GNU sort's inheritance, applied once the options are all read: a key with
   no ordering letter of its own takes every global one (-b -d -f -i -n -g
   -h -M -V -r); a key with any letter takes none, not even -r, which then
   only reverses the last-resort comparison. With no -k at all, the whole
   line is the one key. */
static void
bs_resolve_keys (bs_opts *o)
{
    if (o->nkeys == 0) {
        memset (&o->keys[0], 0, sizeof o->keys[0]);
        o->nkeys = 1;
    }
    for (int i = 0; i < o->nkeys; i++) {
        bs_keydef *k = &o->keys[i];
        if (k->has_ordering)
            continue;
        k->skip_start_blanks = k->skip_end_blanks = o->bflag;
        k->dictionary_order = o->dflag;
        k->ignore_case = o->fflag;
        k->ignore_nonprinting = o->iflag;
        k->numeric = o->nflag;
        k->general_numeric = o->gflag;
        k->human_numeric = o->hflag;
        k->month = o->mflag;
        k->version = o->vflag;
        k->reverse = o->rflag;
    }
}

/* --- input -------------------------------------------------------------
   Each file is read whole into one buffer and split into records in place.
   A record is a span of its buffer ending in the record delimiter; a final
   record that lacks one gets it appended (GNU sort does the same), which is
   why every buffer keeps a spare byte. Nothing is copied per line. */
typedef struct {
    bs_line *lines;
    size_t n, cap;
    char **bufs;            /* one per input, freed at the end */
    size_t nbufs, bufcap;
} bs_input;

/* Read F to end of file: 0 with the data, 1 on a read error (errno set,
   the data read so far is still returned), -1 out of memory. The buffer
   has at least one byte of room past LEN. */
static int
bs_read_stream (FILE *f, char **bufp, size_t *lenp)
{
    size_t cap = 65536, len = 0;
    struct stat st;
    char *buf;

    if (fstat (fileno (f), &st) == 0 && S_ISREG (st.st_mode) && st.st_size > 0
        && (uintmax_t) st.st_size < (size_t) -2)
        cap = (size_t) st.st_size + 2;
    buf = malloc (cap);
    if (!buf)
        return -1;
    for (;;) {
        size_t want = cap - len - 1, got;
        if (want == 0) {
            char *nb;
            if (cap > ((size_t) -1) / 2) {
                free (buf);
                return -1;
            }
            nb = realloc (buf, cap * 2);
            if (!nb) {
                free (buf);
                return -1;
            }
            buf = nb;
            cap *= 2;
            continue;
        }
        got = fread (buf + len, 1, want, f);
        len += got;
        if (got < want) {
            *bufp = buf;
            *lenp = len;
            return ferror (f) ? 1 : 0;
        }
    }
}

/* Take ownership of BUF (LEN bytes, room for one more) and split it. */
static int
bs_add_input (bs_input *in, char *buf, size_t len, int delim)
{
    char *p, *e;

    if (in->nbufs >= in->bufcap) {
        size_t ncap = in->bufcap ? in->bufcap * 2 : 8;
        char **nb = realloc (in->bufs, ncap * sizeof *nb);
        if (!nb) {
            free (buf);
            return -1;
        }
        in->bufs = nb;
        in->bufcap = ncap;
    }
    in->bufs[in->nbufs++] = buf;
    if (len == 0)
        return 0;
    if ((unsigned char) buf[len - 1] != (unsigned char) delim)
        buf[len++] = (char) delim;
    for (p = buf, e = buf + len; p < e; ) {
        char *q = memchr (p, delim, (size_t) (e - p));
        bs_line *ln;
        if (!q)
            q = e - 1;
        if (in->n >= in->cap) {
            size_t ncap = in->cap ? in->cap * 2 : 1024;
            bs_line *nl = realloc (in->lines, ncap * sizeof *nl);
            if (!nl)
                return -1;
            in->lines = nl;
            in->cap = ncap;
        }
        ln = &in->lines[in->n];
        ln->buf = p;
        ln->len = (size_t) (q + 1 - p);
        ln->index = in->n;
        ln->random_rank = 0;
        ln->keys = NULL;
        in->n++;
        p = q + 1;
    }
    return 0;
}

/* Read one input into IN: 0, or 1 after reporting a read error (what was
   read is kept), or -1 after reporting exhausted memory. */
static int
bs_read_input (bs_input *in, FILE *f, const char *name, int delim)
{
    char *buf = NULL;
    size_t len = 0;
    int r = bs_read_stream (f, &buf, &len);

    if (r < 0) {
        builtin_error ("memory exhausted");
        return -1;
    }
    if (r > 0)
        builtin_error ("%s: read error: %s", name, strerror (errno));
    if (bs_add_input (in, buf, len, delim) < 0) {
        builtin_error ("memory exhausted");
        return -1;
    }
    return r;
}

static void
bs_free_input (bs_input *in)
{
    for (size_t i = 0; i < in->nbufs; i++)
        free (in->bufs[i]);
    free (in->bufs);
    free (in->lines);
    in->lines = NULL;
    in->bufs = NULL;
    in->n = in->cap = in->nbufs = in->bufcap = 0;
}

/* --- keys --------------------------------------------------------------
   GNU sort's tables: a blank is what isblank() says plus newline (a record
   under -z may hold one); the decimal point is the locale's when it is a
   single byte, else '.'. Thousands grouping is not recognised, as in the C
   locale. */
static unsigned char bs_blank[256];
static int bs_decimal_point = '.';

static void
bs_init_tables (void)
{
    struct lconv *lc = localeconv ();

    for (int c = 0; c < 256; c++)
        bs_blank[c] = (c == '\n') || isblank (c);
    bs_decimal_point = (lc && lc->decimal_point[0] && !lc->decimal_point[1])
                       ? (unsigned char) lc->decimal_point[0] : '.';
}

#define BS_BLANK(c) (bs_blank[(unsigned char) (c)])
#define BS_ISDIGIT(c) ((unsigned char) ((c) - '0') <= 9)

/* Where a key starts in [line, lim): GNU sort's begfield. A field's leading
   blanks belong to it unless the key skips them; a start char counts from
   the field's start, after that skip. */
static const char *
bs_begfield (const char *line, const char *lim, const bs_opts *o, const bs_keydef *k)
{
    const char *ptr = line;
    int sword = k->field - 1;
    int schar = k->start_char > 0 ? k->start_char - 1 : 0;

    if (o->has_tsep) {
        while (ptr < lim && sword-- > 0) {
            while (ptr < lim && *ptr != o->tsep) ptr++;
            if (ptr < lim) ptr++;
        }
    } else {
        while (ptr < lim && sword-- > 0) {
            while (ptr < lim && BS_BLANK (*ptr)) ptr++;
            while (ptr < lim && !BS_BLANK (*ptr)) ptr++;
        }
    }
    if (k->skip_start_blanks)
        while (ptr < lim && BS_BLANK (*ptr)) ptr++;
    return (lim - ptr < schar) ? lim : ptr + schar;
}

/* Where a key ends: GNU sort's limfield. ",M" is the end of field M's text;
   ",M.C" is C chars into field M (after its blanks, if the key skips them). */
static const char *
bs_limfield (const char *line, const char *lim, const bs_opts *o, const bs_keydef *k)
{
    const char *ptr = line;
    int eword = k->end_field - 1;
    int echar = k->end_char;

    if (echar == 0)
        eword++;                    /* the whole of the end field */
    if (o->has_tsep) {
        while (ptr < lim && eword-- > 0) {
            while (ptr < lim && *ptr != o->tsep) ptr++;
            if (ptr < lim && (eword || echar)) ptr++;
        }
    } else {
        while (ptr < lim && eword-- > 0) {
            while (ptr < lim && BS_BLANK (*ptr)) ptr++;
            while (ptr < lim && !BS_BLANK (*ptr)) ptr++;
        }
    }
    if (echar != 0) {
        if (k->skip_end_blanks)
            while (ptr < lim && BS_BLANK (*ptr)) ptr++;
        ptr = (lim - ptr < echar) ? lim : ptr + echar;
    }
    return ptr;
}

/* The text of one key of a line, as a span [*sp, *sp + *lp) inside the
   line, which runs from LINE for LINE_LEN bytes (the record delimiter
   excluded). No copy, no length limit. */
static void
bs_key_span (const char *line, size_t line_len, const bs_opts *o, const bs_keydef *k, const char **sp, size_t *lp)
{
    const char *lim = line + line_len, *beg, *end;

    if (k->field <= 0) {
        beg = line;
        if (k->skip_start_blanks)
            while (beg < lim && BS_BLANK (*beg)) beg++;
    } else
        beg = bs_begfield (line, lim, o, k);
    end = k->end_field <= 0 ? lim : bs_limfield (line, lim, o, k);
    if (end < beg)
        end = beg;
    *sp = beg;
    *lp = (size_t) (end - beg);
}

/* --- numeric keys, GNU sort's -n --------------------------------------
   GNU compares -n keys as strings of digits, never as machine numbers: skip
   leading blanks, an optional '-', leading zeros; then integer digits, one
   decimal point, fraction digits. Anything else (a '+', 'e', "0x", "inf",
   letters) ends the number, and a key with no digits at all is zero -- so
   "abc", "", "-", "+5" and "-0" all compare equal to "0". Precision is
   unbounded: 12345678901234567890 and ...891 are different. Each line's key
   is decomposed once here; a comparison is then a sign test, a length test
   and a memcmp. */
static void
bs_numeric_parse (bs_keyval *k)
{
    const char *p = k->s, *e = k->s + k->len;
    int neg = 0;

    while (p < e && BS_BLANK (*p))
        p++;
    if (p < e && *p == '-') {
        neg = 1;
        p++;
    }
    while (p < e && *p == '0')
        p++;
    k->ip = p;
    while (p < e && BS_ISDIGIT (*p))
        p++;
    k->ilen = (size_t) (p - k->ip);
    k->fp = p;
    k->flen = 0;
    if (p < e && (unsigned char) *p == bs_decimal_point) {
        const char *f = ++p;
        while (p < e && BS_ISDIGIT (*p))
            p++;
        while (p > f && p[-1] == '0')
            p--;
        k->fp = f;
        k->flen = (size_t) (p - f);
    }
    k->sign = (k->ilen || k->flen) ? (neg ? -1 : 1) : 0;
}

static int
bs_numeric_cmp (const bs_keyval *a, const bs_keyval *b)
{
    int c;

    if (a->sign != b->sign)
        return (a->sign < b->sign) ? -1 : 1;
    if (a->sign == 0)
        return 0;
    if (a->ilen != b->ilen)
        c = (a->ilen < b->ilen) ? -1 : 1;
    else if ((c = a->ilen ? memcmp (a->ip, b->ip, a->ilen) : 0) == 0) {
        size_t m = a->flen < b->flen ? a->flen : b->flen;
        c = m ? memcmp (a->fp, b->fp, m) : 0;
        if (c == 0)
            c = (a->flen > b->flen) - (a->flen < b->flen);
    }
    c = (c > 0) - (c < 0);
    return a->sign < 0 ? -c : c;
}

/* --- text keys ----------------------------------------------------------- */
static int
bs_dictionary_byte (unsigned char ch)
{
    return isalnum (ch) || ch == ' ' || ch == '\t';
}

static int
bs_cmp_bytes (const char *a, size_t la, const char *b, size_t lb, int icase, int ignore_nonprint, int dictionary_order)
{
    size_t ia = 0, ib = 0;

    if (!icase && !ignore_nonprint && !dictionary_order) {
        size_t m = la < lb ? la : lb;
        int c = m ? memcmp (a, b, m) : 0;
        if (c)
            return c;
        return (la > lb) - (la < lb);
    }

    while (ia < la || ib < lb) {
        while (ignore_nonprint && ia < la && !isprint ((unsigned char) a[ia]))
            ia++;
        while (ignore_nonprint && ib < lb && !isprint ((unsigned char) b[ib]))
            ib++;
        while (dictionary_order && ia < la && !bs_dictionary_byte ((unsigned char) a[ia]))
            ia++;
        while (dictionary_order && ib < lb && !bs_dictionary_byte ((unsigned char) b[ib]))
            ib++;
        if (ia >= la || ib >= lb)
            break;
        int ca = (unsigned char) a[ia];
        int cb = (unsigned char) b[ib];
        if (icase) {
            /* GNU -f folds lower case to upper case, so bytes between 'Z'
               and 'a' ('[', '_', ...) sort after the letters. */
            ca = toupper (ca);
            cb = toupper (cb);
        }
        if (ca != cb)
            return ca - cb;
        ia++;
        ib++;
    }
    if (ia >= la && ib >= lb)
        return 0;
    if (ia >= la)
        return -1;
    return 1;
}

/* How a key compares, in GNU sort's precedence. */
enum { BS_TEXT, BS_NUMERIC, BS_GENERAL, BS_HUMAN, BS_MONTH, BS_VERSION };

static int
bs_key_mode (const bs_keydef *k)
{
    if (k->numeric) return BS_NUMERIC;
    if (k->general_numeric) return BS_GENERAL;
    if (k->human_numeric) return BS_HUMAN;
    if (k->month) return BS_MONTH;
    if (k->version) return BS_VERSION;
    return BS_TEXT;
}

/* A 64-bit prefix of a key that orders like the key: unequal prefixes give
   the key order, equal ones say nothing. For -n: 2^63 for zero, above it
   for positive and below for negative by a code of the digit count (13
   bits) and the first 14 digits, integer then fraction, right-padded with
   zeros; so two 14-digit-or-shorter numbers are ordered by the prefix alone.
   For text: the first 8 compared bytes, big-endian, zero-padded. */
static uint64_t
bs_prefix (const bs_keyval *kv, const bs_keydef *k)
{
    int mode = bs_key_mode (k);

    if (mode == BS_NUMERIC) {
        uint64_t half = (uint64_t) 1 << 63, d = 0, code;
        size_t nd = 0, i;

        if (kv->sign == 0)
            return half;
        for (i = 0; i < kv->ilen && nd < 14; i++, nd++)
            d = d * 10 + (uint64_t) (kv->ip[i] - '0');
        for (i = 0; i < kv->flen && nd < 14; i++, nd++)
            d = d * 10 + (uint64_t) (kv->fp[i] - '0');
        for (; nd < 14; nd++)
            d *= 10;
        code = ((uint64_t) (kv->ilen < 8191 ? kv->ilen : 8191) << 50) | d;
        return kv->sign > 0 ? half + code : half - code;
    }
    if (mode == BS_TEXT) {
        uint64_t p = 0;
        int nb = 0;

        for (size_t i = 0; i < kv->len && nb < 8; i++) {
            unsigned char c = (unsigned char) kv->s[i];
            if (k->ignore_nonprinting && !isprint (c))
                continue;
            if (k->dictionary_order && !bs_dictionary_byte (c))
                continue;
            if (k->ignore_case)
                c = (unsigned char) toupper (c);
            p = (p << 8) | c;
            nb++;
        }
        return p << (8 * (8 - nb));
    }
    return 0;
}

/* Default lexicographic sort: one whole-line text key, no -k and no
   byte-skipping flags. The key is the record minus its delimiter, so a
   key block is the same bytes as last-resort memcmp. */
static int
bs_plain_text (const bs_opts *o)
{
    const bs_keydef *k;

    if (o->nkeys != 1 || o->Rflag)
        return 0;
    k = &o->keys[0];
    if (k->field > 0 || k->end_field > 0 || k->start_char || k->end_char)
        return 0;
    if (k->skip_start_blanks || k->skip_end_blanks)
        return 0;
    if (k->dictionary_order || k->ignore_case || k->ignore_nonprinting)
        return 0;
    if (k->numeric || k->general_numeric || k->human_numeric || k->month || k->version)
        return 0;
    return 1;
}

static uint64_t
bs_line_text_prefix (const bs_line *ln)
{
    uint64_t p = 0;
    size_t llen = ln->len ? ln->len - 1 : 0;
    size_t n = llen < 8 ? llen : 8;
    size_t i;

    for (i = 0; i < n; i++)
        p = (p << 8) | (unsigned char) ln->buf[i];
    return p << (8 * (8 - (int) n));
}

/* Compute the keys of every line -- one bs_keyval per key, in a single
   block -- and the array the sort permutes: the first key's prefix beside a
   pointer to the line. The caller frees both. Default text sort stores
   only the prefix array. */
static int
bs_prepare_keys (bs_line *lines, size_t n, const bs_opts *o, bs_keyval **blockp, bs_elem **elemsp)
{
    size_t nslots = (size_t) o->nkeys;
    bs_keyval *blk = NULL;
    bs_elem *el = NULL;

    *blockp = NULL;
    *elemsp = NULL;
    if (n == 0)
        return 0;
    el = malloc (n * sizeof *el);
    if (!el)
        return -1;
    if (bs_plain_text (o)) {
        for (size_t i = 0; i < n; i++) {
            lines[i].keys = NULL;
            el[i].pre = bs_line_text_prefix (&lines[i]);
            el[i].ln = &lines[i];
        }
        *elemsp = el;
        return 0;
    }
    if (n > ((size_t) -1) / sizeof *blk / nslots) {
        free (el);
        return -1;
    }
    blk = malloc (n * nslots * sizeof *blk);
    if (!blk) {
        free (el);
        return -1;
    }
    bs_init_tables ();
    for (size_t i = 0; i < n; i++) {
        bs_keyval *kv = blk + i * nslots;
        /* Every stored record ends with the delimiter; keys exclude it. */
        size_t llen = lines[i].len ? lines[i].len - 1 : 0;

        lines[i].keys = kv;
        for (size_t s = 0; s < nslots; s++) {
            bs_key_span (lines[i].buf, llen, o, &o->keys[s], &kv[s].s, &kv[s].len);
            kv[s].ip = kv[s].fp = kv[s].s;
            kv[s].ilen = kv[s].flen = 0;
            kv[s].sign = 0;
            if (o->keys[s].numeric)
                bs_numeric_parse (&kv[s]);
        }
        el[i].pre = bs_prefix (&kv[0], &o->keys[0]);
        el[i].ln = &lines[i];
    }
    *blockp = blk;
    *elemsp = el;
    return 0;
}

/* -M, -V, -h and -g compare NUL-terminated text: a copy of the key, on the
   stack when it fits, on the heap otherwise (*heap, for the caller to free). */
static const char *
bs_key_cstr (const bs_keyval *k, char *scratch, size_t sz, char **heap)
{
    char *d = scratch;

    *heap = NULL;
    if (k->len >= sz) {
        d = malloc (k->len + 1);
        if (!d) {
            scratch[0] = '\0';
            return scratch;
        }
        *heap = d;
    }
    memcpy (d, k->s, k->len);
    d[k->len] = '\0';
    return d;
}

static int
bs_compare_key (const bs_keyval *a, const bs_keyval *b, const bs_keydef *k)
{
    int mode = bs_key_mode (k);
    char sa[256], sb[256], *ha, *hb;
    const char *ax, *bx;
    int cmp;

    if (mode == BS_NUMERIC)
        return bs_numeric_cmp (a, b);
    if (mode == BS_TEXT)
        return bs_cmp_bytes (a->s, a->len, b->s, b->len,
                             k->ignore_case, k->ignore_nonprinting, k->dictionary_order);
    ax = bs_key_cstr (a, sa, sizeof sa, &ha);
    bx = bs_key_cstr (b, sb, sizeof sb, &hb);
    switch (mode) {
        case BS_GENERAL: cmp = bs_general_numcmp (ax, bx); break;
        case BS_HUMAN:   cmp = bs_human_numcmp (ax, bx); break;
        case BS_MONTH:   cmp = bs_month_value (ax) - bs_month_value (bx); break;
        default:         cmp = bs_version_cmp (ax, bx); break;
    }
    free (ha);
    free (hb);
    return cmp;
}

static int bs_last_resort (const bs_line *la, const bs_line *lb, const bs_opts *o);

/* The keys, in order, each with its own -r. What -u calls equal is 0 here.
   A NULL key list is the default whole-line text path: same as last resort. */
static int
bs_compare_keys (const bs_line *la, const bs_line *lb, const bs_opts *o)
{
    if (!la->keys || !lb->keys)
        return bs_last_resort (la, lb, o);
    for (int i = 0; i < o->nkeys; i++) {
        int cmp = bs_compare_key (&la->keys[i], &lb->keys[i], &o->keys[i]);
        if (cmp)
            return o->keys[i].reverse ? -cmp : cmp;
    }
    return 0;
}

static int
bs_index_order (const bs_line *la, const bs_line *lb)
{
    return (la->index > lb->index) - (la->index < lb->index);
}

/* GNU's last resort when the keys are equal: the whole records bytewise,
   delimiter excluded, subject to the global -r. */
static int
bs_last_resort (const bs_line *la, const bs_line *lb, const bs_opts *o)
{
    size_t na = la->len ? la->len - 1 : 0, nb = lb->len ? lb->len - 1 : 0;
    size_t m = na < nb ? na : nb;
    int c = m ? memcmp (la->buf, lb->buf, m) : 0;

    if (c == 0)
        c = (na > nb) - (na < nb);
    c = (c > 0) - (c < 0);
    return o->rflag ? -c : c;
}

/* The whole order: keys; then, for -s and -u, input order (GNU sort skips
   the last resort under -u too, so the line -u keeps of an equal-key run is
   the first one read); else the last resort. */
static int
bs_full_compare (const bs_line *la, const bs_line *lb, const bs_opts *o)
{
    int cmp = bs_compare_keys (la, lb, o);

    if (cmp)
        return cmp;
    if (o->sflag || o->uflag)
        return bs_index_order (la, lb);
    return bs_last_resort (la, lb, o);
}

/* The prefix order is reversed by the first key's -r (under -R, by the
   global -r), as the full comparison would reverse a first-key decision. */
static int bs_pre_reverse;

static int
bs_compare (const void *va, const void *vb)
{
    const bs_elem *ea = (const bs_elem *) va;
    const bs_elem *eb = (const bs_elem *) vb;
    const bs_opts *o = bs_cmp_opts;
    int cmp;

    /* The prefixes are order-preserving: unequal ones settle the first key
       (or the random rank) without touching the lines. */
    if (ea->pre != eb->pre) {
        cmp = (ea->pre < eb->pre) ? -1 : 1;
        return bs_pre_reverse ? -cmp : cmp;
    }
    if (!ea->ln->keys) {
        cmp = bs_last_resort (ea->ln, eb->ln, o);
        if (cmp)
            return cmp;
        if (o->sflag || o->uflag)
            return bs_index_order (ea->ln, eb->ln);
        return 0;
    }
    if (o->Rflag) {
        /* Equal ranks: the same key text, by construction. */
        cmp = bs_compare_keys (ea->ln, eb->ln, o);
        if (cmp)
            return o->rflag ? -cmp : cmp;
        return (o->sflag || o->uflag) ? bs_index_order (ea->ln, eb->ln) : 0;
    }
    return bs_full_compare (ea->ln, eb->ln, o);
}

/* Sort disjoint halves with a shared merge buffer. Each subtree has its
   own worker allowance and writes only its slice of each array. */
typedef struct {
    bs_elem *items, *scratch;
    size_t count;
    unsigned long workers;
} bs_sort_job;

static void *
bs_sort_partition (void *arg)
{
    bs_sort_job *job = arg;
    size_t n = job->count, mid = n / 2;
    if (job->workers > 1 && n >= 8192) {
        unsigned long half = job->workers / 2;
        bs_sort_job left = { job->items, job->scratch, mid, half };
        bs_sort_job right = { job->items + mid, job->scratch + mid,
                              n - mid, job->workers - half };
        pthread_t thread;
        if (pthread_create (&thread, NULL, bs_sort_partition, &left) == 0) {
            bs_sort_partition (&right);
            pthread_join (thread, NULL);
            size_t i = 0, j = mid;
            for (size_t k = 0; k < n; k++) {
                if (j == n || (i < mid && bs_compare (&job->items[i], &job->items[j]) <= 0))
                    job->scratch[k] = job->items[i++];
                else
                    job->scratch[k] = job->items[j++];
            }
            memcpy (job->items, job->scratch, n * sizeof *job->items);
            return NULL;
        }
    }
    qsort (job->items, n, sizeof *job->items, bs_compare);
    return NULL;
}

static void
bs_sort_elements (bs_elem *items, size_t n, unsigned long workers)
{
    if (workers > 1 && n >= 8192) {
        long cpus = sysconf (_SC_NPROCESSORS_ONLN);
        if (cpus > 0 && workers > (unsigned long) cpus)
            workers = cpus;
        bs_elem *scratch = workers > 1 ? malloc (n * sizeof *items) : NULL;
        if (scratch) {
            /* Keep shell signal handlers away from worker stacks and defer
               a nonlocal exit from the builtin until all workers join. */
            sigset_t all, oldmask;
            sigfillset (&all);
            if (pthread_sigmask (SIG_BLOCK, &all, &oldmask) == 0) {
                bs_sort_job job = { items, scratch, n, workers };
                bs_sort_partition (&job);
                free (scratch);
                pthread_sigmask (SIG_SETMASK, &oldmask, NULL);
                return;
            }
            free (scratch);
        }
    }
    qsort (items, n, sizeof *items, bs_compare);
}

/* --- output: one buffer rather than a stdio call per line ----------------- */
typedef struct {
    FILE *f;
    size_t n;
    char buf[32768];
} bs_out;

static void
bs_out_flush (bs_out *ob)
{
    if (ob->n)
        fwrite (ob->buf, 1, ob->n, ob->f);
    ob->n = 0;
}

static void
bs_out_write (bs_out *ob, const char *p, size_t len)
{
    if (len > sizeof ob->buf - ob->n) {
        bs_out_flush (ob);
        if (len >= sizeof ob->buf) {
            fwrite (p, 1, len, ob->f);
            return;
        }
    }
    memcpy (ob->buf + ob->n, p, len);
    ob->n += len;
}

static void
bs_emit_lines (bs_out *ob, const bs_elem *elems, size_t n, const bs_opts *o)
{
    for (size_t i = 0; i < n; i++) {
        const bs_line *ln = elems[i].ln;
        if (o->uflag && i > 0 && bs_compare_keys (elems[i - 1].ln, ln, o) == 0)
            continue;
        bs_out_write (ob, ln->buf, ln->len);
    }
}

static void
bs_emit_merged (bs_out *ob, bs_line *lines, bs_run *runs, size_t nruns, const bs_opts *o)
{
    bs_line *last = NULL;

    for (;;) {
        size_t best = (size_t) -1;
        for (size_t r = 0; r < nruns; r++) {
            if (runs[r].pos >= runs[r].end)
                continue;
            if (best == (size_t) -1
                || bs_full_compare (&lines[runs[r].pos], &lines[runs[best].pos], o) < 0)
                best = r;
        }
        if (best == (size_t) -1)
            break;
        bs_line *cur = &lines[runs[best].pos++];
        if (o->uflag && last && bs_compare_keys (last, cur, o) == 0)
            continue;
        bs_out_write (ob, cur->buf, cur->len);
        last = cur;
    }
}


/* --- external sort: -S SIZE, -T DIR, and inputs larger than memory -------
   GNU sort bounds its main buffer by -S or by the process limits and spills
   sorted runs to temporary files, merging them at the end. Here, when the
   estimated in-memory size of the input exceeds that budget, the input is
   read in blocks; each block is sorted with the ordinary code and written as
   a run to an unlinked temporary file; the runs are then merged as streams.
   Inputs that fit keep the in-memory path. */

typedef struct {
    FILE **f;               /* sorted runs, oldest input first */
    unsigned char *level;   /* how many merges each run has been through */
    size_t n, cap;
} bs_runs;

typedef struct {
    const char *tmpdir;     /* -T, else $TMPDIR, else /tmp */
    size_t limit;           /* estimated bytes the in-memory phase may use */
    int explicit_size;      /* -S was given */
    int delim;              /* record delimiter */
} bs_ext;

/* Bytes of bookkeeping per record beyond its text. */
static size_t
bs_ext_record_overhead (const bs_opts *o)
{
    return sizeof (bs_line) + sizeof (bs_elem) + (size_t) o->nkeys * sizeof (bs_keyval);
}

/* GNU's SIZE: a number with an optional suffix b (bytes), K M G T P E
   (powers of 1024; K is the default), or % of physical memory. */
static int
bs_parse_buffer_size (const char *s, size_t *out)
{
    char *end;
    errno = 0;
    if (!*s || !isdigit ((unsigned char) *s))
        return -1;
    uintmax_t v = strtoumax (s, &end, 10);
    if (errno == ERANGE)
        v = UINTMAX_MAX;
    uintmax_t mult = 1024;
    if (*end) {
        static const char suffixes[] = "KMGTPEZY";
        if (end[1])
            return -1;
        if (*end == 'b')
            mult = 1;
        else if (*end == '%') {
            long pages = sysconf (_SC_PHYS_PAGES), psz = sysconf (_SC_PAGESIZE);
            uintmax_t phys = (pages > 0 && psz > 0) ? (uintmax_t) pages * (uintmax_t) psz : 0;
            if (v > 100)
                return -1;
            *out = (size_t) (phys / 100 * v);
            return 0;
        } else {
            const char *p = strchr (suffixes, toupper ((unsigned char) *end));
            if (!p)
                return -1;
            mult = 1;
            for (const char *q = suffixes; q <= p; q++)
                mult = mult > UINTMAX_MAX / 1024 ? UINTMAX_MAX : mult * 1024;
        }
    }
    uintmax_t bytes = (v != 0 && mult > UINTMAX_MAX / v) ? UINTMAX_MAX : v * mult;
    *out = bytes > SIZE_MAX ? SIZE_MAX : (size_t) bytes;
    return 0;
}

/* Default budget: a third of the tightest address-space/data limit (the
   shell itself and the sort's temporary arrays need the rest), and at most
   half of physical memory. */
static size_t
bs_default_limit (void)
{
    uintmax_t lim = UINTMAX_MAX;
    struct rlimit rl;
    if (getrlimit (RLIMIT_AS, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
        lim = (uintmax_t) rl.rlim_cur / 3;
    if (getrlimit (RLIMIT_DATA, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY
        && (uintmax_t) rl.rlim_cur / 3 < lim)
        lim = (uintmax_t) rl.rlim_cur / 3;
    long pages = sysconf (_SC_PHYS_PAGES), psz = sysconf (_SC_PAGESIZE);
    if (pages > 0 && psz > 0 && (uintmax_t) pages * (uintmax_t) psz / 2 < lim)
        lim = (uintmax_t) pages * (uintmax_t) psz / 2;
    return lim > SIZE_MAX ? SIZE_MAX : (size_t) lim;
}

static FILE *
bs_ext_tempfile (const bs_ext *x)
{
    size_t n = strlen (x->tmpdir) + sizeof "/sortXXXXXX";
    char *path = malloc (n);
    if (!path)
        return NULL;
    snprintf (path, n, "%s/sortXXXXXX", x->tmpdir);
    int fd = mkstemp (path);
    if (fd < 0) {
        builtin_error ("cannot create temporary file in '%s': %s", x->tmpdir, strerror (errno));
        free (path);
        return NULL;
    }
    unlink (path);
    free (path);
    FILE *f = fdopen (fd, "w+");
    if (!f) {
        close (fd);
        builtin_error ("cannot create temporary file in '%s': %s", x->tmpdir, strerror (errno));
    }
    return f;
}

static int bs_ext_merge (FILE **runs, size_t nruns, FILE *out, const bs_opts *o, int delim);

/* A merge reads one record per run at once. Runs are merged in levels as
   they are produced: when the newest BS_EXT_FANIN runs share a level they
   become one run of the next level, so open descriptors stay near
   BS_EXT_FANIN per level and merged groups are always contiguous in input
   order (which -s and -u rely on). */
#define BS_EXT_FANIN 16

/* Merge runs [FROM, R->n) into one new run at LEVEL. */
static int
bs_ext_merge_tail (bs_runs *r, size_t from, unsigned char level, const bs_opts *o,
                   int delim, const bs_ext *x)
{
    FILE *f = bs_ext_tempfile (x);
    if (!f)
        return -1;
    int rc = bs_ext_merge (r->f + from, r->n - from, f, o, delim);
    for (size_t j = from; j < r->n; j++)
        fclose (r->f[j]);
    r->n = from;
    if (rc == 0 && (fflush (f) == EOF || ferror (f))) {
        builtin_error ("write error on temporary file: %s", strerror (errno ? errno : EIO));
        rc = -1;
    }
    if (rc < 0) {
        fclose (f);
        return -1;
    }
    rewind (f);
    r->f[r->n] = f;
    r->level[r->n++] = level;
    return 0;
}

/* Sort the records gathered in IN and write them to a new run file. */
static int
bs_ext_spill (bs_input *in, const bs_opts *o, unsigned long workers, const bs_ext *x,
              bs_runs *r)
{
    bs_keyval *blk = NULL;
    bs_elem *elems = NULL;
    FILE *f;
    int rc = -1;

    if (r->n >= r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 2 * BS_EXT_FANIN;
        FILE **nf = realloc (r->f, ncap * sizeof *nf);
        if (nf)
            r->f = nf;
        unsigned char *nl = nf ? realloc (r->level, ncap) : NULL;
        if (!nf || !nl) {
            builtin_error ("memory exhausted");
            bs_free_input (in);
            return -1;
        }
        r->level = nl;
        r->cap = ncap;
    }
    if (bs_prepare_keys (in->lines, in->n, o, &blk, &elems) < 0) {
        builtin_error ("memory exhausted");
        goto out;
    }
    if (in->n > 1)
        bs_sort_elements (elems, in->n, workers);
    f = bs_ext_tempfile (x);
    if (!f)
        goto out;
    {
        bs_out ob;
        ob.f = f;
        ob.n = 0;
        bs_emit_lines (&ob, elems, in->n, o);
        bs_out_flush (&ob);
    }
    if (fflush (f) == EOF || ferror (f)) {
        builtin_error ("write error on temporary file: %s", strerror (errno ? errno : EIO));
        fclose (f);
        goto out;
    }
    rewind (f);
    r->f[r->n] = f;
    r->level[r->n++] = 0;
    rc = 0;
out:
    free (blk);
    free (elems);
    bs_free_input (in);
    /* Cascade: BS_EXT_FANIN newest runs of one level become one run. */
    while (rc == 0 && r->n >= BS_EXT_FANIN) {
        size_t from = r->n - BS_EXT_FANIN;
        unsigned char lv = r->level[r->n - 1];
        size_t j;
        for (j = from; j < r->n && r->level[j] == lv; j++)
            ;
        if (j < r->n || lv == UCHAR_MAX)
            break;
        rc = bs_ext_merge_tail (r, from, (unsigned char) (lv + 1), o, x->delim, x);
    }
    return rc;
}

/* Read F in blocks into IN, spilling a run whenever the estimate passes the
   budget: 0, 1 after a reported read error, -1 after a fatal error. */
static int
bs_ext_read (FILE *f, const char *name, int delim, bs_input *in, size_t *estp,
             const bs_opts *o, unsigned long workers, const bs_ext *x, bs_runs *r)
{
    size_t block = x->limit / 4;
    size_t per = bs_ext_record_overhead (o);
    char *carry = NULL;
    size_t carry_len = 0;
    int rc = 0;

    if (block < 1024)
        block = 1024;
    if (block > ((size_t) 64 << 20))
        block = (size_t) 64 << 20;
    for (;;) {
        size_t cap = carry_len + block + 2;
        char *buf = malloc (cap);
        if (!buf) {
            free (carry);
            builtin_error ("memory exhausted");
            return -1;
        }
        if (carry_len)
            memcpy (buf, carry, carry_len);
        free (carry);
        carry = NULL;
        size_t len = carry_len;
        carry_len = 0;
        size_t got = fread (buf + len, 1, block, f);
        len += got;
        int at_end = got < block;
        if (at_end && ferror (f)) {
            builtin_error ("%s: read error: %s", name, strerror (errno));
            rc = 1;
        }
        size_t keep = len;
        if (!at_end) {
            char *last = NULL;
            for (size_t i = len; i > 0; i--)
                if ((unsigned char) buf[i - 1] == (unsigned char) delim) {
                    last = buf + i - 1;
                    break;
                }
            keep = last ? (size_t) (last + 1 - buf) : 0;
            carry_len = len - keep;
            if (carry_len) {
                carry = malloc (carry_len);
                if (!carry) {
                    free (buf);
                    builtin_error ("memory exhausted");
                    return -1;
                }
                memcpy (carry, buf + keep, carry_len);
            }
        }
        if (keep == 0 && !at_end) {
            /* One record longer than the block: keep reading. */
            free (buf);
            block = block > SIZE_MAX / 2 ? block : block * 2;
            continue;
        }
        size_t before = in->n;
        if (bs_add_input (in, buf, keep, delim) < 0) {
            free (carry);
            builtin_error ("memory exhausted");
            return -1;
        }
        *estp += keep + (in->n - before) * per;
        if (*estp > x->limit && in->n > 0) {
            if (bs_ext_spill (in, o, workers, x, r) < 0) {
                free (carry);
                return -1;
            }
            *estp = 0;
        }
        if (at_end)
            break;
    }
    free (carry);
    return rc;
}

typedef struct {
    FILE *f;
    char *buf;
    size_t cap;
    bs_line ln;
    bs_keyval kv[8];
    int live;
} bs_ext_cursor;

static int
bs_ext_next (bs_ext_cursor *c, const bs_opts *o, int delim, size_t run)
{
    ssize_t got = getdelim (&c->buf, &c->cap, delim, c->f);
    if (got <= 0) {
        c->live = 0;
        return ferror (c->f) ? -1 : 0;
    }
    c->ln.buf = c->buf;
    c->ln.len = (size_t) got;
    c->ln.index = run;      /* runs are in input order: earliest wins ties */
    c->ln.random_rank = 0;
    if (bs_plain_text (o))
        c->ln.keys = NULL;
    else {
        size_t llen = c->ln.len - 1;
        c->ln.keys = c->kv;
        for (int s = 0; s < o->nkeys; s++) {
            bs_key_span (c->ln.buf, llen, o, &o->keys[s], &c->kv[s].s, &c->kv[s].len);
            c->kv[s].ip = c->kv[s].fp = c->kv[s].s;
            c->kv[s].ilen = c->kv[s].flen = 0;
            c->kv[s].sign = 0;
            if (o->keys[s].numeric)
                bs_numeric_parse (&c->kv[s]);
        }
    }
    c->live = 1;
    return 1;
}

/* Merge the sorted runs into OUT; -u keeps the first of each equal run. */
static int
bs_ext_merge (FILE **runs, size_t nruns, FILE *out, const bs_opts *o, int delim)
{
    bs_ext_cursor *cur = calloc (nruns, sizeof *cur);
    char *last = NULL;
    size_t lastcap = 0;
    bs_line lastln;
    bs_keyval lastkv[8];
    int have_last = 0, rc = 0;
    bs_out ob;

    if (!cur) {
        builtin_error ("memory exhausted");
        return -1;
    }
    ob.f = out;
    ob.n = 0;
    for (size_t r = 0; r < nruns; r++) {
        cur[r].f = runs[r];
        if (bs_ext_next (&cur[r], o, delim, r) < 0)
            rc = -1;
    }
    while (rc == 0) {
        size_t best = (size_t) -1;
        for (size_t r = 0; r < nruns; r++) {
            if (!cur[r].live)
                continue;
            if (best == (size_t) -1 || bs_full_compare (&cur[r].ln, &cur[best].ln, o) < 0)
                best = r;
        }
        if (best == (size_t) -1)
            break;
        bs_line *ln = &cur[best].ln;
        if (!(o->uflag && have_last && bs_compare_keys (&lastln, ln, o) == 0)) {
            bs_out_write (&ob, ln->buf, ln->len);
            if (o->uflag) {
                /* Keep a private copy: the cursor's buffer is reused. */
                if (lastcap < ln->len) {
                    char *nl = realloc (last, ln->len);
                    if (!nl) {
                        builtin_error ("memory exhausted");
                        rc = -1;
                        break;
                    }
                    last = nl;
                    lastcap = ln->len;
                }
                memcpy (last, ln->buf, ln->len);
                lastln = *ln;
                lastln.buf = last;
                if (ln->keys) {
                    for (int s = 0; s < o->nkeys; s++) {
                        lastkv[s] = ln->keys[s];
                        lastkv[s].s = last + (ln->keys[s].s - ln->buf);
                        lastkv[s].ip = last + (ln->keys[s].ip - ln->buf);
                        lastkv[s].fp = last + (ln->keys[s].fp - ln->buf);
                    }
                    lastln.keys = lastkv;
                }
                have_last = 1;
            }
        }
        if (bs_ext_next (&cur[best], o, delim, best) < 0) {
            builtin_error ("read error on temporary file: %s", strerror (errno));
            rc = -1;
        }
    }
    bs_out_flush (&ob);
    for (size_t r = 0; r < nruns; r++)
        free (cur[r].buf);
    free (cur);
    free (last);
    return rc;
}

/* Before the final merge, fold the remaining runs (at most BS_EXT_FANIN - 1
   per level) into at most BS_EXT_FANIN, newest groups first. */
static int
bs_ext_reduce (bs_runs *r, const bs_opts *o, const bs_ext *x)
{
    while (r->n > BS_EXT_FANIN) {
        size_t from = r->n - BS_EXT_FANIN;
        if (bs_ext_merge_tail (r, from, r->level[r->n - 1], o, x->delim, x) < 0)
            return -1;
    }
    return 0;
}

/* The whole external path: 0/1 as the builtin's status, after writing. */
static int
bs_ext_sort (const char **files, size_t n_files, const bs_opts *o, unsigned long workers,
             const bs_ext *x, const char *output_file)
{
    int delim = o->zflag ? '\0' : '\n';
    bs_input in = {0};
    size_t est = 0;
    bs_runs runs = {0};
    int rc = EXECUTION_SUCCESS, fatal = 0;
    size_t nin = n_files ? n_files : 1;

    clearerr (stdin);
    for (size_t i = 0; i < nin && !fatal; i++) {
        const char *name = n_files ? files[i] : "-";
        FILE *f = stdin;
        if (strcmp (name, "-") != 0)
            f = fopen (name, "r");
        else
            clearerr (stdin);
        if (!f) {
            /* GNU: an unreadable input ends the sort before any output. */
            builtin_error ("%s: %s", name, strerror (errno));
            fatal = 1;
            break;
        }
        int r = bs_ext_read (f, name, delim, &in, &est, o, workers, x, &runs);
        if (f != stdin)
            fclose (f);
        if (r < 0)
            fatal = 1;
        else if (r > 0)
            rc = BS_TROUBLE;
    }
    /* Nothing spilled: the input fit after all, so sort it in memory. */
    int in_memory = !fatal && runs.n == 0;
    bs_keyval *blk = NULL;
    bs_elem *elems = NULL;
    if (in_memory) {
        if (bs_prepare_keys (in.lines, in.n, o, &blk, &elems) < 0) {
            builtin_error ("memory exhausted");
            fatal = 1;
        } else if (in.n > 1)
            bs_sort_elements (elems, in.n, workers);
    } else {
        if (!fatal && in.n > 0 && bs_ext_spill (&in, o, workers, x, &runs) < 0)
            fatal = 1;
        bs_free_input (&in);
        if (!fatal && bs_ext_reduce (&runs, o, x) < 0)
            fatal = 1;
    }

    FILE *outf = stdout;
    if (!fatal) {
        /* Like GNU, the output is opened only after every input is read, so
           -o may name an input file. */
        if (output_file && strcmp (output_file, "-") != 0) {
            outf = fopen (output_file, "w");
            if (!outf) {
                builtin_error ("%s: %s", output_file, strerror (errno));
                fatal = 1;
            }
        } else
            clearerr (stdout);
    }
    if (!fatal) {
        if (in_memory) {
            bs_out ob;
            ob.f = outf;
            ob.n = 0;
            bs_emit_lines (&ob, elems, in.n, o);
            bs_out_flush (&ob);
        } else if (bs_ext_merge (runs.f, runs.n, outf, o, delim) < 0)
            fatal = 1;
        if (fflush (outf) == EOF || ferror (outf)) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            rc = BS_TROUBLE;
        }
        if (outf != stdout && fclose (outf) != 0) {
            builtin_error ("%s: %s", output_file, strerror (errno));
            rc = BS_TROUBLE;
        }
    }
    for (size_t r = 0; r < runs.n; r++)
        fclose (runs.f[r]);
    free (runs.f);
    free (runs.level);
    free (blk);
    free (elems);
    bs_free_input (&in);
    return fatal ? BS_TROUBLE : rc;
}

/* Whether the inputs need the external path under budget X. */
static int
bs_ext_needed (const char **files, size_t n_files, const bs_opts *o, const bs_ext *x)
{
    uintmax_t total = 0;
    size_t nin = n_files ? n_files : 1;

    if (x->limit == SIZE_MAX)
        return 0;
    for (size_t i = 0; i < nin; i++) {
        const char *name = n_files ? files[i] : "-";
        struct stat st;
        int ok = strcmp (name, "-") == 0 ? fstat (fileno (stdin), &st) : stat (name, &st);
        if (ok != 0)
            continue;               /* the read reports it */
        if (!S_ISREG (st.st_mode))
            return 1;               /* unknown size: read in blocks */
        total += (uintmax_t) st.st_size;
    }
    /* At least one record per 16 bytes is a conservative overhead guess;
       the block reader measures the real count. */
    uintmax_t est = total + total / 16 * bs_ext_record_overhead (o);
    return est > x->limit;
}

static int
bs_sort (WORD_LIST *list, const char **files)
{
    bs_opts o = {0};
    const char *output_file = NULL;
    const char *random_source = NULL;
    const char *tmpdir = NULL;
    size_t buffer_size = 0;
    int have_buffer_size = 0;
    /* Parse flags. */
    unsigned long workers = 1;
    size_t n_files = 0;
    int operands_only = 0;
    int posix = getenv ("POSIXLY_CORRECT") != NULL;
    while (list) {
        const char *w = list->word->word;
        if (operands_only || w[0] != '-' || !w[1]) {
            files[n_files++] = w;
            if (posix) operands_only = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--")) { operands_only = 1; list = list->next; continue; }
        if (!strcmp (w, "--parallel") || !strncmp (w, "--parallel=", 11)) {
            const char *value;
            if (w[10] == '=') value = w + 11;
            else {
                if (!list->next) { builtin_error ("--parallel needs a count"); return EX_USAGE; }
                list = list->next;
                value = list->word->word;
            }
            const char *digits = value;
            while (isspace ((unsigned char) *digits)) digits++;
            if (*digits == '+') digits++;
            char *end;
            workers = strtoul (digits, &end, 10);
            if (!isdigit ((unsigned char) *digits) || *end) {
                builtin_error ("invalid --parallel argument '%s'", value);
                return EX_USAGE;
            }
            if (!workers) {
                builtin_error ("number in parallel must be nonzero");
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--help")) {
            builtin_help ();
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
        if (!strcmp (w, "--buffer-size") || !strncmp (w, "--buffer-size=", 14)
            || !strcmp (w, "--temporary-directory") || !strncmp (w, "--temporary-directory=", 22)) {
            int is_size = w[2] == 'b';
            const char *eq = strchr (w, '=');
            const char *val;
            if (eq)
                val = eq + 1;
            else {
                if (!list->next) { builtin_error ("%s needs an argument", w); return EX_USAGE; }
                list = list->next;
                val = list->word->word;
            }
            if (is_size) {
                if (bs_parse_buffer_size (val, &buffer_size) < 0) {
                    builtin_error ("invalid --buffer-size argument '%s'", val);
                    return EX_USAGE;
                }
                have_buffer_size = 1;
            } else if (!tmpdir)
                tmpdir = val;
            list = list->next;
            continue;
        }
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
                case 'S':
                case 'T': {
                    const char *val;
                    char opt = *p;
                    if (p[1]) {
                        val = p + 1;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("-%c needs an argument", opt); return EX_USAGE; }
                        list = list->next;
                        val = list->word->word;
                    }
                    if (opt == 'S') {
                        if (bs_parse_buffer_size (val, &buffer_size) < 0) {
                            builtin_error ("invalid -S argument '%s'", val);
                            return EX_USAGE;
                        }
                        have_buffer_size = 1;
                    } else if (!tmpdir)
                        tmpdir = val;
                    break;
                }
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

    bs_resolve_keys (&o);

    /* Larger than the budget (or -S): sort in runs through temporary files. */
    if (!o.cflag && !o.mergeflag && !o.Rflag) {
        bs_ext x;
        x.tmpdir = tmpdir;
        if (!x.tmpdir || !*x.tmpdir)
            x.tmpdir = getenv ("TMPDIR");
        if (!x.tmpdir || !*x.tmpdir)
            x.tmpdir = "/tmp";
        x.explicit_size = have_buffer_size;
        x.delim = o.zflag ? '\0' : '\n';
        x.limit = have_buffer_size ? buffer_size : bs_default_limit ();
        if (x.limit < 4096)
            x.limit = 4096;
        if (have_buffer_size || bs_ext_needed (files, n_files, &o, &x)) {
            bs_cmp_opts = &o;
            bs_pre_reverse = o.keys[0].reverse;
            return bs_ext_sort (files, n_files, &o, workers, &x, output_file);
        }
    }

    /* Read every input whole; a record is a span of that buffer. */
    bs_input in = {0};
    bs_run *runs = calloc ((size_t) (n_files > 0 ? n_files : 1), sizeof *runs);
    size_t nruns = 0;
    if (!runs)
        return BS_TROUBLE;
    int bs_rc = EXECUTION_SUCCESS;
    int record_delim = o.zflag ? '\0' : '\n';

    clearerr (stdin);

    if (n_files == 0) {
        size_t start = in.n;
        int r = bs_read_input (&in, stdin, "-", record_delim);
        if (r < 0) {
            free (runs);
            bs_free_input (&in);
            return BS_TROUBLE;
        }
        if (r > 0)
            bs_rc = BS_TROUBLE;
        runs[nruns++] = (bs_run) { start, in.n, start, "-" };
    } else {
        for (size_t i = 0; i < n_files; i++) {
            FILE *f = stdin;
            size_t start = in.n;
            int r;
            if (strcmp (files[i], "-") != 0)
                f = fopen (files[i], "r");
            else
                clearerr (stdin);
            if (!f) {
                /* GNU: an unreadable input ends the sort before any output. */
                builtin_error ("%s: %s", files[i], strerror (errno));
                free (runs);
                bs_free_input (&in);
                return BS_TROUBLE;
            }
            r = bs_read_input (&in, f, files[i], record_delim);
            if (f != stdin)
                fclose (f);
            if (r < 0) {
                free (runs);
                bs_free_input (&in);
                return BS_TROUBLE;
            }
            if (r > 0)
                bs_rc = BS_TROUBLE;
            runs[nruns++] = (bs_run) { start, in.n, start, files[i] };
        }
    }
    bs_line *lines = in.lines;
    size_t n = in.n;
    int rc = bs_rc;

    /* Every comparison key, once per line, and the array the sort moves:
       a prefix of the first key beside a pointer to the line. */
    bs_keyval *keyblk = NULL;
    bs_elem *elems = NULL;
    if (bs_prepare_keys (lines, n, &o, &keyblk, &elems) < 0) {
        builtin_error ("memory exhausted");
        rc = BS_TROUBLE;
        goto out;
    }
    bs_cmp_opts = &o;
    bs_pre_reverse = o.keys[0].reverse;

    if (o.Rflag) {
        if (bs_random_seed (random_source) < 0) {
            rc = BS_TROUBLE;
            goto out;
        }
        for (size_t i = 0; i < n; i++) {
            int found = 0;
            for (size_t j = 0; j < i; j++) {
                if (bs_compare_keys (&lines[i], &lines[j], &o) == 0) {
                    lines[i].random_rank = lines[j].random_rank;
                    found = 1;
                    break;
                }
            }
            if (!found)
                lines[i].random_rank = bs_random_next ();
        }
        /* Under -R the rank is the first-order key. */
        for (size_t i = 0; i < n; i++)
            elems[i].pre = lines[i].random_rank;
        bs_pre_reverse = o.rflag;
    }

    if (o.cflag) {
        /* -c / -C: check if input is already sorted, by the whole order the
         * sort would use; under -u, two lines with equal keys are disorder
         * too, as GNU sort has it.
         * -C (Cflag) is silent; -c emits a GNU-style disorder diagnostic
         *   "bashsort: <file>:<line>: disorder: <line-content>"
         * where <file> is the source file name ("-" for stdin), <line> is
         * the 1-based line number within that file, and <line-content> is
         * the offending record with its trailing record delimiter stripped. */
        for (size_t i = 1; i < n; i++) {
            int d = bs_compare_keys (&lines[i - 1], &lines[i], &o);
            if (d == 0 && o.uflag)
                d = 1;
            else if (d == 0 && !o.sflag)
                d = bs_last_resort (&lines[i - 1], &lines[i], &o);
            if (d > 0) {
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
                rc = EXECUTION_FAILURE;
                goto out;
            }
        }
        goto out;
    }

    if (!o.mergeflag && n > 1)
        bs_sort_elements (elems, n, workers);

    FILE *outf = stdout;
    if (output_file && strcmp (output_file, "-") != 0) {
        outf = fopen (output_file, "w");
        if (!outf) {
            builtin_error ("%s: %s", output_file, strerror (errno));
            rc = BS_TROUBLE;
            goto out;
        }
    } else {
        clearerr (stdout);
    }

    {
        bs_out ob;
        ob.f = outf;
        ob.n = 0;
        if (o.mergeflag)
            bs_emit_merged (&ob, lines, runs, nruns, &o);
        else
            bs_emit_lines (&ob, elems, n, &o);
        bs_out_flush (&ob);
        if (fflush (outf) == EOF || ferror (outf)) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            rc = BS_TROUBLE;
        }
    }
    if (outf != stdout && fclose (outf) != 0) {
        builtin_error ("%s: %s", output_file, strerror (errno));
        rc = BS_TROUBLE;
    }

out:
    free (runs);
    free (keyblk);
    free (elems);
    bs_free_input (&in);
    return rc;
}

int
sort_builtin (WORD_LIST *list)
{
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc (count ? count : 1, sizeof *files);
    if (!files) return EXECUTION_FAILURE;
    int rc = bs_sort (list, files);
    free (files);
    return rc;
}

char *sort_doc[] = {
    "Sort lines in FILEs (or stdin).",
    "",
    "    sort [-zRVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [-S SIZE] [-T DIR] [FILE...]",
    "",
    "    -n   numeric compare, GNU sort's rules: leading blanks, an optional -,",
    "         digits and one decimal point; anything else compares as zero",
    "    -g   general numeric compare (strtold; supports +, exponent, inf, NaN)",
    "    -h   human numeric compare (SI suffix order)",
    "    -V   version/natural compare",
    "    -R   random compare (shuffle, grouping equal keys)",
    "         --random-source=FILE  seed random ordering from FILE bytes",
    "    -M   month compare (Jan..Dec; unknown names sort before Jan)",
    "    --parallel=N  use up to N concurrent sorting workers",
    "    -S, --buffer-size=SIZE  main memory buffer (b, K, M, G, T... or %;",
    "         K is the default); larger input is sorted in runs on disk",
    "    -T, --temporary-directory=DIR  directory for those runs",
    "         (default $TMPDIR, else /tmp)",
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
    "    -k KEYDEF  FIELD[.CHAR][OPTS][,FIELD[.CHAR][OPTS]], 1-based, as GNU sort's:",
    "         a key with letters of its own takes no global ordering option",
    "    -o FILE   write result to FILE",
    (char *)NULL
};

struct builtin sort_struct = {
    "sort",
    sort_builtin,
    BUILTIN_ENABLED,
    sort_doc,
    "sort [-RVbdghnmrufcisM] [-t SEP] [-k KEYDEF] [-o FILE] [-S SIZE] [-T DIR] [FILE...]",
    0
};
