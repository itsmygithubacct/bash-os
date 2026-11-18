/* SPDX-License-Identifier: MIT */
/* iconv.c — convert text between character sets, as glibc iconv(1) does
 * for the common Western and Unicode encodings.
 *
 *   iconv [-c] [-s] [-f FROM] [-t TO[//TRANSLIT][//IGNORE]] [-o FILE] [FILE...]
 *   iconv -l
 *
 * Charsets: UTF-8, ASCII, ISO-8859-1, ISO-8859-15, CP1252, UTF-16,
 * UTF-16LE/BE, UCS-2, UCS-2LE/BE, UTF-32, UTF-32LE/BE, UCS-4 and their usual
 * aliases. UTF-16, UCS-2 and UTF-32 input without a byte order mark is
 * read little-endian, the host order glibc assumes on these targets. Names compare without case. FROM and TO default to the locale's
 * charset.
 *
 * Errors follow glibc: input that is not valid in FROM, or a character TO
 * cannot hold, stops the conversion with "illegal input sequence at
 * position N" (exit 1) after writing what was converted, even with -s; a truncated final
 * character reports "incomplete character or shift sequence at end of
 * buffer". -c and //IGNORE drop such characters and exit 1 at the end.
 * //TRANSLIT replaces a character TO lacks: punctuation, ligatures and
 * symbols by glibc's C transliterations, and in a UTF-8 locale accented
 * Latin letters by their base letters; anything else becomes '?'.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <langinfo.h>

#include "loadables.h"

enum { CS_UTF8, CS_ASCII, CS_LATIN1, CS_LATIN9, CS_CP1252, CS_UTF16, CS_UTF16LE,
       CS_UTF16BE, CS_UCS2, CS_UCS2LE, CS_UCS2BE, CS_UTF32, CS_UTF32LE, CS_UTF32BE };

static const struct { const char *name; int cs; } bic_names[] = {
    { "UTF-8", CS_UTF8 }, { "UTF8", CS_UTF8 },
    { "ASCII", CS_ASCII }, { "US-ASCII", CS_ASCII }, { "ANSI_X3.4-1968", CS_ASCII },
    { "646", CS_ASCII }, { "US", CS_ASCII }, { "ISO646-US", CS_ASCII }, { "CSASCII", CS_ASCII },
    { "ISO-8859-1", CS_LATIN1 }, { "ISO8859-1", CS_LATIN1 }, { "ISO_8859-1", CS_LATIN1 },
    { "ISO88591", CS_LATIN1 }, { "LATIN1", CS_LATIN1 }, { "L1", CS_LATIN1 },
    { "CP819", CS_LATIN1 }, { "IBM819", CS_LATIN1 },
    { "ISO-8859-15", CS_LATIN9 }, { "ISO8859-15", CS_LATIN9 }, { "ISO_8859-15", CS_LATIN9 },
    { "ISO885915", CS_LATIN9 }, { "LATIN-9", CS_LATIN9 }, { "LATIN9", CS_LATIN9 },
    { "CP1252", CS_CP1252 }, { "WINDOWS-1252", CS_CP1252 }, { "MS-ANSI", CS_CP1252 },
    { "UTF-16", CS_UTF16 }, { "UTF16", CS_UTF16 },
    { "UTF-16LE", CS_UTF16LE }, { "UTF16LE", CS_UTF16LE },
    { "UTF-16BE", CS_UTF16BE }, { "UTF16BE", CS_UTF16BE },
    { "UCS-2", CS_UCS2 }, { "UCS2", CS_UCS2 }, { "ISO-10646-UCS-2", CS_UCS2 },
    { "UCS-2LE", CS_UCS2LE }, { "UNICODELITTLE", CS_UCS2LE },
    { "UCS-2BE", CS_UCS2BE }, { "UNICODEBIG", CS_UCS2BE },
    { "UTF-32", CS_UTF32 }, { "UTF32", CS_UTF32 },
    { "UTF-32LE", CS_UTF32LE }, { "UTF32LE", CS_UTF32LE },
    { "UTF-32BE", CS_UTF32BE }, { "UTF32BE", CS_UTF32BE },
    { "UCS-4", CS_UTF32BE }, { "UCS4", CS_UTF32BE }, { "ISO-10646-UCS-4", CS_UTF32BE },
    { "UCS-4LE", CS_UTF32LE }, { "UCS-4BE", CS_UTF32BE },
};

/* CP1252 0x80..0x9F; 0 marks the five undefined bytes. */
static const uint16_t bic_cp1252[32] = {
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0,
    0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178
};

/* ISO-8859-15 differs from Latin-1 at eight positions. */
static const uint16_t bic_latin9[][2] = {
    { 0xA4, 0x20AC }, { 0xA6, 0x0160 }, { 0xA8, 0x0161 }, { 0xB4, 0x017D },
    { 0xB8, 0x017E }, { 0xBC, 0x0152 }, { 0xBD, 0x0153 }, { 0xBE, 0x0178 }
};

/* glibc's C-locale transliterations (locale/C-translit.h), the common part. */
static const struct { uint32_t cp; const char *to; } bic_translit[] = {
    { 0x00A0, " " }, { 0x00A9, "(C)" }, { 0x00AB, "<<" }, { 0x00AD, "-" },
    { 0x00AE, "(R)" }, { 0x00B5, "u" }, { 0x00B8, "," }, { 0x00BB, ">>" },
    { 0x00BC, " 1/4 " }, { 0x00BD, " 1/2 " }, { 0x00BE, " 3/4 " }, { 0x00C6, "AE" },
    { 0x00D7, "x" }, { 0x00DF, "ss" }, { 0x00E6, "ae" }, { 0x0132, "IJ" },
    { 0x0133, "ij" }, { 0x0149, "'n" }, { 0x0152, "OE" }, { 0x0153, "oe" },
    { 0x017F, "s" }, { 0x02BC, "'" }, { 0x02C6, "^" }, { 0x02C8, "'" },
    { 0x02CB, "`" }, { 0x02CD, "_" }, { 0x02D0, ":" }, { 0x02DC, "~" },
    { 0x2002, " " }, { 0x2003, " " }, { 0x2009, " " }, { 0x2010, "-" },
    { 0x2011, "-" }, { 0x2012, "-" }, { 0x2013, "-" }, { 0x2014, "-" },
    { 0x2015, "-" }, { 0x2018, "'" }, { 0x2019, "'" }, { 0x201A, "," },
    { 0x201B, "'" }, { 0x201C, "\"" }, { 0x201D, "\"" }, { 0x201E, ",," },
    { 0x201F, "\"" }, { 0x2020, "+" }, { 0x2022, "o" }, { 0x2024, "." },
    { 0x2025, ".." }, { 0x2026, "..." }, { 0x2030, " 0/00" }, { 0x2032, "'" },
    { 0x2033, "\"" }, { 0x2039, "<" }, { 0x203A, ">" }, { 0x20AC, "EUR" },
    { 0x2122, "(TM)" }, { 0x2190, "<-" }, { 0x2192, "->" }, { 0x2194, "<->" },
    { 0x21D0, "<=" }, { 0x21D2, "=>" }, { 0x2212, "-" }, { 0x2215, "/" },
    { 0x2260, "!=" }, { 0x2264, "<=" }, { 0x2265, ">=" }, { 0xFB00, "ff" },
    { 0xFB01, "fi" }, { 0xFB02, "fl" },
};

/* Base letters of U+00C0..U+017F for UTF-8 locales (translit_combining);
   '\0' means the code point has no single base letter. */
static const char bic_base_c0[] =
    "AAAAAA\0CEEEEIIII" "DNOOOOO\0OUUUUY\0\0" "aaaaaa\0ceeeeiiii" "dnooooo\0ouuuuy\0y";
static const char bic_base_100[] =
    "AaAaAaCcCcCcCcDd" "DdEeEeEeEeEeGgGg" "GgGgHhHhIiIiIiIi" "I\0\0\0JjKk\0LlLlLlL"
    "lLlNnNnNn\0\0\0OoOo" "Oo\0\0RrRrRrSsSsSs" "SsTtTtTtUuUuUuUu" "UuUuWwYyYZzZzZz\0";

typedef struct {
    int from, to, translit, ignore, omit, utf8_locale;
    int bom_done, in_order;      /* UTF-16/32 input: 1 big-endian, 2 little */
    FILE *out;
    int failed;                  /* a character was dropped or invalid */
    unsigned long long consumed; /* input bytes handled, across files */
} bic_state;

static int
bic_lookup (const char *spec, int *cs, int *translit, int *ignore)
{
    char name[64];
    size_t n = strcspn (spec, "/");
    if (n >= sizeof name) return -1;
    memcpy (name, spec, n);
    name[n] = '\0';
    for (const char *s = spec + n; *s; ) {
        while (*s == '/') s++;
        size_t len = strcspn (s, "/,");
        if (len == 8 && !strncasecmp (s, "TRANSLIT", 8)) { if (translit) *translit = 1; }
        else if (len == 6 && !strncasecmp (s, "IGNORE", 6)) { if (ignore) *ignore = 1; }
        s += len;
        while (*s == ',') s++;
    }
    if (!*name) {
        const char *codeset = nl_langinfo (CODESET);
        snprintf (name, sizeof name, "%s", codeset && *codeset ? codeset : "ANSI_X3.4-1968");
    }
    for (size_t i = 0; i < sizeof bic_names / sizeof bic_names[0]; i++)
        if (!strcasecmp (name, bic_names[i].name)) { *cs = bic_names[i].cs; return 0; }
    return -1;
}

static int
bic_put (bic_state *st, const void *p, size_t n)
{
    return fwrite (p, 1, n, st->out) == n ? 0 : -1;
}

/* Encode one code point in TO. Returns 0, 1 if TO cannot hold it, -1 on a
   write error. */
static int
bic_encode_one (bic_state *st, uint32_t cp)
{
    unsigned char b[8];
    switch (st->to) {
    case CS_UTF8:
        if (cp < 0x80) { b[0] = (unsigned char) cp; return bic_put (st, b, 1); }
        if (cp < 0x800) { b[0] = 0xC0 | (cp >> 6); b[1] = 0x80 | (cp & 0x3F); return bic_put (st, b, 2); }
        if (cp < 0x10000) {
            b[0] = 0xE0 | (cp >> 12); b[1] = 0x80 | ((cp >> 6) & 0x3F); b[2] = 0x80 | (cp & 0x3F);
            return bic_put (st, b, 3);
        }
        b[0] = 0xF0 | (cp >> 18); b[1] = 0x80 | ((cp >> 12) & 0x3F);
        b[2] = 0x80 | ((cp >> 6) & 0x3F); b[3] = 0x80 | (cp & 0x3F);
        return bic_put (st, b, 4);
    case CS_ASCII:
        if (cp >= 0x80) return 1;
        b[0] = (unsigned char) cp;
        return bic_put (st, b, 1);
    case CS_LATIN1:
        if (cp >= 0x100) return 1;
        b[0] = (unsigned char) cp;
        return bic_put (st, b, 1);
    case CS_LATIN9:
        for (size_t i = 0; i < sizeof bic_latin9 / sizeof bic_latin9[0]; i++) {
            if (bic_latin9[i][1] == cp) { b[0] = (unsigned char) bic_latin9[i][0]; return bic_put (st, b, 1); }
            if (bic_latin9[i][0] == cp) return 1;
        }
        if (cp >= 0x100) return 1;
        b[0] = (unsigned char) cp;
        return bic_put (st, b, 1);
    case CS_CP1252:
        if (cp < 0x80 || (cp >= 0xA0 && cp < 0x100)) { b[0] = (unsigned char) cp; return bic_put (st, b, 1); }
        for (int i = 0; i < 32; i++)
            if (bic_cp1252[i] && bic_cp1252[i] == cp) { b[0] = (unsigned char) (0x80 + i); return bic_put (st, b, 1); }
        return 1;
    case CS_UTF16: case CS_UTF16LE: case CS_UTF16BE:
    case CS_UCS2: case CS_UCS2LE: case CS_UCS2BE: {
        int ucs2 = st->to == CS_UCS2 || st->to == CS_UCS2LE || st->to == CS_UCS2BE;
        /* glibc's UTF-16 and UCS-2 write host (little) order; UTF-16 adds a BOM. */
        int be = st->to == CS_UTF16BE || st->to == CS_UCS2BE;
        if (st->to == CS_UTF16 && !st->bom_done) {
            unsigned char bom[2] = { 0xFF, 0xFE };
            st->bom_done = 1;
            if (bic_put (st, bom, 2) < 0) return -1;
        }
        uint16_t units[2];
        int count = 1;
        if (cp >= 0x10000) {
            if (ucs2) return 1;
            cp -= 0x10000;
            units[0] = (uint16_t) (0xD800 | (cp >> 10));
            units[1] = (uint16_t) (0xDC00 | (cp & 0x3FF));
            count = 2;
        } else units[0] = (uint16_t) cp;
        for (int i = 0; i < count; i++) {
            b[2 * i] = be ? units[i] >> 8 : units[i] & 0xFF;
            b[2 * i + 1] = be ? units[i] & 0xFF : units[i] >> 8;
        }
        return bic_put (st, b, (size_t) count * 2);
    }
    default: {   /* UTF-32 */
        int be = st->to == CS_UTF32BE;
        if (st->to == CS_UTF32 && !st->bom_done) {
            unsigned char bom[4] = { 0xFF, 0xFE, 0, 0 };
            st->bom_done = 1;
            if (bic_put (st, bom, 4) < 0) return -1;
        }
        for (int i = 0; i < 4; i++)
            b[i] = (unsigned char) (be ? cp >> (24 - 8 * i) : cp >> (8 * i));
        return bic_put (st, b, 4);
    }
    }
}

/* Encode with //TRANSLIT fallbacks. 0, 1 (cannot), -1 (write error). */
static int
bic_encode (bic_state *st, uint32_t cp)
{
    int rc = bic_encode_one (st, cp);
    if (rc != 1 || !st->translit) return rc;
    if (st->utf8_locale) {
        char base = 0;
        if (cp >= 0xC0 && cp < 0x100) base = bic_base_c0[cp - 0xC0];
        else if (cp >= 0x100 && cp < 0x180) base = bic_base_100[cp - 0x100];
        if (base) return bic_encode_one (st, (unsigned char) base);
    }
    for (size_t i = 0; i < sizeof bic_translit / sizeof bic_translit[0]; i++)
        if (bic_translit[i].cp == cp) {
            for (const char *s = bic_translit[i].to; *s; s++)
                if ((rc = bic_encode_one (st, (unsigned char) *s)) != 0) return rc;
            return 0;
        }
    return bic_encode_one (st, '?');
}

/* Decode one character at P (N bytes left). Sets *used. Returns 0, 1 for an
   invalid sequence, 2 for a truncated one at the end of the input. */
static int
bic_decode (bic_state *st, const unsigned char *p, size_t n, uint32_t *cp, size_t *used)
{
    switch (st->from) {
    case CS_UTF8: {
        unsigned char c = p[0];
        size_t len;
        uint32_t v, min;
        if (c < 0x80) { *cp = c; *used = 1; return 0; }
        if (c >= 0xC2 && c <= 0xDF) { len = 2; v = c & 0x1F; min = 0x80; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; v = c & 0x0F; min = 0x800; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; v = c & 0x07; min = 0x10000; }
        else return 1;
        for (size_t i = 1; i < len; i++) {
            if (i >= n) return 2;
            if ((p[i] & 0xC0) != 0x80) return 1;
            v = (v << 6) | (p[i] & 0x3F);
        }
        if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return 1;
        *cp = v; *used = len;
        return 0;
    }
    case CS_ASCII:
        if (p[0] >= 0x80) return 1;
        *cp = p[0]; *used = 1;
        return 0;
    case CS_LATIN1:
        *cp = p[0]; *used = 1;
        return 0;
    case CS_LATIN9:
        *cp = p[0]; *used = 1;
        for (size_t i = 0; i < sizeof bic_latin9 / sizeof bic_latin9[0]; i++)
            if (bic_latin9[i][0] == p[0]) *cp = bic_latin9[i][1];
        return 0;
    case CS_CP1252:
        *used = 1;
        if (p[0] >= 0x80 && p[0] < 0xA0) {
            if (!bic_cp1252[p[0] - 0x80]) return 1;
            *cp = bic_cp1252[p[0] - 0x80];
        } else *cp = p[0];
        return 0;
    case CS_UTF16: case CS_UTF16LE: case CS_UTF16BE:
    case CS_UCS2: case CS_UCS2LE: case CS_UCS2BE: {
        int ucs2 = st->from == CS_UCS2 || st->from == CS_UCS2LE || st->from == CS_UCS2BE;
        int order = st->from == CS_UTF16BE || st->from == CS_UCS2BE ? 1
                  : st->from == CS_UTF16LE || st->from == CS_UCS2LE ? 2 : st->in_order;
        if (n < 2) return 2;
        if (!order) {
            /* A BOM sets the order; without one glibc reads host order. */
            if (p[0] == 0xFE && p[1] == 0xFF) { st->in_order = 1; *used = 2; *cp = 0xFEFF; return 3; }
            if (p[0] == 0xFF && p[1] == 0xFE) { st->in_order = 2; *used = 2; *cp = 0xFEFF; return 3; }
            st->in_order = order = 2;
        }
        uint32_t u = order == 1 ? (uint32_t) (p[0] << 8 | p[1]) : (uint32_t) (p[1] << 8 | p[0]);
        if (u >= 0xD800 && u <= 0xDBFF && !ucs2) {
            if (n < 4) return 2;
            uint32_t l = order == 1 ? (uint32_t) (p[2] << 8 | p[3]) : (uint32_t) (p[3] << 8 | p[2]);
            if (l < 0xDC00 || l > 0xDFFF) return 1;
            *cp = 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00);
            *used = 4;
            return 0;
        }
        if (u >= 0xD800 && u <= 0xDFFF) return 1;
        *cp = u; *used = 2;
        return 0;
    }
    default: {
        int order = st->from == CS_UTF32BE ? 1 : st->from == CS_UTF32LE ? 2 : st->in_order;
        if (n < 4) return 2;
        if (!order) {
            if (!p[0] && !p[1] && p[2] == 0xFE && p[3] == 0xFF) { st->in_order = 1; *used = 4; *cp = 0xFEFF; return 3; }
            if (p[0] == 0xFF && p[1] == 0xFE && !p[2] && !p[3]) { st->in_order = 2; *used = 4; *cp = 0xFEFF; return 3; }
            st->in_order = order = 2;
        }
        uint32_t v = order == 1 ? (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3]
                                : (uint32_t) p[3] << 24 | (uint32_t) p[2] << 16 | (uint32_t) p[1] << 8 | p[0];
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return 1;
        *cp = v; *used = 4;
        return 0;
    }
    }
}

static int
bic_slurp (int fd, unsigned char **out, size_t *len)
{
    size_t cap = 65536, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;
    for (;;) {
        if (n == cap) {
            unsigned char *grown = cap > SIZE_MAX / 2 ? NULL : realloc (buf, cap * 2);
            if (!grown) { free (buf); errno = ENOMEM; return -1; }
            buf = grown;
            cap *= 2;
        }
        ssize_t r = read (fd, buf + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { int e = errno; free (buf); errno = e; return -1; }
        if (r == 0) break;
        n += (size_t) r;
    }
    *out = buf;
    *len = n;
    return 0;
}

/* Convert one input. Returns 0, 1 (stopped on bad input), 2 (write error). */
static int
bic_convert (bic_state *st, const unsigned char *p, size_t n)
{
    size_t i = 0;
    st->in_order = 0;
    while (i < n) {
        uint32_t cp;
        size_t used = 0;
        int d = bic_decode (st, p + i, n - i, &cp, &used);
        if (d == 3) { i += used; continue; }   /* byte order mark */
        if (d == 2) {
            if (st->omit) { st->failed = 1; break; }
            fflush (st->out);
            builtin_error ("incomplete character or shift sequence at end of buffer");
            return 1;
        }
        if (d == 1) {
            if (st->omit || st->ignore) { st->failed = 1; i++; continue; }
            fflush (st->out);
            builtin_error ("illegal input sequence at position %llu", st->consumed + i);
            return 1;
        }
        int e = bic_encode (st, cp);
        if (e < 0) return 2;
        if (e == 1) {
            if (st->omit || st->ignore) { st->failed = 1; i += used; continue; }
            fflush (st->out);
            builtin_error ("illegal input sequence at position %llu", st->consumed + i);
            return 1;
        }
        i += used;
    }
    st->consumed += n;
    return 0;
}

static void
bic_list (void)
{
    puts ("The following list contains the supported coded character sets.");
    puts ("");
    for (size_t i = 0; i < sizeof bic_names / sizeof bic_names[0]; i++)
        printf ("%s//\n", bic_names[i].name);
}

int
iconv_builtin (WORD_LIST *list)
{
    const char *from = "", *to = "", *output = NULL;
    int omit = 0, list_only = 0;
    const char *files[256];
    int nfiles = 0, end_options = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_options && !strcmp (w, "--")) { end_options = 1; continue; }
        if (!end_options && w[0] == '-' && w[1] == '-') {
            const char **slot = NULL;
            const char *v = NULL;
            if (!strncmp (w, "--from-code=", 12)) { slot = &from; v = w + 12; }
            else if (!strncmp (w, "--to-code=", 10)) { slot = &to; v = w + 10; }
            else if (!strncmp (w, "--output=", 9)) { slot = &output; v = w + 9; }
            else if (!strcmp (w, "--from-code") || !strcmp (w, "--to-code") || !strcmp (w, "--output")) {
                if (!p->next) { builtin_error ("option '%s' requires an argument", w); return 64; }
                slot = w[2] == 'f' ? &from : w[2] == 't' ? &to : &output;
                p = p->next;
                v = p->word->word;
            }
            else if (!strcmp (w, "--list")) { list_only = 1; continue; }
            else if (!strcmp (w, "--silent")) continue;   /* glibc still reports errors */
            else if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
            else if (!strcmp (w, "--version")) { puts ("iconv (bash-os) 0.1.5"); return EXECUTION_SUCCESS; }
            else { builtin_error ("unrecognized option '%s'", w); builtin_usage (); return 64; }
            *slot = v;
            continue;
        }
        if (!end_options && w[0] == '-' && w[1]) {
            for (int i = 1; w[i]; i++) {
                char c = w[i];
                if (c == 'c') omit = 1;
                else if (c == 's') continue;
                else if (c == 'l') list_only = 1;
                else if (c == 'f' || c == 't' || c == 'o') {
                    const char *v = w[i + 1] ? &w[i + 1] : NULL;
                    if (!v) {
                        if (!p->next) { builtin_error ("option requires an argument -- '%c'", c); return 64; }
                        p = p->next;
                        v = p->word->word;
                    }
                    if (c == 'f') from = v; else if (c == 't') to = v; else output = v;
                    break;
                } else {
                    builtin_error ("invalid option -- '%c'", c);
                    builtin_usage ();
                    return 64;
                }
            }
            continue;
        }
        if (nfiles >= (int) (sizeof files / sizeof files[0])) { builtin_error ("too many files"); return 1; }
        files[nfiles++] = w;
    }
    if (list_only) { bic_list (); return fflush (stdout) == EOF ? 1 : EXECUTION_SUCCESS; }

    bic_state st;
    memset (&st, 0, sizeof st);
    int bad_from = bic_lookup (from, &st.from, NULL, NULL) < 0;
    int bad_to = bic_lookup (to, &st.to, &st.translit, &st.ignore) < 0;
    if (bad_from || bad_to) {
        if (bad_from && bad_to)
            builtin_error ("conversions from `%.*s' and to `%.*s' are not supported",
                           (int) strcspn (from, "/"), from, (int) strcspn (to, "/"), to);
        else if (bad_from)
            builtin_error ("conversion from `%.*s' is not supported", (int) strcspn (from, "/"), from);
        else
            builtin_error ("conversion to `%.*s' is not supported", (int) strcspn (to, "/"), to);
        fputs ("Try `iconv --help' or `iconv --usage' for more information.\n", stderr);
        return 1;
    }
    st.omit = omit;
    const char *codeset = nl_langinfo (CODESET);
    st.utf8_locale = codeset && (!strcasecmp (codeset, "UTF-8") || !strcasecmp (codeset, "UTF8"));

    int rc = 0, out_fd = -1;
    if (output && strcmp (output, "-")) {
        out_fd = open (output, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (out_fd < 0 || !(st.out = fdopen (out_fd, "w"))) {
            builtin_error ("cannot open output file: %s", strerror (errno));
            if (out_fd >= 0) close (out_fd);
            return 1;
        }
    } else st.out = stdout;

    if (!nfiles) files[nfiles++] = "-";
    for (int i = 0; i < nfiles && rc == 0; i++) {
        int fd = strcmp (files[i], "-") ? open (files[i], O_RDONLY | O_CLOEXEC) : STDIN_FILENO;
        if (fd < 0) { builtin_error ("cannot open input file `%s': %s", files[i], strerror (errno)); rc = 1; break; }
        unsigned char *data;
        size_t len;
        int read_rc = bic_slurp (fd, &data, &len);
        if (fd != STDIN_FILENO) close (fd);
        if (read_rc < 0) { builtin_error ("unable to read %s: %s", files[i], strerror (errno)); rc = 1; break; }
        int c = bic_convert (&st, data, len);
        free (data);
        if (c == 2) { builtin_error ("write error: %s", strerror (errno ? errno : EIO)); rc = 1; }
        else if (c) rc = 1;
    }
    /* glibc reports //IGNORE drops at the end, at the input's end position. */
    if (rc == 0 && st.failed && st.ignore && !omit) {
        fflush (st.out);
        builtin_error ("illegal input sequence at position %llu", st.consumed);
    }
    if (rc == 0 && st.failed) rc = 1;
    if (st.out != stdout) {
        if (fclose (st.out) == EOF) { builtin_error ("write error: %s", strerror (errno)); rc = 1; }
    } else if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        clearerr (stdout);
        rc = 1;
    }
    return rc;
}

char *iconv_doc[] = {
    "Convert text from one character set to another.",
    "",
    "    iconv [-c] [-s] [-f FROM] [-t TO[//TRANSLIT][//IGNORE]] [-o FILE] [FILE...]",
    "    iconv -l",
    "",
    "    -f, --from-code=NAME   input charset (default: the locale's)",
    "    -t, --to-code=NAME     output charset; //TRANSLIT approximates and",
    "                           //IGNORE drops characters it cannot hold",
    "    -c                     drop characters that cannot be converted",
    "    -o, --output=FILE      write to FILE",
    "    -s, --silent           accepted; errors are still reported, as in glibc",
    "    -l, --list             list the supported charsets",
    "",
    "Charsets: UTF-8, ASCII, ISO-8859-1, ISO-8859-15, CP1252, UTF-16[LE|BE],",
    "UCS-2[LE|BE], UTF-32[LE|BE], UCS-4 and common aliases.",
    (char *)NULL
};

struct builtin iconv_struct = {
    "iconv",
    iconv_builtin,
    BUILTIN_ENABLED,
    iconv_doc,
    "iconv [-cs] [-f FROM] [-t TO] [-o FILE] [FILE...]",
    0
};
