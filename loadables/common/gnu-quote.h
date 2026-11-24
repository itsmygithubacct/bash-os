/* SPDX-License-Identifier: MIT */
/* Operand quoting for diagnostics that follow GNU coreutils: file names in
   the always-quoted shell style, other words in the locale's quotation
   marks. Both return allocated text, or NULL when memory is exhausted. */
#ifndef BASHOS_GNU_QUOTE_H
#define BASHOS_GNU_QUOTE_H

#include <langinfo.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>
#include <wctype.h>

/* Byte length of the next character and whether it is printable. */
static inline size_t
bos_quote_next (const char *text, size_t left, mbstate_t *state, int *printable)
{
    unsigned char c = (unsigned char) *text;
    if (c < 0x80) {
        *printable = c >= 0x20 && c != 0x7f;
        return 1;
    }
    wchar_t wide;
    size_t n = mbrtowc (&wide, text, left, state);
    if (n == 0 || n == (size_t) -1 || n == (size_t) -2) {
        memset (state, 0, sizeof *state);
        *printable = 0;
        return 1;
    }
    *printable = iswprint ((wint_t) wide) != 0;
    return n;
}

/* The letter of a C escape for a control character, or 0. */
static inline char
bos_quote_letter (unsigned char c)
{
    switch (c) {
    case '\a': return 'a';
    case '\b': return 'b';
    case '\f': return 'f';
    case '\n': return 'n';
    case '\r': return 'r';
    case '\t': return 't';
    case '\v': return 'v';
    default: return 0;
    }
}

/* A file name between single quotes. Unprintable bytes move into $'...'
   sections; an apostrophe leaves the quotes as \', unless the whole name
   can sit unchanged between double quotes. */
static inline char *
bos_quoteaf (const char *name)
{
    size_t length = strlen (name), at = 0;
    char *out = malloc (length * 9 + 8);
    if (!out)
        return NULL;
    int apostrophe = 0, plain = 1, section = 0;
    mbstate_t state;
    memset (&state, 0, sizeof state);
    out[at++] = '\'';
    for (size_t i = 0; i < length;) {
        unsigned char c = (unsigned char) name[i];
        int printable;
        size_t n = bos_quote_next (name + i, length - i, &state, &printable);
        char letter = bos_quote_letter (c);
        if (c == '\'') {
            apostrophe = 1;
            memcpy (out + at, "'\\''", 4);
            at += 4;
            section = 0;
            i++;
            continue;
        }
        if (letter || !printable) {
            plain = 0;
            for (size_t k = 0; k < n; k++) {
                unsigned char b = (unsigned char) name[i + k];
                if (!section) {
                    memcpy (out + at, "'$'", 3);
                    at += 3;
                    section = 1;
                }
                out[at++] = '\\';
                if (letter)
                    out[at++] = letter;
                else {
                    out[at++] = (char) ('0' + (b >> 6));
                    out[at++] = (char) ('0' + ((b >> 3) & 7));
                    out[at++] = (char) ('0' + (b & 7));
                }
            }
            i += n;
            continue;
        }
        if (c == '#' || c == '~') {
            if (i)
                plain = 0;
        } else if (c == '{' || c == '}') {
            if (length != 1)
                plain = 0;
        } else if (c < 0x80 && strchr ("!\"$&()*;<=>?[\\^`|", c))
            plain = 0;
        if (section) {
            memcpy (out + at, "''", 2);
            at += 2;
            section = 0;
        }
        memcpy (out + at, name + i, n);
        at += n;
        i += n;
    }
    out[at++] = '\'';
    out[at] = 0;
    if (apostrophe && plain) {
        out[0] = '"';
        memcpy (out + 1, name, length);
        out[length + 1] = '"';
        out[length + 2] = 0;
    }
    return out;
}

/* A file name at the start of a "NAME: message" diagnostic, quoted as
   bos_quoteaf does only when a shell (or a reader splitting at ": ") needs
   it, as GNU's diagnostics that start with a file name do: an empty name,
   white space, shell metacharacters, a colon, a leading '#' or '~', a lone
   brace, or an unprintable character. */
static inline char *
bos_quotef (const char *name)
{
    size_t len = strlen (name), i;
    int need = len == 0;
    mbstate_t st;

    memset (&st, 0, sizeof st);
    for (i = 0; i < len && !need;) {
        unsigned char c = (unsigned char) name[i];

        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f || strchr (" !\"$&'()*;<=>?[\\^`|:", c))
                need = 1;
            else if ((c == '#' || c == '~') && i == 0)
                need = 1;
            else if ((c == '{' || c == '}') && len == 1)
                need = 1;
            i++;
        } else {
            wchar_t w;
            size_t n = mbrtowc (&w, name + i, len - i, &st);

            if (n == 0 || n == (size_t) -1 || n == (size_t) -2 || !iswprint ((wint_t) w))
                need = 1;
            else
                i += n;
        }
    }
    return need ? bos_quoteaf (name) : strdup (name);
}

/* A word between the locale's quotation marks: U+2018 and U+2019 under a
   UTF-8 character set, apostrophes otherwise. */
static inline char *
bos_quote (const char *text)
{
    const char *codeset = nl_langinfo (CODESET);
    int utf8 = codeset && (!strcasecmp (codeset, "UTF-8") || !strcasecmp (codeset, "UTF8"));
    const char *left = utf8 ? "\xe2\x80\x98" : "'";
    const char *right = utf8 ? "\xe2\x80\x99" : "'";
    size_t length = strlen (text), mark = strlen (right), at = 0;
    char *out = malloc (length * 4 + 8);
    if (!out)
        return NULL;
    mbstate_t state;
    memset (&state, 0, sizeof state);
    memcpy (out, left, strlen (left));
    at += strlen (left);
    for (size_t i = 0; i < length;) {
        unsigned char c = (unsigned char) text[i];
        int printable;
        size_t n = bos_quote_next (text + i, length - i, &state, &printable);
        char letter = bos_quote_letter (c);
        if (letter || !printable) {
            for (size_t k = 0; k < n; k++) {
                unsigned char b = (unsigned char) text[i + k];
                out[at++] = '\\';
                if (letter)
                    out[at++] = letter;
                else {
                    out[at++] = (char) ('0' + (b >> 6));
                    out[at++] = (char) ('0' + ((b >> 3) & 7));
                    out[at++] = (char) ('0' + (b & 7));
                }
            }
            i += n;
            continue;
        }
        if (c == '\\' || (length - i >= mark && !memcmp (text + i, right, mark)))
            out[at++] = '\\';
        memcpy (out + at, text + i, n);
        at += n;
        i += n;
    }
    memcpy (out + at, right, mark + 1);
    return out;
}

#endif
