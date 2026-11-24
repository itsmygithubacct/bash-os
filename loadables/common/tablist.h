/* SPDX-License-Identifier: MIT */
/* The TAB-LIST of expand -t and unexpand -t, read as GNU coreutils 9.7
   reads it (worked out from its manual and from runs of the GNU tools, all
   observed from outside):

   - Values are decimal numbers separated by commas or blanks; empty items
     are ignored. A '/' or '+' makes the numbers after it in the same
     argument tab extensions (the last mark seen wins; it may stand before
     a separator): '/N' adds stops at multiples of N after the last
     explicit stop, '+N' every N columns after it. A zero extension is
     ignored.
   - Explicit stops accumulate across -t options. Each kind of extension
     may be given a nonzero size once ("'/' specifier only allowed with
     the last value"), so after a mark only zeros may precede the last
     value.
   - A character that is none of these is an error naming the rest of the
     argument; a mark straight after digits is "not at start of number".
     Both end option processing at once.
   - A value above INTMAX_MAX is "too large"; the rest of that argument is
     still scanned for such errors, then option processing ends.
   - When all options are read, bos_tabs_finish() rejects a zero stop, stops
     that do not ascend, and both kinds of extension together.

   Diagnostics go through builtin_error; every error is status 1. */
#ifndef BASHOS_TABLIST_H
#define BASHOS_TABLIST_H

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gnu-quote.h"

typedef struct {
    uintmax_t *stops;
    size_t n_stops, allocated;
    uintmax_t extend_size, increment_size;
} bos_tabs;

static inline void
bos_tabs_quoted_error (const char *format, const char *text, size_t length)
{
    char *copy = malloc (length + 1);
    char *q = NULL;
    if (copy) {
        memcpy (copy, text, length);
        copy[length] = '\0';
        q = bos_quote (copy);
    }
    builtin_error (format, q ? q : (copy ? copy : text));
    free (q);
    free (copy);
}

static inline int
bos_tabs_add (bos_tabs *t, uintmax_t value)
{
    if (t->n_stops == t->allocated) {
        size_t capacity = t->allocated ? t->allocated * 2 : 16;
        if (capacity < t->allocated || capacity > SIZE_MAX / sizeof *t->stops) {
            builtin_error ("memory exhausted");
            return -1;
        }
        uintmax_t *grown = realloc (t->stops, capacity * sizeof *t->stops);
        if (!grown) {
            builtin_error ("memory exhausted");
            return -1;
        }
        t->stops = grown;
        t->allocated = capacity;
    }
    t->stops[t->n_stops++] = value;
    return 0;
}

/* One -t argument. Returns 0, or -1 after a diagnostic (the command then
   stops with status 1). */
static inline int
bos_tabs_parse (bos_tabs *t, const char *arg)
{
    const char *p = arg;
    int mark = 0, too_large = 0;

    while (*p) {
        unsigned char c = (unsigned char) *p;
        if (c == ',' || isblank (c)) { p++; continue; }
        if (c == '/' || c == '+') { mark = c; p++; continue; }
        if (!isdigit (c)) {
            bos_tabs_quoted_error ("tab size contains invalid character(s): %s", p, strlen (p));
            return -1;
        }
        const char *start = p;
        uintmax_t value = 0;
        int big = 0;
        for (; isdigit ((unsigned char) *p); p++) {
            unsigned int digit = (unsigned int) (*p - '0');
            if (big || value > ((uintmax_t) INTMAX_MAX - digit) / 10)
                big = 1;
            else
                value = value * 10 + digit;
        }
        if (*p == '/' || *p == '+') {
            bos_tabs_quoted_error (*p == '/' ? "'/' specifier not at start of number: %s"
                                             : "'+' specifier not at start of number: %s",
                                   p, strlen (p));
            return -1;
        }
        int kind = mark;
        if (big) {
            bos_tabs_quoted_error ("tab stop is too large %s", start, (size_t) (p - start));
            too_large = 1;
            continue;
        }
        if (too_large)
            continue;
        if (kind) {
            uintmax_t *size = kind == '/' ? &t->extend_size : &t->increment_size;
            if (*size) {
                builtin_error (kind == '/' ? "'/' specifier only allowed with the last value"
                                           : "'+' specifier only allowed with the last value");
                return -1;
            }
            *size = value;
        } else {
            if (bos_tabs_add (t, value) < 0)
                return -1;
        }
    }
    return too_large ? -1 : 0;
}

/* After the last option: 0, or -1 after a diagnostic. */
static inline int
bos_tabs_finish (const bos_tabs *t)
{
    for (size_t i = 0; i < t->n_stops; i++) {
        if (t->stops[i] == 0) {
            builtin_error ("tab size cannot be 0");
            return -1;
        }
        if (i && t->stops[i] <= t->stops[i - 1]) {
            builtin_error ("tab sizes must be ascending");
            return -1;
        }
    }
    if (t->extend_size && t->increment_size) {
        builtin_error ("'/' specifier is mutually exclusive with '+'");
        return -1;
    }
    return 0;
}

#endif
