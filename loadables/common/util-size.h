/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_UTIL_SIZE_H
#define BASHOS_UTIL_SIZE_H

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/* util-linux size syntax: base-0 integer, optional fraction, K..Y with
   optional "iB" (1024) or "B" (1000). */

static int
bashos_scale_size (uintmax_t *x, unsigned base, int pwr)
{
    while (pwr--) {
        if (*x > UINTMAX_MAX / base)
            return -ERANGE;
        *x *= base;
    }
    return 0;
}

static int
bashos_parse_size (const char *str, uint64_t *out)
{
    static const char suf[] = "KMGTPEZY", suf2[] = "kmgtpezy";
    const char *p = str;
    char *end = NULL;
    uintmax_t x, frac = 0;
    unsigned base = 1024;
    int pwr = 0, frac_zeros = 0;

    if (!str || !*str)
        return -EINVAL;
    while (isspace ((unsigned char) *p))
        p++;
    if (*p == '-')
        return -EINVAL;
    errno = 0;
    x = strtoumax (str, &end, 0);
    if (end == str || (errno != 0 && (x == UINTMAX_MAX || x == 0)))
        return errno ? -errno : -EINVAL;
    if (!end || !*end)
        goto done;
    p = end;
check_suffix:
    if (*p && p[1] == 'i' && (p[2] == 'B' || p[2] == 'b') && !p[3])
        base = 1024;
    else if (*p && (p[1] == 'B' || p[1] == 'b') && !p[2])
        base = 1000;
    else if (*p && p[1]) {
        if (frac == 0 && *p == '.') {
            const char *f = p + 1;
            for (; *f == '0'; f++)
                frac_zeros++;
            p = f;
            if (isdigit ((unsigned char) *f)) {
                errno = 0;
                frac = strtoumax (f, &end, 0);
                if (end == f || (errno != 0 && (frac == UINTMAX_MAX || frac == 0)))
                    return errno ? -errno : -EINVAL;
                p = end;
            }
            if (!*p)
                return -EINVAL;
            goto check_suffix;
        }
        return -EINVAL;
    }
    {
        const char *sp = *p ? strchr (suf, *p) : NULL;
        if (sp)
            pwr = (int) (sp - suf) + 1;
        else if (*p && (sp = strchr (suf2, *p)))
            pwr = (int) (sp - suf2) + 1;
        else
            return -EINVAL;
    }
    if (bashos_scale_size (&x, base, pwr) < 0)
        return -ERANGE;
    if (frac && pwr) {
        uintmax_t frac_div = 10, frac_poz = 1, frac_base = 1;
        bashos_scale_size (&frac_base, base, pwr);
        while (frac_div < frac) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        for (int i = 0; i < frac_zeros; i++) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        do {
            unsigned seg = (unsigned) (frac % 10);
            uintmax_t seg_div = frac_div / frac_poz;
            frac /= 10;
            frac_poz *= 10;
            if (seg && seg_div / seg)
                x += frac_base / (seg_div / seg);
        } while (frac);
    }
done:
    if (x > UINT64_MAX)
        return -ERANGE;
    *out = (uint64_t) x;
    return 0;
}

#endif
