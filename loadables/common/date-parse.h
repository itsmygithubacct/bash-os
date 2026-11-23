/* SPDX-License-Identifier: MIT */
/* GNU-style date strings for date -d/-s/-f and touch -d: ISO 8601,
   @SECONDS, RFC 5322, calendar dates with month names or MM/DD/YYYY,
   times of day with fractional seconds, am/pm and zones, and the GNU
   relative items, applied to a base time (now, or touch -r's REF). */
#ifndef BASHOS_DATE_PARSE_H
#define BASHOS_DATE_PARSE_H

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int
bd_parse_tz_offset (const char *s, long *offset)
{
    int sign, hh, mm;

    if (s[0] != '+' && s[0] != '-')
        return -1;
    sign = s[0] == '+' ? 1 : -1;

    if (s[1] < '0' || s[1] > '9' || s[2] < '0' || s[2] > '9')
        return -1;

    hh = (s[1] - '0') * 10 + (s[2] - '0');
    if (s[3] == ':') {
        if (s[4] < '0' || s[4] > '9' || s[5] < '0' || s[5] > '9' || s[6] != '\0')
            return -1;
        mm = (s[4] - '0') * 10 + (s[5] - '0');
    } else {
        if (s[3] < '0' || s[3] > '9' || s[4] < '0' || s[4] > '9' || s[5] != '\0')
            return -1;
        mm = (s[3] - '0') * 10 + (s[4] - '0');
    }

    if (hh > 23 || mm > 59)
        return -1;
    *offset = sign * (long) (hh * 3600 + mm * 60);
    return 0;
}

static int
bd_ci3_eq (const char *s, const char *lit)
{
    for (int i = 0; i < 3; i++) {
        char a = s[i];
        char b = lit[i];
        if (a >= 'A' && a <= 'Z')
            a = (char) (a + 32);
        if (b >= 'A' && b <= 'Z')
            b = (char) (b + 32);
        if (a != b)
            return 0;
    }
    return 1;
}

static const char *
bd_skip_space (const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int
bd_parse_uint_width (const char **pp, int min_digits, int max_digits, int *out)
{
    const char *p = *pp;
    int n = 0;
    int v = 0;
    while (n < max_digits && *p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        p++;
        n++;
    }
    if (n < min_digits)
        return -1;
    *pp = p;
    *out = v;
    return 0;
}

static int
bd_month_index (const char *p)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int i = 0; i < 12; i++)
        if (bd_ci3_eq (p, months[i]))
            return i;
    return -1;
}

static int
bd_weekday_index (const char *p)
{
    static const char *days[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    for (int i = 0; i < 7; i++)
        if (bd_ci3_eq (p, days[i]))
            return i;
    return -1;
}

static int
bd_convert_tm (struct tm *t, int utc, time_t *out)
{
    int year = t->tm_year;
    int mon = t->tm_mon;
    int mday = t->tm_mday;
    int hour = t->tm_hour;
    int min = t->tm_min;
    int sec = t->tm_sec;
    errno = 0;
    time_t tt = utc ? timegm (t) : mktime (t);
    if (tt == (time_t) -1 && errno != 0)
        return -1;
    if (t->tm_year != year || t->tm_mon != mon ||
        t->tm_mday != mday || t->tm_hour != hour ||
        t->tm_min != min || t->tm_sec != sec)
        return -1;
    *out = tt;
    return 0;
}

static int
bd_parse_rfc_lenient (const char *s, time_t *out)
{
    const char *p = s;
    struct tm t;
    int day, month, year, hour, minute, second;
    long offset = 0;

    if (bd_weekday_index (p) >= 0) {
        p += 3;
        if (*p == ',')
            p++;
        if (*p != ' ' && *p != '\t')
            return -1;
        p = bd_skip_space (p);
    }

    if (bd_parse_uint_width (&p, 1, 2, &day) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    month = bd_month_index (p);
    if (month < 0)
        return -1;
    p += 3;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (bd_parse_uint_width (&p, 4, 4, &year) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (bd_parse_uint_width (&p, 2, 2, &hour) < 0 || *p++ != ':' ||
        bd_parse_uint_width (&p, 2, 2, &minute) < 0 || *p++ != ':' ||
        bd_parse_uint_width (&p, 2, 2, &second) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (!strcmp (p, "UTC") || !strcmp (p, "utc") ||
        !strcmp (p, "GMT") || !strcmp (p, "gmt")) {
        offset = 0;
    } else if (bd_parse_tz_offset (p, &offset) == 0) {
        ;
    } else {
        return -1;
    }

    memset (&t, 0, sizeof t);
    t.tm_year = year - 1900;
    t.tm_mon = month;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = minute;
    t.tm_sec = second;
    t.tm_isdst = -1;
    if (bd_convert_tm (&t, 1, out) < 0)
        return -1;
    *out -= (time_t) offset;
    return 0;
}

static int bd_parse_d (const char *s, const struct timespec *now,
                       time_t *out, long *nsec, int utc);

/* GNU relative items: "yesterday", "tomorrow", "today", "now",
   "[+-]N UNIT[s] [ago]", "next|last|this UNIT", and a day of the week
   with an optional next/last/this.  They apply, in GNU's order, to the
   current time or to an absolute date written before them: day of week
   first, then years, months and days on the calendar, then hours,
   minutes and seconds as elapsed time.  A day of week without a date
   resets the time of day to midnight, as GNU does.  Returns 0 and sets
   *out/*nsec, or -1 when any word is not a relative item. */
static int
bd_parse_relative (const char *s, time_t base, long base_nsec, int utc,
                   int dated, time_t *out, long *nsec)
{
    static const struct { const char *name; int field; long mult; } units[] = {
        { "year", 0, 1 }, { "month", 1, 1 }, { "fortnight", 2, 14 },
        { "week", 2, 7 }, { "day", 2, 1 }, { "hour", 3, 3600 },
        { "minute", 3, 60 }, { "min", 3, 60 }, { "second", 3, 1 },
        { "sec", 3, 1 }
    };
    static const char *days[] = {
        "sunday", "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday"
    };
    long long rel[4] = { 0, 0, 0, 0 };   /* years, months, days, seconds */
    int day_number = -1, day_ordinal = 0, seen = 0;
    int last_field = -1;
    long long last_amount = 0;
    const char *p = s;

    for (;;) {
        char word[16];
        size_t n = 0;
        long long amount = 1;
        int have_amount = 0;

        p = bd_skip_space (p);
        if (!*p) break;
        if (*p == '+' || *p == '-' || (*p >= '0' && *p <= '9')) {
            int neg = *p == '-';
            if (*p == '+' || *p == '-') p = bd_skip_space (p + 1);
            if (*p < '0' || *p > '9') return -1;
            amount = 0;
            while (*p >= '0' && *p <= '9') {
                if (amount > 100000000LL) return -1;
                amount = amount * 10 + (*p++ - '0');
            }
            if (neg) amount = -amount;
            have_amount = 1;
            p = bd_skip_space (p);
        }
        while ((*p | 0x20) >= 'a' && (*p | 0x20) <= 'z') {
            if (n + 1 >= sizeof word) return -1;
            word[n++] = (char) (*p++ | 0x20);
        }
        word[n] = '\0';
        if (!n) return -1;

        if (!have_amount) {
            if (!strcmp (word, "now") || !strcmp (word, "today")) { seen = 1; continue; }
            if (!strcmp (word, "yesterday")) { rel[2] -= 1; seen = 1; continue; }
            if (!strcmp (word, "tomorrow")) { rel[2] += 1; seen = 1; continue; }
            if (!strcmp (word, "ago")) {
                if (last_field < 0) return -1;
                rel[last_field] -= 2 * last_amount;
                last_field = -1;
                continue;
            }
            if (!strcmp (word, "next") || !strcmp (word, "last") || !strcmp (word, "this")) {
                amount = word[0] == 'n' ? 1 : word[0] == 'l' ? -1 : 0;
                have_amount = 2;
                p = bd_skip_space (p);
                n = 0;
                while ((*p | 0x20) >= 'a' && (*p | 0x20) <= 'z') {
                    if (n + 1 >= sizeof word) return -1;
                    word[n++] = (char) (*p++ | 0x20);
                }
                word[n] = '\0';
                if (!n) return -1;
            }
        }

        /* Day of the week: the full name, its first three letters, or
           GNU's "tues", "wednes", "thur" and "thurs". */
        int wd = -1;
        for (int i = 0; i < 7 && wd < 0; i++)
            if (!strcmp (word, days[i]) || (n == 3 && !strncmp (word, days[i], 3)))
                wd = i;
        if (!strcmp (word, "tues")) wd = 2;
        if (!strcmp (word, "wednes")) wd = 3;
        if (!strcmp (word, "thur") || !strcmp (word, "thurs")) wd = 4;
        if (wd >= 0) {
            if (have_amount == 1 || day_number >= 0) return -1;
            day_number = wd;
            day_ordinal = have_amount ? (int) amount : 0;
            seen = 1;
            if (*p == ',') p++;
            continue;
        }

        int u = -1;
        for (size_t i = 0; i < sizeof units / sizeof units[0]; i++) {
            size_t len = strlen (units[i].name);
            if (!strcmp (word, units[i].name) ||
                (n == len + 1 && !strncmp (word, units[i].name, len) && word[len] == 's')) {
                u = (int) i;
                break;
            }
        }
        if (u < 0) return -1;
        long long add = amount * units[u].mult;
        rel[units[u].field] += add;
        last_field = units[u].field;
        last_amount = add;
        seen = 1;
    }
    if (!seen) return -1;

    struct tm tm;
    time_t t = base;
    if (!(utc ? gmtime_r (&t, &tm) : localtime_r (&t, &tm))) return -1;
    /* GNU ignores a day of the week when a calendar date is also given. */
    if (day_number >= 0 && !dated) {
        tm.tm_mday += (day_number - tm.tm_wday + 7) % 7
            + 7 * (day_ordinal - (0 < day_ordinal && tm.tm_wday != day_number));
        tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
        base_nsec = 0;
    }
    if (rel[0] > INT_MAX / 2 || rel[0] < -(INT_MAX / 2) ||
        rel[1] > INT_MAX / 2 || rel[1] < -(INT_MAX / 2) ||
        rel[2] > INT_MAX / 2 || rel[2] < -(INT_MAX / 2))
        return -1;
    tm.tm_year += (int) rel[0];
    tm.tm_mon += (int) rel[1];
    tm.tm_mday += (int) rel[2];
    tm.tm_isdst = -1;
    errno = 0;
    t = utc ? timegm (&tm) : mktime (&tm);
    if (t == (time_t) -1 && errno != 0) return -1;
    *out = t + (time_t) rel[3];
    *nsec = base_nsec;
    return 0;
}

/* An absolute date followed by relative items ("2024-01-31 +1 month").
   Like GNU, the shortest absolute prefix wins, so "2024-01-01 3 hours ago"
   is three hours before midnight; and a signed number right after a time
   of day is its zone ("12:00 -2 days" is 12:00 at UTC-2, then +1 day). */
static int
bd_parse_with_relative (const char *s, const struct timespec *now,
                        time_t *out, long *nsec, int utc)
{
    if (bd_parse_relative (s, now->tv_sec, now->tv_nsec, utc, 0, out, nsec) == 0)
        return 0;
    size_t len = strlen (s);
    if (s[0] == '@') return -1;   /* GNU takes nothing after @SECONDS */
    char *copy = malloc (len + 1);
    if (!copy) return -1;
    for (size_t cut = 1; cut < len; cut++) {
        if (s[cut] != ' ' && s[cut] != '\t') continue;
        if (s[cut - 1] == ' ' || s[cut - 1] == '\t') continue;
        memcpy (copy, s, cut);
        copy[cut] = '\0';
        time_t base;
        long base_nsec;
        if (bd_parse_d (copy, now, &base, &base_nsec, utc) != 0) continue;
        const char *rest = bd_skip_space (s + cut);
        if (strchr (copy, ':') && (*rest == '+' || *rest == '-') &&
            rest[1] >= '0' && rest[1] <= '9') {
            /* Numeric zone: H, HH, HHMM or HH:MM after the sign. */
            const char *z = rest + 1;
            int digits = 0, value = 0, minutes = 0;
            while (z[digits] >= '0' && z[digits] <= '9' && digits < 5)
                value = value * 10 + (z[digits++] - '0');
            const char *after = z + digits;
            if (digits <= 2 && *after == ':' && after[1] >= '0' && after[1] <= '9' &&
                after[2] >= '0' && after[2] <= '9') {
                minutes = (after[1] - '0') * 10 + (after[2] - '0');
                after += 3;
            } else if (digits == 4) {
                minutes = value % 100;
                value /= 100;
            } else if (digits > 2) {
                continue;
            }
            if (*after && *after != ' ' && *after != '\t') continue;
            long offset = (value * 3600L + minutes * 60L) * (*rest == '-' ? -1 : 1);
            time_t wall;
            long wall_nsec;
            if (bd_parse_d (copy, now, &wall, &wall_nsec, 1) != 0) continue;
            base = wall - (time_t) offset;
            base_nsec = wall_nsec;
            rest = after;
            if (!*bd_skip_space (rest)) {
                free (copy);
                *out = base;
                *nsec = base_nsec;
                return 0;
            }
        }
        if (bd_parse_relative (rest, base, base_nsec, utc, 1, out, nsec) == 0) {
            free (copy);
            return 0;
        }
    }
    free (copy);
    return -1;
}

static int
bd_is_alpha (char c)
{
    return (c | 0x20) >= 'a' && (c | 0x20) <= 'z';
}

static int
bd_read_num (const char **pp, long long *value, int *digits)
{
    const char *p = *pp;
    long long v = 0;
    int n = 0;
    while (*p >= '0' && *p <= '9') {
        if (n >= 12)
            return -1;
        v = v * 10 + (*p++ - '0');
        n++;
    }
    if (!n)
        return -1;
    *pp = p;
    *value = v;
    *digits = n;
    return 0;
}

/* Read a run of letters (dots dropped, so "a.m." is "am") into WORD in
   lower case.  Returns its length, or 0 when it does not fit. */
static size_t
bd_read_word (const char **pp, char *word, size_t size)
{
    const char *p = *pp;
    size_t n = 0;
    while (bd_is_alpha (*p) || (n && *p == '.')) {
        if (n + 1 >= size)
            return 0;
        if (*p != '.')
            word[n++] = (char) (*p | 0x20);
        p++;
    }
    word[n] = '\0';
    *pp = p;
    return n;
}

/* Month 0-11 for a full English month name, its first three letters or
   "sept"; -1 otherwise.  WORD is lower case. */
static int
bd_month_word (const char *word)
{
    static const char *names[] = {
        "january", "february", "march", "april", "may", "june", "july",
        "august", "september", "october", "november", "december"
    };
    size_t n = strlen (word);
    for (int i = 0; i < 12; i++)
        if (!strcmp (word, names[i]) || (n == 3 && !strncmp (word, names[i], 3)))
            return i;
    return strcmp (word, "sept") ? -1 : 8;
}

static int
bd_weekday_word (const char *word)
{
    static const char *names[] = {
        "sunday", "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday"
    };
    size_t n = strlen (word);
    for (int i = 0; i < 7; i++)
        if (!strcmp (word, names[i]) || (n == 3 && !strncmp (word, names[i], 3)))
            return i;
    if (!strcmp (word, "tues")) return 2;
    if (!strcmp (word, "wednes")) return 3;
    if (!strcmp (word, "thur") || !strcmp (word, "thurs")) return 4;
    return -1;
}

/* The zone abbreviations GNU's parse-datetime knows, in minutes east of
   UTC.  Returns 0 and sets *seconds, or -1. */
static int
bd_zone_word (const char *word, long *seconds)
{
    static const struct { const char *name; int minutes; } zones[] = {
        { "utc", 0 }, { "gmt", 0 }, { "ut", 0 }, { "z", 0 }, { "wet", 0 },
        { "west", 60 }, { "bst", 60 }, { "art", -180 }, { "brt", -180 },
        { "brst", -120 }, { "nst", -210 }, { "ndt", -150 }, { "ast", -240 },
        { "adt", -180 }, { "clt", -240 }, { "clst", -180 }, { "est", -300 },
        { "edt", -240 }, { "cst", -360 }, { "cdt", -300 }, { "mst", -420 },
        { "mdt", -360 }, { "pst", -480 }, { "pdt", -420 }, { "akst", -540 },
        { "akdt", -480 }, { "hst", -600 }, { "hast", -600 }, { "hadt", -540 },
        { "sst", -720 }, { "wat", 60 }, { "cet", 60 }, { "cest", 120 },
        { "met", 60 }, { "mez", 60 }, { "mest", 120 }, { "mesz", 120 },
        { "eet", 120 }, { "eest", 180 }, { "cat", 120 }, { "sast", 120 },
        { "eat", 180 }, { "msk", 180 }, { "msd", 240 }, { "ist", 330 },
        { "sgt", 480 }, { "kst", 540 }, { "jst", 540 }, { "gst", 600 },
        { "nzst", 720 }, { "nzdt", 780 }
    };
    for (size_t i = 0; i < sizeof zones / sizeof zones[0]; i++)
        if (!strcmp (word, zones[i].name)) {
            *seconds = zones[i].minutes * 60L;
            return 0;
        }
    return -1;
}

/* A year written after a calendar date: "Mar 5, 2024" or "5 Mar 24".
   Takes the number only when it is not the hour of a time of day. */
static int
bd_take_year (const char **pp, long long *year, int *digits)
{
    const char *q = bd_skip_space (*pp);
    long long v;
    int d;
    if (bd_read_num (&q, &v, &d) < 0 || *q == ':' || *q == '.')
        return 0;
    *pp = q;
    *year = v;
    *digits = d;
    return 1;
}

/* GNU calendar-date, time-of-day, zone and day-of-week items in any order:
   "Mar 5 2024", "5 March 2024", "March 5, 2024", "03/05/2024", "5-Mar-2024",
   "Tue Mar  5 07:08:09 UTC 2024", "2024-03-05 07:08:09.5", "7:30 pm",
   "20240305 1230".  A missing date is NOW's, a missing time is midnight
   and a two-digit year is 1969-2068.  Relative items (and a day of the
   week without a date) are bd_parse_with_relative's. */
static int
bd_parse_items (const char *s, const struct timespec *now,
                time_t *out, long *nsec, int utc)
{
    long long year = -1, v;
    int year_digits = 0, mon = 0, day = 1, d;
    int hour = 0, min = 0, sec = 0, merid = 0;
    long frac = 0, zone = 0;
    int dates = 0, times = 0, zones = 0, wdays = 0, last_time = 0;
    const char *p = s;
    char word[16];

    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;
        if (!*p)
            break;
        int after_time = last_time;
        last_time = 0;

        if (bd_is_alpha (*p)) {
            if (!bd_read_word (&p, word, sizeof word))
                return -1;
            int m = bd_month_word (word);
            if (m >= 0) {
                /* Month D[, YEAR] or Month-D[-YEAR]; a month needs its day. */
                if (dates++)
                    return -1;
                mon = m;
                if (*p == '-' && p[1] >= '0' && p[1] <= '9') {
                    p++;
                    if (bd_read_num (&p, &v, &d) < 0) return -1;
                    day = (int) v;
                    if (*p == '-' && p[1] >= '0' && p[1] <= '9') {
                        p++;
                        if (bd_read_num (&p, &year, &year_digits) < 0) return -1;
                    }
                    continue;
                }
                p = bd_skip_space (p);
                if (bd_read_num (&p, &v, &d) < 0 || *p == ':' || d > 2)
                    return -1;
                day = (int) v;
                const char *q = bd_skip_space (p);
                if (*q == ',') {
                    q++;
                    if (bd_take_year (&q, &year, &year_digits))
                        p = q;
                }
                continue;
            }
            if (bd_weekday_word (word) >= 0) {
                wdays++;
                continue;
            }
            if (!strcmp (word, "am") || !strcmp (word, "pm")) {
                if (!after_time || merid)
                    return -1;
                merid = word[0] == 'a' ? 1 : 2;
                continue;
            }
            long z;
            if (bd_zone_word (word, &z) == 0) {
                if (zones++)
                    return -1;
                zone = z;
                continue;
            }
            return -1;
        }

        if ((*p == '+' || *p == '-') && p[1] >= '0' && p[1] <= '9') {
            /* A numeric zone right after a time: H, HH, HHMM or HH:MM. */
            int sign = *p == '-' ? -1 : 1;
            if (!after_time || zones++)
                return -1;
            p++;
            if (bd_read_num (&p, &v, &d) < 0) return -1;
            long hh = (long) v, mm = 0;
            if (*p == ':' && d <= 2) {
                p++;
                long long m2;
                int d2;
                if (bd_read_num (&p, &m2, &d2) < 0 || d2 != 2) return -1;
                mm = (long) m2;
            } else if (d == 3 || d == 4) {
                hh = (long) v / 100;
                mm = (long) v % 100;
            } else if (d > 4) {
                return -1;
            }
            if (hh > 24 || mm > 59)
                return -1;
            zone = sign * (hh * 3600 + mm * 60);
            continue;
        }

        if (*p < '0' || *p > '9')
            return -1;
        if (bd_read_num (&p, &v, &d) < 0)
            return -1;

        if (*p == ':') {                        /* HH:MM[:SS[.frac]] */
            long long m2, s2;
            int d2;
            if (times++)
                return -1;
            p++;
            if (d > 2 || bd_read_num (&p, &m2, &d2) < 0 || d2 > 2)
                return -1;
            hour = (int) v;
            min = (int) m2;
            sec = 0;
            frac = 0;
            if (*p == ':') {
                p++;
                if (bd_read_num (&p, &s2, &d2) < 0 || d2 > 2)
                    return -1;
                sec = (int) s2;
                if ((*p == '.' || *p == ',') && p[1] >= '0' && p[1] <= '9') {
                    int fd = 0;
                    for (p++; *p >= '0' && *p <= '9'; p++)
                        if (fd < 9) {
                            frac = frac * 10 + (*p - '0');
                            fd++;
                        }
                    while (fd++ < 9)
                        frac *= 10;
                }
            }
            last_time = 1;
            continue;
        }

        if (*p == '/') {                        /* M/D[/Y] or Y/M/D */
            long long b, c;
            int db, dc;
            if (dates++)
                return -1;
            p++;
            if (bd_read_num (&p, &b, &db) < 0)
                return -1;
            if (d >= 3) {
                if (*p != '/') return -1;
                p++;
                if (bd_read_num (&p, &c, &dc) < 0) return -1;
                year = v;
                year_digits = d;
                mon = (int) b - 1;
                day = (int) c;
            } else {
                mon = (int) v - 1;
                day = (int) b;
                if (*p == '/') {
                    p++;
                    if (bd_read_num (&p, &year, &year_digits) < 0) return -1;
                }
            }
            continue;
        }

        if (*p == '-' && p[1] >= '0' && p[1] <= '9') {   /* YYYY-MM-DD */
            long long b, c;
            int db, dc;
            if (dates++)
                return -1;
            p++;
            if (bd_read_num (&p, &b, &db) < 0 || *p != '-')
                return -1;
            p++;
            if (bd_read_num (&p, &c, &dc) < 0)
                return -1;
            year = v;
            year_digits = d;
            mon = (int) b - 1;
            day = (int) c;
            if ((*p == 'T' || *p == 't') && p[1] >= '0' && p[1] <= '9')
                p++;
            continue;
        }

        if (*p == '-' && bd_is_alpha (p[1])) {          /* D-Mon[-YEAR] */
            p++;
            if (!bd_read_word (&p, word, sizeof word))
                return -1;
            int m = bd_month_word (word);
            if (m < 0 || dates++)
                return -1;
            mon = m;
            day = (int) v;
            if (*p == '-' && p[1] >= '0' && p[1] <= '9') {
                p++;
                if (bd_read_num (&p, &year, &year_digits) < 0) return -1;
            }
            continue;
        }

        {                                               /* D Month [YEAR] */
            const char *q = bd_skip_space (p);
            if (bd_is_alpha (*q)) {
                const char *w = q;
                int m = bd_read_word (&w, word, sizeof word) ? bd_month_word (word) : -1;
                if (m >= 0) {
                    if (dates++ || d > 2)
                        return -1;
                    mon = m;
                    day = (int) v;
                    p = w;
                    bd_take_year (&p, &year, &year_digits);
                    continue;
                }
            }
        }

        /* A bare number, as GNU reads it: the year after a date, a
           YYYYMMDD date, or an hour (H, HH) or HHMM time of day. */
        if (dates && year < 0 && (times || d > 2)) {
            year = v;
            year_digits = d;
            continue;
        }
        if (d > 4) {
            if (dates++)
                return -1;
            day = (int) (v % 100);
            mon = (int) ((v / 100) % 100) - 1;
            year = v / 10000;
            year_digits = d - 4;
            continue;
        }
        if (times++)
            return -1;
        hour = (int) (d <= 2 ? v : v / 100);
        min = (int) (d <= 2 ? 0 : v % 100);
        sec = 0;
        frac = 0;
        last_time = 1;
    }

    if (wdays > 1 || (wdays && !dates))
        return -1;
    if (merid) {
        if (hour < 1 || hour > 12)
            return -1;
        hour = merid == 1 ? hour % 12 : hour % 12 + 12;
    }

    struct tm base;
    time_t nt = now->tv_sec;
    if (!((utc || zones) ? gmtime_r (&nt, &base) : localtime_r (&nt, &base)))
        return -1;
    if (!dates) {
        year = base.tm_year + 1900L;
        mon = base.tm_mon;
        day = base.tm_mday;
    } else if (year < 0) {
        year = base.tm_year + 1900L;
    } else if (year_digits <= 2) {
        year += year < 69 ? 2000 : 1900;
    }
    if (year > 100000000LL)
        return -1;

    struct tm t;
    memset (&t, 0, sizeof t);
    t.tm_year = (int) (year - 1900);
    t.tm_mon = mon;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_isdst = -1;
    if (bd_convert_tm (&t, utc || zones, out) < 0)
        return -1;
    *out -= (time_t) zone;
    *nsec = frac;
    return 0;
}

static int
bd_parse_d (const char *s, const struct timespec *now,
            time_t *out, long *nsec, int utc)
{
    *nsec = 0;
    if (!strcmp (s, "now")) {
        *out = now->tv_sec;
        *nsec = now->tv_nsec;
        return 0;
    }
    if (s[0] == '@') {
        char *end;
        errno = 0;
        long long ll = strtoll (s + 1, &end, 10);
        if (errno == ERANGE || end == s + 1) return -1;
        /* Store a floor second plus nonnegative nanoseconds. Negative
           fractions need a borrow, including -0 and sub-nanosecond input. */
        if (*end == '.') {
            const char *q = end + 1;
            int digits = 0, remainder = 0;
            if (*q < '0' || *q > '9') return -1;
            while (*q >= '0' && *q <= '9') {
                if (digits < 9) {
                    *nsec = *nsec * 10 + (*q - '0');
                    digits++;
                } else if (*q != '0') remainder = 1;
                q++;
            }
            if (*q != '\0') return -1;
            while (digits++ < 9) *nsec *= 10;
            const char *sign = s + 1;
            while (*sign == ' ' || *sign == '\t') sign++;
            if (*sign == '-' && (*nsec || remainder)) {
                if (ll == LLONG_MIN) return -1;
                ll--;
                *nsec = 1000000000L - *nsec - remainder;
            }
        } else if (*end != '\0') {
            return -1;
        }
        *out = (time_t) ll;
        if ((long long) *out != ll) return -1;
        return 0;
    }
    if (bd_parse_rfc_lenient (s, out) == 0)
        return 0;
    struct tm t;
    memset (&t, 0, sizeof t);
    t.tm_isdst = -1;
    const char *fmts[] = {
        "%a, %d %b %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%MZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H",
        "%Y-%m-%d %H",
        "%Y%m%d",
        "%Y-%m-%d",
        NULL
    };
    /* Slash dates (Y/M/D and GNU's M/D/Y) are bd_parse_items'. */
    const int fmt_zulu[] = { 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 };
    const int fmt_terminal_ok[] = { 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1 };
    for (int i = 0; fmts[i]; i++) {
        char *e = strptime (s, fmts[i], &t);
        if (e && fmt_terminal_ok[i] && (*e == '\0' || (*e == 'Z' && e[1] == '\0')
            || strcmp (e, " UTC") == 0)) {
            int zulu = (*e == 'Z') || strcmp (e, " UTC") == 0 || fmt_zulu[i];
            return bd_convert_tm (&t, zulu || utc, out);
        }
        if (e && i < 9) {
            while (*e == ' ' || *e == '\t') e++;
        }
        if (e && i < 9 && (*e == '+' || *e == '-')) {
            long offset;
            if (bd_parse_tz_offset (e, &offset) == 0) {
                if (bd_convert_tm (&t, 1, out) < 0) return -1;
                *out -= (time_t) offset;
                return 0;
            }
        }
        memset (&t, 0, sizeof t);
        t.tm_isdst = -1;
    }
    return bd_parse_items (s, now, out, nsec, utc);
}

/* The whole -d grammar: an absolute date, relative items alone, or an
   absolute date followed by relative items, all against base time NOW. */
static int
bd_parse_date (const char *s, const struct timespec *now,
               time_t *out, long *nsec, int utc)
{
    if (bd_parse_d (s, now, out, nsec, utc) == 0)
        return 0;
    return bd_parse_with_relative (s, now, out, nsec, utc);
}

#endif
