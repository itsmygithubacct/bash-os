/* bashdate.c — POSIX date(1) as a bash builtin.
 *
 *   bashdate [-u] [-d STRING|-f FILE|-r FILE] [-I[FMT]|--iso-8601[=FMT]]
 *            [--rfc-3339=FMT] [+FORMAT]
 *   bashdate [-u] -s STRING|--set=STRING [+FORMAT]
 *   bashdate [-u] MMDDhhmm[[CC]YY][.ss]
 *
 *   -u           use UTC (gmtime instead of localtime)
 *   -s STRING    set the system clock to STRING (same shapes as -d), then
 *   --set=STRING print that time; a refused request is diagnosed, the time
 *                is still printed and the status is 1
 *   MMDDhhmm[[CC]YY][.ss]
 *                POSIX form of the same request; a two-digit year 00-68 is
 *                20YY and 69-99 is 19YY
 *   -d STRING    parse STRING (the GNU date-string items below) instead
 *   --date=STRING
 *                of the current time
 *   -f FILE, --file=FILE
 *                like -d once per line of FILE ("-" is standard input)
 *   -I[FMT], --iso-8601[=FMT]
 *                GNU ISO-8601 output forms: date, hours, minutes, seconds, ns.
 *   --rfc-3339=FMT
 *                GNU RFC 3339 output forms: date, seconds, ns.
 *   +FORMAT      strftime(3) format plus GNU %N, %q and %:z/%::z/%:::z forms.
 *                Default: %a %b %e %T %Z %Y
 *
 * Closes the POSIX-2024 medium-impact gap (POSIX-CONFORMANCE-RESEARCH
 * §4.1: bashclock has time underpinnings but no date(1) shape).
 *
 * The -d parser (common/date-parse.h, shared with touch -d) accepts:
 *   YYYY-MM-DDTHH[:MM[:SS[.FRAC]]][Z|+HH:MM|-HHMM]
 *                              (ISO 8601 with optional zone)
 *   YYYY-MM-DD HH[:MM[:SS[.FRAC]]]   (separator space variant)
 *   [DAY[,]] D Mon YYYY HH:MM:SS UTC|GMT|+HHMM|-HH:MM
 *                              (RFC/email timestamp)
 *   Mon D[, YYYY], D Mon [YYYY], D-Mon-YYYY, MM/DD[/YY[YY]], YYYY/MM/DD,
 *   YYYYMMDD                  (calendar dates; no year = this year)
 *   H[H][:MM[:SS[.FRAC]]] [am|pm] [UTC|GMT|EST|...|+HHMM]
 *                              (time of day, in any order with the date;
 *                               no time = 00:00:00, no date = today)
 *   ZONE[+-]HH[[:]MM]         (a zone plus an offset: UTC+3, UTC-0500)
 *   TZ="ZONE" STRING          (STRING read in time zone ZONE)
 *   @SECONDS[.FRAC]           (epoch seconds — useful for scripts)
 *   now, today, yesterday, tomorrow, [+-]N UNIT [ago], next/last UNIT,
 *   a day of the week         (GNU relative items, alone or after a date)
 * Unsupported formats return failure.
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
#include <limits.h>
#include <time.h>
#include <sys/stat.h>

#include "loadables.h"
#include "shim-prog-name.h"

#include "date-parse.h"


static long
bd_tm_offset (const struct tm *tm, time_t t, int utc)
{
    struct tm copy;

    if (utc)
        return 0;
    copy = *tm;
    return (long) (timegm (&copy) - t);
}

static void
bd_format_offset (long offset, int colons, char *out, size_t outsz)
{
    char sign = '+';
    long hh, mm, ss;

    if (offset < 0) {
        sign = '-';
        offset = -offset;
    }
    hh = offset / 3600;
    mm = (offset / 60) % 60;
    ss = offset % 60;

    if (colons == 1)
        snprintf (out, outsz, "%c%02ld:%02ld", sign, hh, mm);
    else if (colons == 2)
        snprintf (out, outsz, "%c%02ld:%02ld:%02ld", sign, hh, mm, ss);
    else if (ss != 0)
        snprintf (out, outsz, "%c%02ld:%02ld:%02ld", sign, hh, mm, ss);
    else if (mm != 0)
        snprintf (out, outsz, "%c%02ld:%02ld", sign, hh, mm);
    else
        snprintf (out, outsz, "%c%02ld", sign, hh);
}

/* Append `n` bytes of `src` to a growable buffer (*out, *cap, *j). Returns
   0 on success, -1 on OOM (caller frees *out). Always leaves room for a
   trailing NUL. */
static int
bd_buf_append (char **out, size_t *cap, size_t *j, const char *src, size_t n)
{
    if (*j + n + 1 > *cap) {
        size_t ncap = *cap * 2 + n + 16;
        char *nb = realloc (*out, ncap);
        if (!nb)
            return -1;
        *out = nb;
        *cap = ncap;
    }
    memcpy (*out + *j, src, n);
    *j += n;
    return 0;
}

/* Append `src` with any '%' doubled to '%%' so a later strftime pass treats
   it as literal text. Rendered date text never contains '%' but we stay
   defensive. */
static int
bd_buf_append_literal (char **out, size_t *cap, size_t *j, const char *src)
{
    for (const char *p = src; *p; p++) {
        char c = *p;
        if (bd_buf_append (out, cap, j, &c, 1) < 0)
            return -1;
        if (c == '%' && bd_buf_append (out, cap, j, &c, 1) < 0)
            return -1;
    }
    return 0;
}

/* Render a single bare "%<spec>" (spec is one strftime conversion char) for
   the given tm into `dst`. */
static void
bd_strftime_one (char spec, const struct tm *tm, char *dst, size_t dstsz)
{
    char one_fmt[3] = { '%', spec, '\0' };
    if (strftime (dst, dstsz, one_fmt, tm) == 0)
        dst[0] = '\0';
}

static char *
bd_expand_gnu_tz_formats (const char *fmt, const struct tm *tm, time_t t, long nsec, int utc)
{
    size_t len = strlen (fmt);
    size_t cap = len * 3 + 32;
    char *out = malloc (cap);
    size_t i, j = 0;
    long offset = bd_tm_offset (tm, t, utc);

    if (!out)
        return NULL;

    for (i = 0; i < len; i++) {
        if (fmt[i] != '%') {
            if (bd_buf_append (&out, &cap, &j, &fmt[i], 1) < 0) {
                free (out);
                return NULL;
            }
            continue;
        }

        /* fmt[i] == '%'. Handle the GNU %:z / %::z / %:::z timezone forms
           first (colons sit between '%' and 'z', not a flag/width run). */
        if (i + 2 < len && fmt[i + 1] == ':' &&
            (fmt[i + 2] == 'z' ||
             (i + 3 < len && fmt[i + 2] == ':' && fmt[i + 3] == 'z') ||
             (i + 4 < len && fmt[i + 2] == ':' && fmt[i + 3] == ':' && fmt[i + 4] == 'z'))) {
            char zbuf[16];
            int colons = 1;
            if (fmt[i + 2] == ':' && fmt[i + 3] == ':')
                colons = 3;
            else if (fmt[i + 2] == ':')
                colons = 2;
            bd_format_offset (offset, colons, zbuf, sizeof zbuf);
            if (bd_buf_append (&out, &cap, &j, zbuf, strlen (zbuf)) < 0) {
                free (out);
                return NULL;
            }
            i += (size_t) colons + 1;
            continue;
        }

        /* General GNU shape: %[flags][width]<spec>. Scan the optional flag
           run ('-' '_' '0' '^' '#') and the optional decimal width. We
           remember the first case-fold flag seen and whether a '0' flag was
           present, then dispatch on the final spec char. */
        size_t k = i + 1;
        int casefold = 0;       /* 0 none, '^' upper, '#' swapcase */
        int zero_flag = 0;
        int minus_flag = 0;     /* '-' => suppress padding */
        while (k < len &&
               (fmt[k] == '-' || fmt[k] == '_' || fmt[k] == '0' ||
                fmt[k] == '^' || fmt[k] == '#')) {
            if (fmt[k] == '^' || fmt[k] == '#') {
                if (!casefold) casefold = fmt[k];
            } else if (fmt[k] == '0') {
                zero_flag = 1;
            } else if (fmt[k] == '-') {
                minus_flag = 1;
            }
            k++;
        }
        size_t width_start = k;
        while (k < len && fmt[k] >= '0' && fmt[k] <= '9')
            k++;
        size_t width = (width_start < k)
            ? (size_t) strtoul (fmt + width_start, NULL, 10) : 0;
        char spec = (k < len) ? fmt[k] : '\0';
        int have_flags = (k > i + 1);   /* anything between '%' and spec */

        /* Sub-second precision: %N (9 digits) or a requested prefix. */
        if (spec == 'N') {
            /* width digits present and > 0 => that many; otherwise bare %N
               which GNU treats as 9-digit nanoseconds. */
            size_t digits = (width_start < k && width > 0) ? width : 9;
            if (digits > 9) digits = 9;
            char nbuf[10];
            snprintf (nbuf, sizeof nbuf, "%09ld", nsec);
            nbuf[digits] = '\0';
            if (bd_buf_append (&out, &cap, &j, nbuf, digits) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* GNU %q: the quarter of the year, 1-4, a number padded with '0'
           to an explicit width ('_' pads with spaces, '-' not at all). */
        if (spec == 'q') {
            char qbuf[32];
            int q = tm->tm_mon / 3 + 1;
            int w = (width_start < k && width > 0) ? (int) width : 1;
            int space_flag = 0;
            for (size_t f = i + 1; f < width_start; f++)
                if (fmt[f] == '_') space_flag = 1;
            if (minus_flag)
                snprintf (qbuf, sizeof qbuf, "%d", q);
            else if (space_flag && !zero_flag)
                snprintf (qbuf, sizeof qbuf, "%*d", w, q);
            else
                snprintf (qbuf, sizeof qbuf, "%0*d", w, q);
            if (bd_buf_append_literal (&out, &cap, &j, qbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (a2) Epoch seconds %s: GNU date emits the actual time_t, NOT
           strftime's %s — glibc/musl derive %s from the broken-down tm via
           mktime(), which is wrong for a UTC-filled tm under -u (it adds the
           local UTC offset). Emit t directly; honor -/0/width like %k/%l. */
        if (spec == 's') {
            char sbuf[32];
            int w = (width_start < k && width > 0) ? (int) width : 0;
            if (minus_flag || w == 0)
                snprintf (sbuf, sizeof sbuf, "%lld", (long long) t);
            else if (zero_flag)
                snprintf (sbuf, sizeof sbuf, "%0*lld", w, (long long) t);
            else
                snprintf (sbuf, sizeof sbuf, "%*lld", w, (long long) t);
            if (bd_buf_append_literal (&out, &cap, &j, sbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (a3) %Z under -u: GNU date prints "UTC" (it operates in the UTC
           zone). gmtime() yields tm_zone "GMT" on glibc (musl gives "UTC"),
           so emit "UTC" explicitly to match GNU independently of the host
           libc. Without -u, strftime's local zone name is correct. */
        if (spec == 'Z' && utc && !have_flags) {
            if (bd_buf_append_literal (&out, &cap, &j, "UTC") < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (b) Case-fold flags %^X / %#X on textual specs: musl strftime
           ignores '^'/'#', so render the bare spec then transform here.
           '^' is uppercase. '#' is GNU's "opposite case": uppercase for
           the names %a %A %b %B %h, lowercase for %p and %Z ("pm",
           "utc"), no change elsewhere; %P stays lowercase under either.
           %Z under -u is "UTC" as in (a3). */
        if (casefold && spec) {
            char tbuf[256];
            if (spec == 'Z' && utc)
                snprintf (tbuf, sizeof tbuf, "UTC");
            else
                bd_strftime_one (spec == 'P' ? 'p' : spec, tm, tbuf, sizeof tbuf);   /* musl lacks %P */
            int mode = spec == 'P' ? 'L'          /* GNU: %^P and %#P are "pm" */
                     : casefold == '^' ? 'U'
                     : strchr ("aAbBh", spec) ? 'U'
                     : strchr ("pPZ", spec) ? 'L' : 0;
            for (char *p = tbuf; *p; p++) {
                unsigned char c = (unsigned char) *p;
                if (mode == 'U' && c >= 'a' && c <= 'z') *p = (char) (c - 32);
                else if (mode == 'L' && c >= 'A' && c <= 'Z') *p = (char) (c + 32);
            }
            if (bd_buf_append_literal (&out, &cap, &j, tbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (b2) Lowercase meridian %P: musl strftime does not implement it
           (returns empty). Render %p (uppercase AM/PM, which musl supports)
           and lowercase the result. */
        if (spec == 'P' && !casefold) {
            char pbuf[16];
            bd_strftime_one ('p', tm, pbuf, sizeof pbuf);
            for (char *p = pbuf; *p; p++)
                if (*p >= 'A' && *p <= 'Z') *p = (char) (*p + 32);
            if (bd_buf_append_literal (&out, &cap, &j, pbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (c) Hour specs %k (24h) and %l (12h): musl strftime does NOT
           implement them at all (it returns an empty string), so compute
           the value from tm here. GNU defaults to field width 2, space
           padded; the '0' flag zero-pads, the '-' flag suppresses padding,
           and an explicit width overrides the default 2. */
        if (spec == 'k' || spec == 'l') {
            int h = tm->tm_hour;
            if (spec == 'l') { h %= 12; if (h == 0) h = 12; }
            int w = (width_start < k && width > 0) ? (int) width : 2;
            char hbuf[32];
            if (minus_flag)
                snprintf (hbuf, sizeof hbuf, "%d", h);
            else if (zero_flag)
                snprintf (hbuf, sizeof hbuf, "%0*d", w, h);
            else
                snprintf (hbuf, sizeof hbuf, "%*d", w, h);
            if (bd_buf_append_literal (&out, &cap, &j, hbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* Fallback: copy the whole "%[flags][width]spec" verbatim so the
           later strftime pass handles already-working specs (%-d, %_d, %0d,
           %0e, plain %B, etc.) exactly as before. */
        (void) have_flags;
        {
            size_t runlen = (spec ? (k - i + 1) : (k - i));
            if (bd_buf_append (&out, &cap, &j, fmt + i, runlen) < 0) {
                free (out);
                return NULL;
            }
            i += runlen - 1;
        }
    }
    out[j] = '\0';
    return out;
}

/* GNU argmatch: WORD is one of NAMES or an unambiguous prefix of one.
   Returns the index or -1. */
static int
bd_argmatch (const char *word, const char *const *names)
{
    size_t n = strlen (word);
    int found = -1;
    if (!n)
        return -1;
    for (int i = 0; names[i]; i++) {
        if (!strcmp (word, names[i]))
            return i;
        if (!strncmp (word, names[i], n)) {
            if (found >= 0)
                return -1;
            found = i;
        }
    }
    return found;
}

static const char *
bd_iso8601_format (const char *level)
{
    static const char *const names[] = {
        "date", "hours", "minutes", "seconds", "ns", NULL
    };
    static const char *const fmts[] = {
        "%Y-%m-%d", "%Y-%m-%dT%H%:z", "%Y-%m-%dT%H:%M%:z",
        "%Y-%m-%dT%H:%M:%S%:z", "%Y-%m-%dT%H:%M:%S,%N%:z"
    };
    if (level == NULL || *level == '\0')
        return fmts[0];
    int i = bd_argmatch (level, names);
    return i < 0 ? NULL : fmts[i];
}

static const char *
bd_rfc3339_format (const char *level)
{
    static const char *const names[] = { "date", "seconds", "ns", NULL };
    static const char *const fmts[] = {
        "%Y-%m-%d", "%Y-%m-%d %H:%M:%S%:z", "%Y-%m-%d %H:%M:%S.%N%:z"
    };
    int i = bd_argmatch (level, names);
    return i < 0 ? NULL : fmts[i];
}

/* The POSIX clock-setting operand MMDDhhmm[[CC]YY][.ss]. A missing year is
   the current one; 00-68 means 2000-2068 and 69-99 means 1969-1999. Fields
   that do not name a real instant are rejected; seconds 60 is the second
   after :59, as POSIX requires. */
static int
bd_parse_posix_set (const char *s, int utc, time_t *out)
{
    const char *dot = strchr (s, '.');
    size_t digits = dot ? (size_t) (dot - s) : strlen (s);
    int pair[6], sec = 0, leap = 0;
    struct tm t;

    if (digits != 8 && digits != 10 && digits != 12)
        return -1;
    for (size_t i = 0; i < digits; i++)
        if (s[i] < '0' || s[i] > '9')
            return -1;
    for (size_t i = 0; i < digits / 2; i++)
        pair[i] = (s[2 * i] - '0') * 10 + (s[2 * i + 1] - '0');
    if (dot) {
        if (dot[1] < '0' || dot[1] > '9' || dot[2] < '0' || dot[2] > '9' || dot[3] != '\0')
            return -1;
        sec = (dot[1] - '0') * 10 + (dot[2] - '0');
        if (sec == 60) {
            sec = 59;
            leap = 1;
        }
    }

    memset (&t, 0, sizeof t);
    if (digits == 8) {
        time_t now = time (NULL);
        struct tm cur;
        if (!(utc ? gmtime_r (&now, &cur) : localtime_r (&now, &cur)))
            return -1;
        t.tm_year = cur.tm_year;
    } else if (digits == 10)
        t.tm_year = pair[4] <= 68 ? pair[4] + 100 : pair[4];
    else
        t.tm_year = pair[4] * 100 + pair[5] - 1900;
    t.tm_mon = pair[0] - 1;
    t.tm_mday = pair[1];
    t.tm_hour = pair[2];
    t.tm_min = pair[3];
    t.tm_sec = sec;
    t.tm_isdst = -1;
    if (bd_convert_tm (&t, utc, out) < 0)
        return -1;
    *out += leap;
    return 0;
}

/* Print T (+NSEC) in FMT on one line.  Returns -1 after a diagnostic. */
static int
bd_print (time_t t, long nsec, const char *fmt, int utc)
{
    struct tm tm;
    if (!(utc ? gmtime_r (&t, &tm) : localtime_r (&t, &tm))) {
        builtin_error ("date out of range");
        return -1;
    }

    char buf[256];
    char *expanded_fmt = bd_expand_gnu_tz_formats (fmt, &tm, t, nsec, utc);
    if (!expanded_fmt) {
        builtin_error ("out of memory");
        return -1;
    }
    if (strftime (buf, sizeof buf, expanded_fmt, &tm) == 0) {
        /* Empty result is allowed (e.g. `+`); but if buf overflowed,
           strftime returned 0 with undefined contents — we conservatively
           print empty in that case. */
        buf[0] = '\0';
    }
    free (expanded_fmt);
    puts (buf);
    return 0;
}

/* GNU date -f FILE: parse each line as -d would and print it; a line that
   does not parse is diagnosed, the rest still print, and the status is 1. */
static int
bd_batch (const char *path, const char *fmt, int utc)
{
    int is_stdin = !strcmp (path, "-");
    FILE *fp;
    if (is_stdin) {
        int fd = dup (0);
        fp = fd < 0 ? NULL : fdopen (fd, "r");
        if (!fp && fd >= 0)
            close (fd);
    } else {
        fp = fopen (path, "r");
    }
    if (!fp) {
        fprintf (stderr, "date: %s: %s\n", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    int rc = EXECUTION_SUCCESS;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline (&line, &cap, fp)) >= 0) {
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        struct timespec now;
        time_t t;
        long nsec;
        if (clock_gettime (CLOCK_REALTIME, &now) < 0 ||
            bd_parse_date (line, &now, &t, &nsec, utc) < 0) {
            fflush (stdout);
            fprintf (stderr, "date: invalid date '%s'\n", line);
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (bd_print (t, nsec, fmt, utc) < 0)
            rc = EXECUTION_FAILURE;
    }
    if (ferror (fp)) {
        fprintf (stderr, "date: %s: %s\n", path, strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    free (line);
    fclose (fp);
    return rc;
}

int
date_builtin (WORD_LIST *list)
{
    int utc = 0;
    int set_clock = 0, set_failed = 0;
    const char *set_str = NULL;
    const char *posix_str = NULL;
    const char *date_str = NULL;
    const char *ref_file = NULL;
    const char *batch_file = NULL;
    const char *fmt = NULL;
    const char *iso_fmt = NULL;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashdate 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-u") || !strcmp (w, "--utc")) {
            utc = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-R") || !strcmp (w, "--rfc-email")) {
            /* RFC 5322 date, C-locale equivalent of
               "+%a, %d %b %Y %H:%M:%S %z". */
            fmt = "%a, %d %b %Y %H:%M:%S %z";
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-I") || !strcmp (w, "--iso-8601")) {
            iso_fmt = bd_iso8601_format ("date");
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-I", 2) && w[2]) {
            iso_fmt = bd_iso8601_format (w + 2);
            if (!iso_fmt) {
                builtin_error ("invalid ISO-8601 timespec: %s", w + 2);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--iso-8601=", 11)) {
            iso_fmt = bd_iso8601_format (w + 11);
            if (!iso_fmt) {
                builtin_error ("invalid ISO-8601 timespec: %s", w + 11);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--rfc-3339")) {
            builtin_error ("--rfc-3339 needs TIMESPEC");
            builtin_usage ();
            return EXECUTION_FAILURE;
        }
        if (!strncmp (w, "--rfc-3339=", 11)) {
            iso_fmt = bd_rfc3339_format (w + 11);
            if (!iso_fmt) {
                builtin_error ("invalid RFC 3339 timespec: %s", w + 11);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-d") || !strcmp (w, "--date")) {
            if (!list->next) {
                bos_shim_missing_arg (w, w[1], "date");
                return EXECUTION_FAILURE;
            }
            list = list->next;
            date_str = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--date=", 7)) {
            if (w[7] == '\0') {
                builtin_error ("--date needs STRING");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            date_str = w + 7;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-d", 2) && w[2]) {
            date_str = w + 2;
            list = list->next;
            continue;
        }
        /* -r FILE: the modification time of FILE (GNU). */
        if (!strcmp (w, "-r") || !strcmp (w, "--reference")) {
            if (!list->next) {
                fprintf (stderr, "date: option requires an argument -- 'r'\n");
                return EXECUTION_FAILURE;
            }
            list = list->next;
            ref_file = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--reference=", 12)) {
            ref_file = w + 12;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-r", 2) && w[2]) {
            ref_file = w + 2;
            list = list->next;
            continue;
        }
        /* -f FILE: like -d once per line of FILE ("-" is stdin). */
        if (!strcmp (w, "-f") || !strcmp (w, "--file")) {
            if (!list->next) {
                fprintf (stderr, "date: option requires an argument -- 'f'\n");
                return EXECUTION_FAILURE;
            }
            list = list->next;
            batch_file = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--file=", 7)) {
            batch_file = w + 7;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-f", 2) && w[2]) {
            batch_file = w + 2;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s") || !strcmp (w, "--set")) {
            if (!list->next) {
                bos_shim_missing_arg (w, w[1], "date");
                return EXECUTION_FAILURE;
            }
            list = list->next;
            set_str = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--set=", 6)) {
            set_str = w + 6;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-s", 2) && w[2]) {
            set_str = w + 2;
            list = list->next;
            continue;
        }
        /* One operand at most, as GNU: +FORMAT or the POSIX set form. */
        if (w[0] != '-' && (fmt || posix_str)) {
            fprintf (stderr, "date: extra operand '%s'\nTry 'date --help' for more information.\n", w);
            return EXECUTION_FAILURE;
        }
        if (w[0] == '+') {
            fmt = w + 1;
            list = list->next;
            continue;
        }
        if (w[0] != '-') {
            posix_str = w;
            list = list->next;
            continue;
        }
        bos_shim_bad_option (w, w[1], "date");
        return EXECUTION_FAILURE;
    }
    /* Words after "--" are operands: a format or the POSIX set form. */
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (fmt || posix_str) {
            fprintf (stderr, "date: extra operand '%s'\nTry 'date --help' for more information.\n", w);
            return EXECUTION_FAILURE;
        }
        if (w[0] == '+')
            fmt = w + 1;
        else
            posix_str = w;
    }
    if ((ref_file != NULL) + (date_str != NULL) + (batch_file != NULL) > 1) {
        fprintf (stderr, "date: the options to specify dates for printing are mutually exclusive\n");
        return EXECUTION_FAILURE;
    }
    if (set_str && (date_str || ref_file || batch_file)) {
        fprintf (stderr, "date: the options to print and set the time may not be used together\n");
        return EXECUTION_FAILURE;
    }
    if (posix_str && (set_str || date_str || ref_file || batch_file)) {
        fprintf (stderr, "date: the argument '%s' lacks a leading '+';\n"
                 "when using an option to specify date(s), any non-option\n"
                 "argument must be a format string beginning with '+'\n", posix_str);
        return EXECUTION_FAILURE;
    }

    const char *use_fmt = fmt ? fmt : (iso_fmt ? iso_fmt : "%a %b %e %T %Z %Y");
    struct timespec now;
    if (clock_gettime (CLOCK_REALTIME, &now) < 0) {
        builtin_error ("clock_gettime: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (batch_file)
        return bd_batch (batch_file, use_fmt, utc);

    time_t t;
    long nsec;
    if (set_str) {
        if (bd_parse_date (set_str, &now, &t, &nsec, utc) < 0) {
            fprintf (stderr, "date: invalid date '%s'\n", set_str);
            return EXECUTION_FAILURE;
        }
        set_clock = 1;
    } else if (posix_str) {
        if (bd_parse_posix_set (posix_str, utc, &t) < 0) {
            fprintf (stderr, "date: invalid date '%s'\n", posix_str);
            return EXECUTION_FAILURE;
        }
        nsec = 0;
        set_clock = 1;
    } else if (ref_file) {
        struct stat st;
        if (stat (ref_file, &st) < 0) {
            fprintf (stderr, "date: %s: %s\n", ref_file, strerror (errno));
            return EXECUTION_FAILURE;
        }
        t = st.st_mtim.tv_sec;
        nsec = st.st_mtim.tv_nsec;
    } else if (date_str) {
        if (bd_parse_date (date_str, &now, &t, &nsec, utc) < 0) {
            fprintf (stderr, "date: invalid date '%s'\n", date_str);
            return EXECUTION_FAILURE;
        }
    } else {
        t = now.tv_sec;
        nsec = now.tv_nsec;
    }

    /* Like GNU date: request the change, then print the requested time
       whether or not the kernel accepted it. */
    if (set_clock) {
        struct timespec when;
        when.tv_sec = t;
        when.tv_nsec = nsec;
        if (clock_settime (CLOCK_REALTIME, &when) != 0) {
            fprintf (stderr, "date: cannot set date: %s\n", strerror (errno));
            set_failed = 1;
        }
    }

    if (bd_print (t, nsec, use_fmt, utc) < 0)
        return EXECUTION_FAILURE;
    return set_failed ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *date_doc[] = {
    "Print the date or convert a timestamp (POSIX date).",
    "",
    "    bashdate [-u] [-d STRING|-f FILE|-r FILE] [-I[FMT]|--iso-8601[=FMT]] [--rfc-3339=FMT] [+FORMAT]",
    "    bashdate [-u] -s STRING|--set=STRING [+FORMAT]",
    "    bashdate [-u] MMDDhhmm[[CC]YY][.ss]",
    "    bashdate --help | --version",
    "",
    "    -u           UTC instead of local time",
    "    -s STRING, --set=STRING",
    "                 set the system clock to STRING (the -d shapes), then",
    "                 print that time; a refused request is diagnosed, the",
    "                 time is still printed and the status is 1",
    "    MMDDhhmm[[CC]YY][.ss]",
    "                 POSIX form of the same request; YY 00-68 is 20YY,",
    "                 69-99 is 19YY, no year is the current year",
    "    -R, --rfc-email",
    "                 RFC 5322 date (%a, %d %b %Y %H:%M:%S %z in C locale)",
    "    -r FILE, --reference=FILE",
    "                 print the last modification time of FILE",
    "    -d STRING, --date=STRING",
    "                 parse STRING; accepted shapes:",
    "                   YYYY-MM-DD[THH[:MM[:SS[.FRAC]]]][Z|+HH:MM|-HHMM]",
    "                   YYYY-MM-DD HH[:MM[:SS[.FRAC]]]",
    "                   [DAY[,]] D Mon YYYY HH:MM:SS UTC|GMT|+HHMM|-HH:MM",
    "                   Mon D[, YYYY]  D Mon [YYYY]  D-Mon-YYYY  MM/DD[/YYYY]",
    "                   H[H][:MM[:SS[.FRAC]]] [am|pm] [ZONE], with or without a date",
    "                   @SECONDS[.FRAC]          (epoch)",
    "                   now, yesterday, [+-]N UNIT [ago], next/last DAY or UNIT,",
    "                   alone or after a date (\"2024-03-05 +1 month\")",
    "                   a zone with an offset: UTC+3, UTC-0500, UTC+05:30",
    "                   TZ=\"ZONE\" first: the rest is read in time zone ZONE",
    "    -f FILE, --file=FILE",
    "                 like -d for each line of FILE (- is standard input)",
    "    -I[FMT], --iso-8601[=FMT]",
    "                 print GNU ISO-8601 form; FMT is date, hours, minutes, seconds, ns",
    "    --rfc-3339=FMT",
    "                 print GNU RFC 3339 form; FMT is date, seconds, ns",
    "    +FORMAT      strftime(3) format plus GNU %N / %[1-9]N, %q, %:z/%::z/%:::z,",
    "                 case-fold %^X/%#X, and zero-padded %0k/%0l forms",
    "                 Default: %a %b %e %T %Z %Y",
    (char *)NULL
};

struct builtin bashdate_struct = {
    "bashdate",
    date_builtin,
    BUILTIN_ENABLED,
    date_doc,
    "bashdate [-u] [-d STRING|-f FILE|-r FILE] [-I[FMT]|--iso-8601[=FMT]] [--rfc-3339=FMT] [+FORMAT]",
    0
};
