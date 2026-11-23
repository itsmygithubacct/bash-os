/* SPDX-License-Identifier: MIT */
/* cal.c — cal(1) calendar display. Loadable for bash.
 *
 * util-linux's misc-utils/cal.c and BusyBox's util-linux/cal.c both
 * implement the same "print one month, one year, or one Julian-day
 * variant" surface; cal ships the same minimal contract as a bash
 * builtin so bash-os doesn't need a separate cal binary on PATH.
 *
 * Verbs:
 *     cal                       # current month (Gregorian, Sunday-first)
 *     cal YYYY | -y YYYY        # full year (12 months, 3 columns)
 *     cal MM YYYY               # specific month
 *     cal -j ...                # Julian day-of-year mode
 *     cal -m ...                # Monday-first week
 *     cal -w ...                # util-linux week numbers (see below)
 *     cal -3 | -A N | -B N ...  # month spans
 *     cal -h | --help           # usage
 *
 * Output shape (default mode):
 *     22-char-wide month grid; 2-char day cells with single space
 *     separators; centered "<MonthName> <YYYY>" title; Sunday-first
 *     header "Su Mo Tu We Th Fr Sa". `-m` rotates to "Mo Tu ... Su".
 *
 * Output shape (-j Julian):
 *     29-char-wide month grid; 3-char day-of-year cells with single
 *     space separators; 2-letter padded " Su  Mo ..." header. Day-of-year
 *     accounts for leap-February.
 *
 * Week numbers (-w, --week[=N]):
 *     util-linux cal's horizontal layout: each week row starts with its
 *     two-digit number and a space, months are 23 columns (30 with -j,
 *     whose headings are "Sun Mon ...") with six week rows, month titles
 *     are "Month YYYY" (a year view prints the year once, centered, and
 *     uses three-space gutters), and nothing is right-trimmed. Sunday-
 *     first weeks use US numbering (week 1 holds January 1); -m uses ISO
 *     8601 numbering (week 1 holds the first Thursday). Week numbers in
 *     the 1752 reform year count the eleven omitted days out, as
 *     util-linux does.
 *
 * Errors:
 *     A month outside 1..12 or a year outside 1..9999 prints util-linux's
 *     "illegal month value: use 1-12" / "illegal year value: use 1-9999"
 *     and exits 1; option errors keep Bash's usage status (2).
 *
 * Year mode:
 *     Non-Julian year output follows util-linux's horizontal
 *     three-column layout. Julian year output uses util-linux's
 *     two-column layout.
 *
 * Calendar model:
 *     Gregorian calendar with util-linux-compatible British 1752
 *     reformation handling: September 3..13, 1752 are omitted. Dates
 *     before the cutover use Julian day-of-week arithmetic. Acceptable
 *     year range: 1..9999.
 *
 * Source counterparts:
 *     research/refs/util-linux/misc-utils/cal.c   (canonical)
 *     research/refs/busybox/util-linux/cal.c
 *
 * Companion wrapper:
 *     /bash-os/cal.sh    (POSIX command-name shim — forwards to builtin
 *                         if loaded, falls back to pure-bash impl).
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "loadables.h"

static const int bc_days_in_month[] = {
    0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static const char *bc_month_names[] = {
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

static int bc_days_this_month (int m, int y);

static int
bc_is_leap (int y)
{
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

/* Zeller's congruence, Gregorian. Returns 0=Sun..6=Sat for the 1st
   of m/y. Treats Jan/Feb as months 13/14 of (y-1). */
static int
bc_dow_of_first (int m, int y)
{
    int q = 1;
    if (m < 3) { m += 12; y -= 1; }
    int K = y % 100;
    int J = y / 100;
    int h = (q + (13 * (m + 1)) / 5 + K + K / 4 + J / 4 - 2 * J) % 7;
    if (h < 0) h += 7;
    /* Zeller's 0=Saturday → shift so 0=Sunday. */
    return (h + 6) % 7;
}

static int
bc_julian_dow (int d, int m, int y)
{
    int a = (14 - m) / 12;
    int yy = y + 4800 - a;
    int mm = m + 12 * a - 3;
    long jdn = d + (153 * mm + 2) / 5 + 365L * yy + yy / 4 - 32083;

    return (int) ((jdn + 1) % 7);
}

static long
bc_gregorian_jdn (int d, int m, int y)
{
    int a = (14 - m) / 12;
    int yy = y + 4800 - a;
    int mm = m + 12 * a - 3;

    return d + (153 * mm + 2) / 5 + 365L * yy + yy / 4 - yy / 100
           + yy / 400 - 32045;
}

static int
bc_gregorian_dow (int d, int m, int y)
{
    return (int) ((bc_gregorian_jdn (d, m, y) + 1) % 7);
}

static int
bc_reform_month (int m, int y)
{
    return y == 1752 && m == 9;
}

static int
bc_before_reform (int m, int y)
{
    return y < 1752 || (y == 1752 && m < 9);
}

static int
bc_display_dow_of_first (int m, int y)
{
    if (bc_before_reform (m, y) || bc_reform_month (m, y))
        return bc_julian_dow (1, m, y);
    return bc_dow_of_first (m, y);
}

static int
bc_display_dow (int d, int m, int y)
{
    if (bc_before_reform (m, y) || (bc_reform_month (m, y) && d < 14))
        return bc_julian_dow (d, m, y);
    return bc_gregorian_dow (d, m, y);
}

/* 1-based day-of-year for (1, m, y). */
static int
bc_doy_of_first (int m, int y)
{
    int doy = 1;
    for (int i = 1; i < m; i++) {
        doy += bc_days_in_month[i];
        if (i == 2 && bc_is_leap (y)) doy += 1;
    }
    return doy;
}

static int
bc_display_doy (int d, int m, int y)
{
    int doy = bc_doy_of_first (m, y) + d - 1;

    if (y == 1752 && (m > 9 || (m == 9 && d >= 14)))
        doy -= 11;
    return doy;
}

static int
bc_days_this_month (int m, int y)
{
    int n = bc_days_in_month[m];
    if (m == 2 && bc_is_leap (y)) n = 29;
    return n;
}

static int
bc_parse_num (const char *s, long min, long max, const char *what, int *out)
{
    char *end = NULL;
    long v;

    v = strtol (s, &end, 10);
    if (end == s || *end != '\0' || v < min || v > max) {
        builtin_error ("bad %s: %s", what, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

/* Month and year operands: util-linux's diagnostics and exit status 1. */
static int
bc_parse_operand (const char *s, int is_month, int *out)
{
    char *end = NULL;
    long v = strtol (s, &end, 10);

    /* util-linux reads a non-numeric month as a name; bash-os knows none. */
    if (is_month && !isdigit ((unsigned char) *s) && *s != '-' && *s != '+') {
        builtin_error ("unknown month name: %s", s);
        return -1;
    }
    if (end == s || *end != '\0') {
        if (is_month)
            builtin_error ("illegal month value: use 1-12: '%s'", s);
        else
            builtin_error ("illegal year value: '%s'", s);
        return -1;
    }
    if (v < 1 || v > (is_month ? 12 : 9999)) {
        /* util-linux has no upper year bound; bash-os stops at 9999. */
        builtin_error (is_month ? "illegal month value: use 1-12"
                       : v < 1 ? "illegal year value: use positive integer"
                       : "illegal year value: use 1-9999");
        return -1;
    }
    *out = (int) v;
    return 0;
}

static void
bc_pad (int n)
{
    for (int i = 0; i < n; i++) putchar (' ');
}

static void
bc_print_title (const char *t, int title_width, int line_width)
{
    int tl = (int) strlen (t);
    int pad = (title_width - tl) / 2;
    if (pad < 0) pad = 0;
    bc_pad (pad);
    fputs (t, stdout);
    bc_pad (line_width - pad - tl);
    putchar ('\n');
}

static void
bc_blank_line (char *line, int width)
{
    memset (line, ' ', (size_t) width);
    line[width] = '\0';
}

static void
bc_put_centered (char *line, int line_width, int title_width, const char *text)
{
    int tl = (int) strlen (text);
    int pad = (title_width - tl) / 2;
    if (pad < 0) pad = 0;
    if (pad + tl > line_width) tl = line_width - pad;
    memcpy (line + pad, text, (size_t) tl);
}

static void
bc_month_lines (int m, int y, int julian, int monday, int include_year,
                char lines[8][32])
{
    char title[64];
    int field = julian ? 4 : 3;
    int title_width = field * 7 - 1;
    int width = title_width + 2;

    if (include_year)
        snprintf (title, sizeof title, "%s %d", bc_month_names[m], y);
    else
        snprintf (title, sizeof title, "%s", bc_month_names[m]);

    for (int i = 0; i < 8; i++)
        bc_blank_line (lines[i], width);

    bc_put_centered (lines[0], width, title_width, title);

    if (julian)
        memcpy (lines[1], monday ? " Mo  Tu  We  Th  Fr  Sa  Su  "
                                : " Su  Mo  Tu  We  Th  Fr  Sa  ",
                (size_t) width);
    else
        memcpy (lines[1], monday ? "Mo Tu We Th Fr Sa Su  "
                                : "Su Mo Tu We Th Fr Sa  ",
                (size_t) width);

    int dow = bc_display_dow_of_first (m, y);
    if (monday) dow = (dow + 6) % 7;

    int days = bc_days_this_month (m, y);
    int row = 2;
    int col = field * dow;
    int wcol = dow;

    for (int d = 1; d <= days && row < 8; d++) {
        char cell[8];
        int display_day = d;
        int display_value;

        if (bc_reform_month (m, y) && d == 3)
            d = display_day = 14;

        display_value = julian ? bc_display_doy (display_day, m, y)
                               : display_day;
        int n = snprintf (cell, sizeof cell, julian ? "%3d" : "%2d",
                          display_value);
        if (n > 0 && col + n <= width)
            memcpy (lines[row] + col, cell, (size_t) n);
        wcol++;
        if (wcol == 7) {
            row++;
            col = 0;
            wcol = 0;
        } else {
            col += field;
        }
    }
}

static void
bc_print_month (int m, int y, int julian, int monday)
{
    char lines[8][32];
    bc_month_lines (m, y, julian, monday, 1, lines);
    for (int i = 0; i < 8; i++)
        puts (lines[i]);
}

static void
bc_month_from_index (int idx, int *m, int *y)
{
    *y = idx / 12;
    *m = idx % 12 + 1;
}

static int
bc_month_index (int m, int y)
{
    return y * 12 + (m - 1);
}

static int
bc_check_span_range (int start_idx, int count)
{
    int end_idx = start_idx + count - 1;
    int m, y;

    bc_month_from_index (start_idx, &m, &y);
    if (y < 1 || y > 9999)
        return -1;
    bc_month_from_index (end_idx, &m, &y);
    if (y < 1 || y > 9999)
        return -1;
    return 0;
}

static void
bc_print_month_span (int start_m, int start_y, int count, int julian, int monday)
{
    int cols = julian ? 2 : 3;
    int start_idx = bc_month_index (start_m, start_y);
    int month_width = julian ? 29 : 22;
    int title_width = cols * (month_width - 2);
    char lines[3][8][32];

    /* Title style, matching cal(1)/ncal: a span is shown in "year" form
       — a centered YEAR header over year-less month sub-titles, one
       header per run of same-year months — only when it begins on a
       row boundary AND its first row is complete. A row holds `cols`
       months (3 normally, 2 in Julian mode), so the boundary is
       (start_m-1) % cols == 0 (Jan/Apr/Jul/Oct for cols=3; odd months
       for cols=2) and "complete first row" is count >= cols. Such a row
       never crosses a year, so every row of the span is single-year;
       any other span gives each month its own "Month YYYY" title.

       The old heuristic (year header for any full row of three same-year
       months) mis-titled forward spans like `-A 2 5 2026` (May/Jun/Jul),
       which cal(1) renders with per-month titles, split multi-row spans
       inconsistently, and wrongly forced Julian spans to per-month. */
    int year_mode = ((start_m - 1) % cols == 0) && (count >= cols);
    int prev_year = 0;          /* year of the last header emitted */
    int first = 1;

    for (int offset = 0; offset < count; offset += cols) {
        int group = count - offset < cols ? count - offset : cols;
        int months[3], years[3];

        for (int col = 0; col < group; col++)
            bc_month_from_index (start_idx + offset + col, &months[col], &years[col]);

        if (!first)
            putchar ('\n');     /* blank line between row groups */

        if (year_mode && years[0] != prev_year) {
            char yt[16];
            snprintf (yt, sizeof yt, "%d", years[0]);
            bc_pad ((title_width - (int) strlen (yt)) / 2);
            fputs (yt, stdout);
            putchar ('\n');
            prev_year = years[0];
        }

        for (int col = 0; col < group; col++)
            bc_month_lines (months[col], years[col], julian, monday,
                            year_mode ? 0 : 1, lines[col]);

        for (int row = 0; row < 8; row++) {
            for (int col = 0; col < group; col++)
                fputs (lines[col][row], stdout);
            putchar ('\n');
        }
        first = 0;
    }
}

static void
bc_print_year (int y, int julian, int monday)
{
    int cols = julian ? 2 : 3;
    int month_width = julian ? 29 : 22;
    int title_width = cols * (month_width - 2);
    char lines[3][8][32];
    char yt[16];

    snprintf (yt, sizeof yt, "%d", y);
    bc_pad ((title_width - (int) strlen (yt)) / 2);
    fputs (yt, stdout);
    putchar ('\n');

    for (int first = 1; first <= 12; first += cols) {
        for (int col = 0; col < cols; col++)
            bc_month_lines (first + col, y, julian, monday, 0, lines[col]);

        for (int row = 0; row < 8; row++) {
            for (int col = 0; col < cols; col++)
                fputs (lines[col][row], stdout);
            putchar ('\n');
        }
        if (first + cols <= 12)
            putchar ('\n');
    }
}

/* ---- util-linux week-number layout (-w) ----------------------------- */

#define BC_REFORM_YDAY 258      /* day of year of 14 September 1752 */

/* util-linux leap rule: Julian through the reform year. */
static int
bc_ul_leap (int y)
{
    return y <= 1752 ? y % 4 == 0 : bc_is_leap (y);
}

static int
bc_ul_doy (int d, int m, int y)
{
    for (int i = 1; i < m; i++)
        d += (i == 2 && bc_ul_leap (y)) ? 29 : bc_days_in_month[i];
    return d;
}

/* Week of the year holding day D (which may be the -1 blank, or a Julian
   day number) of M/Y. US weeks (Sunday first): week 1 holds January 1. ISO
   weeks (Monday first): week 1 holds the first Thursday, and the last days
   of December can be week 1 of the next year. */
static int
bc_week_number (int d, int m, int y, int iso)
{
    int wday = bc_display_dow (1, 1, y);
    int fday = iso ? wday + (wday >= 5 ? -2 : 5) : wday + 6;

    if (d > 31)
        m = 1;
    int yday = bc_ul_doy (d, m, y);
    if (y == 1752 && yday >= BC_REFORM_YDAY)
        fday -= 11;
    if (yday + fday < 7)
        return bc_week_number (31, 12, y - 1, iso);
    if (iso && yday >= 363) {
        int dw = bc_display_dow (d, m, y), last = bc_display_dow (31, 12, y);
        if (dw >= 1 && dw <= 3 && last >= 1 && last <= 3)
            return bc_week_number (1, 1, y + 1, iso);
    }
    return (yday + fday) / 7;
}

/* Fill the 6x7 day grid (-1 blank) and the six row numbers (-1 blank). */
static void
bc_week_grid (int m, int y, int julian, int monday, int days[42], int weeks[6])
{
    int first = bc_display_dow (1, m, y);
    if (monday) first = (first + 6) % 7;
    int j = julian ? bc_ul_doy (1, m, y) : 1;
    int end = j + ((m == 2 && bc_ul_leap (y)) ? 29 : bc_days_in_month[m]);
    int trailing = 0;

    for (int i = 0; i < 42; i++) {
        if (first > 0) { days[i] = -1; first--; continue; }
        if (j < end) {
            if (y == 1752 && m == 9 && (j == 3 || j == 247))
                j += 11;
            days[i] = j++;
            continue;
        }
        days[i] = -1;
        trailing++;
    }
    int lines = 6 - trailing / 7;
    int week = bc_week_number (1, m, y, monday);
    for (int i = 0; i < 6; i++) {
        if (i < lines) {
            if (week > 52)
                week = bc_week_number (days[i * 7], m, y, monday);
            weeks[i] = week++;
        } else
            weeks[i] = -1;
    }
}

/* util-linux center: the odd space goes on the left. */
static void
bc_center (const char *text, int width)
{
    int len = (int) strlen (text), spaces = width > len ? width - len : 0;
    bc_pad (spaces / 2 + spaces % 2);
    fputs (text, stdout);
    bc_pad (spaces / 2);
}

/* COUNT months from START_M/START_Y, three to a row. A year view prints
   the year over the rows and month names without the year. */
static void
bc_print_weeks (int start_m, int start_y, int count, int julian, int monday,
                int year_view)
{
    static const char *sun2 = "Su Mo Tu We Th Fr Sa", *mon2 = "Mo Tu We Th Fr Sa Su";
    static const char *sun3 = "Sun Mon Tue Wed Thu Fri Sat",
                      *mon3 = "Mon Tue Wed Thu Fri Sat Sun";
    int day_width = julian ? 4 : 3;
    int width = day_width * 7 + 2;
    int per_row = count > 1 ? 3 : 1;
    int gutter = year_view ? 3 : 2;
    int idx = bc_month_index (start_m, start_y);

    if (year_view) {
        char yt[16];
        snprintf (yt, sizeof yt, "%04d", start_y);
        bc_center (yt, per_row * width + (per_row - 1) * gutter);
        fputs ("\n\n", stdout);
    }
    for (int done = 0; done < count; done += per_row) {
        int n = count - done < per_row ? count - done : per_row;
        int months[3], years[3], days[3][42], weeks[3][6];

        for (int k = 0; k < n; k++) {
            bc_month_from_index (idx + done + k, &months[k], &years[k]);
            bc_week_grid (months[k], years[k], julian, monday, days[k], weeks[k]);
        }
        for (int k = 0; k < n; k++) {
            char title[64];
            if (year_view)
                snprintf (title, sizeof title, "%s", bc_month_names[months[k]]);
            else
                snprintf (title, sizeof title, "%s %04d", bc_month_names[months[k]], years[k]);
            bc_center (title, width);
            if (k + 1 < n) bc_pad (gutter);
        }
        putchar ('\n');
        for (int k = 0; k < n; k++) {
            bc_pad (3);
            fputs (julian ? (monday ? mon3 : sun3) : (monday ? mon2 : sun2), stdout);
            if (k + 1 < n) bc_pad (gutter);
        }
        putchar ('\n');
        for (int row = 0; row < 6; row++) {
            for (int k = 0; k < n; k++) {
                if (weeks[k][row] > 0)
                    printf ("%2d", weeks[k][row]);
                else
                    bc_pad (2);
                for (int c = 0; c < 7; c++) {
                    int v = days[k][row * 7 + c];
                    if (v > 0)
                        printf ("%*d", day_width, v);
                    else
                        bc_pad (day_width);
                }
                if (k + 1 < n) bc_pad (gutter);
            }
            putchar ('\n');
        }
    }
}

int
cal_builtin (WORD_LIST *list)
{
    int julian = 0;
    int monday = 0;
    int explicit_year = 0;
    int year = 0;
    int before = 0;
    int after = 0;
    int span_requested = 0;
    int three_requested = 0;
    int week_numbers = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--version")) {
            puts ("cal 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        /* Bundled argument-less short options: -wm, -jw3, ... */
        if (w[1] != '-' && w[2] && strspn (w + 1, "jmMSsw31") == strlen (w + 1)) {
            for (const char *o = w + 1; *o; o++) {
                switch (*o) {
                    case 'j': julian = 1; break;
                    case 'm': case 'M': monday = 1; break;
                    case 'S': case 's': monday = 0; break;
                    case 'w': week_numbers = 1; break;
                    case '3':
                        before = 1; after = 1; span_requested = 1; three_requested = 1;
                        break;
                    default:
                        before = 0; after = 0; span_requested = 0; three_requested = 0;
                        break;
                }
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-j") || !strcmp (w, "--julian")) {
            julian = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-m") || !strcmp (w, "--monday")) {
            monday = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-M") || !strcmp (w, "--monday")) {
            monday = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-S") || !strcmp (w, "-s") || !strcmp (w, "--sunday")) {
            monday = 0; list = list->next; continue;
        }
        if (!strcmp (w, "-w") || !strcmp (w, "--week") ||
            !strncmp (w, "--week=", 7)) {
            /* --week=N only selects a week to highlight in color. */
            int highlight;
            if (w[2] == 'e' && w[6] == '=' &&
                bc_parse_num (w + 7, 1, 54, "week", &highlight) < 0)
                return EXECUTION_FAILURE;
            week_numbers = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-3") || !strcmp (w, "--three")) {
            before = 1; after = 1; span_requested = 1;
            three_requested = 1;
            list = list->next; continue;
        }
        if (!strcmp (w, "-1") || !strcmp (w, "--one")) {
            /* Single month (the default); resets any prior -3/-A/-B span,
               matching util-linux/bsd cal's last-one-wins flag handling. */
            before = 0; after = 0; span_requested = 0; three_requested = 0;
            list = list->next; continue;
        }
        if (!strcmp (w, "-A") || !strcmp (w, "--after")) {
            if (!list->next) {
                builtin_error ("%s requires a month count", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_num (list->next->word->word, 0, 120000, "month count", &after) < 0)
                return EX_USAGE;
            span_requested = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-B") || !strcmp (w, "--before")) {
            if (!list->next) {
                builtin_error ("%s requires a month count", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_num (list->next->word->word, 0, 120000, "month count", &before) < 0)
                return EX_USAGE;
            span_requested = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-y") || !strcmp (w, "--year")) {
            if (!list->next) {
                builtin_error ("%s requires a year", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_operand (list->next->word->word, 0, &year) < 0)
                return EXECUTION_FAILURE;
            explicit_year = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            puts ("cal: display a calendar (cal(1) subset)");
            puts ("Usage: cal [-jm] [-1|-3] [-A N] [-B N] [[MM] YYYY]");
            puts ("       cal [-jm] -y YEAR");
            puts ("  -j   Julian day-of-year mode (3-digit cells)");
            puts ("  -m   Monday-first week");
            puts ("  -S   Sunday-first week (default)");
            puts ("  -w   week numbers (US; ISO 8601 with -m), util-linux layout");
            puts ("  -1   display single month (default)");
            puts ("  -3   display previous, current, and next month");
            puts ("  -A N display N months after the target month");
            puts ("  -B N display N months before the target month");
            puts ("  -y   display a full year");
            puts ("  --version   show version");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int npos = 0;
    WORD_LIST *p;
    for (p = list; p; p = p->next) npos++;

    if (explicit_year) {
        if (npos != 0) {
            builtin_error ("too many arguments");
            return EX_USAGE;
        }
        if (week_numbers)
            bc_print_weeks (1, year, 12, julian, monday, 1);
        else
            bc_print_year (year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 0) {
        time_t now = time (NULL);
        struct tm *lt = localtime (&now);
        if (!lt) {
            builtin_error ("localtime: failed");
            return EXECUTION_FAILURE;
        }
        int m = lt->tm_mon + 1;
        int y = lt->tm_year + 1900;
        if (span_requested) {
            int start_idx = bc_month_index (m, y) - before;
            int count = before + 1 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            bc_month_from_index (start_idx, &m, &y);
            if (week_numbers)
                bc_print_weeks (m, y, count, julian, monday, 0);
            else
                bc_print_month_span (m, y, count, julian, monday);
            return EXECUTION_SUCCESS;
        }
        if (week_numbers)
            bc_print_weeks (m, y, 1, julian, monday, 0);
        else
            bc_print_month (m, y, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 1) {
        if (bc_parse_operand (list->word->word, 0, &year) < 0)
            return EXECUTION_FAILURE;
        if (span_requested) {
            int start_idx;
            int count;

            if (three_requested) {
                builtin_error ("-3 together with a given year but no given month is not supported");
                return EX_USAGE;
            }
            start_idx = bc_month_index (1, year) - before;
            count = before + 12 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            {
                int start_m, start_y;
                bc_month_from_index (start_idx, &start_m, &start_y);
                if (week_numbers)
                    bc_print_weeks (start_m, start_y, count, julian, monday, 0);
                else
                    bc_print_month_span (start_m, start_y, count, julian, monday);
            }
            return EXECUTION_SUCCESS;
        }
        if (week_numbers)
            bc_print_weeks (1, year, 12, julian, monday, 1);
        else
            bc_print_year (year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 2) {
        int month;
        if (bc_parse_operand (list->word->word, 1, &month) < 0)
            return EXECUTION_FAILURE;
        if (bc_parse_operand (list->next->word->word, 0, &year) < 0)
            return EXECUTION_FAILURE;
        if (span_requested) {
            int start_idx = bc_month_index (month, year) - before;
            int count = before + 1 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            bc_month_from_index (start_idx, &month, &year);
            if (week_numbers)
                bc_print_weeks (month, year, count, julian, monday, 0);
            else
                bc_print_month_span (month, year, count, julian, monday);
            return EXECUTION_SUCCESS;
        }
        if (week_numbers) {
            bc_print_weeks (month, year, 1, julian, monday, 0);
            return EXECUTION_SUCCESS;
        }
        bc_print_month (month, year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    builtin_error ("too many arguments");
    return EX_USAGE;
}

char *cal_doc[] = {
    "Display a calendar month or year (cal(1) subset).",
    "",
    "    cal                   # current month",
    "    cal YYYY | -y YYYY    # entire year (12 months)",
    "    cal MM YYYY           # specific month",
    "    cal -j ...            # Julian day-of-year mode (3-digit cells)",
    "    cal -m ...            # Monday-first week",
    "    cal -w ...            # week numbers: US, or ISO 8601 with -m",
    "    cal -3 | -A N | -B N  # month spans",
    "    cal --help | --version",
    "",
    "Gregorian calendar with British 1752 reformation correction.",
    "Day-of-week derived from Gregorian/Julian arithmetic. Year range: 1..9999.",
    "With -w the util-linux layout is used: each week row starts with its",
    "number. A bad month or year exits 1 (util-linux).",
    "",
    "Source counterparts:",
    "    research/refs/util-linux/misc-utils/cal.c",
    "    research/refs/busybox/util-linux/cal.c",
    (char *) NULL
};

struct builtin cal_struct = {
    "cal",
    cal_builtin,
    BUILTIN_ENABLED,
    cal_doc,
    "cal [-jmw] [-3] [-A N] [-B N] [[MM] YYYY] | cal [-jmw] -y YEAR",
    0
};
