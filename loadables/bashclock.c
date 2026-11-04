/* bashclock.c — high-resolution time. Loadable for bash.
 *
 * Bash's built-in time access is whole-seconds (`printf '%(...)T' -1`
 * truncates to seconds, EPOCHSECONDS is integer, EPOCHREALTIME is
 * locale-dependent in formatting). No CLOCK_MONOTONIC access at all,
 * so benchmark harnesses can't get a clock that doesn't jump on
 * settimeofday or NTP step.
 *
 * bashclock exposes clock_gettime(2) directly. Output format is always
 * "<secs>.<nanos>" with a literal '.' regardless of locale, so it
 * composes cleanly with bash's other text processing and with fltexpr.
 *
 * Subcommands:
 *     bashclock now              CLOCK_REALTIME (wallclock)
 *     bashclock mono             CLOCK_MONOTONIC (steady, no NTP step)
 *     bashclock boot             CLOCK_BOOTTIME (mono + suspend time)
 *     bashclock since T0         elapsed seconds since prior `mono`
 *     bashclock sleep SECS       ns-precision sleep (clock_nanosleep)
 *
 * Examples:
 *     t0=$(bashclock mono)
 *     ./expensive-job
 *     elapsed=$(bashclock since "$t0")
 *     echo "took $elapsed seconds"
 *
 *     # Periodic loop with stable cadence (no drift):
 *     while bashclock sleep 0.5; do tick; done
 *
 * Companion docs:
 *     /docs/bash/bashclock.txt
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
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+.
 * MIT for this source lets it be lifted into other projects.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>

#include "loadables.h"

/* Print a struct timespec as "<secs>.<nanos>" with 9-digit ns. Always
   uses '.' as the decimal separator regardless of locale. */
static void
bc_print_ts (struct timespec *ts)
{
  printf ("%lld.%09ld\n",
          (long long) ts->tv_sec,
          (long) ts->tv_nsec);
}

/* Read a "<secs>.<nanos>" string into a struct timespec. Returns 0 on
   success, -1 on parse failure. The fractional part is treated as
   nanoseconds when 9 digits, scaled when fewer. */
static int
bc_parse_ts (const char *s, struct timespec *out)
{
  long long secs = 0;
  long nanos = 0;
  const char *p = s;
  int neg = 0;
  if (*p == '-') { neg = 1; p++; }
  while (*p >= '0' && *p <= '9')
    { secs = secs * 10 + (*p - '0'); p++; }
  if (*p == '.')
    {
      p++;
      int digits = 0;
      while (*p >= '0' && *p <= '9' && digits < 9)
        { nanos = nanos * 10 + (*p - '0'); p++; digits++; }
      /* Pad with zeros if fewer than 9 digits given. */
      while (digits < 9) { nanos *= 10; digits++; }
      /* Skip trailing digits past 9 (sub-ns ignored). */
      while (*p >= '0' && *p <= '9') p++;
    }
  if (*p != '\0' && *p != '\n') return -1;
  out->tv_sec = (time_t) (neg ? -secs : secs);
  out->tv_nsec = nanos;
  return 0;
}

static int
bc_get_clock (clockid_t clk)
{
  struct timespec ts;
  if (clock_gettime (clk, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  bc_print_ts (&ts);
  return EXECUTION_SUCCESS;
}

static int
bc_since (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("since: needs T0"); return EX_USAGE; }
  if (args->next)
    { builtin_error ("since: unexpected extra argument"); return EX_USAGE; }

  /* Parse the signed decimal as a magnitude.  A negative fraction cannot
     be represented by simply negating the seconds field of a timespec. */
  const char *p = args->word->word;
  int negative = (*p == '-'), digits = 0, fractional_digits = 0;
  uintmax_t start_sec = 0;
  long start_ns = 0;
  if (negative) p++;
  while (*p >= '0' && *p <= '9')
    {
      unsigned int digit = *p++ - '0';
      if (start_sec > (UINTMAX_MAX - digit) / 10) goto bad_start;
      start_sec = start_sec * 10 + digit;
      digits = 1;
    }
  if (*p == '.')
    {
      p++;
      while (*p >= '0' && *p <= '9')
        {
          if (fractional_digits < 9)
            { start_ns = start_ns * 10 + (*p - '0'); fractional_digits++; }
          p++;
        }
      if (!fractional_digits) goto bad_start;
    }
  if (!digits || *p) goto bad_start;
  while (fractional_digits++ < 9) start_ns *= 10;

  struct timespec t1;
  if (clock_gettime (CLOCK_MONOTONIC, &t1) < 0)
    { builtin_error ("clock_gettime: %s", strerror (errno)); return EXECUTION_FAILURE; }

  uintmax_t now_sec = (uintmax_t) t1.tv_sec, sec;
  long ns;
  int result_negative = 0;
  if (negative)
    {
      if (start_sec > UINTMAX_MAX - now_sec)
        { builtin_error ("since: result out of range"); return EXECUTION_FAILURE; }
      sec = now_sec + start_sec;
      ns = t1.tv_nsec + start_ns;
      if (ns >= 1000000000L)
        {
          if (sec == UINTMAX_MAX)
            { builtin_error ("since: result out of range"); return EXECUTION_FAILURE; }
          sec++; ns -= 1000000000L;
        }
    }
  else
    {
      int start_later = start_sec > now_sec ||
        (start_sec == now_sec && start_ns > t1.tv_nsec);
      uintmax_t high_sec = start_later ? start_sec : now_sec;
      uintmax_t low_sec = start_later ? now_sec : start_sec;
      long high_ns = start_later ? start_ns : t1.tv_nsec;
      long low_ns = start_later ? t1.tv_nsec : start_ns;
      sec = high_sec - low_sec;
      ns = high_ns - low_ns;
      if (ns < 0) { sec--; ns += 1000000000L; }
      result_negative = start_later;
    }
  printf ("%s%" PRIuMAX ".%09ld\n", result_negative ? "-" : "", sec, ns);
  return EXECUTION_SUCCESS;

bad_start:
    { builtin_error ("since: bad T0 format (want SECS.NANOS): %s", args->word->word); return EX_USAGE; }
}

static int
bc_sleep (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("sleep: needs SECS"); return EX_USAGE; }
  struct timespec req;
  if (bc_parse_ts (args->word->word, &req) < 0)
    { builtin_error ("sleep: bad SECS format: %s", args->word->word); return EX_USAGE; }
  /* Honor SIGINT / Ctrl-C — don't loop EINTR away. */
  int err = clock_nanosleep (CLOCK_MONOTONIC, 0, &req, NULL);
  if (err != 0)
    {
      /* Unlike nanosleep, clock_nanosleep returns the error number. */
      if (err == EINTR) return EXECUTION_FAILURE;
      builtin_error ("clock_nanosleep: %s", strerror (err));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

int
bashclock_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "now")   == 0) {
    if (args) { builtin_error ("now: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_REALTIME);
  }
  if (strcmp (cmd, "mono")  == 0) {
    if (args) { builtin_error ("mono: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_MONOTONIC);
  }
  if (strcmp (cmd, "boot")  == 0) {
    if (args) { builtin_error ("boot: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_BOOTTIME);
  }
  if (strcmp (cmd, "since") == 0) return bc_since (args);
  if (strcmp (cmd, "sleep") == 0) return bc_sleep (args);

  builtin_error ("unknown subcommand: %s (try now/mono/boot/since/sleep)", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *bashclock_doc[] = {
  "High-resolution time access via clock_gettime(2).",
  "",
  "    bashclock now           CLOCK_REALTIME wallclock seconds.nanos",
  "    bashclock mono          CLOCK_MONOTONIC (steady; no NTP step)",
  "    bashclock boot          CLOCK_BOOTTIME (mono + time spent suspended)",
  "    bashclock since T0      elapsed seconds since a prior `mono` reading",
  "    bashclock sleep SECS    ns-precision sleep (clock_nanosleep)",
  "",
  "Output is always SECS.NANOS with literal '.' (locale-independent).",
  "Use with fltexpr to compose with floats; with `bench.sh` for timing.",
  (char *)NULL
};

struct builtin bashclock_struct = {
  "bashclock",
  bashclock_builtin,
  BUILTIN_ENABLED,
  bashclock_doc,
  "bashclock now|mono|boot|since T0|sleep SECS",
  0
};
