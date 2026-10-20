/* SPDX-License-Identifier: MIT
 * Closed RTC/time-setting boundary around the genuine production source.
 * Only adjfile stdio reaches the filesystem. RTC descriptors are synthetic;
 * no ioctl or clock-setting wrapper can invoke a kernel mutation operation.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/rtc.h>
#include "loadables.h"
static int fixture_open (const char *, int, ...);
static int fixture_close (int);
static int fixture_ioctl (int, unsigned long, ...);
static int fixture_get (clockid_t, struct timespec *);
static int fixture_set (clockid_t, const struct timespec *);
static FILE *fixture_fdopen (int, const char *);
static int fixture_fprintf (FILE *, const char *, ...);
static int fixture_fclose (FILE *);
static int fixture_rename (const char *, const char *);
#define open fixture_open
#define close fixture_close
#define ioctl fixture_ioctl
#define clock_gettime fixture_get
#define clock_settime fixture_set
#define fdopen fixture_fdopen
#define fprintf fixture_fprintf
#define fclose fixture_fclose
#define rename fixture_rename
#ifndef HWCLOCK_SOURCE
#define HWCLOCK_SOURCE "../loadables/hwclock.c"
#endif
#include HWCLOCK_SOURCE
#undef open
#undef close
#undef ioctl
#undef clock_gettime
#undef clock_settime
#undef fdopen
#undef fprintf
#undef fclose
#undef rename

static struct rtc_time input, written;
static struct timespec now, system_set;
static int opens, reads, writes, closes, gets, sets, live, bad, flags;
static const int rtc_fd = 1000000;
static char fail[32], fixture_trace[8192];
static size_t used;
static int quiet;
static FILE *writer;
static void event (const char *s)
{
  if (quiet) return;
  size_t n = strlen (s);
  if (used + n + 1 >= sizeof fixture_trace) { bad++; return; }
  memcpy (fixture_trace + used, s, n + 1); used += n;
}
static int denied (const char *op)
{
  if (strcmp (op, fail)) return 0;
  errno = (!strcmp (op, "set") || !strcmp (op, "write")) ? EPERM : EIO;
  return 1;
}
static int fixture_open (const char *path, int mode, ...)
{
  opens++; flags = mode;
  if (mode & ~(O_ACCMODE | O_CLOEXEC)) bad++;
  event ((mode & O_ACCMODE) == O_RDONLY ? "OPEN r\n" : "OPEN w\n");
  if (denied ("open")) return -1;
  if (strcmp (path, "/fixture/rtc")) { errno = ENOENT; return -1; }
  if (live) { bad++; errno = EMFILE; return -1; }
  live = 1; return rtc_fd;
}
static int fixture_close (int fd)
{
  /* fdopen failure cleanup uses an actual private adjfile descriptor. */
  if (fd != rtc_fd) return close (fd);
  closes++; event ("CLOSE\n");
  if (!live) bad++;
  live = 0; return denied ("close") ? -1 : 0;
}
static int fixture_ioctl (int fd, unsigned long request, ...)
{
  if (fd != rtc_fd || !live) { bad++; errno = EBADF; return -1; }
  va_list ap; va_start (ap, request); struct rtc_time *r = va_arg (ap, struct rtc_time *); va_end (ap);
  if (request == RTC_RD_TIME) {
    reads++; if ((flags & O_ACCMODE) != O_RDONLY) bad++; event ("READ\n"); if (denied ("read")) return -1; *r = input; return 0;
  }
  if (request == RTC_SET_TIME) {
    writes++; if ((flags & O_ACCMODE) != O_WRONLY) bad++; event ("WRITE\n"); if (denied ("write")) return -1; written = *r; return 0;
  }
  bad++; errno = EINVAL; return -1;
}
static int fixture_get (clockid_t id, struct timespec *t)
{
  gets++; event ("GET\n"); if (id != CLOCK_REALTIME) bad++;
  if (denied ("get")) return -1;
  *t = now; return 0;
}
static int fixture_set (clockid_t id, const struct timespec *t)
{
  sets++; event ("SET\n"); if (id != CLOCK_REALTIME || t->tv_nsec != 0) bad++;
  if (denied ("set")) return -1;
  system_set = *t; return 0;
}
static FILE *fixture_fdopen (int fd, const char *mode)
{
  if (denied ("fdopen")) return NULL;
  writer = fdopen (fd, mode); return writer;
}
static int fixture_fprintf (FILE *fp, const char *fmt, ...)
{
  if (fp == writer && denied ("writefile")) return -1;
  va_list ap; va_start (ap, fmt); int rc = vfprintf (fp, fmt, ap); va_end (ap); return rc;
}
static int fixture_fclose (FILE *fp)
{
  int writing = fp == writer;
  if (writing) writer = NULL;
  int rc = fclose (fp);
  if (writing && denied ("closefile")) return -1;
  return rc;
}
static int fixture_rename (const char *a, const char *b)
{
  return denied ("rename") ? -1 : rename (a, b);
}
static void calendar (struct rtc_time *r, const char **a)
{
  memset (r, 0, sizeof *r);
  r->tm_year = atoi (a[0]) - 1900; r->tm_mon = atoi (a[1]) - 1; r->tm_mday = atoi (a[2]);
  r->tm_hour = atoi (a[3]); r->tm_min = atoi (a[4]); r->tm_sec = atoi (a[5]);
}
static int same_calendar (const struct rtc_time *a, const struct rtc_time *b)
{
  return a->tm_year == b->tm_year && a->tm_mon == b->tm_mon && a->tm_mday == b->tm_mday
      && a->tm_hour == b->tm_hour && a->tm_min == b->tm_min && a->tm_sec == b->tm_sec;
}
int hwclock_fixture_builtin (WORD_LIST *list)
{
  const char *a[10]; int n = 0;
  for (; list && n < 10; list = list->next) a[n++] = list->word->word;
  if (list || !n) return 2;
  if (!strcmp (a[0], "reset") && n == 1) {
    memset (&input, 0, sizeof input); memset (&written, 0, sizeof written);
    now.tv_sec = system_set.tv_sec = now.tv_nsec = system_set.tv_nsec = 0;
    opens = reads = writes = closes = gets = sets = live = bad = flags = quiet = 0;
    used = 0; fixture_trace[0] = fail[0] = 0; writer = NULL;
  } else if (!strcmp (a[0], "rtc") && n == 7) calendar (&input, a + 1);
  else if (!strcmp (a[0], "now") && n == 2) { now.tv_sec = strtoll (a[1], NULL, 10); now.tv_nsec = 987654321; }
  else if (!strcmp (a[0], "fail") && n == 2) snprintf (fail, sizeof fail, "%s", a[1]);
  else if (!strcmp (a[0], "quiet") && n == 1) quiet = 1;
  else if (!strcmp (a[0], "trace") && n == 1) fputs (fixture_trace, stdout);
  else if (!strcmp (a[0], "verify-sys") && n == 2) {
    if (bad || live || !sets || system_set.tv_sec != strtoll (a[1], NULL, 10) || system_set.tv_nsec) return 1;
  } else if (!strcmp (a[0], "verify-rtc") && (n == 7 || n == 9)) {
    struct rtc_time expected; calendar (&expected, a + 1);
    if (bad || live || !writes || !same_calendar (&expected, &written)
        || written.tm_isdst != 0) return 1;
    if (n == 9 && (written.tm_wday != atoi (a[7]) || written.tm_yday != atoi (a[8]))) return 1;
  } else if (!strcmp (a[0], "verify-counts") && n == 8) {
    int k = atoi (a[1]);
    int actual[] = {opens, reads, writes, closes, gets, sets};
    if (bad || live) return 1;
    for (int i = 0; i < 6; i++) if (actual[i] != k * atoi (a[i+2])) return 1;
  } else if (!strcmp (a[0], "stats") && n == 1) {
    printf ("open=%d read=%d write=%d close=%d get=%d set=%d live=%d bad=%d cloexec=%d sys=%lld nsec=%ld rtc=%04d-%02d-%02dT%02d:%02d:%02d wday=%d yday=%d isdst=%d\n",
        opens, reads, writes, closes, gets, sets, live, bad, !!(flags & O_CLOEXEC),
        (long long)system_set.tv_sec, system_set.tv_nsec, written.tm_year + 1900, written.tm_mon + 1,
        written.tm_mday, written.tm_hour, written.tm_min, written.tm_sec,
        written.tm_wday, written.tm_yday, written.tm_isdst);
  } else return 2;
  return 0;
}
char *hwclock_fixture_doc[] = { "Private hwclock fixture control.", NULL };
struct builtin hwclock_fixture_struct = { "hwclock_fixture", hwclock_fixture_builtin, BUILTIN_ENABLED,
    hwclock_fixture_doc, "hwclock_fixture OP ARGS", 0 };

#ifdef HWCLOCK_STANDALONE
void builtin_error (const char *fmt, ...)
{
  va_list ap; va_start (ap, fmt); vfprintf (stderr, fmt, ap); fputc ('\n', stderr); va_end (ap);
}
void builtin_usage (void) { fputs ("hwclock usage error\n", stderr); }
/* Tab separated commands on stdin, preserving empty arguments. Same test
   protocol as Bash, with no fork/exec or privileged operation underneath. */
int main (void)
{
  char *line = NULL; size_t cap = 0;
  while (getline (&line, &cap, stdin) >= 0) {
    line[strcspn (line, "\n")] = 0;
    char *cursor = line, *word; WORD_LIST *head = NULL, **tail = &head;
    while ((word = strsep (&cursor, "\t")) != NULL) {
      WORD_LIST *item = calloc (1, sizeof *item); item->word = calloc (1, sizeof *item->word);
      item->word->word = word; *tail = item; tail = &item->next;
    }
    int rc;
    if (!strcmp (head->word->word, "fixture")) rc = hwclock_fixture_builtin (head->next);
    else rc = hwclock_builtin (head->next);
    while (head) { WORD_LIST *next = head->next; free (head->word); free (head); head = next; }
    if (rc == EX_USAGE) rc = EX_BADUSAGE; /* Bash dispatcher translation. */
    printf ("STATUS=%d\n", rc); fflush (stdout);
  }
  free (line); return 0;
}
#endif
