/* SPDX-License-Identifier: MIT */
/* Scripted byte-arrival clock. No PTY, sleeping, or physical-hardware claim.
 * Input: monotonic milliseconds and byte in hex, one event per line.
 * Output: key code, return time, number of consumed bytes, for each read.
 * The scheduler implements readiness/time only; expected keys live elsewhere. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <errno.h>

static struct { long ms; unsigned char byte; } events[128];
static size_t used, at;
static long now;

static ssize_t q_read(int fd, void *buf, size_t count)
{
  if (fd != 0 || count != 1) { errno = EINVAL; return -1; }
  if (at == used) return 0;
  if (now < events[at].ms) now = events[at].ms;
  *(unsigned char *)buf = events[at++].byte;
  return 1;
}

static int q_poll(struct pollfd *fds, nfds_t n, int ms)
{
  if (n != 1 || fds[0].fd != 0 || ms < 0) { errno = EINVAL; return -1; }
  fds[0].revents = 0;
  if (at < used && events[at].ms <= now + ms) {
    if (now < events[at].ms) now = events[at].ms;
    fds[0].revents = POLLIN;
    return 1;
  }
  now += ms;
  return 0;
}

static int q_clock_gettime(clockid_t clock, struct timespec *ts)
{
  if (clock != CLOCK_MONOTONIC) { errno = EINVAL; return -1; }
  ts->tv_sec = now / 1000;
  ts->tv_nsec = (now % 1000) * 1000000L;
  return 0;
}

#define read q_read
#define poll q_poll
#define clock_gettime q_clock_gettime
#include QUAL_WGETCH_SOURCE
#undef clock_gettime
#undef poll
#undef read

int main(int argc, char **argv)
{
  long t;
  unsigned b;
  char extra;
  char line[128];
  int reads;
  if (!getenv("BASHOS_QUALIFICATION_GUEST") ||
      strcmp(getenv("BASHOS_QUALIFICATION_GUEST"), "1")) return 125;
  if (argc != 2 || (reads = atoi(argv[1])) < 1 || reads > 16) return 125;
#ifdef QUAL_RUNTIME_KEYS
  if (bw_define_key("qualification_short",1792,"\033[9") ||
      bw_define_key("qualification_long",1793,"\033[9~")) return 125;
#endif
  while (fgets(line, sizeof line, stdin)) {
    if (sscanf(line, "%ld %x %c", &t, &b, &extra) != 2 ||
        t < 0 || t > 50000 || b > 255 || used == 128 ||
        (used && t < events[used-1].ms)) return 125;
    events[used].ms = t; events[used++].byte = (unsigned char)b;
  }
  for (int i = 0; i < reads; ++i) {
    int key = bw_read_key_fd(0);
    printf("%d %ld %zu\n", key, now, at);
  }
  return ferror(stdin) || ferror(stdout) ? 125 : 0;
}
