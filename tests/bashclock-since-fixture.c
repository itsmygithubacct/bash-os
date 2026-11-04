/* Run only in a disposable VM. Compile against tests/sol-pgrep-stubs. */
#include <time.h>
#include <errno.h>
static struct timespec sample;
static int fail_clock;
static int fixture_clock_gettime (clockid_t clock, struct timespec *out)
{
  if (clock != CLOCK_MONOTONIC || fail_clock) { errno = EIO; return -1; }
  *out = sample;
  return 0;
}
#define clock_gettime fixture_clock_gettime
#include "../loadables/bashclock.c"
#undef clock_gettime

int main (int argc, char **argv)
{
  WORD_DESC words[3];
  WORD_LIST nodes[3];
  int count, i;
  if (argc < 4 || argc > 6) return 99;
  sample.tv_sec = (time_t) strtoll (argv[1], NULL, 10);
  sample.tv_nsec = strtol (argv[2], NULL, 10);
  fail_clock = atoi (argv[3]);
  count = argc - 4;
  words[0].word = "since";
  nodes[0].word = &words[0];
  nodes[0].next = count ? &nodes[1] : NULL;
  for (i = 0; i < count; i++)
    {
      words[i + 1].word = argv[i + 4];
      nodes[i + 1].word = &words[i + 1];
      nodes[i + 1].next = i + 1 < count ? &nodes[i + 2] : NULL;
    }
  return bashclock_builtin (&nodes[0]);
}
