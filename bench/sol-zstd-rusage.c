/* SPDX-License-Identifier: MIT */
/* Exec this small launcher before fork so wait4 measures the command, without
   the Python fixture generator's inherited pre-exec RSS high-water mark.
   Build separately through the build gate; the benchmark never compiles. */
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
int main (int argc, char **argv)
{
  if (argc < 3) return 2;
  pid_t pid = fork ();
  if (pid < 0) { perror ("fork"); return 2; }
  if (pid == 0)
    { execv (argv[2], argv + 2); perror ("execv"); _exit (127); }
  int status; struct rusage usage; pid_t waited;
  do waited = wait4 (pid, &status, 0, &usage); while (waited < 0 && errno == EINTR);
  if (waited < 0) { perror ("wait4"); return 2; }
  FILE *out = fopen (argv[1], "w");
  if (!out) { perror ("rusage output"); return 2; }
  int failed = fprintf (out, "%ld\n", usage.ru_maxrss) < 0;
  if (fclose (out)) failed = 1;
  if (failed) return 2;
  return WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status);
}
