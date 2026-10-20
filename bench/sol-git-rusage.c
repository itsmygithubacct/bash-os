/* SPDX-License-Identifier: MIT */
/* Exec a small launcher before forking: exclude Python fixture memory from
   the measured command's inherited pre-exec RSS high-water mark. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
int main (int argc, char **argv)
{
  if (argc < 3) return 2;
  pid_t child = fork ();
  if (child < 0) { perror ("fork"); return 2; }
  if (child == 0) { execv (argv[2], argv + 2); perror ("execv"); _exit (127); }
  int status;
  struct rusage usage;
  pid_t waited;
  do waited = wait4 (child, &status, 0, &usage); while (waited < 0 && errno == EINTR);
  if (waited < 0) { perror ("wait4"); return 2; }
  FILE *report = fopen (argv[1], "w");
  if (!report) { perror ("report"); return 2; }
  int bad = fprintf (report, "%ld %.6f %.6f\n", usage.ru_maxrss,
                     usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6,
                     usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6) < 0;
  if (fclose (report)) bad = 1;
  if (bad) return 2;
  return WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status);
}
