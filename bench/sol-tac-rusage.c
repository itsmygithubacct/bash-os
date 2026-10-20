/* SPDX-License-Identifier: MIT */
/* A small wait4 launcher keeps the Python fixture generator's resident heap
   out of the measured child's pre-exec RSS high-water mark. Build separately
   through the build gate; the benchmark never invokes a compiler. */
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
    pid_t child = fork ();
    if (child < 0) { perror ("fork"); return 2; }
    if (!child) {
        execv (argv[2], argv + 2);
        perror ("execv"); _exit (127);
    }
    struct rusage usage;
    int status;
    pid_t result;
    do result = wait4 (child, &status, 0, &usage); while (result < 0 && errno == EINTR);
    if (result < 0) { perror ("wait4"); return 2; }
    FILE *out = fopen (argv[1], "w");
    if (!out) { perror ("rusage output"); return 2; }
    int failed = fprintf (out,
        "{\"peak_rss_kib\":%ld,\"user_ms\":%.3f,\"system_ms\":%.3f,\"minor_faults\":%ld}\n",
        usage.ru_maxrss,
        usage.ru_utime.tv_sec * 1000.0 + usage.ru_utime.tv_usec / 1000.0,
        usage.ru_stime.tv_sec * 1000.0 + usage.ru_stime.tv_usec / 1000.0,
        usage.ru_minflt) < 0;
    if (fclose (out)) failed = 1;
    if (failed) return 2;
    return WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status);
}
