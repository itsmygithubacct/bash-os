/* A fresh C parent avoids inherited Python high-water RSS in memory probes.
   Compile through the build gate; invoke through the benchmark gate.
   Usage: sol-wc-rusage RSS-FILE ABSOLUTE-COMMAND [ARG...]
   stdout/stderr and command status are preserved for independent validation. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int
main (int argc, char **argv)
{
    if (argc < 3) return 2;
    pid_t pid = fork ();
    if (pid < 0) { perror ("fork"); return 125; }
    if (pid == 0) {
        execv (argv[2], argv + 2);
        perror ("execv");
        _exit (127);
    }
    int status;
    struct rusage usage;
    while (wait4 (pid, &status, 0, &usage) < 0) {
        if (errno == EINTR) continue;
        perror ("wait4");
        return 125;
    }
    FILE *f = fopen (argv[1], "w");
    if (!f) { perror (argv[1]); return 125; }
    int failed = fprintf (f, "%ld\n", usage.ru_maxrss) < 0;
    if (fclose (f) != 0) failed = 1;
    if (failed) { perror (argv[1]); return 125; }
    if (WIFEXITED (status)) return WEXITSTATUS (status);
    return WIFSIGNALED (status) ? 128 + WTERMSIG (status) : 125;
}
