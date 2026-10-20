/* Small memory-accounting launcher. Fork after exec so the measured child
   cannot inherit the Python fixture generator's pre-exec peak RSS. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/wait.h>
int main (int argc, char **argv)
{
    if (argc < 3) return 2;
    pid_t child = fork ();
    if (child < 0) { perror ("fork"); return 2; }
    if (child == 0) {
        execv (argv[2], argv + 2);
        perror ("execv");
        _exit (127);
    }
    int status;
    struct rusage usage;
    pid_t result;
    do result = wait4 (child, &status, 0, &usage); while (result < 0 && errno == EINTR);
    if (result < 0) { perror ("wait4"); return 2; }
    FILE *f = fopen (argv[1], "w");
    if (!f) { perror ("rusage output"); return 2; }
    fprintf (f, "%ld\n", usage.ru_maxrss);
    if (fclose (f) != 0) return 2;
    return WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status);
}
