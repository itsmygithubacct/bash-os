/* SPDX-License-Identifier: MIT
 * Measure a child after this small launcher has exec'd, so Python's inherited
 * high-water RSS does not contaminate the shell's wait4 result. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (!pid) { execv(argv[2], argv+2); perror("execv"); _exit(127); }
    int status;
    struct rusage usage;
    while (wait4(pid, &status, 0, &usage) < 0) {
        if (errno == EINTR) continue;
        perror("wait4"); return 2;
    }
    FILE *out = fopen(argv[1], "w");
    if (!out) { perror("fopen"); return 2; }
    fprintf(out, "%ld\n", usage.ru_maxrss);
    if (fclose(out)) return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
}
