/* Guest-only stand-in for uv: inspect dispositions or die by a signal. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "defaults") == 0) {
        const int signals[] = { SIGINT, SIGQUIT };
        for (unsigned i = 0; i < sizeof signals / sizeof signals[0]; i++) {
            struct sigaction action;
            if (sigaction(signals[i], NULL, &action) < 0) return 3;
            printf("%s=%s\n", i ? "QUIT" : "INT",
                   action.sa_handler == SIG_DFL ? "default" :
                   action.sa_handler == SIG_IGN ? "ignored" : "caught");
        }
        return 0;
    }
    int sig = strcmp(argv[1], "term") == 0 ? SIGTERM :
              strcmp(argv[1], "kill") == 0 ? SIGKILL :
              strcmp(argv[1], "usr1") == 0 ? SIGUSR1 : 0;
    if (!sig || kill(getpid(), sig) < 0) return 4;
    return 5;
}
