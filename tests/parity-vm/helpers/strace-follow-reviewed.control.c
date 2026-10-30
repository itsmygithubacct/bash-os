/* Guest-only independent ptrace observer; it traces only its own descendants. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    pid_t root = fork(), child = -1;
    if (root < 0) { perror("fork"); return 98; }
    if (root == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME"); _exit(96); }
        raise(SIGSTOP);
        execl("./follow-tracee", "./follow-tracee", (char *)0);
        perror("exec"); _exit(96);
    }
    int s, alive = 1, root_ok = 0, child_ok = 0, root_live = 1, child_live = 0;
    pid_t first;
    do first = waitpid(root, &s, 0); while (first < 0 && errno == EINTR);
    if (first != root) { root_live = 0; goto fail; }
    if (WIFEXITED(s) || WIFSIGNALED(s)) root_live = 0;
    if (!WIFSTOPPED(s) || WSTOPSIG(s) != SIGSTOP) goto fail;
    if (ptrace(PTRACE_SETOPTIONS, root, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_EXITKILL) < 0) goto fail;
    if (ptrace(PTRACE_SYSCALL, root, 0, 0) < 0) goto fail;
    while (alive) {
        pid_t p;
        do p = waitpid(-1, &s, __WALL); while (p < 0 && errno == EINTR);
        if (p < 0) { if (errno == ECHILD) root_live = child_live = 0; goto fail; }
        if (WIFEXITED(s)) {
            fprintf(stderr, "EXIT %ld %d\n", (long)p, WEXITSTATUS(s));
            if (p == root) root_live = 0;
            if (p == child) child_live = 0;
            if (p == root && WEXITSTATUS(s) == 42) root_ok = 1;
            if (p == child && WEXITSTATUS(s) == 23) child_ok = 1;
            alive--; continue;
        }
        if (WIFSIGNALED(s)) {
            if (p == root) root_live = 0;
            if (p == child) child_live = 0;
            goto fail;
        }
        if (!WIFSTOPPED(s)) goto fail;
        int sig = WSTOPSIG(s), deliver = 0;
        unsigned event = (unsigned)s >> 16;
        if (p != root && child == -1 && sig == SIGSTOP) {
            child = p; child_live = 1; alive++;
        }
        if (p != root && p != child) goto fail;
        if (event == PTRACE_EVENT_FORK) {
            unsigned long n = 0;
            if (p != root || ptrace(PTRACE_GETEVENTMSG, p, 0, &n) < 0 || !n ||
                (child != -1 && child != (pid_t)n)) goto fail;
            if (child == -1) { child = (pid_t)n; child_live = 1; alive++; }
            fprintf(stderr, "FORK %ld %ld\n", (long)p, (long)child);
        } else if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, p, 0, &r) < 0) goto fail;
            fprintf(stderr, "CALL %ld %ld %ld\n", (long)p, (long)r.orig_rax, (long)r.rax);
        } else if (sig != SIGSTOP && sig != SIGTRAP) deliver = sig;
        if (ptrace(PTRACE_SYSCALL, p, 0, (void *)(long)deliver) < 0) goto fail;
    }
    return root_ok && child_ok && child > 0 ? 0 : 98;
fail:
    perror("native control");
    if (root_live) kill(root, SIGKILL);
    if (child_live) kill(child, SIGKILL);
    while (waitpid(-1, &s, __WALL) > 0 || errno == EINTR) { }
    return 98;
}
