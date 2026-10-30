/* SPDX-License-Identifier: MIT */
/* Guest-only guard: a signal syscall terminates the calling process before delivery. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

#if !defined(__x86_64__)
#error This fixture guard requires x86_64
#endif
#define BLOCK(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
                  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
static int guard(void) {
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BLOCK(__NR_kill), BLOCK(__NR_tkill), BLOCK(__NR_tgkill),
        BLOCK(__NR_rt_sigqueueinfo), BLOCK(__NR_rt_tgsigqueueinfo),
        BLOCK(__NR_pidfd_send_signal),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog prog = { .len = sizeof insns / sizeof insns[0], .filter = insns };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) return -1;
    return 0;
}
static int control(void) {
    const long calls[] = {__NR_kill, __NR_tkill, __NR_tgkill, __NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo,
        __NR_pidfd_send_signal,
    };
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) {
        pid_t p = fork(); int status = 0; pid_t w;
        if (p < 0) { perror("fork"); return 90; }
        if (p == 0) {
            if (guard()) _exit(91);
            syscall(calls[i], getpid(), 0, 0, 0);
            _exit(92);
        }
        do w = waitpid(p, &status, 0); while (w < 0 && errno == EINTR);
        if (w != p || !WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
            fprintf(stderr, "guard control syscall=%ld status=%d wait=%ld\n", calls[i], status, (long)w);
            return 93;
        }
        printf("blocked syscall=%ld signal=%d\n", calls[i], WTERMSIG(status));
    }
    return 0;
}
int main(int argc, char **argv) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) { perror("setrlimit"); return 97; }
    if (argc == 2 && strcmp(argv[1], "--check") == 0) return control();
    if (argc < 2) return 94;
    if (guard()) { perror("seccomp guard"); return 95; }
    execv(argv[1], argv + 1);
    perror("exec candidate"); return 96;
}
