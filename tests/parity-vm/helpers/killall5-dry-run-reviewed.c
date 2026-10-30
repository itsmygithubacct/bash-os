/* SPDX-License-Identifier: MIT */
/* Guest-only guard: a signal syscall terminates the calling process before delivery. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
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
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#if !defined(__x86_64__)
#error This fixture guard requires x86_64
#endif
#define BLOCK(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
                  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* ABI 1 is sufficient; do not depend on a recent guest's kernel headers. */
struct ll_ruleset { uint64_t handled_access_fs; };
struct ll_path { uint64_t allowed_access; int32_t parent_fd; } __attribute__((packed));
enum { LL_READ_FILE = 1 << 2, LL_READ_DIR = 1 << 3, LL_PATH_BENEATH = 1 };

/* Reject procfs mounts outside /proc: no allowed tree may contain an alias. */
static int proc_mounts_safe(void) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    char *line = NULL; size_t cap = 0; int ok = 1;
    if (!f) return -1;
    while (getline(&line, &cap, f) >= 0) {
        if (!strstr(line, " - proc ")) continue;
        char *save = NULL, *field = strtok_r(line, " ", &save);
        for (int n = 1; n < 5 && field; n++) field = strtok_r(NULL, " ", &save);
        if (!field || (strcmp(field, "/proc") && strncmp(field, "/proc/", 6))) { ok = 0; break; }
    }
    if (ferror(f)) ok = 0;
    free(line); fclose(f);
    if (!ok) { errno = EPERM; return -1; }
    return 0;
}
static int allow_path(int ruleset, const char *path, uint64_t rights) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct ll_path rule = { rights, fd };
    int r = (int) syscall(445, ruleset, LL_PATH_BENEATH, &rule, 0);
    int saved = errno; close(fd); errno = saved;
    return r;
}
static int confine(void) {
    if (proc_mounts_safe() || syscall(444, NULL, 0, 1) < 1) return -1;
    struct ll_ruleset attr = { LL_READ_FILE | LL_READ_DIR };
    int rs = (int) syscall(444, &attr, sizeof attr, 0);
    if (rs < 0) return -1;
    const char *dirs[] = { "/usr", "/lib", "/lib64", "/bin", "/etc", "/opt/bashos-parity", "/tmp/parity-case", "/tmp/parity-home" };
    const char *files[] = { "/sys/class/dmi/id/sys_vendor", "/dev/null", "/dev/urandom", "/proc/self/stat" };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (allow_path(rs, dirs[i], LL_READ_FILE | LL_READ_DIR)) goto fail;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++)
        if (allow_path(rs, files[i], LL_READ_FILE)) goto fail;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(446, rs, 0)) goto fail;
    close(rs);
    return 0;
fail:
    { int saved = errno; close(rs); errno = saved; return -1; }
}

/* Open attempts only; this never reads or enumerates a real proc directory. */
static int probe(pid_t caller) {
    char own[80];
    if (caller <= 1 || snprintf(own, sizeof own, "/proc/%ld/stat", (long)caller) >= (int)sizeof own) return 1;
    const char *denied[] = { "/proc", "/proc/self", "/proc/1", "/proc/1/stat", "/proc/self/cmdline", "/proc/self/mountinfo" };
    for (size_t i = 0; i < sizeof denied / sizeof denied[0]; i++) {
        int fd = open(denied[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { close(fd); fprintf(stderr, "unexpectedly readable: %s\n", denied[i]); return 1; }
        if (errno != EACCES) { fprintf(stderr, "unexpected denial %s: %s\n", denied[i], strerror(errno)); return 1; }
        printf("denied %s EACCES\n", denied[i]);
    }
    int fd = open(own, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("caller stat"); return 1; }
    close(fd);
    fd = open("/tmp/parity-case", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) { perror("fixture directory"); return 1; }
    close(fd);
    printf("allowed caller-stat fixture-directory\n");
    return 0;
}
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
        BLOCK(__NR_mount), BLOCK(__NR_umount2), BLOCK(__NR_unshare), BLOCK(__NR_setns),
        BLOCK(__NR_ptrace), BLOCK(__NR_process_vm_readv), BLOCK(__NR_open_by_handle_at),
        BLOCK(__NR_pidfd_getfd),
        BLOCK(__NR_io_uring_setup),
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
    if (argc == 2 && strcmp(argv[1], "--check-scope") == 0) {
        if (confine() || guard()) { perror("scope setup"); return 98; }
        return probe(getpid());
    }
    if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
        char *end; long p = strtol(argv[2], &end, 10);
        if (*end || p <= 1 || p > 2147483647) return 99;
        return probe((pid_t)p);
    }
    if (argc < 2) return 94;
    if (confine()) { perror("proc confinement"); return 98; }
    if (guard()) { perror("seccomp guard"); return 95; }
    if (syscall(436, 3U, ~0U, 0U)) { perror("close_range"); return 99; }
    execv(argv[1], argv + 1);
    perror("exec candidate"); return 96;
}
