/* SPDX-License-Identifier: MIT */
/* x86-64 guest-only ptrace observer for the selected ioctl requests. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <net/if.h>
#include <net/route.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_child(pid_t pid, unsigned long ptr, void *dst, size_t n) {
    unsigned char *p = dst;
    for (size_t off = 0; off < n; off += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(ptr + off), 0);
        if (word == -1 && errno) return -1;
        size_t count = n - off < sizeof word ? n - off : sizeof word;
        memcpy(p + off, &word, count);
    }
    return 0;
}
static void hex(FILE *f, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n && p[i]; i++) fprintf(f, "%02x", p[i]);
}
static int wait_for(pid_t p, int *st) {
    pid_t r; do r = waitpid(p, st, 0); while (r < 0 && errno == EINTR);
    return r == p;
}
static int drop_caps(void) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct d[2] = {{0}};
    if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
              SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED) < 0) return -1;
    return syscall(SYS_capset, &h, d);
}
static int caps(pid_t pid, char out[32]) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    int ok = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "CapEff: %31[0-9a-fA-F]", out) == 1) { ok = 1; break; }
    fclose(f); return ok ? 0 : -1;
}
struct saved { unsigned long req; int valid; const char *window; struct ifreq ifr; struct rtentry rt; unsigned char dev[IFNAMSIZ]; int devok; };
static void save(pid_t p, struct saved *s, unsigned long req, unsigned long ptr, const char *window) {
    memset(s, 0, sizeof *s); s->req = req; s->window = window;
    if (req == SIOCADDRT) {
        s->valid = read_child(p, ptr, &s->rt, sizeof s->rt) == 0;
        if (s->valid && s->rt.rt_dev) {
            s->devok = 1;
            for (size_t i = 0; i < sizeof s->dev; i++) {
                unsigned char c;
                if (read_child(p, (unsigned long)s->rt.rt_dev + i, &c, 1) < 0) { s->devok = 0; break; }
                s->dev[i] = c;
                if (!c) break;
            }
        }
    } else if (req == SIOCSIFADDR || req == SIOCSIFNETMASK || req == SIOCGIFFLAGS || req == SIOCSIFFLAGS)
        s->valid = read_child(p, ptr, &s->ifr, sizeof s->ifr) == 0;
    else s->valid = 1;
}
static void address(FILE *f, const char *name, const struct sockaddr *sa) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
    char buf[INET_ADDRSTRLEN] = "?";
    if (sa->sa_family == AF_INET) inet_ntop(AF_INET, &a->sin_addr, buf, sizeof buf);
    fprintf(f, ",\"%s_family\":%d,\"%s\":\"%s\"", name, sa->sa_family, name, buf);
}
static void emit(FILE *f, struct saved *s, long ret) {
    fprintf(f, "{\"type\":\"ioctl\",\"window\":\"%s\",\"request\":%lu,\"valid\":%s,\"return\":%ld,\"errno\":%ld",
            s->window, s->req, s->valid ? "true" : "false", ret, ret < 0 && ret >= -4095 ? -ret : 0L);
    if (s->valid && s->req == SIOCADDRT) {
        address(f, "dst", &s->rt.rt_dst); address(f, "mask", &s->rt.rt_genmask);
        address(f, "gateway", &s->rt.rt_gateway);
        fprintf(f, ",\"flags\":%u,\"dev_present\":%s,\"dev_valid\":%s,\"dev_hex\":\"",
                (unsigned)s->rt.rt_flags, s->rt.rt_dev ? "true" : "false", s->devok ? "true" : "false");
        hex(f, s->dev, sizeof s->dev); fprintf(f, "\"");
    } else if (s->valid && (s->req == SIOCSIFADDR || s->req == SIOCSIFNETMASK ||
                            s->req == SIOCGIFFLAGS || s->req == SIOCSIFFLAGS)) {
        fprintf(f, ",\"ifname_hex\":\""); hex(f, (const unsigned char *)s->ifr.ifr_name, IFNAMSIZ); fprintf(f, "\"");
        if (s->req == SIOCSIFADDR || s->req == SIOCSIFNETMASK) address(f, "address", &s->ifr.ifr_addr);
        if (s->req == SIOCSIFFLAGS) fprintf(f, ",\"flags\":%u", (unsigned short)s->ifr.ifr_flags);
    }
    fprintf(f, "}\n"); fflush(f);
}
int main(int argc, char **argv) {
    if (argc < 5 || (strcmp(argv[2], "keep") && strcmp(argv[2], "drop")) || strcmp(argv[3], "mark")) return 90;
    FILE *f = fopen(argv[1], "w"); if (!f || fcntl(fileno(f), F_SETFD, FD_CLOEXEC) < 0) return 91;
    pid_t child = fork();
    if (child < 0) return 92;
    if (!child) {
        if (!strcmp(argv[2], "drop") && drop_caps() < 0) _exit(120);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(121);
        raise(SIGSTOP); execv(argv[4], &argv[4]); _exit(122);
    }
    int st, entering = 1, active = 0, exec_seen = 0, deliver = 0, ended = 0, marked = 0; struct saved s;
    if (!wait_for(child, &st) || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) goto bad;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) < 0) goto bad;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, 0, (void *)(long)deliver) < 0 || !wait_for(child, &st)) goto bad;
        deliver = 0;
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            fprintf(f, "{\"type\":\"exit\",\"status\":%d,\"signal\":%d}\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
            fclose(f); return exec_seen ? 0 : 93;
        }
        if (!WIFSTOPPED(st)) goto bad;
        if (WSTOPSIG(st) == SIGTRAP && ((unsigned)st >> 16) == PTRACE_EVENT_EXEC) {
            char cap[32]; if (caps(child, cap) < 0) goto bad;
            fprintf(f, "{\"type\":\"exec\",\"cap_eff\":\"%s\"}\n", cap); fflush(f); exec_seen = 1; continue;
        }
        if (WSTOPSIG(st) == SIGSTOP && exec_seen && !ended) {
            fprintf(f, "{\"type\":\"marker\",\"phase\":\"%s\"}\n", marked ? "end" : "begin");
            fflush(f);
            if (marked) { marked = 0; ended = 1; } else marked = 1;
            continue;
        }
        if (WSTOPSIG(st) != (SIGTRAP | 0x80)) { deliver = WSTOPSIG(st); continue; }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) < 0) goto bad;
        if (entering) {
            active = 0;
            if ((long)regs.orig_rax == SYS_ioctl) {
                const char *window = marked ? "inside" : ended ? "after" : "before";
                active = 1; save(child, &s, regs.rsi, regs.rdx, window);
            } else if ((long)regs.orig_rax == SYS_clone || (long)regs.orig_rax == SYS_fork ||
                       (long)regs.orig_rax == SYS_vfork
#ifdef SYS_clone3
                       || (long)regs.orig_rax == SYS_clone3
#endif
                       ) active = 2;
        } else if (active == 1) emit(f, &s, (long)regs.rax);
        else if (active == 2) {
            fprintf(f, "{\"type\":\"spawn\",\"syscall\":%ld,\"return\":%ld}\n", (long)regs.orig_rax, (long)regs.rax);
            fflush(f);
        }
        entering = !entering;
    }
bad:
    fprintf(f, "{\"type\":\"observer_error\",\"errno\":%d}\n", errno); fclose(f);
    kill(child, SIGKILL); wait_for(child, &st); return 94;
}
