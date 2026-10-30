/* SPDX-License-Identifier: MIT */
/* Guest-only, owned two-thread attach fixture and native ptrace control. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void guard(void) {
    char vendor[32], marker[64], uuid[64], cwd[128];
    FILE *f = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (!f || !fgets(vendor, sizeof vendor, f)) exit(90);
    fclose(f);
    f = fopen("/etc/bashos-parity-vm", "r");
    if (!f || !fgets(marker, sizeof marker, f)) exit(90);
    fclose(f);
    f = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (!f || !fgets(uuid, sizeof uuid, f)) exit(90);
    fclose(f);
    if (getuid() != 2000 || geteuid() != 2000 || strcmp(vendor, "QEMU\n") ||
        strlen(marker) != 37 || strcasecmp(marker, uuid) ||
        !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/tmp/parity-case") ||
        !getenv("HOME") || strcmp(getenv("HOME"), "/tmp/parity-home")) exit(90);
}
static atomic_int worker_tid;
static int gate;
static void await_gate(void) {
    char c;
    ssize_t n;
    do n = read(gate, &c, 1); while (n < 0 && errno == EINTR);
    if (n != 1 || c != 'G') _exit(91);
}
static void *worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid, (int)syscall(SYS_gettid));
    await_gate();
    long parent = syscall(SYS_getppid);
    if (parent <= 0 || write(1, "worker-done\n", 12) != 12) _exit(92);
    return NULL;
}
static int tracee(pid_t tracer, const char *prefix) {
    char path[256];
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1 ||
        prctl(PR_SET_PTRACER, tracer, 0, 0, 0)) { perror("tracee prctl"); return 93; }
    alarm(14);
    snprintf(path, sizeof path, "%s.gate", prefix);
    gate = open(path, O_RDWR | O_CLOEXEC);
    if (gate < 0) { perror("gate open"); return 93; }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return 93;
    while (!atomic_load(&worker_tid)) { struct timespec t = {0, 1000000}; nanosleep(&t, NULL); }
    snprintf(path, sizeof path, "%s.ready", prefix);
    FILE *f = fopen(path, "w");
    if (!f) { perror("ready open"); return 93; }
    fprintf(f, "%ld %d\n", (long)getpid(), atomic_load(&worker_tid));
    if (fclose(f)) return 93;
    await_gate();
    long pid = syscall(SYS_getpid);
    if (pid != getpid() || write(1, "leader-done\n", 12) != 12) return 94;
    if (pthread_join(thread, NULL)) return 94;
    close(gate);
    return 0;
}
static int wait_one(pid_t pid, int *status) {
    pid_t got;
    do got = waitpid(pid, status, __WALL); while (got < 0 && errno == EINTR);
    return got == pid;
}
static int tasks_match(pid_t pid, pid_t tid) {
    char path[128]; snprintf(path, sizeof path, "/proc/%ld/task", (long)pid);
    DIR *d = opendir(path); if (!d) return 0;
    int count = 0, leader = 0, worker = 0; struct dirent *e;
    while ((e = readdir(d))) {
        char *end; long n = strtol(e->d_name, &end, 10);
        if (*e->d_name && !*end) { count++; leader |= n == pid; worker |= n == tid; }
    }
    closedir(d); return count == 2 && leader && worker && pid != tid;
}
static int native_control(const char *self) {
    (void)self;
    int status = 0, ready = 0; long root = 0, tid = 0, expected = 0;
    for (int i = 0; i < 500; i++) {
        FILE *f = fopen("native.pid", "r");
        if (f) { int ok = fscanf(f, "%ld", &expected) == 1; fclose(f); if (!ok) expected = 0; }
        f = fopen("native.ready", "r");
        if (f) { ready = fscanf(f, "%ld %ld", &root, &tid) == 2; fclose(f); }
        if (ready && expected > 0) break;
        struct timespec t = {0, 10000000}; nanosleep(&t, NULL);
    }
    pid_t pid = (pid_t)expected;
    if (!ready || root != pid || tid <= 0 || !tasks_match(pid, (pid_t)tid)) {
        fprintf(stderr, "native fixture precondition failed: ready=%d root=%ld tid=%ld expected=%ld\n", ready, root, tid, expected); return 98;
    }
    pid_t ids[2] = {pid, (pid_t)tid};
    for (int i = 0; i < 2; i++) {
        if (ptrace(PTRACE_ATTACH, ids[i], 0, 0) < 0) { perror("native PTRACE_ATTACH"); goto fail; }
        if (!wait_one(ids[i], &status) || !WIFSTOPPED(status)) { fprintf(stderr, "native attach wait %#x\n", status); goto fail; }
        if (ptrace(PTRACE_SETOPTIONS, ids[i], 0, PTRACE_O_TRACESYSGOOD) < 0) { perror("native SETOPTIONS"); goto fail; }
    }
    for (int i = 0; i < 2; i++) if (ptrace(PTRACE_SYSCALL, ids[i], 0, 0) < 0) { perror("native resume"); goto fail; }
    int fd = open("native.gate", O_WRONLY | O_NONBLOCK);
    if (fd < 0 || write(fd, "GG", 2) != 2) { perror("native release"); if (fd >= 0) close(fd); goto fail; }
    close(fd);
    int alive = 2, leader_seen = 0, worker_seen = 0, exits = 0, exited[2] = {0, 0};
    while (alive) {
        pid_t got; do got = waitpid(-1, &status, __WALL); while (got < 0 && errno == EINTR);
        if (got < 0) { perror("native wait"); goto fail; }
        if (WIFEXITED(status)) {
            int index = got == ids[0] ? 0 : got == ids[1] ? 1 : -1;
            fprintf(stderr, "native exit tid=%ld status=%d\n", (long)got, WEXITSTATUS(status));
            if (index < 0 || exited[index] || WEXITSTATUS(status)) goto fail;
            exited[index] = 1; exits++; alive--; continue;
        }
        if (!WIFSTOPPED(status)) { fprintf(stderr, "native unexpected status %#x\n", status); goto fail; }
        if (WSTOPSIG(status) == SIGSTOP) {
            if (ptrace(PTRACE_SYSCALL, got, 0, 0) < 0 && errno != ESRCH) { perror("native resume stop"); goto fail; }
            continue;
        }
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) { fprintf(stderr, "native unexpected stop %#x\n", status); goto fail; }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, got, 0, &regs) < 0) { perror("native GETREGS"); goto fail; }
        if ((long)regs.rax == -ENOSYS) {
            if (got == ids[0] && (long)regs.orig_rax == SYS_getpid) {
                leader_seen++; fprintf(stderr, "native syscall tid=%ld getpid\n", (long)got);
            }
            if (got == ids[1] && (long)regs.orig_rax == SYS_getppid) {
                worker_seen++; fprintf(stderr, "native syscall tid=%ld getppid\n", (long)got);
            }
        }
        if (ptrace(PTRACE_SYSCALL, got, 0, 0) < 0 && errno != ESRCH) { perror("native resume event"); goto fail; }
    }
    fprintf(stderr, "native ids=%ld,%ld leader_getpid=%d worker_getppid=%d exits=%d\n", root, tid, leader_seen, worker_seen, exits);
    return leader_seen && worker_seen && exits == 2 ? 0 : 98;
fail:
    return 98; /* The owner cleans up its child if control fails. */
}
int main(int argc, char **argv) {
    guard();
    if (argc == 2 && !strcmp(argv[1], "native")) return native_control(argv[0]);
    if (argc == 4 && !strcmp(argv[1], "tracee")) return tracee((pid_t)strtol(argv[2], NULL, 10), argv[3]);
    return 99;
}
