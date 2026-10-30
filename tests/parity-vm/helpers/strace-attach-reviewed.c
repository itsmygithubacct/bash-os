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
#include <sys/mman.h>
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
/* [worker gate, leader gate, worker ready, leader ready]. */
_Static_assert(sizeof(atomic_int) == 4, "fixture requires 32-bit atomic int");
static atomic_int *shared;
static atomic_int worker_tid;
static void await_gate(int index) {
    while (atomic_load(&shared[index]) != 1) { }
}
static void *worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid, (int)syscall(SYS_gettid));
    atomic_store(&shared[2], 1);
    await_gate(0);
    long parent = syscall(SYS_getppid);
    if (parent <= 0 || write(1, "worker-done\n", 12) != 12) _exit(92);
    return NULL;
}
static int tracee(pid_t tracer, const char *prefix) {
    char path[256];
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1 ||
        prctl(PR_SET_PTRACER, tracer, 0, 0, 0)) { perror("tracee prctl"); return 93; }
    alarm(25);
    snprintf(path, sizeof path, "%s.shared", prefix);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("shared open"); return 93; }
    shared = mmap(NULL, 16, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shared == MAP_FAILED) { perror("shared mmap"); return 93; }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return 93;
    while (!atomic_load(&worker_tid)) { }
    snprintf(path, sizeof path, "%s.ready", prefix);
    FILE *f = fopen(path, "w");
    if (!f) { perror("ready open"); return 93; }
    fprintf(f, "%ld %d\n", (long)getpid(), atomic_load(&worker_tid));
    if (fclose(f)) return 93;
    atomic_store(&shared[3], 1);
    await_gate(1);
    long pid = syscall(SYS_getpid);
    if (pid != getpid() || write(1, "leader-done\n", 12) != 12) return 94;
    if (pthread_join(thread, NULL)) return 94;
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
static int gate_write(int fd, int index) {
    int value = 1;
    return pwrite(fd, &value, sizeof value, index * 4) == sizeof value;
}
static int native_control(void) {
    int status = 0, ready = 0, flags[4] = {0}; long root = 0, tid = 0, expected = 0, parent = 0;
    int fd = open("native.shared", O_RDWR);
    if (fd < 0) { perror("native shared"); return 98; }
    for (int i = 0; i < 500; i++) {
        FILE *f = fopen("native.pid", "r");
        if (f) { int ok = fscanf(f, "%ld %ld", &expected, &parent) == 2; fclose(f); if (!ok) expected = 0; }
        f = fopen("native.ready", "r");
        if (f) { ready = fscanf(f, "%ld %ld", &root, &tid) == 2; fclose(f); }
        if (pread(fd, flags, sizeof flags, 0) != sizeof flags) { perror("native ready flags"); close(fd); return 98; }
        if (ready && expected > 0 && flags[2] == 1 && flags[3] == 1) break;
        struct timespec t = {0, 10000000}; nanosleep(&t, NULL);
    }
    pid_t pid = (pid_t)expected;
    if (!ready || root != pid || tid <= 0 || flags[2] != 1 || flags[3] != 1 || !tasks_match(pid, (pid_t)tid)) {
        fprintf(stderr, "native precondition failed ready=%d root=%ld tid=%ld expected=%ld flags=%d,%d\n", ready, root, tid, expected, flags[2], flags[3]); close(fd); return 98;
    }
    pid_t ids[2] = {pid, (pid_t)tid};
    for (int i = 0; i < 2; i++) {
        if (ptrace(PTRACE_ATTACH, ids[i], 0, 0) < 0) { perror("native PTRACE_ATTACH"); goto fail; }
        if (!wait_one(ids[i], &status) || !WIFSTOPPED(status)) { fprintf(stderr, "native attach wait %#x\n", status); goto fail; }
        if (ptrace(PTRACE_SETOPTIONS, ids[i], 0, PTRACE_O_TRACESYSGOOD) < 0) { perror("native SETOPTIONS"); goto fail; }
    }
    for (int i = 0; i < 2; i++) if (ptrace(PTRACE_SYSCALL, ids[i], 0, 0) < 0) { perror("native resume"); goto fail; }
    if (!gate_write(fd, 0)) { perror("native worker release"); goto fail; }
    int alive = 2, seen[2] = {0, 0}, pending[2] = {0, 0}, exited[2] = {0, 0};
    while (alive) {
        pid_t got; do got = waitpid(-1, &status, __WALL); while (got < 0 && errno == EINTR);
        if (got < 0) { perror("native wait"); goto fail; }
        int index = got == ids[0] ? 0 : got == ids[1] ? 1 : -1;
        if (index < 0) { fprintf(stderr, "native unknown tid=%ld\n", (long)got); goto fail; }
        if (WIFEXITED(status)) {
            fprintf(stderr, "native exit tid=%ld status=%d\n", (long)got, WEXITSTATUS(status));
            if (exited[index] || WEXITSTATUS(status) || !seen[index]) goto fail;
            exited[index] = 1; alive--;
            if (index == 1 && !gate_write(fd, 1)) { perror("native leader release"); goto fail; }
            continue;
        }
        if (!WIFSTOPPED(status)) { fprintf(stderr, "native unexpected status %#x\n", status); goto fail; }
        if (WSTOPSIG(status) == SIGSTOP) {
            if (ptrace(PTRACE_SYSCALL, got, 0, 0) < 0 && errno != ESRCH) { perror("native resume stop"); goto fail; }
            continue;
        }
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) { fprintf(stderr, "native unexpected stop %#x\n", status); goto fail; }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, got, 0, &regs) < 0) { perror("native GETREGS"); goto fail; }
        long wanted = index == 0 ? SYS_getpid : SYS_getppid;
        if ((long)regs.orig_rax == wanted) {
            if ((long)regs.rax == -ENOSYS) pending[index] = 1;
            else if (pending[index]) {
                long value = (long)regs.rax, expected_value = index == 0 ? root : parent;
                fprintf(stderr, "native syscall tid=%ld nr=%ld result=%ld expected=%ld\n", (long)got, wanted, value, expected_value);
                if (value != expected_value) goto fail;
                pending[index] = 0; seen[index]++;
            }
        }
        if (ptrace(PTRACE_SYSCALL, got, 0, 0) < 0 && errno != ESRCH) { perror("native resume event"); goto fail; }
    }
    close(fd);
    fprintf(stderr, "native ids=%ld,%ld leader_getpid=%d worker_getppid=%d exits=2\n", root, tid, seen[0], seen[1]);
    return seen[0] && seen[1] ? 0 : 98;
fail:
    close(fd); return 98;
}
int main(int argc, char **argv) {
    guard();
    if (argc == 2 && !strcmp(argv[1], "native")) return native_control();
    if (argc == 4 && !strcmp(argv[1], "tracee")) return tracee((pid_t)strtol(argv[2], NULL, 10), argv[3]);
    return 99;
}
