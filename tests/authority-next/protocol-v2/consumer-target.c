/* SPDX-License-Identifier: MIT */
/* Harmless native target and independent libc accounting decoder. Runtime is
 * permitted only beneath the separately attested disposable guest observer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <lastlog.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utmp.h>

extern char **environ;

static void hex(const char *text)
{
    static const char digits[] = "0123456789abcdef";
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        putchar(digits[*p >> 4]); putchar(digits[*p & 15]);
    }
    putchar('"');
}

static unsigned number(const char *text)
{
    char *end;
    unsigned long value;
    errno = 0; value = strtoul(text, &end, 10);
    if (errno || !*text || *end || value >= UINT_MAX) exit(125);
    return (unsigned)value;
}

static int accounting(unsigned uid, const char *user, const char *tty)
{
    const char *paths[] = {"/var/run/utmp", "/var/log/wtmp"};
    unsigned counts[2] = {0, 0};
    long pid = 0;
    for (unsigned i = 0; i < 2; i++) {
        struct utmp record;
        ssize_t n;
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 125;
        while ((n = read(fd, &record, sizeof record)) == sizeof record) {
            if (record.ut_type == USER_PROCESS && record.ut_tv.tv_sec > 0 &&
                !strncmp(record.ut_user, user, sizeof record.ut_user) &&
                !strncmp(record.ut_line, tty, sizeof record.ut_line)) {
                counts[i]++; pid = record.ut_pid;
            }
        }
        close(fd);
        if (n) return 125;
    }
    int fd = open("/var/log/lastlog", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct lastlog record;
    if (fd < 0) return 125;
    ssize_t n = pread(fd, &record, sizeof record, (off_t)uid * sizeof record);
    close(fd);
    if (n != sizeof record) return 125;
    int last = record.ll_time > 0 && !strncmp(record.ll_line, tty, sizeof record.ll_line);
    printf("AUTHORITY_ACCOUNTING_V2 {\"utmp\":%u,\"wtmp\":%u,\"lastlog\":%d,\"pid\":%ld,\"utmp_size\":%zu,\"lastlog_size\":%zu}\n",
           counts[0], counts[1], last, pid, sizeof(struct utmp), sizeof(struct lastlog));
    return ferror(stdout) ? 125 : 0;
}

static int bad_actor(int argc, char **argv)
{
    /* Intentional independent oracle controls. The supervisor must reject their
     * traces, even when its execution guard prevents the bad target exec. */
    if (argc != 6 || getuid() || geteuid()) return 125;
    if (!strcmp(argv[2], "orphan-connection")) {
        int gate[2];
        char ready;
        if (pipe2(gate, O_CLOEXEC)) return 125;
        pid_t child = fork();
        if (child < 0) return 125;
        if (!child) {
            close(gate[0]);
            if (write(gate[1], "R", 1) != 1) _exit(125);
            close(gate[1]);
            for (;;) pause();
        }
        close(gate[1]);
        ssize_t n;
        do { n = read(gate[0], &ready, 1); } while (n < 0 && errno == EINTR);
        close(gate[0]);
        /* Deliberately return while the owned child is alive. The observer
           must reject this lifecycle and clean only this adopted descendant. */
        return n == 1 && ready == 'R' ? 0 : 125;
    }
    uid_t uid = number(argv[3]);
    gid_t gid = number(argv[4]);
    if (setgroups(1, &gid)) return 125;
    if (!strcmp(argv[2], "continue-after-fault")) {
        if (setresgid(gid, gid, gid)) return 125;
        (void)setresuid(uid, uid, uid); /* deliberately ignore the selected fault */
    } else if (!strcmp(argv[2], "ignore-saved-ids")) {
        if (setresgid((gid_t)-1, gid, (gid_t)-1) ||
            setresuid((uid_t)-1, uid, (uid_t)-1)) return 125;
    } else return 125;
    execl(argv[5], argv[5], "bad-control", (char *)NULL);
    return 126;
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "--accounting"))
        return accounting(number(argv[2]), argv[3], argv[4]);
    if (argc > 1 && !strcmp(argv[1], "--observer-control")) return bad_actor(argc, argv);
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid, groups[256];
    char cwd[PATH_MAX];
    int count = getgroups(256, groups);
    if (getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) ||
        count < 0 || !getcwd(cwd, sizeof cwd)) return 125;
    printf("\nAUTHORITY_TARGET_V2 {\"pid\":%ld,\"uid\":[%u,%u,%u],\"gid\":[%u,%u,%u],\"groups\":[",
           (long)getpid(), ruid, euid, suid, rgid, egid, sgid);
    for (int i = 0; i < count; i++) printf("%s%u", i ? "," : "", groups[i]);
    printf("],\"cwd_hex\":"); hex(cwd);
    printf(",\"argv_hex\":[");
    for (int i = 0; i < argc; i++) { if (i) putchar(','); hex(argv[i]); }
    printf("],\"env_hex\":[");
    for (size_t i = 0; environ[i]; i++) { if (i) putchar(','); hex(environ[i]); }
    puts("]}");
    return ferror(stdout) ? 125 : 37;
}
