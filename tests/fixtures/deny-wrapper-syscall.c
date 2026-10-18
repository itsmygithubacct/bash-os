/* SPDX-License-Identifier: MIT */
/* Restrict only this private test process and its descendants. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main (int argc, char **argv)
{
    if (argc < 3) return 2;
    int number, error;
    if (!strcmp (argv[1], "pidfd")) {
#ifdef SYS_pidfd_open
        number = SYS_pidfd_open; error = ENOSYS;
#else
        return 77;
#endif
    } else if (!strcmp (argv[1], "ioprio")) {
        number = SYS_ioprio_set; error = EPERM;
    } else if (!strcmp (argv[1], "priority")) {
        number = SYS_setpriority; error = EPERM;
    } else return 2;
    struct sock_filter filter[] = {
        BPF_STMT (BPF_LD | BPF_W | BPF_ABS, offsetof (struct seccomp_data, nr)),
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, (unsigned) number, 0, 1),
        BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned) error),
        BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { sizeof filter / sizeof filter[0], filter };
    if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        prctl (PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0) {
        perror ("test seccomp setup");
        return 77;
    }
    execv (argv[2], argv + 2);
    perror ("test exec");
    return 126;
}
