/* SPDX-License-Identifier: MIT */
/* Qualification only: install a syscall listener, then enter the unmodified
 * native executor. The production executor contains no observer hook. The
 * independently pinned root guest observer owns the listener and verdict. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/nsfs.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef BA_EXECUTOR_SOURCE
#define BA_EXECUTOR_SOURCE "../../../kernel/bashos-auth/authority/v2/executor.c"
#endif
#define main ba_executor_unmodified_main
#include BA_EXECUTOR_SOURCE
#undef main

/* UMH starts outside the evaluator's private network namespace. The abstract
 * observer socket lives inside it. Select only the unique nsfs network handle
 * already installed by the kernel from the bound actor; never select a namespace
 * by caller pathname, environment, PID or guessed descriptor number. Leave the
 * held descriptor available to the unmodified executor's normal setup. */
static int observer_network(void)
{
	DIR *directory = opendir("/proc/self/fd");
	struct dirent *entry;
	unsigned int count = 0;
	int net = -1, result = -1, saved = 0;
	if (!directory) return -1;
	for (;;) {
		char *end;
		long descriptor;
		errno = 0; entry = readdir(directory);
		if (!entry) { saved = errno; break; }
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
		if (++count > 64) { saved = E2BIG; break; }
		errno = 0; descriptor = strtol(entry->d_name, &end, 10);
		if (errno || *end || descriptor < 0 || descriptor > INT_MAX) { saved = EINVAL; break; }
		if (ioctl((int)descriptor, NS_GET_NSTYPE) != CLONE_NEWNET) continue;
		if (net >= 0) { saved = EEXIST; break; }
		net = (int)descriptor;
	}
	if (closedir(directory) && !saved) saved = errno;
	if (!saved && net >= 0) result = setns(net, CLONE_NEWNET);
	else errno = saved ? saved : ENOENT;
	return result;
}

#define OBSERVE(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
static int observer_connect(void)
{
	static const char address[] = "\0bashos-privcmd-v2-qualification-observer";
	struct sockaddr_un peer = {.sun_family = AF_UNIX};
	struct ucred cred;
	unsigned char admission = 0;
	ssize_t n;
	socklen_t size = sizeof(cred);
	struct timeval timeout = {.tv_sec = 10};
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	memcpy(peer.sun_path, address, sizeof(address) - 1);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
	    connect(fd, (struct sockaddr *)&peer, offsetof(struct sockaddr_un, sun_path) + sizeof(address) - 1) ||
	    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) || size != sizeof(cred) ||
	    cred.uid || cred.gid || cred.pid <= 0) {
		close(fd); return -1;
	}
	/* The observer must first bind the live peer PID, credentials, executable
	 * and namespace. A rejected/invisible peer must never install a filter
	 * whose exit notifications have nobody left to service them. */
	do { n = recv(fd, &admission, sizeof(admission), 0); } while (n < 0 && errno == EINTR);
	if (n != 1 || admission != 2) { close(fd); errno = EACCES; return -1; }
	return fd;
}

static _Noreturn void observer_abort(void)
{
	/* After listener installation, exit/exit_group are themselves observed.
	 * On an incomplete handshake, uncatchable self-termination avoids libc's
	 * failed-exit trap when a disconnected listener returns ENOSYS. This is a
	 * setup ERROR, never a candidate abort observation or qualification. */
	(void)syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGKILL);
	for (;;) (void)syscall(SYS_pause);
}

static int install_observer(int server)
{
	struct sock_filter instructions[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		OBSERVE(setgroups), OBSERVE(setresgid), OBSERVE(setresuid), OBSERVE(capset),
		OBSERVE(getresuid), OBSERVE(getresgid), OBSERVE(setfsuid), OBSERVE(setfsgid),
		OBSERVE(execve), OBSERVE(execveat), OBSERVE(exit), OBSERVE(exit_group),
		/* Alternative credential changes are observed and rejected, not a
		 * route around the expected ordered calls. */
		OBSERVE(setuid), OBSERVE(setgid), OBSERVE(setreuid), OBSERVE(setregid),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog filter = {sizeof(instructions) / sizeof(instructions[0]), instructions};
	union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
	unsigned char payload[8] = {'B', 'A', 'E', 'X', 'O', 'B', 'S', 2}, ack = 0;
	struct iovec vector = {payload, sizeof(payload)};
	struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
		.msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);
	int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		SECCOMP_FILTER_FLAG_NEW_LISTENER, &filter);
	ssize_t n;
	if (listener < 0) return -1;
	/* This root-only test bootstrap uses CAP_SYS_ADMIN to install the filter.
	 * It does not pre-set no_new_privs or change credentials for the source
	 * being tested. The listener is not inherited by the executor child. */
	header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(listener));
	memcpy(CMSG_DATA(header), &listener, sizeof(listener));
	do { n = sendmsg(server, &message, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
	close(listener);
	if (n != (ssize_t)sizeof(payload)) observer_abort();
	do { n = recv(server, &ack, sizeof(ack), 0); } while (n < 0 && errno == EINTR);
	if (n != 1 || ack != 1) observer_abort();
	return 0;
}

int main(int argc, char **argv)
{
	int server;
	if (getuid() || geteuid() || getgid() || getegid()) return 125;
	if (observer_network()) return 125;
	server = observer_connect();
	if (server < 0) return 125;
	if (install_observer(server)) { close(server); return 125; }
	close(server);
	return ba_executor_unmodified_main(argc, argv);
}
