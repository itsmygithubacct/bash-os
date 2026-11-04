/* SPDX-License-Identifier: MIT */
/* Pinned native command monitor. The private kernel channel supplies already
 * authorized, captured objects. This program does no policy lookup, password
 * verification, NSS resolution, PATH search, or interpreter evaluation. */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/close_range.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "executor-protocol.h"

_Static_assert(sizeof(struct ba_v2_exec_request) == 688, "executor request layout");
_Static_assert(sizeof(struct ba_v2_exec_response) == 96, "executor response layout");
struct child_error { uint32_t step, error; };
struct native_request {
	struct ba_v2_exec_request *wire;
	size_t size;
	char *argv[BA_V2_EXEC_MAX_ITEMS + 1], *env[BA_V2_EXEC_MAX_ITEMS + 1];
	int fds[BA_V2_EXEC_FDS];
	gid_t groups[BA_V2_EXEC_MAX_GROUPS];
	uint32_t group_count;
	uid_t uid;
	gid_t gid;
};

static void wipe(void *p, size_t n)
{
	volatile unsigned char *v = p;
	while (n--) *v++ = 0;
}

static int read_exact(int fd, void *data, size_t size)
{
	size_t have = 0;
	while (have < size) {
		ssize_t n = read(fd, (char *)data + have, size - have);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) { if (!n) errno = EPIPE; return -1; }
		have += (size_t)n;
	}
	return 0;
}

static int framed_strings(char *bytes, uint32_t size, uint32_t count, char **out, int environment)
{
	uint32_t offset = 0, i;
	if (!count || count > BA_V2_EXEC_MAX_ITEMS || !size || size > BA_V2_EXEC_MAX_BLOB) return -1;
	for (i = 0; i < count; i++) {
		char *end;
		if (offset >= size || !(end = memchr(bytes + offset, 0, size - offset))) return -1;
		if (environment && (!strchr(bytes + offset, '=') || bytes[offset] == '=')) return -1;
		out[i] = bytes + offset; offset = (uint32_t)(end - bytes) + 1;
	}
	out[count] = NULL;
	return offset == size ? 0 : -1;
}

static int receive_request(int channel, struct native_request *r)
{
	struct ba_v2_exec_request header;
	uint32_t argv_bytes, env_bytes, i, j;
	unsigned char extra;
	ssize_t n;
	memset(&header, 0, sizeof(header));
	if (read_exact(channel, &header, sizeof(header))) return -1;
	argv_bytes = le32toh(header.argv_bytes); env_bytes = le32toh(header.env_bytes);
	if (le32toh(header.magic) != BA_V2_EXEC_MAGIC || le32toh(header.version) != BA_V2_EXEC_VERSION ||
	    header.reserved || header.reserved2 || !argv_bytes || argv_bytes > BA_V2_EXEC_MAX_BLOB ||
	    !env_bytes || env_bytes > BA_V2_EXEC_MAX_BLOB ||
	    le32toh(header.size) != sizeof(header) + argv_bytes + env_bytes ||
	    !le32toh(header.timeout_seconds) || le32toh(header.timeout_seconds) > BA_V2_EXEC_MAX_TIMEOUT)
		return -1;
	r->group_count = le32toh(header.group_count);
	if (!r->group_count || r->group_count > BA_V2_EXEC_MAX_GROUPS) return -1;
	r->uid = le32toh(header.uid); r->gid = le32toh(header.gid);
	if (r->uid == (uid_t)-1 || r->gid == (gid_t)-1) return -1;
	for (i = 0; i < r->group_count; i++) {
		r->groups[i] = le32toh(header.groups[i]);
		if (r->groups[i] == (gid_t)-1) return -1;
		for (j = 0; j < i; j++) if (r->groups[j] == r->groups[i]) return -1;
	}
	for (; i < BA_V2_EXEC_MAX_GROUPS; i++) if (header.groups[i]) return -1;
	for (i = 0; i < BA_V2_EXEC_FDS; i++) {
		uint32_t fd = le32toh(header.descriptors[i]);
		if (fd > INT_MAX || (int)fd == channel) return -1;
		for (j = 0; j < i; j++) if (header.descriptors[j] == header.descriptors[i]) return -1;
		if ((r->fds[i] = fcntl((int)fd, F_DUPFD_CLOEXEC, 64)) < 0) return -1;
	}
	r->size = le32toh(header.size);
	r->wire = mmap(NULL, r->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r->wire == MAP_FAILED) { r->wire = NULL; return -1; }
	if (madvise(r->wire, r->size, MADV_DONTDUMP)) return -1;
	memcpy(r->wire, &header, sizeof(header));
	if (read_exact(channel, r->wire->blobs, argv_bytes + env_bytes)) return -1;
	do { n = read(channel, &extra, 1); } while (n < 0 && errno == EINTR);
	if (n != 0 || framed_strings((char *)r->wire->blobs, argv_bytes, le32toh(header.argc), r->argv, 0) ||
	    framed_strings((char *)r->wire->blobs + argv_bytes, env_bytes, le32toh(header.envc), r->env, 1) ||
	    !r->argv[0][0]) return -1;
	/* The request now owns independent high descriptors. Original low slots
	 * must be free before child stdio is installed. */
	for (i = 0; i < BA_V2_EXEC_FDS; i++) close((int)le32toh(header.descriptors[i]));
	wipe(&header, sizeof(header));
	return 0;
}

static int send_result(int channel, const struct native_request *r, uint32_t kind,
		uint32_t status, uint32_t step, uint32_t error, pid_t child)
{
	struct ba_v2_exec_response reply = {0};
	ssize_t n;
	reply.magic = htole32(BA_V2_EXEC_MAGIC); reply.version = htole32(BA_V2_EXEC_VERSION);
	reply.size = htole32(sizeof(reply)); reply.kind = htole32(kind); reply.status = htole32(status);
	reply.failed_step = htole32(step); reply.error = htole32(error); reply.child_pid = htole32((uint32_t)child);
	memcpy(reply.nonce, r->wire->nonce, 32); memcpy(reply.request_digest, r->wire->request_digest, 32);
	do { n = write(channel, &reply, sizeof(reply)); } while (n < 0 && errno == EINTR);
	wipe(&reply, sizeof(reply));
	return n == (ssize_t)sizeof(reply) ? 0 : -1;
}

static int join_namespaces(const struct native_request *r)
{
	static const struct { unsigned int index; int type; } joins[] = {
		{BA_V2_EXEC_MNT, CLONE_NEWNS}, {BA_V2_EXEC_UTS, CLONE_NEWUTS},
		{BA_V2_EXEC_IPC, CLONE_NEWIPC}, {BA_V2_EXEC_NET, CLONE_NEWNET},
		{BA_V2_EXEC_CGROUP, CLONE_NEWCGROUP}, {BA_V2_EXEC_TIME, CLONE_NEWTIME},
		{BA_V2_EXEC_PID_ACTIVE, CLONE_NEWPID}
	};
	/* The kernel rejects split active/future PID or time namespaces before
	 * granting. Non-USER namespace installation keeps this monitor's creds. */
	for (size_t i = 0; i < sizeof(joins) / sizeof(joins[0]); i++)
		if (setns(r->fds[joins[i].index], joins[i].type)) return -1;
	return 0;
}

static int high_pipe(int p[2])
{
	int low[2], a, b, saved;
	if (pipe2(low, O_CLOEXEC)) return -1;
	a = fcntl(low[0], F_DUPFD_CLOEXEC, 64);
	b = a < 0 ? -1 : fcntl(low[1], F_DUPFD_CLOEXEC, 64);
	saved = errno; close(low[0]); close(low[1]);
	if (a < 0 || b < 0) { if (a >= 0) close(a); errno = saved; return -1; }
	p[0] = a; p[1] = b; return 0;
}

static int live_parent(int parent_fd)
{
	struct pollfd p = {.fd = parent_fd, .events = POLLIN};
	int rc;
	do { rc = poll(&p, 1, 0); } while (rc < 0 && errno == EINTR);
	if (rc != 0) { if (rc > 0) errno = ESRCH; return -1; }
	return 0;
}

static void child_fail(int fd, uint32_t step, int error)
{
	struct child_error report = { step, error > 0 && error <= 4095 ? (uint32_t)error : EIO };
	ssize_t n;
	do { n = write(fd, &report, sizeof(report)); } while (n < 0 && errno == EINTR);
	(void)n;
	/* Failure is terminal even if the setup reporter itself has failed. */
	_exit(126);
}

static int prepare_security(void)
{
	const unsigned int secure = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
		SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED |
		SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
	unsigned int cap;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
	    prctl(PR_SET_SECUREBITS, secure, 0, 0, 0)) return -1;
	/* Drop the bounding set while CAP_SETPCAP is still held. The explicit
	 * securebits retain setup caps across uid change; capset below removes
	 * every effective/permitted/inheritable bit before exact fd exec. */
	for (cap = 0; cap < 256; cap++) {
		int state = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
		if (state < 0) return errno == EINVAL && cap ? 0 : -1;
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
	}
	errno = E2BIG; return -1;
}

static int clear_capabilities(void)
{
	struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct caps[2] = {{0}, {0}};
	if (syscall(SYS_capset, &header, caps) || syscall(SYS_capget, &header, caps)) return -1;
	for (unsigned int i = 0; i < 2; i++)
		if (caps[i].effective || caps[i].permitted || caps[i].inheritable) { errno = EPERM; return -1; }
	return 0;
}

static int check_ids(const struct native_request *r)
{
	uid_t real, effective, saved;
	gid_t greal, geffective, gsaved, groups[BA_V2_EXEC_MAX_GROUPS];
	int count;
	if (getresuid(&real, &effective, &saved) || getresgid(&greal, &geffective, &gsaved)) return -1;
	if (real != r->uid || effective != r->uid || saved != r->uid ||
	    greal != r->gid || geffective != r->gid || gsaved != r->gid ||
	    (uid_t)setfsuid((uid_t)-1) != r->uid || (gid_t)setfsgid((gid_t)-1) != r->gid) goto mismatch;
	count = getgroups(BA_V2_EXEC_MAX_GROUPS, groups);
	if (count < 0) return -1;
	if ((uint32_t)count != r->group_count) goto mismatch;
	for (uint32_t i = 0; i < r->group_count; i++) {
		uint32_t j;
		for (j = 0; j < r->group_count; j++) if (groups[j] == r->groups[i]) break;
		if (j == r->group_count) goto mismatch;
	}
	return 0;
mismatch:
	errno = EPERM; return -1;
}

static int reset_signals(void)
{
	struct sigaction action = {.sa_handler = SIG_DFL};
	sigset_t empty;
	if (sigemptyset(&empty) || sigemptyset(&action.sa_mask) || sigprocmask(SIG_SETMASK, &empty, NULL)) return -1;
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP) continue;
		if (sigaction(sig, &action, NULL)) {
			/* glibc reserves these two NPTL signals from sigaction. The
			 * static single-thread monitor installs no handlers for them. */
			if (errno == EINVAL && (sig == 32 || sig == 33)) continue;
			return -1;
		}
	}
	return 0;
}

static void run_child(int channel, int gate, int errors, int parent_fd, struct native_request *r)
{
	unsigned char go = 0;
	struct rlimit core = {0, 0};
	close(channel);
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || live_parent(parent_fd))
		child_fail(errors, BA_V2_EXEC_STEP_SECURITY, errno);
	if (read_exact(gate, &go, 1) || go != 1) child_fail(errors, BA_V2_EXEC_STEP_INPUT, EPIPE);
	close(gate);
	if (syscall(SYS_close_range, 3U, UINT_MAX, CLOSE_RANGE_CLOEXEC))
		child_fail(errors, BA_V2_EXEC_STEP_DESCRIPTORS, errno);
	for (unsigned int i = 0; i < 3; i++)
		if (dup2(r->fds[BA_V2_EXEC_STDIN + i], (int)i) < 0)
			child_fail(errors, BA_V2_EXEC_STEP_DESCRIPTORS, errno);
	if (fchdir(r->fds[BA_V2_EXEC_ROOT]) || chroot(".")) child_fail(errors, BA_V2_EXEC_STEP_ROOT, errno);
	if (fchdir(r->fds[BA_V2_EXEC_CWD])) child_fail(errors, BA_V2_EXEC_STEP_CWD, errno);
	if (prepare_security() || setrlimit(RLIMIT_CORE, &core)) child_fail(errors, BA_V2_EXEC_STEP_SECURITY, errno);
	if (setgroups(r->group_count, r->groups)) child_fail(errors, BA_V2_EXEC_STEP_GROUPS, errno);
	if (setresgid(r->gid, r->gid, r->gid)) child_fail(errors, BA_V2_EXEC_STEP_GID, errno);
	if (setresuid(r->uid, r->uid, r->uid)) child_fail(errors, BA_V2_EXEC_STEP_UID, errno);
	if (clear_capabilities()) child_fail(errors, BA_V2_EXEC_STEP_CAPABILITIES, errno);
	if (check_ids(r)) child_fail(errors, BA_V2_EXEC_STEP_IDS, errno);
	/* Credential changes can clear PDEATHSIG and reset dumpability. Restore
	 * both and use the retained pidfd to close the death-before-prctl race,
	 * including when the parent is outside the child's active PID namespace. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || live_parent(parent_fd) ||
	    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) child_fail(errors, BA_V2_EXEC_STEP_SECURITY, errno);
	umask(022);
	if (reset_signals()) child_fail(errors, BA_V2_EXEC_STEP_SIGNALS, errno);
	syscall(SYS_execveat, r->fds[BA_V2_EXEC_PROGRAM], "", r->argv, r->env, AT_EMPTY_PATH);
	child_fail(errors, BA_V2_EXEC_STEP_EXEC, errno);
}

static int reap(pid_t child, int *status)
{
	pid_t got;
	do { got = waitpid(child, status, 0); } while (got < 0 && errno == EINTR);
	return got == child ? 0 : -1;
}

static int monitor(int channel, struct native_request *r)
{
	int gate[2] = {-1, -1}, errors[2] = {-1, -1}, parent_fd = -1, child_fd = -1, timer = -1;
	int status, result = -1, error = 0;
	uint32_t step = BA_V2_EXEC_STEP_NAMESPACE;
	pid_t child = -1, child_number = 0;
	unsigned char go = 1;
	struct child_error report = {0};
	struct itimerspec limit = {0};
	struct pollfd waiting[2];
	ssize_t n;
	if (join_namespaces(r)) goto setup_error;
	step = BA_V2_EXEC_STEP_DESCRIPTORS;
	if (high_pipe(gate) || high_pipe(errors)) goto setup_error;
	parent_fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
	if (parent_fd < 0) goto setup_error;
	{
		int high = fcntl(parent_fd, F_DUPFD_CLOEXEC, 64), saved = errno;
		close(parent_fd); parent_fd = high; errno = saved;
		if (parent_fd < 0) goto setup_error;
	}
	timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC);
	if (timer < 0) goto setup_error;
	limit.it_value.tv_sec = le32toh(r->wire->timeout_seconds);
	if (timerfd_settime(timer, 0, &limit, NULL)) goto setup_error;
	child = fork();
	if (child < 0) goto setup_error;
	if (!child) {
		close(gate[1]); close(errors[0]); close(timer);
		run_child(channel, gate[0], errors[1], parent_fd, r);
		_exit(126);
	}
	child_number = child;
	close(gate[0]); gate[0] = -1; close(errors[1]); errors[1] = -1;
	child_fd = (int)syscall(SYS_pidfd_open, child, 0);
	/* The blocked direct child is not released until the kernel has pinned
	 * its actual task. No command runs on a failed READY notification. */
	if (child_fd < 0 || send_result(channel, r, BA_V2_EXEC_CHILD_READY, 0, 0, 0, child)) goto kill_child;
	do { n = write(gate[1], &go, 1); } while (n < 0 && errno == EINTR);
	if (n != 1) goto kill_child;
	close(gate[1]); gate[1] = -1;
	waiting[0] = (struct pollfd){.fd = child_fd, .events = POLLIN};
	waiting[1] = (struct pollfd){.fd = timer, .events = POLLIN};
	for (;;) {
		int ready = poll(waiting, 2, -1);
		if (ready < 0 && errno == EINTR) continue;
		if (ready < 0) goto kill_child;
		if (waiting[0].revents & POLLIN) break;
		if (waiting[1].revents & POLLIN) {
			if (syscall(SYS_pidfd_send_signal, child_fd, SIGKILL, NULL, 0) || reap(child, &status)) goto done;
			child = -1;
			result = send_result(channel, r, BA_V2_EXEC_TIMEOUT, SIGKILL, 0, ETIMEDOUT,
				child_number);
			goto done;
		}
		if ((waiting[0].revents | waiting[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) goto kill_child;
	}
	if (reap(child, &status)) goto kill_child;
	/* CLOEXEC on the pipe distinguishes a failed setup/exec from a command
	 * that successfully started and chose exit status 126. */
	do { n = read(errors[0], &report, sizeof(report)); } while (n < 0 && errno == EINTR);
	if (n == (ssize_t)sizeof(report)) {
		if (!report.step || report.step > BA_V2_EXEC_STEP_EXEC || !report.error || report.error > 4095 ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 126) goto done;
		result = send_result(channel, r, BA_V2_EXEC_SETUP_ERROR, 126, report.step, report.error, child);
	} else if (n == 0 && WIFEXITED(status)) {
		result = send_result(channel, r, BA_V2_EXEC_EXIT, (uint32_t)WEXITSTATUS(status), 0, 0, child);
	} else if (n == 0 && WIFSIGNALED(status)) {
		result = send_result(channel, r, BA_V2_EXEC_SIGNAL, (uint32_t)WTERMSIG(status), 0, 0, child);
	}
	child = -1;
	goto done;
setup_error:
	error = errno > 0 && errno <= 4095 ? errno : EIO;
	result = send_result(channel, r, BA_V2_EXEC_SETUP_ERROR, 126, step, (uint32_t)error, 0);
	goto done;
kill_child:
	/* Before READY the PID is an owned, unreaped direct child; afterwards a
	 * pidfd and the kernel's task reference independently prevent PID reuse. */
	if (child > 0) {
		if (child_fd >= 0) (void)syscall(SYS_pidfd_send_signal, child_fd, SIGKILL, NULL, 0);
		else (void)kill(child, SIGKILL);
		(void)reap(child, &status); child = -1;
	}
done:
	if (child_fd >= 0) close(child_fd);
	if (parent_fd >= 0) close(parent_fd);
	if (timer >= 0) close(timer);
	for (unsigned int i = 0; i < 2; i++) { if (gate[i] >= 0) close(gate[i]); if (errors[i] >= 0) close(errors[i]); }
	return result;
}

int main(int argc, char **argv)
{
	struct native_request r = {0};
	struct rlimit core = {0, 0};
	struct sigaction ignore = {.sa_handler = SIG_IGN};
	char *end;
	long parsed;
	int fd, result = 125;
	for (unsigned int i = 0; i < BA_V2_EXEC_FDS; i++) r.fds[i] = -1;
	if (argc != 3 || strcmp(argv[1], "--kernel-channel") || !argv[2][0]) return 125;
	for (const char *p = argv[2]; *p; p++) if (*p < '0' || *p > '9') return 125;
	errno = 0; parsed = strtol(argv[2], &end, 10);
	if (errno || *end || parsed < 0 || parsed > INT_MAX) return 125;
	fd = (int)parsed;
	if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || reset_signals() ||
	    sigemptyset(&ignore.sa_mask) || sigaction(SIGPIPE, &ignore, NULL)) return 125;
	if (receive_request(fd, &r)) goto done;
	if (!monitor(fd, &r)) result = 0;
done:
	for (unsigned int i = 0; i < BA_V2_EXEC_FDS; i++) if (r.fds[i] >= 0) close(r.fds[i]);
	if (r.wire) { wipe(r.wire, r.size); munmap(r.wire, r.size); }
	wipe(&r, sizeof(r)); close(fd);
	return result;
}
