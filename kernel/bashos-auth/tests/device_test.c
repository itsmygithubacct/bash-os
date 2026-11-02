/* SPDX-License-Identifier: MIT */
/* Real-device test. Build here; RUN ONLY in the coordinator's disposable guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/bashos_auth.h>

static unsigned int checks;
#define CHECK(e) do { checks++; if (!(e)) { \
	fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #e, errno); \
	exit(1); } } while (0)
#define ERROR(e, code) do { errno = 0; int result_ = (e); \
	CHECK(result_ == -1 && errno == (code)); } while (0)

static int device_open(void)
{
	int fd = open("/dev/bashos-auth", O_RDWR | O_CLOEXEC);
	CHECK(fd >= 0);
	return fd;
}

static uint32_t slot_new(int fd)
{
	struct bashos_auth_handle h = { 0 };
	CHECK(ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &h) == 0);
	CHECK(h.id != 0 && h.flags == 0);
	return h.id;
}

static int slot_write(int fd, uint32_t id, const void *bytes, uint32_t n)
{
	struct bashos_auth_secret_write w = {
		.id = id, .len = n, .user_ptr = (uintptr_t)bytes,
	};
	return ioctl(fd, BASHOS_AUTH_IOC_WRITE_SECRET, &w);
}

static int slot_op(int fd, unsigned long command, uint32_t id)
{
	struct bashos_auth_handle h = { .id = id };
	return ioctl(fd, command, &h);
}

static int slot_export(int fd, uint32_t id, void *buf, uint32_t *n)
{
	struct bashos_auth_secret_export e = {
		.id = id, .len = *n, .user_ptr = (uintptr_t)buf,
	};
	int rc = ioctl(fd, BASHOS_AUTH_IOC_EXPORT_ONCE, &e);
	if (!rc)
		*n = e.len;
	return rc;
}

static struct bashos_auth_stats stats(int fd)
{
	struct bashos_auth_stats s;
	memset(&s, 0xa7, sizeof(s));
	CHECK(ioctl(fd, BASHOS_AUTH_IOC_STATS, &s) == 0);
	CHECK(!s.minted_tokens && !s.consumed_tokens && !s.expired_tokens);
	for (size_t i = 0; i < sizeof(s.reserved) / sizeof(s.reserved[0]); i++)
		CHECK(s.reserved[i] == 0);
	return s;
}

static void unsupported_and_malformed(int fd)
{
	const unsigned long unsupported[] = {
		BASHOS_AUTH_IOC_MINT_TOKEN, BASHOS_AUTH_IOC_CONSUME_TOKEN,
		BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, BASHOS_AUTH_IOC_POLICY_INFO,
		BASHOS_AUTH_IOC_EXEC_HANDOFF, BASHOS_AUTH_IOC_EXEC_INTERACTIVE,
		BASHOS_AUTH_IOC_EXEC_VERIFY, BASHOS_AUTH_IOC_MINT_TIMESTAMP,
		BASHOS_AUTH_IOC_NOTE_VERIFY_FAILURE, BASHOS_AUTH_IOC_AUDIT_READ,
		BASHOS_AUTH_IOC_AUDIT_READ_TEXT,
	};
	for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++)
		ERROR(ioctl(fd, unsupported[i], (void *)0), ENOTTY);
	ERROR(ioctl(fd, _IO(0xBA, 1), (void *)0), ENOTTY);
	ERROR(ioctl(fd, _IOR(0xBA, 1, char), (void *)0), ENOTTY);
	ERROR(ioctl(fd, _IOR(0xBB, 1, struct bashos_auth_version), (void *)0), ENOTTY);
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_VERSION, (void *)0), EFAULT);
	struct bashos_auth_handle h = { .flags = 1 };
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &h), EINVAL);
	h = (struct bashos_auth_handle) { .id = 1 };
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &h), EINVAL);
}

static void normal_lifecycle(int fd)
{
	const unsigned char input[] = { 0xa7, 0, 0xff, 0x23 };
	unsigned char output[16] = { 0 };
	uint32_t a = slot_new(fd), b = slot_new(fd), n = sizeof(output);
	struct bashos_auth_secret_compare c = { .id_a = a, .id_b = b };
	ERROR(slot_export(fd, a, output, &n), EPERM);
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_SAME_SECRET, &c), EPERM);
	CHECK(slot_write(fd, a, NULL, 0) == 0);
	for (size_t i = 0; i < sizeof(input); i++)
		CHECK(slot_write(fd, a, input + i, 1) == 0);
	CHECK(slot_write(fd, b, input, sizeof(input)) == 0);
	ERROR(slot_write(fd, b, input, UINT32_MAX), E2BIG);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, a) == 0);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, b) == 0);
	ERROR(slot_write(fd, a, input, 1), EPERM);
	ERROR(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, a), EPERM);
	CHECK(ioctl(fd, BASHOS_AUTH_IOC_SAME_SECRET, &c) == 0 && c.result == 1);
	c.flags = 1;
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_SAME_SECRET, &c), EINVAL);
	c.flags = 0;
	n = 3;
	ERROR(slot_export(fd, a, output, &n), ENOSPC);
	n = sizeof(output);
	CHECK(slot_export(fd, a, output, &n) == 0);
	CHECK(n == sizeof(input) && !memcmp(output, input, sizeof(input)));
	ERROR(slot_export(fd, a, output, &n), EPERM);
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_SAME_SECRET, &c), EPERM);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, a) == 0);
	ERROR(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, a), ENOENT);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, b) == 0);
	uint32_t next = slot_new(fd);
	CHECK(next != a && next != b);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, next) == 0);
	memset(output, 0, sizeof(output));
}

static void copy_faults(int fd)
{
	long page = sysconf(_SC_PAGESIZE);
	CHECK(page > 0);
	unsigned char *memory = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(memory != MAP_FAILED);
	memory[page - 1] = 0xa7;
	CHECK(mprotect(memory + page, (size_t)page, PROT_NONE) == 0);
	const unsigned char input[] = { 0x23, 0xff };
	unsigned char output[2] = { 0 };
	uint32_t id = slot_new(fd), n = sizeof(output);
	CHECK(slot_write(fd, id, input, sizeof(input)) == 0);
	ERROR(slot_write(fd, id, memory + page - 1, 2), EFAULT);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, id) == 0);
	CHECK(slot_export(fd, id, output, &n) == 0);
	CHECK(n == sizeof(input) && !memcmp(output, input, n));
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, id) == 0);

	id = slot_new(fd);
	CHECK(slot_write(fd, id, input, sizeof(input)) == 0);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, id) == 0);
	n = sizeof(input);
	ERROR(slot_export(fd, id, memory + page - 1, &n), EFAULT);
	ERROR(slot_export(fd, id, output, &n), EPERM);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, id) == 0);

	/* NEW copy-out failure rolls back its allocation. */
	struct bashos_auth_handle *h = (void *)memory;
	*h = (struct bashos_auth_handle) { 0 };
	struct bashos_auth_stats before = stats(fd);
	CHECK(mprotect(memory, (size_t)page, PROT_READ) == 0);
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, h), EFAULT);
	struct bashos_auth_stats after = stats(fd);
	CHECK(after.created_secrets == before.created_secrets + 1);
	CHECK(after.cleared_secrets == before.cleared_secrets + 1);
	CHECK(mprotect(memory, (size_t)page, PROT_READ | PROT_WRITE) == 0);

	/* Exported bytes cannot become replayable on a reply-structure fault. */
	id = slot_new(fd);
	CHECK(slot_write(fd, id, input, sizeof(input)) == 0);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, id) == 0);
	struct bashos_auth_secret_export *e = (void *)memory;
	*e = (struct bashos_auth_secret_export) {
		.id = id, .len = sizeof(output), .user_ptr = (uintptr_t)output,
	};
	CHECK(mprotect(memory, (size_t)page, PROT_READ) == 0);
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_EXPORT_ONCE, e), EFAULT);
	CHECK(!memcmp(output, input, sizeof(input)));
	n = sizeof(output);
	ERROR(slot_export(fd, id, output, &n), EPERM);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, id) == 0);
	CHECK(munmap(memory, (size_t)page * 2) == 0);
}

struct race {
	int fd, result, error;
	uint32_t id;
	unsigned char output[2];
	pthread_barrier_t *barrier;
};

static void *export_thread(void *arg)
{
	struct race *r = arg;
	uint32_t n = sizeof(r->output);
	(void)pthread_barrier_wait(r->barrier);
	r->result = slot_export(r->fd, r->id, r->output, &n);
	r->error = errno;
	return NULL;
}

static void concurrent_export(int fd)
{
	unsigned char input[] = { 0xa7, 0x23 };
	uint32_t id = slot_new(fd);
	CHECK(slot_write(fd, id, input, sizeof(input)) == 0);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_SEAL_SECRET, id) == 0);
	pthread_barrier_t barrier;
	pthread_t threads[2];
	struct race r[2] = {
		{ .fd = fd, .id = id, .barrier = &barrier },
		{ .fd = fd, .id = id, .barrier = &barrier },
	};
	CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
	CHECK(pthread_create(&threads[0], NULL, export_thread, &r[0]) == 0);
	CHECK(pthread_create(&threads[1], NULL, export_thread, &r[1]) == 0);
	CHECK(pthread_join(threads[0], NULL) == 0);
	CHECK(pthread_join(threads[1], NULL) == 0);
	CHECK((r[0].result == 0) + (r[1].result == 0) == 1);
	for (size_t i = 0; i < 2; i++) {
		if (!r[i].result)
			CHECK(!memcmp(r[i].output, input, sizeof(input)));
		else
			CHECK(r[i].result == -1 && r[i].error == EPERM);
	}
	CHECK(pthread_barrier_destroy(&barrier) == 0);
	CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, id) == 0);
}

static void descriptor_lifetime(void)
{
	int a = device_open(), independent = device_open();
	uint32_t id = slot_new(a);
	CHECK(slot_op(a, BASHOS_AUTH_IOC_SEAL_SECRET, id) == 0);
	ERROR(slot_op(independent, BASHOS_AUTH_IOC_CLEAR_SECRET, id), ENOENT);
	CHECK(stats(independent).created_secrets == 0);
	CHECK(close(independent) == 0);
	int copy = dup(a);
	CHECK(copy >= 0);
	CHECK(close(a) == 0);
	struct bashos_auth_secret_compare c = { .id_a = id, .id_b = id };
	CHECK(ioctl(copy, BASHOS_AUTH_IOC_SAME_SECRET, &c) == 0 && c.result == 1);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (!pid) {
		if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) ||
		    setresuid(65534, 65534, 65534))
			_exit(2);
		struct bashos_auth_version v;
		int rc = ioctl(copy, BASHOS_AUTH_IOC_VERSION, &v), saved = errno;
		close(copy); /* Must remain safe after credentials have been dropped. */
		_exit(rc == -1 && saved == EPERM ? 0 : 3);
	}
	int status;
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
	CHECK(ioctl(copy, BASHOS_AUTH_IOC_SAME_SECRET, &c) == 0 && c.result == 1);
	CHECK(close(copy) == 0); /* Final close: kernel-side tests inspect actual erase. */
	int fresh = device_open();
	CHECK(stats(fresh).created_secrets == 0);
	ERROR(slot_op(fresh, BASHOS_AUTH_IOC_CLEAR_SECRET, id), ENOENT);
	CHECK(close(fresh) == 0);
}

static void quotas(int fd)
{
	uint32_t ids[16];
	for (size_t i = 0; i < 16; i++)
		ids[i] = slot_new(fd);
	struct bashos_auth_handle h = { 0 };
	ERROR(ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &h), ENOSPC);
	for (size_t i = 0; i < 16; i++)
		CHECK(slot_op(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, ids[i]) == 0);
	struct rlimit limit;
	CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur >= 256);
	int fds[128];
	size_t count;
	for (count = 0; count < 128; count++) {
		fds[count] = open("/dev/bashos-auth", O_RDWR | O_CLOEXEC);
		if (fds[count] < 0)
			break;
	}
	CHECK(count == 127 && errno == EMFILE); /* One context already held by main. */
	for (size_t i = 0; i < count; i++)
		CHECK(close(fds[i]) == 0);
	int fresh = device_open();
	CHECK(close(fresh) == 0);
}

int main(int argc, char **argv)
{
	if (argc != 2 || strcmp(argv[1], "--disposable-guest")) {
		fputs("Usage: device_test --disposable-guest (coordinator guest only)\n", stderr);
		return 2;
	}
	CHECK(geteuid() == 0);
	CHECK(access("/sys/module/bashos_auth_stage1", F_OK) == 0);
	alarm(30);
	int fd = device_open();
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode));
	CHECK(st.st_uid == 0 && (st.st_mode & 0777) == 0600);
	struct bashos_auth_version v;
	memset(&v, 0xa7, sizeof(v));
	CHECK(ioctl(fd, BASHOS_AUTH_IOC_VERSION, &v) == 0);
	CHECK(v.abi_major == 1 && v.abi_minor == 0 && v.features == 5);
	for (size_t i = 0; i < sizeof(v.reserved); i++)
		CHECK(v.reserved[i] == 0);
	CHECK(stats(fd).created_secrets == 0);
	unsupported_and_malformed(fd);
	normal_lifecycle(fd);
	copy_faults(fd);
	concurrent_export(fd);
	descriptor_lifetime();
	quotas(fd);
	struct bashos_auth_stats end = stats(fd);
	CHECK(end.created_secrets == end.cleared_secrets);
	CHECK(close(fd) == 0);
	printf("PASS: %u real-device checks; kernel erasure still requires KUnit evidence\n", checks);
	return 0;
}
