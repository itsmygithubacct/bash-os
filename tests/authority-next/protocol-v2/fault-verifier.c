/* SPDX-License-Identifier: MIT */
/* Intentionally invalid verifier images. Each FAULT_MODE is separately built
 * and pinned ONLY by disposable test configuration. Never install as a trusted
 * verifier. A normal exit or a forged result must not become an event. */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../kernel/bashos-auth/authority/v2/protocol.h"

#ifndef FAULT_MODE
#error explicit negative control mode required
#endif

static int full_read(int fd, void *data, size_t size)
{
	size_t offset = 0;
	while (offset < size) {
		ssize_t n = read(fd, (char *)data + offset, size - offset);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		offset += (size_t)n;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ba_v2_challenge challenge = {0};
	struct ba_v2_response response = {0};
	int fd, status;
	pid_t child;
	if (argc == 2 && !strcmp(argv[1], "--negative-exit")) return 0;
	if (argc != 3 || strcmp(argv[1], "--kernel-channel")) return 125;
	fd = atoi(argv[2]);
	if (FAULT_MODE == 1) return 0; /* no reply, zero exit */
	if (FAULT_MODE == 2) { for (;;) pause(); } /* kernel deadline */
	if (FAULT_MODE == 3) {
		if (read(fd, &challenge, 1) != 1) return 125;
	} else if (full_read(fd, &challenge, sizeof(challenge))) return 125;
	response.magic = htole32(BA_V2_MAGIC);
	response.version = htole32(BA_V2_VERSION);
	response.size = htole32(sizeof(response));
	response.status = htole32(BA_V2_VERIFY_OK);
	memcpy(response.nonce, challenge.nonce, sizeof(response.nonce));
	memcpy(response.request_digest, challenge.request_digest, sizeof(response.request_digest));
	if (FAULT_MODE == 4) response.nonce[31] ^= 1;
	if (FAULT_MODE == 5) response.request_digest[31] ^= 1;
	if (FAULT_MODE == 6) { (void)write(fd, &response, sizeof(response) - 1); return 0; }
	if (FAULT_MODE == 7) { /* inherited channel, wrong task */
		child = fork();
		if (child < 0) return 125;
		if (!child) { (void)write(fd, &response, sizeof(response)); _exit(0); }
		if (waitpid(child, &status, 0) != child) return 125;
		return 0;
	}
	if (FAULT_MODE == 8) response.magic ^= htole32(1);
	if (FAULT_MODE == 9) response.version = htole32(1);
	if (FAULT_MODE == 10) response.status = htole32(3);
	if (FAULT_MODE == 11) response.status = htole32(BA_V2_VERIFY_DENIED);
	if (FAULT_MODE == 12) response.status = htole32(BA_V2_VERIFY_ERROR);
	if (FAULT_MODE == 13 && setresuid(1, 1, 1)) return 125;
	(void)write(fd, &response, sizeof(response));
	if (FAULT_MODE == 14) (void)write(fd, &response, sizeof(response)); /* second reply revokes */
	if (FAULT_MODE == 15) { /* success-looking reply followed by a second exec */
		char *next[] = {"fault-verifier", "--negative-exit", NULL};
		execv("/proc/self/exe", next);
		return 125;
	}
	return 0;
}
