/* SPDX-License-Identifier: MIT */
/* Dedicated native verifier for a kernel-created private channel. This is not
 * a general-purpose command or an authority grant API. Never prints secrets or
 * result material. Compile as a static native ELF without an interpreter. */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include "protocol.h"
#include "../../../../loadables/common/argon2-phc-record.h"
#include "../../../../loadables/_monocypher/monocypher.h"

_Static_assert(sizeof(struct ba_v2_challenge) == 4784, "challenge layout");
_Static_assert(sizeof(struct ba_v2_response) == 80, "response layout");
_Static_assert(sizeof(struct ba_v2_account_header) == 32, "snapshot header layout");
_Static_assert(sizeof(struct ba_v2_account_record) == 592, "account layout");

static void wipe(void *p, size_t size)
{
	volatile unsigned char *v = p;
	while (size--) *v++ = 0;
}

static int read_challenge(int fd, struct ba_v2_challenge *c)
{
	size_t have = 0;
	unsigned char extra;
	ssize_t n;
	while (have < sizeof(*c)) {
		n = read(fd, (unsigned char *)c + have, sizeof(*c) - have);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		have += (size_t)n;
	}
	do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
	return n == 0 ? 0 : -1;
}

/* This trusted service has stricter memory requirements than the historical
 * general-purpose KDF wrapper. Refuse verification when its password-derived
 * work area cannot be locked and excluded from dumps. */
static int derive(const struct ba_v2_challenge *c, const struct bashos_phc_record *r,
		unsigned char out[128])
{
	size_t size = (size_t)r->memory * 1024;
	void *work = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	crypto_argon2_config config = {
		.algorithm = CRYPTO_ARGON2_ID, .nb_blocks = r->memory,
		.nb_passes = r->iterations, .nb_lanes = r->lanes,
	};
	crypto_argon2_inputs inputs = {
		.pass = c->secret, .pass_size = le32toh(c->secret_length),
		.salt = r->salt, .salt_size = (uint32_t)r->salt_length,
	};
	int rc = -1;
	if (work == MAP_FAILED) return -1;
	if (mlock(work, size) || madvise(work, size, MADV_DONTDUMP)) goto done;
	crypto_argon2(out, (uint32_t)r->hash_length, work, config, inputs, crypto_argon2_no_extras);
	rc = 0;
done:
	wipe(work, size);
	munlock(work, size);
	munmap(work, size);
	return rc;
}

static int verify(const struct ba_v2_challenge *c)
{
	struct bashos_phc_record record;
	unsigned char derived[128] = {0};
	unsigned char different = 0;
	enum bashos_phc_encoding format;
	uint32_t purpose = le32toh(c->purpose), encoding = le32toh(c->encoding);
	int rc = BA_V2_VERIFY_ERROR;
	memset(&record, 0, sizeof(record));
	if (le32toh(c->magic) != BA_V2_MAGIC || le32toh(c->version) != BA_V2_VERSION ||
	    le32toh(c->size) != sizeof(*c) ||
	    (purpose != BA_V2_PURPOSE_LOGIN && purpose != BA_V2_PURPOSE_SU && purpose != BA_V2_PURPOSE_SSH &&
	     purpose != BA_V2_PURPOSE_PRIVCMD) ||
	    le32toh(c->secret_length) > BA_V2_SECRET_BYTES ||
	    !le64toh(c->account_generation) || !le64toh(c->policy_generation) ||
	    !c->user[0] || !memchr(c->user, 0, sizeof(c->user)) ||
	    !memchr(c->phc, 0, sizeof(c->phc))) goto done;
	if (encoding == BA_V2_ENCODING_STANDARD) format = BASHOS_PHC_STANDARD_BASE64;
	else if (encoding == BA_V2_ENCODING_LEGACY_HEX) format = BASHOS_PHC_LEGACY_HEX;
	else goto done;
	if (bashos_phc_parse_record(c->phc, format, &record)) goto done;
	if (derive(c, &record, derived)) goto done;
	/* Compare decoded bytes; no second format or case-normalization retry. */
	for (size_t i = 0; i < record.hash_length; i++) different |= derived[i] ^ record.hash[i];
	rc = different ? BA_V2_VERIFY_DENIED : BA_V2_VERIFY_OK;
done:
	wipe(derived, sizeof(derived));
	wipe(&record, sizeof(record));
	return rc;
}

int main(int argc, char **argv)
{
	struct ba_v2_challenge *challenge;
	struct ba_v2_response response = {0};
	struct rlimit core = {0, 0}, memory = {512UL << 20, 512UL << 20};
	struct rlimit cpu = {20, 20};
	size_t allocation = 8192;
	char *end;
	long parsed;
	ssize_t written;
	int fd, result = 125;
	if (argc != 3 || strcmp(argv[1], "--kernel-channel") || !argv[2][0]) return 125;
	for (const char *p = argv[2]; *p; p++) if (*p < '0' || *p > '9') return 125;
	errno = 0; parsed = strtol(argv[2], &end, 10);
	if (errno || *end || parsed < 0 || parsed > INT_MAX) return 125;
	fd = (int)parsed;
	if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_AS, &memory) ||
	    setrlimit(RLIMIT_CPU, &cpu) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 125;
	challenge = mmap(NULL, allocation, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (challenge == MAP_FAILED) return 125;
	/* Refuse to receive password bytes without locked, nondumpable storage. */
	if (mlock(challenge, allocation) || madvise(challenge, allocation, MADV_DONTDUMP)) goto done;
	if (read_challenge(fd, challenge)) goto done;
	response.magic = htole32(BA_V2_MAGIC);
	response.version = htole32(BA_V2_VERSION);
	response.size = htole32(sizeof(response));
	memcpy(response.nonce, challenge->nonce, sizeof(response.nonce));
	memcpy(response.request_digest, challenge->request_digest, sizeof(response.request_digest));
	response.status = htole32(verify(challenge));
	wipe(challenge, allocation);
	/* Exactly one response write. A short write is terminal; never retry a
	 * partially accepted result on a one-use authority channel. */
	do { written = write(fd, &response, sizeof(response)); } while (written < 0 && errno == EINTR);
	if (written == (ssize_t)sizeof(response)) result = 0;
done:
	wipe(&response, sizeof(response));
	wipe(challenge, allocation);
	munlock(challenge, allocation);
	munmap(challenge, allocation);
	close(fd);
	return result;
}
