// SPDX-License-Identifier: GPL-2.0-only
/* Owned, bounded request capture. Not wired to the stage-1 device. */
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "request.h"

static int ba_request_header(const struct bashos_auth_privcmd *r)
{
	if (r->size != sizeof(*r) || r->non_interactive > 1 ||
	    r->mode < BASHOS_AUTH_PRIVCMD_MODE_EXEC ||
	    r->mode > BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT ||
	    (r->flags & ~(BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL |
			  BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP)))
		return -EINVAL;
	if ((r->flags & BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL) &&
	    r->mode != BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP)
		return -EINVAL;
	if (r->argc > BA_REQUEST_MAX_ITEMS || r->envc > BA_REQUEST_MAX_ITEMS ||
	    r->argv_bytes > BA_REQUEST_MAX_BLOB || r->env_bytes > BA_REQUEST_MAX_BLOB)
		return -E2BIG;
	if (!!r->argc != !!r->argv_bytes || !!r->envc != !!r->env_bytes ||
	    r->argc > r->argv_bytes || r->envc > r->env_bytes)
		return -EINVAL;
	if (!memchr(r->caller_user, 0, sizeof(r->caller_user)) ||
	    !r->caller_user[0] ||
	    !memchr(r->target_user, 0, sizeof(r->target_user)) ||
	    !r->target_user[0] || !memchr(r->cwd, 0, sizeof(r->cwd)) ||
	    r->cwd[0] != '/')
		return -EINVAL;
	if (r->mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT &&
	    (!r->argc || r->argc > BA_EDIT_MAX_TARGETS || r->envc))
		return -EINVAL;
	if ((r->mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE ||
	     r->mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP) && r->argc)
		return -EINVAL;
	if ((r->mode == BASHOS_AUTH_PRIVCMD_MODE_EXEC ||
	     r->mode == BASHOS_AUTH_PRIVCMD_MODE_SHELL ||
	     r->mode == BASHOS_AUTH_PRIVCMD_MODE_LOGIN) && !r->argc)
		return -EINVAL;
	return 0;
}

/* Exactly count terminated strings; reject missing terminators and spare bytes.
 * Empty command arguments are legal. Environment names and edit paths are not
 * policy decisions, but malformed wire encodings must never reach a parser. */
static int ba_request_blob(const u8 *data, u32 bytes, u32 count,
			   bool environment, bool edit)
{
	u32 i, offset = 0;

	for (i = 0; i < count; i++) {
		const u8 *nul, *eq;
		size_t length, j;

		if (offset >= bytes)
			return -EINVAL;
		nul = memchr(data + offset, 0, bytes - offset);
		if (!nul)
			return -EINVAL;
		length = nul - (data + offset);
		if (edit && (!length || data[offset] != '/'))
			return -EINVAL;
		if (environment) {
			eq = memchr(data + offset, '=', length);
			if (!eq || eq == data + offset)
				return -EINVAL;
			for (j = 0; j < eq - (data + offset); j++) {
				u8 c = data[offset + j];

				if (!((c >= 'a' && c <= 'z') ||
				      (c >= 'A' && c <= 'Z') || c == '_' ||
				      (j && c >= '0' && c <= '9')))
					return -EINVAL;
			}
		}
		offset += length + 1;
	}
	return offset == bytes ? 0 : -EINVAL;
}

static void ba_digest_u32(struct sha256_state *state, u32 value)
{
	u8 b[4] = { value, value >> 8, value >> 16, value >> 24 };

	sha256_update(state, b, sizeof(b));
}

static void ba_digest_string(struct sha256_state *state, const char *value)
{
	u32 length = strlen(value);

	ba_digest_u32(state, length);
	sha256_update(state, (const u8 *)value, length);
}

static void ba_request_digest(struct ba_request_snapshot *s)
{
	const struct bashos_auth_privcmd *r = &s->wire;
	struct sha256_state state;

	/* Exact existing auth.c/doas.c framing, not a new wire digest format. */
	sha256_init(&state);
	sha256_update(&state, (const u8 *)"bashos-privcmd-v1", 16);
	ba_digest_u32(&state, r->mode);
	ba_digest_u32(&state, r->flags);
	ba_digest_u32(&state, r->non_interactive);
	ba_digest_u32(&state, r->caller_uid);
	ba_digest_u32(&state, r->caller_gid);
	ba_digest_u32(&state, r->target_uid);
	ba_digest_u32(&state, r->target_gid);
	ba_digest_u32(&state, r->argc);
	ba_digest_u32(&state, r->envc);
	ba_digest_u32(&state, r->argv_bytes);
	ba_digest_u32(&state, r->env_bytes);
	ba_digest_string(&state, r->caller_user);
	ba_digest_string(&state, r->target_user);
	ba_digest_string(&state, r->cwd);
	sha256_update(&state, s->blobs, r->argv_bytes + r->env_bytes);
	sha256_final(&state, s->digest);
	memzero_explicit(&state, sizeof(state));
}

static struct ba_request_snapshot *ba_request_allocate(
		const struct bashos_auth_privcmd *wire)
{
	struct ba_request_snapshot *s;
	size_t bytes;

	/* Header bounds make overflow impossible; retain checked arithmetic. */
	if (check_add_overflow((size_t)wire->argv_bytes,
			       (size_t)wire->env_bytes, &bytes) ||
	    check_add_overflow(bytes, sizeof(*s), &bytes))
		return NULL;
	s = kvzalloc(bytes, GFP_KERNEL);
	if (s) {
		s->allocation = bytes;
		s->wire = *wire;
		/* The response tail is not part of the request digest. Never retain
		 * caller-supplied ALLOW, handles, policy metadata or audit results as
		 * authority state; only a later authenticated decision may fill it. */
		memset((u8 *)&s->wire + offsetof(struct bashos_auth_privcmd, decision),
		       0, sizeof(s->wire) - offsetof(struct bashos_auth_privcmd, decision));
		/* No user pointers survive capture, even in private kernel state. */
		s->wire.argv_user_ptr = 0;
		s->wire.env_user_ptr = 0;
	}
	return s;
}

static int ba_request_finish(struct ba_request_snapshot *s)
{
	const struct bashos_auth_privcmd *r = &s->wire;
	int rc;

	rc = ba_request_blob(s->blobs, r->argv_bytes, r->argc, false,
			r->mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT);
	if (!rc)
		rc = ba_request_blob(s->blobs + r->argv_bytes,
				r->env_bytes, r->envc, true, false);
	if (rc)
		return rc;
	ba_request_digest(s);
	return crypto_memneq(s->digest, r->request_digest, sizeof(s->digest)) ?
		-EBADMSG : 0;
}

void ba_request_snapshot_free(struct ba_request_snapshot *s)
{
	if (s)
		kvfree_sensitive(s, s->allocation);
}

int ba_request_snapshot_kernel(const struct bashos_auth_privcmd *wire,
		const void *argv, const void *env, struct ba_request_snapshot **out)
{
	struct ba_request_snapshot *s;
	int rc;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!wire || (wire->argv_bytes && !argv) || (wire->env_bytes && !env))
		return -EINVAL;
	rc = ba_request_header(wire);
	if (rc)
		return rc;
	s = ba_request_allocate(wire);
	if (!s)
		return -ENOMEM;
	if (wire->argv_bytes)
		memcpy(s->blobs, argv, wire->argv_bytes);
	if (wire->env_bytes)
		memcpy(s->blobs + wire->argv_bytes, env, wire->env_bytes);
	rc = ba_request_finish(s);
	if (rc)
		ba_request_snapshot_free(s);
	else
		*out = s;
	return rc;
}

int ba_request_snapshot_user(const struct bashos_auth_privcmd __user *user,
		struct ba_request_snapshot **out)
{
	struct bashos_auth_privcmd wire;
	struct ba_request_snapshot *s;
	int rc;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (copy_from_user(&wire, user, sizeof(wire)))
		return -EFAULT;
	rc = ba_request_header(&wire);
	if (rc)
		return rc;
	/* The adapter has no compat handler. Refuse unrepresentable pointers. */
	if (wire.argv_user_ptr != (unsigned long)wire.argv_user_ptr ||
	    wire.env_user_ptr != (unsigned long)wire.env_user_ptr)
		return -EFAULT;
	s = ba_request_allocate(&wire);
	if (!s)
		return -ENOMEM;
	if ((wire.argv_bytes && copy_from_user(s->blobs,
		    u64_to_user_ptr(wire.argv_user_ptr), wire.argv_bytes)) ||
	    (wire.env_bytes && copy_from_user(s->blobs + wire.argv_bytes,
		    u64_to_user_ptr(wire.env_user_ptr), wire.env_bytes)))
		rc = -EFAULT;
	else
		rc = ba_request_finish(s);
	memzero_explicit(&wire, sizeof(wire));
	if (rc)
		ba_request_snapshot_free(s);
	else
		*out = s;
	return rc;
}
