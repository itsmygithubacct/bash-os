/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BASHOS_AUTH_REQUEST_SNAPSHOT_H
#define BASHOS_AUTH_REQUEST_SNAPSHOT_H

#include <linux/types.h>
#include "../uapi/linux/bashos_auth.h"

/* New conservative bounds; not a recovered historical authority contract. */
#define BA_REQUEST_MAX_ITEMS 256U
#define BA_REQUEST_MAX_BLOB 65536U
#define BA_EDIT_MAX_TARGETS 16U

struct ba_request_snapshot {
	struct bashos_auth_privcmd wire;
	size_t allocation;
	u8 digest[BASHOS_AUTH_DIGEST_BYTES];
	u8 blobs[]; /* owned argv followed by owned environment; no user pointers */
};

/* Integrity and framing only. Neither a matching digest nor claimed uid/name
 * authenticates the request or authorizes a target. No ioctl calls this code.
 * The eventual authority must derive the actor, resolve targets, pin cwd and
 * evaluate a trusted policy before using this snapshot to create any grant. */
int ba_request_snapshot_kernel(const struct bashos_auth_privcmd *wire,
		const void *argv, const void *env, struct ba_request_snapshot **out);
int ba_request_snapshot_user(const struct bashos_auth_privcmd __user *wire,
		struct ba_request_snapshot **out);
void ba_request_snapshot_free(struct ba_request_snapshot *snapshot);

#endif
