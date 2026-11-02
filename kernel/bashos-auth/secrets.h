/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BASHOS_AUTH_STAGE1_SECRETS_H
#define BASHOS_AUTH_STAGE1_SECRETS_H

#include <linux/mutex.h>
#include <linux/types.h>
#include "uapi/linux/bashos_auth.h"

/* New implementation limits, not recovered historical policy. */
#define BA_MAX_SECRET 4096U
#define BA_MAX_SLOTS 16U
#define BA_MAX_CONTEXTS 128U

enum ba_slot_state { BA_WRITABLE, BA_SEALED, BA_EXPORTED };
enum ba_wipe_kind { BA_WIPE_STAGING, BA_WIPE_EXPORT, BA_WIPE_SLOT,
		    BA_WIPE_CONTEXT, BA_WIPE_KINDS };

struct ba_slot {
	u32 id;
	u32 len;
	enum ba_slot_state state;
	u8 bytes[BA_MAX_SECRET];
};

struct ba_ctx {
	struct mutex lock;
	u32 next_id;
	struct ba_slot *slots[BA_MAX_SLOTS];
	struct bashos_auth_stats stats;
#ifdef BA_KUNIT_TEST
	/* Compiled only into the separate KUnit module, never the device module. */
	void (*after_wipe)(const void *, size_t, enum ba_wipe_kind, void *);
	void *wipe_cookie;
#endif
};

/* Transport callbacks return 0 on full copy, -EFAULT on any incomplete copy.
 * Device callbacks use actual copy_{from,to}_user. Tests inject faults here.
 * All operations except create/destroy require ctx->lock to be held, including
 * across ioctl reply copies. No secret is exported by a test-only ioctl.
 */
typedef int (*ba_read_fn)(void *cookie, void *dst, size_t len);
typedef int (*ba_write_fn)(void *cookie, const void *src, size_t len);

struct ba_ctx *ba_ctx_create(void);
void ba_ctx_destroy(struct ba_ctx *ctx);
int ba_new(struct ba_ctx *ctx, u32 *id);
int ba_clear(struct ba_ctx *ctx, u32 id);
int ba_seal(struct ba_ctx *ctx, u32 id);
int ba_append(struct ba_ctx *ctx, u32 id, u32 len,
	      ba_read_fn read_fn, void *cookie);
int ba_same(struct ba_ctx *ctx, u32 a, u32 b, u32 *result);
int ba_export(struct ba_ctx *ctx, u32 id, u32 capacity, u32 *length,
	      ba_write_fn write_fn, void *cookie);

#endif
