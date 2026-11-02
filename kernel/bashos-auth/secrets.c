/* SPDX-License-Identifier: GPL-2.0-only */
/* Real bounded kernel storage; no token, credential or policy implementation. */
#include <crypto/utils.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "secrets.h"

static void ba_erase(struct ba_ctx *ctx, void *p, size_t n,
		     enum ba_wipe_kind kind)
{
#ifdef BA_KUNIT_TEST
	void (*observer)(const void *, size_t, enum ba_wipe_kind, void *) =
		ctx->after_wipe;
	void *cookie = ctx->wipe_cookie;
#endif
	memzero_explicit(p, n);
#ifdef BA_KUNIT_TEST
	if (observer)
		observer(p, n, kind, cookie);
#endif
}

static int ba_index(struct ba_ctx *ctx, u32 id)
{
	unsigned int i;

	lockdep_assert_held(&ctx->lock);
	if (!id)
		return -ENOENT;
	for (i = 0; i < BA_MAX_SLOTS; i++)
		if (ctx->slots[i] && ctx->slots[i]->id == id)
			return i;
	return -ENOENT;
}

struct ba_ctx *ba_ctx_create(void)
{
	struct ba_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (ctx) {
		mutex_init(&ctx->lock);
		ctx->next_id = 1;
	}
	return ctx;
}

int ba_new(struct ba_ctx *ctx, u32 *id)
{
	struct ba_slot *slot;
	unsigned int i;

	lockdep_assert_held(&ctx->lock);
	/* IDs never repeat in an open file description, including after CLEAR. */
	if (!ctx->next_id)
		return -EOVERFLOW;
	for (i = 0; i < BA_MAX_SLOTS && ctx->slots[i]; i++)
		;
	if (i == BA_MAX_SLOTS)
		return -ENOSPC;
	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;
	slot->id = ctx->next_id++;
	slot->state = BA_WRITABLE;
	ctx->slots[i] = slot;
	ctx->stats.created_secrets++;
	*id = slot->id;
	return 0;
}

int ba_clear(struct ba_ctx *ctx, u32 id)
{
	int i = ba_index(ctx, id);
	struct ba_slot *slot;

	if (i < 0)
		return i;
	slot = ctx->slots[i];
	ctx->slots[i] = NULL;
	ba_erase(ctx, slot, sizeof(*slot), BA_WIPE_SLOT);
	kfree_sensitive(slot);
	ctx->stats.cleared_secrets++;
	return 0;
}

void ba_ctx_destroy(struct ba_ctx *ctx)
{
	unsigned int i;

	if (!ctx)
		return;
	/* Called by .release only at the final struct file reference, or tests. */
	mutex_lock(&ctx->lock);
	for (i = 0; i < BA_MAX_SLOTS; i++)
		if (ctx->slots[i])
			ba_clear(ctx, ctx->slots[i]->id);
	mutex_unlock(&ctx->lock);
	mutex_destroy(&ctx->lock);
	ba_erase(ctx, ctx, sizeof(*ctx), BA_WIPE_CONTEXT);
	kfree_sensitive(ctx);
}

int ba_seal(struct ba_ctx *ctx, u32 id)
{
	int i = ba_index(ctx, id);

	if (i < 0)
		return i;
	if (ctx->slots[i]->state != BA_WRITABLE)
		return -EPERM;
	ctx->slots[i]->state = BA_SEALED;
	return 0;
}

int ba_append(struct ba_ctx *ctx, u32 id, u32 len,
	      ba_read_fn read_fn, void *cookie)
{
	int i = ba_index(ctx, id), ret;
	struct ba_slot *slot;
	void *staging;

	if (i < 0)
		return i;
	slot = ctx->slots[i];
	if (slot->state != BA_WRITABLE)
		return -EPERM;
	/* Subtraction avoids integer overflow and bounds allocation before copy. */
	if (len > BA_MAX_SECRET - slot->len)
		return -E2BIG;
	if (!len)
		return 0;
	staging = kzalloc(len, GFP_KERNEL);
	if (!staging)
		return -ENOMEM;
	ret = read_fn(cookie, staging, len);
	if (!ret) {
		memcpy(slot->bytes + slot->len, staging, len);
		slot->len += len;
	}
	/* Includes partial copy_from_user failures; no prefix is committed. */
	ba_erase(ctx, staging, len, BA_WIPE_STAGING);
	kfree_sensitive(staging);
	return ret;
}

int ba_same(struct ba_ctx *ctx, u32 a, u32 b, u32 *result)
{
	int ai = ba_index(ctx, a), bi = ba_index(ctx, b), different;
	struct ba_slot *as, *bs;

	if (ai < 0 || bi < 0)
		return -ENOENT;
	as = ctx->slots[ai];
	bs = ctx->slots[bi];
	if (as->state != BA_SEALED || bs->state != BA_SEALED)
		return -EPERM;
	/* Compare the entire zero-padded capacity, including embedded NUL bytes.
	 * No early exit on secret contents. This is not a timing-proof claim.
	 */
	different = crypto_memneq(as->bytes, bs->bytes, BA_MAX_SECRET);
	*result = (!different) & (as->len == bs->len);
	return 0;
}

int ba_export(struct ba_ctx *ctx, u32 id, u32 capacity, u32 *length,
	      ba_write_fn write_fn, void *cookie)
{
	int i = ba_index(ctx, id), ret;
	struct ba_slot *slot;
	u32 len;

	if (i < 0) {
		ret = i;
		goto refused;
	}
	slot = ctx->slots[i];
	if (slot->state != BA_SEALED) {
		ret = -EPERM;
		goto refused;
	}
	if (capacity < slot->len) {
		ret = -ENOSPC;
		goto refused;
	}
	len = slot->len;
	/* Once copying can disclose any bytes, consume even on EFAULT. Never
	 * restore SEALED after a partial copy or failed ioctl reply copy.
	 */
	slot->state = BA_EXPORTED;
	ret = len ? write_fn(cookie, slot->bytes, len) : 0;
	ba_erase(ctx, slot->bytes, sizeof(slot->bytes), BA_WIPE_EXPORT);
	slot->len = 0;
	if (ret)
		goto refused;
	*length = len;
	return 0;
refused:
	ctx->stats.refused_exports++;
	return ret;
}
