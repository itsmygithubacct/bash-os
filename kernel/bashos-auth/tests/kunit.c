/* SPDX-License-Identifier: GPL-2.0-only */
#define BA_KUNIT_TEST
#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../secrets.h"

struct fixture {
	struct kunit *test;
	struct ba_ctx *ctx;
	unsigned int wipes[BA_WIPE_KINDS];
	size_t wiped_bytes[BA_WIPE_KINDS];
	unsigned int nonzero_wipes;
};

struct transport {
	u8 *bytes;
	size_t prefix;
	bool fail;
	unsigned int calls;
};

static void observe_wipe(const void *p, size_t n, enum ba_wipe_kind kind,
			 void *cookie)
{
	struct fixture *f = cookie;

	/* Inspect before free; defer KUnit assertions until no core lock is held. */
	if (memchr_inv(p, 0, n))
		f->nonzero_wipes++;
	f->wipes[kind]++;
	f->wiped_bytes[kind] += n;
}

static int receive(void *cookie, void *dst, size_t n)
{
	struct transport *t = cookie;

	t->calls++;
	memcpy(dst, t->bytes, t->fail ? min(n, t->prefix) : n);
	return t->fail ? -EFAULT : 0;
}

static int transmit(void *cookie, const void *src, size_t n)
{
	struct transport *t = cookie;

	t->calls++;
	memcpy(t->bytes, src, t->fail ? min(n, t->prefix) : n);
	return t->fail ? -EFAULT : 0;
}

/* Each call returns with its mutex released before KUnit evaluates the
 * assertion. KUnit may run fixture cleanup in a different task, and a fatal
 * assertion may abort the test body. No lock may span either boundary.
 */
static int locked_new(struct ba_ctx *ctx, u32 *id)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_new(ctx, id);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int locked_clear(struct ba_ctx *ctx, u32 id)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_clear(ctx, id);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int locked_seal(struct ba_ctx *ctx, u32 id)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_seal(ctx, id);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int locked_append(struct ba_ctx *ctx, u32 id, u32 len,
			 ba_read_fn read_fn, void *cookie)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_append(ctx, id, len, read_fn, cookie);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int locked_same(struct ba_ctx *ctx, u32 a, u32 b, u32 *result)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_same(ctx, a, b, result);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int locked_export(struct ba_ctx *ctx, u32 id, u32 capacity, u32 *length,
			 ba_write_fn write_fn, void *cookie)
{
	int ret;

	mutex_lock(&ctx->lock);
	ret = ba_export(ctx, id, capacity, length, write_fn, cookie);
	mutex_unlock(&ctx->lock);
	return ret;
}

static int append(struct ba_ctx *ctx, u32 id, const void *bytes, u32 n)
{
	struct transport t = { .bytes = (u8 *)bytes };

	return locked_append(ctx, id, n, receive, &t);
}

static int fixture_init(struct kunit *test)
{
	struct fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	f->test = test;
	f->ctx = ba_ctx_create();
	if (!f->ctx)
		return -ENOMEM;
	f->ctx->after_wipe = observe_wipe;
	f->ctx->wipe_cookie = f;
	test->priv = f;
	return 0;
}

static void fixture_exit(struct kunit *test)
{
	struct fixture *f = test->priv;

	if (f->ctx)
		ba_ctx_destroy(f->ctx);
	KUNIT_EXPECT_EQ(f->test, f->nonzero_wipes, 0U);
}

static void append_binary_compare(struct kunit *test)
{
	struct fixture *f = test->priv;
	const u8 input[] = { 0xa7, 0, 0xff, 0x23 };
	u32 a, b, c, same = 9;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &a), 0);
	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &b), 0);
	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &c), 0);
	/* Independently specified equivalence: 1 + 1 + 2 bytes equals 4 bytes. */
	KUNIT_ASSERT_EQ(test, append(f->ctx, a, input, 1), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, a, input + 1, 1), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, a, input + 2, 2), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, b, input, sizeof(input)), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, c, input, 1), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, a), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, b), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, c), 0);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, a, b, &same), 0);
	KUNIT_EXPECT_EQ(test, same, 1U);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, a, c, &same), 0);
	KUNIT_EXPECT_EQ(test, same, 0U);
	KUNIT_EXPECT_EQ(test, f->ctx->stats.created_secrets, 3ULL);
}

static void length_distinguishes_zero_padding(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 zero = 0;
	u32 a, b, same = 9;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &a), 0);
	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &b), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, b, &zero, 1), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, a), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, b), 0);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, a, b, &same), 0);
	KUNIT_EXPECT_EQ(test, same, 0U);
}

static void seal_is_immutable(struct kunit *test)
{
	struct fixture *f = test->priv;
	u32 id, same = 9;
	u8 byte = 0xa7;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, id, id, &same), -EPERM);
	KUNIT_ASSERT_EQ(test, append(f->ctx, id, &byte, 1), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, append(f->ctx, id, &byte, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, locked_seal(f->ctx, id), -EPERM);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, id, id, &same), 0);
	KUNIT_EXPECT_EQ(test, same, 1U);
}

static void append_fault_is_atomic_and_erased(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 old[] = { 0xa7, 0x23 }, bad[] = { 0x44, 0x55, 0x66 };
	u8 output[sizeof(old)] = { 0 };
	struct transport input = { .bytes = bad, .prefix = 2, .fail = true };
	struct transport exported = { .bytes = output };
	u32 id, len = 99;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, id, old, sizeof(old)), 0);
	KUNIT_EXPECT_EQ(test, locked_append(f->ctx, id, sizeof(bad), receive, &input), -EFAULT);
	KUNIT_EXPECT_EQ(test, f->wipes[BA_WIPE_STAGING], 2U);
	KUNIT_EXPECT_EQ(test, f->wiped_bytes[BA_WIPE_STAGING], sizeof(old) + sizeof(bad));
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, sizeof(output), &len, transmit, &exported), 0);
	KUNIT_EXPECT_EQ(test, len, (u32)sizeof(old));
	KUNIT_EXPECT_MEMEQ(test, output, old, sizeof(old));
}

static void capacity_and_overflow(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 *input = kunit_kmalloc(test, BA_MAX_SECRET, GFP_KERNEL);
	struct transport t;
	u32 id;

	KUNIT_ASSERT_NOT_NULL(test, input);
	memset(input, 0xa7, BA_MAX_SECRET);
	t = (struct transport) { .bytes = input };
	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_EXPECT_EQ(test, locked_append(f->ctx, id, U32_MAX, receive, &t), -E2BIG);
	KUNIT_EXPECT_EQ(test, t.calls, 0U);
	KUNIT_EXPECT_EQ(test, locked_append(f->ctx, id, BA_MAX_SECRET, receive, &t), 0);
	KUNIT_EXPECT_EQ(test, locked_append(f->ctx, id, 1, receive, &t), -E2BIG);
	KUNIT_EXPECT_EQ(test, t.calls, 1U);
	KUNIT_EXPECT_EQ(test, locked_append(f->ctx, id, 0, receive, NULL), 0);
}

static void export_preconditions_retain_secret(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 input[] = { 0xa7, 0x23 }, output[2] = { 0 };
	struct transport t = { .bytes = output };
	u32 id, len = 99;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, id, input, sizeof(input)), 0);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 2, &len, transmit, &t), -EPERM);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 1, &len, transmit, &t), -ENOSPC);
	KUNIT_EXPECT_EQ(test, len, 99U);
	KUNIT_EXPECT_EQ(test, t.calls, 0U);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 2, &len, transmit, &t), 0);
	KUNIT_EXPECT_MEMEQ(test, output, input, sizeof(input));
	KUNIT_EXPECT_EQ(test, f->ctx->stats.refused_exports, 2ULL);
}

static void export_once_erases_even_on_fault(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 input[] = { 0xa7, 0x23 }, output[2] = { 0 };
	struct transport t = { .bytes = output, .prefix = 1, .fail = true };
	u32 id, len = 99, same = 9;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, id, input, sizeof(input)), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 2, &len, transmit, &t), -EFAULT);
	KUNIT_EXPECT_EQ(test, output[0], input[0]);
	KUNIT_EXPECT_EQ(test, output[1], (u8)0);
	KUNIT_EXPECT_EQ(test, f->wiped_bytes[BA_WIPE_EXPORT], (size_t)BA_MAX_SECRET);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 2, &len, transmit, &t), -EPERM);
	KUNIT_EXPECT_EQ(test, t.calls, 1U);
	KUNIT_EXPECT_EQ(test, locked_same(f->ctx, id, id, &same), -EPERM);
	KUNIT_EXPECT_EQ(test, append(f->ctx, id, input, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, locked_seal(f->ctx, id), -EPERM);
	KUNIT_EXPECT_EQ(test, f->ctx->stats.refused_exports, 2ULL);
}

static void empty_export_is_consumed(struct kunit *test)
{
	struct fixture *f = test->priv;
	u32 id, len = 99;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 0, &len, NULL, NULL), 0);
	KUNIT_EXPECT_EQ(test, len, 0U);
	KUNIT_EXPECT_EQ(test, locked_export(f->ctx, id, 0, &len, NULL, NULL), -EPERM);
}

static void clear_erases_and_ids_do_not_repeat(struct kunit *test)
{
	struct fixture *f = test->priv;
	u8 bytes[] = { 0xa7, 0x23 };
	u32 a, b;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &a), 0);
	KUNIT_ASSERT_EQ(test, append(f->ctx, a, bytes, sizeof(bytes)), 0);
	KUNIT_EXPECT_EQ(test, locked_clear(f->ctx, a), 0);
	KUNIT_EXPECT_EQ(test, f->wipes[BA_WIPE_SLOT], 1U);
	KUNIT_EXPECT_EQ(test, locked_clear(f->ctx, a), -ENOENT);
	KUNIT_EXPECT_EQ(test, locked_seal(f->ctx, a), -ENOENT);
	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &b), 0);
	KUNIT_EXPECT_NE(test, a, b);
	KUNIT_EXPECT_EQ(test, f->ctx->stats.cleared_secrets, 1ULL);
}

static void close_path_erases_every_state(struct kunit *test)
{
	struct fixture *f = test->priv;
	struct ba_ctx *ctx = f->ctx;
	u8 input[] = { 0xa7, 0x23 }, output[2];
	struct transport t = { .bytes = output };
	u32 a, b, c, len;

	KUNIT_ASSERT_EQ(test, locked_new(ctx, &a), 0);
	KUNIT_ASSERT_EQ(test, locked_new(ctx, &b), 0);
	KUNIT_ASSERT_EQ(test, locked_new(ctx, &c), 0);
	KUNIT_ASSERT_EQ(test, append(ctx, a, input, 2), 0);
	KUNIT_ASSERT_EQ(test, append(ctx, b, input, 2), 0);
	KUNIT_ASSERT_EQ(test, append(ctx, c, input, 2), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(ctx, b), 0);
	KUNIT_ASSERT_EQ(test, locked_seal(ctx, c), 0);
	KUNIT_ASSERT_EQ(test, locked_export(ctx, c, 2, &len, transmit, &t), 0);
	f->ctx = NULL;
	ba_ctx_destroy(ctx); /* Exactly the destructor called from .release. */
	KUNIT_EXPECT_EQ(test, f->wipes[BA_WIPE_SLOT], 3U);
	KUNIT_EXPECT_EQ(test, f->wipes[BA_WIPE_CONTEXT], 1U);
	KUNIT_EXPECT_EQ(test, f->wiped_bytes[BA_WIPE_SLOT], 3 * sizeof(struct ba_slot));
}

static void bounded_slots_and_id_exhaustion(struct kunit *test)
{
	struct fixture *f = test->priv;
	u32 id, first = 0;
	unsigned int i;

	for (i = 0; i < BA_MAX_SLOTS; i++) {
		KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
		if (!i)
			first = id;
	}
	KUNIT_EXPECT_EQ(test, locked_new(f->ctx, &id), -ENOSPC);
	KUNIT_ASSERT_EQ(test, locked_clear(f->ctx, first), 0);
	mutex_lock(&f->ctx->lock);
	f->ctx->next_id = U32_MAX;
	mutex_unlock(&f->ctx->lock);
	KUNIT_EXPECT_EQ(test, locked_new(f->ctx, &id), 0);
	KUNIT_EXPECT_EQ(test, id, U32_MAX);
	KUNIT_ASSERT_EQ(test, locked_clear(f->ctx, id), 0);
	KUNIT_EXPECT_EQ(test, locked_new(f->ctx, &id), -EOVERFLOW);
}

static void contexts_are_independent(struct kunit *test)
{
	struct fixture *f = test->priv;
	struct ba_ctx *other;
	u32 id;

	KUNIT_ASSERT_EQ(test, locked_new(f->ctx, &id), 0);
	other = ba_ctx_create();
	KUNIT_ASSERT_NOT_NULL(test, other);
	KUNIT_EXPECT_EQ(test, locked_clear(other, id), -ENOENT);
	KUNIT_EXPECT_EQ(test, other->stats.created_secrets, 0ULL);
	ba_ctx_destroy(other);
	KUNIT_EXPECT_EQ(test, locked_seal(f->ctx, id), 0);
}

static struct kunit_case ba_cases[] = {
	KUNIT_CASE(append_binary_compare),
	KUNIT_CASE(length_distinguishes_zero_padding),
	KUNIT_CASE(seal_is_immutable),
	KUNIT_CASE(append_fault_is_atomic_and_erased),
	KUNIT_CASE(capacity_and_overflow),
	KUNIT_CASE(export_preconditions_retain_secret),
	KUNIT_CASE(export_once_erases_even_on_fault),
	KUNIT_CASE(empty_export_is_consumed),
	KUNIT_CASE(clear_erases_and_ids_do_not_repeat),
	KUNIT_CASE(close_path_erases_every_state),
	KUNIT_CASE(bounded_slots_and_id_exhaustion),
	KUNIT_CASE(contexts_are_independent),
	{}
};

static struct kunit_suite ba_suite = {
	.name = "bashos-auth-stage1-secrets",
	.init = fixture_init,
	.exit = fixture_exit,
	.test_cases = ba_cases,
};
kunit_test_suite(ba_suite);
MODULE_LICENSE("GPL");
