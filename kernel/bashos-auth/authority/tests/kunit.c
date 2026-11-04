// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../reference.h"
#include "../request.h"
#include "vectors.h"

struct reference_fixture {
	struct kunit *test;
	struct ba_reference_store *store;
	unsigned int grant_wipes;
	unsigned int store_wipes;
	unsigned int nonzero_wipes;
};

static void observe_reference_wipe(void *cookie, const void *data, size_t len,
				   enum ba_reference_wipe kind)
{
	struct reference_fixture *f = cookie;

	/* Called under the core mutex: record only, assert after unlock/destruction. */
	f->nonzero_wipes += !!memchr_inv(data, 0, len);
	if (kind == BA_REFERENCE_WIPE_GRANT)
		f->grant_wipes++;
	else
		f->store_wipes++;
}

static void reference_cleanup(void *cookie)
{
	struct reference_fixture *f = cookie;

	ba_reference_store_destroy(f->store);
	f->store = NULL;
	KUNIT_EXPECT_EQ(f->test, f->nonzero_wipes, 0U);
	KUNIT_EXPECT_EQ(f->test, f->store_wipes, 1U);
}

static struct reference_fixture *reference_create(struct kunit *test)
{
	struct reference_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return NULL;
	f->test = test;
	/* Capture identity in the test task, never in a separate suite init task. */
	f->store = ba_reference_store_create();
	if (!f->store)
		return NULL;
	ba_reference_test_observer(f->store, observe_reference_wipe, f);
	ba_reference_test_clock(f->store, 1000);
	if (kunit_add_action_or_reset(test, reference_cleanup, f))
		return NULL;
	return f;
}

static struct ba_reference_claim reference_claim(void)
{
	struct ba_reference_claim claim = {
		.uid = KUIDT_INIT(3101), .gid = KGIDT_INIT(3201),
		.purpose = 1, .user = "fixture",
		.request_digest = { 0x19, 0x23 },
	};

	return claim;
}

static int copy_reference(void *cookie, const void *data, size_t len)
{
	memcpy(cookie, data, len);
	return 0;
}

static int partial_copy_reference(void *cookie, const void *data, size_t len)
{
	if (len)
		memcpy(cookie, data, 1);
	return -EFAULT;
}

static struct bashos_auth_privcmd request_wire(void)
{
	struct bashos_auth_privcmd r = {
		.size = sizeof(r), .mode = BASHOS_AUTH_PRIVCMD_MODE_EXEC,
		.non_interactive = 1, .caller_uid = 1000, .caller_gid = 1000,
		.argc = BA_VECTOR_EXEC_ARGC, .envc = BA_VECTOR_EXEC_ENVC,
		.argv_bytes = sizeof(ba_vector_exec_argv),
		.env_bytes = sizeof(ba_vector_exec_env),
		.caller_user = "1000", .target_user = "root", .cwd = "/tmp",
		.argv_user_ptr = 0x1234, .env_user_ptr = 0x5678,
	};

	memcpy(r.request_digest, ba_vector_exec_digest, sizeof(r.request_digest));
	return r;
}

static void snapshot_cleanup(void *snapshot)
{
	ba_request_snapshot_free(snapshot);
}

static void request_known_vector(struct kunit *test)
{
	struct bashos_auth_privcmd r = request_wire();
	struct ba_request_snapshot *snapshot = NULL;
	int rc;

	/* A valid request digest does not cover any claimed response fields. */
	memset((u8 *)&r + offsetof(struct bashos_auth_privcmd, decision), 0xa5,
	       sizeof(r) - offsetof(struct bashos_auth_privcmd, decision));
	r.decision = BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC;
	rc = ba_request_snapshot_kernel(&r, ba_vector_exec_argv,
					ba_vector_exec_env, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, snapshot);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, snapshot_cleanup, snapshot), 0);
	KUNIT_EXPECT_MEMEQ(test, snapshot->digest, ba_vector_exec_digest, 32);
	KUNIT_EXPECT_EQ(test, snapshot->wire.argv_user_ptr, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot->wire.env_user_ptr, 0ULL);
	KUNIT_EXPECT_PTR_EQ(test, memchr_inv((u8 *)&snapshot->wire +
			offsetof(struct bashos_auth_privcmd, decision), 0,
			sizeof(snapshot->wire) - offsetof(struct bashos_auth_privcmd, decision)), NULL);
}

static void request_owned_snapshot(struct kunit *test)
{
	struct bashos_auth_privcmd r = request_wire();
	u8 argv[sizeof(ba_vector_exec_argv)];
	u8 env[sizeof(ba_vector_exec_env)];
	struct ba_request_snapshot *snapshot = NULL;
	int rc;

	memcpy(argv, ba_vector_exec_argv, sizeof(argv));
	memcpy(env, ba_vector_exec_env, sizeof(env));
	rc = ba_request_snapshot_kernel(&r, argv, env, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, snapshot_cleanup, snapshot), 0);
	memset(argv, 0xff, sizeof(argv));
	memset(env, 0xff, sizeof(env));
	memset(&r, 0xff, sizeof(r));
	KUNIT_EXPECT_MEMEQ(test, snapshot->blobs, ba_vector_exec_argv, sizeof(argv));
	KUNIT_EXPECT_MEMEQ(test, snapshot->blobs + sizeof(argv), ba_vector_exec_env, sizeof(env));
	KUNIT_EXPECT_MEMEQ(test, snapshot->digest, ba_vector_exec_digest, 32);
}

static void request_changed_binding_rejected(struct kunit *test)
{
	unsigned int i;

	/* Every change is well-formed where possible; the old digest cannot attest it. */
	for (i = 0; i < 11; i++) {
		struct bashos_auth_privcmd r = request_wire();
		struct ba_request_snapshot *snapshot = NULL;
		u8 argv[sizeof(ba_vector_exec_argv)], env[sizeof(ba_vector_exec_env)];
		int rc;

		memcpy(argv, ba_vector_exec_argv, sizeof(argv));
		memcpy(env, ba_vector_exec_env, sizeof(env));
		switch (i) {
		case 0: r.caller_uid++; break;
		case 1: r.caller_gid++; break;
		case 2: r.target_uid++; break;
		case 3: r.target_gid++; break;
		case 4: r.mode = BASHOS_AUTH_PRIVCMD_MODE_SHELL; break;
		case 5: r.flags = BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP; break;
		case 6: r.non_interactive = 0; break;
		case 7: r.cwd[1] = 'x'; break;
		case 8: r.target_user[0] = 'X'; break;
		case 9: argv[1] = 'X'; break;
		case 10: env[5] = 'X'; break;
		}
		rc = ba_request_snapshot_kernel(&r, argv, env, &snapshot);
		KUNIT_EXPECT_EQ_MSG(test, rc, -EBADMSG, "binding field %u", i);
		KUNIT_EXPECT_PTR_EQ(test, snapshot, NULL);
		ba_request_snapshot_free(snapshot);
	}
}

static void request_framing_and_bounds(struct kunit *test)
{
	unsigned int i;

	for (i = 0; i < 10; i++) {
		struct bashos_auth_privcmd r = request_wire();
		struct ba_request_snapshot *snapshot = NULL;
		u8 argv[sizeof(ba_vector_exec_argv)], env[sizeof(ba_vector_exec_env)];
		int rc;

		memcpy(argv, ba_vector_exec_argv, sizeof(argv));
		memcpy(env, ba_vector_exec_env, sizeof(env));
		switch (i) {
		case 0: argv[sizeof(argv) - 1] = 'X'; break;
		case 1: r.argc--; break;
		case 2: r.argc++; break;
		case 3: env[0] = '='; break;
		case 4: env[0] = '0'; break;
		case 5: r.argv_bytes = BA_REQUEST_MAX_BLOB + 1; break;
		case 6: r.envc = BA_REQUEST_MAX_ITEMS + 1; break;
		case 7: memset(r.cwd, 'X', sizeof(r.cwd)); break;
		case 8: r.flags = 0x80000000U; break;
		case 9: r.size--; break;
		}
		rc = ba_request_snapshot_kernel(&r, argv, env, &snapshot);
		KUNIT_EXPECT_LT_MSG(test, rc, 0, "malformed case %u", i);
		KUNIT_EXPECT_PTR_EQ(test, snapshot, NULL);
		ba_request_snapshot_free(snapshot);
	}
}

static void request_edit_limit_and_reset(struct kunit *test)
{
	struct bashos_auth_privcmd r = request_wire();
	struct ba_request_snapshot *snapshot = NULL;
	int rc;

	r.mode = BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT;
	r.argc = BA_VECTOR_EDIT16_ARGC;
	r.argv_bytes = sizeof(ba_vector_edit16_argv);
	r.envc = r.env_bytes = 0;
	memcpy(r.request_digest, ba_vector_edit16_digest, 32);
	rc = ba_request_snapshot_kernel(&r, ba_vector_edit16_argv, NULL, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);
	ba_request_snapshot_free(snapshot);
	snapshot = NULL;
	r.argc = 17;
	KUNIT_EXPECT_EQ(test, ba_request_snapshot_kernel(&r, ba_vector_edit16_argv,
			NULL, &snapshot), -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, snapshot, NULL);
	r.mode = BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP;
	r.argc = r.argv_bytes = 0;
	memcpy(r.request_digest, ba_vector_reset_digest, 32);
	rc = ba_request_snapshot_kernel(&r, NULL, NULL, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);
	ba_request_snapshot_free(snapshot);
}

static void request_user_header_fault(struct kunit *test)
{
	struct ba_request_snapshot *snapshot = NULL;

	KUNIT_EXPECT_EQ(test, ba_request_snapshot_user((void __user *)1, &snapshot), -EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, snapshot, NULL);
}

static void reference_without_issuer_stays_empty(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32] = { 0 }, bytes[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, sizeof(bytes), copy_reference, bytes), 0L);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
}

static void reference_stream_and_single_redemption(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32], bytes[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 0, copy_reference, bytes), 0L);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 7, copy_reference, bytes), 7L);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 40, copy_reference, bytes + 7), 25L);
	KUNIT_EXPECT_MEMEQ(test, bytes, reference, 32);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 32, copy_reference, bytes), 0L);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
}

static void reference_unknown_value_is_not_a_grant(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32], wrong[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	memcpy(wrong, reference, 32);
	wrong[0] ^= 1;
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, wrong, &claim), -ENOENT);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), 0);
}

static void reference_changed_claim_revokes(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32];
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	for (i = 0; i < 8; i++) {
		struct ba_reference_claim wrong = claim;

		KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
		switch (i) {
		case 0: wrong.uid = KUIDT_INIT(0); break;
		case 1: wrong.gid = KGIDT_INIT(0); break;
		case 2: wrong.purpose = 2; break;
		case 3: wrong.user[0] = 'X'; break;
		case 4: wrong.request_digest[31] ^= 1; break;
		case 5: wrong.uid = INVALID_UID; break;
		case 6: wrong.purpose = 0; break;
		case 7: memset(wrong.user, 'X', sizeof(wrong.user)); break;
		}
		KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &wrong), -EACCES);
		KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
	}
}

static void reference_deadline_limits_and_overflow(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32], bytes[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_EXPECT_EQ(test, ba_reference_test_seed(f->store, &claim, 0, reference), -EINVAL);
	KUNIT_EXPECT_EQ(test, ba_reference_test_seed(f->store, &claim,
		BA_REFERENCE_MAX_LIFETIME_NS + 1, reference), -EINVAL);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, bytes), -EBUSY);
	ba_reference_test_clock(f->store, 1099);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 1, copy_reference, bytes), 1L);
	ba_reference_test_clock(f->store, 1100);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -EKEYEXPIRED);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
	ba_reference_test_clock(f->store, U64_MAX - 5);
	KUNIT_EXPECT_EQ(test, ba_reference_test_seed(f->store, &claim, 10, reference), -EOVERFLOW);
}

static void reference_partial_copy_revokes(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32], byte;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 32, partial_copy_reference, &byte), -EFAULT);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
	KUNIT_EXPECT_GT(test, f->grant_wipes, 0U);
}

static void reference_generation_revocation(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_advance_epochs(f->store, 1, 2), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_advance_epochs(f->store, 2, 2), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), -ENOENT);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_advance_epochs(f->store, 1, 2), -EINVAL);
	KUNIT_EXPECT_EQ(test, ba_reference_advance_epochs(f->store, 2, 2), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, reference, &claim), 0);
}

static void reference_contexts_are_independent(struct kunit *test)
{
	struct reference_fixture *a = reference_create(test), *b = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 one[32], two[32];

	KUNIT_ASSERT_NOT_NULL(test, a);
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(a->store, &claim, 100, one), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(b->store, one, &claim), -ENOENT);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(b->store, &claim, 100, two), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(b->store, one, &claim), -ENOENT);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(a->store, one, &claim), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(b->store, two, &claim), 0);
}

static void reference_actor_drift_is_rejected(struct kunit *test)
{
	struct ba_reference_actor actor, wrong;
	unsigned int i;

	KUNIT_ASSERT_EQ(test, ba_reference_actor_capture(&actor), 0);
	KUNIT_EXPECT_TRUE(test, ba_reference_actor_matches(&actor));
	for (i = 0; i < 6; i++) {
		wrong = actor; /* borrowed fields: only release the original capture */
		switch (i) {
		case 0: wrong.task = NULL; break;
		case 1: wrong.cred = NULL; break;
		case 2: wrong.session = NULL; break;
		case 3: wrong.namespaces = NULL; break;
		case 4: wrong.cwd.dentry = NULL; break;
		case 5: wrong.root.mnt = NULL; break;
		}
		KUNIT_EXPECT_FALSE_MSG(test, ba_reference_actor_matches(&wrong), "actor field %u", i);
	}
	ba_reference_actor_release(&actor);
}

struct reference_other_task {
	struct ba_reference_store *store;
	struct ba_reference_claim claim;
	u8 reference[32];
	struct completion done;
	int result;
};

static int reference_other_task_worker(void *cookie)
{
	struct reference_other_task *work = cookie;

	work->result = ba_reference_consume(work->store, work->reference, &work->claim);
	complete(&work->done);
	return 0;
}

static void reference_other_task_cannot_redeem(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct reference_other_task work = { .claim = reference_claim() };
	struct task_struct *task;
	unsigned long completed;

	KUNIT_ASSERT_NOT_NULL(test, f);
	work.store = f->store;
	init_completion(&work.done);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &work.claim, 100, work.reference), 0);
	task = kthread_create(reference_other_task_worker, &work, "ba-ref-negative");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	get_task_struct(task);
	wake_up_process(task);
	completed = wait_for_completion_timeout(&work.done, msecs_to_jiffies(2000));
	kthread_stop(task);
	put_task_struct(task);
	KUNIT_ASSERT_NE(test, completed, 0UL);
	KUNIT_EXPECT_EQ(test, work.result, -EPERM);
	KUNIT_EXPECT_EQ(test, ba_reference_consume(f->store, work.reference, &work.claim), 0);
}

static void reference_final_release_erases(struct kunit *test)
{
	struct reference_fixture *f = reference_create(test);
	struct ba_reference_claim claim = reference_claim();
	u8 reference[32], partial;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ba_reference_test_seed(f->store, &claim, 100, reference), 0);
	KUNIT_EXPECT_EQ(test, ba_reference_read(f->store, 1, copy_reference, &partial), 1L);
	ba_reference_store_destroy(f->store);
	f->store = NULL;
	KUNIT_EXPECT_EQ(test, f->nonzero_wipes, 0U);
	KUNIT_EXPECT_EQ(test, f->store_wipes, 1U);
	KUNIT_EXPECT_GT(test, f->grant_wipes, 0U);
}

static struct kunit_case authority_cases[] = {
	KUNIT_CASE(request_known_vector),
	KUNIT_CASE(request_owned_snapshot),
	KUNIT_CASE(request_changed_binding_rejected),
	KUNIT_CASE(request_framing_and_bounds),
	KUNIT_CASE(request_edit_limit_and_reset),
	KUNIT_CASE(request_user_header_fault),
	KUNIT_CASE(reference_without_issuer_stays_empty),
	KUNIT_CASE(reference_stream_and_single_redemption),
	KUNIT_CASE(reference_unknown_value_is_not_a_grant),
	KUNIT_CASE(reference_changed_claim_revokes),
	KUNIT_CASE(reference_deadline_limits_and_overflow),
	KUNIT_CASE(reference_partial_copy_revokes),
	KUNIT_CASE(reference_generation_revocation),
	KUNIT_CASE(reference_contexts_are_independent),
	KUNIT_CASE(reference_actor_drift_is_rejected),
	KUNIT_CASE(reference_other_task_cannot_redeem),
	KUNIT_CASE(reference_final_release_erases),
	{}
};

static struct kunit_suite authority_suite = {
	.name = "bashos-auth-authority-next",
	.test_cases = authority_cases,
};
kunit_test_suite(authority_suite);
MODULE_LICENSE("GPL");
