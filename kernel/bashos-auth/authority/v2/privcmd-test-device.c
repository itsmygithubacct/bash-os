// SPDX-License-Identifier: GPL-2.0-only
/* Separately named qualification endpoint. Not part of the production module
 * or old ABI. This is the same policy/verifier/executor path for every caller;
 * root uid and Bash identity never create a command grant. */
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/random.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "audit-store.h"
#include "executor-channel.h"
#include "safeedit.h"
#include "timestamp-store.h"
#include "../../uapi/linux/bashos_privcmd_v2.h"

#define PRIVCMD_CONTEXTS 16U
static bool test_only;
module_param(test_only, bool, 0400);
/* Denial-only qualification control. Immutable at module load, absent from
 * production Kbuild, and never substitutes an allow/authentication result. */
static int test_edit_fail_index = -1;
module_param(test_edit_fail_index, int, 0400);
/* Fail RESET alone after normal framing/audit admission. This gives the
 * consumer ordering control a working PREPARE/RUN positive control in the
 * same module instance. It cannot mint a grant or alter a policy decision. */
static bool test_reset_fail;
module_param(test_reset_fail, bool, 0400);
#define INPUT_PARAMETERS(name) \
static char *name##_path, *name##_sha256; \
module_param(name##_path, charp, 0400); module_param(name##_sha256, charp, 0400)
INPUT_PARAMETERS(accounts);
INPUT_PARAMETERS(groups);
INPUT_PARAMETERS(profiles);
INPUT_PARAMETERS(policy);
INPUT_PARAMETERS(verifier);
INPUT_PARAMETERS(executor);
static struct ba_v2_accounts accounts;
static struct ba_v2_groups groups;
static struct ba_v2_profiles profiles;
static struct ba_v2_policy policy;
static struct ba_v2_trusted_file verifier, executor;
static const struct cred *administrator;
static struct ba_v2_audit_store *audit;
static struct ba_v2_timestamp_store *timestamps;
static atomic_t contexts = ATOMIC_INIT(0);
static DEFINE_SEMAPHORE(verifications, 2);

struct privcmd_context {
	struct mutex operation;
	struct ba_reference_actor actor;
	struct ba_ctx *secrets;
	struct ba_v2_timestamp_lease lease;
	struct ba_v2_timestamp_key cache_key;
	struct ba_v2_audit_ticket ticket;
	struct ba_v2_bound_request *bound;
	struct ba_v2_bound_request *edit_bound;
	struct ba_v2_environment environment;
	struct ba_v2_edit_session *edit;
	u32 edit_committed;
	u8 edit_transaction_digest[32];
	u8 grant_digest[32];
	u64 edit_request_id;
	u64 epoch, request_id, deadline, password_deadline, audit_sequence;
	bool pending, ready, cache_hit, commit_prepared;
};

static bool administrator_admission(void)
{
	return current_user_ns() == &init_user_ns && uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_SYS_ADMIN);
}

static int record_event(struct privcmd_context *c, u32 outcome, u32 reason, u32 kind, u32 code)
{
	struct bashos_audit_v2_record *event;
	const struct ba_v2_bound_request *b = c->bound ? c->bound : c->edit_bound;
	struct sha256_state hash;
	u32 length;
	int rc;
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) return -ENOMEM;
	event->account_generation = cpu_to_le64(accounts.generation);
	event->policy_generation = cpu_to_le64(policy.generation);
	event->group_generation = cpu_to_le64(groups.generation);
	event->verifier_generation = cpu_to_le64(accounts.generation);
	event->outcome = cpu_to_le32(outcome); event->reason = cpu_to_le32(reason);
	event->caller_uid = cpu_to_le32(__kuid_val(c->actor.cred->uid));
	event->caller_gid = cpu_to_le32(__kgid_val(c->actor.cred->gid));
	event->result_kind = cpu_to_le32(kind); event->result_code = cpu_to_le32(code);
	event->cache_hit = cpu_to_le32(c->cache_hit);
	memcpy(event->policy_digest, policy.input.digest, 32);
	memcpy(event->normalized_policy_digest, policy.normalized_digest, 32);
	if (b) {
		const char *command = b->query.command;
		event->mode = cpu_to_le32(b->request->wire.mode);
		event->target_uid = cpu_to_le32(b->identities.target.uid);
		event->target_gid = cpu_to_le32(b->identities.target_gid);
		event->rule_index = cpu_to_le32(b->decision.rule_index);
		memcpy(event->request_digest, b->request->digest, 32);
		if (c->commit_prepared) memcpy(event->request_digest, c->grant_digest, 32);
		if (b->query.edit) {
			event->target_count = cpu_to_le32(b->request->wire.argc);
			event->committed_count = cpu_to_le32(c->edit_committed);
			if (outcome == BASHOS_AUDIT_V2_EDIT_COMMIT && kind < b->request->wire.argc)
				command = b->argv[kind];
			if ((outcome == BASHOS_AUDIT_V2_EDIT_COMMIT || outcome == BASHOS_AUDIT_V2_EDIT_RESULT ||
			     (outcome == BASHOS_AUDIT_V2_EDIT_OPEN && kind == BASHOS_PRIVCMD_V2_EDIT_SEALED)) &&
			    memchr_inv(c->edit_transaction_digest, 0, sizeof(c->edit_transaction_digest)))
				memcpy(event->request_digest, c->edit_transaction_digest, 32);
		}
		length = min_t(size_t, strlen(command), sizeof(event->command));
		event->command_length = cpu_to_le32(length); memcpy(event->command, command, length);
		length = strlen(b->request->wire.cwd);
		event->cwd_length = cpu_to_le32(length); memcpy(event->cwd, b->request->wire.cwd, length);
		sha256_init(&hash); sha256_update(&hash, (const u8 *)b->request->wire.cwd, length);
		sha256_final(&hash, event->cwd_digest); memzero_explicit(&hash, sizeof(hash));
	}
	rc = ba_v2_audit_commit(&c->ticket, event, &c->audit_sequence);
	kfree_sensitive(event);
	return rc;
}

static void drop_edit(struct privcmd_context *c)
{
	ba_v2_edit_close(c->edit); c->edit = NULL;
	ba_v2_bound_free(c->edit_bound); c->edit_bound = NULL;
	c->edit_request_id = 0;
}

static void forget_request(struct privcmd_context *c)
{
	ba_v2_audit_cancel(&c->ticket);
	ba_v2_environment_free(&c->environment);
	ba_v2_bound_free(c->bound); c->bound = NULL;
	memzero_explicit(&c->cache_key, sizeof(c->cache_key));
	c->epoch = c->request_id = c->deadline = c->password_deadline = 0;
	c->pending = c->ready = c->cache_hit = false;
	c->commit_prepared = false; memzero_explicit(c->grant_digest, sizeof(c->grant_digest));
	c->edit_committed = 0; memzero_explicit(c->edit_transaction_digest, sizeof(c->edit_transaction_digest));
}

static int reject_request(struct privcmd_context *c, u32 reason, int error)
{
	int rc = 0;
	if (c->ticket.remaining) rc = record_event(c, BASHOS_AUDIT_V2_REJECTED, reason, 0, -error);
	drop_edit(c);
	forget_request(c);
	return rc ? rc : error;
}

static void destroy_context(struct privcmd_context *c)
{
	if (!c) return;
	if (c->pending && c->ticket.remaining)
		(void)record_event(c, BASHOS_AUDIT_V2_REJECTED, BASHOS_AUDIT_V2_REASON_BINDING, 0, ECANCELED);
	forget_request(c); drop_edit(c); ba_ctx_destroy(c->secrets);
	ba_v2_timestamp_release(&c->lease); ba_reference_actor_release(&c->actor);
	mutex_destroy(&c->operation); kfree_sensitive(c);
}

static int privcmd_open(struct inode *inode, struct file *file)
{
	struct privcmd_context *c;
	int rc;
	if (current_user_ns() != &init_user_ns ||
	    (file->f_mode & (FMODE_READ | FMODE_WRITE)) != (FMODE_READ | FMODE_WRITE)) return -EPERM;
	if (atomic_inc_return(&contexts) > PRIVCMD_CONTEXTS) { atomic_dec(&contexts); return -EMFILE; }
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) { rc = -ENOMEM; goto no_context; }
	mutex_init(&c->operation);
	rc = ba_reference_actor_capture(&c->actor);
	if (rc) goto failed;
	c->secrets = ba_ctx_create();
	if (!c->secrets) { rc = -ENOMEM; goto failed; }
	rc = ba_v2_timestamp_acquire(timestamps, &c->actor, &c->lease);
	if (rc) goto failed;
	file->private_data = c;
	return stream_open(inode, file);
failed:
	destroy_context(c);
no_context:
	atomic_dec(&contexts); return rc;
}

static int privcmd_release(struct inode *inode, struct file *file)
{
	destroy_context(file->private_data); file->private_data = NULL;
	atomic_dec(&contexts); return 0;
}

static int prepare_request(struct privcmd_context *c, void __user *argument)
{
	struct bashos_privcmd_v2_prepare __user *user = argument;
	struct bashos_privcmd_v2_prepare *reply;
	struct ba_request_snapshot *snapshot = NULL;
	const struct ba_v2_profile *profile;
	u32 header[4], decision, reason, password_seconds;
	u64 now;
	int rc;
	if (c->pending) (void)reject_request(c, BASHOS_AUDIT_V2_REASON_BINDING, -ECANCELED);
	rc = ba_v2_audit_reserve(audit, 4, &c->ticket);
	if (rc) { drop_edit(c); return rc; }
	if (copy_from_user(header, argument, sizeof(header))) { rc = -EFAULT; goto malformed; }
	if (header[0] != sizeof(*reply) || header[1] != BASHOS_PRIVCMD_V2_VERSION || header[2] || header[3]) {
		rc = -EINVAL; goto malformed;
	}
	rc = ba_request_snapshot_user(&user->request, &snapshot);
	if (rc) goto malformed;
	/* Shell/login replacement cannot fall through to supervised EXEC. Edit
	 * has a separate open/commit state machine and never calls the executor. */
	if (snapshot->wire.mode != BASHOS_AUTH_PRIVCMD_MODE_EXEC &&
	    snapshot->wire.mode != BASHOS_AUTH_PRIVCMD_MODE_VALIDATE &&
	    snapshot->wire.mode != BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT) {
		ba_request_snapshot_free(snapshot); rc = -EOPNOTSUPP; goto malformed;
	}
	if (snapshot->wire.mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT &&
	    (!snapshot->wire.argc || snapshot->wire.argc > BA_V2_EDIT_MAX_TARGETS)) {
		ba_request_snapshot_free(snapshot); rc = -E2BIG; goto malformed;
	}
	if (snapshot->wire.mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT) {
		ba_v2_audit_cancel(&c->ticket);
		rc = ba_v2_audit_reserve(audit, 4 + 2 * snapshot->wire.argc, &c->ticket);
		if (rc) { ba_request_snapshot_free(snapshot); drop_edit(c); return rc; }
	}
	rc = ba_v2_bound_capture(snapshot, &accounts, &groups, &policy, administrator, &c->bound);
	if (rc) goto malformed;
	memcpy(c->grant_digest, c->bound->request->digest, 32);
	if (c->edit) {
		if (!c->bound->query.edit) { rc = -EKEYREJECTED; goto malformed; }
		rc = ba_v2_edit_bound_digest(c->edit, c->bound->request->digest, c->grant_digest);
		if (rc) goto malformed;
		c->commit_prepared = true;
	}
	decision = BASHOS_PRIVCMD_V2_DENY; reason = BASHOS_AUDIT_V2_REASON_POLICY;
	if (!c->bound->decision.allow) {
		rc = record_event(c, BASHOS_AUDIT_V2_DENIED, reason, 0, EACCES);
		if (rc) goto failed;
		goto respond;
	}
	if (!c->bound->query.validate && !c->bound->query.edit) {
		profile = ba_v2_profile_find(&profiles, c->bound->identities.target.name);
		if (!profile) { rc = -EACCES; goto malformed; }
		rc = ba_v2_environment_build(c->bound, profile, &c->environment);
		if (rc) goto malformed;
	}
	rc = ba_v2_timestamp_key(c->bound, &accounts, &groups, &policy, &verifier,
		accounts.generation, &c->cache_key);
	if (rc) goto malformed;
	c->epoch = ba_v2_timestamp_epoch(&c->lease);
	if (!c->epoch) { rc = -EKEYREVOKED; goto malformed; }
	now = ktime_get_boottime_ns();
	if (c->bound->decision.nopasswd) {
		if (check_add_overflow(now, BA_REFERENCE_MAX_LIFETIME_NS, &c->deadline)) { rc = -EOVERFLOW; goto malformed; }
		c->ready = true;
	} else if (c->bound->decision.timestamp_seconds) {
		rc = ba_v2_timestamp_lookup(&c->lease, c->epoch, &c->cache_key, &c->deadline);
		if (rc < 0) goto malformed;
		c->ready = c->cache_hit = rc == 1;
	}
	password_seconds = c->bound->decision.password_seconds;
	/* Zero is the policy's no-prompt-timeout setting. The pending context
	 * remains bounded by fd lifetime; actual native verification is 30s. */
	if (password_seconds && check_add_overflow(now, (u64)password_seconds * NSEC_PER_SEC, &c->password_deadline)) {
		rc = -EOVERFLOW; goto malformed;
	}
	do { get_random_bytes(&c->request_id, sizeof(c->request_id)); } while (!c->request_id);
	c->pending = true;
	decision = c->ready ? BASHOS_PRIVCMD_V2_READY : BASHOS_PRIVCMD_V2_AUTH_REQUIRED;
	reason = c->bound->request->wire.non_interactive && !c->ready ?
		BASHOS_AUDIT_V2_REASON_NONINTERACTIVE : BASHOS_AUDIT_V2_REASON_AUTH;
	rc = record_event(c, c->ready ? BASHOS_AUDIT_V2_AUTHORIZED : BASHOS_AUDIT_V2_AUTH_REQUIRED, reason, 0, 0);
	if (rc) goto failed;
respond:
	reply = kzalloc(sizeof(*reply), GFP_KERNEL);
	if (!reply) { rc = -ENOMEM; goto malformed; }
	reply->size = sizeof(*reply); reply->version = BASHOS_PRIVCMD_V2_VERSION;
	reply->request = c->bound->request->wire;
	memcpy(reply->request.request_digest, c->grant_digest, 32);
	reply->decision = decision; reply->reason = reason;
	reply->encoding = le32_to_cpu(c->bound->identities.caller_account->encoding);
	reply->cache_hit = c->cache_hit; reply->request_id = c->request_id;
	reply->deadline_ns = c->deadline; reply->audit_sequence = c->audit_sequence;
	rc = copy_to_user(argument, reply, sizeof(*reply)) ? -EFAULT : 0;
	kfree_sensitive(reply);
	if (rc) return reject_request(c, BASHOS_AUDIT_V2_REASON_MALFORMED, rc);
	if (decision == BASHOS_PRIVCMD_V2_DENY) { drop_edit(c); forget_request(c); }
	return 0;
malformed:
	return reject_request(c, BASHOS_AUDIT_V2_REASON_MALFORMED, rc);
failed:
	drop_edit(c); forget_request(c); return rc;
}

static bool pending_matches(struct privcmd_context *c, u64 id, const u8 digest[32])
{
	return c->pending && c->bound && id == c->request_id &&
		!crypto_memneq(digest, c->grant_digest, 32) && ba_v2_bound_matches(c->bound);
}

static int verify_request(struct privcmd_context *c, bool legacy, void __user *argument)
{
	struct bashos_privcmd_v2_verify request;
	struct ba_v2_verified_event *event = NULL;
	struct ba_reference_claim claim = {0};
	const struct ba_v2_account_record *caller;
	int rc;
	if (copy_from_user(&request, argument, sizeof(request)))
		return reject_request(c, BASHOS_AUDIT_V2_REASON_MALFORMED, -EFAULT);
	if (request.size != sizeof(request) || request.version != BASHOS_PRIVCMD_V2_VERSION || request.reserved ||
	    request.deadline_ns || request.audit_sequence || !pending_matches(c, request.request_id, request.request_digest) || c->ready)
		return reject_request(c, BASHOS_AUDIT_V2_REASON_BINDING, -EKEYREJECTED);
	if (c->bound->request->wire.non_interactive)
		return reject_request(c, BASHOS_AUDIT_V2_REASON_NONINTERACTIVE, -EACCES);
	if ((c->password_deadline && ktime_get_boottime_ns() >= c->password_deadline) ||
	    !ba_v2_timestamp_epoch_matches(&c->lease, c->epoch))
		return reject_request(c, BASHOS_AUDIT_V2_REASON_EXPIRED, -EKEYEXPIRED);
	caller = c->bound->identities.caller_account;
	if (le32_to_cpu(caller->encoding) != (legacy ? BA_V2_ENCODING_LEGACY_HEX : BA_V2_ENCODING_STANDARD))
		return reject_request(c, BASHOS_AUDIT_V2_REASON_AUTH, -EACCES);
	if (down_trylock(&verifications)) return reject_request(c, BASHOS_AUDIT_V2_REASON_INTERNAL, -EBUSY);
	rc = ba_v2_verify_account(&verifier, &accounts, policy.generation, c,
		c->secrets, request.secret_id, caller->user, BA_V2_PURPOSE_PRIVCMD, c->grant_digest, &event);
	up(&verifications);
	mutex_lock(&c->secrets->lock); (void)ba_clear(c->secrets, request.secret_id); mutex_unlock(&c->secrets->lock);
	if (!rc && !ba_v2_bound_matches(c->bound)) rc = -EPERM;
	if (!rc) {
		claim.uid = make_kuid(&init_user_ns, le32_to_cpu(caller->uid));
		claim.gid = make_kgid(&init_user_ns, le32_to_cpu(caller->gid)); claim.purpose = BA_V2_PURPOSE_PRIVCMD;
		memcpy(claim.user, caller->user, sizeof(claim.user)); memcpy(claim.request_digest, c->grant_digest, 32);
		rc = ba_v2_timestamp_verified(&c->lease, c->epoch, &c->cache_key, c->bound->decision.timestamp_seconds,
			event, c, &claim, &c->deadline);
	}
	ba_v2_event_destroy(event); memzero_explicit(&claim, sizeof(claim));
	if (rc) {
		int audit_rc = record_event(c, BASHOS_AUDIT_V2_VERIFY_DENIED, BASHOS_AUDIT_V2_REASON_AUTH, 0, -rc);
		drop_edit(c); forget_request(c); return audit_rc ? audit_rc : rc;
	}
	rc = record_event(c, BASHOS_AUDIT_V2_AUTHORIZED, BASHOS_AUDIT_V2_REASON_AUTH, 0, 0);
	if (rc) {
		/* A verified password must not leave reusable authentication behind
		 * when this operation cannot publish its required authorization log. */
		(void)ba_v2_timestamp_reset(&c->lease, false);
		drop_edit(c); forget_request(c); return rc;
	}
	c->ready = true; request.deadline_ns = c->deadline; request.audit_sequence = c->audit_sequence;
	if (copy_to_user(argument, &request, sizeof(request))) {
		(void)ba_v2_timestamp_reset(&c->lease, false);
		return reject_request(c, BASHOS_AUDIT_V2_REASON_MALFORMED, -EFAULT);
	}
	return 0;
}

static int run_request(struct privcmd_context *c, void __user *argument)
{
	struct bashos_privcmd_v2_run request;
	struct ba_v2_exec_response response = {0};
	int rc;
	if (copy_from_user(&request, argument, sizeof(request)))
		return reject_request(c, BASHOS_AUDIT_V2_REASON_MALFORMED, -EFAULT);
	if (request.size != sizeof(request) || request.version != BASHOS_PRIVCMD_V2_VERSION ||
	    request.reserved[0] || request.reserved[1] || request.result || request.status || request.failed_step || request.error ||
	    request.audit_sequence || !pending_matches(c, request.request_id, request.request_digest) || !c->ready ||
	    c->bound->query.edit)
		return reject_request(c, BASHOS_AUDIT_V2_REASON_BINDING, -EKEYREJECTED);
	/* Irreversible fd-local consumption precedes the reset-ordered redemption
	 * check. Copyout faults, helper failures and signals never restore it. */
	c->pending = c->ready = false;
	rc = ba_v2_timestamp_redeem(&c->lease, c->epoch, c->deadline);
	if (rc) return reject_request(c, BASHOS_AUDIT_V2_REASON_EXPIRED, rc);
	if (c->bound->query.validate) {
		rc = record_event(c, BASHOS_AUDIT_V2_VALIDATED, BASHOS_AUDIT_V2_REASON_AUTH, 0, 0);
		request.result = BASHOS_PRIVCMD_V2_VALIDATED;
	} else {
		rc = record_event(c, BASHOS_AUDIT_V2_EXEC_START, BASHOS_AUDIT_V2_REASON_EXEC, 0, 0);
		if (rc) goto done;
		rc = ba_v2_execute_native(&executor, c->bound, &c->environment, BA_V2_EXEC_MAX_TIMEOUT, &response);
		if (rc) {
			request.result = BASHOS_PRIVCMD_V2_LAUNCH_ERROR; request.status = 126; request.error = -rc;
		} else {
			request.result = le32_to_cpu(response.kind); request.status = le32_to_cpu(response.status);
			request.failed_step = le32_to_cpu(response.failed_step); request.error = le32_to_cpu(response.error);
		}
		rc = record_event(c, BASHOS_AUDIT_V2_EXEC_RESULT, BASHOS_AUDIT_V2_REASON_EXEC, request.result, request.status);
	}
	request.audit_sequence = c->audit_sequence;
	if (!rc && copy_to_user(argument, &request, sizeof(request))) rc = -EFAULT;
done:
	memzero_explicit(&response, sizeof(response)); forget_request(c); return rc;
}

static int edit_intent(void *cookie, u32 index, u32 committed, const u8 digest[32])
{
	struct privcmd_context *c = cookie;
	bool fault = test_edit_fail_index >= 0 && index == (u32)test_edit_fail_index;
	int rc;
	if (!c->bound || !c->bound->query.edit || !ba_v2_bound_matches(c->bound)) return -EPERM;
	c->edit_committed = committed;
	memcpy(c->edit_transaction_digest, digest, sizeof(c->edit_transaction_digest));
	rc = record_event(c, BASHOS_AUDIT_V2_EDIT_COMMIT,
		fault ? BASHOS_AUDIT_V2_REASON_INTERNAL : BASHOS_AUDIT_V2_REASON_EDIT, index, fault ? EIO : 0);
	return rc ? rc : fault ? -EIO : 0;
}

static int edit_request(struct privcmd_context *c, unsigned int phase, void __user *argument)
{
	bool commit = phase == 1, seal = phase == 2;
	struct bashos_privcmd_v2_edit request;
	struct ba_v2_edit_result result = {.failed_index = U32_MAX};
	struct file *copies[BA_V2_EDIT_MAX_TARGETS] = {NULL};
	u32 i;
	int rc, audit_rc;
	static_assert(sizeof(request) == 184);
	if (copy_from_user(&request, argument, sizeof(request))) { rc = -EFAULT; goto malformed; }
	if (request.size != sizeof(request) || request.version != BASHOS_PRIVCMD_V2_VERSION ||
	    !request.count || request.count > BA_V2_EDIT_MAX_TARGETS || request.reserved || request.reserved2 ||
	    request.result || request.committed_count || request.failed_index || request.error || request.cleanup_error ||
	    request.audit_sequence || memchr_inv(request.transaction_digest, 0, sizeof(request.transaction_digest))) {
		rc = -EKEYREJECTED; goto malformed;
	}
	if (seal) {
		if (c->pending || !c->edit || !c->edit_bound || request.request_id != c->edit_request_id ||
		    request.count != c->edit_bound->request->wire.argc ||
		    crypto_memneq(request.request_digest, c->edit_bound->request->digest, 32)) {
			rc = -EKEYREJECTED; goto malformed;
		}
	} else if (!pending_matches(c, request.request_id, request.request_digest) || !c->ready ||
	    !c->bound->query.edit || commit != c->commit_prepared || c->bound->request->wire.argc != request.count) {
		rc = -EKEYREJECTED; goto malformed;
	}
	for (i = request.count; i < BA_V2_EDIT_MAX_TARGETS; i++)
		if (request.copy_fds[i]) { rc = -EINVAL; goto malformed; }
	/* This consumes the fresh phase grant before acquiring any caller fd or
	 * touching any file. OPEN and COMMIT cannot reuse each other's approval. */
	if (seal) {
		rc = ba_v2_audit_reserve(audit, 1, &c->ticket);
		if (rc) goto malformed;
	}
	else {
		c->pending = c->ready = false;
		rc = ba_v2_timestamp_redeem(&c->lease, c->epoch, c->deadline);
	}
	if (rc) goto complete;
	for (i = 0; i < request.count; i++) {
		if (request.copy_fds[i] > INT_MAX || !(copies[i] = fget(request.copy_fds[i]))) {
			rc = -EBADF; result.failed_index = i; goto complete;
		}
	}
	if (seal) {
		rc = ba_v2_edit_seal(c->edit, administrator, request.request_digest, copies, request.count, &result);
	} else if (commit) {
		rc = ba_v2_edit_commit(&c->edit, c->bound, administrator, copies, request.count,
			edit_intent, c, &result);
	} else {
		drop_edit(c);
		rc = ba_v2_edit_open(c->bound, administrator, copies, request.count, &c->edit);
	}
complete:
	request.result = rc ? BASHOS_PRIVCMD_V2_EDIT_FAILED :
		seal ? BASHOS_PRIVCMD_V2_EDIT_SEALED : commit ? BASHOS_PRIVCMD_V2_EDIT_COMMITTED : BASHOS_PRIVCMD_V2_EDIT_OPENED;
	request.error = rc < 0 ? -rc : 0; request.committed_count = result.committed;
	request.failed_index = result.failed_index; request.cleanup_error = result.cleanup_error;
	memcpy(request.transaction_digest, result.transaction_digest, sizeof(request.transaction_digest));
	c->edit_committed = result.committed;
	memcpy(c->edit_transaction_digest, result.transaction_digest, sizeof(c->edit_transaction_digest));
	audit_rc = record_event(c, commit ? BASHOS_AUDIT_V2_EDIT_RESULT : BASHOS_AUDIT_V2_EDIT_OPEN,
		BASHOS_AUDIT_V2_REASON_EDIT, request.result, request.error);
	if (audit_rc) {
		request.result = BASHOS_PRIVCMD_V2_EDIT_FAILED;
		if (!request.error) request.error = -audit_rc;
	}
	if (request.result == BASHOS_PRIVCMD_V2_EDIT_FAILED) {
		drop_edit(c);
	}
	request.audit_sequence = c->audit_sequence;
	/* Structured failures preserve a committed prefix. An inaccessible reply
	 * is separately EFAULT; it never restores a grant or claims rollback. */
	rc = copy_to_user(argument, &request, sizeof(request)) ? -EFAULT : 0;
	if (rc) drop_edit(c);
	else if (!commit && !seal && c->edit) {
		c->edit_bound = c->bound; c->bound = NULL;
		c->edit_request_id = request.request_id;
	}
	if (commit) drop_edit(c);
	for (i = 0; i < BA_V2_EDIT_MAX_TARGETS; i++) if (copies[i]) fput(copies[i]);
	memzero_explicit(&request, sizeof(request)); memzero_explicit(&result, sizeof(result));
	forget_request(c);
	return rc;
malformed:
	return reject_request(c, BASHOS_AUDIT_V2_REASON_BINDING, rc);
}

static int reset_timestamp(struct privcmd_context *c, void __user *argument)
{
	struct bashos_privcmd_v2_reset request;
	int rc;
	if (c->pending) (void)reject_request(c, BASHOS_AUDIT_V2_REASON_RESET, -ECANCELED);
	else drop_edit(c);
	if (copy_from_user(&request, argument, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BASHOS_PRIVCMD_V2_VERSION ||
	    (request.flags & ~BASHOS_PRIVCMD_V2_RESET_ALL) || request.reserved || request.audit_sequence) return -EINVAL;
	rc = ba_v2_audit_reserve(audit, 1, &c->ticket);
	if (rc) return rc;
	if (test_reset_fail) {
		rc = record_event(c, BASHOS_AUDIT_V2_REJECTED,
				  BASHOS_AUDIT_V2_REASON_RESET, 0, EIO);
		ba_v2_audit_cancel(&c->ticket);
		return rc ? rc : -EIO;
	}
	/* If logging fails, no later command can use this fd's previous grant.
	 * A successful reset is never undone because the reply buffer faults. */
	rc = ba_v2_timestamp_reset(&c->lease, request.flags & BASHOS_PRIVCMD_V2_RESET_ALL);
	if (!rc) rc = record_event(c, BASHOS_AUDIT_V2_RESET, BASHOS_AUDIT_V2_REASON_RESET, 0, request.flags);
	request.audit_sequence = c->audit_sequence;
	ba_v2_audit_cancel(&c->ticket);
	if (!rc && copy_to_user(argument, &request, sizeof(request))) rc = -EFAULT;
	return rc;
}

static int secret_input(void *cookie, void *data, size_t size)
{
	u64 address = *(u64 *)cookie;
	return address != (unsigned long)address || copy_from_user(data, u64_to_user_ptr(address), size) ? -EFAULT : 0;
}

static long secret_ioctl(struct privcmd_context *c, unsigned int command, void __user *arg)
{
	long rc = -ENOTTY;
	mutex_lock(&c->secrets->lock);
	if (command == BASHOS_AUTH_IOC_NEW_SECRET) {
		struct bashos_auth_handle request;
		if (copy_from_user(&request, arg, sizeof(request))) rc = -EFAULT;
		else if (request.id || request.flags) rc = -EINVAL;
		else {
			rc = ba_new(c->secrets, &request.id);
			if (!rc && copy_to_user(arg, &request, sizeof(request))) { ba_clear(c->secrets, request.id); rc = -EFAULT; }
		}
	} else if (command == BASHOS_AUTH_IOC_WRITE_SECRET) {
		struct bashos_auth_secret_write request;
		if (copy_from_user(&request, arg, sizeof(request))) rc = -EFAULT;
		else rc = ba_append(c->secrets, request.id, request.len, secret_input, &request.user_ptr);
	} else if (command == BASHOS_AUTH_IOC_SEAL_SECRET || command == BASHOS_AUTH_IOC_CLEAR_SECRET) {
		struct bashos_auth_handle request;
		if (copy_from_user(&request, arg, sizeof(request))) rc = -EFAULT;
		else if (request.flags) rc = -EINVAL;
		else rc = command == BASHOS_AUTH_IOC_SEAL_SECRET ? ba_seal(c->secrets, request.id) : ba_clear(c->secrets, request.id);
	}
	mutex_unlock(&c->secrets->lock);
	return rc;
}

static long audit_ioctl(unsigned int command, void __user *argument)
{
	struct bashos_audit_v2_record *record;
	int rc;
	if (!administrator_admission()) return -EPERM;
	if (command == BASHOS_PRIVCMD_V2_AUDIT_INFO) {
		struct ba_v2_audit_info info;
		struct bashos_privcmd_v2_audit_info result;
		ba_v2_audit_info(audit, &info);
		result.epoch = info.epoch; result.next_sequence = info.next_sequence;
		result.oldest_sequence = info.oldest_sequence; result.backpressure_denials = info.backpressure_denials;
		result.available = info.available; result.reserved = info.reserved;
		return copy_to_user(argument, &result, sizeof(result)) ? -EFAULT : 0;
	}
	if (command == BASHOS_PRIVCMD_V2_AUDIT_ACK) {
		struct bashos_privcmd_v2_audit_ack ack;
		if (copy_from_user(&ack, argument, sizeof(ack))) return -EFAULT;
		return ba_v2_audit_ack(audit, ack.epoch, ack.sequence);
	}
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record) return -ENOMEM;
	if (command == BASHOS_PRIVCMD_V2_AUDIT_VERIFY) {
		if (copy_from_user(record, argument, sizeof(*record))) rc = -EFAULT;
		else rc = ba_v2_audit_verify(audit, record);
	} else {
		rc = ba_v2_audit_peek(audit, record);
		if (!rc && copy_to_user(argument, record, sizeof(*record))) rc = -EFAULT;
	}
	kfree_sensitive(record); return rc;
}

static long privcmd_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	struct privcmd_context *c = file->private_data;
	void __user *arg = (void __user *)argument;
	long rc;
	/* Foreign tasks cannot use or revoke the owner's context via a fork,
	 * inherited descriptor, another thread, exec, or SCM_RIGHTS transfer. */
	if (!ba_reference_actor_matches(&c->actor)) return -EPERM;
	mutex_lock(&c->operation);
	if (!ba_reference_actor_matches(&c->actor)) { rc = -EPERM; goto done; }
	switch (command) {
	case BASHOS_PRIVCMD_V2_INFO: {
		struct bashos_privcmd_v2_info info = {
			.size = sizeof(info), .version = BASHOS_PRIVCMD_V2_VERSION, .flags = BASHOS_PRIVCMD_V2_QUALIFICATION_ONLY,
			.account_generation = accounts.generation, .policy_generation = policy.generation,
			.group_generation = groups.generation, .verifier_generation = accounts.generation
		};
		memcpy(info.policy_digest, policy.input.digest, 32); memcpy(info.normalized_policy_digest, policy.normalized_digest, 32);
		rc = copy_to_user(arg, &info, sizeof(info)) ? -EFAULT : 0; break;
	}
	case BASHOS_PRIVCMD_V2_PREPARE: rc = prepare_request(c, arg); break;
	case BASHOS_PRIVCMD_V2_VERIFY: rc = verify_request(c, false, arg); break;
	case BASHOS_PRIVCMD_V2_VERIFY_LEGACY_HEX: rc = verify_request(c, true, arg); break;
	case BASHOS_PRIVCMD_V2_RUN: rc = run_request(c, arg); break;
	case BASHOS_PRIVCMD_V2_EDIT_OPEN: rc = edit_request(c, 0, arg); break;
	case BASHOS_PRIVCMD_V2_EDIT_COMMIT: rc = edit_request(c, 1, arg); break;
	case BASHOS_PRIVCMD_V2_EDIT_SEAL: rc = edit_request(c, 2, arg); break;
	case BASHOS_PRIVCMD_V2_RESET: rc = reset_timestamp(c, arg); break;
	case BASHOS_PRIVCMD_V2_CANCEL:
		drop_edit(c);
		rc = c->pending ? reject_request(c, BASHOS_AUDIT_V2_REASON_BINDING, -ECANCELED) : 0;
		if (rc == -ECANCELED) rc = 0;
		break;
	case BASHOS_PRIVCMD_V2_AUDIT_PEEK: case BASHOS_PRIVCMD_V2_AUDIT_ACK:
	case BASHOS_PRIVCMD_V2_AUDIT_VERIFY: case BASHOS_PRIVCMD_V2_AUDIT_INFO:
		rc = audit_ioctl(command, arg); break;
	default: rc = secret_ioctl(c, command, arg);
	}
done:
	mutex_unlock(&c->operation); return rc;
}

static const struct file_operations privcmd_operations = {
	.owner = THIS_MODULE, .open = privcmd_open, .release = privcmd_release, .unlocked_ioctl = privcmd_ioctl
};
static struct miscdevice privcmd_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "bashos-privcmd-v2-test", .mode = 0666, .fops = &privcmd_operations
};

static void close_bundle(void)
{
	ba_v2_timestamp_destroy(timestamps); timestamps = NULL;
	ba_v2_audit_destroy(audit); audit = NULL;
	ba_v2_policy_close(&policy); ba_v2_profiles_close(&profiles); ba_v2_groups_close(&groups);
	ba_v2_accounts_close(&accounts); ba_v2_trusted_close(&verifier); ba_v2_trusted_close(&executor);
	if (administrator) put_cred(administrator);
	administrator = NULL;
}

static int __init privcmd_init(void)
{
	u8 pin[6][32];
	const char *hashes[] = {accounts_sha256, groups_sha256, profiles_sha256, policy_sha256, verifier_sha256, executor_sha256};
	u32 i;
	int rc;
	if (!test_only || !administrator_admission()) return -EPERM;
	if (test_edit_fail_index < -1 || test_edit_fail_index >= (int)BA_V2_EDIT_MAX_TARGETS) return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(hashes); i++)
		if (!hashes[i] || strlen(hashes[i]) != 64 || hex2bin(pin[i], hashes[i], 32)) return -EINVAL;
	administrator = get_current_cred();
	rc = ba_v2_accounts_open(accounts_path, pin[0], &accounts);
	if (rc) goto failed;
	rc = ba_v2_groups_open(groups_path, pin[1], accounts.generation, &accounts, &groups);
	if (rc) goto failed;
	rc = ba_v2_profiles_open(profiles_path, pin[2], accounts.generation, &accounts, &profiles);
	if (rc) goto failed;
	rc = ba_v2_policy_open(policy_path, pin[3], accounts.generation, &policy);
	if (rc) goto failed;
	rc = ba_v2_trusted_open(verifier_path, pin[4], 8U << 20, true, &verifier);
	if (rc) goto failed;
	rc = ba_v2_trusted_open(executor_path, pin[5], 8U << 20, true, &executor);
	if (rc) goto failed;
	audit = ba_v2_audit_create();
	if (IS_ERR(audit)) { rc = PTR_ERR(audit); audit = NULL; goto failed; }
	timestamps = ba_v2_timestamp_create();
	if (IS_ERR(timestamps)) { rc = PTR_ERR(timestamps); timestamps = NULL; goto failed; }
	rc = misc_register(&privcmd_device);
	if (rc) goto failed;
	memzero_explicit(pin, sizeof(pin)); return 0;
failed:
	close_bundle(); memzero_explicit(pin, sizeof(pin)); return rc;
}

static void __exit privcmd_exit(void)
{
	misc_deregister(&privcmd_device); close_bundle();
}
module_init(privcmd_init);
module_exit(privcmd_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable PRIVCMD v2 qualification endpoint; production features off");
