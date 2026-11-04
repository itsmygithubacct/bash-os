// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include "timestamp-store.h"

struct ba_v2_timestamp_scope {
	struct pid *session;
	u64 epoch, last_used;
	u32 uid, users;
};
struct ba_v2_timestamp_entry {
	struct ba_v2_timestamp_scope *scope;
	struct ba_v2_timestamp_key key;
	u64 epoch, expires;
	bool active;
};
struct ba_v2_timestamp_store {
	struct mutex lock;
	u64 epoch_counter;
	struct ba_v2_timestamp_scope scopes[BA_V2_TIMESTAMP_SCOPES];
	struct ba_v2_timestamp_entry entries[BA_V2_TIMESTAMP_ENTRIES];
};

static void timestamp_number(struct sha256_state *sha, u64 n)
{
	__le64 value = cpu_to_le64(n);
	sha256_update(sha, (const u8 *)&value, sizeof(value));
}

int ba_v2_timestamp_key(const struct ba_v2_bound_request *b,
		const struct ba_v2_accounts *a, const struct ba_v2_groups *g,
		const struct ba_v2_policy *p, const struct ba_v2_trusted_file *v,
		u64 verifier_generation, struct ba_v2_timestamp_key *key)
{
	struct sha256_state sha;
	const struct cred *c;
	u32 i, secid = 0;
	if (!key) return -EINVAL;
	memset(key, 0, sizeof(*key));
	if (!b || !a || !g || !p || !v || !a->generation || !g->generation ||
	    !p->generation || !v->file || !verifier_generation || !ba_v2_bound_matches(b)) return -EINVAL;
	c = b->actor.cred;
	key->caller_uid = b->identities.caller.uid; key->caller_gid = b->identities.caller.primary_gid;
	key->target_uid = b->identities.target.uid; key->target_gid = b->identities.target_gid;
	key->encoding = le32_to_cpu(b->identities.caller_account->encoding);
	key->account_generation = a->generation; key->policy_generation = p->generation;
	key->group_generation = g->generation; key->verifier_generation = verifier_generation;
	memcpy(key->account_digest, a->input.digest, 32); memcpy(key->policy_digest, p->input.digest, 32);
	memcpy(key->group_digest, g->input.digest, 32); memcpy(key->verifier_digest, v->digest, 32);
	sha256_init(&sha);
	sha256_update(&sha, (const u8 *)"bashos-timestamp-cred-v2", 24);
	timestamp_number(&sha, from_kuid(&init_user_ns, c->uid));
	timestamp_number(&sha, from_kuid(&init_user_ns, c->euid));
	timestamp_number(&sha, from_kuid(&init_user_ns, c->suid));
	timestamp_number(&sha, from_kuid(&init_user_ns, c->fsuid));
	timestamp_number(&sha, from_kgid(&init_user_ns, c->gid));
	timestamp_number(&sha, from_kgid(&init_user_ns, c->egid));
	timestamp_number(&sha, from_kgid(&init_user_ns, c->sgid));
	timestamp_number(&sha, from_kgid(&init_user_ns, c->fsgid));
	timestamp_number(&sha, c->securebits);
	timestamp_number(&sha, c->cap_inheritable.val); timestamp_number(&sha, c->cap_permitted.val);
	timestamp_number(&sha, c->cap_effective.val); timestamp_number(&sha, c->cap_bset.val);
	timestamp_number(&sha, c->cap_ambient.val);
	security_cred_getsecid(c, &secid); timestamp_number(&sha, secid);
	timestamp_number(&sha, c->group_info->ngroups);
	for (i = 0; i < c->group_info->ngroups; i++) timestamp_number(&sha, from_kgid(&init_user_ns, c->group_info->gid[i]));
	sha256_final(&sha, key->caller_credential_digest);
	memzero_explicit(&sha, sizeof(sha));
	return 0;
}

struct ba_v2_timestamp_store *ba_v2_timestamp_create(void)
{
	struct ba_v2_timestamp_store *s = kvzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) return ERR_PTR(-ENOMEM);
	mutex_init(&s->lock);
	return s;
}

void ba_v2_timestamp_destroy(struct ba_v2_timestamp_store *s)
{
	u32 i;
	if (!s || IS_ERR(s)) return;
	/* Module ownership must quiesce every context/lease before teardown. */
	for (i = 0; i < BA_V2_TIMESTAMP_SCOPES; i++) put_pid(s->scopes[i].session);
	mutex_destroy(&s->lock);
	kvfree_sensitive(s, sizeof(*s));
}

static void timestamp_clear_scope(struct ba_v2_timestamp_store *s, struct ba_v2_timestamp_scope *scope)
{
	u32 i;
	for (i = 0; i < BA_V2_TIMESTAMP_ENTRIES; i++)
		if (s->entries[i].scope == scope) memzero_explicit(&s->entries[i], sizeof(s->entries[i]));
}

int ba_v2_timestamp_acquire(struct ba_v2_timestamp_store *s,
		const struct ba_reference_actor *actor, struct ba_v2_timestamp_lease *lease)
{
	struct ba_v2_timestamp_scope *scope = NULL, *victim = NULL;
	u32 uid, i;
	int rc = 0;
	if (!s || !actor || !lease || lease->store || !ba_reference_actor_matches(actor)) return -EINVAL;
	uid = from_kuid(&init_user_ns, actor->cred->uid);
	mutex_lock(&s->lock);
	for (i = 0; i < BA_V2_TIMESTAMP_SCOPES; i++) {
		struct ba_v2_timestamp_scope *one = &s->scopes[i];
		if (one->session == actor->session && one->uid == uid) { scope = one; break; }
		if (!one->users && (!victim || !one->session ||
		    (victim->session && one->last_used < victim->last_used))) victim = one;
	}
	if (!scope) {
		if (!victim) { rc = -EMFILE; goto done; }
		if (s->epoch_counter == U64_MAX) { rc = -EOVERFLOW; goto done; }
		scope = victim;
		timestamp_clear_scope(s, scope);
		put_pid(scope->session);
		memset(scope, 0, sizeof(*scope));
		scope->uid = uid; scope->session = get_pid(actor->session);
		scope->epoch = ++s->epoch_counter;
	}
	if (scope->users == U32_MAX) { rc = -EOVERFLOW; goto done; }
	scope->users++; scope->last_used = ktime_get_boottime_ns();
	lease->store = s; lease->scope = scope;
done:
	mutex_unlock(&s->lock);
	return rc;
}

void ba_v2_timestamp_release(struct ba_v2_timestamp_lease *lease)
{
	struct ba_v2_timestamp_store *s;
	if (!lease || !(s = lease->store) || !lease->scope) return;
	mutex_lock(&s->lock);
	if (lease->scope->users) lease->scope->users--;
	lease->scope->last_used = ktime_get_boottime_ns();
	memzero_explicit(lease, sizeof(*lease));
	mutex_unlock(&s->lock);
}

u64 ba_v2_timestamp_epoch(const struct ba_v2_timestamp_lease *lease)
{
	u64 epoch;
	if (!lease || !lease->store || !lease->scope) return 0;
	mutex_lock(&lease->store->lock);
	epoch = lease->scope->epoch;
	mutex_unlock(&lease->store->lock);
	return epoch;
}

bool ba_v2_timestamp_epoch_matches(const struct ba_v2_timestamp_lease *lease, u64 epoch)
{
	return epoch && ba_v2_timestamp_epoch(lease) == epoch;
}

int ba_v2_timestamp_reset(const struct ba_v2_timestamp_lease *lease, bool all)
{
	struct ba_v2_timestamp_store *s;
	u32 i, count = 0;
	int rc = 0;
	if (!lease || !(s = lease->store) || !lease->scope) return -EINVAL;
	mutex_lock(&s->lock);
	for (i = 0; i < BA_V2_TIMESTAMP_SCOPES; i++)
		if (s->scopes[i].session && s->scopes[i].uid == lease->scope->uid &&
		    (all || &s->scopes[i] == lease->scope)) count++;
	if (s->epoch_counter > U64_MAX - count) { rc = -EOVERFLOW; goto done; }
	for (i = 0; i < BA_V2_TIMESTAMP_SCOPES; i++) {
		struct ba_v2_timestamp_scope *scope = &s->scopes[i];
		if (!scope->session || scope->uid != lease->scope->uid || (!all && scope != lease->scope)) continue;
		timestamp_clear_scope(s, scope);
		scope->epoch = ++s->epoch_counter;
	}
done:
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_timestamp_redeem(const struct ba_v2_timestamp_lease *lease, u64 epoch, u64 deadline)
{
	struct ba_v2_timestamp_store *s;
	int rc;
	if (!lease || !(s = lease->store) || !lease->scope) return -EINVAL;
	mutex_lock(&s->lock);
	if (!epoch || lease->scope->epoch != epoch) rc = -EKEYREVOKED;
	else if (!deadline || ktime_get_boottime_ns() >= deadline) rc = -EKEYEXPIRED;
	else rc = 0;
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_timestamp_lookup(const struct ba_v2_timestamp_lease *lease, u64 epoch,
		const struct ba_v2_timestamp_key *key, u64 *deadline)
{
	struct ba_v2_timestamp_store *s;
	u64 now, maximum;
	u32 i;
	int rc = 0;
	if (!deadline) return -EINVAL;
	*deadline = 0;
	if (!lease || !(s = lease->store) || !lease->scope || !key ||
	    key->caller_uid != lease->scope->uid) return -EINVAL;
	mutex_lock(&s->lock);
	now = ktime_get_boottime_ns();
	if (check_add_overflow(now, BA_REFERENCE_MAX_LIFETIME_NS, &maximum)) { rc = -EOVERFLOW; goto done; }
	if (!epoch || lease->scope->epoch != epoch) { rc = -EKEYREVOKED; goto done; }
	for (i = 0; i < BA_V2_TIMESTAMP_ENTRIES; i++) {
		struct ba_v2_timestamp_entry *entry = &s->entries[i];
		if (entry->active && now >= entry->expires) memzero_explicit(entry, sizeof(*entry));
		if (!entry->active || entry->scope != lease->scope || entry->epoch != epoch ||
		    crypto_memneq(&entry->key, key, sizeof(*key))) continue;
		*deadline = min(maximum, entry->expires);
		rc = 1;
		break;
	}
done:
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_timestamp_verified(const struct ba_v2_timestamp_lease *lease, u64 epoch,
		const struct ba_v2_timestamp_key *key, u32 timeout,
		struct ba_v2_verified_event *event, const void *recipient,
		const struct ba_reference_claim *expected, u64 *deadline)
{
	struct ba_v2_timestamp_store *s;
	struct ba_reference_claim actual = {0};
	struct ba_v2_timestamp_entry *slot = NULL;
	u64 expires = 0, verified_deadline = 0, now;
	u32 i;
	int rc;
	if (!deadline) return -EINVAL;
	*deadline = 0;
	if (!lease || !(s = lease->store) || !lease->scope || !key || !event || !expected ||
	    !recipient || timeout > 86400 || key->caller_uid != lease->scope->uid ||
	    expected->purpose != BA_V2_PURPOSE_PRIVCMD ||
	    from_kuid(&init_user_ns, expected->uid) != key->caller_uid ||
	    from_kgid(&init_user_ns, expected->gid) != key->caller_gid) return -EINVAL;
	rc = ba_v2_event_take(event, recipient, key->account_generation, key->policy_generation,
			&actual, &verified_deadline);
	if (rc) goto done;
	if (!uid_eq(actual.uid, expected->uid) || !gid_eq(actual.gid, expected->gid) ||
	    actual.purpose != expected->purpose || strcmp(actual.user, expected->user) ||
	    crypto_memneq(actual.request_digest, expected->request_digest, 32)) { rc = -EKEYREJECTED; goto done; }
	now = ktime_get_boottime_ns();
	if (now >= verified_deadline || verified_deadline < BA_REFERENCE_MAX_LIFETIME_NS ||
	    (timeout && check_add_overflow(verified_deadline - BA_REFERENCE_MAX_LIFETIME_NS,
			(u64)timeout * NSEC_PER_SEC, &expires))) { rc = -EKEYEXPIRED; goto done; }
	mutex_lock(&s->lock);
	if (!epoch || lease->scope->epoch != epoch) { rc = -EKEYREVOKED; goto unlock; }
	now = ktime_get_boottime_ns();
	if (now >= verified_deadline) { rc = -EKEYEXPIRED; goto unlock; }
	if (timeout && expires > now) {
		for (i = 0; i < BA_V2_TIMESTAMP_ENTRIES; i++) {
			struct ba_v2_timestamp_entry *entry = &s->entries[i];
			if (entry->active && entry->scope == lease->scope && entry->epoch == epoch &&
			    !crypto_memneq(&entry->key, key, sizeof(*key))) { slot = entry; break; }
			if (!slot || !entry->active || (slot->active && entry->expires < slot->expires)) slot = entry;
		}
		memzero_explicit(slot, sizeof(*slot));
		slot->key = *key; slot->scope = lease->scope; slot->epoch = epoch; slot->expires = expires;
		slot->active = true;
	}
	*deadline = verified_deadline;
	rc = 0;
unlock:
	mutex_unlock(&s->lock);
done:
	memzero_explicit(&actual, sizeof(actual));
	return rc;
}
