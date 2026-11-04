/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_TIMESTAMP_STORE_H
#define BA_V2_TIMESTAMP_STORE_H
#include "request-binding.h"
#include "verifier-channel.h"

#define BA_V2_TIMESTAMP_SCOPES 128U
#define BA_V2_TIMESTAMP_ENTRIES 256U
struct ba_v2_timestamp_store;
struct ba_v2_timestamp_scope;
struct ba_v2_timestamp_lease {
	struct ba_v2_timestamp_store *store;
	struct ba_v2_timestamp_scope *scope;
};
struct ba_v2_timestamp_key {
	u32 caller_uid, caller_gid, target_uid, target_gid, encoding;
	u64 account_generation, policy_generation, group_generation, verifier_generation;
	u8 caller_credential_digest[32], account_digest[32], policy_digest[32],
		group_digest[32], verifier_digest[32];
};

struct ba_v2_timestamp_store *ba_v2_timestamp_create(void);
void ba_v2_timestamp_destroy(struct ba_v2_timestamp_store *store);
int ba_v2_timestamp_key(const struct ba_v2_bound_request *bound,
		const struct ba_v2_accounts *accounts, const struct ba_v2_groups *groups,
		const struct ba_v2_policy *policy, const struct ba_v2_trusted_file *verifier,
		u64 verifier_generation, struct ba_v2_timestamp_key *key);
int ba_v2_timestamp_acquire(struct ba_v2_timestamp_store *store,
		const struct ba_reference_actor *actor, struct ba_v2_timestamp_lease *lease);
void ba_v2_timestamp_release(struct ba_v2_timestamp_lease *lease);
u64 ba_v2_timestamp_epoch(const struct ba_v2_timestamp_lease *lease);
bool ba_v2_timestamp_epoch_matches(const struct ba_v2_timestamp_lease *lease, u64 epoch);
/* The caller irreversibly consumes its fd-bound grant before this call. This
 * is the reset/redemption ordering point under the same lock as reset. A later
 * reset cannot retroactively cancel an already redeemed operation. */
int ba_v2_timestamp_redeem(const struct ba_v2_timestamp_lease *lease, u64 epoch, u64 deadline);
/* scope reset removes every target/method in this caller's session; reset_all
 * removes this caller's scopes in every session. Other caller uids are intact.
 * Each live scope epoch advances, invalidating pending grants as well as cache. */
int ba_v2_timestamp_reset(const struct ba_v2_timestamp_lease *lease, bool reset_all);
int ba_v2_timestamp_lookup(const struct ba_v2_timestamp_lease *lease, u64 epoch,
		const struct ba_v2_timestamp_key *key, u64 *grant_deadline);
/* The only insertion API consumes a real opaque native-verifier event. No
 * bool, child exit status, uid, root process or public ioctl can seed a cache.
 * timeout zero verifies without caching. Deadline never extends the event. */
int ba_v2_timestamp_verified(const struct ba_v2_timestamp_lease *lease, u64 epoch,
		const struct ba_v2_timestamp_key *key, u32 timeout_seconds,
		struct ba_v2_verified_event *event, const void *recipient,
		const struct ba_reference_claim *expected, u64 *grant_deadline);
#endif
