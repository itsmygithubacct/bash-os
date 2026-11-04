/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_IDENTITY_SNAPSHOT_H
#define BA_V2_IDENTITY_SNAPSHOT_H
#include <linux/cred.h>
#include "trusted-input.h"
#include "policy-snapshot.h"
#include "../request.h"

#define BA_V2_MAX_GROUPS 128U
struct ba_v2_group {
	u32 gid, count;
	char name[BA_V2_USER_BYTES];
	u32 members[BA_V2_MAX_ACCOUNTS];
};
struct ba_v2_groups {
	struct ba_v2_trusted_file input;
	u64 generation;
	u32 count;
	struct ba_v2_group records[BA_V2_MAX_GROUPS];
};
struct ba_v2_identity_binding {
	const struct ba_v2_account_record *caller_account, *target_account;
	struct ba_policy_subject caller, target;
	struct ba_policy_group caller_groups[BA_V2_MAX_GROUPS];
	struct ba_policy_group target_groups[BA_V2_MAX_GROUPS];
	u32 exec_gids[BA_V2_MAX_GROUPS], exec_group_count, target_gid;
	const char *target_group;
};
struct ba_v2_profile {
	char user[BA_V2_USER_BYTES], home[256], shell[256];
};
struct ba_v2_profiles {
	struct ba_v2_trusted_file input;
	u64 generation;
	u32 count;
	struct ba_v2_profile records[BA_V2_MAX_ACCOUNTS];
};

/* Additive, administrator-pinned snapshot using the explicit traditional group
 * fields name:password-placeholder:gid:members. It never rewrites /etc/group.
 * Unknown members/primary gids, duplicate names/gids or ambiguous account uids
 * reject the entire snapshot. The password placeholder is never authentication. */
int ba_v2_groups_open(const char *path, const u8 pin[32], u64 generation,
		const struct ba_v2_accounts *accounts, struct ba_v2_groups *groups);
void ba_v2_groups_close(struct ba_v2_groups *groups);
int ba_v2_identity_bind(const struct ba_v2_accounts *accounts,
		const struct ba_v2_groups *groups, const struct cred *actor,
		const struct bashos_auth_privcmd *request, struct ba_v2_identity_binding *out);
/* Dedicated pinned profile file uses the seven traditional passwd fields.
 * Name/uid/gid must exactly agree with the explicit authentication snapshot;
 * password and gecos fields never authenticate or choose an execution target. */
int ba_v2_profiles_open(const char *path, const u8 pin[32], u64 generation,
		const struct ba_v2_accounts *accounts, struct ba_v2_profiles *profiles);
void ba_v2_profiles_close(struct ba_v2_profiles *profiles);
const struct ba_v2_profile *ba_v2_profile_find(const struct ba_v2_profiles *profiles,
		const char *user);
#endif
