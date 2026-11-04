/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_POLICY_SNAPSHOT_H
#define BA_V2_POLICY_SNAPSHOT_H
#include "trusted-input.h"
#include "../../../../loadables/common/auth-policy-types.h"

struct ba_v2_policy {
	struct ba_v2_trusted_file input;
	struct ba_policy_document *document;
	u64 generation;
	u8 normalized_digest[32];
	unsigned int error_line;
};
/* No public client chooses this path, pin or generation. The administrator
 * configures the immutable policy at authority initialization. No default allow. */
int ba_v2_policy_open(const char *path, const u8 pin[32], u64 generation,
		struct ba_v2_policy *policy);
void ba_v2_policy_close(struct ba_v2_policy *policy);
int ba_v2_policy_evaluate(const struct ba_v2_policy *policy,
		const struct ba_policy_query *query, struct ba_policy_decision *decision);
bool ba_v2_policy_environment_name_safe(const char *name);
#endif
