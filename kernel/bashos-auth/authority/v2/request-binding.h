/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_REQUEST_BINDING_H
#define BA_V2_REQUEST_BINDING_H
#include "identity-snapshot.h"
#include "program-snapshot.h"
#include "../reference.h"

struct tty_struct;
struct ba_v2_bound_request {
	struct ba_reference_actor actor;
	struct ba_request_snapshot *request;
	struct ba_v2_identity_binding identities;
	struct ba_v2_trusted_file program;
	struct file *cwd, *root, *stdio[3];
	struct tty_struct *tty;
	const char *argv[BA_REQUEST_MAX_ITEMS], *env[BA_REQUEST_MAX_ITEMS];
	char hostname[65];
	struct ba_policy_query query;
	struct ba_policy_decision decision;
};

/* Takes ownership of request on every path. admin is a retained authority
 * initialization credential, never selected by an ioctl; temporary subjective
 * override is used only for bounded readonly object capture and is reverted
 * before returning. No caller credential is committed and no grant is issued. */
int ba_v2_bound_capture(struct ba_request_snapshot *request,
		const struct ba_v2_accounts *accounts, const struct ba_v2_groups *groups,
		const struct ba_v2_policy *policy, const struct cred *admin,
		struct ba_v2_bound_request **out);
bool ba_v2_bound_matches(const struct ba_v2_bound_request *bound);
void ba_v2_bound_free(struct ba_v2_bound_request *bound);
#endif
