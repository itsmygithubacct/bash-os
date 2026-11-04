/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_VERIFIER_CHANNEL_H
#define BA_V2_VERIFIER_CHANNEL_H
#include "trusted-input.h"
#include "../reference.h"
#include "../../secrets.h"

struct ba_v2_verified_event;
/* A recipient is a live adapter-owned open-file context, never a user pointer.
 * The secret is exported/erased once from its sealed kernel slot. A successful
 * result requires the pinned native verifier, complete private-channel reply,
 * normal helper termination and unchanged requesting actor. */
int ba_v2_verify_account(const struct ba_v2_trusted_file *verifier,
		const struct ba_v2_accounts *accounts, u64 policy_generation,
		const void *recipient, struct ba_ctx *secrets, u32 secret_id,
		const char *target, u32 purpose, const u8 request_digest[32],
		struct ba_v2_verified_event **out);
/* Internal one-shot redemption. No ioctl can manufacture an event. */
int ba_v2_event_take(struct ba_v2_verified_event *event, const void *recipient,
		u64 account_generation, u64 policy_generation,
		struct ba_reference_claim *claim, u64 *deadline);
void ba_v2_event_destroy(struct ba_v2_verified_event *event);
#endif
