/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_IDENTITY_TRANSPORT_H
#define BA_V2_IDENTITY_TRANSPORT_H
#include "verifier-channel.h"
#include "../../uapi/linux/bashos_auth_v2.h"
int ba_v2_identity_verify(const struct ba_v2_trusted_file *verifier,
		const struct ba_v2_accounts *accounts, u64 policy_generation,
		struct ba_ctx *secrets, struct ba_reference_store *references,
		bool legacy_hex, const void __user *argument);
int ba_v2_identity_consume(struct ba_reference_store *references, const void __user *argument);
#endif
