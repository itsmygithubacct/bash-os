// SPDX-License-Identifier: GPL-2.0-only
/* Client identity requests choose no verifier or PHC and carry no claimed
 * verification result. Expected uid/gid must agree with the trusted record. */
#include <crypto/sha2.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "identity-transport.h"

static bool identity_valid(const struct bashos_auth_v2_identity *who)
{
	const char *end = memchr(who->user, 0, sizeof(who->user));
	return end && end != who->user &&
		!memchr_inv(end, 0, sizeof(who->user) - (end - who->user)) &&
		(who->encoding == BASHOS_AUTH_V2_STANDARD_PHC || who->encoding == BASHOS_AUTH_V2_LEGACY_HEX) &&
		(who->purpose == BASHOS_AUTH_V2_LOGIN || who->purpose == BASHOS_AUTH_V2_SU || who->purpose == BASHOS_AUTH_V2_SSH);
}

static void identity_digest(const struct bashos_auth_v2_identity *who, u8 digest[32])
{
	static const char domain[] = "bashos-identity-v2";
	struct sha256_state state;
	__le32 fields[] = {
		cpu_to_le32(who->purpose), cpu_to_le32(who->uid), cpu_to_le32(who->gid),
		cpu_to_le32(who->encoding), cpu_to_le32(strlen(who->user)),
	};
	sha256_init(&state);
	sha256_update(&state, (const u8 *)domain, sizeof(domain) - 1);
	sha256_update(&state, (const u8 *)fields, sizeof(fields));
	sha256_update(&state, (const u8 *)who->user, strlen(who->user));
	sha256_final(&state, digest);
	memzero_explicit(&state, sizeof(state));
}

int ba_v2_identity_verify(const struct ba_v2_trusted_file *verifier,
		const struct ba_v2_accounts *accounts, u64 policy_generation,
		struct ba_ctx *secrets, struct ba_reference_store *references,
		bool legacy_hex, const void __user *argument)
{
	struct bashos_auth_v2_verify request = {0};
	struct ba_v2_verified_event *event = NULL;
	const struct ba_v2_account_record *account;
	u8 digest[32] = {0};
	u32 encoding = legacy_hex ? BASHOS_AUTH_V2_LEGACY_HEX : BASHOS_AUTH_V2_STANDARD_PHC;
	int rc = -EINVAL;
	/* This versioned operation starts a new attempt. A failed replacement
	 * cannot leave an earlier successful proof available to its caller. The
	 * transport has already required the original actor and serialized writes. */
	ba_reference_revoke(references);
	if (copy_from_user(&request, argument, sizeof(request))) { rc = -EFAULT; goto done; }
	if (request.size != sizeof(request) || request.version != BASHOS_AUTH_V2_VERSION ||
	    request.reserved || !request.secret_id || !identity_valid(&request.identity) ||
	    request.identity.encoding != encoding) goto done;
	account = ba_v2_account_find(accounts, request.identity.user);
	if (!account || le32_to_cpu(account->uid) != request.identity.uid ||
	    le32_to_cpu(account->gid) != request.identity.gid || le32_to_cpu(account->encoding) != encoding) {
		rc = -EACCES; goto done;
	}
	identity_digest(&request.identity, digest);
	rc = ba_v2_verify_account(verifier, accounts, policy_generation, references, secrets,
		request.secret_id, request.identity.user, request.identity.purpose, digest, &event);
	if (!rc) rc = ba_reference_issue_verified(references, event, accounts->generation, policy_generation);
done:
	ba_v2_event_destroy(event);
	memzero_explicit(digest, sizeof(digest));
	memzero_explicit(&request, sizeof(request));
	return rc;
}

int ba_v2_identity_consume(struct ba_reference_store *references, const void __user *argument)
{
	struct bashos_auth_v2_consume request = {0};
	struct ba_reference_claim claim = {0};
	int rc = -EINVAL;
	if (copy_from_user(&request, argument, sizeof(request))) {
		/* An unrelated recipient of this fd gains no revocation authority.
		 * The transport's operation mutex serializes explicit delegation. */
		(void)ba_reference_revoke_current(references);
		rc = -EFAULT; goto done;
	}
	if (request.size != sizeof(request) || request.version != BASHOS_AUTH_V2_VERSION ||
	    request.reserved[0] || request.reserved[1]) {
		/* Spend a known value even when its envelope is malformed. Random
		 * unknown values still cannot identify a different live proof. */
		(void)ba_reference_consume(references, request.reference, &claim);
		goto done;
	}
	/* These are expected redemption fields, not minting authority. The store
	 * compares them to the native verified claim and spends a known reference
	 * on any mismatch. A uid-0 tuple by itself cannot create a claim. */
	claim.uid = make_kuid(&init_user_ns, request.identity.uid);
	claim.gid = make_kgid(&init_user_ns, request.identity.gid);
	claim.purpose = request.identity.purpose;
	memcpy(claim.user, request.identity.user, sizeof(claim.user));
	if (identity_valid(&request.identity)) identity_digest(&request.identity, claim.request_digest);
	else claim.purpose = 0; /* A known reference with invalid expected fields is terminal too. */
	rc = ba_reference_consume(references, request.reference, &claim);
done:
	memzero_explicit(&claim, sizeof(claim));
	memzero_explicit(&request, sizeof(request));
	return rc;
}
