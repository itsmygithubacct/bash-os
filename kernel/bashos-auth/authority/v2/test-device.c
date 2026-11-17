// SPDX-License-Identifier: GPL-2.0-only
/* Qualification wrapper of the identity protocol v2 device, for disposable
 * guests only: a separately named node, an explicit load-time opt-in and the
 * 0xbb control operations. None of this file is linked into production. */
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "test-uapi.h"
#include "identity-device.h"

static bool test_only;
module_param(test_only, bool, 0400);
MODULE_PARM_DESC(test_only, "Required explicit opt-in; disposable qualification guest only");

static int verify_account(struct ba_v2_identity_context *ctx,
		const struct ba_v2_identity_bundle *bundle, unsigned int command, void __user *arg)
{
	struct ba_v2_test_verify request;
	struct ba_v2_verified_event *event = NULL;
	const struct ba_v2_account_record *account;
	u32 encoding = command == BA_V2_TEST_VERIFY ? BA_V2_ENCODING_STANDARD : BA_V2_ENCODING_LEGACY_HEX;
	int rc;
	if (copy_from_user(&request, arg, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BA_V2_VERSION ||
	    memchr_inv(request.reserved, 0, sizeof(request.reserved)) ||
	    !memchr(request.user, 0, sizeof(request.user))) return -EINVAL;
	account = ba_v2_account_find(&bundle->accounts, request.user);
	/* Separate explicit legacy operation; the caller cannot reinterpret an
	 * administrator's record by selecting a different encoding. */
	if (!account || le32_to_cpu(account->encoding) != encoding) return -EACCES;
	rc = ba_v2_verify_account(&bundle->verifier, &bundle->accounts, 1,
			ctx->references, ctx->secrets, request.secret_id,
			request.user, request.purpose, request.request_digest, &event);
	if (!rc) rc = ba_reference_issue_verified(ctx->references, event, bundle->accounts.generation, 1);
	ba_v2_event_destroy(event);
	memzero_explicit(&request, sizeof(request));
	return rc;
}

static int consume_reference(struct ba_v2_identity_context *ctx,
		const struct ba_v2_identity_bundle *bundle, void __user *arg)
{
	struct ba_v2_test_consume request;
	struct ba_reference_claim claim = {0};
	const struct ba_v2_account_record *account;
	int rc;
	if (copy_from_user(&request, arg, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BA_V2_VERSION || request.reserved ||
	    !memchr(request.user, 0, sizeof(request.user))) { rc = -EINVAL; goto done; }
	account = ba_v2_account_find(&bundle->accounts, request.user);
	/* Unknown targets must still reach known-reference revocation. Never
	 * invent a uid/gid for them, including the all-zero root identity. */
	claim.uid = account ? make_kuid(&init_user_ns, le32_to_cpu(account->uid)) : INVALID_UID;
	claim.gid = account ? make_kgid(&init_user_ns, le32_to_cpu(account->gid)) : INVALID_GID;
	claim.purpose = request.purpose;
	memcpy(claim.user, request.user, sizeof(claim.user));
	memcpy(claim.request_digest, request.request_digest, sizeof(claim.request_digest));
	rc = ba_reference_consume(ctx->references, request.reference, &claim);
done:
	memzero_explicit(&request, sizeof(request));
	memzero_explicit(&claim, sizeof(claim));
	return rc;
}

static long delegate_child(struct ba_v2_identity_context *ctx, void __user *arg)
{
	struct ba_v2_test_delegate request;
	if (copy_from_user(&request, arg, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BA_V2_VERSION ||
	    request.reserved || !request.child_pid || request.child_pid > INT_MAX) return -EINVAL;
	return ba_reference_delegate_ssh_child(ctx->references, request.child_pid);
}

static bool test_ioctl(struct ba_v2_identity_context *ctx,
		const struct ba_v2_identity_bundle *bundle, unsigned int command,
		void __user *arg, long *result)
{
	switch (command) {
	case BA_V2_TEST_VERSION: {
		struct ba_v2_test_version version = {
			.size = sizeof(version), .version = BA_V2_VERSION, .production_features = 0,
		};
		*result = copy_to_user(arg, &version, sizeof(version)) ? -EFAULT : 0;
		return true;
	}
	case BA_V2_TEST_VERIFY:
	case BA_V2_TEST_VERIFY_LEGACY:
		*result = verify_account(ctx, bundle, command, arg);
		return true;
	case BA_V2_TEST_CONSUME:
		*result = consume_reference(ctx, bundle, arg);
		return true;
	case BA_V2_TEST_RESET:
		ba_reference_revoke(ctx->references);
		*result = 0;
		return true;
	case BA_V2_TEST_DELEGATE_SSH:
		*result = delegate_child(ctx, arg);
		return true;
	}
	return false;
}

static bool test_delegated_command(unsigned int command)
{
	return command == BA_V2_TEST_CONSUME;
}

static const struct ba_v2_identity_variant qualification = {
	.node = "bashos-auth-v2-test",
	.info_flags = BASHOS_AUTH_V2_QUALIFICATION_ONLY,
	.extra_ioctl = test_ioctl,
	.delegated_command = test_delegated_command,
};

static int __init test_init(void)
{
	if (!test_only) return -EINVAL;
	return ba_v2_identity_device_register(&qualification);
}

static void __exit test_exit(void)
{
	ba_v2_identity_device_unregister();
}
module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable native-verifier protocol v2 qualification endpoint; production features off");
