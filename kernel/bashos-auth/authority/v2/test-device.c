// SPDX-License-Identifier: GPL-2.0-only
/* Native verifier integration endpoint for disposable qualification guests.
 * Deliberately absent from the production Makefile; no credential/exec grant. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "test-uapi.h"
#include "verifier-channel.h"
#include "identity-transport.h"

static bool test_only;
static char *verifier_path, *verifier_sha256, *accounts_path, *accounts_sha256;
module_param(test_only, bool, 0400);
module_param(verifier_path, charp, 0400);
module_param(verifier_sha256, charp, 0400);
module_param(accounts_path, charp, 0400);
module_param(accounts_sha256, charp, 0400);
MODULE_PARM_DESC(test_only, "Required explicit opt-in; disposable qualification guest only");
static struct ba_v2_trusted_file trusted_verifier;
static struct ba_v2_accounts trusted_accounts;
static atomic_t contexts = ATOMIC_INIT(0);

struct test_context {
	struct mutex operation;
	struct ba_ctx *secrets;
	struct ba_reference_store *references;
	struct ba_reference_actor actor;
};

static bool test_admission(void)
{
	return current_user_ns() == &init_user_ns && uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_SYS_ADMIN);
}

static void context_destroy(struct test_context *ctx)
{
	if (!ctx) return;
	ba_ctx_destroy(ctx->secrets);
	ba_reference_store_destroy(ctx->references);
	ba_reference_actor_release(&ctx->actor);
	mutex_destroy(&ctx->operation);
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int test_open(struct inode *inode, struct file *file)
{
	struct test_context *ctx;
	int rc;
	if (!test_admission()) return -EPERM;
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) != (FMODE_READ | FMODE_WRITE)) return -EACCES;
	if (atomic_inc_return(&contexts) > BA_MAX_CONTEXTS) {
		atomic_dec(&contexts); return -EMFILE;
	}
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) { rc = -ENOMEM; goto fail; }
	mutex_init(&ctx->operation);
	rc = ba_reference_actor_capture(&ctx->actor);
	if (rc) goto ctx_fail;
	ctx->secrets = ba_ctx_create();
	ctx->references = ba_reference_store_create();
	if (!ctx->secrets || !ctx->references) { rc = -ENOMEM; goto ctx_fail; }
	file->private_data = ctx;
	return stream_open(inode, file);
ctx_fail:
	context_destroy(ctx);
fail:
	atomic_dec(&contexts);
	return rc;
}

static int test_release(struct inode *inode, struct file *file)
{
	context_destroy(file->private_data);
	file->private_data = NULL;
	atomic_dec(&contexts);
	return 0;
}

static int copy_secret(void *cookie, void *data, size_t size)
{
	u64 address = *(u64 *)cookie;
	if (address != (unsigned long)address || copy_from_user(data, u64_to_user_ptr(address), size))
		return -EFAULT;
	return 0;
}

static int copy_reference_out(void *cookie, const void *data, size_t size)
{
	return copy_to_user((void __user *)cookie, data, size) ? -EFAULT : 0;
}

static ssize_t test_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
	struct test_context *ctx = file->private_data;
	if (!test_admission()) return -EPERM;
	return ba_reference_read(ctx->references, count, copy_reference_out, buffer);
}

static int verify_account(struct test_context *ctx, unsigned int command, void __user *arg)
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
	account = ba_v2_account_find(&trusted_accounts, request.user);
	/* Separate explicit legacy operation; the caller cannot reinterpret an
	 * administrator's record by selecting a different encoding. */
	if (!account || le32_to_cpu(account->encoding) != encoding) return -EACCES;
	rc = ba_v2_verify_account(&trusted_verifier, &trusted_accounts, 1,
			ctx->references, ctx->secrets, request.secret_id,
			request.user, request.purpose, request.request_digest, &event);
	if (!rc) rc = ba_reference_issue_verified(ctx->references, event, trusted_accounts.generation, 1);
	ba_v2_event_destroy(event);
	memzero_explicit(&request, sizeof(request));
	return rc;
}

static int consume_reference(struct test_context *ctx, void __user *arg)
{
	struct ba_v2_test_consume request;
	struct ba_reference_claim claim = {0};
	const struct ba_v2_account_record *account;
	int rc;
	if (copy_from_user(&request, arg, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BA_V2_VERSION || request.reserved ||
	    !memchr(request.user, 0, sizeof(request.user))) { rc = -EINVAL; goto done; }
	account = ba_v2_account_find(&trusted_accounts, request.user);
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

static long test_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	struct test_context *ctx = file->private_data;
	void __user *arg = (void __user *)argument;
	long rc = -ENOTTY;
	if (!test_admission()) return -EPERM;
	/* A delegated SSH child gets only read/consume. Original owner retains
	 * revocation; secret input and verifier creation never transfer. */
	if (command != BA_V2_TEST_CONSUME && command != BASHOS_AUTH_V2_CONSUME &&
	    command != BASHOS_AUTH_V2_INFO && !ba_reference_actor_matches(&ctx->actor)) return -EPERM;
	mutex_lock(&ctx->operation);
	if (command == BASHOS_AUTH_V2_INFO) {
		struct bashos_auth_v2_info info = {
			.size = sizeof(info), .version = BASHOS_AUTH_V2_VERSION,
			.flags = BASHOS_AUTH_V2_QUALIFICATION_ONLY,
			.account_generation = trusted_accounts.generation, .policy_generation = 1,
		};
		rc = copy_to_user(arg, &info, sizeof(info)) ? -EFAULT : 0;
	} else if (command == BASHOS_AUTH_V2_VERIFY || command == BASHOS_AUTH_V2_VERIFY_LEGACY_HEX) {
		rc = ba_v2_identity_verify(&trusted_verifier, &trusted_accounts, 1, ctx->secrets,
			ctx->references, command == BASHOS_AUTH_V2_VERIFY_LEGACY_HEX, arg);
	} else if (command == BASHOS_AUTH_V2_CONSUME) {
		rc = ba_v2_identity_consume(ctx->references, arg);
	} else if (command == BA_V2_TEST_VERSION) {
		struct ba_v2_test_version version = {
			.size = sizeof(version), .version = BA_V2_VERSION, .production_features = 0,
		};
		rc = copy_to_user(arg, &version, sizeof(version)) ? -EFAULT : 0;
	} else if (command == BA_V2_TEST_VERIFY || command == BA_V2_TEST_VERIFY_LEGACY) {
		rc = verify_account(ctx, command, arg);
	} else if (command == BA_V2_TEST_CONSUME) {
		rc = consume_reference(ctx, arg);
	} else if (command == BA_V2_TEST_RESET || command == BASHOS_AUTH_V2_RESET) {
		ba_reference_revoke(ctx->references); rc = 0;
	} else if (command == BA_V2_TEST_DELEGATE_SSH || command == BASHOS_AUTH_V2_DELEGATE_SSH) {
		struct ba_v2_test_delegate request;
		if (copy_from_user(&request, arg, sizeof(request))) rc = -EFAULT;
		else if (request.size != sizeof(request) || request.version != BA_V2_VERSION ||
			 request.reserved || !request.child_pid || request.child_pid > INT_MAX) rc = -EINVAL;
		else rc = ba_reference_delegate_ssh_child(ctx->references, request.child_pid);
	} else {
		/* Only the minimum sealed-secret input subset is accepted on this
		 * new endpoint. Old MINT/CONSUME/EXPORT/PRIVCMD remain unavailable. */
		mutex_lock(&ctx->secrets->lock);
		if (command == BASHOS_AUTH_IOC_NEW_SECRET) {
			struct bashos_auth_handle handle;
			if (copy_from_user(&handle, arg, sizeof(handle))) rc = -EFAULT;
			else if (handle.id || handle.flags) rc = -EINVAL;
			else {
				rc = ba_new(ctx->secrets, &handle.id);
				if (!rc && copy_to_user(arg, &handle, sizeof(handle))) {
					ba_clear(ctx->secrets, handle.id); rc = -EFAULT;
				}
			}
		} else if (command == BASHOS_AUTH_IOC_WRITE_SECRET) {
			struct bashos_auth_secret_write write;
			if (copy_from_user(&write, arg, sizeof(write))) rc = -EFAULT;
			else rc = ba_append(ctx->secrets, write.id, write.len, copy_secret, &write.user_ptr);
		} else if (command == BASHOS_AUTH_IOC_SEAL_SECRET || command == BASHOS_AUTH_IOC_CLEAR_SECRET) {
			struct bashos_auth_handle handle;
			if (copy_from_user(&handle, arg, sizeof(handle))) rc = -EFAULT;
			else if (handle.flags) rc = -EINVAL;
			else rc = command == BASHOS_AUTH_IOC_SEAL_SECRET ?
				ba_seal(ctx->secrets, handle.id) : ba_clear(ctx->secrets, handle.id);
		}
		mutex_unlock(&ctx->secrets->lock);
	}
	mutex_unlock(&ctx->operation);
	return rc;
}

static const struct file_operations test_operations = {
	.owner = THIS_MODULE, .open = test_open, .release = test_release,
	.read = test_read, .unlocked_ioctl = test_ioctl,
};
static struct miscdevice test_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "bashos-auth-v2-test", .mode = 0600,
	.fops = &test_operations,
};

static int __init test_init(void)
{
	u8 verifier_pin[32], accounts_pin[32];
	int rc;
	if (!test_only || !test_admission() || !verifier_sha256 || !accounts_sha256 ||
	    strlen(verifier_sha256) != 64 || strlen(accounts_sha256) != 64 ||
	    hex2bin(verifier_pin, verifier_sha256, sizeof(verifier_pin)) ||
	    hex2bin(accounts_pin, accounts_sha256, sizeof(accounts_pin))) return -EINVAL;
	rc = ba_v2_trusted_open(verifier_path, verifier_pin, 8U << 20, true, &trusted_verifier);
	if (rc) return rc;
	rc = ba_v2_accounts_open(accounts_path, accounts_pin, &trusted_accounts);
	if (rc) goto verifier_fail;
	rc = misc_register(&test_device);
	if (!rc) return 0;
	ba_v2_accounts_close(&trusted_accounts);
verifier_fail:
	ba_v2_trusted_close(&trusted_verifier);
	return rc;
}

static void __exit test_exit(void)
{
	misc_deregister(&test_device);
	ba_v2_accounts_close(&trusted_accounts);
	ba_v2_trusted_close(&trusted_verifier);
}
module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable native-verifier protocol v2 qualification endpoint; production features off");
