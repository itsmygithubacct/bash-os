// SPDX-License-Identifier: GPL-2.0-only
/* Identity protocol v2 device: native-verifier proof and same-fd reference.
 * It grants no credential and runs no command. Linked unchanged into the
 * production module and into the qualification module. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/hex.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "identity-device.h"

/* The identity protocol has no policy input; its references carry this fixed
 * policy generation so that a later protocol revision can change it. */
#define IDENTITY_POLICY_GENERATION 1ULL
#define IDENTITY_VERIFIER_LIMIT (8U << 20)

static char *verifier_path, *verifier_sha256, *accounts_path, *accounts_sha256;
module_param(verifier_path, charp, 0400);
module_param(verifier_sha256, charp, 0400);
module_param(accounts_path, charp, 0400);
module_param(accounts_sha256, charp, 0400);
MODULE_PARM_DESC(verifier_path, "Absolute path of the pinned static native verifier");
MODULE_PARM_DESC(verifier_sha256, "SHA-256 of the verifier, 64 hex digits");
MODULE_PARM_DESC(accounts_path, "Absolute path of the pinned account snapshot");
MODULE_PARM_DESC(accounts_sha256, "SHA-256 of the account snapshot, 64 hex digits");

static const struct ba_v2_identity_variant *variant;
static struct ba_v2_identity_bundle bundle;
static atomic_t contexts = ATOMIC_INIT(0);

bool ba_v2_identity_admission(void)
{
	return current_user_ns() == &init_user_ns && uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_SYS_ADMIN);
}

static void context_destroy(struct ba_v2_identity_context *ctx)
{
	if (!ctx) return;
	ba_ctx_destroy(ctx->secrets);
	ba_reference_store_destroy(ctx->references);
	ba_reference_actor_release(&ctx->actor);
	mutex_destroy(&ctx->operation);
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int identity_open(struct inode *inode, struct file *file)
{
	struct ba_v2_identity_context *ctx;
	int rc;
	if (!ba_v2_identity_admission()) return -EPERM;
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

static int identity_release(struct inode *inode, struct file *file)
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

static ssize_t identity_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
	struct ba_v2_identity_context *ctx = file->private_data;
	if (!ba_v2_identity_admission()) return -EPERM;
	return ba_reference_read(ctx->references, count, copy_reference_out, buffer);
}

static long identity_info(void __user *arg)
{
	struct bashos_auth_v2_info info = {
		.size = sizeof(info), .version = BASHOS_AUTH_V2_VERSION,
		.flags = variant->info_flags,
		.account_generation = bundle.accounts.generation,
		.policy_generation = IDENTITY_POLICY_GENERATION,
	};
	return copy_to_user(arg, &info, sizeof(info)) ? -EFAULT : 0;
}

static long identity_delegate(struct ba_v2_identity_context *ctx, void __user *arg)
{
	struct bashos_auth_v2_delegate request;
	if (copy_from_user(&request, arg, sizeof(request))) return -EFAULT;
	if (request.size != sizeof(request) || request.version != BASHOS_AUTH_V2_VERSION ||
	    request.reserved || !request.child_pid || request.child_pid > INT_MAX) return -EINVAL;
	return ba_reference_delegate_ssh_child(ctx->references, request.child_pid);
}

/* Only the minimum sealed-secret input subset is accepted on this endpoint.
 * The stage-1 EXPORT, SAME and STATS operations and every legacy token,
 * PRIVCMD, policy and audit operation remain unavailable here. */
static long identity_secret_ioctl(struct ba_v2_identity_context *ctx, unsigned int command,
		void __user *arg)
{
	long rc = -ENOTTY;
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
	return rc;
}

/* A delegated SSH child gets only read and consume. The original owner keeps
 * revocation; secret input and verifier creation never transfer. */
static bool identity_delegated_command(unsigned int command)
{
	return command == BASHOS_AUTH_V2_CONSUME || command == BASHOS_AUTH_V2_INFO ||
		(variant->delegated_command && variant->delegated_command(command));
}

static long identity_dispatch(struct ba_v2_identity_context *ctx, unsigned int command,
		void __user *arg)
{
	long rc;
	switch (command) {
	case BASHOS_AUTH_V2_INFO:
		return identity_info(arg);
	case BASHOS_AUTH_V2_VERIFY:
	case BASHOS_AUTH_V2_VERIFY_LEGACY_HEX:
		return ba_v2_identity_verify(&bundle.verifier, &bundle.accounts,
			IDENTITY_POLICY_GENERATION, ctx->secrets, ctx->references,
			command == BASHOS_AUTH_V2_VERIFY_LEGACY_HEX, arg);
	case BASHOS_AUTH_V2_CONSUME:
		return ba_v2_identity_consume(ctx->references, arg);
	case BASHOS_AUTH_V2_RESET:
		ba_reference_revoke(ctx->references);
		return 0;
	case BASHOS_AUTH_V2_DELEGATE_SSH:
		return identity_delegate(ctx, arg);
	}
	if (variant->extra_ioctl && variant->extra_ioctl(ctx, &bundle, command, arg, &rc))
		return rc;
	return identity_secret_ioctl(ctx, command, arg);
}

static long identity_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	struct ba_v2_identity_context *ctx = file->private_data;
	long rc;
	if (!ba_v2_identity_admission()) return -EPERM;
	if (!identity_delegated_command(command) && !ba_reference_actor_matches(&ctx->actor))
		return -EPERM;
	mutex_lock(&ctx->operation);
	rc = identity_dispatch(ctx, command, (void __user *)argument);
	mutex_unlock(&ctx->operation);
	return rc;
}

static const struct file_operations identity_operations = {
	.owner = THIS_MODULE, .open = identity_open, .release = identity_release,
	.read = identity_read, .unlocked_ioctl = identity_ioctl,
};
static struct miscdevice identity_device = {
	.minor = MISC_DYNAMIC_MINOR, .mode = 0600, .fops = &identity_operations,
};

static int parse_pin(const char *text, u8 pin[32])
{
	return text && strlen(text) == 64 && !hex2bin(pin, text, 32) ? 0 : -EINVAL;
}

int ba_v2_identity_device_register(const struct ba_v2_identity_variant *selected)
{
	u8 verifier_pin[32], accounts_pin[32];
	int rc;
	if (!selected || !selected->node || !ba_v2_identity_admission() ||
	    parse_pin(verifier_sha256, verifier_pin) || parse_pin(accounts_sha256, accounts_pin))
		return -EINVAL;
	rc = ba_v2_trusted_open(verifier_path, verifier_pin, IDENTITY_VERIFIER_LIMIT, true,
			&bundle.verifier);
	if (rc) return rc;
	rc = ba_v2_accounts_open(accounts_path, accounts_pin, &bundle.accounts);
	if (rc) goto verifier_fail;
	variant = selected;
	identity_device.name = selected->node;
	rc = misc_register(&identity_device);
	if (!rc) return 0;
	ba_v2_accounts_close(&bundle.accounts);
verifier_fail:
	ba_v2_trusted_close(&bundle.verifier);
	return rc;
}

void ba_v2_identity_device_unregister(void)
{
	misc_deregister(&identity_device);
	ba_v2_accounts_close(&bundle.accounts);
	ba_v2_trusted_close(&bundle.verifier);
}
