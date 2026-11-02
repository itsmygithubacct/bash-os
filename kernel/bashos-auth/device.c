/* SPDX-License-Identifier: GPL-2.0-only */
/* Stage 1: real secret slots only. No authentication/authorization decisions. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "secrets.h"

static atomic_t ba_contexts = ATOMIC_INIT(0);

/* Conservative stage-1 access rule, explicitly not recovered historical policy.
 * Recheck on every ioctl, so handing off an fd cannot bypass the access rule.
 * .release always erases, even after the process has dropped credentials.
 */
static bool ba_access_ok(void)
{
	return uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_SYS_ADMIN);
}

static int ba_open(struct inode *inode, struct file *file)
{
	struct ba_ctx *ctx;

	if (!ba_access_ok())
		return -EPERM;
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) !=
	    (FMODE_READ | FMODE_WRITE))
		return -EACCES;
	if (atomic_inc_return(&ba_contexts) > BA_MAX_CONTEXTS) {
		atomic_dec(&ba_contexts);
		return -EMFILE;
	}
	ctx = ba_ctx_create();
	if (!ctx) {
		atomic_dec(&ba_contexts);
		return -ENOMEM;
	}
	file->private_data = ctx;
	return stream_open(inode, file);
}

static int ba_release(struct inode *inode, struct file *file)
{
	ba_ctx_destroy(file->private_data);
	file->private_data = NULL;
	atomic_dec(&ba_contexts);
	return 0;
}

struct ba_user_copy { u64 address; };

static bool ba_pointer_fits(u64 address)
{
	return (u64)(unsigned long)address == address &&
		(!in_compat_syscall() || !(address >> 32));
}

static int ba_copy_in(void *cookie, void *dst, size_t len)
{
	struct ba_user_copy *copy = cookie;

	if (!ba_pointer_fits(copy->address) ||
	    copy_from_user(dst, u64_to_user_ptr(copy->address), len))
		return -EFAULT;
	return 0;
}

static int ba_copy_out(void *cookie, const void *src, size_t len)
{
	struct ba_user_copy *copy = cookie;

	if (!ba_pointer_fits(copy->address) ||
	    copy_to_user(u64_to_user_ptr(copy->address), src, len))
		return -EFAULT;
	return 0;
}

static long ba_ioctl_locked(struct ba_ctx *ctx, unsigned int cmd,
			    void __user *arg)
{
	int ret;

	lockdep_assert_held(&ctx->lock);
	/* Exact command match includes direction and size, not merely _IOC_NR. */
	switch (cmd) {
	case BASHOS_AUTH_IOC_VERSION: {
		struct bashos_auth_version version = {
			.abi_major = 1, .abi_minor = 0,
			.features = BASHOS_AUTH_FEAT_SECRETS | BASHOS_AUTH_FEAT_STATS,
		};

		return copy_to_user(arg, &version, sizeof(version)) ? -EFAULT : 0;
	}
	case BASHOS_AUTH_IOC_NEW_SECRET: {
		struct bashos_auth_handle h;

		if (copy_from_user(&h, arg, sizeof(h)))
			return -EFAULT;
		if (h.id || h.flags)
			return -EINVAL;
		ret = ba_new(ctx, &h.id);
		if (ret)
			return ret;
		if (copy_to_user(arg, &h, sizeof(h))) {
			/* Failed publication must not leave an unreachable live slot. */
			ba_clear(ctx, h.id);
			return -EFAULT;
		}
		return 0;
	}
	case BASHOS_AUTH_IOC_WRITE_SECRET: {
		struct bashos_auth_secret_write w;
		struct ba_user_copy copy;

		if (copy_from_user(&w, arg, sizeof(w)))
			return -EFAULT;
		copy.address = w.user_ptr;
		return ba_append(ctx, w.id, w.len, ba_copy_in, &copy);
	}
	case BASHOS_AUTH_IOC_SEAL_SECRET:
	case BASHOS_AUTH_IOC_CLEAR_SECRET: {
		struct bashos_auth_handle h;

		if (copy_from_user(&h, arg, sizeof(h)))
			return -EFAULT;
		if (h.flags)
			return -EINVAL;
		return cmd == BASHOS_AUTH_IOC_SEAL_SECRET ?
			ba_seal(ctx, h.id) : ba_clear(ctx, h.id);
	}
	case BASHOS_AUTH_IOC_EXPORT_ONCE: {
		struct bashos_auth_secret_export e;
		struct ba_user_copy copy;

		if (copy_from_user(&e, arg, sizeof(e)))
			return -EFAULT;
		copy.address = e.user_ptr;
		ret = ba_export(ctx, e.id, e.len, &e.len, ba_copy_out, &copy);
		if (ret)
			return ret;
		if (copy_to_user(arg, &e, sizeof(e))) {
			ctx->stats.refused_exports++;
			return -EFAULT;
		}
		return 0;
	}
	case BASHOS_AUTH_IOC_SAME_SECRET: {
		struct bashos_auth_secret_compare compare;

		if (copy_from_user(&compare, arg, sizeof(compare)))
			return -EFAULT;
		if (compare.flags)
			return -EINVAL;
		ret = ba_same(ctx, compare.id_a, compare.id_b, &compare.result);
		if (ret)
			return ret;
		return copy_to_user(arg, &compare, sizeof(compare)) ? -EFAULT : 0;
	}
	case BASHOS_AUTH_IOC_STATS:
		return copy_to_user(arg, &ctx->stats, sizeof(ctx->stats)) ? -EFAULT : 0;
	default:
		/* Tokens, policy, audit, verification, timestamps and handoff absent.
		 * Never synthesize an allow or successful token consumption.
		 */
		return -ENOTTY;
	}
}

static long ba_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ba_ctx *ctx = file->private_data;
	long ret;

	if (!ba_access_ok())
		return -EPERM;
	mutex_lock(&ctx->lock);
	ret = ba_ioctl_locked(ctx, cmd, (void __user *)arg);
	mutex_unlock(&ctx->lock);
	return ret;
}

static const struct file_operations ba_fops = {
	.owner = THIS_MODULE,
	.open = ba_open,
	.release = ba_release,
	.unlocked_ioctl = ba_ioctl,
	/* Only stage-1 payloads are accepted; their layouts are 32/64-bit stable.
	 * Embedded __u64 pointers are checked in the copy callbacks above.
	 */
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice ba_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "bashos-auth",
	.fops = &ba_fops,
	.mode = 0600,
};

static int __init ba_init(void)
{
	/* Collision with an existing authority fails misc_register. */
	return misc_register(&ba_device);
}

static void __exit ba_exit(void)
{
	misc_deregister(&ba_device);
}

module_init(ba_init);
module_exit(ba_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Experimental bash-os stage-1 secret storage; no token or PRIVCMD authority");
MODULE_VERSION("0.1-stage1");
