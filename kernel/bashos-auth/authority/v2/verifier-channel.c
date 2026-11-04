// SPDX-License-Identifier: GPL-2.0-only
/* Kernel-owned verifier IPC. Not connected to the production stage-1 device. */
#include <crypto/algapi.h>
#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/umh.h>
#include <linux/user_namespace.h>
#include <linux/workqueue.h>
#include "verifier-channel.h"

#define BA_V2_VERIFY_TIMEOUT_MS 30000U

struct ba_v2_channel {
	struct kref references;
	struct mutex lock;
	struct ba_v2_challenge *challenge;
	struct ba_v2_response response;
	struct file *executable; /* borrowed from the pinned verifier for the call */
	struct file *channel_file; /* caller holds this through UMH_WAIT_PROC */
	struct task_struct *helper;
	const struct cred *helper_cred;
	u64 helper_exec_id;
	size_t read_offset;
	bool replied, failed, timed_out;
	struct delayed_work timeout;
	char exec_path[64], channel_number[16];
};

struct ba_v2_verified_event {
	struct mutex lock;
	struct ba_reference_actor actor;
	struct ba_reference_claim claim;
	const void *recipient;
	u64 account_generation, policy_generation, deadline;
	bool active;
};

static void channel_free(struct kref *reference)
{
	struct ba_v2_channel *c = container_of(reference, struct ba_v2_channel, references);
	if (c->helper_cred) put_cred(c->helper_cred);
	if (c->helper) put_task_struct(c->helper);
	if (c->challenge) kvfree_sensitive(c->challenge, sizeof(*c->challenge));
	mutex_destroy(&c->lock);
	memzero_explicit(c, sizeof(*c));
	kfree(c);
}

static int channel_release(struct inode *inode, struct file *file)
{
	struct ba_v2_channel *c = file->private_data;
	kref_put(&c->references, channel_free);
	return 0;
}

/* Called under the channel lock. The exact helper task and its one expected
 * exec are selected in kernel setup before any userspace runs. No pathname,
 * uid alone, or arbitrary inherited/transferred file can establish this role. */
static bool channel_actor(struct ba_v2_channel *c)
{
	if (c->failed || c->helper != current ||
	    READ_ONCE(current->self_exec_id) != c->helper_exec_id ||
	    current_user_ns() != &init_user_ns) return false;
	if (!c->helper_cred) c->helper_cred = get_current_cred();
	return c->helper_cred == current_cred();
}

static void channel_fail(struct ba_v2_channel *c)
{
	c->failed = true;
	memzero_explicit(c->challenge->secret, sizeof(c->challenge->secret));
	memzero_explicit(&c->response, sizeof(c->response));
}

static ssize_t channel_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
	struct ba_v2_channel *c = file->private_data;
	size_t n;
	ssize_t rc;
	mutex_lock(&c->lock);
	if (!channel_actor(c) || c->replied) {
		channel_fail(c); rc = -EPERM; goto done;
	}
	n = min(count, sizeof(*c->challenge) - c->read_offset);
	if (n && copy_to_user(buffer, (u8 *)c->challenge + c->read_offset, n)) {
		channel_fail(c); rc = -EFAULT; goto done;
	}
	c->read_offset += n;
	if (c->read_offset == sizeof(*c->challenge))
		memzero_explicit(c->challenge->secret, sizeof(c->challenge->secret));
	rc = n;
done:
	mutex_unlock(&c->lock);
	return rc;
}

static ssize_t channel_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
	struct ba_v2_channel *c = file->private_data;
	struct ba_v2_response reply;
	ssize_t rc;
	memset(&reply, 0, sizeof(reply));
	mutex_lock(&c->lock);
	if (!channel_actor(c) || c->replied || c->read_offset != sizeof(*c->challenge) ||
	    count != sizeof(reply)) { channel_fail(c); rc = -EPERM; goto done; }
	if (copy_from_user(&reply, buffer, sizeof(reply))) {
		channel_fail(c); rc = -EFAULT; goto done;
	}
	if (le32_to_cpu(reply.magic) != BA_V2_MAGIC || le32_to_cpu(reply.version) != BA_V2_VERSION ||
	    le32_to_cpu(reply.size) != sizeof(reply) || le32_to_cpu(reply.status) > BA_V2_VERIFY_ERROR ||
	    crypto_memneq(reply.nonce, c->challenge->nonce, sizeof(reply.nonce)) ||
	    crypto_memneq(reply.request_digest, c->challenge->request_digest, sizeof(reply.request_digest))) {
		channel_fail(c); rc = -EKEYREJECTED; goto done;
	}
	c->response = reply;
	c->replied = true;
	rc = sizeof(reply);
done:
	mutex_unlock(&c->lock);
	memzero_explicit(&reply, sizeof(reply));
	return rc;
}

static const struct file_operations channel_operations = {
	.owner = THIS_MODULE,
	.read = channel_read,
	.write = channel_write,
	.release = channel_release,
	/* No llseek operation: the private stream has one shared read cursor. */
};

static void channel_timeout(struct work_struct *work)
{
	struct ba_v2_channel *c = container_of(to_delayed_work(work), struct ba_v2_channel, timeout);
	mutex_lock(&c->lock);
	c->timed_out = true;
	channel_fail(c);
	if (c->helper) send_sig(SIGKILL, c->helper, 1);
	mutex_unlock(&c->lock);
}

static int helper_setup(struct subprocess_info *info, struct cred *new)
{
	struct ba_v2_channel *c = info->data;
	int channel_fd, executable_fd;
	/* CONFIG_STATIC_USERMODEHELPER may substitute another executable, including
	 * a successful no-op. Never give such a dispatcher the private channel. */
	if (info->path != c->exec_path) return -EOPNOTSUPP;
	channel_fd = get_unused_fd_flags(0);
	if (channel_fd < 0) return channel_fd;
	executable_fd = get_unused_fd_flags(O_CLOEXEC);
	if (executable_fd < 0) { put_unused_fd(channel_fd); return executable_fd; }
	/* Exec resolves the held inode through this helper's own proc-fd table;
	 * later pathname replacement cannot substitute another executable. */
	snprintf(c->exec_path, sizeof(c->exec_path), "/proc/self/fd/%d", executable_fd);
	snprintf(c->channel_number, sizeof(c->channel_number), "%d", channel_fd);
	fd_install(channel_fd, get_file(c->channel_file));
	fd_install(executable_fd, get_file(c->executable));
	mutex_lock(&c->lock);
	c->helper = current;
	get_task_struct(current);
	c->helper_exec_id = READ_ONCE(current->self_exec_id) + 1;
	mutex_unlock(&c->lock);
	schedule_delayed_work(&c->timeout, msecs_to_jiffies(BA_V2_VERIFY_TIMEOUT_MS));
	return 0;
}

static int export_to_challenge(void *cookie, const void *secret, size_t length)
{
	struct ba_v2_challenge *c = cookie;
	if (length > sizeof(c->secret)) return -EFAULT;
	memcpy(c->secret, secret, length);
	return 0;
}

void ba_v2_event_destroy(struct ba_v2_verified_event *event)
{
	if (!event) return;
	ba_reference_actor_release(&event->actor);
	mutex_destroy(&event->lock);
	memzero_explicit(event, sizeof(*event));
	kfree(event);
}

int ba_v2_event_take(struct ba_v2_verified_event *event, const void *recipient,
		u64 account_generation, u64 policy_generation,
		struct ba_reference_claim *claim, u64 *deadline)
{
	int rc = -EKEYREJECTED;
	if (!event || !recipient || !claim || !deadline) return -EINVAL;
	memset(claim, 0, sizeof(*claim));
	*deadline = 0;
	mutex_lock(&event->lock);
	if (event->active && event->recipient == recipient &&
	    event->account_generation == account_generation && event->policy_generation == policy_generation &&
	    ba_reference_actor_matches(&event->actor) && ktime_get_boottime_ns() < event->deadline) {
		*claim = event->claim;
		*deadline = event->deadline;
		rc = 0;
	}
	/* Attempting redemption is terminal, including mismatched recipients. */
	event->active = false;
	memzero_explicit(&event->claim, sizeof(event->claim));
	mutex_unlock(&event->lock);
	return rc;
}

int ba_v2_verify_account(const struct ba_v2_trusted_file *verifier,
		const struct ba_v2_accounts *accounts, u64 policy_generation,
		const void *recipient, struct ba_ctx *secrets, u32 secret_id,
		const char *target, u32 purpose, const u8 request_digest[32],
		struct ba_v2_verified_event **out)
{
	const struct ba_v2_account_record *account;
	struct ba_v2_verified_event *event;
	struct ba_v2_channel *c;
	struct subprocess_info *info;
	char *argv[4], *envp[] = { "LANG=C", "LC_ALL=C", NULL };
	u32 length = 0;
	u64 deadline;
	int rc;
	if (!out) return -EINVAL;
	*out = NULL;
	if (!verifier || !verifier->file || !accounts || !policy_generation || !recipient ||
	    !secrets || !request_digest || (purpose != BA_V2_PURPOSE_LOGIN &&
	    purpose != BA_V2_PURPOSE_SU && purpose != BA_V2_PURPOSE_SSH && purpose != BA_V2_PURPOSE_PRIVCMD))
		return -EINVAL;
	account = ba_v2_account_find(accounts, target);
	if (!account) return -EACCES;
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) return -ENOMEM;
	mutex_init(&event->lock);
	rc = ba_reference_actor_capture(&event->actor);
	if (rc) goto event_fail;
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) { rc = -ENOMEM; goto event_fail; }
	kref_init(&c->references);
	mutex_init(&c->lock);
	INIT_DELAYED_WORK(&c->timeout, channel_timeout);
	c->challenge = kvzalloc(sizeof(*c->challenge), GFP_KERNEL);
	if (!c->challenge) { rc = -ENOMEM; goto channel_fail; }
	c->challenge->magic = cpu_to_le32(BA_V2_MAGIC);
	c->challenge->version = cpu_to_le32(BA_V2_VERSION);
	c->challenge->size = cpu_to_le32(sizeof(*c->challenge));
	c->challenge->purpose = cpu_to_le32(purpose);
	c->challenge->target_uid = account->uid;
	c->challenge->target_gid = account->gid;
	c->challenge->encoding = account->encoding;
	c->challenge->account_generation = cpu_to_le64(accounts->generation);
	c->challenge->policy_generation = cpu_to_le64(policy_generation);
	get_random_bytes(c->challenge->nonce, sizeof(c->challenge->nonce));
	memcpy(c->challenge->request_digest, request_digest, 32);
	memcpy(c->challenge->user, account->user, sizeof(account->user));
	memcpy(c->challenge->phc, account->phc, sizeof(account->phc));
	mutex_lock(&secrets->lock);
	rc = ba_export(secrets, secret_id, BA_V2_SECRET_BYTES, &length, export_to_challenge, c->challenge);
	mutex_unlock(&secrets->lock);
	if (rc) goto channel_fail;
	c->challenge->secret_length = cpu_to_le32(length);
	c->executable = verifier->file;
	/* File and waiting caller hold separate references, so a deliberately bad
	 * verifier cannot free kernel state by closing or transferring its fd. */
	kref_get(&c->references);
	c->channel_file = anon_inode_getfile("[bashos-auth-v2-verifier]", &channel_operations, c, O_RDWR);
	if (IS_ERR(c->channel_file)) {
		rc = PTR_ERR(c->channel_file);
		kref_put(&c->references, channel_free);
		goto channel_fail;
	}
	stream_open(file_inode(c->channel_file), c->channel_file);
	strscpy(c->exec_path, "/proc/self/fd/pending", sizeof(c->exec_path));
	argv[0] = "bashos-auth-verify-v2";
	argv[1] = "--kernel-channel";
	argv[2] = c->channel_number;
	argv[3] = NULL;
	info = call_usermodehelper_setup(c->exec_path, argv, envp, GFP_KERNEL, helper_setup, NULL, c);
	if (!info) rc = -ENOMEM;
	else rc = call_usermodehelper_exec(info, UMH_WAIT_PROC);
	cancel_delayed_work_sync(&c->timeout);
	mutex_lock(&c->lock);
	if (rc || c->failed || !c->helper || !c->replied ||
	    READ_ONCE(c->helper->self_exec_id) != c->helper_exec_id ||
	    c->read_offset != sizeof(*c->challenge) ||
	    !ba_reference_actor_matches(&event->actor)) {
		rc = c->timed_out ? -ETIMEDOUT : -EKEYREJECTED;
	} else if (le32_to_cpu(c->response.status) != BA_V2_VERIFY_OK) {
		rc = le32_to_cpu(c->response.status) == BA_V2_VERIFY_DENIED ? -EACCES : -EIO;
	} else if (check_add_overflow(ktime_get_boottime_ns(), BA_REFERENCE_MAX_LIFETIME_NS, &deadline)) {
		rc = -EOVERFLOW;
	} else {
		event->claim.uid = make_kuid(&init_user_ns, le32_to_cpu(account->uid));
		event->claim.gid = make_kgid(&init_user_ns, le32_to_cpu(account->gid));
		event->claim.purpose = purpose;
		memcpy(event->claim.user, account->user, sizeof(event->claim.user));
		memcpy(event->claim.request_digest, c->challenge->request_digest, 32);
		event->account_generation = accounts->generation;
		event->policy_generation = policy_generation;
		event->recipient = recipient;
		event->deadline = deadline;
		event->active = true;
		rc = 0;
	}
	/* Even a surviving transferred fd cannot access a finished challenge. */
	channel_fail(c);
	mutex_unlock(&c->lock);
	fput(c->channel_file);
channel_fail:
	kref_put(&c->references, channel_free);
	if (rc) goto event_fail;
	*out = event;
	return 0;
event_fail:
	ba_v2_event_destroy(event);
	return rc;
}
