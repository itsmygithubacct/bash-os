// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/algapi.h>
#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/umh.h>
#include <linux/user_namespace.h>
#include <linux/workqueue.h>
#include "executor-channel.h"

struct exec_channel {
	struct kref references;
	struct mutex lock;
	struct ba_v2_exec_request *request;
	struct ba_v2_exec_response response;
	size_t size, read_offset;
	const struct ba_v2_bound_request *bound;
	struct file *executable, *channel;
	struct task_struct *helper, *child;
	const struct cred *helper_cred;
	u64 helper_exec_id;
	u32 child_number;
	bool failed, replied, timed_out;
	struct delayed_work timeout;
	char exec_path[64], channel_number[16];
};
static_assert(sizeof(struct ba_v2_exec_request) == 688);
static_assert(sizeof(struct ba_v2_exec_response) == 96);

static void exec_free(struct kref *reference)
{
	struct exec_channel *c = container_of(reference, struct exec_channel, references);
	if (c->helper_cred) put_cred(c->helper_cred);
	if (c->helper) put_task_struct(c->helper);
	if (c->child) put_task_struct(c->child);
	if (c->request) kvfree_sensitive(c->request, c->size);
	mutex_destroy(&c->lock);
	kfree_sensitive(c);
}

static int exec_release(struct inode *inode, struct file *file)
{
	struct exec_channel *c = file->private_data;
	kref_put(&c->references, exec_free);
	return 0;
}

static bool exec_actor(struct exec_channel *c)
{
	if (c->failed || current != c->helper || current_user_ns() != &init_user_ns ||
	    READ_ONCE(current->self_exec_id) != c->helper_exec_id) return false;
	if (!c->helper_cred) c->helper_cred = get_current_cred();
	return current_cred() == c->helper_cred;
}

static void exec_fail(struct exec_channel *c)
{
	c->failed = true;
	if (c->request) memzero_explicit(c->request->blobs, c->size - sizeof(*c->request));
	memzero_explicit(&c->response, sizeof(c->response));
}

static ssize_t exec_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
	struct exec_channel *c = file->private_data;
	size_t n;
	ssize_t rc;
	mutex_lock(&c->lock);
	if (!exec_actor(c) || c->replied) { exec_fail(c); rc = -EPERM; goto done; }
	n = min(count, c->size - c->read_offset);
	if (n && copy_to_user(buffer, (u8 *)c->request + c->read_offset, n)) {
		exec_fail(c); rc = -EFAULT; goto done;
	}
	c->read_offset += n;
	if (c->read_offset == c->size)
		memzero_explicit(c->request->blobs, c->size - sizeof(*c->request));
	rc = n;
done:
	mutex_unlock(&c->lock);
	return rc;
}

static int exec_track_child(struct exec_channel *c, u32 number)
{
	struct pid *pid;
	struct task_struct *task;
	bool direct;
	if (!number || number > INT_MAX || c->child) return -EINVAL;
	pid = find_get_pid((pid_t)number);
	if (!pid) return -ESRCH;
	task = get_pid_task(pid, PIDTYPE_PID); put_pid(pid);
	if (!task) return -ESRCH;
	rcu_read_lock();
	direct = rcu_dereference(task->real_parent) == c->helper &&
		task->group_leader == task && !READ_ONCE(task->exit_state);
	rcu_read_unlock();
	if (!direct) { put_task_struct(task); return -EPERM; }
	c->child = task; c->child_number = number;
	return 0;
}

static ssize_t exec_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
	struct exec_channel *c = file->private_data;
	struct ba_v2_exec_response reply = {0};
	u32 kind, status, step, error, child;
	ssize_t rc;
	mutex_lock(&c->lock);
	if (!exec_actor(c) || c->replied || c->read_offset != c->size || count != sizeof(reply)) {
		rc = -EPERM; goto failed;
	}
	if (copy_from_user(&reply, buffer, sizeof(reply))) { rc = -EFAULT; goto failed; }
	if (le32_to_cpu(reply.magic) != BA_V2_EXEC_MAGIC || le32_to_cpu(reply.version) != BA_V2_EXEC_VERSION ||
	    le32_to_cpu(reply.size) != sizeof(reply) ||
	    crypto_memneq(reply.nonce, c->request->nonce, 32) ||
	    crypto_memneq(reply.request_digest, c->request->request_digest, 32)) { rc = -EKEYREJECTED; goto failed; }
	kind = le32_to_cpu(reply.kind); status = le32_to_cpu(reply.status);
	step = le32_to_cpu(reply.failed_step); error = le32_to_cpu(reply.error); child = le32_to_cpu(reply.child_pid);
	if (kind == BA_V2_EXEC_CHILD_READY) {
		if (status || step || error) { rc = -EINVAL; goto failed; }
		rc = exec_track_child(c, child);
		if (rc) goto failed;
		goto accepted;
	}
	if (child != c->child_number || kind < BA_V2_EXEC_EXIT || kind > BA_V2_EXEC_TIMEOUT ||
	    (!c->child && kind != BA_V2_EXEC_SETUP_ERROR) ||
	    (kind == BA_V2_EXEC_EXIT && (status > 255 || step || error)) ||
	    (kind == BA_V2_EXEC_SIGNAL && (!status || status > 64 || step || error)) ||
	    (kind == BA_V2_EXEC_SETUP_ERROR && (status != 126 || !step || step > BA_V2_EXEC_STEP_EXEC || !error || error > 4095)) ||
	    (kind == BA_V2_EXEC_TIMEOUT && (status != SIGKILL || step || error != ETIMEDOUT))) {
		rc = -EKEYREJECTED; goto failed;
	}
	c->response = reply; c->replied = true;
accepted:
	rc = sizeof(reply);
	goto done;
failed:
	exec_fail(c);
	if (c->child) send_sig(SIGKILL, c->child, 1);
done:
	memzero_explicit(&reply, sizeof(reply));
	mutex_unlock(&c->lock);
	return rc;
}

static const struct file_operations exec_operations = {
	.owner = THIS_MODULE, .read = exec_read, .write = exec_write, .release = exec_release
};

static void exec_timeout(struct work_struct *work)
{
	struct exec_channel *c = container_of(to_delayed_work(work), struct exec_channel, timeout);
	mutex_lock(&c->lock);
	c->timed_out = true; exec_fail(c);
	if (c->child) send_sig(SIGKILL, c->child, 1);
	if (c->helper) send_sig(SIGKILL, c->helper, 1);
	mutex_unlock(&c->lock);
}

static int exec_setup(struct subprocess_info *info, struct cred *new)
{
	struct exec_channel *c = info->data;
	struct file *files[BA_V2_EXEC_FDS];
	int descriptors[BA_V2_EXEC_FDS + 2], rc;
	u32 i, n = 0;
	if (info->path != c->exec_path) return -EOPNOTSUPP;
	files[BA_V2_EXEC_PROGRAM] = c->bound->program.file;
	files[BA_V2_EXEC_CWD] = c->bound->cwd;
	files[BA_V2_EXEC_ROOT] = c->bound->root;
	for (i = 0; i < 3; i++) files[BA_V2_EXEC_STDIN + i] = c->bound->stdio[i];
	for (i = 0; i < 9; i++) files[BA_V2_EXEC_MNT + i] = c->bound->actor.namespaces[i];
	for (i = 0; i < BA_V2_EXEC_FDS; i++) if (!files[i]) return -EINVAL;
	/* Reserve the entire table before installing anything. Only the helper's
	 * own executable closes at its first exec; the native monitor owns the
	 * explicit request descriptors until it installs the target's stdio. */
	for (n = 0; n < ARRAY_SIZE(descriptors); n++) {
		rc = get_unused_fd_flags(n == 1 ? O_CLOEXEC : 0);
		if (rc < 0) goto unused;
		descriptors[n] = rc;
	}
	snprintf(c->exec_path, sizeof(c->exec_path), "/proc/self/fd/%d", descriptors[1]);
	snprintf(c->channel_number, sizeof(c->channel_number), "%d", descriptors[0]);
	fd_install(descriptors[0], get_file(c->channel));
	fd_install(descriptors[1], get_file(c->executable));
	for (i = 0; i < BA_V2_EXEC_FDS; i++) {
		c->request->descriptors[i] = cpu_to_le32(descriptors[i + 2]);
		fd_install(descriptors[i + 2], get_file(files[i]));
	}
	mutex_lock(&c->lock);
	c->helper = current; get_task_struct(current);
	c->helper_exec_id = READ_ONCE(current->self_exec_id) + 1;
	mutex_unlock(&c->lock);
	schedule_delayed_work(&c->timeout,
		msecs_to_jiffies((le32_to_cpu(c->request->timeout_seconds) + 10U) * 1000U));
	return 0;
unused:
	while (n) put_unused_fd(descriptors[--n]);
	return rc;
}

int ba_v2_execute_native(const struct ba_v2_trusted_file *executor,
		const struct ba_v2_bound_request *bound, const struct ba_v2_environment *env,
		u32 timeout_seconds, struct ba_v2_exec_response *result)
{
	const struct ba_request_snapshot *request;
	struct exec_channel *c;
	struct subprocess_info *info;
	char *argv[4], *envp[] = { "LANG=C", "LC_ALL=C", NULL };
	u32 i;
	int rc;
	if (!result) return -EINVAL;
	memset(result, 0, sizeof(*result));
	if (!executor || !executor->file || !bound || !bound->request || !env || !env->blob ||
	    !bound->program.file || !bound->decision.allow || !ba_v2_bound_matches(bound) ||
	    !timeout_seconds || timeout_seconds > BA_V2_EXEC_MAX_TIMEOUT ||
	    !bound->identities.exec_group_count || bound->identities.exec_group_count > BA_V2_EXEC_MAX_GROUPS ||
	    !env->count || env->count > BA_V2_EXEC_MAX_ITEMS || !env->bytes || env->bytes > BA_V2_EXEC_MAX_BLOB)
		return -EINVAL;
	request = bound->request;
	if (!request->wire.argc || request->wire.argc > BA_V2_EXEC_MAX_ITEMS ||
	    !request->wire.argv_bytes || request->wire.argv_bytes > BA_V2_EXEC_MAX_BLOB)
		return -EINVAL;
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) return -ENOMEM;
	kref_init(&c->references); mutex_init(&c->lock);
	INIT_DELAYED_WORK(&c->timeout, exec_timeout);
	c->size = sizeof(*c->request) + request->wire.argv_bytes + env->bytes;
	c->request = kvzalloc(c->size, GFP_KERNEL);
	if (!c->request) { rc = -ENOMEM; goto free_channel; }
	c->bound = bound; c->executable = executor->file;
	c->request->magic = cpu_to_le32(BA_V2_EXEC_MAGIC);
	c->request->version = cpu_to_le32(BA_V2_EXEC_VERSION);
	c->request->size = cpu_to_le32(c->size);
	c->request->uid = cpu_to_le32(bound->identities.target.uid);
	c->request->gid = cpu_to_le32(bound->identities.target_gid);
	c->request->group_count = cpu_to_le32(bound->identities.exec_group_count);
	c->request->argc = cpu_to_le32(request->wire.argc);
	c->request->envc = cpu_to_le32(env->count);
	c->request->argv_bytes = cpu_to_le32(request->wire.argv_bytes);
	c->request->env_bytes = cpu_to_le32(env->bytes);
	c->request->timeout_seconds = cpu_to_le32(timeout_seconds);
	get_random_bytes(c->request->nonce, sizeof(c->request->nonce));
	memcpy(c->request->request_digest, request->digest, 32);
	for (i = 0; i < bound->identities.exec_group_count; i++)
		c->request->groups[i] = cpu_to_le32(bound->identities.exec_gids[i]);
	memcpy(c->request->blobs, request->blobs, request->wire.argv_bytes);
	memcpy(c->request->blobs + request->wire.argv_bytes, env->blob, env->bytes);
	kref_get(&c->references);
	c->channel = anon_inode_getfile("[bashos-auth-v2-executor]", &exec_operations, c, O_RDWR);
	if (IS_ERR(c->channel)) {
		rc = PTR_ERR(c->channel); kref_put(&c->references, exec_free); goto free_channel;
	}
	stream_open(file_inode(c->channel), c->channel);
	strscpy(c->exec_path, "/proc/self/fd/pending", sizeof(c->exec_path));
	argv[0] = "bashos-auth-execute-v2"; argv[1] = "--kernel-channel";
	argv[2] = c->channel_number; argv[3] = NULL;
	info = call_usermodehelper_setup(c->exec_path, argv, envp, GFP_KERNEL, exec_setup, NULL, c);
	rc = info ? call_usermodehelper_exec(info, UMH_WAIT_PROC) : -ENOMEM;
	cancel_delayed_work_sync(&c->timeout);
	mutex_lock(&c->lock);
	if (!rc && !c->failed && c->helper && c->replied &&
	    READ_ONCE(c->helper->self_exec_id) == c->helper_exec_id) {
		*result = c->response;
	} else {
		/* Once a child exists, absence of a trustworthy completion cannot be
		 * reported as "no execution". Preserve that distinction for audit. */
		result->magic = cpu_to_le32(BA_V2_EXEC_MAGIC);
		result->version = cpu_to_le32(BA_V2_EXEC_VERSION);
		result->size = cpu_to_le32(sizeof(*result));
		result->kind = cpu_to_le32(c->child ? BA_V2_EXEC_CONTROL_ERROR : BA_V2_EXEC_LAUNCH_ERROR);
		result->status = cpu_to_le32(126);
		result->error = cpu_to_le32(c->timed_out ? ETIMEDOUT : (rc < 0 && rc >= -4095 ? -rc : EIO));
		result->child_pid = cpu_to_le32(c->child_number);
		memcpy(result->nonce, c->request->nonce, 32);
		memcpy(result->request_digest, c->request->request_digest, 32);
		if (c->child) send_sig(SIGKILL, c->child, 1);
	}
	exec_fail(c);
	mutex_unlock(&c->lock);
	fput(c->channel);
	rc = 0;
free_channel:
	kref_put(&c->references, exec_free);
	return rc;
}
