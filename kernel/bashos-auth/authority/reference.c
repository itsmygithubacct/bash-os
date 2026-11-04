// SPDX-License-Identifier: GPL-2.0-only
/* Proposed reference mechanics only. No device, issuer or verifier is added. */
#include <crypto/algapi.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs_struct.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include "reference.h"
#ifdef BA_AUTHORITY_V2
#include <linux/cgroup.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/ipc_namespace.h>
#include <linux/magic.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/time_namespace.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include "v2/verifier-channel.h"
#endif

struct ba_reference_grant {
	u8 reference[BA_REFERENCE_BYTES];
	struct ba_reference_claim claim;
	u64 expires;
	u64 policy_epoch;
	u64 timestamp_epoch;
	size_t read_offset;
	bool active;
	bool delegated;
};

struct ba_reference_store {
	struct mutex lock;
	struct ba_reference_actor actor;
	struct ba_reference_grant grant;
	u64 policy_epoch;
	u64 timestamp_epoch;
#ifdef BA_AUTHORITY_KUNIT
	bool test_clock;
	u64 test_now;
	ba_reference_observer observer;
	void *observer_cookie;
#endif
};

#ifdef BA_AUTHORITY_V2
/* nsfs owns namespace references through file lifetime. Its public namespace
 * operations are used to validate the mount anchor against the actual task;
 * the other identities are available directly in the task's nsproxy. This
 * does not trust /proc spelling, inode numbers, a caller-supplied fd, or the
 * recyclable address of an unreferenced nsproxy container. */
static bool ba_reference_namespace_matches(struct file *file,
		struct task_struct *task, unsigned int index)
{
	struct ns_common *pinned, *actual = NULL;
	struct nsproxy *n;
	bool match;
	if (!file || file_inode(file)->i_sb->s_magic != NSFS_MAGIC) return false;
	pinned = get_proc_ns(file_inode(file));
	if (!pinned || !pinned->ops) return false;
	if (index == 0 || index == 8) {
		/* mnt_namespace is intentionally opaque to modules. The nsfs-owned
		 * operation obtains its real identity and a temporary ref. The
		 * active PID selector is distinct from pid_ns_for_children. */
		int type = index == 0 ? CLONE_NEWNS : CLONE_NEWPID;
		if (pinned->ops->type != type || !pinned->ops->get || !pinned->ops->put)
			return false;
		actual = pinned->ops->get(task);
		if (!actual) return false;
		match = actual == pinned;
		actual->ops->put(actual);
		return match;
	}
	task_lock(task);
	n = task->nsproxy;
	if (n) switch (index) {
	case 1: actual = n->uts_ns ? &n->uts_ns->ns : NULL; break;
	case 2: actual = n->ipc_ns ? &n->ipc_ns->ns : NULL; break;
	case 3: actual = n->pid_ns_for_children ? &n->pid_ns_for_children->ns : NULL; break;
	case 4: actual = n->net_ns ? &n->net_ns->ns : NULL; break;
	case 5: actual = n->time_ns ? &n->time_ns->ns : NULL; break;
	case 6: actual = n->time_ns_for_children ? &n->time_ns_for_children->ns : NULL; break;
	case 7: actual = n->cgroup_ns ? &n->cgroup_ns->ns : NULL; break;
	}
	match = actual && actual == pinned;
	task_unlock(task);
	return match;
}

static bool ba_reference_namespaces_match(const struct ba_reference_actor *actor,
		struct task_struct *task)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(actor->namespaces); i++)
		if (!ba_reference_namespace_matches(actor->namespaces[i], task, i)) return false;
	return true;
}

static int ba_reference_namespaces_capture(struct ba_reference_actor *actor)
{
	static const char * const names[] = {
		"mnt", "uts", "ipc", "pid_for_children", "net", "time", "time_for_children", "cgroup",
		"pid",
	};
	char path[64];
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		struct file *file;
		snprintf(path, sizeof(path), "/proc/thread-self/ns/%s", names[i]);
		file = filp_open(path, O_RDONLY | O_CLOEXEC, 0);
		if (IS_ERR(file)) return PTR_ERR(file);
		actor->namespaces[i] = file;
		if (!ba_reference_namespace_matches(file, current, i)) return -EPERM;
	}
	return 0;
}

static void ba_reference_namespaces_release(struct ba_reference_actor *actor)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(actor->namespaces); i++) {
		if (actor->namespaces[i]) fput(actor->namespaces[i]);
		actor->namespaces[i] = NULL;
	}
}
#endif

int ba_reference_actor_capture(struct ba_reference_actor *actor)
{
#ifdef BA_AUTHORITY_V2
	int rc;
#endif
	memset(actor, 0, sizeof(*actor));
	if (!current->fs || !current->nsproxy ||
	    current_user_ns() != &init_user_ns)
		return -EPERM;
	actor->task = current;
	actor->exec_id = READ_ONCE(current->self_exec_id);
	get_task_struct(actor->task);
	actor->cred = get_current_cred();
	rcu_read_lock();
	actor->session = get_pid(task_session(current));
	rcu_read_unlock();
	get_fs_pwd(current->fs, &actor->cwd);
	get_fs_root(current->fs, &actor->root);
#ifdef BA_AUTHORITY_V2
	rc = ba_reference_namespaces_capture(actor);
	if (rc) { ba_reference_actor_release(actor); return rc; }
#else
	actor->namespaces = current->nsproxy;
	get_nsproxy(actor->namespaces);
#endif
	return 0;
}

void ba_reference_actor_release(struct ba_reference_actor *actor)
{
	if (!actor->task)
		return;
	path_put(&actor->cwd);
	path_put(&actor->root);
#ifdef BA_AUTHORITY_V2
	ba_reference_namespaces_release(actor);
#else
	put_nsproxy(actor->namespaces);
#endif
	put_pid(actor->session);
	put_cred(actor->cred);
	put_task_struct(actor->task);
	memzero_explicit(actor, sizeof(*actor));
}

bool ba_reference_actor_matches(const struct ba_reference_actor *actor)
{
	struct path cwd, root;
	bool match;

	if (actor->task != current || actor->cred != current_cred() ||
	    !current->fs || !current->nsproxy ||
	    actor->exec_id != READ_ONCE(current->self_exec_id))
		return false;
#ifdef BA_AUTHORITY_V2
	if (!ba_reference_namespaces_match(actor, current)) return false;
#else
	if (actor->namespaces != current->nsproxy) return false;
#endif
	rcu_read_lock();
	match = actor->session == task_session(current);
	rcu_read_unlock();
	if (!match)
		return false;
	get_fs_pwd(current->fs, &cwd);
	get_fs_root(current->fs, &root);
	match = path_equal(&actor->cwd, &cwd) && path_equal(&actor->root, &root);
	path_put(&cwd);
	path_put(&root);
	return match;
}

static u64 ba_reference_now(struct ba_reference_store *store)
{
#ifdef BA_AUTHORITY_KUNIT
	if (store->test_clock)
		return store->test_now;
#endif
	/* Suspend time counts; wall-clock adjustment cannot prolong a grant. */
	return ktime_get_boottime_ns();
}

static void ba_reference_erase_grant(struct ba_reference_store *store)
{
	memzero_explicit(&store->grant, sizeof(store->grant));
#ifdef BA_AUTHORITY_KUNIT
	if (store->observer)
		store->observer(store->observer_cookie, &store->grant,
			       sizeof(store->grant), BA_REFERENCE_WIPE_GRANT);
#endif
}

/* Call with the store lock held. Observers must only record data, never assert. */
static int ba_reference_live(struct ba_reference_store *store)
{
	struct ba_reference_grant *grant = &store->grant;

	if (!ba_reference_actor_matches(&store->actor))
		return -EPERM;
	if (!grant->active)
		return -ENOENT;
	if (ba_reference_now(store) >= grant->expires) {
		ba_reference_erase_grant(store);
		return -EKEYEXPIRED;
	}
	if (grant->policy_epoch != store->policy_epoch ||
	    grant->timestamp_epoch != store->timestamp_epoch) {
		ba_reference_erase_grant(store);
		return -EKEYREVOKED;
	}
	return 0;
}

static bool ba_reference_claim_valid(const struct ba_reference_claim *claim)
{
	return claim && uid_valid(claim->uid) && gid_valid(claim->gid) &&
		(claim->purpose == 1 || claim->purpose == 2
#ifdef BA_AUTHORITY_V2
		 || claim->purpose == BA_V2_PURPOSE_SSH
#endif
		) && claim->user[0] &&
		memchr(claim->user, 0, sizeof(claim->user));
}

static bool ba_reference_claim_equal(const struct ba_reference_claim *a,
				     const struct ba_reference_claim *b)
{
	return uid_eq(a->uid, b->uid) && gid_eq(a->gid, b->gid) &&
		a->purpose == b->purpose && !strcmp(a->user, b->user) &&
		!crypto_memneq(a->request_digest, b->request_digest,
			      sizeof(a->request_digest));
}

struct ba_reference_store *ba_reference_store_create(void)
{
	struct ba_reference_store *store = kzalloc(sizeof(*store), GFP_KERNEL);

	if (!store)
		return NULL;
	if (ba_reference_actor_capture(&store->actor)) {
		kfree_sensitive(store);
		return NULL;
	}
	mutex_init(&store->lock);
	store->policy_epoch = 1;
	store->timestamp_epoch = 1;
	return store;
}

void ba_reference_store_destroy(struct ba_reference_store *store)
{
#ifdef BA_AUTHORITY_KUNIT
	ba_reference_observer observer;
	void *cookie;
#endif
	if (!store)
		return;
	mutex_lock(&store->lock);
	ba_reference_erase_grant(store);
	mutex_unlock(&store->lock);
	mutex_destroy(&store->lock);
	ba_reference_actor_release(&store->actor);
#ifdef BA_AUTHORITY_KUNIT
	observer = store->observer;
	cookie = store->observer_cookie;
#endif
	memzero_explicit(store, sizeof(*store));
#ifdef BA_AUTHORITY_KUNIT
	if (observer)
		observer(cookie, store, sizeof(*store), BA_REFERENCE_WIPE_STORE);
#endif
	kfree_sensitive(store);
}

ssize_t ba_reference_read(struct ba_reference_store *store, size_t count,
		ba_reference_copy_fn copy, void *cookie)
{
	struct ba_reference_grant *grant;
	ssize_t rc;
	size_t n;

	if (!store || !copy)
		return -EINVAL;
	if (!count)
		return 0;
	mutex_lock(&store->lock);
	rc = ba_reference_live(store);
	if (rc == -ENOENT) {
		rc = 0; /* No queued reference; login treats premature EOF as failure. */
		goto done;
	}
	if (rc)
		goto done;
	grant = &store->grant;
	n = min(count, BA_REFERENCE_BYTES - grant->read_offset);
	if (!n) {
		rc = 0;
		goto done;
	}
	if (copy(cookie, grant->reference + grant->read_offset, n)) {
		/* Some bytes may already be in userspace. Revoke the whole grant. */
		ba_reference_erase_grant(store);
		rc = -EFAULT;
		goto done;
	}
	grant->read_offset += n;
	rc = n;
done:
	mutex_unlock(&store->lock);
	return rc;
}

int ba_reference_consume(struct ba_reference_store *store,
		const u8 reference[BA_REFERENCE_BYTES],
		const struct ba_reference_claim *claim)
{
	int rc;

	if (!store || !reference || !claim)
		return -EINVAL;
	mutex_lock(&store->lock);
	rc = ba_reference_live(store);
	if (rc)
		goto done;
	if (crypto_memneq(store->grant.reference, reference, BA_REFERENCE_BYTES)) {
		rc = -ENOENT;
		goto done;
	}
	/* A known reference with a changed target/purpose/request is terminal. */
	rc = ba_reference_claim_valid(claim) &&
		ba_reference_claim_equal(&store->grant.claim, claim) ? 0 : -EACCES;
	ba_reference_erase_grant(store);
done:
	mutex_unlock(&store->lock);
	return rc;
}

int ba_reference_advance_epochs(struct ba_reference_store *store,
		u64 policy_epoch, u64 timestamp_epoch)
{
	int rc = 0;

	if (!store)
		return -EINVAL;
	mutex_lock(&store->lock);
	if (!policy_epoch || !timestamp_epoch ||
	    policy_epoch < store->policy_epoch ||
	    timestamp_epoch < store->timestamp_epoch) {
		rc = -EINVAL;
		goto done;
	}
	if (policy_epoch != store->policy_epoch ||
	    timestamp_epoch != store->timestamp_epoch)
		ba_reference_erase_grant(store);
	store->policy_epoch = policy_epoch;
	store->timestamp_epoch = timestamp_epoch;
done:
	mutex_unlock(&store->lock);
	return rc;
}

void ba_reference_revoke(struct ba_reference_store *store)
{
	if (!store)
		return;
	mutex_lock(&store->lock);
	ba_reference_erase_grant(store);
	mutex_unlock(&store->lock);
}

#ifdef BA_AUTHORITY_V2
int ba_reference_revoke_current(struct ba_reference_store *store)
{
	int rc = -EPERM;
	if (!store) return -EINVAL;
	mutex_lock(&store->lock);
	if (ba_reference_actor_matches(&store->actor)) {
		ba_reference_erase_grant(store);
		rc = 0;
	}
	mutex_unlock(&store->lock);
	return rc;
}

static bool same_capabilities(kernel_cap_t a, kernel_cap_t b)
{
	return cap_issubset(a, b) && cap_issubset(b, a);
}

/* Ordinary fork allocates a new cred object. At explicit delegation, compare
 * the inherited identities/groups/capabilities/security label, then pin the
 * child's own exact object for all subsequent operations. Pointer equality to
 * the parent would reject every ordinary fork on the supported kernel. */
static bool ba_reference_inherited_creds(const struct cred *parent, const struct cred *child)
{
	u32 parent_secid = 0, child_secid = 0;
	if (!uid_eq(parent->uid, child->uid) || !uid_eq(parent->euid, child->euid) ||
	    !uid_eq(parent->suid, child->suid) || !uid_eq(parent->fsuid, child->fsuid) ||
	    !gid_eq(parent->gid, child->gid) || !gid_eq(parent->egid, child->egid) ||
	    !gid_eq(parent->sgid, child->sgid) || !gid_eq(parent->fsgid, child->fsgid) ||
	    parent->user_ns != child->user_ns || parent->group_info != child->group_info ||
	    parent->securebits != child->securebits ||
	    !same_capabilities(parent->cap_inheritable, child->cap_inheritable) ||
	    !same_capabilities(parent->cap_permitted, child->cap_permitted) ||
	    !same_capabilities(parent->cap_effective, child->cap_effective) ||
	    !same_capabilities(parent->cap_bset, child->cap_bset) ||
	    !same_capabilities(parent->cap_ambient, child->cap_ambient)) return false;
#ifdef CONFIG_KEYS
	if (parent->session_keyring != child->session_keyring || child->process_keyring ||
	    child->thread_keyring || parent->request_key_auth != child->request_key_auth ||
	    parent->jit_keyring != child->jit_keyring) return false;
#endif
	security_cred_getsecid(parent, &parent_secid);
	security_cred_getsecid(child, &child_secid);
	return parent_secid == child_secid;
}

static int ba_reference_capture_ssh_child(const struct ba_reference_actor *parent,
		pid_t child_pid, struct ba_reference_actor *child)
{
	struct pid *pid;
	struct task_struct *task;
	unsigned int i;
	bool lineage;
	int rc = -EPERM;
	memset(child, 0, sizeof(*child));
	if (child_pid <= 0 || current->group_leader != current) return -EINVAL;
	pid = find_get_pid(child_pid);
	if (!pid) return -ESRCH;
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task) return -ESRCH;
	rcu_read_lock();
	lineage = rcu_dereference(task->real_parent) == current && task->group_leader == task;
	child->session = get_pid(task_session(task));
	rcu_read_unlock();
	if (!lineage || child->session != parent->session) goto failed;
	child->cred = get_task_cred(task);
	if (!ba_reference_inherited_creds(parent->cred, child->cred)) goto failed;
	if (!ba_reference_namespaces_match(parent, task)) goto failed;
	for (i = 0; i < ARRAY_SIZE(child->namespaces); i++)
		child->namespaces[i] = get_file(parent->namespaces[i]);
	task_lock(task);
	if (!task->fs || !task->nsproxy || task->exit_state ||
	    READ_ONCE(task->self_exec_id) != parent->exec_id) {
		task_unlock(task); goto failed;
	}
	child->exec_id = READ_ONCE(task->self_exec_id);
	get_fs_pwd(task->fs, &child->cwd);
	get_fs_root(task->fs, &child->root);
	task_unlock(task);
	if (!path_equal(&child->cwd, &parent->cwd) || !path_equal(&child->root, &parent->root))
		goto failed;
	child->task = task;
	return 0;
failed:
	if (child->cwd.dentry) {
		path_put(&child->cwd); path_put(&child->root);
	}
	ba_reference_namespaces_release(child);
	if (child->cred) put_cred(child->cred);
	put_pid(child->session);
	put_task_struct(task);
	memset(child, 0, sizeof(*child));
	return rc;
}

int ba_reference_delegate_ssh_child(struct ba_reference_store *store, pid_t child_pid)
{
	struct ba_reference_actor child;
	int rc;
	if (!store) return -EINVAL;
	mutex_lock(&store->lock);
	rc = ba_reference_live(store);
	if (rc) goto done;
	if (store->grant.claim.purpose != BA_V2_PURPOSE_SSH || store->grant.delegated ||
	    store->grant.read_offset) { rc = -EPERM; goto done; }
	rc = ba_reference_capture_ssh_child(&store->actor, child_pid, &child);
	if (rc) goto done;
	ba_reference_actor_release(&store->actor);
	store->actor = child;
	store->grant.delegated = true;
done:
	mutex_unlock(&store->lock);
	return rc;
}

/* Only a kernel-owned completed native-verifier event can enter this path.
 * The legacy device and the isolated mechanics KUnit target do not compile it. */
int ba_reference_issue_verified(struct ba_reference_store *store,
		struct ba_v2_verified_event *event, u64 account_generation, u64 policy_generation)
{
	struct ba_reference_claim claim = {0};
	struct ba_reference_grant *grant;
	u64 deadline = 0;
	int rc;
	if (!store || !event) return -EINVAL;
	mutex_lock(&store->lock);
	if (!ba_reference_actor_matches(&store->actor)) { rc = -EPERM; goto done; }
	grant = &store->grant;
	if (grant->active && ba_reference_now(store) >= grant->expires)
		ba_reference_erase_grant(store);
	if (grant->active) { rc = -EBUSY; goto done; }
	rc = ba_v2_event_take(event, store, account_generation, policy_generation, &claim, &deadline);
	if (rc) goto done;
	if (!ba_reference_claim_valid(&claim) || ba_reference_now(store) >= deadline) {
		rc = -EKEYREJECTED; goto done;
	}
	do { get_random_bytes(grant->reference, sizeof(grant->reference)); }
	while (!memchr_inv(grant->reference, 0, sizeof(grant->reference)));
	grant->claim = claim;
	grant->expires = deadline; /* Never extend the verification event's deadline. */
	grant->policy_epoch = store->policy_epoch;
	grant->timestamp_epoch = store->timestamp_epoch;
	grant->active = true;
	rc = 0;
done:
	mutex_unlock(&store->lock);
	memzero_explicit(&claim, sizeof(claim));
	return rc;
}
#endif

#ifdef BA_AUTHORITY_KUNIT
/* No version of this function is compiled into the production module. */
int ba_reference_test_seed(struct ba_reference_store *store,
		const struct ba_reference_claim *claim, u64 lifetime,
		u8 reference[BA_REFERENCE_BYTES])
{
	struct ba_reference_grant *grant;
	u64 expires;
	int rc = 0;

	if (!store || !reference || !ba_reference_claim_valid(claim) ||
	    !lifetime || lifetime > BA_REFERENCE_MAX_LIFETIME_NS)
		return -EINVAL;
	mutex_lock(&store->lock);
	if (!ba_reference_actor_matches(&store->actor)) {
		rc = -EPERM;
		goto done;
	}
	grant = &store->grant;
	if (grant->active && ba_reference_now(store) >= grant->expires)
		ba_reference_erase_grant(store);
	if (grant->active) {
		rc = -EBUSY;
		goto done;
	}
	if (check_add_overflow(ba_reference_now(store), lifetime, &expires)) {
		rc = -EOVERFLOW;
		goto done;
	}
	do {
		get_random_bytes(grant->reference, sizeof(grant->reference));
	} while (!memchr_inv(grant->reference, 0, sizeof(grant->reference)));
	grant->claim = *claim;
	grant->expires = expires;
	grant->policy_epoch = store->policy_epoch;
	grant->timestamp_epoch = store->timestamp_epoch;
	grant->active = true;
	memcpy(reference, grant->reference, BA_REFERENCE_BYTES);
done:
	mutex_unlock(&store->lock);
	return rc;
}

void ba_reference_test_clock(struct ba_reference_store *store, u64 now)
{
	mutex_lock(&store->lock);
	store->test_clock = true;
	store->test_now = now;
	mutex_unlock(&store->lock);
}

void ba_reference_test_observer(struct ba_reference_store *store,
		ba_reference_observer observer, void *cookie)
{
	mutex_lock(&store->lock);
	store->observer = observer;
	store->observer_cookie = cookie;
	mutex_unlock(&store->lock);
}
#endif
