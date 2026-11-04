/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BASHOS_AUTH_REFERENCE_H
#define BASHOS_AUTH_REFERENCE_H

#include <linux/path.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#define BA_REFERENCE_BYTES 32U
#define BA_REFERENCE_USER_BYTES 64U
#define BA_REFERENCE_MAX_LIFETIME_NS (5ULL * 1000000000ULL)

struct cred;
struct file;
struct nsproxy;
struct pid;
struct task_struct;

/* Pinned kernel identities, never numbers supplied in an ioctl. Exact task and
 * credential object binding deliberately rejects fork/exec/credential changes.
 * A future delegation protocol must create a separately authenticated binding. */
struct ba_reference_actor {
	struct task_struct *task;
	const struct cred *cred;
	struct pid *session;
#ifdef BA_AUTHORITY_V2
	/* nsfs files own the complete namespace tuple, including PID/time for
	 * children AND active PID. No dependency on unexported free_nsproxy. */
	struct file *namespaces[9];
#else
	struct nsproxy *namespaces;
#endif
	struct path cwd;
	struct path root;
	u64 exec_id;
};

struct ba_reference_claim {
	kuid_t uid;
	kgid_t gid;
	u32 purpose; /* LOGIN=1 or SU=2, never a PRIVCMD exec/edit bearer token */
	char user[BA_REFERENCE_USER_BYTES];
	u8 request_digest[BA_REFERENCE_BYTES];
};

struct ba_reference_store;
typedef int (*ba_reference_copy_fn)(void *cookie, const void *data, size_t len);

int ba_reference_actor_capture(struct ba_reference_actor *actor);
void ba_reference_actor_release(struct ba_reference_actor *actor);
bool ba_reference_actor_matches(const struct ba_reference_actor *actor);
struct ba_reference_store *ba_reference_store_create(void);
/* Final-file-release semantics: caller must own the final reference; no
 * concurrent operations may remain. Destruction does not require owner creds. */
void ba_reference_store_destroy(struct ba_reference_store *store);
ssize_t ba_reference_read(struct ba_reference_store *store, size_t count,
		ba_reference_copy_fn copy, void *cookie);
int ba_reference_consume(struct ba_reference_store *store,
		const u8 reference[BA_REFERENCE_BYTES],
		const struct ba_reference_claim *claim);
int ba_reference_advance_epochs(struct ba_reference_store *store,
		u64 policy_epoch, u64 timestamp_epoch);
void ba_reference_revoke(struct ba_reference_store *store);

#ifdef BA_AUTHORITY_V2
struct ba_v2_verified_event;
/* Copy-fault cancellation by the exact current reference owner only. */
int ba_reference_revoke_current(struct ba_reference_store *store);
int ba_reference_issue_verified(struct ba_reference_store *store,
		struct ba_v2_verified_event *event, u64 account_generation, u64 policy_generation);
/* Only a live SSH proof, once, to an exact direct child before any read/exec or
 * credential/namespace/session/path drift. Numeric pid is resolved and pinned
 * at the explicit parent call; later PID reuse cannot acquire the reference. */
int ba_reference_delegate_ssh_child(struct ba_reference_store *store, pid_t child_pid);
#endif

/* There is intentionally NO public mint/approve/verify shortcut. No userspace
 * result, target tuple, root uid or Bash executable identity establishes an
 * authenticated grant. The optional v2 internal issuer accepts only the opaque
 * result of the kernel-created native verifier channel; it is not a wire API.
 * Positive states below exist only in the dedicated KUnit translation unit. */
#ifdef BA_AUTHORITY_KUNIT
enum ba_reference_wipe { BA_REFERENCE_WIPE_GRANT, BA_REFERENCE_WIPE_STORE };
typedef void (*ba_reference_observer)(void *cookie, const void *data,
		size_t len, enum ba_reference_wipe kind);
void ba_reference_test_observer(struct ba_reference_store *store,
		ba_reference_observer observer, void *cookie);
void ba_reference_test_clock(struct ba_reference_store *store, u64 now);
int ba_reference_test_seed(struct ba_reference_store *store,
		const struct ba_reference_claim *claim, u64 lifetime,
		u8 reference[BA_REFERENCE_BYTES]);
#endif
#endif
