// SPDX-License-Identifier: GPL-2.0-only
#include <linux/err.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/proc_ns.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/user_namespace.h>
#include <linux/utsname.h>
#include "request-binding.h"

static bool request_string(const char *s, size_t size)
{
	const char *nul = memchr(s, 0, size);
	return nul && !memchr_inv(nul, 0, size - (nul - s));
}

void ba_v2_bound_free(struct ba_v2_bound_request *bound)
{
	unsigned int i;
	if (!bound) return;
	ba_v2_trusted_close(&bound->program);
	if (bound->cwd) fput(bound->cwd);
	if (bound->root) fput(bound->root);
	for (i = 0; i < 3; i++) if (bound->stdio[i]) fput(bound->stdio[i]);
	if (bound->tty) tty_kref_put(bound->tty);
	ba_reference_actor_release(&bound->actor);
	ba_request_snapshot_free(bound->request);
	kvfree_sensitive(bound, sizeof(*bound));
}

bool ba_v2_bound_matches(const struct ba_v2_bound_request *bound)
{
	struct tty_struct *tty;
	bool same;
	if (!bound || !ba_reference_actor_matches(&bound->actor)) return false;
	if (strcmp(bound->hostname, utsname()->nodename)) return false;
	tty = get_current_tty();
	same = tty == bound->tty;
	if (tty) tty_kref_put(tty);
	return same;
}

static int bound_paths(struct ba_v2_bound_request *bound, const struct cred *admin)
{
	struct path claimed;
	const struct cred *previous;
	struct file *file;
	int rc;
	/* Match the client's spelling to the real current directory before any
 * authority filesystem access. A hash of an arbitrary claimed cwd is not a pin. */
	rc = kern_path(bound->request->wire.cwd, LOOKUP_DIRECTORY | LOOKUP_NO_SYMLINKS, &claimed);
	if (rc) return rc;
	if (!path_equal(&claimed, &bound->actor.cwd)) rc = -EACCES;
	path_put(&claimed);
	if (rc) return rc;
	previous = override_creds(admin);
	file = dentry_open(&bound->actor.cwd, O_PATH | O_CLOEXEC, current_cred());
	if (IS_ERR(file)) { rc = PTR_ERR(file); goto done; }
	bound->cwd = file;
	file = dentry_open(&bound->actor.root, O_PATH | O_CLOEXEC, current_cred());
	if (IS_ERR(file)) { rc = PTR_ERR(file); goto done; }
	bound->root = file;
	if (!bound->query.validate && !bound->query.edit)
		rc = ba_v2_program_open(bound->argv[0], &bound->program);
done:
	revert_creds(previous);
	return rc;
}

int ba_v2_bound_capture(struct ba_request_snapshot *request,
		const struct ba_v2_accounts *accounts, const struct ba_v2_groups *groups,
		const struct ba_v2_policy *policy, const struct cred *admin,
		struct ba_v2_bound_request **out)
{
	struct ba_v2_bound_request *bound;
	const struct bashos_auth_privcmd *r;
	u32 i, offset = 0;
	int rc = -EINVAL;
	if (!out) { ba_request_snapshot_free(request); return -EINVAL; }
	*out = NULL;
	if (!request || !admin || admin->user_ns != &init_user_ns) goto no_bound;
	r = &request->wire;
	if (memchr_inv(r->auth_token, 0, sizeof(r->auth_token)) ||
	    !request_string(r->caller_user, sizeof(r->caller_user)) ||
	    !request_string(r->target_user, sizeof(r->target_user)) ||
	    !request_string(r->cwd, sizeof(r->cwd))) goto no_bound;
	bound = kvzalloc(sizeof(*bound), GFP_KERNEL);
	if (!bound) { rc = -ENOMEM; goto no_bound; }
	bound->request = request;
	rc = ba_reference_actor_capture(&bound->actor);
	if (rc) goto failed;
	/* The native executor forks in the captured active namespaces. setns for
 * time replaces both active and child-time identities; split tuples are an
 * unsupported request, never an implicit cross-namespace handoff. */
	if (get_proc_ns(file_inode(bound->actor.namespaces[3])) !=
	    get_proc_ns(file_inode(bound->actor.namespaces[8])) ||
	    get_proc_ns(file_inode(bound->actor.namespaces[5])) !=
	    get_proc_ns(file_inode(bound->actor.namespaces[6]))) { rc = -EOPNOTSUPP; goto failed; }
	rc = ba_v2_identity_bind(accounts, groups, bound->actor.cred, r, &bound->identities);
	if (rc) goto failed;
	bound->tty = get_current_tty();
	strscpy(bound->hostname, utsname()->nodename, sizeof(bound->hostname));
	for (i = 0; i < r->argc; i++) {
		bound->argv[i] = (const char *)request->blobs + offset;
		offset += strlen(bound->argv[i]) + 1;
	}
	for (i = 0; i < r->envc; i++) {
		bound->env[i] = (const char *)request->blobs + offset;
		offset += strlen(bound->env[i]) + 1;
	}
	bound->query.caller = &bound->identities.caller;
	bound->query.target = &bound->identities.target;
	bound->query.target_gid = bound->identities.target_gid;
	bound->query.target_group = bound->identities.target_group;
	bound->query.host = bound->hostname;
	bound->query.has_tty = bound->tty != NULL;
	bound->query.edit = r->mode == BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT;
	bound->query.validate = r->mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE ||
		r->mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP;
	bound->query.command = bound->query.validate ? "/" : bound->argv[0];
	bound->query.argc = r->argc;
	bound->query.argv = bound->argv;
	if (!bound->query.command || bound->query.command[0] != '/') { rc = -EINVAL; goto failed; }
	/* The versioned audit schema carries a complete command path in 256
	 * bytes. Refuse unrepresentable paths instead of logging a prefix. */
	if (strlen(bound->query.command) >= BASHOS_AUTH_PATH_BYTES) { rc = -ENAMETOOLONG; goto failed; }
	if (bound->query.edit) for (i = 0; i < r->argc; i++) {
		if (bound->argv[i][0] != '/' || strlen(bound->argv[i]) >= BASHOS_AUTH_PATH_BYTES) {
			rc = -ENAMETOOLONG; goto failed;
		}
	}
	rc = bound_paths(bound, admin);
	if (rc) goto failed;
	if (bound->program.file) {
		memcpy(bound->query.executable_sha256, bound->program.digest, 32);
		bound->query.digest_valid = 1;
	}
	rc = ba_v2_policy_evaluate(policy, &bound->query, &bound->decision);
	if (rc) goto failed;
	/* ALL may authorize each edit target, but no single allowed prefix can
 * authorize a later target. Every target's tags participate in auth policy. */
	if (bound->query.edit && bound->decision.allow) {
		struct ba_policy_decision *next = kvzalloc(sizeof(*next), GFP_KERNEL);
		if (!next) { rc = -ENOMEM; goto failed; }
		for (i = 1; i < r->argc; i++) {
			bound->query.command = bound->argv[i];
			rc = ba_v2_policy_evaluate(policy, &bound->query, next);
			if (rc || !next->allow) { bound->decision.allow = 0; break; }
			bound->decision.nopasswd &= next->nopasswd;
			bound->decision.timestamp_seconds = min(bound->decision.timestamp_seconds, next->timestamp_seconds);
		}
		kvfree_sensitive(next, sizeof(*next));
		bound->query.command = bound->argv[0];
		if (rc) goto failed;
	}
	if (!ba_v2_bound_matches(bound)) { rc = -EPERM; goto failed; }
	if (bound->decision.allow && !bound->query.validate) {
		for (i = 0; i < 3; i++) {
			bound->stdio[i] = fget(i);
			if (!bound->stdio[i] || !(bound->stdio[i]->f_mode & (i ? FMODE_WRITE : FMODE_READ))) {
				rc = -EBADF; goto failed;
			}
		}
	}
	*out = bound;
	return 0;
failed:
	ba_v2_bound_free(bound);
	return rc;
no_bound:
	ba_request_snapshot_free(request);
	return rc;
}
