// SPDX-License-Identifier: GPL-2.0-only
/* Bounded safeedit object lifecycle. No public ioctl, credential grant, native
 * helper, shell invocation or policy bypass is provided by this component. */
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/ktime.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/overflow.h>
#include <linux/random.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/xattr.h>
#include "safeedit.h"

#define EDIT_CHUNK 16384U
struct edit_target {
	char name[BASHOS_AUTH_PATH_BYTES], leaf[BASHOS_AUTH_PATH_BYTES];
	struct path parent;
	struct file *original, *directory;
	struct timespec64 ctime;
	loff_t size;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	u8 digest[32];
	bool denied;
};
struct edit_upload {
	struct file *file;
	loff_t size;
	u8 digest[32];
	bool denied;
};
struct ba_v2_edit_session {
	struct ba_reference_actor actor;
	u64 deadline;
	u32 count;
	u8 request_digest[32];
	u8 transaction_digest[32];
	bool sealed;
	struct edit_target targets[BA_V2_EDIT_MAX_TARGETS];
	struct edit_upload uploads[BA_V2_EDIT_MAX_TARGETS];
};
struct edit_stage {
	struct path path;
	struct file *file;
	bool created, denied, mount_write;
};

static bool edit_administrator(const struct cred *cred)
{
	return cred && cred->user_ns == &init_user_ns && uid_eq(cred->euid, GLOBAL_ROOT_UID);
}

static bool canonical_target(const char *name)
{
	const char *part, *p;
	size_t length;
	if (!name || name[0] != '/') return false;
	length = strnlen(name, BASHOS_AUTH_PATH_BYTES);
	if (length < 2 || length >= BASHOS_AUTH_PATH_BYTES || name[length - 1] == '/') return false;
	part = name + 1;
	for (p = part; ; p++) {
		if (*p && (unsigned char)*p < 32) return false;
		if (!*p || *p == '/') {
			size_t n = p - part;
			if (!n || (n == 1 && part[0] == '.') || (n == 2 && part[0] == '.' && part[1] == '.')) return false;
			if (!*p) break;
			part = p + 1;
		}
	}
	return true;
}

static int no_xattrs(struct dentry *dentry)
{
	ssize_t size = vfs_listxattr(dentry, NULL, 0);
	if (size == -EOPNOTSUPP) return 0;
	return size < 0 ? (int)size : size ? -EOPNOTSUPP : 0;
}

static int ordinary_file(struct file *file, kuid_t owner, bool copy)
{
	struct inode *inode;
	loff_t size;
	if (!file) return -EBADF;
	inode = file_inode(file); size = i_size_read(inode);
	if (!S_ISREG(inode->i_mode) || inode->i_nlink != 1 || !uid_eq(inode->i_uid, owner) ||
	    (inode->i_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH)) ||
	    (copy && (inode->i_mode & 0777) != 0600) ||
	    IS_IMMUTABLE(inode) || IS_APPEND(inode) || IS_SWAPFILE(inode) ||
	    is_idmapped_mnt(file->f_path.mnt) || !ba_v2_local_executable_inode(inode) ||
	    (file->f_flags & (O_APPEND | O_PATH | O_DIRECT))) return -EPERM;
	if (size < 0 || size > BA_V2_EDIT_MAX_BYTES) return -EFBIG;
	return no_xattrs(file->f_path.dentry);
}

static int transfer(struct file *from, struct file *to, loff_t size, u8 digest[32], u8 *buffer)
{
	struct sha256_state hash;
	loff_t input = 0, output = 0;
	int rc = 0;
	sha256_init(&hash);
	while (input < size) {
		size_t want = min_t(loff_t, size - input, EDIT_CHUNK);
		ssize_t got = kernel_read(from, buffer, want, &input), sent = 0;
		if (got <= 0) { rc = got ? (int)got : -EIO; goto done; }
		sha256_update(&hash, buffer, got);
		while (to && sent < got) {
			ssize_t n = kernel_write(to, buffer + sent, got - sent, &output);
			if (n <= 0) { rc = n ? (int)n : -EIO; goto done; }
			sent += n;
		}
	}
	if (i_size_read(file_inode(from)) != size || (to && i_size_read(file_inode(to)) != size)) { rc = -ESTALE; goto done; }
	sha256_final(&hash, digest);
done:
	memzero_explicit(&hash, sizeof(hash)); memzero_explicit(buffer, EDIT_CHUNK);
	return rc;
}

static void target_drop_denial(struct edit_target *target)
{
	if (target->denied) allow_write_access(target->original);
	target->denied = false;
}

void ba_v2_edit_close(struct ba_v2_edit_session *session)
{
	u32 i;
	if (!session) return;
	for (i = 0; i < session->count; i++) {
		struct edit_target *t = &session->targets[i];
		struct edit_upload *upload = &session->uploads[i];
		if (upload->denied) allow_write_access(upload->file);
		if (upload->file) fput(upload->file);
		target_drop_denial(t);
		if (t->original) fput(t->original);
		if (t->directory) fput(t->directory);
		if (t->parent.dentry) path_put(&t->parent);
	}
	ba_reference_actor_release(&session->actor);
	kvfree_sensitive(session, sizeof(*session));
}

static int open_target(struct edit_target *t, const char *name,
		const struct ba_v2_bound_request *bound, u8 *buffer)
{
	struct path path, parent;
	struct inode *inode;
	struct file *file;
	char *directory, *last;
	int rc;
	if (!canonical_target(name)) return -EINVAL;
	directory = kstrdup(name, GFP_KERNEL);
	if (!directory) return -ENOMEM;
	last = strrchr(directory, '/'); strscpy(t->leaf, last + 1, sizeof(t->leaf));
	if (last == directory) last[1] = 0; else *last = 0;
	rc = kern_path(directory, LOOKUP_DIRECTORY | LOOKUP_NO_SYMLINKS, &parent);
	kfree_sensitive(directory);
	if (rc) return rc;
	t->parent = parent;
	rc = kern_path(name, LOOKUP_NO_SYMLINKS, &path);
	if (rc) return rc;
	/* Mountpoint substitutions, disconnected parents, symlink components and
	 * non-root-writable ancestors cannot redefine the authorized basename. */
	if (path.mnt != parent.mnt || path.dentry->d_parent != parent.dentry ||
	    d_unhashed(path.dentry) || is_idmapped_mnt(path.mnt) ||
	    !path_is_under(&path, &bound->actor.root) || !ba_v2_trusted_parents(&path) ||
	    !S_ISREG(d_inode(path.dentry)->i_mode) || !ba_v2_local_executable_inode(d_inode(path.dentry))) {
		path_put(&path); return -EPERM;
	}
	file = dentry_open(&path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, current_cred());
	path_put(&path);
	if (IS_ERR(file)) return PTR_ERR(file);
	t->original = file;
	rc = ordinary_file(file, GLOBAL_ROOT_UID, false);
	if (rc) return rc;
	/* This first adapter edits protected administrator-owned ordinary files.
	 * Non-root owned targets are refused before any copy; no metadata race
	 * with an untrusted inode owner is treated as a supported overwrite. */
	rc = deny_write_access(file);
	if (rc) return rc;
	t->denied = true;
	rc = ordinary_file(file, GLOBAL_ROOT_UID, false);
	if (rc) return rc;
	inode = file_inode(file);
	t->size = i_size_read(inode); t->uid = inode->i_uid; t->gid = inode->i_gid;
	t->mode = inode->i_mode; t->ctime = inode_get_ctime(inode);
	rc = transfer(file, NULL, t->size, t->digest, buffer);
	if (rc) return rc;
	file = dentry_open(&parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC, current_cred());
	if (IS_ERR(file)) return PTR_ERR(file);
	t->directory = file;
	strscpy(t->name, name, sizeof(t->name));
	return 0;
}

static int check_target(struct edit_target *t, u8 *buffer)
{
	struct path now;
	struct inode *inode = file_inode(t->original);
	struct timespec64 ctime;
	u8 digest[32];
	int rc = kern_path(t->name, LOOKUP_NO_SYMLINKS, &now);
	if (rc) return rc;
	if (!path_equal(&now, &t->original->f_path) || now.dentry->d_parent != t->parent.dentry ||
	    !ba_v2_trusted_parents(&now)) rc = -ESTALE;
	path_put(&now);
	if (rc) return rc;
	rc = ordinary_file(t->original, GLOBAL_ROOT_UID, false);
	if (rc) return rc;
	ctime = inode_get_ctime(inode);
	if (i_size_read(inode) != t->size || inode->i_mode != t->mode ||
	    !uid_eq(inode->i_uid, t->uid) || !gid_eq(inode->i_gid, t->gid) ||
	    !timespec64_equal(&t->ctime, &ctime)) return -ESTALE;
	rc = transfer(t->original, NULL, t->size, digest, buffer);
	if (!rc && crypto_memneq(digest, t->digest, 32)) rc = -ESTALE;
	memzero_explicit(digest, sizeof(digest));
	return rc;
}

int ba_v2_edit_open(const struct ba_v2_bound_request *bound, const struct cred *admin,
		struct file * const *copies, u32 count, struct ba_v2_edit_session **out)
{
	struct ba_v2_edit_session *session = NULL;
	const struct cred *previous;
	u8 *buffer, digest[32];
	u32 i, j;
	int rc = -EINVAL;
	if (!out) return -EINVAL;
	*out = NULL;
	if (!bound || !bound->request || !bound->query.edit || !bound->decision.allow ||
	    bound->identities.target.uid != 0 || !copies || !count || count > BA_V2_EDIT_MAX_TARGETS ||
	    bound->request->wire.argc != count || !edit_administrator(admin) || !ba_v2_bound_matches(bound)) return -EPERM;
	buffer = kmalloc(EDIT_CHUNK, GFP_KERNEL);
	if (!buffer) return -ENOMEM;
	session = kvzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) { rc = -ENOMEM; goto done; }
	session->count = count;
	rc = ba_reference_actor_capture(&session->actor);
	if (rc) goto done;
	if (check_add_overflow(ktime_get_boottime_ns(), BA_V2_EDIT_SESSION_NS, &session->deadline)) { rc = -EOVERFLOW; goto done; }
	memcpy(session->request_digest, bound->request->digest, 32);
	previous = override_creds(admin);
	/* Both complete target and destination vectors are preflighted before
	 * writing the first caller-owned copy. No privileged temp path is returned. */
	for (i = 0; i < count; i++) {
		rc = open_target(&session->targets[i], bound->argv[i], bound, buffer);
		if (rc) goto restored;
		rc = ordinary_file(copies[i], session->actor.cred->uid, true);
		if (rc) goto restored;
		if ((copies[i]->f_mode & (FMODE_READ | FMODE_WRITE)) != (FMODE_READ | FMODE_WRITE) ||
		    i_size_read(file_inode(copies[i]))) { rc = -EINVAL; goto restored; }
		for (j = 0; j < i; j++) {
			if (file_inode(session->targets[j].original) == file_inode(session->targets[i].original) ||
			    file_inode(copies[j]) == file_inode(copies[i])) { rc = -EEXIST; goto restored; }
		}
		for (j = 0; j <= i; j++) {
			if (file_inode(copies[j]) == file_inode(session->targets[i].original) ||
			    file_inode(copies[i]) == file_inode(session->targets[j].original)) { rc = -EINVAL; goto restored; }
		}
	}
	for (i = 0; i < count; i++) {
		rc = transfer(session->targets[i].original, copies[i], session->targets[i].size, digest, buffer);
		if (!rc && crypto_memneq(digest, session->targets[i].digest, 32)) rc = -ESTALE;
		if (!rc) rc = vfs_fsync(copies[i], 0);
		if (rc) goto restored;
	}
restored:
	revert_creds(previous);
	if (!rc && (!ba_v2_bound_matches(bound) || !ba_reference_actor_matches(&session->actor))) rc = -EPERM;
	if (!rc) {
		for (i = 0; i < count; i++) target_drop_denial(&session->targets[i]);
		*out = session; session = NULL;
	}
done:
	ba_v2_edit_close(session); kfree_sensitive(buffer); memzero_explicit(digest, sizeof(digest));
	return rc;
}

int ba_v2_edit_bound_digest(const struct ba_v2_edit_session *session,
		const u8 original_request_digest[32], u8 sealed_digest[32])
{
	if (!session || !session->sealed || !original_request_digest || !sealed_digest ||
	    crypto_memneq(original_request_digest, session->request_digest, 32) ||
	    !ba_reference_actor_matches(&session->actor)) return -EKEYREJECTED;
	if (ktime_get_boottime_ns() >= session->deadline) return -EKEYEXPIRED;
	memcpy(sealed_digest, session->transaction_digest, 32);
	return 0;
}

int ba_v2_edit_seal(struct ba_v2_edit_session *session, const struct cred *admin,
		const u8 original_request_digest[32], struct file * const *copies, u32 count,
		struct ba_v2_edit_result *result)
{
	const struct cred *previous = NULL;
	struct sha256_state hash;
	u8 *buffer = NULL;
	u32 i = U32_MAX, j;
	__le32 number;
	int rc = -EINVAL;
	if (!result) return -EINVAL;
	memset(result, 0, sizeof(*result)); result->failed_index = U32_MAX;
	if (!session || session->sealed || !original_request_digest || !copies || !count ||
	    count != session->count || count > BA_V2_EDIT_MAX_TARGETS || !edit_administrator(admin) ||
	    crypto_memneq(original_request_digest, session->request_digest, 32) ||
	    !ba_reference_actor_matches(&session->actor)) goto done;
	if (ktime_get_boottime_ns() >= session->deadline) { rc = -EKEYEXPIRED; goto done; }
	result->count = count;
	buffer = kmalloc(EDIT_CHUNK, GFP_KERNEL);
	if (!buffer) { rc = -ENOMEM; goto done; }
	previous = override_creds(admin);
	for (i = 0; i < count; i++) {
		struct edit_upload *upload = &session->uploads[i];
		if (!copies[i]) { rc = -EBADF; goto done; }
		upload->file = get_file(copies[i]);
		rc = ordinary_file(upload->file, session->actor.cred->uid, true);
		if (rc) goto done;
		if (!(upload->file->f_mode & FMODE_READ) || (upload->file->f_mode & FMODE_WRITE)) { rc = -EBADF; goto done; }
		for (j = 0; j < count; j++)
			if (file_inode(upload->file) == file_inode(session->targets[j].original)) { rc = -EINVAL; goto done; }
		for (j = 0; j < i; j++)
			if (file_inode(upload->file) == file_inode(session->uploads[j].file)) { rc = -EEXIST; goto done; }
		rc = deny_write_access(upload->file);
		if (rc) goto done;
		upload->denied = true;
		rc = ordinary_file(upload->file, session->actor.cred->uid, true);
		if (rc) goto done;
		upload->size = i_size_read(file_inode(upload->file));
		rc = transfer(upload->file, NULL, upload->size, upload->digest, buffer);
		if (rc) goto done;
	}
	revert_creds(previous); previous = NULL;
	if (!ba_reference_actor_matches(&session->actor)) { rc = -EPERM; goto done; }
	sha256_init(&hash);
	sha256_update(&hash, (const u8 *)"bashos-safeedit-v2", 18);
	sha256_update(&hash, session->request_digest, 32);
	number = cpu_to_le32(count); sha256_update(&hash, (u8 *)&number, sizeof(number));
	for (i = 0; i < count; i++) {
		__le64 size = cpu_to_le64(session->uploads[i].size);
		sha256_update(&hash, session->targets[i].digest, 32);
		sha256_update(&hash, session->uploads[i].digest, 32);
		sha256_update(&hash, (u8 *)&size, sizeof(size));
	}
	sha256_final(&hash, session->transaction_digest); memzero_explicit(&hash, sizeof(hash));
	memcpy(result->transaction_digest, session->transaction_digest, 32);
	session->sealed = true; rc = 0;
done:
	if (previous) revert_creds(previous);
	if (rc && i < count) result->failed_index = i;
	result->error = rc < 0 ? -rc : 0;
	kfree_sensitive(buffer);
	return rc;
}

static int stage_cleanup(struct edit_stage *stage, const struct edit_target *target)
{
	int rc = 0;
	if (stage->created) {
		struct inode *directory = d_inode(target->parent.dentry);
		inode_lock_nested(directory, I_MUTEX_PARENT);
		if (stage->path.dentry->d_parent != target->parent.dentry ||
		    d_unhashed(stage->path.dentry) || !d_is_reg(stage->path.dentry)) rc = -ESTALE;
		else {
			rc = security_path_unlink(&target->parent, stage->path.dentry);
			if (!rc) rc = vfs_unlink(mnt_idmap(target->parent.mnt), directory, stage->path.dentry, NULL);
		}
		inode_unlock(directory);
	}
	if (stage->denied) allow_write_access(stage->file);
	if (stage->file) fput(stage->file);
	if (stage->path.dentry) dput(stage->path.dentry);
	if (stage->mount_write) mnt_drop_write(target->parent.mnt);
	memzero_explicit(stage, sizeof(*stage));
	return rc;
}

static int stage_create(struct edit_stage *stage, const struct edit_target *target,
		const struct edit_upload *upload, u8 *buffer)
{
	struct inode *directory = d_inode(target->parent.dentry);
	struct dentry *dentry = NULL;
	struct file *writer = NULL, *reader;
	struct iattr attributes = {0};
	u8 random[16], digest[32];
	char name[64];
	int rc, tries;
	rc = mnt_want_write(target->parent.mnt);
	if (rc) return rc;
	stage->mount_write = true;
	inode_lock_nested(directory, I_MUTEX_PARENT);
	for (tries = 0; tries < 8; tries++) {
		get_random_bytes(random, sizeof(random));
		snprintf(name, sizeof(name), ".bashos-v2-edit-%*phN", (int)sizeof(random), random);
		dentry = lookup_one(mnt_idmap(target->parent.mnt), name, target->parent.dentry, strlen(name));
		if (IS_ERR(dentry)) { rc = PTR_ERR(dentry); dentry = NULL; goto unlock; }
		if (!d_really_is_positive(dentry)) break;
		dput(dentry); dentry = NULL;
	}
	if (!dentry) { rc = -EEXIST; goto unlock; }
	rc = security_path_mknod(&target->parent, dentry, S_IFREG | 0600, 0);
	if (!rc) rc = vfs_create(mnt_idmap(target->parent.mnt), directory, dentry, 0600, true);
	if (!rc) {
		stage->path = (struct path){.mnt = target->parent.mnt, .dentry = dentry};
		stage->created = true; dentry = NULL;
	}
unlock:
	if (dentry) dput(dentry);
	inode_unlock(directory); memzero_explicit(random, sizeof(random));
	if (rc) return rc;
	writer = dentry_open(&stage->path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW, current_cred());
	if (IS_ERR(writer)) return PTR_ERR(writer);
	rc = ordinary_file(writer, GLOBAL_ROOT_UID, true);
	if (!rc) rc = transfer(upload->file, writer, upload->size, digest, buffer);
	if (!rc && crypto_memneq(digest, upload->digest, 32)) rc = -ESTALE;
	if (!rc) rc = vfs_fsync(writer, 0);
	/* This private, locally created regular-file writer has never entered a
	 * task fd table. Release its write access synchronously, with no VFS lock
	 * held, before opening the read-only stage and denying further writes.
	 * Ordinary fput() defers final release until ioctl return in this task. */
	__fput_sync(writer); memzero_explicit(digest, sizeof(digest));
	if (rc) return rc;
	reader = dentry_open(&stage->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, current_cred());
	if (IS_ERR(reader)) return PTR_ERR(reader);
	stage->file = reader;
	rc = deny_write_access(reader);
	if (rc) return rc;
	stage->denied = true;
	attributes.ia_valid = ATTR_MODE | ATTR_UID | ATTR_GID;
	attributes.ia_mode = target->mode; attributes.ia_uid = target->uid; attributes.ia_gid = target->gid;
	inode_lock(file_inode(reader));
	rc = notify_change(mnt_idmap(stage->path.mnt), stage->path.dentry, &attributes, NULL);
	inode_unlock(file_inode(reader));
	if (!rc) rc = no_xattrs(stage->path.dentry);
	if (!rc) rc = vfs_fsync(reader, 0);
	if (!rc) rc = vfs_fsync(target->directory, 0);
	return rc;
}

static int stage_commit(struct edit_stage *stage, const struct edit_target *target)
{
	struct inode *directory = d_inode(target->parent.dentry);
	struct dentry *destination;
	struct renamedata rename = {.flags = 0};
	int rc;
	inode_lock_nested(directory, I_MUTEX_PARENT);
	destination = lookup_one(mnt_idmap(target->parent.mnt), target->leaf,
		target->parent.dentry, strlen(target->leaf));
	if (IS_ERR(destination)) { rc = PTR_ERR(destination); goto unlock; }
	if (destination != target->original->f_path.dentry || d_inode(destination) != file_inode(target->original) ||
	    stage->path.dentry->d_parent != target->parent.dentry || d_unhashed(stage->path.dentry) ||
	    d_inode(stage->path.dentry) != file_inode(stage->file)) { rc = -ESTALE; goto put; }
	/* vfs_rename locks both non-directory children in inode order itself.
	 * Only the common parent is held here; no double child-inode locking. */
	rc = security_path_rename(&target->parent, stage->path.dentry, &target->parent, destination, 0);
	if (rc) goto put;
	rename.old_mnt_idmap = rename.new_mnt_idmap = mnt_idmap(target->parent.mnt);
	rename.old_dir = rename.new_dir = directory;
	rename.old_dentry = stage->path.dentry; rename.new_dentry = destination;
	rc = vfs_rename(&rename);
	if (!rc) stage->created = false;
put:
	dput(destination);
unlock:
	inode_unlock(directory);
	return rc;
}

int ba_v2_edit_commit(struct ba_v2_edit_session **owner,
		const struct ba_v2_bound_request *fresh, const struct cred *admin,
		struct file * const *copies, u32 count, ba_v2_edit_intent intent, void *cookie,
		struct ba_v2_edit_result *result)
{
	struct ba_v2_edit_session *session = owner ? *owner : NULL;
	struct edit_stage *stages = NULL;
	const struct cred *previous = NULL;
	u8 *buffer = NULL;
	u32 i = U32_MAX, j;
	int rc = -EINVAL;
	if (owner) *owner = NULL;
	if (!result) { ba_v2_edit_close(session); return -EINVAL; }
	memset(result, 0, sizeof(*result)); result->failed_index = U32_MAX;
	if (!session || !session->sealed || !fresh || !fresh->request || !intent || !copies || !count ||
	    count != session->count || count > BA_V2_EDIT_MAX_TARGETS || fresh->request->wire.argc != count ||
	    !fresh->query.edit || !fresh->decision.allow || fresh->identities.target.uid != 0 ||
	    crypto_memneq(fresh->request->digest, session->request_digest, 32) ||
	    !edit_administrator(admin) || !ba_reference_actor_matches(&session->actor) || !ba_v2_bound_matches(fresh)) goto done;
	result->count = count;
	memcpy(result->transaction_digest, session->transaction_digest, 32);
	if (ktime_get_boottime_ns() >= session->deadline) { rc = -EKEYEXPIRED; goto done; }
	stages = kcalloc(count, sizeof(*stages), GFP_KERNEL);
	buffer = kmalloc(EDIT_CHUNK, GFP_KERNEL);
	if (!stages || !buffer) { rc = -ENOMEM; goto done; }
	previous = override_creds(admin);
	/* Upload bytes were already pinned before fresh verification. Reject fd
	 * substitution and revalidate every original before any staging rename. */
	for (i = 0; i < count; i++) {
		struct edit_upload *upload = &session->uploads[i];
		if (copies[i] != upload->file || !upload->denied) { rc = -EKEYREJECTED; goto done; }
		rc = ordinary_file(upload->file, session->actor.cred->uid, true);
		if (rc) goto done;
		if (i_size_read(file_inode(upload->file)) != upload->size) { rc = -ESTALE; goto done; }
		rc = deny_write_access(session->targets[i].original);
		if (rc) goto done;
		session->targets[i].denied = true;
		rc = check_target(&session->targets[i], buffer);
		if (rc) goto done;
	}
	for (i = 0; i < count; i++) {
		rc = stage_create(&stages[i], &session->targets[i], &session->uploads[i], buffer);
		if (rc) goto done;
	}
	for (i = 0; i < count; i++) {
		revert_creds(previous); previous = NULL;
		if (!ba_reference_actor_matches(&session->actor) || !ba_v2_bound_matches(fresh) ||
		    ktime_get_boottime_ns() >= session->deadline) { rc = -EKEYREVOKED; goto done; }
		rc = intent(cookie, i, result->committed, result->transaction_digest);
		if (rc) goto done;
		previous = override_creds(admin);
		rc = check_target(&session->targets[i], buffer);
		if (rc) goto done;
		rc = stage_commit(&stages[i], &session->targets[i]);
		if (rc) goto done;
		result->committed++;
		/* A durability error after rename still reports that committed file.
		 * It can never be described as an untouched target or rollback. */
		rc = vfs_fsync(session->targets[i].directory, 0);
		if (rc) goto done;
	}
	rc = 0;
done:
	if (rc && i < count) result->failed_index = i;
	if (stages) {
		if (!previous) previous = override_creds(admin);
		for (j = 0; j < count; j++) {
			int cleanup = stage_cleanup(&stages[j], &session->targets[j]);
			if (cleanup && !result->cleanup_error) result->cleanup_error = -cleanup;
		}
	}
	if (previous) revert_creds(previous);
	if (!rc && result->cleanup_error) rc = -(int)result->cleanup_error;
	result->error = rc < 0 ? -rc : 0;
	kfree_sensitive(stages); kfree_sensitive(buffer);
	ba_v2_edit_close(session);
	return rc;
}
