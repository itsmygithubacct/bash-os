// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/sha2.h>
#include <linux/cred.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include "program-snapshot.h"

#define BA_V2_PROGRAM_LIMIT (64U * 1024U * 1024U)
#define BA_V2_PROGRAM_CHUNK 16384U

int ba_v2_program_open(const char *name, struct ba_v2_trusted_file *out)
{
	struct path path;
	struct file *file;
	struct inode *inode;
	struct sha256_state sha;
	Elf64_Ehdr header;
	loff_t offset = 0, size;
	u8 *buffer = NULL;
	bool first = true;
	int rc;
	if (!out) return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!name || name[0] != '/') return -EINVAL;
	rc = kern_path(name, LOOKUP_FOLLOW | LOOKUP_NO_SYMLINKS, &path);
	if (rc) return rc;
	if (!ba_v2_trusted_parents(&path)) { path_put(&path); return -EPERM; }
	/* Refuse special/remote objects before invoking their open operation.
	 * An executable-mode FIFO is not a program and must not block PREPARE
	 * waiting for a writer while the caller holds an authority context. */
	if (!S_ISREG(d_inode(path.dentry)->i_mode) || !ba_v2_local_executable_inode(d_inode(path.dentry))) {
		path_put(&path); return -EPERM;
	}
	rc = inode_permission(mnt_idmap(path.mnt), d_inode(path.dentry), MAY_EXEC);
	if (rc) { path_put(&path); return rc; }
	file = dentry_open(&path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, current_cred());
	path_put(&path);
	if (IS_ERR(file)) return PTR_ERR(file);
	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode) || !uid_eq(inode->i_uid, GLOBAL_ROOT_UID) ||
	    inode->i_nlink != 1 || !(inode->i_mode & S_IXUSR) ||
	    (inode->i_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) ||
	    !ba_v2_local_executable_inode(inode)) { rc = -EPERM; goto unpinned; }
	rc = deny_write_access(file);
	if (rc) goto unpinned;
	out->file = file;
	size = i_size_read(inode);
	if (size < sizeof(header) || size > BA_V2_PROGRAM_LIMIT) { rc = -EFBIG; goto failed; }
	out->size = size;
	buffer = kmalloc(BA_V2_PROGRAM_CHUNK, GFP_KERNEL);
	if (!buffer) { rc = -ENOMEM; goto failed; }
	sha256_init(&sha);
	while (offset < size) {
		size_t count = min_t(loff_t, size - offset, BA_V2_PROGRAM_CHUNK);
		ssize_t n = kernel_read(file, buffer, count, &offset);
		if (n <= 0) { rc = n ? (int)n : -EIO; goto hash_failed; }
		if (first) {
			if (n < sizeof(header)) { rc = -ENOEXEC; goto hash_failed; }
			memcpy(&header, buffer, sizeof(header));
			if (memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
			    header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_VERSION] != EV_CURRENT ||
			    header.e_machine != EM_X86_64 || header.e_version != EV_CURRENT ||
			    (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
			    header.e_ehsize != sizeof(header)) { rc = -ENOEXEC; goto hash_failed; }
			first = false;
		}
		sha256_update(&sha, buffer, n);
	}
	sha256_final(&sha, out->digest);
	memzero_explicit(&sha, sizeof(sha));
	kfree_sensitive(buffer);
	return 0;
hash_failed:
	memzero_explicit(&sha, sizeof(sha));
failed:
	kfree_sensitive(buffer);
	ba_v2_trusted_close(out);
	return rc;
unpinned:
	fput(file);
	return rc;
}
