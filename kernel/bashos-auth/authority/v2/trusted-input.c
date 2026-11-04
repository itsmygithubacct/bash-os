// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/algapi.h>
#include <crypto/sha2.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "trusted-input.h"

/* Executable bytes are subsequently faulted from the held inode. Local inode
 * write denial is not a remote lease or a lock on a layered lower filesystem.
 * The reviewed qualification contract supports these direct local filesystems;
 * administrative raw-device/kernel mutation remains outside the trust boundary. */
bool ba_v2_local_executable_inode(const struct inode *inode)
{
	if (!inode || !inode->i_sb) return false;
	switch (inode->i_sb->s_magic) {
	case EXT4_SUPER_MAGIC: case XFS_SUPER_MAGIC: case BTRFS_SUPER_MAGIC: case TMPFS_MAGIC:
		return true;
	default: return false;
	}
}

/* Check the opened path, including mount roots and their mountpoint parents.
 * A writable or non-administrator-owned ancestor is not a trusted config
 * location even when its current contents happen to have the expected hash. */
bool ba_v2_trusted_parents(const struct path *opened)
{
	struct path walk = *opened;
	unsigned int depth;
	bool ok = false;
	path_get(&walk);
	for (depth = 0; depth < 256; depth++) {
		struct inode *inode;
		if (!IS_ROOT(walk.dentry)) {
			struct dentry *parent = dget_parent(walk.dentry);
			dput(walk.dentry);
			walk.dentry = parent;
		} else if (!follow_up(&walk)) {
			/* The last root was checked on the preceding iteration. */
			ok = depth != 0;
			break;
		}
		inode = d_inode(walk.dentry);
		if (!inode || !S_ISDIR(inode->i_mode) ||
		    !uid_eq(inode->i_uid, GLOBAL_ROOT_UID) ||
		    (inode->i_mode & (S_IWGRP | S_IWOTH))) break;
	}
	path_put(&walk);
	return ok;
}

/* First implementation supports the qualified native x86-64 guest only. */
static int native_static_elf(const void *bytes, size_t size)
{
	const Elf64_Ehdr *e = bytes;
	const Elf64_Phdr *p;
	size_t table_bytes, end;
	unsigned int i;
	bool text = false;

	if (size < sizeof(*e) || memcmp(e->e_ident, ELFMAG, SELFMAG) ||
	    e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_ident[EI_DATA] != ELFDATA2LSB ||
	    e->e_ident[EI_VERSION] != EV_CURRENT || e->e_version != EV_CURRENT ||
	    e->e_type != ET_EXEC || e->e_machine != EM_X86_64 ||
	    e->e_ehsize != sizeof(*e) || e->e_phentsize != sizeof(*p) ||
	    !e->e_phnum || e->e_phnum > 128 ||
	    check_mul_overflow((size_t)e->e_phnum, sizeof(*p), &table_bytes) ||
	    e->e_phoff > size || check_add_overflow((size_t)e->e_phoff, table_bytes, &end) ||
	    end > size) return -ENOEXEC;
	/* memcpy each entry: a signed image may still have an unaligned table. */
	for (i = 0; i < e->e_phnum; i++) {
		Elf64_Phdr ph;
		memcpy(&ph, (const u8 *)bytes + e->e_phoff + i * sizeof(ph), sizeof(ph));
		if (ph.p_type == PT_INTERP || ph.p_type == PT_DYNAMIC) return -ENOEXEC;
		if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) text = true;
	}
	return text ? 0 : -ENOEXEC;
}

void ba_v2_trusted_close(struct ba_v2_trusted_file *input)
{
	if (!input) return;
	if (input->bytes) kvfree_sensitive(input->bytes, input->size);
	if (input->file) {
		allow_write_access(input->file);
		fput(input->file);
	}
	memzero_explicit(input, sizeof(*input));
}

int ba_v2_trusted_open(const char *path, const u8 expected[32], size_t limit,
		bool executable, struct ba_v2_trusted_file *out)
{
	struct inode *inode;
	struct file *file;
	struct path opened;
	struct sha256_state hash;
	loff_t offset = 0, size;
	int rc;

	if (!out) return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!path || path[0] != '/' || !expected || !limit ||
	    !memchr_inv(expected, 0, 32)) return -EINVAL;
	rc = kern_path(path, LOOKUP_FOLLOW | LOOKUP_NO_SYMLINKS, &opened);
	if (rc) return rc;
	if (!ba_v2_trusted_parents(&opened)) { path_put(&opened); return -EPERM; }
	/* Inspect the resolved type before invoking open: a FIFO/device is never
	 * a snapshot, and opening it may block or have device-specific effects. */
	if (!S_ISREG(d_inode(opened.dentry)->i_mode) ||
	    (executable && !ba_v2_local_executable_inode(d_inode(opened.dentry)))) {
		path_put(&opened); return -EPERM;
	}
	file = dentry_open(&opened, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, current_cred());
	path_put(&opened);
	if (IS_ERR(file)) return PTR_ERR(file);
	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode) || !uid_eq(inode->i_uid, GLOBAL_ROOT_UID) ||
	    inode->i_nlink != 1 || (inode->i_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) ||
	    (executable && (!(inode->i_mode & S_IXUSR) || !ba_v2_local_executable_inode(inode)))) {
		rc = -EPERM;
		goto unpinned;
	}
	rc = deny_write_access(file);
	if (rc) goto unpinned;
	out->file = file;
	size = i_size_read(inode);
	if (size <= 0 || size > limit) { rc = -EFBIG; goto fail; }
	out->size = size;
	out->bytes = kvzalloc(out->size, GFP_KERNEL);
	if (!out->bytes) { rc = -ENOMEM; goto fail; }
	while (offset < size) {
		ssize_t n = kernel_read(file, (u8 *)out->bytes + offset, size - offset, &offset);
		if (n <= 0) { rc = n ? (int)n : -EIO; goto fail; }
	}
	sha256_init(&hash);
	sha256_update(&hash, out->bytes, out->size);
	sha256_final(&hash, out->digest);
	memzero_explicit(&hash, sizeof(hash));
	if (crypto_memneq(expected, out->digest, 32)) { rc = -EKEYREJECTED; goto fail; }
	if (executable && (rc = native_static_elf(out->bytes, out->size))) goto fail;
	return 0;
fail:
	ba_v2_trusted_close(out);
	return rc;
unpinned:
	fput(file);
	return rc;
}

static bool canonical_string(const char *s, size_t capacity, bool user)
{
	const char *end = memchr(s, 0, capacity);
	size_t i;
	if (!end || end == s || memchr_inv(end, 0, capacity - (end - s))) return false;
	if (!user) return true;
	for (i = 0; s + i < end; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
		      (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' || s[i] == '.'))
			return false;
	return true;
}

int ba_v2_accounts_open(const char *path, const u8 expected[32], struct ba_v2_accounts *accounts)
{
	const struct ba_v2_account_header *header;
	u32 i, j;
	int rc;
	if (!accounts) return -EINVAL;
	memset(accounts, 0, sizeof(*accounts));
	rc = ba_v2_trusted_open(path, expected, sizeof(*header) +
			BA_V2_MAX_ACCOUNTS * sizeof(struct ba_v2_account_record), false, &accounts->input);
	if (rc) return rc;
	header = accounts->input.bytes;
	if (accounts->input.size < sizeof(*header) || le32_to_cpu(header->magic) != BA_V2_MAGIC ||
	    le32_to_cpu(header->version) != BA_V2_VERSION ||
	    le32_to_cpu(header->size) != accounts->input.size || header->reserved ||
	    !le64_to_cpu(header->generation)) goto invalid;
	accounts->count = le32_to_cpu(header->count);
	if (!accounts->count || accounts->count > BA_V2_MAX_ACCOUNTS ||
	    accounts->input.size != sizeof(*header) + accounts->count * sizeof(*accounts->records))
		goto invalid;
	accounts->generation = le64_to_cpu(header->generation);
	accounts->records = (const void *)(header + 1);
	for (i = 0; i < accounts->count; i++) {
		const struct ba_v2_account_record *record = accounts->records + i;
		u32 encoding = le32_to_cpu(record->encoding);
		if (le32_to_cpu(record->uid) == U32_MAX || le32_to_cpu(record->gid) == U32_MAX ||
		    (encoding != BA_V2_ENCODING_STANDARD && encoding != BA_V2_ENCODING_LEGACY_HEX) ||
		    (le32_to_cpu(record->flags) & ~BA_V2_ACCOUNT_ENABLED) ||
		    !canonical_string(record->user, sizeof(record->user), true) ||
		    !canonical_string(record->phc, sizeof(record->phc), false)) goto invalid;
		for (j = 0; j < i; j++)
			if (!strcmp(record->user, accounts->records[j].user)) goto invalid;
	}
	return 0;
invalid:
	ba_v2_accounts_close(accounts);
	return -EINVAL;
}

void ba_v2_accounts_close(struct ba_v2_accounts *accounts)
{
	if (!accounts) return;
	ba_v2_trusted_close(&accounts->input);
	memzero_explicit(accounts, sizeof(*accounts));
}

const struct ba_v2_account_record *ba_v2_account_find(const struct ba_v2_accounts *accounts,
		const char *user)
{
	u32 i;
	if (!accounts || !user || strnlen(user, BA_V2_USER_BYTES) == BA_V2_USER_BYTES) return NULL;
	for (i = 0; i < accounts->count; i++)
		if (!strcmp(accounts->records[i].user, user) &&
		    (le32_to_cpu(accounts->records[i].flags) & BA_V2_ACCOUNT_ENABLED))
			return accounts->records + i;
	return NULL;
}
