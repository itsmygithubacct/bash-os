/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_TRUSTED_INPUT_H
#define BA_V2_TRUSTED_INPUT_H
#include <linux/fs.h>
#include "protocol.h"

struct ba_v2_trusted_file {
	struct file *file;
	void *bytes;
	size_t size;
	u8 digest[32];
};
struct ba_v2_accounts {
	struct ba_v2_trusted_file input;
	u64 generation;
	u32 count;
	const struct ba_v2_account_record *records;
};

/* Caller supplies an administrator-established pin, never an ioctl field. The
 * exact opened inode is held against writes through all dependent operations. */
int ba_v2_trusted_open(const char *path, const u8 expected[32], size_t limit,
		bool executable, struct ba_v2_trusted_file *out);
void ba_v2_trusted_close(struct ba_v2_trusted_file *input);
bool ba_v2_trusted_parents(const struct path *opened);
bool ba_v2_local_executable_inode(const struct inode *inode);
int ba_v2_accounts_open(const char *path, const u8 expected[32],
		struct ba_v2_accounts *accounts);
void ba_v2_accounts_close(struct ba_v2_accounts *accounts);
const struct ba_v2_account_record *ba_v2_account_find(
		const struct ba_v2_accounts *accounts, const char *user);
#endif
