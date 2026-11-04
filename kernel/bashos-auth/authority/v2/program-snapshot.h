/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_PROGRAM_SNAPSHOT_H
#define BA_V2_PROGRAM_SNAPSHOT_H
#include "trusted-input.h"
/* Canonical native ELF target, root-owned immutable inode and trusted parents.
 * The digest is computed from the held inode; policy chooses whether it must
 * match a configured command digest. No digest alone authorizes execution. */
int ba_v2_program_open(const char *path, struct ba_v2_trusted_file *program);
#endif
