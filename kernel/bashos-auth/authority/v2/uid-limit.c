// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bug.h>
#include <linux/errno.h>
#include "uid-limit.h"

static struct ba_v2_uid_count *uid_row(struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid)
{
	u32 i;
	for (i = 0; i < capacity; i++)
		if (rows[i].count && uid_eq(rows[i].uid, uid)) return &rows[i];
	return NULL;
}

static struct ba_v2_uid_count *uid_unused_row(struct ba_v2_uid_count *rows, u32 capacity)
{
	u32 i;
	for (i = 0; i < capacity; i++)
		if (!rows[i].count) return &rows[i];
	return NULL;
}

int ba_v2_uid_charge(struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid,
		u32 amount, u32 limit)
{
	struct ba_v2_uid_count *row;
	u32 held;
	if (!rows || !uid_valid(uid) || !amount) return -EINVAL;
	row = uid_row(rows, capacity, uid);
	held = row ? row->count : 0;
	if (held > limit || amount > limit - held) return -EDQUOT;
	if (!row) {
		row = uid_unused_row(rows, capacity);
		if (!row) return -ENOSPC;
		row->uid = uid;
	}
	row->count += amount;
	return 0;
}

void ba_v2_uid_uncharge(struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid,
		u32 amount)
{
	struct ba_v2_uid_count *row = rows ? uid_row(rows, capacity, uid) : NULL;
	if (WARN_ON_ONCE(!row || row->count < amount)) return;
	row->count -= amount;
}

u32 ba_v2_uid_charged(const struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid)
{
	u32 i;
	for (i = 0; rows && i < capacity; i++)
		if (rows[i].count && uid_eq(rows[i].uid, uid)) return rows[i].count;
	return 0;
}
