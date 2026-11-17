/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed-size per-uid counters behind the limits that keep one unprivileged
 * user of the 0666 PRIVCMD node from taking a whole shared table. */
#ifndef BA_V2_UID_LIMIT_H
#define BA_V2_UID_LIMIT_H
#include <linux/types.h>
#include <linux/uidgid.h>

/* A row is unused while its count is zero; its uid is then meaningless. */
struct ba_v2_uid_count {
	kuid_t uid;
	u32 count;
};

/* The caller serializes all access to rows[] with its own lock. Adds amount
 * to uid's count, or changes nothing: -EDQUOT when the sum would pass limit,
 * -ENOSPC when uid has no row and none is unused. */
int ba_v2_uid_charge(struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid,
		u32 amount, u32 limit);
/* Returns amount previously charged to uid. Uncharging more than was charged
 * is an accounting defect: it warns once and changes nothing. */
void ba_v2_uid_uncharge(struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid,
		u32 amount);
u32 ba_v2_uid_charged(const struct ba_v2_uid_count *rows, u32 capacity, kuid_t uid);
#endif
