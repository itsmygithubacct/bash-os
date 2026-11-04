/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_AUDIT_STORE_H
#define BA_V2_AUDIT_STORE_H
#include "../../uapi/linux/bashos_audit_v2.h"
#define BA_V2_AUDIT_CAPACITY 128U
struct ba_v2_audit_store;
struct ba_v2_audit_ticket {
	struct ba_v2_audit_store *store;
	u64 epoch;
	u32 remaining;
};
struct ba_v2_audit_info {
	u64 epoch, next_sequence, oldest_sequence, backpressure_denials;
	u32 available, reserved;
};
struct ba_v2_audit_store *ba_v2_audit_create(void);
void ba_v2_audit_destroy(struct ba_v2_audit_store *store);
int ba_v2_audit_reserve(struct ba_v2_audit_store *store, u32 count,
		struct ba_v2_audit_ticket *ticket);
void ba_v2_audit_cancel(struct ba_v2_audit_ticket *ticket);
/* All event fields originate in the authority's owned state. Epoch/sequence/
 * time/HMAC are filled here. A successful commit consumes one reservation. */
int ba_v2_audit_commit(struct ba_v2_audit_ticket *ticket,
		const struct bashos_audit_v2_record *event, u64 *sequence);
/* The eventual ioctl adapter must require initial-user-namespace CAP_SYS_ADMIN.
 * Peek is non-destructive; acknowledge only after successful decode/output.
 * Exact epoch + oldest sequence prevents stale or out-of-order removal. */
int ba_v2_audit_peek(struct ba_v2_audit_store *store, struct bashos_audit_v2_record *record);
int ba_v2_audit_ack(struct ba_v2_audit_store *store, u64 epoch, u64 sequence);
int ba_v2_audit_verify(struct ba_v2_audit_store *store, const struct bashos_audit_v2_record *record);
void ba_v2_audit_info(struct ba_v2_audit_store *store, struct ba_v2_audit_info *info);
#endif
