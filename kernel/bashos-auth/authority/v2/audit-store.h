/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_AUDIT_STORE_H
#define BA_V2_AUDIT_STORE_H
#include <linux/uidgid.h>
#include "../../uapi/linux/bashos_audit_v2.h"
#define BA_V2_AUDIT_CAPACITY 128U
/* Most pending records one limited owner uid may hold: its outstanding
 * reservations plus its committed records that are not yet acknowledged.
 * One 16-target edit reserves 36 at once, on top of the 4 its open and seal
 * phases committed. The other 80 records stay available to other owners. */
#define BA_V2_AUDIT_UID_LIMIT 48U
struct ba_v2_audit_store;
struct ba_v2_audit_ticket {
	struct ba_v2_audit_store *store;
	u64 epoch;
	u32 remaining;
	kuid_t uid;
	bool limited;
};
struct ba_v2_audit_info {
	u64 epoch, next_sequence, oldest_sequence, backpressure_denials, uid_limit_denials;
	u32 available, reserved;
};
struct ba_v2_audit_store *ba_v2_audit_create(void);
void ba_v2_audit_destroy(struct ba_v2_audit_store *store);
/* uid is the owner the records are charged to. A limited owner is refused
 * with -EDQUOT at BA_V2_AUDIT_UID_LIMIT while the ring still has room; a full
 * ring refuses every owner with -ENOSPC. The adapter passes limited == false
 * only for the administrator, who can acknowledge records. The charge moves
 * from the ticket to each committed record and ends at acknowledgement or
 * cancellation. */
int ba_v2_audit_reserve(struct ba_v2_audit_store *store, u32 count, kuid_t uid,
		bool limited, struct ba_v2_audit_ticket *ticket);
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
