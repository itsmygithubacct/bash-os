/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_SAFEEDIT_H
#define BA_V2_SAFEEDIT_H
#include "request-binding.h"

#define BA_V2_EDIT_MAX_TARGETS 16U
#define BA_V2_EDIT_MAX_BYTES (1024U * 1024U)
#define BA_V2_EDIT_SESSION_NS (3600ULL * NSEC_PER_SEC)
struct ba_v2_edit_session;
struct ba_v2_edit_result {
	u32 count, committed, failed_index, error, cleanup_error;
	u8 transaction_digest[32];
};

/* The adapter MUST consume a fresh, verified (or explicit NOPASSWD) grant and
 * reserve audit capacity before either operation. These internal functions do
 * not issue grants. Source/target paths come only from the owned bound request.
 * Files in the fd vectors are borrowed with stable references for the call. */
int ba_v2_edit_open(const struct ba_v2_bound_request *bound, const struct cred *administrator,
		struct file * const *copies, u32 count, struct ba_v2_edit_session **out);

/* Pin the complete edited byte vector before the next PREPARE/VERIFY. This
 * reads only the supplied caller-owned files and never changes an original.
 * The adapter destroys the session on any failed seal or reply-copy fault. */
int ba_v2_edit_seal(struct ba_v2_edit_session *session, const struct cred *administrator,
		const u8 original_request_digest[32], struct file * const *copies, u32 count,
		struct ba_v2_edit_result *result);
int ba_v2_edit_bound_digest(const struct ba_v2_edit_session *session,
		const u8 original_request_digest[32], u8 sealed_digest[32]);

/* Takes and destroys *session on EVERY path, including malformed inputs and
 * a failed preflight. The intent callback must record the next per-file
 * commit in the bounded kernel audit before that rename; it may deny it. It is
 * called without inode locks and with the requesting credentials restored.
 * Callback denial is a real partial-prefix failure, never rollback. */
typedef int (*ba_v2_edit_intent)(void *cookie, u32 index, u32 committed,
		const u8 transaction_digest[32]);
int ba_v2_edit_commit(struct ba_v2_edit_session **session,
		const struct ba_v2_bound_request *fresh, const struct cred *administrator,
		struct file * const *copies, u32 count, ba_v2_edit_intent intent, void *cookie,
		struct ba_v2_edit_result *result);
void ba_v2_edit_close(struct ba_v2_edit_session *session);
#endif
