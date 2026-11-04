/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef BASHOS_PRIVCMD_V2_H
#define BASHOS_PRIVCMD_V2_H
#include <linux/ioctl.h>
#include <linux/types.h>
#include "_bashos_auth_uapi.h"
#include "_bashos_audit_v2_uapi.h"
#define BASHOS_PRIVCMD_V2_VERSION 2U
#define BASHOS_PRIVCMD_V2_MAGIC 0xbd
#define BASHOS_PRIVCMD_V2_QUALIFICATION_ONLY 1U
#define BASHOS_PRIVCMD_V2_RESET_ALL 1U
enum bashos_privcmd_v2_decision {
	BASHOS_PRIVCMD_V2_DENY = 1, BASHOS_PRIVCMD_V2_AUTH_REQUIRED, BASHOS_PRIVCMD_V2_READY
};
enum bashos_privcmd_v2_result {
	BASHOS_PRIVCMD_V2_EXIT = 1, BASHOS_PRIVCMD_V2_SIGNAL, BASHOS_PRIVCMD_V2_SETUP_ERROR,
	BASHOS_PRIVCMD_V2_TIMEOUT, BASHOS_PRIVCMD_V2_LAUNCH_ERROR, BASHOS_PRIVCMD_V2_CONTROL_ERROR,
	BASHOS_PRIVCMD_V2_VALIDATED, BASHOS_PRIVCMD_V2_EDIT_OPENED,
	BASHOS_PRIVCMD_V2_EDIT_COMMITTED, BASHOS_PRIVCMD_V2_EDIT_FAILED,
	BASHOS_PRIVCMD_V2_EDIT_SEALED
};
struct bashos_privcmd_v2_info {
	__u32 size, version, flags, reserved;
	__u64 account_generation, policy_generation, group_generation, verifier_generation;
	__u8 policy_digest[32], normalized_policy_digest[32];
};
/* The existing input framing/digest is reused explicitly, without changing an
 * old opcode. Returned request pointers and all legacy response fields are zero.
 * After EDIT_SEAL, a fresh edit PREPARE returns the sealed transaction digest
 * in request.request_digest. VERIFY and COMMIT must use that authorized digest.
 * A request_id is a correlation id, never a transferable authorization token. */
struct bashos_privcmd_v2_prepare {
	__u32 size, version, reserved[2];
	struct bashos_auth_privcmd request;
	__u32 decision, reason, encoding, cache_hit;
	__u64 request_id, deadline_ns, audit_sequence;
};
struct bashos_privcmd_v2_verify {
	__u32 size, version, secret_id, reserved;
	__u64 request_id;
	__u8 request_digest[32];
	__u64 deadline_ns, audit_sequence;
};
struct bashos_privcmd_v2_run {
	__u32 size, version, reserved[2];
	__u64 request_id;
	__u8 request_digest[32];
	__u32 result, status, failed_step, error;
	__u64 audit_sequence;
};
struct bashos_privcmd_v2_reset {
	__u32 size, version, flags, reserved;
	__u64 audit_sequence;
};
#define BASHOS_PRIVCMD_V2_EDIT_MAX_TARGETS 16U
/* OPEN receives caller-owned empty read/write copies. SEAL receives read-only
 * edited copies with OPEN's id/original digest and pins them before a fresh
 * PREPARE/VERIFY. COMMIT must present those same open-file objects and the new
 * grant's sealed transaction digest on the same owner context.
 * The fd vector is an input capability, not a path selected by privileged code.
 * Every unused fd and response field must be zero on input. A completed ioctl
 * reports per-target commit prefix even on filesystem or late-audit failure. */
struct bashos_privcmd_v2_edit {
	__u32 size, version, count, reserved;
	__u64 request_id;
	__u8 request_digest[32];
	__u32 copy_fds[BASHOS_PRIVCMD_V2_EDIT_MAX_TARGETS];
	__u32 result, committed_count, failed_index, error, cleanup_error, reserved2;
	__u8 transaction_digest[32];
	__u64 audit_sequence;
};
struct bashos_privcmd_v2_audit_ack { __u64 epoch, sequence; };
struct bashos_privcmd_v2_audit_info {
	__u64 epoch, next_sequence, oldest_sequence, backpressure_denials;
	__u32 available, reserved;
};
#define BASHOS_PRIVCMD_V2_INFO _IOR(BASHOS_PRIVCMD_V2_MAGIC, 0, struct bashos_privcmd_v2_info)
#define BASHOS_PRIVCMD_V2_PREPARE _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 1, struct bashos_privcmd_v2_prepare)
#define BASHOS_PRIVCMD_V2_VERIFY _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 2, struct bashos_privcmd_v2_verify)
#define BASHOS_PRIVCMD_V2_VERIFY_LEGACY_HEX _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 3, struct bashos_privcmd_v2_verify)
#define BASHOS_PRIVCMD_V2_RUN _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 4, struct bashos_privcmd_v2_run)
#define BASHOS_PRIVCMD_V2_RESET _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 5, struct bashos_privcmd_v2_reset)
#define BASHOS_PRIVCMD_V2_CANCEL _IO(BASHOS_PRIVCMD_V2_MAGIC, 6)
#define BASHOS_PRIVCMD_V2_EDIT_OPEN _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 7, struct bashos_privcmd_v2_edit)
#define BASHOS_PRIVCMD_V2_EDIT_COMMIT _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 8, struct bashos_privcmd_v2_edit)
#define BASHOS_PRIVCMD_V2_EDIT_SEAL _IOWR(BASHOS_PRIVCMD_V2_MAGIC, 9, struct bashos_privcmd_v2_edit)
#define BASHOS_PRIVCMD_V2_AUDIT_PEEK _IOR(BASHOS_PRIVCMD_V2_MAGIC, 16, struct bashos_audit_v2_record)
#define BASHOS_PRIVCMD_V2_AUDIT_ACK _IOW(BASHOS_PRIVCMD_V2_MAGIC, 17, struct bashos_privcmd_v2_audit_ack)
#define BASHOS_PRIVCMD_V2_AUDIT_VERIFY _IOW(BASHOS_PRIVCMD_V2_MAGIC, 18, struct bashos_audit_v2_record)
#define BASHOS_PRIVCMD_V2_AUDIT_INFO _IOR(BASHOS_PRIVCMD_V2_MAGIC, 19, struct bashos_privcmd_v2_audit_info)
#endif
