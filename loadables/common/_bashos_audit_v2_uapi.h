/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef BASHOS_AUDIT_V2_H
#define BASHOS_AUDIT_V2_H
#include <linux/types.h>

#define BASHOS_AUDIT_V2_VERSION 2U
#define BASHOS_AUDIT_V2_BYTES 800U
#define BASHOS_AUDIT_V2_PATH_BYTES 256U
enum bashos_audit_v2_outcome {
	BASHOS_AUDIT_V2_DENIED = 1, BASHOS_AUDIT_V2_AUTH_REQUIRED,
	BASHOS_AUDIT_V2_VERIFY_DENIED, BASHOS_AUDIT_V2_AUTHORIZED,
	BASHOS_AUDIT_V2_EXEC_START, BASHOS_AUDIT_V2_EXEC_RESULT,
	BASHOS_AUDIT_V2_RESET, BASHOS_AUDIT_V2_VALIDATED,
	BASHOS_AUDIT_V2_EDIT_OPEN, BASHOS_AUDIT_V2_EDIT_COMMIT,
	BASHOS_AUDIT_V2_EDIT_RESULT, BASHOS_AUDIT_V2_REJECTED
};
enum bashos_audit_v2_reason {
	BASHOS_AUDIT_V2_REASON_POLICY = 1, BASHOS_AUDIT_V2_REASON_AUTH,
	BASHOS_AUDIT_V2_REASON_NONINTERACTIVE, BASHOS_AUDIT_V2_REASON_BINDING,
	BASHOS_AUDIT_V2_REASON_EXPIRED, BASHOS_AUDIT_V2_REASON_RESET,
	BASHOS_AUDIT_V2_REASON_EXEC, BASHOS_AUDIT_V2_REASON_EDIT,
	BASHOS_AUDIT_V2_REASON_MALFORMED, BASHOS_AUDIT_V2_REASON_INTERNAL
};

/* Exactly 800 bytes, little endian. Zero reserved fields and unused path tails.
 * Paths are length-bearing opaque bytes, displayed as hex by the new decoder.
 * No passwords, references, argv, environment values or addresses are logged.
 * HMAC-SHA256 covers exactly bytes [0,768), including the fresh authority epoch
 * and monotonic sequence. Key is random, kernel-only, and wiped at teardown.
 * Old epochs cease to verify at teardown; this is not a durable signature. */
struct bashos_audit_v2_record {
	__le32 size, version;
	__le64 epoch, sequence, boottime_ns;
	__le64 account_generation, policy_generation, group_generation, verifier_generation;
	__le32 outcome, mode, caller_uid, caller_gid, target_uid, target_gid;
	__le32 rule_index, cache_hit, result_kind, result_code, target_count, committed_count;
	__u8 request_digest[32], policy_digest[32], normalized_policy_digest[32], cwd_digest[32];
	__le32 command_length, cwd_length, reason, reserved;
	__u8 command[BASHOS_AUDIT_V2_PATH_BYTES], cwd[BASHOS_AUDIT_V2_PATH_BYTES];
	__u8 hmac[32];
};
#endif
