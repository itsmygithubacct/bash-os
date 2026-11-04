/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef BA_V2_EXECUTOR_PROTOCOL_H
#define BA_V2_EXECUTOR_PROTOCOL_H
#include <linux/types.h>
#define BA_V2_EXEC_MAGIC 0x32584542U
#define BA_V2_EXEC_VERSION 2U
#define BA_V2_EXEC_MAX_ITEMS 256U
#define BA_V2_EXEC_MAX_GROUPS 128U
#define BA_V2_EXEC_MAX_BLOB 65536U
#define BA_V2_EXEC_MAX_TIMEOUT 300U
#define BA_V2_EXEC_FDS 15U
enum ba_v2_exec_descriptor {
	BA_V2_EXEC_PROGRAM, BA_V2_EXEC_CWD, BA_V2_EXEC_ROOT,
	BA_V2_EXEC_STDIN, BA_V2_EXEC_STDOUT, BA_V2_EXEC_STDERR,
	BA_V2_EXEC_MNT, BA_V2_EXEC_UTS, BA_V2_EXEC_IPC,
	BA_V2_EXEC_PID_CHILDREN, BA_V2_EXEC_NET, BA_V2_EXEC_TIME,
	BA_V2_EXEC_TIME_CHILDREN, BA_V2_EXEC_CGROUP, BA_V2_EXEC_PID_ACTIVE
};
enum ba_v2_exec_result_kind {
	BA_V2_EXEC_CHILD_READY = 0, BA_V2_EXEC_EXIT = 1, BA_V2_EXEC_SIGNAL,
	BA_V2_EXEC_SETUP_ERROR, BA_V2_EXEC_TIMEOUT, BA_V2_EXEC_LAUNCH_ERROR,
	BA_V2_EXEC_CONTROL_ERROR /* an owned child existed; its final result is unknown */
};
enum ba_v2_exec_setup_step {
	BA_V2_EXEC_STEP_INPUT = 1, BA_V2_EXEC_STEP_NAMESPACE, BA_V2_EXEC_STEP_DESCRIPTORS,
	BA_V2_EXEC_STEP_ROOT, BA_V2_EXEC_STEP_CWD, BA_V2_EXEC_STEP_SECURITY,
	BA_V2_EXEC_STEP_GROUPS, BA_V2_EXEC_STEP_GID, BA_V2_EXEC_STEP_UID,
	BA_V2_EXEC_STEP_CAPABILITIES, BA_V2_EXEC_STEP_IDS, BA_V2_EXEC_STEP_SIGNALS,
	BA_V2_EXEC_STEP_EXEC
};
/* Private kernel-to-native channel, never a public authorization request. All
 * descriptors are installed by the kernel from held objects. Groups and final
 * environment are resolved from trusted snapshots; no native NSS/PATH lookup.
 * Exactly argv_bytes of NUL-framed arguments followed by env_bytes follow. */
struct ba_v2_exec_request {
	__le32 magic, version, size, reserved;
	__le32 uid, gid, group_count, argc;
	__le32 envc, argv_bytes, env_bytes, timeout_seconds;
	__le32 descriptors[BA_V2_EXEC_FDS], reserved2;
	__u8 nonce[32], request_digest[32];
	__le32 groups[BA_V2_EXEC_MAX_GROUPS];
	__u8 blobs[];
};
/* READY is sent before the native monitor releases its blocked direct child.
 * The kernel retains that exact task for cancellation. One final response must
 * then distinguish real child exit/signal from setup failure or timeout. */
struct ba_v2_exec_response {
	__le32 magic, version, size, kind;
	__le32 status, failed_step, error, child_pid;
	__u8 nonce[32], request_digest[32];
};
#endif
