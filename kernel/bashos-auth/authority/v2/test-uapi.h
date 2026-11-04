/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/* Explicit disposable-guest test endpoint, separate from the production ABI. */
#ifndef BA_V2_TEST_UAPI_H
#define BA_V2_TEST_UAPI_H
#include <linux/ioctl.h>
#include "protocol.h"
#define BA_V2_TEST_DEVICE "/dev/bashos-auth-v2-test"
struct ba_v2_test_version {
	__u32 size, version;
	__u64 production_features; /* always zero */
};
struct ba_v2_test_verify {
	__u32 size, version, secret_id, purpose;
	char user[BA_V2_USER_BYTES];
	__u8 request_digest[32];
	__u64 reserved[4];
};
struct ba_v2_test_consume {
	__u32 size, version, purpose, reserved;
	char user[BA_V2_USER_BYTES];
	__u8 reference[32], request_digest[32];
};
struct ba_v2_test_delegate {
	__u32 size, version, child_pid, reserved;
};
#define BA_V2_TEST_VERSION _IOR(0xbb, 0, struct ba_v2_test_version)
#define BA_V2_TEST_VERIFY _IOW(0xbb, 1, struct ba_v2_test_verify)
#define BA_V2_TEST_VERIFY_LEGACY _IOW(0xbb, 2, struct ba_v2_test_verify)
#define BA_V2_TEST_CONSUME _IOW(0xbb, 3, struct ba_v2_test_consume)
#define BA_V2_TEST_RESET _IO(0xbb, 4)
#define BA_V2_TEST_DELEGATE_SSH _IOW(0xbb, 5, struct ba_v2_test_delegate)
#endif
