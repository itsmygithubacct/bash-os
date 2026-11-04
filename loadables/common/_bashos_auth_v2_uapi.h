/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/* Explicit new identity-proof protocol. The stage-1 ABI remains unchanged.
 * Qualification builds expose this only on the separate test endpoint. */
#ifndef BASHOS_AUTH_V2_UAPI_H
#define BASHOS_AUTH_V2_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>

#define BASHOS_AUTH_V2_VERSION 2U
#define BASHOS_AUTH_V2_DEVICE "/dev/bashos-auth-v2"
#define BASHOS_AUTH_V2_QUALIFICATION_DEVICE "/dev/bashos-auth-v2-test"
#define BASHOS_AUTH_V2_QUALIFICATION_ONLY 1ULL
#define BASHOS_AUTH_V2_STANDARD_PHC 1U
#define BASHOS_AUTH_V2_LEGACY_HEX 2U
#define BASHOS_AUTH_V2_LOGIN 1U
#define BASHOS_AUTH_V2_SU 2U
#define BASHOS_AUTH_V2_SSH 4U

struct bashos_auth_v2_info {
	__u32 size, version;
	__u64 flags, account_generation, policy_generation;
};
struct bashos_auth_v2_identity {
	__u32 purpose, uid, gid, encoding;
	char user[64];
};
struct bashos_auth_v2_verify {
	__u32 size, version, secret_id, reserved;
	struct bashos_auth_v2_identity identity;
};
struct bashos_auth_v2_consume {
	__u32 size, version, reserved[2];
	struct bashos_auth_v2_identity identity;
	__u8 reference[32];
};
struct bashos_auth_v2_delegate {
	__u32 size, version, child_pid, reserved;
};

#define BASHOS_AUTH_V2_INFO _IOR(0xbc, 0, struct bashos_auth_v2_info)
#define BASHOS_AUTH_V2_VERIFY _IOW(0xbc, 1, struct bashos_auth_v2_verify)
#define BASHOS_AUTH_V2_VERIFY_LEGACY_HEX _IOW(0xbc, 2, struct bashos_auth_v2_verify)
#define BASHOS_AUTH_V2_CONSUME _IOW(0xbc, 3, struct bashos_auth_v2_consume)
#define BASHOS_AUTH_V2_RESET _IO(0xbc, 4)
#define BASHOS_AUTH_V2_DELEGATE_SSH _IOW(0xbc, 5, struct bashos_auth_v2_delegate)
#endif
