/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/* New private verifier protocol. Does not change the existing device ABI. */
#ifndef BASHOS_AUTH_V2_PROTOCOL_H
#define BASHOS_AUTH_V2_PROTOCOL_H
#include <linux/types.h>

#define BA_V2_MAGIC 0x32564142U
#define BA_V2_VERSION 2U
#define BA_V2_SECRET_BYTES 4096U
#define BA_V2_PHC_BYTES 512U
#define BA_V2_USER_BYTES 64U
#define BA_V2_NONCE_BYTES 32U
#define BA_V2_ENCODING_STANDARD 1U
#define BA_V2_ENCODING_LEGACY_HEX 2U
#define BA_V2_PURPOSE_LOGIN 1U
#define BA_V2_PURPOSE_SU 2U
#define BA_V2_PURPOSE_SSH 4U /* distinct from the old PRIVCMD purpose 3 */
#define BA_V2_PURPOSE_PRIVCMD 5U /* caller-password event, never an identity reference */
#define BA_V2_VERIFY_OK 0U
#define BA_V2_VERIFY_DENIED 1U
#define BA_V2_VERIFY_ERROR 2U
#define BA_V2_ACCOUNT_ENABLED 1U
#define BA_V2_MAX_ACCOUNTS 32U

/* Fixed little-endian wire fields, no native pointers, padding or credentials
 * from a public client. The kernel fills this from its owned request/secret and
 * trusted account snapshot; only the launched verifier receives the channel. */
struct ba_v2_challenge {
	__le32 magic, version, size, purpose;
	__le32 target_uid, target_gid, secret_length, encoding;
	__le64 account_generation, policy_generation;
	__u8 nonce[BA_V2_NONCE_BYTES];
	__u8 request_digest[32];
	char user[BA_V2_USER_BYTES];
	char phc[BA_V2_PHC_BYTES];
	__u8 secret[BA_V2_SECRET_BYTES];
};

struct ba_v2_response {
	__le32 magic, version, size, status;
	__u8 nonce[BA_V2_NONCE_BYTES];
	__u8 request_digest[32];
};

/* Immutable administrator-authored account snapshot. Each record explicitly
 * names its field encoding; existing passwd/shadow files are never rewritten. */
struct ba_v2_account_header {
	__le32 magic, version, size, count;
	__le64 generation;
	__le64 reserved;
};
struct ba_v2_account_record {
	__le32 uid, gid, encoding, flags;
	char user[BA_V2_USER_BYTES];
	char phc[BA_V2_PHC_BYTES];
};
#endif
