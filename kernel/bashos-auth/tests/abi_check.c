/* SPDX-License-Identifier: MIT */
/* No device operations. Safe native run; BA_LAYOUT_ONLY permits cross syntax checks. */
#include <stddef.h>
#ifdef ABI_REFERENCE
#include ABI_REFERENCE
#else
#include <linux/bashos_auth.h>
#endif

_Static_assert(sizeof(struct bashos_auth_version) == 32, "version size");
_Static_assert(offsetof(struct bashos_auth_version, features) == 8, "features offset");
_Static_assert(offsetof(struct bashos_auth_version, reserved) == 16, "reserved offset");
_Static_assert(sizeof(struct bashos_auth_handle) == 8, "handle size");
_Static_assert(sizeof(struct bashos_auth_secret_write) == 16, "write size");
_Static_assert(offsetof(struct bashos_auth_secret_write, user_ptr) == 8, "write pointer");
_Static_assert(sizeof(struct bashos_auth_secret_export) == 16, "export size");
_Static_assert(offsetof(struct bashos_auth_secret_export, user_ptr) == 8, "export pointer");
_Static_assert(sizeof(struct bashos_auth_secret_compare) == 16, "compare size");
_Static_assert(offsetof(struct bashos_auth_secret_compare, result) == 8, "compare result");
_Static_assert(sizeof(struct bashos_auth_stats) == 128, "stats size");
_Static_assert(offsetof(struct bashos_auth_stats, reserved) == 48, "stats reserved");
_Static_assert(sizeof(struct bashos_auth_token_req) == 120, "token transport size");
_Static_assert(BASHOS_AUTH_IOC_VERSION == 0x8020ba01U, "VERSION encoding");
_Static_assert(BASHOS_AUTH_IOC_NEW_SECRET == 0xc008ba02U, "NEW encoding");
_Static_assert(BASHOS_AUTH_IOC_WRITE_SECRET == 0x4010ba03U, "WRITE encoding");
_Static_assert(BASHOS_AUTH_IOC_SEAL_SECRET == 0x4008ba04U, "SEAL encoding");
_Static_assert(BASHOS_AUTH_IOC_CLEAR_SECRET == 0x4008ba05U, "CLEAR encoding");
_Static_assert(BASHOS_AUTH_IOC_EXPORT_ONCE == 0xc010ba06U, "EXPORT encoding");
_Static_assert(BASHOS_AUTH_IOC_SAME_SECRET == 0xc010ba07U, "SAME encoding");
_Static_assert(BASHOS_AUTH_IOC_STATS == 0x8080ba0aU, "STATS encoding");
_Static_assert(BASHOS_AUTH_FEAT_SECRETS == 1ULL, "SECRETS bit");
_Static_assert(BASHOS_AUTH_FEAT_TOKENS == 2ULL, "TOKENS bit");
_Static_assert(BASHOS_AUTH_FEAT_STATS == 4ULL, "STATS bit");
_Static_assert(BASHOS_AUTH_FEAT_PRIVCMD == 8ULL, "PRIVCMD bit");

#ifndef BA_LAYOUT_ONLY
#include <stdio.h>
int main(void)
{
	puts("PASS: stage-1 sizes, offsets, feature bits and ioctl encodings (no device accessed)");
	return 0;
}
#endif
