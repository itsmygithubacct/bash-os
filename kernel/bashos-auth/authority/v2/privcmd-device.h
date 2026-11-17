/* SPDX-License-Identifier: GPL-2.0-only */
/* PRIVCMD protocol v2 device, shared by the production module and the
 * separately named qualification module. Everything a variant can change is
 * in one constant table; the shared code has no conditional compilation. */
#ifndef BA_V2_PRIVCMD_DEVICE_H
#define BA_V2_PRIVCMD_DEVICE_H
#include <linux/types.h>

/* Open contexts of the whole node, how many of them are kept free for the
 * administrator (who needs one to read and acknowledge audit records), and
 * how many one other uid may hold at once. Each context has at most one
 * pending request, so these also bound pending requests. */
#define BA_V2_PRIVCMD_CONTEXTS 16U
#define BA_V2_PRIVCMD_ADMIN_RESERVE 4U
#define BA_V2_PRIVCMD_UID_CONTEXTS 4U
/* Native password verifications in flight: in total, and per other uid. */
#define BA_V2_PRIVCMD_VERIFICATIONS 2U
#define BA_V2_PRIVCMD_UID_VERIFICATIONS 1U

struct ba_v2_privcmd_variant {
	const char *node;	/* misc device name, without /dev/ */
	u32 info_flags;		/* reported by BASHOS_PRIVCMD_V2_INFO */
	/* Qualification-only denial controls, both NULL in production. Each
	 * can only turn an operation that would have proceeded into a recorded
	 * failure; neither can allow, authenticate or skip an audit record. */
	bool (*edit_fault)(u32 target_index);
	bool (*reset_fault)(void);
};

/* Initial-user-namespace root with CAP_SYS_ADMIN. */
bool ba_v2_privcmd_administrator(void);
/* Opens and pins the bundle named by the module parameters, then registers
 * the variant's node. Nothing is registered on failure. */
int ba_v2_privcmd_device_register(const struct ba_v2_privcmd_variant *variant);
void ba_v2_privcmd_device_unregister(void);
#endif
