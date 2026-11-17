/* SPDX-License-Identifier: GPL-2.0-only */
/* Identity protocol v2 device, shared by the production module and the
 * separately named qualification module. Everything a variant can change is
 * in one constant table; the shared code has no conditional compilation. */
#ifndef BA_V2_IDENTITY_DEVICE_H
#define BA_V2_IDENTITY_DEVICE_H
#include <linux/mutex.h>
#include "identity-transport.h"

struct ba_v2_identity_context {
	struct mutex operation;
	struct ba_ctx *secrets;
	struct ba_reference_store *references;
	struct ba_reference_actor actor;
};

/* The administrator-pinned inputs of one module instance. Fixed at load. */
struct ba_v2_identity_bundle {
	struct ba_v2_trusted_file verifier;
	struct ba_v2_accounts accounts;
};

struct ba_v2_identity_variant {
	const char *node;	/* misc device name, without /dev/ */
	u64 info_flags;		/* reported by BASHOS_AUTH_V2_INFO */
	/* Qualification only, NULL in production. Called with the context's
	 * operation mutex held, after admission and actor checks. Returns true
	 * when it owns the command and stored its result. */
	bool (*extra_ioctl)(struct ba_v2_identity_context *context,
			const struct ba_v2_identity_bundle *bundle,
			unsigned int command, void __user *argument, long *result);
	/* Qualification only, NULL in production: further commands that a
	 * delegated SSH child may issue besides the public CONSUME and INFO. */
	bool (*delegated_command)(unsigned int command);
};

/* Initial-user-namespace root with CAP_SYS_ADMIN. Required to load, to open
 * and on every read and ioctl. */
bool ba_v2_identity_admission(void);
/* Opens and pins the bundle named by the module parameters, then registers
 * the variant's node. Nothing is registered on failure. */
int ba_v2_identity_device_register(const struct ba_v2_identity_variant *variant);
void ba_v2_identity_device_unregister(void);
#endif
