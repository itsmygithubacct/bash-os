/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_ENVIRONMENT_H
#define BA_V2_ENVIRONMENT_H
#include "request-binding.h"
struct ba_v2_environment {
	u32 count, bytes;
	char *blob;
};
/* Decode the existing BASHOS_CALLER_/BASHOS_INLINE_ request framing exactly
 * once. Inline assignments require SETENV; dangerous variables and synthesized
 * identity/PATH/SUDO fields cannot override authority-owned values. */
int ba_v2_environment_build(const struct ba_v2_bound_request *bound,
		const struct ba_v2_profile *profile, struct ba_v2_environment *out);
void ba_v2_environment_free(struct ba_v2_environment *environment);
#endif
