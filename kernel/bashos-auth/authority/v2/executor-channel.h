/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BA_V2_EXECUTOR_CHANNEL_H
#define BA_V2_EXECUTOR_CHANNEL_H
#include "environment.h"
#include "executor-protocol.h"
/* Caller must consume its one-use authenticated or explicit NOPASSWD grant,
 * check its actor/epoch/deadline, and reserve/commit audit before launch. This
 * internal adapter never changes the requesting task's credentials. */
int ba_v2_execute_native(const struct ba_v2_trusted_file *executor,
		const struct ba_v2_bound_request *request, const struct ba_v2_environment *env,
		u32 timeout_seconds, struct ba_v2_exec_response *result);
#endif
