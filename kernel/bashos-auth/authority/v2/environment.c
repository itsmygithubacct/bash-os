// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "environment.h"

struct environment_builder { char *entries[BA_REQUEST_MAX_ITEMS]; u32 count, bytes; };

static int environment_set(struct environment_builder *b, const char *name, const char *value)
{
	size_t name_length = strlen(name), n = name_length + strlen(value) + 2;
	size_t old_length = 0;
	u32 at;
	char *entry;
	for (at = 0; at < b->count; at++)
		if (!strncmp(b->entries[at], name, name_length) && b->entries[at][name_length] == '=') break;
	if (at == b->count && b->count == BA_REQUEST_MAX_ITEMS) return -E2BIG;
	if (at < b->count) old_length = strlen(b->entries[at]) + 1;
	if (n > BA_REQUEST_MAX_BLOB || b->bytes - old_length > BA_REQUEST_MAX_BLOB - n) return -E2BIG;
	entry = kmalloc(n, GFP_KERNEL);
	if (!entry) return -ENOMEM;
	memcpy(entry, name, name_length); entry[name_length] = '=';
	memcpy(entry + name_length + 1, value, n - name_length - 1);
	if (at < b->count) {
		b->bytes -= strlen(b->entries[at]) + 1;
		kfree_sensitive(b->entries[at]);
	} else b->count++;
	b->entries[at] = entry; b->bytes += n;
	return 0;
}

static bool environment_protected(const char *name)
{
	static const char *const forced[] = { "HOME", "USER", "LOGNAME", "SHELL", "PATH" };
	u32 i;
	if (!strncmp(name, "SUDO_", 5)) return true;
	for (i = 0; i < ARRAY_SIZE(forced); i++) if (!strcmp(name, forced[i])) return true;
	return false;
}

static bool environment_kept(const struct ba_policy_decision *decision, const char *name)
{
	u32 i;
	if (!decision->env_reset) return true;
	for (i = 0; i < decision->keep_count; i++) if (!strcmp(name, decision->keep[i])) return true;
	return false;
}

void ba_v2_environment_free(struct ba_v2_environment *env)
{
	if (!env) return;
	if (env->blob) kvfree_sensitive(env->blob, env->bytes);
	memzero_explicit(env, sizeof(*env));
}

int ba_v2_environment_build(const struct ba_v2_bound_request *bound,
		const struct ba_v2_profile *profile, struct ba_v2_environment *out)
{
	const struct bashos_auth_privcmd *r;
	struct environment_builder *b;
	char number[16], name[256], *command;
	u32 i, j, offset = 0;
	bool saw_assignment = false;
	int rc = -EINVAL;
	if (!out) return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!bound || !profile || !bound->decision.allow ||
	    strcmp(profile->user, bound->identities.target.name)) return -EINVAL;
	r = &bound->request->wire;
	b = kzalloc(sizeof(*b), GFP_KERNEL);
	command = kzalloc(4097, GFP_KERNEL);
	if (!b || !command) { kfree(b); kfree(command); return -ENOMEM; }
#define ENV_SET(n, v) do { rc = environment_set(b, n, v); if (rc) goto done; } while (0)
	ENV_SET("HOME", profile->home); ENV_SET("USER", profile->user);
	ENV_SET("LOGNAME", profile->user); ENV_SET("SHELL", profile->shell);
	ENV_SET("PATH", bound->decision.secure_path); ENV_SET("LANG", "C");
	ENV_SET("SUDO_USER", bound->identities.caller.name);
	snprintf(number, sizeof(number), "%u", bound->identities.caller.uid); ENV_SET("SUDO_UID", number);
	snprintf(number, sizeof(number), "%u", bound->identities.caller.primary_gid); ENV_SET("SUDO_GID", number);
	for (i = 0; i < r->argc && offset < 4096; i++) {
		size_t n;
		if (i) command[offset++] = ' ';
		n = min_t(size_t, strlen(bound->argv[i]), 4096 - offset);
		memcpy(command + offset, bound->argv[i], n); offset += n;
	}
	ENV_SET("SUDO_COMMAND", command);
	for (i = 0; i < r->envc; i++) {
		const char *entry = bound->env[i], *value, *key;
		bool assignment;
		size_t length;
		if (!strncmp(entry, "BASHOS_CALLER_", 14)) assignment = false;
		else if (!strncmp(entry, "BASHOS_INLINE_", 14)) assignment = true;
		else { rc = -EINVAL; goto done; }
		/* The public request uses inherited entries followed by inline
		 * assignments. Reject reordered frames rather than allowing a later
		 * inherited value to undo an explicit assignment. */
		if (!assignment && saw_assignment) { rc = -EINVAL; goto done; }
		if (assignment) saw_assignment = true;
		key = entry + 14; value = strchr(key, '=');
		if (!value || value == key || (length = value - key) >= sizeof(name)) { rc = -EINVAL; goto done; }
		memcpy(name, key, length); name[length] = 0;
		if (assignment && !bound->decision.setenv) { rc = -EACCES; goto done; }
		/* A duplicated inherited name is ambiguous; repeated inline assignments
 * deliberately keep the client's existing last-assignment-wins contract. */
		if (!assignment) for (j = 0; j < i; j++)
			if (!strncmp(bound->env[j], "BASHOS_CALLER_", 14) &&
			    !strncmp(bound->env[j] + 14, name, length) && bound->env[j][14 + length] == '=') {
				rc = -EINVAL; goto done;
			}
		if (!ba_v2_policy_environment_name_safe(name) || environment_protected(name)) continue;
		if (assignment || environment_kept(&bound->decision, name)) ENV_SET(name, value + 1);
	}
	out->blob = kvmalloc(b->bytes, GFP_KERNEL);
	if (!out->blob) { rc = -ENOMEM; goto done; }
	offset = 0;
	for (i = 0; i < b->count; i++) {
		size_t n = strlen(b->entries[i]) + 1;
		memcpy(out->blob + offset, b->entries[i], n); offset += n;
	}
	out->bytes = offset; out->count = b->count; rc = 0;
done:
	for (i = 0; i < b->count; i++) kfree_sensitive(b->entries[i]);
	kfree_sensitive(b); kfree_sensitive(command);
	if (rc) ba_v2_environment_free(out);
	return rc;
#undef ENV_SET
}
