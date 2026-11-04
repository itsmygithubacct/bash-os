// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include "identity-snapshot.h"

static bool identity_name(const char *s)
{
	size_t i, n = strlen(s);
	if (!n || n >= BA_V2_USER_BYTES) return false;
	for (i = 0; i < n; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
		      (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' || s[i] == '.'))
			return false;
	return true;
}

static int identity_number(const char *s, u32 *out)
{
	u32 n = 0;
	if (!s || !*s) return -EINVAL;
	for (; *s; s++) {
		u32 d = (u8)*s - '0';
		if (d > 9 || n > (U32_MAX - 1 - d) / 10) return -EINVAL;
		n = n * 10 + d;
	}
	*out = n;
	return 0;
}

static const struct ba_v2_group *identity_group(const struct ba_v2_groups *groups, u32 gid)
{
	u32 i;
	for (i = 0; i < groups->count; i++) if (groups->records[i].gid == gid) return &groups->records[i];
	return NULL;
}

static const struct ba_v2_account_record *identity_account_uid(
		const struct ba_v2_accounts *accounts, u32 uid)
{
	const struct ba_v2_account_record *found = NULL;
	u32 i;
	for (i = 0; i < accounts->count; i++) {
		const struct ba_v2_account_record *r = accounts->records + i;
		if (le32_to_cpu(r->uid) != uid || !(le32_to_cpu(r->flags) & BA_V2_ACCOUNT_ENABLED)) continue;
		if (found) return NULL;
		found = r;
	}
	return found;
}

static bool identity_member(const struct ba_v2_group *group, u32 uid)
{
	u32 i;
	for (i = 0; i < group->count; i++) if (group->members[i] == uid) return true;
	return false;
}

static int group_line(char *line, const struct ba_v2_accounts *accounts,
		struct ba_v2_groups *groups)
{
	char *name, *placeholder, *number, *members, *member;
	struct ba_v2_group *g;
	u32 i;
	if (!*line || *line == '#') return 0;
	if (groups->count == BA_V2_MAX_GROUPS) return -E2BIG;
	name = strsep(&line, ":");
	placeholder = strsep(&line, ":");
	number = strsep(&line, ":");
	members = strsep(&line, ":");
	if (!name || !placeholder || !number || !members || line ||
	    !identity_name(name) || strlen(placeholder) > 128) return -EINVAL;
	g = &groups->records[groups->count];
	if (identity_number(number, &g->gid)) return -EINVAL;
	strscpy(g->name, name, sizeof(g->name));
	for (i = 0; i < groups->count; i++)
		if (groups->records[i].gid == g->gid || !strcmp(groups->records[i].name, name)) return -EINVAL;
	while (*members) {
		const struct ba_v2_account_record *a;
		char *next = members;
		member = strsep(&next, ",");
		if (!identity_name(member) || (next && !*next)) return -EINVAL;
		a = ba_v2_account_find(accounts, member);
		if (!a || g->count == BA_V2_MAX_ACCOUNTS || identity_member(g, le32_to_cpu(a->uid)))
			return -EINVAL;
		g->members[g->count++] = le32_to_cpu(a->uid);
		if (!next) break;
		members = next;
	}
	groups->count++;
	return 0;
}

void ba_v2_groups_close(struct ba_v2_groups *groups)
{
	if (!groups) return;
	ba_v2_trusted_close(&groups->input);
	memzero_explicit(groups, sizeof(*groups));
}

int ba_v2_groups_open(const char *path, const u8 pin[32], u64 generation,
		const struct ba_v2_accounts *accounts, struct ba_v2_groups *groups)
{
	char *copy, *rest, *line;
	size_t i;
	int rc;
	if (!groups) return -EINVAL;
	memset(groups, 0, sizeof(*groups));
	if (!accounts || !accounts->generation || !generation) return -EINVAL;
	for (i = 0; i < accounts->count; i++) {
		const struct ba_v2_account_record *a = accounts->records + i;
		if ((le32_to_cpu(a->flags) & BA_V2_ACCOUNT_ENABLED) &&
		    identity_account_uid(accounts, le32_to_cpu(a->uid)) != a) return -EINVAL;
	}
	rc = ba_v2_trusted_open(path, pin, 65536, false, &groups->input);
	if (rc) return rc;
	for (i = 0; i < groups->input.size; i++) {
		u8 c = ((const u8 *)groups->input.bytes)[i];
		if (!c || c > 126 || (c < 32 && c != '\n')) { rc = -EINVAL; goto failed; }
	}
	copy = kvmalloc(groups->input.size + 1, GFP_KERNEL);
	if (!copy) { rc = -ENOMEM; goto failed; }
	memcpy(copy, groups->input.bytes, groups->input.size);
	copy[groups->input.size] = 0;
	rest = copy;
	while ((line = strsep(&rest, "\n"))) {
		if (strlen(line) > 4096) { rc = -E2BIG; break; }
		rc = group_line(line, accounts, groups);
		if (rc) break;
	}
	kvfree_sensitive(copy, groups->input.size + 1);
	if (rc) goto failed;
	for (i = 0; i < accounts->count; i++)
		if ((le32_to_cpu(accounts->records[i].flags) & BA_V2_ACCOUNT_ENABLED) &&
		    !identity_group(groups, le32_to_cpu(accounts->records[i].gid))) { rc = -EINVAL; goto failed; }
	groups->generation = generation;
	return 0;
failed:
	ba_v2_groups_close(groups);
	return rc;
}

static int caller_group_add(struct ba_v2_identity_binding *out,
		const struct ba_v2_groups *groups, u32 gid)
{
	const struct ba_v2_group *g = identity_group(groups, gid);
	u32 i;
	if (!g) return -EACCES;
	for (i = 0; i < out->caller.group_count; i++) if (out->caller_groups[i].gid == gid) return 0;
	if (i == BA_V2_MAX_GROUPS) return -E2BIG;
	out->caller_groups[i].gid = gid;
	out->caller_groups[i].name = g->name;
	out->caller.group_count++;
	return 0;
}

int ba_v2_identity_bind(const struct ba_v2_accounts *accounts,
		const struct ba_v2_groups *groups, const struct cred *actor,
		const struct bashos_auth_privcmd *r, struct ba_v2_identity_binding *out)
{
	const struct ba_v2_account_record *caller, *target;
	const struct ba_v2_group *selected;
	u32 uid, gid, i;
	int rc = -EACCES;
	if (!out) return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!accounts || !accounts->generation || !groups || !groups->generation || !actor || !r ||
	    actor->user_ns != &init_user_ns || !uid_eq(actor->uid, actor->euid) ||
	    !uid_eq(actor->uid, actor->suid) || !uid_eq(actor->uid, actor->fsuid) ||
	    !gid_eq(actor->gid, actor->egid) || !gid_eq(actor->gid, actor->sgid) ||
	    !gid_eq(actor->gid, actor->fsgid) ||
	    !memchr(r->caller_user, 0, sizeof(r->caller_user)) ||
	    !memchr(r->target_user, 0, sizeof(r->target_user))) return -EACCES;
	uid = from_kuid(&init_user_ns, actor->uid);
	gid = from_kgid(&init_user_ns, actor->gid);
	caller = identity_account_uid(accounts, uid);
	target = ba_v2_account_find(accounts, r->target_user);
	if (!caller || !target || r->caller_uid != uid || r->caller_gid != gid ||
	    le32_to_cpu(caller->gid) != gid || strcmp(r->caller_user, caller->user) ||
	    r->target_uid != le32_to_cpu(target->uid) ||
	    (!(r->flags & BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP) && r->target_gid != le32_to_cpu(target->gid)))
		return -EACCES;
	selected = identity_group(groups, r->target_gid);
	if (!selected) return -EACCES;
	out->caller_account = caller; out->target_account = target;
	out->caller.name = caller->user; out->caller.uid = uid; out->caller.primary_gid = gid;
	out->caller.groups = out->caller_groups;
	out->target.name = target->user; out->target.uid = le32_to_cpu(target->uid);
	out->target.primary_gid = le32_to_cpu(target->gid); out->target.groups = out->target_groups;
	out->target_gid = r->target_gid; out->target_group = selected->name;
	rc = caller_group_add(out, groups, gid);
	if (rc) goto failed;
	if (actor->group_info->ngroups > BA_V2_MAX_GROUPS) { rc = -E2BIG; goto failed; }
	for (i = 0; i < actor->group_info->ngroups; i++) {
		rc = caller_group_add(out, groups, from_kgid(&init_user_ns, actor->group_info->gid[i]));
		if (rc) goto failed;
	}
	for (i = 0; i < groups->count; i++) {
		const struct ba_v2_group *g = &groups->records[i];
		bool member = identity_member(g, out->target.uid);
		if (g->gid == out->target.primary_gid || member) {
			u32 at = out->target.group_count++;
			out->target_groups[at].gid = g->gid; out->target_groups[at].name = g->name;
		}
		if (g->gid == r->target_gid || member) out->exec_gids[out->exec_group_count++] = g->gid;
	}
	return 0;
failed:
	memzero_explicit(out, sizeof(*out));
	return rc;
}

const struct ba_v2_profile *ba_v2_profile_find(const struct ba_v2_profiles *profiles, const char *user)
{
	u32 i;
	if (!profiles || !user) return NULL;
	for (i = 0; i < profiles->count; i++)
		if (!strcmp(profiles->records[i].user, user)) return &profiles->records[i];
	return NULL;
}

void ba_v2_profiles_close(struct ba_v2_profiles *profiles)
{
	if (!profiles) return;
	ba_v2_trusted_close(&profiles->input);
	memzero_explicit(profiles, sizeof(*profiles));
}

static bool profile_path(const char *path)
{
	const char *p;
	if (!path || path[0] != '/' || strlen(path) >= 256) return false;
	for (p = path; *p;) {
		const char *end;
		size_t n;
		while (*p == '/') p++;
		end = strchr(p, '/'); n = end ? (size_t)(end - p) : strlen(p);
		if ((n == 1 && *p == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) return false;
		if (!end) break;
		p = end;
	}
	return true;
}

static int profile_line(char *line, const struct ba_v2_accounts *accounts,
		struct ba_v2_profiles *profiles)
{
	char *field[7];
	const struct ba_v2_account_record *a;
	struct ba_v2_profile *record;
	u32 i, uid, gid;
	if (!*line || *line == '#') return 0;
	for (i = 0; i < ARRAY_SIZE(field); i++) {
		field[i] = strsep(&line, ":");
		if (!field[i]) return -EINVAL;
	}
	if (line || profiles->count == BA_V2_MAX_ACCOUNTS ||
	    !identity_name(field[0]) || ba_v2_profile_find(profiles, field[0]) ||
	    strlen(field[1]) > 128 || strlen(field[4]) > 256 ||
	    identity_number(field[2], &uid) || identity_number(field[3], &gid) ||
	    !profile_path(field[5]) || !profile_path(field[6])) return -EINVAL;
	a = ba_v2_account_find(accounts, field[0]);
	if (!a || uid != le32_to_cpu(a->uid) || gid != le32_to_cpu(a->gid)) return -EINVAL;
	record = &profiles->records[profiles->count++];
	strscpy(record->user, field[0], sizeof(record->user));
	strscpy(record->home, field[5], sizeof(record->home));
	strscpy(record->shell, field[6], sizeof(record->shell));
	return 0;
}

int ba_v2_profiles_open(const char *path, const u8 pin[32], u64 generation,
		const struct ba_v2_accounts *accounts, struct ba_v2_profiles *profiles)
{
	char *copy, *rest, *line;
	size_t i;
	int rc;
	if (!profiles) return -EINVAL;
	memset(profiles, 0, sizeof(*profiles));
	if (!accounts || !accounts->generation || !generation) return -EINVAL;
	rc = ba_v2_trusted_open(path, pin, 32768, false, &profiles->input);
	if (rc) return rc;
	for (i = 0; i < profiles->input.size; i++) {
		u8 c = ((const u8 *)profiles->input.bytes)[i];
		if (!c || c > 126 || (c < 32 && c != '\n')) { rc = -EINVAL; goto failed; }
	}
	copy = kvmalloc(profiles->input.size + 1, GFP_KERNEL);
	if (!copy) { rc = -ENOMEM; goto failed; }
	memcpy(copy, profiles->input.bytes, profiles->input.size);
	copy[profiles->input.size] = 0;
	rest = copy;
	while ((line = strsep(&rest, "\n"))) {
		if (strlen(line) > 1024) { rc = -E2BIG; break; }
		rc = profile_line(line, accounts, profiles);
		if (rc) break;
	}
	kvfree_sensitive(copy, profiles->input.size + 1);
	if (rc) goto failed;
	for (i = 0; i < accounts->count; i++)
		if ((le32_to_cpu(accounts->records[i].flags) & BA_V2_ACCOUNT_ENABLED) &&
		    !ba_v2_profile_find(profiles, accounts->records[i].user)) { rc = -EINVAL; goto failed; }
	profiles->generation = generation;
	return 0;
failed:
	ba_v2_profiles_close(profiles);
	return rc;
}
