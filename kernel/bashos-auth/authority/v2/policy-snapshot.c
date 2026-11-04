// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include "policy-snapshot.h"

static char *ba_policy_kernel_split(char *input, const char *delimiters, char **save)
{
	char *p = input ? input : *save, *start;
	if (!p) return NULL;
	p += strspn(p, delimiters);
	if (!*p) { *save = NULL; return NULL; }
	start = p;
	p += strcspn(p, delimiters);
	if (*p) { *p++ = 0; *save = p; }
	else *save = NULL;
	return start;
}

static int ba_policy_kernel_hostname(char *out, size_t size)
{
	return strscpy(out, utsname()->nodename, size) < 0 ? -1 : 0;
}

/* Syntax errors carry an exact line in the snapshot result. Never log policy
 * bytes or use a diagnostic as a successful parse result. */
static __printf(1, 2) void ba_policy_kernel_error(const char *format, ...)
{
	(void)format;
}
#define BA_POLICY_ERROR(...) ba_policy_kernel_error(__VA_ARGS__)
#define BA_POLICY_DUP(s) kstrdup(s, GFP_KERNEL)
#define BA_POLICY_FREE(p) kvfree(p)
#define BA_POLICY_SPLIT(s, d, save) ba_policy_kernel_split(s, d, save)
#define BA_POLICY_HOSTNAME(p, n) ba_policy_kernel_hostname(p, n)
#define BA_MODEL_ALLOC(n) kvzalloc(n, GFP_KERNEL)
#include "../../../../loadables/common/auth-policy-model.h"

static int ba_policy_hash_record(void *cookie, const char *record, size_t length)
{
	struct sha256_state *sha = cookie;
	sha256_update(sha, record, length);
	sha256_update(sha, (const u8 *)"\n", 1);
	return 0;
}

void ba_v2_policy_close(struct ba_v2_policy *policy)
{
	if (!policy) return;
	if (policy->document) {
		ba_policy_document_clear(policy->document);
		kvfree(policy->document);
	}
	ba_v2_trusted_close(&policy->input);
	memzero_explicit(policy, sizeof(*policy));
}

int ba_v2_policy_open(const char *path, const u8 pin[32], u64 generation,
		struct ba_v2_policy *policy)
{
	struct sha256_state sha;
	unsigned int error_line = 0;
	int rc;
	if (!policy) return -EINVAL;
	memset(policy, 0, sizeof(*policy));
	if (!generation) return -EINVAL;
	rc = ba_v2_trusted_open(path, pin, BA_POLICY_MAX_INPUT, false, &policy->input);
	if (rc) return rc;
	policy->document = kvzalloc(sizeof(*policy->document), GFP_KERNEL);
	if (!policy->document) { rc = -ENOMEM; goto failed; }
	sha256_init(&sha);
	rc = ba_policy_document_parse(policy->document, policy->input.bytes,
			policy->input.size, ba_policy_hash_record, &sha);
	if (rc) {
		error_line = policy->document->error_line;
		memzero_explicit(&sha, sizeof(sha));
		rc = -EINVAL;
		goto failed;
	}
	sha256_final(&sha, policy->normalized_digest);
	memzero_explicit(&sha, sizeof(sha));
	policy->generation = generation;
	return 0;
failed:
	ba_v2_policy_close(policy);
	policy->error_line = error_line;
	return rc;
}

int ba_v2_policy_evaluate(const struct ba_v2_policy *policy,
		const struct ba_policy_query *query, struct ba_policy_decision *decision)
{
	if (!decision) return -EINVAL;
	memset(decision, 0, sizeof(*decision));
	if (!policy || !policy->generation || !policy->input.file || !policy->document)
		return -EACCES;
	return ba_policy_document_evaluate(policy->document, query, decision) ? -EINVAL : 0;
}

bool ba_v2_policy_environment_name_safe(const char *name)
{
	return name && ba_policy_ident_ok(name) && !ba_policy_env_name_dangerous(name);
}
