/* SPDX-License-Identifier: MIT */
/* Compile on the build host; execute only in the authorized disposable guest.
 * Exact shared parser/evaluator with independently specified policy outcomes.
 * This test makes no claim about authenticated kernel grants or consumer exec.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static void diag(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void diag(const char *format, ...) { (void)format; }
static int hostname_copy(char *s, size_t n)
{
	const char name[] = "fixturehost";
	if (n < sizeof(name)) return -1;
	memcpy(s, name, sizeof(name));
	return 0;
}
#define BA_POLICY_DUP(s) strdup(s)
#define BA_POLICY_FREE(p) free(p)
#define BA_POLICY_SPLIT(s, d, save) strtok_r(s, d, save)
#define BA_POLICY_HOSTNAME(p, n) hostname_copy(p, n)
#define BA_POLICY_ERROR(...) diag(__VA_ARGS__)
#define BA_MODEL_ALLOC(n) calloc(1, n)
#include "../../../loadables/common/auth-policy-model.h"

static unsigned int assertions, failed;
static void check(int ok, const char *name)
{
	assertions++;
	if (!ok) { failed++; fprintf(stderr, "FAIL %s\n", name); }
}
static struct ba_policy_document *document;
static struct ba_policy_decision *decision;
static const struct ba_policy_group caller_groups[] = { {1000, "alice"}, {2000, "staff"} };
static const struct ba_policy_group root_groups[] = { {0, "root"} };
static const struct ba_policy_subject caller = { "alice", 1000, 1000, 2, caller_groups };
static const struct ba_policy_subject target = { "root", 0, 0, 1, root_groups };
static const char *const args[] = { "/usr/bin/id", "-u" };
static const char *const args_empty[] = { "/usr/bin/id" };
static const char *const args_other[] = { "/usr/bin/id", "-g" };
static const char *const args_ambiguous[] = { "/usr/bin/id", "-u -n" };
static const char *const args_two[] = { "/usr/bin/id", "-u", "-n" };
static struct ba_policy_query base_query(void)
{
	struct ba_policy_query q = {
		.caller = &caller, .target = &target, .host = "fixturehost", .target_group = "root",
		.command = "/usr/bin/id", .target_gid = 0, .argc = 2, .argv = args, .has_tty = 1
	};
	return q;
}
static int parse(const char *policy)
{
	ba_policy_document_clear(document);
	return ba_policy_document_parse(document, policy, strlen(policy), NULL, NULL);
}
static void expect(const char *name, const char *policy, struct ba_policy_query q,
		int allow, int nopasswd)
{
	int rc = parse(policy);
	check(rc == 0, name);
	if (!rc) {
		rc = ba_policy_document_evaluate(document, &q, decision);
		check(rc == 0 && decision->allow == allow && (!allow || decision->nopasswd == nopasswd), name);
	}
}
static void invalid(const char *name, const char *policy)
{
	struct ba_policy_query q = base_query();
	check(parse(policy) != 0 && !document->valid, name);
	memset(decision, 0xa5, sizeof(*decision));
	check(ba_policy_document_evaluate(document, &q, decision) != 0 && !decision->allow, name);
}
struct records { char bytes[4096]; size_t used; };
static int collect(void *cookie, const char *record, size_t n)
{
	struct records *r = cookie;
	if (n + 1 >= sizeof(r->bytes) - r->used) return -1;
	memcpy(r->bytes + r->used, record, n);
	r->used += n;
	r->bytes[r->used++] = '\n';
	return 0;
}

int main(void)
{
	struct ba_policy_query q = base_query();
	const char *allow = "alice ALL = (root) /usr/bin/id -u\n";
	const char *aliases =
		"User_Alias OPS = alice, bob\nRunas_Alias ADMIN = root\n"
		"Host_Alias HERE = fixturehost\nCmnd_Alias SHOW = /usr/bin/id -u,/usr/bin/true \"\"\n"
		"OPS HERE = (ADMIN) NOPASSWD: SHOW\n";
	unsigned int i;
	document = calloc(1, sizeof(*document));
	decision = calloc(1, sizeof(*decision));
	if (!document || !decision) return 99;
	expect("exact command arguments", allow, q, 1, 0);
	q.argv = args_other;
	expect("changed argument denied", allow, q, 0, 0);
	q = base_query(); q.host = "otherhost";
	expect("host denied", "alice fixturehost = (root) ALL\n", q, 0, 0);
	q = base_query();
	expect("another caller denied", "bob ALL = (root) ALL\n", q, 0, 0);
	expect("target denied", "alice ALL = (daemon) ALL\n", q, 0, 0);
	expect("numeric caller", "#1000 ALL = (root) /usr/bin/id\n", q, 1, 0);
	expect("numeric other caller", "#1001 ALL = (root) /usr/bin/id\n", q, 0, 0);
	expect("actual group", "%staff ALL = (root) /usr/bin/id\n", q, 1, 0);
	expect("absent group", "%wheel ALL = (root) /usr/bin/id\n", q, 0, 0);
	expect("typed aliases", aliases, q, 1, 1);
	expect("nested aliases", "User_Alias A = B\nUser_Alias B = alice\nA ALL = (root) ALL\n", q, 1, 0);
	expect("last matching tags require password", "alice ALL = (root) NOPASSWD: ALL\nalice ALL = (root) /usr/bin/id\n", q, 1, 0);
	expect("last unrelated tags do not replace", "alice ALL = (root) NOPASSWD: ALL\nbob ALL = (root) ALL\n", q, 1, 1);
	expect("glob direct path", "alice ALL = (root) /usr/bin/i?\n", q, 1, 0);
	q.command = "/usr/bin/sub/id";
	expect("glob does not cross slash", "alice ALL = (root) /usr/bin/*\n", q, 0, 0);
	q = base_query(); q.target_gid = 5; q.target_group = "tty";
	expect("bare runas pins primary gid", allow, q, 0, 0);
	expect("explicit runas group", "alice ALL = (root:tty) /usr/bin/id\n", q, 1, 0);
	expect("wrong runas group", "alice ALL = (root:staff) /usr/bin/id\n", q, 0, 0);
	q = base_query(); q.argc = 1; q.argv = args_empty;
	expect("no arguments positive", "alice ALL = (root) /usr/bin/id \"\"\n", q, 1, 0);
	q = base_query();
	expect("no arguments rejects extra", "alice ALL = (root) /usr/bin/id \"\"\n", q, 0, 0);
	q.argc = 2; q.argv = args_ambiguous;
	expect("argument boundaries deny joined spoof", "alice ALL = (root) /usr/bin/id -u -n\n", q, 0, 0);
	q.argc = 3; q.argv = args_two;
	expect("argument boundaries positive", "alice ALL = (root) /usr/bin/id -u -n\n", q, 1, 0);
	q = base_query(); q.has_tty = 0;
	expect("tty required", "Defaults requiretty\nalice ALL = (root) ALL\n", q, 0, 0);
	q = base_query(); q.preserve_environment = 1;
	expect("preserve needs SETENV", allow, q, 0, 0);
	expect("explicit SETENV", "alice ALL = (root) SETENV: /usr/bin/id\n", q, 1, 0);
	q = base_query(); q.command = "/etc/service.conf"; q.edit = 1;
	expect("edit specific path", "alice ALL = (root) sudoedit /etc/service.conf\n", q, 1, 0);
	expect("exec rule cannot edit", "alice ALL = (root) /etc/service.conf\n", q, 0, 0);
	q.edit = 0;
	expect("edit rule cannot execute", "alice ALL = (root) sudoedit /etc/service.conf\n", q, 0, 0);
	{
		/* The serialized edit prefix must not consume the target-path limit.
		 * Exercise every parser/normalizer/alias/evaluator stage, with literal
		 * boundary sizes independent of the implementation's capacity macro. */
		const size_t lengths[] = {246, 247, 254, 255};
		char path[257], input[768], expected_record[768];
		unsigned int j;
		for (j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
			struct records records = {0};
			memset(path, 'b', lengths[j]); path[0] = '/'; path[lengths[j]] = 0;
			q = base_query(); q.command = path; q.edit = 1;
			snprintf(input, sizeof(input), "alice ALL = (root) NOPASSWD: sudoedit %s\n", path);
			expect("full-length edit target", input, q, 1, 1);
			snprintf(expected_record, sizeof(expected_record),
				"rule user=alice host=ALL runas=root nopasswd=1 setenv=0 commands=sudoedit %s\n", path);
			ba_policy_document_clear(document);
			check(ba_policy_document_parse(document, input, strlen(input), collect, &records) == 0 &&
				records.used == strlen(expected_record) &&
				!memcmp(records.bytes, expected_record, records.used), "long edit canonical bytes");
			q.edit = 0;
			expect("long edit cannot execute", input, q, 0, 0);
			q.edit = 1; q.command = "/different";
			expect("long edit cannot authorize other path", input, q, 0, 0);
			q.command = path;
			snprintf(input, sizeof(input),
				"Cmnd_Alias LONGEDIT = sudoedit %s\nalice ALL = (root) LONGEDIT\n", path);
			expect("long edit command alias", input, q, 1, 0);
		}
		memset(path, 'b', 256); path[0] = '/'; path[256] = 0;
		snprintf(input, sizeof(input), "alice ALL = (root) sudoedit %s\n", path);
		invalid("256-byte edit target rejected without truncation", input);
		snprintf(input, sizeof(input), "alice ALL = (root) %s\n", path);
		invalid("ordinary token bound unchanged", input);
		path[255] = 0; q = base_query(); q.command = path;
		snprintf(input, sizeof(input), "alice ALL = (root) %s\n", path);
		expect("255-byte ordinary token still admitted", input, q, 1, 0);
		memset(path, 'A', 256); path[256] = 0;
		snprintf(input, sizeof(input), "User_Alias LONGUSER = %s\nalice ALL = (root) ALL\n", path);
		invalid("non-command token bound unchanged", input);
	}
	q = base_query();
	{
		const char *policy = "alice ALL = (root) sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:/usr/bin/id -u\n";
		const unsigned char digest[] = {1,35,69,103,137,171,205,239};
		for (i = 0; i < 32; i++) q.executable_sha256[i] = digest[i % 8];
		q.digest_valid = 1;
		expect("pinned executable digest", policy, q, 1, 0);
		q.executable_sha256[0] ^= 1;
		expect("changed executable digest", policy, q, 0, 0);
		q.digest_valid = 0;
		expect("missing executable digest", policy, q, 0, 0);
	}
	q = base_query();
	check(parse(allow) == 0 && ba_policy_document_evaluate(document, &q, decision) == 0 &&
		decision->timestamp_seconds == 0 && decision->env_reset == 1 &&
		!strcmp(decision->secure_path, "/usr/sbin:/usr/bin:/sbin:/bin"), "fail-closed defaults");
	check(parse("Defaults timestamp_timeout=1\nDefaults:alice timestamp_timeout=2\nDefaults:bob timestamp_timeout=9\n"
		"Defaults env_keep=TERM\nDefaults env_keep+=LANG\nDefaults env_keep-=TERM\nalice ALL = (root) ALL\n") == 0 &&
		ba_policy_document_evaluate(document, &q, decision) == 0 && decision->allow &&
		decision->timestamp_seconds == 120 && decision->keep_count == 1 &&
		!strcmp(decision->keep[0], "LANG"), "ordered scoped defaults and env operations");
	expect("empty policy denies", "", q, 0, 0);
	expect("comments only deny", "# no grants\n", q, 0, 0);
	invalid("undefined user alias", "MISSING ALL = (root) ALL\n");
	invalid("undefined command alias", "alice ALL = (root) MISSING\n");
	invalid("self alias", "User_Alias A = A\nalice ALL = (root) ALL\n");
	invalid("cyclic aliases", "User_Alias A = B\nUser_Alias B = A\nalice ALL = (root) ALL\n");
	invalid("duplicate aliases", "User_Alias A = alice\nUser_Alias A = bob\n");
	invalid("reserved ALL alias", "User_Alias ALL = alice\n");
	invalid("cross-kind alias", "User_Alias A = alice\nalice ALL = (root) A\n");
	invalid("unsupported negation", "alice ALL = (root) !/usr/bin/id\n");
	invalid("include rejected", "alice ALL = (root) ALL\n#include unsafe\n");
	invalid("valid prefix invalid tail", "alice ALL = (root) ALL\nalice ALL (root) ALL\n");
	invalid("empty command list entry", "alice ALL = (root) /usr/bin/id,,/usr/bin/true\n");
	invalid("trailing command comma", "alice ALL = (root) /usr/bin/id,\n");
	invalid("empty alias entry", "User_Alias A = alice, ,bob\n");
	invalid("empty runas entry", "alice ALL = (root,,daemon) ALL\n");
	invalid("timeout overflow", "Defaults timestamp_timeout=429496729600\n");
	invalid("negative timeout unsupported", "Defaults timestamp_timeout=-1\n");
	invalid("unsafe environment", "Defaults env_keep=LD_PRELOAD\n");
	invalid("unsafe secure_path empty component", "Defaults secure_path=/usr/bin::/bin\n");
	invalid("unsafe secure_path dot component", "Defaults secure_path=/usr/bin:/a/../bin\n");
	{
		char long_command[700], input[900];
		memset(long_command, 'x', sizeof(long_command) - 1);
		long_command[0] = '/'; long_command[sizeof(long_command) - 1] = 0;
		snprintf(input, sizeof(input), "alice ALL = (root) %s\n", long_command);
		invalid("overlong command never truncated", input);
	}
	{
		char input[] = "alice ALL = (root) ALL\0bob ALL (root) ALL\n";
		ba_policy_document_clear(document);
		check(ba_policy_document_parse(document, input, sizeof(input) - 1, NULL, NULL) != 0 &&
			!document->valid, "embedded NUL never truncates input");
	}
	{
		char *input = malloc(BA_POLICY_MAX_LINE + 2);
		if (!input) return 99;
		memset(input, '#', BA_POLICY_MAX_LINE + 1); input[BA_POLICY_MAX_LINE + 1] = 0;
		invalid("overlong comment rejected before parsing", input);
		free(input);
	}
	{
		struct records records = {0};
		const char policy[] = "Defaults env_reset\nUser_Alias OPS = alice, bob\nOPS ALL = ( root : root ) NOPASSWD: /usr/bin/id -u\n";
		const char expected[] = "defaults scope=global key=env_reset value=true\nalias type=User_Alias name=OPS values=alice,bob\nrule user=OPS host=ALL runas=root runas_group=root nopasswd=1 setenv=0 commands=/usr/bin/id -u\n";
		ba_policy_document_clear(document);
		check(ba_policy_document_parse(document, policy, sizeof(policy) - 1, collect, &records) == 0 &&
			records.used == sizeof(expected) - 1 && !memcmp(records.bytes, expected, sizeof(expected) - 1),
			"independent exact canonical records");
	}
	ba_policy_document_clear(document); free(document); free(decision);
	printf("{\"assertions\":%u,\"failures\":%u,\"authority_runtime\":false}\n", assertions, failed);
	return failed ? 1 : 0;
}
