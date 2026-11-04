/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_AUTH_POLICY_TYPES_H
#define BASHOS_AUTH_POLICY_TYPES_H
#define BA_POLICY_ROWS 256U
#define BA_POLICY_ALIAS_DEPTH 8U
#define BA_POLICY_EVAL_WORK 4096U
#define BA_POLICY_KEEP_NAMES 64U
#define BA_POLICY_KEEP_BYTES 64U

enum ba_policy_row_kind { BA_POLICY_ALIAS = 1, BA_POLICY_DEFAULT, BA_POLICY_RULE };
/* Alias: kind, name, values. Default: scope, key, op, value, bind.
 * Rule: user, host, runas, runas_group (empty means primary), commands. */
struct ba_policy_row {
	unsigned int kind, line;
	int nopasswd, setenv;
	char *field[5];
};
struct ba_policy_document {
	unsigned int count, error_line;
	int valid;
	struct ba_policy_row rows[BA_POLICY_ROWS];
};
/* These identities and object pins are supplied by the authority, never copied
 * from a public wire request. Caller group names correspond to actual kernel
 * gids resolved through the pinned group snapshot. Target groups come from the
 * administrator's pinned account/group snapshot. */
struct ba_policy_group { unsigned int gid; const char *name; };
struct ba_policy_subject {
	const char *name;
	unsigned int uid, primary_gid, group_count;
	const struct ba_policy_group *groups;
};
struct ba_policy_query {
	const struct ba_policy_subject *caller, *target;
	const char *host, *target_group, *command;
	unsigned int target_gid, argc;
	const char *const *argv; /* includes argv[0]; owns exact argument boundaries */
	unsigned char executable_sha256[32];
	int digest_valid, edit, validate, has_tty, preserve_environment;
};
struct ba_policy_decision {
	int allow, nopasswd, setenv, env_reset, requiretty;
	unsigned int rule_index, timestamp_seconds, password_seconds, keep_count;
	char secure_path[1024];
	char keep[BA_POLICY_KEEP_NAMES][BA_POLICY_KEEP_BYTES];
};

#endif
