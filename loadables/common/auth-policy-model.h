/* SPDX-License-Identifier: MIT */
/* Typed model of the existing sudoers subset. The platform supplies bounded
 * allocation/string operations from auth-policy-parser.h and BA_MODEL_ALLOC.
 * This evaluator accepts only previously resolved identities/objects. It does
 * not authenticate a client, open a target, issue a grant, or change credentials.
 */
#ifndef BASHOS_AUTH_POLICY_MODEL_H
#define BASHOS_AUTH_POLICY_MODEL_H
#include "auth-policy-types.h"
struct ba_policy_parse_ctx {
	struct ba_policy_document *document;
	unsigned int line;
	int (*record)(void *, const char *, size_t);
	void *cookie;
};

static void ba_policy_document_clear(struct ba_policy_document *doc)
{
	unsigned int i, j;
	if (!doc) return;
	for (i = 0; i < doc->count; i++)
		for (j = 0; j < 5; j++) BA_POLICY_FREE(doc->rows[i].field[j]);
	memset(doc, 0, sizeof(*doc));
}

static int ba_policy_emit(struct ba_policy_parse_ctx *ctx, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static int ba_policy_emit(struct ba_policy_parse_ctx *ctx, const char *fmt, ...)
{
	struct ba_policy_row row = {0};
	const char *field[5] = { "", "", "", "", "" };
	va_list ap, aq, render;
	char *record;
	int n, rc = -1;
	unsigned int i;
	if (ctx->document->count == BA_POLICY_ROWS) return -1;
	row.line = ctx->line;
	va_start(ap, fmt);
	va_copy(aq, ap);
	va_copy(render, ap);
	if (!strcmp(fmt, "alias type=%s name=%s values=%s")) {
		row.kind = BA_POLICY_ALIAS;
		for (i = 0; i < 3; i++) field[i] = va_arg(ap, const char *);
	} else if (!strncmp(fmt, "defaults ", 9)) {
		int operation = strstr(fmt, " op=%s") != NULL;
		int binding = strstr(fmt, " bind=%s") != NULL;
		row.kind = BA_POLICY_DEFAULT;
		field[0] = va_arg(ap, const char *);
		field[1] = va_arg(ap, const char *);
		field[2] = operation ? va_arg(ap, const char *) : "=";
		field[3] = va_arg(ap, const char *);
		field[4] = binding ? va_arg(ap, const char *) : "global";
		if (binding && strcmp(field[0], va_arg(ap, const char *))) goto done;
	} else if (!strncmp(fmt, "rule ", 5)) {
		row.kind = BA_POLICY_RULE;
		for (i = 0; i < 3; i++) field[i] = va_arg(ap, const char *);
		if (strstr(fmt, " runas_group=%s")) field[3] = va_arg(ap, const char *);
		row.nopasswd = va_arg(ap, int);
		row.setenv = va_arg(ap, int);
		field[4] = va_arg(ap, const char *);
	} else goto done;
	for (i = 0; i < 5; i++) {
		row.field[i] = BA_POLICY_DUP(field[i]);
		if (!row.field[i]) goto done;
	}
	n = vsnprintf(NULL, 0, fmt, aq);
	if (n < 0 || n > 4 * 4096) goto done;
	record = BA_MODEL_ALLOC((size_t)n + 1);
	if (!record) goto done;
	if (vsnprintf(record, (size_t)n + 1, fmt, render) != n ||
	    (ctx->record && ctx->record(ctx->cookie, record, (size_t)n))) {
		BA_POLICY_FREE(record);
		goto done;
	}
	BA_POLICY_FREE(record);
	ctx->document->rows[ctx->document->count++] = row;
	memset(&row, 0, sizeof(row));
	rc = 0;
done:
	va_end(render);
	va_end(aq);
	va_end(ap);
	for (i = 0; i < 5; i++) BA_POLICY_FREE(row.field[i]);
	return rc;
}

#include "auth-policy-parser.h"

static int ba_policy_model_uint(const char *s, unsigned int maximum,
		unsigned int *value)
{
	unsigned int n = 0;
	if (!s || !*s) return -1;
	for (; *s; s++) {
		unsigned int digit = (unsigned char)*s - '0';
		if (digit > 9 || digit > maximum || n > (maximum - digit) / 10) return -1;
		n = n * 10 + digit;
	}
	*value = n;
	return 0;
}

/* Return one nonempty normalized comma element; do not collapse empty ones. */
static int ba_policy_model_token(const char **next, char *token, size_t capacity)
{
	const char *end;
	size_t n;
	if (!*next) return 0;
	end = strchr(*next, ',');
	n = end ? (size_t)(end - *next) : strlen(*next);
	if (!n || n >= capacity || (end && !end[1])) return -1;
	memcpy(token, *next, n);
	token[n] = 0;
	*next = end ? end + 1 : NULL;
	return 1;
}

static int ba_policy_model_alias(const struct ba_policy_document *doc,
		const char *kind, const char *name)
{
	unsigned int i;
	for (i = 0; i < doc->count; i++) {
		const struct ba_policy_row *r = &doc->rows[i];
		if (r->kind == BA_POLICY_ALIAS && !strcmp(r->field[0], kind) &&
		    !strcmp(r->field[1], name)) return (int)i;
	}
	return -1;
}

static int ba_policy_model_validate_list(const struct ba_policy_document *doc,
		const char *kind, const char *list, unsigned int depth, unsigned int *work)
{
	char token[BA_POLICY_COMMAND_TEXT_BYTES];
	size_t capacity = !strcmp(kind, "Cmnd_Alias") ? sizeof(token) : 256;
	int rc;
	if (depth > BA_POLICY_ALIAS_DEPTH) return -1;
	while ((rc = ba_policy_model_token(&list, token, capacity)) > 0) {
		int alias;
		if (++*work > BA_POLICY_EVAL_WORK) return -1;
		if (!strcmp(token, "ALL")) continue;
		if (!ba_policy_name_ok(token, 1)) continue;
		alias = ba_policy_model_alias(doc, kind, token);
		if (alias < 0 || ba_policy_model_validate_list(doc, kind,
				doc->rows[alias].field[2], depth + 1, work)) return -1;
	}
	return rc;
}

static int ba_policy_model_validate(struct ba_policy_document *doc)
{
	unsigned int i, j;
	for (i = 0; i < doc->count; i++) {
		const struct ba_policy_row *r = &doc->rows[i];
		unsigned int work = 0, unused;
		doc->error_line = r->line;
		if (r->kind == BA_POLICY_ALIAS) {
			if (!strcmp(r->field[1], "ALL")) return -1;
			for (j = 0; j < i; j++)
				if (doc->rows[j].kind == BA_POLICY_ALIAS &&
				    !strcmp(r->field[0], doc->rows[j].field[0]) &&
				    !strcmp(r->field[1], doc->rows[j].field[1])) return -1;
			if (ba_policy_model_validate_list(doc, r->field[0], r->field[2], 0, &work))
				return -1;
		} else if (r->kind == BA_POLICY_RULE) {
			static const char *const kinds[] = {
				"User_Alias", "Host_Alias", "Runas_Alias", "Runas_Alias", "Cmnd_Alias"
			};
			for (j = 0; j < 5; j++)
				if (*r->field[j] && ba_policy_model_validate_list(doc, kinds[j],
						r->field[j], 0, &work)) return -1;
		} else {
			const char *kind = !strcmp(r->field[4], "user") ? "User_Alias" :
				!strcmp(r->field[4], "host") ? "Host_Alias" :
				!strcmp(r->field[4], "runas") ? "Runas_Alias" : "Cmnd_Alias";
			if (strcmp(r->field[4], "global") &&
			    ba_policy_model_validate_list(doc, kind, r->field[0], 0, &work)) return -1;
			if (!strcmp(r->field[1], "timestamp_timeout") &&
			    ba_policy_model_uint(r->field[3], 1440, &unused)) return -1;
			if (!strcmp(r->field[1], "passwd_timeout") &&
			    ba_policy_model_uint(r->field[3], 60, &unused)) return -1;
			if (!strcmp(r->field[1], "env_keep")) {
				char *copy = BA_POLICY_DUP(r->field[3]), *p, *save = NULL, *token;
				unsigned int count = 0;
				size_t n;
				int ok = 1;
				if (!copy) return -1;
				p = ba_policy_trim(copy); n = strlen(p);
				if (n >= 2 && ((p[0] == '"' && p[n - 1] == '"') ||
				    (p[0] == '\'' && p[n - 1] == '\''))) { p[n - 1] = 0; p++; }
				for (token = BA_POLICY_SPLIT(p, " \t,", &save); token;
				     token = BA_POLICY_SPLIT(NULL, " \t,", &save))
					if (++count > BA_POLICY_KEEP_NAMES || strlen(token) >= BA_POLICY_KEEP_BYTES) ok = 0;
				BA_POLICY_FREE(copy);
				if (!ok) return -1;
			}
			if (!strcmp(r->field[1], "secure_path")) {
				const char *s = r->field[3];
				if (strlen(s) >= sizeof(((struct ba_policy_decision *)0)->secure_path)) return -1;
				while (*s) {
					const char *end = strchr(s, ':');
					size_t n = end ? (size_t)(end - s) : strlen(s);
					if (*s != '/' || !n || ba_policy_path_has_dot_component(s, n)) return -1;
					if (!end) break;
					s = end + 1;
					if (!*s) return -1;
				}
			}
		}
	}
	doc->error_line = 0;
	doc->valid = 1;
	return 0;
}

/* Caller initializes doc to zero and discards it on any failure. No row may be
 * used until the whole input and alias graph have validated. */
static int ba_policy_document_parse(struct ba_policy_document *doc,
		const char *bytes, size_t length,
		int (*record)(void *, const char *, size_t), void *cookie)
{
	struct ba_policy_parse_ctx ctx = { .document = doc, .record = record, .cookie = cookie };
	char *line;
	size_t start = 0;
	int rc = -1;
	if (!doc || doc->count || doc->valid || (!bytes && length) || length > BA_POLICY_MAX_INPUT)
		return -1;
	line = BA_MODEL_ALLOC(BA_POLICY_MAX_LINE + 1);
	if (!line) return -1;
	while (start < length) {
		size_t end = start;
		while (end < length && bytes[end] != '\n') end++;
		if (end < length) end++;
		ctx.line++;
		doc->error_line = ctx.line;
		if (!ba_policy_line_bytes_ok(bytes + start, end - start)) goto done;
		memcpy(line, bytes + start, end - start);
		line[end - start] = 0;
		if (ba_policy_parse_line(&ctx, line, ctx.line)) goto done;
		start = end;
	}
	rc = ba_policy_model_validate(doc);
done:
	BA_POLICY_FREE(line);
	return rc;
}

enum ba_policy_match_mode { BA_MATCH_CALLER, BA_MATCH_HOST, BA_MATCH_TARGET,
	BA_MATCH_GROUP, BA_MATCH_COMMAND };

static int ba_policy_model_args(const struct ba_policy_command_spec *spec,
		const struct ba_policy_query *q)
{
	const char *p = spec->args;
	unsigned int i = 1;
	if (spec->args_mode == BA_POLICY_COMMAND_ANY_ARGS) return 1;
	if (spec->args_mode == BA_POLICY_COMMAND_NO_ARGS) return q->argc == 1;
	/* This restricted grammar cannot quote an argument containing whitespace.
 * Preserve argv boundaries instead of granting two different argv vectors that
 * happen to produce the same space-joined string. */
	while (*p) {
		const char *end;
		size_t n;
		while (*p == ' ' || *p == '\t') p++;
		if (!*p) break;
		end = p;
		while (*end && *end != ' ' && *end != '\t') end++;
		n = (size_t)(end - p);
		if (i >= q->argc || strlen(q->argv[i]) != n || memcmp(q->argv[i], p, n)) return 0;
		i++;
		p = end;
	}
	return i == q->argc;
}

static int ba_policy_model_command(const char *token, const struct ba_policy_query *q)
{
	struct ba_policy_command_spec spec;
	const char *path;
	unsigned int i, diff = 0;
	if (ba_policy_parse_command_spec(token, &spec)) return -1;
	if (q->validate) return 1; /* validation cannot issue an execution grant */
	if (spec.type == BA_POLICY_TOKEN_ALL) return 1;
	if (q->edit) return spec.type == BA_POLICY_TOKEN_SUDOEDIT_EDIT &&
		!strcmp(spec.cmd, q->command);
	if (spec.type == BA_POLICY_TOKEN_SUDOEDIT_EDIT) return 0;
	path = spec.cmd;
	if (spec.type == BA_POLICY_TOKEN_SHA256_PATH) {
		if (!q->digest_valid) return 0;
		for (i = 0; i < 32; i++) {
			unsigned int j, value = 0;
			for (j = 0; j < 2; j++) {
				unsigned char c = (unsigned char)spec.cmd[7 + i * 2 + j];
				value = value * 16 + (c >= '0' && c <= '9' ? c - '0' :
					c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10);
			}
			diff |= value ^ q->executable_sha256[i];
		}
		if (diff) return 0;
		path += 72;
	}
	if (spec.type == BA_POLICY_TOKEN_GLOB_PATH) {
		if (!ba_policy_fnmatch(path, q->command)) return 0;
	} else if (strcmp(path, q->command)) return 0;
	return ba_policy_model_args(&spec, q);
}

static int ba_policy_model_subject(const char *token, const struct ba_policy_subject *subject)
{
	unsigned int i, number;
	if (token[0] == '#') return !ba_policy_model_uint(token + 1, 0xfffffffeU, &number) &&
		number == subject->uid;
	if (token[0] != '%') return !strcmp(token, subject->name);
	for (i = 0; i < subject->group_count; i++)
		if (!strcmp(token + 1, subject->groups[i].name)) return 1;
	return 0;
}

static int ba_policy_model_match(const struct ba_policy_document *doc,
		const char *list, enum ba_policy_match_mode mode,
		const struct ba_policy_query *q, unsigned int depth, unsigned int *work)
{
	static const char *const kinds[] = {
		"User_Alias", "Host_Alias", "Runas_Alias", "Runas_Alias", "Cmnd_Alias"
	};
	char token[BA_POLICY_COMMAND_TEXT_BYTES];
	size_t capacity = mode == BA_MATCH_COMMAND ? sizeof(token) : 256;
	int rc, matched = 0;
	if (depth > BA_POLICY_ALIAS_DEPTH) return -1;
	while ((rc = ba_policy_model_token(&list, token, capacity)) > 0) {
		int one = 0;
		if (++*work > BA_POLICY_EVAL_WORK) return -1;
		if (!strcmp(token, "ALL")) one = 1;
		else if (ba_policy_name_ok(token, 1)) {
			int alias = ba_policy_model_alias(doc, kinds[mode], token);
			if (alias < 0) return -1;
			one = ba_policy_model_match(doc, doc->rows[alias].field[2], mode,
					q, depth + 1, work);
		} else if (mode == BA_MATCH_CALLER || mode == BA_MATCH_TARGET)
			one = ba_policy_model_subject(token, mode == BA_MATCH_CALLER ? q->caller : q->target);
		else if (mode == BA_MATCH_HOST) one = !strcmp(token, q->host);
		else if (mode == BA_MATCH_GROUP) {
			unsigned int gid;
			if (token[0] == '#') one = !ba_policy_model_uint(token + 1, 0xfffffffeU, &gid) &&
				gid == q->target_gid;
			else one = !strcmp(token + (token[0] == '%'), q->target_group);
		} else one = ba_policy_model_command(token, q);
		if (one < 0) return -1;
		matched |= one;
	}
	return rc < 0 ? -1 : matched;
}

static int ba_policy_model_keep(struct ba_policy_decision *out,
		const char *op, const char *value)
{
	char *copy = BA_POLICY_DUP(value), *p, *save = NULL, *token;
	size_t length;
	int rc = -1;
	if (!copy) return -1;
	p = ba_policy_trim(copy);
	length = strlen(p);
	if (length >= 2 && ((p[0] == '"' && p[length - 1] == '"') ||
	    (p[0] == '\'' && p[length - 1] == '\''))) {
		p[length - 1] = 0;
		p++;
	}
	if (!strcmp(op, "=")) out->keep_count = 0;
	for (token = BA_POLICY_SPLIT(p, " \t,", &save); token;
	     token = BA_POLICY_SPLIT(NULL, " \t,", &save)) {
		unsigned int i;
		length = strlen(token);
		if (!length || length >= BA_POLICY_KEEP_BYTES || !ba_policy_ident_ok(token) ||
		    ba_policy_env_name_dangerous(token)) goto done;
		for (i = 0; i < out->keep_count; i++) if (!strcmp(token, out->keep[i])) break;
		if (!strcmp(op, "-=")) {
			if (i < out->keep_count) {
				out->keep_count--;
				memmove(out->keep[i], out->keep[i + 1],
					(out->keep_count - i) * BA_POLICY_KEEP_BYTES);
				memset(out->keep[out->keep_count], 0, BA_POLICY_KEEP_BYTES);
			}
		} else if (i == out->keep_count) {
			if (i == BA_POLICY_KEEP_NAMES) goto done;
			memcpy(out->keep[i], token, length + 1);
			out->keep_count++;
		}
	}
	rc = 0;
done:
	BA_POLICY_FREE(copy);
	return rc;
}

static int ba_policy_model_default(const struct ba_policy_row *r,
		struct ba_policy_decision *out)
{
	unsigned int value;
	const char *key = r->field[1], *v = r->field[3];
	if (!strcmp(key, "timestamp_timeout") || !strcmp(key, "passwd_timeout")) {
		if (ba_policy_model_uint(v, !strcmp(key, "timestamp_timeout") ? 1440 : 60, &value)) return -1;
		if (!strcmp(key, "timestamp_timeout")) out->timestamp_seconds = value * 60;
		else out->password_seconds = value * 60;
	} else if (!strcmp(key, "env_reset")) out->env_reset = !strcmp(v, "true");
	else if (!strcmp(key, "requiretty")) out->requiretty = !strcmp(v, "true");
	else if (!strcmp(key, "secure_path")) {
		if (strlen(v) >= sizeof(out->secure_path)) return -1;
		memcpy(out->secure_path, v, strlen(v) + 1);
	} else if (!strcmp(key, "env_keep")) return ba_policy_model_keep(out, r->field[2], v);
	else return -1;
	return 0;
}

/* Explicit v2 precedence: matching Defaults apply in file order; the last full
 * matching rule chooses tags. Includes, negated rules, undefined aliases and
 * unsupported syntax never enter a valid document. Default caching is zero. */
static int ba_policy_document_evaluate(const struct ba_policy_document *doc,
		const struct ba_policy_query *q, struct ba_policy_decision *out)
{
	unsigned int i, j, work = 0;
	int rc;
	if (!out) return -1;
	memset(out, 0, sizeof(*out));
	if (!doc || !doc->valid || !q || !q->caller || !q->target || !q->host ||
	    !q->target_group || !q->command || q->command[0] != '/' ||
	    !q->caller->name || !q->target->name ||
	    (q->caller->group_count && !q->caller->groups) ||
	    (q->target->group_count && !q->target->groups) ||
	    (!q->edit && !q->validate && (!q->argc || !q->argv))) return -1;
	for (i = 0; !q->edit && !q->validate && i < q->argc; i++) if (!q->argv[i]) return -1;
	out->env_reset = 1;
	out->password_seconds = 300;
	memcpy(out->secure_path, "/usr/sbin:/usr/bin:/sbin:/bin",
		sizeof("/usr/sbin:/usr/bin:/sbin:/bin"));
	for (i = 0; i < doc->count; i++) {
		const struct ba_policy_row *r = &doc->rows[i];
		if (r->kind == BA_POLICY_DEFAULT) {
			enum ba_policy_match_mode mode = !strcmp(r->field[4], "user") ? BA_MATCH_CALLER :
				!strcmp(r->field[4], "host") ? BA_MATCH_HOST :
				!strcmp(r->field[4], "runas") ? BA_MATCH_TARGET : BA_MATCH_COMMAND;
			rc = !strcmp(r->field[4], "global") ? 1 :
				ba_policy_model_match(doc, r->field[0], mode, q, 0, &work);
			if (rc < 0 || (rc && ba_policy_model_default(r, out))) goto failed;
		} else if (r->kind == BA_POLICY_RULE) {
			for (j = 0; j < 5; j++) {
				if (j == 3 && !*r->field[j]) rc = q->target_gid == q->target->primary_gid;
				else rc = ba_policy_model_match(doc, r->field[j],
					(enum ba_policy_match_mode)j, q, 0, &work);
				if (rc < 0) goto failed;
				if (!rc) break;
			}
			if (j == 5) {
				out->allow = 1;
				out->rule_index = i + 1;
				out->nopasswd = r->nopasswd;
				out->setenv = r->setenv;
			}
		}
	}
	if ((out->requiretty && !q->has_tty) ||
	    (q->preserve_environment && !out->setenv)) out->allow = 0;
	return 0;
failed:
	memset(out, 0, sizeof(*out));
	return -1;
}

#endif
