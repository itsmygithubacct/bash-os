/* SPDX-License-Identifier: MIT */
/* Shared project sudoers-subset grammar and canonical records. Platform users
 * define struct ba_policy_parse_ctx, ba_policy_emit and the five operations
 * below before inclusion. This parser alone makes no authorization decision. */
#ifndef BASHOS_AUTH_POLICY_PARSER_H
#define BASHOS_AUTH_POLICY_PARSER_H
#if !defined(BA_POLICY_DUP) || !defined(BA_POLICY_FREE) || !defined(BA_POLICY_SPLIT) || !defined(BA_POLICY_HOSTNAME) || !defined(BA_POLICY_ERROR)
#error "policy parser platform operations required"
#endif
#define BA_POLICY_MAX_LINE 4096U
#define BA_POLICY_MAX_INPUT 65536U
/* A 255-byte target still needs the serialized "sudoedit " prefix and NUL.
 * This changes command-text storage only; cmd[] and ordinary tokens retain
 * their 256-byte bound. The model and normalizer must use the same capacity. */
#define BA_POLICY_COMMAND_TEXT_BYTES (256U + sizeof("sudoedit ") - 1U)

static int ba_policy_ascii_isspace (unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}
static int ba_policy_ascii_isdigit (unsigned char c) { return c >= '0' && c <= '9'; }
static int ba_policy_ascii_isupper (unsigned char c) { return c >= 'A' && c <= 'Z'; }
static int ba_policy_ascii_isalnum (unsigned char c)
{
	return ba_policy_ascii_isdigit(c) || ba_policy_ascii_isupper(c) || (c >= 'a' && c <= 'z');
}
static int ba_policy_ascii_isxdigit (unsigned char c)
{
	return ba_policy_ascii_isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Input length is supplied by the reader, before C-string parsing. */
static int
ba_policy_line_bytes_ok (const char *line, size_t n)
{
	if (!line || n > BA_POLICY_MAX_LINE)
		return 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char) line[i];
		if (c == 0 || c == 0x7f || (c < 0x20 && c != '\t' && c != '\n' && c != '\r'))
			return 0;
	}
	return 1;
}

static char *
ba_policy_trim (char *s)
{
	while (*s && ba_policy_ascii_isspace ((unsigned char) *s)) s++;
	char *e = s + strlen (s);
	while (e > s && ba_policy_ascii_isspace ((unsigned char) e[-1])) *--e = '\0';
	return s;
}

static int
ba_policy_has_glob_or_negation (const char *s)
{
	for (; *s; s++)
		if (*s == '*' || *s == '?' || *s == '[' || *s == ']' || *s == '!')
			return 1;
	return 0;
}

static int
ba_policy_has_negation (const char *s)
{
	for (; *s; s++)
		if (*s == '!')
			return 1;
	return 0;
}

static int
ba_policy_path_has_glob (const char *s)
{
	int esc = 0;

	for (; *s; s++) {
		if (esc) {
			if (*s == '*' || *s == '?' || *s == '[' ||
			    *s == ']' || *s == '\\')
				return 1;
			esc = 0;
			continue;
		}
		if (*s == '\\') {
			esc = 1;
			continue;
		}
		if (*s == '*' || *s == '?' || *s == '[' || *s == ']')
			return 1;
	}
	return 0;
}

static int
ba_policy_glob_syntax_ok (const char *s)
{
	int esc = 0, in_class = 0, class_has_char = 0;

	for (; *s; s++) {
		if (esc) {
			esc = 0;
			if (in_class)
				class_has_char = 1;
			continue;
		}
		if (*s == '\\') {
			esc = 1;
			continue;
		}
		if (*s == '!')
			return 0;
		if (*s == '[' && !in_class) {
			in_class = 1;
			class_has_char = 0;
			continue;
		}
		if (*s == ']' && in_class) {
			if (!class_has_char)
				return 0;
			in_class = 0;
			continue;
		}
		if (in_class)
			class_has_char = 1;
	}
	return !in_class;
}

static int
ba_policy_path_has_dot_component (const char *s, size_t len)
{
	size_t start = 0;

	while (start < len) {
		size_t end = start;

		while (start < len && s[start] == '/')
			start++;
		end = start;
		while (end < len && s[end] != '/')
			end++;
		if (end > start &&
		    ((end - start == 1 && s[start] == '.') ||
		     (end - start == 2 && s[start] == '.' && s[start + 1] == '.')))
			return 1;
		start = end;
	}
	return 0;
}

static int
ba_policy_normalize_cmd_path (const char *in, char *out, size_t cap)
{
	size_t i, pos = 0, len;

	if (!in || !out || cap < 2 || in[0] != '/')
		return -1;
	len = strnlen (in, 256);
	if (len == 0 || len >= 256)
		return -1;
	if (ba_policy_path_has_dot_component (in, len))
		return -1;
	for (i = 0; in[i]; i++) {
		if (in[i] == '/' && pos > 0 && out[pos - 1] == '/')
			continue;
		if (pos + 1 >= cap)
			return -1;
		out[pos++] = in[i];
	}
	while (pos > 1 && out[pos - 1] == '/')
		pos--;
	out[pos] = '\0';
	return pos ? 0 : -1;
}

static int
ba_policy_class_match (const char **patp, char c)
{
	const char *p = *patp;
	int matched = 0, any = 0, negate = 0;

	/* FNM_PATHNAME: a class never matches '/' or the empty string. '!' as
	   the first class character negates; a leading ']' stays literal. */
	if (!c || c == '/')
		return 0;
	if (*p == '!') {
		negate = 1;
		p++;
	}
	if (*p == ']') {
		matched = c == ']';
		any = 1;
		p++;
	}
	while (*p && *p != ']') {
		char first, last;

		if (*p == '\\' && p[1])
			p++;
		first = *p++;
		any = 1;
		if (*p == '-' && p[1] && p[1] != ']') {
			p++;
			if (*p == '\\' && p[1])
				p++;
			last = *p++;
			if ((first <= last && c >= first && c <= last) ||
			    (last < first && c >= last && c <= first))
				matched = 1;
		} else if (c == first) {
			matched = 1;
		}
	}
	if (*p != ']' || !any)
		return 0;
	*patp = p + 1;
	return negate ? !matched : matched;
}

static int
ba_policy_fnmatch_inner (const char *pat, const char *str, unsigned int depth)
{
	if (depth > 512)
		return 0;
	while (*pat) {
		char pc = *pat++;

		if (pc == '\\' && *pat) {
			pc = *pat++;
			if (*str++ != pc)
				return 0;
			continue;
		}
		if (pc == '?') {
			if (!*str || *str == '/')
				return 0;
			str++;
			continue;
		}
		if (pc == '*') {
			const char *scan = str;

			while (*pat == '*')
				pat++;
			do {
				if (ba_policy_fnmatch_inner (pat, scan, depth + 1))
					return 1;
				if (!*scan || *scan == '/')
					break;
				scan++;
			} while (1);
			return 0;
		}
		if (pc == '[') {
			if (!ba_policy_class_match (&pat, *str))
				return 0;
			str++;
			continue;
		}
		if (*str++ != pc)
			return 0;
	}
	return *str == '\0';
}

static int
ba_policy_fnmatch (const char *pat, const char *str)
{
	if (!pat || !str)
		return 0;
	return ba_policy_fnmatch_inner (pat, str, 0);
}

static int
ba_policy_name_ok (const char *s, int alias)
{
	if (!s || !*s) return 0;
	if (alias && !ba_policy_ascii_isupper ((unsigned char) *s)) return 0;
	if (!alias && !(ba_policy_ascii_isalnum ((unsigned char) *s) || *s == '_' || *s == '%' || *s == '.'))
		return 0;
	for (const char *p = s + 1; *p; p++) {
		if (ba_policy_ascii_isalnum ((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.')
			continue;
		return 0;
	}
	return 1;
}

static int
ba_policy_ident_ok (const char *s)
{
	if (!s || !((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_'))
		return 0;
	for (const char *p = s + 1; *p; p++)
		if (!(ba_policy_ascii_isalnum ((unsigned char) *p) || *p == '_'))
			return 0;
	return 1;
}

static int
ba_policy_uint_ok (const char *s)
{
	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++)
		if (!ba_policy_ascii_isdigit ((unsigned char) *p))
			return 0;
	return 1;
}

static int
ba_policy_bool_value (const char *s, const char **normalized)
{
	if (!s || !*s)
		return 0;
	if (strcmp (s, "true") == 0 || strcmp (s, "on") == 0) {
		if (normalized) *normalized = "true";
		return 1;
	}
	if (strcmp (s, "false") == 0 || strcmp (s, "off") == 0) {
		if (normalized) *normalized = "false";
		return 1;
	}
	return 0;
}

static int
ba_policy_secure_path_ok (const char *s)
{
	if (!s || s[0] != '/')
		return 0;
	if (ba_policy_has_glob_or_negation (s))
		return 0;
	for (const char *p = s; *p; p++)
		if (ba_policy_ascii_isspace ((unsigned char) *p))
			return 0;
	return 1;
}

static int
ba_policy_env_name_dangerous (const char *s)
{
	/* Keep in sync with bashos_ce_env_name_is_dangerous
	   (_bashauth/cred_exec.c), the canonical runtime scrub. */
	static const char *const exact[] = {
		"BASH_ENV", "CDPATH", "ENV", "GETCONF_DIR", "GLOBIGNORE",
		"GCONV_PATH", "HOSTALIASES", "IFS", "LOCPATH", "NLSPATH",
		"NODE_OPTIONS", "NODE_PATH", "PERL5LIB", "PERL5OPT",
		"PROMPT_COMMAND", "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH",
		"PYTHONSTARTUP", "RES_OPTIONS", "RUBYLIB", "RUBYOPT",
		"TERMCAP", "TZDIR",
		/* Bash startup-influencing family + interpreter extras (added
		   2026-06-28 to match the canonical cred_exec.c list). */
		"SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD",
		"PERLLIB", "PERL5DB", "PYTHONUSERBASE", "PYTHONNOUSERSITE",
		"PYTHONOPTIMIZE", "RUBYPATH",
	};
	static const char *const prefix[] = {
		"BASH_FUNC_", "DYLD_", "LD_",
	};

	for (size_t i = 0; i < sizeof (exact) / sizeof (exact[0]); i++)
		if (strcmp (s, exact[i]) == 0)
			return 1;
	for (size_t i = 0; i < sizeof (prefix) / sizeof (prefix[0]); i++)
		if (strncmp (s, prefix[i], strlen (prefix[i])) == 0)
			return 1;
	return 0;
}

static int
ba_policy_env_list_ok (const char *value)
{
	char *copy = BA_POLICY_DUP (value);
	if (!copy)
		return 0;
	char *v = ba_policy_trim (copy);
	size_t len = strlen (v);
	if (len >= 2 && ((v[0] == '"' && v[len - 1] == '"') ||
	                 (v[0] == '\'' && v[len - 1] == '\''))) {
		v[len - 1] = '\0';
		v++;
	}
	int n = 0;
	char *save = NULL;
	for (char *tok = BA_POLICY_SPLIT (v, " \t,", &save); tok; tok = BA_POLICY_SPLIT (NULL, " \t,", &save)) {
		if (!ba_policy_ident_ok (tok) || ba_policy_has_glob_or_negation (tok) ||
		    ba_policy_env_name_dangerous (tok)) {
			BA_POLICY_FREE (copy);
			return 0;
		}
		n++;
	}
	BA_POLICY_FREE (copy);
	return n > 0;
}

static int
ba_policy_sha256_cmd_ok (const char *s)
{
	if (strncmp (s, "sha256:", 7) != 0) return 0;
	const char *hex = s + 7;
	for (int i = 0; i < 64; i++)
		if (!ba_policy_ascii_isxdigit ((unsigned char) hex[i]))
			return 0;
	return hex[64] == ':' && hex[65] == '/';
}

enum ba_policy_command_args_mode {
	BA_POLICY_COMMAND_ANY_ARGS = 0,
	BA_POLICY_COMMAND_NO_ARGS,
	BA_POLICY_COMMAND_EXACT_ARGS
};

enum ba_policy_token_type {
	BA_POLICY_TOKEN_ALL = 1,
	BA_POLICY_TOKEN_ALIAS_REF = 2,
	BA_POLICY_TOKEN_SHA256_PATH = 3,
	BA_POLICY_TOKEN_ABSOLUTE_PATH = 4,
	BA_POLICY_TOKEN_SUDOEDIT_EDIT = 5,
	BA_POLICY_TOKEN_GLOB_PATH = 6
};

struct ba_policy_command_spec {
	int type;
	enum ba_policy_command_args_mode args_mode;
	char cmd[256];
	char args[256];
};

static int
ba_policy_arg_text_ok (const char *s)
{
	if (!s || !*s)
		return 0;
	if (strcmp (s, "\"\"") == 0)
		return 1;
	for (const char *p = s; *p; p++) {
		unsigned char c = (unsigned char) *p;
		if (c == '"' || c == '\'' || c == '\\' || c == ',' ||
		    c == ';' || c == '&' || c == '|' || c == '`' ||
		    c == '$' || c == '<' || c == '>' || c == '(' || c == ')' ||
		    c == '*' || c == '?' || c == '[' || c == ']' || c == '!')
			return 0;
		if (c < 0x20 && !ba_policy_ascii_isspace (c))
			return 0;
	}
	return 1;
}

static int
ba_policy_parse_command_spec (const char *tok, struct ba_policy_command_spec *spec)
{
	char buf[BA_POLICY_COMMAND_TEXT_BYTES];
	char norm[256];
	char *p, *args = NULL, *scan;
	size_t cmd_len;
	int ret;

	if (!tok || !spec || strnlen (tok, sizeof buf) >= sizeof buf)
		return -1;
	memset (spec, 0, sizeof *spec);
	snprintf (buf, sizeof buf, "%s", tok);
	p = ba_policy_trim (buf);
	if (!*p)
		return -1;
	if (strnlen (tok, 256) >= 256 &&
	    !(strncmp (p, "sudoedit", 8) == 0 && (p[8] == ' ' || p[8] == '\t')))
		return -1;
	if (strcmp (p, "ALL") == 0) {
		spec->type = BA_POLICY_TOKEN_ALL;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		memcpy (spec->cmd, "ALL", 4);
		return 0;
	}
	if (ba_policy_name_ok (p, 1)) {
		size_t n = strlen (p);
		if (n >= sizeof spec->cmd)
			return -1;
		spec->type = BA_POLICY_TOKEN_ALIAS_REF;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		memcpy (spec->cmd, p, n + 1);
		return 0;
	}
	/* `sudoedit <abs-path>`: an EDIT-ONLY command spec. Shared by the offline client and versioned kernel parser. Single
	 * absolute target per spec, no command args. type 5 = SUDOEDIT_EDIT. */
	if (strncmp (p, "sudoedit", 8) == 0 && (p[8] == ' ' || p[8] == '\t')) {
		char *t = ba_policy_trim (p + 8);
		if (t[0] != '/')
			return -1;
		if (ba_policy_has_glob_or_negation (t))
			return -1;
		for (const char *q = t; *q; q++)
			if (ba_policy_ascii_isspace ((unsigned char) *q))
				return -1;
		if (ba_policy_normalize_cmd_path (t, norm, sizeof norm) < 0)
			return -1;
		if (!norm[0] || strlen (norm) >= sizeof spec->cmd)
			return -1;
		spec->type = BA_POLICY_TOKEN_SUDOEDIT_EDIT;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		snprintf (spec->cmd, sizeof spec->cmd, "%s", norm);
		return 0;
	}

	scan = p;
	if (ba_policy_sha256_cmd_ok (p))
		scan = p + 72;
	else if (p[0] != '/')
		return -1;
	for (; *scan && !ba_policy_ascii_isspace ((unsigned char) *scan); scan++)
		;
	if (*scan) {
		*scan++ = '\0';
		args = ba_policy_trim (scan);
	}
	if (ba_policy_sha256_cmd_ok (p)) {
		spec->type = BA_POLICY_TOKEN_SHA256_PATH;
		if (p[72] != '/')
			return -1;
		if (ba_policy_has_glob_or_negation (p))
			return -1;
		if (ba_policy_normalize_cmd_path (p + 72, norm, sizeof norm) < 0)
			return -1;
		ret = snprintf (spec->cmd, sizeof spec->cmd, "%.72s%s", p, norm);
		if (ret < 0 || ret >= (int) sizeof spec->cmd)
			return -1;
	} else {
		if (ba_policy_has_negation (p))
			return -1;
		if (ba_policy_normalize_cmd_path (p, norm, sizeof norm) < 0)
			return -1;
		if (ba_policy_path_has_glob (norm)) {
			if (!ba_policy_glob_syntax_ok (norm))
				return -1;
			spec->type = BA_POLICY_TOKEN_GLOB_PATH;
		} else {
			spec->type = BA_POLICY_TOKEN_ABSOLUTE_PATH;
		}
	}
	if (spec->type != BA_POLICY_TOKEN_SHA256_PATH)
		snprintf (spec->cmd, sizeof spec->cmd, "%s", norm);
	cmd_len = strlen (spec->cmd);
	if (cmd_len == 0 || cmd_len >= sizeof spec->cmd)
		return -1;
	if (!args || !*args) {
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		return 0;
	}
	if (!ba_policy_arg_text_ok (args) || strlen (args) >= sizeof spec->args)
		return -1;
	if (strcmp (args, "\"\"") == 0) {
		spec->args_mode = BA_POLICY_COMMAND_NO_ARGS;
		return 0;
	}
	spec->args_mode = BA_POLICY_COMMAND_EXACT_ARGS;
	snprintf (spec->args, sizeof spec->args, "%s", args);
	return 0;
}

static int
ba_policy_append_text (char *out, size_t cap, size_t *pos, const char *s)
{
	size_t len;

	if (!out || !pos || !s)
		return -1;
	len = strlen (s);
	if (*pos + len >= cap)
		return -1;
	memcpy (out + *pos, s, len);
	*pos += len;
	out[*pos] = '\0';
	return 0;
}

static int
ba_policy_normalize_command_spec_text (const char *tok, char *out, size_t cap)
{
	struct ba_policy_command_spec spec;
	size_t pos = 0;
	int ret;

	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	ret = ba_policy_parse_command_spec (tok, &spec);
	if (ret)
		return ret;
	if (spec.type == BA_POLICY_TOKEN_SUDOEDIT_EDIT) {
		ret = snprintf (out, cap, "sudoedit %s", spec.cmd);
		if (ret < 0 || ret >= (int) cap)
			return -1;
	} else if (ba_policy_append_text (out, cap, &pos, spec.cmd) < 0) {
		return -1;
	}
	if (spec.args_mode == BA_POLICY_COMMAND_NO_ARGS)
		return ba_policy_append_text (out, cap, &pos, " \"\"");
	if (spec.args_mode == BA_POLICY_COMMAND_EXACT_ARGS) {
		if (ba_policy_append_text (out, cap, &pos, " ") < 0)
			return -1;
		return ba_policy_append_text (out, cap, &pos, spec.args);
	}
	return 0;
}

static int
ba_policy_normalize_command_list (const char *list, char *out, size_t cap)
{
	char *copy, *save = NULL;
	size_t pos = 0;
	int n = 0, ret = 0;

	if (!list || !out || cap == 0)
		return -1;
	out[0] = '\0';
	copy = BA_POLICY_DUP (list);
	if (!copy)
		return -1;
	for (char *tok = BA_POLICY_SPLIT (copy, ",", &save); tok;
	     tok = BA_POLICY_SPLIT (NULL, ",", &save)) {
		char one[BA_POLICY_COMMAND_TEXT_BYTES];

		tok = ba_policy_trim (tok);
		if (!*tok)
			continue;
		ret = ba_policy_normalize_command_spec_text (tok, one, sizeof one);
		if (ret)
			break;
		if (n++ > 0 && ba_policy_append_text (out, cap, &pos, ",") < 0) {
			ret = -1;
			break;
		}
		if (ba_policy_append_text (out, cap, &pos, one) < 0) {
			ret = -1;
			break;
		}
	}
	BA_POLICY_FREE (copy);
	return ret ? ret : (n > 0 ? 0 : -1);
}

/* Join a comma-separated name list with no whitespace. sudoers treats
   whitespace around ',' as insignificant. */
static int
ba_policy_normalize_name_list (const char *list, char *out, size_t cap)
{
	char *copy, *save = NULL;
	size_t pos = 0;
	int n = 0;

	if (!list || !out || cap == 0)
		return -1;
	out[0] = '\0';
	copy = BA_POLICY_DUP (list);
	if (!copy)
		return -1;
	for (char *tok = BA_POLICY_SPLIT (copy, ",", &save); tok;
	     tok = BA_POLICY_SPLIT (NULL, ",", &save)) {
		tok = ba_policy_trim (tok);
		if (!*tok)
			continue;
		if (n++ > 0 && ba_policy_append_text (out, cap, &pos, ",") < 0) {
			BA_POLICY_FREE (copy);
			return -1;
		}
		if (ba_policy_append_text (out, cap, &pos, tok) < 0) {
			BA_POLICY_FREE (copy);
			return -1;
		}
	}
	BA_POLICY_FREE (copy);
	return n > 0 ? 0 : -1;
}

static int
ba_policy_value_ok (const char *s, int command)
{
	if (!s || !*s) return 0;
	if (command) {
		struct ba_policy_command_spec spec;
		return ba_policy_parse_command_spec (s, &spec) == 0;
	}
	if (ba_policy_has_glob_or_negation (s)) return 0;
	if (strcmp (s, "ALL") == 0) return 1;
	/* sudoers #uid user form. A leading '#' is otherwise a comment. */
	if (s[0] == '#' && ba_policy_uint_ok (s + 1))
		return 1;
	return ba_policy_name_ok (s, 1) || ba_policy_name_ok (s, 0);
}

static int
ba_policy_list_ok (char *list, int command)
{
	char *save = NULL;
	const char *p;
	int n = 0;
	/* strtok_r skips empty entries. Validate separators before tokenization so
	 * an incomplete alias, target or command list cannot become a shorter rule. */
	if (!list || !*list)
		return 0;
	p = list;
	for (;;) {
		int content = 0;
		while (*p && *p != ',') {
			if (!ba_policy_ascii_isspace ((unsigned char) *p)) content = 1;
			p++;
		}
		if (!content) return 0;
		if (!*p) break;
		p++;
	}
	for (char *tok = BA_POLICY_SPLIT (list, ",", &save); tok; tok = BA_POLICY_SPLIT (NULL, ",", &save)) {
		tok = ba_policy_trim (tok);
		if (!ba_policy_value_ok (tok, command))
			return 0;
		n++;
	}
	return n > 0;
}

static int
ba_policy_host_ok (const char *host)
{
	if (strcmp (host, "ALL") == 0) return 1;
	char local[128];
	if (BA_POLICY_HOSTNAME (local, sizeof local) < 0)
		local[0] = '\0';
	local[sizeof local - 1] = '\0';
	if (local[0] && strcmp (host, local) == 0) return 1;
	if (ba_policy_name_ok (host, 1)) return 1;
	return ba_policy_name_ok (host, 0) && host[0] != '%';
}

static int
ba_policy_parse_alias (struct ba_policy_parse_ctx *ctx,
                       const char *kind, char *line, unsigned int lineno)
{
	char *name = line + strlen (kind);
	name = ba_policy_trim (name);
	char *eq = strchr (name, '=');
	if (!eq) {
		BA_POLICY_ERROR ("policy-parse:%u: alias missing '='", lineno);
		return -1;
	}
	*eq++ = '\0';
	name = ba_policy_trim (name);
	char *values = ba_policy_trim (eq);
	char normalized_values[BA_POLICY_COMMAND_TEXT_BYTES];
	if (!ba_policy_name_ok (name, 1)) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid alias name", lineno);
		return -1;
	}
	char *copy = BA_POLICY_DUP (values);
	if (!copy) return -1;
	int command = strcmp (kind, "Cmnd_Alias") == 0;
	int ok = ba_policy_list_ok (copy, command);
	BA_POLICY_FREE (copy);
	if (!ok) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid alias list", lineno);
		return -1;
	}
	if (command) {
		if (ba_policy_normalize_command_list (values, normalized_values,
		                                      sizeof normalized_values) < 0) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid alias list", lineno);
			return -1;
		}
	} else if (ba_policy_normalize_name_list (values, normalized_values,
	                                          256) < 0) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid alias list", lineno);
		return -1;
	}
	values = normalized_values;
	return ba_policy_emit (ctx, "alias type=%s name=%s values=%s",
	                       kind, name, values);
}

enum ba_policy_default_bind_kind {
	BA_POLICY_DEFAULT_BIND_GLOBAL = 0,
	BA_POLICY_DEFAULT_BIND_USER,
	BA_POLICY_DEFAULT_BIND_HOST,
	BA_POLICY_DEFAULT_BIND_RUNAS,
	BA_POLICY_DEFAULT_BIND_CMND
};

static const char *
ba_policy_default_bind_name (enum ba_policy_default_bind_kind bind_kind)
{
	switch (bind_kind) {
	case BA_POLICY_DEFAULT_BIND_USER: return "user";
	case BA_POLICY_DEFAULT_BIND_HOST: return "host";
	case BA_POLICY_DEFAULT_BIND_RUNAS: return "runas";
	case BA_POLICY_DEFAULT_BIND_CMND: return "cmnd";
	default: return "global";
	}
}

static int
ba_policy_default_scope_ok (enum ba_policy_default_bind_kind bind_kind,
                            const char *scope)
{
	if (!scope || !*scope)
		return 0;
	switch (bind_kind) {
	case BA_POLICY_DEFAULT_BIND_USER:
	case BA_POLICY_DEFAULT_BIND_RUNAS:
		return ba_policy_value_ok (scope, 0);
	case BA_POLICY_DEFAULT_BIND_HOST:
		return ba_policy_host_ok (scope);
	case BA_POLICY_DEFAULT_BIND_CMND:
		return ba_policy_name_ok (scope, 1);
	default:
		return strcmp (scope, "global") == 0;
	}
}

static int
ba_policy_default_key_boolean (const char *key)
{
	return strcmp (key, "requiretty") == 0 || strcmp (key, "env_reset") == 0;
}

static int
ba_policy_emit_default (struct ba_policy_parse_ctx *ctx,
                        enum ba_policy_default_bind_kind bind_kind,
                        const char *scope, const char *key, const char *op,
                        const char *value)
{
	if (bind_kind != BA_POLICY_DEFAULT_BIND_GLOBAL) {
		const char *bind = ba_policy_default_bind_name (bind_kind);
		if (strcmp (op, "=") != 0)
			return ba_policy_emit (ctx,
			                       "defaults scope=%s key=%s op=%s value=%s bind=%s bind_scope=%s",
			                       scope, key, op, value, bind, scope);
		return ba_policy_emit (ctx,
		                       "defaults scope=%s key=%s value=%s bind=%s bind_scope=%s",
		                       scope, key, value, bind, scope);
	}
	if (strcmp (op, "=") != 0)
		return ba_policy_emit (ctx, "defaults scope=%s key=%s op=%s value=%s",
		                       scope, key, op, value);
	return ba_policy_emit (ctx, "defaults scope=%s key=%s value=%s",
	                       scope, key, value);
}

static int
ba_policy_parse_defaults (struct ba_policy_parse_ctx *ctx,
                          char *line, unsigned int lineno)
{
	char *p = line + 8;
	enum ba_policy_default_bind_kind bind_kind = BA_POLICY_DEFAULT_BIND_GLOBAL;
	char *scope = "global";
	if (*p == ':' || *p == '@' || *p == '>' || *p == '!') {
		char sigil = *p;

		*p++ = '\0';
		scope = p;
		while (*p && !ba_policy_ascii_isspace ((unsigned char) *p)) p++;
		if (*p) *p++ = '\0';
		if (sigil == ':')
			bind_kind = BA_POLICY_DEFAULT_BIND_USER;
		else if (sigil == '@')
			bind_kind = BA_POLICY_DEFAULT_BIND_HOST;
		else if (sigil == '>')
			bind_kind = BA_POLICY_DEFAULT_BIND_RUNAS;
		else
			bind_kind = BA_POLICY_DEFAULT_BIND_CMND;
		if (!ba_policy_default_scope_ok (bind_kind, scope)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults scope", lineno);
			return -1;
		}
	}
	p = ba_policy_trim (p);
	if (!*p) {
		BA_POLICY_ERROR ("policy-parse:%u: Defaults requires assignment", lineno);
		return -1;
	}
	int negated = 0;
	if (*p == '!') {
		negated = 1;
		p = ba_policy_trim (p + 1);
		if (!*p) {
			BA_POLICY_ERROR ("policy-parse:%u: Defaults requires assignment", lineno);
			return -1;
		}
	}
	char *eq = strchr (p, '=');
	const char *op = "=";
	char *key;
	char *value;
	char bool_buf[6];
	if (eq) {
		if (negated) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		*eq++ = '\0';
		key = ba_policy_trim (p);
		size_t keylen = strlen (key);
		while (keylen > 0 && ba_policy_ascii_isspace ((unsigned char) key[keylen - 1]))
			key[--keylen] = '\0';
		if (keylen > 0 && (key[keylen - 1] == '+' || key[keylen - 1] == '-')) {
			op = key[keylen - 1] == '+' ? "+=" : "-=";
			key[--keylen] = '\0';
			while (keylen > 0 && ba_policy_ascii_isspace ((unsigned char) key[keylen - 1]))
				key[--keylen] = '\0';
		}
		value = ba_policy_trim (eq);
	} else {
		key = ba_policy_trim (p);
		size_t keylen = strlen (key);
		while (keylen > 0 && ba_policy_ascii_isspace ((unsigned char) key[keylen - 1]))
			key[--keylen] = '\0';
		if (!ba_policy_default_key_boolean (key)) {
			BA_POLICY_ERROR ("policy-parse:%u: Defaults requires key=value", lineno);
			return -1;
		}
		snprintf (bool_buf, sizeof bool_buf, "%s", negated ? "false" : "true");
		value = bool_buf;
	}
	if (!ba_policy_ident_ok (key) || !*value) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
		return -1;
	}
	if (strcmp (key, "timestamp_timeout") == 0) {
		if (strcmp (op, "=") != 0 || ba_policy_has_glob_or_negation (value) ||
		    !ba_policy_uint_ok (value)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (strcmp (key, "passwd_timeout") == 0) {
		if (strcmp (op, "=") != 0 || ba_policy_has_glob_or_negation (value) ||
		    !ba_policy_uint_ok (value)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (strcmp (key, "env_keep") == 0) {
		if (negated || !eq) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		if (!ba_policy_env_list_ok (value)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (ba_policy_default_key_boolean (key)) {
		const char *normalized = NULL;
		if (strcmp (op, "=") != 0 || !ba_policy_bool_value (value, &normalized)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		value = (char *) normalized;
	} else if (strcmp (key, "secure_path") == 0) {
		if (strcmp (op, "=") != 0 || !eq || !ba_policy_secure_path_ok (value)) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else {
		BA_POLICY_ERROR ("policy-parse:%u: unsupported Defaults key", lineno);
		return -1;
	}
	return ba_policy_emit_default (ctx, bind_kind, scope, key, op, value);
}

static int
ba_policy_parse_rule (struct ba_policy_parse_ctx *ctx,
                      char *line, unsigned int lineno)
{
	char *eq = strchr (line, '=');
	if (!eq) {
		BA_POLICY_ERROR ("policy-parse:%u: rule missing '='", lineno);
		return -1;
	}
	*eq++ = '\0';
	char *left = ba_policy_trim (line);
	char *right = ba_policy_trim (eq);
	char *save = NULL;
	char *user = BA_POLICY_SPLIT (left, " \t", &save);
	char *host = BA_POLICY_SPLIT (NULL, " \t", &save);
	if (!user || !host || BA_POLICY_SPLIT (NULL, " \t", &save)) {
		BA_POLICY_ERROR ("policy-parse:%u: rule left side must be 'user host'", lineno);
		return -1;
	}
	if (!ba_policy_value_ok (user, 0) || !ba_policy_host_ok (host)) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid user or host", lineno);
		return -1;
	}
	if (*right != '(') {
		BA_POLICY_ERROR ("policy-parse:%u: rule requires '(runas)'", lineno);
		return -1;
	}
	char *closep = strchr (right, ')');
	if (!closep) {
		BA_POLICY_ERROR ("policy-parse:%u: unterminated runas list", lineno);
		return -1;
	}
	*closep++ = '\0';
	char *runas = ba_policy_trim (right + 1);
	/* Split the (users:groups) runas spec; a bare (users) has no group half.
	 * Mirrors the kernel parser so offline validation and the normalized
	 * digest agree (the canonical (ALL:ALL) must parse). */
	char *runas_group = strchr (runas, ':');
	if (runas_group) {
		*runas_group++ = '\0';
		runas = ba_policy_trim (runas);
		runas_group = ba_policy_trim (runas_group);
	}
	char *runas_copy = BA_POLICY_DUP (runas);
	if (!runas_copy) return -1;
	int runas_ok = ba_policy_list_ok (runas_copy, 0);
	BA_POLICY_FREE (runas_copy);
	if (!runas_ok) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid runas list", lineno);
		return -1;
	}
	if (runas_group) {
		char *group_copy = BA_POLICY_DUP (runas_group);
		if (!group_copy) return -1;
		int group_ok = ba_policy_list_ok (group_copy, 0);
		BA_POLICY_FREE (group_copy);
		if (!group_ok) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid runas group list", lineno);
			return -1;
		}
	}
	char runas_norm[256], group_norm[256];
	if (ba_policy_normalize_name_list (runas, runas_norm, sizeof runas_norm) < 0) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid runas list", lineno);
		return -1;
	}
	runas = runas_norm;
	if (runas_group) {
		if (ba_policy_normalize_name_list (runas_group, group_norm,
		                                   sizeof group_norm) < 0) {
			BA_POLICY_ERROR ("policy-parse:%u: invalid runas group list", lineno);
			return -1;
		}
		runas_group = group_norm;
	}
	char *cmds = ba_policy_trim (closep);
	char normalized_cmds[BA_POLICY_COMMAND_TEXT_BYTES];
	int nopasswd = 0, setenv = 0;
	for (;;) {
		if (strncmp (cmds, "NOPASSWD:", 9) == 0) { nopasswd = 1; cmds = ba_policy_trim (cmds + 9); continue; }
		if (strncmp (cmds, "SETENV:", 7) == 0) { setenv = 1; cmds = ba_policy_trim (cmds + 7); continue; }
		break;
	}
	char *cmd_copy = BA_POLICY_DUP (cmds);
	if (!cmd_copy) return -1;
	int cmd_ok = ba_policy_list_ok (cmd_copy, 1);
	BA_POLICY_FREE (cmd_copy);
	if (!cmd_ok) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid command list", lineno);
		return -1;
	}
	if (ba_policy_normalize_command_list (cmds, normalized_cmds,
	                                      sizeof normalized_cmds) < 0) {
		BA_POLICY_ERROR ("policy-parse:%u: invalid command list", lineno);
		return -1;
	}
	/* Emit the group half only when present, matching the kernel parser so a
	 * bare (users) rule keeps its prior normalized digest. */
	if (runas_group)
		return ba_policy_emit (ctx,
		                       "rule user=%s host=%s runas=%s runas_group=%s nopasswd=%d setenv=%d commands=%s",
		                       user, host, runas, runas_group, nopasswd, setenv,
		                       normalized_cmds);
	return ba_policy_emit (ctx,
	                       "rule user=%s host=%s runas=%s nopasswd=%d setenv=%d commands=%s",
	                       user, host, runas, nopasswd, setenv, normalized_cmds);
}

static int
ba_policy_include_directive (const char *line)
{
	static const char *const words[] = {
		"@includedir", "@include", "#includedir", "#include", NULL
	};

	for (int i = 0; words[i]; i++) {
		size_t n = strlen (words[i]);
		if (strncmp (line, words[i], n) == 0 &&
		    (line[n] == '\0' || ba_policy_ascii_isspace ((unsigned char) line[n])))
			return 1;
	}
	return 0;
}

static int
ba_policy_parse_line (struct ba_policy_parse_ctx *ctx,
                      char *line, unsigned int lineno)
{
	char *hash;

	/* sudoers: '#' starts a comment, except '#include'/'#includedir'
	   (unsupported directives) and a '#uid' user id. '@include' and
	   '@includedir' are the same directives. A command path that merely
	   contains the letters "include" is not one. */
	line = ba_policy_trim (line);
	if (!*line)
		return 0;
	if (ba_policy_include_directive (line)) {
		BA_POLICY_ERROR ("policy-parse:%u: includes are not supported", lineno);
		return -1;
	}
	if (line[0] == '#' && !ba_policy_ascii_isdigit ((unsigned char) line[1])) {
		line[0] = '\0';
		return 0;
	}
	hash = strchr (line[0] == '#' ? line + 1 : line, '#');
	if (hash)
		*hash = '\0';
	line = ba_policy_trim (line);
	if (!*line)
		return 0;
	if (strncmp (line, "User_Alias", 10) == 0 && ba_policy_ascii_isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "User_Alias", line, lineno);
	if (strncmp (line, "Runas_Alias", 11) == 0 && ba_policy_ascii_isspace ((unsigned char) line[11]))
		return ba_policy_parse_alias (ctx, "Runas_Alias", line, lineno);
	if (strncmp (line, "Cmnd_Alias", 10) == 0 && ba_policy_ascii_isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "Cmnd_Alias", line, lineno);
	if (strncmp (line, "Host_Alias", 10) == 0 && ba_policy_ascii_isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "Host_Alias", line, lineno);
	if (strncmp (line, "Defaults", 8) == 0 &&
	    (line[8] == ':' || line[8] == '@' || line[8] == '>' ||
	     line[8] == '!' || ba_policy_ascii_isspace ((unsigned char) line[8])))
		return ba_policy_parse_defaults (ctx, line, lineno);
	return ba_policy_parse_rule (ctx, line, lineno);
}

#endif
