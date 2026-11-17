/* SPDX-License-Identifier: MIT */
/* bashos-policy-check FILE
 *
 * Parses a sudoers-subset policy with the same parser source the PRIVCMD v2
 * module compiles in, so a policy can be checked before it is pinned in a
 * trust bundle. Exit 0: the module would accept the text. Exit 1: it would
 * refuse to load, with the first rejected line on stdout. Exit 2: usage or
 * read error. It evaluates no request and grants nothing. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void ignore_diagnostic(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void ignore_diagnostic(const char *format, ...) { (void)format; }
static int host_name(char *out, size_t size)
{
	if (!size || gethostname(out, size)) return -1;
	out[size - 1] = 0;
	return 0;
}
#define BA_POLICY_DUP(s) strdup(s)
#define BA_POLICY_FREE(p) free(p)
#define BA_POLICY_SPLIT(s, d, save) strtok_r(s, d, save)
#define BA_POLICY_HOSTNAME(p, n) host_name(p, n)
#define BA_POLICY_ERROR(...) ignore_diagnostic(__VA_ARGS__)
#define BA_MODEL_ALLOC(n) calloc(1, n)
#include "../../../loadables/common/auth-policy-model.h"

static int count_record(void *cookie, const char *record, size_t length)
{
	(void)record; (void)length;
	++*(unsigned int *)cookie;
	return 0;
}

int main(int argc, char **argv)
{
	static char bytes[BA_POLICY_MAX_INPUT + 1];
	struct ba_policy_document *document;
	unsigned int records = 0;
	size_t length;
	FILE *input;
	int rc;
	(void)ba_policy_document_evaluate; /* the shared header also defines the evaluator */
	if (argc != 2) {
		fprintf(stderr, "usage: bashos-policy-check FILE\n");
		return 2;
	}
	input = fopen(argv[1], "rb");
	if (!input) { perror(argv[1]); return 2; }
	length = fread(bytes, 1, sizeof(bytes), input);
	if (ferror(input) || fclose(input)) { fprintf(stderr, "%s: read error\n", argv[1]); return 2; }
	if (!length || length > BA_POLICY_MAX_INPUT) {
		printf("rejected: policy must hold 1 to %u bytes\n", BA_POLICY_MAX_INPUT);
		return 1;
	}
	document = calloc(1, sizeof(*document));
	if (!document) return 2;
	rc = ba_policy_document_parse(document, bytes, length, count_record, &records);
	if (rc) printf("rejected: line %u\n", document->error_line);
	else printf("accepted: %u normalized records\n", records);
	ba_policy_document_clear(document);
	free(document);
	return rc ? 1 : 0;
}
