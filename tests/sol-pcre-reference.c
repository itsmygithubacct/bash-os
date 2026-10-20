/* SPDX-License-Identifier: MIT */
/* Independent PCRE2 reference for the exact catalog line-selection operation.
   Build explicitly through the campaign build gate; never builds at runtime. */
#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
  if (argc != 3) return 2;
  int err; PCRE2_SIZE off;
  pcre2_code *code = pcre2_compile((PCRE2_SPTR)argv[1], PCRE2_ZERO_TERMINATED,
                                 PCRE2_UTF | PCRE2_UCP, &err, &off, NULL);
  if (!code) return 2;
  pcre2_match_data *md = pcre2_match_data_create_from_pattern(code, NULL);
  pcre2_match_context *ctx = pcre2_match_context_create(NULL);
  if (!md || !ctx) return 2;
  pcre2_set_match_limit(ctx, 1000000);
  pcre2_set_depth_limit(ctx, 10000);
  pcre2_set_heap_limit(ctx, 16384);
  FILE *f = fopen(argv[2], "rb");
  if (!f) return 2;
  char *line = NULL; size_t cap = 0; ssize_t n; int hit = 0, status = 0;
  while ((n = getline(&line, &cap, f)) >= 0) {
    size_t len = n - (n > 0 && line[n-1] == '\n');
    int rc = pcre2_match(code, (PCRE2_SPTR)line, len, 0, 0, md, ctx);
    if (rc >= 0) {
      fwrite(line, 1, n, stdout);
      if (!n || line[n-1] != '\n') putchar('\n');
      hit = 1;
    } else if (rc != PCRE2_ERROR_NOMATCH) status = 2;
  }
  if (ferror(f) || fflush(stdout) || ferror(stdout)) status = 2;
  fclose(f); free(line); pcre2_match_data_free(md);
  pcre2_match_context_free(ctx); pcre2_code_free(code);
  return status ? status : !hit;
}
