/* SPDX-License-Identifier: MIT */
/* Count production PCRE2 calls without sampling or changing their results. */
#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <dlfcn.h>
#include <stdio.h>
static unsigned long compiles, data_allocs, matches, substitutes;
pcre2_code *pcre2_compile_8(PCRE2_SPTR p, PCRE2_SIZE n, uint32_t o, int *e,
                          PCRE2_SIZE *off, pcre2_compile_context *c) {
  static pcre2_code *(*fn)(PCRE2_SPTR,PCRE2_SIZE,uint32_t,int*,PCRE2_SIZE*,pcre2_compile_context*);
  if (!fn) fn = dlsym(RTLD_NEXT, "pcre2_compile_8");
  compiles++; return fn(p,n,o,e,off,c);
}
pcre2_match_data *pcre2_match_data_create_from_pattern_8(const pcre2_code *c, pcre2_general_context *g) {
  static pcre2_match_data *(*fn)(const pcre2_code*,pcre2_general_context*);
  if (!fn) fn = dlsym(RTLD_NEXT, "pcre2_match_data_create_from_pattern_8");
  data_allocs++; return fn(c,g);
}
int pcre2_match_8(const pcre2_code *c, PCRE2_SPTR s, PCRE2_SIZE n, PCRE2_SIZE off,
                  uint32_t o, pcre2_match_data *d, pcre2_match_context *ctx) {
  static int (*fn)(const pcre2_code*,PCRE2_SPTR,PCRE2_SIZE,PCRE2_SIZE,uint32_t,pcre2_match_data*,pcre2_match_context*);
  if (!fn) fn = dlsym(RTLD_NEXT, "pcre2_match_8");
  matches++; return fn(c,s,n,off,o,d,ctx);
}
int pcre2_substitute_8(const pcre2_code *c, PCRE2_SPTR s, PCRE2_SIZE n, PCRE2_SIZE off,
                       uint32_t o, pcre2_match_data *d, pcre2_match_context *ctx,
                       PCRE2_SPTR r, PCRE2_SIZE rn, PCRE2_UCHAR *out, PCRE2_SIZE *on) {
  static int (*fn)(const pcre2_code*,PCRE2_SPTR,PCRE2_SIZE,PCRE2_SIZE,uint32_t,pcre2_match_data*,pcre2_match_context*,PCRE2_SPTR,PCRE2_SIZE,PCRE2_UCHAR*,PCRE2_SIZE*);
  if (!fn) fn = dlsym(RTLD_NEXT, "pcre2_substitute_8");
  substitutes++; return fn(c,s,n,off,o,d,ctx,r,rn,out,on);
}
__attribute__((destructor)) static void report(void) {
  fprintf(stderr,"PCRE_PROFILE compile=%lu match_data=%lu match=%lu substitute=%lu\n",
          compiles,data_allocs,matches,substitutes);
}
