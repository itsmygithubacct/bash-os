/* Count wrapper overhead on the genuine command paths; no timing claims.
 * Build as a replacement loadable against staged Bash/helper headers. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>
#include "loadables.h"
static size_t allocations, resizes, allocated_bytes, format_calls, hex_chars, reads;
static void *count_malloc(size_t n) { allocations++; allocated_bytes += n; return malloc(n); }
static void *count_realloc(void *p, size_t n) { resizes++; allocated_bytes += n; return realloc(p,n); }
static int count_snprintf(char *s, size_t n, const char *format, ...) {
  format_calls++;
  va_list ap; va_start(ap,format); int rc=vsnprintf(s,n,format,ap); va_end(ap); return rc;
}
static int count_putchar(int c) { hex_chars++; return putchar(c); }
static ssize_t count_read(int fd, void *p, size_t n) { reads++; return read(fd,p,n); }
__attribute__((destructor)) static void report_counts(void) {
  fprintf(stderr,"crypto-wrapper-counts allocations=%zu resizes=%zu allocated_bytes=%zu format_calls=%zu putchars=%zu reads=%zu\n",
          allocations,resizes,allocated_bytes,format_calls,hex_chars,reads);
}
#define malloc count_malloc
#define realloc count_realloc
#define snprintf count_snprintf
#undef putchar
#define putchar count_putchar
#define read count_read
#include "../loadables/crypto.c"
