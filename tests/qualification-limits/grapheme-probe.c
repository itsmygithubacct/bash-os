/* SPDX-License-Identifier: MIT */
/* Length-aware library probe. This is not the Bash TEXT interface. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "grapheme.h"

static int nibble(unsigned char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

int main(void)
{
  char line[16384];
  unsigned char text[8192];
  size_t offsets[8193];
  if (!getenv("BASHOS_QUALIFICATION_GUEST") ||
      strcmp(getenv("BASHOS_QUALIFICATION_GUEST"), "1")) return 125;
  while (fgets(line, sizeof line, stdin)) {
    size_t len = strlen(line), n, count = 0, pos = 0;
    if (!len || line[len - 1] != '\n') return 125;
    line[--len] = 0;
    if (len % 2) return 125;
    n = len / 2;
    for (size_t i = 0; i < n; ++i) {
      int a = nibble(line[2*i]), b = nibble(line[2*i+1]);
      if (a < 0 || b < 0) return 125;
      text[i] = (unsigned char)(a * 16 + b);
    }
#ifdef QUALIFY_TRUNCATE_NUL
    /* Deliberately broken input adapter: the independent corpus must catch it. */
    for (size_t i = 0; i < n; ++i) if (text[i] == 0) { n = i; break; }
#endif
    offsets[0] = 0;
    while (pos < n) {
      size_t step = grapheme_next_character_break_utf8((char *)text + pos, n - pos);
      if (!step || step > n - pos) return 125;
      pos += step;
      offsets[++count] = pos;
    }
    printf("%zu\t", count);
    for (size_t i = 0; i <= count; ++i)
      printf("%s%zu", i ? "," : "", offsets[i]);
    putchar('\t');
    for (size_t i = 0; i < count; ++i) {
      if (i) putchar(',');
      for (size_t j = offsets[i]; j < offsets[i+1]; ++j) printf("%02x", text[j]);
    }
    putchar('\n');
  }
  return ferror(stdin) || ferror(stdout) ? 125 : 0;
}
