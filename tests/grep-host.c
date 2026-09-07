/* tests/grep-host.c — the grep loadable as a standalone program, for running
 * the parity cases under AddressSanitizer and UBSan: loadables/grep.c is
 * linked against the built tree's headers with the one bash runtime symbol
 * it calls stubbed, and main() hands argv to grep_builtin as a WORD_LIST.
 * tests/grep-parity.sh runs its whole case list through this binary when
 * GREP_IMPL names it (tests/run.sh does), so every path the cases exercise
 * is checked for memory errors and leaks as well as for output.
 *
 *   cc -O1 -g -fsanitize=address,undefined -DHAVE_CONFIG_H -Ibuild/bash-5.3 \
 *      -Ibuild/bash-5.3/include -Ibuild/bash-5.3/builtins \
 *      -Ibuild/bash-5.3/examples/loadables loadables/grep.c tests/grep-host.c -o grep
 *
 * SPDX-License-Identifier: MIT
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <locale.h>
#include "loadables.h"

/* ---- the bash runtime, stubbed ---------------------------------------------- */
void builtin_error (const char *fmt, ...)
{ va_list a; va_start (a, fmt); fputs ("grep: ", stderr); vfprintf (stderr, fmt, a); fputc ('\n', stderr); va_end (a); }
void builtin_usage (void) { fputs ("grep: usage: grep [OPTION]... PATTERNS [FILE]...\n", stderr); }
extern int grep_builtin (WORD_LIST *);

int
main (int argc, char **argv)
{
  WORD_LIST *head = 0, **tail = &head, *l;
  setlocale (LC_ALL, "");            /* as the shell does at start-up */
  for (int i = 1; i < argc; i++)
    {
      WORD_LIST *x = calloc (1, sizeof *x);
      x->word = calloc (1, sizeof *x->word);
      x->word->word = argv[i];
      *tail = x; tail = &x->next;
    }
  int rc = grep_builtin (head);
  fflush (stdout);
  while ((l = head)) { head = l->next; free (l->word); free (l); }
  /* the shell maps EX_USAGE to exit status 2, as grep uses it */
  return rc == EX_USAGE ? 2 : rc;
}
