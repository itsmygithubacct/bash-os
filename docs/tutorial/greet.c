/* SPDX-License-Identifier: MIT */
/* greet.c — the tutorial loadable. See docs/anatomy-of-a-loadable.md.
 *
 *   greet [-n TIMES] [-u] [NAME]     print a greeting TIMES times
 *
 * Everything a bash builtin needs is here: the entry point that receives the
 * argument list, option parsing with bash's own getopt, the help text, the
 * table entry that names it, and the exit status. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "loadables.h"          /* bash's builtin API: WORD_LIST, builtin_error, internal_getopt … */

int
greet_builtin (WORD_LIST *list)
{
  int opt, times = 1, upper = 0;
  const char *name;

  /* 1. Options. internal_getopt walks LIST like getopt(3); list_optarg is the
        option's argument; loptend is the list after the options. */
  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "n:u")) != -1)
    switch (opt)
      {
      case 'n': times = atoi (list_optarg); break;
      case 'u': upper = 1; break;
      CASE_HELPOPT;                     /* --help prints the long doc below */
      default: builtin_usage (); return EX_USAGE;
      }
  list = loptend;

  /* 2. Operands. What is left of LIST is the positional arguments. */
  name = list ? list->word->word : "world";
  if (times < 1)
    { builtin_error ("-n: %d: must be at least 1", times); return EXECUTION_FAILURE; }

  /* 3. Work. A builtin writes to the shell's stdout — flush before returning,
        so output stays ordered with the script's own echo. */
  while (times-- > 0)
    {
      const char *p;
      fputs ("hello, ", stdout);
      for (p = name; *p; p++) putchar (upper ? toupper ((unsigned char) *p) : *p);
      putchar ('\n');
    }
  fflush (stdout);

  /* 4. Exit status, which becomes $?. sh_chkwrite turns a failed write on
        stdout into EXECUTION_FAILURE. */
  return sh_chkwrite (EXECUTION_SUCCESS);
}

/* The long documentation, shown by `help greet`. One line per array entry. */
char *greet_doc[] = {
  "Print a greeting.",
  "",
  "Prints \"hello, NAME\" (NAME defaults to world).",
  "  -n TIMES   repeat TIMES times",
  "  -u         upper-case the name",
  "",
  "Exit status: 0, or 1 if TIMES is not a positive number.",
  (char *)NULL
};

/* The table entry: the command name, the entry point, flags, the docs, and
   the one-line usage `help` prints. build.sh splices exactly this row into
   bash's own builtin table; `enable -f` reads it from the shared object. */
struct builtin greet_struct = {
  "greet", greet_builtin, BUILTIN_ENABLED, greet_doc, "greet [-n TIMES] [-u] [NAME]", 0
};
