/* SPDX-License-Identifier: MIT */
/* The program name a coreutils-style builtin prints in its "Try 'NAME
   --help' for more information." line. GNU prints the name it was invoked
   by; under the bashy-box /bin shim that is the DISPLAY part of the
   unexported shell variable BASHOS_SHIM_COMMAND=BUILTIN=DISPLAY set for
   the running builtin. Otherwise FALLBACK, the command's usual name. */
#ifndef BASHOS_SHIM_PROG_NAME_H
#define BASHOS_SHIM_PROG_NAME_H

#include <stdio.h>
#include <string.h>

extern char *this_command_name;

static inline const char *
bos_shim_prog_name (const char *fallback)
{
    SHELL_VAR *v = find_variable ("BASHOS_SHIM_COMMAND");
    const char *val, *self = this_command_name;
    size_t n;

    if (v == 0 || exported_p (v) || array_p (v) || assoc_p (v) || self == 0)
        return fallback;
    val = value_cell (v);
    n = strlen (self);
    if (val && strncmp (val, self, n) == 0 && val[n] == '=' && val[n + 1])
        return val + n + 1;
    return fallback;
}

/* coreutils' usage (EXIT_FAILURE) line. */
static inline void
bos_shim_try_help (const char *fallback)
{
    fflush (stdout);
    fprintf (stderr, "Try '%s --help' for more information.\n", bos_shim_prog_name (fallback));
}

/* glibc getopt's diagnostic for an unknown option in WORD, then the Try
   line: "unrecognized option '--name'" for a long option (WORD starts with
   "--"), else "invalid option -- 'C'" for the offending character C of a
   short-option cluster. The caller returns its command's usage status
   (1 for most coreutils, 2 for sort, cmp, diff, grep, ...). */
static inline void
bos_shim_bad_option (const char *word, int c, const char *fallback)
{
    fflush (stdout);
    if (word[0] == '-' && word[1] == '-')
        builtin_error ("unrecognized option '%s'", word);
    else
        builtin_error ("invalid option -- '%c'", c);
    bos_shim_try_help (fallback);
}

/* glibc getopt's diagnostic for an option missing its argument: "option
   '--name' requires an argument" for a long option WORD (any "=VALUE"
   part is not shown), else "option requires an argument -- 'C'"; then the
   Try line. */
static inline void
bos_shim_missing_arg (const char *word, int c, const char *fallback)
{
    fflush (stdout);
    if (word[0] == '-' && word[1] == '-')
        builtin_error ("option '%.*s' requires an argument", (int) strcspn (word, "="), word);
    else
        builtin_error ("option requires an argument -- '%c'", c);
    bos_shim_try_help (fallback);
}

/* A procps tool's usage error (free, vmstat, pgrep, sysctl, ...): the
   getopt diagnostic for WORD as above (none when WORD is NULL), then a
   blank line, "Usage:", " NAME ARGS" and the manual pointer, all on
   stderr; SECTION is the manual section. The caller returns the tool's
   usage status. */
static inline void
bos_shim_procps_usage (const char *word, int c, const char *args,
                       const char *section, const char *fallback)
{
    const char *name = bos_shim_prog_name (fallback);

    fflush (stdout);
    if (word && word[0] == '-' && word[1] == '-')
        builtin_error ("unrecognized option '%s'", word);
    else if (word)
        builtin_error ("invalid option -- '%c'", c);
    fprintf (stderr, "\nUsage:\n %s %s\n\nFor more details see %s(%s).\n",
             name, args, name, section);
}

#endif
