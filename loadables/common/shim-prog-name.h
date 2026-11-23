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

#endif
