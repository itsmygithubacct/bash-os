/* SPDX-License-Identifier: MIT */
/* Optional in-process access to escdelay, including dynamically loaded builds.
   The builtin lookup avoids linking separately loaded modules to each other. */
#ifndef BASHOS_ESCDELAY_RESOLVE_H
#define BASHOS_ESCDELAY_RESOLVE_H

static int
bashos_escdelay_resolve (const char *screen, int kgetch)
{
  const char *ed = getenv ("BASHESCDELAY");
  /* Preserve kgetch's legacy environment override when the global variable
     is absent or empty. A malformed nonempty global value suppresses it. */
  if (kgetch && (!ed || !*ed))
    {
      const char *legacy = getenv ("BASHKGETCH_ESCDELAY");
      if (legacy && *legacy)
        {
          char *end;
          long v = strtol (legacy, &end, 10);
          if (end != legacy && *end == '\0' && v >= 0 && v <= 5000)
            return (int) v;
        }
    }
  sh_builtin_func_t *resolver = find_shell_builtin ("escdelay");
  if (resolver)
    {
      WORD_DESC command = { .word = "\001bashos-escdelay-resolve-v1", .flags = 0 };
      WORD_DESC name = { .word = (char *) screen, .flags = 0 };
      WORD_LIST arg = { .next = NULL, .word = &name };
      WORD_LIST request = { .next = screen ? &arg : NULL, .word = &command };
      int result = (*resolver) (&request);
      if (result >= 0x10000 && result <= 0x10000 + 5000)
        return result - 0x10000;
    }
  /* Decoders remain usable when escdelay is not loaded. */
  if (ed && *ed)
    {
      char *end;
      long v = strtol (ed, &end, 10);
      if (end != ed && *end == '\0' && v >= 0 && v <= 5000)
        return (int) v;
    }
  return 50;
}
#endif
