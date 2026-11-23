/* SPDX-License-Identifier: MIT */
/* chown: change the owner and group of files. A bash-os loadable written
   from the coreutils manual, POSIX chown and the observed behaviour of GNU
   coreutils 9.7; the work is shared with chgrp in chown-operand.h. */
#include <config.h>
#include "loadables.h"
#include "chown-operand.h"

int
chown_builtin (WORD_LIST *list)
{
  return bos_chown_main (list, 0);
}

char *chown_doc[] = {
  "Change file owner and group.",
  "",
  "chown [OPTION]... [OWNER][:[GROUP]] FILE...",
  "chown [OPTION]... --reference=RFILE FILE...",
  "",
  "Change the owner and/or group of each FILE to OWNER and/or GROUP.",
  "With --reference, change the owner and group of each FILE to those of RFILE.",
  "",
  "  -c, --changes          like verbose but report only when a change is made",
  "  -f, --silent, --quiet  suppress most error messages",
  "  -v, --verbose          output a diagnostic for every file processed",
  "      --dereference      affect the referent of each symbolic link (this is",
  "                         the default), rather than the symbolic link itself",
  "  -h, --no-dereference   affect symbolic links instead of any referenced file",
  "      --from=CURRENT_OWNER:CURRENT_GROUP",
  "                         change the ownership of each file only if",
  "                         its current owner and/or group match those specified",
  "                         here. Either may be omitted, in which case a match",
  "                         is not required for the omitted attribute",
  "      --no-preserve-root  do not treat '/' specially (the default)",
  "      --preserve-root    fail to operate recursively on '/'",
  "      --reference=RFILE  use RFILE's ownership rather than specifying values.",
  "                         RFILE is always dereferenced if a symbolic link.",
  "  -R, --recursive        operate on files and directories recursively",
  "",
  "With -R: -H traverses a command-line symbolic link to a directory, -L",
  "traverses every symbolic link to a directory, -P (the default) none.",
  "",
  "Owner is unchanged if missing.  Group is unchanged if missing, but changed",
  "to login group if implied by a ':' following a symbolic OWNER.",
  "OWNER and GROUP may be numeric as well as symbolic; a leading '+' forces",
  "a numeric ID.",
  (char *) NULL
};

struct builtin chown_struct = {
  "chown", chown_builtin, BUILTIN_ENABLED, chown_doc,
  "chown OWNER[:GROUP] FILE...", 0
};
