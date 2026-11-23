/* SPDX-License-Identifier: MIT */
/* chgrp: change the group of files. A bash-os loadable written from the
   coreutils manual, POSIX chgrp and the observed behaviour of GNU
   coreutils 9.7; the work is shared with chown in chown-operand.h. */
#include <config.h>
#include "loadables.h"
#include "chown-operand.h"

int
chgrp_builtin (WORD_LIST *list)
{
  return bos_chown_main (list, 1);
}

char *chgrp_doc[] = {
  "Change file group.",
  "",
  "chgrp [OPTION]... GROUP FILE...   GROUP is a name or numeric id.",
  "chgrp [OPTION]... --reference=RFILE FILE...",
  "",
  "Change the group of each FILE to GROUP.",
  "With --reference, change the group of each FILE to that of RFILE.",
  "A leading '+' makes GROUP a numeric ID.",
  "",
  "  -c, --changes          like verbose but report only when a change is made",
  "  -f, --silent, --quiet  suppress most error messages",
  "  -v, --verbose          output a diagnostic for every file processed",
  "      --dereference      affect the referent of each symbolic link (this is",
  "                         the default), rather than the symbolic link itself",
  "  -h, --no-dereference   affect symbolic links instead of any referenced file",
  "      --from=CURRENT_OWNER:CURRENT_GROUP",
  "                         change the group of each file only if its current",
  "                         owner and/or group match those specified here",
  "      --no-preserve-root  do not treat '/' specially (the default)",
  "      --preserve-root    fail to operate recursively on '/'",
  "      --reference=RFILE  use RFILE's group rather than specifying a value.",
  "                         RFILE is always dereferenced if a symbolic link.",
  "  -R, --recursive        operate on files and directories recursively",
  "",
  "With -R: -H traverses a command-line symbolic link to a directory, -L",
  "traverses every symbolic link to a directory, -P (the default) none.",
  (char *) NULL
};

struct builtin chgrp_struct = {
  "chgrp", chgrp_builtin, BUILTIN_ENABLED, chgrp_doc,
  "chgrp GROUP FILE...", 0
};
