/* SPDX-License-Identifier: MIT */
/* chgrp.c — change file group via chown(2)/lchown(2). bash-os loadable (MIT).
 * Replaces busybox chgrp (plan D22).  chgrp [-fhR] [-H|-L|-P] GROUP FILE... */
#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include "loadables.h"
#include "bashgetopt.h"
#include "chown-operand.h"

int
chgrp_builtin (WORD_LIST *list)
{
  int opt, deref = 1, recurse = 0, traverse = BOS_TRAVERSE_P, rc = EXECUTION_SUCCESS;
  gid_t gid; char *end; struct group *gr;
  WORD_LIST *l;

  bos_chown_quiet = 0;
  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "hRHLPf")) != -1)
    {
      if (opt == 'h') deref = 0;
      else if (opt == 'R') recurse = 1;
      else if (opt == 'H') traverse = BOS_TRAVERSE_H;
      else if (opt == 'L') traverse = BOS_TRAVERSE_L;
      else if (opt == 'P') traverse = BOS_TRAVERSE_P;
      else if (opt == 'f') bos_chown_quiet = 1;
      else { builtin_usage (); return (EXECUTION_FAILURE); }
    }
  list = loptend;
  if (list == 0 || list->next == 0)
    { builtin_usage (); return (EXECUTION_FAILURE); }

  gr = getgrnam (list->word->word);
  if (gr)
    gid = gr->gr_gid;
  else
    {
      long v = strtol (list->word->word, &end, 10);
      if (*end)
	{
	  char *quoted = bos_quote (list->word->word);

	  builtin_error ("invalid group: %s", quoted ? quoted : list->word->word);
	  free (quoted);
	  return (EXECUTION_FAILURE);
	}
      gid = (gid_t) v;
    }

  for (l = list->next; l; l = l->next)
    if ((recurse ? bos_chown_tree (l->word->word, (uid_t) -1, gid, deref, traverse, 1, NULL)
                 : bos_chown_operand (l->word->word, (uid_t) -1, gid, deref)) < 0)
      rc = EXECUTION_FAILURE;
  return (rc);
}

char *chgrp_doc[] = {
  "Change file group.",
  "",
  "chgrp [-fhR] [-H|-L|-P] GROUP FILE...   GROUP is a name or numeric id.",
  (char *) NULL
};

struct builtin chgrp_struct = {
  "chgrp", chgrp_builtin, BUILTIN_ENABLED, chgrp_doc, "chgrp [-fhR] [-H|-L|-P] GROUP FILE...", 0
};
