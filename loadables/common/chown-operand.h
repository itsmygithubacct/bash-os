/* SPDX-License-Identifier: MIT */
/* One file operand of chown or chgrp, reported the way GNU coreutils does:
   the operand is examined first, a followed link must resolve, and a
   refused change names what was being changed. */
#ifndef BASHOS_CHOWN_OPERAND_H
#define BASHOS_CHOWN_OPERAND_H

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gnu-quote.h"

static inline int
bos_chown_operand (const char *file, uid_t uid, gid_t gid, int follow)
{
    struct stat st;
    const char *action;

    if (lstat (file, &st) < 0)
        action = "cannot access";
    else if (follow && S_ISLNK (st.st_mode) && stat (file, &st) < 0)
        action = "cannot dereference";
    else if ((follow ? chown (file, uid, gid) : lchown (file, uid, gid)) == 0)
        return 0;
    else
        action = uid != (uid_t) -1 ? "changing ownership of" : "changing group of";

    int error = errno;
    char *quoted = bos_quoteaf (file);
    builtin_error ("%s %s: %s", action, quoted ? quoted : file, strerror (error));
    free (quoted);
    return -1;
}

#endif
