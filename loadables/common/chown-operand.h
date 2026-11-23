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
#include <dirent.h>
#include <stdio.h>

#include "gnu-quote.h"

/* -f: suppress most error messages (exit status is unaffected). */
static int bos_chown_quiet;

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
    if (bos_chown_quiet)
        return -1;
    char *quoted = bos_quoteaf (file);
    builtin_error ("%s %s: %s", action, quoted ? quoted : file, strerror (error));
    free (quoted);
    return -1;
}

/* -R traversal, following GNU chown/chgrp: -P (default) never follows a
   symbolic link and changes links themselves; -H follows links named on the
   command line; -L follows every link to a directory. Directories are
   changed after their contents. */
enum { BOS_TRAVERSE_P, BOS_TRAVERSE_H, BOS_TRAVERSE_L };

struct bos_chown_ancestor
{
    dev_t dev;
    ino_t ino;
    const struct bos_chown_ancestor *up;
};

static inline void
bos_chown_tree_error (const char *what, const char *file, int error)
{
    if (bos_chown_quiet)
        return;
    char *quoted = bos_quoteaf (file);
    builtin_error ("%s %s: %s", what, quoted ? quoted : file, strerror (error));
    free (quoted);
}

static int
bos_chown_tree (const char *file, uid_t uid, gid_t gid, int deref,
                int traverse, int top, const struct bos_chown_ancestor *up)
{
    struct stat st;
    int rc = 0, follow, referent;

    if (lstat (file, &st) < 0)
        return bos_chown_operand (file, uid, gid, 0);

    follow = traverse == BOS_TRAVERSE_L || (traverse == BOS_TRAVERSE_H && top);
    /* GNU: with -P a link is always changed itself; otherwise -h decides. */
    referent = traverse == BOS_TRAVERSE_P ? 0 : deref;

    if (S_ISLNK (st.st_mode))
    {
        struct stat target;

        if (!follow || stat (file, &target) < 0 || !S_ISDIR (target.st_mode))
            return bos_chown_operand (file, uid, gid, referent);
        st = target;
    }

    if (S_ISDIR (st.st_mode))
    {
        const struct bos_chown_ancestor *a;
        struct bos_chown_ancestor self = { st.st_dev, st.st_ino, up };

        for (a = up; a; a = a->up)
            if (a->dev == st.st_dev && a->ino == st.st_ino)
            {
                if (!bos_chown_quiet)
                {
                    char *quoted = bos_quoteaf (file);
                    builtin_warning ("circular directory structure at %s",
                                     quoted ? quoted : file);
                    free (quoted);
                }
                return -1;
            }

        DIR *dir = opendir (file);
        if (dir == NULL)
        {
            bos_chown_tree_error ("cannot read directory", file, errno);
            rc = -1;
        }
        else
        {
            struct dirent *de;
            size_t base = strlen (file);
            int slash = base > 0 && file[base - 1] == '/';

            errno = 0;
            while ((de = readdir (dir)) != NULL)
            {
                if (de->d_name[0] == '.' &&
                    (de->d_name[1] == '\0' ||
                     (de->d_name[1] == '.' && de->d_name[2] == '\0')))
                    continue;
                size_t len = base + 1 + strlen (de->d_name) + 1;
                char *child = malloc (len);
                if (child == NULL)
                {
                    bos_chown_tree_error ("cannot read directory", file, ENOMEM);
                    rc = -1;
                    break;
                }
                snprintf (child, len, "%s%s%s", file, slash ? "" : "/", de->d_name);
                if (bos_chown_tree (child, uid, gid, deref, traverse, 0, &self) < 0)
                    rc = -1;
                free (child);
                errno = 0;
            }
            if (de == NULL && errno != 0)
            {
                bos_chown_tree_error ("cannot read directory", file, errno);
                rc = -1;
            }
            closedir (dir);
        }
        /* A followed link to a directory changes the directory itself. */
        if (bos_chown_operand (file, uid, gid, 1) < 0)
            rc = -1;
        return rc;
    }

    return bos_chown_operand (file, uid, gid, referent);
}

#endif
