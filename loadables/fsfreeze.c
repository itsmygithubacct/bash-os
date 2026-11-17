/* SPDX-License-Identifier: MIT */
/* fsfreeze.c — suspend or resume access to a filesystem, as a bash builtin
 * (util-linux fsfreeze).
 *
 *   fsfreeze -f | --freeze    MOUNTPOINT
 *   fsfreeze -u | --unfreeze  MOUNTPOINT
 *
 * Issues the FIFREEZE / FITHAW ioctls on the mountpoint's directory fd.
 * Requires CAP_SYS_ADMIN (root) and a filesystem that supports freezing.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"

#ifndef FIFREEZE
#  define FIFREEZE _IOWR('X', 119, int)   /* freeze the filesystem */
#endif
#ifndef FITHAW
#  define FITHAW   _IOWR('X', 120, int)   /* thaw  the filesystem */
#endif

static int
fsfreeze_try (void)
{
    fprintf (stderr, "Try 'fsfreeze --help' for more information.\n");
    return EXECUTION_FAILURE;
}

/* Checks, their order, their wording and status 1 follow util-linux. */
int
fsfreeze_builtin (WORD_LIST *list)
{
    int freeze = 0, unfreeze = 0, options = 1, nops = 0;
    const char *mp = NULL;

    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (!options || w[0] != '-' || !w[1]) {
            if (nops++ == 0) mp = w;
            continue;
        }
        if (!strcmp (w, "--")) { options = 0; continue; }
        if (!strcmp (w, "--help")) {
            extern char *fsfreeze_doc[];
            clearerr (stdout);
            for (char **lp = fsfreeze_doc; *lp; lp++)
                if (puts (*lp) == EOF) return EXECUTION_FAILURE;
            return (fflush (stdout) == EOF || ferror (stdout))
                ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--freeze")) { freeze = 1; continue; }
        if (!strcmp (w, "--unfreeze")) { unfreeze = 1; continue; }
        if (w[1] == '-') {
            builtin_error ("unrecognized option '%s'", w);
            return fsfreeze_try ();
        }
        for (const char *c = w + 1; *c; c++) {
            if (*c == 'f') freeze = 1;
            else if (*c == 'u') unfreeze = 1;
            else {
                builtin_error ("invalid option -- '%c'", *c);
                return fsfreeze_try ();
            }
        }
    }
    if (freeze && unfreeze) {
        builtin_error ("mutually exclusive arguments: --freeze --unfreeze");
        return EXECUTION_FAILURE;
    }
    if (!freeze && !unfreeze) {
        builtin_error ("neither --freeze or --unfreeze specified");
        return EXECUTION_FAILURE;
    }
    if (nops == 0) { builtin_error ("no filename specified"); return EXECUTION_FAILURE; }
    if (nops > 1) { builtin_error ("unexpected number of arguments"); return fsfreeze_try (); }

    int fd = open (mp, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error ("cannot open %s: %s", mp, strerror (errno)); return EXECUTION_FAILURE; }

    /* The object actually opened is the one checked, so a replacement
     * between the two cannot be frozen in its place. The kernel ioctl decides
     * whether this directory's filesystem supports the requested action. */
    struct stat st;
    if (fstat (fd, &st) < 0) {
        builtin_error ("stat of %s failed: %s", mp, strerror (errno));
        close (fd);
        return EXECUTION_FAILURE;
    }
    if (!S_ISDIR (st.st_mode)) {
        builtin_error ("%s: is not a directory", mp);
        close (fd);
        return EXECUTION_FAILURE;
    }

    int rc = ioctl (fd, freeze ? FIFREEZE : FITHAW, 0);
    int e = errno;
    close (fd);
    if (rc < 0) {
        builtin_error ("%s: %s failed: %s", mp, freeze ? "freeze" : "unfreeze", strerror (e));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

char *fsfreeze_doc[] = {
    "Suspend or resume access to a filesystem.",
    "",
    "    fsfreeze -f | --freeze    MOUNTPOINT",
    "    fsfreeze -u | --unfreeze  MOUNTPOINT",
    "",
    "Uses the FIFREEZE / FITHAW ioctls; requires root and a freezable fs.",
    (char *) NULL
};

struct builtin fsfreeze_struct = {
    "fsfreeze",
    fsfreeze_builtin,
    BUILTIN_ENABLED,
    fsfreeze_doc,
    "fsfreeze {-f|-u} MOUNTPOINT",
    0
};
