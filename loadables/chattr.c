/* SPDX-License-Identifier: MIT */
/* chattr.c — change ext2/3/4 file attributes, as a bash builtin.
 *
 *   chattr [-R] [+-=]MODE file...
 *
 *   +flags   add the listed attributes
 *   -flags   remove the listed attributes
 *   =flags   set exactly the listed attributes
 *   -R       recurse into directories
 *
 * Flags: a(append) i(immutable) A(no-atime) d(no-dump) s(secure-delete)
 *        u(undeletable) S(sync) D(dirsync) c(compress) j(data-journal)
 *        t(no-tail-merge) T(top-of-dir) e(extents) C(no-COW)
 *
 * Uses the FS_IOC_GETFLAGS / FS_IOC_SETFLAGS ioctls. Note that i/a require
 * CAP_LINUX_IMMUTABLE, and many filesystems (tmpfs) don't support these at
 * all (the ioctl returns ENOTTY / EOPNOTSUPP).
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
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"

/* Self-contained ioctl + flag definitions: musl's headers may not pull all of
   these in, and the numeric ABI is stable. */
#ifndef FS_IOC_GETFLAGS
#  define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#  define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif

static const struct { unsigned int bit; char ch; } chattr_flagtab[] = {
    { 0x00000001u, 's' }, /* SECRM   */
    { 0x00000002u, 'u' }, /* UNRM    */
    { 0x00000004u, 'c' }, /* COMPR   */
    { 0x00000008u, 'S' }, /* SYNC    */
    { 0x00000010u, 'i' }, /* IMMUTABLE */
    { 0x00000020u, 'a' }, /* APPEND  */
    { 0x00000040u, 'd' }, /* NODUMP  */
    { 0x00000080u, 'A' }, /* NOATIME */
    { 0x00004000u, 'j' }, /* JOURNAL_DATA */
    { 0x00008000u, 't' }, /* NOTAIL  */
    { 0x00010000u, 'D' }, /* DIRSYNC */
    { 0x00020000u, 'T' }, /* TOPDIR  */
    { 0x00080000u, 'e' }, /* EXTENT  */
    { 0x00800000u, 'C' }, /* NOCOW   */
};
#define CHATTR_NFLAGS (sizeof chattr_flagtab / sizeof chattr_flagtab[0])

static int
char_to_bit (char c, unsigned int *bit)
{
    for (size_t i = 0; i < CHATTR_NFLAGS; i++)
        if (chattr_flagtab[i].ch == c) { *bit = chattr_flagtab[i].bit; return 0; }
    return -1;
}

struct chattr_change {
    unsigned int add, remove, set;
    int assignment;
};

/* Descend through held directory descriptors; never reopen a child through a
   pathname whose parent can be replaced during recursive traversal. */
static int
apply_to_path_at (int parent, const char *name, const char *display,
                  const struct chattr_change *change, int recurse)
{
    struct stat st;
    if (fstatat (parent, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        fprintf (stderr, "chattr: %s while trying to stat %s\n", strerror (errno), display);
        return -1;
    }
    if (!S_ISREG (st.st_mode) && !S_ISDIR (st.st_mode)) {
        fprintf (stderr, "chattr: %s while reading flags on %s\n", strerror (EOPNOTSUPP), display);
        return -1;
    }
    int fd = openat (parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        if (e == ELOOP || e == ENXIO) e = EOPNOTSUPP;
        fprintf (stderr, "chattr: %s while reading flags on %s\n", strerror (e), display);
        return -1;
    }
    if (fstat (fd, &st) < 0) {
        int e = errno; close (fd);
        fprintf (stderr, "chattr: %s while reading flags on %s\n", strerror (e), display);
        return -1;
    }
    if (!S_ISREG (st.st_mode) && !S_ISDIR (st.st_mode)) {
        close (fd);
        fprintf (stderr, "chattr: %s while reading flags on %s\n", strerror (EOPNOTSUPP), display);
        return -1;
    }
    unsigned int flags = 0;
    if (ioctl (fd, FS_IOC_GETFLAGS, &flags) < 0) {
        int e = errno == ENOTTY ? EOPNOTSUPP : errno; close (fd);
        fprintf (stderr, "chattr: %s while reading flags on %s\n", strerror (e), display);
        return -1;
    }
    unsigned int newflags = change->assignment ? change->set :
        (flags & ~change->remove) | change->add;
    if (!change->assignment && !S_ISDIR (st.st_mode)) newflags &= ~0x00010000u;
    if (ioctl (fd, FS_IOC_SETFLAGS, &newflags) < 0) {
        int e = errno == ENOTTY ? EOPNOTSUPP : errno;
        if (change->assignment) {
            fprintf (stderr, "%s: %s\n", display, strerror (e));
        } else {
            fprintf (stderr, "chattr: %s while setting flags on %s\n", strerror (e), display);
            close (fd);
            return -1;
        }
    }
    if (!recurse || !S_ISDIR (st.st_mode)) { close (fd); return 0; }
    DIR *dir = fdopendir (fd);
    if (!dir) {
        int e = errno; close (fd);
        fprintf (stderr, "chattr: %s while reading directory %s\n", strerror (e), display);
        return -1;
    }
    int rc = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir (dir);
        if (!de) {
            if (errno) { fprintf (stderr, "chattr: %s while reading directory %s\n", strerror (errno), display); rc = -1; }
            break;
        }
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        size_t a = strlen (display), b = strlen (de->d_name);
        if (b > (size_t)-1 - 2 || a > (size_t)-1 - b - 2) { errno = ENAMETOOLONG; rc = -1; break; }
        char *child = malloc (a + b + 2);
        if (!child) { rc = -1; break; }
        memcpy (child, display, a); child[a] = '/';
        memcpy (child + a + 1, de->d_name, b + 1);
        if (apply_to_path_at (dirfd (dir), de->d_name, child, change, recurse) < 0) rc = -1;
        free (child);
    }
    if (closedir (dir) < 0) rc = -1;
    return rc;
}

int
chattr_builtin (WORD_LIST *list)
{
    int recurse = 0;
    struct chattr_change change = { 0, 0, 0, 0 };
    int have_add = 0, have_remove = 0;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) {
            extern char *chattr_doc[];
            for (char **lp = chattr_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-R") || !strcmp (w, "--recursive")) { recurse = 1; list = list->next; continue; }
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (w[0] == '+' || w[0] == '-' || w[0] == '=') {
            /* A flag-spec token. (A bare "-" with no following letters is not
               valid here; "-R" was handled above.) */
            if (w[0] == '-' && w[1] == '\0') break;
            unsigned int *mask;
            if (w[0] == '+') { have_add = 1; mask = &change.add; }
            else if (w[0] == '-') { have_remove = 1; mask = &change.remove; }
            else { change.assignment = 1; mask = &change.set; }
            for (const char *c = w + 1; *c; c++) {
                unsigned int bit;
                if (char_to_bit (*c, &bit) < 0) {
                    fprintf (stderr, "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project] [-v version] files...\n");
                    return EXECUTION_FAILURE;
                }
                *mask |= bit;
            }
            list = list->next;
            continue;
        }
        break;  /* first non-option, non-flagspec token → start of file list */
    }

    if (!list) {
        fprintf (stderr, "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project] [-v version] files...\n");
        return EXECUTION_FAILURE;
    }
    if (!change.assignment && !have_add && !have_remove) {
        fputs ("Must use '-v', =, - or +\n", stderr);
        return EXECUTION_FAILURE;
    }

    if (change.assignment && (have_add || have_remove)) {
        fputs ("= is incompatible with - and +\n", stderr);
        return EXECUTION_FAILURE;
    }
    if (change.add & change.remove) {
        fputs ("Can't both set and unset same flag.\n", stderr);
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (apply_to_path_at (AT_FDCWD, p->word->word, p->word->word, &change, recurse) < 0)
            rc = EXECUTION_FAILURE;
    return rc;
}

char *chattr_doc[] = {
    "Change file attributes on a Linux filesystem.",
    "",
    "    chattr [-R] [+-=]MODE file...",
    "",
    "    +flags  add attributes      -flags  remove attributes",
    "    =flags  set exactly         -R      recurse into directories",
    "",
    "Flags: a append, i immutable, A no-atime, d no-dump, s secure-delete,",
    "       u undeletable, S sync, D dirsync, c compress, j data-journal,",
    "       t no-tail, T top-of-dir, e extents, C no-COW.",
    "i and a require CAP_LINUX_IMMUTABLE; some filesystems support no flags.",
    (char *) NULL
};

struct builtin chattr_struct = {
    "chattr",
    chattr_builtin,
    BUILTIN_ENABLED,
    chattr_doc,
    "chattr [-R] [+-=]MODE file...",
    0
};
