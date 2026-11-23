/* SPDX-License-Identifier: MIT */
/* The shared engine of the chown and chgrp builtins: option scanning,
   OWNER[:GROUP] and GROUP operands, --from and --reference, the walk
   behind -R with -H/-L/-P, --preserve-root, and the -c/-v reports.
   Written for bash-os from the coreutils manual ("chown invocation",
   "chgrp invocation", "Disambiguating names and IDs", "Traversing
   symlinks", "Treating / specially"), POSIX chown/chgrp, and the observed
   behaviour of GNU coreutils 9.7. */
#ifndef BASHOS_CHOWN_OPERAND_H
#define BASHOS_CHOWN_OPERAND_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "gnu-quote.h"
#include "gnu-longopt.h"

#define BOS_CHOWN_KEEP_UID ((uid_t) -1)
#define BOS_CHOWN_KEEP_GID ((gid_t) -1)

/* How -R treats symbolic links: -P never follows one, -H follows those
   named as operands, -L follows every link to a directory. */
enum { BOS_TRAVERSE_P, BOS_TRAVERSE_H, BOS_TRAVERSE_L };

/* What goes to standard output: nothing, -c changes, or -v everything. */
enum { BOS_REPORT_NONE, BOS_REPORT_CHANGES, BOS_REPORT_ALL };

/* The outcome of one file, for the report. */
enum { BOS_CHOWN_CHANGED, BOS_CHOWN_RETAINED, BOS_CHOWN_FAILED };

struct bos_chown_job
{
    const char *prog;           /* "chown" or "chgrp" */
    int chgrp;                  /* running as chgrp */
    uid_t uid;                  /* requested owner, or KEEP */
    gid_t gid;                  /* requested group, or KEEP */
    char *to;                   /* the request as the reports name it, or NULL */
    int named;                  /* the request named a user or group */
    uid_t from_uid;             /* --from owner, or KEEP for any */
    gid_t from_gid;             /* --from group, or KEEP for any */
    int report;                 /* BOS_REPORT_* */
    int quiet;                  /* -f */
    int deref;                  /* act on a link's referent rather than the link */
    int recurse;                /* -R */
    int traverse;               /* BOS_TRAVERSE_* */
    int preserve_root;          /* --preserve-root */
    struct stat root;           /* "/" when preserve_root is set */
    int stopped;                /* an interrupt arrived during a walk */
};

/* A directory being walked, to notice a link that leads back up. */
struct bos_chown_level
{
    dev_t dev;
    ino_t ino;
    const struct bos_chown_level *up;
};

/* ---- names and numbers ------------------------------------------------ */

static inline char *
bos_chown_strdup (const char *text)
{
    char *copy = strdup (text);
    if (copy == NULL)
        builtin_error ("memory exhausted");
    return copy;
}

static inline char *
bos_chown_number_text (unsigned long value)
{
    char buf[32];
    snprintf (buf, sizeof buf, "%lu", value);
    return bos_chown_strdup (buf);
}

/* The user's name, or its number when the database has none. */
static inline char *
bos_chown_user_text (uid_t uid)
{
    struct passwd *pw = getpwuid (uid);
    return pw ? bos_chown_strdup (pw->pw_name) : bos_chown_number_text ((unsigned long) uid);
}

static inline char *
bos_chown_group_text (gid_t gid)
{
    struct group *gr = getgrgid (gid);
    return gr ? bos_chown_strdup (gr->gr_name) : bos_chown_number_text ((unsigned long) gid);
}

/* A numeric ID as the manual describes it: decimal digits, optionally
   after blanks and one '+'. A sign, other bases, trailing text and the
   value (uid_t) -1, which chown(2) reads as "unchanged", are refused. */
static inline int
bos_chown_parse_id (const char *text, unsigned long *value)
{
    const unsigned long max = (unsigned long) (uid_t) -1 - 1;
    unsigned long v = 0;
    int big = 0;

    while (*text == ' ' || (*text >= '\t' && *text <= '\r'))
        text++;
    if (*text == '+')
        text++;
    if (*text < '0' || *text > '9')
        return -1;
    for (; *text >= '0' && *text <= '9'; text++)
    {
        unsigned digit = (unsigned) (*text - '0');
        if (v > (max - digit) / 10)
            big = 1;
        else
            v = v * 10 + digit;
    }
    if (*text != '\0' || big)
        return -1;
    *value = v;
    return 0;
}

/* ---- OWNER[:GROUP] ---------------------------------------------------- */

enum { BOS_SPEC_OK, BOS_SPEC_BAD_USER, BOS_SPEC_BAD_GROUP, BOS_SPEC_BAD_SPEC, BOS_SPEC_NOMEM };

/* Resolve SPEC split at SEP (NULL: SPEC is all owner). A name is looked
   up first and a number tried after, except that a leading '+' means a
   number. "OWNER:" takes OWNER's login group, so OWNER must be a name.
   *TO, when TO is not NULL, receives the request as the reports show it:
   NULL when no name was given, else "OWNER" or "OWNER:GROUP" where a
   numeric owner is left out and a numeric group is written as a number. */
static inline int
bos_chown_split (const char *spec, const char *sep, uid_t *uid, gid_t *gid, char **to)
{
    char *user = sep ? strndup (spec, (size_t) (sep - spec)) : strdup (spec);
    const char *group = sep ? sep + 1 : NULL;
    char *user_name = NULL, *group_name = NULL;
    unsigned long n;
    int named_user = 0, rc = BOS_SPEC_OK;
    gid_t login = BOS_CHOWN_KEEP_GID;

    *uid = BOS_CHOWN_KEEP_UID;
    *gid = BOS_CHOWN_KEEP_GID;
    if (to)
        *to = NULL;
    if (user == NULL)
        return BOS_SPEC_NOMEM;

    if (*user)
    {
        struct passwd *pw = user[0] != '+' ? getpwnam (user) : NULL;
        if (pw)
        {
            *uid = pw->pw_uid;
            login = pw->pw_gid;
            named_user = 1;
        }
        else if (sep && *group == '\0')
            rc = BOS_SPEC_BAD_SPEC;
        else if (bos_chown_parse_id (user, &n) == 0)
            *uid = (uid_t) n;
        else
            rc = BOS_SPEC_BAD_USER;
    }
    if (rc == BOS_SPEC_OK && sep && *group == '\0' && named_user)
    {
        struct group *gr = getgrgid (login);
        *gid = login;
        if (gr && (group_name = strdup (gr->gr_name)) == NULL)
            rc = BOS_SPEC_NOMEM;
    }
    else if (rc == BOS_SPEC_OK && group && *group)
    {
        struct group *gr = group[0] != '+' ? getgrnam (group) : NULL;
        if (gr)
        {
            *gid = gr->gr_gid;
            if ((group_name = strdup (group)) == NULL)
                rc = BOS_SPEC_NOMEM;
        }
        else if (bos_chown_parse_id (group, &n) == 0)
            *gid = (gid_t) n;
        else
            rc = BOS_SPEC_BAD_GROUP;
    }
    if (named_user)
        user_name = user;

    if (rc == BOS_SPEC_OK && to && (user_name || group_name))
    {
        char gbuf[32];
        const char *gtext = group_name;
        if (gtext == NULL && *gid != BOS_CHOWN_KEEP_GID)
        {
            snprintf (gbuf, sizeof gbuf, "%lu", (unsigned long) *gid);
            gtext = gbuf;
        }
        size_t size = (user_name ? strlen (user_name) : 0) + (gtext ? strlen (gtext) : 0) + 2;
        *to = malloc (size);
        if (*to == NULL)
            rc = BOS_SPEC_NOMEM;
        else
            snprintf (*to, size, "%s%s%s", user_name ? user_name : "",
                      gtext ? ":" : "", gtext ? gtext : "");
    }
    free (user);
    free (group_name);
    return rc;
}

/* Parse a chown operand or a --from value, with GNU's diagnostics.
   Without a ':', the whole operand is first taken as an owner; if that
   fails and it holds a '.', the old OWNER.GROUP spelling is tried and,
   when it works, accepted with a warning. Returns 0, or -1 after the
   diagnostic. */
static inline int
bos_chown_parse_spec (const char *spec, uid_t *uid, gid_t *gid, char **to)
{
    const char *colon = strchr (spec, ':'), *dot;
    int rc = bos_chown_split (spec, colon, uid, gid, to);

    if (rc != BOS_SPEC_OK && rc != BOS_SPEC_NOMEM && colon == NULL
        && (dot = strchr (spec, '.')) != NULL)
    {
        char *dotted = NULL;
        if (bos_chown_split (spec, dot, uid, gid, to ? &dotted : NULL) == BOS_SPEC_OK)
        {
            char *quoted = bos_quote (spec);
            builtin_warning ("'.' should be ':': %s", quoted ? quoted : spec);
            free (quoted);
            if (to)
                *to = dotted;
            return 0;
        }
        free (dotted);
    }
    if (rc == BOS_SPEC_OK)
        return 0;
    if (rc == BOS_SPEC_NOMEM)
    {
        builtin_error ("memory exhausted");
        return -1;
    }
    char *quoted = bos_quote (spec);
    builtin_error ("invalid %s: %s",
                   rc == BOS_SPEC_BAD_USER ? "user" : rc == BOS_SPEC_BAD_GROUP ? "group" : "spec",
                   quoted ? quoted : spec);
    free (quoted);
    return -1;
}

/* A chgrp GROUP operand: empty for no change, a name, or a number. */
static inline int
bos_chgrp_parse_group (const char *group, gid_t *gid, char **to)
{
    struct group *gr;
    unsigned long n;

    *gid = BOS_CHOWN_KEEP_GID;
    *to = NULL;
    if (*group == '\0')
        return 0;
    gr = group[0] != '+' ? getgrnam (group) : NULL;
    if (gr)
    {
        *gid = gr->gr_gid;
        *to = bos_chown_strdup (group);
        return *to ? 0 : -1;
    }
    if (bos_chown_parse_id (group, &n) == 0)
    {
        *gid = (gid_t) n;
        return 0;
    }
    char *quoted = bos_quote (group);
    builtin_error ("invalid group: %s", quoted ? quoted : group);
    free (quoted);
    return -1;
}

/* ---- reports ---------------------------------------------------------- */

/* Whether the reports speak of the "group" rather than the "ownership". */
static inline int
bos_chown_group_only (const struct bos_chown_job *job)
{
    return job->uid == BOS_CHOWN_KEEP_UID && job->gid != BOS_CHOWN_KEEP_GID
        && (job->chgrp || !job->named);
}

/* The request in words when no name was given: the numbers. */
static inline char *
bos_chown_numeric_to (const struct bos_chown_job *job)
{
    char buf[64];
    if (job->uid == BOS_CHOWN_KEEP_UID && job->gid == BOS_CHOWN_KEEP_GID)
        return NULL;
    if (job->uid == BOS_CHOWN_KEEP_UID)
        snprintf (buf, sizeof buf, "%lu", (unsigned long) job->gid);
    else if (job->gid == BOS_CHOWN_KEEP_GID)
        snprintf (buf, sizeof buf, "%lu", (unsigned long) job->uid);
    else
        snprintf (buf, sizeof buf, "%lu:%lu", (unsigned long) job->uid, (unsigned long) job->gid);
    return bos_chown_strdup (buf);
}

/* The file's present owner, in the terms of the request. */
static inline char *
bos_chown_old_text (const struct bos_chown_job *job, const struct stat *st)
{
    if (job->uid == BOS_CHOWN_KEEP_UID && job->gid == BOS_CHOWN_KEEP_GID)
        return NULL;
    if (bos_chown_group_only (job))
        return bos_chown_group_text (st->st_gid);
    char *user = bos_chown_user_text (st->st_uid);
    if (user == NULL || job->gid == BOS_CHOWN_KEEP_GID)
        return user;
    char *group = bos_chown_group_text (st->st_gid);
    char *both = group ? malloc (strlen (user) + strlen (group) + 2) : NULL;
    if (both)
        sprintf (both, "%s:%s", user, group);
    free (user);
    free (group);
    return both;
}

/* One -c/-v line. OLD is the file's status before the change, or NULL
   when it could not be read. */
static inline void
bos_chown_report (const struct bos_chown_job *job, const char *file, int outcome,
                  const struct stat *old)
{
    if (job->report == BOS_REPORT_NONE)
        return;
    if (outcome != BOS_CHOWN_CHANGED && job->report != BOS_REPORT_ALL)
        return;

    const char *kind = bos_chown_group_only (job) ? "group" : "ownership";
    char *quoted = bos_quoteaf (file);
    char *from = old ? bos_chown_old_text (job, old) : NULL;
    const char *name = quoted ? quoted : file;

    switch (outcome)
    {
    case BOS_CHOWN_CHANGED:
        printf ("changed %s of %s from %s to %s\n", kind, name,
                from ? from : "", job->to ? job->to : "");
        break;
    case BOS_CHOWN_RETAINED:
        if (from)
            printf ("%s of %s retained as %s\n", kind, name, from);
        else
            printf ("%s of %s retained\n", kind, name);
        break;
    default:
        printf ("failed to change %s of %s%s%s%s%s\n", kind, name,
                from ? " from " : "", from ? from : "",
                job->to ? " to " : "", job->to ? job->to : "");
        break;
    }
    free (from);
    free (quoted);
}

/* A diagnostic about FILE, unless -f silenced it. */
static inline void
bos_chown_diag (const struct bos_chown_job *job, const char *what, const char *file, int error)
{
    if (job->quiet)
        return;
    char *quoted = bos_quoteaf (file);
    fflush (stdout);
    builtin_error ("%s %s: %s", what, quoted ? quoted : file, strerror (error));
    free (quoted);
}

/* ---- the change itself ------------------------------------------------ */

/* Change NAME in DIRFD (shown as PATH), whose status ST was read before
   any walk below it. */
static inline int
bos_chown_apply (const struct bos_chown_job *job, int dirfd, const char *name,
                 const char *path, const struct stat *st)
{
    struct stat old = *st;

    if (job->deref && S_ISLNK (old.st_mode))
    {
        struct stat target;
        if (fstatat (dirfd, name, &target, 0) < 0)
        {
            int error = errno;
            bos_chown_diag (job, "cannot dereference", path, error);
            bos_chown_report (job, path, BOS_CHOWN_FAILED, &old);
            return -1;
        }
        old = target;
    }

    if ((job->from_uid != BOS_CHOWN_KEEP_UID && old.st_uid != job->from_uid)
        || (job->from_gid != BOS_CHOWN_KEEP_GID && old.st_gid != job->from_gid))
    {
        bos_chown_report (job, path, BOS_CHOWN_RETAINED, &old);
        return 0;
    }

    if (fchownat (dirfd, name, job->uid, job->gid, job->deref ? 0 : AT_SYMLINK_NOFOLLOW) < 0)
    {
        int error = errno;
        bos_chown_diag (job, job->uid != BOS_CHOWN_KEEP_UID ? "changing ownership of"
                                                             : "changing group of", path, error);
        bos_chown_report (job, path, BOS_CHOWN_FAILED, &old);
        return -1;
    }

    int changed = (job->uid != BOS_CHOWN_KEEP_UID && job->uid != old.st_uid)
               || (job->gid != BOS_CHOWN_KEEP_GID && job->gid != old.st_gid);
    bos_chown_report (job, path, changed ? BOS_CHOWN_CHANGED : BOS_CHOWN_RETAINED, &old);
    return 0;
}

static inline int bos_chown_entry (struct bos_chown_job *, int, const char *, const char *,
                                   int, const struct bos_chown_level *);

/* A directory entry waiting for its turn. */
struct bos_chown_name
{
    ino_t ino;
    char *name;
};

static inline int
bos_chown_by_inode (const void *a, const void *b)
{
    ino_t x = ((const struct bos_chown_name *) a)->ino;
    ino_t y = ((const struct bos_chown_name *) b)->ino;
    return x < y ? -1 : x > y;
}

/* Entries beyond which GNU visits a directory on an ext2/3/4 file system
   in inode order rather than in the order the directory lists them. */
#define BOS_CHOWN_INODE_ORDER_ABOVE 10000
#define BOS_CHOWN_EXT_MAGIC 0xEF53

/* Read every name in the open directory FD, in the order they will be
   visited; NULL with errno on failure. */
static inline struct bos_chown_name *
bos_chown_read_names (int fd, size_t *count)
{
    int copy = dup (fd);
    DIR *dir = copy >= 0 ? fdopendir (copy) : NULL;
    struct bos_chown_name *names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *de;
    int error = 0;

    if (dir == NULL)
    {
        error = errno;
        if (copy >= 0)
            close (copy);
        errno = error;
        return NULL;
    }
    for (;;)
    {
        errno = 0;
        de = readdir (dir);
        if (de == NULL)
        {
            error = errno;
            break;
        }
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        if (n + 1 >= cap)
        {
            size_t ncap = cap ? cap * 2 : 32;
            struct bos_chown_name *grown = realloc (names, ncap * sizeof *grown);
            if (grown == NULL)
            {
                error = ENOMEM;
                break;
            }
            names = grown;
            cap = ncap;
        }
        names[n].ino = de->d_ino;
        if ((names[n].name = strdup (de->d_name)) == NULL)
        {
            error = ENOMEM;
            break;
        }
        n++;
    }
    closedir (dir);
    if (error)
    {
        while (n > 0)
            free (names[--n].name);
        free (names);
        errno = error;
        return NULL;
    }
    if (names == NULL && (names = malloc (sizeof *names)) == NULL)
        return NULL;
    if (n > BOS_CHOWN_INODE_ORDER_ABOVE)
    {
        struct statfs fs;
        if (fstatfs (fd, &fs) == 0 && fs.f_type == BOS_CHOWN_EXT_MAGIC)
            qsort (names, n, sizeof *names, bos_chown_by_inode);
    }
    *count = n;
    return names;
}

/* Walk the directory NAME in DIRFD, reached through a link when FOLLOW.
   Returns 0, -1 after a failure below it, or -2 (errno set) when the
   directory itself cannot be read. */
static inline int
bos_chown_descend (struct bos_chown_job *job, int dirfd, const char *name, const char *path,
                   int follow, const struct stat *st, const struct bos_chown_level *up)
{
    int fd = openat (dirfd, name, O_RDONLY | O_DIRECTORY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC
                                  | (follow ? 0 : O_NOFOLLOW));
    struct bos_chown_level self = { st->st_dev, st->st_ino, up };
    size_t count = 0, i, len = strlen (path);
    struct bos_chown_name *names;
    int rc = 0;

    if (fd < 0)
        return -2;
    names = bos_chown_read_names (fd, &count);
    if (names == NULL)
    {
        int error = errno;
        close (fd);
        errno = error;
        return -2;
    }
    for (i = 0; i < count; i++)
    {
        if (!job->stopped && (interrupt_state || terminating_signal))
            job->stopped = 1;
        if (!job->stopped)
        {
            int slash = len > 0 && path[len - 1] == '/';
            size_t size = len + strlen (names[i].name) + 2;
            char *child = malloc (size);
            if (child == NULL)
            {
                bos_chown_diag (job, "cannot read directory", path, ENOMEM);
                rc = -1;
                job->stopped = 1;
            }
            else
            {
                snprintf (child, size, "%s%s%s", path, slash ? "" : "/", names[i].name);
                if (bos_chown_entry (job, fd, names[i].name, child, 0, &self) < 0)
                    rc = -1;
                free (child);
            }
        }
        free (names[i].name);
    }
    free (names);
    close (fd);
    return rc;
}

/* One file: an operand (DIRFD is AT_FDCWD and TOP is set) or an entry met
   during -R. Directories are changed after their contents. */
static inline int
bos_chown_entry (struct bos_chown_job *job, int dirfd, const char *name, const char *path,
                 int top, const struct bos_chown_level *up)
{
    int follow = job->recurse && (job->traverse == BOS_TRAVERSE_L
                                  || (job->traverse == BOS_TRAVERSE_H && top));
    struct stat st;
    int rc = 0;

    if (fstatat (dirfd, name, &st, follow ? 0 : AT_SYMLINK_NOFOLLOW) < 0)
    {
        int error = errno;
        /* A dangling link met while following links is taken as itself. */
        if (!follow || fstatat (dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        {
            bos_chown_diag (job, "cannot access", path, error);
            bos_chown_report (job, path, BOS_CHOWN_FAILED, NULL);
            return -1;
        }
    }

    if (job->recurse && S_ISDIR (st.st_mode))
    {
        const struct bos_chown_level *level;
        int loop = 0;

        if (job->preserve_root && st.st_dev == job->root.st_dev && st.st_ino == job->root.st_ino)
        {
            char *quoted = bos_quoteaf (path);
            fflush (stdout);
            if (strcmp (path, "/") == 0)
                builtin_error ("it is dangerous to operate recursively on %s",
                               quoted ? quoted : path);
            else
                builtin_error ("it is dangerous to operate recursively on %s (same as '/')",
                               quoted ? quoted : path);
            builtin_error ("use --no-preserve-root to override this failsafe");
            free (quoted);
            return -1;
        }
        /* A link back to a directory being walked is changed, not entered. */
        for (level = up; level; level = level->up)
            if (level->dev == st.st_dev && level->ino == st.st_ino)
                loop = 1;
        if (!loop)
        {
            rc = bos_chown_descend (job, dirfd, name, path, follow, &st, up);
            if (rc == -2)
            {
                bos_chown_diag (job, "cannot read directory", path, errno);
                bos_chown_report (job, path, BOS_CHOWN_FAILED, NULL);
                return -1;
            }
        }
    }
    if (bos_chown_apply (job, dirfd, name, path, &st) < 0)
        rc = -1;
    return rc;
}

/* An operand as the walk names it: a run of trailing slashes becomes one. */
static inline char *
bos_chown_operand_path (const char *operand)
{
    size_t len = strlen (operand);
    char *path;

    if (len > 2 && operand[len - 1] == '/')
        while (len > 1 && operand[len - 1] == '/' && operand[len - 2] == '/')
            len--;
    path = malloc (len + 1);
    if (path == NULL)
    {
        builtin_error ("memory exhausted");
        return NULL;
    }
    memcpy (path, operand, len);
    path[len] = '\0';
    return path;
}

/* ---- the command ------------------------------------------------------ */

enum
{
    BOS_CHOWN_OPT_DEREFERENCE = BOS_OPT_FIRST,
    BOS_CHOWN_OPT_FROM,
    BOS_CHOWN_OPT_NO_PRESERVE_ROOT,
    BOS_CHOWN_OPT_PRESERVE_ROOT,
    BOS_CHOWN_OPT_REFERENCE
};

/* chown (CHGRP == 0) or chgrp (CHGRP == 1) over the words LIST. */
static inline int
bos_chown_main (WORD_LIST *list, int chgrp)
{
    static const struct bos_longopt longopts[] = {
        { "changes", BOS_NO_ARG, 'c' },
        { "dereference", BOS_NO_ARG, BOS_CHOWN_OPT_DEREFERENCE },
        { "from", BOS_REQ_ARG, BOS_CHOWN_OPT_FROM },
        { "no-dereference", BOS_NO_ARG, 'h' },
        { "no-preserve-root", BOS_NO_ARG, BOS_CHOWN_OPT_NO_PRESERVE_ROOT },
        { "preserve-root", BOS_NO_ARG, BOS_CHOWN_OPT_PRESERVE_ROOT },
        { "quiet", BOS_NO_ARG, 'f' },
        { "silent", BOS_NO_ARG, 'f' },
        { "recursive", BOS_NO_ARG, 'R' },
        { "reference", BOS_REQ_ARG, BOS_CHOWN_OPT_REFERENCE },
        { "verbose", BOS_NO_ARG, 'v' },
        { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    struct bos_chown_job job;
    bos_getopt g;
    const char *reference = NULL;
    int c, deref = -1, rc = EXECUTION_SUCCESS, i, first;

    memset (&job, 0, sizeof job);
    job.prog = chgrp ? "chgrp" : "chown";
    job.chgrp = chgrp;
    job.uid = BOS_CHOWN_KEEP_UID;
    job.gid = BOS_CHOWN_KEEP_GID;
    job.from_uid = BOS_CHOWN_KEEP_UID;
    job.from_gid = BOS_CHOWN_KEEP_GID;
    job.traverse = BOS_TRAVERSE_P;

    bos_getopt_init (&g, job.prog, "HLPRcfhv", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
    {
        switch (c)
        {
        case 'H': job.traverse = BOS_TRAVERSE_H; break;
        case 'L': job.traverse = BOS_TRAVERSE_L; break;
        case 'P': job.traverse = BOS_TRAVERSE_P; break;
        case 'R': job.recurse = 1; break;
        case 'c': job.report = BOS_REPORT_CHANGES; break;
        case 'v': job.report = BOS_REPORT_ALL; break;
        case 'f': job.quiet = 1; break;
        case 'h': deref = 0; break;
        case BOS_CHOWN_OPT_DEREFERENCE: deref = 1; break;
        case BOS_CHOWN_OPT_NO_PRESERVE_ROOT: job.preserve_root = 0; break;
        case BOS_CHOWN_OPT_PRESERVE_ROOT: job.preserve_root = 1; break;
        case BOS_CHOWN_OPT_REFERENCE: reference = g.optarg; break;
        case BOS_CHOWN_OPT_FROM:
            if (bos_chown_parse_spec (g.optarg, &job.from_uid, &job.from_gid, NULL) < 0)
            {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case BOS_OPT_HELP:
            bos_getopt_free (&g);
            builtin_help ();
            return EXECUTION_SUCCESS;
        case BOS_OPT_VERSION:
            bos_getopt_free (&g);
            printf ("%s 2.0 (bash-loadable)\n", job.prog);
            return sh_chkwrite (EXECUTION_SUCCESS);
        default:
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
    }

    if (job.recurse && job.traverse == BOS_TRAVERSE_P)
    {
        if (deref == 1)
        {
            builtin_error ("-R --dereference requires either -H or -L");
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
        deref = 0;
    }
    job.deref = deref != 0;

    if (g.noperands < (reference ? 1 : 2))
    {
        if (g.noperands == 0)
            builtin_error ("missing operand");
        else
        {
            char *quoted = bos_quote (g.operands[g.noperands - 1]);
            builtin_error ("missing operand after %s", quoted ? quoted : g.operands[0]);
            free (quoted);
        }
        bos_try_help (job.prog);
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }

    if (reference)
    {
        struct stat ref;
        if (stat (reference, &ref) < 0)
        {
            int error = errno;
            char *quoted = bos_quoteaf (reference);
            builtin_error ("failed to get attributes of %s: %s", quoted ? quoted : reference,
                           strerror (error));
            free (quoted);
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
        job.gid = ref.st_gid;
        if (chgrp)
            job.to = bos_chown_group_text (ref.st_gid);
        else
        {
            char *user = bos_chown_user_text (ref.st_uid);
            char *group = bos_chown_group_text (ref.st_gid);
            job.uid = ref.st_uid;
            if (user && group && (job.to = malloc (strlen (user) + strlen (group) + 2)))
                sprintf (job.to, "%s:%s", user, group);
            free (user);
            free (group);
        }
        if (job.to == NULL)
        {
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
        job.named = 1;
        first = 0;
    }
    else
    {
        if ((chgrp ? bos_chgrp_parse_group (g.operands[0], &job.gid, &job.to)
                   : bos_chown_parse_spec (g.operands[0], &job.uid, &job.gid, &job.to)) < 0)
        {
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
        job.named = job.to != NULL;
        if (job.to == NULL)
            job.to = bos_chown_numeric_to (&job);
        first = 1;
    }

    if (job.preserve_root && stat ("/", &job.root) < 0)
    {
        int error = errno;
        builtin_error ("failed to get attributes of '/': %s", strerror (error));
        free (job.to);
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }

    for (i = first; i < g.noperands; i++)
    {
        char *path = bos_chown_operand_path (g.operands[i]);
        if (path == NULL || bos_chown_entry (&job, AT_FDCWD, path, path, 1, NULL) < 0)
            rc = EXECUTION_FAILURE;
        free (path);
        if (job.stopped || interrupt_state || terminating_signal)
        {
            free (job.to);
            bos_getopt_free (&g);
            fflush (stdout);
            QUIT;
            return EXECUTION_FAILURE;
        }
    }
    free (job.to);
    bos_getopt_free (&g);
    return sh_chkwrite (rc);
}

#endif
