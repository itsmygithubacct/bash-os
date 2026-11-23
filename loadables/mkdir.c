/* SPDX-License-Identifier: MIT */
/* mkdir: make directories, as a bash builtin.
 *
 *   mkdir [-pvZ] [-m MODE] [--context[=CTX]] DIRECTORY...
 *
 * Written for bash-os from the coreutils manual, POSIX mkdir and the
 * observed behaviour of GNU coreutils 9.7 mkdir: -m/--mode (octal or
 * symbolic, starting from a=rwx), -p/--parents (missing parents get the
 * umask with u+wx), -v/--verbose, -Z/--context, the same diagnostics and
 * exit status. The umask is changed only around each mkdir call and is
 * always put back before the builtin returns.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-longopt.h"
#include "gnu-quote.h"
#include "gnu-mode.h"

enum { MKD_OPT_CONTEXT = BOS_OPT_FIRST };

static const struct bos_longopt mkd_longopts[] = {
    { "mode", BOS_REQ_ARG, 'm' },
    { "context", BOS_OPT_ARG, MKD_OPT_CONTEXT },
    { "parents", BOS_NO_ARG, 'p' },
    { "verbose", BOS_NO_ARG, 'v' },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

struct mkd
{
    struct bos_mode_change *changes;    /* NULL without -m */
    mode_t umask_value;
    int parents, verbose;
};

static void
mkd_error (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static void
mkd_error (const char *fmt, ...)
{
    va_list ap;
    char buf[8192];

    va_start (ap, fmt);
    vsnprintf (buf, sizeof buf, fmt, ap);
    va_end (ap);
    fflush (stdout);
    builtin_error ("%s", buf);
}

static void
mkd_fail (const char *what, const char *name, int e)
{
    char *q = bos_quote (name);

    mkd_error ("%s %s: %s", what, q ? q : name, strerror (e));
    free (q);
}

static void
mkd_created (const struct mkd *o, const char *name)
{
    if (o->verbose)
    {
        char *q = bos_quoteaf (name);
        printf ("mkdir: created directory %s\n", q ? q : name);
        free (q);
    }
}

/* mkdirat with umask MASK in force for just that call. */
static int
mkd_call (int dirfd, const char *name, mode_t mode, mode_t mask)
{
    mode_t saved = umask (mask);
    int r = mkdirat (dirfd, name, mode), e = errno;

    umask (saved);
    errno = e;
    return r;
}

/* Create NAME (relative to DIRFD) as a directory the command line named:
   with the -m mode, or 0777 under the umask. Returns 0 or an errno. */
static int
mkd_final (const struct mkd *o, int dirfd, const char *name, const char *disp)
{
    mode_t mode, bits, desired;
    int special, fd, e;
    struct stat st;

    if (o->changes == NULL)
        return mkd_call (dirfd, name, 0777, o->umask_value) == 0 ? 0 : errno;

    mode = bos_mode_adjust (0777, 1, o->umask_value, o->changes, &bits);
    /* mkdir(2) cannot set the set-ID bits, and a set-group-ID parent can
       pass its bit on: such a directory is made without group and other
       write permission, and the bits the MODE named are then put right. */
    special = (mode & 07000) != 0 || (bits & 06000) != 0;
    if (mkd_call (dirfd, name, special ? mode & ~(mode_t) 022 : mode,
                  o->umask_value & ~mode) != 0)
        return errno;
    if (!special)
        return 0;

    fd = openat (dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC);
    if ((fd >= 0 ? fstat (fd, &st) : fstatat (dirfd, name, &st, AT_SYMLINK_NOFOLLOW)) != 0)
    {
        e = errno;
        if (fd >= 0)
            close (fd);
        mkd_fail ("cannot set permissions of", disp, e);
        return -1;
    }
    desired = bos_mode_adjust (0777 | (st.st_mode & 06000), 1, o->umask_value, o->changes, NULL);
    if (((st.st_mode ^ desired) & bits & BOS_MODE_BITS)
        && (fd >= 0 ? fchmod (fd, desired) : fchmodat (dirfd, name, desired, 0)) != 0)
    {
        e = errno;
        if (fd >= 0)
            close (fd);
        mkd_fail ("cannot set permissions of", disp, e);
        return -1;
    }
    if (fd >= 0)
        close (fd);
    return 0;
}

/* After a failed creation under -p: success when DISP already names a
   directory; otherwise report. Returns 0 or 1. */
static int
mkd_existing (int dirfd, const char *name, const char *disp, int e)
{
    struct stat st;

    if (fstatat (dirfd, name, &st, 0) == 0)
    {
        if (S_ISDIR (st.st_mode))
            return 0;
    }
    else if (e == EEXIST && errno != ENOENT)
    {
        mkd_fail ("cannot stat", disp, errno);
        return 1;
    }
    mkd_fail ("cannot create directory", disp, e);
    return 1;
}

static int
mkd_parents (const struct mkd *o, const char *path)
{
    size_t len = strlen (path), i = 0, end;
    int dirfd = AT_FDCWD, rc = 0, e0;
    char *buf = malloc (len + 1), *prefix = malloc (len + 1);

    if (buf == NULL || prefix == NULL)
    {
        free (buf);
        free (prefix);
        mkd_error ("memory exhausted");
        return 1;
    }
    if (len == 0)
    {
        free (buf);
        free (prefix);
        e0 = mkd_final (o, AT_FDCWD, path, path);
        return e0 == 0 ? 0 : e0 > 0 ? mkd_existing (AT_FDCWD, path, path, e0) : 1;
    }
    if (path[0] == '/')
    {
        dirfd = open ("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0)
        {
            mkd_fail ("cannot create directory", path, errno);
            free (buf);
            free (prefix);
            return 1;
        }
    }

    /* The last component is the directory itself. */
    end = len;
    while (end > 0 && path[end - 1] == '/')
        end--;
    if (end == 0)
        goto done;              /* "/" or "" */

    for (;;)
    {
        size_t start, n;
        int last, made, mkerr = 0, next;

        while (i < end && path[i] == '/')
            i++;
        start = i;
        while (i < end && path[i] != '/')
            i++;
        n = i - start;
        memcpy (buf, path + start, n);
        buf[n] = '\0';
        last = i >= end;

        if (last)
        {
            int e = mkd_final (o, dirfd, buf, path);

            if (e == 0)
                mkd_created (o, path);
            else if (e > 0)
                rc = mkd_existing (dirfd, buf, path, e);
            else
                rc = 1;
            break;
        }

        memcpy (prefix, path, i);
        prefix[i] = '\0';
        if (n == 1 && buf[0] == '.')
            continue;
        made = 0;
        if (!(n == 2 && buf[0] == '.' && buf[1] == '.'))
        {
            if (mkd_call (dirfd, buf, 0777, o->umask_value & ~0300) == 0)
            {
                made = 1;
                mkd_created (o, prefix);
            }
            else
                mkerr = errno;
        }
        /* Entering the directory needs search permission, not read. */
        next = openat (dirfd, buf, O_PATH | O_DIRECTORY | O_CLOEXEC | (made ? O_NOFOLLOW : 0));
        if (next >= 0 && faccessat (next, ".", X_OK, 0) != 0)
        {
            int e = errno;
            close (next);
            next = -1;
            errno = e;
        }
        if (next < 0)
        {
            int e = errno;

            if (e == ENOENT && mkerr)
                e = mkerr;
            mkd_fail ("cannot create directory", prefix, e);
            rc = 1;
            break;
        }
        if (dirfd != AT_FDCWD)
            close (dirfd);
        dirfd = next;
    }

done:
    if (dirfd != AT_FDCWD)
        close (dirfd);
    free (buf);
    free (prefix);
    return rc;
}

static void
mkd_usage (void)
{
    puts ("Usage: mkdir [OPTION]... DIRECTORY...\n"
          "Create the DIRECTORY(ies), if they do not already exist.\n"
          "\n"
          "Mandatory arguments to long options are mandatory for short options too.\n"
          "  -m, --mode=MODE   set file mode (as in chmod), not a=rwx - umask\n"
          "  -p, --parents     no error if existing, make parent directories as needed,\n"
          "                    with their file modes unaffected by any -m option\n"
          "  -v, --verbose     print a message for each created directory\n"
          "  -Z                   set SELinux security context of each created directory\n"
          "                         to the default type\n"
          "      --context[=CTX]  like -Z, or if CTX is specified then set the SELinux\n"
          "                         or SMACK security context to CTX\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit");
}

int
mkdir_builtin (WORD_LIST *list)
{
    struct mkd o;
    bos_getopt g;
    const char *modearg = NULL;
    int c, i, status = EXECUTION_SUCCESS, nomem = 0;

    memset (&o, 0, sizeof o);
    bos_getopt_init (&g, "mkdir", "m:pvZ", mkd_longopts, list);
    while ((c = bos_getopt_next (&g)) != -1)
    {
        switch (c)
        {
        case 'm': modearg = g.optarg; break;
        case 'p': o.parents = 1; break;
        case 'v': o.verbose = 1; break;
        case 'Z': break;
        case MKD_OPT_CONTEXT:
            if (g.optarg)
                mkd_error ("warning: ignoring --context; it requires an SELinux/SMACK-enabled kernel");
            break;
        case BOS_OPT_HELP:
            mkd_usage ();
            bos_getopt_free (&g);
            return sh_chkwrite (EXECUTION_SUCCESS);
        case BOS_OPT_VERSION:
            puts ("mkdir (bash-os coreutils) 9.7-compat\n"
                  "bash-os mkdir builtin; behaves like GNU coreutils 9.7 mkdir.\n"
                  "License MIT (bash-os); not GNU coreutils code.");
            bos_getopt_free (&g);
            return sh_chkwrite (EXECUTION_SUCCESS);
        default:
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
    }

    if (g.noperands == 0)
    {
        mkd_error ("missing operand");
        bos_try_help ("mkdir");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }

    o.umask_value = umask (0);
    umask (o.umask_value);
    if (modearg)
    {
        o.changes = bos_mode_compile (modearg, &nomem);
        if (o.changes == NULL)
        {
            if (nomem)
                mkd_error ("memory exhausted");
            else
            {
                char *q = bos_quote (modearg);
                mkd_error ("invalid mode %s", q ? q : modearg);
                free (q);
            }
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
    }

    for (i = 0; i < g.noperands; i++)
    {
        const char *dir = g.operands[i];

        QUIT;
        if (o.parents)
        {
            if (mkd_parents (&o, dir))
                status = EXECUTION_FAILURE;
        }
        else
        {
            int e = mkd_final (&o, AT_FDCWD, dir, dir);

            if (e == 0)
                mkd_created (&o, dir);
            else
            {
                if (e > 0)
                    mkd_fail ("cannot create directory", dir, e);
                status = EXECUTION_FAILURE;
            }
        }
    }

    umask (o.umask_value);
    free (o.changes);
    bos_getopt_free (&g);
    return sh_chkwrite (status);
}

char *mkdir_doc[] = {
    "Make directories.",
    "",
    "Create each DIRECTORY, in the order given.",
    "",
    "    -m, --mode=MODE   set file mode (as in chmod), not a=rwx - umask",
    "    -p, --parents     no error if existing, make parent directories as",
    "                      needed, with their file modes unaffected by -m",
    "    -v, --verbose     print a message for each created directory",
    "    -Z, --context[=CTX]  accepted; SELinux contexts are not supported",
    "",
    "Exit status is 0 on success and 1 if any directory could not be made.",
    (char *) NULL
};

struct builtin mkdir_struct = {
    "mkdir",
    mkdir_builtin,
    BUILTIN_ENABLED,
    mkdir_doc,
    "mkdir [-pvZ] [-m MODE] [--context[=CTX]] DIRECTORY...",
    0
};
