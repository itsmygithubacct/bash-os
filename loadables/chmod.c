/* SPDX-License-Identifier: MIT */
/* chmod: change file mode bits, as a bash builtin.
 *
 *   chmod [OPTION]... MODE[,MODE]... FILE...
 *   chmod [OPTION]... OCTAL-MODE FILE...
 *   chmod [OPTION]... --reference=RFILE FILE...
 *
 * Written for bash-os from the coreutils manual, POSIX chmod and the
 * observed behaviour of GNU coreutils 9.7 chmod: the same options
 * (-c -f -v -h -R -H -L -P, --dereference, --reference, --preserve-root),
 * the same -c/-v reports, diagnostics and exit status, and mode words that
 * look like options ("chmod -w FILE"). Mode parsing and evaluation live in
 * common/gnu-mode.h. The shell's umask is read, never changed.
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
#include <dirent.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-longopt.h"
#include "gnu-quote.h"
#include "gnu-mode.h"

enum { CHM_QUIET, CHM_CHANGES, CHM_ALWAYS };

enum
{
    CHM_OPT_DEREF = BOS_OPT_FIRST,
    CHM_OPT_NO_PRESERVE,
    CHM_OPT_PRESERVE,
    CHM_OPT_REFERENCE
};

static const struct bos_longopt chm_longopts[] = {
    { "changes", BOS_NO_ARG, 'c' },
    { "dereference", BOS_NO_ARG, CHM_OPT_DEREF },
    { "no-dereference", BOS_NO_ARG, 'h' },
    { "no-preserve-root", BOS_NO_ARG, CHM_OPT_NO_PRESERVE },
    { "preserve-root", BOS_NO_ARG, CHM_OPT_PRESERVE },
    { "quiet", BOS_NO_ARG, 'f' },
    { "recursive", BOS_NO_ARG, 'R' },
    { "reference", BOS_REQ_ARG, CHM_OPT_REFERENCE },
    { "silent", BOS_NO_ARG, 'f' },
    { "verbose", BOS_NO_ARG, 'v' },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

/* Letters that make an option-looking word a MODE ("-w", "-x,+r"). */
static const char chm_mode_letters[] = "rwxXstugoa,+=01234567";
static const char chm_short[] = "cfhvHLPR";

struct chm_anc
{
    dev_t dev;
    ino_t ino;
    const struct chm_anc *up;
};

struct chm
{
    struct bos_mode_change *changes;
    int use_ref;
    mode_t ref_mode;
    int verbosity, force, recurse, deref;   /* deref: -1 default, 0 -h, 1 */
    int traverse;                           /* 'H', 'L' or 'P' */
    int preserve_root, have_root, diagnose, stop;
    dev_t root_dev;
    ino_t root_ino;
    mode_t umask_value;
    int status;
};

static void
chm_error (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static void
chm_error (const char *fmt, ...)
{
    va_list ap;
    char buf[8192];

    va_start (ap, fmt);
    vsnprintf (buf, sizeof buf, fmt, ap);
    va_end (ap);
    fflush (stdout);
    builtin_error ("%s", buf);
}

/* A name quoted only when the shell (or a "NAME: message" reader) needs
   it, as GNU's diagnostics that start with a file name do. */
static char *
chm_quotef (const char *name)
{
    size_t len = strlen (name), i;
    int need = len == 0;
    mbstate_t st;

    memset (&st, 0, sizeof st);
    for (i = 0; i < len && !need;)
    {
        unsigned char c = (unsigned char) name[i];

        if (c < 0x80)
        {
            if (c < 0x20 || c == 0x7f || strchr (" !\"$&'()*;<=>?[\\^`|:", c))
                need = 1;
            else if ((c == '#' || c == '~') && i == 0)
                need = 1;
            else if ((c == '{' || c == '}') && len == 1)
                need = 1;
            i++;
        }
        else
        {
            wchar_t w;
            size_t n = mbrtowc (&w, name + i, len - i, &st);

            if (n == 0 || n == (size_t) -1 || n == (size_t) -2 || !iswprint ((wint_t) w))
                need = 1;
            else
                i += n;
        }
    }
    return need ? bos_quoteaf (name) : strdup (name);
}

static char *
chm_q (const char *name)
{
    char *q = bos_quoteaf (name);
    return q ? q : strdup ("''");
}

/* The display name of a command-line FILE: runs of trailing slashes
   become one, unless the name is all slashes. */
static char *
chm_top_name (const char *file)
{
    size_t len = strlen (file), end = len;
    char *out;

    while (end > 0 && file[end - 1] == '/')
        end--;
    if (end > 0 && end < len)
        end++;
    else
        end = len;
    out = malloc (end + 1);
    if (out)
    {
        memcpy (out, file, end);
        out[end] = '\0';
    }
    return out;
}

static char *
chm_join (const char *dir, const char *name)
{
    size_t dl = strlen (dir), nl = strlen (name);
    char *out;

    if (dl > 0 && dir[dl - 1] == '/')
        dl--;
    out = malloc (dl + nl + 2);
    if (out)
    {
        memcpy (out, dir, dl);
        out[dl] = '/';
        memcpy (out + dl + 1, name, nl + 1);
    }
    return out;
}

static void
chm_inaccessible (struct chm *o, const char *disp)
{
    if (o->verbosity == CHM_ALWAYS)
    {
        char *q = chm_q (disp);
        printf ("%s could not be accessed\n", q);
        free (q);
    }
    o->status = EXECUTION_FAILURE;
}

static void
chm_apply (struct chm *o, int dirfd, const char *name, const char *disp, mode_t oldmode)
{
    int is_dir = S_ISDIR (oldmode);
    mode_t newmode = o->use_ref ? o->ref_mode
                                : bos_mode_adjust (oldmode, is_dir, o->umask_value, o->changes, NULL);
    char before[10], after[10], *q;

    oldmode &= BOS_MODE_BITS;
    newmode &= BOS_MODE_BITS;
    bos_mode_string (oldmode, before);
    bos_mode_string (newmode, after);
    q = chm_q (disp);

    if (fchmodat (dirfd, name, newmode, 0) != 0)
    {
        int e = errno;

        if (!o->force)
            chm_error ("changing permissions of %s: %s", q, strerror (e));
        if (o->verbosity == CHM_ALWAYS)
            printf ("failed to change mode of %s from %04lo (%s) to %04lo (%s)\n",
                    q, (unsigned long) oldmode, before, (unsigned long) newmode, after);
        o->status = EXECUTION_FAILURE;
        free (q);
        return;
    }

    if (oldmode != newmode)
    {
        if (o->verbosity != CHM_QUIET)
            printf ("mode of %s changed from %04lo (%s) to %04lo (%s)\n",
                    q, (unsigned long) oldmode, before, (unsigned long) newmode, after);
    }
    else if (o->verbosity == CHM_ALWAYS)
        printf ("mode of %s retained as %04lo (%s)\n", q, (unsigned long) newmode, after);
    free (q);

    if (o->diagnose)
    {
        /* A MODE given like an option ("-w") warns when the umask kept a
           bit that the same MODE applied to all classes ("a-w") would not
           leave set. */
        mode_t naive = bos_mode_adjust (oldmode, is_dir, 0, o->changes, NULL) & BOS_MODE_BITS;

        if (newmode & ~naive)
        {
            char want[10], *f = chm_quotef (disp);

            bos_mode_string (naive, want);
            chm_error ("%s: new permissions are %s, not %s", f ? f : disp, after, want);
            free (f);
            o->status = EXECUTION_FAILURE;
        }
    }
}

static void chm_walk (struct chm *o, int dirfd, const char *name, const char *disp,
                      int top, const struct chm_anc *up);

static void
chm_descend (struct chm *o, int dirfd, const char *name, const char *disp,
             int follow, const struct chm_anc *up)
{
    struct chm_anc here;
    struct stat st;
    DIR *dp;
    struct dirent *de;
    char **names = NULL;
    size_t n = 0, cap = 0, i;
    int fd, dup_fd, read_errno = 0;
    const struct chm_anc *a;

    fd = openat (dirfd, name, O_RDONLY | O_DIRECTORY | O_NOCTTY | O_CLOEXEC
                 | (follow ? 0 : O_NOFOLLOW));
    if (fd < 0)
    {
        int e = errno;
        char *q = chm_q (disp);

        if (!o->force)
            chm_error ("cannot read directory %s: %s", q, strerror (e));
        free (q);
        chm_inaccessible (o, disp);
        return;
    }
    if (fstat (fd, &st) == 0)
    {
        /* A directory that is its own ancestor (via -L) is not entered again. */
        for (a = up; a; a = a->up)
            if (a->dev == st.st_dev && a->ino == st.st_ino)
            {
                close (fd);
                return;
            }
        here.dev = st.st_dev;
        here.ino = st.st_ino;
    }
    else
        here.dev = 0, here.ino = 0;
    here.up = up;

    dup_fd = dup (fd);
    dp = dup_fd >= 0 ? fdopendir (dup_fd) : NULL;
    if (dp == NULL)
    {
        int e = errno;
        char *q = chm_q (disp);

        if (dup_fd >= 0)
            close (dup_fd);
        close (fd);
        if (!o->force)
            chm_error ("cannot read directory %s: %s", q, strerror (e));
        free (q);
        chm_inaccessible (o, disp);
        return;
    }
    for (;;)
    {
        errno = 0;
        de = readdir (dp);
        if (de == NULL)
        {
            read_errno = errno;
            break;
        }
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0'
                                     || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        if (n == cap)
        {
            size_t ncap = cap ? cap * 2 : 32;
            char **v = realloc (names, ncap * sizeof *v);
            if (v == NULL)
            {
                read_errno = ENOMEM;
                break;
            }
            names = v;
            cap = ncap;
        }
        names[n] = strdup (de->d_name);
        if (names[n] == NULL)
        {
            read_errno = ENOMEM;
            break;
        }
        n++;
    }
    closedir (dp);

    for (i = 0; i < n; i++)
    {
        if (!o->stop && !interrupt_state && !terminating_signal)
        {
            char *child = chm_join (disp, names[i]);

            if (child)
            {
                chm_walk (o, fd, names[i], child, 0, &here);
                free (child);
            }
            else
            {
                chm_error ("memory exhausted");
                o->status = EXECUTION_FAILURE;
                o->stop = 1;
            }
        }
        else
            o->stop = 1;
        free (names[i]);
    }
    free (names);

    if (read_errno && !o->stop)
    {
        char *q = chm_q (disp);

        if (!o->force)
            chm_error ("cannot read directory %s: %s", q, strerror (read_errno));
        free (q);
        chm_inaccessible (o, disp);
    }
    close (fd);
}

static void
chm_walk (struct chm *o, int dirfd, const char *name, const char *disp,
          int top, const struct chm_anc *up)
{
    struct stat st, target, lst;
    int follow = top ? o->traverse != 'P' : o->traverse == 'L';
    int act = 1;
    mode_t source;

    if (fstatat (dirfd, name, &st, follow ? 0 : AT_SYMLINK_NOFOLLOW) != 0)
    {
        int e = errno, dangling;
        char *q;

        dangling = follow && e == ENOENT
            && fstatat (dirfd, name, &lst, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK (lst.st_mode);
        if (dangling && o->deref == 0)
        {
            /* -h acts on the link itself, which needs no referent. */
            if (o->verbosity == CHM_ALWAYS)
            {
                q = chm_q (disp);
                printf ("neither symbolic link %s nor referent has been changed\n", q);
                free (q);
            }
            return;
        }
        q = chm_q (disp);
        if (dangling)
        {
            if (!o->force)
                chm_error ("cannot operate on dangling symlink %s", q);
        }
        else if (!o->force)
            chm_error ("cannot access %s: %s", q, strerror (e));
        free (q);
        chm_inaccessible (o, disp);
        return;
    }

    if (top && o->recurse && o->preserve_root && o->have_root && S_ISDIR (st.st_mode)
        && st.st_dev == o->root_dev && st.st_ino == o->root_ino)
    {
        char *q = chm_q (disp);

        if (strcmp (disp, "/") == 0)
            chm_error ("it is dangerous to operate recursively on %s", q);
        else
        {
            char *r = chm_q ("/");
            chm_error ("it is dangerous to operate recursively on %s (same as %s)", q, r);
            free (r);
        }
        chm_error ("use --no-preserve-root to override this failsafe");
        free (q);
        o->status = EXECUTION_FAILURE;
        return;
    }

    source = st.st_mode;
    if (S_ISLNK (st.st_mode))
    {
        if (o->deref == 1)
        {
            if (fstatat (dirfd, name, &target, 0) != 0)
            {
                int e = errno;
                char *q = chm_q (disp);

                if (!o->force)
                    chm_error ("cannot dereference %s: %s", q, strerror (e));
                free (q);
                chm_inaccessible (o, disp);
                return;
            }
            source = target.st_mode;
        }
        else if (o->deref == 0 || o->recurse)
            act = 0;
    }
    else if (o->deref == 0
             && fstatat (dirfd, name, &lst, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK (lst.st_mode))
        act = 0;

    if (act)
        chm_apply (o, dirfd, name, disp, source);
    else if (o->verbosity == CHM_ALWAYS)
    {
        char *q = chm_q (disp);
        printf ("neither symbolic link %s nor referent has been changed\n", q);
        free (q);
    }

    if (o->recurse && S_ISDIR (st.st_mode))
        chm_descend (o, dirfd, name, disp, follow, up);
}

static int
chm_is_mode_word (const char *w)
{
    const char *p;

    if (w[0] != '-' || w[1] == '\0' || w[1] == '-')
        return 0;
    for (p = w + 1; *p; p++)
    {
        if (strchr (chm_mode_letters, *p))
            return 1;
        if (!strchr (chm_short, *p))
            return 0;
    }
    return 0;
}

/* Whether long option word W takes the next word as its argument. */
static int
chm_long_takes_next (const char *w)
{
    const char *name = w + 2;
    size_t len = strlen (name);
    const struct bos_longopt *o, *hit = NULL;

    if (strchr (name, '='))
        return 0;
    for (o = chm_longopts; o->name; o++)
        if (strncmp (o->name, name, len) == 0)
        {
            if (strlen (o->name) == len)
                return o->has_arg == BOS_REQ_ARG;
            if (hit && hit->val != o->val)
                return 0;
            hit = o;
        }
    return hit && hit->has_arg == BOS_REQ_ARG;
}

static void
chm_usage (void)
{
    puts ("Usage: chmod [OPTION]... MODE[,MODE]... FILE...\n"
          "  or:  chmod [OPTION]... OCTAL-MODE FILE...\n"
          "  or:  chmod [OPTION]... --reference=RFILE FILE...\n"
          "Change the mode of each FILE to MODE.\n"
          "With --reference, change the mode of each FILE to that of RFILE.\n"
          "\n"
          "  -c, --changes          like verbose but report only when a change is made\n"
          "  -f, --silent, --quiet  suppress most error messages\n"
          "  -v, --verbose          output a diagnostic for every file processed\n"
          "      --dereference      affect the referent of each symbolic link,\n"
          "                           rather than the symbolic link itself\n"
          "  -h, --no-dereference   affect each symbolic link, rather than the referent\n"
          "      --no-preserve-root  do not treat '/' specially (the default)\n"
          "      --preserve-root    fail to operate recursively on '/'\n"
          "      --reference=RFILE  use RFILE's mode instead of specifying MODE values.\n"
          "                         RFILE is always dereferenced if a symbolic link.\n"
          "  -R, --recursive        change files and directories recursively\n"
          "\n"
          "The following options modify how a hierarchy is traversed when the -R\n"
          "option is also specified.  If more than one is specified, only the final\n"
          "one takes effect. -H is the default.\n"
          "\n"
          "  -H                     if a command line argument is a symbolic link\n"
          "                         to a directory, traverse it\n"
          "  -L                     traverse every symbolic link to a directory\n"
          "                         encountered\n"
          "  -P                     do not traverse any symbolic links\n"
          "\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n"
          "\n"
          "Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.");
}

int
chmod_builtin (WORD_LIST *list)
{
    struct chm o;
    bos_getopt g;
    WORD_LIST *rest = NULL, **tail = &rest, *p;
    WORD_LIST *nodes = NULL;
    char *modetext = NULL;
    size_t modelen = 0, count = 0;
    const char *reference = NULL;
    int c, i, first_file, ended = 0, posix = getenv ("POSIXLY_CORRECT") != NULL;
    int nomem = 0;

    memset (&o, 0, sizeof o);
    o.deref = -1;
    o.traverse = 'H';
    o.status = EXECUTION_SUCCESS;

    /* Mode words that look like options are taken out first (GNU's
       getopt sees them as option letters and keeps the whole word). */
    for (p = list; p; p = p->next)
        count++;
    if (count)
    {
        nodes = calloc (count, sizeof *nodes);
        if (nodes == NULL)
        {
            chm_error ("memory exhausted");
            return EXECUTION_FAILURE;
        }
    }
    for (p = list, i = 0; p; p = p->next)
    {
        const char *w = p->word->word;

        if (!ended && strcmp (w, "--") == 0)
            ended = 1;
        else if (!ended && chm_is_mode_word (w))
        {
            size_t wl = strlen (w);
            char *m = realloc (modetext, modelen + wl + 2);

            if (m == NULL)
            {
                chm_error ("memory exhausted");
                free (modetext);
                free (nodes);
                return EXECUTION_FAILURE;
            }
            modetext = m;
            if (modelen)
                modetext[modelen++] = ',';
            memcpy (modetext + modelen, w, wl + 1);
            modelen += wl;
            continue;
        }
        else if (!ended && w[0] == '-' && w[1] == '-' && w[2] && chm_long_takes_next (w) && p->next)
        {
            nodes[i].word = p->word;
            *tail = &nodes[i++];
            tail = &(*tail)->next;
            p = p->next;
        }
        else if (!ended && posix && (w[0] != '-' || w[1] == '\0'))
            ended = 1;
        nodes[i].word = p->word;
        *tail = &nodes[i++];
        tail = &(*tail)->next;
    }
    *tail = NULL;

    bos_getopt_init (&g, "chmod", chm_short, chm_longopts, rest);
    while ((c = bos_getopt_next (&g)) != -1)
    {
        switch (c)
        {
        case 'c': o.verbosity = CHM_CHANGES; break;
        case 'v': o.verbosity = CHM_ALWAYS; break;
        case 'f': o.force = 1; break;
        case 'h': o.deref = 0; break;
        case CHM_OPT_DEREF: o.deref = 1; break;
        case 'R': o.recurse = 1; break;
        case 'H': case 'L': case 'P': o.traverse = c; break;
        case CHM_OPT_PRESERVE: o.preserve_root = 1; break;
        case CHM_OPT_NO_PRESERVE: o.preserve_root = 0; break;
        case CHM_OPT_REFERENCE: reference = g.optarg; break;
        case BOS_OPT_HELP:
            chm_usage ();
            bos_getopt_free (&g);
            free (modetext);
            free (nodes);
            return sh_chkwrite (EXECUTION_SUCCESS);
        case BOS_OPT_VERSION:
            puts ("chmod (bash-os coreutils) 9.7-compat\n"
                  "bash-os chmod builtin; behaves like GNU coreutils 9.7 chmod.\n"
                  "License MIT (bash-os); not GNU coreutils code.");
            bos_getopt_free (&g);
            free (modetext);
            free (nodes);
            return sh_chkwrite (EXECUTION_SUCCESS);
        default:
            bos_getopt_free (&g);
            free (modetext);
            free (nodes);
            return EXECUTION_FAILURE;
        }
    }

    first_file = 0;
    if (reference && modetext)
    {
        chm_error ("cannot combine mode and --reference options");
        bos_try_help ("chmod");
        goto usage_fail;
    }
    if (!reference && !modetext)
    {
        if (g.noperands == 0)
        {
            chm_error ("missing operand");
            bos_try_help ("chmod");
            goto usage_fail;
        }
        modetext = strdup (g.operands[0]);
        if (modetext == NULL)
        {
            chm_error ("memory exhausted");
            goto usage_fail;
        }
        first_file = 1;
        if (g.noperands == 1)
        {
            char *q = bos_quote (modetext);
            chm_error ("missing operand after %s", q ? q : modetext);
            free (q);
            bos_try_help ("chmod");
            goto usage_fail;
        }
    }
    else
    {
        o.diagnose = modetext != NULL;
        if (g.noperands == 0)
        {
            chm_error ("missing operand");
            bos_try_help ("chmod");
            goto usage_fail;
        }
    }

    if (reference)
    {
        struct stat rs;

        if (stat (reference, &rs) != 0)
        {
            int e = errno;
            char *q = chm_q (reference);
            chm_error ("failed to get attributes of %s: %s", q, strerror (e));
            free (q);
            goto usage_fail;
        }
        o.use_ref = 1;
        o.ref_mode = rs.st_mode & BOS_MODE_BITS;
    }
    else
    {
        o.changes = bos_mode_compile (modetext, &nomem);
        if (o.changes == NULL)
        {
            if (nomem)
                chm_error ("memory exhausted");
            else
            {
                char *q = bos_quote (modetext);
                chm_error ("invalid mode: %s", q ? q : modetext);
                free (q);
                bos_try_help ("chmod");
            }
            goto usage_fail;
        }
        o.umask_value = umask (0);
        umask (o.umask_value);
    }

    if (o.recurse && o.traverse == 'P' && o.deref == 1)
    {
        chm_error ("-R --dereference requires either -H or -L");
        goto usage_fail;
    }
    if (o.recurse && o.preserve_root)
    {
        struct stat rs;

        if (lstat ("/", &rs) == 0)
        {
            o.have_root = 1;
            o.root_dev = rs.st_dev;
            o.root_ino = rs.st_ino;
        }
        else
        {
            int e = errno;
            chm_error ("failed to get attributes of %s: %s", "'/'", strerror (e));
            goto usage_fail;
        }
    }

    for (i = first_file; i < g.noperands; i++)
    {
        char *disp;

        QUIT;
        disp = chm_top_name (g.operands[i]);
        if (disp == NULL)
        {
            chm_error ("memory exhausted");
            o.status = EXECUTION_FAILURE;
            break;
        }
        chm_walk (&o, AT_FDCWD, disp, disp, 1, NULL);
        free (disp);
        if (o.stop)
            break;
    }

    bos_getopt_free (&g);
    free (o.changes);
    free (modetext);
    free (nodes);
    QUIT;
    return sh_chkwrite (o.status);

usage_fail:
    bos_getopt_free (&g);
    free (o.changes);
    free (modetext);
    free (nodes);
    return EXECUTION_FAILURE;
}

char *chmod_doc[] = {
    "Change file mode bits.",
    "",
    "Change the mode of each FILE to MODE, or with --reference to that of",
    "RFILE. MODE is octal or symbolic: [ugoa]*([-+=]([rwxXst]*|[ugo]))+",
    "or [-+=][0-7]+, with several separated by commas.",
    "",
    "    -c, --changes          like verbose but report only when a change is made",
    "    -f, --silent, --quiet  suppress most error messages",
    "    -v, --verbose          output a diagnostic for every file processed",
    "        --dereference      affect the referent of each symbolic link",
    "    -h, --no-dereference   affect each symbolic link, rather than the referent",
    "        --no-preserve-root  do not treat '/' specially (the default)",
    "        --preserve-root    fail to operate recursively on '/'",
    "        --reference=RFILE  use RFILE's mode instead of specifying MODE values",
    "    -R, --recursive        change files and directories recursively",
    "    -H  with -R, traverse command-line symbolic links to directories (default)",
    "    -L  with -R, traverse every symbolic link to a directory",
    "    -P  with -R, do not traverse any symbolic links",
    "",
    "Exit status is 0 on success and 1 if any file could not be changed.",
    (char *) NULL
};

struct builtin chmod_struct = {
    "chmod",
    chmod_builtin,
    BUILTIN_ENABLED,
    chmod_doc,
    "chmod [-cfhvRHLP] [--reference=RFILE] MODE[,MODE]... FILE...",
    0
};
