/* pidof.c — find process IDs by name, as a bash builtin.
 *
 * Behavior follows sysvinit-utils 3.14 pidof (killall5.c main_pidof,
 * pidof, and readproc). Matching, option letters, separator, omit
 * parsing, quiet, single-shot, zombies, and root filtering follow that
 * source.
 *
 * Two adaptations keep the builtin observable from the shell:
 *   %PPID omits this shell (getpid). An external pidof is a child of
 *   the shell, so its getppid is this same process.
 *   Diagnostics use the sysvinit ttyname(0) gate and the same text, but
 *   a missing tty does not call syslog, and the builtin never exits
 *   the shell. /proc is read by absolute path; the builtin does not
 *   chdir.
 *
 * The network-filesystem match in that pidof() is unreachable: its
 * local nfs flag stays zero, and -n / PIDOF_NETFS do not change which
 * PIDs are selected. Those options are accepted and ignored.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "loadables.h"

#ifndef PATH_MAX
#  ifdef MAXPATHLEN
#    define PATH_MAX MAXPATHLEN
#  else
#    define PATH_MAX 2048
#  endif
#endif

#define PIDOF_STATNAME_LEN 15

#define PIDOF_SINGLE 0x01
#define PIDOF_OMIT   0x02
#define PIDOF_NETFS  0x04
#define PIDOF_QUIET  0x08

/* libc getopt. bashgetopt.h does not define these. */
extern char *optarg;
extern int optind, opterr, optopt;
extern int getopt (int, char *const *, const char *);

struct pidof_proc {
    char *pathname;
    char *argv0;
    char *argv0base;
    char *argv1;
    char *argv1base;
    char *statname;
    pid_t pid;
    struct pidof_proc *next;
};

struct pidof_omit {
    pid_t pid;
    struct pidof_omit *next;
};

static void
pidof_warn (const char *fmt, ...)
{
    va_list ap;

    /* sysvinit nsyslog writes stderr only when stdin is a terminal. */
    if (ttyname (0) == NULL)
        return;

    va_start (ap, fmt);
    fprintf (stderr, "pidof: ");
    vfprintf (stderr, fmt, ap);
    fprintf (stderr, "\n");
    va_end (ap);
}

static void
pidof_usage (void)
{
    printf ("pidof usage: [options] <program-name>\n\n");
    printf (" -c           Return PIDs with the same root directory\n");
    printf (" -d <sep>     Use the provided character as output separator\n");
    printf (" -h           Display this help text\n");
    printf (" -n           Avoid using stat system function on network shares\n");
    printf (" -o <pid>     Omit results with a given PID\n");
    printf (" -q           Quiet mode. Do not display output\n");
    printf (" -s           Only return one PID\n");
    printf (" -x           Return PIDs of shells running scripts with a matching name\n");
    printf (" -z           List zombie and I/O waiting processes. May cause pidof to hang.\n");
    printf ("\n");
}

static void
pidof_free_proc (struct pidof_proc *p)
{
    if (p == NULL)
        return;
    free (p->pathname);
    free (p->argv0);
    free (p->argv1);
    free (p->statname);
    free (p);
}

static void
pidof_free_list (struct pidof_proc *list)
{
    while (list != NULL) {
        struct pidof_proc *next = list->next;
        pidof_free_proc (list);
        list = next;
    }
}

static void
pidof_free_omit (struct pidof_omit *omit)
{
    while (omit != NULL) {
        struct pidof_omit *next = omit->next;
        free (omit);
        omit = next;
    }
}

/* Stop at PATH_MAX-1 bytes or a NUL, and do not consume the rest of a
   longer argument. A following read sees those leftover bytes. On an
   immediate EOF the buffer is cleared. */
static int
pidof_readarg (FILE *fp, char *buf, int sz)
{
    int c = 0;
    int f = 0;

    while (f < (sz - 1) && (c = fgetc (fp)) != EOF && c)
        buf[f++] = (char) c;
    buf[f] = '\0';
    return (c == EOF && f == 0) ? c : f;
}

static char *
pidof_dup_arg (const char *buf, int len)
{
    char *copy;

    if (len < 0)
        return NULL;
    copy = (char *) malloc ((size_t) len + 1);
    if (copy == NULL)
        return NULL;
    memcpy (copy, buf, (size_t) len + 1);
    return copy;
}

static int
pidof_readproc (int list_zombies, struct pidof_proc **out)
{
    DIR *dir;
    struct dirent *d;
    struct pidof_proc *list = NULL;
    int failed = 0;

    *out = NULL;
    dir = opendir ("/proc");
    if (dir == NULL) {
        pidof_warn ("cannot opendir(/proc)");
        return -1;
    }

    while ((d = readdir (dir)) != NULL) {
        struct pidof_proc *p;
        FILE *fp;
        char path[PATH_MAX + 1];
        char buf[PATH_MAX + 1];
        char status[11];
        char *s;
        char *q;
        unsigned long startcode, endcode;
        int pid, sid, f, nread;
        size_t len;

        pid = atoi (d->d_name);
        if (pid == 0)
            continue;

        p = (struct pidof_proc *) calloc (1, sizeof *p);
        if (p == NULL) {
            pidof_warn ("out of memory");
            failed = 1;
            break;
        }
        p->pid = (pid_t) pid;

        snprintf (path, sizeof path, "/proc/%s/stat", d->d_name);
        fp = fopen (path, "r");
        if (fp == NULL) {
            pidof_free_proc (p);
            continue;
        }
        len = fread (buf, 1, sizeof buf - 1, fp);
        buf[len] = '\0';
        fclose (fp);
        if (buf[0] == '\0') {
            pidof_warn ("can't read from %s\n", path);
            pidof_free_proc (p);
            continue;
        }

        s = buf;
        while (*s && *s != ' ')
            s++;
        if (*s)
            s++;
        if (*s == '(') {
            q = strrchr (buf, ')');
            if (q == NULL) {
                pidof_warn ("can't get program name from /proc/%s\n", path);
                pidof_free_proc (p);
                continue;
            }
            s++;
        } else {
            q = s;
            while (*q && *q != ' ')
                q++;
        }
        if (*q)
            *q++ = '\0';
        while (*q == ' ')
            q++;

        startcode = endcode = 0;
        sid = 0;
        nread = sscanf (q, "%10s %*d %*d %d %*d %*d %*u %*u "
                           "%*u %*u %*u %*u %*u %*d %*d "
                           "%*d %*d %*d %*d %*u %*u %*d "
                           "%*u %lu %lu",
                           status, &sid, &startcode, &endcode);
        if (nread != 4) {
            pidof_warn ("can't read sid from %s\n", path);
            pidof_free_proc (p);
            continue;
        }
        (void) sid;
        (void) startcode;
        (void) endcode;
        if (!list_zombies && strchr (status, 'Z') != NULL) {
            pidof_free_proc (p);
            continue;
        }

        p->statname = strdup (s);
        if (p->statname == NULL) {
            pidof_warn ("out of memory");
            pidof_free_proc (p);
            failed = 1;
            break;
        }

        snprintf (path, sizeof path, "/proc/%s/cmdline", d->d_name);
        fp = fopen (path, "r");
        if (fp == NULL) {
            pidof_free_proc (p);
            continue;
        }
        f = pidof_readarg (fp, buf, (int) sizeof buf);
        if (buf[0] != '\0') {
            p->argv0 = pidof_dup_arg (buf, f);
            if (p->argv0 == NULL) {
                fclose (fp);
                pidof_warn ("out of memory");
                pidof_free_proc (p);
                failed = 1;
                break;
            }
            p->argv0base = strrchr (p->argv0, '/');
            if (p->argv0base != NULL)
                p->argv0base++;
            else
                p->argv0base = p->argv0;
        }
        while ((f = pidof_readarg (fp, buf, (int) sizeof buf)) != EOF)
            if (buf[0] != '-')
                break;
        if (buf[0] != '\0') {
            p->argv1 = pidof_dup_arg (buf, f);
            if (p->argv1 == NULL) {
                fclose (fp);
                pidof_warn ("out of memory");
                pidof_free_proc (p);
                failed = 1;
                break;
            }
            p->argv1base = strrchr (p->argv1, '/');
            if (p->argv1base != NULL)
                p->argv1base++;
            else
                p->argv1base = p->argv1;
        }
        fclose (fp);

        snprintf (path, sizeof path, "/proc/%s/exe", d->d_name);
        p->pathname = (char *) calloc (PATH_MAX + 1, 1);
        if (p->pathname == NULL) {
            pidof_warn ("out of memory");
            pidof_free_proc (p);
            failed = 1;
            break;
        }
        if (readlink (path, p->pathname, PATH_MAX) < 0) {
            free (p->pathname);
            p->pathname = NULL;
        }

        /* Prepend, so a later walk is reverse readdir order. */
        p->next = list;
        list = p;
    }
    closedir (dir);

    if (failed) {
        pidof_free_list (list);
        return -1;
    }
    *out = list;
    return 0;
}

static int
pidof_name_match (const struct pidof_proc *p, const char *prog,
                  const char *base, int scripts_too)
{
    int ok = 0;

    ok |= (p->argv0 && strcmp (p->argv0, prog) == 0)
        || (p->argv0 && base != prog && strcmp (p->argv0, base) == 0)
        || (p->argv0base && strcmp (p->argv0base, prog) == 0);

    if (scripts_too && p->statname && p->argv1base
        && strncmp (p->statname, p->argv1base, PIDOF_STATNAME_LEN) == 0) {
        ok |= (p->argv1 && strcmp (p->argv1, prog) == 0)
            || (p->argv1 && base != prog && strcmp (p->argv1, base) == 0)
            || (p->argv1base && strcmp (p->argv1base, prog) == 0);
    }

    /* setproctitle leaves a space in argv[0], or an empty command line. */
    if (p->statname && strlen (base) <= PIDOF_STATNAME_LEN
        && (p->argv0 == NULL || p->argv0[0] == '\0' || strchr (p->argv0, ' ')))
        ok |= (strcmp (p->statname, base) == 0);

    /* Login shells keep the leading '-' on argv[0]. Do not strip it.
       This clause is only reached when no later argument was stored. */
    if (p->statname && strlen (base) <= PIDOF_STATNAME_LEN
        && p->argv1 == NULL && p->argv0 != NULL && p->argv0[0] == '-')
        ok |= (strcmp (p->statname, base) == 0);

    return ok;
}

/* 1 = pathname match, 0 = skip, -1 = fall through to the name match. */
static int
pidof_absolute_match (const struct pidof_proc *p, const char *prog,
                      int root, int scripts_too)
{
    size_t len;

    if (p->pathname == NULL) {
        if (root)
            return 0;
        return -1;
    }
    if (strcmp (prog, p->pathname) == 0)
        return 1;

    len = strlen (prog);
    if (strncmp (prog, p->pathname, len) != 0
        || strcmp (" (deleted)", p->pathname + len) != 0) {
        if (scripts_too)
            return -1;
        return 0;
    }
    return 1;
}

static int
pidof_push (struct pidof_proc ***arr, size_t *n, size_t *cap,
            struct pidof_proc *p)
{
    if (*n == *cap) {
        size_t next = *cap ? *cap * 2 : 16;
        struct pidof_proc **grown;

        if (next < *cap || next > (size_t) -1 / sizeof **arr)
            return -1;
        grown = (struct pidof_proc **) realloc (*arr, next * sizeof **arr);
        if (grown == NULL)
            return -1;
        *arr = grown;
        *cap = next;
    }
    (*arr)[(*n)++] = p;
    return 0;
}

static int
pidof_collect (struct pidof_proc *list, const char *prog, int scripts_too,
               struct pidof_proc ***out, size_t *nmatch)
{
    struct pidof_proc *p;
    struct pidof_proc **arr = NULL;
    size_t n = 0, cap = 0;
    char real_path[PATH_MAX + 1];
    const char *base;
    int dostat = 0;
    int foundone = 0;
    int root = (getuid () == 0);

    *out = NULL;
    *nmatch = 0;
    if (prog == NULL)
        return 0;

    memset (real_path, 0, sizeof real_path);
    if (prog[0] == '/' && realpath (prog, real_path) != NULL)
        dostat = 1;

    base = strrchr (prog, '/');
    if (base == NULL)
        base = prog;
    else
        base++;
    if (*base == '\0')
        return 0;

    if (dostat) {
        for (p = list; p != NULL; p = p->next) {
            int hit = 0;

            if (p->pathname && strcmp (real_path, p->pathname) == 0)
                hit = 1;
            else if (p->argv0 && strcmp (p->argv0, prog) == 0)
                hit = 1;
            if (!hit)
                continue;
            if (pidof_push (&arr, &n, &cap, p) < 0) {
                free (arr);
                pidof_warn ("out of memory");
                return -1;
            }
            foundone = 1;
        }
    }

    /* The sysvinit network-fs pass is dead because its nfs flag is 0. */
    if (!foundone) {
        for (p = list; p != NULL; p = p->next) {
            int hit = 0;

            if (prog[0] == '/') {
                int absolute = pidof_absolute_match (p, prog, root, scripts_too);

                if (absolute == 0)
                    continue;
                if (absolute == 1)
                    hit = 1;
            }
            if (!hit && !pidof_name_match (p, prog, base, scripts_too))
                continue;
            if (pidof_push (&arr, &n, &cap, p) < 0) {
                free (arr);
                pidof_warn ("out of memory");
                return -1;
            }
        }
    }

    *out = arr;
    *nmatch = n;
    return 0;
}

static int
pidof_is_omitted (const struct pidof_omit *omit, pid_t pid)
{
    for (; omit != NULL; omit = omit->next)
        if (omit->pid == pid)
            return 1;
    return 0;
}

static int
pidof_add_omit (struct pidof_omit **omit, const char *arg)
{
    char *copy;
    char *here;
    char *token;

    if (arg == NULL)
        return 0;
    copy = strdup (arg);
    if (copy == NULL) {
        pidof_warn ("out of memory");
        return -1;
    }
    here = copy;
    while ((token = strsep (&here, ",;:")) != NULL) {
        struct pidof_omit *op;
        pid_t opid;

        if (strcmp (token, "%PPID") == 0)
            opid = getpid ();
        else
            opid = (pid_t) atoi (token);
        if (opid < 1) {
            pidof_warn ("illegal omit pid value (%s)!\n", token);
            continue;
        }
        op = (struct pidof_omit *) malloc (sizeof *op);
        if (op == NULL) {
            free (copy);
            pidof_warn ("out of memory");
            return -1;
        }
        op->pid = opid;
        op->next = *omit;
        *omit = op;
    }
    free (copy);
    return 0;
}

int
pidof_builtin (WORD_LIST *list)
{
    WORD_LIST *w;
    char **argv = NULL;
    struct pidof_proc *procs = NULL;
    struct pidof_omit *omit = NULL;
    struct stat self_root;
    int save_optind, save_opterr, save_optopt;
    char *save_optarg;
    int argc = 1;
    int opt, flags = 0;
    int scripts_too = 0;
    int list_zombies = 0;
    int chroot_check = 0;
    int first = 1;
    int ret = EXECUTION_FAILURE;
    int noperands, i;
    char sep = ' ';
    char *netfs;
    char self_path[64];

    for (w = list; w != NULL; w = w->next)
        argc++;
    argv = (char **) malloc (((size_t) argc + 1) * sizeof *argv);
    if (argv == NULL) {
        pidof_warn ("out of memory");
        return EXECUTION_FAILURE;
    }
    argv[0] = (char *) "pidof";
    i = 1;
    for (w = list; w != NULL; w = w->next)
        argv[i++] = w->word->word;
    argv[i] = NULL;

    save_optind = optind;
    save_opterr = opterr;
    save_optopt = optopt;
    save_optarg = optarg;
    optind = 0;
    opterr = 0;

    netfs = getenv ("PIDOF_NETFS");
    if (netfs != NULL && strcmp (netfs, "no") != 0)
        flags |= PIDOF_NETFS;

    while ((opt = getopt (argc, argv, "qhco:d:sxzn")) != -1) {
        switch (opt) {
        case '?':
            pidof_warn ("invalid options on command line!\n");
            goto done;
        case 'c':
            if (geteuid () == 0)
                chroot_check = 1;
            break;
        case 'h':
            pidof_usage ();
            ret = EXECUTION_SUCCESS;
            goto done;
        case 'd':
            sep = optarg[0];
            break;
        case 'o':
            if (pidof_add_omit (&omit, optarg) < 0)
                goto done;
            flags |= PIDOF_OMIT;
            break;
        case 'q':
            flags |= PIDOF_QUIET;
            break;
        case 's':
            flags |= PIDOF_SINGLE;
            break;
        case 'x':
            scripts_too = 1;
            break;
        case 'z':
            list_zombies = 1;
            break;
        case 'n':
            flags |= PIDOF_NETFS;
            break;
        default:
            break;
        }
    }

    if (chroot_check) {
        snprintf (self_path, sizeof self_path, "/proc/%d/root", (int) getpid ());
        if (stat (self_path, &self_root) < 0) {
            pidof_warn ("stat failed for %s!\n", self_path);
            goto done;
        }
    }

    if (pidof_readproc (list_zombies, &procs) < 0)
        goto done;

    noperands = argc - optind;
    for (i = 0; i < noperands; i++) {
        struct pidof_proc **matches = NULL;
        size_t nmatch = 0;
        size_t m;
        int spid = 0;

        if (pidof_collect (procs, argv[optind + i], scripts_too,
                           &matches, &nmatch) < 0) {
            free (matches);
            goto done;
        }
        for (m = 0; m < nmatch; m++) {
            struct pidof_proc *p = matches[m];

            if ((flags & PIDOF_OMIT) && omit != NULL
                && pidof_is_omitted (omit, p->pid))
                continue;
            /* Consumed before the root check, and reset for each name. */
            if (flags & PIDOF_SINGLE) {
                if (spid)
                    continue;
                spid = 1;
            }
            if (chroot_check) {
                struct stat st2;
                char root_path[64];

                snprintf (root_path, sizeof root_path, "/proc/%d/root",
                          (int) p->pid);
                if (stat (root_path, &st2) < 0
                    || self_root.st_dev != st2.st_dev
                    || self_root.st_ino != st2.st_ino)
                    continue;
            }
            if ((flags & PIDOF_QUIET) == 0) {
                if (!first)
                    printf ("%c", sep);
                printf ("%d", (int) p->pid);
            }
            first = 0;
        }
        free (matches);
    }

    if (!first && (flags & PIDOF_QUIET) == 0)
        printf ("\n");
    ret = first ? EXECUTION_FAILURE : EXECUTION_SUCCESS;

done:
    optind = save_optind;
    opterr = save_opterr;
    optopt = save_optopt;
    optarg = save_optarg;
    pidof_free_list (procs);
    pidof_free_omit (omit);
    free (argv);
    return ret;
}

char *pidof_doc[] = {
    "Find process IDs by name (sysvinit-utils pidof).",
    "",
    "    pidof [-c] [-d sep] [-h] [-n] [-o pid] [-q] [-s] [-x] [-z] name...",
    "",
    "    -c   same root directory; ignored unless the effective user is root",
    "    -d   separator between PIDs (the first character only)",
    "    -h   print help and succeed",
    "    -n   accepted; does not change which PIDs match",
    "    -o   omit PIDs (comma, semicolon, or colon) and %PPID",
    "    -q   do not print PIDs; the status still reports whether any matched",
    "    -s   print one PID for each name",
    "    -x   also match a script name in the arguments",
    "    -z   include zombie processes",
    "",
    "Returns 0 when any PID is listed, and 1 otherwise.",
    (char *) NULL
};

struct builtin bashpidof_struct = {
    "bashpidof",
    pidof_builtin,
    BUILTIN_ENABLED,
    pidof_doc,
    "pidof [-c] [-d sep] [-h] [-n] [-o pid] [-q] [-s] [-x] [-z] name...",
    0
};
