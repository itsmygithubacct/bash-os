/* SPDX-License-Identifier: MIT */
/* lsof.c — list open file descriptors via /proc/PID/fd.
 *
 *   lsof [-a] [-p PID] [-u USER] [PID...]
 *
 *   -a        intersect selections (default is union)
 *   -p PID    select one PID (repeatable)
 *   -u USER   restrict to processes owned by USER (name or uid)
 *   PID...    bare PIDs are equivalent to -p PID PID...
 *
 * Output (POSIX-ish columns):
 *   COMMAND   PID    USER  FD  TYPE  PATH
 *
 * TYPE column heuristics:
 *   REG       regular file
 *   DIR       directory
 *   CHR/BLK   char / block device
 *   FIFO      named pipe
 *   SOCK      socket (stat shows sockfs)
 *   sock      anonymous (`socket:[N]`)
 *   pipe      anonymous pipe
 *   IPv4/IPv6 inferred from `socket:[N]` + /proc/net/{tcp,udp} match (skipped at v1)
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
#include <inttypes.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>

#include "loadables.h"

/* Read the real UID, independently of its display name.  A failed read must
   never match a user selection. */
static int
bl_uid_for_pid (int pid, uid_t *uid)
{
    char path[64], line[256];
    snprintf (path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen (path, "r");
    if (!f) return 0;
    int found = 0;
    while (fgets (line, sizeof line, f)) {
        uintmax_t n;
        if (strncmp (line, "Uid:", 4) == 0 &&
            sscanf (line + 4, "%ju", &n) == 1 && (uintmax_t) (uid_t) n == n) {
            *uid = (uid_t) n;
            found = 1;
            break;
        }
    }
    fclose (f);
    return found;
}

static const char *
bl_user_for_uid (uid_t uid, int known)
{
    static char buf[64];
    if (!known) return "?";
    struct passwd *pw = getpwuid (uid);
    if (pw) snprintf (buf, sizeof buf, "%s", pw->pw_name);
    else snprintf (buf, sizeof buf, "%ju", (uintmax_t) uid);
    return buf;
}

static const char *
bl_comm_for_pid (int pid)
{
    static char comm[64];
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/comm", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "?";
    ssize_t n = read (fd, comm, sizeof comm - 1);
    close (fd);
    if (n <= 0) return "?";
    comm[n] = '\0';
    if (n > 0 && comm[n - 1] == '\n') comm[n - 1] = '\0';
    return comm;
}

static const char *
bl_classify (const char *target, const struct stat *st)
{
    if (target[0] != '/') {
        /* Anonymous: socket:[N], pipe:[N], anon_inode:[N], ... */
        if (!strncmp (target, "socket:", 7)) return "sock";
        if (!strncmp (target, "pipe:",   5)) return "pipe";
        if (!strncmp (target, "anon_inode:", 11)) return "anon";
        return "OTHER";
    }
    if (S_ISREG (st->st_mode))  return "REG";
    if (S_ISDIR (st->st_mode))  return "DIR";
    if (S_ISCHR (st->st_mode))  return "CHR";
    if (S_ISBLK (st->st_mode))  return "BLK";
    if (S_ISFIFO (st->st_mode)) return "FIFO";
    if (S_ISSOCK (st->st_mode)) return "SOCK";
    if (S_ISLNK (st->st_mode))  return "LNK";
    return "OTHER";
}

static int
bl_dump_pid (int pid, uid_t uid, int uid_known)
{
    const char *user = bl_user_for_uid (uid, uid_known);
    const char *comm = bl_comm_for_pid (pid);

    char fdpath[64];
    snprintf (fdpath, sizeof fdpath, "/proc/%d/fd", pid);
    DIR *d = opendir (fdpath);
    if (!d) return 0;   /* Permission denied is normal for other-user PIDs. */
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] == '.') continue;
        char linkbuf[1024];
        char fullpath[128];
        snprintf (fullpath, sizeof fullpath, "/proc/%d/fd/%s", pid, de->d_name);
        ssize_t n = readlink (fullpath, linkbuf, sizeof linkbuf - 1);
        if (n < 0) continue;
        linkbuf[n] = '\0';
        struct stat st;
        if (stat (fullpath, &st) < 0) memset (&st, 0, sizeof st);
        const char *type = bl_classify (linkbuf, &st);
        printf ("%-12s %5d %-8s %3s %-5s %s\n",
                comm, pid, user, de->d_name, type, linkbuf);
    }
    closedir (d);
    return 0;
}

static int
bl_resolve_user (const char *s, uid_t *uid)
{
    const unsigned char *p = (const unsigned char *) s;
    if (!*p) return 0;
    while (isdigit (*p)) p++;
    if (!*p) {
        char *end;
        errno = 0;
        uintmax_t n = strtoumax (s, &end, 10);
        if (errno || *end || (uintmax_t) (uid_t) n != n) return 0;
        *uid = (uid_t) n;
        return 1;
    }
    struct passwd *pw = getpwnam (s);
    if (!pw) return 0;
    *uid = pw->pw_uid;
    return 1;
}

static void
bl_select_pid (int pid, const int *pids, int n_pids, int have_user,
               uid_t wanted_uid, int and_selection)
{
    uid_t uid = 0;
    int known = bl_uid_for_pid (pid, &uid);
    int pid_match = 0;
    for (int i = 0; i < n_pids; i++)
        if (pids[i] == pid) { pid_match = 1; break; }
    int user_match = known && uid == wanted_uid;
    int selected = !n_pids && !have_user;
    if (n_pids && have_user)
        selected = and_selection ? pid_match && user_match : pid_match || user_match;
    else if (n_pids) selected = pid_match;
    else if (have_user) selected = user_match;
    if (selected) bl_dump_pid (pid, uid, known);
}

int
lsof_builtin (WORD_LIST *list)
{
    int explicit_pids[256];
    int n_pids = 0;
    uid_t want_uid = 0;
    int have_user = 0, and_selection = 0;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-v")) {
            puts ("lsof 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-a")) {
            and_selection = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-p")) {
            if (!list->next) {
                builtin_error ("-p needs PID");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            if (n_pids >= (int) (sizeof explicit_pids / sizeof explicit_pids[0])) {
                builtin_error ("too many -p PIDs");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            explicit_pids[n_pids++] = atoi (list->word->word);
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-u")) {
            if (!list->next) {
                builtin_error ("-u needs USER");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            if (!bl_resolve_user (list->word->word, &want_uid)) {
                builtin_error ("unknown user: %s", list->word->word);
                return EXECUTION_FAILURE;
            }
            have_user = 1;
            list = list->next;
            continue;
        }
        if (w[0] >= '0' && w[0] <= '9') {
            if (n_pids >= (int) (sizeof explicit_pids / sizeof explicit_pids[0])) {
                builtin_error ("too many PIDs");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            explicit_pids[n_pids++] = atoi (w);
            list = list->next;
            continue;
        }
        builtin_error ("unknown arg: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }

    printf ("%-12s %5s %-8s %3s %-5s %s\n",
            "COMMAND", "PID", "USER", "FD", "TYPE", "PATH");

    if (n_pids > 0 && (!have_user || and_selection)) {
        for (int i = 0; i < n_pids; i++) {
            bl_select_pid (explicit_pids[i], explicit_pids, n_pids, have_user,
                           want_uid, and_selection);
        }
        return EXECUTION_SUCCESS;
    }
    DIR *d = opendir ("/proc");
    if (!d) { builtin_error ("opendir /proc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        bl_select_pid (pid, explicit_pids, n_pids, have_user,
                       want_uid, and_selection);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

char *lsof_doc[] = {
    "List open file descriptors via /proc/PID/fd.",
    "",
    "    lsof [-a] [-p PID]... [-u USER] [PID...]",
    "",
    "    -a        intersect selections (default is union)",
    "    -p PID    select one PID (repeatable)",
    "    -u USER   restrict to one user (name or uid)",
    "    PID...    bare numeric PIDs equivalent to -p PID PID...",
    "    --help    print usage information and exit",
    "    -v, --version",
    "              print version information and exit",
    "",
    "Output columns: COMMAND PID USER FD TYPE PATH.",
    "TYPE: REG / DIR / CHR / BLK / FIFO / SOCK / LNK for fs entries;",
    "sock / pipe / anon for kernel anonymous fds.",
    (char *)NULL
};

struct builtin lsof_struct = {
    "lsof",
    lsof_builtin,
    BUILTIN_ENABLED,
    lsof_doc,
    "lsof [-a] [-p PID]... [-u USER] [PID...]",
    0
};
