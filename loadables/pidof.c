/* bashpidof.c — pidof(1) via /proc walking.
 *
 *   bashpidof [-s] [-q] [-c] [-x] [-o PID[,PID...]] [-S SEP] CMD [CMD...]
 *
 *   -s   single-shot: print only the first matching PID and exit
 *   -q   quiet: suppress output, return status only
 *   -c   check root: only match processes with this shell's root
 *   -x   also match shell scripts by argv[1]
 *   -o   omit PID(s) from output; accepts comma/semicolon/colon lists and %PPID
 *   -S   separator between PIDs (-d is a sysvinit-compatible alias)
 *
 * Walks /proc process records; if CMD matches argv[0], the executable,
 * or (with -x) argv[1] for script interpreters, the PID joins
 * the output. Returns 0 if any PID found, 1 otherwise.
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
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>

#include "loadables.h"

typedef struct {
    pid_t pids[64];
    size_t len;
} bp_omit_list;

static int
bp_read_comm (int pid, char *out, size_t cap)
{
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/comm", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read (fd, out, cap - 1);
    close (fd);
    if (n <= 0) return -1;
    out[n] = '\0';
    /* Strip trailing newline. */
    if (n > 0 && out[n - 1] == '\n') out[n - 1] = '\0';
    return 0;
}

static int
bp_read_proc_link (int pid, const char *name, char *out, size_t cap)
{
    char path[64];
    ssize_t n;

    snprintf (path, sizeof path, "/proc/%d/%s", pid, name);
    n = readlink (path, out, cap - 1);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

static int
bp_read_cmdline (int pid, char *out, size_t cap)
{
    char path[64];
    ssize_t n;
    int fd;

    snprintf (path, sizeof path, "/proc/%d/cmdline", pid);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read (fd, out, cap);
    close (fd);
    if (n <= 0)
        return -1;
    if ((size_t)n < cap)
        out[n] = '\0';
    else {
        out[cap - 1] = '\0';
        n = (ssize_t)cap - 1; /* Do not treat a truncated argument as complete. */
    }
    return (int)n;
}

static const char *
bp_basename (const char *s)
{
    const char *base = strrchr (s, '/');
    return base ? base + 1 : s;
}

static int
bp_match_cmdline (int pid, const char *comm, const char *want, const char *base, int scripts_too)
{
    char cmdline[1024], exe[1024];
    char *arg0, *arg1;
    const char *arg0base;
    int n;

    n = bp_read_cmdline (pid, cmdline, sizeof cmdline);
    if (n <= 0 || cmdline[0] == '\0')
        return 0;

    /* Executable identity remains usable even if argv[0] is truncated. */
    if (bp_read_proc_link (pid, "exe", exe, sizeof exe) == 0 &&
        (!strcmp (want, exe) || !strcmp (want, bp_basename (exe))))
        return 1;
    if (memchr (cmdline, '\0', (size_t)n) == NULL)
        return 0; /* argv[0] is incomplete, so do not match its prefix. */

    arg0 = cmdline;
    if (arg0[0] == '-')
        arg0++;
    arg0base = bp_basename (arg0);
    if (!strcmp (arg0base, want) || !strcmp (arg0base, base) ||
        !strcmp (arg0, want) || !strcmp (arg0, base))
        return 1;

    /* procps uses comm for processes that changed their argv title. */
    if (strchr (arg0, ' ') && !strcmp (want, comm))
        return 1;

    if (!scripts_too)
        return 0;

    arg1 = memchr (cmdline, '\0', (size_t)n);
    if (arg1 != NULL && ++arg1 < cmdline + n && *arg1 != '\0' &&
        memchr (arg1, '\0', (size_t)(cmdline + n - arg1)) != NULL) {
        const char *arg1base = bp_basename (arg1);
        size_t len = strlen (arg1base);
        size_t commlen = len < 15 ? len : 15;

        /* Linux task names hold at most 15 bytes, excluding the NUL. */
        if (strlen (comm) == commlen && !strncmp (comm, arg1base, commlen) &&
            (!strcmp (arg1base, base) || !strcmp (arg1, want)))
            return 1;
    }

    return 0;
}

static int
bp_is_omitted (const bp_omit_list *omit, pid_t pid)
{
    for (size_t i = 0; i < omit->len; i++)
        if (omit->pids[i] == pid)
            return 1;
    return 0;
}

static int
bp_add_omit_pid (bp_omit_list *omit, const char *s)
{
    char *end = NULL;
    unsigned long v;
    pid_t pid;

    if (!strcmp (s, "%PPID")) {
        /* The external pidof would be a child of the invoking shell. */
        pid = getpid ();
    } else {
        const char *p;

        for (p = s; *p; p++)
            if (*p < '0' || *p > '9')
                return -1;
        errno = 0;
        v = strtoul (s, &end, 10);
        if (errno != 0 || end == s || *end != '\0' || v == 0 || v > INT_MAX)
            return -1;
        pid = (pid_t)v;
    }

    if (omit->len >= sizeof omit->pids / sizeof omit->pids[0])
        return -1;
    omit->pids[omit->len++] = pid;
    return 0;
}

static int
bp_parse_omit (bp_omit_list *omit, const char *arg)
{
    char *copy, *tok, *saveptr = NULL;
    int rc = 0;

    if (arg == NULL || *arg == '\0')
        return -1;

    /* strtok_r skips empty fields; reject them before tokenizing. */
    if (strchr (",;:", *arg) || strchr (",;:", arg[strlen (arg) - 1]))
        return -1;
    for (const char *p = arg; *p; p++)
        if (strchr (",;:", *p) && p[1] && strchr (",;:", p[1]))
            return -1;

    copy = strdup (arg);
    if (copy == NULL)
        return -1;

    for (tok = strtok_r (copy, ",;:", &saveptr);
         tok != NULL;
         tok = strtok_r (NULL, ",;:", &saveptr)) {
        if (bp_add_omit_pid (omit, tok) < 0) {
            rc = -1;
            break;
        }
    }

    free (copy);
    return rc;
}

int
pidof_builtin (WORD_LIST *list)
{
    int single = 0;
    int quiet = 0;
    int check_root = 0;
    int scripts_too = 0;
    const char *separator = " ";
    char self_root[1024];
    bp_omit_list omit = { { 0 }, 0 };

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("bashpidof 1.0 (bash-loadable, procps-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--single-shot")) { single = 1; list = list->next; continue; }
        if (!strcmp (w, "--quiet")) { quiet = 1; single = 1; list = list->next; continue; }
        if (!strcmp (w, "--check-root")) { check_root = 1; list = list->next; continue; }
        if (!strcmp (w, "--omit-pid")) {
            if (list->next == NULL) {
                builtin_error ("%s requires a PID list", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bp_parse_omit (&omit, list->word->word) < 0) {
                builtin_error ("invalid omit PID list: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--omit-pid=", 11)) {
            if (bp_parse_omit (&omit, w + 11) < 0) {
                builtin_error ("invalid omit PID list: %s", w + 11);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--separator")) {
            if (list->next == NULL) {
                builtin_error ("%s requires a separator", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            separator = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--separator=", 12)) {
            separator = w + 12;
            list = list->next;
            continue;
        }
        if (w[0] == '-' && w[1] != '-' && w[1] != '\0') {
            for (size_t i = 1; w[i] != '\0'; i++) {
                switch (w[i]) {
                    case 's':
                        single = 1;
                        break;
                    case 'q':
                        quiet = 1;
                        single = 1;
                        break;
                    case 'c':
                        check_root = 1;
                        break;
                    case 'x':
                        scripts_too = 1;
                        break;
                    case 'o':
                    {
                        const char *arg = w[i + 1] ? w + i + 1 : NULL;
                        if (arg == NULL) {
                            if (list->next == NULL) {
                                builtin_error ("-%c requires a PID list", w[i]);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                            list = list->next;
                            arg = list->word->word;
                        }
                        if (bp_parse_omit (&omit, arg) < 0) {
                            builtin_error ("invalid omit PID list: %s", arg);
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        i = strlen (w) - 1;
                        break;
                    }
                    case 'S':
                    case 'd':
                    {
                        const char *arg = w[i + 1] ? w + i + 1 : NULL;
                        if (arg == NULL) {
                            if (list->next == NULL) {
                                builtin_error ("-%c requires a separator", w[i]);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                            list = list->next;
                            arg = list->word->word;
                        }
                        separator = arg;
                        i = strlen (w) - 1;
                        break;
                    }
                    default:
                        builtin_error ("unknown flag: -%c", w[i]);
                        builtin_usage ();
                        return EX_USAGE;
                }
            }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }
    if (!list) {
        builtin_usage ();
        return EX_USAGE;
    }

    if (check_root && bp_read_proc_link ((int)getpid (), "root", self_root, sizeof self_root) < 0) {
        builtin_error ("readlink /proc/%d/root: %s", (int)getpid (), strerror (errno));
        return EXECUTION_FAILURE;
    }

    DIR *d = opendir ("/proc");
    if (!d) { builtin_error ("opendir /proc: %s", strerror (errno)); return EXECUTION_FAILURE; }

    pid_t *matches = NULL;
    size_t found = 0, capacity = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        if (bp_is_omitted (&omit, (pid_t)pid)) continue;
        if (check_root) {
            char proc_root[1024];
            if (bp_read_proc_link (pid, "root", proc_root, sizeof proc_root) < 0)
                continue;
            if (strcmp (self_root, proc_root))
                continue;
        }
        char comm[64];
        if (bp_read_comm (pid, comm, sizeof comm) < 0) continue;
        for (WORD_LIST *p = list; p; p = p->next) {
            const char *want = p->word->word;
            const char *base = bp_basename (want);
            int match = bp_match_cmdline (pid, comm, want, base, scripts_too);

            if (match) {
                if (found == capacity) {
                    size_t next = capacity ? capacity * 2 : 64;
                    pid_t *grown;
                    if (next < capacity || next > (size_t)-1 / sizeof *matches ||
                        (grown = realloc (matches, next * sizeof *matches)) == NULL) {
                        free (matches);
                        closedir (d);
                        builtin_error ("cannot allocate process list");
                        return EXECUTION_FAILURE;
                    }
                    matches = grown;
                    capacity = next;
                }
                matches[found++] = (pid_t)pid;
                break;
            }
        }
    }
    closedir (d);
    if (!quiet && found > 0) {
        size_t i = found;
        int first_print = 1;
        while (i > 0) {
            if (!first_print) fputs (separator, stdout);
            printf ("%ld", (long)matches[--i]);
            first_print = 0;
            if (single) break;
        }
        putchar ('\n');
    }
    free (matches);
    return found > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *pidof_doc[] = {
    "Find PIDs by command name (via /proc/PID/comm).",
    "",
    "    bashpidof [-s] [-q] [-c] [-x] [-o PID[,PID...]] [-S SEP] CMD [CMD...]",
    "",
    "    -s   stop at the first match (single-shot)",
    "    -q   quiet: suppress output and return status only",
    "    -c   only match processes with this shell's root",
    "    -x   also match shell scripts by argv[1]",
    "    -o   omit PID(s); accepts comma/semicolon/colon lists and %PPID",
    "    -S   separator between PIDs (-d is an alias)",
    "    --version   print version information and exit",
    "",
    "Walks /proc and matches argv[0], executable, or changed-title comm.",
    "With -x, argv[1] is also checked when its basename matches comm.",
    "Returns 0 if any PID",
    "is found, 1 otherwise — usable in `if bashpidof daemon; then ...`.",
    (char *)NULL
};

struct builtin bashpidof_struct = {
    "bashpidof",
    pidof_builtin,
    BUILTIN_ENABLED,
    pidof_doc,
    "bashpidof [-s] [-q] [-c] [-x] [-o PID[,PID...]] [-S SEP] CMD [CMD...]",
    0
};
