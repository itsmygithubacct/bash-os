/* bashkillall.c — killall(1) with psmisc option and signal parsing.
 *
 * Exact comm matching, long-name argv[0] fallback, -f, and the fatal
 * status when /proc cannot be opened stay in bp_dispatch. Options psmisc
 * implements and bp_dispatch rejects (-l -q -w -I -r -g -y -o -v), signal
 * 0, and `-usr1` (a -u user, not SIGUSR1) are handled here. Usage errors
 * return 1, as psmisc's usage() does.
 *
 * Numeric -u is still accepted: the uid-filter contract addresses a
 * numeric uid, which psmisc's getpwnam-only lookup would reject.
 *
 * --- LICENSE --- MIT, same boilerplate as bashpgrep.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "loadables.h"

#define BP_MODE_KILLALL 2

extern int bp_dispatch (WORD_LIST *list, int mode);

/* Same set cpp -dM produces for psmisc signames.h on glibc x86_64,
   in numeric order, without three-digit realtime aliases. */
static const struct { int num; const char *name; } ka_sigs[] = {
    { 1, "HUP" },    { 2, "INT" },    { 3, "QUIT" },   { 4, "ILL" },
    { 5, "TRAP" },   { 6, "ABRT" },   { 7, "BUS" },    { 8, "FPE" },
    { 9, "KILL" },   { 10, "USR1" },  { 11, "SEGV" },  { 12, "USR2" },
    { 13, "PIPE" },  { 14, "ALRM" },  { 15, "TERM" },  { 16, "STKFLT" },
    { 17, "CHLD" },  { 18, "CONT" },  { 19, "STOP" },  { 20, "TSTP" },
    { 21, "TTIN" },  { 22, "TTOU" },  { 23, "URG" },   { 24, "XCPU" },
    { 25, "XFSZ" },  { 26, "VTALRM" },{ 27, "PROF" },  { 28, "WINCH" },
    { 29, "POLL" },  { 30, "PWR" },   { 31, "SYS" },
    { 0, NULL }
};

static void
ka_list_signals (void)
{
    int col = 0;
    for (int i = 0; ka_sigs[i].name; i++) {
        size_t n = strlen (ka_sigs[i].name);
        if (col + (int) n + 1 > 80) {
            putchar ('\n');
            col = 0;
        }
        printf ("%s%s", col ? " " : "", ka_sigs[i].name);
        col += (int) n + 1;
    }
    putchar ('\n');
}

static int
ka_usage (void)
{
    fprintf (stderr, "Usage: killall [OPTION]... [--] NAME...\n");
    return EXECUTION_FAILURE;
}

static int
ka_unknown_signal (const char *spec)
{
    fprintf (stderr, "%s: unknown signal; killall -l lists signals.\n", spec);
    return -1;
}

static int
ka_parse_signal (const char *spec, int *out)
{
    if (!spec || !*spec)
        return ka_unknown_signal (spec ? spec : "");
    if (isdigit ((unsigned char) spec[0])) {
        char *end = NULL;
        errno = 0;
        long v = strtol (spec, &end, 10);
        if (errno || end == spec || *end || v < 0 || v > INT_MAX)
            return ka_unknown_signal (spec);
        *out = (int) v;
        return 0;
    }
    if (strncmp (spec, "SIG", 3) == 0)
        spec += 3;
    for (int i = 0; ka_sigs[i].name; i++)
        if (!strcmp (spec, ka_sigs[i].name)) {
            *out = ka_sigs[i].num;
            return 0;
        }
    return ka_unknown_signal (spec);
}

/* Seconds, or -1. Units are psmisc's s/m/h/d/w/M/y. */
static long
ka_parse_time (const char *age)
{
    char *unit = NULL;
    errno = 0;
    long num = strtol (age, &unit, 10);
    if (errno || age == unit || !unit || !*unit)
        return -1;
    switch (unit[0]) {
    case 's': return num;
    case 'm': return num * 60;
    case 'h': return num * 60 * 60;
    case 'd': return num * 60 * 60 * 24;
    case 'w': return num * 60 * 60 * 24 * 7;
    case 'M': return num * 60 * 60 * 24 * 7 * 4;
    case 'y': return num * 60 * 60 * 24 * 7 * 4 * 12;
    default:  return -1;
    }
}

static int
ka_resolve_user (const char *spec, uid_t *out)
{
    int alldigit = spec[0] != '\0';
    for (const char *q = spec; *q && alldigit; q++)
        if (!isdigit ((unsigned char) *q))
            alldigit = 0;
    if (alldigit) {
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul (spec, &end, 10);
        if (errno || end == spec || *end || v > UINT_MAX)
            return -1;
        *out = (uid_t) v;
        return 0;
    }
    struct passwd *pw = getpwnam (spec);
    if (!pw) {
        fprintf (stderr, "Cannot find user %s\n", spec);
        return -1;
    }
    *out = pw->pw_uid;
    return 0;
}

static int
ka_read_comm (int pid, char *buf, size_t sz)
{
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/comm", pid);
    FILE *fp = fopen (path, "r");
    if (!fp)
        return -1;
    if (!fgets (buf, (int) sz, fp)) {
        fclose (fp);
        return -1;
    }
    fclose (fp);
    size_t n = strlen (buf);
    if (n && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    return 0;
}

static int
ka_read_uid (int pid, uid_t *out)
{
    char path[64], line[256];
    snprintf (path, sizeof path, "/proc/%d/status", pid);
    FILE *fp = fopen (path, "r");
    if (!fp)
        return -1;
    int rc = -1;
    while (fgets (line, sizeof line, fp)) {
        if (strncmp (line, "Uid:", 4) == 0) {
            unsigned long v = 0;
            if (sscanf (line + 4, "%lu", &v) == 1) {
                *out = (uid_t) v;
                rc = 0;
            }
            break;
        }
    }
    fclose (fp);
    return rc;
}

static int
ka_read_age (int pid, double *age)
{
    FILE *fp = fopen ("/proc/uptime", "r");
    double up = 0;
    if (!fp || fscanf (fp, "%lf", &up) != 1) {
        if (fp) fclose (fp);
        return -1;
    }
    fclose (fp);
    char path[64], statbuf[1024];
    snprintf (path, sizeof path, "/proc/%d/stat", pid);
    fp = fopen (path, "r");
    if (!fp)
        return -1;
    if (!fgets (statbuf, sizeof statbuf, fp)) {
        fclose (fp);
        return -1;
    }
    fclose (fp);
    char *rp = strrchr (statbuf, ')');
    if (!rp)
        return -1;
    /* field 22 is starttime; field 3 (state) is the first token after ") ". */
    unsigned long long start = 0;
    int n = 0;
    char *p = rp + 2;
    for (int field = 3; field <= 22 && p && *p; field++) {
        if (field == 22) {
            errno = 0;
            start = strtoull (p, NULL, 10);
            n = errno ? 0 : 1;
            break;
        }
        p = strchr (p, ' ');
        if (p) p++;
    }
    if (!n)
        return -1;
    long ticks = sysconf (_SC_CLK_TCK);
    if (ticks <= 0)
        ticks = 100;
    double seconds = up - (double) start / (double) ticks;
    if (seconds < 0)
        seconds = 0;
    *age = seconds;
    return 0;
}

static int
ka_walk (int sig, char **names, int nnames, int ignore_case, int regexp,
         int process_group, int quiet, int verbose, int wait_dead,
         int filter_uid, uid_t want_uid, long younger, long older)
{
    regex_t *regs = NULL;
    if (regexp && nnames) {
        regs = calloc ((size_t) nnames, sizeof *regs);
        if (!regs)
            return 3;
        int flag = REG_EXTENDED | REG_NOSUB | (ignore_case ? REG_ICASE : 0);
        for (int i = 0; i < nnames; i++) {
            if (regcomp (&regs[i], names[i], flag) != 0) {
                fprintf (stderr, "killall: Bad regular expression: %s\n", names[i]);
                for (int j = 0; j < i; j++)
                    regfree (&regs[j]);
                free (regs);
                return EXECUTION_FAILURE;
            }
        }
    }
    DIR *d = opendir ("/proc");
    if (!d) {
        if (regs) {
            for (int i = 0; i < nnames; i++)
                regfree (&regs[i]);
            free (regs);
        }
        return 3;
    }
    unsigned char *found = calloc ((size_t) (nnames > 0 ? nnames : 1), 1);
    int *killed = NULL;
    int nkilled = 0, kcap = 0;
    pid_t self = getpid ();
    struct dirent *de;
    while ((de = readdir (d))) {
        char *end = NULL;
        long lpid = strtol (de->d_name, &end, 10);
        if (lpid <= 0 || (end && *end) || lpid > INT_MAX)
            continue;
        int pid = (int) lpid;
        if (pid == (int) self || pid == (int) dollar_dollar_pid)
            continue;
        if (filter_uid) {
            uid_t uid;
            if (ka_read_uid (pid, &uid) < 0 || uid != want_uid)
                continue;
        }
        if (younger || older) {
            double age = 0;
            if (ka_read_age (pid, &age) < 0)
                continue;
            if (younger && age > (double) younger)
                continue;
            if (older && age < (double) older)
                continue;
        }
        char comm[64];
        if (ka_read_comm (pid, comm, sizeof comm) < 0)
            continue;
        int which = -1;
        for (int j = 0; j < nnames; j++) {
            int hit;
            if (regs)
                hit = regexec (&regs[j], comm, 0, NULL, 0) == 0;
            else if (ignore_case)
                hit = strcasecmp (comm, names[j]) == 0;
            else
                hit = strcmp (comm, names[j]) == 0;
            if (hit) { which = j; break; }
        }
        if (which < 0)
            continue;
        pid_t dest = pid;
        if (process_group) {
            dest = getpgid (pid);
            if (dest < 0)
                continue;
            int seen = 0;
            for (int k = 0; k < nkilled; k++)
                if (killed[k] == (int) dest)
                    seen = 1;
            if (seen)
                continue;
            dest = -dest;
        }
        if (kill (dest, sig) == 0) {
            if (which >= 0)
                found[which] = 1;
            if (verbose)
                fprintf (stderr, "Killed %s(%s%d) with signal %d\n",
                         comm, process_group ? "pgid " : "",
                         process_group ? (int) -dest : pid, sig);
            if (nkilled == kcap) {
                int next = kcap ? kcap * 2 : 8;
                int *grown = realloc (killed, (size_t) next * sizeof *killed);
                if (!grown)
                    break;
                killed = grown;
                kcap = next;
            }
            killed[nkilled++] = process_group ? (int) -dest : pid;
        } else if (errno != ESRCH) {
            fprintf (stderr, "%s(%d): %s\n", comm, pid, strerror (errno));
        }
    }
    closedir (d);
    if (regs) {
        for (int i = 0; i < nnames; i++)
            regfree (&regs[i]);
        free (regs);
    }
    if (!quiet) {
        for (int i = 0; i < nnames; i++)
            if (!found[i])
                fprintf (stderr, "%s: no process found\n", names[i]);
    }
    int ok = nnames > 0;
    for (int i = 0; i < nnames; i++)
        if (!found[i])
            ok = 0;
    free (found);
    while (wait_dead && nkilled > 0) {
        for (int i = 0; i < nkilled; ) {
            if (kill (killed[i], 0) < 0 && errno == ESRCH) {
                killed[i] = killed[--nkilled];
                continue;
            }
            i++;
        }
        if (nkilled)
            sleep (1);
    }
    free (killed);
    return ok ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static WORD_LIST *
ka_push (WORD_LIST **head, WORD_LIST **tail, const char *text)
{
    WORD_LIST *node = make_word_list (make_word (text), NULL);
    if (!*head)
        *head = node;
    else
        (*tail)->next = node;
    *tail = node;
    return node;
}

static int
ka_take_arg (WORD_LIST **list, const char **out)
{
    if (!*list || !(*list)->next || !(*list)->next->word)
        return -1;
    *list = (*list)->next;
    *out = (*list)->word->word;
    return 0;
}

int
killall_builtin (WORD_LIST *list)
{
    int sig = SIGTERM;
    int sig_set = 0;
    int quiet = 0, wait_dead = 0, ignore_case = 0, regexp = 0;
    int process_group = 0, verbose = 0, exact = 0, full = 0;
    int filter_uid = 0;
    uid_t want_uid = 0;
    long younger = 0, older = 0;
    const char *user_spec = NULL;

    while (list && list->word && list->word->word[0] == '-') {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) {
            list = list->next;
            break;
        }
        if (!strcmp (w, "-l") || !strcmp (w, "--list") || !strcmp (w, "--list-signals")) {
            ka_list_signals ();
            return sh_chkwrite (EXECUTION_SUCCESS);
        }
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) { quiet = 1; list = list->next; continue; }
        if (!strcmp (w, "-w") || !strcmp (w, "--wait")) { wait_dead = 1; list = list->next; continue; }
        if (!strcmp (w, "-I") || !strcmp (w, "--ignore-case")) { ignore_case = 1; list = list->next; continue; }
        if (!strcmp (w, "-r") || !strcmp (w, "--regexp")) { regexp = 1; list = list->next; continue; }
        if (!strcmp (w, "-g") || !strcmp (w, "--process-group")) { process_group = 1; list = list->next; continue; }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose") || !strcmp (w, "-verbose")) {
            verbose = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-ve")) { verbose = 1; exact = 1; list = list->next; continue; }
        if (!strcmp (w, "-e") || !strcmp (w, "--exact")) { exact = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--full")) { full = 1; list = list->next; continue; }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("killall (bash-loadable)");
            return sh_chkwrite (EXECUTION_SUCCESS);
        }
        if (!strcmp (w, "-y") || !strcmp (w, "--younger-than")
            || !strncmp (w, "--younger-than=", 15) || (w[1] == 'y' && w[2])) {
            const char *val = NULL;
            if (!strncmp (w, "--younger-than=", 15))
                val = w + 15;
            else if (w[0] == '-' && w[1] == 'y' && w[2])
                val = w + 2;
            else if (ka_take_arg (&list, &val) < 0)
                return ka_usage ();
            younger = ka_parse_time (val);
            if (younger <= 0)
                return ka_usage ();
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-o") || !strcmp (w, "--older-than")
            || !strncmp (w, "--older-than=", 13) || (w[1] == 'o' && w[2])) {
            const char *val = NULL;
            if (!strncmp (w, "--older-than=", 13))
                val = w + 13;
            else if (w[0] == '-' && w[1] == 'o' && w[2])
                val = w + 2;
            else if (ka_take_arg (&list, &val) < 0)
                return ka_usage ();
            older = ka_parse_time (val);
            if (older <= 0)
                return ka_usage ();
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s") || !strcmp (w, "--signal") || !strncmp (w, "--signal=", 9)
            || (!strncmp (w, "-s", 2) && w[2])) {
            const char *val = NULL;
            if (!strncmp (w, "--signal=", 9))
                val = w + 9;
            else if (!strncmp (w, "-s", 2) && w[2])
                val = w + 2;
            else if (ka_take_arg (&list, &val) < 0)
                return ka_usage ();
            if (ka_parse_signal (val, &sig) < 0)
                return EXECUTION_FAILURE;
            sig_set = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-u") || !strcmp (w, "--user") || !strncmp (w, "--user=", 7)
            || (w[1] == 'u' && w[2])) {
            /* -usr1 is -u with argument sr1, not SIGUSR1. */
            const char *val = NULL;
            if (!strncmp (w, "--user=", 7))
                val = w + 7;
            else if (w[1] == 'u' && w[2])
                val = w + 2;
            else if (ka_take_arg (&list, &val) < 0)
                return ka_usage ();
            if (ka_resolve_user (val, &want_uid) < 0)
                return EXECUTION_FAILURE;
            filter_uid = 1;
            user_spec = val;
            list = list->next;
            continue;
        }
        if (w[1] >= 'A' && w[1] <= 'Z') {
            if (ka_parse_signal (w + 1, &sig) < 0)
                return EXECUTION_FAILURE;
            sig_set = 1;
            list = list->next;
            continue;
        }
        if (w[1] >= '0' && w[1] <= '9') {
            if (ka_parse_signal (w + 1, &sig) < 0)
                return EXECUTION_FAILURE;
            sig_set = 1;
            list = list->next;
            continue;
        }
        return ka_usage ();
    }

    int nnames = 0;
    for (WORD_LIST *p = list; p && p->word && p->word->word; p = p->next)
        nnames++;
    if (nnames == 0)
        return ka_usage ();

    int special = quiet || wait_dead || ignore_case || regexp || process_group
        || verbose || younger || older || (sig_set && sig == 0);
    if (special || filter_uid) {
        /* -u on the shared walker is fine, but signal 0 and the psmisc
           flags are not. Any of those takes the local walker, which also
           applies a uid filter when one was given. */
        if (!special && filter_uid)
            goto dispatch;
        char **names = calloc ((size_t) nnames, sizeof *names);
        if (!names)
            return 3;
        int i = 0;
        for (WORD_LIST *p = list; p && p->word && p->word->word; p = p->next)
            names[i++] = p->word->word;
        int rc = ka_walk (sig, names, nnames, ignore_case, regexp, process_group,
                          quiet, verbose, wait_dead, filter_uid, want_uid,
                          younger, older);
        free (names);
        (void) exact;
        (void) full;
        return sh_chkwrite (rc);
    }

dispatch:
    {
        WORD_LIST *head = NULL, *tail = NULL;
        char sigbuf[32];
        if (sig_set && sig != SIGTERM) {
            snprintf (sigbuf, sizeof sigbuf, "%d", sig);
            ka_push (&head, &tail, "-s");
            ka_push (&head, &tail, sigbuf);
        }
        if (full)
            ka_push (&head, &tail, "-f");
        if (exact)
            ka_push (&head, &tail, "-e");
        if (filter_uid && user_spec) {
            ka_push (&head, &tail, "-u");
            ka_push (&head, &tail, user_spec);
        }
        for (WORD_LIST *p = list; p && p->word && p->word->word; p = p->next)
            ka_push (&head, &tail, p->word->word);
        int rc = bp_dispatch (head, BP_MODE_KILLALL);
        dispose_words (head);
        if (rc == EX_USAGE)
            rc = EXECUTION_FAILURE;
        return sh_chkwrite (rc);
    }
}

char *killall_doc[] = {
    "Signal every process whose comm equals NAME, the way psmisc killall does.",
    "",
    "    killall [-SIGNAL | -s SIGNAL | --signal SIGNAL] [-e] [-f] [-u USER] NAME...",
    "    killall [-q] [-w] [-v] [-I] [-r] [-g] [-y TIME] [-o TIME] NAME...",
    "    killall -l",
    "",
    "    -SIGNAL    uppercase name (HUP, SIGUSR1) or a number. -usr1 is -u sr1.",
    "    -s, --signal   signal name or number, including 0. Names are case-sensitive.",
    "    -e, --exact    ignored; matching is already exact",
    "    -q, --quiet    do not complain when a NAME matches nothing",
    "    -w, --wait     wait until the signalled process is gone",
    "    -v, --verbose  report each signal that was sent",
    "    -I, --ignore-case",
    "    -r, --regexp   NAME is an extended regular expression",
    "    -g, --process-group",
    "               signal the process group of each match",
    "    -y, --younger-than TIME",
    "    -o, --older-than TIME",
    "               TIME is a number plus s, m, h, d, w, M, or y",
    "    -u, --user USER",
    "               real uid. A numeric USER is accepted.",
    "    -f         match the full command line (candidate extension)",
    "",
    "Self is never signalled. Returns 0 if every NAME was signalled, 1 if",
    "none matched or the usage was wrong, 3 if /proc cannot be opened.",
    (char *) NULL
};

struct builtin bashkillall_struct = {
    "bashkillall",
    killall_builtin,
    BUILTIN_ENABLED,
    killall_doc,
    "bashkillall [OPTION]... NAME...",
    0
};
