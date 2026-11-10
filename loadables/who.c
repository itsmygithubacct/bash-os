/* SPDX-License-Identifier: MIT */
/* who.c — POSIX/GNU-style who as a bash builtin.
 * Independently implemented from private utmp fixtures and CLI observations.
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
#include <fcntl.h>
#include <time.h>
#include <locale.h>
#include <utmp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <sys/sysinfo.h>
#include "loadables.h"

/* GNU who prints ISO times unless LC_TIME is the C or POSIX locale, where it
   keeps the traditional "%b %e %H:%M" (gnulib hard_locale). */
static int
bw_iso_times (void)
{
    const char *name = setlocale (LC_TIME, NULL);
    return name && strcmp (name, "C") != 0 && strcmp (name, "POSIX") != 0;
}

#define BW_DEFAULT_PATH "/var/run/utmp"
#define BW_TYPE(t) (1u << (t))

/* Fixed-width utmp strings need not contain a terminating NUL. */
static void
bw_field (char *out, const char *in, size_t len)
{
    memcpy (out, in, len);
    out[len] = 0;
}

static int
bw_option (const char *word)
{
    static const struct { const char *name; int flag; } aliases[] = {
        {"--all", 'a'}, {"--boot", 'b'}, {"--dead", 'd'},
        {"--heading", 'H'}, {"--login", 'l'}, {"--process", 'p'},
        {"--count", 'q'}, {"--runlevel", 'r'}, {"--short", 's'},
        {"--time", 't'}, {"--mesg", 'T'}, {"--message", 'T'},
        {"--writable", 'T'}, {"--users", 'u'}, {NULL, 0}
    };
    for (int i = 0; aliases[i].name; i++)
        if (!strcmp (word, aliases[i].name)) return aliases[i].flag;
    return 0;
}

/* No FILE operand follows GNU who 9.7 read_utmp_from_systemd.  Sessions come
   from libsystemd (sd_get_sessions and sd_session_get_*).  Each session with a
   seat or a tty becomes one or two rows: seat first, then tty.  The tty is the
   session tty, or for type "tty" the service plus a pts guessed from /dev/pts,
   or for type "web" the service name.  A remote host is "user@host" when a
   remote user is set, otherwise the host.  An x11 session with no remote host
   stores the display in the host field.  Class names that start with "manager"
   are login rows; other classes are user rows.  User rows whose leader pid is
   dead are omitted.  The boot row is the BOOT_TIME record in /var/run/utmp,
   with the same Raspbian, stamp-file, and uptime fallbacks GNU uses, and is
   not a logind record.  A FILE operand does not use this path. */

struct bw_ent {
    char *user;
    char *id;
    char *line;
    char *host;
    time_t sec;
    pid_t pid;
    short type;
};

struct bw_sd {
    int (*get_sessions) (char ***);
    int (*get_start_time) (const char *, uint64_t *);
    int (*get_seat) (const char *, char **);
    int (*get_tty) (const char *, char **);
    int (*get_type) (const char *, char **);
    int (*get_service) (const char *, char **);
    int (*get_uid) (const char *, uid_t *);
    int (*get_username) (const char *, char **);
    int (*get_leader) (const char *, pid_t *);
    int (*get_class) (const char *, char **);
    int (*get_remote_host) (const char *, char **);
    int (*get_display) (const char *, char **);
    int (*get_remote_user) (const char *, char **);
};

typedef int (*bw_sd_str_fn) (const char *, char **);

static void
bw_free_ents (struct bw_ent *ents, int n)
{
    for (int i = 0; i < n; i++) {
        free (ents[i].user);
        free (ents[i].id);
        free (ents[i].line);
        free (ents[i].host);
    }
    free (ents);
}

static int
bw_add (struct bw_ent **ents, int *n, int *cap, const char *user, const char *id,
        const char *line, const char *host, time_t sec, pid_t pid, short type)
{
    char *u = strdup (user ? user : "");
    char *i = strdup (id ? id : "");
    char *l = strdup (line ? line : "");
    char *h = strdup (host ? host : "");
    if (!u || !i || !l || !h) {
        free (u); free (i); free (l); free (h);
        return -1;
    }
    if (*n == *cap) {
        int c = *cap ? *cap * 2 : 8;
        struct bw_ent *p = realloc (*ents, (size_t) c * sizeof *p);
        if (!p) {
            free (u); free (i); free (l); free (h);
            return -1;
        }
        *ents = p;
        *cap = c;
    }
    (*ents)[*n] = (struct bw_ent) { u, i, l, h, sec, pid, type };
    (*n)++;
    return 0;
}

static int
bw_load_sd (struct bw_sd *out)
{
    static int state;
    static struct bw_sd cached;
    static void *hold;
    if (state) {
        *out = cached;
        return state > 0;
    }
    const char *libs[] = { "libsystemd.so.0", "libsystemd.so", NULL };
    void *h = NULL;
    for (int i = 0; libs[i] && !h; i++)
        h = dlopen (libs[i], RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        state = -1;
        return 0;
    }
#define BW_SYM(field, name) do { \
        void *sym = dlsym (h, name); \
        if (!sym) { dlclose (h); state = -1; return 0; } \
        memcpy (&cached.field, &sym, sizeof cached.field); \
    } while (0)
    BW_SYM (get_sessions, "sd_get_sessions");
    BW_SYM (get_start_time, "sd_session_get_start_time");
    BW_SYM (get_seat, "sd_session_get_seat");
    BW_SYM (get_tty, "sd_session_get_tty");
    BW_SYM (get_type, "sd_session_get_type");
    BW_SYM (get_service, "sd_session_get_service");
    BW_SYM (get_uid, "sd_session_get_uid");
    BW_SYM (get_username, "sd_session_get_username");
    BW_SYM (get_leader, "sd_session_get_leader");
    BW_SYM (get_class, "sd_session_get_class");
    BW_SYM (get_remote_host, "sd_session_get_remote_host");
    BW_SYM (get_display, "sd_session_get_display");
    BW_SYM (get_remote_user, "sd_session_get_remote_user");
#undef BW_SYM
    hold = h;
    if (!hold) return 0;
    state = 1;
    *out = cached;
    return 1;
}

static char *
bw_call_str (bw_sd_str_fn fn, const char *session)
{
    char *p = NULL;
    if (!fn || fn (session, &p) < 0) return NULL;
    return p;
}

static int
bw_dead (pid_t pid)
{
    return pid > 0 && kill (pid, 0) < 0 && errno == ESRCH;
}

/* Earliest /dev/pts node owned by UID whose ctime is at most five seconds
   after the session start.  The name has no /dev/ prefix.  *out is NULL when
   no node matches.  Returns -1 only when that name cannot be allocated. */
static int
bw_guess_pty (uid_t uid, time_t sec, long nsec, char **out)
{
    *out = NULL;
    DIR *dir = opendir ("/dev/pts");
    if (!dir) return 0;
    char best[32];
    int have = 0;
    time_t best_sec = 0;
    long best_nsec = 0;
    struct dirent *dp;
    while ((dp = readdir (dir)) != NULL) {
        if (dp->d_name[0] == '.' || strlen (dp->d_name) > 10) continue;
        char path[64];
        snprintf (path, sizeof path, "/dev/pts/%s", dp->d_name);
        struct stat st;
        if (stat (path, &st) < 0 || st.st_uid != uid) continue;
        time_t cs = st.st_ctim.tv_sec;
        long cn = st.st_ctim.tv_nsec;
        if (cs < sec || (cs == sec && cn < nsec)) continue;
        if (!have || cs < best_sec || (cs == best_sec && cn < best_nsec)) {
            snprintf (best, sizeof best, "pts/%s", dp->d_name);
            best_sec = cs;
            best_nsec = cn;
            have = 1;
        }
    }
    closedir (dir);
    if (!have) return 0;
    if (best_sec > sec + 5 || (best_sec == sec + 5 && best_nsec > nsec)) return 0;
    *out = strdup (best);
    return *out ? 0 : -1;
}

/* Seconds since boot.  CLOCK_BOOTTIME, then the first field of /proc/uptime,
   then sysinfo.  Matches the order GNU who 9.7 uses for its last fallback. */
static int
bw_uptime (time_t *sec, long *nsec)
{
    struct timespec ts;
    if (clock_gettime (CLOCK_BOOTTIME, &ts) == 0) {
        *sec = ts.tv_sec;
        *nsec = ts.tv_nsec;
        return 0;
    }
    int fd = open ("/proc/uptime", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = read (fd, buf, sizeof buf - 1);
        close (fd);
        if (n > 0) {
            buf[n] = 0;
            char *p = buf;
            if (*p >= '0' && *p <= '9') {
                time_t s = 0;
                while (*p >= '0' && *p <= '9')
                    s = 10 * s + (*p++ - '0');
                long ns = 0;
                if (*p == '.') {
                    p++;
                    for (int i = 0; i < 9; i++)
                        ns = 10 * ns + (*p >= '0' && *p <= '9' ? *p++ - '0' : 0);
                }
                *sec = s;
                *nsec = ns;
                return 0;
            }
        }
    }
    struct sysinfo info;
    if (sysinfo (&info) == 0) {
        *sec = (time_t) info.uptime;
        *nsec = 0;
        return 0;
    }
    return -1;
}

static time_t
bw_boot_time (void)
{
    time_t boot = 0, runlevel = 0;
    int have = 0;
    int fd = open (BW_DEFAULT_PATH, O_RDONLY | O_CLOEXEC);
    struct utmp u;
    while (fd >= 0 && read (fd, &u, sizeof u) == sizeof u) {
        char name[sizeof u.ut_user + 1], line[sizeof u.ut_line + 1];
        bw_field (name, u.ut_user, sizeof u.ut_user);
        bw_field (line, u.ut_line, sizeof u.ut_line);
        if (!have && u.ut_type == BOOT_TIME) {
            boot = (time_t) u.ut_tv.tv_sec;
            have = 1;
        }
        if (!strcmp (name, "runlevel") && !strcmp (line, "~"))
            runlevel = (time_t) u.ut_tv.tv_sec;
    }
    if (fd >= 0) close (fd);
    /* A runlevel stamp of zero is not a clock correction. */
    if (have && boot <= 60 && runlevel != 0) boot = runlevel;
    if (have) return boot;
    static const char *files[] = {
        "/var/lib/systemd/random-seed",
        "/var/lib/urandom/random-seed",
        "/var/lib/random-seed",
        "/var/run/utmp",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        struct stat st;
        if (stat (files[i], &st) == 0 && st.st_mtim.tv_sec >= 1122334455)
            return st.st_mtim.tv_sec;
    }
    time_t up_sec;
    long up_nsec;
    struct timespec now;
    if (bw_uptime (&up_sec, &up_nsec) == 0 && timespec_get (&now, TIME_UTC) != 0) {
        if ((long) now.tv_nsec < up_nsec) {
            now.tv_nsec += 1000000000L;
            now.tv_sec -= 1;
        }
        return (time_t) now.tv_sec - up_sec;
    }
    return 0;
}

static int
bw_session_rows (struct bw_sd *sd, struct bw_ent **ents, int *n, int *cap,
                 char *session, int user_only, int check_pids)
{
    char *seat = NULL, *tty = NULL, *type = NULL, *user = NULL;
    char *clasz = NULL, *host = NULL, *remote = NULL, *service = NULL, *pty = NULL;
    int type_known = 0, rc = 0;
    uint64_t usec = 0;
    time_t sec;
    long nsec;

    if (sd->get_start_time (session, &usec) < 0) usec = 0;
    sec = (time_t) (usec / 1000000);
    nsec = (long) ((usec % 1000000) * 1000);
    seat = bw_call_str (sd->get_seat, session);
    tty = bw_call_str (sd->get_tty, session);
    if (!tty) {
        type = bw_call_str (sd->get_type, session);
        type_known = 1;
        if (type && !strcmp (type, "tty")) {
            uid_t uid = 0;
            service = bw_call_str (sd->get_service, session);
            if (sd->get_uid (session, &uid) >= 0 &&
                bw_guess_pty (uid, sec, nsec, &pty) < 0) {
                rc = -1;
                goto done;
            }
            if (service && pty) {
                size_t ns = strlen (service), np = strlen (pty);
                tty = malloc (ns + 1 + np + 1);
                if (!tty) { rc = -1; goto done; }
                memcpy (tty, service, ns);
                tty[ns] = ' ';
                memcpy (tty + ns + 1, pty, np + 1);
                free (service); service = NULL;
                free (pty); pty = NULL;
            } else if (service) {
                tty = service; service = NULL;
            } else if (pty) {
                tty = pty; pty = NULL;
            }
        } else if (type && !strcmp (type, "web")) {
            tty = bw_call_str (sd->get_service, session);
        }
    }
    if (seat || tty) {
        pid_t leader = 0;
        short ctype;
        int keep = 1;
        user = bw_call_str (sd->get_username, session);
        if (sd->get_leader (session, &leader) < 0) leader = 0;
        clasz = bw_call_str (sd->get_class, session);
        ctype = (clasz && !strncmp (clasz, "manager", 7)) ? LOGIN_PROCESS : USER_PROCESS;
        remote = bw_call_str (sd->get_remote_host, session);
        if (!remote) {
            if (!type_known) type = bw_call_str (sd->get_type, session);
            if (type && !strcmp (type, "x11"))
                host = bw_call_str (sd->get_display, session);
        } else {
            char *ruser = bw_call_str (sd->get_remote_user, session);
            if (!ruser) {
                host = remote;
                remote = NULL;
            } else {
                size_t nu = strlen (ruser), nh = strlen (remote);
                host = malloc (nu + 1 + nh + 1);
                if (!host) { free (ruser); rc = -1; goto done; }
                memcpy (host, ruser, nu);
                host[nu] = '@';
                memcpy (host + nu + 1, remote, nh + 1);
                free (ruser);
            }
        }
        if (ctype == USER_PROCESS && !(user && user[0])) keep = 0;
        if (user_only && ctype != USER_PROCESS) keep = 0;
        if (keep && check_pids && ctype == USER_PROCESS && bw_dead (leader)) keep = 0;
        if (keep && seat && bw_add (ents, n, cap, user, session, seat, host, sec, leader, ctype) < 0)
            rc = -1;
        if (rc == 0 && keep && tty &&
            bw_add (ents, n, cap, user, session, tty, host, sec, leader, ctype) < 0)
            rc = -1;
    }
done:
    free (seat); free (tty); free (type); free (user);
    free (clasz); free (host); free (remote); free (service); free (pty);
    free (session);
    return rc;
}

static int
bw_collect (struct bw_ent **out, int *nout, int user_only)
{
    struct bw_ent *ents = NULL;
    struct bw_sd sd;
    char **sessions = NULL;
    int n = 0, cap = 0, num;
    time_t boot = bw_boot_time ();
    *out = NULL;
    *nout = 0;
    if (!user_only && bw_add (&ents, &n, &cap, "reboot", "", "~", "", boot, 0, BOOT_TIME) < 0)
        goto oom;
    if (!bw_load_sd (&sd)) {
        *out = ents;
        *nout = n;
        return 0;
    }
    num = sd.get_sessions (&sessions);
    if (num < 0 || !sessions) {
        *out = ents;
        *nout = n;
        return 0;
    }
    for (char **sp = sessions; *sp; sp++) {
        if (bw_session_rows (&sd, &ents, &n, &cap, *sp, user_only, 1) < 0) {
            for (sp++; *sp; sp++) free (*sp);
            free (sessions);
            goto oom;
        }
    }
    free (sessions);
    *out = ents;
    *nout = n;
    return 0;
oom:
    bw_free_ents (ents, n);
    builtin_error ("out of memory");
    return -1;
}

static int
bw_stat_dev (const char *line, struct stat *st)
{
    const char *space = strchr (line, ' ');
    const char *dev = space ? space + 1 : line;
    char path[PATH_MAX];
    int wrote;
    if (!dev[0]) return -1;
    if (dev[0] == '/') return stat (dev, st);
    wrote = snprintf (path, sizeof path, "/dev/%s", dev);
    if (wrote < 0 || wrote >= (int) sizeof path) return -1;
    return stat (path, st);
}

static int
bw_line_ok (const char *line, int my_line, int quiet, const char *tty)
{
    size_t n, m;
    if (!my_line || quiet) return 1;
    if (!tty) return 0;
    n = strlen (line);
    m = strlen (tty);
    return m <= n && !memcmp (line + (n - m), tty, m);
}

static void
bw_trim (char *s)
{
    size_t n = strlen (s);
    while (n && s[n - 1] == ' ') s[--n] = 0;
}

static void
bw_print_ent (const struct bw_ent *e, time_t boot, int idle, int pidcol, int mesg)
{
    int is_user = e->type == USER_PROCESS && e->user[0];
    char tbuf[64] = "?", idlebuf[32] = "  ?";
    struct tm tm;
    const char *display_line = e->line;
    const char *display_name = "";
    struct stat st;
    int have;
    char status = '?';

    if (localtime_r (&e->sec, &tm))
        strftime (tbuf, sizeof tbuf, bw_iso_times () ? "%Y-%m-%d %H:%M" : "%b %e %H:%M", &tm);
    if (e->type == BOOT_TIME) display_line = "system boot";
    else if (e->type == LOGIN_PROCESS) display_name = "LOGIN";
    else if (is_user) display_name = e->user;
    have = is_user && (idle || mesg) && bw_stat_dev (e->line, &st) == 0;
    if (have) {
        time_t now = time (NULL);
        double age = difftime (now, st.st_atime);
        status = (st.st_mode & S_IWGRP) ? '+' : '-';
        /* An atime equal to the boot second is idle "old", as in GNU who. */
        if (age < 0 || st.st_atime <= boot || age >= 86400) strcpy (idlebuf, " old");
        else if (age < 60) strcpy (idlebuf, "  .");
        else snprintf (idlebuf, sizeof idlebuf, "%02d:%02d", (int) age / 3600, ((int) age / 60) % 60);
    }
    printf ("%-8s ", display_name);
    if (mesg) printf ("%c ", is_user ? status : ' ');
    printf ("%-12s %s", display_line, tbuf);
    if (is_user) {
        if (idle) printf (" %-6s", idlebuf);
        if (pidcol) printf (" %10d", (int) e->pid);
        if (e->host[0]) printf (" (%s)", e->host);
    } else if (e->type == LOGIN_PROCESS) {
        if (idle) printf (" %-6s", "");
        if (pidcol) printf (" %10d", (int) e->pid);
        printf (" id=%s", e->id);
    }
    putchar ('\n');
}

static int
bw_show_logind (unsigned int mask, int quiet, int idle, int pidcol, int mesg, int my_line)
{
    struct bw_ent *ents = NULL;
    int n = 0, count = 0;
    time_t boot = 0;
    char ttybuf[PATH_MAX];
    const char *tty = NULL;

    if (bw_collect (&ents, &n, quiet) < 0) return EXECUTION_FAILURE;
    for (int i = 0; i < n; i++)
        if (ents[i].type == BOOT_TIME) boot = ents[i].sec;
    if (my_line) {
        const char *got = ttyname (STDIN_FILENO);
        if (got) {
            snprintf (ttybuf, sizeof ttybuf, "%s", got);
            tty = ttybuf;
            if (!strncmp (tty, "/dev/", 5)) tty += 5;
        }
    }
    for (int i = 0; i < n; i++) {
        struct bw_ent *e = &ents[i];
        if (e->type < 0 || e->type >= 32 || !(mask & BW_TYPE (e->type))) continue;
        if (e->type == USER_PROCESS && !e->user[0]) continue;
        if (!bw_line_ok (e->line, my_line, quiet, tty)) continue;
        if (quiet) {
            char *name = strdup (e->user);
            if (!name) {
                bw_free_ents (ents, n);
                builtin_error ("out of memory");
                return EXECUTION_FAILURE;
            }
            bw_trim (name);
            printf ("%s%s", count++ ? " " : "", name);
            free (name);
            continue;
        }
        bw_print_ent (e, boot, idle, pidcol, mesg);
    }
    bw_free_ents (ents, n);
    if (quiet) printf ("\n# users=%d\n", count);
    return ferror (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
who_builtin (WORD_LIST *list)
{
    int headers = 0, quiet = 0, users = 0, all = 0, short_form = 0;
    int mesg = 0, my_line = 0, idle, pid, exits;
    unsigned int mask = 0;
    int file_operand = 0;
    const char *path = BW_DEFAULT_PATH;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word, *flags = w + 1;
        char single[2] = {0, 0};
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("who 1.0 (bash-loadable)"); return EXECUTION_SUCCESS;
        }
        if (w[1] == '-') {
            single[0] = bw_option (w);
            if (!single[0]) {
                builtin_error ("unrecognized option: %s", w);
                return EXECUTION_FAILURE;
            }
            flags = single;
        }
        for (const char *c = flags; *c; c++) {
            switch (*c) {
            case 'a':
                all = 1;
                mask |= BW_TYPE (USER_PROCESS) | BW_TYPE (BOOT_TIME)
                      | BW_TYPE (RUN_LVL) | BW_TYPE (DEAD_PROCESS)
                      | BW_TYPE (LOGIN_PROCESS) | BW_TYPE (INIT_PROCESS)
                      | BW_TYPE (NEW_TIME);
                break;
            case 'b': mask |= BW_TYPE (BOOT_TIME); break;
            case 'd': mask |= BW_TYPE (DEAD_PROCESS); break;
            case 'l': mask |= BW_TYPE (LOGIN_PROCESS); break;
            case 'p': mask |= BW_TYPE (INIT_PROCESS); break;
            case 'r': mask |= BW_TYPE (RUN_LVL); break;
            case 't': mask |= BW_TYPE (NEW_TIME); break;
            case 'u': users = 1; mask |= BW_TYPE (USER_PROCESS); break;
            case 'H': headers = 1; break;
            case 'q': quiet = 1; break;
            case 's': short_form = 1; break;
            case 'T': case 'w': mesg = 1; break;
            case 'm': my_line = 1; break;
            default:
                builtin_error ("invalid option: -%c", *c);
                return EXECUTION_FAILURE;
            }
        }
        list = list->next;
    }
    if (list && list->next && !list->next->next) {
        /* GNU's two-operand form selects the current terminal and still
           reads logind, regardless of the operand spelling. */
        my_line = 1;
    } else if (list) {
        path = list->word->word;
        file_operand = 1;
        if (list->next) {
            builtin_error ("extra operand: %s", list->next->word->word);
            return EXECUTION_FAILURE;
        }
    }
    pid = mask != 0;
    idle = users || (mask & (BW_TYPE (DEAD_PROCESS) | BW_TYPE (LOGIN_PROCESS)
                           | BW_TYPE (RUN_LVL))) || all;
    exits = (mask & BW_TYPE (DEAD_PROCESS)) != 0;
    if (short_form && !all) idle = pid = 0;
    if (all) mesg = 1;
    if (!mask || quiet) mask = BW_TYPE (USER_PROCESS);

    if (headers && !quiet) {
        printf ("%-8s %s%-12s %-*s", "NAME", mesg ? "  " : "", "LINE", bw_iso_times () ? 16 : 12, "TIME");
        if (idle) printf (" %-6s", "IDLE");
        if (pid) printf (" %10s", "PID");
        printf (" COMMENT%s\n", exits ? "  EXIT" : "");
    }

    /* An explicit FILE, including /var/run/utmp, stays on the utmp reader.
       GNU who 9.7 switches on the path string; this builtin switches on
       whether a FILE operand was present. */
    if (!file_operand)
        return bw_show_logind (mask, quiet, idle, pid, mesg, my_line);

    /* GNU who treats unavailable explicit inputs and incomplete tails as empty.
       Use a private fd rather than changing libc's process-wide utmp state. */
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    const char *tty = my_line ? ttyname (STDIN_FILENO) : NULL;
    if (tty && !strncmp (tty, "/dev/", 5)) tty += 5;
    struct utmp u;
    int count = 0;
    time_t boot_time = 0;
    while (fd >= 0 && read (fd, &u, sizeof u) == sizeof u) {
        /* Boot records affect idle calculations even if -b is not selected. */
        if (u.ut_type == BOOT_TIME) boot_time = (time_t) u.ut_tv.tv_sec;
        if (u.ut_type < 0 || u.ut_type >= 32 || !(mask & BW_TYPE (u.ut_type))) continue;
        int is_user = u.ut_type == USER_PROCESS;
        if (is_user && !u.ut_user[0]) continue;
        char name[sizeof u.ut_user + 1], line[sizeof u.ut_line + 1];
        char host[sizeof u.ut_host + 1], id[sizeof u.ut_id + 1];
        bw_field (name, u.ut_user, sizeof u.ut_user);
        bw_field (line, u.ut_line, sizeof u.ut_line);
        bw_field (host, u.ut_host, sizeof u.ut_host);
        bw_field (id, u.ut_id, sizeof u.ut_id);
        if (my_line && !quiet && (!tty || strcmp (tty, line))) continue;
        if (quiet) {
            printf ("%s%s", count++ ? " " : "", name);
            continue;
        }
        char tbuf[64] = "?", idlebuf[32] = "  ?";
        time_t t = (time_t) u.ut_tv.tv_sec;
        struct tm tm;
        if (localtime_r (&t, &tm)) strftime (tbuf, sizeof tbuf, bw_iso_times () ? "%Y-%m-%d %H:%M" : "%b %e %H:%M", &tm);
        struct stat st;
        char terminal[sizeof u.ut_line + 6];
        snprintf (terminal, sizeof terminal, "/dev/%s", line);
        int have_stat = is_user && (idle || mesg) && stat (terminal, &st) == 0;
        char status = have_stat ? ((st.st_mode & S_IWGRP) ? '+' : '-') : '?';
        if (have_stat && idle) {
            time_t now = time (NULL);
            double age = difftime (now, st.st_atime);
            if (age < 0 || st.st_atime < boot_time || age >= 86400) strcpy (idlebuf, " old");
            else if (age < 60) strcpy (idlebuf, "  .");
            else snprintf (idlebuf, sizeof idlebuf, "%02d:%02d", (int)age / 3600, ((int)age / 60) % 60);
        }
        const char *display_name = is_user ? name : u.ut_type == LOGIN_PROCESS ? "LOGIN" : "";
        char runlevel[16];
        const char *display_line = line;
        if (u.ut_type == BOOT_TIME) display_line = "system boot";
        if (u.ut_type == NEW_TIME) display_line = "clock change";
        if (u.ut_type == RUN_LVL) {
            snprintf (runlevel, sizeof runlevel, "run-level %c", u.ut_pid & 255);
            display_line = runlevel;
        }
        printf ("%-8s ", display_name);
        if (mesg) printf ("%c ", is_user ? status : ' ');
        printf ("%-12s %s", display_line, tbuf);
        if (is_user) {
            if (idle) printf (" %-6s", idlebuf);
            if (pid) printf (" %10d", (int) u.ut_pid);
            if (host[0]) printf (" (%s)", host);
        } else if (u.ut_type == INIT_PROCESS || u.ut_type == LOGIN_PROCESS || u.ut_type == DEAD_PROCESS) {
            if (idle) printf (" %-6s", "");
            if (pid) printf (" %10d", (int) u.ut_pid);
            printf (" id=%s", id);
            if (u.ut_type == DEAD_PROCESS && exits)
                printf ("%*s term=%d exit=%d", (int)(5 - strlen (id)), "", u.ut_exit.e_termination, u.ut_exit.e_exit);
        } else if (u.ut_type == RUN_LVL) {
            int previous = (u.ut_pid >> 8) & 255;
            if (previous >= 32 && previous < 127) {
                if (idle) printf (" %-6s", "");
                if (pid) printf (" %10s", "");
                /* GNU who reports no previous level ('N') as single-user. */
                printf (" last=%c", previous == 'N' ? 'S' : previous);
            }
        }
        putchar ('\n');
    }
    if (fd >= 0) close (fd);
    if (quiet) printf ("\n# users=%d\n", count);
    return ferror (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *who_doc[] = {
    "List logged-in users and selected utmp records.",
    "",
    "    who [-abdHlmpqrstTuw] [--help|--version] [FILE | ARG1 ARG2]",
    "",
    "    -a all; -b boot; -d dead; -l login; -p init; -r run-level; -t clock change",
    "    -H headings; -q usernames and count; -s short format; -T/-w terminal status",
    "    -u users with idle time and pid; -m current terminal only",
    "    Long aliases: --all, --boot, --dead, --heading, --login, --process,",
    "    --count, --runlevel, --short, --time, --mesg, --message, --writable, --users.",
    "    With no FILE, read systemd-logind sessions the way GNU who 9.7 does.",
    "    A FILE operand reads that utmp file. Two words select the current terminal.",
    "    Selection flags compose; -q selects users.",
    (char *)NULL
};

struct builtin who_struct = {
    "who", who_builtin, BUILTIN_ENABLED, who_doc,
    "who [-abdHlmpqrstTuw] [--help|--version] [FILE | ARG1 ARG2]", 0
};
