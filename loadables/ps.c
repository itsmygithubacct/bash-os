/* bashps.c — procps-shaped ps(1) via /proc walking.
 *
 *   bashps [-efFjlLy] [-o KEY,...] [-p PIDLIST] [PID...]
 *   bashps [aux] [j|l|u] [PID...]
 *
 * Output keys, the -f/-F/-l/-j formats and the BSD u/j/l formats follow
 * procps ps(1) (STANDARD FORMAT SPECIFIERS) and the observed procps-ng
 * column layout. BASHOS_PROC_ROOT names another /proc for tests.
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
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <langinfo.h>
#include <pwd.h>
#include <grp.h>
#include <strings.h>
#include <sys/stat.h>
#if defined (__linux__)
#  include <sys/sysmacros.h>
#endif
#include <time.h>

#include "loadables.h"
#include "shim-prog-name.h"

#define BPS_BUF 4096
#define BPS_MAX_COLS 64
#define BPS_PATH_MAX 1024

typedef struct {
    int pid, ppid, pgrp, sid;
    int   lwp;               /* thread id (-L), else the pid */
    int   tty_nr;            /* /proc/[pid]/stat field 7 */
    int   tpgid;             /* /proc/[pid]/stat field 8  (for STAT '+') */
    uid_t uid;               /* effective */
    uid_t ruid, suid, fsuid;
    gid_t egid, rgid, sgid, fsgid;
    unsigned long flags;     /* field 9 */
    long  priority;          /* field 18 */
    long  processor;         /* field 39 */
    long  rt_priority;       /* field 40 */
    long  policy;            /* field 41 */
    char  state;
    char  comm[64];
    char  args[256];
    long  starttime_ticks;   /* /proc/[pid]/stat field 22 */
    long  utime, stime;
    long  nice;              /* field 19 (for STAT '<' / 'N') */
    long  num_threads;       /* field 20 (for STAT 'l') */
    long  vmlck_kb;          /* /proc/[pid]/status VmLck  (for STAT 'L') */
    long  vmrss_kb;          /* /proc/[pid]/status VmRSS, or -1 if absent */
    long  rss_pages;
    long  vsize_bytes;
} bps_proc;

static const char *
bps_proc_root (void)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");
    return (root && *root) ? root : "/proc";
}

static int
bps_proc_path (char *buf, size_t bufsz, const char *name)
{
    int n = snprintf (buf, bufsz, "%s/%s", bps_proc_root (), name);
    return (n < 0 || (size_t)n >= bufsz) ? -1 : 0;
}

static int
bps_proc_pid_path (char *buf, size_t bufsz, int pid, const char *name)
{
    char rel[64];
    int n = snprintf (rel, sizeof rel, "%d/%s", pid, name);
    if (n < 0 || (size_t)n >= sizeof rel)
        return -1;
    return bps_proc_path (buf, bufsz, rel);
}

/* Make S printable the way procps ps does, in place.  Single-byte locales
   turn control bytes into '.' and bytes above 0x7e into '?'.  UTF-8 locales
   keep valid sequences and turn control bytes, C1 controls and invalid
   bytes into one '?' each, and U+FFFE/U+FFFF into a single '?'. */
static void
bps_escape (char *s)
{
    const char *set = nl_langinfo (CODESET);
    int utf8 = set && (!strcasecmp (set, "UTF-8") || !strcasecmp (set, "utf8"));
    unsigned char *r = (unsigned char *) s, *w = (unsigned char *) s;

    while (*r) {
        unsigned char c = *r;
        if (!utf8) {
            *w++ = c < 0x20 || c == 0x7f ? '.' : c > 0x7e ? '?' : c;
            r++;
            continue;
        }
        if (c < 0x80) {
            *w++ = c < 0x20 || c == 0x7f ? '?' : c;
            r++;
            continue;
        }
        int len = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3
                : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
        unsigned char lo = 0x80, hi = 0xbf;
        if (c == 0xe0) lo = 0xa0;
        else if (c == 0xed) hi = 0x9f;
        else if (c == 0xf0) lo = 0x90;
        else if (c == 0xf4) hi = 0x8f;
        int ok = len > 0 && r[1] >= lo && r[1] <= hi;
        for (int i = 2; ok && i < len; i++)
            ok = r[i] >= 0x80 && r[i] <= 0xbf;
        if (!ok) {
            *w++ = '?';
            r++;
        } else if (c == 0xc2 && r[1] <= 0x9f) {
            *w++ = '?'; *w++ = '?';
            r += 2;
        } else if (c == 0xef && r[1] == 0xbf && (r[2] == 0xbe || r[2] == 0xbf)) {
            *w++ = '?';
            r += 3;
        } else {
            for (int i = 0; i < len; i++) *w++ = *r++;
        }
    }
    *w = '\0';
}

/* /proc/PID/NAME, or /proc/PID/task/TID/NAME for one thread (TID > 0). */
static int
bps_proc_task_path (char *buf, size_t bufsz, int pid, int tid, const char *name)
{
    char rel[96];
    if (tid <= 0)
        return bps_proc_pid_path (buf, bufsz, pid, name);
    int n = snprintf (rel, sizeof rel, "%d/task/%d/%s", pid, tid, name);
    if (n < 0 || (size_t)n >= sizeof rel)
        return -1;
    return bps_proc_path (buf, bufsz, rel);
}

/* Read all of /proc/PID/stat (or one thread's, TID > 0) into buf and slot
   fields. Returns 0 on success. The `comm` field is in `()` parens and may
   contain spaces; we anchor on the LAST `)` to find the rest of the line. */
static int
bps_read_task (int pid, int tid, bps_proc *p)
{
    char path[BPS_PATH_MAX];
    if (bps_proc_task_path (path, sizeof path, pid, tid, "stat") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BPS_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    /* Find last `)` to skip past comm. */
    char *last = strrchr (buf, ')');
    if (!last) return -1;
    /* Extract comm: between first '(' and last ')'. */
    char *first = strchr (buf, '(');
    if (!first || first > last) return -1;
    size_t clen = (size_t) (last - first - 1);
    if (clen >= sizeof p->comm) clen = sizeof p->comm - 1;
    memcpy (p->comm, first + 1, clen);
    p->comm[clen] = '\0';
    bps_escape (p->comm);

    p->pid = pid;
    p->lwp = tid > 0 ? tid : pid;
    /* Skip past `) ` and parse the rest. Field 3 = state. */
    char *rest = last + 2;
    /* Layout per proc(5):
       (3) state, (4) ppid, (5) pgrp, (6) session, (7) tty_nr, (8) tpgid,
       (9) flags ... (14) utime, (15) stime, (18) priority, (19) nice,
       (20) num_threads, ... (22) starttime, (23) vsize, (24) rss.
       We capture tpgid/nice/num_threads for the procps STAT flag chars. */
    /* Numeric fields from (4) on; records may stop after (24). */
    long long f[53];
    memset (f, 0, sizeof f);
    if (!*rest) return -1;
    p->state = *rest;
    char *q = rest + 1;
    int nf;
    for (nf = 4; nf < 53; nf++) {
        while (*q == ' ') q++;
        if (!*q || *q == '\n') break;
        char *e;
        f[nf] = strtoll (q, &e, 10);
        if (e == q) return -1;
        q = e;
    }
    if (nf < 25) return -1;
    p->ppid = (int) f[4]; p->pgrp = (int) f[5]; p->sid = (int) f[6];
    p->tty_nr = (int) f[7]; p->tpgid = (int) f[8];
    p->flags = (unsigned long) f[9];
    p->utime = (long) f[14]; p->stime = (long) f[15];
    p->priority = (long) f[18]; p->nice = (long) f[19]; p->num_threads = (long) f[20];
    p->starttime_ticks = (long) f[22]; p->vsize_bytes = (long) f[23]; p->rss_pages = (long) f[24];
    p->processor = (long) f[39]; p->rt_priority = (long) f[40]; p->policy = (long) f[41];
    p->vmrss_kb = -1;

    /* uid: read /proc/PID/status. */
    if (bps_proc_task_path (path, sizeof path, pid, tid, "status") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char sbuf[BPS_BUF];
        ssize_t sn = read (fd, sbuf, sizeof sbuf - 1);
        close (fd);
        if (sn > 0) {
            sbuf[sn] = '\0';
            char *u = strstr (sbuf, "\nUid:");
            if (u) {
                u++;
            } else if (strncmp (sbuf, "Uid:", 4) == 0) {
                u = sbuf;
            }
            if (u) {
                long uid_val = 0, ruid_val = 0, suid_val = 0, fsuid_val = 0;
                u += 4;
                while (*u == ' ' || *u == '\t') u++;
                int nu = sscanf (u, "%ld %ld %ld %ld", &ruid_val, &uid_val, &suid_val, &fsuid_val);
                if (nu < 3) suid_val = uid_val;
                if (nu < 4) fsuid_val = uid_val;
                p->uid = (uid_t) uid_val;
                p->ruid = (uid_t) ruid_val;
                p->suid = (uid_t) suid_val;
                p->fsuid = (uid_t) fsuid_val;
            }
            char *gl = strstr (sbuf, "\nGid:");
            if (gl) {
                long g[4] = { 0, 0, 0, 0 };
                int ng = sscanf (gl + 5, "%ld %ld %ld %ld", &g[0], &g[1], &g[2], &g[3]);
                for (int i = ng < 0 ? 0 : ng; i < 4; i++) g[i] = i ? g[1] : 0;
                p->rgid = (gid_t) g[0]; p->egid = (gid_t) g[1];
                p->sgid = (gid_t) g[2]; p->fsgid = (gid_t) g[3];
            }
            /* VmLck: locked pages -> STAT 'L' (rarely nonzero). Never the
               first status line (Name: is), so anchoring on '\n' is safe. */
            char *vl = strstr (sbuf, "\nVmLck:");
            if (vl) sscanf (vl + 7, "%ld", &p->vmlck_kb);
            /* procps reports RSS from VmRSS; stat's rss field can lag
               behind it by the kernel's per-CPU counter batches. */
            char *vr = strstr (sbuf, "\nVmRSS:");
            if (vr && sscanf (vr + 7, "%ld", &p->vmrss_kb) != 1) p->vmrss_kb = -1;
        }
    }

    /* args: /proc/PID/cmdline (NUL-separated argv). */
    if (bps_proc_pid_path (path, sizeof path, pid, "cmdline") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t an = read (fd, p->args, sizeof p->args - 1);
        close (fd);
        if (an > 0) {
            /* Like procps, separators and newlines read as spaces. */
            for (ssize_t i = 0; i < an - 1; i++)
                if (p->args[i] == '\0' || p->args[i] == '\n') p->args[i] = ' ';
            p->args[an] = '\0';
            bps_escape (p->args);
        } else {
            /* Kernel threads have empty cmdline — fall back to [comm]. */
            snprintf (p->args, sizeof p->args, "[%s]", p->comm);
        }
    } else {
        snprintf (p->args, sizeof p->args, "[%s]", p->comm);
    }
    return 0;
}

static int
bps_read_stat (int pid, bps_proc *p)
{
    return bps_read_task (pid, 0, p);
}

static long
bps_rss_kb (const bps_proc *p)
{
    long page_size = sysconf (_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    return p->vmrss_kb >= 0 ? p->vmrss_kb : p->rss_pages * page_size / 1024;
}

/* Static glibc cannot safely load NSS modules from a different host libc. */
static struct passwd *
bps_lookup_user (const char *name, uid_t uid)
{
#if defined (BASHOS_STATIC) && defined (__GLIBC__)
    FILE *accounts = fopen ("/etc/passwd", "r");
    struct passwd *entry = NULL;
    if (accounts) {
        while ((entry = fgetpwent (accounts)) != NULL)
            if (name ? strcmp (entry->pw_name, name) == 0 : entry->pw_uid == uid)
                break;
        fclose (accounts);
    }
    return entry;
#else
    return name ? getpwnam (name) : getpwuid (uid);
#endif
}

static const char *
bps_user (uid_t uid)
{
    static char buf[32];
    struct passwd *pw = bps_lookup_user (NULL, uid);
    if (pw) return pw->pw_name;
    snprintf (buf, sizeof buf, "%u", (unsigned) uid);
    return buf;
}

static int
bps_parse_pid_operand (const char *s, int *pidp)
{
    char *end = NULL;
    long n;

    if (s == NULL || *s == '\0') {
        builtin_error ("PID operand must be a decimal integer");
        builtin_usage ();
        return -1;
    }

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end != '\0' || n < 0 || n > INT_MAX) {
        builtin_error ("invalid PID operand: %s", s);
        builtin_usage ();
        return -1;
    }

    *pidp = (int) n;
    return 0;
}

static int
bps_add_pid_operand (const char *s, int *explicit_pids, int *n_pids, int max_pids)
{
    if (*n_pids >= max_pids) {
        builtin_error ("too many PIDs");
        builtin_usage ();
        return -1;
    }
    if (bps_parse_pid_operand (s, &explicit_pids[*n_pids]) < 0)
        return -1;
    (*n_pids)++;
    return 0;
}

static int
bps_add_pid_list (const char *s, int *explicit_pids, int *n_pids, int max_pids)
{
    const char *p = s;

    if (!s || !*s) {
        builtin_error ("PID operand must be a decimal integer");
        builtin_usage ();
        return -1;
    }
    while (*p) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen (p);
        char buf[64];

        if (len == 0 || len >= sizeof buf) {
            builtin_error ("invalid PID operand: %s", s);
            builtin_usage ();
            return -1;
        }
        memcpy (buf, p, len);
        buf[len] = '\0';
        if (bps_add_pid_operand (buf, explicit_pids, n_pids, max_pids) < 0)
            return -1;
        if (!comma)
            break;
        p = comma + 1;
    }
    return 0;
}

/* Convert /proc/PID/stat start ticks using btime from the current proc root. */
static int
bps_start_localtime (long ticks_since_boot, struct tm *tm_start)
{
    time_t btime = 0;
    {
        char path[BPS_PATH_MAX];
        if (bps_proc_path (path, sizeof path, "stat") == 0) {
            FILE *f = fopen (path, "r");
            if (f) {
                char line[256];
                long v;
                while (fgets (line, sizeof line, f))
                    if (sscanf (line, "btime %ld", &v) == 1) { btime = (time_t) v; break; }
                fclose (f);
            }
        }
    }
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    if (btime == 0) return 0;
    time_t start = btime + ticks_since_boot / hz;
    return localtime_r (&start, tm_start) != NULL;
}

/* STIME displays HH:MM for today's processes and MMMDD for older ones. */
static void
bps_fmt_stime (long ticks_since_boot, char *buf, size_t bufsz)
{
    time_t now = time (NULL);
    struct tm tm_start, tm_now;
    if (!bps_start_localtime (ticks_since_boot, &tm_start) ||
        !localtime_r (&now, &tm_now))
        { snprintf (buf, bufsz, "?"); return; }
    if (tm_start.tm_year == tm_now.tm_year && tm_start.tm_yday == tm_now.tm_yday)
        strftime (buf, bufsz, "%H:%M", &tm_start);
    else
        strftime (buf, bufsz, "%b%d", &tm_start);
}

static void
bps_fmt_lstart (long ticks_since_boot, char *buf, size_t bufsz)
{
    struct tm tm_start;
    tzset ();
    if (!bps_start_localtime (ticks_since_boot, &tm_start) ||
        strftime (buf, bufsz, "%a %b %e %H:%M:%S %Y", &tm_start) == 0)
        snprintf (buf, bufsz, "?");
}

/* Build the procps STAT string: the run-state char followed by mode flags
   in procps' fixed order ( <|N , L , s , l , + ). Matches ps(1)'s pr_stat():
     <  nice < 0      N  nice > 0       L  VmLck > 0
     s  session leader (session == pid)  l  multithreaded (nlwp > 1)
     +  pgrp == tpgid (foreground process group). */
static void
bps_build_stat (const bps_proc *p, char *buf, size_t bufsz)
{
    size_t i = 0;
    if (i + 1 < bufsz) buf[i++] = p->state;
    if (p->nice < 0)      { if (i + 1 < bufsz) buf[i++] = '<'; }
    else if (p->nice > 0) { if (i + 1 < bufsz) buf[i++] = 'N'; }
    if (p->vmlck_kb > 0)        { if (i + 1 < bufsz) buf[i++] = 'L'; }
    if (p->sid == p->pid)       { if (i + 1 < bufsz) buf[i++] = 's'; }
    if (p->num_threads > 1)     { if (i + 1 < bufsz) buf[i++] = 'l'; }
    if (p->pgrp == p->tpgid)    { if (i + 1 < bufsz) buf[i++] = '+'; }
    buf[i] = '\0';
}

/* Resolve a controlling tty by kernel device number, preferring a matching
   /proc/PID/fd link and then the ordinary device directories. */
static void
bps_tty_name (const bps_proc *p, char *out, size_t size)
{
    snprintf (out, size, "?");
#if defined (__linux__)
    if (!p->tty_nr) return;
    unsigned int n = (unsigned int) p->tty_nr;
    unsigned int want_major = (n >> 8) & 0xfff;
    unsigned int want_minor = (n & 0xff) | ((n >> 12) & 0xfff00);
    char path[BPS_PATH_MAX], name[BPS_PATH_MAX];
    struct stat st;
    for (int fd = 0; fd < 3; fd++) {
        char rel[16];
        snprintf (rel, sizeof rel, "fd/%d", fd);
        if (bps_proc_pid_path (path, sizeof path, p->pid, rel) < 0 ||
            stat (path, &st) < 0 || !S_ISCHR (st.st_mode) ||
            major (st.st_rdev) != want_major || minor (st.st_rdev) != want_minor)
            continue;
        ssize_t len = readlink (path, name, sizeof name - 1);
        if (len <= 0 || (size_t) len >= sizeof name - 1) continue;
        name[len] = '\0';
        if (strncmp (name, "/dev/", 5) == 0) {
            snprintf (out, size, "%s", name + 5);
            return;
        }
    }
    const char *dirs[] = { "/dev/pts", "/dev" };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        DIR *dir = opendir (dirs[i]);
        if (!dir) continue;
        struct dirent *de;
        while ((de = readdir (dir)) != NULL) {
            if (de->d_name[0] == '.') continue;
            int len = snprintf (path, sizeof path, "%s/%s", dirs[i], de->d_name);
            if (len < 0 || (size_t) len >= sizeof path || stat (path, &st) < 0 ||
                !S_ISCHR (st.st_mode) || major (st.st_rdev) != want_major ||
                minor (st.st_rdev) != want_minor) continue;
            snprintf (out, size, "%s%s", i == 0 ? "pts/" : "", de->d_name);
            closedir (dir);
            return;
        }
        closedir (dir);
    }
#endif
}

static double bps_cpu_percent (const bps_proc *p);
static long bps_elapsed (const bps_proc *p);
static double bps_mem_percent (const bps_proc *p);

/* procps etime: [[DD-]hh:]mm:ss. */
static void
bps_fmt_etime (long secs, char *buf, size_t bufsz)
{
    long d = secs / 86400, h = secs / 3600 % 24, m = secs / 60 % 60, sec = secs % 60;
    if (d) snprintf (buf, bufsz, "%ld-%02ld:%02ld:%02ld", d, h, m, sec);
    else if (h) snprintf (buf, bufsz, "%02ld:%02ld:%02ld", h, m, sec);
    else snprintf (buf, bufsz, "%02ld:%02ld", m, sec);
}

static long
bps_mem_total_kb (void)
{
    long mem_total = 0;

    char path[BPS_PATH_MAX];
    if (bps_proc_path (path, sizeof path, "meminfo") == 0) {
        FILE *f = fopen (path, "r");
        if (f) {
            char line[256];
            long v;
            while (fgets (line, sizeof line, f)) {
                if (sscanf (line, "MemTotal: %ld kB", &v) == 1) {
                    mem_total = v;
                    break;
                }
            }
            fclose (f);
        }
    }

    return mem_total;
}

static void
bps_fmt_aux_time (long ticks, char *buf, size_t bufsz)
{
    long ticks_per_sec = sysconf (_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;
    long total_secs = ticks / ticks_per_sec;
    snprintf (buf, bufsz, "%ld:%02ld", total_secs / 60, total_secs % 60);
}

/* Procps reports lifetime CPU usage, truncated to one decimal place. */
static double
bps_cpu_percent (const bps_proc *p)
{
    char path[BPS_PATH_MAX];
    double uptime = 0.0;
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    if (bps_proc_path (path, sizeof path, "uptime") == 0) {
        FILE *f = fopen (path, "r");
        if (f) { if (fscanf (f, "%lf", &uptime) != 1) uptime = 0.0; fclose (f); }
    }
    double elapsed = uptime - (double) p->starttime_ticks / hz;
    if (elapsed <= 0.0) return 0.0;
    double tenths = ((double) p->utime + p->stime) * 1000.0 / hz / elapsed;
    if (tenths > 999999.0) tenths = 999999.0;
    return (long) tenths / 10.0;
}

static double
bps_uptime (void)
{
    char path[BPS_PATH_MAX];
    double uptime = 0.0;
    if (bps_proc_path (path, sizeof path, "uptime") == 0) {
        FILE *f = fopen (path, "r");
        if (f) { if (fscanf (f, "%lf", &uptime) != 1) uptime = 0.0; fclose (f); }
    }
    return uptime;
}

/* Whole seconds since the process started (procps etimes). */
static long
bps_elapsed (const bps_proc *p)
{
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    double elapsed = bps_uptime () - (double) p->starttime_ticks / hz;
    return elapsed > 0.0 ? (long) elapsed : 0;
}

/* Resident share of MemTotal, truncated to one decimal place like procps. */
static double
bps_mem_percent (const bps_proc *p)
{
    long rss_kb = bps_rss_kb (p), mem_total = bps_mem_total_kb ();
    if (mem_total <= 0 || rss_kb <= 0) return 0.0;
    return (long) ((double) rss_kb * 1000.0 / (double) mem_total) / 10.0;
}

/* procps shows a defunct marker in argument columns even when the kernel
   cmdline is empty; the command-name column stays the bare name. */
static void
bps_command (const bps_proc *p, int arguments, char *buf, size_t size)
{
    if (arguments && p->state == 'Z')
        snprintf (buf, size, "[%s] <defunct>", p->comm);
    else
        snprintf (buf, size, "%s", arguments ? (p->args[0] ? p->args : p->comm) : p->comm);
}

/* -u/-U USERLIST: comma or blank separated names or numeric IDs. */
static int
bps_add_user_list (const char *s, uid_t *uids, int *n, int max)
{
    char *copy = strdup (s);
    if (!copy) { builtin_error ("out of memory"); return -1; }
    int rc = 0, any = 0;
    for (char *save = NULL, *tok = strtok_r (copy, ", \t", &save); tok;
         tok = strtok_r (NULL, ", \t", &save)) {
        struct passwd *pw = bps_lookup_user (tok, 0);
        uid_t uid;
        if (pw) uid = pw->pw_uid;
        else {
            char *end;
            errno = 0;
            unsigned long v = strtoul (tok, &end, 10);
            if (errno || *end || end == tok || tok[0] == '-' || (uid_t) v != v) {
                builtin_error ("user name does not exist: %s", tok);
                rc = -1;
                break;
            }
            uid = (uid_t) v;
        }
        if (*n >= max) { builtin_error ("too many users"); rc = -1; break; }
        uids[(*n)++] = uid;
        any = 1;
    }
    if (rc == 0 && !any) { builtin_error ("list of users must follow -u"); rc = -1; }
    free (copy);
    return rc;
}

static int
bps_uid_in (uid_t uid, const uid_t *uids, int n)
{
    for (int i = 0; i < n; i++)
        if (uids[i] == uid) return 1;
    return 0;
}

/* A growable list of selected processes (threads with -L). */
typedef struct { bps_proc *v; size_t n, cap; } bps_list;

static int
bps_list_add (bps_list *l, const bps_proc *p)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 256;
        bps_proc *v = realloc (l->v, cap * sizeof *v);
        if (!v) { builtin_error ("out of memory"); return -1; }
        l->v = v; l->cap = cap;
    }
    l->v[l->n++] = *p;
    return 0;
}

static int
bps_compare_lwp (const void *x, const void *y)
{
    const bps_proc *a = x, *b = y;
    return a->lwp < b->lwp ? -1 : a->lwp > b->lwp;
}

/* Add P, or with -L each of its threads (in thread-id order) from /proc/PID/task. */
static int
bps_list_add_tasks (bps_list *l, const bps_proc *p, int threads)
{
    if (!threads) return bps_list_add (l, p);
    char path[BPS_PATH_MAX];
    DIR *d = bps_proc_task_path (path, sizeof path, p->pid, 0, "task") == 0 ? opendir (path) : NULL;
    if (!d) return bps_list_add (l, p);
    size_t first = l->n;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        bps_proc t = { 0 };
        if (bps_read_task (p->pid, atoi (de->d_name), &t) == 0)
            rc = bps_list_add (l, &t);
    }
    closedir (d);
    if (rc == 0 && l->n == first) rc = bps_list_add (l, p);
    else if (rc == 0) qsort (l->v + first, l->n - first, sizeof *l->v, bps_compare_lwp);
    return rc;
}

/* -C CMDLIST: comma or blank separated command names (comm). */
static int
bps_add_name_list (const char *s, char names[][64], int *n, int max)
{
    char *copy = strdup (s);
    if (!copy) { builtin_error ("out of memory"); return -1; }
    int any = 0;
    for (char *save = NULL, *tok = strtok_r (copy, ", \t", &save); tok;
         tok = strtok_r (NULL, ", \t", &save)) {
        if (*n >= max) { builtin_error ("too many command names"); free (copy); return -1; }
        snprintf (names[(*n)++], 64, "%s", tok);
        any = 1;
    }
    free (copy);
    if (!any) { builtin_error ("list of command names must follow -C"); return -1; }
    return 0;
}

/* procps ps's usage error: "error: WHY" with no command prefix, then its
   usage block, all on stderr; the caller returns 1. */
static void
bps_usage_error (const char *why)
{
    const char *name = bos_shim_prog_name ("ps");
    fflush (stdout);
    fprintf (stderr, "error: %s\n\nUsage:\n %s [options]\n\n"
             " Try '%s --help <simple|list|output|threads|misc|all>'\n"
             "  or '%s --help <s|l|o|t|m|a>'\n"
             " for additional help text.\n\n"
             "For more details see ps(1).\n", why, name, name, name);
}

/* Output keys, from procps ps(1)'s STANDARD FORMAT SPECIFIERS and the
   observed procps-ng layout: each key has a header, a minimum width and an
   alignment. Columns are separated by one blank. A left-aligned text value
   wider than its column is cut to the width unless it is the last column;
   user and group names are cut with a '+' mark everywhere. A right-aligned
   value wider than its column takes blanks from the left, keeping one
   blank after the previous value, and later columns move over by what it
   could not take. */
typedef enum {
    K_PID, K_PPID, K_PGRP, K_SID, K_TPGID, K_LWP, K_NLWP,
    K_EUID, K_RUID, K_SUID, K_FSUID, K_EGID, K_RGID, K_SGID, K_FSGID,
    K_EUSER, K_RUSER, K_SUSER, K_FSUSER, K_EGROUP, K_RGROUP, K_SGROUP, K_FSGROUP,
    K_STATE, K_STAT, K_COMM, K_FNAME, K_ARGS,
    K_TIME, K_BSDTIME, K_STIME, K_START, K_BSDSTART, K_LSTART, K_ETIME, K_ETIMES,
    K_PCPU, K_PMEM, K_C, K_RSS, K_VSZ, K_SZ,
    K_NI, K_PRI, K_OPRI, K_PRIORITY, K_PSR, K_CLS, K_POLICY, K_SCHED, K_RTPRIO, K_F,
    K_TTY, K_WCHAN, K_ADDR, K_EXE, K_TTYBYTES
} bps_col;

#define BPS_NUM   0x1     /* sorts numerically */
#define BPS_NAME  0x2     /* a user or group name: cut with '+' */
#define BPS_CUT   0x4     /* text cut to the width unless last */

typedef struct {
    const char *name;     /* -o name; '_' names are internal to the built-in formats */
    const char *header;
    int width;
    char align;           /* 'L' or 'R' */
    int flags;
    bps_col col;
} bps_key;

static const bps_key bps_keys[] = {
    { "pid",        "PID",      7, 'R', BPS_NUM, K_PID },
    { "ppid",       "PPID",     7, 'R', BPS_NUM, K_PPID },
    { "pgrp",       "PGRP",     7, 'R', BPS_NUM, K_PGRP },
    { "pgid",       "PGID",     7, 'R', BPS_NUM, K_PGRP },
    { "sid",        "SID",      7, 'R', BPS_NUM, K_SID },
    { "sess",       "SESS",     7, 'R', BPS_NUM, K_SID },
    { "session",    "SESS",     7, 'R', BPS_NUM, K_SID },
    { "tpgid",      "TPGID",    7, 'R', BPS_NUM, K_TPGID },
    { "lwp",        "LWP",      7, 'R', BPS_NUM, K_LWP },
    { "tid",        "TID",      7, 'R', BPS_NUM, K_LWP },
    { "spid",       "SPID",     7, 'R', BPS_NUM, K_LWP },
    { "nlwp",       "NLWP",     4, 'R', BPS_NUM, K_NLWP },
    { "thcount",    "THCNT",    5, 'R', BPS_NUM, K_NLWP },
    { "uid",        "UID",      5, 'R', BPS_NUM, K_EUID },
    { "euid",       "EUID",     5, 'R', BPS_NUM, K_EUID },
    { "ruid",       "RUID",     5, 'R', BPS_NUM, K_RUID },
    { "suid",       "SUID",     5, 'R', BPS_NUM, K_SUID },
    { "svuid",      "SVUID",    5, 'R', BPS_NUM, K_SUID },
    { "fsuid",      "FSUID",    5, 'R', BPS_NUM, K_FSUID },
    { "gid",        "GID",      5, 'R', BPS_NUM, K_EGID },
    { "egid",       "EGID",     5, 'R', BPS_NUM, K_EGID },
    { "rgid",       "RGID",     5, 'R', BPS_NUM, K_RGID },
    { "sgid",       "SGID",     5, 'R', BPS_NUM, K_SGID },
    { "svgid",      "SVGID",    5, 'R', BPS_NUM, K_SGID },
    { "fsgid",      "FSGID",    5, 'R', BPS_NUM, K_FSGID },
    { "fgid",       "FGID",     5, 'R', BPS_NUM, K_FSGID },
    { "user",       "USER",     8, 'L', BPS_NAME, K_EUSER },
    { "euser",      "EUSER",    8, 'L', BPS_NAME, K_EUSER },
    { "uname",      "USER",     8, 'L', BPS_NAME, K_EUSER },
    { "_uidname",   "UID",      8, 'L', BPS_NAME, K_EUSER },
    { "ruser",      "RUSER",    8, 'L', BPS_NAME, K_RUSER },
    { "suser",      "SUSER",    8, 'L', BPS_NAME, K_SUSER },
    { "svuser",     "SVUSER",   8, 'L', BPS_NAME, K_SUSER },
    { "fsuser",     "FSUSER",   8, 'L', BPS_NAME, K_FSUSER },
    { "fuser",      "FUSER",    8, 'L', BPS_NAME, K_FSUSER },
    { "group",      "GROUP",    8, 'L', BPS_NAME, K_EGROUP },
    { "egroup",     "EGROUP",   8, 'L', BPS_NAME, K_EGROUP },
    { "rgroup",     "RGROUP",   8, 'L', BPS_NAME, K_RGROUP },
    { "sgroup",     "SGROUP",   8, 'L', BPS_NAME, K_SGROUP },
    { "svgroup",    "SVGROUP",  8, 'L', BPS_NAME, K_SGROUP },
    { "fsgroup",    "FSGROUP",  8, 'L', BPS_NAME, K_FSGROUP },
    { "fgroup",     "FGROUP",   8, 'L', BPS_NAME, K_FSGROUP },
    { "state",      "S",        1, 'L', 0, K_STATE },
    { "s",          "S",        1, 'L', 0, K_STATE },
    { "stat",       "STAT",     4, 'L', 0, K_STAT },
    { "comm",       "COMMAND", 15, 'L', BPS_CUT, K_COMM },
    { "ucmd",       "CMD",     15, 'L', BPS_CUT, K_COMM },
    { "ucomm",      "COMMAND", 15, 'L', BPS_CUT, K_COMM },
    { "fname",      "COMMAND",  8, 'L', BPS_CUT, K_FNAME },
    { "args",       "COMMAND", 27, 'L', BPS_CUT, K_ARGS },
    { "command",    "COMMAND", 27, 'L', BPS_CUT, K_ARGS },
    { "cmd",        "CMD",     27, 'L', BPS_CUT, K_ARGS },
    { "time",       "TIME",     8, 'R', BPS_NUM, K_TIME },
    { "cputime",    "TIME",     8, 'R', BPS_NUM, K_TIME },
    { "bsdtime",    "TIME",     6, 'R', BPS_NUM, K_BSDTIME },
    { "stime",      "STIME",    5, 'R', BPS_NUM, K_STIME },
    { "start_time", "START",    5, 'R', BPS_NUM, K_STIME },
    { "start",      "STARTED",  8, 'R', BPS_NUM, K_START },
    { "bsdstart",   "START",    6, 'R', BPS_NUM, K_BSDSTART },
    { "lstart",     "STARTED", 24, 'R', BPS_NUM, K_LSTART },
    { "etime",      "ELAPSED", 11, 'R', BPS_NUM, K_ETIME },
    { "etimes",     "ELAPSED",  7, 'R', BPS_NUM, K_ETIMES },
    { "%cpu",       "%CPU",     4, 'R', BPS_NUM, K_PCPU },
    { "pcpu",       "%CPU",     4, 'R', BPS_NUM, K_PCPU },
    { "%mem",       "%MEM",     4, 'R', BPS_NUM, K_PMEM },
    { "pmem",       "%MEM",     4, 'R', BPS_NUM, K_PMEM },
    { "c",          "C",        2, 'R', BPS_NUM, K_C },
    { "rss",        "RSS",      5, 'R', BPS_NUM, K_RSS },
    { "rssize",     "RSS",      5, 'R', BPS_NUM, K_RSS },
    { "rsz",        "RSZ",      5, 'R', BPS_NUM, K_RSS },
    { "vsz",        "VSZ",      6, 'R', BPS_NUM, K_VSZ },
    { "vsize",      "VSZ",      6, 'R', BPS_NUM, K_VSZ },
    { "sz",         "SZ",       5, 'R', BPS_NUM, K_SZ },
    { "_szl",       "SZ",       2, 'R', BPS_NUM, K_SZ },
    { "ni",         "NI",       3, 'R', BPS_NUM, K_NI },
    { "nice",       "NI",       3, 'R', BPS_NUM, K_NI },
    { "pri",        "PRI",      3, 'R', BPS_NUM, K_PRI },
    { "_opri",      "PRI",      3, 'R', BPS_NUM, K_OPRI },
    { "priority",   "PRI",      3, 'R', BPS_NUM, K_PRIORITY },
    { "psr",        "PSR",      3, 'R', BPS_NUM, K_PSR },
    { "cls",        "CLS",      3, 'R', 0, K_CLS },
    { "class",      "CLS",      3, 'L', 0, K_CLS },
    { "policy",     "POL",      3, 'L', 0, K_POLICY },
    { "sched",      "SCH",      3, 'R', BPS_NUM, K_SCHED },
    { "rtprio",     "RTPRIO",   6, 'R', BPS_NUM, K_RTPRIO },
    { "f",          "F",        1, 'R', BPS_NUM, K_F },
    { "flags",      "F",        1, 'R', BPS_NUM, K_F },
    { "tty",        "TT",       8, 'L', BPS_CUT, K_TTY },
    { "tt",         "TT",       8, 'L', BPS_CUT, K_TTY },
    { "tname",      "TTY",      8, 'L', BPS_CUT, K_TTY },
    { "wchan",      "WCHAN",    6, 'L', BPS_CUT, K_WCHAN },
    { "addr",       "ADDR",     4, 'R', 0, K_ADDR },
    { "_addrl",     "ADDR",     4, 'L', 0, K_ADDR },
    { "exe",        "EXE",     27, 'L', BPS_CUT, K_EXE },
    { "ttybytes",   "TTYBYTES", 8, 'L', 0, K_TTYBYTES },
};

typedef struct {
    const bps_key *key;
    char header[64];      /* the key's, or the -o NAME=HEADER text */
    int width;
} bps_colspec;

static const bps_key *
bps_key_find (const char *name, int internal)
{
    if (name[0] == '_' && !internal) return NULL;
    for (size_t i = 0; i < sizeof bps_keys / sizeof bps_keys[0]; i++)
        if (strcmp (name, bps_keys[i].name) == 0)
            return &bps_keys[i];
    return NULL;
}

static int
bps_col_set (bps_colspec *c, const bps_key *k, const char *header)
{
    c->key = k;
    snprintf (c->header, sizeof c->header, "%s", header ? header : k->header);
    int hl = (int) strlen (c->header);
    c->width = hl > k->width ? hl : k->width;
    return 0;
}

/* Append the built-in format NAMES (blank separated, internal names allowed). */
static void
bps_add_format (const char *names, bps_colspec *cols, int *n_cols)
{
    char buf[512];
    snprintf (buf, sizeof buf, "%s", names);
    for (char *save = NULL, *tok = strtok_r (buf, " ", &save); tok; tok = strtok_r (NULL, " ", &save)) {
        const bps_key *k = bps_key_find (tok, 1);
        if (k && *n_cols < BPS_MAX_COLS) bps_col_set (&cols[(*n_cols)++], k, NULL);
    }
}

/* -o LIST: comma or blank separated names, each optionally NAME=HEADER. */
static int
bps_add_o_list (const char *list, bps_colspec *cols, int *n_cols)
{
    char buf[512];
    size_t n = strlen (list);
    if (n >= sizeof buf) {
        bps_usage_error ("improper list");
        return -1;
    }
    memcpy (buf, list, n + 1);
    char *save = NULL;
    for (char *tok = strtok_r (buf, ", \t", &save); tok; tok = strtok_r (NULL, ", \t", &save)) {
        const char *ovr = NULL;
        char *eq = strchr (tok, '=');
        if (eq) { ovr = eq + 1; *eq = '\0'; }
        const bps_key *k = *tok ? bps_key_find (tok, 0) : NULL;
        if (!k) {
            char why[320];
            snprintf (why, sizeof why, "unknown user-defined format specifier \"%s\"", tok);
            bps_usage_error (why);
            return -1;
        }
        if (*n_cols >= BPS_MAX_COLS) {
            bps_usage_error ("too many output columns");
            return -1;
        }
        bps_col_set (&cols[(*n_cols)++], k, ovr);
    }
    return 0;
}

static const char *
bps_group (gid_t gid)
{
    static char buf[32];
    struct group *gr = getgrgid (gid);
    if (gr) return gr->gr_name;
    snprintf (buf, sizeof buf, "%u", (unsigned) gid);
    return buf;
}

static const char *
bps_policy_name (long policy)
{
    switch (policy) {
        case 0: return "TS";
        case 1: return "FF";
        case 2: return "RR";
        case 3: return "B";
        case 5: return "IDL";
        case 6: return "DLN";
    }
    return "?";
}

/* procps cumulative CPU time: [DD-]hh:mm:ss. */
static void
bps_fmt_cputime (long ticks, char *buf, size_t bufsz)
{
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    long t = ticks / hz;
    long d = t / 86400, h = t / 3600 % 24, m = t / 60 % 60, s = t % 60;
    if (d) snprintf (buf, bufsz, "%ld-%02ld:%02ld:%02ld", d, h, m, s);
    else snprintf (buf, bufsz, "%02ld:%02ld:%02ld", h, m, s);
}

/* START (start) shows hh:mm:ss within a day, else "Mmm dd"; bsdstart
   shows hh:mm within a day, else "Mmm dd". */
static void
bps_fmt_start (long ticks_since_boot, int bsd, char *buf, size_t bufsz)
{
    struct tm tm_start;
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    if (!bps_start_localtime (ticks_since_boot, &tm_start)) { snprintf (buf, bufsz, "?"); return; }
    long age = bps_uptime () - (double) ticks_since_boot / hz;
    if (age < 86400)
        strftime (buf, bufsz, bsd ? "%H:%M" : "%H:%M:%S", &tm_start);
    else
        strftime (buf, bufsz, "%b %d", &tm_start);
}

static void
bps_read_small (const bps_proc *p, const char *name, int link, char *buf, size_t bufsz)
{
    char path[BPS_PATH_MAX];
    buf[0] = '\0';
    if (bps_proc_pid_path (path, sizeof path, p->pid, name) < 0) return;
    if (link) {
        ssize_t n = readlink (path, buf, bufsz - 1);
        buf[n > 0 ? n : 0] = '\0';
        return;
    }
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read (fd, buf, bufsz - 1);
    close (fd);
    buf[n > 0 ? n : 0] = '\0';
    buf[strcspn (buf, "\n")] = '\0';
}

static int
bps_is_rt (const bps_proc *p)
{
    return p->policy == 1 || p->policy == 2;
}

/* Numeric sort value of a key; text keys compare as formatted. */
static long long
bps_num_value (const bps_proc *p, bps_col col)
{
    switch (col) {
        case K_PID: return p->pid;
        case K_PPID: return p->ppid;
        case K_PGRP: return p->pgrp;
        case K_SID: return p->sid;
        case K_TPGID: return p->tpgid;
        case K_LWP: return p->lwp;
        case K_NLWP: return p->num_threads;
        case K_EUID: return p->uid;
        case K_RUID: return p->ruid;
        case K_SUID: return p->suid;
        case K_FSUID: return p->fsuid;
        case K_EGID: return p->egid;
        case K_RGID: return p->rgid;
        case K_SGID: return p->sgid;
        case K_FSGID: return p->fsgid;
        case K_TIME: case K_BSDTIME: return p->utime + p->stime;
        case K_STIME: case K_START: case K_BSDSTART: case K_LSTART: return p->starttime_ticks;
        case K_ETIME: case K_ETIMES: return -p->starttime_ticks;
        case K_PCPU: case K_C: return (long long) (bps_cpu_percent (p) * 10);
        case K_PMEM: case K_RSS: return bps_rss_kb (p);
        case K_VSZ: case K_SZ: return p->vsize_bytes;
        case K_NI: return p->nice;
        case K_PRI: case K_OPRI: case K_PRIORITY: return -p->priority;
        case K_PSR: return p->processor;
        case K_SCHED: return p->policy;
        case K_RTPRIO: return p->rt_priority;
        case K_F: return (long long) p->flags;
        default: return 0;
    }
}

static void
bps_value (const bps_proc *p, bps_col col, char *buf, size_t n)
{
    long page = sysconf (_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    switch (col) {
        case K_PID:   snprintf (buf, n, "%d", p->pid); break;
        case K_PPID:  snprintf (buf, n, "%d", p->ppid); break;
        case K_PGRP:  snprintf (buf, n, "%d", p->pgrp); break;
        case K_SID:   snprintf (buf, n, "%d", p->sid); break;
        case K_TPGID: snprintf (buf, n, "%d", p->tpgid); break;
        case K_LWP:   snprintf (buf, n, "%d", p->lwp); break;
        case K_NLWP:  snprintf (buf, n, "%ld", p->num_threads); break;
        case K_EUID:  snprintf (buf, n, "%u", (unsigned) p->uid); break;
        case K_RUID:  snprintf (buf, n, "%u", (unsigned) p->ruid); break;
        case K_SUID:  snprintf (buf, n, "%u", (unsigned) p->suid); break;
        case K_FSUID: snprintf (buf, n, "%u", (unsigned) p->fsuid); break;
        case K_EGID:  snprintf (buf, n, "%u", (unsigned) p->egid); break;
        case K_RGID:  snprintf (buf, n, "%u", (unsigned) p->rgid); break;
        case K_SGID:  snprintf (buf, n, "%u", (unsigned) p->sgid); break;
        case K_FSGID: snprintf (buf, n, "%u", (unsigned) p->fsgid); break;
        case K_EUSER:  snprintf (buf, n, "%s", bps_user (p->uid)); break;
        case K_RUSER:  snprintf (buf, n, "%s", bps_user (p->ruid)); break;
        case K_SUSER:  snprintf (buf, n, "%s", bps_user (p->suid)); break;
        case K_FSUSER: snprintf (buf, n, "%s", bps_user (p->fsuid)); break;
        case K_EGROUP:  snprintf (buf, n, "%s", bps_group (p->egid)); break;
        case K_RGROUP:  snprintf (buf, n, "%s", bps_group (p->rgid)); break;
        case K_SGROUP:  snprintf (buf, n, "%s", bps_group (p->sgid)); break;
        case K_FSGROUP: snprintf (buf, n, "%s", bps_group (p->fsgid)); break;
        case K_STATE: snprintf (buf, n, "%c", p->state); break;
        case K_STAT:  bps_build_stat (p, buf, n); break;
        case K_COMM:  bps_command (p, 0, buf, n); break;
        case K_FNAME: snprintf (buf, n, "%.8s", p->comm); break;
        case K_ARGS:  bps_command (p, 1, buf, n); break;
        case K_TIME:  bps_fmt_cputime (p->utime + p->stime, buf, n); break;
        case K_BSDTIME: bps_fmt_aux_time (p->utime + p->stime, buf, n); break;
        case K_STIME: bps_fmt_stime (p->starttime_ticks, buf, n); break;
        case K_START: bps_fmt_start (p->starttime_ticks, 0, buf, n); break;
        case K_BSDSTART: bps_fmt_start (p->starttime_ticks, 1, buf, n); break;
        case K_LSTART: bps_fmt_lstart (p->starttime_ticks, buf, n); break;
        case K_ETIME: bps_fmt_etime (bps_elapsed (p), buf, n); break;
        case K_ETIMES: snprintf (buf, n, "%ld", bps_elapsed (p)); break;
        case K_PCPU:  snprintf (buf, n, "%.1f", bps_cpu_percent (p)); break;
        case K_PMEM:  snprintf (buf, n, "%.1f", bps_mem_percent (p)); break;
        case K_C:     snprintf (buf, n, "%d", (int) bps_cpu_percent (p)); break;
        case K_RSS:   snprintf (buf, n, "%ld", bps_rss_kb (p)); break;
        case K_VSZ:   snprintf (buf, n, "%ld", p->vsize_bytes / 1024); break;
        case K_SZ:    snprintf (buf, n, "%ld", p->vsize_bytes / page); break;
        case K_NI:
            if (bps_is_rt (p)) snprintf (buf, n, "-");
            else snprintf (buf, n, "%ld", p->nice);
            break;
        case K_PRI:   snprintf (buf, n, "%ld", 39 - p->priority); break;
        case K_OPRI:  snprintf (buf, n, "%ld", 60 + p->priority); break;
        case K_PRIORITY: snprintf (buf, n, "%ld", p->priority); break;
        case K_PSR:   snprintf (buf, n, "%ld", p->processor); break;
        case K_CLS:
        case K_POLICY: snprintf (buf, n, "%s", bps_policy_name (p->policy)); break;
        case K_SCHED: snprintf (buf, n, "%ld", p->policy); break;
        case K_RTPRIO:
            if (bps_is_rt (p)) snprintf (buf, n, "%ld", p->rt_priority);
            else snprintf (buf, n, "-");
            break;
        /* PF_FORKNOEXEC (1) and PF_SUPERPRIV (4), as ps -l shows them. */
        case K_F:     snprintf (buf, n, "%lu", (p->flags >> 6) & 5); break;
        case K_TTY:   bps_tty_name (p, buf, n); break;
        case K_WCHAN:
            bps_read_small (p, "wchan", 0, buf, n);
            if (!buf[0] || !strcmp (buf, "0")) snprintf (buf, n, "-");
            break;
        case K_ADDR:  snprintf (buf, n, "-"); break;
        case K_EXE:
            bps_read_small (p, "exe", 1, buf, n);
            if (!buf[0]) snprintf (buf, n, "-");
            break;
        case K_TTYBYTES: snprintf (buf, n, "?"); break;
    }
}

/* Lay out one line of TEXTS (values or headers) in COLS. */
static void
bps_print_line (const bps_colspec *cols, int n_cols, char texts[][512])
{
    char line[BPS_MAX_COLS * 520];
    size_t len = 0;           /* bytes in line, including padding */
    size_t content = 0;       /* end of the last nonblank value */
    size_t pos = 0;           /* nominal end of the previous column */
    for (int i = 0; i < n_cols; i++) {
        const bps_key *k = cols[i].key;
        int last = i == n_cols - 1;
        char *t = texts[i];
        size_t w = (size_t) cols[i].width, l = strlen (t);
        size_t start = i ? pos + 1 : 0;
        if ((k->flags & BPS_NAME) && l > w && w > 0) {
            t[w - 1] = '+';
            t[w] = '\0';
            l = w;
        } else if ((k->flags & BPS_CUT) && !last && l > w) {
            t[w] = '\0';
            l = w;
        }
        /* At least one blank after the previous value. */
        size_t min = i ? content + 1 : 0;
        size_t at;
        if (k->align == 'R') {
            size_t end = start + w;
            at = end >= l ? end - l : 0;
            if (at < min) at = min;
            pos = at + l > end ? at + l : end;
        } else {
            at = start > min ? start : min;
            pos = at + w > at + l ? at + w : at + l;
        }
        while (len < at && len < sizeof line - 1) line[len++] = ' ';
        if (len > at) len = at;
        if (len + l >= sizeof line) l = sizeof line - 1 - len;
        memcpy (line + len, t, l);
        len += l;
        if (l) content = len;
    }
    /* Right-aligned values already end at their column; left-aligned last
       values stop at their text. */
    line[len] = '\0';
    puts (line);
}

static void
bps_print_header (const bps_colspec *cols, int n_cols)
{
    static char texts[BPS_MAX_COLS][512];
    int any = 0;
    for (int i = 0; i < n_cols; i++) {
        snprintf (texts[i], sizeof texts[i], "%s", cols[i].header);
        if (cols[i].header[0]) any = 1;
    }
    if (any) bps_print_line (cols, n_cols, texts);
}

static void
bps_print_row (const bps_proc *p, const bps_colspec *cols, int n_cols)
{
    static char texts[BPS_MAX_COLS][512];
    for (int i = 0; i < n_cols; i++)
        bps_value (p, cols[i].key->col, texts[i], sizeof texts[i]);
    bps_print_line (cols, n_cols, texts);
}

#define BPS_MAX_SORT 16
typedef struct { const bps_key *key; int desc; } bps_sortkey;
static bps_sortkey bps_sort_keys[BPS_MAX_SORT];
static int bps_n_sort;

/* --sort=[+|-]KEY[,[+|-]KEY]...; KEY is any -o key name. */
static int
bps_add_sort (const char *spec)
{
    char buf[256];
    size_t len = strlen (spec);
    if (len == 0 || len >= sizeof buf) goto bad;
    memcpy (buf, spec, len + 1);
    for (char *save = NULL, *tok = strtok_r (buf, ",", &save); tok;
         tok = strtok_r (NULL, ",", &save)) {
        int desc = 0;
        if (*tok == '+' || *tok == '-') desc = *tok++ == '-';
        const bps_key *k = bps_key_find (tok, 0);
        if (bps_n_sort >= BPS_MAX_SORT || !k) goto bad;
        bps_sort_keys[bps_n_sort].key = k;
        bps_sort_keys[bps_n_sort++].desc = desc;
    }
    return 0;
bad:
    builtin_error ("unknown sort specifier");
    builtin_usage ();
    return -1;
}

static int
bps_compare_key (const bps_proc *a, const bps_proc *b, const bps_key *k)
{
    if (k->flags & BPS_NUM) {
        long long x = bps_num_value (a, k->col), y = bps_num_value (b, k->col);
        return x < y ? -1 : x > y;
    }
    char x[512], y[512];
    bps_value (a, k->col, x, sizeof x);
    bps_value (b, k->col, y, sizeof y);
    return strcmp (x, y);
}

static int
bps_cmp_long (long a, long b)
{
    return a < b ? -1 : a > b;
}

static int
bps_compare (const void *x, const void *y)
{
    const bps_proc *a = x, *b = y;
    for (int i = 0; i < bps_n_sort; i++) {
        int c = bps_compare_key (a, b, bps_sort_keys[i].key);
        if (c) return bps_sort_keys[i].desc ? -c : c;
    }
    /* Keep /proc order (pid, then thread id) between equal keys. */
    int c = bps_cmp_long (a->pid, b->pid);
    return c ? c : bps_cmp_long (a->lwp, b->lwp);
}

/* A BSD-syntax option word (no dash): procps' a, u, x, j, l and w. */
static int
bps_bsd_word (const char *s)
{
    if (!s[0] || !isalpha ((unsigned char) s[0])) return 0;
    for (const char *p = s; *p; p++)
        if (!strchr ("auxjlw", *p)) return -1;
    return 1;
}

/* Replace the blank-delimited word FROM in S with TO. */
static void
bps_format_replace (char *s, size_t size, const char *from, const char *to)
{
    char pat[64], out[512];
    snprintf (pat, sizeof pat, " %s ", from);
    char padded[512];
    snprintf (padded, sizeof padded, " %s ", s);
    char *hit = strstr (padded, pat);
    if (!hit) return;
    *hit = '\0';
    snprintf (out, sizeof out, "%s %s %s", padded, to, hit + strlen (pat));
    /* trim the padding again */
    char *b = out;
    while (*b == ' ') b++;
    size_t n = strlen (b);
    while (n && b[n - 1] == ' ') b[--n] = '\0';
    snprintf (s, size, "%s", b);
}

int
ps_builtin (WORD_LIST *list)
{
    int all = 0, full = 0, Full = 0, longf = 0, jobs = 0, yflag = 0;
    int bsd = 0, bsd_a = 0, bsd_x = 0, bsd_u = 0, bsd_j = 0, bsd_l = 0, bsd_operand = 0;
    bps_colspec cols[BPS_MAX_COLS];
    int n_cols = 0;
    int explicit_pids[256];
    int n_pids = 0;
    uid_t euids[64], ruids[64];
    int n_euids = 0, n_ruids = 0;
    char cmds[64][64];
    int n_cmds = 0;
    int ppids[256];
    int n_ppids = 0;
    int no_headers = 0, threads = 0, end_options = 0;
    bps_list procs = { 0 };
    int rc = EXECUTION_SUCCESS;

    bps_n_sort = 0;
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (end_options || w[0] != '-' || !w[1]) {
            int b = bps_bsd_word (w);
            if (b < 0) {
                bps_usage_error ("unsupported option (BSD syntax)");
                return EXECUTION_FAILURE;
            }
            if (b > 0) {
                bsd = 1;
                for (const char *c = w; *c; c++)
                    switch (*c) {
                        case 'a': bsd_a = 1; break;
                        case 'x': bsd_x = 1; break;
                        case 'u': bsd_u = 1; break;
                        case 'j': bsd_j = 1; break;
                        case 'l': bsd_l = 1; break;
                    }
                continue;
            }
            /* A bare PID selects it, as -p does, with BSD-style output. */
            if (bps_add_pid_operand (w, explicit_pids, &n_pids,
                                     (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EXECUTION_FAILURE;
            bsd_operand = 1;
            continue;
        }
        if (!strcmp (w, "--")) { end_options = 1; continue; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashps 1.0 (bash-loadable, procps-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--no-headers") || !strcmp (w, "--no-heading") ||
            !strcmp (w, "--noheaders") || !strcmp (w, "--noheading")) {
            no_headers = 1;
            continue;
        }
        if (!strcmp (w, "--pid") || !strcmp (w, "--ppid") || !strcmp (w, "--sort")
            || !strcmp (w, "--format")) {
            const char *opt = w;
            list = list->next;
            if (!list) {
                builtin_error ("option %s requires an argument", opt);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            int bad = opt[2] == 's' ? bps_add_sort (list->word->word)
                    : opt[2] == 'f' ? bps_add_o_list (list->word->word, cols, &n_cols)
                    : opt[3] == 'i' ? bps_add_pid_list (list->word->word, explicit_pids, &n_pids,
                                                        (int) (sizeof explicit_pids / sizeof explicit_pids[0]))
                    : bps_add_pid_list (list->word->word, ppids, &n_ppids,
                                        (int) (sizeof ppids / sizeof ppids[0]));
            if (bad < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (!strncmp (w, "--pid=", 6)) {
            if (bps_add_pid_list (w + 6, explicit_pids, &n_pids,
                                  (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (!strncmp (w, "--ppid=", 7)) {
            if (bps_add_pid_list (w + 7, ppids, &n_ppids, (int) (sizeof ppids / sizeof ppids[0])) < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (!strncmp (w, "--sort=", 7)) {
            if (bps_add_sort (w + 7) < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (!strncmp (w, "--format=", 9)) {
            if (bps_add_o_list (w + 9, cols, &n_cols) < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (!strncmp (w, "--user=", 7) || !strncmp (w, "--User=", 7)) {
            if (bps_add_user_list (w + 7, w[2] == 'u' ? euids : ruids,
                                   w[2] == 'u' ? &n_euids : &n_ruids, 64) < 0)
                return EXECUTION_FAILURE;
            continue;
        }
        if (w[1] == '-') {
            bps_usage_error ("unknown gnu long option");
            return EXECUTION_FAILURE;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case 'e': case 'A': all = 1; break;
                case 'f':           full = 1; break;
                case 'F':           Full = 1; break;
                case 'l':           longf = 1; break;
                case 'j':           jobs = 1; break;
                case 'y':           yflag = 1; break;
                case 'w':           break;
                case 'L':           threads = 1; break;
                case 'o': case 'p': case 'u': case 'U': case 'C': {
                    /* Argument-taking options inside a combined token, e.g.
                       procps `ps -eo comm` or `ps -ep PID`. The remainder of
                       the token after this letter is the argument; if empty
                       the next word is consumed. */
                    char opt = *c;
                    const char *arg = c + 1;
                    if (*arg == '\0') {
                        list = list->next;
                        if (!list) {
                            builtin_error (opt == 'o'
                                ? "option -o requires a column list"
                                : opt == 'p' ? "option -p requires a PID list"
                                : opt == 'C' ? "list of command names must follow -C"
                                : "list of users must follow -%c", opt);
                            builtin_usage ();
                            return EXECUTION_FAILURE;
                        }
                        arg = list->word->word;
                    }
                    if (opt == 'u' || opt == 'U') {
                        if (bps_add_user_list (arg, opt == 'u' ? euids : ruids,
                                               opt == 'u' ? &n_euids : &n_ruids, 64) < 0)
                            return EXECUTION_FAILURE;
                    } else if (opt == 'C') {
                        if (bps_add_name_list (arg, cmds, &n_cmds, 64) < 0)
                            return EXECUTION_FAILURE;
                    } else if (opt == 'o') {
                        if (bps_add_o_list (arg, cols, &n_cols) < 0)
                            return EXECUTION_FAILURE;
                    } else {
                        if (bps_add_pid_list (arg, explicit_pids, &n_pids,
                                              (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                            return EXECUTION_FAILURE;
                    }
                    goto next_word;
                }
                case 'V':
                    if (c[1] != '\0' || c != w + 1) {
                        bps_usage_error ("the option is exclusive: -V");
                        return EXECUTION_FAILURE;
                    }
                    puts ("ps 1.0 (bash-loadable, procps-compatible)");
                    return EXECUTION_SUCCESS;
                default:
                    bps_usage_error ("unsupported SysV option");
                    return EXECUTION_FAILURE;
            }
        }
    next_word:
        ;
    }

    if (n_cols > 0 && (longf || Full || jobs || bsd_u || bsd_j || bsd_l)) {
        bps_usage_error ("conflicting format options");
        return EXECUTION_FAILURE;
    }
    if (n_cols == 0) {
        char fmt[512];
        int sysv_full = full || Full;
        if (bsd_u)
            snprintf (fmt, sizeof fmt, "user pid pcpu pmem vsz rss tname stat start_time bsdtime args");
        else if (bsd_j)
            snprintf (fmt, sizeof fmt, "ppid pid pgid sid tname tpgid stat uid bsdtime args");
        else if (bsd_l)
            snprintf (fmt, sizeof fmt, "f uid pid ppid priority ni vsz rss wchan stat tname bsdtime args");
        else if (longf)
            snprintf (fmt, sizeof fmt, "%s state %s pid ppid%s c%s _opri ni %s wchan%s%s tname time %s",
                      yflag ? "" : "f", sysv_full ? "_uidname" : "uid",
                      threads ? " lwp" : "", threads && sysv_full ? " nlwp" : "",
                      yflag ? "rss sz" : "_addrl _szl",
                      Full ? " rss psr" : "", sysv_full ? " stime" : "",
                      sysv_full ? "cmd" : "ucmd");
        else if (Full)
            snprintf (fmt, sizeof fmt, "_uidname pid ppid%s c%s sz rss psr stime tname time cmd",
                      threads ? " lwp" : "", threads ? " nlwp" : "");
        else if (full)
            snprintf (fmt, sizeof fmt, "_uidname pid ppid%s%s c%s stime tname time cmd",
                      jobs ? " pgid sid" : "", threads ? " lwp" : "", threads ? " nlwp" : "");
        else if (jobs)
            snprintf (fmt, sizeof fmt, "pid%s pgid sid tname time ucmd", threads ? " lwp" : "");
        else if (bsd || bsd_operand)
            snprintf (fmt, sizeof fmt, "pid%s tname stat bsdtime args", threads ? " lwp" : "");
        else
            snprintf (fmt, sizeof fmt, "pid%s tname time ucmd", threads ? " lwp" : "");
        /* procps switches a SysV format to BSD times and the full command
           for bare PID operands; formats other than -l also show STAT. */
        if (bsd_operand && !bsd && (sysv_full || longf || jobs)) {
            bps_format_replace (fmt, sizeof fmt, "time", longf ? "bsdtime" : "stat bsdtime");
            bps_format_replace (fmt, sizeof fmt, "ucmd", longf ? "cmd" : "args");
        }
        bps_add_format (fmt, cols, &n_cols);
    }

    /* procps selections add up: a process is listed when it matches any of
       -p, -u, -U, -C, --ppid, or BSD a (has a terminal) / x (own process);
       every process with -e or ax, or when nothing selects. */
    int by_select = n_pids > 0 || n_euids > 0 || n_ruids > 0 || n_cmds > 0 || n_ppids > 0
                    || bsd_a || bsd_x;
    if ((bsd_a && bsd_x) || !by_select) all = 1;
    uid_t self = geteuid ();

    DIR *d = opendir (bps_proc_root ());
    if (!d) { builtin_error ("opendir %s: %s", bps_proc_root (), strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        bps_proc p = { 0 };
        if (bps_read_stat (pid, &p) != 0) continue;
        if (!all) {
            int keep = bps_uid_in (p.uid, euids, n_euids) ||
                       bps_uid_in (p.ruid, ruids, n_ruids) ||
                       (bsd_x && p.uid == self) || (bsd_a && p.tty_nr != 0);
            for (int i = 0; !keep && i < n_pids; i++)
                keep = explicit_pids[i] == pid;
            for (int i = 0; !keep && i < n_ppids; i++)
                keep = ppids[i] == p.ppid;
            for (int i = 0; !keep && i < n_cmds; i++)
                keep = strncmp (cmds[i], p.comm, 15) == 0 && strlen (p.comm) == (strlen (cmds[i]) < 15 ? strlen (cmds[i]) : 15);
            if (!keep) continue;
        }
        if (bps_list_add_tasks (&procs, &p, threads) < 0) { closedir (d); free (procs.v); return EXECUTION_FAILURE; }
    }
    closedir (d);
    /* procps exits 1 when no process is listed; the header still prints. */
    if (procs.n == 0) rc = EXECUTION_FAILURE;
    /* A /proc walk is listed in pid order, as procps does. procs.v is NULL
       when nothing matched; qsort must not see it. */
    if (procs.n > 1)
        qsort (procs.v, procs.n, sizeof *procs.v, bps_compare);

    if (!no_headers)
        bps_print_header (cols, n_cols);
    for (size_t i = 0; i < procs.n; i++)
        bps_print_row (&procs.v[i], cols, n_cols);
    free (procs.v);
    return rc;
}

char *ps_doc[] = {
    "List processes via /proc (POSIX-shape ps).",
    "",
    "    bashps [-efFjlLy] [-o KEY[=HEADER],...] [-p PIDLIST] [-u|-U USERLIST] [-C CMDLIST]",
    "           [--ppid PIDLIST] [--sort=[+|-]KEY,...] [--no-headers] [PID...]",
    "    bashps [aux] [j|l|u] [PID...]",
    "",
    "    -e        all processes (default if nothing selects)",
    "    -f        full format: UID PID PPID C STIME TTY TIME CMD",
    "    -F        extra full format: adds SZ RSS PSR",
    "    -l        long format: F S UID PID PPID C PRI NI ADDR SZ WCHAN TTY TIME CMD",
    "              (-y with -l: RSS and SZ in place of F and ADDR)",
    "    -j        jobs format: PID PGID SID TTY TIME CMD",
    "    a x       BSD selection: processes with a terminal, your own processes",
    "    u j l     BSD user, job and long formats (aux: everything, user format)",
    "    -p LIST   select comma-separated process IDs (also --pid=LIST)",
    "    -u LIST   select by effective user name or ID (also --user=LIST)",
    "    -U LIST   select by real user name or ID (also --User=LIST)",
    "    -C LIST   select by command name (comm)",
    "    --ppid LIST  select by parent process ID (selections add up)",
    "    -L        one line per thread (adds the LWP column)",
    "    --sort=[+|-]KEY,...  order by -o key names (- descending)",
    "    --no-headers  omit the header row (also --no-heading)",
    "    -o LIST   custom columns (also --format=LIST); procps keys:",
    "              pid ppid pgrp pgid sid sess tpgid lwp tid spid nlwp thcount",
    "              uid euid ruid suid fsuid gid egid rgid sgid fsgid",
    "              user euser ruser suser fsuser group egroup rgroup sgroup fsgroup",
    "              state s stat comm ucmd fname args command cmd exe",
    "              time cputime bsdtime stime start_time start bsdstart lstart",
    "              etime etimes %cpu pcpu %mem pmem c rss rsz vsz sz",
    "              ni pri priority psr cls class policy sched rtprio f flags",
    "              tty tt tname wchan addr ttybytes",
    "              repeat -o to append columns; use key= to leave a heading blank",
    "              if all headings are blank, omit the header row",
    "    --help    print usage information and exit",
    "    -V, --version",
    "              print version information and exit",
    "",
    "Columns are laid out as procps does. Without a format, output is",
    "`PID TTY TIME CMD` (`PID TTY STAT TIME COMMAND` for BSD forms and bare",
    "PID operands). CMD comes from /proc/PID/cmdline (or [comm] for kernel",
    "threads). ps exits 1 when no process is listed.",
    (char *)NULL
};

struct builtin bashps_struct = {
    "bashps",
    ps_builtin,
    BUILTIN_ENABLED,
    ps_doc,
    "bashps [-efFjlLy] [-o KEYS] [-p PIDLIST] [-u|-U USERLIST] [-C CMDLIST] [--ppid PIDLIST] [--sort=KEYS] [--no-headers] [PID...] | bashps [aux] [j|l|u] [PID...]",
    0
};
