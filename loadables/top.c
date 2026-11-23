/* SPDX-License-Identifier: MIT */
/* top.c — interactive top(1) over /proc + termraw-style termios.
 *
 *   top [--once|-b] [-n COUNT] [-d SEC] [-o COL] [-r N]
 *
 *   --once / -b   one snapshot, write to stdout, exit (smoke / batch).
 *   -n COUNT      run COUNT redraws, then exit (default: forever).
 *   -d SEC        refresh interval, integer seconds (default 2).
 *   -o COL        initial sort column: cpu, mem, pid, time (default cpu).
 *   -r N          row cap (max process rows, default = tty rows - 7).
 *
 * Interactive keys (TUI mode):
 *   q / ESC     exit
 *   space       redraw immediately
 *   Up / Down   scroll process list by one row
 *   PgUp / PgDn scroll process list by one page
 *   Home / End  jump to first / last process
 *   n           prompt for new refresh interval
 *   o / O       prompt for a sort column (cpu, mem, pid, time); Enter
 *               alone cycles cpu → mem → pid → time → cpu
 *   k           prompt for PID + signal, send signal
 *   r           prompt for PID + nice delta, renice
 *
 * Data sources:
 *   /proc/[pid]/stat       — pid, comm, state, ppid, utime+stime, rss, vsize
 *   /proc/[pid]/status     — Uid (for username via getpwuid)
 *   /proc/[pid]/cmdline    — full args (NUL-separated)
 *   /proc/stat             — total CPU jiffies for %CPU delta
 *   /proc/meminfo          — MemTotal/MemAvailable/SwapTotal/SwapFree
 *   /proc/loadavg          — load averages (1/5/15)
 *
 * Source counterparts consulted (none ported verbatim):
 *   research/refs/procps-ng/src/top/top.c   (canonical, big)
 *   research/refs/busybox/procps/top.c      (minimal)
 *   research/refs/toybox/toys/posix/top.c   (middle)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as ps.c. When statically linked
 * into bash, the combined binary is governed by bash's GPL-3+.
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
#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <poll.h>
#include <time.h>

/* Shared CSI/SS3 key decoder (vendored under scripts/loadables/_bl_key/,
 * flattened to builtins/_bl_key_bl_key.{c,h} by patch-bash-loadables.sh).
 * Bashtop uses it for arrow/PgUp/PgDn/Home/End scroll of the process
 * list — see btop_run_interactive's input dispatch. */
#include "_bl_key_bl_key.h"
#include "_bl_screen_screen.h"   /* ncurses-subset cell/diff TUI engine */

#include "loadables.h"

#define BTOP_BUF       4096
#define BTOP_MAX_PROCS 8192
#define BTOP_COMM_LEN  64
#define BTOP_ARGS_LEN  256

/* --- per-process snapshot ----------------------------------------------- */
typedef struct {
    int   pid;
    int   ppid;
    uid_t uid;
    char  state;
    char  comm[BTOP_COMM_LEN];
    char  args[BTOP_ARGS_LEN];
    long  utime;        /* jiffies */
    long  stime;        /* jiffies */
    long  rss_pages;    /* RSS in pages */
    long  vsize_bytes;
    long  nice;
    long  prio;         /* proc(5) field 18 */
    unsigned long long starttime; /* identity across PID reuse */
    /* derived */
    long  cpu_total;    /* utime + stime, current snapshot */
    long  cpu_delta;    /* (utime+stime) - prev (utime+stime) */
    double pcpu;        /* % of total cpu time in interval */
} btop_proc;

/* --- system-wide snapshot ------------------------------------------------ */
typedef struct {
    long  cpu_jiffies_total;  /* first eight fields of /proc/stat cpu line */
    long  mem_total_kb;
    long  mem_avail_kb;
    long  swap_total_kb;
    long  swap_free_kb;
    char  loadavg[64];
    int   nproc;              /* count populated in procs[] */
} btop_sys;

/* --- sort column enum --------------------------------------------------- */
typedef enum {
    BTOP_SORT_CPU = 0,
    BTOP_SORT_MEM,
    BTOP_SORT_PID,
    BTOP_SORT_TIME,
    BTOP_SORT__COUNT
} btop_sort;

static const char *btop_sort_name[BTOP_SORT__COUNT] = {
    "CPU", "MEM", "PID", "TIME"
};

/* --- prev-snapshot table (pid → prev cpu_total) ------------------------- */
typedef struct {
    int  pid;
    long cpu_total;
    unsigned long long starttime;
} btop_prev;

static btop_prev *btop_prev_tbl = NULL;
static int        btop_prev_n   = 0;
static long       btop_prev_total = 0;

/* Terminal lifecycle, raw mode, winsize, alt-screen and the diff-optimized
   frame emit are owned by the shared _bl_screen module (interactive mode). */

/* --- helpers ------------------------------------------------------------ */

static long
btop_page_size (void)
{
    long p = sysconf (_SC_PAGESIZE);
    return p > 0 ? p : 4096;
}

static const char *
btop_user (uid_t uid)
{
    static char buf[32];
    struct passwd *pw = getpwuid (uid);
    if (pw) return pw->pw_name;
    snprintf (buf, sizeof buf, "%u", (unsigned) uid);
    return buf;
}

/* Read /proc/[pid]/stat into p. Anchor on the LAST ')' to skip past comm
   (which may contain spaces or parentheses). */
static int
btop_read_stat (int pid, btop_proc *p)
{
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/stat", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *first = strchr (buf, '(');
    char *last  = strrchr (buf, ')');
    if (!first || !last || first >= last) return -1;
    size_t clen = (size_t)(last - first - 1);
    if (clen >= sizeof p->comm) clen = sizeof p->comm - 1;
    memcpy (p->comm, first + 1, clen);
    p->comm[clen] = '\0';

    /* Per proc(5): after `pid (comm) `:
       (3) state (4) ppid (5) pgrp (6) sid (7) tty_nr (8) tpgid (9) flags
       (10) minflt (11) cminflt (12) majflt (13) cmajflt
       (14) utime (15) stime (16) cutime (17) cstime
       (18) priority (19) nice ...
       (23) vsize (24) rss */
    char *rest = last + 2;
    int got = sscanf (rest,
        "%c %d %*d %*d %*d %*d %*u "             /* state ppid pgrp sid tty tpgid flags */
        "%*u %*u %*u %*u "                       /* minflt cminflt majflt cmajflt */
        "%ld %ld %*d %*d "                       /* utime stime cutime cstime */
        "%ld %ld "                               /* priority nice */
        "%*d %*d %llu "                           /* num_threads itrealvalue starttime */
        "%ld %ld",                               /* vsize rss */
        &p->state, &p->ppid,
        &p->utime, &p->stime,
        &p->prio, &p->nice, &p->starttime,
        &p->vsize_bytes, &p->rss_pages);
    if (got != 9) return -1;

    p->pid = pid;
    p->cpu_total = p->utime + p->stime;

    /* uid via /proc/PID/status */
    snprintf (path, sizeof path, "/proc/%d/status", pid);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    p->uid = 0;
    if (fd >= 0) {
        char sbuf[1024];
        ssize_t sn = read (fd, sbuf, sizeof sbuf - 1);
        close (fd);
        if (sn > 0) {
            sbuf[sn] = '\0';
            char *u = strstr (sbuf, "\nUid:");
            if (u) {
                long uid_val = 0;
                sscanf (u, "\nUid:\t%ld", &uid_val);
                p->uid = (uid_t) uid_val;
            }
        }
    }

    /* args via /proc/PID/cmdline */
    snprintf (path, sizeof path, "/proc/%d/cmdline", pid);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    p->args[0] = '\0';
    if (fd >= 0) {
        ssize_t an = read (fd, p->args, sizeof p->args - 1);
        close (fd);
        if (an > 0) {
            for (ssize_t i = 0; i < an - 1; i++)
                if (p->args[i] == '\0') p->args[i] = ' ';
            p->args[an] = '\0';
        }
    }
    if (!p->args[0])
        snprintf (p->args, sizeof p->args, "[%s]", p->comm);

    return 0;
}

/* Read /proc/stat first 'cpu' line; sum the first eight fields (guest is already in user/nice). */
static int
btop_read_cpu_total (long *result)
{
    int fd = open ("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    int saved_errno = n < 0 ? errno : EIO;
    close (fd);
    if (n <= 0) { errno = saved_errno; return -1; }
    buf[n] = '\0';
    /* First line: "cpu  user nice system idle iowait irq softirq steal guest guest_nice" */
    if (strncmp (buf, "cpu ", 4) != 0 && strncmp (buf, "cpu\t", 4) != 0) { *result = 0; return 0; }
    char *p = buf + 3;
    long total = 0;
    char *end;
    for (int field = 0; field < 8 && *p && *p != '\n'; field++) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\0') break;
        long v = strtol (p, &end, 10);
        if (end == p) break;
        total += v;
        p = end;
    }
    *result = total;
    return 0;
}

/* Read /proc/meminfo into sys. Robust: parse line-by-line. */
static int
btop_read_meminfo (btop_sys *sys)
{
    sys->mem_total_kb = sys->mem_avail_kb = 0;
    sys->swap_total_kb = sys->swap_free_kb = 0;
    int fd = open ("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    int saved_errno = n < 0 ? errno : EIO;
    close (fd);
    if (n <= 0) { errno = saved_errno; return -1; }
    buf[n] = '\0';
    char *line = buf;
    while (*line) {
        char *nl = strchr (line, '\n');
        if (nl) *nl = '\0';
        long v;
        if      (sscanf (line, "MemTotal: %ld kB",     &v) == 1) sys->mem_total_kb  = v;
        else if (sscanf (line, "MemAvailable: %ld kB", &v) == 1) sys->mem_avail_kb  = v;
        else if (sscanf (line, "SwapTotal: %ld kB",    &v) == 1) sys->swap_total_kb = v;
        else if (sscanf (line, "SwapFree: %ld kB",     &v) == 1) sys->swap_free_kb  = v;
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

static void
btop_read_loadavg (btop_sys *sys)
{
    sys->loadavg[0] = '\0';
    int fd = open ("/proc/loadavg", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read (fd, sys->loadavg, sizeof sys->loadavg - 1);
    close (fd);
    if (n <= 0) { sys->loadavg[0] = '\0'; return; }
    sys->loadavg[n] = '\0';
    /* keep just the three load numbers (chop after the 3rd whitespace-sep field). */
    int spaces = 0;
    for (char *q = sys->loadavg; *q; q++) {
        if (*q == ' ') { spaces++; if (spaces == 3) { *q = '\0'; break; } }
        if (*q == '\n') { *q = '\0'; break; }
    }
}

/* --- sample everything ------------------------------------------------- */
static int
btop_sample (btop_proc *procs, int cap, btop_sys *sys)
{
    if (btop_read_cpu_total (&sys->cpu_jiffies_total) < 0) {
        builtin_error ("/proc/stat: %s", strerror (errno));
        return -1;
    }
    if (btop_read_meminfo (sys) < 0) {
        builtin_error ("/proc/meminfo: %s", strerror (errno));
        return -1;
    }
    btop_read_loadavg (sys);

    DIR *d = opendir ("/proc");
    if (!d) { builtin_error ("opendir /proc: %s", strerror (errno)); return -1; }
    int n = 0;
    struct dirent *de;
    while ((de = readdir (d)) && n < cap) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        btop_proc p; memset (&p, 0, sizeof p);
        if (btop_read_stat (pid, &p) == 0) {
            procs[n++] = p;
        }
    }
    closedir (d);
    sys->nproc = n;
    return n;
}

/* --- prev-snapshot lookup ---------------------------------------------- */
static long
btop_prev_lookup (int pid, unsigned long long starttime)
{
    for (int i = 0; i < btop_prev_n; i++)
        if (btop_prev_tbl[i].pid == pid && btop_prev_tbl[i].starttime == starttime)
            return btop_prev_tbl[i].cpu_total;
    return -1;
}

static void
btop_prev_store (btop_proc *procs, int n, long cpu_total)
{
    free (btop_prev_tbl);
    btop_prev_tbl = (btop_prev *) calloc ((size_t) n, sizeof (btop_prev));
    if (!btop_prev_tbl) { btop_prev_n = 0; btop_prev_total = 0; return; }
    btop_prev_n = n;
    btop_prev_total = cpu_total;
    for (int i = 0; i < n; i++) {
        btop_prev_tbl[i].pid = procs[i].pid;
        btop_prev_tbl[i].cpu_total = procs[i].cpu_total;
        btop_prev_tbl[i].starttime = procs[i].starttime;
    }
}

/* --- compute pcpu, then sort ------------------------------------------- */
static void
btop_compute_pcpu (btop_proc *procs, int n, long cpu_total)
{
    long delta_total = cpu_total - btop_prev_total;
    for (int i = 0; i < n; i++) {
        long prev = btop_prev_lookup (procs[i].pid, procs[i].starttime);
        if (prev < 0 || delta_total <= 0) { procs[i].cpu_delta = 0; procs[i].pcpu = 0.0; continue; }
        long d = procs[i].cpu_total - prev;
        if (d < 0) d = 0;
        procs[i].cpu_delta = d;
        procs[i].pcpu = (double) d * 100.0 / (double) delta_total;
    }
}

/* --- comparators -------------------------------------------------------- */
static int
btop_cmp_cpu (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->pcpu < q->pcpu) return 1;
    if (p->pcpu > q->pcpu) return -1;
    return q->pid - p->pid;
}
static int
btop_cmp_mem (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->rss_pages < q->rss_pages) return 1;
    if (p->rss_pages > q->rss_pages) return -1;
    return q->pid - p->pid;
}
static int
btop_cmp_pid (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    return p->pid - q->pid;
}
static int
btop_cmp_time (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->cpu_total < q->cpu_total) return 1;
    if (p->cpu_total > q->cpu_total) return -1;
    return q->pid - p->pid;
}

static void
btop_sort_procs (btop_proc *procs, int n, btop_sort sort)
{
    int (*cmp) (const void *, const void *);
    switch (sort) {
        case BTOP_SORT_MEM:  cmp = btop_cmp_mem;  break;
        case BTOP_SORT_PID:  cmp = btop_cmp_pid;  break;
        case BTOP_SORT_TIME: cmp = btop_cmp_time; break;
        case BTOP_SORT_CPU:
        default:             cmp = btop_cmp_cpu;  break;
    }
    qsort (procs, (size_t) n, sizeof procs[0], cmp);
}

/* --- formatting --------------------------------------------------------- */

static void
btop_print_header (FILE *fp, const btop_sys *sys, int delay_sec, btop_sort sort,
                   const char *extra)
{
    long mem_used = sys->mem_total_kb - sys->mem_avail_kb;
    long swap_used = sys->swap_total_kb - sys->swap_free_kb;
    fprintf (fp, "top - load %s  procs %d  sort %s  every %ds\n",
             sys->loadavg[0] ? sys->loadavg : "?", sys->nproc,
             btop_sort_name[sort], delay_sec);
    fprintf (fp, "Mem: %ld kB total, %ld kB used, %ld kB avail\n",
             sys->mem_total_kb, mem_used, sys->mem_avail_kb);
    fprintf (fp, "Swap: %ld kB total, %ld kB used, %ld kB free\n",
             sys->swap_total_kb, swap_used, sys->swap_free_kb);
    if (extra && extra[0])
        fprintf (fp, "%s\n", extra);
    fprintf (fp, "  PID USER     %%CPU    RSS S COMMAND\n");
}

static void
btop_print_row (FILE *fp, const btop_proc *p)
{
    long rss_kb = p->rss_pages * btop_page_size () / 1024;
    const char *cmd = p->args[0] ? p->args : p->comm;
    fprintf (fp, "%5d %-8.8s %5.1f %6ld %c %s\n",
             p->pid, btop_user (p->uid), p->pcpu, rss_kb, p->state, cmd);
}

/* --- cell-drawing variants for interactive mode (_bl_screen) ----------- */

/* Draw the header block into stdscr; returns the row after the header (where
   the process rows begin). Truecolor title/column bars exercise the new path. */
static int
btop_draw_header (bls_win *w, const btop_sys *sys, int delay_sec,
                  btop_sort sort, const char *extra)
{
    long mem_used = sys->mem_total_kb - sys->mem_avail_kb;
    long swap_used = sys->swap_total_kb - sys->swap_free_kb;
    int cols = bls_cols (); char bar[1024];
    int row = 0;

    bls_attrset (w, BLS_A_BOLD);
    bls_setfg (w, BLS_RGB (16, 16, 24)); bls_setbg (w, BLS_RGB (120, 200, 140));
    snprintf (bar, sizeof bar, " top  load %s  procs %d  sort %s  every %ds",
              sys->loadavg[0] ? sys->loadavg : "?", sys->nproc,
              btop_sort_name[sort], delay_sec);
    bls_mvaddstr (w, row, 0, bar); bls_clrtoeol (w); row++;

    bls_attrset (w, BLS_A_NORMAL); bls_setfg (w, BLS_DEFAULT); bls_setbg (w, BLS_DEFAULT);
    bls_move (w, row, 0);
    bls_printw (w, "Mem: %ld kB total, %ld kB used, %ld kB avail",
                sys->mem_total_kb, mem_used, sys->mem_avail_kb);
    bls_clrtoeol (w); row++;
    bls_move (w, row, 0);
    bls_printw (w, "Swap: %ld kB total, %ld kB used, %ld kB free",
                sys->swap_total_kb, swap_used, sys->swap_free_kb);
    bls_clrtoeol (w); row++;
    if (extra && extra[0]) {
        bls_attrset (w, BLS_A_BOLD); bls_setfg (w, BLS_RGB (255, 220, 120));
        bls_mvaddstr (w, row, 0, extra); bls_clrtoeol (w);
        bls_attrset (w, BLS_A_NORMAL); bls_setfg (w, BLS_DEFAULT); row++;
    }
    bls_attrset (w, BLS_A_REVERSE);
    snprintf (bar, sizeof bar, "%-*.*s", cols, cols, "  PID USER     %CPU    RSS S COMMAND");
    bls_mvaddstr (w, row, 0, bar);
    bls_attrset (w, BLS_A_NORMAL);
    row++;
    return row;
}

static void
btop_draw_row (bls_win *w, int row, const btop_proc *p)
{
    long rss_kb = p->rss_pages * btop_page_size () / 1024;
    const char *cmd = p->args[0] ? p->args : p->comm;
    bls_setfg (w, BLS_DEFAULT); bls_setbg (w, BLS_DEFAULT); bls_attrset (w, BLS_A_NORMAL);
    bls_move (w, row, 0);
    bls_printw (w, "%5d %-8.8s %5.1f %6ld %c %s",
                p->pid, btop_user (p->uid), p->pcpu, rss_kb, p->state, cmd);
    bls_clrtoeol (w);
}

static int btop_parse_sort (const char *s, btop_sort *out);

/* termios/tty/winsize/cursor and the cooked-prompt path are now provided by
   the shared _bl_screen module (bls_init/bls_getnstr/...). */

/* --- procps-style batch mode (-b / --batch) ------------------------------
   `top -b` writes procps-ng's batch layout, which scripts parse (guest
   compatibility pass 1: `top -bn1 | grep 'Cpu(s)'`). -n is the number of
   frames, -d the delay between them. --once keeps the bash-os layout. */

typedef struct { unsigned long long f[8]; } btop_cpu;

static int
btop_read_cpu_fields (btop_cpu *c, int *ncpu)
{
    memset (c, 0, sizeof *c);
    *ncpu = 0;
    FILE *fp = fopen ("/proc/stat", "re");
    if (!fp) return -1;
    char line[512];
    while (fgets (line, sizeof line, fp)) {
        if (!strncmp (line, "cpu ", 4))
            sscanf (line + 4, "%llu %llu %llu %llu %llu %llu %llu %llu",
                    &c->f[0], &c->f[1], &c->f[2], &c->f[3],
                    &c->f[4], &c->f[5], &c->f[6], &c->f[7]);
        else if (!strncmp (line, "cpu", 3) && isdigit ((unsigned char) line[3]))
            (*ncpu)++;
    }
    fclose (fp);
    if (*ncpu < 1) *ncpu = 1;
    return 0;
}

static void
btop_meminfo_extra (long *free_kb, long *cache_kb)
{
    *free_kb = *cache_kb = 0;
    FILE *fp = fopen ("/proc/meminfo", "re");
    if (!fp) return;
    char line[256];
    long v;
    while (fgets (line, sizeof line, fp)) {
        if (sscanf (line, "MemFree: %ld kB", &v) == 1) *free_kb = v;
        else if (sscanf (line, "Buffers: %ld kB", &v) == 1) *cache_kb += v;
        else if (sscanf (line, "Cached: %ld kB", &v) == 1) *cache_kb += v;
        else if (sscanf (line, "SReclaimable: %ld kB", &v) == 1) *cache_kb += v;
    }
    fclose (fp);
}

static int
btop_user_sessions (void)
{
    /* utmp records: ut_type (short) first, USER_PROCESS == 7, 384 bytes each. */
    int fd = open ("/run/utmp", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fd = open ("/var/run/utmp", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    unsigned char rec[384];
    int users = 0;
    while (read (fd, rec, sizeof rec) == (ssize_t) sizeof rec) {
        short type;
        memcpy (&type, rec, sizeof type);
        if (type == 7 && rec[44]) users++;
    }
    close (fd);
    return users;
}

/* KiB amount in WIDTH columns, scaling to m/g/t like procps. */
static void
btop_scale_kib (char *out, size_t n, unsigned long long kib, int width)
{
    snprintf (out, n, "%llu", kib);
    if ((int) strlen (out) <= width) return;
    double v = (double) kib;
    const char *units = "mgtpe";
    for (int i = 0; units[i]; i++) {
        v /= 1024.0;
        snprintf (out, n, "%.1f%c", v, units[i]);
        if ((int) strlen (out) <= width) return;
        snprintf (out, n, "%.0f%c", v, units[i]);
        if ((int) strlen (out) <= width) return;
    }
}

static void
btop_procps_header (const btop_sys *sys, const btop_proc *procs, int n,
                    const btop_cpu *c0, const btop_cpu *c1)
{
    char clock[16] = "", up[64] = "";
    time_t now = time (NULL);
    struct tm tmv;
    if (localtime_r (&now, &tmv)) strftime (clock, sizeof clock, "%H:%M:%S", &tmv);
    double upsec = 0;
    FILE *fp = fopen ("/proc/uptime", "re");
    if (fp) { if (fscanf (fp, "%lf", &upsec) != 1) upsec = 0; fclose (fp); }
    long u = (long) upsec, days = u / 86400, hrs = (u % 86400) / 3600, mins = (u % 3600) / 60;
    int k = 0;
    if (days) k = snprintf (up, sizeof up, "%ld day%s, ", days, days == 1 ? "" : "s");
    if (hrs) snprintf (up + k, sizeof up - (size_t) k, "%2ld:%02ld", hrs, mins);
    else snprintf (up + k, sizeof up - (size_t) k, "%ld min", mins);
    double la[3] = {0, 0, 0};
    sscanf (sys->loadavg, "%lf %lf %lf", &la[0], &la[1], &la[2]);
    int users = btop_user_sessions ();
    printf ("top - %s up %s, %2d user%s,  load average: %.2f, %.2f, %.2f\n",
            clock, up, users, users == 1 ? "" : "s", la[0], la[1], la[2]);

    int run = 0, sleep_ = 0, stop = 0, zomb = 0;
    for (int i = 0; i < n; i++)
        switch (procs[i].state) {
        case 'R': run++; break;
        case 'T': case 't': stop++; break;
        case 'Z': zomb++; break;
        default: sleep_++; break;
        }
    printf ("Tasks: %3d total, %3d running, %3d sleeping, %3d stopped, %3d zombie\n",
            n, run, sleep_, stop, zomb);

    /* us sy ni id wa hi si st, from proc(5) order user nice system idle
       iowait irq softirq steal. */
    static const int order[8] = { 0, 2, 1, 3, 4, 5, 6, 7 };
    static const char *const label[8] = { "us", "sy", "ni", "id", "wa", "hi", "si", "st" };
    double d[8], tot = 0;
    for (int i = 0; i < 8; i++) {
        unsigned long long a = c0->f[i], b = c1->f[i];
        d[i] = b > a ? (double) (b - a) : 0;
        tot += d[i];
    }
    printf ("%%Cpu(s):");
    for (int i = 0; i < 8; i++)
        printf ("%5.1f %s%s", tot > 0 ? d[order[i]] * 100.0 / tot : (order[i] == 3 ? 100.0 : 0.0),
                label[i], i < 7 ? "," : " ");
    putchar ('\n');

    long free_kb, cache_kb;
    btop_meminfo_extra (&free_kb, &cache_kb);
    double mt = sys->mem_total_kb / 1024.0, mf = free_kb / 1024.0;
    double mu = (sys->mem_total_kb - sys->mem_avail_kb) / 1024.0, mc = cache_kb / 1024.0;
    printf ("MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache     \n", mt, mf, mu, mc);
    printf ("MiB Swap: %8.1f total, %8.1f free, %8.1f used. %8.1f avail Mem \n",
            sys->swap_total_kb / 1024.0, sys->swap_free_kb / 1024.0,
            (sys->swap_total_kb - sys->swap_free_kb) / 1024.0, sys->mem_avail_kb / 1024.0);
    putchar ('\n');
    printf ("    PID USER      PR  NI    VIRT    RES    SHR S  %%CPU  %%MEM     TIME+ COMMAND\n");
}

static void
btop_procps_row (const btop_proc *p, long mem_total_kb, int ncpu, int width)
{
    long page_kb = btop_page_size () / 1024;
    unsigned long long shr = 0;
    char path[64], pr[8], virt[16], res[16], shrs[16], tim[24], line[1024];
    snprintf (path, sizeof path, "/proc/%d/statm", p->pid);
    FILE *fp = fopen (path, "re");
    if (fp) { if (fscanf (fp, "%*u %*u %llu", &shr) != 1) shr = 0; fclose (fp); }
    if (p->prio < -99) snprintf (pr, sizeof pr, "rt");
    else snprintf (pr, sizeof pr, "%ld", p->prio);
    btop_scale_kib (virt, sizeof virt, (unsigned long long) p->vsize_bytes / 1024, 7);
    btop_scale_kib (res, sizeof res, (unsigned long long) p->rss_pages * (unsigned long long) page_kb, 6);
    btop_scale_kib (shrs, sizeof shrs, shr * (unsigned long long) page_kb, 6);
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    unsigned long long cs = (unsigned long long) p->cpu_total * 100 / (unsigned long long) hz;
    snprintf (tim, sizeof tim, "%llu:%02llu.%02llu", cs / 6000, cs / 100 % 60, cs % 100);
    double pmem = mem_total_kb > 0 ? (double) p->rss_pages * page_kb * 100.0 / mem_total_kb : 0;
    int k = snprintf (line, sizeof line, "%7d %-8.8s %3s %3ld %7s %6s %6s %c %5.1f %5.1f %9s %s",
                      p->pid, btop_user (p->uid), pr, p->nice, virt, res, shrs, p->state,
                      p->pcpu * ncpu, pmem, tim, p->comm);
    if (k >= (int) sizeof line) k = (int) sizeof line - 1;
    if (width > 1 && k > width - 1) { line[width - 2] = '+'; line[width - 1] = '\0'; }
    puts (line);
}

static int
btop_run_batch (btop_sort sort, int frames, int delay_ms, int row_cap, int width,
                const int *pids, int npids, int uid_filter)
{
    btop_proc *procs = (btop_proc *) calloc (BTOP_MAX_PROCS, sizeof (btop_proc));
    if (!procs) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    btop_sys sys; memset (&sys, 0, sizeof sys);
    btop_cpu c0, c1;
    int ncpu = 1, rc = EXECUTION_SUCCESS;

    int n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) { free (procs); return EXECUTION_FAILURE; }
    btop_read_cpu_fields (&c0, &ncpu);
    btop_prev_store (procs, n, sys.cpu_jiffies_total);
    for (int frame = 0; frames == 0 || frame < frames; frame++) {
        int ms = frame == 0 ? 200 : delay_ms;
        struct timespec ts = { ms / 1000, (long) (ms % 1000) * 1000000L };
        nanosleep (&ts, NULL);
        n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
        if (n < 0) { rc = EXECUTION_FAILURE; break; }
        btop_read_cpu_fields (&c1, &ncpu);
        btop_compute_pcpu (procs, n, sys.cpu_jiffies_total);
        btop_sort_procs (procs, n, sort);
        if (frame) putchar ('\n');
        btop_procps_header (&sys, procs, n, &c0, &c1);
        int shown = 0;
        for (int i = 0; i < n && (row_cap == 0 || shown < row_cap); i++) {
            if (npids) {
                int hit = 0;
                for (int j = 0; j < npids; j++) hit |= pids[j] == procs[i].pid;
                if (!hit) continue;
            }
            if (uid_filter >= 0 && procs[i].uid != (uid_t) uid_filter) continue;
            btop_procps_row (&procs[i], sys.mem_total_kb, ncpu, width);
            shown++;
        }
        if (fflush (stdout) == EOF || ferror (stdout)) {
            builtin_error ("write error: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
            break;
        }
        c0 = c1;
        btop_prev_store (procs, n, sys.cpu_jiffies_total);
    }
    free (procs);
    return rc;
}

/* --- once mode --------------------------------------------------------- */
static int
btop_run_once (btop_sort sort, int row_cap)
{
    btop_proc *procs = (btop_proc *) calloc (BTOP_MAX_PROCS, sizeof (btop_proc));
    if (!procs) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    btop_sys sys; memset (&sys, 0, sizeof sys);

    /* Two snapshots ~200ms apart so %CPU has real numbers in --once. */
    int n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) {
        free (procs);
        return EXECUTION_FAILURE;
    }
    long cpu_total_1 = sys.cpu_jiffies_total;
    btop_prev_store (procs, n, cpu_total_1);

    struct timespec ts = { 0, 200000000L };  /* 200 ms */
    nanosleep (&ts, NULL);

    n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) {
        free (procs);
        return EXECUTION_FAILURE;
    }
    btop_compute_pcpu (procs, n, sys.cpu_jiffies_total);
    btop_sort_procs (procs, n, sort);

    btop_print_header (stdout, &sys, 0, sort, "(--once snapshot)");
    int limit = row_cap > 0 && row_cap < n ? row_cap : n;
    for (int i = 0; i < limit; i++)
        btop_print_row (stdout, &procs[i]);

    free (procs);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Strict decimal input: reject prefixes, whitespace, suffixes and overflow. */
static int
btop_parse_int (const char *s, int min, int max, int *value)
{
    if (!s || !*s) return -1;
    const char *p = s;
    if (*p == '-' && min < 0) p++;
    if (!*p) return -1;
    for (; *p; p++) if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end;
    long v = strtol (s, &end, 10);
    if (errno == ERANGE || *end || v < min || v > max) return -1;
    *value = (int) v;
    return 0;
}

/* --- interactive mode -------------------------------------------------- */
static int
btop_run_interactive (int delay_sec, btop_sort sort, int max_iters, int row_cap)
{
    btop_proc *procs = (btop_proc *) calloc (BTOP_MAX_PROCS, sizeof (btop_proc));
    if (!procs) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    btop_sys sys; memset (&sys, 0, sizeof sys);

    struct sigaction old_winch, old_term, old_hup;
    sigaction (SIGWINCH, NULL, &old_winch);
    sigaction (SIGTERM, NULL, &old_term);
    sigaction (SIGHUP, NULL, &old_hup);
    if (bls_init () != 0) { free (procs); builtin_error ("not a terminal"); return EXECUTION_FAILURE; }
    bls_win *win = bls_stdscr ();
    bls_timeout (delay_sec * 1000);

    /* Prime previous snapshot so the first redraw has %CPU numbers. */
    int rc = EXECUTION_SUCCESS;
    int n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) { rc = EXECUTION_FAILURE; goto out; }
    btop_prev_store (procs, n, sys.cpu_jiffies_total);

    int iter = 0;
    int redraw = 1;
    int scroll = 0;          /* row offset into the sorted process list */
    int last_n = n;          /* last n seen by redraw (for clamping) */
    int last_window = 1;     /* last visible window size (for PgUp/PgDn) */
    char extra[160] = "";

    for (;;) {
        if (redraw) {
            n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
            if (n < 0) {
                rc = EXECUTION_FAILURE;
                break;
            }
            btop_compute_pcpu (procs, n, sys.cpu_jiffies_total);
            btop_sort_procs (procs, n, sort);

            /* Clamp scroll offset against the post-sample list. */
            if (scroll < 0) scroll = 0;
            if (n == 0) scroll = 0;
            else if (scroll > n - 1) scroll = n - 1;
            last_n = n;

            /* Let the helper apply a pending resize before calculating rows. */
            bls_refresh (win);
            bls_erase (win);
            int hr = btop_draw_header (win, &sys, delay_sec, sort, extra);
            int limit = bls_lines () - hr;
            if (row_cap > 0 && row_cap < limit) limit = row_cap;
            if (limit < 1) limit = 1;
            last_window = limit;
            int avail = n - scroll;
            int rowmax = limit > avail ? avail : limit;
            if (rowmax < 0) rowmax = 0;
            for (int i = 0; i < rowmax; i++)
                btop_draw_row (win, hr + i, &procs[scroll + i]);
            bls_move (win, bls_lines () - 1, 0);
            bls_refresh (win);

            btop_prev_store (procs, n, sys.cpu_jiffies_total);
            extra[0] = '\0';
            redraw = 0;
            iter++;
            if (max_iters > 0 && iter >= max_iters) break;
        }

        /* bls_getch blocks up to the refresh interval (bls_timeout); a timeout
         * or a SIGWINCH-interrupted poll both surface as BLS_ERR → redraw.
         * bls_refresh re-queries the terminal size on resize internally. */
        int k = bls_getch ();
        if (k == BLS_ERR) { redraw = 1; continue; }
        if (k == BLS_KEY_NONE) {
            /* EOF on stdin (pipe-fed input drained). Treat as exit. */
            break;
        }
        if (k == 0x03) goto out;          /* Ctrl-C → quit */
        if (k == BL_KEY_ESC) goto out;     /* bare ESC → quit */

        /* Page size for PgUp/PgDn — visible-window minus 1 row of
         * overlap, never less than 1. */
        int page = last_window > 1 ? last_window - 1 : 1;

        switch (k) {
            case 'q': case 'Q':
                goto out;
            case ' ':
                redraw = 1;
                break;
            case BL_KEY_UP:
                if (scroll > 0) { scroll--; redraw = 1; }
                break;
            case BL_KEY_DOWN:
                if (scroll + 1 < last_n) { scroll++; redraw = 1; }
                break;
            case BL_KEY_PGUP:
                scroll -= page;
                if (scroll < 0) scroll = 0;
                redraw = 1;
                break;
            case BL_KEY_PGDN: {
                int max_scroll = last_n - 1;
                if (max_scroll < 0) max_scroll = 0;
                scroll += page;
                if (scroll > max_scroll) scroll = max_scroll;
                redraw = 1;
                break;
            }
            case BL_KEY_HOME:
                scroll = 0;
                redraw = 1;
                break;
            case BL_KEY_END: {
                int max_scroll = last_n - 1;
                if (max_scroll < 0) max_scroll = 0;
                scroll = max_scroll;
                redraw = 1;
                break;
            }
            case 'o': case 'O': {
                /* Prompt for a column name; an empty answer cycles to the
                   next column and ESC cancels. */
                char buf[32];
                int got = bls_getnstr (win, bls_lines () - 1, 0,
                                       "sort (cpu|mem|pid|time, Enter=next): ",
                                       buf, sizeof buf);
                btop_sort want;
                if (got == 0) {
                    sort = (btop_sort) ((sort + 1) % BTOP_SORT__COUNT);
                    snprintf (extra, sizeof extra, "sort → %s", btop_sort_name[sort]);
                } else if (got > 0 && btop_parse_sort (buf, &want) == 0) {
                    sort = want;
                    snprintf (extra, sizeof extra, "sort → %s", btop_sort_name[sort]);
                } else if (got > 0)
                    snprintf (extra, sizeof extra, "invalid sort column (cpu|mem|pid|time)");
                redraw = 1;
                break;
            }
            case 'n': case 'N': {
                char buf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"delay (s): ", buf, sizeof buf) > 0) {
                    int v;
                    if (btop_parse_int (buf, 1, 3599, &v) == 0) {
                        delay_sec = v; bls_timeout (delay_sec * 1000);
                        snprintf (extra, sizeof extra, "delay → %ds", delay_sec);
                    } else snprintf (extra, sizeof extra, "invalid delay (1..3599)");
                }
                redraw = 1;
                break;
            }
            case 'k': case 'K': {
                char pidbuf[32], sigbuf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"kill PID: ", pidbuf, sizeof pidbuf) <= 0) {
                    redraw = 1; break;
                }
                if (bls_getnstr (win, bls_lines () - 1, 0,"signal [TERM]: ", sigbuf, sizeof sigbuf) < 0) {
                    redraw = 1; break;
                }
                int pid, sig = SIGTERM;
                if (btop_parse_int (pidbuf, 1, INT_MAX, &pid) < 0 ||
                    (sigbuf[0] && btop_parse_int (sigbuf, 1, NSIG - 1, &sig) < 0)) {
                    snprintf (extra, sizeof extra, "invalid PID or signal");
                    redraw = 1; break;
                }
                if (kill (pid, sig) == 0)
                    snprintf (extra, sizeof extra, "kill -%d %d ok", sig, pid);
                else
                    snprintf (extra, sizeof extra, "kill -%d %d: %s", sig, pid, strerror (errno));
                redraw = 1;
                break;
            }
            case 'r': case 'R': {
                char pidbuf[32], nicebuf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"renice PID: ", pidbuf, sizeof pidbuf) <= 0) {
                    redraw = 1; break;
                }
                if (bls_getnstr (win, bls_lines () - 1, 0,"delta: ", nicebuf, sizeof nicebuf) <= 0) {
                    redraw = 1; break;
                }
                int pid, delta;
                if (btop_parse_int (pidbuf, 1, INT_MAX, &pid) < 0 ||
                    btop_parse_int (nicebuf, -40, 40, &delta) < 0) {
                    snprintf (extra, sizeof extra, "invalid PID or nice delta (-40..40)");
                    redraw = 1; break;
                }
                errno = 0;
                int cur = getpriority (PRIO_PROCESS, (id_t) pid);
                if (cur == -1 && errno != 0) {
                    snprintf (extra, sizeof extra, "renice %d: %s", pid, strerror (errno));
                } else if (setpriority (PRIO_PROCESS, (id_t) pid, cur + delta) == 0) {
                    snprintf (extra, sizeof extra, "renice %d → %d", pid, cur + delta);
                } else {
                    snprintf (extra, sizeof extra, "renice %d: %s", pid, strerror (errno));
                }
                redraw = 1;
                break;
            }
            default:
                /* ignore */
                break;
        }
    }

out:
    bls_end ();
    sigaction (SIGWINCH, &old_winch, NULL);
    sigaction (SIGTERM, &old_term, NULL);
    sigaction (SIGHUP, &old_hup, NULL);
    free (procs);
    return rc;
}

/* --- arg parsing -------------------------------------------------------- */

static int
btop_parse_sort (const char *s, btop_sort *out)
{
    if (!s || !*s) return -1;
    /* procps field names: %CPU, %MEM, RES, PID, TIME+ */
    if (!strcmp (s, "%CPU")) s = "cpu";
    else if (!strcmp (s, "%MEM") || !strcmp (s, "RES")) s = "mem";
    else if (!strcmp (s, "TIME+") || !strcmp (s, "TIME")) s = "time";
    if (!strcasecmp (s, "cpu"))  { *out = BTOP_SORT_CPU;  return 0; }
    if (!strcasecmp (s, "mem"))  { *out = BTOP_SORT_MEM;  return 0; }
    if (!strcasecmp (s, "pid"))  { *out = BTOP_SORT_PID;  return 0; }
    if (!strcasecmp (s, "time")) { *out = BTOP_SORT_TIME; return 0; }
    return -1;
}

static int
btop_parse_delay (const char *s, int frac, int *ms)
{
    /* DIGITS[.DIGITS]; fractions only for batch (frac != 0). */
    int whole = 0, i = 0;
    if (!isdigit ((unsigned char) s[0])) return -1;
    while (isdigit ((unsigned char) s[i])) {
        if (whole > 3599) return -1;
        whole = whole * 10 + (s[i++] - '0');
    }
    int milli = 0;
    if (s[i] == '.' && frac && isdigit ((unsigned char) s[i + 1])) {
        int scale = 100;
        for (i++; isdigit ((unsigned char) s[i]); i++, scale /= 10)
            milli += (s[i] - '0') * scale;
    }
    if (s[i] || whole > 3599 || (whole == 3599 && milli) || (!whole && !milli) || (!frac && !whole))
        return -1;
    *ms = whole * 1000 + milli;
    return 0;
}

int
top_builtin (WORD_LIST *list)
{
    int       once = 0, batch = 0;
    int       iters = 0;
    int       delay_ms = -1;
    btop_sort sort = BTOP_SORT_CPU;
    int       row_cap = 0, width = 0;
    int       pids[64], npids = 0, uid_filter = -1;
    const char *delay_arg = NULL;

    while (list) {
        const char *w = list->word->word;
        if (!w || !*w || w[0] != '-') break;
        if (!w[1]) { builtin_error ("unknown option: %s", w); return EX_USAGE; }

        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--once")) { once = 1; list = list->next; continue; }
        if (!strcmp (w, "--batch")) { batch = 1; list = list->next; continue; }
        if (!strcmp (w, "--help")) {
            extern char *top_doc[];
            for (char **dp = top_doc; *dp; dp++) puts (*dp);
            return EX_USAGE;
        }
        if (w[1] == '-') { builtin_error ("unknown option: %s", w); return EX_USAGE; }
        /* Short options cluster (-bn1, -b -n 1, -d0.5) as procps allows. */
        for (int i = 1; w[i]; i++) {
            char c = w[i];
            if (c == 'b') { batch = 1; continue; }
            if (c == 'c' || c == 'i' || c == 'S' || c == 'H') continue;
            if (c == 'h') {
                extern char *top_doc[];
                for (char **dp = top_doc; *dp; dp++) puts (*dp);
                return EX_USAGE;
            }
            if (!strchr ("ndorwpuU", c)) { builtin_error ("unknown option: -%c", c); return EX_USAGE; }
            const char *v = NULL;
            if (w[i + 1]) v = w + i + 1;
            else if (c == 'w') {
                /* -w takes an optional number */
                if (list->next && isdigit ((unsigned char) list->next->word->word[0])) {
                    list = list->next; v = list->word->word;
                }
            } else if (list->next) { list = list->next; v = list->word->word; }
            else {
                static const char *const need[] = { "n", "COUNT", "d", "SEC", "o", "COLUMN",
                    "r", "N", "p", "PID", "u", "USER", "U", "USER", NULL };
                const char *what = "VALUE";
                for (int k = 0; need[k]; k += 2) if (need[k][0] == c) what = need[k + 1];
                builtin_error ("-%c requires %s", c, what);
                return EX_USAGE;
            }
            switch (c) {
            case 'n':
                if (btop_parse_int (v, 0, INT_MAX, &iters) < 0) { builtin_error ("invalid count: %s", v); return EX_USAGE; }
                break;
            case 'd':
                delay_arg = v;   /* validated once -b is known */
                if (btop_parse_delay (v, 1, &delay_ms) < 0) { builtin_error ("invalid delay (1..3599): %s", v); return EX_USAGE; }
                break;
            case 'o':
                if (btop_parse_sort (v, &sort) < 0) {
                    builtin_error ("unknown sort column: %s (cpu|mem|pid|time)", v);
                    return EX_USAGE;
                }
                break;
            case 'r':
                if (btop_parse_int (v, 0, INT_MAX, &row_cap) < 0) { builtin_error ("invalid row cap: %s", v); return EX_USAGE; }
                break;
            case 'w':
                if (!v) width = 512;
                else if (btop_parse_int (v, 1, 512, &width) < 0) { builtin_error ("invalid width: %s", v); return EX_USAGE; }
                break;
            case 'p': {
                const char *q = v;
                while (*q) {
                    char *end; long pid = strtol (q, &end, 10);
                    if (end == q || pid <= 0 || pid > INT_MAX || (*end && *end != ',') || npids == 64) {
                        builtin_error ("invalid PID list: %s", v); return EX_USAGE;
                    }
                    pids[npids++] = (int) pid;
                    q = *end ? end + 1 : end;
                }
                break;
            }
            case 'u': case 'U': {
                char *end; long u = strtol (v, &end, 10);
                if (end != v && !*end && u >= 0) uid_filter = (int) u;
                else {
                    struct passwd *pw = getpwnam (v);
                    if (!pw) { builtin_error ("invalid user: %s", v); return EX_USAGE; }
                    uid_filter = (int) pw->pw_uid;
                }
                break;
            }
            }
            break;   /* the value used the rest of this word */
        }
        list = list->next;
    }

    if (list) { builtin_error ("unexpected operand: %s", list->word->word); return EX_USAGE; }
    if (delay_arg && btop_parse_delay (delay_arg, batch && !once, &delay_ms) < 0) {
        builtin_error ("invalid delay (1..3599): %s", delay_arg);
        return EX_USAGE;
    }
    /* Previous samples belong only to this invocation, including failure paths. */
    btop_prev_n = 0; btop_prev_total = 0;
    int rc;
    if (once) {
        /* --once: the bash-os snapshot layout; -n caps rows there. */
        if (iters > 0 && (row_cap == 0 || iters < row_cap))
            row_cap = iters;
        rc = btop_run_once (sort, row_cap);
    } else if (batch) {
        if (!width) {
            const char *cols = getenv ("COLUMNS");
            if (!cols || btop_parse_int (cols, 1, 512, &width) < 0) width = 80;
        }
        rc = btop_run_batch (sort, iters, delay_ms > 0 ? delay_ms : 3000, row_cap, width,
                             pids, npids, uid_filter);
    } else {
        rc = btop_run_interactive (delay_ms > 0 ? delay_ms / 1000 : 2, sort, iters, row_cap);
    }
    free (btop_prev_tbl); btop_prev_tbl = NULL;
    btop_prev_n = 0; btop_prev_total = 0;
    return rc;
}

char *top_doc[] = {
    "Interactive process viewer over /proc (top(1) shape).",
    "",
    "    top [--once|-b] [-n COUNT] [-d SEC] [-o COL] [-r N] [-w [N]] [-p PID,...] [-u USER]",
    "",
    "    -b, --batch   procps-ng batch output: the top/Tasks/%Cpu(s)/MiB Mem/",
    "                  MiB Swap summary and PID USER PR NI VIRT RES SHR S",
    "                  %CPU %MEM TIME+ COMMAND rows, every -d seconds (default",
    "                  3), -n frames (default: until killed). Options cluster:",
    "                  top -bn1.",
    "    --once        one bash-os snapshot (the layout below), then exit.",
    "    -n COUNT      interactive redraws, batch frames, --once row cap.",
    "    -d SEC        refresh interval, 1..3599 seconds; -b also takes",
    "                  fractions such as 0.5. Default 2, or 3 with -b.",
    "    -o COL        initial sort: cpu | mem | pid | time (also %CPU, %MEM,",
    "                  RES, PID, TIME+). Default cpu.",
    "    -r N          cap process rows shown (0: available terminal rows).",
    "    -w [N]        batch line width (default COLUMNS, else 80; -w alone 512).",
    "    -p PID,...    batch: only these processes.   -u/-U USER  batch: one user.",
    "    -c -i -S -H   accepted for procps compatibility; no effect.",
    "",
    "Interactive keys:",
    "    q / ESC       exit.",
    "    space         redraw immediately.",
    "    Up / Down     scroll the process list one row.",
    "    PgUp / PgDn   scroll the process list one page.",
    "    Home / End    jump to first / last process.",
    "    n             prompt for new refresh interval.",
    "    o / O         prompt for sort column; Enter alone cycles.",
    "    k             prompt for PID + signal, send signal.",
    "    r             prompt for PID + nice delta, renice.",
    "",
    "Header lines: load averages, process count, sort column, refresh;",
    "Mem total/used/avail (kB); Swap total/used/free (kB). Row columns:",
    "PID USER %CPU RSS S COMMAND. %CPU is computed across two snapshots",
    "(refresh interval in interactive mode, 200ms in --once).",
    "CPU percentages are a share of total machine time; ties use descending PID.",
    "New/reused PIDs have zero CPU delta until their next observation.",
    (char *) NULL
};

struct builtin top_struct = {
    "top",
    top_builtin,
    BUILTIN_ENABLED,
    top_doc,
    "top [--once|-b] [-n COUNT] [-d SEC] [-o cpu|mem|pid|time] [-r N]",
    0
};
