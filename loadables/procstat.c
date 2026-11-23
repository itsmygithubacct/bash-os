/* SPDX-License-Identifier: MIT */
/* Linux process/accounting snapshots. Written from the documented proc ABI:
   https://docs.kernel.org/filesystems/proc.html
   https://docs.kernel.org/admin-guide/iostats.html
   The upstream command/help surface supplies the verbs; its implementation
   is not incorporated here. Counters are snapshots, without interval sampling. */
#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include "loadables.h"

static const char *proc_root (void)
{
  const char *root = getenv ("BASHOS_PROC_ROOT");
  return root && *root ? root : "/proc";
}
static FILE *proc_open (const char *pid, const char *leaf, int quiet)
{
  const char *root = proc_root ();
  size_t n = strlen (root) + (pid ? strlen (pid) : 0) + strlen (leaf) + 3;
  char *path = xmalloc (n);
  snprintf (path, n, "%s/%s%s%s", root, pid ? pid : "", pid ? "/" : "", leaf);
  FILE *fp = fopen (path, "r");
  if (!fp && !quiet) builtin_error ("%s: %s", path, strerror (errno));
  free (path);
  return fp;
}
static int proc_pid (const char *s)
{
  if (!s || !*s) return 0;
  unsigned long n = 0;
  for (; *s; s++) {
    if (!isdigit ((unsigned char) *s) || n > (INT_MAX - (unsigned) (*s - '0')) / 10UL) return 0;
    n = n * 10 + (unsigned) (*s - '0');
  }
  return n > 0;
}
static int proc_end (FILE *fp)
{
  int failed = ferror (fp);
  if (fclose (fp) != 0) failed = 1;
  if (failed) builtin_error ("read failed");
  return failed;
}
static double proc_uptime (void)
{
  FILE *fp = proc_open (NULL, "uptime", 0);
  if (!fp) return -1;
  double value = 0;
  int valid = fscanf (fp, "%lf", &value) == 1 && value > 0;
  if (proc_end (fp) || !valid) return -1;
  return value;
}
static int proc_cpu (int all)
{
  FILE *fp = proc_open (NULL, "stat", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0; int count = 0;
  puts ("CPU %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle");
  while (getline (&line, &cap, fp) >= 0) {
    char label[32] = {0}; uint64_t v[10] = {0};
    int fields = sscanf (line, "%31s %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64
                         " %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64,
                         label, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9]);
    if (strncmp (label, "cpu", 3) || (label[3] && !isdigit ((unsigned char) label[3]))) continue;
    if (fields < 5) { free (line); proc_end (fp); builtin_error ("malformed CPU counters"); return 1; }
    if (!all && label[3]) continue;
    long double total = 0; for (int i = 0; i < 8; i++) total += v[i];
    long double scale = total > 0 ? 100 / total : 0;
    uint64_t user = v[0] >= v[8] ? v[0] - v[8] : 0;
    uint64_t nice = v[1] >= v[9] ? v[1] - v[9] : 0;
    printf ("%s %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf\n",
            label[3] ? label + 3 : "all", user*scale, nice*scale, v[2]*scale,
            v[4]*scale, v[5]*scale, v[6]*scale, v[7]*scale, v[8]*scale, v[9]*scale, v[3]*scale);
    count++;
  }
  free (line);
  return proc_end (fp) || count == 0;
}
/* sysstat iostat's report, with counters averaged since boot: the banner,
   then avg-cpu (-c), the device table (-d) or the extended device table
   (-x), each in sysstat 12's columns. Devices are the whole disks in
   /sys/block (all of them for an alternate proc tree) that have done any
   I/O, sorted by name as sysstat lists them. A missing /proc/diskstats
   leaves the device table empty. */
enum { IOS_CPU = 1, IOS_DEV = 2, IOS_EXT = 4 };

static void
proc_iostat_banner (void)
{
  struct utsname u;
  char date[64] = "";
  time_t now = time (NULL);
  struct tm tm;
  const char *fmt = getenv ("S_TIME_FORMAT");
  int iso = fmt && !strcmp (fmt, "ISO");   /* before localtime_r reads TZ */
  if (uname (&u) != 0) memset (&u, 0, sizeof u);
  if (localtime_r (&now, &tm))
    strftime (date, sizeof date, iso ? "%Y-%m-%d" : "%x", &tm);
  int cpus = 0;
  FILE *fp = proc_open (NULL, "stat", 1);
  if (fp) {
    char *line = NULL; size_t cap = 0;
    while (getline (&line, &cap, fp) >= 0)
      if (!strncmp (line, "cpu", 3) && isdigit ((unsigned char) line[3])) cpus++;
    free (line); fclose (fp);
  }
  printf ("%s %s (%s) \t%s \t_%s_\t(%d CPU)\n\n", u.sysname, u.release, u.nodename, date, u.machine, cpus);
}
static int
proc_iostat_cpu (void)
{
  FILE *fp = proc_open (NULL, "stat", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0; int found = 0;
  uint64_t v[10] = {0};
  while (getline (&line, &cap, fp) >= 0) {
    char label[32] = {0};
    int fields = sscanf (line, "%31s %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64
                         " %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64,
                         label, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9]);
    if (strcmp (label, "cpu")) continue;
    if (fields < 5) { free (line); proc_end (fp); builtin_error ("malformed CPU counters"); return 1; }
    found = 1;
    break;
  }
  free (line);
  if (proc_end (fp)) return 1;
  if (!found) { builtin_error ("no CPU counters"); return 1; }
  /* sysstat: guest time is part of user time; the total leaves it out. */
  long double total = 0; for (int i = 0; i < 8; i++) total += v[i];
  long double scale = total > 0 ? 100 / total : 0;
  puts ("avg-cpu:  %user   %nice %system %iowait  %steal   %idle");
  printf ("       %8.2Lf%8.2Lf%8.2Lf%8.2Lf%8.2Lf%8.2Lf\n\n", v[0]*scale, v[1]*scale,
          (v[2]+v[5]+v[6])*scale, v[4]*scale, v[7]*scale, v[3]*scale);
  return 0;
}
/* Is NAME a whole disk (sysstat leaves partitions out without -p)? */
static int
proc_iostat_whole_disk (const char *name)
{
  /* Bash's getenv returns temporary-environment values in one buffer that
     the next call frees, so test BASHOS_PROC_ROOT before keeping sys. */
  const char *proc = getenv ("BASHOS_PROC_ROOT");
  int alternate = proc && *proc;
  const char *env = getenv ("BASHOS_SYS_ROOT");
  if (!(env && *env) && alternate) return 1;   /* an alternate proc tree */
  char sys[2048], path[4096];
  snprintf (sys, sizeof sys, "%s", env && *env ? env : "/sys");
  snprintf (path, sizeof path, "%s/block", sys);
  struct stat st;
  if (stat (path, &st) != 0 || !S_ISDIR (st.st_mode)) return 1;
  snprintf (path, sizeof path, "%s/block/%s", sys, name);
  return access (path, F_OK) == 0;
}
typedef struct { char *name; char *row; } proc_iostat_row;
static int proc_iostat_row_cmp (const void *a, const void *b)
{
  return strcmp (((const proc_iostat_row *) a)->name, ((const proc_iostat_row *) b)->name);
}
/* printf into a new string. */
static char *proc_iostat_fmt (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static char *proc_iostat_fmt (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  int n = vsnprintf (NULL, 0, fmt, ap);
  va_end (ap);
  char *s = xmalloc ((size_t) (n > 0 ? n : 0) + 1);
  va_start (ap, fmt);
  vsnprintf (s, (size_t) (n > 0 ? n : 0) + 1, fmt, ap);
  va_end (ap);
  return s;
}
static int
proc_iostat_devices (int extended, double uptime)
{
  if (extended)
    puts ("Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz"
          "     d/s     dkB/s   drqm/s  %drqm d_await dareq-sz     f/s f_await  aqu-sz  %util");
  else
    puts ("Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd");
  FILE *fp = proc_open (NULL, "diskstats", 1);
  if (!fp) { puts (""); return 0; }
  char *line = NULL; size_t cap = 0; int result = 0;
  proc_iostat_row *rows = NULL; size_t nrows = 0;
  while (getline (&line, &cap, fp) >= 0) {
    unsigned major, minor; char name[128]; int pos = 0;
    if (sscanf (line, "%u %u %127s %n", &major, &minor, name, &pos) != 3 || !pos) {
      builtin_error ("malformed disk counters"); result = 1; break;
    }
    /* Fields 4-20 of iostats.rst: reads, merges, sectors, ms; the same for
       writes; in flight, io ms, weighted ms; discards; flushes. */
    uint64_t f[17] = {0}; int n = 0; char *p = line + pos;
    while (n < 17) {
      char *end; errno = 0;
      unsigned long long x = strtoull (p, &end, 10);
      if (end == p || errno) break;
      f[n++] = x; p = end;
    }
    if (n < 11) { builtin_error ("malformed disk counters"); result = 1; break; }
    if (!(f[0] || f[4] || f[11] || f[15]) || !proc_iostat_whole_disk (name)) continue;
    double t = uptime;
    char *row;
    if (!extended) {
      row = proc_iostat_fmt ("%-13s %8.2f %12.2f %12.2f %12.2f %10"PRIu64" %10"PRIu64" %10"PRIu64, name,
                             (double) (f[0] + f[4] + f[11]) / t, f[2] / 2.0 / t, f[6] / 2.0 / t, f[13] / 2.0 / t,
                             f[2] / 2, f[6] / 2, f[13] / 2);
    } else {
      /* r w d: ios merges sectors ms at 0 4 11; flush ios ms at 15 16. */
      char *part[3];
      for (int k = 0; k < 3; k++) {
        int b = k == 0 ? 0 : k == 1 ? 4 : 11;
        double ios = f[b], merges = f[b + 1], kb = f[b + 2] / 2.0, ms = f[b + 3];
        part[k] = proc_iostat_fmt (" %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f", ios / t, kb / t, merges / t,
                                   merges + ios > 0 ? merges * 100 / (merges + ios) : 0.0,
                                   ios > 0 ? ms / ios : 0.0, ios > 0 ? kb / ios : 0.0);
      }
      double util = f[9] / t / 10;
      row = proc_iostat_fmt ("%-13s%s%s%s %7.2f %7.2f %7.2f %6.2f", name, part[0], part[1], part[2],
                             f[15] / t, f[15] > 0 ? (double) f[16] / f[15] : 0.0,
                             f[10] / 1000.0 / t, util > 100 ? 100.0 : util);
      for (int k = 0; k < 3; k++) free (part[k]);
    }
    rows = xreallocarray (rows, nrows + 1, sizeof *rows);
    rows[nrows].name = proc_iostat_fmt ("%s", name);
    rows[nrows++].row = row;
  }
  free (line);
  if (proc_end (fp)) result = 1;
  if (nrows) qsort (rows, nrows, sizeof *rows, proc_iostat_row_cmp);
  for (size_t i = 0; i < nrows; i++) {
    if (!result) puts (rows[i].row);
    free (rows[i].name); free (rows[i].row);
  }
  free (rows);
  puts ("");
  return result;
}
static int
proc_iostat (WORD_LIST *args)
{
  int show = 0;
  for (; args; args = args->next) {
    const char *w = args->word->word;
    if (w[0] != '-' || !w[1]) return EX_USAGE;
    for (const char *p = w + 1; *p; p++) {
      if (*p == 'c') show |= IOS_CPU;
      else if (*p == 'd') show |= IOS_DEV;
      else if (*p == 'x') show |= IOS_EXT;
      else if (*p == 'k' || *p == 'y' || *p == 'z') ;   /* kB is the unit; one since-boot report */
      else return EX_USAGE;
    }
  }
  /* Neither -c nor -d: both reports, as sysstat; -x asks for devices. */
  int cpu = (show & IOS_CPU) || !(show & IOS_DEV);
  int dev = (show & (IOS_DEV | IOS_EXT)) || !(show & IOS_CPU);
  double uptime = 0;
  if (dev && (uptime = proc_uptime ()) <= 0) return 1;
  proc_iostat_banner ();
  if (cpu && proc_iostat_cpu ()) return 1;
  int result = dev ? proc_iostat_devices ((show & IOS_EXT) != 0, uptime) : 0;
  if (!dev) puts ("");   /* sysstat ends a CPU-only report with one more */
  puts ("");
  return result;
}

/* stat's command is parenthesized and can contain spaces and ')' characters.
   Only fields needed by these reports are parsed; the final ')' delimits it. */
static int proc_task (const char *pid, int raw, int terse, double uptime, int quiet)
{
  FILE *fp = proc_open (pid, "stat", quiet);
  if (!fp) return quiet ? 0 : 1;
  char *line = NULL; size_t cap = 0;
  ssize_t length = getline (&line, &cap, fp);
  int failed = proc_end (fp);
  if (length < 0 || failed) { free (line); return 1; }
  if (raw) { fwrite (line, 1, (size_t) length, stdout); free (line); return 0; }
  char *start = strchr (line, '('), *end = strrchr (line, ')');
  uint64_t values[52] = {0}; char state = 0;
  int valid = start && end && end > start && end[1] == ' ' && end[2] && end[3] == ' ';
  if (valid) {
    state = end[2]; *end = 0;
    char *cursor = end + 4, *save = NULL;
    for (int field = 4; field <= 24; field++) {
      char *token = strtok_r (field == 4 ? cursor : NULL, " \t\n", &save);
      if (!token) { valid = 0; break; }
      /* Signed fields (tty, child times, priority) are skipped. */
      if (field != 4 && field != 14 && field != 15 && field != 20 && field != 22 && field != 23 && field != 24) continue;
      errno = 0; char *tail; values[field] = strtoull (token, &tail, 10);
      if (token[0] == '-' || errno || tail == token || *tail) { valid = 0; break; }
    }
  }
  if (!valid) { free (line); if (!quiet) builtin_error ("%s: malformed process stat", pid); return quiet ? 0 : 1; }
  long ticks = sysconf (_SC_CLK_TCK), pagesize = sysconf (_SC_PAGESIZE);
  if (ticks <= 0 || pagesize <= 0) { free (line); return 1; }
  if (terse) {
    double elapsed = uptime - (double) values[22]/ticks;
    double factor = elapsed > 0 ? 100.0 / ticks / elapsed : 0;
    printf ("%s %.2f %.2f %.2f %.0Lf %s\n", pid,
            values[14]*factor, values[15]*factor, ((double) values[14]+values[15])*factor,
            (long double) values[24]*pagesize/1024, start+1);
  } else {
    printf ("Process: %s (%s)\nState: %c\nParent: %"PRIu64"\nThreads: %"PRIu64
            "\nUser seconds: %.2f\nSystem seconds: %.2f\nVirtual bytes: %"PRIu64
            "\nResident KiB: %.0Lf\n", pid, start+1, state, values[4], values[20],
            (double) values[14]/ticks, (double) values[15]/ticks, values[23],
            (long double) values[24]*pagesize/1024);
  }
  free (line); return 0;
}
static int proc_dir_filter (const struct dirent *entry) { return proc_pid (entry->d_name); }
static int proc_pidstat (const char *pid)
{
  double uptime = proc_uptime ();
  if (uptime <= 0) return 1;
  puts ("PID %usr %system %CPU RSS_KiB Command");
  if (pid) return proc_task (pid, 0, 1, uptime, 0);
  struct dirent **entries;
  int n = scandir (proc_root (), &entries, proc_dir_filter, versionsort);
  if (n < 0) { builtin_error ("%s: %s", proc_root (), strerror (errno)); return 1; }
  int result = 0;
  for (int i = 0; i < n; i++) {
    result |= proc_task (entries[i]->d_name, 0, 1, uptime, 1);
    free (entries[i]);
  }
  free (entries); return result;
}
/* procps pmap's header: "PID:   COMMAND ARGS" from cmdline, "[comm]" for
   a process without one (a kernel thread), or "PID:" when neither reads. */
static void proc_maps_header (const char *pid)
{
  printf ("%s:", pid);
  FILE *fp = proc_open (pid, "cmdline", 1);
  char buf[4096]; size_t n = 0;
  if (fp) { n = fread (buf, 1, sizeof buf - 1, fp); fclose (fp); }
  while (n && buf[n - 1] == 0) n--;
  if (n) {
    for (size_t i = 0; i < n; i++) if (!buf[i]) buf[i] = ' ';
    buf[n] = 0;
    printf ("   %s\n", buf);
    return;
  }
  fp = proc_open (pid, "comm", 1);
  if (fp && fgets (buf, sizeof buf, fp)) {
    buf[strcspn (buf, "\n")] = 0;
    printf ("   [%s]", buf);
  }
  if (fp) fclose (fp);
  putchar ('\n');
}
static int proc_maps (const char *pid, int extended, int libraries)
{
  FILE *fp = proc_open (pid, "maps", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0; long double total = 0;
  char **seen = NULL; size_t count = 0;
  if (libraries) printf ("%s:\n", pid);
  else proc_maps_header (pid);
  if (extended) puts ("Address Kbytes Mode Offset Mapping");
  int result = 0;
  while (getline (&line, &cap, fp) >= 0) {
    uint64_t start, end, offset, inode; unsigned major, minor; char mode[5]; int position = 0;
    if (sscanf (line, "%"SCNx64"-%"SCNx64" %4s %"SCNx64" %x:%x %"SCNu64" %n",
                &start, &end, mode, &offset, &major, &minor, &inode, &position) != 7 || end < start || !position) {
      builtin_error ("%s: malformed mapping", pid); result = 1; break;
    }
    char *name = line + position;
    name[strcspn (name, "\n")] = 0;
    if (libraries) {
      if (*name != '/' || !strstr (name, ".so")) continue;
      size_t i; for (i = 0; i < count; i++) if (!strcmp (seen[i], name)) break;
      if (i < count) continue;
      seen = xreallocarray (seen, count + 1, sizeof *seen);
      size_t len = strlen (name) + 1; seen[count] = xmalloc (len); memcpy (seen[count++], name, len);
      puts (name);
    } else if (extended) {
      long double kib = (end - start)/1024.0L; total += kib;
      printf ("%016"PRIx64" %.0Lf %s %016"PRIx64" %s\n", start, kib, mode, offset, *name ? name : "[anon]");
    } else {
      /* procps: the file's base name, else [ stack ] or [ anon ]; the mode
         is rwx, then s for a shared mapping, then - (no MAP_NORESERVE). */
      long double kib = (end - start)/1024.0L; total += kib;
      char perms[6] = { mode[0], mode[1], mode[2], mode[3] == 's' ? 's' : '-', '-', 0 };
      const char *slash = strrchr (name, '/');
      const char *shown = slash ? (slash[1] ? slash + 1 : slash)
                        : !strcmp (name, "[stack]") ? "  [ stack ]" : "  [ anon ]";
      printf ("%016"PRIx64" %6.0LfK %s %s\n", start, kib, perms, shown);
    }
  }
  for (size_t i = 0; i < count; i++) free (seen[i]); free (seen);
  if (extended) printf ("total %.0LfK\n", total);
  else if (!libraries) printf (" total %16.0LfK\n", total);
  free (line); return proc_end (fp) || result;
}
static void proc_help (void)
{
  puts ("procstat iostat [-cdx] | mpstat [-P ALL] | sar [-u] | pidstat [-p PID]\n"
        "procstat prtstat [-r] PID... | pmap [-x] PID... | pldd PID\n"
        "Linux snapshots. CPU/disk averages are since boot; process CPU averages\n"
        "are since process start. iostat prints sysstat's avg-cpu (-c), device\n"
        "(-d) and extended device (-x) reports. pmap prints procps's report;\n"
        "pmap -x adds file offsets; pldd lists mapped shared-object paths.\n"
        "BASHOS_PROC_ROOT selects an alternate proc tree.");
}
int procstat_builtin (WORD_LIST *list)
{
  clearerr (stdout);
  if (!list) { proc_help (); return EX_USAGE; }
  const char *verb = list->word->word; WORD_LIST *args = list->next;
  if (!strcmp (verb, "--help") || (args && (!strcmp (args->word->word, "--help") || !strcmp (args->word->word, "-h")))) {
    proc_help (); return 0;
  }
  int result = EX_USAGE;
  if (!strcmp (verb, "iostat")) {
    result = proc_iostat (args);
  } else if (!strcmp (verb, "mpstat") || !strcmp (verb, "sar")) {
    if (!args) result = proc_cpu (0);
    else if (!strcmp (verb, "sar") && !args->next && !strcmp (args->word->word, "-u")) result = proc_cpu (0);
    else if (!strcmp (verb, "mpstat") && args->next && !args->next->next && !strcmp (args->word->word, "-P") && !strcmp (args->next->word->word, "ALL")) result = proc_cpu (1);
  } else if (!strcmp (verb, "pidstat")) {
    if (!args) result = proc_pidstat (NULL);
    else if (!strcmp (args->word->word, "-p") && args->next && !args->next->next && proc_pid (args->next->word->word)) result = proc_pidstat (args->next->word->word);
  } else if (!strcmp (verb, "prtstat") || !strcmp (verb, "pmap") || !strcmp (verb, "pldd")) {
    int raw = 0, extended = 0, libraries = !strcmp (verb, "pldd");
    if (args && !strcmp (verb, "prtstat") && !strcmp (args->word->word, "-r")) { raw = 1; args = args->next; }
    if (args && !strcmp (verb, "pmap") && !strcmp (args->word->word, "-x")) { extended = 1; args = args->next; }
    int valid = args != NULL && (!libraries || !args->next);
    for (WORD_LIST *p = args; p; p = p->next) if (!proc_pid (p->word->word)) valid = 0;
    if (valid) {
      result = 0;
      for (WORD_LIST *p = args; p; p = p->next)
        result |= !strcmp (verb, "prtstat") ? proc_task (p->word->word, raw, 0, 0, 0) : proc_maps (p->word->word, extended, libraries);
    }
  }
  if (result == EX_USAGE) builtin_usage ();
  if (fflush (stdout) == EOF || ferror (stdout)) result = 1;
  return result;
}
char *procstat_doc[] = {
  "Linux CPU, disk, process, and mapping snapshots (procstat --help for options).",
  "CPU/disk counters are averaged since boot; process CPU usage since start.",
  "iostat -c/-d/-x print sysstat's reports; pmap prints procps's report.",
  "prtstat -r emits raw stat; pmap -x adds offsets; pldd lists mapped .so paths.",
  "BASHOS_PROC_ROOT selects the proc tree. No interval or history collection.",
  (char *) NULL
};
struct builtin procstat_struct = {
  "procstat", procstat_builtin, BUILTIN_ENABLED, procstat_doc,
  "procstat iostat|mpstat|sar|pidstat|prtstat|pmap|pldd [OPTIONS]", 0
};
