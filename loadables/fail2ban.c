/* SPDX-License-Identifier: MIT */
/* fail2ban.c - fail2ban-class control plane (Debian-server-parity AUDIT-6.6).
 *
 *   fail2ban selftest
 *   fail2ban parse-command VERB [ARG...]
 *   fail2ban validate-ip   IP
 *   fail2ban validate-jail JAIL
 *   fail2ban format-status DB [JAIL]
 *   fail2ban banip   DB JAIL IP
 *   fail2ban unbanip DB JAIL IP
 *   fail2ban -s SOCKET status
 *   fail2ban -s SOCKET reload
 *
 * parse-command, the validators, and format-status never mutate the db.
 * banip appends one `<ip>\t<jail>\t<epoch>` row. unbanip removes only rows
 * whose ip and jail fields match and leaves every other line in place.
 * Invalid tokens return status 2 with an "invalid" diagnostic and do not
 * create the database or call fw.
 *
 * fw is the only firewall actor. This file never execs nft or iptables.
 *   banip   -> fw deny  IP
 *   unbanip -> fw unban IP
 *   reload  -> fw restore          (re-apply the saved ruleset)
 * status/reload with -s SOCKET are a fail2ban-server client: one command
 * line ("status\n" or "reload\n"), write-side shutdown, then the reply
 * bytes copied unchanged to stdout. reload calls fw only after that
 * exchange. status does not call fw.
 *
 * Validators:
 *   IPv4  ^[0-9]{1,3}(\.[0-9]{1,3}){3}$
 *   IPv6  ^[0-9A-Fa-f:]+$  AND contains ':'
 *   jail  ^[A-Za-z0-9_.-]{1,64}$
 * Status formatting: sorted-unique jail list, file-order banned-IP list,
 * single-space joins with no trailing space.
 *
 * Exit: 0 ok, 1 operational failure, 2 usage / out-of-subset / invalid token.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "loadables.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define F2B_MAX_LINE   1024
#define F2B_MAX_BANS   200000

/* ---- validators (replicate lib/fail2ban-db.sh) ---- */

static int
f2b_valid_ip (const char *ip)
{
  if (ip == NULL || ip[0] == '\0')
    return 0;

  /* IPv4: four 1-3 digit groups separated by single dots. */
  {
    const char *p = ip;
    int groups = 0, digits;
    int ok = 1;
    while (ok)
      {
        digits = 0;
        while (*p >= '0' && *p <= '9') { p++; digits++; }
        if (digits < 1 || digits > 3) { ok = 0; break; }
        groups++;
        if (*p == '.') { p++; continue; }
        if (*p == '\0') break;
        ok = 0;
      }
    if (ok && groups == 4 && *p == '\0')
      return 1;
  }

  /* IPv6 (bracket-free): only hex digits and colons, and at least one colon. */
  {
    int has_colon = 0;
    const char *p;
    for (p = ip; *p; p++)
      {
        if (*p == ':') { has_colon = 1; continue; }
        if (!isxdigit ((unsigned char) *p))
          return 0;
      }
    if (has_colon)
      return 1;
  }
  return 0;
}

static int
f2b_valid_jail (const char *j)
{
  size_t n, i;
  if (j == NULL)
    return 0;
  n = strlen (j);
  if (n < 1 || n > 64)
    return 0;
  for (i = 0; i < n; i++)
    {
      int c = (unsigned char) j[i];
      if (!(isalnum (c) || c == '_' || c == '.' || c == '-'))
        return 0;
    }
  return 1;
}

/* ---- accepted fail2ban-client argv subset (replicate fail2ban-client.sh) ---- */

static int
f2b_in_subset (const char *verb)
{
  return verb && (!strcmp (verb, "status") || !strcmp (verb, "banip")
                  || !strcmp (verb, "unbanip") || !strcmp (verb, "reload"));
}

static int
f2b_known_unsupported (const char *verb)
{
  /* commands fail2ban-client.sh explicitly rejects as out-of-subset */
  return verb && (!strcmp (verb, "set") || !strcmp (verb, "get")
                  || !strcmp (verb, "start") || !strcmp (verb, "stop")
                  || !strcmp (verb, "add") || !strcmp (verb, "ping")
                  || !strcmp (verb, "reload-all"));
}

/* ---- ban.db parsing + status formatting ---- */

struct f2b_ban { char *ip; char *jail; };

static void
f2b_free_bans (struct f2b_ban *b, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) { free (b[i].ip); free (b[i].jail); }
  free (b);
}

/* Read DB into a bounded array of {ip,jail}. Returns count, or -1 on a read
 * error other than "missing file" (missing file => 0 bans, like the shell). */
static long
f2b_read_db (const char *path, struct f2b_ban **out)
{
  FILE *fp;
  char line[F2B_MAX_LINE];
  struct f2b_ban *bans = NULL;
  size_t cap = 0, n = 0;

  *out = NULL;
  fp = fopen (path, "r");
  if (fp == NULL)
    return (errno == ENOENT) ? 0 : -1;

  while (fgets (line, sizeof line, fp))
    {
      char *tab1, *tab2, *nl;
      if (n >= F2B_MAX_BANS)
        break;
      nl = strchr (line, '\n');
      if (nl) *nl = '\0';
      else { int c; while ((c = fgetc (fp)) != '\n' && c != EOF) ; } /* drop overlong tail */
      if (line[0] == '\0')
        continue;
      tab1 = strchr (line, '\t');
      if (tab1 == NULL)
        continue;                         /* malformed: no jail field */
      *tab1 = '\0';
      tab2 = strchr (tab1 + 1, '\t');
      if (tab2) *tab2 = '\0';             /* epoch (ignored) trimmed off */
      if (line[0] == '\0' || (tab1 + 1)[0] == '\0')
        continue;                         /* empty ip or jail */
      if (n == cap)
        {
          size_t ncap = cap ? cap * 2 : 64;
          struct f2b_ban *nb = realloc (bans, ncap * sizeof *nb);
          if (nb == NULL) { f2b_free_bans (bans, n); fclose (fp); return -1; }
          bans = nb; cap = ncap;
        }
      bans[n].ip = strdup (line);
      bans[n].jail = strdup (tab1 + 1);
      if (bans[n].ip == NULL || bans[n].jail == NULL)
        { free (bans[n].ip); free (bans[n].jail); f2b_free_bans (bans, n); fclose (fp); return -1; }
      n++;
    }
  fclose (fp);
  *out = bans;
  return (long) n;
}

static int
f2b_cmp_str (const void *a, const void *b)
{
  return strcmp (*(const char *const *) a, *(const char *const *) b);
}

/* Print `<items joined by single space, no trailing space>` then newline. */
static void
f2b_print_joined (char **items, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    {
      if (i) putchar (' ');
      fputs (items[i], stdout);
    }
  putchar ('\n');
}

static int
f2b_format_status (const char *db, const char *jail)
{
  struct f2b_ban *bans;
  long n;

  n = f2b_read_db (db, &bans);
  if (n < 0)
    { builtin_error ("format-status: cannot read db: %s", db); return EXECUTION_FAILURE; }

  if (jail == NULL)
    {
      /* distinct jails, sorted-unique (mirrors f2b_db_jails | sort -u) */
      char **jails = NULL;
      size_t jn = 0, uniq = 0, i;
      if (n > 0)
        {
          jails = malloc ((size_t) n * sizeof *jails);
          if (jails == NULL) { f2b_free_bans (bans, (size_t) n); builtin_error ("oom"); return EXECUTION_FAILURE; }
          for (i = 0; i < (size_t) n; i++) jails[jn++] = bans[i].jail;
          qsort (jails, jn, sizeof *jails, f2b_cmp_str);
          for (i = 0; i < jn; i++)
            if (i == 0 || strcmp (jails[i], jails[uniq - 1]) != 0)
              jails[uniq++] = jails[i];
        }
      printf ("Status\n");
      printf ("|- Number of jails:\t%zu\n", uniq);
      printf ("`- Jail list:\t");
      f2b_print_joined (jails, uniq);
      free (jails);
      f2b_free_bans (bans, (size_t) (n < 0 ? 0 : n));
      return EXECUTION_SUCCESS;
    }

  if (!f2b_valid_jail (jail))
    { f2b_free_bans (bans, (size_t) n); builtin_error ("format-status: invalid jail name: %s", jail); return EX_USAGE; }

  /* banned IPs for one jail, in file order (mirrors f2b_db_list JAIL) */
  {
    char **ips = NULL;
    size_t cnt = 0, i;
    if (n > 0)
      {
        ips = malloc ((size_t) n * sizeof *ips);
        if (ips == NULL) { f2b_free_bans (bans, (size_t) n); builtin_error ("oom"); return EXECUTION_FAILURE; }
        for (i = 0; i < (size_t) n; i++)
          if (strcmp (bans[i].jail, jail) == 0)
            ips[cnt++] = bans[i].ip;
      }
    printf ("Status for the jail: %s\n", jail);
    printf ("|- Currently banned:\t%zu\n", cnt);
    printf ("`- Banned IP list:\t");
    f2b_print_joined (ips, cnt);
    free (ips);
  }
  f2b_free_bans (bans, (size_t) n);
  return EXECUTION_SUCCESS;
}

/* ---- self-test ---- */

static int
f2b_selftest (void)
{
  int fails = 0;
#define CK(cond, msg) do { if (!(cond)) { printf ("FAIL: %s\n", msg); fails++; } } while (0)
  CK (f2b_valid_ip ("1.2.3.4") == 1, "ipv4 1.2.3.4 valid");
  CK (f2b_valid_ip ("203.0.113.7") == 1, "ipv4 203.0.113.7 valid");
  CK (f2b_valid_ip ("1.2.3") == 0, "ipv4 1.2.3 invalid (3 groups)");
  CK (f2b_valid_ip ("1.2.3.4.5") == 0, "ipv4 5 groups invalid");
  CK (f2b_valid_ip ("12.34.56.789") == 1, "ipv4 1-3 digit groups (loose, matches shell)");
  CK (f2b_valid_ip ("1.2.3.4567") == 0, "ipv4 4-digit group invalid");
  CK (f2b_valid_ip ("fe80::1") == 1, "ipv6 fe80::1 valid");
  CK (f2b_valid_ip ("2001:db8::dead:beef") == 1, "ipv6 valid");
  CK (f2b_valid_ip ("not.an.ip.x") == 0, "alpha octet invalid");
  CK (f2b_valid_ip ("g::1") == 0, "ipv6 non-hex invalid");
  CK (f2b_valid_ip ("") == 0, "empty invalid");
  CK (f2b_valid_jail ("sshd") == 1, "jail sshd valid");
  CK (f2b_valid_jail ("nginx-http-auth") == 1, "jail with dash valid");
  CK (f2b_valid_jail ("bad jail") == 0, "jail with space invalid");
  CK (f2b_valid_jail ("") == 0, "empty jail invalid");
  CK (f2b_in_subset ("status") && f2b_in_subset ("banip")
      && f2b_in_subset ("unbanip") && f2b_in_subset ("reload"), "accepted subset");
  CK (!f2b_in_subset ("set") && f2b_known_unsupported ("set"), "set rejected/known");
  CK (!f2b_in_subset ("bogus") && !f2b_known_unsupported ("bogus"), "unknown verb");
#undef CK
  if (fails == 0)
    { printf ("fail2ban selftest: OK\n"); return EXECUTION_SUCCESS; }
  printf ("fail2ban selftest: %d failure(s)\n", fails);
  return EXECUTION_FAILURE;
}

/* ---- firewall actor (fw only; never nft or iptables) ---- */

struct f2b_child_guard {
  struct sigaction old_action;
  sigset_t old_mask;
};

static void
f2b_child_guard_begin (struct f2b_child_guard *g)
{
  struct sigaction chld_dfl;
  sigset_t chld_set;

  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &g->old_action);
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  sigprocmask (SIG_BLOCK, &chld_set, &g->old_mask);
}

static void
f2b_child_guard_parent_end (struct f2b_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
  sigaction (SIGCHLD, &g->old_action, NULL);
}

static void
f2b_child_guard_child_end (struct f2b_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

/* Resolve fw from PATH in the parent so a temporary PATH= assignment is
 * visible to bash's getenv. The child execs that absolute path. */
static int
f2b_find_fw (char *out, size_t outsz)
{
  const char *path, *p;

  path = getenv ("PATH");
  if (path == NULL || path[0] == '\0')
    return -1;
  p = path;
  for (;;)
    {
      const char *start = p;
      size_t n;
      int wr;

      while (*p && *p != ':')
        p++;
      n = (size_t) (p - start);
      if (n == 0)
        wr = snprintf (out, outsz, "./fw");
      else
        wr = snprintf (out, outsz, "%.*s/fw", (int) n, start);
      if (wr > 0 && (size_t) wr < outsz && access (out, X_OK) == 0)
        return 0;
      if (*p != ':')
        break;
      p++;
    }
  return -1;
}

/* op is "deny", "unban", or "restore". ip is NULL for restore.
 * Returns 0 when fw exits 0. stdout/stderr of fw are discarded so a
 * chatty actor cannot change this builtin's stdout. */
static int
f2b_fw (const char *op, const char *ip)
{
  char fwpath[PATH_MAX];
  char *argv[4];
  struct f2b_child_guard guard;
  pid_t pid;
  int st, devnull;

  if (f2b_find_fw (fwpath, sizeof fwpath) != 0)
    {
      builtin_error ("fw %s: fw not executable on PATH", op);
      return -1;
    }
  argv[0] = fwpath;
  argv[1] = (char *) op;
  argv[2] = (char *) ip;          /* NULL terminates when ip is NULL */
  argv[3] = NULL;

  fflush (stdout);
  fflush (stderr);
  f2b_child_guard_begin (&guard);
  pid = fork ();
  if (pid < 0)
    {
      f2b_child_guard_parent_end (&guard);
      builtin_error ("fw %s: fork: %s", op, strerror (errno));
      return -1;
    }
  if (pid == 0)
    {
      f2b_child_guard_child_end (&guard);
      devnull = open ("/dev/null", O_RDWR);
      if (devnull >= 0)
        {
          dup2 (devnull, STDIN_FILENO);
          dup2 (devnull, STDOUT_FILENO);
          dup2 (devnull, STDERR_FILENO);
          if (devnull > 2)
            close (devnull);
        }
      execv (fwpath, argv);
      _exit (127);
    }
  st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR)
        continue;
      f2b_child_guard_parent_end (&guard);
      builtin_error ("fw %s: wait: %s", op, strerror (errno));
      return -1;
    }
  f2b_child_guard_parent_end (&guard);
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0)
    {
      builtin_error ("fw %s failed", op);
      return -1;
    }
  return 0;
}

static int
f2b_write_all (int fd, const char *buf, size_t n)
{
  while (n > 0)
    {
      ssize_t w = write (fd, buf, n);
      if (w < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (w == 0)
        return -1;
      buf += w;
      n -= (size_t) w;
    }
  return 0;
}

static int
f2b_append_ban (const char *db, const char *ip, const char *jail)
{
  char line[F2B_MAX_LINE];
  time_t now;
  int n, fd;

  now = time (NULL);
  if (now < 0)
    {
      builtin_error ("banip: time: %s", strerror (errno));
      return -1;
    }
  n = snprintf (line, sizeof line, "%s\t%s\t%ld\n", ip, jail, (long) now);
  if (n < 0 || (size_t) n >= sizeof line)
    {
      builtin_error ("banip: row too long");
      return -1;
    }
  fd = open (db, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
  if (fd < 0)
    {
      builtin_error ("banip: cannot write %s: %s", db, strerror (errno));
      return -1;
    }
  if (f2b_write_all (fd, line, (size_t) n) < 0)
    {
      builtin_error ("banip: write %s: %s", db, strerror (errno));
      close (fd);
      return -1;
    }
  if (close (fd) < 0)
    {
      builtin_error ("banip: close %s: %s", db, strerror (errno));
      return -1;
    }
  return 0;
}

/* True when LINE is `<ip>\t<jail>\t...` for this ip and jail. LINE may
 * include a trailing newline. The buffer is mutated. */
static int
f2b_row_match (char *line, const char *ip, const char *jail)
{
  char *nl, *tab, *tab2;

  nl = strchr (line, '\n');
  if (nl)
    *nl = '\0';
  if (nl && nl > line && nl[-1] == '\r')
    nl[-1] = '\0';
  tab = strchr (line, '\t');
  if (tab == NULL || tab == line)
    return 0;
  *tab = '\0';
  if (strcmp (line, ip) != 0)
    return 0;
  tab2 = strchr (tab + 1, '\t');
  if (tab2)
    *tab2 = '\0';
  if ((tab + 1)[0] == '\0')
    return 0;
  return strcmp (tab + 1, jail) == 0;
}

/* Drop matching rows. A missing file is already empty. Other lines,
 * including malformed ones, are copied unchanged. */
static int
f2b_remove_ban (const char *db, const char *ip, const char *jail)
{
  FILE *in, *out;
  char line[F2B_MAX_LINE];
  char tmp[PATH_MAX];
  struct stat st;
  int tfd, dirn;
  const char *slash;

  in = fopen (db, "r");
  if (in == NULL)
    {
      if (errno == ENOENT)
        return 0;
      builtin_error ("unbanip: cannot read %s: %s", db, strerror (errno));
      return -1;
    }
  slash = strrchr (db, '/');
  if (slash)
    dirn = snprintf (tmp, sizeof tmp, "%.*s/.f2b-XXXXXX", (int) (slash - db), db);
  else
    dirn = snprintf (tmp, sizeof tmp, ".f2b-XXXXXX");
  if (dirn < 0 || (size_t) dirn >= sizeof tmp)
    {
      fclose (in);
      builtin_error ("unbanip: path too long");
      return -1;
    }
  tfd = mkstemp (tmp);
  if (tfd < 0)
    {
      builtin_error ("unbanip: temp file: %s", strerror (errno));
      fclose (in);
      return -1;
    }
  if (fstat (fileno (in), &st) == 0)
    fchmod (tfd, st.st_mode & 0777);
  out = fdopen (tfd, "w");
  if (out == NULL)
    {
      builtin_error ("unbanip: temp file: %s", strerror (errno));
      close (tfd);
      unlink (tmp);
      fclose (in);
      return -1;
    }
  while (fgets (line, sizeof line, in))
    {
      size_t n = strlen (line);
      int has_nl = n > 0 && line[n - 1] == '\n';
      int partial = !has_nl && n + 1 == sizeof line;
      int drop = 0;

      if (!partial)
        {
          char scratch[F2B_MAX_LINE];
          memcpy (scratch, line, n + 1);
          drop = f2b_row_match (scratch, ip, jail);
        }
      if (!drop && fputs (line, out) == EOF)
        {
          builtin_error ("unbanip: write %s: %s", db, strerror (errno));
          fclose (out);
          unlink (tmp);
          fclose (in);
          return -1;
        }
      if (partial)
        {
          int c;
          while ((c = fgetc (in)) != EOF && c != '\n')
            {
              if (fputc (c, out) == EOF)
                {
                  builtin_error ("unbanip: write %s: %s", db, strerror (errno));
                  fclose (out);
                  unlink (tmp);
                  fclose (in);
                  return -1;
                }
            }
          if (c == '\n' && fputc ('\n', out) == EOF)
            {
              builtin_error ("unbanip: write %s: %s", db, strerror (errno));
              fclose (out);
              unlink (tmp);
              fclose (in);
              return -1;
            }
        }
    }
  if (ferror (in))
    {
      builtin_error ("unbanip: read %s: %s", db, strerror (errno));
      fclose (out);
      unlink (tmp);
      fclose (in);
      return -1;
    }
  if (fclose (out) != 0)
    {
      builtin_error ("unbanip: close temp: %s", strerror (errno));
      unlink (tmp);
      fclose (in);
      return -1;
    }
  fclose (in);
  if (rename (tmp, db) < 0)
    {
      builtin_error ("unbanip: rename %s: %s", db, strerror (errno));
      unlink (tmp);
      return -1;
    }
  return 0;
}

static int
f2b_check_tokens (const char *cmd, const char *jail, const char *ip)
{
  if (!f2b_valid_jail (jail))
    {
      builtin_error ("%s: invalid jail name: %s", cmd, jail);
      return -1;
    }
  if (!f2b_valid_ip (ip))
    {
      builtin_error ("%s: invalid IP address: %s", cmd, ip);
      return -1;
    }
  return 0;
}

static int
f2b_banip (const char *db, const char *jail, const char *ip)
{
  if (f2b_check_tokens ("banip", jail, ip) != 0)
    return EX_USAGE;
  if (f2b_fw ("deny", ip) != 0)
    return EXECUTION_FAILURE;
  if (f2b_append_ban (db, ip, jail) != 0)
    return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

static int
f2b_unbanip (const char *db, const char *jail, const char *ip)
{
  if (f2b_check_tokens ("unbanip", jail, ip) != 0)
    return EX_USAGE;
  if (f2b_fw ("unban", ip) != 0)
    return EXECUTION_FAILURE;
  if (f2b_remove_ban (db, ip, jail) != 0)
    return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

/* ---- fail2ban-server socket client ---- */

static int
f2b_copy_reply (int fd)
{
  char buf[4096];

  for (;;)
    {
      ssize_t r = read (fd, buf, sizeof buf);
      size_t put;

      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          builtin_error ("socket read: %s", strerror (errno));
          return -1;
        }
      if (r == 0)
        return 0;
      put = fwrite (buf, 1, (size_t) r, stdout);
      if (put != (size_t) r)
        {
          builtin_error ("status reply: short write");
          return -1;
        }
    }
}

/* Send "<verb>\n", half-close, copy the server's bytes to stdout. */
static int
f2b_server_client (const char *sock_path, const char *verb)
{
  struct sockaddr_un addr;
  struct timeval tv;
  char req[64];
  size_t len;
  int fd, reqlen;

  len = strlen (sock_path);
  if (len == 0 || len >= sizeof addr.sun_path)
    {
      builtin_error ("socket path invalid");
      return EXECUTION_FAILURE;
    }
  reqlen = snprintf (req, sizeof req, "%s\n", verb);
  if (reqlen < 0 || (size_t) reqlen >= sizeof req)
    return EXECUTION_FAILURE;

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
      builtin_error ("socket: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  memset (&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  memcpy (addr.sun_path, sock_path, len + 1);
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

  while (connect (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    {
      if (errno == EINTR)
        continue;
      builtin_error ("connect %s: %s", sock_path, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  if (f2b_write_all (fd, req, (size_t) reqlen) < 0
      || shutdown (fd, SHUT_WR) < 0)
    {
      builtin_error ("socket send: %s", strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  if (f2b_copy_reply (fd) != 0)
    {
      close (fd);
      return EXECUTION_FAILURE;
    }
  close (fd);
  fflush (stdout);
  return EXECUTION_SUCCESS;
}

/* ---- verb dispatch ---- */

static int
f2b_parse_command (WORD_LIST *args)
{
  const char *verb;
  if (args == NULL)
    { builtin_error ("parse-command: need VERB"); return EX_USAGE; }
  verb = args->word->word;
  if (f2b_in_subset (verb))
    { printf ("%s\n", verb); return EXECUTION_SUCCESS; }
  if (f2b_known_unsupported (verb))
    { builtin_error ("%s: not in accepted subset (status banip unbanip reload)", verb); return EX_USAGE; }
  builtin_error ("%s: unknown command (accepted: status banip unbanip reload)", verb);
  return EX_USAGE;
}

static int
f2b_take_socket (WORD_LIST **list, const char **sock)
{
  *sock = NULL;
  while (*list && (*list)->word && (*list)->word->word
         && (*list)->word->word[0] == '-')
    {
      const char *opt = (*list)->word->word;
      if (!strcmp (opt, "--"))
        {
          *list = (*list)->next;
          break;
        }
      if (!strcmp (opt, "-s"))
        {
          WORD_LIST *val = (*list)->next;
          if (val == NULL || val->word == NULL || val->word->word == NULL)
            {
              builtin_error ("-s: need SOCKET");
              return -1;
            }
          *sock = val->word->word;
          *list = val->next;
          continue;
        }
      builtin_error ("unknown option: %s", opt);
      return -1;
    }
  return 0;
}

int
fail2ban_builtin (WORD_LIST *list)
{
  const char *cmd, *sock;
  WORD_LIST *args;

  if (list == NULL)
    { builtin_usage (); return EX_USAGE; }
  if (f2b_take_socket (&list, &sock) != 0)
    return EX_USAGE;
  if (list == NULL || list->word == NULL)
    { builtin_usage (); return EX_USAGE; }
  cmd = list->word->word;
  args = list->next;

  if (sock)
    {
      int rc;
      if (strcmp (cmd, "status") != 0 && strcmp (cmd, "reload") != 0)
        {
          builtin_error ("-s applies to status and reload");
          return EX_USAGE;
        }
      if (args)
        {
          builtin_error ("%s: too many arguments", cmd);
          return EX_USAGE;
        }
      rc = f2b_server_client (sock, cmd);
      if (rc != EXECUTION_SUCCESS)
        return rc;
      if (!strcmp (cmd, "reload") && f2b_fw ("restore", NULL) != 0)
        return EXECUTION_FAILURE;
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "selftest"))
    {
      if (args) { builtin_error ("selftest takes no args"); return EX_USAGE; }
      return f2b_selftest ();
    }
  if (!strcmp (cmd, "parse-command"))
    return f2b_parse_command (args);
  if (!strcmp (cmd, "validate-ip"))
    {
      if (args == NULL || args->next) { builtin_error ("validate-ip: need exactly one IP"); return EX_USAGE; }
      return f2b_valid_ip (args->word->word) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (cmd, "validate-jail"))
    {
      if (args == NULL || args->next) { builtin_error ("validate-jail: need exactly one JAIL"); return EX_USAGE; }
      return f2b_valid_jail (args->word->word) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (cmd, "format-status"))
    {
      const char *db, *jail = NULL;
      if (args == NULL) { builtin_error ("format-status: need DB [JAIL]"); return EX_USAGE; }
      db = args->word->word;
      if (args->next)
        {
          jail = args->next->word->word;
          if (args->next->next) { builtin_error ("format-status: too many arguments"); return EX_USAGE; }
        }
      return f2b_format_status (db, jail);
    }
  if (!strcmp (cmd, "banip") || !strcmp (cmd, "unbanip"))
    {
      const char *db, *jail, *ip;
      if (args == NULL || args->next == NULL || args->next->next == NULL
          || args->next->next->next != NULL)
        {
          builtin_error ("%s: need DB JAIL IP", cmd);
          return EX_USAGE;
        }
      db = args->word->word;
      jail = args->next->word->word;
      ip = args->next->next->word->word;
      if (!strcmp (cmd, "banip"))
        return f2b_banip (db, jail, ip);
      return f2b_unbanip (db, jail, ip);
    }

  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *fail2ban_doc[] = {
  "Native control-plane helper for the fail2ban-class engine.",
  "",
  "    fail2ban selftest",
  "    fail2ban parse-command VERB [ARG...]",
  "    fail2ban validate-ip   IP",
  "    fail2ban validate-jail JAIL",
  "    fail2ban format-status DB [JAIL]",
  "    fail2ban banip DB JAIL IP",
  "    fail2ban unbanip DB JAIL IP",
  "    fail2ban -s SOCKET status",
  "    fail2ban -s SOCKET reload",
  "",
  "Validates the accepted subset (status/banip/unbanip/reload) and IP/jail",
  "tokens, and formats TAB-separated ban.db into fail2ban-client status.",
  "format-status never mutates the db. banip appends <ip> TAB <jail> TAB",
  "<epoch> after `fw deny IP`. unbanip removes only that row after",
  "`fw unban IP`. Invalid tokens return status 2 and create no database.",
  "-s SOCKET speaks one command line to a fail2ban-server Unix socket and",
  "copies the reply to stdout. reload then runs `fw restore` to re-apply",
  "firewall state. nft and iptables are never executed.",
  "Exit: 0 ok, 1 failure (including false validate-ip/validate-jail predicates).",
  "Status 2 is usage, an out-of-subset command, or invalid parse-command tokens.",
  (char *) NULL
};

struct builtin fail2ban_struct = {
  "fail2ban",
  fail2ban_builtin,
  BUILTIN_ENABLED,
  fail2ban_doc,
  "fail2ban selftest|parse-command|validate-ip|validate-jail|format-status|banip|unbanip|-s SOCKET status|reload ...",
  0
};
