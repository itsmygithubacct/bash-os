/* SPDX-License-Identifier: MIT */
/* passwd.c — password verification for bash-os.
 *
 * Stage 35 first slice: move password verification out of shell scripts.
 * This loadable reads password bytes into C-owned memory, verifies the
 * existing Argon2id PHC strings from /etc/shadow, wipes the password buffer,
 * and returns only an exit status to Bash.
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
#include <stdint.h>
#include <termios.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashauth_pwverify.h"
#include "loadables.h"
#include "unwind_prot.h"

#define BPW_MAX_PASSWORD 4096
#define BPW_LOCK_FAIL_MAX 5
#define BPW_LOCK_WINDOW 600
#define BPW_LOCK_DURATION 900
#define BPW_AUTH_IOC_MAGIC 0xBA
#define BPW_AUTH_DEV "/dev/bashos-auth"
#define BPW_AUTH_FEAT_SECRETS (1ull << 0)

/* QUIT exits on a terminating signal without running the general unwind list,
   and runs an interrupt trap before unwinding.  Release this invocation's
   registered tty, secret and account resources before either path.  A nested
   interrupt count greater than one only decrements the count, without jumping. */
static void
bpw_check_signals (void)
{
  if (terminating_signal || interrupt_state == 1)
    run_unwind_frame ("passwd environment snapshot");
  QUIT;
}

/* RFC 9106 §4 lists two recommended argon2id parameter sets:
 *   - m=2^16 KiB (64 MiB), t=3, p=1  — recommended for high-security
 *     contexts. Was the bash-os default through v3.4.
 *   - m=2^14.246 KiB (~19 MiB), t=2, p=1 — minimum recommended for
 *     resource-constrained contexts.
 * bash-os historically shipped with a 128 MiB QEMU default, where a
 * 64 MiB mlock'd argon2 working set could run the guest into OOM-kill
 * on the first `passwd add`. The launcher now defaults to 512 MiB
 * to keep the initramfs-backed writable root above 128 MiB, but this
 * 19 MiB / t=2 / p=1 floor remains the conservative default for small
 * or overridden boots. Operators can override via PHCLIB_M / PHCLIB_T /
 * PHCLIB_P env vars (clamped to [1024,262144] / [1,10] / [1,8] at use
 * time). Re-tuned 2026-05-13; launcher default raised 2026-06-04. */
#define BPW_ARGON_M 19456
#define BPW_ARGON_T 2
#define BPW_ARGON_P 1
#define BPW_HASH_LEN 32

struct bpw_auth_version {
  unsigned int abi_major;
  unsigned int abi_minor;
  unsigned long long features;
  unsigned char reserved[16];
};

struct bpw_auth_handle {
  unsigned int id;
  unsigned int flags;
};

struct bpw_auth_secret_write {
  unsigned int id;
  unsigned int len;
  unsigned long long user_ptr;
};

struct bpw_auth_secret_export {
  unsigned int id;
  unsigned int len;
  unsigned long long user_ptr;
};

struct bpw_auth_secret_compare {
  unsigned int id_a;
  unsigned int id_b;
  unsigned int result;
  unsigned int flags;
};

#define BPW_AUTH_IOC_VERSION \
  _IOR(BPW_AUTH_IOC_MAGIC, 0x01, struct bpw_auth_version)
#define BPW_AUTH_IOC_NEW_SECRET \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x02, struct bpw_auth_handle)
#define BPW_AUTH_IOC_WRITE_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x03, struct bpw_auth_secret_write)
#define BPW_AUTH_IOC_SEAL_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x04, struct bpw_auth_handle)
#define BPW_AUTH_IOC_CLEAR_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x05, struct bpw_auth_handle)
#define BPW_AUTH_IOC_EXPORT_ONCE \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x06, struct bpw_auth_secret_export)
#define BPW_AUTH_IOC_SAME_SECRET \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x07, struct bpw_auth_secret_compare)

static unsigned int
bpw_env_uint (const char *name, unsigned int def, unsigned int min, unsigned int max)
{
  const char *s = getenv (name);
  if (!s || !*s) return def;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 10);
  if (end == s || *end != '\0' || v < min || v > max) return def;
  return (unsigned int) v;
}

typedef struct {
  unsigned int m, t, p;
  char salt_hex[129];
  char hash_hex[257];
} bpw_phc;

typedef struct {
  char name[64];
  unsigned int uid;
  unsigned int gid;
  char gecos[128];
  char home[256];
  char shell[256];
} bpw_user;

typedef struct {
  int fd;
  unsigned int id;
  int owns_fd;
} bpw_secret_ref;

typedef struct {
  char phc[512];
  int fd;
  dev_t dev;
  ino_t ino;
} bpw_auth_snapshot;

static int bpw_read_tty_password (const char *prompt, unsigned char **out, size_t *out_len);
static int bpw_verify_user_buf (const char *user, const unsigned char *pw, size_t pw_len);
static int bpw_temp_open (const char *path, char *tmp, size_t tmpsz, mode_t mode);
static int bpw_fsync_parent (const char *path);
static int bpw_id_in_file (const char *path, unsigned int id, int is_group);

static void
bpw_wipe (void *p, size_t n)
{
  if (!p || n == 0) return;
  crypto_wipe (p, n);
}

static void
bpw_release_tty_password (unsigned char *p)
{
  if (!p) return;
  bpw_wipe (p, BPW_MAX_PASSWORD);
  munlock (p, BPW_MAX_PASSWORD);
  munmap (p, BPW_MAX_PASSWORD);
}

static int
bpw_kernel_secrets_disabled (void)
{
  const char *v = getenv ("BASHPASSWD_KERNEL_SECRETS");
  return v && strcmp (v, "0") == 0;
}

static int
bpw_kernel_secrets_required (void)
{
  const char *v = getenv ("BASHPASSWD_REQUIRE_KERNEL_SECRETS");
  return v && strcmp (v, "0") != 0;
}

static int
bpw_auth_open_optional (void)
{
  if (bpw_kernel_secrets_disabled ())
    return -1;

  int fd = open (BPW_AUTH_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (bpw_kernel_secrets_required ())
        builtin_error ("%s: %s", BPW_AUTH_DEV, strerror (errno));
      return -1;
    }
  int fl = fcntl (fd, F_GETFD, 0);
  if (fl >= 0)
    (void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);

  struct bpw_auth_version v;
  memset (&v, 0, sizeof v);
  if (ioctl (fd, BPW_AUTH_IOC_VERSION, &v) < 0 ||
      v.abi_major != 1 ||
      (v.features & BPW_AUTH_FEAT_SECRETS) == 0)
    {
      if (bpw_kernel_secrets_required ())
        builtin_error ("%s: missing secret-slot support", BPW_AUTH_DEV);
      close (fd);
      return -1;
    }
  return fd;
}

static int
bpw_secret_new (bpw_secret_ref *s)
{
  int fd = bpw_auth_open_optional ();
  if (fd < 0)
    return bpw_kernel_secrets_required () ? -1 : -2;

  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  if (ioctl (fd, BPW_AUTH_IOC_NEW_SECRET, &h) < 0)
    {
      builtin_error ("kernel secret create: %s", strerror (errno));
      close (fd);
      return -1;
    }
  s->fd = fd;
  s->id = h.id;
  s->owns_fd = 1;
  return 0;
}

static int
bpw_secret_new_on_fd (int fd, bpw_secret_ref *s)
{
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  if (ioctl (fd, BPW_AUTH_IOC_NEW_SECRET, &h) < 0)
    {
      builtin_error ("kernel secret create: %s", strerror (errno));
      return -1;
    }
  s->fd = fd;
  s->id = h.id;
  s->owns_fd = 0;
  return 0;
}

static void
bpw_secret_clear (bpw_secret_ref *s)
{
  if (!s || s->fd < 0)
    return;
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  h.id = s->id;
  (void) ioctl (s->fd, BPW_AUTH_IOC_CLEAR_SECRET, &h);
  if (s->owns_fd)
    close (s->fd);
  s->fd = -1;
  s->id = 0;
  s->owns_fd = 0;
}

static int
bpw_secret_write (const bpw_secret_ref *s, const void *buf, size_t len)
{
  if (len == 0)
    return 0;
  if (len > BPW_MAX_PASSWORD)
    {
      errno = E2BIG;
      return -1;
    }
  struct bpw_auth_secret_write w;
  memset (&w, 0, sizeof w);
  w.id = s->id;
  w.len = (unsigned int) len;
  w.user_ptr = (unsigned long long) (uintptr_t) buf;
  return ioctl (s->fd, BPW_AUTH_IOC_WRITE_SECRET, &w);
}

static int
bpw_secret_seal (const bpw_secret_ref *s)
{
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  h.id = s->id;
  return ioctl (s->fd, BPW_AUTH_IOC_SEAL_SECRET, &h);
}

static int
bpw_secret_same (const bpw_secret_ref *a, const bpw_secret_ref *b)
{
  struct bpw_auth_secret_compare c;
  memset (&c, 0, sizeof c);
  c.id_a = a->id;
  c.id_b = b->id;
  if (ioctl (a->fd, BPW_AUTH_IOC_SAME_SECRET, &c) < 0)
    return -1;
  return c.result ? 1 : 0;
}

static int
bpw_secret_export_once (const bpw_secret_ref *s, unsigned char **out, size_t *out_len)
{
  unsigned char *buf = mmap (NULL, BPW_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED)
    return -1;
  if (mlock (buf, BPW_MAX_PASSWORD) < 0)
    ; /* best effort; exported bytes are wiped before munmap */

  struct bpw_auth_secret_export e;
  memset (&e, 0, sizeof e);
  e.id = s->id;
  e.len = BPW_MAX_PASSWORD;
  e.user_ptr = (unsigned long long) (uintptr_t) buf;
  if (ioctl (s->fd, BPW_AUTH_IOC_EXPORT_ONCE, &e) < 0)
    {
      int err = errno;
      bpw_release_tty_password (buf);
      errno = err;
      return -1;
    }
  *out = buf;
  *out_len = e.len;
  return 0;
}

static int
bpw_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bpw_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      int v = bpw_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

static int
bpw_valid_user (const char *u)
{
  if (!u || !*u) return 0;
  unsigned char c0 = (unsigned char) u[0];
  if (!((c0 >= 'a' && c0 <= 'z') || c0 == '_')) return 0;
  size_t n = strlen (u);
  if (n > 32) return 0;
  for (size_t i = 1; i < n; i++)
    {
      unsigned char c = (unsigned char) u[i];
      if (!((c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-'))
        return 0;
    }
  return 1;
}

/* Bash getenv() reuses one allocation for command-local assignments.
   Own the account paths and default user for the complete invocation so a
   later environment lookup cannot invalidate a path retained by a mutation.
   A stack of snapshots also preserves an outer invocation across a trap. */
typedef struct bpw_environment {
  char *passwd_path, *shadow_path, *group_path, *lock_dir, *user;
  struct bpw_environment *previous;
} bpw_environment;

static bpw_environment *bpw_current_environment;

static const char *bpw_passwd_path (void) { return bpw_current_environment->passwd_path; }
static const char *bpw_shadow_path (void) { return bpw_current_environment->shadow_path; }
static const char *bpw_group_path (void) { return bpw_current_environment->group_path; }
static const char *bpw_lock_dir (void) { return bpw_current_environment->lock_dir; }

static const char *
bpw_configured_shadow_path (void)
{
  const char *path = getenv ("PHCLIB_SHADOW");
  if (!path || !*path) path = getenv ("SHADOW_FILE");
  if (!path || !*path) path = "/etc/shadow";
  return path;
}

static const char *
bpw_configured_passwd_path (void)
{
  const char *path = getenv ("PHCLIB_PASSWD");
  if (!path || !*path) path = getenv ("PASSWD_FILE");
  if (!path || !*path) path = "/etc/passwd";
  return path;
}

/* Split all seven passwd fields, including empty ones such as GECOS.
   strtok_r skips empty fields and silently shifts HOME into SHELL. */
static int
bpw_passwd_fields (char *line, char *fields[7])
{
  char *p = line;
  for (int i = 0; i < 6; i++)
    {
      fields[i] = p;
      p = strchr (p, ':');
      if (!p) return -1;
      *p++ = '\0';
    }
  if (strchr (p, ':')) return -1;
  fields[6] = p;
  return 0;
}

static const char *
bpw_configured_group_path (void)
{
  const char *path = getenv ("PHCLIB_GROUP");
  if (!path || !*path) path = getenv ("GROUP_FILE");
  if (!path || !*path) path = "/etc/group";
  return path;
}

static void
bpw_print_b64 (const unsigned char *buf, size_t n, char *out)
{
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0, j = 0;
  while (i + 3 <= n)
    {
      unsigned int v = ((unsigned int) buf[i] << 16) | ((unsigned int) buf[i+1] << 8) | buf[i+2];
      out[j++] = alphabet[v >> 18]; out[j++] = alphabet[(v >> 12) & 63];
      out[j++] = alphabet[(v >> 6) & 63]; out[j++] = alphabet[v & 63];
      i += 3;
    }
  if (i < n)
    {
      unsigned int v = (unsigned int) buf[i] << 16;
      if (i + 1 < n) v |= (unsigned int) buf[i+1] << 8;
      out[j++] = alphabet[v >> 18]; out[j++] = alphabet[(v >> 12) & 63];
      if (i + 1 < n) out[j++] = alphabet[(v >> 6) & 63];
    }
  out[j] = '\0';
}

static int
bpw_random_bytes (unsigned char *buf, size_t n)
{
  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) { builtin_error ("/dev/urandom: %s", strerror (errno)); return -1; }
  size_t off = 0;
  while (off < n)
    {
      ssize_t r = read (fd, buf + off, n - off);
      if (r < 0) { if (errno == EINTR) continue; close (fd); return -1; }
      if (r == 0) { close (fd); errno = EIO; return -1; }
      off += (size_t) r;
    }
  close (fd);
  return 0;
}

static int
bpw_parse_phc (const char *phc, bpw_phc *out)
{
  if (!phc || strncmp (phc, "$argon2id$", 10) != 0) return -1;

  char *copy = strdup (phc);
  if (!copy) return -1;
  char *save = NULL;
  char *parts[6] = { 0 };
  int n = 0;
  for (char *tok = strtok_r (copy, "$", &save); tok && n < 6;
       tok = strtok_r (NULL, "$", &save))
    parts[n++] = tok;

  if (n != 5 || strcmp (parts[0], "argon2id") != 0 ||
      strcmp (parts[1], "v=19") != 0)
    { free (copy); return -1; }

  memset (out, 0, sizeof *out);
  char *psave = NULL;
  for (char *kv = strtok_r (parts[2], ",", &psave); kv;
       kv = strtok_r (NULL, ",", &psave))
    {
      if (strncmp (kv, "m=", 2) == 0) out->m = (unsigned int) strtoul (kv + 2, NULL, 10);
      else if (strncmp (kv, "t=", 2) == 0) out->t = (unsigned int) strtoul (kv + 2, NULL, 10);
      else if (strncmp (kv, "p=", 2) == 0) out->p = (unsigned int) strtoul (kv + 2, NULL, 10);
    }

  size_t sl = strlen (parts[3]), hl = strlen (parts[4]);
  if (out->m < 1024 || out->m > 262144 ||
      out->t < 1 || out->t > 10 ||
      out->p < 1 || out->p > 8 ||
      sl < 16 || sl > 128 || (sl & 1) ||
      hl < 32 || hl > 256 || (hl & 1))
    { free (copy); return -1; }

  strncpy (out->salt_hex, parts[3], sizeof out->salt_hex - 1);
  strncpy (out->hash_hex, parts[4], sizeof out->hash_hex - 1);
  free (copy);
  return 0;
}

static int
bpw_shadow_phc_capture (const char *user, char *out, size_t outsz,
                        bpw_auth_snapshot *auth)
{
  const char *path = bpw_shadow_path ();

  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("cannot read %s: %s", path, strerror (errno)); return -1; }

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = -1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *first_colon = strchr (line, ':');
      if (!first_colon) continue;
      *first_colon = '\0';
      if (strcmp (line, user) != 0) continue;
      char *phc = first_colon + 1;
      char *next = strchr (phc, ':');
      if (next) *next = '\0';
      if (phc[0] == '\0' || phc[0] == '!' || phc[0] == '*')
        { builtin_error ("%s is locked or has no password", user); rc = -2; break; }
      if (strlen (phc) >= outsz) { builtin_error ("shadow PHC too long"); rc = -1; break; }
      if (auth)
        {
          struct stat st;
          int fd = fcntl (fileno (f), F_DUPFD_CLOEXEC, 3);
          if (fd < 0 || fstat (fd, &st) < 0)
            {
              if (fd >= 0) close (fd);
              builtin_error ("cannot retain authenticated shadow: %s", strerror (errno));
              break;
            }
          auth->fd = fd;
          auth->dev = st.st_dev;
          auth->ino = st.st_ino;
        }
      strcpy (out, phc);
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  if (rc == -1) builtin_error ("no shadow entry for %s", user);
  return rc;
}

static int
bpw_shadow_phc (const char *user, char *out, size_t outsz)
{
  return bpw_shadow_phc_capture (user, out, outsz, NULL);
}

/* Decimal id, same acceptance as login lookup: empty and non-numeric
   fields are rejected rather than becoming uid 0 or gid 0. */
static int
bpw_parse_id (const char *s, unsigned int *out)
{
  unsigned long v = 0;
  if (!s || !*s || !out) return -1;
  for (const char *p = s; *p; p++)
    {
      if (*p < '0' || *p > '9') return -1;
      unsigned digit = (unsigned) (*p - '0');
      if (v > (4294967295UL - digit) / 10) return -1;
      v = v * 10 + digit;
    }
  if (v >= 4294967295UL) return -1;
  *out = (unsigned int) v;
  return 0;
}

static int
bpw_lookup_user (const char *user, bpw_user *out, const char *default_shell)
{
  FILE *f = fopen (bpw_passwd_path (), "r");
  if (!f) return -1;
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = -1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *fields[7];
      if (bpw_passwd_fields (line, fields) < 0 ||
          strcmp (fields[0], user) != 0) continue;
      unsigned int uid, gid;
      if (bpw_parse_id (fields[2], &uid) < 0 || bpw_parse_id (fields[3], &gid) < 0)
        continue;
      memset (out, 0, sizeof *out);
      snprintf (out->name, sizeof out->name, "%s", fields[0]);
      out->uid = uid;
      out->gid = gid;
      snprintf (out->gecos, sizeof out->gecos, "%s", fields[4]);
      snprintf (out->home, sizeof out->home, "%s", *fields[5] ? fields[5] : "/");
      snprintf (out->shell, sizeof out->shell, "%s", *fields[6] ? fields[6] : default_shell);
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  return rc;
}

static int
bpw_user_uid_token (const char *user, char *out, size_t outsz)
{
  const char *path = bpw_passwd_path ();

  FILE *f = fopen (path, "r");
  if (f)
    {
      char *line = NULL;
      size_t cap = 0;
      ssize_t n;
      while ((n = getline (&line, &cap, f)) > 0)
        {
          if (n && line[n - 1] == '\n') line[n - 1] = '\0';
          char *fields[7];
          if (bpw_passwd_fields (line, fields) == 0 &&
              strcmp (fields[0], user) == 0 && *fields[2])
            {
              snprintf (out, outsz, "%s", fields[2]);
              free (line);
              fclose (f);
              return 0;
            }
        }
      free (line);
      fclose (f);
    }

  /* Tests may provide a shadow-only fixture. Fall back to a username
     token so lockout still works there; real systems use uid scope. */
  size_t j = 0;
  for (const char *p = user; *p && j + 1 < outsz; p++)
    {
      unsigned char c = (unsigned char) *p;
      out[j++] = ((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '_' || c == '-') ? (char) c : '_';
    }
  out[j] = '\0';
  return out[0] ? 0 : -1;
}

static const char *
bpw_configured_lock_dir (void)
{
  const char *d = getenv ("BPW_LOCK_DIR");
  if (!d || !*d) d = "/run/login";
  return d;
}

static int
bpw_lock_path (const char *user, char *out, size_t outsz)
{
  char tok[64];
  if (bpw_user_uid_token (user, tok, sizeof tok) < 0)
    return -1;
  snprintf (out, outsz, "%s/fail.%s", bpw_lock_dir (), tok);
  return 0;
}

static int
bpw_read_lock_state (const char *path, int *count, long *last, long *locked_until)
{
  *count = 0;
  *last = 0;
  *locked_until = 0;

  FILE *f = fopen (path, "r");
  if (!f) return 0;
  char line[128];
  while (fgets (line, sizeof line, f))
    {
      if (strncmp (line, "COUNT=", 6) == 0) *count = atoi (line + 6);
      else if (strncmp (line, "LAST=", 5) == 0) *last = strtol (line + 5, NULL, 10);
      else if (strncmp (line, "LOCKED_UNTIL=", 13) == 0) *locked_until = strtol (line + 13, NULL, 10);
    }
  fclose (f);
  return 0;
}

static int
bpw_check_lockout (const char *user)
{
  char path[256];
  if (bpw_lock_path (user, path, sizeof path) < 0)
    return 0;
  int count;
  long last, locked_until;
  bpw_read_lock_state (path, &count, &last, &locked_until);
  long now = (long) time (NULL);
  if (locked_until > now)
    {
      builtin_error ("account locked; try again in %ld seconds", locked_until - now);
      return -1;
    }
  return 0;
}

static void
bpw_record_failure (const char *user)
{
  const char *dir = bpw_lock_dir ();
  if (mkdir (dir, 0700) < 0 && errno != EEXIST)
    return;

  char path[256], tmp[512];
  if (bpw_lock_path (user, path, sizeof path) < 0)
    return;
  int count;
  long last, locked_until;
  bpw_read_lock_state (path, &count, &last, &locked_until);

  long now = (long) time (NULL);
  if (now - last > BPW_LOCK_WINDOW)
    count = 0;
  count++;
  last = now;
  if (count >= BPW_LOCK_FAIL_MAX)
    locked_until = now + BPW_LOCK_DURATION;
  else
    locked_until = 0;

  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) return;
  FILE *f = fdopen (fd, "w");
  if (!f) { close (fd); unlink (tmp); return; }
  fprintf (f, "COUNT=%d\nLAST=%ld\nLOCKED_UNTIL=%ld\n", count, last, locked_until);
  fflush (f);
  fd = fileno (f);
  if (fd >= 0) fsync (fd);
  fclose (f);
  chmod (tmp, 0600);
  rename (tmp, path);
}

static void
bpw_record_success (const char *user)
{
  char path[256];
  if (bpw_lock_path (user, path, sizeof path) == 0)
    unlink (path);
}

static int
bpw_verify_secret (const unsigned char *pw, size_t pw_len, const char *phc)
{
  int rc = bashos_verify_phc_secret (pw, pw_len, phc);
  if (rc < 0)
    builtin_error ("unsupported or malformed PHC string");
  return rc;
}

static int
bpw_hash_secret (const unsigned char *pw, size_t pw_len, char *out, size_t outsz)
{
  unsigned char salt[16];
  unsigned char hash[BPW_HASH_LEN];
  if (bpw_random_bytes (salt, sizeof salt) < 0)
    return -1;

  unsigned int argon_m = bpw_env_uint ("PHCLIB_M", BPW_ARGON_M, 1024, 262144);
  unsigned int argon_t = bpw_env_uint ("PHCLIB_T", BPW_ARGON_T, 1, 10);
  unsigned int argon_p = bpw_env_uint ("PHCLIB_P", BPW_ARGON_P, 1, 8);
  size_t work_bytes = (size_t) argon_m * 1024;
  void *work = malloc (work_bytes);
  if (!work) { builtin_error ("argon2id: out of memory"); return -1; }
  int locked = (mlock (work, work_bytes) == 0);

  crypto_argon2_config cfg = {
    .algorithm = CRYPTO_ARGON2_ID,
    .nb_blocks = argon_m,
    .nb_passes = argon_t,
    .nb_lanes = argon_p,
  };
  crypto_argon2_inputs in = {
    .pass = pw,
    .salt = salt,
    .pass_size = (uint32_t) pw_len,
    .salt_size = (uint32_t) sizeof salt,
  };
  crypto_argon2 (hash, sizeof hash, work, cfg, in, crypto_argon2_no_extras);
  bpw_wipe (work, work_bytes);
  if (locked) munlock (work, work_bytes);
  free (work);

  char salt_hex[(sizeof salt * 4 + 2) / 3 + 1], hash_hex[(sizeof hash * 4 + 2) / 3 + 1];
  bpw_print_b64 (salt, sizeof salt, salt_hex);
  bpw_print_b64 (hash, sizeof hash, hash_hex);
  int n = snprintf (out, outsz, "$argon2id$v=19$m=%u,t=%u,p=%u$%s$%s",
                    argon_m, argon_t, argon_p, salt_hex, hash_hex);
  bpw_wipe (salt, sizeof salt);
  bpw_wipe (hash, sizeof hash);
  bpw_wipe (salt_hex, sizeof salt_hex);
  bpw_wipe (hash_hex, sizeof hash_hex);
  return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

/* The first entry must also be wiped if Bash unwinds during confirmation. */
static void
bpw_unwind_password (void *arg)
{
  unsigned char **p = arg;
  bpw_release_tty_password (*p);
  *p = NULL;
}

static int
bpw_read_new_password (unsigned char **out, size_t *out_len)
{
  unsigned char *a = NULL, *b = NULL;
  size_t al = 0, bl = 0;
  if (bpw_read_tty_password ("New password: ", &a, &al) < 0) return -1;
  begin_unwind_frame ("passwd confirmation");
  add_unwind_protect (bpw_unwind_password, &a);
  int confirmation = bpw_read_tty_password ("Retype new password: ", &b, &bl);
  discard_unwind_frame ("passwd confirmation");
  if (confirmation < 0)
    {
      bpw_release_tty_password (a);
      return -1;
    }
  if (al == 0)
    {
      builtin_error ("empty password rejected");
      bpw_release_tty_password (a);
      bpw_release_tty_password (b);
      return -1;
    }
  if (al != bl || memcmp (a, b, al) != 0)
    {
      builtin_error ("passwords did not match");
      bpw_release_tty_password (a);
      bpw_release_tty_password (b);
      return -1;
    }
  bpw_release_tty_password (b);
  *out = a;
  *out_len = al;
  return 0;
}

static int
bpw_parent_dir (const char *path, char *dir, size_t dirsz)
{
  const char *slash = strrchr (path, '/');
  if (!slash)
    return snprintf (dir, dirsz, ".") < (int) dirsz ? 0 : -1;
  if (slash == path)
    return snprintf (dir, dirsz, "/") < (int) dirsz ? 0 : -1;
  size_t n = (size_t) (slash - path);
  if (n == 0 || n >= dirsz) return -1;
  memcpy (dir, path, n);
  dir[n] = '\0';
  return 0;
}

static int
bpw_temp_open (const char *path, char *tmp, size_t tmpsz, mode_t mode)
{
  char dir[512];
  struct stat st;
  if (bpw_parent_dir (path, dir, sizeof dir) < 0 ||
      lstat (dir, &st) < 0 ||
      !S_ISDIR (st.st_mode))
    {
      builtin_error ("unsafe temp parent for %s", path);
      return -1;
    }
  if (st.st_uid != geteuid ())
    {
      builtin_error ("refusing temp file in directory not owned by caller: %s", dir);
      return -1;
    }
  if (st.st_mode & (S_IWGRP | S_IWOTH))
    {
      builtin_error ("refusing temp file in group/world-writable dir: %s", dir);
      return -1;
    }

  int n = snprintf (tmp, tmpsz, "%s/.%s.XXXXXX", dir, strrchr (path, '/') ? strrchr (path, '/') + 1 : path);
  if (n <= 0 || (size_t) n >= tmpsz)
    {
      builtin_error ("temp file name too long for %s", path);
      errno = ENAMETOOLONG;
      return -1;
    }

  int fd = mkstemp (tmp);
  if (fd < 0)
    {
      int saved = errno;
      builtin_error ("create temp file in %s: %s", dir, strerror (saved));
      errno = saved;
      return -1;
    }
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0 ||
      fchmod (fd, mode) < 0)
    {
      int saved = errno;
      close (fd);
      unlink (tmp);
      builtin_error ("prepare temp file %s: %s", tmp, strerror (saved));
      errno = saved;
      return -1;
    }
  return fd;
}

static int
bpw_fsync_parent (const char *path)
{
  char dir[512];
  if (bpw_parent_dir (path, dir, sizeof dir) < 0)
    return -1;
  int dfd = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0)
    return -1;
  int rc = fsync (dfd);
  close (dfd);
  return rc;
}

static int
bpw_shadow_set (const char *user, const char *phc, int add_missing)
{
  if (!bpw_valid_user (user)) { builtin_error ("invalid user name"); return -1; }
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }

  struct stat shadow_stat;
  mode_t mode = 0600;
  if (in)
    {
      if (fstat (fileno (in), &shadow_stat) < 0) { fclose (in); return -1; }
      mode = shadow_stat.st_mode & 07777;
    }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, mode);
  if (fd < 0) { if (in) fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }

  long today = (long) (time (NULL) / 86400);
  int found = 0;
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int read_error = 0;
  if (in)
    {
      while ((n = getline (&line, &cap, in)) > 0)
        {
          if (n && line[n - 1] == '\n') line[n - 1] = '\0';
          char *colon = strchr (line, ':');
          if (!colon) { fprintf (out, "%s\n", line); continue; }
          *colon = '\0';
          char *rest = colon + 1;
          char *next = strchr (rest, ':');
          if (strcmp (line, user) == 0)
            {
              found = 1;
              fprintf (out, "%s:%s:%ld%s\n", user, phc, today,
                       next ? strchr (next + 1, ':') ? strchr (next + 1, ':') : "" : ":0:99999:7:::");
            }
          else
            {
              *colon = ':';
              fprintf (out, "%s\n", line);
            }
          (void) next;
        }
      if (ferror (in)) read_error = 1;
      if (fclose (in) != 0) read_error = 1;
    }
  free (line);
  if (!found)
    {
      if (!add_missing)
        {
          fclose (out); unlink (tmp);
          builtin_error ("no shadow entry for %s", user);
          return -1;
        }
      fprintf (out, "%s:%s:%ld:0:99999:7:::\n", user, phc, today);
    }
  int write_error = read_error || ferror (out);
  if (fflush (out) != 0) write_error = 1;
  if (fsync (fd) != 0) write_error = 1;
  if (fclose (out) != 0) write_error = 1;
  if (write_error || rename (tmp, path) != 0)
    { unlink (tmp); builtin_error ("rewrite %s: %s", path, strerror (errno)); return -1; }
  return bpw_fsync_parent (path);
}

static int
bpw_shadow_delete (const char *user)
{
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in) return errno == ENOENT ? 0 : -1;
  struct stat st;
  if (fstat (fileno (in), &st) < 0) { fclose (in); return -1; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, st.st_mode & 07777);
  if (fd < 0) { fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return -1; }
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      char *colon = memchr (line, ':', (size_t) n);
      int match = colon && (size_t) (colon - line) == strlen (user) &&
                  !memcmp (line, user, (size_t) (colon - line));
      if (!match && fwrite (line, 1, (size_t) n, out) != (size_t) n)
        break;
    }
  int bad = ferror (in) || ferror (out);
  free (line);
  if (fclose (in) != 0) bad = 1;
  if (fflush (out) != 0) bad = 1;
  if (fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  return bpw_fsync_parent (path);
}

/* Copy the original bytes, including any embedded NUL, before appending a
   new record.  A nonempty unterminated final row needs a separator. */
static int
bpw_copy_for_append (FILE *in, FILE *out)
{
  unsigned char buf[4096]; size_t n; int last = -1, bad = 0;
  while ((n = fread (buf, 1, sizeof buf, in)) != 0)
    {
      if (fwrite (buf, 1, n, out) != n) bad = 1;
      last = buf[n - 1];
    }
  if (ferror (in)) bad = 1;
  if (last >= 0 && last != '\n' && fputc ('\n', out) == EOF) bad = 1;
  return bad ? -1 : 0;
}

static int
bpw_passwd_add (const bpw_user *u)
{
  if (!bpw_valid_user (u->name)) { builtin_error ("invalid user name"); return -1; }
  bpw_user existing;
  if (bpw_lookup_user (u->name, &existing, "/bin/bash") == 0)
    { builtin_error ("%s already exists", u->name); return -1; }
  const char *path = bpw_passwd_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
  mode_t mode = 0644;
  if (in)
    {
      struct stat st;
      if (fstat (fileno (in), &st) < 0) { fclose (in); return -1; }
      mode = st.st_mode & 07777;
    }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, mode);
  if (fd < 0) { if (in) fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }
  int read_error = 0;
  if (in)
    {
      if (bpw_copy_for_append (in, out) < 0) read_error = 1;
      if (fclose (in) != 0) read_error = 1;
    }
  fprintf (out, "%s:x:%u:%u:%s:%s:%s\n", u->name, u->uid, u->gid,
           u->gecos, u->home, u->shell);
  int bad = read_error || ferror (out);
  if (fflush (out) != 0) bad = 1;
  if (fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  return bpw_fsync_parent (path);
}

static int
bpw_file_delete_user (const char *path, const char *user)
{
  FILE *in = fopen (path, "r");
  if (!in) return errno == ENOENT ? 0 : -1;
  struct stat st;
  if (fstat (fileno (in), &st) < 0) { fclose (in); return -1; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, st.st_mode & 07777);
  if (fd < 0) { fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return -1; }
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      char *colon = memchr (line, ':', (size_t) n);
      int match = colon && (size_t) (colon - line) == strlen (user) &&
                  !memcmp (line, user, (size_t) (colon - line));
      if (!match && fwrite (line, 1, (size_t) n, out) != (size_t) n)
        break;
    }
  int bad = ferror (in) || ferror (out);
  free (line);
  if (fclose (in) != 0) bad = 1;
  if (fflush (out) != 0) bad = 1;
  if (fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  return bpw_fsync_parent (path);
}

static int
bpw_group_add_primary (const char *user, unsigned int gid)
{
  const char *path = bpw_group_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT) return -1;
  mode_t mode = 0644;
  if (in)
    {
      struct stat st;
      if (fstat (fileno (in), &st) < 0) { fclose (in); return -1; }
      mode = st.st_mode & 07777;
    }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, mode);
  if (fd < 0) { if (in) fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }
  int read_error = 0;
  if (in)
    {
      if (bpw_copy_for_append (in, out) < 0) read_error = 1;
      if (fclose (in) != 0) read_error = 1;
    }
  fprintf (out, "%s:x:%u:\n", user, gid);
  int bad = read_error || ferror (out);
  if (fflush (out) != 0) bad = 1;
  if (fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  return bpw_fsync_parent (path);
}

/* Cooperative directory locks survive replacement of an account file's
   inode.  Sort by device/inode so writers using multiple directories acquire
   them in the same order.  The bounded wait avoids hanging an interactive
   shell; writers that do not use this protocol are not serialized. */
typedef struct {
  int fd[3];
  dev_t dev[3];
  ino_t ino[3];
  size_t count;
} bpw_dir_locks;

static void
bpw_unlock_dirs (void *arg)
{
  bpw_dir_locks *locks = arg;
  for (size_t i = 0; i < locks->count; i++)
    if (locks->fd[i] >= 0) { close (locks->fd[i]); locks->fd[i] = -1; }
  locks->count = 0;
}

static int
bpw_lock_dirs (bpw_dir_locks *locks, const char **paths, size_t count)
{
  for (size_t i = 0; i < count; i++)
    {
      char parent[512]; struct stat st;
      if (bpw_parent_dir (paths[i], parent, sizeof parent) < 0) return -1;
      int fd = open (parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (fd < 0) return -1;
      if (fstat (fd, &st) < 0 || !S_ISDIR (st.st_mode) ||
          st.st_uid != geteuid () || (st.st_mode & (S_IWGRP | S_IWOTH)))
        { close (fd); errno = EPERM; return -1; }
      int duplicate = 0;
      for (size_t j = 0; j < locks->count; j++)
        if (locks->dev[j] == st.st_dev && locks->ino[j] == st.st_ino)
          { duplicate = 1; break; }
      if (duplicate) { close (fd); continue; }
      size_t at = locks->count++;
      locks->fd[at] = fd; locks->dev[at] = st.st_dev; locks->ino[at] = st.st_ino;
    }
  for (size_t i = 0; i < locks->count; i++)
    for (size_t j = i + 1; j < locks->count; j++)
      if (locks->dev[j] < locks->dev[i] ||
          (locks->dev[j] == locks->dev[i] && locks->ino[j] < locks->ino[i]))
        {
          int fd = locks->fd[i]; dev_t dev = locks->dev[i]; ino_t ino = locks->ino[i];
          locks->fd[i] = locks->fd[j]; locks->dev[i] = locks->dev[j]; locks->ino[i] = locks->ino[j];
          locks->fd[j] = fd; locks->dev[j] = dev; locks->ino[j] = ino;
        }
  for (size_t i = 0; i < locks->count; i++)
    {
      int acquired = 0;
      for (int attempt = 0; attempt < 100; attempt++)
        {
          bpw_check_signals ();
          if (flock (locks->fd[i], LOCK_EX | LOCK_NB) == 0) { acquired = 1; break; }
          if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) return -1;
          struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000 };
          (void) nanosleep (&delay, NULL);
        }
      if (!acquired) { errno = EBUSY; return -1; }
    }
  return 0;
}

/* Hard-linked snapshots make rollback independent of RLIMIT_FSIZE.  These
   are operation rollback, not a crash-atomic multi-file transaction. */
typedef struct {
  const char *path;
  char backup[512];
  int present, touched;
  dev_t dev;
  ino_t ino;
} bpw_snapshot;

static int
bpw_snapshot_one (bpw_snapshot *s)
{
  struct stat before, after;
  if (lstat (s->path, &before) < 0)
    return errno == ENOENT ? 0 : -1;
  if (!S_ISREG (before.st_mode)) { errno = EINVAL; return -1; }
  int fd = bpw_temp_open (s->path, s->backup, sizeof s->backup, 0600);
  if (fd < 0) return -1;
  if (close (fd) != 0 || unlink (s->backup) != 0)
    { unlink (s->backup); return -1; }
  if (link (s->path, s->backup) != 0) return -1;
  if (lstat (s->backup, &after) != 0 || !S_ISREG (after.st_mode) ||
      before.st_dev != after.st_dev || before.st_ino != after.st_ino)
    { unlink (s->backup); errno = EAGAIN; return -1; }
  s->present = 1; s->dev = before.st_dev; s->ino = before.st_ino;
  return 0;
}

static int
bpw_snapshot_all (bpw_snapshot *snap, size_t count)
{
  for (size_t i = 0; i < count; i++)
    {
      for (size_t j = 0; j < i; j++)
        if (!strcmp (snap[i].path, snap[j].path)) { errno = EINVAL; goto fail; }
      if (bpw_snapshot_one (&snap[i]) < 0) goto fail;
      for (size_t j = 0; j < i; j++)
        if (snap[i].present && snap[j].present &&
            snap[i].dev == snap[j].dev && snap[i].ino == snap[j].ino)
          { errno = EINVAL; goto fail; }
    }
  return 0;
fail:
  for (size_t i = 0; i < count; i++)
    if (snap[i].present && unlink (snap[i].backup) != 0)
      builtin_error ("remove backup %s failed: %s", snap[i].backup, strerror (errno));
  return -1;
}

static int
bpw_snapshot_finish (bpw_snapshot *snap, size_t count, int restore)
{
  int bad = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (restore && snap[i].touched)
        {
          if (snap[i].present)
            {
              struct stat current;
              /* rename of two names for the same inode is a no-op; remove
                 the backup explicitly if no replacement happened. */
              if (lstat (snap[i].path, &current) == 0 &&
                  current.st_dev == snap[i].dev && current.st_ino == snap[i].ino)
                {
                  if (unlink (snap[i].backup) != 0)
                    { builtin_error ("remove backup %s failed: %s", snap[i].backup, strerror (errno)); bad = 1; continue; }
                }
              else if (rename (snap[i].backup, snap[i].path) != 0)
                { builtin_error ("restore %s failed; backup retained at %s", snap[i].path, snap[i].backup); bad = 1; continue; }
              snap[i].present = 0;
            }
          else if (unlink (snap[i].path) != 0 && errno != ENOENT)
            { builtin_error ("remove newly created %s failed: %s", snap[i].path, strerror (errno)); bad = 1; continue; }
          if (bpw_fsync_parent (snap[i].path) != 0)
            { builtin_error ("sync restored %s failed: %s", snap[i].path, strerror (errno)); bad = 1; }
        }
      if (snap[i].present)
        {
          if (unlink (snap[i].backup) != 0)
            { builtin_error ("remove backup %s failed: %s", snap[i].backup, strerror (errno)); bad = 1; }
          else if (bpw_fsync_parent (snap[i].path) != 0)
            { builtin_error ("sync backup cleanup for %s failed: %s", snap[i].path, strerror (errno)); bad = 1; }
        }
    }
  return bad ? -1 : 0;
}

typedef struct {
  bpw_snapshot *snap;
  size_t count;
  int active;
} bpw_unwind_snapshot;

static void
bpw_snapshot_unwind (void *arg)
{
  bpw_unwind_snapshot *state = arg;
  if (state->active) { state->active = 0; (void) bpw_snapshot_finish (state->snap, state->count, 1); }
}

/* A shadow rewrite can fail after rename (for example on directory fsync).
   Keep the old file until that outcome is known. */
static int
bpw_shadow_set_transaction_checked (const char *user, const char *phc,
                                    int add_missing, const bpw_auth_snapshot *auth)
{
  const char *paths[] = { bpw_shadow_path () };
  bpw_dir_locks locks = { 0 };
  int rc = -1;
  begin_unwind_frame ("passwd mutation lock");
  add_unwind_protect (bpw_unlock_dirs, &locks);
  if (bpw_lock_dirs (&locks, paths, 1) < 0)
    { builtin_error ("cannot lock account directory: %s", strerror (errno)); goto done; }
  bpw_user existing;
  if (!bpw_valid_user (user) || bpw_lookup_user (user, &existing, "/bin/bash") < 0) goto done;
  if (auth)
    {
      char current[512] = { 0 };
      bpw_auth_snapshot now = { .fd = -1 };
      int read_rc = bpw_shadow_phc_capture (user, current, sizeof current, &now);
      int same = read_rc == 0 && auth->fd >= 0 &&
                 now.dev == auth->dev && now.ino == auth->ino &&
                 strcmp (current, auth->phc) == 0;
      if (now.fd >= 0) close (now.fd);
      bpw_wipe (current, sizeof current);
      if (!same)
        { builtin_error ("authentication changed; retry password change"); goto done; }
    }
  bpw_snapshot snap[1] = { { .path = paths[0] } };
  bpw_unwind_snapshot cleanup = { .snap = snap, .count = 1, .active = 1 };
  add_unwind_protect (bpw_snapshot_unwind, &cleanup);
  if (bpw_snapshot_all (snap, 1) < 0) { cleanup.active = 0; goto done; }
  snap[0].touched = 1;
  rc = bpw_shadow_set (user, phc, add_missing);
  if (bpw_snapshot_finish (snap, 1, rc != 0) < 0 && rc == 0)
    { builtin_error ("shadow update committed but backup cleanup failed"); rc = -1; }
  cleanup.active = 0;
done:
  run_unwind_frame ("passwd mutation lock");
  return rc;
}

static int
bpw_shadow_set_transaction (const char *user, const char *phc, int add_missing)
{
  return bpw_shadow_set_transaction_checked (user, phc, add_missing, NULL);
}

static int
bpw_create_account (const bpw_user *u, const char *phc, int create_group)
{
  const char *paths[] = { bpw_passwd_path (), bpw_shadow_path (), bpw_group_path () };
  bpw_dir_locks locks = { 0 };
  int rc = -1;
  begin_unwind_frame ("passwd mutation lock");
  add_unwind_protect (bpw_unlock_dirs, &locks);
  if (bpw_lock_dirs (&locks, paths, 3) < 0)
    { builtin_error ("cannot lock account directory: %s", strerror (errno)); goto done; }
  /* Allocation occurred before the password was read. Recheck under the
     lock so two cooperating writers cannot install the same uid or gid. */
  int used = bpw_id_in_file (paths[0], u->uid, 0);
  int group_exists = bpw_id_in_file (paths[2], u->gid, 1);
  if (used != 0 || group_exists < 0 || (!!group_exists == !!create_group))
    { builtin_error ("account ids changed or are already in use"); goto done; }
  bpw_snapshot snap[3] = { { .path = paths[0] }, { .path = paths[1] }, { .path = paths[2] } };
  size_t count = create_group ? 3 : 2;
  bpw_unwind_snapshot cleanup = { .snap = snap, .count = count, .active = 1 };
  add_unwind_protect (bpw_snapshot_unwind, &cleanup);
  if (bpw_snapshot_all (snap, count) < 0) { cleanup.active = 0; goto done; }
  snap[0].touched = 1;
  if (bpw_passwd_add (u) < 0) goto rollback;
  if (create_group)
    {
      snap[2].touched = 1;
      if (bpw_group_add_primary (u->name, u->gid) < 0) goto rollback;
    }
  snap[1].touched = 1;
  if (bpw_shadow_set (u->name, phc, 1) < 0) goto rollback;
  rc = 0;
rollback:
  if (bpw_snapshot_finish (snap, count, rc != 0) < 0 && rc == 0)
    { builtin_error ("account creation committed but backup cleanup failed"); rc = -1; }
  cleanup.active = 0;
done:
  run_unwind_frame ("passwd mutation lock");
  return rc;
}

static int
bpw_read_fd_all (int fd, unsigned char **out, size_t *out_len)
{
  size_t cap = 128, len = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) return -1;
  for (;;)
    {
      if (len == cap)
        {
          if (cap >= BPW_MAX_PASSWORD) { free (buf); errno = E2BIG; return -1; }
          cap *= 2;
          if (cap > BPW_MAX_PASSWORD) cap = BPW_MAX_PASSWORD;
          unsigned char *n = realloc (buf, cap);
          if (!n) { free (buf); return -1; }
          buf = n;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0) { if (errno == EINTR) continue; free (buf); return -1; }
      if (r == 0) break;
      len += (size_t) r;
    }
  while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) len--;
  *out = buf;
  *out_len = len;
  return 0;
}

/* Bash may longjmp from QUIT. Register ownership before changing the tty,
   and restore it before Bash runs an interrupt handler or trap. */
typedef struct {
  int fd, have_termios;
  struct termios saved;
  unsigned char *buf;
  bpw_secret_ref *secret;
} bpw_tty_session;

static void
bpw_tty_cleanup (void *arg)
{
  bpw_tty_session *s = arg;
  if (s->have_termios) (void) tcsetattr (s->fd, TCSANOW, &s->saved);
  if (s->fd >= 0 && s->fd != STDIN_FILENO) close (s->fd);
  bpw_release_tty_password (s->buf);
  if (s->secret) bpw_secret_clear (s->secret);
}

static int
bpw_tty_open (bpw_tty_session *s, const char *prompt)
{
  /* Noninteractive Bash may still have default terminating dispositions.
     Like read -s, arrange deferred signal handling before changing the tty. */
  initialize_terminating_signals ();
  s->fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
  if (s->fd < 0)
    {
      if (!isatty (STDIN_FILENO))
        { builtin_error ("stdin is not a tty"); return -1; }
      s->fd = STDIN_FILENO;
    }
  if (tcgetattr (s->fd, &s->saved) < 0) return -1;
  s->have_termios = 1;
  {
    struct termios newt = s->saved;
    newt.c_lflag &= ~(ECHO | ICANON);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    if (tcsetattr (s->fd, TCSAFLUSH, &newt) < 0) return -1;
  }
  if (prompt && *prompt)
    (void) write (s->fd == STDIN_FILENO ? STDERR_FILENO : s->fd, prompt, strlen (prompt));
  return 0;
}

static int
bpw_read_tty_password (const char *prompt, unsigned char **out, size_t *out_len)
{
  bpw_tty_session s = { .fd = -1 };
  size_t len = 0;
  int err = 0;
  begin_unwind_frame ("passwd tty");
  add_unwind_protect (bpw_tty_cleanup, &s);
  if (bpw_tty_open (&s, prompt) < 0) { err = errno; goto done; }
  s.buf = mmap (NULL, BPW_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (s.buf == MAP_FAILED) { s.buf = NULL; err = errno; goto newline; }
  (void) mlock (s.buf, BPW_MAX_PASSWORD);
  for (;;)
    {
      unsigned char c;
      bpw_check_signals ();
      ssize_t r = read (s.fd, &c, 1);
      int read_errno = errno;
      if (terminating_signal || interrupt_state == 1) bpw_wipe (&c, sizeof c);
      bpw_check_signals ();
      if (r < 0) { if (read_errno == EINTR) continue; err = read_errno; break; }
      if (r == 0) { err = EIO; break; }
      if (c == '\n' || c == '\r') break;
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; break; }
      s.buf[len++] = c;
    }
newline:
  if (s.have_termios)
    {
      if (tcsetattr (s.fd, TCSANOW, &s.saved) < 0) { if (!err) err = errno; }
      else s.have_termios = 0;
    }
  (void) write (s.fd == STDIN_FILENO ? STDERR_FILENO : s.fd, "\n", 1);
  if (!err) { *out = s.buf; *out_len = len; s.buf = NULL; }
done:
  run_unwind_frame ("passwd tty");
  if (err) { errno = err; return -1; }
  return 0;
}

static int
bpw_read_tty_secret_common (const char *prompt, bpw_secret_ref *secret,
                            size_t *out_len)
{
  bpw_tty_session s = { .fd = -1, .secret = secret };
  size_t len = 0;
  int err = 0;
  begin_unwind_frame ("passwd tty secret");
  add_unwind_protect (bpw_tty_cleanup, &s);
  if (bpw_tty_open (&s, prompt) < 0) { err = errno; goto done; }
  for (;;)
    {
      unsigned char c = 0;
      bpw_check_signals ();
      ssize_t r = read (s.fd, &c, 1);
      int read_errno = errno;
      if (terminating_signal || interrupt_state == 1) bpw_wipe (&c, sizeof c);
      bpw_check_signals ();
      if (r < 0) { if (read_errno == EINTR) continue; err = read_errno; break; }
      if (r == 0) { err = EIO; bpw_wipe (&c, sizeof c); break; }
      if (c == '\n' || c == '\r') { bpw_wipe (&c, sizeof c); break; }
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
      if (bpw_secret_write (secret, &c, 1) < 0)
        { err = errno; bpw_wipe (&c, sizeof c); break; }
      bpw_wipe (&c, sizeof c);
      len++;
    }
  if (s.have_termios)
    {
      if (tcsetattr (s.fd, TCSANOW, &s.saved) < 0) { if (!err) err = errno; }
      else s.have_termios = 0;
    }
  (void) write (s.fd == STDIN_FILENO ? STDERR_FILENO : s.fd, "\n", 1);
  if (!err && bpw_secret_seal (secret) < 0) err = errno;
  if (!err) { *out_len = len; s.secret = NULL; }
done:
  run_unwind_frame ("passwd tty secret");
  if (err) { errno = err; return -1; }
  return 0;
}

static int
bpw_read_tty_secret (const char *prompt, bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new (secret);
  return nr ? nr : bpw_read_tty_secret_common (prompt, secret, out_len);
}

static int
bpw_read_tty_secret_on_auth_fd (int auth_fd, const char *prompt,
                                bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new_on_fd (auth_fd, secret);
  return nr ? nr : bpw_read_tty_secret_common (prompt, secret, out_len);
}

static int
bpw_read_fd_secret (int input_fd, bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new (secret);
  if (nr)
    return nr;

  size_t len = 0, pending_eol = 0;
  int err = 0;
  for (;;)
    {
      unsigned char c = 0;
      ssize_t r = read (input_fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
      if (r == 0)
        {
          bpw_wipe (&c, sizeof c);
          break;
        }
      if (c == '\n' || c == '\r')
        {
          if (len + pending_eol >= BPW_MAX_PASSWORD)
            { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
          pending_eol++;
          bpw_wipe (&c, sizeof c);
          continue;
        }
      while (pending_eol)
        {
          unsigned char nl = '\n';
          if (bpw_secret_write (secret, &nl, 1) < 0)
            { err = errno; bpw_wipe (&nl, sizeof nl); break; }
          bpw_wipe (&nl, sizeof nl);
          len++;
          pending_eol--;
        }
      if (err) { bpw_wipe (&c, sizeof c); break; }
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
      if (bpw_secret_write (secret, &c, 1) < 0)
        { err = errno; bpw_wipe (&c, sizeof c); break; }
      bpw_wipe (&c, sizeof c);
      len++;
    }

  if (err)
    {
      bpw_secret_clear (secret);
      errno = err;
      return -1;
    }
  if (bpw_secret_seal (secret) < 0)
    {
      int saved = errno;
      bpw_secret_clear (secret);
      errno = saved;
      return -1;
    }
  *out_len = len;
  return 0;
}

typedef struct { int fd; bpw_secret_ref *first; } bpw_confirmation;

static void
bpw_confirmation_cleanup (void *arg)
{
  bpw_confirmation *c = arg;
  bpw_secret_clear (c->first);
  close (c->fd);
}

static int
bpw_read_new_password_secret (bpw_secret_ref *secret, size_t *out_len)
{
  int auth_fd = bpw_auth_open_optional ();
  if (auth_fd < 0)
    return bpw_kernel_secrets_required () ? -1 : -2;

  bpw_secret_ref a = { -1, 0, 0 }, b = { -1, 0, 0 };
  size_t al = 0, bl = 0;
  bpw_confirmation confirmation = { auth_fd, &a };
  begin_unwind_frame ("passwd secret confirmation");
  add_unwind_protect (bpw_confirmation_cleanup, &confirmation);
  int ar = bpw_read_tty_secret_on_auth_fd (auth_fd, "New password: ", &a, &al);
  if (ar)
    {
      run_unwind_frame ("passwd secret confirmation");
      return ar;
    }
  int br = bpw_read_tty_secret_on_auth_fd (auth_fd, "Retype new password: ", &b, &bl);
  if (br)
    {
      run_unwind_frame ("passwd secret confirmation");
      return br;
    }
  int same = (al == bl) ? bpw_secret_same (&a, &b) : 0;
  bpw_secret_clear (&b);
  if (same != 1)
    {
      run_unwind_frame ("passwd secret confirmation");
      if (same < 0)
        builtin_error ("kernel secret compare: %s", strerror (errno));
      else
        builtin_error ("passwords do not match");
      return -1;
    }
  if (al == 0)
    {
      run_unwind_frame ("passwd secret confirmation");
      builtin_error ("empty password rejected");
      return -1;
    }
  discard_unwind_frame ("passwd secret confirmation");
  a.owns_fd = 1;
  *secret = a;
  *out_len = al;
  return 0;
}

static int
bpw_hash_secret_ref (bpw_secret_ref *secret, char *out, size_t outsz)
{
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_secret_export_once (secret, &pw, &pw_len) < 0)
    return -1;
  int rc = bpw_hash_secret (pw, pw_len, out, outsz);
  bpw_release_tty_password (pw);
  return rc;
}

static int
bpw_verify_user_secret_ref (const char *user, bpw_secret_ref *secret)
{
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_secret_export_once (secret, &pw, &pw_len) < 0)
    return 2;
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_release_tty_password (pw);
  return rc;
}

static int
bpw_verify_user_buf (const char *user, const unsigned char *pw, size_t pw_len)
{
  if (bpw_check_lockout (user) < 0) return 1;
  char phc[512];
  if (bpw_shadow_phc (user, phc, sizeof phc) != 0) return 2;
  int r = bpw_verify_secret (pw, pw_len, phc);
  if (r == 0) bpw_record_success (user);
  else if (r == 1) bpw_record_failure (user);
  return r == 0 ? 0 : (r == 1 ? 1 : 2);
}

static int
bpw_verify_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("verify needs USER"); return EX_USAGE; }
  const char *user = args->word->word;
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_tty_secret ("Password: ", &secret, &secret_len);
  if (sr == 0)
    {
      int rc = bpw_verify_user_secret_ref (user, &secret);
      bpw_secret_clear (&secret);
      return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
    }
  if (sr != -2)
    {
      builtin_error ("password read: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_read_tty_password ("Password: ", &pw, &pw_len) < 0)
    { builtin_error ("password read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_release_tty_password (pw);
  return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
}

static int
bpw_verify_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("verify-fd needs USER FD"); return EX_USAGE; }
  const char *user = args->word->word;
  int fd = atoi (args->next->word->word);
  if (fd < 0) { builtin_error ("bad fd"); return EX_USAGE; }
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      int rc = bpw_verify_user_secret_ref (user, &secret);
      bpw_secret_clear (&secret);
      return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
    }
  if (sr != -2)
    { builtin_error ("fd read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0)
    { builtin_error ("fd read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_wipe (pw, pw_len);
  free (pw);
  return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
}

/* Modify only the password field; preserve all aging fields and refuse
   missing users and an unlock that would leave an empty password. */
static int
bpw_lock_change (const char *user, int unlock)
{
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in) return EXECUTION_FAILURE;
  struct stat st;
  if (fstat (fileno (in), &st) < 0) { fclose (in); return EXECUTION_FAILURE; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, st.st_mode & 07777);
  if (fd < 0) { fclose (in); return EXECUTION_FAILURE; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return EXECUTION_FAILURE; }
  char *line = NULL; size_t cap = 0; ssize_t n; int found = 0, bad = 0;
  while ((n = getline (&line, &cap, in)) >= 0)
    {
      char *c = memchr (line, ':', (size_t) n);
      if (c && (size_t) (c - line) == strlen (user) &&
          memcmp (line, user, (size_t) (c - line)) == 0)
        {
          char *hash = c + 1, *end = memchr (hash, ':', (size_t) (line + n - hash));
          found = 1;
          if (!end || (unlock && (hash == end || hash[0] == '*' || (hash[0] == '!' && hash + 1 == end))))
            { bad = 1; break; }
          if (fwrite (line, 1, (size_t) (hash - line), out) != (size_t) (hash - line)) bad = 1;
          if (!unlock && hash[0] != '!') fputc ('!', out);
          if (unlock && hash[0] == '!') hash++;
          if (fwrite (hash, 1, (size_t) (line + n - hash), out) != (size_t) (line + n - hash)) bad = 1;
        }
      else if (fwrite (line, 1, (size_t) n, out) != (size_t) n) bad = 1;
    }
  if (ferror (in) || ferror (out)) bad = 1;
  free (line);
  if (fclose (in) != 0) bad = 1;
  if (fflush (out) != 0 || fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || !found || rename (tmp, path) != 0)
    { unlink (tmp); return EXECUTION_FAILURE; }
  if (bpw_fsync_parent (path) != 0) return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

static int
bpw_lock_transaction (const char *user, int unlock)
{
  const char *paths[] = { bpw_shadow_path () };
  bpw_dir_locks locks = { 0 };
  int rc = EXECUTION_FAILURE;
  begin_unwind_frame ("passwd mutation lock");
  add_unwind_protect (bpw_unlock_dirs, &locks);
  if (bpw_lock_dirs (&locks, paths, 1) < 0)
    { builtin_error ("cannot lock account directory: %s", strerror (errno)); goto done; }
  bpw_user existing;
  if (bpw_lookup_user (user, &existing, "/bin/bash") < 0) goto done;
  bpw_snapshot snap[1] = { { .path = paths[0] } };
  bpw_unwind_snapshot cleanup = { .snap = snap, .count = 1, .active = 1 };
  add_unwind_protect (bpw_snapshot_unwind, &cleanup);
  if (bpw_snapshot_all (snap, 1) < 0) { cleanup.active = 0; goto done; }
  snap[0].touched = 1;
  rc = bpw_lock_change (user, unlock);
  if (bpw_snapshot_finish (snap, 1, rc != EXECUTION_SUCCESS) < 0 && rc == EXECUTION_SUCCESS)
    { builtin_error ("lock update committed but backup cleanup failed"); rc = EXECUTION_FAILURE; }
  cleanup.active = 0;
done:
  run_unwind_frame ("passwd mutation lock");
  return rc;
}

static int
bpw_lock_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("lock needs USER"); return EX_USAGE; }
  return bpw_lock_transaction (args->word->word, 0);
}

static int
bpw_unlock_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("unlock needs USER"); return EX_USAGE; }
  return bpw_lock_transaction (args->word->word, 1);
}

/* A same-named group is private only if its gid is the deleted user's
   primary gid and no other account or member still uses it. */
static int
bpw_other_primary_gid (const char *user, unsigned int gid)
{
  FILE *f = fopen (bpw_passwd_path (), "r");
  if (!f) return -1;
  char *line = NULL; size_t cap = 0; int shared = 0;
  while (getline (&line, &cap, f) >= 0)
    {
      char *fields[7]; unsigned int id;
      if (bpw_passwd_fields (line, fields) < 0 ||
          bpw_parse_id (fields[3], &id) < 0)
        { shared = 1; break; }
      if (strcmp (fields[0], user) && id == gid) { shared = 1; break; }
    }
  if (ferror (f)) shared = -1;
  free (line); if (fclose (f) != 0) shared = -1;
  return shared;
}

static int
bpw_group_delete_user (const char *user, unsigned int gid, int shared_gid)
{
  const char *path = bpw_group_path ();
  FILE *in = fopen (path, "r");
  if (!in) return errno == ENOENT ? 0 : -1;
  struct stat st;
  if (fstat (fileno (in), &st) < 0) { fclose (in); return -1; }
  char tmp[512]; int fd = bpw_temp_open (path, tmp, sizeof tmp, st.st_mode & 07777);
  if (fd < 0) { fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return -1; }
  char *line = NULL; size_t cap = 0; ssize_t n; int bad = 0;
  while ((n = getline (&line, &cap, in)) >= 0)
    {
      char *c1 = memchr (line, ':', (size_t) n);
      char *c2 = c1 ? memchr (c1 + 1, ':', (size_t) (line + n - c1 - 1)) : NULL;
      char *c3 = c2 ? memchr (c2 + 1, ':', (size_t) (line + n - c2 - 1)) : NULL;
      if (!c3) { if (fwrite (line, 1, (size_t) n, out) != (size_t) n) bad = 1; continue; }
      char saved = *c3; *c3 = 0; unsigned int group_gid;
      int same_gid = bpw_parse_id (c2 + 1, &group_gid) == 0 && group_gid == gid;
      *c3 = saved;
      char *end = line + n;
      if (end > c3 + 1 && end[-1] == '\n') end--;
      int has_user = 0, other_members = 0;
      for (char *p = c3 + 1; p < end; )
        {
          char *q = memchr (p, ',', (size_t) (end - p));
          if (!q) q = end;
          if ((size_t) (q - p) == strlen (user) && !memcmp (p, user, (size_t) (q - p))) has_user = 1;
          else if (q != p) other_members = 1;
          p = q < end ? q + 1 : end;
        }
      if (!shared_gid && !other_members && same_gid &&
          (size_t) (c1 - line) == strlen (user) && !memcmp (line, user, strlen (user)))
        continue;
      if (!has_user)
        { if (fwrite (line, 1, (size_t) n, out) != (size_t) n) bad = 1; continue; }
      if (fwrite (line, 1, (size_t) (c3 + 1 - line), out) != (size_t) (c3 + 1 - line)) bad = 1;
      int first = 1;
      for (char *p = c3 + 1; p < end; )
        {
          char *q = memchr (p, ',', (size_t) (end - p));
          if (!q) q = end;
          if ((size_t) (q - p) != strlen (user) || memcmp (p, user, (size_t) (q - p)))
            { if (!first) fputc (',', out); if (fwrite (p, 1, (size_t) (q - p), out) != (size_t) (q - p)) bad = 1; first = 0; }
          p = q < end ? q + 1 : end;
        }
      if (end < line + n) fputc ('\n', out);
    }
  if (ferror (in) || ferror (out)) bad = 1;
  free (line); if (fclose (in) != 0) bad = 1;
  if (fflush (out) != 0) bad = 1;
  if (fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || rename (tmp, path) != 0) { unlink (tmp); return -1; }
  return bpw_fsync_parent (path);
}

static int
bpw_delete_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("delete needs USER"); return EX_USAGE; }
  const char *user = args->word->word;
  const char *paths[] = { bpw_passwd_path (), bpw_shadow_path (), bpw_group_path () };
  bpw_dir_locks locks = { 0 }; bpw_user existing;
  int rc = EXECUTION_FAILURE;
  begin_unwind_frame ("passwd mutation lock");
  add_unwind_protect (bpw_unlock_dirs, &locks);
  if (bpw_lock_dirs (&locks, paths, 3) < 0)
    { builtin_error ("cannot lock account directory: %s", strerror (errno)); goto done; }
  if (bpw_lookup_user (user, &existing, "/bin/bash") < 0) goto done;
  int shared = bpw_other_primary_gid (user, existing.gid);
  if (shared < 0) goto done;
  bpw_snapshot snap[3] = { { .path = paths[0] }, { .path = paths[1] }, { .path = paths[2] } };
  bpw_unwind_snapshot cleanup = { .snap = snap, .count = 3, .active = 1 };
  add_unwind_protect (bpw_snapshot_unwind, &cleanup);
  if (bpw_snapshot_all (snap, 3) < 0) { cleanup.active = 0; goto done; }
  snap[0].touched = 1;
  if (bpw_file_delete_user (paths[0], user) < 0) goto rollback;
  snap[1].touched = 1;
  if (bpw_shadow_delete (user) < 0) goto rollback;
  snap[2].touched = 1;
  if (bpw_group_delete_user (user, existing.gid, shared) < 0) goto rollback;
  rc = EXECUTION_SUCCESS;
rollback:
  if (bpw_snapshot_finish (snap, 3, rc != EXECUTION_SUCCESS) < 0 && rc == EXECUTION_SUCCESS)
    { builtin_error ("account deletion committed but backup cleanup failed"); rc = EXECUTION_FAILURE; }
  cleanup.active = 0;
done:
  run_unwind_frame ("passwd mutation lock");
  return rc;
}

static int
bpw_info_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("info needs USER"); return EX_USAGE; }
  bpw_user u;
  if (!*args->word->word || bpw_lookup_user (args->word->word, &u, "/bin/sh") < 0)
    { builtin_error ("no passwd entry for %s", args->word->word); return EXECUTION_FAILURE; }
  const char *state = "NP";
  /* A status query must not use the authentication lookup: locked and
     empty passwords are successful results, not authentication errors. */
  FILE *f = fopen (bpw_shadow_path (), "r");
  if (f)
    {
      char *line = NULL; size_t cap = 0; ssize_t n;
      while ((n = getline (&line, &cap, f)) > 0)
        {
          if (n && line[n - 1] == '\n') line[n - 1] = '\0';
          char *colon = strchr (line, ':');
          if (!colon) continue;
          *colon = '\0';
          if (strcmp (line, args->word->word) == 0)
            {
              char *h = colon + 1;
              if (*h == '!' || *h == '*') state = "L";
              else if (*h && *h != ':') state = "P";
              break;
            }
        }
      free (line); fclose (f);
    }
  printf ("%s uid=%u gid=%u home=%s shell=%s password=%s\n",
          u.name, u.uid, u.gid, u.home, u.shell, state);
  return EXECUTION_SUCCESS;
}

static int
bpw_list_cmd (WORD_LIST *args)
{
  int long_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      if (strcmp (p->word->word, "-l") == 0) long_out = 1;
      else { builtin_error ("list: unexpected arg %s", p->word->word); return EX_USAGE; }
    }
  FILE *f = fopen (bpw_passwd_path (), "r");
  if (!f) { builtin_error ("open passwd: %s", strerror (errno)); return EXECUTION_FAILURE; }
  char *line = NULL; size_t cap = 0; ssize_t n;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *fields[7];
      if (bpw_passwd_fields (line, fields) == 0 && *fields[0])
        {
          if (long_out)
            printf ("%s:%s:%s:%s:%s\n", fields[0], fields[2], fields[3],
                    fields[5], fields[6]);
          else
            printf ("%s\n", fields[0]);
        }
    }
  free (line);
  fclose (f);
  return EXECUTION_SUCCESS;
}

static int
bpw_expire_inner (WORD_LIST *args)
{
  if (!args) { builtin_error ("expire needs USER [DAYS]"); return EX_USAGE; }
  const char *user = args->word->word;
  const char *days = args->next ? args->next->word->word : "0";
  if (args->next && args->next->next) { builtin_error ("expire: too many args"); return EX_USAGE; }

  unsigned int day_value;
  if (bpw_parse_id (days, &day_value) < 0) return EXECUTION_FAILURE;
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in) { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  struct stat st;
  if (fstat (fileno (in), &st) < 0) { fclose (in); return EXECUTION_FAILURE; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, st.st_mode & 07777);
  if (fd < 0) { fclose (in); return EXECUTION_FAILURE; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return EXECUTION_FAILURE; }
  char *line = NULL; size_t cap = 0; ssize_t n; int found = 0;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *copy = strdup (line);
      char *name = copy;
      char *c1 = copy ? strchr (copy, ':') : NULL;
      char *hash = c1 ? c1 + 1 : NULL;
      char *c2 = hash ? strchr (hash, ':') : NULL;
      if (c1)
        *c1 = '\0';
      if (name && strcmp (name, user) == 0)
        {
          found = 1;
          if (c2)
            {
              *c2 = '\0';
              char *aging = c2 + 1;
              char *after_lastchg = strchr (aging, ':');
              if (after_lastchg)
                fprintf (out, "%s:%s:%s:%s\n", name, hash ? hash : "", days,
                         after_lastchg + 1);
              else
                fprintf (out, "%s:%s:%s:0:99999:7:::\n", name,
                         hash ? hash : "", days);
            }
          else
            fprintf (out, "%s:%s:%s:0:99999:7:::\n", name, hash ? hash : "", days);
        }
      else
        fprintf (out, "%s\n", line);
      free (copy);
    }
  int bad = ferror (in) || ferror (out);
  free (line); if (fclose (in) != 0) bad = 1;
  if (fflush (out) != 0 || fsync (fd) != 0) bad = 1;
  if (fclose (out) != 0) bad = 1;
  if (bad || !found || rename (tmp, path) != 0)
    { unlink (tmp); return EXECUTION_FAILURE; }
  return bpw_fsync_parent (path) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_expire_cmd (WORD_LIST *args)
{
  unsigned int days;
  if (!args || (args->next && args->next->next) ||
      (args->next && bpw_parse_id (args->next->word->word, &days) < 0))
    return bpw_expire_inner (args);
  const char *paths[] = { bpw_shadow_path () };
  bpw_dir_locks locks = { 0 };
  int rc = EXECUTION_FAILURE;
  begin_unwind_frame ("passwd mutation lock");
  add_unwind_protect (bpw_unlock_dirs, &locks);
  if (bpw_lock_dirs (&locks, paths, 1) < 0)
    { builtin_error ("cannot lock account directory: %s", strerror (errno)); goto done; }
  bpw_user existing;
  if (bpw_lookup_user (args->word->word, &existing, "/bin/bash") < 0) goto done;
  bpw_snapshot snap[1] = { { .path = paths[0] } };
  bpw_unwind_snapshot cleanup = { .snap = snap, .count = 1, .active = 1 };
  add_unwind_protect (bpw_snapshot_unwind, &cleanup);
  if (bpw_snapshot_all (snap, 1) < 0) { cleanup.active = 0; goto done; }
  snap[0].touched = 1;
  rc = bpw_expire_inner (args);
  if (bpw_snapshot_finish (snap, 1, rc != EXECUTION_SUCCESS) < 0 && rc == EXECUTION_SUCCESS)
    { builtin_error ("expiry update committed but backup cleanup failed"); rc = EXECUTION_FAILURE; }
  cleanup.active = 0;
done:
  run_unwind_frame ("passwd mutation lock");
  return rc;
}

static int
bpw_set_user (const char *user, const bpw_auth_snapshot *auth)
{
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_new_password_secret (&secret, &secret_len);
  if (sr == 0)
    {
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_shadow_set_transaction_checked (user, phc, 1, auth) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_new_password (&pw, &pw_len) < 0) return EXECUTION_FAILURE;
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_release_tty_password (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_shadow_set_transaction_checked (user, phc, 1, auth) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_set_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("set needs USER"); return EX_USAGE; }
  return bpw_set_user (args->word->word, NULL);
}

static int
bpw_set_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("set-fd needs USER FD"); return EX_USAGE; }
  bpw_user user;
  if (!bpw_valid_user (args->word->word) ||
      bpw_lookup_user (args->word->word, &user, "/bin/bash") < 0)
    { builtin_error ("invalid or missing user"); return EXECUTION_FAILURE; }
  int fd = atoi (args->next->word->word);
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      if (secret_len == 0)
        { bpw_secret_clear (&secret); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_shadow_set_transaction (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0) return EXECUTION_FAILURE;
  if (pw_len == 0) { free (pw); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_wipe (pw, pw_len); free (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_shadow_set_transaction (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

typedef struct {
  bpw_auth_snapshot auth;
  bpw_secret_ref secret;
  unsigned char *old;
} bpw_change_state;

static void
bpw_change_cleanup (void *arg)
{
  bpw_change_state *state = arg;
  bpw_secret_clear (&state->secret);
  bpw_release_tty_password (state->old);
  state->old = NULL;
  if (state->auth.fd >= 0) close (state->auth.fd);
  state->auth.fd = -1;
  bpw_wipe (state->auth.phc, sizeof state->auth.phc);
}

static int
bpw_change_cmd (WORD_LIST *args)
{
  const char *user = args ? args->word->word : bpw_current_environment->user;
  if (!user || !*user) user = "root";
  if (args && args->next) { builtin_error ("change takes at most USER"); return EX_USAGE; }
  bpw_change_state state = { .auth = { .fd = -1 }, .secret = { -1, 0, 0 }, .old = NULL };
  size_t old_len = 0;
  int rc = EXECUTION_FAILURE;
  begin_unwind_frame ("passwd change authentication");
  add_unwind_protect (bpw_change_cleanup, &state);
  int sr = bpw_read_tty_secret ("Current password: ", &state.secret, &old_len);
  if (sr == 0)
    {
      if (bpw_secret_export_once (&state.secret, &state.old, &old_len) < 0) goto done;
      bpw_secret_clear (&state.secret);
    }
  else if (sr == -2)
    {
      if (bpw_read_tty_password ("Current password: ", &state.old, &old_len) < 0) goto done;
    }
  else goto done;
  if (bpw_check_lockout (user) < 0 ||
      bpw_shadow_phc_capture (user, state.auth.phc, sizeof state.auth.phc, &state.auth) != 0)
    goto auth_failure;
  int verified = bpw_verify_secret (state.old, old_len, state.auth.phc);
  bpw_release_tty_password (state.old);
  state.old = NULL;
  if (verified != 0)
    {
      if (verified == 1) bpw_record_failure (user);
      goto auth_failure;
    }
  bpw_record_success (user);
  rc = bpw_set_user (user, &state.auth);
  goto done;
auth_failure:
  builtin_error ("authentication failure");
done:
  run_unwind_frame ("passwd change authentication");
  return rc;
}

/* Scan the private account databases rather than NSS when assigning IDs. */
static int
bpw_id_in_file (const char *path, unsigned int id, int is_group)
{
  FILE *f = fopen (path, "r");
  if (!f) return errno == ENOENT ? 0 : -1;
  char *line = NULL; size_t cap = 0; int found = 0;
  while (getline (&line, &cap, f) >= 0)
    {
      char *a = strchr (line, ':');
      char *b = a ? strchr (a + 1, ':') : NULL;
      char *c = b ? strchr (b + 1, ':') : NULL;
      if (c) { unsigned int v; *c = 0; if (bpw_parse_id (b + 1, &v) == 0 && v == id) { found = 1; break; } }
    }
  if (ferror (f)) found = -1;
  free (line); fclose (f); (void) is_group;
  return found;
}

static int
bpw_init_add (bpw_user *u, const char *name, WORD_LIST *opts, int *create_group)
{
  int have_uid = 0, have_gid = 0;
  if (!bpw_valid_user (name)) return -1;
  memset (u, 0, sizeof *u);
  snprintf (u->name, sizeof u->name, "%s", name);
  snprintf (u->gecos, sizeof u->gecos, "%s", name);
  snprintf (u->home, sizeof u->home, "/home/%s", name);
  snprintf (u->shell, sizeof u->shell, "/bin/bash");
  for (WORD_LIST *p = opts; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!p->next) return -1;
      p = p->next; const char *v = p->word->word;
      if (!strcmp (w, "-u")) { if (bpw_parse_id (v, &u->uid) < 0) return -1; have_uid = 1; }
      else if (!strcmp (w, "-g")) { if (bpw_parse_id (v, &u->gid) < 0) return -1; have_gid = 1; }
      else if (!strcmp (w, "-d") || !strcmp (w, "-s"))
        {
          char *dst = !strcmp (w, "-d") ? u->home : u->shell;
          size_t sz = !strcmp (w, "-d") ? sizeof u->home : sizeof u->shell;
          if (strpbrk (v, ":\n\r") || strlen (v) >= sz) return -1;
          memcpy (dst, v, strlen (v) + 1);
        }
      else return -1;
    }
  if (!have_uid)
    {
      for (u->uid = 1000; u->uid < 60000; u->uid++)
        {
          int used = bpw_id_in_file (bpw_passwd_path (), u->uid, 0);
          int group_used = have_gid ? 0 : bpw_id_in_file (bpw_group_path (), u->uid, 1);
          if (used < 0 || group_used < 0) return -1;
          if (!used && !group_used) break;
        }
      if (u->uid == 60000) return -1;
    }
  if (have_uid)
    {
      int used = bpw_id_in_file (bpw_passwd_path (), u->uid, 0);
      if (used != 0) return -1;
    }
  if (!have_gid) u->gid = u->uid;
  int exists = bpw_id_in_file (bpw_group_path (), u->gid, 1);
  if (exists < 0) return -1;
  if (have_gid && !exists)
    { builtin_error ("add: primary group does not exist"); return -1; }
  *create_group = !exists;
  return 0;
}

static int
bpw_add_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("add needs USER"); return EX_USAGE; }
  bpw_user u; int create_group;
  if (bpw_init_add (&u, args->word->word, args->next, &create_group) < 0)
    { builtin_error ("add: invalid account options"); return EX_USAGE; }

  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_new_password_secret (&secret, &secret_len);
  if (sr == 0)
    {
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_create_account (&u, phc, create_group) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_new_password (&pw, &pw_len) < 0) return EXECUTION_FAILURE;
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_release_tty_password (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_create_account (&u, phc, create_group) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_add_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("add-fd needs USER FD"); return EX_USAGE; }
  unsigned int parsed_fd;
  if (bpw_parse_id (args->next->word->word, &parsed_fd) < 0 || parsed_fd > 2147483647U)
    return EX_USAGE;
  int fd = (int) parsed_fd;
  bpw_user u; int create_group;
  if (bpw_init_add (&u, args->word->word, args->next->next, &create_group) < 0)
    { builtin_error ("add-fd: invalid account options"); return EX_USAGE; }
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      if (secret_len == 0) { bpw_secret_clear (&secret); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_create_account (&u, phc, create_group) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0) return EXECUTION_FAILURE;
  if (pw_len == 0) { free (pw); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_wipe (pw, pw_len); free (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_create_account (&u, phc, create_group) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

extern char *passwd_doc[];

static int
bpw_dispatch (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0) {
      char **d;
      for (d = passwd_doc; *d; d++) puts (*d);
      return EXECUTION_SUCCESS;
  }
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "add") == 0) return bpw_add_cmd (args);
  if (strcmp (cmd, "add-fd") == 0) return bpw_add_fd_cmd (args);
  if (strcmp (cmd, "change") == 0) return bpw_change_cmd (args);
  if (strcmp (cmd, "set") == 0) return bpw_set_cmd (args);
  if (strcmp (cmd, "set-fd") == 0) return bpw_set_fd_cmd (args);
  if (strcmp (cmd, "delete") == 0) return bpw_delete_cmd (args);
  if (strcmp (cmd, "lock") == 0) return bpw_lock_cmd (args);
  if (strcmp (cmd, "unlock") == 0) return bpw_unlock_cmd (args);
  if (strcmp (cmd, "list") == 0) return bpw_list_cmd (args);
  if (strcmp (cmd, "expire") == 0) return bpw_expire_cmd (args);
  if (strcmp (cmd, "info") == 0) return bpw_info_cmd (args);
  if (strcmp (cmd, "verify") == 0) return bpw_verify_cmd (args);
  if (strcmp (cmd, "verify-fd") == 0) return bpw_verify_fd_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

static void
bpw_environment_cleanup (void *arg)
{
  bpw_environment *environment = arg;
  bpw_current_environment = environment->previous;
  free (environment->passwd_path);
  free (environment->shadow_path);
  free (environment->group_path);
  free (environment->lock_dir);
  free (environment->user);
}

int
passwd_builtin (WORD_LIST *list)
{
  bpw_environment environment = { .previous = bpw_current_environment };
  int rc = EXECUTION_FAILURE;
  begin_unwind_frame ("passwd environment snapshot");
  add_unwind_protect (bpw_environment_cleanup, &environment);
  environment.passwd_path = strdup (bpw_configured_passwd_path ());
  environment.shadow_path = strdup (bpw_configured_shadow_path ());
  environment.group_path = strdup (bpw_configured_group_path ());
  environment.lock_dir = strdup (bpw_configured_lock_dir ());
  const char *user = getenv ("USER");
  environment.user = strdup (user && *user ? user : "root");
  if (!environment.passwd_path || !environment.shadow_path ||
      !environment.group_path || !environment.lock_dir || !environment.user)
    builtin_error ("cannot copy account environment: out of memory");
  else
    {
      bpw_current_environment = &environment;
      rc = bpw_dispatch (list);
    }
  run_unwind_frame ("passwd environment snapshot");
  return rc;
}

char *passwd_doc[] = {
  "Password and account management for bash-os.",
  "",
  "    passwd add USER [-u UID] [-g GID] [-d HOME] [-s SHELL]",
  "    passwd add-fd USER FD [-u UID] [-g GID] [-d HOME] [-s SHELL]",
  "    passwd change [USER]",
  "    passwd set USER",
  "    passwd set-fd USER FD",
  "    passwd delete USER",
  "    passwd lock USER",
  "    passwd unlock USER",
  "    passwd list [-l]",
  "    passwd expire USER [DAYS]",
  "    passwd info USER",
  "    passwd verify USER",
  "        Prompt on /dev/tty and verify USER's password.",
  "",
  "    passwd verify-fd USER FD",
  "        Read password bytes from FD and verify USER.",
  "",
  "Password bytes are handled in C-owned buffers and wiped after use.",
  (char *)NULL
};

struct builtin passwd_struct = {
  "passwd",
  passwd_builtin,
  BUILTIN_ENABLED,
  passwd_doc,
  "passwd add|change|set|delete|lock|unlock|list|expire|info|verify|verify-fd ...",
  0
};
