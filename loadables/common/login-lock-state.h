/* SPDX-License-Identifier: MIT */
/* Versioned login's persistent state. The existing COUNT/LAST/LOCKED_UNTIL
 * record is preserved; a separate stable guard inode serializes writers. */
#ifndef BASHOS_LOGIN_LOCK_STATE_H
#define BASHOS_LOGIN_LOCK_STATE_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct bls_state {
  int directory, guard;
  char name[80];
  int count;
  long last, until;
};

static inline void
bls_close (struct bls_state *state)
{
  int saved = errno;
  if (state->guard >= 0) close (state->guard);
  if (state->directory >= 0) close (state->directory);
  state->guard = state->directory = -1;
  errno = saved;
}

static inline int
bls_directory (const char *path)
{
  char copy[PATH_MAX], *part, *save = NULL;
  struct stat st;
  int fd, next;
  if (!path || path[0] != '/' || strlen (path) >= sizeof copy)
    { errno = EINVAL; return -1; }
  strcpy (copy, path);
  fd = open ("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  part = strtok_r (copy, "/", &save);
  if (!part) { close (fd); errno = EINVAL; return -1; }
  while (part)
    {
      char *following = strtok_r (NULL, "/", &save);
      if (!strcmp (part, ".") || !strcmp (part, ".."))
        { errno = EINVAL; goto failed; }
      if (fstat (fd, &st) < 0) goto failed;
      /* A root-owned sticky ancestor (e.g. /tmp) cannot let another user
         replace the root-owned child. The final state directory is private. */
      if (st.st_uid != 0 || ((st.st_mode & 0022) && !(st.st_mode & S_ISVTX)))
        { errno = EPERM; goto failed; }
      next = openat (fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (next < 0 && errno == ENOENT && !following)
        {
          if (mkdirat (fd, part, 0700) < 0 && errno != EEXIST) goto failed;
          if (fsync (fd) < 0) goto failed;
          next = openat (fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
      if (next < 0) goto failed;
      close (fd); fd = next; part = following;
    }
  if (fstat (fd, &st) < 0) goto failed;
  if (st.st_uid != 0 || (st.st_mode & 07777) != 0700)
    { errno = EPERM; goto failed; }
  return fd;
failed:
  { int saved_errno = errno; close (fd); errno = saved_errno; }
  return -1;
}

static inline int
bls_regular (const struct stat *st)
{
  return S_ISREG (st->st_mode) && st->st_uid == 0 && st->st_nlink == 1 &&
         (st->st_mode & 07777) == 0600;
}

static inline int
bls_open_regular (int directory, const char *name, int flags)
{
  struct stat st;
  int fd;
  if (fstatat (directory, name, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
      if (!bls_regular (&st)) { errno = EPERM; return -1; }
    }
  else if (errno != ENOENT) return -1;
  fd = openat (directory, name, flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
  if (fd < 0) return -1;
  if (fstat (fd, &st) < 0 || !bls_regular (&st))
    { close (fd); errno = EPERM; return -1; }
  return fd;
}

static inline int
bls_number (const char *p, long maximum, long *value)
{
  unsigned long n = 0;
  if (!*p) return -1;
  for (; *p; p++)
    {
      unsigned digit = (unsigned char) *p - '0';
      if (digit > 9 || n > ((unsigned long) maximum - digit) / 10) return -1;
      n = n * 10 + digit;
    }
  *value = (long) n;
  return 0;
}

static inline int
bls_read (struct bls_state *state)
{
  struct stat st;
  char data[128], *line, *save = NULL;
  size_t used = 0;
  unsigned fields = 0;
  int fd = bls_open_regular (state->directory, state->name, O_RDONLY);
  state->count = 0; state->last = state->until = 0;
  if (fd < 0) return errno == ENOENT ? 0 : -1;
  if (fstat (fd, &st) < 0) goto failed;
  if (st.st_size <= 0 || st.st_size >= (off_t) sizeof data)
    { errno = EINVAL; goto failed; }
  for (;;)
    {
      ssize_t n = read (fd, data + used, sizeof data - used);
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) goto failed;
      if (!n) break;
      used += n;
      if (used == sizeof data) { errno = EINVAL; goto failed; }
    }
  if (used != (size_t) st.st_size || memchr (data, 0, used))
    { errno = EINVAL; goto failed; }
  if (close (fd) < 0) return -1;
  data[used] = 0;
  if (data[0] == '\n' || strstr (data, "\n\n")) { errno = EINVAL; return -1; }
  for (line = strtok_r (data, "\n", &save); line; line = strtok_r (NULL, "\n", &save))
    {
      long value;
      unsigned field;
      if (!strncmp (line, "COUNT=", 6))
        {
          field = 1;
          if (bls_number (line + 6, INT_MAX, &value)) goto invalid;
          state->count = (int) value;
        }
      else if (!strncmp (line, "LAST=", 5))
        {
          field = 2;
          if (bls_number (line + 5, LONG_MAX, &value)) goto invalid;
          state->last = value;
        }
      else if (!strncmp (line, "LOCKED_UNTIL=", 13))
        {
          field = 4;
          if (bls_number (line + 13, LONG_MAX, &value)) goto invalid;
          state->until = value;
        }
      else goto invalid;
      if (fields & field) goto invalid;
      fields |= field;
    }
  if (fields != 7 || (state->until && state->until < state->last)) goto invalid;
  return 0;
invalid:
  errno = EINVAL;
  return -1;
failed:
  { int saved_errno = errno; close (fd); errno = saved_errno; }
  return -1;
}

static inline int
bls_begin (const char *directory, const char *key, struct bls_state *state)
{
  char guard[80];
  size_t n;
  *state = (struct bls_state) { .directory = -1, .guard = -1 };
  if (!key || !(n = strlen (key)) || n >= 64) { errno = EINVAL; return -1; }
  for (size_t i = 0; i < n; i++)
    if (!((key[i] >= '0' && key[i] <= '9') || (key[i] >= 'a' && key[i] <= 'z') ||
          (key[i] >= 'A' && key[i] <= 'Z') || key[i] == '_' || key[i] == '-'))
      { errno = EINVAL; return -1; }
  snprintf (state->name, sizeof state->name, "fail.%s", key);
  snprintf (guard, sizeof guard, ".guard.%s", key);
  state->directory = bls_directory (directory);
  if (state->directory < 0) return -1;
  state->guard = bls_open_regular (state->directory, guard, O_RDWR | O_CREAT);
  if (state->guard < 0 || flock (state->guard, LOCK_EX | LOCK_NB) < 0 || bls_read (state) < 0)
    { bls_close (state); return -1; }
  return 0;
}

static inline int
bls_now (const struct bls_state *state, long *now)
{
  time_t t = time (NULL);
  if (t < 0 || (uintmax_t) t > LONG_MAX || (long) t < state->last)
    { errno = EOVERFLOW; return -1; }
  *now = (long) t;
  return 0;
}

static inline int
bls_store (struct bls_state *state)
{
  unsigned char random[16];
  char name[48] = ".state-", data[128];
  static const char hex[] = "0123456789abcdef";
  int fd, length, saved = 0;
  ssize_t got;
  do got = getrandom (random, sizeof random, GRND_NONBLOCK); while (got < 0 && errno == EINTR);
  if (got != sizeof random) { if (got >= 0) errno = EIO; return -1; }
  for (size_t i = 0; i < sizeof random; i++)
    { name[7 + i * 2] = hex[random[i] >> 4]; name[8 + i * 2] = hex[random[i] & 15]; }
  name[39] = 0;
  length = snprintf (data, sizeof data, "COUNT=%d\nLAST=%ld\nLOCKED_UNTIL=%ld\n",
                     state->count, state->last, state->until);
  if (length < 0 || (size_t) length >= sizeof data) { errno = EOVERFLOW; return -1; }
  fd = openat (state->directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return -1;
  if (fchmod (fd, 0600) < 0) saved = errno;
  for (int at = 0; !saved && at < length;)
    {
      ssize_t n = write (fd, data + at, (size_t) (length - at));
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) saved = n < 0 ? errno : EIO;
      else at += n;
    }
  if (!saved && fsync (fd) < 0) saved = errno;
  if (close (fd) < 0 && !saved) saved = errno;
  if (!saved && renameat (state->directory, name, state->directory, state->name) < 0) saved = errno;
  if (!saved && fsync (state->directory) < 0) saved = errno;
  if (saved)
    { unlinkat (state->directory, name, 0); errno = saved; return -1; }
  return 0;
}

static inline int
bls_failure (struct bls_state *state, int maximum, long window, long duration)
{
  long now;
  if (maximum <= 0 || window < 0 || duration < 0) { errno = EINVAL; return -1; }
  if (bls_now (state, &now) < 0) return -1;
  if (state->until > now) { errno = EACCES; return -1; }
  if (now - state->last > window) state->count = 0;
  if (state->count < INT_MAX) state->count++;
  state->last = now;
  if (state->count >= maximum && duration > LONG_MAX - now)
    { errno = EOVERFLOW; return -1; }
  state->until = state->count >= maximum ? now + duration : 0;
  return bls_store (state);
}

static inline int
bls_success (struct bls_state *state)
{
  long now;
  if (bls_now (state, &now) < 0) return -1;
  if (state->until > now) { errno = EACCES; return -1; }
  if (unlinkat (state->directory, state->name, 0) < 0 && errno != ENOENT) return -1;
  return fsync (state->directory);
}
#endif
