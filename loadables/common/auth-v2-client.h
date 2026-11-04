/* SPDX-License-Identifier: MIT */
/* Native calls only: proof bytes stay in wiped C storage and the bound fd.
 * No environment-selected verifier, userspace authentication result, raw MINT,
 * interpreter child or uid-0 shortcut participates in this protocol. */
#ifndef BASHOS_AUTH_V2_CLIENT_H
#define BASHOS_AUTH_V2_CLIENT_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "_bashos_auth_uapi.h"
#include "_bashos_auth_v2_uapi.h"

_Static_assert(sizeof(struct bashos_auth_v2_info) == 32, "v2 info size");
_Static_assert(sizeof(struct bashos_auth_v2_identity) == 80, "v2 identity size");
_Static_assert(sizeof(struct bashos_auth_v2_verify) == 96, "v2 verify size");
_Static_assert(sizeof(struct bashos_auth_v2_consume) == 128, "v2 consume size");

static inline void
bashos_v2_wipe(void *data, size_t size)
{
  volatile unsigned char *p = data;
  while (size--) *p++ = 0;
}

static inline int
bashos_v2_identity(struct bashos_auth_v2_identity *out, unsigned purpose,
                   uid_t uid, gid_t gid, const char *user, unsigned encoding)
{
  size_t n;
  if (!out) { errno = EINVAL; return -1; }
  memset(out, 0, sizeof *out);
  if (!user || !(n = strnlen(user, sizeof out->user)) || n == sizeof out->user ||
      (purpose != BASHOS_AUTH_V2_LOGIN && purpose != BASHOS_AUTH_V2_SU && purpose != BASHOS_AUTH_V2_SSH) ||
      (encoding != BASHOS_AUTH_V2_STANDARD_PHC && encoding != BASHOS_AUTH_V2_LEGACY_HEX) ||
      (uint32_t)uid == UINT32_MAX || (uint32_t)gid == UINT32_MAX) {
    errno = EINVAL; return -1;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)user[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
      errno = EINVAL; return -1;
    }
  }
  out->purpose = purpose; out->uid = uid; out->gid = gid; out->encoding = encoding;
  memcpy(out->user, user, n + 1);
  return 0;
}

/* Version/layout checks are transport checks only. Successful authentication
 * still requires the kernel's native verifier and a subsequent redemption. */
static inline int
bashos_v2_check_fd(int fd)
{
  struct bashos_auth_v2_info info = {0};
  struct stat actual, node;
  const char *path;
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fstat(fd, &actual) < 0) return -1;
  if ((flags & O_ACCMODE) != O_RDWR || !S_ISCHR(actual.st_mode)) { errno = ENODEV; return -1; }
  if (ioctl(fd, BASHOS_AUTH_V2_INFO, &info) < 0) return -1;
  if (info.size != sizeof info || info.version != BASHOS_AUTH_V2_VERSION ||
      (info.flags & ~BASHOS_AUTH_V2_QUALIFICATION_ONLY) ||
      !info.account_generation || !info.policy_generation) { errno = EPROTO; return -1; }
  path = info.flags & BASHOS_AUTH_V2_QUALIFICATION_ONLY ?
      BASHOS_AUTH_V2_QUALIFICATION_DEVICE : BASHOS_AUTH_V2_DEVICE;
  if (lstat(path, &node) < 0) return -1;
  if (!S_ISCHR(node.st_mode) || node.st_uid != 0 || node.st_dev != actual.st_dev ||
      node.st_ino != actual.st_ino || node.st_rdev != actual.st_rdev) { errno = ENODEV; return -1; }
  return 0;
}

static inline int
bashos_v2_open(int qualification_only)
{
  int fd, saved;
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return -1;
  fd = open(qualification_only ? BASHOS_AUTH_V2_QUALIFICATION_DEVICE : BASHOS_AUTH_V2_DEVICE,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  if (bashos_v2_check_fd(fd)) { saved = errno; close(fd); errno = saved; return -1; }
  return fd;
}

static inline int
bashos_v2_verify_handle(int fd, unsigned handle, const struct bashos_auth_v2_identity *identity)
{
  struct bashos_auth_v2_verify request = {0};
  int rc, saved;
  if (!identity || !handle) { errno = EINVAL; return -1; }
  if (bashos_v2_check_fd(fd)) return -1;
  request.size = sizeof request; request.version = BASHOS_AUTH_V2_VERSION;
  request.secret_id = handle; request.identity = *identity;
  rc = ioctl(fd, identity->encoding == BASHOS_AUTH_V2_LEGACY_HEX ?
             BASHOS_AUTH_V2_VERIFY_LEGACY_HEX : BASHOS_AUTH_V2_VERIFY, &request);
  saved = errno; bashos_v2_wipe(&request, sizeof request); errno = saved;
  return rc;
}

static inline int
bashos_v2_verify_password(int fd, const unsigned char *password, size_t length,
                          const struct bashos_auth_v2_identity *identity)
{
  struct bashos_auth_handle handle = {0};
  struct bashos_auth_secret_write write_request = {0};
  int rc = -1, saved;
  if (!password || length > 4096 || !identity) { errno = EINVAL; return -1; }
  if (bashos_v2_check_fd(fd) || ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &handle)) return -1;
  write_request.id = handle.id; write_request.len = (uint32_t)length;
  write_request.user_ptr = (uint64_t)(uintptr_t)password;
  if (!ioctl(fd, BASHOS_AUTH_IOC_WRITE_SECRET, &write_request) &&
      !ioctl(fd, BASHOS_AUTH_IOC_SEAL_SECRET, &handle))
    rc = bashos_v2_verify_handle(fd, handle.id, identity);
  saved = errno;
  (void)ioctl(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &handle);
  bashos_v2_wipe(&handle, sizeof handle); bashos_v2_wipe(&write_request, sizeof write_request);
  errno = saved;
  return rc;
}

static inline int
bashos_v2_consume(int fd, const struct bashos_auth_v2_identity *identity)
{
  struct bashos_auth_v2_consume request = {0};
  size_t have = 0;
  ssize_t n;
  unsigned char extra = 0;
  int rc = -1, saved;
  if (!identity) { errno = EINVAL; return -1; }
  if (bashos_v2_check_fd(fd)) return -1;
  request.size = sizeof request; request.version = BASHOS_AUTH_V2_VERSION;
  request.identity = *identity;
  while (have < sizeof request.reference) {
    n = read(fd, request.reference + have, sizeof request.reference - have);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = EPROTO; goto done; }
    have += (size_t)n;
  }
  do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
  if (n != 0) { if (n > 0) errno = EPROTO; goto done; }
  rc = ioctl(fd, BASHOS_AUTH_V2_CONSUME, &request);
done:
  saved = errno;
  if (rc) (void)ioctl(fd, BASHOS_AUTH_V2_RESET);
  bashos_v2_wipe(&request, sizeof request); bashos_v2_wipe(&extra, sizeof extra);
  errno = saved;
  return rc;
}

static inline int
bashos_v2_delegate_ssh(int fd, pid_t child)
{
  struct bashos_auth_v2_delegate request = {sizeof request, BASHOS_AUTH_V2_VERSION, 0, 0};
  if (child <= 0) { errno = EINVAL; return -1; }
  if (bashos_v2_check_fd(fd)) return -1;
  request.child_pid = (uint32_t)child;
  return ioctl(fd, BASHOS_AUTH_V2_DELEGATE_SSH, &request);
}
#endif
