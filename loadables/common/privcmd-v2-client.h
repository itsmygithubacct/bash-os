/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PRIVCMD_V2_CLIENT_H
#define BASHOS_PRIVCMD_V2_CLIENT_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include "_bashos_privcmd_v2_uapi.h"
_Static_assert(sizeof(struct bashos_auth_privcmd) == 832, "request input layout");
_Static_assert(sizeof(struct bashos_privcmd_v2_prepare) == 888, "prepare layout");
_Static_assert(sizeof(struct bashos_privcmd_v2_verify) == 72, "verify layout");
_Static_assert(sizeof(struct bashos_privcmd_v2_run) == 80, "run layout");
_Static_assert(sizeof(struct bashos_privcmd_v2_edit) == 184, "edit layout");
_Static_assert(sizeof(struct bashos_audit_v2_record) == 800, "audit layout");

static inline void bpv2_wipe(void *p, size_t size)
{
  volatile unsigned char *v = p;
  while (size--) *v++ = 0;
}

static inline int bpv2_check(int fd, int qualification)
{
  struct bashos_privcmd_v2_info info = {0};
  struct stat actual, node;
  const char *path = qualification ? "/dev/bashos-privcmd-v2-test" : "/dev/bashos-privcmd-v2";
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fstat(fd, &actual) || lstat(path, &node)) return -1;
  if ((flags & O_ACCMODE) != O_RDWR || !S_ISCHR(actual.st_mode) || !S_ISCHR(node.st_mode) ||
      node.st_uid || actual.st_dev != node.st_dev || actual.st_ino != node.st_ino || actual.st_rdev != node.st_rdev) {
    errno = ENODEV; return -1;
  }
  if (ioctl(fd, BASHOS_PRIVCMD_V2_INFO, &info)) return -1;
  if (info.size != sizeof info || info.version != BASHOS_PRIVCMD_V2_VERSION || info.reserved ||
      info.flags != (qualification ? BASHOS_PRIVCMD_V2_QUALIFICATION_ONLY : 0) ||
      !info.account_generation || !info.policy_generation || !info.group_generation || !info.verifier_generation) {
    errno = EPROTO; return -1;
  }
  return 0;
}

static inline int bpv2_open(int qualification)
{
  int fd, saved;
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return -1;
  fd = open(qualification ? "/dev/bashos-privcmd-v2-test" : "/dev/bashos-privcmd-v2", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  if (bpv2_check(fd, qualification)) { saved = errno; close(fd); errno = saved; return -1; }
  return fd;
}

static inline int bpv2_reset(int fd, int all)
{
  struct bashos_privcmd_v2_reset request = {0};
  request.size = sizeof request; request.version = BASHOS_PRIVCMD_V2_VERSION;
  request.flags = all ? BASHOS_PRIVCMD_V2_RESET_ALL : 0;
  return ioctl(fd, BASHOS_PRIVCMD_V2_RESET, &request);
}

static inline int bpv2_verify(int fd, struct bashos_privcmd_v2_prepare *prepared,
                             const unsigned char *secret, size_t length, int legacy)
{
  struct bashos_auth_handle handle = {0};
  struct bashos_auth_secret_write input = {0};
  struct bashos_privcmd_v2_verify request = {0};
  int rc = -1, saved;
  if (!prepared || !secret || length > 4096 || prepared->decision != BASHOS_PRIVCMD_V2_AUTH_REQUIRED ||
      !prepared->request_id || prepared->encoding != (legacy ? 2U : 1U)) { errno = EINVAL; return -1; }
  if (ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &handle)) return -1;
  input.id = handle.id; input.len = (uint32_t)length; input.user_ptr = (uint64_t)(uintptr_t)secret;
  request.size = sizeof request; request.version = BASHOS_PRIVCMD_V2_VERSION;
  request.secret_id = handle.id; request.request_id = prepared->request_id;
  memcpy(request.request_digest, prepared->request.request_digest, 32);
  if (!ioctl(fd, BASHOS_AUTH_IOC_WRITE_SECRET, &input) && !ioctl(fd, BASHOS_AUTH_IOC_SEAL_SECRET, &handle))
    rc = ioctl(fd, legacy ? BASHOS_PRIVCMD_V2_VERIFY_LEGACY_HEX : BASHOS_PRIVCMD_V2_VERIFY, &request);
  saved = errno;
  (void)ioctl(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &handle);
  if (!rc) {
    if (!request.deadline_ns || !request.audit_sequence) { rc = -1; saved = EPROTO; }
    else { prepared->decision = BASHOS_PRIVCMD_V2_READY; prepared->deadline_ns = request.deadline_ns; }
  }
  if (rc) (void)ioctl(fd, BASHOS_PRIVCMD_V2_CANCEL);
  bpv2_wipe(&handle, sizeof handle); bpv2_wipe(&input, sizeof input); bpv2_wipe(&request, sizeof request);
  errno = saved; return rc;
}

static inline int bpv2_run(int fd, const struct bashos_privcmd_v2_prepare *prepared,
                          struct bashos_privcmd_v2_run *result)
{
  if (!prepared || !result || prepared->decision != BASHOS_PRIVCMD_V2_READY || !prepared->request_id) {
    errno = EINVAL; return -1;
  }
  memset(result, 0, sizeof *result); result->size = sizeof *result; result->version = BASHOS_PRIVCMD_V2_VERSION;
  result->request_id = prepared->request_id; memcpy(result->request_digest, prepared->request.request_digest, 32);
  return ioctl(fd, BASHOS_PRIVCMD_V2_RUN, result);
}

static inline int bpv2_exit_status(const struct bashos_privcmd_v2_run *result)
{
  if (!result || result->size != sizeof *result || result->version != BASHOS_PRIVCMD_V2_VERSION ||
      result->reserved[0] || result->reserved[1] || !result->audit_sequence) return 125;
  if (result->result == BASHOS_PRIVCMD_V2_EXIT && result->status <= 255 && !result->failed_step && !result->error)
    return (int)result->status;
  if (result->result == BASHOS_PRIVCMD_V2_SIGNAL && result->status && result->status <= 64 && !result->failed_step && !result->error)
    return 128 + (int)result->status;
  if (result->result == BASHOS_PRIVCMD_V2_VALIDATED && !result->status && !result->failed_step && !result->error) return 0;
  if (result->result == BASHOS_PRIVCMD_V2_TIMEOUT && result->status == SIGKILL && result->error == ETIMEDOUT) return 124;
  if ((result->result == BASHOS_PRIVCMD_V2_SETUP_ERROR || result->result == BASHOS_PRIVCMD_V2_LAUNCH_ERROR ||
       result->result == BASHOS_PRIVCMD_V2_CONTROL_ERROR) && result->status == 126 && result->error) return 126;
  return 125;
}

/* phase 0 OPEN, 1 COMMIT, 2 SEAL; SEAL precedes fresh PREPARE/VERIFY. */
static inline int bpv2_edit(int fd, unsigned int phase, const struct bashos_privcmd_v2_prepare *prepared,
                           const int *copies, unsigned int count, struct bashos_privcmd_v2_edit *result)
{
  unsigned int i, any = 0;
  if (phase > 2 || !prepared || !result || !copies || !count || count > BASHOS_PRIVCMD_V2_EDIT_MAX_TARGETS ||
      prepared->decision != BASHOS_PRIVCMD_V2_READY || !prepared->request_id ||
      prepared->request.mode != BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT || prepared->request.argc != count) {
    errno = EINVAL; return -1;
  }
  memset(result, 0, sizeof *result); result->size = sizeof *result; result->version = BASHOS_PRIVCMD_V2_VERSION;
  result->count = count; result->request_id = prepared->request_id;
  memcpy(result->request_digest, prepared->request.request_digest, sizeof result->request_digest);
  for (i = 0; i < count; i++) {
    if (copies[i] < 0) { errno = EBADF; return -1; }
    result->copy_fds[i] = (uint32_t)copies[i];
  }
  if (ioctl(fd, phase == 2 ? BASHOS_PRIVCMD_V2_EDIT_SEAL :
            phase == 1 ? BASHOS_PRIVCMD_V2_EDIT_COMMIT : BASHOS_PRIVCMD_V2_EDIT_OPEN, result)) return -1;
  if (result->size != sizeof *result || result->version != BASHOS_PRIVCMD_V2_VERSION || result->count != count ||
      result->reserved || result->reserved2 || result->request_id != prepared->request_id ||
      memcmp(result->request_digest, prepared->request.request_digest, sizeof result->request_digest) ||
      !result->audit_sequence || result->committed_count > count || result->error > 4095 || result->cleanup_error > 4095 ||
      (result->failed_index != UINT32_MAX && result->failed_index >= count)) goto malformed;
  for (i = 0; i < 32; i++) any |= result->transaction_digest[i];
  if (phase == 1 && any && memcmp(result->transaction_digest, prepared->request.request_digest, 32)) goto malformed;
  if (result->result == BASHOS_PRIVCMD_V2_EDIT_FAILED) {
    if (!result->error || (phase != 1 && result->committed_count)) goto malformed;
    return 0;
  }
  if (result->error || result->cleanup_error || result->failed_index != UINT32_MAX ||
      result->result != (phase == 2 ? BASHOS_PRIVCMD_V2_EDIT_SEALED :
                         phase == 1 ? BASHOS_PRIVCMD_V2_EDIT_COMMITTED : BASHOS_PRIVCMD_V2_EDIT_OPENED) ||
      result->committed_count != (phase == 1 ? count : 0) || (!!any != !!phase)) goto malformed;
  return 0;
malformed:
  errno = EPROTO; return -1;
}

static volatile sig_atomic_t bpv2_caught_signal;
static void bpv2_password_signal(int sig) { bpv2_caught_signal = sig; }

static inline void bpv2_password_free(unsigned char *buffer)
{
  if (buffer) { bpv2_wipe(buffer, 4096); (void)munlock(buffer, 4096); (void)munmap(buffer, 4096); }
}

/* Versioned reader: refusal to disable echo or protect memory is terminal.
 * Restore terminal/signal state and wipe before delivering a caught signal to
 * Bash. Passwords never enter shell variables, argv, environment or stdout. */
static inline int bpv2_authenticate(int authority, struct bashos_privcmd_v2_prepare *prepared, int legacy)
{
  static const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};
  struct sigaction old[sizeof signals / sizeof signals[0]], action = {0};
  struct termios before, hidden;
  sigset_t blocked, previous;
  unsigned char *buffer = NULL;
  size_t used = 0, installed = 0, written = 0;
  const char prompt[] = "Password: ";
  int fd = -1, changed = 0, rc = -1, saved = 0, caught, mask_changed = 0;
  bpv2_caught_signal = 0;
  fd = open("/dev/tty", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  if (tcgetattr(fd, &before)) goto done;
  buffer = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) { buffer = NULL; goto done; }
  if (mlock(buffer, 4096) || madvise(buffer, 4096, MADV_DONTDUMP)) goto done;
  action.sa_handler = bpv2_password_signal;
  if (sigemptyset(&action.sa_mask)) goto done;
  for (; installed < sizeof signals / sizeof signals[0]; installed++)
    if (sigaction(signals[installed], &action, &old[installed])) goto done;
  hidden = before; hidden.c_lflag &= ~(ECHO | ECHONL | ICANON);
  hidden.c_cc[VMIN] = 1; hidden.c_cc[VTIME] = 0;
  if (tcsetattr(fd, TCSAFLUSH, &hidden)) goto done;
  changed = 1;
  while (written < sizeof prompt - 1 && !bpv2_caught_signal) {
    ssize_t n = write(fd, prompt + written, sizeof prompt - 1 - written);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = EIO; goto done; }
    written += (size_t)n;
  }
  while (!bpv2_caught_signal) {
    unsigned char byte;
    ssize_t n = read(fd, &byte, 1);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = EIO; goto done; }
    if (byte == '\n' || byte == '\r') { rc = 0; break; }
    if (byte == 4) { errno = ECANCELED; goto done; }
    if (byte == 8 || byte == 127) { if (used) buffer[--used] = 0; continue; }
    if (used == 4096) { errno = E2BIG; goto done; }
    buffer[used++] = byte; byte = 0;
  }
  if (!rc && !bpv2_caught_signal) rc = bpv2_verify(authority, prepared, buffer, used, legacy);
done:
  saved = errno;
  sigemptyset(&blocked);
  for (size_t i = 0; i < sizeof signals / sizeof signals[0]; i++) sigaddset(&blocked, signals[i]);
  if (!sigprocmask(SIG_BLOCK, &blocked, &previous)) mask_changed = 1;
  else { rc = -1; saved = errno; }
  caught = bpv2_caught_signal;
  if (caught) { rc = -1; saved = EINTR; }
  if (changed && tcsetattr(fd, TCSAFLUSH, &before)) { rc = -1; saved = errno; }
  if (changed) { ssize_t ignored = write(fd, "\n", 1); (void)ignored; }
  bpv2_password_free(buffer);
  if (rc) (void)ioctl(authority, BASHOS_PRIVCMD_V2_CANCEL);
  while (installed) { installed--; (void)sigaction(signals[installed], &old[installed], NULL); }
  close(fd);
  if (caught) (void)raise(caught);
  if (mask_changed && sigprocmask(SIG_SETMASK, &previous, NULL)) { rc = -1; saved = errno; }
  errno = saved; return rc;
}
#endif
