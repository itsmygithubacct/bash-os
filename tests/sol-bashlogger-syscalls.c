/* SPDX-License-Identifier: MIT
 * Test-only interposer: observe the production descriptor, never send to syslog.
 * Compile separately through the campaign build gate; see docs/sol-bashlogger.md.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int is_mode(const char *name)
{
  const char *mode = getenv("BLOG_TEST_MODE");
  return mode && strcmp(mode, name) == 0;
}

int socket(int domain, int type, int protocol)
{
  int (*real_socket)(int, int, int) = dlsym(RTLD_NEXT, "socket");
  if (domain == AF_UNIX && (type & 0xf) == SOCK_DGRAM) {
    if (is_mode("socket-fail")) { errno = EMFILE; return -1; }
    if (is_mode("fallback") && (type & SOCK_CLOEXEC)) { errno = EINVAL; return -1; }
  }
  return real_socket(domain, type, protocol);
}

/* Bash uses fcntl for its own descriptors too. Forward the actual argument type. */
int fcntl(int fd, int cmd, ...)
{
  int (*real_fcntl)(int, int, ...) = dlsym(RTLD_NEXT, "fcntl");
  va_list ap;
  int value, type;
  socklen_t size = sizeof(type);
  switch (cmd) {
  case F_GETFD: case F_GETFL: case F_GETOWN:
    return real_fcntl(fd, cmd);
  case F_DUPFD: case F_DUPFD_CLOEXEC: case F_SETFD: case F_SETFL: case F_SETOWN:
    va_start(ap, cmd); value = va_arg(ap, int); va_end(ap);
    if (cmd == F_SETFD && is_mode("setfd-fail") &&
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_DGRAM) {
      errno = EIO; return -1;
    }
    return real_fcntl(fd, cmd, value);
  default: {
    void *pointer;
    va_start(ap, cmd); pointer = va_arg(ap, void *); va_end(ap);
    return real_fcntl(fd, cmd, pointer);
  }
  }
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *address, socklen_t address_len)
{
  ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) =
    dlsym(RTLD_NEXT, "sendto");
  const char *path = getenv("BASHLOGGER_SOCKET");
  const struct sockaddr_un *sun = (const struct sockaddr_un *)address;
  static int interrupted;
  /* Refuse any accidental host write even if a test is broken. */
  if (!path || address->sa_family != AF_UNIX || strcmp(path, sun->sun_path) != 0 ||
      strcmp(path, "/dev/log") == 0) { errno = EPERM; return -1; }
  int descriptor_flags = fcntl(fd, F_GETFD);
  if (descriptor_flags < 0 || !(descriptor_flags & FD_CLOEXEC)) { errno = EPERM; return -1; }
  char command[128];
  snprintf(command, sizeof(command), "test ! -e /proc/self/fd/%d", fd);
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    execl("/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(99);
  }
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { errno = EPERM; return -1; }
  int audit = open(getenv("BLOG_TEST_AUDIT"), O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0600);
  if (audit < 0) return -1;
  const char record[] = "cloexec+exec-closed\n";
  if (write(audit, record, sizeof(record)-1) != sizeof(record)-1) { close(audit); errno = EIO; return -1; }
  close(audit);
  if (is_mode("send-fail")) { errno = EIO; return -1; }
  if (is_mode("short-send")) return len-1;
  if (is_mode("eintr") && !interrupted++) { errno = EINTR; return -1; }
  return real_sendto(fd, buf, len, flags, address, address_len);
}
