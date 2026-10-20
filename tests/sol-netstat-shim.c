/* SPDX-License-Identifier: MIT
 * Test-only syscall fixture transport; never linked into the product.
 * All decoding, filtering, PID lookup and rendering remain production code.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>

static int diag_fd = -1;
static unsigned request_seq;
static int request_family, request_proto, delivered;
static unsigned request_states;

static const char *root(void) { return getenv("SOL_NETSTAT_FIXTURE"); }
static int mode(const char *s) {
  const char *m = getenv("SOL_NETSTAT_TRANSPORT");
  return m && strcmp(m, s) == 0;
}
static const char *mapped(const char *path, char *buf, size_t size) {
  const char *r = root();
  if (r && (strcmp(path, "/proc") == 0 || strncmp(path, "/proc/net/", 10) == 0 ||
            strncmp(path, "/proc/4242/", 11) == 0 || strncmp(path, "/proc/9999/", 11) == 0)) {
    snprintf(buf, size, "%s%s", r, path);
    return buf;
  }
  return path;
}
FILE *fopen(const char *path, const char *how) {
  FILE *(*real_fn)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
  char buf[4096];
  if (root() && mode("denied") && strncmp(path, "/proc/net/", 10) == 0) {
    errno = EACCES; return NULL;
  }
  return real_fn(mapped(path, buf, sizeof buf), how);
}
DIR *opendir(const char *path) {
  DIR *(*real_fn)(const char *) = dlsym(RTLD_NEXT, "opendir");
  char buf[4096];
  if (root() && strcmp(path, "/proc/9999/fd") == 0) {
    errno = EACCES; return NULL;
  }
  return real_fn(mapped(path, buf, sizeof buf));
}
ssize_t readlink(const char *path, char *out, size_t size) {
  ssize_t (*real_fn)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
  char buf[4096];
  return real_fn(mapped(path, buf, sizeof buf), out, size);
}
int socket(int family, int type, int proto) {
  int (*real_fn)(int, int, int) = dlsym(RTLD_NEXT, "socket");
  if (root() && family == AF_NETLINK && proto == NETLINK_SOCK_DIAG) {
    if (!mode("diag")) { errno = EACCES; return -1; }
    diag_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    delivered = 0;
    return diag_fd;
  }
  return real_fn(family, type, proto);
}
int bind(int fd, const struct sockaddr *sa, socklen_t len) {
  int (*real_fn)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
  return fd == diag_fd ? 0 : real_fn(fd, sa, len);
}
ssize_t sendto(int fd, const void *data, size_t size, int flags,
               const struct sockaddr *sa, socklen_t len) {
  ssize_t (*real_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)
    = dlsym(RTLD_NEXT, "sendto");
  if (fd != diag_fd) return real_fn(fd, data, size, flags, sa, len);
  if (size < NLMSG_LENGTH(sizeof(struct unix_diag_req))) { errno = EINVAL; return -1; }
  const struct nlmsghdr *h = data;
  const struct inet_diag_req_v2 *r = NLMSG_DATA(h);
  if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
      h->nlmsg_flags != (NLM_F_REQUEST | NLM_F_DUMP) || h->nlmsg_len != size) {
    errno = EINVAL; return -1;
  }
  request_seq = h->nlmsg_seq;
  request_family = r->sdiag_family;
  request_proto = request_family == AF_UNIX ? 0 : r->sdiag_protocol;
  request_states = r->idiag_states;
  delivered = 0;
  return size;
}
ssize_t recv(int fd, void *out, size_t size, int flags) {
  ssize_t (*real_fn)(int, void *, size_t, int) = dlsym(RTLD_NEXT, "recv");
  if (fd != diag_fd) return real_fn(fd, out, size, flags);
  if (delivered++) return 0;
  char path[4096];
  snprintf(path, sizeof path, "%s/diag/%d-%d.bin", root(), request_family, request_proto);
  int input = open(path, O_RDONLY | O_CLOEXEC);
  if (input < 0) return -1;
  ssize_t n = read(input, out, size);
  close(input);
  if (n <= 0) return n;
  /* Patch only transport sequence numbers; preserve intentional mismatches.
   * Honor the kernel's state mask so a bad production request is observable. */
  ssize_t left = n;
  struct nlmsghdr *h = out;
  while (NLMSG_OK(h, left)) {
    h->nlmsg_seq = h->nlmsg_seq == 0xffffffffU ? request_seq + 1 : request_seq;
    if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
        h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct unix_diag_msg))) {
      unsigned char *payload = NLMSG_DATA(h);
      unsigned st = request_family == AF_UNIX ? payload[2] : payload[1];
      if (st >= 32 || !(request_states & (1U << st))) h->nlmsg_seq = request_seq + 1;
    }
    h = NLMSG_NEXT(h, left);
  }
  return n;
}
int close(int fd) {
  int (*real_fn)(int) = dlsym(RTLD_NEXT, "close");
  if (fd == diag_fd) diag_fd = -1;
  return real_fn(fd);
}
