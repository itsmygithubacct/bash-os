/* Compile only through the campaign build gate. This translation unit includes
   the production implementation; only socket/time calls are replaced. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
static int fx_socket(int, int, int);
static int fx_close(int);
static int fx_connect(int, const struct sockaddr *, socklen_t);
static int fx_getsockname(int, struct sockaddr *, socklen_t *);
static int fx_setsockopt(int, int, int, const void *, socklen_t);
static ssize_t fx_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t fx_recvmsg(int, struct msghdr *, int);
static int fx_poll(struct pollfd *, nfds_t, int);
static int fx_clock_gettime(clockid_t, struct timespec *);
static int fx_nanosleep(const struct timespec *, struct timespec *);
#define socket fx_socket
#define close fx_close
#define connect fx_connect
#define getsockname fx_getsockname
#define setsockopt fx_setsockopt
#define sendto fx_sendto
#define recvmsg fx_recvmsg
#define poll fx_poll
#define clock_gettime fx_clock_gettime
#define nanosleep fx_nanosleep
#include "../loadables/ping.c"
#undef socket
#undef close
#undef connect
#undef getsockname
#undef setsockopt
#undef sendto
#undef recvmsg
#undef poll
#undef clock_gettime
#undef nanosleep
struct builtin ping_struct = { "ping", ping_builtin, BUILTIN_ENABLED, ping_doc,
                               "ping [options] HOST", 0 };
static unsigned char request[64], previous[64];
static int family, raw, active = -1, sends, reads, stage, poll_intr, recv_intr;
static double now_ms;
static const char *mode;
static void require(int ok) { if (!ok) { fputs("FIXTURE assertion failed\n", stderr); abort(); } }
static int ismode(const char *s) { return mode && strcmp(mode, s) == 0; }
/* Independent byte-wise network checksum oracle, never bp_checksum. */
static unsigned checksum(const unsigned char *p, size_t n) {
  unsigned sum = 0;
  for (size_t i = 0; i < n; i += 2) sum += (p[i] << 8) + (i+1 < n ? p[i+1] : 0);
  while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
  return (~sum) & 65535;
}
static void set_checksum(unsigned char *p, size_t n, int offset) {
  p[offset] = p[offset+1] = 0; unsigned c = checksum(p, n);
  p[offset] = c >> 8; p[offset+1] = c;
}
static int fx_socket(int af, int type, int protocol) {
  mode = getenv("SOL_PING_MODE");
  require(af == AF_INET || af == AF_INET6);
  require(protocol == (af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6));
  if (ismode("denied") || ismode("denied-access")) { errno = ismode("denied") ? EPERM : EACCES; return -1; }
  if (ismode("unsupported")) { errno = EAFNOSUPPORT; return -1; }
  if ((ismode("dgram") || ismode("connect-error") || ismode("name-error")) && type == SOCK_RAW) { errno = EPERM; return -1; }
  require(active == -1);
  family = af; raw = type == SOCK_RAW; sends = reads = stage = poll_intr = recv_intr = 0; now_ms = 1000;
  active = open("/dev/null", O_RDONLY | O_CLOEXEC); require(active >= 0);
  return active;
}
static int fx_close(int fd) {
  require(fd == active);
  fprintf(stderr, "FIXTURE sends=%d reads=%d elapsed=%.3f raw=%d\n", sends, reads, now_ms-1000, raw);
  active = -1; return close(fd);
}
static int fx_connect(int fd, const struct sockaddr *addr, socklen_t len) {
  require(fd == active && addr && len > 0);
  if (ismode("connect-error")) { errno=EACCES; return -1; } return 0;
}
static int fx_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
  require(fd == active);
  if (ismode("name-error")) { errno=EIO; return -1; }
  memset(addr, 0, *len); addr->sa_family = family;
  if (family == AF_INET) ((struct sockaddr_in *)addr)->sin_port = htons(4242);
  else ((struct sockaddr_in6 *)addr)->sin6_port = htons(4242);
  return 0;
}
static int fx_setsockopt(int fd, int level, int opt, const void *v, socklen_t len) {
  require(fd == active && level == IPPROTO_IPV6 && opt == IPV6_RECVHOPLIMIT && len == sizeof(int) && *(const int *)v == 1); return 0;
}
static ssize_t fx_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dst, socklen_t slen) {
  require(fd == active && len == 64 && flags == 0 && slen > 0);
  if (family == AF_INET) require(((const struct sockaddr_in *)dst)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
  else require(IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)dst)->sin6_addr));
  memcpy(previous, request, 64); memcpy(request, buf, 64); sends++; stage=0;
  require(request[0] == (family == AF_INET ? 8 : 128) && request[1] == 0);
  require(((request[6]<<8)|request[7]) == sends);
  require(((request[4]<<8)|request[5]) == (raw ? (getpid() & 65535) : 4242));
  for (int i=16; i<64; i++) require(request[i] == i);
  double stamp; memcpy(&stamp, request+8, 8); require(fabs(stamp - now_ms) < .000002);
  if (family == AF_INET) require(checksum(request, len) == 0);
  if (ismode("send-error")) { errno=ENETUNREACH; return -1; }
  if (ismode("short-send")) return 63;
  return len;
}
static int fx_poll(struct pollfd *p, nfds_t n, int timeout) {
  require(n == 1 && p->fd == active && timeout > 0);
  if (ismode("poll-error")) { errno=EIO; return -1; }
  if (ismode("poll-revents")) { p->revents=POLLERR; return 1; }
  if (ismode("eintr") && !poll_intr++) { errno=EINTR; return -1; }
  int limit = ismode("mixed") ? (family == AF_INET ? 21 : 13) : 1;
  if (ismode("timeout") || (ismode("loss-duplicates") && sends == 2 && stage >= 1) || stage >= limit) { now_ms += timeout; return 0; }
  p->revents=POLLIN; return 1;
}
static ssize_t fx_recvmsg(int fd, struct msghdr *m, int flags) {
  require(fd == active && flags == MSG_DONTWAIT && m->msg_iovlen == 1);
  if (ismode("recv-error")) { errno=EIO; return -1; }
  if (ismode("eintr") && !recv_intr++) { errno=EINTR; return -1; }
  if (ismode("eagain") && !recv_intr++) { errno=EAGAIN; return -1; }
  unsigned char p[124] = {0}; int h = family == AF_INET && raw ? 20 : 0;
  unsigned char *icmp = p+h;
  memcpy(icmp, ismode("loss-duplicates") && sends == 2 ? previous : request, 64);
  icmp[0] = family == AF_INET ? 0 : 129;
  int k = stage++; reads++; now_ms += ismode("late-reply") ? 101 : .25;
  int variant = ismode("mixed") ? (family == AF_INET || k < 6 ? k : k + 8) : -1;
  if (ismode("wrong-id")) variant=0;
  if (ismode("wrong-seq")) variant=1;
  if (ismode("wrong-payload")) variant=2;
  if (variant == 0) icmp[4] ^= 1;
  if (variant == 1) icmp[7] ^= 1;
  if (variant == 2) icmp[32] ^= 1;
  if (variant == 3) icmp[1] = 1;
  if (variant == 4) icmp[0] = 3;
  if (variant == 5) icmp[8] ^= 1; /* timestamp corruption */
  if (family == AF_INET) set_checksum(icmp, 64, 2);
  if (variant == 6 && family == AF_INET) icmp[2] ^= 1;
  size_t length = h+64;
  if (h) {
    p[0]=0x45; p[2]=length>>8; p[3]=length; p[8]=64; p[9]=IPPROTO_ICMP;
    p[12]=127; p[15]=1; p[16]=127; p[19]=1;
    if (variant == 7) p[0]=0x65;
    if (variant == 8) p[0]=0x4f;
    if (variant == 9) p[3]--;
    if (variant == 10) p[6]=0x20;
    if (variant == 11) p[9]=IPPROTO_UDP;
    if (variant == 12) p[15]=2;
    set_checksum(p, h, 10);
    if (variant == 13) p[10] ^= 1;
  }
  if (variant == 8 && h) length=68;
  if (variant == 14) length=7;
  if (variant == 15) length=h+63;
  if (variant == 19) length=0;
  if (variant == 16) m->msg_flags=MSG_TRUNC;
  if (variant == 17) m->msg_flags=MSG_CTRUNC;
  require(m->msg_iov[0].iov_len >= length); memcpy(m->msg_iov[0].iov_base, p, length);
  memset(m->msg_name, 0, m->msg_namelen);
  struct sockaddr *src = m->msg_name; src->sa_family=family;
  if (family == AF_INET) ((struct sockaddr_in *)src)->sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  else ((struct sockaddr_in6 *)src)->sin6_addr=in6addr_loopback;
  if (variant == 18) {
    if (family == AF_INET) ((struct sockaddr_in *)src)->sin_addr.s_addr=htonl(0x7f000002);
    else ((struct sockaddr_in6 *)src)->sin6_addr.s6_addr[15]=2;
  }
  m->msg_controllen=0;
  return length;
}
static int fx_clock_gettime(clockid_t clock, struct timespec *ts) {
  require(clock == CLOCK_MONOTONIC);
  if (ismode("clock-error") || (ismode("clock-late-error") && sends)) { errno=EIO; return -1; }
  double clock_ms = now_ms - (ismode("clock-backwards") && sends ? 100 : 0);
  ts->tv_sec=(time_t)(clock_ms/1000); ts->tv_nsec=(long)((clock_ms-ts->tv_sec*1000)*1e6); return 0;
}
static int fx_nanosleep(const struct timespec *ts, struct timespec *remaining) {
  (void) remaining; require(ts->tv_nsec>=0 && ts->tv_nsec<1000000000);
  if (ismode("sleep-error")) { errno=EIO; return -1; }
  now_ms+=ts->tv_sec*1000+ts->tv_nsec/1e6;
  if (ismode("interrupt")) raise(SIGINT);
  return 0;
}
