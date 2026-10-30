/* SPDX-License-Identifier: MIT */
/* Guest-only native tracee: guarded ioctls surround a marked operation. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bashio-network-reviewed-identity.h"

static int guard(int fd, const char *name) {
    struct ifreq r = {0};
    if (strlen(name) >= IFNAMSIZ) return -1;
    strcpy(r.ifr_name, name);
    return ioctl(fd, SIOCGIFFLAGS, &r);
}
static int operation(int fd, char **args) {
    if (!strcmp(args[0], "empty")) return 0;
    if (!strcmp(args[0], "addr")) {
        struct ifreq r = {0}; struct sockaddr_in *a = (void *)&r.ifr_addr;
        if (strlen(args[1]) >= IFNAMSIZ || inet_pton(AF_INET, args[2], &a->sin_addr) != 1) return 92;
        strcpy(r.ifr_name, args[1]); a->sin_family = AF_INET;
        if (ioctl(fd, SIOCSIFADDR, &r) < 0) return errno;
        if (inet_pton(AF_INET, args[3], &a->sin_addr) != 1) return 93;
        if (ioctl(fd, SIOCSIFNETMASK, &r) < 0) return errno;
        if (ioctl(fd, SIOCGIFFLAGS, &r) < 0) return errno;
        r.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &r) < 0) return errno;
    } else if (!strcmp(args[0], "route")) {
        struct rtentry r = {0}; struct sockaddr_in *a = (void *)&r.rt_gateway;
        ((struct sockaddr_in *)&r.rt_dst)->sin_family = AF_INET;
        ((struct sockaddr_in *)&r.rt_genmask)->sin_family = AF_INET;
        a->sin_family = AF_INET;
        if (inet_pton(AF_INET, args[2], &a->sin_addr) != 1) return 94;
        r.rt_flags = RTF_UP | RTF_GATEWAY;
        if (strcmp(args[1], "-")) r.rt_dev = args[1];
        if (ioctl(fd, SIOCADDRT, &r) < 0) return errno;
    } else return 95;
    return 0;
}
int main(int argc, char **argv) {
    if (bashio_network_guest_guard() < 0) return 89;
    if (argc != 7 || strcmp(argv[1], "--marked")) return 90;
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return 91;
    if (guard(fd, argv[2]) < 0 || kill(getpid(), SIGSTOP) < 0) return 96;
    int result = operation(fd, &argv[3]);
    if (kill(getpid(), SIGSTOP) < 0 || guard(fd, argv[2]) < 0) return 97;
    close(fd); return result;
}
