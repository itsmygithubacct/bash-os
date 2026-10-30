/* SPDX-License-Identifier: MIT */
/* Independent guest-only ioctl control, used solely in a private network namespace. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 5) return 90;
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return 91;
    if (!strcmp(argv[1], "addr")) {
        struct ifreq r = {0}; struct sockaddr_in *a = (void *)&r.ifr_addr;
        if (strlen(argv[2]) >= IFNAMSIZ || inet_pton(AF_INET, argv[3], &a->sin_addr) != 1) return 92;
        strcpy(r.ifr_name, argv[2]); a->sin_family = AF_INET;
        if (ioctl(fd, SIOCSIFADDR, &r) < 0) return errno;
        if (inet_pton(AF_INET, argv[4], &a->sin_addr) != 1) return 93;
        if (ioctl(fd, SIOCSIFNETMASK, &r) < 0) return errno;
        if (ioctl(fd, SIOCGIFFLAGS, &r) < 0) return errno;
        r.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &r) < 0) return errno;
    } else if (!strcmp(argv[1], "route")) {
        struct rtentry r = {0}; struct sockaddr_in *a = (void *)&r.rt_gateway;
        ((struct sockaddr_in *)&r.rt_dst)->sin_family = AF_INET;
        ((struct sockaddr_in *)&r.rt_genmask)->sin_family = AF_INET;
        a->sin_family = AF_INET;
        if (inet_pton(AF_INET, argv[3], &a->sin_addr) != 1) return 94;
        r.rt_flags = RTF_UP | RTF_GATEWAY;
        if (strcmp(argv[2], "-")) r.rt_dev = argv[2];
        if (ioctl(fd, SIOCADDRT, &r) < 0) return errno;
    } else return 95;
    close(fd); return 0;
}
