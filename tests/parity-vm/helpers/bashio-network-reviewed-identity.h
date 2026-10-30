/* SPDX-License-Identifier: MIT
 * Verify the protected controller identity in the mapped guest namespace. */
#ifndef BASHIO_NETWORK_REVIEWED_IDENTITY_H
#define BASHIO_NETWORK_REVIEWED_IDENTITY_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int bio_read(int fd, char *buf, size_t capacity, size_t *length) {
    size_t n = 0;
    while (n < capacity) {
        ssize_t got = read(fd, buf + n, capacity - n);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -1;
        if (!got) { *length = n; return 0; }
        n += (size_t)got;
    }
    return -1;
}
static int bio_small(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    size_t n = 0;
    if (fd < 0) return -1;
    int ok = bio_read(fd, buf, cap - 1, &n);
    close(fd);
    if (ok < 0) return -1;
    buf[n] = 0;
    return 0;
}
static int bio_map(const char *path) {
    char text[128], extra;
    unsigned long inside, outside, count;
    if (bio_small(path, text, sizeof text) < 0) return -1;
    if (sscanf(text, " %lu %lu %lu %c", &inside, &outside, &count, &extra) != 3 ||
        inside != 0 || outside != 2000 || count != 1) return -1;
    return 0;
}
static int bio_overflow(const char *path, unsigned long *value) {
    char text[64], extra;
    if (bio_small(path, text, sizeof text) < 0 || sscanf(text, " %lu %c", value, &extra) != 1) return -1;
    return 0;
}
static int bio_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_mode == b->st_mode &&
           a->st_nlink == b->st_nlink && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
static int bio_identity(const char *directory, const char *name, uid_t uid, gid_t gid, char out[38]) {
    int d = -1, fd = -1, ok = -1;
    struct stat parent, before, after, entry;
    size_t n = 0;
    d = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (d < 0 || fstat(d, &parent) < 0 || !S_ISDIR(parent.st_mode) ||
        parent.st_uid != uid || parent.st_gid != gid || (parent.st_mode & 0022)) goto done;
    fd = openat(d, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != uid || before.st_gid != gid || (before.st_mode & 07777) != 0444 ||
        before.st_nlink != 1 || before.st_size != 37) goto done;
    if (bio_read(fd, out, 38, &n) < 0 || n != 37 || fstat(fd, &after) < 0 ||
        fstatat(d, name, &entry, AT_SYMLINK_NOFOLLOW) < 0 ||
        !bio_same(&before, &after) || !bio_same(&after, &entry) || out[36] != '\n') goto done;
    out[37] = 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (out[i] != '-') goto done; }
        else if (!((out[i] >= '0' && out[i] <= '9') || (out[i] >= 'a' && out[i] <= 'f'))) goto done;
    }
    ok = 0;
done:
    if (fd >= 0) close(fd);
    if (d >= 0) close(d);
    return ok;
}
static int bio_ns_name(const char *name, const char *kind) {
    size_t prefix = strlen(kind), len;
    if (!name || strncmp(name, kind, prefix) != 0) return -1;
    len = strlen(name);
    if (len <= prefix + 1 || name[len - 1] != ']') return -1;
    for (size_t i = prefix; i < len - 1; i++) if (name[i] < '0' || name[i] > '9') return -1;
    return 0;
}
static int bio_ns(const char *path, const char *outer, const char *kind) {
    char current[128];
    if (bio_ns_name(outer, kind) < 0) return -1;
    ssize_t n = readlink(path, current, sizeof current - 1);
    if (n <= 0 || (size_t)n >= sizeof current - 1) return -1;
    current[n] = 0;
    return bio_ns_name(current, kind) == 0 && strcmp(current, outer) != 0 ? 0 : -1;
}
static int bashio_network_guest_guard(void) {
    char cwd[PATH_MAX], vendor[32], marker[38], attest[38];
    unsigned long uid, gid;
    const char *token = getenv("BASHIO_VM_UUID");
    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0 ||
        !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/tmp/parity-case") ||
        !getenv("HOME") || strcmp(getenv("HOME"), "/tmp/parity-home") ||
        bio_map("/proc/self/uid_map") < 0 || bio_map("/proc/self/gid_map") < 0 ||
        bio_overflow("/proc/sys/kernel/overflowuid", &uid) < 0 ||
        bio_overflow("/proc/sys/kernel/overflowgid", &gid) < 0 ||
        uid > (unsigned long)(uid_t)-1 || gid > (unsigned long)(gid_t)-1 ||
        bio_identity("/etc", "bashos-parity-vm", (uid_t)uid, (gid_t)gid, marker) < 0 ||
        bio_identity("/run", "bashos-parity-vm-identity", (uid_t)uid, (gid_t)gid, attest) < 0 ||
        memcmp(marker, attest, 37) != 0 || !token || strlen(token) != 36 || strncmp(marker, token, 36) != 0 ||
        bio_small("/sys/class/dmi/id/sys_vendor", vendor, sizeof vendor) < 0 || strcmp(vendor, "QEMU\n") ||
        bio_ns("/proc/self/ns/user", getenv("BASHIO_OUTER_USER_NS"), "user:[") < 0 ||
        bio_ns("/proc/self/ns/net", getenv("BASHIO_OUTER_NET_NS"), "net:[") < 0) return -1;
    return 0;
}
#endif
