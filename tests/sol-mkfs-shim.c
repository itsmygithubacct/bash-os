/* SPDX-License-Identifier: MIT
 * Compile the production source behind a closed boundary. Images must be
 * direct children of a private fixture directory, regular, owned, unlinked
 * elsewhere, and never symlinks. The block-size ioctl is simulated, never sent
 * to a kernel device. No source path is replaced by a separate formatter.
 */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include "loadables.h"

static const char *mode;
static int nth, ac, wc, rcalls, opens, live, blocks, ioctls, active;
static uint64_t bytes;
static int imagefd = -1, randomfd = -1;
static int fail_at(const char *s, int count) { return mode && !strcmp(mode, s) && count == nth; }
static int fixture_open(const char *p, int flags) {
    if (!strcmp(p, "/dev/urandom")) {
        if (fail_at("random-open", 1)) { errno = EACCES; return -1; }
        randomfd = open(p, flags); if (randomfd >= 0) opens++;
        return randomfd;
    }
    const char *root = getenv("MKFS_FIXTURE_ROOT");
    struct stat st;
    char cwd[4096];
    int child = root && !strncmp(p, root, strlen(root)) && p[strlen(root)] == '/' &&
                !strchr(p + strlen(root) + 1, '/');
    if (!child && root && !strchr(p, '/') && getcwd(cwd, sizeof cwd) && !strcmp(cwd, root)) child = 1;
    if (!child || lstat(p, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != getuid() || st.st_nlink != 1) { errno = EPERM; return -1; }
    if (fail_at("open", 1)) { errno = EACCES; return -1; }
    imagefd = open(p, flags); if (imagefd >= 0) opens++;
    return imagefd;
}
static int fixture_close(int fd) {
    int isimage = fd == imagefd;
    int ret = close(fd);
    if (fd == imagefd) imagefd = -1;
    if (fd == randomfd) randomfd = -1;
    if (ret == 0) opens--;
    if (isimage && fail_at("close", 1)) { errno = EIO; return -1; }
    return ret;
}
static int fixture_fstat(int fd, struct stat *st) {
    if (fail_at("fstat", 1)) { errno = EIO; return -1; }
    int ret = fstat(fd, st);
    if (!ret && blocks) st->st_mode = (st->st_mode & ~S_IFMT) | S_IFBLK;
    return ret;
}
static int fixture_ioctl(int fd, unsigned long request, void *arg) {
    ioctls++;
    if (fd != imagefd || !blocks || request != BLKGETSIZE64) abort();
    if (fail_at("ioctl", 1)) { errno = EIO; return -1; }
    struct stat st;
    if (fstat(fd, &st)) abort();
    *(uint64_t *)arg = st.st_size;
    return 0;
}
static ssize_t fixture_read(int fd, void *buf, size_t n) {
    if (fd != randomfd) abort();
    rcalls++;
    if (fail_at("read", rcalls)) { errno = EIO; return -1; }
    if (fail_at("read-zero", rcalls)) return 0;
    if (fail_at("read-eintr", rcalls)) { errno = EINTR; return -1; }
    if (fail_at("read-short", rcalls) && n > 1) n /= 2;
    return read(fd, buf, n);
}
static void *fixture_malloc(size_t n) {
    ac++;
    if (fail_at("alloc", ac)) { errno = ENOMEM; return NULL; }
    void *p = malloc(n); if (p) live++; return p;
}
static void *fixture_calloc(size_t n, size_t s) {
    ac++;
    if (fail_at("alloc", ac)) { errno = ENOMEM; return NULL; }
    void *p = calloc(n, s); if (p) live++; return p;
}
static void fixture_free(void *p) { if (p) live--; free(p); }
static ssize_t fixture_pwrite(int fd, const void *buf, size_t n, off_t off) {
    if (fd != imagefd || !active) abort();
    wc++;
    if (fail_at("write", wc)) { errno = ENOSPC; return -1; }
    if (fail_at("write-zero", wc)) return 0;
    if (fail_at("write-eintr", wc)) { errno = EINTR; return -1; }
    if (fail_at("write-short", wc) && n > 1) n /= 2;
    ssize_t ret = pwrite(fd, buf, n, off);
    if (ret > 0) bytes += ret;
    return ret;
}
static int fixture_fsync(int fd) {
    if (fd != imagefd) abort();
    if (fail_at("fsync", 1)) { errno = EIO; return -1; }
    if (fail_at("fsync-einval", 1)) { errno = EINVAL; return -1; }
    return fsync(fd);
}
#define open fixture_open
#define close fixture_close
#define fstat fixture_fstat
#define ioctl fixture_ioctl
#define read fixture_read
#define malloc fixture_malloc
#define calloc fixture_calloc
#define free fixture_free
#define pwrite fixture_pwrite
#define fsync fixture_fsync
#ifndef MKFS_SOURCE
#define MKFS_SOURCE "../loadables/mkfs.c"
#endif
#define mkfs_builtin production_mkfs_builtin
#define mkfs_struct production_mkfs_struct
#include MKFS_SOURCE
#undef mkfs_builtin
#undef mkfs_struct
#undef open
#undef close
#undef fstat
#undef ioctl
#undef read
#undef malloc
#undef calloc
#undef free
#undef pwrite
#undef fsync

int mkfs_probe_builtin(WORD_LIST *list) {
    if (!list || !list->next || !list->next->next) return EX_USAGE;
    mode = list->word->word;
    nth = atoi(list->next->word->word);
    ac = wc = rcalls = opens = live = ioctls = 0; bytes = 0;
    blocks = !strcmp(mode, "block") || !strcmp(mode, "ioctl");
    imagefd = randomfd = -1;
    if (!strcmp(mode, "helpers")) {
        /* Exercise sparse-super powers beyond ordinary fixture sizes. */
        for (uint32_t base = 3; base <= 7; base += 2) {
            for (uint64_t power = base; power <= UINT32_MAX; power *= base)
                if (!has_super((uint32_t) power)) abort();
        }
        const uint32_t ordinary[] = {2, 4, 6, 10, 15, 21, 32, 100, UINT32_MAX};
        for (size_t i = 0; i < sizeof ordinary / sizeof *ordinary; i++)
            if (has_super(ordinary[i])) abort();
        for (uint32_t bs = 1024; bs <= 4096; bs *= 2) {
            uint32_t pairs[][2] = {{0,0}, {bs*8,0}, {0,bs*8}, {1,bs*8-1}, {bs*8-1,1}, {8,16}, {13,17}};
            unsigned char bitmap[4098];
            for (size_t i = 0; i < sizeof pairs / sizeof *pairs; i++) {
                memset(bitmap, 0x5a, sizeof bitmap);
                mkfs_bitmap(bitmap+1, bs, pairs[i][0], pairs[i][1]);
                if (bitmap[0] != 0x5a || bitmap[bs+1] != 0x5a) abort();
                for (uint32_t bit = 0; bit < bs*8; bit++)
                    if (((bitmap[1+bit/8] >> (bit%8)) & 1) !=
                        (bit < pairs[i][0] || bit >= bs*8-pairs[i][1])) abort();
            }
        }
        puts("helpers passed");
        return 0;
    }
    active = 1;
    int ret = production_mkfs_builtin(list->next->next);
    active = 0;
    printf("{\"status\":%d,\"allocations\":%d,\"write_calls\":%d,\"written_bytes\":%" PRIu64
           ",\"live_fds\":%d,\"live_allocations\":%d,\"ioctls\":%d}\n",
           ret, ac, wc, bytes, opens, live, ioctls);
    if (opens || live || imagefd != -1 || randomfd != -1) return 99;
    return ret;
}
static char *probe_doc[] = { "Private fixture/failure wrapper around production mkfs.", NULL };
struct builtin mkfs_probe_struct = {"mkfs_probe", mkfs_probe_builtin, BUILTIN_ENABLED,
                                    probe_doc, "mkfs_probe MODE N IMAGE [OPTIONS]", 0};

static int checked_mkfs_builtin(WORD_LIST *list) {
    mode = "none"; nth = 0;
    ac = wc = rcalls = opens = live = ioctls = blocks = 0;
    imagefd = randomfd = -1;
    active = 1;
    int ret = production_mkfs_builtin(list);
    active = 0;
    if (opens || live || imagefd != -1 || randomfd != -1) return 99;
    return ret;
}
struct builtin mkfs_struct = {"mkfs", checked_mkfs_builtin, BUILTIN_ENABLED,
                              mkfs_doc, "mkfs IMAGE [OPTIONS]", 0};
