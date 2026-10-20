/* SPDX-License-Identifier: MIT
 * Compile the genuine buf source with local allocation/copy/IO interception.
 * No production hooks or process-wide allocator interposition. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "loadables.h"
static long fail_alloc, fail_read, fail_write;
static int fail_sync, force_stream, zero_write, short_write, interrupt_write;
static size_t allocs, requested, copies, writes, written;
static int reject_alloc(size_t n) {
    allocs++; requested += n;
    if (fail_alloc && --fail_alloc == 0) { errno = ENOMEM; return 1; }
    return 0;
}
static void *probe_malloc(size_t n) { return reject_alloc(n) ? NULL : malloc(n); }
static void *probe_calloc(size_t n, size_t s) { return reject_alloc(n*s) ? NULL : calloc(n,s); }
static void *probe_realloc(void *p, size_t n) { return reject_alloc(n) ? NULL : realloc(p,n); }
static void *probe_memcpy(void *d, const void *s, size_t n) { copies += n; return memcpy(d,s,n); }
static char *probe_strdup(const char *s) {
    size_t n = strlen(s)+1;
    char *p = probe_malloc(n);
    if (p) probe_memcpy(p,s,n);
    return p;
}
static ssize_t probe_read(int fd, void *p, size_t n) {
    if (fail_read && --fail_read == 0) { errno = EIO; return -1; }
    return read(fd,p,n);
}
static ssize_t probe_write(int fd, const void *p, size_t n) {
    writes++;
    if (fail_write && --fail_write == 0) { errno = EIO; return -1; }
    if (zero_write) { zero_write=0; return 0; }
    if (interrupt_write) { interrupt_write=0; errno=EINTR; return -1; }
    if (short_write && n > 7) n=7;
    ssize_t rc = write(fd,p,n);
    if (rc > 0) written += rc;
    return rc;
}
static int probe_fdatasync(int fd) {
    if (fail_sync) { fail_sync=0; errno=EIO; return -1; }
    return fdatasync(fd);
}
static void *probe_mmap(void *a,size_t n,int p,int f,int fd,off_t o) {
    if (force_stream) { errno=ENOMEM; return MAP_FAILED; }
    return mmap(a,n,p,f,fd,o);
}
#define malloc probe_malloc
#define calloc probe_calloc
#define realloc probe_realloc
#define strdup probe_strdup
#define memcpy probe_memcpy
#define read probe_read
#define write probe_write
#define fdatasync probe_fdatasync
#define mmap probe_mmap
#ifndef BUF_SOURCE
#define BUF_SOURCE "../loadables/buf.c"
#endif
#include BUF_SOURCE
#undef malloc
#undef calloc
#undef realloc
#undef strdup
#undef memcpy
#undef read
#undef write
#undef fdatasync
#undef mmap
int bufprobe_builtin(WORD_LIST *a) {
    if (!a) return 2;
    const char *cmd=a->word->word;
    long n=a->next ? strtol(a->next->word->word,NULL,10) : 1;
    if (!strcmp(cmd,"reset")) {
        allocs=requested=copies=writes=written=0;
        fail_alloc=fail_read=fail_write=0;
        fail_sync=force_stream=zero_write=short_write=interrupt_write=0;
    } else if (!strcmp(cmd,"alloc")) fail_alloc=n;
    else if (!strcmp(cmd,"read")) { fail_read=n; force_stream=1; }
    else if (!strcmp(cmd,"stream")) force_stream=1;
    else if (!strcmp(cmd,"write")) fail_write=n;
    else if (!strcmp(cmd,"sync")) fail_sync=1;
    else if (!strcmp(cmd,"zero")) zero_write=1;
    else if (!strcmp(cmd,"short")) short_write=1;
    else if (!strcmp(cmd,"eintr")) interrupt_write=1;
    else if (!strcmp(cmd,"stats")) printf("{\"allocations\":%zu,\"requested_bytes\":%zu,\"copied_bytes\":%zu,\"write_calls\":%zu,\"written_bytes\":%zu}\n",allocs,requested,copies,writes,written);
    else return 2;
    return 0;
}
char *bufprobe_doc[]={"Task-owned buffer fault injection and cost counters.",NULL};
struct builtin bufprobe_struct={"bufprobe",bufprobe_builtin,BUILTIN_ENABLED,bufprobe_doc,"bufprobe COMMAND [N]",0};
