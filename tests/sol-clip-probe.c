/* SPDX-License-Identifier: MIT
 * Compile the genuine buf and clip sources into one module with local
 * allocation/copy/write counters and allocation-failure injection. No
 * production hooks and no process-wide allocator interposition: only calls
 * made by these two translation units are counted or failed. */
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
static long fail_alloc;
static int fired;
static size_t allocs, requested, copies, moves, writes, written;
static int reject_alloc(size_t n) {
    allocs++; requested += n;
    if (fail_alloc && --fail_alloc == 0) { fired = 1; errno = ENOMEM; return 1; }
    return 0;
}
static void *probe_malloc(size_t n) { return reject_alloc(n) ? NULL : malloc(n); }
static void *probe_calloc(size_t n, size_t s) { return reject_alloc(n*s) ? NULL : calloc(n,s); }
static void *probe_realloc(void *p, size_t n) { return reject_alloc(n) ? NULL : realloc(p,n); }
static void *probe_memcpy(void *d, const void *s, size_t n) { copies += n; return memcpy(d,s,n); }
static void *probe_memmove(void *d, const void *s, size_t n) { moves += n; return memmove(d,s,n); }
static char *probe_strdup(const char *s) {
    size_t n = strlen(s)+1;
    char *p = probe_malloc(n);
    if (p) probe_memcpy(p,s,n);
    return p;
}
static ssize_t probe_write(int fd, const void *p, size_t n) {
    writes++;
    ssize_t rc = write(fd,p,n);
    if (rc > 0) written += rc;
    return rc;
}
#define malloc probe_malloc
#define calloc probe_calloc
#define realloc probe_realloc
#define strdup probe_strdup
#define memcpy probe_memcpy
#define memmove probe_memmove
#define write probe_write
#ifndef BUF_SOURCE
#define BUF_SOURCE "../loadables/buf.c"
#endif
#ifndef CLIP_SOURCE
#define CLIP_SOURCE "../loadables/clip.c"
#endif
#include BUF_SOURCE
#include CLIP_SOURCE
#undef malloc
#undef calloc
#undef realloc
#undef strdup
#undef memcpy
#undef memmove
#undef write
int clipprobe_builtin(WORD_LIST *a) {
    if (!a) return 2;
    const char *cmd=a->word->word;
    long n=a->next ? strtol(a->next->word->word,NULL,10) : 1;
    if (!strcmp(cmd,"reset")) {
        allocs=requested=copies=moves=writes=written=0;
        fail_alloc=0; fired=0;
    } else if (!strcmp(cmd,"alloc")) { fail_alloc=n; fired=0; }
    else if (!strcmp(cmd,"fired")) return fired ? 0 : 1;
    else if (!strcmp(cmd,"stats")) printf("{\"allocations\":%zu,\"requested_bytes\":%zu,\"copied_bytes\":%zu,\"moved_bytes\":%zu,\"write_calls\":%zu,\"written_bytes\":%zu}\n",allocs,requested,copies,moves,writes,written);
    else return 2;
    return 0;
}
char *clipprobe_doc[]={"Task-owned buf/clip fault injection and cost counters.",NULL};
struct builtin clipprobe_struct={"clipprobe",clipprobe_builtin,BUILTIN_ENABLED,clipprobe_doc,"clipprobe COMMAND [N]",0};
