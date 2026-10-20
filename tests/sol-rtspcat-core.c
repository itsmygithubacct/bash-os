/* SPDX-License-Identifier: MIT */
/* Include the genuine implementation, instrument its allocation boundary, and
 * exercise adversarial assembly under ASan/UBSan. No copied depacketizer. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
struct allocation { void *p; size_t n; };
static struct allocation allocations[64];
static size_t live, peak, largest, calls, fail_at;
static int slot(void *p) {
    for (int i = 0; i < 64; i++) if (allocations[i].p == p) return i;
    abort();
}
static void *tracked_malloc(size_t n) {
    if (++calls == fail_at) return NULL;
    void *p = malloc(n); if (!p) return p;
    int i = slot(NULL); allocations[i] = (struct allocation){p, n};
    live += n; if (live > peak) peak = live; if (n > largest) largest = n;
    return p;
}
static void tracked_free(void *p) {
    if (!p) return;
    int i = slot(p); live -= allocations[i].n; allocations[i] = (struct allocation){0}; free(p);
}
static void *tracked_realloc(void *p, size_t n) {
    if (!p) return tracked_malloc(n);
    if (++calls == fail_at) return NULL;
    int i = slot(p); void *q = realloc(p, n); if (!q) return NULL;
    live -= allocations[i].n; allocations[i] = (struct allocation){q, n}; live += n;
    if (live > peak) peak = live; if (n > largest) largest = n;
    return q;
}
#define malloc tracked_malloc
#define realloc tracked_realloc
#define free tracked_free
#define RTSPCAT_STANDALONE
#define main standalone_main
#include "../loadables/rtspcat.c"
#undef main
#undef malloc
#undef realloc
#undef free
static struct rc context(void) {
    struct rc c = {0}; c.fd = -1; c.out = open("/dev/null", O_WRONLY); c.pt = 96; c.timeout_ms = 1000; assert(c.out >= 0); return c;
}
static void cleanup(struct rc *c) { close(c->out); rc_free(c); assert(live == 0); }
static const char sdp[] = "v=0\nm=video 0 RTP/AVP 96\na=control:track\na=rtpmap:96 H264/90000\na=fmtp:96 sprop-parameter-sets=Z0IAHqs=,aM4G4g==\na=fmtp:96 sprop-parameter-sets=Z0IAHqs=,aM4G4g==\n";
int main(void) {
    char hash[33]; md5_str("", hash); assert(!strcmp(hash, "d41d8cd98f00b204e9800998ecf8427e"));
    md5_str("abc", hash); assert(!strcmp(hash, "900150983cd24fb0d6963f7d28e17f72"));
    for (int f = 1; f <= 8; f++) {
        struct rc c = context(); strcpy(c.base, "rtsp://127.0.0.1/");
        calls = 0; fail_at = f;
        int result = parse_sdp(&c, sdp);
        if (f <= 5) assert(result == -1); else assert(result == 0);
        cleanup(&c); fail_at = 0;
    }
    for (int fu = 0; fu < 2; fu++) {
        struct rc c = context(); unsigned char p[60015] = {0x80,96};
        memset(p+12, 'x', sizeof p-12); p[12] = fu ? 0x7c : 0x61;
        size_t before = calls; int result = 0;
        for (unsigned i = 0; i < 200 && !result; i++) {
            p[2] = i >> 8; p[3] = i; if (fu) p[13] = i ? 0x05 : 0x85;
            result = rtp_packet(&c, p, sizeof p);
        }
        assert(result == -1); assert(strstr(c.err, "8 MiB"));
        assert(c.au_cap <= RC_MAX_UNIT && c.fu_cap <= RC_MAX_UNIT);
        assert(calls - before <= 8); cleanup(&c);
    }
    /* OOM on the first AU/FU allocation must propagate without leaking. */
    for (int fu = 0; fu < 2; fu++) {
        struct rc c = context(); unsigned char p[] = {0x80,96,0,1,0,0,0,1,0,0,0,1,0x7c,0x85,'a'};
        if (!fu) p[12] = 0x61;
        calls = 0; fail_at = 1; assert(rtp_packet(&c, p, sizeof p) == -1);
        cleanup(&c); fail_at = 0;
    }
    struct rc c = context(); unsigned char p[2048]; unsigned state = 0x617ac;
    for (unsigned i = 0; i < 100000; i++) {
        for (size_t j = 0; j < sizeof p; j++) { state = state * 1664525 + 1013904223; p[j] = state >> 24; }
        size_t n = (state >> 8) % sizeof p;
        if (i % 2 == 0) { p[0] = 0x80 | (p[0] & 0x3f); p[1] = 96 | (p[1] & 0x80); p[2] = i >> 8; p[3] = i; }
        assert(rtp_packet(&c, p, n) == 0);
    }
    cleanup(&c);
    assert(largest <= RC_MAX_UNIT); assert(peak <= 2 * RC_MAX_UNIT + 200000);
    printf("PASS production RTP/SDP allocation faults, 100000 adversarial packets; largest=%zu peak=%zu live=%zu\n", largest, peak, live);
}
