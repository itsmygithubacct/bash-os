/* SPDX-License-Identifier: MIT */
/* Bounded gzip streams shared by gzip and tar. No external compressor. */
#ifndef BASHOS_GZIP_STREAM_H
#define BASHOS_GZIP_STREAM_H
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static int bgz_write(int fd, const unsigned char *p, size_t len)
{
    if (fd < 0) return 0; /* gzip -t */
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; builtin_error("write: %s", strerror(errno)); return 1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* rsyncable (gzip --rsyncable): end the deflate block, byte-aligned, at
   content-defined points, as GNU gzip does, so a local change to the input
   changes only the compressed bytes up to the next point past the 32 KiB
   window. A point is where the sum of the last BGZ_RSYNC_WIN input bytes is
   a multiple of BGZ_RSYNC_WIN (GNU's rule), except where the byte entering
   the window equals the one leaving it, so long runs of one value (zeros)
   do not make a point at every byte. */
#define BGZ_RSYNC_WIN 4096
static int bgz_encode_flags(int in, int out, int level, const char *name, unsigned long mtime, int rsyncable)
{
    z_stream z = {0};
    if (deflateInit2(&z, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        builtin_error("cannot initialize gzip compressor"); return 1;
    }
    gz_header header = {0};
    header.os = 3; header.time = mtime; header.name = (Bytef *)name;
    deflateSetHeader(&z, &header);
    unsigned char src[32768], dst[32768];
    unsigned char window[BGZ_RSYNC_WIN];
    unsigned long rsum = 0, seen = 0;
    int rc = 0, done = 0;
    while (!done) {
        ssize_t n = read(in, src, sizeof src);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); rc = 1; break; }
        size_t pos = 0;
        do {
            /* With rsyncable, feed the input up to each sync point and flush there. */
            size_t take = (size_t)n - pos;
            int flush = n ? Z_NO_FLUSH : Z_FINISH, status;
            if (rsyncable && n) {
                size_t i = pos;
                for (; i < (size_t)n; i++) {
                    unsigned char c = src[i], old = window[seen % BGZ_RSYNC_WIN];
                    int full = seen >= BGZ_RSYNC_WIN;
                    if (full) rsum -= old;
                    window[seen % BGZ_RSYNC_WIN] = c; rsum += c; seen++;
                    if (seen >= BGZ_RSYNC_WIN && rsum % BGZ_RSYNC_WIN == 0 && !(full && c == old)) {
                        i++; flush = Z_SYNC_FLUSH; break;
                    }
                }
                take = i - pos;
            }
            z.next_in = src + pos; z.avail_in = (uInt)take;
            pos += take;
            do {
                z.next_out = dst; z.avail_out = sizeof dst;
                status = deflate(&z, flush);
                if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) { rc = 1; break; }
                if (bgz_write(out, dst, sizeof dst - z.avail_out)) { rc = 1; break; }
            } while (z.avail_in || !z.avail_out || (!n && status != Z_STREAM_END));
        } while (!rc && pos < (size_t)n);
        if (rc) break;
        done = !n;
    }
    deflateEnd(&z);
    return rc;
}

static inline int bgz_encode(int in, int out, int level, const char *name, unsigned long mtime)
{
    return bgz_encode_flags(in, out, level, name, mtime, 0);
}

/* bgz_decode results besides 0 and 1 (an error, already reported): every
   member decoded, then bytes that are not another member followed. GNU gzip
   ignores trailing garbage with a warning (exit status 2) and trailing zero
   bytes silently (warning only under -v). */
#define BGZ_TRAILING_GARBAGE 2
#define BGZ_TRAILING_ZEROS 3

/* At a member boundary, make at least two bytes available unless EOF comes
   first. Returns the bytes available, or -1 after a read error. */
static long bgz_fill2(int in, z_stream *z, unsigned char *src, size_t size)
{
    while (z->avail_in < 2) {
        if (z->avail_in) memmove(src, z->next_in, z->avail_in);
        z->next_in = src;
        ssize_t n = read(in, src + z->avail_in, size - z->avail_in);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); return -1; }
        if (!n) break;
        z->avail_in += (uInt)n;
    }
    return (long)z->avail_in;
}

/* NAME, when given, prefixes the diagnostics as gzip does ("NAME: ..."). */
static int bgz_decode_named(int in, int out, unsigned long *mtime, const char *name)
{
    const char *sep = name ? ": " : "";
    if (!name) name = "";
    z_stream z = {0};
    if (inflateInit2(&z, 15 + 16) != Z_OK) {
        builtin_error("cannot initialize gzip decompressor"); return 1;
    }
    unsigned char src[32768], dst[32768];
    gz_header header = {0};
    inflateGetHeader(&z, &header);
    int rc = 0, ended = 0, first = 1;
    for (;;) {
        if (ended) {
            /* After a member: EOF, the next member, zero padding or garbage. */
            long avail = bgz_fill2(in, &z, src, sizeof src);
            if (avail < 0) { rc = 1; break; }
            if (!avail) break;
            if (z.next_in[0] == 0) {
                for (;;) {
                    while (z.avail_in && !z.next_in[0]) { z.next_in++; z.avail_in--; }
                    if (z.avail_in) break;
                    ssize_t n = read(in, src, sizeof src);
                    if (n < 0 && errno == EINTR) continue;
                    if (n < 0) { builtin_error("read: %s", strerror(errno)); rc = 1; break; }
                    if (!n) break;
                    z.next_in = src; z.avail_in = (uInt)n;
                }
                if (!rc) rc = z.avail_in ? BGZ_TRAILING_GARBAGE : BGZ_TRAILING_ZEROS;
                break;
            }
            if (avail < 2) {
                if (*name) fputc('\n', stderr);   /* gzip's blank line before the error */
                builtin_error("%s%sunexpected end of file", name, sep); rc = 1; break;
            }
            if (z.next_in[0] != 0x1f || z.next_in[1] != 0x8b) { rc = BGZ_TRAILING_GARBAGE; break; }
            /* Concatenated gzip members are a single decompressed stream. */
            Bytef *next = z.next_in; uInt remaining = z.avail_in;
            inflateReset(&z);
            z.next_in = next; z.avail_in = remaining;
            ended = 0;
        }
        if (!z.avail_in) {
            ssize_t n = read(in, src, sizeof src);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { builtin_error("read: %s", strerror(errno)); rc = 1; break; }
            if (!n) {
                if (*name) fputc('\n', stderr);
                builtin_error("%s%sunexpected end of file", name, sep); rc = 1; break;
            }
            z.next_in = src; z.avail_in = (uInt)n;
        }
        z.next_out = dst; z.avail_out = sizeof dst;
        int status = inflate(&z, Z_NO_FLUSH);
        if (first && header.done) { if (mtime) *mtime = header.time; first = 0; }
        if (bgz_write(out, dst, sizeof dst - z.avail_out)) { rc = 1; break; }
        if (status == Z_STREAM_END) ended = 1;
        else if (status != Z_OK && status != Z_BUF_ERROR) {
            builtin_error("%s%sinvalid gzip data: %s", name, sep, z.msg ? z.msg : "decompression failed"); rc = 1; break;
        }
        else if (status == Z_BUF_ERROR && z.avail_in) {
            builtin_error("%s%sinvalid gzip data", name, sep); rc = 1; break;
        }
    }
    inflateEnd(&z);
    return rc;
}

static inline int bgz_decode(int in, int out, unsigned long *mtime)
{
    return bgz_decode_named(in, out, mtime, NULL);
}
#endif
