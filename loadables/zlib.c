/* SPDX-License-Identifier: MIT */
/* zlib.c — multi-format compression/decompression loadable for bash.
 *
 * Wraps libz / liblzma / libzstd as a single bash builtin. Operates on
 * file descriptors (read(2)/write(2)) for NUL safety — same model as
 * binhex. Supports gzip (RFC 1952), zlib (RFC 1950), raw deflate
 * (RFC 1951), xz/lzma, and zstd in both directions.
 *
 * Why this exists:
 *   /docs/bash/COMPRESSION-LIMIT.txt explains why pure bash can't do
 *   gzip/xz/zstd at usable speed. This loadable is the bash-os answer:
 *   a static C wrapper around mature audited libraries (libz, liblzma,
 *   libzstd), exposed as a bash builtin so callers don't fork.
 *
 * Usage:
 *     zlib < foo.gz > foo                 # decode (default)
 *     zlib -e < foo > foo.gz              # encode (gzip default)
 *     zlib -e -1 < foo > foo.gz           # fastest level
 *     zlib -e -9 < foo > foo.gz           # max level
 *     zlib -f xz < foo.xz > foo
 *     zlib -f zstd < foo.zst > foo
 *     zlib -e -f zstd -3 < foo > foo.zst  # zstd level 3
 *     zlib -z < foo.zlib > foo            # raw RFC 1950 zlib
 *     zlib -R < foo.deflate > foo         # raw RFC 1951 deflate
 *
 * NUL safety: input/output flow through file descriptors (no bash
 * variable in the byte path). Output is binary; pipe to `binhex` if
 * you need to round-trip through a bash variable.
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED. See the full MIT text for the standard disclaimer.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible, so
 * the binary's GPL-3+ status is unchanged. The MIT grant lets anyone
 * lift this file into a non-GPL project independently of our build.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <zlib.h>
#include <lzma.h>
#include <zstd.h>
#include <bzlib.h>

#include "loadables.h"

#define BZ_BUFSZ 65536

enum bz_format { BZ_GZIP = 0, BZ_XZ, BZ_LZMA, BZ_ZSTD, BZ_ZLIB, BZ_DEFLATE, BZ_BZIP2 };

/* A codec's result when trailing garbage followed a complete gzip member
   or bzip2 stream (decoding itself succeeded). */
#define BZ_GARBAGE 2

/* ---- gzip / zlib / deflate (libz) ----------------------------------- */
static int
bz_codec_zlib (int in_fd, int out_fd, int encode, int level, enum bz_format fmt)
{
  z_stream s;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  int ret, wbits;
  ssize_t n = 0;

  memset (&s, 0, sizeof s);

  /* wbits convention (zlib.h):
   *    8..15      → zlib wrap
   *    -8..-15    → raw deflate (no header/trailer)
   *    16+(8..15) → gzip wrap (encode side)
   *    32+(8..15) → autodetect (inflate side; gzip OR zlib)
   */
  switch (fmt)
    {
    case BZ_GZIP:    wbits = encode ? (15 + 16) : (15 + 32); break;
    case BZ_ZLIB:    wbits = 15;                              break;
    case BZ_DEFLATE: wbits = -15;                             break;
    default:         builtin_error ("bz_codec_zlib: bad format");  return 1;
    }

  if (encode)
    {
      if (level < 0) level = Z_DEFAULT_COMPRESSION;
      ret = deflateInit2 (&s, level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY);
    }
  else
    {
      ret = inflateInit2 (&s, wbits);
    }
  if (ret != Z_OK)
    {
      /* On init failure, s.msg may be NULL (stream wasn't fully set up).
         zError(ret) is a static lookup that always returns a string. */
      builtin_error ("zlib init: %s", zError (ret));
      return 1;
    }

  for (;;)
    {
      /* Read input unless leftover data from a concatenated gzip member
       * boundary is already buffered (inflateReset preserves avail_in). */
      if (s.avail_in == 0)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              (encode ? deflateEnd : inflateEnd) (&s);
              return 1;
            }
          s.next_in = inbuf;
          s.avail_in = (uInt) n;
        }
      int flush = (n == 0) ? Z_FINISH : Z_NO_FLUSH;

      do
        {
          s.next_out = outbuf;
          s.avail_out = sizeof outbuf;
          ret = encode ? deflate (&s, flush) : inflate (&s, flush);
          /* Inflate may produce valid prefix bytes in the same call that
             detects a CRC or length error. Keep streaming output visible
             before reporting the failure, as gzip does. */
          size_t produced = sizeof outbuf - s.avail_out;
          if (produced > 0)
            {
              unsigned char *p = outbuf;
              size_t left = produced;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w <= 0)
                    {
                      if (w < 0 && errno == EINTR) continue;
                      if (w == 0) errno = EIO;
                      builtin_error ("write: %s", strerror (errno));
                      (encode ? deflateEnd : inflateEnd) (&s);
                      return 1;
                    }
                  p += w;
                  left -= (size_t) w;
                }
            }
          if (ret == Z_STREAM_ERROR ||
              ret == Z_NEED_DICT    ||
              ret == Z_DATA_ERROR   ||
              ret == Z_MEM_ERROR    ||
              ret == Z_BUF_ERROR)
            {
              builtin_error ("zlib: %s",
                             s.msg ? s.msg : zError (ret));
              (encode ? deflateEnd : inflateEnd) (&s);
              return 1;
            }
        }
      while (s.avail_out == 0 && ret != Z_STREAM_END);

      if (ret == Z_STREAM_END)
        {
          /* Concatenated gzip: inflate does not auto-skip to the next
           * member, so we inflateReset and continue when more input is
           * available (buffered or from the fd).  For encode or non-gzip
           * formats a single Z_STREAM_END is terminal. */
          if (!encode && fmt == BZ_GZIP)
            {
              inflateReset (&s);
              /* What follows a member, by gzip's rules: EOF, another
                 member (magic 1f 8b), zero padding (ignored silently),
                 or trailing garbage (ignored with a warning). One stray
                 byte before EOF is an unexpected end of file. */
              while (s.avail_in < 2)
                {
                  if (s.avail_in)
                    memmove (inbuf, s.next_in, s.avail_in);
                  s.next_in = inbuf;
                  do
                    n = read (in_fd, inbuf + s.avail_in, sizeof inbuf - s.avail_in);
                  while (n < 0 && errno == EINTR);
                  if (n < 0)
                    {
                      builtin_error ("read: %s", strerror (errno));
                      inflateEnd (&s);
                      return 1;
                    }
                  if (n == 0)
                    break;
                  s.avail_in += (uInt) n;
                }
              if (s.avail_in == 0)
                break;                /* EOF — all members processed */
              if (s.next_in[0] == 0)
                {
                  /* Zero padding (tape blocks) is ignored when nothing
                     else follows it. */
                  for (;;)
                    {
                      while (s.avail_in && s.next_in[0] == 0)
                        { s.next_in++; s.avail_in--; }
                      if (s.avail_in)
                        break;
                      do
                        n = read (in_fd, inbuf, sizeof inbuf);
                      while (n < 0 && errno == EINTR);
                      if (n <= 0)
                        break;
                      s.next_in = inbuf;
                      s.avail_in = (uInt) n;
                    }
                  inflateEnd (&s);
                  if (n < 0)
                    {
                      builtin_error ("read: %s", strerror (errno));
                      return 1;
                    }
                  return s.avail_in ? BZ_GARBAGE : 0;
                }
              if (s.avail_in < 2)
                {
                  builtin_error ("unexpected end of file");
                  inflateEnd (&s);
                  return 1;
                }
              if (s.next_in[0] != 0x1f || s.next_in[1] != 0x8b)
                {
                  inflateEnd (&s);
                  return BZ_GARBAGE;
                }
              n = 1;                  /* more input may follow */
              continue;
            }
          /* Non-gzip or encode: single member is terminal. */
          break;
        }
      if (n == 0)
        break;
    }

  (encode ? deflateEnd : inflateEnd) (&s);
  return 0;
}

/* ---- xz / lzma (liblzma) -------------------------------------------- */
static int
bz_codec_xz (int in_fd, int out_fd, int encode, int level, enum bz_format fmt)
{
  lzma_stream s = LZMA_STREAM_INIT;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  lzma_ret ret;
  ssize_t n = 0;

  if (level < 0) level = LZMA_PRESET_DEFAULT;
  if (level > 9) level = 9;

  if (fmt == BZ_LZMA)
    {
      if (encode)
        {
          lzma_options_lzma opt_lzma;
          if (lzma_lzma_preset (&opt_lzma, (uint32_t) level))
            {
              builtin_error ("lzma preset: %d", level);
              return 1;
            }
          ret = lzma_alone_encoder (&s, &opt_lzma);
        }
      else
        ret = lzma_alone_decoder (&s, UINT64_MAX);
    }
  else
    ret = encode
          ? lzma_easy_encoder (&s, (uint32_t) level, LZMA_CHECK_CRC64)
          : lzma_auto_decoder (&s, UINT64_MAX, LZMA_CONCATENATED);
  if (ret != LZMA_OK)
    {
      builtin_error ("lzma init: code=%d", (int) ret);
      return 1;
    }

  lzma_action action = LZMA_RUN;
  s.next_in = NULL; s.avail_in = 0;
  s.next_out = outbuf; s.avail_out = sizeof outbuf;

  for (;;)
    {
      if (s.avail_in == 0 && action != LZMA_FINISH)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              lzma_end (&s);
              return 1;
            }
          s.next_in = inbuf;
          s.avail_in = (size_t) n;
          if (n == 0) action = LZMA_FINISH;
        }

      ret = lzma_code (&s, action);

      if (s.avail_out == 0 || ret == LZMA_STREAM_END)
        {
          size_t produced = sizeof outbuf - s.avail_out;
          unsigned char *p = outbuf;
          size_t left = produced;
          while (left > 0)
            {
              ssize_t w = write (out_fd, p, left);
              if (w <= 0)
                {
                  if (w < 0 && errno == EINTR) continue;
                  if (w == 0) errno = EIO;
                  builtin_error ("write: %s", strerror (errno));
                  lzma_end (&s);
                  return 1;
                }
              p += w;
              left -= (size_t) w;
            }
          s.next_out = outbuf;
          s.avail_out = sizeof outbuf;
        }

      if (ret == LZMA_STREAM_END) break;
      if (ret != LZMA_OK)
        {
          builtin_error ("lzma: code=%d", (int) ret);
          lzma_end (&s);
          return 1;
        }
    }

  lzma_end (&s);
  return 0;
}

/* ---- zstd (libzstd) ------------------------------------------------- */
static int
bz_codec_zstd (int in_fd, int out_fd, int encode, int level)
{
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  ssize_t n = 0;

  if (encode)
    {
      ZSTD_CStream *cctx = ZSTD_createCStream ();
      if (!cctx) { builtin_error ("zstd: createCStream"); return 1; }
      if (level < 0) level = ZSTD_CLEVEL_DEFAULT;
      ZSTD_CCtx_setParameter (cctx, ZSTD_c_compressionLevel, level);

      for (;;)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              ZSTD_freeCStream (cctx); return 1;
            }
          ZSTD_inBuffer in = { inbuf, (size_t) n, 0 };
          ZSTD_EndDirective mode = (n == 0) ? ZSTD_e_end : ZSTD_e_continue;

          int finished;
          do
            {
              ZSTD_outBuffer out = { outbuf, sizeof outbuf, 0 };
              size_t rem = ZSTD_compressStream2 (cctx, &out, &in, mode);
              if (ZSTD_isError (rem))
                {
                  builtin_error ("zstd compress: %s", ZSTD_getErrorName (rem));
                  ZSTD_freeCStream (cctx); return 1;
                }
              unsigned char *p = outbuf;
              size_t left = out.pos;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w <= 0)
                    {
                      if (w < 0 && errno == EINTR) continue;
                      if (w == 0) errno = EIO;
                      builtin_error ("write: %s", strerror (errno));
                      ZSTD_freeCStream (cctx); return 1;
                    }
                  p += w; left -= (size_t) w;
                }
              finished = (mode == ZSTD_e_end) ? (rem == 0) : (in.pos == in.size);
            }
          while (!finished);

          if (n == 0) break;
        }
      ZSTD_freeCStream (cctx);
      return 0;
    }
  else
    {
      ZSTD_DStream *dctx = ZSTD_createDStream ();
      if (!dctx) { builtin_error ("zstd: createDStream"); return 1; }
      size_t remaining = 1;

      for (;;)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              ZSTD_freeDStream (dctx); return 1;
            }
          if (n == 0) break;
          ZSTD_inBuffer in = { inbuf, (size_t) n, 0 };
          ZSTD_outBuffer out;
          do
            {
              out = (ZSTD_outBuffer) { outbuf, sizeof outbuf, 0 };
              size_t rc = ZSTD_decompressStream (dctx, &out, &in);
              remaining = rc;
              if (ZSTD_isError (rc))
                {
                  builtin_error ("zstd decompress: %s", ZSTD_getErrorName (rc));
                  ZSTD_freeDStream (dctx); return 1;
                }
              unsigned char *p = outbuf;
              size_t left = out.pos;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w <= 0)
                    {
                      if (w < 0 && errno == EINTR) continue;
                      if (w == 0) errno = EIO;
                      builtin_error ("write: %s", strerror (errno));
                      ZSTD_freeDStream (dctx); return 1;
                    }
                  p += w; left -= (size_t) w;
                }
            }
          while (in.pos < in.size || (out.pos == out.size && remaining != 0));
        }
      ZSTD_freeDStream (dctx);
      if (remaining) { builtin_error ("zstd: truncated stream"); return 1; }
      return 0;
    }
}

/* ---- bzip2 (libbz2) ------------------------------------------------- */
/* Decoding follows bzip2 1.0.8: concatenated streams (pbzip2/lbzip2 output,
   or `bzip2 >> file`) decode one after another.  Bytes after a complete
   stream that do not start another one ("BZh" plus a block-size digit) are
   trailing garbage: bzip2 ignores them with a warning.  Returns 0, 1 after a
   diagnostic, or BZ_GARBAGE when garbage followed a complete stream. */
static int
bz_codec_bzip2 (int in_fd, int out_fd, int encode, int level)
{
  bz_stream s;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  int ret;
  ssize_t n = 0;
  int streams = 0;   /* complete streams decoded so far */
  int started = 0;   /* the current stream has consumed input */

  memset (&s, 0, sizeof s);   /* bzalloc/bzfree/opaque NULL → libc malloc */

  if (encode)
    {
      if (level < 1) level = 9;      /* blockSize100k must be 1..9 */
      if (level > 9) level = 9;
      ret = BZ2_bzCompressInit (&s, level, 0, 0);
      if (ret != BZ_OK)
        { builtin_error ("bzip2 compressInit: error %d", ret); return 1; }
    }
  else
    {
      ret = BZ2_bzDecompressInit (&s, 0, 0);
      if (ret != BZ_OK)
        { builtin_error ("bzip2 decompressInit: error %d", ret); return 1; }
    }

  for (;;)
    {
      if (s.avail_in == 0)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
              return 1;
            }
          s.next_in = (char *) inbuf;
          s.avail_in = (unsigned int) n;
          /* EOF between streams: every stream was complete. */
          if (!encode && n == 0 && streams > 0 && !started)
            {
              BZ2_bzDecompressEnd (&s);
              return 0;
            }
        }
      int action = (n == 0) ? BZ_FINISH : BZ_RUN;   /* encode side only */

      do
        {
          unsigned int before = s.avail_in;
          s.next_out = (char *) outbuf;
          s.avail_out = sizeof outbuf;
          ret = encode ? BZ2_bzCompress (&s, action) : BZ2_bzDecompress (&s);
          if (!encode && s.avail_in != before)
            started = 1;

          if (encode)
            {
              if (ret != BZ_RUN_OK && ret != BZ_FINISH_OK && ret != BZ_STREAM_END)
                {
                  builtin_error ("bzip2 compress: error %d", ret);
                  BZ2_bzCompressEnd (&s);
                  return 1;
                }
            }
          else
            {
              if (ret == BZ_DATA_ERROR_MAGIC && streams > 0)
                {
                  /* Not another stream: bzip2's "trailing garbage after
                     EOF ignored", which is not an error. */
                  BZ2_bzDecompressEnd (&s);
                  return BZ_GARBAGE;
                }
              if (ret != BZ_OK && ret != BZ_STREAM_END)
                {
                  builtin_error ("bzip2 decompress: %s",
                                 ret == BZ_DATA_ERROR_MAGIC ? "not a bzip2 file (bad magic number)"
                                 : ret == BZ_DATA_ERROR ? "data integrity error (CRC or stream corrupt)"
                                 : ret == BZ_MEM_ERROR ? "out of memory" : "decompression failed");
                  BZ2_bzDecompressEnd (&s);
                  return 1;
                }
            }

          size_t produced = sizeof outbuf - s.avail_out;
          if (produced > 0)
            {
              unsigned char *p = outbuf;
              size_t left = produced;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w <= 0)
                    {
                      if (w < 0 && errno == EINTR) continue;
                      if (w == 0) errno = EIO;
                      builtin_error ("write: %s", strerror (errno));
                      (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
                      return 1;
                    }
                  p += w;
                  left -= (size_t) w;
                }
            }
        }
      while (s.avail_out == 0 && ret != BZ_STREAM_END);

      if (ret == BZ_STREAM_END)
        {
          if (encode)
            break;             /* the one encoded stream is complete */
          /* Another stream may follow: keep the unread bytes and restart
             the decoder on them (BZ2_bzDecompressEnd leaves next_in). */
          char *next = s.next_in;
          unsigned int left = s.avail_in;
          streams++;
          started = 0;
          BZ2_bzDecompressEnd (&s);
          memset (&s, 0, sizeof s);
          ret = BZ2_bzDecompressInit (&s, 0, 0);
          if (ret != BZ_OK)
            { builtin_error ("bzip2 decompressInit: error %d", ret); return 1; }
          s.next_in = next;
          s.avail_in = left;
          if (n == 0 && left == 0)
            { BZ2_bzDecompressEnd (&s); return 0; }
          continue;
        }
      if (n == 0)
        break;
    }

  (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
  if (ret != BZ_STREAM_END) { builtin_error ("bzip2: truncated stream (compressed file ends unexpectedly)"); return 1; }
  return 0;
}

/* ---- xz --list (-l -f xz) ------------------------------------------- */
struct bz_xz_totals { uint64_t files, streams, blocks, compressed, uncompressed; uint32_t checks; };

static const char *
bz_xz_nicestr (uint64_t v, char *buf, size_t n)
{
  static const char units[][4] = { "B", "KiB", "MiB", "GiB", "TiB" };
  if (v < 10000)
    snprintf (buf, n, "%llu B", (unsigned long long) v);
  else
    {
      double d = (double) v;
      int unit = 0;
      do { d /= 1024.0; unit++; } while (d > 9999.9 && unit < 4);
      snprintf (buf, n, "%.1f %s", d, units[unit]);
    }
  return buf;
}

static const char *
bz_xz_ratio (uint64_t comp, uint64_t uncomp, char *buf, size_t n)
{
  double r = uncomp ? (double) comp / (double) uncomp : 0.0;
  if (!uncomp || r > 9.999) return "---";
  snprintf (buf, n, "%.3f", r);
  return buf;
}

static const char *
bz_xz_checks (uint32_t mask, char *buf, size_t n)
{
  static const char *names[16] = { "None", "CRC32", NULL, NULL, "CRC64", NULL, NULL, NULL,
                                   NULL, NULL, "SHA-256", NULL, NULL, NULL, NULL, NULL };
  size_t used = 0;
  buf[0] = '\0';
  for (int i = 0; i < 16; i++)
    {
      if (!(mask & (1u << i))) continue;
      char one[16];
      if (names[i]) snprintf (one, sizeof one, "%s", names[i]);
      else snprintf (one, sizeof one, "Unknown-%d", i);
      used += (size_t) snprintf (buf + used, used < n ? n - used : 0, "%s%s", used ? "," : "", one);
    }
  return buf;
}

static void
bz_xz_row (uint64_t streams, uint64_t blocks, uint64_t comp, uint64_t uncomp,
           uint32_t checks, const char *name)
{
  char a[32], b[32], c[32], d[32], e[32], f[96];
  snprintf (a, sizeof a, "%llu", (unsigned long long) streams);
  snprintf (b, sizeof b, "%llu", (unsigned long long) blocks);
  printf ("%5s %7s  %11s  %11s  %5s  %-7s %s\n", a, b,
          bz_xz_nicestr (comp, c, sizeof c), bz_xz_nicestr (uncomp, d, sizeof d),
          bz_xz_ratio (comp, uncomp, e, sizeof e), bz_xz_checks (checks, f, sizeof f), name);
}

/* Read the stream index of every concatenated .xz stream, last to first,
   as xz --list does. Returns 0, or 1 after a diagnostic. */
static int
bz_xz_list_file (const char *path, int *headings, struct bz_xz_totals *t)
{
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { builtin_error ("%s: %s", path, strerror (errno)); return 1; }
  struct stat st;
  uint8_t buf[LZMA_STREAM_HEADER_SIZE];
  static const uint8_t magic[6] = { 0xFD, '7', 'z', 'X', 'Z', 0 };
  if (fstat (fd, &st) < 0 || !S_ISREG (st.st_mode) || st.st_size < 2 * LZMA_STREAM_HEADER_SIZE
      || pread (fd, buf, sizeof buf, 0) != (ssize_t) sizeof buf || memcmp (buf, magic, 6))
    {
      builtin_error ("%s: File format not recognized", path);
      close (fd);
      return 1;
    }
  lzma_index *combined = NULL;
  uint64_t pos = (uint64_t) st.st_size;
  int bad = 0;
  while (pos > 0 && !bad)
    {
      /* Stream Padding: multiples of four zero bytes after a stream. */
      uint64_t padding = 0;
      for (;;)
        {
          uint8_t w[4];
          if (pos < 4 || pread (fd, w, 4, (off_t) (pos - 4)) != 4) { bad = 1; break; }
          if (w[0] | w[1] | w[2] | w[3]) break;
          pos -= 4; padding += 4;
        }
      lzma_stream_flags footer, header;
      if (bad || pos < 2 * LZMA_STREAM_HEADER_SIZE
          || pread (fd, buf, sizeof buf, (off_t) (pos - LZMA_STREAM_HEADER_SIZE)) != (ssize_t) sizeof buf
          || lzma_stream_footer_decode (&footer, buf) != LZMA_OK
          || footer.backward_size > pos - 2 * LZMA_STREAM_HEADER_SIZE)
        { bad = 1; break; }
      size_t isize = (size_t) footer.backward_size;
      uint8_t *ibuf = malloc (isize);
      lzma_index *idx = NULL;
      uint64_t memlimit = UINT64_MAX;
      size_t in_pos = 0;
      if (!ibuf || pread (fd, ibuf, isize, (off_t) (pos - LZMA_STREAM_HEADER_SIZE - isize)) != (ssize_t) isize
          || lzma_index_buffer_decode (&idx, &memlimit, NULL, ibuf, &in_pos, isize) != LZMA_OK)
        { free (ibuf); bad = 1; break; }
      free (ibuf);
      uint64_t ssize = lzma_index_stream_size (idx);
      if (ssize > pos
          || pread (fd, buf, sizeof buf, (off_t) (pos - ssize)) != (ssize_t) sizeof buf
          || lzma_stream_header_decode (&header, buf) != LZMA_OK
          || lzma_stream_flags_compare (&header, &footer) != LZMA_OK
          || lzma_index_stream_flags (idx, &footer) != LZMA_OK
          || lzma_index_stream_padding (idx, padding) != LZMA_OK
          || (combined && lzma_index_cat (idx, combined, NULL) != LZMA_OK))
        { lzma_index_end (idx, NULL); bad = 1; break; }
      combined = idx;
      pos -= ssize;
    }
  close (fd);
  if (bad || !combined)
    {
      if (combined) lzma_index_end (combined, NULL);
      builtin_error ("%s: Compressed data is corrupt", path);
      return 1;
    }
  if (!*headings)
    {
      puts ("Strms  Blocks   Compressed Uncompressed  Ratio  Check   Filename");
      *headings = 1;
    }
  uint64_t streams = lzma_index_stream_count (combined), blocks = lzma_index_block_count (combined);
  uint64_t comp = lzma_index_file_size (combined), uncomp = lzma_index_uncompressed_size (combined);
  uint32_t checks = lzma_index_checks (combined);
  bz_xz_row (streams, blocks, comp, uncomp, checks, path);
  t->files++; t->streams += streams; t->blocks += blocks;
  t->compressed += comp; t->uncompressed += uncomp; t->checks |= checks;
  lzma_index_end (combined, NULL);
  return 0;
}

static int
bz_xz_list (WORD_LIST *list)
{
  int headings = 0, rc = 0;
  struct bz_xz_totals t = { 0 };
  if (!list)
    {
      builtin_error ("--list does not support reading from standard input");
      return EXECUTION_FAILURE;
    }
  for (; list; list = list->next)
    {
      const char *path = list->word->word;
      if (!strcmp (path, "-"))
        {
          builtin_error ("--list does not support reading from standard input");
          rc = 1;
          continue;
        }
      rc |= bz_xz_list_file (path, &headings, &t);
    }
  if (t.files > 1)
    {
      char files[48];
      puts ("-------------------------------------------------------------------------------");
      snprintf (files, sizeof files, "%llu files", (unsigned long long) t.files);
      bz_xz_row (t.streams, t.blocks, t.compressed, t.uncompressed, t.checks, files);
    }
  fflush (stdout);
  return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* ---- bash builtin entry --------------------------------------------- */
int
zlib_builtin (WORD_LIST *list)
{
  int opt;
  int encode = 0;          /* default: decode */
  int level = -1;          /* default per format */
  enum bz_format fmt = BZ_GZIP;
  int explicit_format = 0;
  const char *path = NULL;
  int in_fd = -1;
  int close_in = 0;
  int list_mode = 0;
  int garbage_status = 0;  /* -g: trailing garbage is exit status 2 */

  reset_internal_getopt ();
  /* Single-char flags. -1..-9 also valid (level shortcuts). */
  while ((opt = internal_getopt (list, "edglzRf:0123456789")) != -1)
    {
      switch (opt)
        {
        case 'l': list_mode = 1; break;
        case 'g': garbage_status = 1; break;
        case 'e': encode = 1; break;
        case 'd': encode = 0; break;
        case 'z': fmt = BZ_ZLIB;    explicit_format = 1; break;
        case 'R': fmt = BZ_DEFLATE; explicit_format = 1; break;
        case 'f':
          {
            const char *fname = list_optarg;
            if      (strcmp (fname, "gzip")    == 0) fmt = BZ_GZIP;
            else if (strcmp (fname, "xz")      == 0) fmt = BZ_XZ;
            else if (strcmp (fname, "lzma")    == 0) fmt = BZ_LZMA;
            else if (strcmp (fname, "zstd")    == 0) fmt = BZ_ZSTD;
            else if (strcmp (fname, "zlib")    == 0) fmt = BZ_ZLIB;
            else if (strcmp (fname, "deflate") == 0) fmt = BZ_DEFLATE;
            else if (strcmp (fname, "bzip2")   == 0) fmt = BZ_BZIP2;
            else if (strcmp (fname, "bz2")     == 0) fmt = BZ_BZIP2;
            else
              {
                builtin_error ("unknown format: %s (use gzip/xz/zstd/bzip2/zlib/deflate)", fname);
                return (EX_USAGE);
              }
            explicit_format = 1;
            break;
          }
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          level = opt - '0';
          break;
        CASE_HELPOPT;
        default:
          builtin_usage ();
          return (EX_USAGE);
        }
    }
  list = loptend;

  if (list_mode)
    {
      if (fmt != BZ_XZ || encode)
        {
          builtin_error ("-l lists .xz files only (use -l -f xz FILE...)");
          return (EX_USAGE);
        }
      return bz_xz_list (list);
    }

  /* Optional FILE arg. "-" or absent → stdin. */
  if (list != 0)
    {
      path = list->word->word;
      if (list->next != 0)
        {
          builtin_error ("at most one FILE argument is accepted");
          return (EX_USAGE);
        }
    }
  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    in_fd = STDIN_FILENO;
  else
    {
      in_fd = open (path, O_RDONLY);
      if (in_fd < 0)
        {
          builtin_error ("%s: %s", path, strerror (errno));
          return (EXECUTION_FAILURE);
        }
      close_in = 1;
    }

  (void) explicit_format;  /* reserved for future "auto-detect from
                              filename" mode; keeps -Wunused quiet. */

  int rc;
  switch (fmt)
    {
    case BZ_GZIP:
    case BZ_ZLIB:
    case BZ_DEFLATE:
      rc = bz_codec_zlib (in_fd, STDOUT_FILENO, encode, level, fmt);
      break;
    case BZ_XZ:
    case BZ_LZMA:
      rc = bz_codec_xz   (in_fd, STDOUT_FILENO, encode, level, fmt);
      break;
    case BZ_ZSTD:
      rc = bz_codec_zstd (in_fd, STDOUT_FILENO, encode, level);
      break;
    case BZ_BZIP2:
      rc = bz_codec_bzip2 (in_fd, STDOUT_FILENO, encode, level);
      break;
    default:
      rc = 1;
    }

  if (close_in) close (in_fd);
  fflush (stdout);
  if (rc == BZ_GARBAGE)
    {
      /* Everything before the garbage decoded. -g leaves the diagnostic
         to the caller (gzip/bzip2 name the file); otherwise warn here.
         gzip treats it as a warning (status 2), bzip2 as success. */
      if (garbage_status)
        return 2;
      builtin_error (fmt == BZ_BZIP2 ? "trailing garbage after EOF ignored"
                                     : "decompression OK, trailing garbage ignored");
      return fmt == BZ_BZIP2 ? EXECUTION_SUCCESS : 2;
    }
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *zlib_doc[] = {
  "Multi-format compression / decompression — wraps libz / liblzma /",
  "libzstd via FD-level read(2)/write(2). Output bytes flow through",
  "stdout (NUL-safe at the FD layer); pipe to binhex if you need to",
  "round-trip through a bash variable.",
  "",
  "Without -e: decode (default).",
  "With    -e: encode.",
  "Decoding streams output; bytes emitted before an integrity error remain visible.",
  "",
  "Formats (-f NAME, default gzip):",
  "    gzip      RFC 1952 (the universal default)",
  "    xz        .xz container; auto-decodes .xz and legacy .lzma",
  "    lzma      legacy .lzma-alone stream",
  "    zstd      RFC 8478",
  "    bzip2     .bz2 (alias bz2); concatenated streams decode in turn",
  "    zlib      RFC 1950 (raw zlib wrap, NOT gzip)",
  "    deflate   RFC 1951 (raw bit stream, no wrap)",
  "  Shortcuts: -z = -f zlib, -R = -f deflate.",
  "  Gzip decode handles concatenated (multi-member) .gz files.",
  "",
  "Trailing data after a complete gzip member or bzip2 stream that does not",
  "start another one is ignored, as gzip and bzip2 do: gzip warns",
  "\"decompression OK, trailing garbage ignored\" and returns 2 (zero padding",
  "alone is ignored silently); bzip2 warns \"trailing garbage after EOF",
  "ignored\" and returns 0. With -g no warning is printed and both return 2,",
  "so a wrapper can name the file in its own diagnostic.",
  "",
  "List mode: -l -f xz FILE... prints xz --list's table (streams, blocks,",
  "  sizes, ratio, check) for each .xz file, with totals for several files.",
  "",
  "Compression levels: -1 (fastest) to -9 (max) for gzip/zlib/xz.",
  "  zstd accepts -1..-22 (use -f zstd -N).",
  "",
  "Examples:",
  "    zlib < foo.gz > foo                 # gunzip-equivalent",
  "    zlib -e -1 < foo > foo.gz           # fastest gzip",
  "    zlib -f xz < foo.xz > foo",
  "    zlib -f lzma < foo.lzma > foo",
  "    zlib -e -f zstd -3 < foo > foo.zst",
  "",
  "See /docs/bash/COMPRESSION-LIMIT.txt for the ceiling this breaks.",
  (char *) NULL
};

struct builtin zlib_struct = {
  "zlib",
  zlib_builtin,
  BUILTIN_ENABLED,
  zlib_doc,
  "zlib [-e|-d] [-g] [-f FORMAT|-z|-R] [-N] [FILE] | zlib -l -f xz FILE...",
  0
};
