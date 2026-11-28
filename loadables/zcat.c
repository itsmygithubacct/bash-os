/* SPDX-License-Identifier: MIT */
/* zcat.c — POSIX zcat(1) wrapper using libz directly.
 *
 *   zcat [FILE...]
 *
 * Decompresses gzip-format input from FILE(s) (or stdin) to stdout.
 * libz is already linked into bash-os via zlib's EXTRA_LIBS. Use its
 * streaming inflater to retain output produced before an integrity error.
 * POSIX shape — no extension sniffing, gzip-only. For xz/zstd use
 * `zlib -d -f xz` directly.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <zlib.h>

#include "loadables.h"
#include "gnu-longopt.h"

extern char *this_command_name;

/* GNU zcat is `gzip -cd`, so its diagnostics name gzip. Like gzip, a
   problem with the compressed data starts on a new line (BLANK). */
static void
bz_error (int blank, const char *fmt, ...)
{
    va_list ap;
    fflush (stdout);
    if (blank)
        fputc ('\n', stderr);
    fputs ("gzip: ", stderr);
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
    fputc ('\n', stderr);
}

/* gzip's wording for an inflate failure. */
static const char *
bz_inflate_error (const z_stream *s, int ret)
{
    if (ret == Z_DATA_ERROR && s->msg && !strcmp (s->msg, "incorrect data check"))
        return "invalid compressed data--crc error";
    if (ret == Z_DATA_ERROR && s->msg && !strcmp (s->msg, "incorrect length check"))
        return "invalid compressed data--length error";
    if (ret == Z_DATA_ERROR)
        return "invalid compressed data--format violated";
    return s->msg ? s->msg : zError (ret);
}

/* BZ_WARNING: every member decoded, then trailing garbage was ignored
 * (gzip -cd exits 2 for it). */
enum bz_result { BZ_OK, BZ_INPUT_ERROR, BZ_FATAL_ERROR, BZ_WARNING };

static int
bz_write_all (const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write (STDOUT_FILENO, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

/* Retain unread bytes when a gzip magic number spans two reads. */
static ssize_t
bz_read_more (int fd, z_stream *s, unsigned char *buf, size_t size)
{
    ssize_t n;
    if (s->avail_in)
        memmove (buf, s->next_in, s->avail_in);
    s->next_in = buf;
    do {
        n = read (fd, buf + s->avail_in, size - s->avail_in);
    } while (n < 0 && errno == EINTR);
    if (n > 0) s->avail_in += (uInt) n;
    return n;
}

/* zcat -f: input that is not gzip is copied through unchanged. */
static enum bz_result
bz_passthrough (int fd, const char *name, const unsigned char *head, size_t len)
{
    unsigned char buf[8192];
    if (bz_write_all (head, len) < 0) goto write_error;
    for (;;) {
        ssize_t n = read (fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { bz_error (0, "%s: %s", name, strerror (errno)); return BZ_FATAL_ERROR; }
        if (n == 0) return BZ_OK;
        if (bz_write_all (buf, (size_t) n) < 0) goto write_error;
    }
write_error:
    bz_error (0, "write: %s", strerror (errno));
    return BZ_FATAL_ERROR;
}

static enum bz_result
bz_pump (int fd, const char *name, int force, int quiet)
{
    z_stream s;
    unsigned char inbuf[8192], outbuf[8192];
    int at_header = 1, seen_member = 0, eof = 0;
    enum bz_result result = BZ_FATAL_ERROR;

    memset (&s, 0, sizeof s);
    /* Accept gzip only, without zlib autodetection or transparent copying. */
    int ret = inflateInit2 (&s, MAX_WBITS + 16);
    if (ret != Z_OK) {
        bz_error (0, "%s: %s", name, zError (ret));
        return BZ_FATAL_ERROR;
    }

    for (;;) {
        if (at_header) {
            while (s.avail_in < 2 && !eof) {
                ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
                if (n < 0) goto read_error;
                if (n == 0) eof = 1;
            }
            if (!seen_member && force &&
                (s.avail_in < 2 || s.next_in[0] != 0x1f || s.next_in[1] != 0x8b)) {
                result = bz_passthrough (fd, name, s.next_in, s.avail_in);
                break;
            }
            if (seen_member && force &&
                (s.avail_in < 2 || s.next_in[0] != 0x1f || s.next_in[1] != 0x8b)) {
                /* gzip -cdf copies data after the last member through. */
                result = bz_passthrough (fd, name, s.next_in, s.avail_in);
                break;
            }
            if (seen_member && s.avail_in && s.next_in[0] == 0) {
                /* Zero padding after the last member is ignored silently;
                 * anything after the zeros is trailing garbage. */
                for (;;) {
                    while (s.avail_in && s.next_in[0] == 0) { s.next_in++; s.avail_in--; }
                    if (s.avail_in || eof) break;
                    ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
                    if (n < 0) goto read_error;
                    if (n == 0) eof = 1;
                }
                if (!s.avail_in) { result = BZ_OK; break; }
                goto trailing_garbage;
            }
            if (s.avail_in < 2) {
                if (seen_member && s.avail_in == 0) result = BZ_OK;
                else bz_error (1, "%s: unexpected end of file", name);
                break;
            }
            if (s.next_in[0] != 0x1f || s.next_in[1] != 0x8b) {
                if (!seen_member) {
                    bz_error (1, "%s: not in gzip format", name);
                    result = BZ_INPUT_ERROR;
                    break;
                }
            trailing_garbage:
                /* GNU gzip -cd: "decompression OK, trailing garbage
                 * ignored", exit status 2. Consume the rest so another
                 * '-' starts at the same stdin EOF. */
                if (!quiet)
                    bz_error (1, "%s: decompression OK, trailing garbage ignored", name);
                while (!eof) {
                    s.avail_in = 0;
                    ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
                    if (n < 0) goto read_error;
                    if (n == 0) eof = 1;
                }
                result = BZ_WARNING;
                break;
            }
            if (seen_member) {
                /* inflateReset retains next_in and avail_in. */
                ret = inflateReset (&s);
                if (ret != Z_OK) {
                    bz_error (0, "%s: %s", name, zError (ret));
                    break;
                }
            }
            at_header = 0;
        }

        if (s.avail_in == 0 && !eof) {
            ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
            if (n < 0) goto read_error;
            if (n == 0) eof = 1;
        }
        uInt available = s.avail_in;
        s.next_out = outbuf;
        s.avail_out = sizeof outbuf;
        ret = inflate (&s, Z_NO_FLUSH);
        size_t produced = sizeof outbuf - s.avail_out;

        /* Even Z_DATA_ERROR can accompany decoded bytes. Write those bytes
         * before diagnosing a CRC or length failure, just as gzip does. */
        if (bz_write_all (outbuf, produced) < 0) {
            bz_error (0, "write: %s", strerror (errno));
            break;
        }
        if (ret == Z_STREAM_END) {
            seen_member = 1;
            at_header = 1;
            continue;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            bz_error (1, "%s: %s", name, bz_inflate_error (&s, ret));
            break;
        }
        if (produced == 0 && s.avail_in == available) {
            bz_error (1, "%s: %s", name,
                      eof ? "unexpected end of file" : "invalid compressed data--format violated");
            break;
        }
    }

done:
    inflateEnd (&s);
    return result;

read_error:
    bz_error (0, "%s: %s", name, strerror (errno));
    goto done;
}

/* gzip -d's suffixes; a missing FILE without one is looked up as FILE.gz
   (and FILE with -S's suffix), and reported under that name. */
static int
bz_has_suffix (const char *path, const char *extra)
{
    static const char *const known[] = { ".gz", "-gz", ".z", "-z", "_z", ".Z", ".tgz", ".taz", NULL };
    size_t n = strlen (path);
    for (int i = 0; known[i] || extra; i++) {
        const char *suf = known[i] ? known[i] : extra;
        size_t k = strlen (suf);
        if (k && n > k && !strcmp (path + n - k, suf))
            return 1;
        if (!known[i])
            break;
    }
    return 0;
}

static int
bz_open (const char *path, const char *suffix, char **shown)
{
    *shown = NULL;
    int fd = open (path, O_RDONLY);
    if (fd >= 0 || errno != ENOENT || bz_has_suffix (path, suffix))
        return fd;
    char *alt = malloc (strlen (path) + strlen (suffix) + 1);
    if (!alt) { errno = ENOENT; return -1; }
    strcpy (alt, path);
    strcat (alt, suffix);
    fd = open (alt, O_RDONLY);
    int saved = errno;
    *shown = alt;
    errno = saved;
    return fd;
}

int
zcat_builtin (WORD_LIST *list)
{
    int force = 0, quiet = 0, c;
    const char *suffix = ".gz";
    static const struct bos_longopt longopts[] = {
        { "force", BOS_NO_ARG, 'f' }, { "quiet", BOS_NO_ARG, 'q' }, { "silent", BOS_NO_ARG, 'q' },
        { "stdout", BOS_NO_ARG, 'c' }, { "to-stdout", BOS_NO_ARG, 'c' },
        { "decompress", BOS_NO_ARG, 'd' }, { "uncompress", BOS_NO_ARG, 'd' },
        { "no-name", BOS_NO_ARG, 'n' }, { "name", BOS_NO_ARG, 'N' },
        { "suffix", BOS_REQ_ARG, 'S' },
        { NULL, 0, 0 }
    };
    /* gzip -cd options: -f passes non-gzip input through, -q silences the
       trailing-garbage warning, -S adds a suffix to look up; -c, -d, -n and
       -N change nothing for zcat. Option errors exit 1 and, as GNU zcat
       runs gzip -cd, name gzip with gzip's `gzip --help' hint. */
    bos_getopt g;
    bos_getopt_init (&g, "gzip", "fcdnNqS:", longopts, list);
    g.no_hint = 1;
    char *saved_name = this_command_name;
    this_command_name = "gzip";
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
            case 'f': force = 1; break;
            case 'q': quiet = 1; break;
            case 'S': suffix = g.optarg; break;
            case 'c': case 'd': case 'n': case 'N': break;
            default:
                this_command_name = saved_name;
                fprintf (stderr, "Try `gzip --help' for more information.\n");
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
        }
    }
    this_command_name = saved_name;
    if (!*suffix) {
        bz_error (0, "invalid suffix ''");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (g.noperands == 0) {
        bos_getopt_free (&g);
        enum bz_result result = bz_pump (STDIN_FILENO, "stdin", force, quiet);
        return result == BZ_OK ? EXECUTION_SUCCESS : result == BZ_WARNING ? 2 : EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS, warned = 0;
    for (int i = 0; i < g.noperands; i++) {
        const char *path = g.operands[i];
        char *shown = NULL;
        int is_stdin = !strcmp (path, "-");
        int fd = is_stdin ? STDIN_FILENO : bz_open (path, suffix, &shown);
        if (fd < 0) {
            bz_error (0, "%s: %s", shown ? shown : path, strerror (errno));
            free (shown);
            rc = EXECUTION_FAILURE;
            continue;
        }
        enum bz_result result = bz_pump (fd, is_stdin ? "stdin" : shown ? shown : path, force, quiet);
        free (shown);
        if (!is_stdin) close (fd);
        if (result == BZ_WARNING) { warned = 1; continue; }
        if (result != BZ_OK) {
            rc = EXECUTION_FAILURE;
            /* Missing/non-gzip named inputs are recoverable. Integrity and
             * stdin failures stop this invocation, without exiting Bash. */
            if (result == BZ_FATAL_ERROR || is_stdin) break;
        }
    }
    bos_getopt_free (&g);
    return rc == EXECUTION_SUCCESS && warned ? 2 : rc;
}

char *zcat_doc[] = {
    "Decompress gzip files to stdout (POSIX zcat).",
    "",
    "    zcat [-f] [FILE...]",
    "",
    "Reads each FILE (or stdin if none given, or `-` in the list) as",
    "gzip-format and writes the decompressed bytes to stdout. With -f",
    "(--force), input that is not gzip is copied unchanged, as gzip -cdf",
    "does; -c, -d, -n, -N, -q and -S SUFFIX are accepted. A missing FILE without a",
    "gzip suffix is read as FILE.gz. Diagnostics are gzip's, as GNU zcat runs",
    "gzip -cd. Trailing garbage after the last",
    "member is ignored with gzip's warning (none with -q) and exit status 2;",
    "zero padding is ignored silently, and -f copies trailing data through. For xz,",
    "zstd, or zlib formats use `zlib -d -f FORMAT` directly.",
    (char *)NULL
};

struct builtin zcat_struct = {
    "zcat",
    zcat_builtin,
    BUILTIN_ENABLED,
    zcat_doc,
    "zcat [-f] [FILE...]",
    0
};
