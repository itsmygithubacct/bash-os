/* SPDX-License-Identifier: MIT */
/* cksum.c — POSIX cksum(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   cksum [FILE...]
 *       Print "<crc> <bytes> <name>" lines, one per FILE. With no
 *       FILE, reads stdin and prints "<crc> <bytes>" with no name.
 *       An explicit "-" reads stdin and retains "-" as the name.
 *   cksum -a md5|sha1|sha224|sha256|sha384|sha512 [FILE...]
 *       Match GNU cksum digest modes for common algorithms, defaulting
 *       to tagged output: "SHA256 (FILE) = HEX". --untagged emits
 *       "HEX  FILE". With stdin, FILE is "-". blake2b is also accepted.
 *   cksum [-a ALG] -c|--check [--quiet] [--status] [--strict] [-w]
 *         [--ignore-missing] [FILE...]
 *       Verify GNU checksum lists: tagged "ALG (FILE) = HEX" lines of
 *       any supported digest, or untagged "HEX  FILE" lines of the -a
 *       algorithm. Reports and exit status follow GNU cksum.
 *
 * Algorithm: POSIX-defined CRC-32 (the "Ethernet" polynomial 0x04C11DB7
 * as a non-reflected CRC, with the file length appended as input bytes
 * before the final XOR-with-zero, per POSIX.1-2024 cksum spec). NOT
 * the same as gzip's CRC-32 (which is reflected). Digest modes use the
 * same vendored mbedTLS primitives as crypto.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>

#include "_mbedtls_md5.h"
#include "_mbedtls_sha1.h"
#include "_mbedtls_sha256.h"
#include "_mbedtls_sha512.h"
#include "_monocypher_monocypher.h"
#include "loadables.h"

/* POSIX cksum CRC-32 table (non-reflected, polynomial 0x04C11DB7). */
static uint32_t bck_table[256];
static int bck_table_init = 0;

static void
bck_init_table (void)
{
    if (bck_table_init) return;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t) i << 24;
        for (int j = 0; j < 8; j++) {
            c = (c & 0x80000000U) ? (c << 1) ^ 0x04C11DB7U : (c << 1);
        }
        bck_table[i] = c;
    }
    bck_table_init = 1;
}

/* Stream FD into the running CRC + byte count. POSIX algorithm. */
static int
bck_compute_fd (int fd, uint32_t *crc_out, uint64_t *bytes_out)
{
    bck_init_table ();
    uint32_t crc = 0;
    uint64_t bytes = 0;
    unsigned char buf[8192];
    ssize_t n = 0;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            crc = (crc << 8) ^ bck_table[((crc >> 24) ^ buf[i]) & 0xFF];
        }
        bytes += (uint64_t) n;
    }
    if (n < 0) return -1;
    /* POSIX: append length octets least-significant first, omitting high
       zero bytes, then final XOR with 0xFFFFFFFF. */
    uint64_t len = bytes;
    while (len > 0) {
        crc = (crc << 8) ^ bck_table[((crc >> 24) ^ (len & 0xFF)) & 0xFF];
        len >>= 8;
    }
    crc = ~crc;
    *crc_out = crc;
    *bytes_out = bytes;
    return 0;
}

enum bck_alg {
    BCK_ALG_CRC = 0,
    BCK_ALG_MD5,
    BCK_ALG_SHA1,
    BCK_ALG_SHA224,
    BCK_ALG_SHA256,
    BCK_ALG_SHA384,
    BCK_ALG_SHA512,
    BCK_ALG_BLAKE2B
};

static enum bck_alg
bck_parse_alg (const char *alg)
{
    if (!strcmp (alg, "crc")) return BCK_ALG_CRC;
    if (!strcmp (alg, "md5")) return BCK_ALG_MD5;
    if (!strcmp (alg, "sha1")) return BCK_ALG_SHA1;
    if (!strcmp (alg, "sha224")) return BCK_ALG_SHA224;
    if (!strcmp (alg, "sha256")) return BCK_ALG_SHA256;
    if (!strcmp (alg, "sha384")) return BCK_ALG_SHA384;
    if (!strcmp (alg, "sha512")) return BCK_ALG_SHA512;
    if (!strcmp (alg, "blake2b")) return BCK_ALG_BLAKE2B;
    return (enum bck_alg) -1;
}

static const char *
bck_alg_tag (enum bck_alg alg)
{
    switch (alg) {
    case BCK_ALG_MD5: return "MD5";
    case BCK_ALG_SHA1: return "SHA1";
    case BCK_ALG_SHA224: return "SHA224";
    case BCK_ALG_SHA256: return "SHA256";
    case BCK_ALG_SHA384: return "SHA384";
    case BCK_ALG_SHA512: return "SHA512";
    case BCK_ALG_BLAKE2B: return "BLAKE2b";
    case BCK_ALG_CRC:
    default: return "CRC";
    }
}

static size_t
bck_alg_digest_len (enum bck_alg alg)
{
    switch (alg) {
    case BCK_ALG_MD5: return 16;
    case BCK_ALG_SHA1: return 20;
    case BCK_ALG_SHA224: return 28;
    case BCK_ALG_SHA256: return 32;
    case BCK_ALG_SHA384: return 48;
    case BCK_ALG_SHA512: return 64;
    case BCK_ALG_BLAKE2B: return 64;
    case BCK_ALG_CRC:
    default: return 0;
    }
}

static void
bck_hex (const unsigned char *digest, size_t len, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hx[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hx[digest[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int
bck_compute_digest_fd (int fd, enum bck_alg alg, unsigned char digest[64])
{
    unsigned char buf[8192];
    ssize_t n = 0;
    int rc = 0;

    switch (alg) {
    case BCK_ALG_MD5: {
        mbedtls_md5_context ctx;
        mbedtls_md5_init (&ctx);
        rc = mbedtls_md5_starts (&ctx);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_md5_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_md5_finish (&ctx, digest);
        mbedtls_md5_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA1: {
        mbedtls_sha1_context ctx;
        mbedtls_sha1_init (&ctx);
        rc = mbedtls_sha1_starts (&ctx);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha1_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha1_finish (&ctx, digest);
        mbedtls_sha1_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA224:
    case BCK_ALG_SHA256: {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init (&ctx);
        rc = mbedtls_sha256_starts (&ctx, alg == BCK_ALG_SHA224);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha256_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha256_finish (&ctx, digest);
        mbedtls_sha256_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA384:
    case BCK_ALG_SHA512: {
        mbedtls_sha512_context ctx;
        mbedtls_sha512_init (&ctx);
        rc = mbedtls_sha512_starts (&ctx, alg == BCK_ALG_SHA384);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha512_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha512_finish (&ctx, digest);
        mbedtls_sha512_free (&ctx);
        return rc;
    }
    case BCK_ALG_BLAKE2B: {
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init (&ctx, 64);
        while ((n = read (fd, buf, sizeof buf)) > 0)
            crypto_blake2b_update (&ctx, buf, (size_t) n);
        if (n < 0) return -1;
        crypto_blake2b_final (&ctx, digest);
        return 0;
    }
    case BCK_ALG_CRC:
    default:
        return -1;
    }
}

/* --check: verify checksum lists. */
struct bck_check {
    int quiet, status, strict, warn, ignore;
    int alg_given;
    enum bck_alg alg;
};

static int bck_needs_escape (const char *s) { return strpbrk (s, "\\\n\r") != NULL; }

static void
bck_put_name (const char *s)
{
    int escape = bck_needs_escape (s);
    if (escape) putchar ('\\');
    for (; *s; s++) {
        if (escape && *s == '\\') fputs ("\\\\", stdout);
        else if (escape && *s == '\n') fputs ("\\n", stdout);
        else if (escape && *s == '\r') fputs ("\\r", stdout);
        else putchar ((unsigned char) *s);
    }
}

static int
bck_unescape (char *s)
{
    char *out = s;
    while (*s) {
        if (*s == '\\') {
            s++;
            if (*s == 'n') *out++ = '\n';
            else if (*s == 'r') *out++ = '\r';
            else if (*s == '\\') *out++ = '\\';
            else return -1;
            s++;
        } else *out++ = *s++;
    }
    *out = 0;
    return 0;
}

/* Hash NAME with ALG into HEX. MISSING is set when it does not exist. */
static int
bck_hash_name (const char *name, enum bck_alg alg, char *hex, int quiet, int *missing)
{
    unsigned char digest[64];
    int from_stdin = !strcmp (name, "-");
    int fd = from_stdin ? STDIN_FILENO : open (name, O_RDONLY);
    *missing = 0;
    if (fd < 0) {
        *missing = errno == ENOENT;
        if (!quiet) builtin_error ("%s: %s", name, strerror (errno));
        return -1;
    }
    int failed = bck_compute_digest_fd (fd, alg, digest) < 0;
    int saved = errno;
    if (!from_stdin) close (fd);
    if (failed) {
        if (!quiet) builtin_error ("%s: %s", name, strerror (saved ? saved : EIO));
        return -1;
    }
    bck_hex (digest, bck_alg_digest_len (alg), hex);
    return 0;
}

static int
bck_verify (const char *file, const struct bck_check *o)
{
    static const enum bck_alg tagged[] = {
        BCK_ALG_MD5, BCK_ALG_SHA1, BCK_ALG_SHA224, BCK_ALG_SHA256,
        BCK_ALG_SHA384, BCK_ALG_SHA512, BCK_ALG_BLAKE2B
    };
    int from_stdin = !strcmp (file, "-");
    FILE *f = from_stdin ? fdopen (dup (STDIN_FILENO), "r") : fopen (file, "r");
    if (!f) { if (!o->status) builtin_error ("%s: %s", file, strerror (errno)); return 1; }
    char *line = NULL;
    size_t cap = 0, number = 0, valid = 0, checked = 0, bad = 0, mismatched = 0, unreadable = 0;
    enum bck_alg last = o->alg;
    int rc = 0;
    ssize_t n;
    while ((n = getline (&line, &cap, f)) >= 0) {
        number++;
        if (n && line[n - 1] == '\n') line[--n] = 0;
        if (n && line[n - 1] == '\r') line[--n] = 0;
        if (!n || line[0] == '#') continue;
        if ((size_t) n != strlen (line)) goto malformed;
        char *p = line, *name = NULL, *digest = NULL;
        int escape = *p == '\\';
        if (escape) p++;
        enum bck_alg alg = (enum bck_alg) -1;
        for (size_t i = 0; i < sizeof tagged / sizeof tagged[0]; i++) {
            const char *tag = bck_alg_tag (tagged[i]);
            size_t tl = strlen (tag);
            if (!strncmp (p, tag, tl) && !strncmp (p + tl, " (", 2)) {
                alg = tagged[i];
                name = p + tl + 2;
                break;
            }
        }
        if ((int) alg >= 0) {
            if (o->alg_given && alg != o->alg) goto malformed;
            char *end = strrchr (name, ')');
            if (!end || strncmp (end, ") = ", 4)) goto malformed;
            *end = 0;
            digest = end + 4;
        } else {
            size_t hl = 2 * bck_alg_digest_len (o->alg);
            if (!o->alg_given || strlen (p) < hl + 3 || p[hl] != ' '
                || (p[hl + 1] != ' ' && p[hl + 1] != '*'))
                goto malformed;
            alg = o->alg;
            digest = p;
            name = p + hl + 2;
            p[hl] = 0;
        }
        last = alg;
        if (strlen (digest) != 2 * bck_alg_digest_len (alg)) goto malformed;
        for (const char *d = digest; *d; d++) if (!isxdigit ((unsigned char) *d)) goto malformed;
        if (!*name || (escape && bck_unescape (name))) goto malformed;
        valid++;
        char actual[129];
        int missing = 0;
        int failed = bck_hash_name (name, alg, actual, o->status || o->ignore, &missing) < 0;
        if (failed && missing && o->ignore) continue;
        checked++;
        int matches = !failed && !strcasecmp (actual, digest);
        if (!matches) { rc = 1; if (failed) unreadable++; else mismatched++; }
        if (!o->status && (!o->quiet || !matches)) {
            bck_put_name (name);
            printf (": %s\n", matches ? "OK" : failed ? "FAILED open or read" : "FAILED");
        }
        continue;
malformed:
        bad++;
        if (o->warn && !o->status)
            builtin_error ("%s: %zu: improperly formatted %s checksum line", file, number, bck_alg_tag (last));
    }
    if (ferror (f)) { if (!o->status) builtin_error ("%s: read error", file); rc = 1; }
    free (line);
    if (fclose (f)) rc = 1;
    if (!valid) {
        if (!o->status) builtin_error ("%s: no properly formatted checksum lines found", file);
        return 1;
    }
    if (!checked) {
        if (!o->status) builtin_error ("%s: no file was verified", file);
        return 1;
    }
    if (!o->status) {
        if (bad) builtin_error ("WARNING: %zu line%s improperly formatted", bad, bad == 1 ? " is" : "s are");
        if (unreadable) builtin_error ("WARNING: %zu listed file%s could not be read", unreadable, unreadable == 1 ? "" : "s");
        if (mismatched) builtin_error ("WARNING: %zu computed checksum%s did NOT match", mismatched, mismatched == 1 ? "" : "s");
    }
    if (bad && o->strict) rc = 1;
    return rc;
}

static int
bck_try (void)
{
    fprintf (stderr, "Try 'cksum --help' for more information.\n");
    return EXECUTION_FAILURE;
}

static void
bck_print_digest (enum bck_alg alg, const char *name,
                  const unsigned char digest[64], int untagged, int delim)
{
    char hex[129];
    size_t dlen = bck_alg_digest_len (alg);
    bck_hex (digest, dlen, hex);
    if (untagged)
        printf ("%s  %s%c", hex, name, delim);
    else
        printf ("%s (%s) = %s%c", bck_alg_tag (alg), name, hex, delim);
}

int
cksum_builtin (WORD_LIST *list)
{
    int rc = EXECUTION_SUCCESS;
    int delim = '\n';   /* '\0' under -z/--zero */
    enum bck_alg selected_alg = BCK_ALG_CRC;
    int untagged = 0, check = 0, tag_given = 0;
    struct bck_check co = { 0, 0, 0, 0, 0, 0, BCK_ALG_CRC };

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("cksum 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-z") || !strcmp (w, "--zero")) {
            delim = '\0';
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--tag")) {
            untagged = 0;
            tag_given = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-c") || !strcmp (w, "--check")) { check = 1; list = list->next; continue; }
        if (!strcmp (w, "-w") || !strcmp (w, "--warn")) { co.warn = 1; list = list->next; continue; }
        if (!strcmp (w, "--quiet")) { co.quiet = 1; list = list->next; continue; }
        if (!strcmp (w, "--status")) { co.status = 1; list = list->next; continue; }
        if (!strcmp (w, "--strict")) { co.strict = 1; list = list->next; continue; }
        if (!strcmp (w, "--ignore-missing")) { co.ignore = 1; list = list->next; continue; }
        if (!strcmp (w, "--untagged")) {
            untagged = 1;
            list = list->next;
            continue;
        }
        /* -a ALG / -aALG / --algorithm ALG / --algorithm=ALG. */
        const char *alg_name = NULL;
        if (!strcmp (w, "-a") || !strcmp (w, "--algorithm")) {
            if (!list->next) {
                builtin_error ("%s needs an algorithm", w);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            alg_name = list->word->word;
        } else if (!strncmp (w, "-a", 2) && w[2]) {
            alg_name = w + 2;
        } else if (!strncmp (w, "--algorithm=", 12)) {
            alg_name = w + 12;
        }
        if (alg_name) {
            enum bck_alg parsed = bck_parse_alg (alg_name);
            if ((int) parsed < 0) {
                builtin_error ("unsupported algorithm: %s "
                               "(supported: crc, md5, sha1, sha224, sha256, sha384, sha512, blake2b)", alg_name);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            selected_alg = parsed;
            co.alg_given = 1;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (check) {
        if (co.alg_given && selected_alg == BCK_ALG_CRC) {
            builtin_error ("--check is not supported with --algorithm={bsd,sysv,crc,crc32b}");
            return EXECUTION_FAILURE;
        }
        if (tag_given) {
            builtin_error ("the --binary and --text options are meaningless when verifying checksums");
            return bck_try ();
        }
        if (delim == '\0') {
            builtin_error ("the --zero option is not supported when verifying checksums");
            return bck_try ();
        }
        co.alg = selected_alg;
        if (!list) return bck_verify ("-", &co) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
        for (WORD_LIST *p = list; p; p = p->next)
            if (bck_verify (p->word->word, &co)) rc = EXECUTION_FAILURE;
        return rc;
    }
    {
        const char *only = co.ignore ? "ignore-missing" : co.status ? "status" : co.warn ? "warn"
            : co.quiet ? "quiet" : co.strict ? "strict" : NULL;
        if (only) {
            builtin_error ("the --%s option is meaningful only when verifying checksums", only);
            return bck_try ();
        }
    }
    if (!list) {
        if (selected_alg != BCK_ALG_CRC) {
            unsigned char digest[64];
            if (bck_compute_digest_fd (STDIN_FILENO, selected_alg, digest) < 0) {
                builtin_error ("read stdin: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
            bck_print_digest (selected_alg, "-", digest, untagged, delim);
            return EXECUTION_SUCCESS;
        }
        uint32_t crc;
        uint64_t bytes;
        if (bck_compute_fd (STDIN_FILENO, &crc, &bytes) < 0) {
            builtin_error ("read stdin: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("%" PRIu32 " %" PRIu64 "%c", crc, bytes, delim);
        return EXECUTION_SUCCESS;
    }
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;
        int fd;
        /* A literal '-' selects stdin. Other dash-leading names can be
           supplied after the '--' option separator. */
        int from_stdin = (strcmp (path, "-") == 0);
        if (from_stdin) {
            fd = STDIN_FILENO;
        } else {
            fd = open (path, O_RDONLY);
            if (fd < 0) {
                builtin_error ("%s: %s", path, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
        }
        if (selected_alg != BCK_ALG_CRC) {
            unsigned char digest[64];
            if (bck_compute_digest_fd (fd, selected_alg, digest) < 0) {
                builtin_error ("read %s: %s", path, strerror (errno));
                if (!from_stdin) close (fd);
                rc = EXECUTION_FAILURE;
                continue;
            }
            bck_print_digest (selected_alg, from_stdin ? "-" : path, digest, untagged, delim);
            if (!from_stdin) close (fd);
            continue;
        }
        uint32_t crc;
        uint64_t bytes;
        if (bck_compute_fd (fd, &crc, &bytes) < 0) {
            builtin_error ("read %s: %s", path, strerror (errno));
            if (!from_stdin) close (fd);
            rc = EXECUTION_FAILURE;
            continue;
        }
        printf ("%" PRIu32 " %" PRIu64 " %s%c", crc, bytes, path, delim);
        if (!from_stdin) close (fd);
    }
    return rc;
}

char *cksum_doc[] = {
    "POSIX CRC-32 + byte-count, plus common GNU cksum digest modes.",
    "",
    "    cksum [-a crc|md5|sha1|sha224|sha256|sha384|sha512|blake2b] [-z] [--tag|--untagged] [FILE...]",
    "    cksum [-a ALG] -c|--check [--quiet|--status] [--strict] [-w] [--ignore-missing] [FILE...]",
    "    cksum --help | --version",
    "        CRC mode prints '<crc> <bytes> <FILE>'. Digest modes",
    "        default to tagged output, e.g. 'SHA256 (FILE) = HEX'.",
    "        With no FILE or '-', read stdin. Explicit '-' operands keep their name.",
    "        Without FILE, CRC stdin omits its name; digest stdin is named '-'.",
    "        Use -- before dash-leading filenames.",
    "",
    "    -a, --algorithm=ALG   crc, md5, sha1, sha224, sha256, sha384, sha512, or blake2b",
    "    -c, --check           verify tagged lines (any digest) or, with -a,",
    "                          untagged 'HEX  FILE' lines; --quiet, --status,",
    "                          --strict, -w/--warn and --ignore-missing as GNU",
    "    -z, --zero            end each output line with NUL, not newline",
    "    --tag / --untagged    tagged or reversed digest output",
    "",
    "Algorithm is POSIX-mandated CRC-32 (polynomial 0x04C11DB7,",
    "non-reflected, with length-byte injection + final XOR).",
    "Unsupported: --raw, --base64, --length, sysv, bsd, crc32b, sm3.",
    (char *)NULL
};

struct builtin cksum_struct = {
    "cksum",
    cksum_builtin,
    BUILTIN_ENABLED,
    cksum_doc,
    "cksum [FILE...]",
    0
};
