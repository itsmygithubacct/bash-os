/* SPDX-License-Identifier: MIT */
/* acme.c — JOSE/JWS + JWK primitives for ACME (RFC 8555).
 *
 * Server-gap slice B from SERVER-GAP-WIREGUARD-ACME-PLAN.md.
 *
 * Lifecycle verbs use the installed curl and crypto builtins for transport
 * and CSR generation, and the local JWS primitives for signed ACME requests.
 * HTTP-01 listens on port 80 by default.  An alternate listener and cleartext
 * transport must be explicitly selected for isolated test environments.
 *
 * Verbs:
 *   acme jwk-thumbprint -k SK_HEX
 *       SHA-256(canonical-JSON({crv,kty,x,y}))  base64url-encoded
 *       — RFC 7638 §3 for ES256/P-256.  Used by ACME's keyAuthorization
 *       (RFC 8555 §8.1).
 *
 *   acme key-authorization TOKEN -k SK_HEX
 *       Emit  TOKEN + "." + jwk-thumbprint  (RFC 8555 §8.1).
 *
 *   acme jws-sign -k SK_HEX --url URL --nonce N
 *                     [--kid KID | --jwk] [-d DATA | -f FILE]
 *       Produce the JSON flattened JWS (RFC 7515 §7.2.2 form ACME
 *       uses): {"protected":B64U,"payload":B64U,"signature":B64U}.
 *       --kid sets the protected header `kid` (post-newAccount calls).
 *       --jwk inlines the JWK (used by newAccount + revokeCert).
 *       -d/-f provide the request body; empty for POST-as-GET (ACME
 *       servers expect `"payload":""` for those).
 *
 *   acme jwk-public -k SK_HEX
 *       Emit the JWK JSON for the account key
 *       ({"crv":"P-256","kty":"EC","x":...,"y":...}).
 *
 *   acme jws-extract-key-authorization TOKEN -k SK_HEX
 *       Alias for key-authorization, mirrors the verb name commonly
 *       used in ACME tutorials.
 *
 * Determinism:
 *   jwk-public / jwk-thumbprint / key-authorization / jws-extract-key-authorization
 *     fully deterministic given inputs (byte-identical to RFC 7638 §3 and
 *     RFC 8555 §8.1 reference implementations such as python cryptography
 *     + authlib).
 *   jws-sign
 *     the JOSE framing (protected header + payload) is byte-stable, but the
 *     ECDSA signature varies per call — the underlying signer is
 *     p256-m's `p256_ecdsa_sign` which uses random nonces (NOT RFC 6979
 *     deterministic-ECDSA). Each signature is a valid ECDSA-P256 signature
 *     over SHA-256(protected||"."||payload) and verifies against the
 *     derived public key. RFC 8555 doesn't require determinism, so ACME
 *     interop is unaffected; callers that need byte-stable JWS must hash
 *     or pin the (protected,payload) pair instead of the whole envelope.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "loadables.h"
#include "command-run.h"
#include "child-wait.h"
#include "trap.h"
#define JSMN_STATIC
#define JSMN_STRICT
#include "_jsmn_jsmn.h"
#include "_mbedtls_base64.h"
#include "_mbedtls_sha256.h"
#include "_mbedtls_ecdsa_p256.h"
#include "_mbedtls_x509_crt.h"
#include "_mbedtls_crypto.h"

#define BA_KEY_LEN 32
#define BA_PUB_LEN 65   /* uncompressed: 0x04 || X(32) || Y(32) */

/* ----- small helpers, parallel to crypto.c's bc_* helpers ----- */

static int
ba_hexval (unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
ba_unhex (const char *hex, unsigned char *out, size_t outsz)
{
    size_t o = 0; int hi = -1;
    for (const char *p = hex; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
        int v = ba_hexval ((unsigned char) *p);
        if (v < 0) return -1;
        if (hi < 0) { hi = v; continue; }
        if (o >= outsz) return -1;
        out[o++] = (unsigned char) ((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) return -1;
    return (int) o;
}

static int
ba_write_all (const unsigned char *buf, size_t n)
{
    size_t left = n; const unsigned char *p = buf;
    while (left > 0) {
        ssize_t w = write (STDOUT_FILENO, p, left);
        if (w < 0) { if (errno == EINTR) continue;
                     builtin_error ("write: %s", strerror (errno)); return -1; }
        p += w; left -= (size_t) w;
    }
    return 0;
}

static int
ba_slurp_file (const char *path, unsigned char **out, size_t *out_len)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); builtin_error ("malloc"); return -1; }
    for (;;) {
        if (len == cap) { cap *= 2;
            unsigned char *n = realloc (buf, cap);
            if (!n) { free (buf); close (fd); builtin_error ("realloc"); return -1; }
            buf = n; }
        ssize_t r = read (fd, buf + len, cap - len);
        if (r < 0) { if (errno == EINTR) continue;
                     free (buf); close (fd);
                     builtin_error ("read %s: %s", path, strerror (errno)); return -1; }
        if (r == 0) break;
        len += (size_t) r;
    }
    close (fd);
    *out = buf; *out_len = len;
    return 0;
}

/* Base64URL encode (no padding) — RFC 4648 §5, JOSE convention. */
static int
ba_base64url_encode (const unsigned char *in, size_t inlen, char *out, size_t outsz)
{
    size_t b64_len = 0;
    mbedtls_base64_encode (NULL, 0, &b64_len, in, inlen);
    if (b64_len + 1 > outsz) return -1;
    int rc = mbedtls_base64_encode ((unsigned char *) out, outsz, &b64_len, in, inlen);
    if (rc != 0) return -1;
    out[b64_len] = 0;
    /* +/= → -/_/ (no padding) */
    char *r = out, *w = out;
    while (*r) {
        if (*r == '+') { *w++ = '-'; r++; }
        else if (*r == '/') { *w++ = '_'; r++; }
        else if (*r == '=') { r++; }
        else { *w++ = *r++; }
    }
    *w = 0;
    return (int) (w - out);
}

/* SHA-256 over a buffer; mbedtls streaming with init/update/finish. */
static int
ba_sha256 (const unsigned char *in, size_t inlen, unsigned char out[32])
{
    mbedtls_sha256_context hc;
    mbedtls_sha256_init (&hc);
    int rc = mbedtls_sha256_starts (&hc, 0);
    if (rc == 0) rc = mbedtls_sha256_update (&hc, in, inlen);
    if (rc == 0) rc = mbedtls_sha256_finish (&hc, out);
    mbedtls_sha256_free (&hc);
    return rc;
}

/* Derive ECDSA-P256 public key (X,Y) from a 32-byte private key.
   Output: x[32], y[32] from the uncompressed pub65[0..65]. */
static int
ba_ecdsa_p256_xy (const unsigned char sk[BA_KEY_LEN],
                  unsigned char x[32], unsigned char y[32])
{
    unsigned char pub[BA_PUB_LEN];
    int rc = mbedtls_ecdsa_p256_public (pub, sk);
    if (rc != 0) return rc;
    if (pub[0] != 0x04) return -1;  /* mbedtls always returns uncompressed */
    memcpy (x, pub + 1, 32);
    memcpy (y, pub + 33, 32);
    return 0;
}

/* ----- jwk-public ------------------------------------------------ */

/* Emit the canonical (RFC 7638 §3) JWK JSON to stdout:
       {"crv":"P-256","kty":"EC","x":"…","y":"…"}
   Keys appear in lexicographic order — required for the thumbprint
   hash to be byte-stable.  */
static int
ba_emit_jwk (const unsigned char x[32], const unsigned char y[32])
{
    char xb[64], yb[64];
    if (ba_base64url_encode (x, 32, xb, sizeof xb) < 0) { builtin_error ("jwk: encode x failed"); return -1; }
    if (ba_base64url_encode (y, 32, yb, sizeof yb) < 0) { builtin_error ("jwk: encode y failed"); return -1; }
    printf ("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
    return 0;
}

static int
ba_jwk_public_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else { builtin_error ("jwk-public: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex) { builtin_error ("jwk-public: -k SK_HEX required"); return EX_USAGE; }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jwk-public: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jwk-public: invalid private key"); return EXECUTION_FAILURE; }
    if (ba_emit_jwk (x, y) < 0) return EXECUTION_FAILURE;
    putchar ('\n');
    return EXECUTION_SUCCESS;
}

/* ----- jwk-thumbprint ------------------------------------------- */

/* Build the same canonical JWK string into `buf` (no trailing NL).
   Returns bytes written (excluding NUL), or -1 on overflow. */
static int
ba_jwk_canonical (char *buf, size_t bufsz,
                  const unsigned char x[32], const unsigned char y[32])
{
    char xb[64], yb[64];
    if (ba_base64url_encode (x, 32, xb, sizeof xb) < 0) return -1;
    if (ba_base64url_encode (y, 32, yb, sizeof yb) < 0) return -1;
    int n = snprintf (buf, bufsz,
                      "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
    if (n < 0 || (size_t) n >= bufsz) return -1;
    return n;
}

static int
ba_jwk_thumbprint_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else { builtin_error ("jwk-thumbprint: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex) { builtin_error ("jwk-thumbprint: -k SK_HEX required"); return EX_USAGE; }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jwk-thumbprint: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jwk-thumbprint: invalid private key"); return EXECUTION_FAILURE; }
    char canonical[256];
    int n = ba_jwk_canonical (canonical, sizeof canonical, x, y);
    if (n < 0) { builtin_error ("jwk-thumbprint: encode failed"); return EXECUTION_FAILURE; }
    unsigned char digest[32];
    if (ba_sha256 ((unsigned char *) canonical, (size_t) n, digest) != 0)
        { builtin_error ("jwk-thumbprint: sha256 failed"); return EXECUTION_FAILURE; }
    char b64[64];
    if (ba_base64url_encode (digest, 32, b64, sizeof b64) < 0)
        { builtin_error ("jwk-thumbprint: base64url encode failed"); return EXECUTION_FAILURE; }
    printf ("%s\n", b64);
    return EXECUTION_SUCCESS;
}

/* ----- key-authorization (RFC 8555 §8.1) ------------------------ */

/* TOKEN + "." + base64url(SHA256(canonical-JWK))  */
static int
ba_key_authorization_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL, *token = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else if (w[0] != '-' && !token) {
            token = w;
        } else { builtin_error ("key-authorization: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!token || !sk_hex) {
        builtin_error ("key-authorization: TOKEN -k SK_HEX required"); return EX_USAGE;
    }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("key-authorization: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("key-authorization: invalid private key"); return EXECUTION_FAILURE; }
    char canonical[256];
    int n = ba_jwk_canonical (canonical, sizeof canonical, x, y);
    if (n < 0) { builtin_error ("key-authorization: encode failed"); return EXECUTION_FAILURE; }
    unsigned char digest[32];
    if (ba_sha256 ((unsigned char *) canonical, (size_t) n, digest) != 0)
        { builtin_error ("key-authorization: sha256 failed"); return EXECUTION_FAILURE; }
    char tp[64];
    if (ba_base64url_encode (digest, 32, tp, sizeof tp) < 0)
        { builtin_error ("key-authorization: b64u encode failed"); return EXECUTION_FAILURE; }
    printf ("%s.%s\n", token, tp);
    return EXECUTION_SUCCESS;
}

/* ----- jws-sign ------------------------------------------------- */

/* Convert a 64-byte raw ECDSA signature (r||s, big-endian) into the
   JOSE-defined fixed-length form (RFC 7515 §3.4 / RFC 7518 §3.4): for
   ES256 it's literally the same r||s 64-byte form, so no conversion
   needed.  We base64url-encode directly. */

static int
ba_jws_sign_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL, *kid = NULL, *url = NULL, *nonce = NULL;
    const char *data_inline = NULL, *data_file = NULL;
    int use_jwk = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k"))         { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
                                          p = p->next; sk_hex = p->word->word; }
        else if (!strcmp (w, "--kid")) { if (!p->next) { builtin_error ("--kid needs URL"); return EX_USAGE; }
                                          p = p->next; kid = p->word->word; }
        else if (!strcmp (w, "--jwk")) use_jwk = 1;
        else if (!strcmp (w, "--url")) { if (!p->next) { builtin_error ("--url needs URL"); return EX_USAGE; }
                                          p = p->next; url = p->word->word; }
        else if (!strcmp (w, "--nonce")) { if (!p->next) { builtin_error ("--nonce needs N"); return EX_USAGE; }
                                            p = p->next; nonce = p->word->word; }
        else if (!strcmp (w, "-d"))    { if (!p->next) { builtin_error ("-d needs DATA"); return EX_USAGE; }
                                          p = p->next; data_inline = p->word->word; }
        else if (!strcmp (w, "-f"))    { if (!p->next) { builtin_error ("-f needs FILE"); return EX_USAGE; }
                                          p = p->next; data_file = p->word->word; }
        else { builtin_error ("jws-sign: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex || !url || !nonce) {
        builtin_error ("jws-sign: -k SK_HEX, --url URL, --nonce N are required");
        return EX_USAGE;
    }
    if (use_jwk && kid) {
        builtin_error ("jws-sign: --jwk and --kid are mutually exclusive");
        return EX_USAGE;
    }
    if (!use_jwk && !kid) {
        /* Default to --jwk for first-time newAccount; otherwise the
           operator must always pass --kid (we don't infer).  Be
           explicit. */
        builtin_error ("jws-sign: exactly one of --kid KID or --jwk required");
        return EX_USAGE;
    }

    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jws-sign: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jws-sign: invalid private key"); return EXECUTION_FAILURE; }

    /* Compose the protected header.  We deliberately do not escape
       URL/KID/NONCE — RFC 8555 specifies these are URL-safe ASCII and
       Let's Encrypt's nonce is base64url alphabet.  If the caller
       feeds bogus inputs they will see a JWS decode error from the
       ACME server, which is preferable to silent JSON corruption. */
    char header[2048];
    if (use_jwk) {
        char jwk[256];
        int jn = ba_jwk_canonical (jwk, sizeof jwk, x, y);
        if (jn < 0) { builtin_error ("jws-sign: jwk encode failed"); return EXECUTION_FAILURE; }
        int n = snprintf (header, sizeof header,
                "{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}",
                jwk, nonce, url);
        if (n < 0 || (size_t) n >= sizeof header)
            { builtin_error ("jws-sign: header too long"); return EXECUTION_FAILURE; }
    } else {
        int n = snprintf (header, sizeof header,
                "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}",
                kid, nonce, url);
        if (n < 0 || (size_t) n >= sizeof header)
            { builtin_error ("jws-sign: header too long"); return EXECUTION_FAILURE; }
    }

    /* Read payload bytes (may be empty = POST-as-GET). */
    unsigned char *payload = NULL; size_t payload_len = 0;
    if (data_file) {
        if (ba_slurp_file (data_file, &payload, &payload_len) < 0) return EXECUTION_FAILURE;
    } else if (data_inline) {
        payload_len = strlen (data_inline);
        payload = malloc (payload_len + 1);
        if (!payload) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
        memcpy (payload, data_inline, payload_len);
    } else {
        payload = malloc (1); if (payload) payload[0] = 0;
        payload_len = 0;
    }

    /* base64url(header) and base64url(payload).  Worst-case is
       4/3 * payload_len + 2.  Bound the payload at 64 KB. */
    if (payload_len > 65536) {
        free (payload);
        builtin_error ("jws-sign: payload too large (>64 KB)");
        return EXECUTION_FAILURE;
    }
    size_t header_len = strlen (header);
    char *h64 = malloc (((header_len + 2) / 3) * 4 + 4);
    char *p64 = malloc (((payload_len + 2) / 3) * 4 + 4);
    if (!h64 || !p64) {
        free (h64); free (p64); free (payload);
        builtin_error ("malloc"); return EXECUTION_FAILURE;
    }
    int h64_n = ba_base64url_encode ((unsigned char *) header, header_len, h64, ((header_len + 2)/3)*4 + 4);
    int p64_n = ba_base64url_encode (payload, payload_len, p64, ((payload_len + 2)/3)*4 + 4);
    free (payload);
    if (h64_n < 0 || p64_n < 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: base64url encode failed"); return EXECUTION_FAILURE;
    }

    /* Signing input: h64 + "." + p64 */
    size_t si_len = (size_t) h64_n + 1 + (size_t) p64_n;
    unsigned char *si = malloc (si_len);
    if (!si) { free (h64); free (p64); builtin_error ("malloc"); return EXECUTION_FAILURE; }
    memcpy (si, h64, (size_t) h64_n);
    si[h64_n] = '.';
    memcpy (si + h64_n + 1, p64, (size_t) p64_n);

    unsigned char digest[32], sig_raw[64];
    if (ba_sha256 (si, si_len, digest) != 0) {
        free (si); free (h64); free (p64);
        builtin_error ("jws-sign: sha256 failed"); return EXECUTION_FAILURE;
    }
    free (si);
    if (mbedtls_ecdsa_p256_sign_raw (sig_raw, sk, digest, 32) != 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: ecdsa sign failed"); return EXECUTION_FAILURE;
    }

    char sig64[128];
    if (ba_base64url_encode (sig_raw, 64, sig64, sizeof sig64) < 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: signature b64u failed"); return EXECUTION_FAILURE;
    }

    /* Flattened-JSON JWS, single line (ACME servers don't care about
       internal whitespace; this is the most compact form). */
    printf ("{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}\n",
            h64, p64, sig64);
    free (h64); free (p64);
    return EXECUTION_SUCCESS;
}

/* ACME lifecycle: bounded requests, argv-only child builtin calls and an
   explicitly configured HTTP-01 responder.  RFC 8555 sections 6-8. */
#define BA_LIFE_MAX_BODY (1024 * 1024)
#define BA_LIFE_URL 2048
#define BA_LIFE_NONCE 1024
#define BA_LIFE_TOKENS 4096

typedef struct {
    char directory[BA_LIFE_URL], nonce_url[BA_LIFE_URL];
    char account_url[BA_LIFE_URL], order_url[BA_LIFE_URL];
    char finalize_url[BA_LIFE_URL], cert_url[BA_LIFE_URL];
    char nonce[BA_LIFE_NONCE], challenge_url[BA_LIFE_URL], token[512];
    char tmp[128], header[160], body[160], capture[160], generated_key[65];
    const char *account_key, *cert_key, *domain, *outdir, *cacert, *cert_ca;
    const char *listen_addr;
    int allow_http, status, responder_fd;
    struct timespec deadline;
    pid_t responder;
    bos_child_wait responder_wait;
    int responder_waiting;
} ba_lifecycle;

/* All network, signing and poll waits share this monotonic budget. */
static int
ba_life_remaining (ba_lifecycle *c, long *ms)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    long long n = ((long long)c->deadline.tv_sec - now.tv_sec) * 1000 +
                  (c->deadline.tv_nsec - now.tv_nsec) / 1000000;
    if (n <= 0) { errno = ETIMEDOUT; return -1; }
    *ms = n > LONG_MAX ? LONG_MAX : (long)n;
    return 0;
}

static int
ba_life_wait (ba_lifecycle *c, long delay)
{
    struct timespec now, until;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    until = now; until.tv_sec += delay / 1000;
    until.tv_nsec += (delay % 1000) * 1000000L;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    for (;;) {
        long left;
        if (interrupt_state || terminating_signal || first_pending_trap() > 0) { errno=EINTR; return -1; }
        if (ba_life_remaining(c, &left) < 0) return -1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
        long long rem = ((long long)until.tv_sec-now.tv_sec)*1000 + (until.tv_nsec-now.tv_nsec)/1000000;
        if (rem <= 0) return 0;
        long slice = rem < 50 ? (long)rem : 50;
        if (slice > left) slice = left;
        struct timespec nap = {slice / 1000, (slice % 1000) * 1000000L};
        if (nanosleep(&nap, NULL) < 0 && errno != EINTR) return -1;
    }
}

/* Never feed protocol data through the shell parser.  Capture a builtin's
   stdout in a private file and reap the exact child even on timeout. */
static int
ba_life_run (ba_lifecycle *c, char **argv, const char *capture)
{
    long left;
    if (ba_life_remaining(c, &left) < 0) return -1;
    FILE *out = fopen (capture, "wb");
    if (!out) { builtin_error ("acme: capture: %s", strerror (errno)); return -1; }
    bos_child_wait wait_state;
    if (bos_child_wait_begin (&wait_state) < 0) { fclose (out); return -1; }
    fflush (stdout); fflush (stderr);
    pid_t pid = fork ();
    if (pid == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() == 1) _exit(125);
        if (dup2 (fileno (out), STDOUT_FILENO) < 0) _exit (125);
        if (fileno (out) != STDOUT_FILENO) fclose (out);
        bos_prepare_child ();
        bos_child_wait_child (&wait_state);
        bos_run_builtin (argv[0], argv, NULL);
        _exit (127);
    }
    int status = 0, rc = -1, saved = errno;
    if (pid > 0) {
        for (;;) {
            rc = waitpid(pid, &status, WNOHANG);
            if (rc == pid || (rc < 0 && errno != EINTR)) break;
            if (ba_life_wait(c, 25) < 0) {
                saved = errno; kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) ;
                rc = -1; errno = saved; break;
            }
        }
        saved = errno;
    }
    fclose (out);
    bos_child_wait_end (&wait_state);
    if (pid < 0 || rc < 0 || !WIFEXITED (status) || WEXITSTATUS (status) != 0) {
        if (pid < 0 || rc < 0) builtin_error ("acme: child: %s", strerror (saved));
        else builtin_error ("acme: %s builtin failed (status %d)", argv[0], WIFEXITED (status) ? WEXITSTATUS (status) : 128 + WTERMSIG (status));
        return -1;
    }
    if (ba_life_remaining(c, &left) < 0) return -1;
    return 0;
}

static int
ba_life_read (const char *path, unsigned char **out, size_t *len, size_t max)
{
    FILE *f = fopen (path, "rb");
    unsigned char *p = NULL; long n;
    if (!f || fseek (f, 0, SEEK_END) || (n = ftell (f)) < 0 || (size_t)n > max || fseek (f, 0, SEEK_SET)) goto fail;
    p = malloc ((size_t)n + 1);
    if (!p || fread (p, 1, (size_t)n, f) != (size_t)n) goto fail;
    p[n] = 0; fclose (f); *out = p; *len = (size_t)n; return 0;
fail:
    free (p); if (f) fclose (f); builtin_error ("acme: cannot read bounded response"); return -1;
}

/* ASCII-only protocol values are copied after JSON unescaping; reject
   controls, invalid Unicode and unrepresentable URL/key bytes. */
static int
ba_life_string (const char *json, const jsmntok_t *t, char *dst, size_t cap)
{
    if (t->type != JSMN_STRING || !cap) return -1;
    size_t o = 0;
    for (int i = t->start; i < t->end; i++) {
        unsigned char c = (unsigned char)json[i];
        if (c == '\\') {
            if (++i >= t->end) return -1;
            c = (unsigned char)json[i];
            if (c == 'u') {
                if (i + 4 >= t->end) return -1;
                int v = 0;
                for (int k = 0; k < 4; k++) { int h = ba_hexval ((unsigned char)json[++i]); if (h < 0) return -1; v = (v << 4) | h; }
                if (v > 0x7e || v < 0x20) return -1;
                c = (unsigned char)v;
            } else if (c != '"' && c != '\\' && c != '/') return -1;
        }
        if (c < 0x20 || c >= 0x7f || o + 1 >= cap) return -1;
        dst[o++] = (char)c;
    }
    dst[o] = 0; return 0;
}

static int
ba_life_equal (const char *json, const jsmntok_t *t, const char *key)
{
    return t->type == JSMN_STRING && (size_t)(t->end - t->start) == strlen (key) &&
           memcmp (json + t->start, key, strlen (key)) == 0;
}

/* Tokens are preorder and their end offsets delimit descendants. */
static int
ba_life_next (const jsmntok_t *t, int count, int i)
{
    int end = t[i].end; i++;
    while (i < count && t[i].start < end) i++;
    return i;
}

static int
ba_life_member (const char *json, const jsmntok_t *t, int count, int obj, const char *key)
{
    if (obj < 0 || obj >= count || t[obj].type != JSMN_OBJECT) return -1;
    int found = -1;
    for (int i = obj + 1; i < count && t[i].start < t[obj].end; ) {
        int val = i + 1;
        if (val >= count || t[i].type != JSMN_STRING || t[val].start >= t[obj].end) return -1;
        if (ba_life_equal (json, &t[i], key)) { if (found >= 0) return -1; found = val; }
        i = ba_life_next (t, count, val);
    }
    return found;
}

static int
ba_life_parse (const unsigned char *body, size_t len, jsmntok_t *tokens)
{
    jsmn_parser p; jsmn_init (&p);
    int n = jsmn_parse (&p, (const char *)body, len, tokens, BA_LIFE_TOKENS);
    size_t first = 0; while (first < len && isspace (body[first])) first++;
    if (n <= 0 || tokens[0].type != JSMN_OBJECT || (size_t)tokens[0].start != first) return -1;
    for (size_t i = (size_t)tokens[0].end; i < len; i++)
        if (!isspace (body[i])) return -1;
    return n;
}

static int
ba_life_get (const unsigned char *body, size_t len, const char *key, char *out, size_t cap)
{
    jsmntok_t t[BA_LIFE_TOKENS]; int n = ba_life_parse (body, len, t);
    if (n < 0) return -1;
    int v = ba_life_member ((const char *)body, t, n, 0, key);
    return v < 0 ? -1 : ba_life_string ((const char *)body, &t[v], out, cap);
}

static int
ba_life_ascii_url (const char *s, int allow_http)
{
    if (strncmp (s, "https://", 8) && !(allow_http && !strncmp (s, "http://", 7))) return 0;
    const char *authority = strstr (s, "://") + 3;
    if (!*authority || *authority == '/' || strchr (authority, '@') || strchr (s, '#')) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p <= 0x20 || *p >= 0x7f || *p == '"' || *p == '\\') return 0;
    return strlen (s) < BA_LIFE_URL;
}

static int
ba_life_domain (const char *s)
{
    size_t n = strlen (s), label = 0;
    if (!n || n > 253) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') { if (!label || label > 63 || s[i-1] == '-') return 0; label = 0; }
        else { if (!(c < 128 && (isalnum(c) || c == '-')) || (!label && c == '-')) return 0; label++; }
    }
    return label && label <= 63 && s[n-1] != '-';
}

static int
ba_life_header (const char *path, const char *name, char *dst, size_t cap)
{
    FILE *f = fopen (path, "rb"); char line[8192]; int found = 0;
    if (!f) return -1;
    while (fgets (line, sizeof line, f)) {
        char *colon = strchr (line, ':');
        if (!colon || (size_t)(colon-line) != strlen (name) || strncasecmp (line, name, strlen(name))) continue;
        char *v = colon + 1; while (*v == ' ' || *v == '\t') v++;
        size_t n = strcspn (v, "\r\n"); while (n && (v[n-1] == ' ' || v[n-1] == '\t')) n--;
        if (found || !n || n >= cap) { fclose (f); return -1; }
        memcpy (dst, v, n); dst[n] = 0; found = 1;
    }
    int bad = ferror (f); fclose (f); return found && !bad ? 0 : -1;
}

/* 0 = absent, 1 = present, -1 = malformed/duplicate. */
static int
ba_life_retry (ba_lifecycle *c, long *delay)
{
    FILE *f=fopen(c->header,"rb"); char line[8192], value[128]={0}; int found=0;
    if (!f) return -1;
    while (fgets(line,sizeof line,f)) {
        size_t ln=strlen(line);
        if (!ln || (line[ln-1]!='\n' && !feof(f))) { fclose(f); return -1; }
        char *colon=strchr(line,':');
        if (!colon || colon-line!=11 || strncasecmp(line,"Retry-After",11)) continue;
        char *v=colon+1; while (*v==' ' || *v=='\t') v++;
        size_t n=strcspn(v,"\r\n"); while (n && (v[n-1]==' ' || v[n-1]=='\t')) n--;
        if (found || !n || n>=sizeof value) { fclose(f); return -1; }
        memcpy(value,v,n); value[n]=0; found=1;
    }
    int bad=ferror(f); fclose(f); if (bad) return -1;
    if (!found) { *delay=250; return 0; }
    if (isdigit((unsigned char)value[0])) {
        unsigned long sec=0;
        for (char *q=value; *q; q++) {
            if (*q<'0' || *q>'9') return -1;
            if (sec <= 600UL) sec=sec*10+(unsigned)(*q-'0');
        }
        if (sec>600UL) sec=600UL;
        *delay=(long)sec*1000; return 1;
    }
    /* HTTP-date has three defined wire forms. Reformat and compare to
       reject malformed or normalized values without depending on locale. */
    static const char *months[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    static const char *days[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char *longdays[]={"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
    char wd[16], mon[4], zone[4], tail, canonical[128];
    int day,year,hour,min,sec,form=0;
    time_t wall=time(NULL); struct tm current;
    if (wall==(time_t)-1 || !gmtime_r(&wall,&current)) return -1;
    if (sscanf(value,"%15[A-Za-z], %2d %3[A-Za-z] %4d %2d:%2d:%2d %3[A-Za-z]%c",wd,&day,mon,&year,&hour,&min,&sec,zone,&tail)==8 && !strcmp(zone,"GMT")) form=1;
    else if (sscanf(value,"%15[A-Za-z], %2d-%3[A-Za-z]-%2d %2d:%2d:%2d %3[A-Za-z]%c",wd,&day,mon,&year,&hour,&min,&sec,zone,&tail)==8 && !strcmp(zone,"GMT")) {
        form=2; year=(current.tm_year+1900)/100*100+year;
        if (year<current.tm_year+1900-49) year+=100;
        if (year>current.tm_year+1900+50) year-=100;
    } else if (sscanf(value,"%15[A-Za-z] %3[A-Za-z] %2d %2d:%2d:%2d %4d%c",wd,mon,&day,&hour,&min,&sec,&year,&tail)==7) form=3;
    if (!form || year<0 || year>9999 || day<1 || day>31 || hour>23 || min>59 || sec>60) return -1;
    int m=-1,w=-1; for(int i=0;i<12;i++) if(!strcmp(mon,months[i])) m=i;
    for(int i=0;i<7;i++) if(!strcmp(wd,form==2 ? longdays[i] : days[i])) w=i;
    if(m<0 || w<0) return -1;
    if (form==1) snprintf(canonical,sizeof canonical,"%s, %02d %s %04d %02d:%02d:%02d GMT",days[w],day,months[m],year,hour,min,sec);
    else if (form==2) snprintf(canonical,sizeof canonical,"%s, %02d-%s-%02d %02d:%02d:%02d GMT",longdays[w],day,months[m],year%100,hour,min,sec);
    else snprintf(canonical,sizeof canonical,"%s %s %2d %02d:%02d:%02d %04d",days[w],months[m],day,hour,min,sec,year);
    if (strcmp(canonical,value)) return -1;
    struct tm t={0}; t.tm_year=year-1900;t.tm_mon=m;t.tm_mday=day;t.tm_hour=hour;t.tm_min=min;t.tm_sec=sec==60 ? 59 : sec;
    errno=0; time_t target=timegm(&t); struct tm check;
    if (form==2 && year==current.tm_year+1900+50) {
        struct tm cutoff=current; cutoff.tm_year+=50;
        time_t limit=timegm(&cutoff);
        if (difftime(target,limit)>0) { year-=100; t.tm_year=year-1900; errno=0; target=timegm(&t); }
    }
    if((target==(time_t)-1 && errno==EOVERFLOW) || !gmtime_r(&target,&check) || check.tm_year!=year-1900 ||
       check.tm_mon!=m || check.tm_mday!=day || check.tm_hour!=hour || check.tm_min!=min || check.tm_sec!=(sec==60 ? 59 : sec) || check.tm_wday!=w) return -1;
    double diff=difftime(target,wall) + (sec==60); if(diff<0) diff=0; if(diff>600) diff=600;
    *delay=(long)diff*1000; return 1;
}

static int
ba_life_poll_delay (ba_lifecycle *c)
{
    long delay;
    if (ba_life_retry(c,&delay)<0) { builtin_error("acme: invalid Retry-After"); return -1; }
    if (delay<50) delay=50; /* avoid a zero-delay busy loop */
    if (ba_life_wait(c,delay)<0) { builtin_error("acme: polling interrupted or deadline expired"); return -1; }
    return 0;
}

static int
ba_life_http (ba_lifecycle *c, const char *method, const char *url, const char *jws,
              unsigned char **body, size_t *body_len)
{
    char *args[24]; int k = 0;
    if (!ba_life_ascii_url (url, c->allow_http)) { builtin_error ("acme: invalid or disallowed URL"); return -1; }
    args[k++] = "curl"; args[k++] = "-sS"; args[k++] = "--max-time"; args[k++] = "10";
    args[k++] = "--connect-timeout"; args[k++] = "5"; args[k++] = "-X"; args[k++] = (char *)method;
    args[k++] = "-D"; args[k++] = c->header; args[k++] = "-o"; args[k++] = c->body;
    args[k++] = "-w"; args[k++] = "%{http_code}";
    if (c->cacert) { args[k++] = "--cacert"; args[k++] = (char *)c->cacert; }
    if (jws) { args[k++] = "-H"; args[k++] = "Content-Type: application/jose+json"; args[k++] = "--data-binary"; args[k++] = (char *)jws; }
    args[k++] = (char *)url; args[k] = NULL;
    if (ba_life_run (c, args, c->capture) < 0) return -1;
    unsigned char *code = NULL; size_t code_len = 0;
    if (ba_life_read (c->capture, &code, &code_len, 3) < 0) return -1;
    if (code_len != 3 || !isdigit(code[0]) || !isdigit(code[1]) || !isdigit(code[2])) { free(code); return -1; }
    c->status = atoi ((char *)code); free (code);
    if (ba_life_header (c->header, "Replay-Nonce", c->nonce, sizeof c->nonce) < 0) c->nonce[0] = 0;
    if (ba_life_read (c->body, body, body_len, BA_LIFE_MAX_BODY) < 0) return -1;
    if (c->status < 200 || c->status >= 300) {
        char problem[128]; int retry = c->status == 400 &&
            ba_life_get (*body,*body_len,"type",problem,sizeof problem)==0 &&
            !strcmp(problem,"urn:ietf:params:acme:error:badNonce");
        free(*body); *body=NULL; *body_len=0;
        if (retry) return -2;
        builtin_error ("acme: HTTP %d for %s", c->status, url); return -1;
    }
    return 0;
}

static int
ba_life_post (ba_lifecycle *c, const char *url, const char *payload, int jwk,
              unsigned char **body, size_t *len)
{
    if (!ba_life_ascii_url (url,c->allow_http) || (!jwk && !ba_life_ascii_url(c->account_url,c->allow_http))) return -1;
    for (int attempt=0; attempt<2; attempt++) {
        if (!c->nonce[0]) {
            unsigned char *discard = NULL; size_t discard_len = 0;
            if (!c->nonce_url[0] || ba_life_http (c, "HEAD", c->nonce_url, NULL, &discard, &discard_len) < 0) return -1;
            free (discard);
        }
        if (!c->nonce[0]) { builtin_error ("acme: missing Replay-Nonce"); return -1; }
        for (const unsigned char *p = (const unsigned char *)c->nonce; *p; p++)
            if (!(*p < 128 && (isalnum (*p) || *p == '-' || *p == '_'))) { builtin_error ("acme: invalid nonce"); return -1; }
        char *a[16]; int n = 0;
        a[n++] = "acme"; a[n++] = "jws-sign"; a[n++] = "-k"; a[n++] = (char *)c->account_key;
        a[n++] = "--url"; a[n++] = (char *)url; a[n++] = "--nonce"; a[n++] = c->nonce;
        if (jwk) a[n++] = "--jwk"; else { a[n++] = "--kid"; a[n++] = c->account_url; }
        if (payload) { a[n++] = "-d"; a[n++] = (char *)payload; } a[n] = NULL;
        if (ba_life_run (c, a, c->capture) < 0) return -1;
        unsigned char *jws = NULL; size_t jlen = 0;
        if (ba_life_read (c->capture, &jws, &jlen, 131072) < 0) return -1;
        while (jlen && (jws[jlen-1] == '\n' || jws[jlen-1] == '\r')) jws[--jlen] = 0;
        int rc = ba_life_http (c, "POST", url, (char *)jws, body, len);
        free (jws);
        if (rc != -2) return rc;
    }
    builtin_error ("acme: repeated badNonce");
    return -1;
}

static int
ba_life_auth_url (const unsigned char *body, size_t len, char *out, size_t cap)
{
    jsmntok_t t[BA_LIFE_TOKENS]; int n = ba_life_parse (body, len, t);
    if (n < 0) return -1;
    int a = ba_life_member ((const char *)body, t, n, 0, "authorizations");
    if (a < 0 || t[a].type != JSMN_ARRAY || a+1 >= n || t[a+1].start >= t[a].end) return -1;
    /* A single identifier produces exactly one authorization in this CLI. */
    if (ba_life_next (t, n, a+1) < n && t[ba_life_next (t, n, a+1)].start < t[a].end) return -1;
    return ba_life_string ((const char *)body, &t[a+1], out, cap);
}

static int
ba_life_challenge (const unsigned char *body, size_t len, char *url, size_t urlcap, char *token, size_t tokcap)
{
    jsmntok_t t[BA_LIFE_TOKENS]; int n = ba_life_parse (body, len, t);
    if (n < 0) return -1;
    int a = ba_life_member ((const char *)body, t, n, 0, "challenges");
    if (a < 0 || t[a].type != JSMN_ARRAY) return -1;
    for (int i = a+1; i < n && t[i].start < t[a].end; i = ba_life_next (t,n,i)) {
        int ty = ba_life_member ((const char *)body,t,n,i,"type");
        int u = ba_life_member ((const char *)body,t,n,i,"url");
        int tk = ba_life_member ((const char *)body,t,n,i,"token");
        if (ty >= 0 && ba_life_equal ((const char *)body,&t[ty],"http-01")) {
            if (u < 0 || tk < 0 || ba_life_string ((const char *)body,&t[u],url,urlcap) < 0 ||
                ba_life_string ((const char *)body,&t[tk],token,tokcap) < 0 || !*token) return -1;
            for (const unsigned char *p = (const unsigned char *)token; *p; p++)
                if (!(*p < 128 && (isalnum (*p) || *p == '-' || *p == '_'))) return -1;
            return 0;
        }
    }
    return -1;
}

static void
ba_life_serve (int fd, const char *token, const char *keyauth)
{
    char expected[1024];
    if (snprintf (expected, sizeof expected, "GET /.well-known/acme-challenge/%s HTTP/", token) >= (int)sizeof expected) _exit (1);
    for (;;) {
        int peer = accept (fd, NULL, NULL);
        if (peer < 0) { if (errno == EINTR) continue; _exit (1); }
        struct timeval timeout = { 2, 0 };
        setsockopt (peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        setsockopt (peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        char req[4096]; size_t used = 0;
        while (used + 1 < sizeof req) {
            ssize_t got = read (peer, req+used, sizeof req-used-1);
            if (got <= 0) break;
            used += (size_t)got; req[used] = 0;
            if (strstr (req, "\r\n\r\n") || strstr (req, "\n\n")) break;
        }
        req[used] = 0;
        const char *data = ""; int ok = !strncmp (req,expected,strlen(expected));
        if (ok) data = keyauth;
        char hdr[256]; int hn = snprintf (hdr,sizeof hdr,
            "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
            ok ? "200 OK" : "404 Not Found", strlen(data));
        if (hn > 0 && hn < (int)sizeof hdr) {
            size_t off = 0; while (off < (size_t)hn) { ssize_t w = send(peer,hdr+off,(size_t)hn-off,MSG_NOSIGNAL); if (w <= 0) break; off += (size_t)w; }
            off = 0; size_t length = strlen (data);
            while (off < length) { ssize_t w = send(peer,data+off,length-off,MSG_NOSIGNAL); if (w <= 0) break; off += (size_t)w; }
        }
        close (peer);
    }
}

static int
ba_life_start_responder (ba_lifecycle *c)
{
    char host[64], auth[1024], canonical[256], thumb[64];
    unsigned char sk[32], x[32], y[32], digest[32];
    const char *sep = strrchr (c->listen_addr, ':');
    if (!sep || sep == c->listen_addr || (size_t)(sep-c->listen_addr) >= sizeof host) return -1;
    memcpy (host,c->listen_addr,(size_t)(sep-c->listen_addr)); host[sep-c->listen_addr] = 0;
    char *end = NULL; errno = 0; long port = strtol (sep+1,&end,10);
    if (errno || !end || *end || port < 1 || port > 65535) return -1;
    if (ba_unhex(c->account_key,sk,sizeof sk) != 32 || ba_ecdsa_p256_xy(sk,x,y) ||
        ba_jwk_canonical(canonical,sizeof canonical,x,y) < 0 ||
        ba_sha256((unsigned char *)canonical,strlen(canonical),digest) ||
        ba_base64url_encode(digest,sizeof digest,thumb,sizeof thumb) < 0 ||
        snprintf(auth,sizeof auth,"%s.%s",c->token,thumb) >= (int)sizeof auth) { memset(sk,0,sizeof sk); return -1; }
    memset(sk,0,sizeof sk);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET,host,&a.sin_addr) != 1) return -1;
    int fd = socket(AF_INET,SOCK_STREAM,0), one = 1;
    if (fd < 0) return -1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    if (bind(fd,(struct sockaddr *)&a,sizeof a) < 0 || listen(fd,8) < 0) { close(fd); return -1; }
    if (bos_child_wait_begin (&c->responder_wait) < 0) { close(fd); return -1; }
    c->responder_waiting = 1;
    fflush(stdout); fflush(stderr);
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == 0) {
        if (prctl(PR_SET_PDEATHSIG,SIGTERM) < 0 || getppid() != parent) _exit(1);
        bos_prepare_child(); bos_child_wait_child(&c->responder_wait);
        signal(SIGTERM,SIG_DFL); signal(SIGPIPE,SIG_IGN);
        ba_life_serve(fd,c->token,auth); _exit(1);
    }
    if (pid < 0) { bos_child_wait_end(&c->responder_wait); c->responder_waiting=0; close(fd); return -1; }
    c->responder = pid; c->responder_fd = fd; close(fd); c->responder_fd=-1;
    return 0;
}

static void
ba_life_stop_responder (ba_lifecycle *c)
{
    if (c->responder > 0) {
        int status; kill(c->responder,SIGTERM);
        while (waitpid(c->responder,&status,0) < 0 && errno == EINTR) ;
        c->responder=0;
    }
    if (c->responder_waiting) { bos_child_wait_end(&c->responder_wait); c->responder_waiting=0; }
}

static void
ba_life_cleanup (void *arg)
{
    ba_lifecycle *c = arg;
    ba_life_stop_responder (c);
    if (c->header[0]) unlink(c->header);
    if (c->body[0]) unlink(c->body);
    if (c->capture[0]) unlink(c->capture);
    if (c->tmp[0]) rmdir(c->tmp);
    memset(c->generated_key,0,sizeof c->generated_key);
}

/* Validate every PEM block before publishing output.  The ACME endpoint and
   certificate trust anchors are independent; never trust a root merely because
   the endpoint returned it.  Accept only the single DNS name requested here. */
#define BA_LIFE_MAX_CERTS 16
static int
ba_life_pem_count (const unsigned char *data, size_t len)
{
    static const char begin[]="-----BEGIN CERTIFICATE-----";
    static const char end[]="-----END CERTIFICATE-----";
    size_t i=0; int count=0;
    if (!data || !len || memchr(data,0,len)) return -1;
    while (i<len) {
        while (i<len && (data[i]==' ' || data[i]=='\t' || data[i]=='\r' || data[i]=='\n')) i++;
        if (i==len) break;
        if (len-i < sizeof begin-1 || memcmp(data+i,begin,sizeof begin-1) || ++count>BA_LIFE_MAX_CERTS) return -1;
        i+=sizeof begin-1;
        if (i>=len || (data[i]!='\r' && data[i]!='\n')) return -1;
        size_t symbols=0;
        while (i<len) {
            if (len-i>=sizeof end-1 && !memcmp(data+i,end,sizeof end-1)) break;
            unsigned char c=data[i++];
            if (c==' ' || c=='\t' || c=='\r' || c=='\n') continue;
            if (!((c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='+' || c=='/' || c=='=')) return -1;
            if (++symbols>262144) return -1;
        }
        if (!symbols || len-i<sizeof end-1) return -1;
        i+=sizeof end-1;
    }
    return count ? count : -1;
}

static int
ba_life_check_certificate (ba_lifecycle *c, const unsigned char *pem, size_t len)
{
    /* ASN.1 SubjectPublicKeyInfo for id-ecPublicKey + prime256v1 followed
       by a 65-byte uncompressed point. DER is canonical, so compare the
       complete algorithm identifier and point, not only a key fingerprint. */
    static const unsigned char spki_prefix[]={
        0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
        0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
    };
    mbedtls_x509_crt cert, trust;
    unsigned char sk[32]={0},x[32],y[32],point[65];
    const char *trust_path=c->cert_ca; uint32_t flags=0; int result=-1, parsed_count=0;
    int expected_count=ba_life_pem_count(pem,len);
    mbedtls_x509_crt_init(&cert); mbedtls_x509_crt_init(&trust);
    if (expected_count<1 || !c->domain || !c->cert_key || psa_crypto_init()!=PSA_SUCCESS) goto done;
    if (mbedtls_x509_crt_parse(&cert,pem,len+1)!=0) goto done;
    for (const mbedtls_x509_crt *p=&cert;p && p->raw.p;p=p->next) parsed_count++;
    if (parsed_count!=expected_count) goto done;
    if (ba_unhex(c->cert_key,sk,sizeof sk)!=32 || ba_ecdsa_p256_xy(sk,x,y)!=0) goto done;
    point[0]=0x04;memcpy(point+1,x,32);memcpy(point+33,y,32);
    if (cert.pk_raw.len != sizeof spki_prefix+sizeof point ||
        memcmp(cert.pk_raw.p,spki_prefix,sizeof spki_prefix) ||
        memcmp(cert.pk_raw.p+sizeof spki_prefix,point,sizeof point)) goto done;
    /* This CLI requests exactly one DNS identifier in its CSR.  Reject CN-only
       certificates, extra identities, embedded NULs and non-DNS GeneralNames. */
    int san_count=0; size_t domain_len=strlen(c->domain);
    for (const mbedtls_x509_sequence *san=&cert.subject_alt_names;san && san->buf.p;san=san->next) {
        if (san->buf.tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC|MBEDTLS_X509_SAN_DNS_NAME) ||
            san->buf.len != domain_len || memchr(san->buf.p,0,san->buf.len) ||
            strncasecmp((const char *)san->buf.p,c->domain,domain_len)) goto done;
        san_count++;
    }
    if (san_count!=1) goto done;
    if (!trust_path) {
        if (access("/etc/ssl/cert.pem",R_OK)==0) trust_path="/etc/ssl/cert.pem";
        else if (access("/etc/ssl/certs/ca-certificates.crt",R_OK)==0) trust_path="/etc/ssl/certs/ca-certificates.crt";
    }
    if (!trust_path) goto done;
    int trust_rc=mbedtls_x509_crt_parse_file(&trust,trust_path);
    /* A caller-supplied fixture or private trust bundle must parse in full.
       System bundles may contain unsupported roots; a successful chain still
       has to terminate at one of the anchors actually parsed. */
    if (trust_rc<0 || (c->cert_ca && trust_rc!=0) || !trust.raw.p) goto done;
    /* Verify every adjacent presented certificate using the verifier's X.509
       name comparison and signature rules; reject unrelated trailing PEM.
       Shallow copies are read-only and are never freed. */
    mbedtls_x509_crt *top=&cert;
    for (mbedtls_x509_crt *p=&cert;p && p->next;p=p->next) {
        mbedtls_x509_crt child=*p, parent=*p->next; child.next=NULL; parent.next=NULL;
        flags=0;
        if (mbedtls_x509_crt_verify(&child,&parent,NULL,NULL,&flags,NULL,NULL)!=0 || flags) goto done;
        top=p->next;
    }
    /* The highest supplied certificate must itself validate against the
       independently configured anchors; otherwise the full verifier can
       skip a corrupted or extraneous top certificate when a root is local. */
    mbedtls_x509_crt top_only=*top; top_only.next=NULL; flags=0;
    if (mbedtls_x509_crt_verify(&top_only,&trust,NULL,NULL,&flags,NULL,NULL)!=0 || flags) goto done;
    flags=0;
    if (mbedtls_x509_crt_verify(&cert,&trust,NULL,c->domain,&flags,NULL,NULL)!=0 || flags) goto done;
    result=0;
done:
    memset(sk,0,sizeof sk);memset(point,0,sizeof point);
    mbedtls_x509_crt_free(&cert);mbedtls_x509_crt_free(&trust);
    if (result<0) builtin_error("acme: issued certificate validation failed");
    return result;
}

static int
ba_life_store (const char *outdir, const unsigned char *data, size_t len)
{
    if (!outdir || !*outdir || len < 27 || memcmp(data,"-----BEGIN CERTIFICATE-----",27)) return -1;
    if (mkdir(outdir,0700) < 0 && errno != EEXIST) return -1;
    int dir = open(outdir,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st; if (fstat(dir,&st)<0 || st.st_uid!=geteuid() || (st.st_mode&0022)) { close(dir); return -1; }
    int fd = openat(dir,"fullchain.pem",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd < 0) { close(dir); return -1; }
    size_t off=0; int ok=1;
    while (off < len) { ssize_t w=write(fd,data+off,len-off); if (w < 0 && errno==EINTR) continue; if (w <= 0) { ok=0; break; } off+=(size_t)w; }
    if (close(fd)<0) ok=0;
    if (!ok) unlinkat(dir,"fullchain.pem",0);
    close(dir); return ok ? 0 : -1;
}

static int
ba_life_save_key (ba_lifecycle *c)
{
    char *a[] = {"crypto","ecdsa-p256-key-pem","-k",(char *)c->cert_key,NULL};
    unsigned char *pem=NULL; size_t len=0; int dir=-1,fd=-1,ok=0,created=0;
    if (ba_life_run(c,a,c->capture)<0 || ba_life_read(c->capture,&pem,&len,8192)<0) goto done;
    if (!len || (mkdir(c->outdir,0700)<0 && errno!=EEXIST)) goto done;
    dir=open(c->outdir,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dir<0) goto done;
    struct stat st; if (fstat(dir,&st)<0 || st.st_uid!=geteuid() || (st.st_mode&0022)) goto done;
    fd=openat(dir,"privkey.pem",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0) goto done;
    created=1;
    size_t off=0;
    while (off<len) { ssize_t w=write(fd,pem+off,len-off); if(w<0&&errno==EINTR)continue; if(w<=0)goto done; off+=(size_t)w; }
    if (close(fd)<0) { fd=-1; goto done; }
    fd=-1; ok=1;
done:
    if (fd>=0) close(fd);
    if (!ok && created && dir>=0) unlinkat(dir,"privkey.pem",0);
    if (dir>=0) close(dir);
    if (pem) { memset(pem,0,len); free(pem); }
    return ok ? 0 : -1;
}

/* Remove only the key just created by this invocation when the matching
   certificate could not be installed. */
static void
ba_life_rollback_key (const char *outdir)
{
    int dir = open(outdir,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dir>=0) { struct stat st; if (fstat(dir,&st)==0 && st.st_uid==geteuid() && !(st.st_mode&0022)) unlinkat(dir,"privkey.pem",0); close(dir); }
}

static int
ba_life_random_key (char key[65])
{
    static const char hex[]="0123456789abcdef";
    unsigned char sk[32],x[32],y[32];
    for (int attempt=0;attempt<64;attempt++) {
        size_t off=0;
        while (off<sizeof sk) { ssize_t n=getrandom(sk+off,sizeof sk-off,0); if(n<0&&errno==EINTR)continue; if(n<=0){memset(sk,0,sizeof sk);return -1;} off+=(size_t)n; }
        if (ba_ecdsa_p256_xy(sk,x,y)==0) {
            for (size_t i=0;i<sizeof sk;i++) {key[2*i]=hex[sk[i]>>4];key[2*i+1]=hex[sk[i]&15];}
            key[64]=0;memset(sk,0,sizeof sk);return 0;
        }
    }
    memset(sk,0,sizeof sk);return -1;
}

static int
ba_lifecycle_cmd (const char *cmd, WORD_LIST *args)
{
    ba_lifecycle c; memset(&c,0,sizeof c); c.responder_fd=-1;
    c.outdir="issued"; c.listen_addr="0.0.0.0:80";
    const char *directory=NULL; int rc=EXECUTION_FAILURE, level=0;
    unsigned long timeout=120;
    char account_endpoint[BA_LIFE_URL]={0}, order_endpoint[BA_LIFE_URL]={0};
    char authz_url[BA_LIFE_URL]={0}, auth_status[64]={0}, order_status[64]={0};
    char account_payload[]="{\"termsOfServiceAgreed\":true}";
    char order_payload[1024];
    unsigned char *body=NULL; size_t len=0;
    if (!strcmp(cmd,"directory")) level=0;
    else if (!strcmp(cmd,"nonce")) level=1;
    else if (!strcmp(cmd,"account")) level=2;
    else if (!strcmp(cmd,"order")) level=3;
    else if (!strcmp(cmd,"challenge")) level=4;
    else if (!strcmp(cmd,"finalize")) level=5;
    else if (!strcmp(cmd,"issue")) level=6;
    else return EX_USAGE;
    for (WORD_LIST *p=args;p;p=p->next) {
        const char *w=p->word->word;
        if (!strcmp(w,"--allow-http")) { c.allow_http=1; continue; }
        if (!strcmp(w,"--directory") || !strcmp(w,"-k") || !strcmp(w,"--domain") ||
            !strcmp(w,"--timeout") || !strcmp(w,"--out") || !strcmp(w,"--cert-key") || !strcmp(w,"--cacert") || !strcmp(w,"--cert-ca") || !strcmp(w,"--http-listen")) {
            if (!p->next) { builtin_error("acme: %s needs a value",w); return EX_USAGE; }
            const char *v=(p=p->next)->word->word;
            if (!strcmp(w,"--timeout")) { char *end; errno=0; timeout=strtoul(v,&end,10); if (errno || !*v || *v<'0' || *v>'9' || *end || timeout<1 || timeout>600) { builtin_error("acme: timeout must be 1..600 seconds"); return EX_USAGE; } }
            else if (!strcmp(w,"--directory")) directory=v;
            else if (!strcmp(w,"-k")) c.account_key=v;
            else if (!strcmp(w,"--domain")) c.domain=v;
            else if (!strcmp(w,"--out")) c.outdir=v;
            else if (!strcmp(w,"--cert-key")) c.cert_key=v;
            else if (!strcmp(w,"--cacert")) c.cacert=v;
            else if (!strcmp(w,"--cert-ca")) c.cert_ca=v;
            else c.listen_addr=v;
        } else if (!directory && level==0 && w[0]!='-') directory=w;
        else { builtin_error("acme: unexpected argument: %s",w); return EX_USAGE; }
    }
    if (!directory || !ba_life_ascii_url(directory,c.allow_http) ||
        (level>=2 && !c.account_key) || (level>=3 && (!c.domain || !ba_life_domain(c.domain)))) {
        builtin_error("acme: valid directory, account key and domain are required"); return EX_USAGE;
    }
    if (snprintf(c.directory,sizeof c.directory,"%s",directory) >= (int)sizeof c.directory) return EX_USAGE;
    if (level==6) {
        const char *trust_path=c.cert_ca;
        if (!trust_path) {
            if (access("/etc/ssl/cert.pem",R_OK)==0) trust_path="/etc/ssl/cert.pem";
            else if (access("/etc/ssl/certs/ca-certificates.crt",R_OK)==0) trust_path="/etc/ssl/certs/ca-certificates.crt";
        }
        if (!trust_path || access(trust_path,R_OK)<0) { builtin_error("acme: certificate trust anchors unavailable"); return EXECUTION_FAILURE; }
    }
    if (level>=2) {
        unsigned char sk[32],x[32],y[32]; int valid=ba_unhex(c.account_key,sk,sizeof sk)==32 && ba_ecdsa_p256_xy(sk,x,y)==0;
        memset(sk,0,sizeof sk); if (!valid) {builtin_error("acme: invalid account key");return EX_USAGE;}
    }
    if (clock_gettime(CLOCK_MONOTONIC,&c.deadline)<0) return EXECUTION_FAILURE;
    c.deadline.tv_sec += timeout;
    snprintf(c.tmp,sizeof c.tmp,"/tmp/bashos-acme-XXXXXX");
    if (!mkdtemp(c.tmp)) { builtin_error("acme: temporary directory: %s",strerror(errno)); return EXECUTION_FAILURE; }
    snprintf(c.header,sizeof c.header,"%s/headers",c.tmp);
    snprintf(c.body,sizeof c.body,"%s/body",c.tmp);
    snprintf(c.capture,sizeof c.capture,"%s/capture",c.tmp);
    begin_unwind_frame ("acme lifecycle");
    add_unwind_protect (ba_life_cleanup, &c);
    if (ba_life_http(&c,"GET",c.directory,NULL,&body,&len)<0) goto done;
    if (ba_life_get(body,len,"newNonce",c.nonce_url,sizeof c.nonce_url)<0 ||
        ba_life_get(body,len,"newAccount",account_endpoint,sizeof account_endpoint)<0 ||
        ba_life_get(body,len,"newOrder",order_endpoint,sizeof order_endpoint)<0 ||
        !ba_life_ascii_url(c.nonce_url,c.allow_http) || !ba_life_ascii_url(account_endpoint,c.allow_http) ||
        !ba_life_ascii_url(order_endpoint,c.allow_http)) { builtin_error("acme: invalid directory"); goto done; }
    if (level==0) { if (fwrite(body,1,len,stdout)!=len || putchar('\n')==EOF) goto done; rc=EXECUTION_SUCCESS; goto done; }
    free(body); body=NULL;
    if (ba_life_http(&c,"HEAD",c.nonce_url,NULL,&body,&len)<0 || !c.nonce[0]) { builtin_error("acme: nonce request failed");goto done; }
    free(body);body=NULL;
    if (level==1) { puts(c.nonce);rc=EXECUTION_SUCCESS;goto done; }
    if (ba_life_post(&c,account_endpoint,account_payload,1,&body,&len)<0 ||
        ba_life_header(c.header,"Location",c.account_url,sizeof c.account_url)<0 ||
        !ba_life_ascii_url(c.account_url,c.allow_http)) { builtin_error("acme: account request failed");goto done; }
    free(body);body=NULL;
    if(level==2) {puts(c.account_url);rc=EXECUTION_SUCCESS;goto done;}
    if (snprintf(order_payload,sizeof order_payload,"{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}",c.domain) >= (int)sizeof order_payload) goto done;
    if (ba_life_post(&c,order_endpoint,order_payload,0,&body,&len)<0 ||
        ba_life_header(c.header,"Location",c.order_url,sizeof c.order_url)<0 ||
        ba_life_auth_url(body,len,authz_url,sizeof authz_url)<0 ||
        ba_life_get(body,len,"finalize",c.finalize_url,sizeof c.finalize_url)<0 ||
        !ba_life_ascii_url(c.order_url,c.allow_http) || !ba_life_ascii_url(authz_url,c.allow_http) ||
        !ba_life_ascii_url(c.finalize_url,c.allow_http)) { builtin_error("acme: order response invalid");goto done; }
    free(body);body=NULL;
    if (ba_life_post(&c,authz_url,NULL,0,&body,&len)<0 || ba_life_get(body,len,"status",auth_status,sizeof auth_status)<0) goto done;
    if (level>=4 && strcmp(auth_status,"valid")) {
        if (strcmp(auth_status,"pending") || ba_life_challenge(body,len,c.challenge_url,sizeof c.challenge_url,c.token,sizeof c.token)<0 ||
            !ba_life_ascii_url(c.challenge_url,c.allow_http)) { builtin_error("acme: no usable HTTP-01 challenge"); goto done; }
    }
    free(body);body=NULL;
    if(level==3) {
        if (ba_life_post(&c,c.order_url,NULL,0,&body,&len)<0) goto done;
        puts(c.order_url);rc=EXECUTION_SUCCESS;goto done;
    }
    if (strcmp(auth_status,"valid")) {
        if (ba_life_start_responder(&c)<0) { builtin_error("acme: HTTP-01 listener failed: %s",strerror(errno)); goto done; }
        if (ba_life_post(&c,c.challenge_url,"{}",0,&body,&len)<0) goto done;
        if (ba_life_get(body,len,"status",auth_status,sizeof auth_status)<0 ||
            (strcmp(auth_status,"pending") && strcmp(auth_status,"processing") && strcmp(auth_status,"valid"))) {
            builtin_error("acme: challenge rejected"); goto done;
        }
        free(body);body=NULL;
        if (strcmp(auth_status,"valid") && ba_life_poll_delay(&c)<0) goto done;
        for (;;) {
            if (ba_life_post(&c,authz_url,NULL,0,&body,&len)<0 || ba_life_get(body,len,"status",auth_status,sizeof auth_status)<0) goto done;
            free(body);body=NULL;
            if (!strcmp(auth_status,"valid")) break;
            if (strcmp(auth_status,"pending") && strcmp(auth_status,"processing")) {builtin_error("acme: authorization rejected");goto done;}
            if (ba_life_poll_delay(&c)<0) goto done;
        }
        ba_life_stop_responder(&c);
    }
    if(level==4) {puts(c.challenge_url);rc=EXECUTION_SUCCESS;goto done;}
    if (!c.cert_key) { if(ba_life_random_key(c.generated_key)<0) goto done; c.cert_key=c.generated_key; }
    {
        char *a[]={"crypto","x509-csr","-k",(char *)c.cert_key,"-d",(char *)c.domain,"--der",NULL};
        unsigned char *der=NULL;size_t dlen=0;
        if (ba_life_run(&c,a,c.capture)<0 || ba_life_read(c.capture,&der,&dlen,16384)<0) goto done;
        size_t cap=((dlen+2)/3)*4+4; char *b64=malloc(cap), *payload=malloc(cap+16);
        if (!b64 || !payload || ba_base64url_encode(der,dlen,b64,cap)<0) {free(der);free(b64);free(payload);goto done;}
        free(der);snprintf(payload,cap+16,"{\"csr\":\"%s\"}",b64);free(b64);
        int sent=ba_life_post(&c,c.finalize_url,payload,0,&body,&len);free(payload);
        if(sent<0)goto done;
    }
    if (ba_life_get(body,len,"status",order_status,sizeof order_status)<0 ||
        (strcmp(order_status,"valid") && strcmp(order_status,"pending") && strcmp(order_status,"processing") && strcmp(order_status,"ready"))) {
        builtin_error("acme: order rejected"); goto done;
    }
    free(body);body=NULL;
    if (strcmp(order_status,"valid") && ba_life_poll_delay(&c)<0) goto done;
    for (;;) {
        if (ba_life_post(&c,c.order_url,NULL,0,&body,&len)<0 || ba_life_get(body,len,"status",order_status,sizeof order_status)<0) goto done;
        if (!strcmp(order_status,"valid")) {
            if (ba_life_get(body,len,"certificate",c.cert_url,sizeof c.cert_url)<0 || !ba_life_ascii_url(c.cert_url,c.allow_http)) goto done;
            break;
        }
        if (strcmp(order_status,"pending") && strcmp(order_status,"processing") && strcmp(order_status,"ready")) {builtin_error("acme: order rejected");goto done;}
        free(body);body=NULL;
        if (ba_life_poll_delay(&c)<0) goto done;
    }
    free(body);body=NULL;
    if(level==5) {
        if (ba_life_save_key(&c)<0) {builtin_error("acme: cannot save certificate key");goto done;}
        puts(c.order_url);rc=EXECUTION_SUCCESS;goto done;
    }
    if (ba_life_post(&c,c.cert_url,NULL,0,&body,&len)<0) {builtin_error("acme: cannot download certificate chain");goto done;}
    if (ba_life_check_certificate(&c,body,len)<0) goto done;
    { long remaining; if (ba_life_remaining(&c,&remaining)<0) goto done; }
    if (ba_life_save_key(&c)<0) {builtin_error("acme: cannot save certificate key");goto done;}
    if (ba_life_store(c.outdir,body,len)<0) {ba_life_rollback_key(c.outdir);builtin_error("acme: cannot store certificate chain");goto done;}
    puts(c.cert_url);rc=EXECUTION_SUCCESS;
done:
    free(body);
    run_unwind_frame ("acme lifecycle");
    return sh_chkwrite (rc);
}

/* ----- builtin entry -------------------------------------------- */

int
acme_builtin (WORD_LIST *list)
{
    if (list == 0) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (cmd, "directory") || !strcmp (cmd, "nonce") ||
        !strcmp (cmd, "account") || !strcmp (cmd, "order") ||
        !strcmp (cmd, "challenge") || !strcmp (cmd, "finalize") ||
        !strcmp (cmd, "issue")) return ba_lifecycle_cmd (cmd, args);

    if (!strcmp (cmd, "jwk-thumbprint"))     return ba_jwk_thumbprint_cmd (args);
    if (!strcmp (cmd, "jwk-public"))         return ba_jwk_public_cmd (args);
    if (!strcmp (cmd, "key-authorization"))  return ba_key_authorization_cmd (args);
    if (!strcmp (cmd, "jws-extract-key-authorization"))
                                              return ba_key_authorization_cmd (args);
    if (!strcmp (cmd, "jws-sign"))           return ba_jws_sign_cmd (args);

    builtin_error ("unknown subcommand: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *acme_doc[] = {
    "ACME lifecycle and JOSE/JWS + JWK primitives (RFC 8555).",
    "",
    "Subcommands:",
    "    acme jwk-public         -k SK_HEX",
    "                                emit canonical {crv,kty,x,y} JWK JSON",
    "    acme jwk-thumbprint     -k SK_HEX",
    "                                base64url(SHA-256(canonical JWK)) (RFC 7638)",
    "    acme key-authorization  TOKEN -k SK_HEX",
    "                                TOKEN + '.' + thumbprint (RFC 8555 §8.1)",
    "    acme jws-sign           -k SK_HEX --url URL --nonce N",
    "                                [--kid KID | --jwk] [-d DATA | -f FILE]",
    "                                emit flattened JSON JWS for an ACME POST",
    "",
    "    directory URL [--allow-http]",
    "    nonce --directory URL [--allow-http]",
    "    account|order|challenge|finalize|issue --directory URL -k SK_HEX",
    "        [--domain DNS] [--cert-key SK_HEX] [--out DIR]",
    "        [--cacert FILE] [--cert-ca FILE] [--allow-http]",
    "        [--http-listen IPV4:PORT] [--timeout SECONDS]",
    "    --timeout bounds the lifecycle (1..600 seconds; default 120).",
    "    --cert-ca supplies certificate trust anchors separately from TLS trust;",
    "    the default is the system CA bundle.",
    "    HTTP-01 defaults to 0.0.0.0:80. Certificate keys are generated",
    "    separately unless --cert-key supplies a P-256 private key.",
    (char *) NULL
};

struct builtin acme_struct = {
    "acme",
    acme_builtin,
    BUILTIN_ENABLED,
    acme_doc,
    "acme SUBCOMMAND [FLAGS...]",
    0
};
