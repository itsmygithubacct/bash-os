/* SPDX-License-Identifier: MIT */
/* GNU-compatible base64 command; bashbase64 retains its unwrapped default. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "loadables.h"
#include "base64-codec.h"
#include "shim-prog-name.h"
#include "gnu-longopt.h"

/* Decode incrementally, including concatenated padded groups. Only LF is
   ignored without -i. Emit each completed byte even if a later byte is bad. */
static int base64_decode(int fd, int ignore)
{
    unsigned char input[16384], output[16384];
    size_t used = 0;
    unsigned bits = 0;
    int count = 0, need_pad = 0, invalid = 0;
    for (;;) {
        ssize_t n = read(fd, input, sizeof input);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); return 1; }
        if (!n) break;
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = input[i];
            if (c == '\n') continue;
            int value = b64_lookup(c, 0);
            if (value < 0 && c != '=' && ignore) continue;
            if (need_pad) {
                if (c != '=') { invalid = 1; break; }
                need_pad = count = 0;
                continue;
            }
            if (c == '=') {
                if (count == 2) need_pad = 1;
                else if (count == 3) count = 0;
                else { invalid = 1; break; }
                continue;
            }
            if (value < 0) { invalid = 1; break; }
            bits = (bits << 6) | (unsigned)value;
            count++;
            if (count >= 2) output[used++] = (unsigned char)(bits >> (8 - 2 * count));
            if (count == 4) count = 0;
        }
        if (b64_write_all(1, (const char *)output, used) < 0) return 1;
        used = 0;
        if (invalid) break;
    }
#ifdef BASHOS_BASE64_REQUIRE_PADDING
    if (count) invalid = 1;
#endif
    if (invalid || need_pad || count == 1) {
        builtin_error("invalid input");
        return 1;
    }
    return 0;
}

/* GNU takes any decimal count; one too large for an int wraps nowhere. */
static int base64_width(const char *s, int *width)
{
    const char *t = s;
    char *end;
    while (*t == ' ' || (*t >= '\t' && *t <= '\r')) t++;
    if (!*s || *t == '-') return -1;
    errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (*end) return -1;
    *width = errno == ERANGE || n > INT_MAX ? INT_MAX : (int)n;
    return 0;
}

static const struct bos_longopt base64_longopts[] = {
    { "decode", BOS_NO_ARG, 'd' },
    { "wrap", BOS_REQ_ARG, 'w' },
    { "ignore-garbage", BOS_NO_ARG, 'i' },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

int base64_builtin(WORD_LIST *list)
{
    int decode = 0, ignore = 0, wrap = 76, c, rc;
    const char *file = NULL, *prog = bos_shim_prog_name("base64");
    bos_getopt g;

    /* glibc getopt_long scanning and diagnostics, as GNU base64: every
       option is read (wherever it is) before the operands are checked. */
    bos_getopt_init(&g, prog, "diw:", base64_longopts, list);
    while ((c = bos_getopt_next(&g)) != -1) {
        switch (c) {
        case 'd': decode = 1; break;
        case 'i': ignore = 1; break;
        case 'w':
            if (base64_width(g.optarg, &wrap) < 0) {
                char *q = bos_quote(g.optarg);
                builtin_error("invalid wrap size: %s", q ? q : g.optarg);
                free(q);
                bos_getopt_free(&g);
                return 1;
            }
            break;
        case BOS_OPT_HELP:
            bos_getopt_free(&g);
            puts("Usage: base64 [-di] [-w COLS] [FILE]\nEncode or decode FILE, or standard input. Default wrap: 76.\n-d, --decode  -i, --ignore-garbage  -w, --wrap=COLS (0 disables wrapping)");
            return fflush(stdout) ? 1 : 0;
        case BOS_OPT_VERSION:
            bos_getopt_free(&g);
            puts("base64 (bash-os) 0.1.1"); return fflush(stdout) ? 1 : 0;
        default:
            bos_getopt_free(&g);
            return 1;
        }
    }
    if (g.noperands > 1) {
        char *q = bos_quote(g.operands[1]);
        builtin_error("extra operand %s", q ? q : g.operands[1]);
        free(q);
        bos_shim_try_help("base64");
        bos_getopt_free(&g);
        return 1;
    }
    if (g.noperands) file = g.operands[0];
    int fd = !file || !strcmp(file, "-") ? 0 : open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error("%s: %s", file, strerror(errno));
        bos_getopt_free(&g);
        return 1;
    }
    rc = decode ? base64_decode(fd, ignore) : b64_encode(fd, 1, 0, wrap);
    if (fd != 0 && close(fd) < 0) rc = 1;
    bos_getopt_free(&g);
    return rc;
}

char *base64_doc[] = {
    "RFC 4648 base64 with GNU wrapping, decoding and ignore-garbage options.",
    "With no FILE or FILE '-', read standard input. Default line width is 76.",
    NULL
};
struct builtin base64_struct = {
    "base64", base64_builtin, BUILTIN_ENABLED, base64_doc,
    "base64 [-di] [-w COLS] [FILE]", 0
};
