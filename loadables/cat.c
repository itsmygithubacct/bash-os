/* SPDX-License-Identifier: MIT */
/* Concatenate files with GNU's common display options. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "loadables.h"
#include "shim-prog-name.h"
#include "gnu-longopt.h"

struct cat_state {
    int number, nonblank, squeeze, ends, tabs, visible;
    int line_start, blank;
    int pending_cr;     /* -E: a CR held back to see whether LF follows */
    unsigned long long line;
};

#define CAT_OUTPUT(call) do { \
    (call); \
    if (ferror(stdout)) { \
        *write_errno = errno ? errno : EIO; \
        return 1; \
    } \
} while (0)

static int cat_copy(int fd, const char *name, struct cat_state *s, int *write_errno)
{
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        /* GNU names the operand ("-" for standard input): cat: DIR: Is a directory. */
        if (n < 0) { builtin_error("%s: %s", name, strerror(errno)); return 1; }
        if (!n) return 0;
        if (!(s->number || s->nonblank || s->squeeze || s->ends || s->tabs || s->visible)) {
            if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n || ferror(stdout)) {
                *write_errno = errno ? errno : EIO;
                return 1;
            }
            continue;
        }
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (s->line_start) {
                if (c == '\n') {
                    if (s->squeeze && s->blank) continue;
                    s->blank = 1;
                } else s->blank = 0;
                if ((s->number || s->nonblank) && (!s->nonblank || c != '\n'))
                    CAT_OUTPUT(printf("%6llu\t", ++s->line));
                s->line_start = 0;
            }
            /* GNU cat 9.x: -E shows the CR of a CRLF line end as ^M (as -v
               would), so "a\r\n" ends "a^M$"; any other CR is kept. The
               held CR carries over to the next file, as in GNU. */
            if (s->pending_cr) {
                s->pending_cr = 0;
                CAT_OUTPUT(fputs(c == '\n' ? "^M" : "\r", stdout));
            }
            if (c == '\r' && s->ends && !s->visible) { s->pending_cr = 1; continue; }
            if (c == '\n') {
                if (s->ends) CAT_OUTPUT(putchar('$'));
                CAT_OUTPUT(putchar('\n')); s->line_start = 1;
            } else if (c == '\t') {
                if (s->tabs) CAT_OUTPUT(fputs("^I", stdout)); else CAT_OUTPUT(putchar(c));
            } else if (s->visible) {
                if (c >= 128) { CAT_OUTPUT(fputs("M-", stdout)); c -= 128; }
                if (c < 32) { CAT_OUTPUT(putchar('^')); CAT_OUTPUT(putchar(c + 64)); }
                else if (c == 127) CAT_OUTPUT(fputs("^?", stdout));
                else CAT_OUTPUT(putchar(c));
            } else CAT_OUTPUT(putchar(c));
        }
    }
}

/* GNU cat's long options, in GNU's order (an ambiguous prefix lists them
   in this order). */
static const struct bos_longopt cat_longopts[] = {
    { "number-nonblank", BOS_NO_ARG, 'b' },
    { "number", BOS_NO_ARG, 'n' },
    { "squeeze-blank", BOS_NO_ARG, 's' },
    { "show-nonprinting", BOS_NO_ARG, 'v' },
    { "show-ends", BOS_NO_ARG, 'E' },
    { "show-tabs", BOS_NO_ARG, 'T' },
    { "show-all", BOS_NO_ARG, 'A' },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

int cat_builtin(WORD_LIST *list)
{
    struct cat_state s = { .line_start = 1 };
    const char *stdin_only[] = { "-", NULL };
    const char **files;
    size_t used;
    int rc = 0, write_errno = 0, c;
    bos_getopt g;

    /* glibc getopt_long scanning: clusters, options after operands,
       abbreviated long options, "--"; its diagnostics and the Try line. */
    bos_getopt_init(&g, bos_shim_prog_name("cat"), "benstuvAET", cat_longopts, list);
    while ((c = bos_getopt_next(&g)) != -1) switch (c) {
        case 'n': s.number = 1; break;
        case 'b': s.nonblank = 1; break;
        case 's': s.squeeze = 1; break;
        case 'E': s.ends = 1; break;
        case 'T': s.tabs = 1; break;
        case 'v': s.visible = 1; break;
        case 'A': s.visible = s.ends = s.tabs = 1; break;
        case 'e': s.visible = s.ends = 1; break;
        case 't': s.visible = s.tabs = 1; break;
        case 'u': break;
        case BOS_OPT_HELP:
            puts("Usage: cat [-AbEnstTuv] [FILE...]\nConcatenate FILEs, or standard input. Use -- before option-like filenames.");
            goto done;
        case BOS_OPT_VERSION: puts("cat (bash-os) 0.1.1"); goto done;
        default: rc = 1; goto done;
    }
    files = g.noperands ? (const char **)g.operands : stdin_only;
    used = g.noperands ? (size_t)g.noperands : 1;
    for (size_t i = 0; i < used; i++) {
        int fd = !strcmp(files[i], "-") ? 0 : open(files[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) { builtin_error("%s: %s", files[i], strerror(errno)); rc = 1; continue; }
        struct stat src, dst;
        if (!fstat(fd, &src) && !fstat(1, &dst) && S_ISREG(dst.st_mode) &&
            src.st_dev == dst.st_dev && src.st_ino == dst.st_ino) {
            builtin_error("%s: input file is output file", files[i]);
            if (fd) close(fd);
            rc = 1; continue;
        }
        rc |= cat_copy(fd, files[i], &s, &write_errno);
        if (fd != 0 && close(fd) < 0) rc = 1;
        if (write_errno) break;
    }
    if (s.pending_cr && !write_errno) putchar('\r');
done:
    bos_getopt_free(&g);
    int flush_failed = fflush(stdout);
    if (write_errno || flush_failed || ferror(stdout)) {
        if (!write_errno) write_errno = errno ? errno : EIO;
        /* GNU's line, without the shell's source prefix. */
        fprintf(stderr, "cat: write error: %s\n", strerror(write_errno));
        clearerr(stdout); rc = 1;
    }
    return rc;
}

char *cat_doc[] = {
    "Concatenate FILEs (or stdin). -- ends option parsing; '-' reads stdin.",
    "-n number lines; -b number nonblank; -s squeeze blank lines; -E show ends;",
    "-T show tabs; -v show nonprinting bytes; -A equals -vET; -u is ignored.",
    "-E also shows the CR of a CRLF line end as ^M (GNU 9.x).",
    NULL
};
struct builtin cat_struct = {
    "cat", cat_builtin, BUILTIN_ENABLED, cat_doc, "cat [-AbEnstTuv] [FILE...]", 0
};
