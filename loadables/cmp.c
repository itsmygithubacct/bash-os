/* bashcmp.c — POSIX cmp(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashcmp [-l|-s] FILE1 FILE2 [SKIP1 [SKIP2]]
 *
 *   -l      list every diff: "<offset> <oct1> <oct2>" (1-indexed bytes,
 *           octal byte values without leading zero per POSIX).
 *   -s      silent: no output, only exit code.
 *
 *   SKIP1   skip first SKIP1 bytes of FILE1.
 *   SKIP2   skip first SKIP2 bytes of FILE2.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Matches POSIX exactly.
 *
 * The first-difference line reads "FILE1 FILE2 differ: byte N, line M",
 * the wording of GNU diffutils 3.4 and later. Like GNU cmp, the C/POSIX
 * message locale keeps POSIX's "char" instead of "byte".
 *
 * Either FILE may be "-" to read stdin (but only one — POSIX).
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
#include <locale.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"
#include "gnu-longopt.h"
#include "shim-prog-name.h"

/* GNU diffutils says "byte", except in the C/POSIX message locale, where
   POSIX requires "char". */
static const char *
bcm_unit_word (void)
{
    const char *loc = setlocale (LC_MESSAGES, NULL);
    if (loc && strcmp (loc, "C") && strcmp (loc, "POSIX"))
        return "byte";
    /* musl reports LC_MESSAGES as "C" for C.UTF-8, which has no message
       catalog there; glibc (whose cmp this follows) treats C.UTF-8 as a
       real locale and says "byte". Look at the name the shell asked for. */
    const char *names[] = { "LC_ALL", "LC_MESSAGES", "LANG" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        const char *v = get_string_value (names[i]);
        if (v && *v)
            return !strncmp (v, "C.", 2) ? "byte" : "char";
    }
    return "char";
}

/* A byte count as diffutils documents SKIP and LIMIT: decimal, octal or
   hex, optionally followed by a multiplier: K, M, G, T, P, E (powers of
   1024, also written KiB, MiB, ...) or kB, KB, MB, GB, ... (powers of
   1000). */
static int
bcm_parse_skip (const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s || s[0] == '-' || s[0] == '+' || s[0] == ' ' || s[0] == '\t')
        return -1;
    errno = 0;
    v = strtoull (s, &end, 0);
    if (errno == ERANGE || !end || end == s)
        return -1;
    if (*end) {
        static const char units[] = "KMGTPE";
        char u = end[0] == 'k' ? 'K' : end[0];
        const char *at = u ? strchr (units, u) : NULL;
        unsigned base = 1024;
        if (!at)
            return -1;
        if (!strcmp (end + 1, "B"))
            base = 1000;
        else if (end[1] && strcmp (end + 1, "iB"))
            return -1;
        else if (end[0] == 'k' && !end[1])
            return -1;
        for (int i = 0; i <= at - units; i++) {
            if (v > UINT64_MAX / base)
                return -1;
            v *= base;
        }
    }
    if ((off_t) v < 0 || (uintmax_t) (off_t) v != (uintmax_t) v)
        return -1;
    *out = (uint64_t) v;
    return 0;
}

/* -b's rendering of a byte: printable ASCII as itself, controls as ^X,
   DEL as ^?, and bytes with the high bit as M- and the same rendering. */
static void
bcm_byte_text (unsigned char c, char *buf)
{
    char *p = buf;
    if (c >= 0x80) { *p++ = 'M'; *p++ = '-'; c -= 0x80; }
    if (c < 0x20) { *p++ = '^'; *p++ = (char) (c + 0x40); }
    else if (c == 0x7f) { *p++ = '^'; *p++ = '?'; }
    else *p++ = (char) c;
    *p = '\0';
}

static int
bcm_open (const char *path, int *out_fd)
{
    if (strcmp (path, "-") == 0) { *out_fd = STDIN_FILENO; return 0; }
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int
bcm_skip (int fd, uint64_t n, const char *name)
{
    /* A borrowed stdin can already be partway through a regular file. */
    off_t offset = (off_t) n;
    if (offset >= 0 && (uint64_t) offset == n &&
        lseek (fd, offset, SEEK_CUR) >= 0) return 0;
    char buf[4096];
    while (n > 0) {
        size_t want = (n > sizeof buf) ? sizeof buf : (size_t) n;
        ssize_t r = read (fd, buf, want);
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) return 0;
        if (r < 0) {
            builtin_error ("skip in %s: %s", name, strerror (errno));
            return -1;
        }
        n -= (uint64_t) r;
    }
    return 0;
}

/* diffutils cmp's option error: glibc's line, then its own Try line,
   which carries the "cmp: " prefix too; status 2. */
static void
bcm_try (void)
{
    fflush (stdout);
    builtin_error ("Try '%s --help' for more information.", bos_shim_prog_name ("cmp"));
}


int
cmp_builtin (WORD_LIST *list)
{
    int lflag = 0, sflag = 0, bflag = 0, c;
    const char *paths[2] = { NULL, NULL };
    int npath = 0;
    uint64_t skip[2] = { 0, 0 };
    uint64_t limit = UINT64_MAX;
    static const struct bos_longopt longopts[] = {
        { "print-bytes", BOS_NO_ARG, 'b' }, { "ignore-initial", BOS_REQ_ARG, 'i' },
        { "verbose", BOS_NO_ARG, 'l' }, { "bytes", BOS_REQ_ARG, 'n' },
        { "quiet", BOS_NO_ARG, 's' }, { "silent", BOS_NO_ARG, 's' },
        { "help", BOS_NO_ARG, BOS_OPT_HELP }, { "version", BOS_NO_ARG, 'v' },
        { NULL, 0, 0 }
    };
    bos_getopt g;

    /* GNU cmp's getopt_long, with diffutils' "cmp: Try ..." line. */
    bos_getopt_init (&g, bos_shim_prog_name ("cmp"), "bi:ln:sv", longopts, list);
    g.no_hint = 1;
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
        case 'b': bflag = 1; break;
        case 'l': lflag = 1; break;
        case 's': sflag = 1; break;
        case 'i': {
            /* SKIP, or SKIP1:SKIP2 */
            const char *colon = strchr (g.optarg, ':');
            char first[64];
            int ok;
            if (colon) {
                size_t len = (size_t) (colon - g.optarg);
                ok = len < sizeof first;
                if (ok) {
                    memcpy (first, g.optarg, len);
                    first[len] = '\0';
                    ok = bcm_parse_skip (first, &skip[0]) == 0
                         && bcm_parse_skip (colon + 1, &skip[1]) == 0;
                }
            } else {
                ok = bcm_parse_skip (g.optarg, &skip[0]) == 0;
                skip[1] = skip[0];
            }
            if (!ok) {
                builtin_error ("invalid --ignore-initial value '%s'", g.optarg);
                bcm_try ();
                bos_getopt_free (&g);
                return 2;
            }
            break;
        }
        case 'n':
            if (bcm_parse_skip (g.optarg, &limit) < 0) {
                builtin_error ("invalid --bytes value '%s'", g.optarg);
                bcm_try ();
                bos_getopt_free (&g);
                return 2;
            }
            break;
        case BOS_OPT_HELP:
            bos_getopt_free (&g);
            builtin_usage ();
            return EXECUTION_SUCCESS;
        case 'v':
            bos_getopt_free (&g);
            puts ("cmp 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        default:
            bcm_try ();
            bos_getopt_free (&g);
            return 2;
        }
    }
    for (int i = 0; i < g.noperands; i++) {
        const char *w = g.operands[i];
        if (npath < 2) paths[npath++] = w;
        else if (i < 4) {
            if (bcm_parse_skip (w, &skip[i - 2]) < 0) {
                builtin_error ("invalid --ignore-initial value '%s'", w);
                bcm_try ();
                bos_getopt_free (&g);
                return EX_USAGE;
            }
        } else {
            builtin_error ("extra operand '%s'", w);
            bcm_try ();
            bos_getopt_free (&g);
            return EX_USAGE;
        }
    }
    bos_getopt_free (&g);
    if (npath != 2) {
        builtin_error ("missing operand after '%s'", npath ? paths[0] : bos_shim_prog_name ("cmp"));
        bcm_try ();
        return EX_USAGE;
    }
    if (lflag && sflag) {
        builtin_error ("options -l and -s are incompatible");
        bcm_try ();
        return EX_USAGE;
    }
    if (strcmp (paths[0], "-") == 0 && strcmp (paths[1], "-") == 0) {
        builtin_error ("only one stdin operand is supported");
        bcm_try ();
        return EX_USAGE;
    }

    int fd[2];
    int owned[2] = { strcmp (paths[0], "-") != 0, strcmp (paths[1], "-") != 0 };
    /* Check before opening operands: an owned file may reuse descriptor 0. */
    if ((!owned[0] || !owned[1]) && fcntl (STDIN_FILENO, F_GETFD) < 0) {
        builtin_error ("standard input: %s", strerror (errno));
        return 2;
    }
    if (bcm_open (paths[0], &fd[0]) < 0) return 2;
    if (bcm_open (paths[1], &fd[1]) < 0) {
        if (owned[0]) close (fd[0]);
        return 2;
    }

    unsigned char buf[2][8192];
    size_t used[2] = { 0, 0 }, available[2] = { 0, 0 };
    uint64_t off = 1, line = 1;
    int rc = 0;
    int offset_width = 1;
    int eof[2] = { 0, 0 };
    if ((skip[0] && bcm_skip (fd[0], skip[0], paths[0]) < 0) ||
        (skip[1] && bcm_skip (fd[1], skip[1], paths[1]) < 0)) {
        rc = 2;
        goto done;
    }
    if (lflag) {
        uint64_t remaining = limit;
        for (int j = 0; j < 2; j++) {
            struct stat st;
            off_t position;
            if (fstat (fd[j], &st) == 0 && S_ISREG (st.st_mode)
                && (position = lseek (fd[j], 0, SEEK_CUR)) >= 0) {
                uint64_t count = position < st.st_size
                    ? (uint64_t) (st.st_size - position) : 0;
                if (count < remaining) remaining = count;
            }
        }
        /* Unknown-length streams use the signed file-offset range, as GNU
           cmp does. Known regular inputs narrow that bound. */
        if (remaining == UINT64_MAX && limit == UINT64_MAX)
            remaining = ((uint64_t) 1 << (sizeof (off_t) * CHAR_BIT - 1)) - 1;
        while (remaining >= 10) {
            offset_width++;
            remaining /= 10;
        }
    }
    for (;;) {
        if (off - 1 >= limit) break;
        /* Short reads are normal for pipes. Retain each unmatched suffix
           until the other input supplies bytes, and only read(2) == 0 is EOF. */
        for (int j = 0; j < 2; j++) {
            if (used[j] == available[j] && !eof[j]) {
                ssize_t n;
                do { n = read (fd[j], buf[j], sizeof buf[j]); }
                while (n < 0 && errno == EINTR);
                if (n < 0) {
                    builtin_error ("read %s: %s", paths[j], strerror (errno));
                    rc = 2;
                    goto done;
                }
                used[j] = 0;
                available[j] = (size_t) n;
                eof[j] = n == 0;
            }
        }
        if (eof[0] || eof[1]) {
            if (eof[0] != eof[1]) {
                if (!sflag && off == 1)
                    fprintf (stderr, "cmp: EOF on %s which is empty\n",
                             eof[0] ? paths[0] : paths[1]);
                else if (!sflag)
                    fprintf (stderr,
                             "cmp: EOF on %s after byte %" PRIu64 ", in line %" PRIu64 "\n",
                             eof[0] ? paths[0] : paths[1], off - 1, line);
                rc = 1;
            }
            break;
        }
        size_t n0 = available[0] - used[0], n1 = available[1] - used[1];
        size_t lim = n0 < n1 ? n0 : n1;
        if ((uint64_t) lim > limit - (off - 1)) lim = (size_t) (limit - (off - 1));
        for (size_t i = 0; i < lim; i++) {
            unsigned char a = buf[0][used[0] + i], b = buf[1][used[1] + i];
            if (a != b) {
                char ta[8], tb[8];
                bcm_byte_text (a, ta);
                bcm_byte_text (b, tb);
                if (lflag && bflag) {
                    printf ("%*" PRIu64 " %3o %-4s %3o %s\n",
                            offset_width, off + (uint64_t) i,
                            (unsigned) a, ta, (unsigned) b, tb);
                } else if (lflag) {
                    printf ("%*" PRIu64 " %3o %3o\n",
                            offset_width, off + (uint64_t) i,
                            (unsigned) a, (unsigned) b);
                } else {
                    /* -b's form says "byte" in every locale. */
                    if (!sflag && bflag)
                        printf ("%s %s differ: byte %" PRIu64 ", line %" PRIu64 " is %3o %s %3o %s\n",
                                paths[0], paths[1], off + (uint64_t) i, line,
                                (unsigned) a, ta, (unsigned) b, tb);
                    else if (!sflag)
                        printf ("%s %s differ: %s %" PRIu64 ", line %" PRIu64 "\n",
                                paths[0], paths[1], bcm_unit_word (),
                                off + (uint64_t) i, line);
                    rc = 1;
                    goto done;
                }
                rc = 1;
            }
            if (a == '\n') line++;
        }
        off += (uint64_t) lim;
        used[0] += lim;
        used[1] += lim;
        if (ferror (stdout)) break;
    }
done:
    if (owned[0]) close (fd[0]);
    if (owned[1]) close (fd[1]);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        clearerr (stdout);
        rc = 2;
    }
    return rc;
}

char *cmp_doc[] = {
    "Byte-compare two files.",
    "",
    "    bashcmp [-b] [-l|-s] [-i SKIP[:SKIP2]] [-n LIMIT] FILE1 FILE2 [SKIP1 [SKIP2]]",
    "        Default: print 'FILE1 FILE2 differ: byte N, line M' on first",
    "        diff ('char' instead of 'byte' in the C/POSIX locale, as GNU).",
    "        Exit 0 (same), 1 (differ), 2 (error).",
    "    -b, --print-bytes   also show the differing bytes (octal and as text)",
    "    -i SKIP, --ignore-initial=SKIP   skip SKIP bytes of both inputs;",
    "         -i SKIP1:SKIP2 skips SKIP1 of FILE1 and SKIP2 of FILE2",
    "    -l, --verbose   list every diff as 'offset oct1 oct2'",
    "    -s, --quiet, --silent   only exit code",
    "    -n LIMIT, --bytes=LIMIT   compare at most LIMIT bytes",
    "    SKIP — skip leading bytes (default 0). SKIP and LIMIT may end in",
    "    K, M, G, T, P, E (powers of 1024) or kB, MB, ... (powers of 1000).",
    "",
    "Either file may be '-' to read stdin (but only one).",
    (char *)NULL
};

struct builtin bashcmp_struct = {
    "bashcmp",
    cmp_builtin,
    BUILTIN_ENABLED,
    cmp_doc,
    "bashcmp [-bls] [-i SKIP[:SKIP2]] [-n LIMIT] FILE1 FILE2 [SKIP1 [SKIP2]]",
    0
};
