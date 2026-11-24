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

static int
bcm_parse_skip (const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s || s[0] == '-')
        return -1;
    errno = 0;
    v = strtoull (s, &end, 0);
    if (errno == ERANGE || !end || end == s || *end ||
        (off_t) v < 0 || (uintmax_t) (off_t) v != (uintmax_t) v)
        return -1;
    *out = (uint64_t) v;
    return 0;
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

static int
bcm_bad_option (const char *word, int c)
{
    fflush (stdout);
    if (word[0] == '-' && word[1] == '-')
        builtin_error ("unrecognized option '%s'", word);
    else
        builtin_error ("invalid option -- '%c'", c);
    builtin_error ("Try '%s --help' for more information.", bos_shim_prog_name ("cmp"));
    return 2;
}

int
cmp_builtin (WORD_LIST *list)
{
    int lflag = 0, sflag = 0;
    const char *paths[2] = { NULL, NULL };
    int npath = 0;
    uint64_t skip[2] = { 0, 0 };
    int nskip = 0;
    uint64_t limit = UINT64_MAX;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("cmp 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strncmp (w, "--bytes=", 8) == 0) {
            if (bcm_parse_skip (w + 8, &limit) < 0) {
                builtin_error ("invalid --bytes value '%s'", w + 8);
                return 2;
            }
            continue;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (npath < 2) paths[npath++] = p->word->word;
                else if (nskip < 2) {
                    if (bcm_parse_skip (p->word->word, &skip[nskip]) < 0) {
                        builtin_error ("invalid --ignore-initial value '%s'", p->word->word);
                        bcm_try ();
                        return EX_USAGE;
                    }
                    nskip++;
                } else {
                    builtin_error ("extra operand '%s'", p->word->word);
                    bcm_try ();
                    return EX_USAGE;
                }
            }
            break;
        }
        if (npath >= 2) {
            if (nskip < 2) {
                if (bcm_parse_skip (w, &skip[nskip]) < 0) {
                    builtin_error ("invalid --ignore-initial value '%s'", w);
                    bcm_try ();
                    return EX_USAGE;
                }
                nskip++;
            } else {
                builtin_error ("extra operand '%s'", p->word->word);
                bcm_try ();
                return EX_USAGE;
            }
            continue;
        }
        if (w[0] == '-' && w[1] == '-')
            return bcm_bad_option (w, 0);
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                if (w[i] == 'n') {
                    /* -n LIMIT: the count is the rest of the word, or the
                       next word. */
                    const char *count = w[i + 1] ? &w[i + 1] : NULL;
                    if (!count) {
                        if (!p->next) {
                            builtin_error ("option requires an argument -- 'n'");
                            bcm_try ();
                            return 2;
                        }
                        p = p->next;
                        count = p->word->word;
                    }
                    if (bcm_parse_skip (count, &limit) < 0) {
                        builtin_error ("invalid --bytes value '%s'", count);
                        return 2;
                    }
                    break;
                }
                switch (w[i]) {
                case 'l': lflag = 1; break;
                case 's': sflag = 1; break;
                default:
                    return bcm_bad_option (w, w[i]);
                }
            }
        } else {
            if (npath < 2) paths[npath++] = w;
            else if (nskip < 2) {
                if (bcm_parse_skip (w, &skip[nskip]) < 0) {
                    builtin_error ("invalid --ignore-initial value '%s'", w);
                    bcm_try ();
                    return EX_USAGE;
                }
                nskip++;
            }
            else { builtin_error ("extra operand '%s'", w); bcm_try (); return EX_USAGE; }
        }
    }
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
                if (!sflag)
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
                if (lflag) {
                    printf ("%*" PRIu64 " %3o %3o\n",
                            offset_width, off + (uint64_t) i,
                            (unsigned) a, (unsigned) b);
                } else {
                    if (!sflag)
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
    "    bashcmp [-l|-s] [-n LIMIT] FILE1 FILE2 [SKIP1 [SKIP2]]",
    "        Default: print 'FILE1 FILE2 differ: byte N, line M' on first",
    "        diff ('char' instead of 'byte' in the C/POSIX locale, as GNU).",
    "        Exit 0 (same), 1 (differ), 2 (error).",
    "    -l   list every diff as 'offset oct1 oct2'",
    "    -s   silent: only exit code",
    "    -n LIMIT, --bytes=LIMIT   compare at most LIMIT bytes",
    "    SKIP — skip leading bytes (default 0).",
    "",
    "Either file may be '-' to read stdin (but only one).",
    (char *)NULL
};

struct builtin bashcmp_struct = {
    "bashcmp",
    cmp_builtin,
    BUILTIN_ENABLED,
    cmp_doc,
    "bashcmp [-ls] [-n LIMIT] FILE1 FILE2 [SKIP1 [SKIP2]]",
    0
};
