/* bashtruncate.c — POSIX truncate(1).
 *
 *   bashtruncate [-c] [-o] -s SIZE FILE [FILE...]
 *   bashtruncate [-c] [-o] -r REF [-s SIZE] FILE [FILE...]
 *
 *   -s SIZE     set size. A leading modifier selects relative behavior:
 *                 +N  extend by N        -N  shrink by N
 *                 <N  shrink to at most N (only if larger)
 *                 >N  grow to at least N  (only if smaller)
 *                 /N  round down to a multiple of N
 *                 %N  round up to a multiple of N
 *               SIZE accepts GNU multiplier suffixes: K/KiB=1024, kB/KB=1000,
 *               M/MiB, MB, G/GiB, GB, T, P, E (lowercase k/m/g/t also accepted,
 *               BSD-style). `c` (bytes) is kept as a bash-os extension.
 *   -c          do not create FILE if it does not exist (--no-create)
 *   -o          treat SIZE as a count of IO blocks, not bytes (--io-blocks)
 *   -r REF      take the base size from REF (--reference); with -s the
 *               modifier is applied relative to REF's size
 *
 * Mirrors GNU coreutils truncate (do_ftruncate). POSIX 2024 Tier 1.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"
#include "gnu-longopt.h"
#include "shim-prog-name.h"

/* GNU truncate's file diagnostics: BEFORE 'FILE'AFTER[: REASON]. */
static void
bt_file_error (const char *before, const char *path, const char *after, int error)
{
    char *q = bos_quoteaf (path);
    if (error)
        builtin_error ("%s %s%s: %s", before, q ? q : path, after, strerror (error));
    else
        builtin_error ("%s %s%s", before, q ? q : path, after);
    free (q);
}

extern char *truncate_doc[];

typedef enum { RM_ABS = 0, RM_REL, RM_MIN, RM_MAX, RM_RDN, RM_RUP } bt_relmode;

/* GNU truncate SIZE suffix multipliers. A bare letter is a power of 1024; a
   letter followed by "B" is a power of 1000; "iB" is the explicit binary form.
   GNU truncate accepts lowercase k/m/g/t (BSD compat) but NOT dd's b=512/c=1;
   we keep `c`=1 (bytes) as a documented bash-os extension. Returns the
   multiplier, or 0 if the suffix is unrecognized. */
static long long
bt_suffix_mult (const char *suf)
{
    static const struct { const char *s; long long m; } tab[] = {
        { "",    1LL },
        { "c",   1LL },                                        /* bash-os ext */
        { "kB",  1000LL },          { "KB",  1000LL },
        { "k",   1024LL },          { "K",   1024LL },          { "KiB", 1024LL },
        { "MB",  1000000LL },
        { "m",   1048576LL },       { "M",   1048576LL },       { "MiB", 1048576LL },
        { "GB",  1000000000LL },
        { "g",   1073741824LL },    { "G",   1073741824LL },    { "GiB", 1073741824LL },
        { "TB",  1000000000000LL },
        { "t",   1099511627776LL }, { "T",   1099511627776LL }, { "TiB", 1099511627776LL },
        { "PB",  1000000000000000LL },
        { "P",   1125899906842624LL }, { "PiB", 1125899906842624LL },
        { "EB",  1000000000000000000LL },
        { "E",   1152921504606846976LL }, { "EiB", 1152921504606846976LL },
        { NULL, 0 }
    };
    for (int i = 0; tab[i].s; i++)
        if (!strcmp (suf, tab[i].s))
            return tab[i].m;
    return 0;
}

/* Parse a SIZE operand: an optional leading relational modifier followed by a
   signed/unsigned integer with an optional suffix, or a unit meaning one.
   On success sets *mode and *mag (the magnitude; signed for +/-).
   Returns 0, -1 on a bad number, or -2 when it does not fit. */
static int
bt_parse_size (const char *s, bt_relmode *mode, long long *mag)
{
    *mode = RM_ABS;
    while (isspace ((unsigned char) *s)) s++;
    switch (*s) {
        case '<': *mode = RM_MAX; s++; break;   /* at most  */
        case '>': *mode = RM_MIN; s++; break;   /* at least */
        case '/': *mode = RM_RDN; s++; break;   /* round down to multiple */
        case '%': *mode = RM_RUP; s++; break;   /* round up to multiple */
        case '+': case '-': *mode = RM_REL; break;   /* sign kept for strtoll */
        default: break;
    }

    char *end = NULL;
    errno = 0;
    long long n = strtoll (s, &end, 10);
    if (errno)
        return errno == ERANGE ? -2 : -1;
    int implicit_one = end == s;
    if (implicit_one) {
        while (isspace ((unsigned char) *end)) end++;
        n = 1;
    }
    long long mult = bt_suffix_mult (end);
    /* Units past exbi (Z, Y, R, Q, with B or iB) always overflow. */
    if (mult == 0 && *end && strchr ("ZYRQ", *end)
        && (!end[1] || !strcmp (end + 1, "B") || !strcmp (end + 1, "iB")))
        return -2;
    /* Empty input and bare `c` are not units with an implicit count.
       Signs still require digits: "+K" and "-K" cannot match a suffix. */
    if (mult == 0 || (implicit_one && mult == 1))
        return -1;
    if (mult > 1) {
        /* Check both signed bounds without negating LLONG_MIN. Its
           magnitude is not representable, but an exact negative product
           of LLONG_MIN is valid (for example -9007199254740992K). */
        if (n > LLONG_MAX / mult || n < LLONG_MIN / mult)
            return -2;
        n *= mult;
    }
    *mag = n;
    return 0;
}

static int bt_run (char **, int, const char *, int, bt_relmode, long long, int, int);

int
truncate_builtin (WORD_LIST *list)
{
    bt_relmode mode = RM_ABS;
    long long  mag = 0;
    int        got_size = 0;
    const char *ref = NULL;
    int        no_create = 0;
    int        block_mode = 0;

    static const struct bos_longopt longopts[] = {
        { "no-create", BOS_NO_ARG, 'c' },
        { "io-blocks", BOS_NO_ARG, 'o' },
        { "reference", BOS_REQ_ARG, 'r' },
        { "size", BOS_REQ_ARG, 's' },
        { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    bos_getopt g;
    int c;
    bos_getopt_init (&g, "truncate", "cor:s:", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
            case 'c': no_create = 1; break;
            case 'o': block_mode = 1; break;
            case 'r': ref = g.optarg; break;
            case 's': {
                int parsed = bt_parse_size (g.optarg, &mode, &mag);
                if (parsed < 0) {
                    /* GNU: Invalid number: 'SIZE'[: Value too large ...] */
                    char *q = bos_quote (g.optarg);
                    if (parsed == -2)
                        builtin_error ("Invalid number: %s: %s", q ? q : g.optarg, strerror (EOVERFLOW));
                    else
                        builtin_error ("Invalid number: %s", q ? q : g.optarg);
                    free (q);
                    bos_getopt_free (&g);
                    return EXECUTION_FAILURE;
                }
                if ((mode == RM_RDN || mode == RM_RUP) && mag == 0) {
                    builtin_error ("division by zero");
                    bos_getopt_free (&g);
                    return EXECUTION_FAILURE;
                }
                got_size = 1;
                break;
            }
            case BOS_OPT_HELP:
                for (char **d = truncate_doc; *d; d++) puts (*d);
                bos_getopt_free (&g);
                return EXECUTION_SUCCESS;
            case BOS_OPT_VERSION:
                puts ("bashtruncate 1.0 (bash-loadable)");
                bos_getopt_free (&g);
                return EXECUTION_SUCCESS;
            default:
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
        }
    }
    /* The operand array (words still owned by the caller) is ours now. */
    char **files = g.operands;
    int nfiles = g.noperands;
    g.operands = NULL;
    bos_getopt_free (&g);
    int rc = bt_run (files, nfiles, ref, got_size, mode, mag, no_create, block_mode);
    free (files);
    return rc;
}

/* Apply the parsed request to each operand. */
static int
bt_run (char **files, int nfiles, const char *ref, int got_size, bt_relmode mode,
        long long mag, int no_create, int block_mode)
{
    if (!ref && !got_size) {
        builtin_error ("you must specify either '--size' or '--reference'");
        bos_shim_try_help ("truncate");
        return EXECUTION_FAILURE;
    }
    /* GNU: a reference file combined with -s requires a relative modifier. */
    if (ref && got_size && mode == RM_ABS) {
        builtin_error ("you must specify a relative '--size' with '--reference'");
        bos_shim_try_help ("truncate");
        return EXECUTION_FAILURE;
    }
    if (!nfiles) {
        builtin_error ("missing file operand");
        bos_shim_try_help ("truncate");
        return EXECUTION_FAILURE;
    }

    /* Resolve the reference base size (used as fsize for relative modes, and
       as the absolute target when only -r is given). */
    long long ref_size = -1;
    if (ref) {
        struct stat rst;
        if (stat (ref, &rst) < 0) {
            bt_file_error ("cannot stat", ref, "", errno);
            return EXECUTION_FAILURE;
        }
        ref_size = (long long) rst.st_size;
        if (!got_size) {           /* -r alone: absolute to the reference size */
            mode = RM_ABS;
            mag = ref_size;
        }
    }

    int rc = EXECUTION_SUCCESS;
    for (int i = 0; i < nfiles; i++) {
        const char *path = files[i];
        /* O_NONBLOCK as GNU: a FIFO without a reader fails (ENXIO) instead
           of blocking the shell. */
        int fd = open (path, O_WRONLY | O_NONBLOCK | (no_create ? 0 : O_CREAT) | O_CLOEXEC, 0666);
        if (fd < 0) {
            if (errno == ENOENT && no_create) continue;
            bt_file_error ("cannot open", path, " for writing", errno);
            rc = EXECUTION_FAILURE;
            continue;
        }

        struct stat st;
        int have_st = 0;
        long long blocks = 1;
        {
            if (fstat (fd, &st) < 0) {
                bt_file_error ("cannot fstat", path, "", errno);
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            have_st = 1;
            if (block_mode && st.st_blksize > 0)
                blocks = (long long) st.st_blksize;
        }

        long long ssize;
        if (block_mode) {
            /* st_blksize is positive; mag * blocks must not wrap. */
            if (blocks > 1 && mag > 0 && mag > LLONG_MAX / blocks) {
                bt_file_error ("overflow extending size of file", path, "", 0);
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            if (blocks > 1 && mag < 0 && mag < LLONG_MIN / blocks) {
                bt_file_error ("overflow extending size of file", path, "", 0);
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            ssize = mag * blocks;
        } else
            ssize = mag;
        /* Base size for relative modes: the reference, else the file itself. */
        long long fsize = (ref_size >= 0) ? ref_size : (have_st ? (long long) st.st_size : 0);
        if (ref_size < 0 && mode != RM_ABS && S_ISBLK (st.st_mode)) {
            /* Linux block devices report st_size == 0.  SEEK_END returns the
               device capacity, which GNU uses for relative size modes. */
            off_t end = lseek (fd, 0, SEEK_END);
            if (end >= 0)
                fsize = (long long) end;
        }
        long long nsize = 0;
        int overflow = 0;
        switch (mode) {
            case RM_REL:
                if (ssize > 0 && fsize > LLONG_MAX - ssize)
                    overflow = 1;
                else if (ssize < 0 && fsize < LLONG_MIN - ssize)
                    overflow = 1;
                else
                    nsize = fsize + ssize;
                break;
            case RM_MIN: nsize = fsize > ssize ? fsize : ssize; break;   /* >= */
            case RM_MAX: nsize = fsize < ssize ? fsize : ssize; break;   /* <= */
            case RM_RDN: nsize = ssize ? fsize - fsize % ssize : fsize; break;
            case RM_RUP: {
                long long r = ssize ? fsize % ssize : 0;
                long long add = r ? ssize - r : 0;
                if (add > 0 && fsize > LLONG_MAX - add)
                    overflow = 1;
                else
                    nsize = fsize + add;
                break;
            }
            case RM_ABS:
            default:     nsize = ssize; break;
        }
        /* GNU: overflow on extend is an error and leaves the file alone.
           A relative shrink past zero is not overflow; it becomes empty. */
        if (!overflow && nsize < 0)
            nsize = 0;
        if (overflow || (long long) (off_t) nsize != nsize) {
            bt_file_error ("overflow extending size of file", path, "", 0);
            close (fd); rc = EXECUTION_FAILURE; continue;
        }

        if (ftruncate (fd, (off_t) nsize) < 0) {
            int error = errno;
            char *q = bos_quoteaf (path);
            builtin_error ("failed to truncate %s at %lld bytes: %s",
                           q ? q : path, nsize, strerror (error));
            free (q);
            rc = EXECUTION_FAILURE;
        }
        close (fd);
    }
    return rc;
}

char *truncate_doc[] = {
    "Shrink or extend files to a given size (POSIX truncate).",
    "",
    "    bashtruncate [-c] [-o] -s SIZE FILE [FILE...]",
    "    bashtruncate [-c] [-o] -r REF [-s SIZE] FILE [FILE...]",
    "",
    "    -s, --size SIZE   target size. A leading modifier selects relative mode:",
    "                        +N extend   -N shrink   <N at most   >N at least",
    "                        /N round down to multiple   %N round up to multiple",
    "                      SIZE suffixes: K/KiB=1024, kB/KB=1000, M/MB, G/GB,",
    "                      T, P, E (lowercase k/m/g/t accepted; c = bytes)",
    "                      A unit alone means one, including <, >, /, % modes",
    "    -c, --no-create   do not create FILE if it is missing",
    "    -o, --io-blocks   treat SIZE as a number of IO blocks instead of bytes",
    "    -r, --reference REF   base the size on REF (with -s, relative to REF)",
    "    --help | --version",
    "",
    "Files smaller than the target gain holes (sparse).",
    (char *)NULL
};

struct builtin bashtruncate_struct = {
    "bashtruncate",
    truncate_builtin,
    BUILTIN_ENABLED,
    truncate_doc,
    "bashtruncate [-co] [-r REF] -s SIZE FILE... | -r REF FILE...",
    0
};
