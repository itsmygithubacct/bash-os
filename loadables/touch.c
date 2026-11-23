/* bashtouch.c — POSIX touch(1) as a bash builtin.
 *
 * Phase A.5+ trailing item from POSIX-CONFORMANCE-RESEARCH §8.1: closes
 * the last high-impact POSIX gap (`touch` was the only Tier-1 item left
 * after Phase S landed cp/mv/cksum/cmp/link/readlink/timeout). Pure
 * `utimensat(2)` + create-if-missing semantics; same shape as
 * vendor/sbase/touch.c trimmed for bash-loadable conventions.
 *
 *   bashtouch [-acm] [--help|--version] [-d DATE | -r REF_FILE | -t TIME] FILE...
 *
 *     -a       set atime only
 *     -m       set mtime only
 *     -c       don't create if missing
 *     -r REF   copy atime+mtime from REF
 *     -t TIME  use TIME ([[CC]YY]MMDDhhmm[.SS])
 *     -d DATE  use DATE: the GNU date strings date -d reads (common/date-parse.h),
 *              e.g. "2024-03-05 07:08:09.5", "Mar 5 2024", "1 hour ago";
 *              with -r, relative items apply to REF's times
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c / bashtail.c / bashlink.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "loadables.h"
#include "date-parse.h"
#include "gnu-longopt.h"
#include "shim-prog-name.h"

/* GNU touch's diagnostics: WHAT 'FILE': REASON, and the date error. */
static void
bt_file_error (const char *what, const char *path, int error)
{
    char *q = bos_quoteaf (path);
    builtin_error ("%s %s: %s", what, q ? q : path, strerror (error));
    free (q);
}

static void
bt_bad_date (const char *text)
{
    char *q = bos_quote (text);
    builtin_error ("invalid date format %s", q ? q : text);
    free (q);
}

/* Parse a -t/-d argument into a time_t. Supports the same length-keyed
   sbase format set: 8/10/11/12/13/15 (-t) and 19/20 (-d ISO). Returns 0
   on success, -1 on parse failure. */
static int
bt_parsetime (const char *str, time_t *out)
{
    struct tm cur_tm, t;
    time_t now;
    const char *fmt;
    int zulu = 0;
    size_t len = strlen (str);
    char buf[64];

    if (len >= sizeof buf) return -1;
    memcpy (buf, str, len + 1);

    memset (&t, 0, sizeof t);
    t.tm_isdst = -1;
    if (time (&now) == (time_t) -1) return -1;
    if (!localtime_r (&now, &cur_tm)) return -1;

    switch (len) {
        case 8:  t.tm_year = cur_tm.tm_year; fmt = "%m%d%H%M"; break;
        case 10: fmt = "%y%m%d%H%M"; break;
        case 11: t.tm_year = cur_tm.tm_year; fmt = "%m%d%H%M.%S"; break;
        case 12: fmt = "%Y%m%d%H%M"; break;
        case 13: fmt = "%y%m%d%H%M.%S"; break;
        case 15: fmt = "%Y%m%d%H%M.%S"; break;
        case 19: fmt = "%Y-%m-%dT%H:%M:%S"; break;
        case 20:
            if (buf[19] != 'Z') return -1;
            buf[19] = 0;
            zulu = 1;
            fmt = "%Y-%m-%dT%H:%M:%S";
            break;
        default: return -1;
    }
    char *end = strptime (buf, fmt, &t);
    if (!end || *end) return -1;
    struct tm parsed = t;
    /* Epoch second -1 is valid; errno distinguishes it from overflow. */
    errno = 0;
    *out = zulu ? timegm (&t) : mktime (&t);
    if (*out == (time_t) -1 && errno != 0) return -1;

    struct tm roundtrip;
    if (zulu) {
        if (!gmtime_r (out, &roundtrip)) return -1;
    } else {
        if (!localtime_r (out, &roundtrip)) return -1;
    }
    if (roundtrip.tm_year != parsed.tm_year
        || roundtrip.tm_mon != parsed.tm_mon
        || roundtrip.tm_mday != parsed.tm_mday
        || roundtrip.tm_hour != parsed.tm_hour
        || roundtrip.tm_min != parsed.tm_min
        || roundtrip.tm_sec != parsed.tm_sec)
        return -1;
    return 0;
}

/* Parse epoch seconds without floating-point rounding. A negative fraction
   is normalized to timespec's non-negative nanoseconds. Extra precision is
   rounded down to the preceding representable nanosecond, as GNU date does. */
static int
bt_date (const char *s, struct timespec *out)
{
    out->tv_nsec = 0;
    if (*s != '@') {
        size_t n = strlen (s);
        if (n >= 10 && s[4] == '-' && s[7] == '-') {
            int utc = 0;
            if (n >= 4 && !strcasecmp (s + n - 4, " UTC")) {
                n -= 4;
                utc = 1;
            } else if (s[n - 1] == 'Z') {
                n--;
                utc = 1;
            }
            /* Normalize date-only and minute precision to the validated
               second-precision ISO parser, keeping UTC independent of TZ. */
            if (n != 10 && n != 16 && n != 19) return -1;
            if (n > 10 && s[10] != ' ' && s[10] != 'T') return -1;
            char iso[21] = "0000-00-00T00:00:00";
            memcpy (iso, s, n);
            iso[10] = 'T';
            if (utc) iso[19] = 'Z';
            return bt_parsetime (iso, &out->tv_sec);
        }
        return bt_parsetime (s, &out->tv_sec);
    }
    s++;
    int negative = *s == '-';
    if (*s == '-' || *s == '+') s++;
    if (*s < '0' || *s > '9') return -1;
    char *end;
    errno = 0;
    uintmax_t whole = strtoumax (s, &end, 10);
    if (errno || whole > (uintmax_t)INTMAX_MAX + (unsigned)negative) return -1;
    long nano = 0;
    int digits = 0, remainder = 0;
    if (*end == '.' || *end == ',') {
        end++;
        if (*end < '0' || *end > '9') return -1;
        for (; *end >= '0' && *end <= '9'; end++) {
            if (digits < 9) { nano = nano * 10 + *end - '0'; digits++; }
            else if (*end != '0') remainder = 1;
        }
        while (digits++ < 9) nano *= 10;
    }
    if (*end) return -1;
    intmax_t seconds;
    if (negative) {
        if (remainder) nano++;
        if (nano) {
            if (whole > (uintmax_t)INTMAX_MAX) return -1;
            seconds = -(intmax_t)whole - 1;
            nano = 1000000000L - nano;
        } else seconds = whole ? -(intmax_t)(whole - 1) - 1 : 0;
    } else seconds = (intmax_t)whole;
    out->tv_sec = (time_t)seconds;
    if ((intmax_t)out->tv_sec != seconds) return -1;
    out->tv_nsec = nano;
    return 0;
}

/* Resolve a -d DATE against BASE (now, or one of -r REF's times): the
   touch-specific epoch, ISO and -t shapes first, then date -d's grammar. */
static int
bt_resolve_date (const char *s, const struct timespec *base, struct timespec *out)
{
    time_t t;
    long nsec;
    if (bt_date (s, out) == 0)
        return 0;
    if (bd_parse_date (s, base, &t, &nsec, 0) < 0)
        return -1;
    out->tv_sec = t;
    out->tv_nsec = nsec;
    return 0;
}

/* Apply `times` to `path`. Creates the file when missing and !cflag. When
   hflag is set (-h/--no-dereference) operate on a symlink itself rather than
   its target, and never create missing operands. Returns 0 on success,
   -1 on a fatal error (already reported). */
static int
bt_touch (const char *path, struct timespec times[2], int cflag, int hflag)
{
    if (utimensat (AT_FDCWD, path, times,
                   hflag ? AT_SYMLINK_NOFOLLOW : 0) == 0)
        return 0;
    int set_errno = errno;
    /* -c and -h never create: -c suppresses only a missing operand. */
    if (cflag || hflag) {
        if (set_errno == ENOENT && cflag)
            return 0;
        bt_file_error ("setting times of", path, set_errno);
        return -1;
    }
    /* As GNU touch: the open (creating a missing file) decides the
       "cannot touch" diagnostic; a directory keeps the time-setting error.
       O_NONBLOCK: a FIFO without a reader must not block the shell. */
    int fd = open (path, O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
    if (fd < 0) {
        if (errno == EISDIR)
            bt_file_error ("setting times of", path, set_errno);
        else
            bt_file_error ("cannot touch", path, errno);
        return -1;
    }
    int rc = futimens (fd, times);
    int saved = errno;
    close (fd);
    if (rc < 0) {
        bt_file_error ("setting times of", path, saved);
        return -1;
    }
    return 0;
}

int
touch_builtin (WORD_LIST *list)
{
    int aflag = 0, mflag = 0, cflag = 0, hflag = 0;
    const char *ref = NULL;
    const char *date_arg = NULL;
    struct timespec fixed = {0};
    int have_fixed = 0;

    /* GNU getopt_long scanning: clusters, -rREF / -r REF, --name=VALUE,
       unambiguous prefixes and options after operands. */
    static const struct bos_longopt longopts[] = {
        { "no-create", BOS_NO_ARG, 'c' },
        { "date", BOS_REQ_ARG, 'd' },
        { "no-dereference", BOS_NO_ARG, 'h' },
        { "reference", BOS_REQ_ARG, 'r' },
        { "time", BOS_REQ_ARG, BOS_OPT_FIRST },
        { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { NULL, 0, 0 }
    };
    static const char *const time_names[] = {
        "atime", "access", "use", "mtime", "modify", NULL
    };
    static const int time_vals[] = { 'a', 'a', 'a', 'm', 'm' };
    bos_getopt g;
    int c;
    bos_getopt_init (&g, "touch", "acd:fhmr:t:", longopts, list);
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
            case 'a': aflag = 1; break;
            case 'm': mflag = 1; break;
            case 'c': cflag = 1; break;
            case 'h': hflag = 1; break;   /* --no-dereference */
            case 'f': break;              /* GNU compat: ignored */
            case 'r': ref = g.optarg; break;
            case 'd': date_arg = g.optarg; have_fixed = 0; break;
            case 't':
                fixed.tv_nsec = 0;
                if (bt_parsetime (g.optarg, &fixed.tv_sec) < 0) {
                    bt_bad_date (g.optarg);
                    bos_getopt_free (&g);
                    return EXECUTION_FAILURE;
                }
                have_fixed = 1;
                date_arg = NULL;
                break;
            case BOS_OPT_FIRST: {
                int v = bos_argmatch ("touch", "--time", g.optarg, time_names, time_vals);
                if (v < 0) { bos_getopt_free (&g); return EXECUTION_FAILURE; }
                if (v == 'a') aflag = 1; else mflag = 1;
                break;
            }
            case BOS_OPT_HELP:
                bos_getopt_free (&g);
                builtin_help ();
                return EXECUTION_SUCCESS;
            case BOS_OPT_VERSION:
                bos_getopt_free (&g);
                puts ("bashtouch 1.0 (bash-loadable)");
                return EXECUTION_SUCCESS;
            default:
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
        }
    }
    /* The operands array (words still owned by the caller) is ours now. */
    char **operands = g.operands;
    int noperands = g.noperands;
    g.operands = NULL;
    bos_getopt_free (&g);

    /* -d is read once the options are known: with -r its relative items
       apply to each of REF's times, as in GNU touch. */
    struct stat ref_st;
    if (ref && stat (ref, &ref_st) < 0) {
        bt_file_error ("failed to get attributes of", ref, errno);
        free (operands);
        return EXECUTION_FAILURE;
    }
    struct timespec dated[2];
    if (date_arg) {
        struct timespec now;
        clock_gettime (CLOCK_REALTIME, &now);
        if (bt_resolve_date (date_arg, ref ? &ref_st.st_atim : &now, &dated[0]) < 0 ||
            bt_resolve_date (date_arg, ref ? &ref_st.st_mtim : &now, &dated[1]) < 0) {
            bt_bad_date (date_arg);
            free (operands);
            return EXECUTION_FAILURE;
        }
    }

    if (!noperands) {
        free (operands);
        builtin_error ("missing file operand");
        bos_shim_try_help ("touch");
        return EXECUTION_FAILURE;
    }

    /* Default: both atime and mtime. */
    if (!aflag && !mflag) aflag = mflag = 1;

    /* Resolve the times. Precedence: -d (relative to -r REF when both are
       given) > -r > -t > now. */
    struct timespec times[2] = {
        { .tv_sec = 0, .tv_nsec = UTIME_NOW },
        { .tv_sec = 0, .tv_nsec = UTIME_NOW },
    };
    if (date_arg) {
        times[0] = dated[0];
        times[1] = dated[1];
    } else if (ref) {
        times[0] = ref_st.st_atim;
        times[1] = ref_st.st_mtim;
    } else if (have_fixed) {
        times[0] = times[1] = fixed;
    }
    if (!aflag) times[0].tv_nsec = UTIME_OMIT;
    if (!mflag) times[1].tv_nsec = UTIME_OMIT;

    int rc = EXECUTION_SUCCESS;
    for (int i = 0; i < noperands; i++) {
        if (bt_touch (operands[i], times, cflag, hflag) < 0)
            rc = EXECUTION_FAILURE;
    }
    free (operands);
    return rc;
}

char *touch_doc[] = {
    "POSIX touch — change file timestamps.",
    "",
    "    bashtouch [-acm] [--help|--version] [-d DATE | -r REF | -t TIME] FILE...",
    "",
    "    -a        set access time only",
    "    -m        set modification time only",
    "    -c, --no-create      do not create FILE if it does not exist",
    "    -h, --no-dereference affect a symlink itself, not its target",
    "    -f        (ignored, for compatibility)",
    "    -r, --reference=REF  use REF's timestamps",
    "    -t TIME   use TIME ([[CC]YY]MMDDhhmm[.SS])",
    "    -d, --date=DATE      use DATE, a date -d string: ISO date/time with optional",
    "                         .FRAC and zone, @SECONDS[.FRAC], \"Mar 5 2024 07:08\",",
    "                         \"1 hour ago\"; with -r, relative to REF's times",
    "    --time=WORD          WORD=access|atime|use → -a; modify|mtime → -m",
    "    --help    show this help",
    "    --version show version",
    "",
    "Default behavior creates missing files and sets both timestamps to",
    "the current time. Default flag set is `-am` (both atime + mtime).",
    (char *)NULL
};

struct builtin bashtouch_struct = {
    "bashtouch",
    touch_builtin,
    BUILTIN_ENABLED,
    touch_doc,
    "bashtouch [-acm] [--help|--version] [-d DATE | -r REF | -t TIME] FILE...",
    0
};
