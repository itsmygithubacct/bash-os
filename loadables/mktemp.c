/* mktemp.c — GNU mktemp(1) as a bash builtin.
 *
 *   mktemp [-dqtu] [-p DIR|--tmpdir[=DIR]] [--suffix=SUFF] [-v VAR] [TEMPLATE]
 *
 * Replaces Bash's example loadable, whose -t took a prefix argument and
 * which had no -p/--tmpdir/--suffix (guest compatibility pass 1). The
 * options, defaults and diagnostics follow GNU coreutils mktemp:
 *
 *   TEMPLATE   at least three consecutive X's in its last component, at
 *              the end or before a suffix; default tmp.XXXXXXXXXX, which
 *              implies --tmpdir
 *   -d, --directory   create a directory (mode 0700) instead of a file (0600)
 *   -u, --dry-run     print a name that does not exist, create nothing
 *   -q, --quiet       no diagnostics about creation failures
 *   -p DIR, --tmpdir[=DIR]   TEMPLATE is relative to DIR, else $TMPDIR,
 *              else /tmp; TEMPLATE may not be absolute
 *   -t         TEMPLATE is a single file name under $TMPDIR, else -p DIR,
 *              else /tmp (deprecated in GNU, still accepted)
 *   --suffix=SUFF   append SUFF; TEMPLATE must then end in X
 *   -v VAR     Bash extension: also store the name in shell variable VAR
 *
 * Exit status 0 on success, 1 on any error.
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/random.h>

#include "loadables.h"

#define MKT_DEFAULT "tmp.XXXXXXXXXX"

static void
mkt_err (int quiet, const char *fmt, const char *a, const char *b)
{
    if (quiet)
        return;
    fflush (stdout);
    fputs ("mktemp: ", stderr);
    fprintf (stderr, fmt, a, b);
    fputc ('\n', stderr);
}

static void
mkt_usage_hint (void)
{
    fputs ("Try 'mktemp --help' for more information.\n", stderr);
}

static int
mkt_random (unsigned char *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom (buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                return -1;
            while (got < n) {
                r = read (fd, buf + got, n - got);
                if (r <= 0) {
                    close (fd);
                    return -1;
                }
                got += (size_t) r;
            }
            close (fd);
            return 0;
        }
        got += (size_t) r;
    }
    return 0;
}

/* Fill the X run at path[at, at+len) and create (or, dry-run, find a free)
   name. Returns 0 with path filled, -1 with errno set. */
static int
mkt_create (char *path, size_t at, size_t len, int dir, int dry)
{
    static const char chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char rnd[256];
    if (len > sizeof rnd)
        len = sizeof rnd;   /* more than 256 X's: the rest stay literal */
    for (int attempt = 0; attempt < 10000; attempt++) {
        if (mkt_random (rnd, len) < 0)
            return -1;
        for (size_t i = 0; i < len; i++)
            path[at + i] = chars[rnd[i] % (sizeof chars - 1)];
        if (dry) {
            struct stat st;
            if (lstat (path, &st) < 0) {
                if (errno == ENOENT)
                    return 0;
                return -1;
            }
            continue;
        }
        if (dir) {
            if (mkdir (path, 0700) == 0)
                return 0;
        } else {
            int fd = open (path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd >= 0) {
                close (fd);
                return 0;
            }
        }
        if (errno != EEXIST)
            return -1;
    }
    errno = EEXIST;
    return -1;
}

int
mktemp_builtin (WORD_LIST *list)
{
    int dflag = 0, qflag = 0, uflag = 0, tflag = 0, use_dir = 0;
    const char *dir_arg = NULL, *suffix = NULL, *varname = NULL;
    const char *template = NULL;
    int nops = 0;
    /* GNU getopt permutes: options may follow the template unless
       POSIXLY_CORRECT is set. */
    int permute = getenv ("POSIXLY_CORRECT") == NULL;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if ((nops == 0 || permute) && w[0] == '-' && w[1]) {
            if (!strcmp (w, "--")) {
                for (p = p->next; p; p = p->next) {
                    if (++nops > 1) {
                        mkt_err (0, "too many templates%s%s", "", "");
                        mkt_usage_hint ();
                        return EXECUTION_FAILURE;
                    }
                    template = p->word->word;
                }
                break;
            }
            if (!strcmp (w, "--help")) { builtin_help (); return EXECUTION_SUCCESS; }
            if (!strcmp (w, "--version")) { puts ("bashmktemp 2.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
            if (!strcmp (w, "--directory")) { dflag = 1; continue; }
            if (!strcmp (w, "--dry-run")) { uflag = 1; continue; }
            if (!strcmp (w, "--quiet")) { qflag = 1; continue; }
            if (!strcmp (w, "--tmpdir")) { use_dir = 1; continue; }
            if (!strncmp (w, "--tmpdir=", 9)) { use_dir = 1; dir_arg = w + 9; continue; }
            if (!strncmp (w, "--suffix=", 9)) { suffix = w + 9; continue; }
            if (!strcmp (w, "--suffix")) {
                if (!p->next) {
                    mkt_err (0, "option '--suffix' requires an argument%s%s", "", "");
                    mkt_usage_hint ();
                    return EXECUTION_FAILURE;
                }
                p = p->next;
                suffix = p->word->word;
                continue;
            }
            if (w[1] == '-') {
                mkt_err (0, "unrecognized option '%s'%s", w, "");
                mkt_usage_hint ();
                return EXECUTION_FAILURE;
            }
            for (int i = 1; w[i]; i++) {
                char c = w[i];
                if (c == 'd') dflag = 1;
                else if (c == 'q') qflag = 1;
                else if (c == 'u') uflag = 1;
                else if (c == 't') tflag = 1;
                else if (c == 'p' || c == 'v') {
                    const char *v;
                    if (w[i + 1]) v = w + i + 1;
                    else if (p->next) { p = p->next; v = p->word->word; }
                    else {
                        char opt[2] = { c, 0 };
                        mkt_err (0, "option requires an argument -- '%s'%s", opt, "");
                        mkt_usage_hint ();
                        return EXECUTION_FAILURE;
                    }
                    if (c == 'p') { use_dir = 1; dir_arg = v; }
                    else varname = v;
                    break;
                } else {
                    char opt[2] = { c, 0 };
                    mkt_err (0, "invalid option -- '%s'%s", opt, "");
                    mkt_usage_hint ();
                    return EXECUTION_FAILURE;
                }
            }
            continue;
        }
        if (++nops > 1) {
            mkt_err (0, "too many templates%s%s", "", "");
            mkt_usage_hint ();
            return EXECUTION_FAILURE;
        }
        template = w;
    }

    if (varname) {
        if (!valid_identifier (varname)) {
            if (!qflag) sh_invalidid ((char *) varname);
            return EXECUTION_FAILURE;
        }
        SHELL_VAR *v = find_variable (varname);
        if (v && readonly_p (v)) {
            if (!qflag) sh_readonly (varname);
            return EXECUTION_FAILURE;
        }
    }

    if (!template) {
        template = MKT_DEFAULT;
        use_dir = 1;
    }

    /* Split off the suffix: explicit, or whatever follows the last X. */
    size_t tlen = strlen (template);
    size_t xend;
    if (suffix) {
        if (strchr (suffix, '/')) {
            mkt_err (0, "invalid suffix '%s', contains directory separator%s", suffix, "");
            return EXECUTION_FAILURE;
        }
        if (tlen == 0 || template[tlen - 1] != 'X') {
            mkt_err (0, "with --suffix, template '%s' must end in X%s", template, "");
            return EXECUTION_FAILURE;
        }
        xend = tlen;
    } else {
        const char *last = strrchr (template, 'X');
        xend = last ? (size_t) (last - template) + 1 : 0;
        suffix = template + xend;
        if (strchr (suffix, '/')) {
            mkt_err (0, "invalid suffix '%s', contains directory separator%s", suffix, "");
            return EXECUTION_FAILURE;
        }
    }
    size_t xstart = xend;
    while (xstart > 0 && template[xstart - 1] == 'X')
        xstart--;
    if (xend - xstart < 3) {
        mkt_err (0, "too few X's in template '%s'%s", template, "");
        return EXECUTION_FAILURE;
    }

    const char *dir = NULL;
    if (tflag) {
        const char *env = getenv ("TMPDIR");
        dir = env && *env ? env : (dir_arg && *dir_arg ? dir_arg : "/tmp");
        if (strchr (template, '/')) {
            mkt_err (0, "invalid template, '%s', contains directory separator%s", template, "");
            return EXECUTION_FAILURE;
        }
    } else if (use_dir) {
        const char *env = getenv ("TMPDIR");
        dir = dir_arg && *dir_arg ? dir_arg : (env && *env ? env : "/tmp");
        if (template[0] == '/') {
            mkt_err (0, "invalid template, '%s'; with --tmpdir, it may not be absolute%s", template, "");
            return EXECUTION_FAILURE;
        }
    }

    /* PATH = [DIR/]TEMPLATE-without-suffix + SUFFIX */
    size_t dlen = dir ? strlen (dir) : 0;
    size_t slen = strlen (suffix);
    size_t plen = dlen + 1 + xend + slen + 1;
    char *path = malloc (plen);
    if (!path) {
        mkt_err (0, "memory exhausted%s%s", "", "");
        return EXECUTION_FAILURE;
    }
    size_t at = 0;
    if (dir) {
        memcpy (path, dir, dlen);
        at = dlen;
        if (dlen == 0 || dir[dlen - 1] != '/')
            path[at++] = '/';
    }
    memcpy (path + at, template, xend);
    memcpy (path + at + xend, suffix, slen);
    path[at + xend + slen] = '\0';

    /* The name as written: TEMPLATE with its suffix, for diagnostics. */
    char *shown = malloc (at + xend + slen + 1);
    if (shown)
        memcpy (shown, path, at + xend + slen + 1);

    int rc = EXECUTION_SUCCESS;
    if (mkt_create (path, at + xstart, xend - xstart, dflag, uflag) < 0) {
        if (uflag)
            mkt_err (qflag, "failed to create file via template '%s': %s",
                     shown ? shown : template, strerror (errno));
        else
            mkt_err (qflag, dflag ? "failed to create directory via template '%s': %s"
                                  : "failed to create file via template '%s': %s",
                     shown ? shown : template, strerror (errno));
        rc = EXECUTION_FAILURE;
    } else {
        puts (path);
        if (varname) {
            SHELL_VAR *v = builtin_bind_variable ((char *) varname, path, 0);
            if (v == 0 || readonly_p (v) || noassign_p (v)) {
                builtin_error ("%s: cannot set variable", varname);
                rc = EXECUTION_FAILURE;
            }
        }
    }
    if (fflush (stdout) == EOF) {
        mkt_err (0, "write error: %s%s", strerror (errno), "");
        rc = EXECUTION_FAILURE;
    }
    free (shown);
    free (path);
    return rc;
}

char *mktemp_doc[] = {
    "Create a temporary file or directory, safely, and print its name.",
    "",
    "    mktemp [-dqtu] [-p DIR|--tmpdir[=DIR]] [--suffix=SUFF] [-v VAR] [TEMPLATE]",
    "",
    "TEMPLATE must contain at least 3 consecutive 'X's in its last component.",
    "If TEMPLATE is not given, tmp.XXXXXXXXXX is used, and --tmpdir is implied.",
    "Files are created u+rw, and directories u+rwx.",
    "",
    "    -d, --directory   create a directory, not a file",
    "    -u, --dry-run     do not create anything; merely print a name",
    "    -q, --quiet       suppress diagnostics about file/dir-creation failure",
    "    --suffix=SUFF     append SUFF to TEMPLATE; SUFF must not contain a slash.",
    "                      Implied if TEMPLATE does not end in X",
    "    -p DIR, --tmpdir[=DIR]   interpret TEMPLATE relative to DIR; without",
    "                      DIR use $TMPDIR if set, else /tmp. TEMPLATE must not",
    "                      be absolute",
    "    -t                interpret TEMPLATE as a single file name component,",
    "                      relative to $TMPDIR if set, else DIR from -p, else /tmp",
    "    -v VAR            also store the name in shell variable VAR (Bash)",
    (char *)NULL
};

struct builtin mktemp_struct = {
    "mktemp",
    mktemp_builtin,
    BUILTIN_ENABLED,
    mktemp_doc,
    "mktemp [-dqtu] [-p DIR|--tmpdir[=DIR]] [--suffix=SUFF] [-v VAR] [TEMPLATE]",
    0
};
