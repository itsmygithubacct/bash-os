/* bashfind.c — POSIX-shape find(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. Recursive walker + predicate
 * expression tree + cycle detection (via dev/inode tuple set).
 *
 * Supported predicates: -name, -iname, -path/-wholename, -ipath/-iwholename,
 * -type, -size, -mtime, -mmin, -amin, -cmin, -atime, -ctime, -daystart,
 * -perm, -user, -group, -uid, -gid, -nouser, -nogroup, -regex, -iregex,
 * -regextype, -maxdepth, -mindepth, -depth, -xdev/-mount, -prune, -empty,
 * -newer, -anewer, -cnewer, -newerXY (X: a/m/c, Y: a/m/c/t), -samefile,
 * -inum, -links, -executable, -readable, -writable, -true, -false.
 * Operators: `-a` (implicit AND between predicates), `-o`, `!`,
 *           `(` `)`.
 * Actions: -print (default), -print0, -printf FORMAT, -fprint FILE,
 *          -fprint0 FILE, -fprintf FILE FORMAT, -delete,
 *          -exec ... \;, -exec ... {} +, -execdir.
 *
 * Out of scope: birth times (-newer with X or Y of B).
 *
 * No static globals — per-call options live on the stack. Walker uses
 * a small (dev,ino) set to avoid symlink-loop infinite recursion.
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
#include <dirent.h>
#include <fnmatch.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <sys/sysmacros.h>

#include "loadables.h"
#include "date-parse.h"

/* Set when the expression parser has already reported its error, so the
   generic "parse error" line is not added (GNU prints one diagnostic and
   exits 1). */
static int bf_reported;
#define builtin_error(...) (bf_reported = 1, builtin_error (__VA_ARGS__))
#include "command-run.h"

/* Predicate kinds. */
typedef enum {
    BF_AND, BF_OR, BF_NOT,
    BF_NAME, BF_INAME, BF_PATH,
    BF_TYPE, BF_SIZE, BF_MTIME, BF_MAXDEPTH, BF_MINDEPTH, BF_XDEV,
    BF_PRUNE, BF_QUIT, BF_EMPTY, BF_NEWER,
    BF_PRINT, BF_PRINT0, BF_PRINTF, BF_EXEC, BF_EXECDIR, BF_DELETE,
    BF_MMIN, BF_AMIN, BF_CMIN, BF_ATIME, BF_CTIME,
    BF_REGEX, BF_IREGEX,
    BF_PERM, BF_USER, BF_GROUP, BF_UID, BF_GID, BF_NOUSER, BF_NOGROUP,
    BF_SAMEFILE, BF_INUM, BF_LINKS,
    BF_TRUE, BF_FALSE,
    BF_IPATH, BF_ACCESS
} bf_kind;

typedef struct bf_expr {
    bf_kind        kind;
    struct bf_expr *a, *b;     /* AND/OR/NOT operands */
    char          *sval;       /* glob pattern, type char, etc. */
    long long      nval;       /* size/mtime/depth */
    int            ncmp;       /* -1: <N, 0: =N, +1: >N (for size/mtime) */
    time_t         tval;       /* -newer reference mtime (seconds) */
    long           tnsec;      /* -newer reference mtime (nanoseconds) */
    /* For BF_EXEC / BF_EXECDIR: argv template terminated by NULL.
       exec_batch: 0 = `\;` (per-file), 1 = `+` (batched until ARG_MAX). */
    char         **exec_argv;
    int            exec_argc;
    int            exec_batch;
    /* For BF_EXEC `+` form: per-node pending batch. */
    char         **pending_paths;
    size_t         pending_count;
    size_t         pending_cap;
    size_t         pending_bytes;
    /* For BF_REGEX / BF_IREGEX: compiled regex. */
    regex_t        re;
    int            re_ok;
    /* -fprint/-fprint0/-fprintf: the output file (NULL = stdout). */
    FILE          *out;
} bf_expr;

/* Symlink-traversal mode. POSIX find takes the first non-option arg as
   one of -H, -L, -P:
     BF_FOLLOW_NONE (-P, default): never follow symlinks (lstat throughout).
     BF_FOLLOW_ARGS (-H): follow symlinks named on the command line, but
                         lstat() everything found via recursion.
     BF_FOLLOW_ALL  (-L): always follow symlinks (stat() throughout). When
                         a symlink would create a directory loop, the
                         existing (dev,ino) seen-set breaks it. */
typedef enum {
    BF_FOLLOW_NONE = 0,
    BF_FOLLOW_ARGS = 1,
    BF_FOLLOW_ALL  = 2
} bf_follow;

typedef struct {
    bf_expr *root;
    int      maxdepth;         /* -1 = unbounded */
    int      mindepth;         /* 0 = no min */
    int      quit;             /* stop the expression and all remaining traversal */
    int      pruned;           /* set by -prune for current dir */
    int      had_action;       /* if no -print/-print0 specified, default to -print */
    int      print0;           /* default action: 0 = newline, 1 = NUL */
    bf_follow follow;          /* -H/-L/-P semantics */
    int      xdev;             /* -xdev/-mount: do not descend across devices */
    int      root_dev_valid;   /* root_dev is set once per starting path */
    dev_t    root_dev;
    int      postorder;        /* set by -depth or -delete */
    int      exit_status;      /* 1 if any search operation failed */
    const char *start_path;    /* current command-line starting point (depth 0); for -printf %P */
    int      regex_bre;        /* -regextype posix-basic & co.: BRE, not ERE */
    int      daystart;         /* -daystart: ages count from the end of today */
} bf_ctx;

typedef struct {
    const char    *path;
    const char    *base;        /* basename within path */
    const char    *root;        /* command-line starting point (for -printf %P) */
    int            depth;
    struct stat    st;
} bf_pinfo;

/* ---- expression parser ---- */

typedef struct {
    int          argc;
    char       **argv;
    int          pos;
} bf_parse;

static const char *bf_peek (bf_parse *p) { return (p->pos < p->argc) ? p->argv[p->pos] : NULL; }
static void        bf_advance (bf_parse *p) { p->pos++; }

static bf_expr *
bf_alloc (bf_kind k)
{
    bf_expr *e = calloc (1, sizeof *e);
    if (e) e->kind = k;
    return e;
}

static void
bf_free (bf_expr *e)
{
    if (!e) return;
    bf_free (e->a);
    bf_free (e->b);
    free (e->sval);
    if (e->exec_argv) {
        for (int i = 0; i < e->exec_argc; i++) free (e->exec_argv[i]);
        free (e->exec_argv);
    }
    if (e->pending_paths) {
        for (size_t i = 0; i < e->pending_count; i++) free (e->pending_paths[i]);
        free (e->pending_paths);
    }
    if (e->re_ok) regfree (&e->re);
    if (e->out) fclose (e->out);
    free (e);
}

/* The date operand of -newerXt. GNU accepts any date(1) -d string; this
   takes the common absolute forms: @EPOCH, YYYY-MM-DD[ T]HH:MM[:SS] with an
   optional Z or numeric zone, YYYY-MM-DD, YYYY/MM/DD, and HH:MM[:SS]
   (today). Local time unless a zone is given. */
static int
bf_parse_when (const char *s, time_t *out)
{
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '@') {
        char *end;
        errno = 0;
        long long v = strtoll (s + 1, &end, 10);
        if (errno || end == s + 1 || *end) return -1;
        *out = (time_t) v;
        return 0;
    }
    static const char *const fmts[] = {
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M",
        "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y-%m-%d", "%Y/%m/%d", "%Y%m%d",
        "%H:%M:%S", "%H:%M", NULL
    };
    for (int i = 0; fmts[i]; i++) {
        struct tm tm;
        memset (&tm, 0, sizeof tm);
        int time_only = fmts[i][1] == 'H';
        if (time_only) {
            time_t now = time (NULL);
            localtime_r (&now, &tm);
        }
        char *e = strptime (s, fmts[i], &tm);
        if (!e) continue;
        while (*e == ' ') e++;
        long off = 0;
        int zoned = 0;
        if (*e == 'Z' && !e[1]) zoned = 1;
        else if ((*e == '+' || *e == '-') && isdigit ((unsigned char) e[1])) {
            int sign = *e == '-' ? -1 : 1, hh = 0, mm = 0, n = 0;
            const char *z = e + 1;
            while (isdigit ((unsigned char) z[n]) && n < 4) n++;
            if (n == 4 && !z[4]) { hh = (z[0]-'0')*10 + (z[1]-'0'); mm = (z[2]-'0')*10 + (z[3]-'0'); }
            else if (n == 2 && z[2] == ':' && isdigit ((unsigned char) z[3]) && isdigit ((unsigned char) z[4]) && !z[5])
                { hh = (z[0]-'0')*10 + (z[1]-'0'); mm = (z[3]-'0')*10 + (z[4]-'0'); }
            else if ((n == 1 || n == 2) && !z[n]) { hh = atoi (z); }
            else continue;
            off = sign * (hh * 3600L + mm * 60L);
            zoned = 1;
        }
        else if (*e) continue;
        tm.tm_isdst = -1;
        time_t t = zoned ? timegm (&tm) - off : mktime (&tm);
        if (t == (time_t) -1 && !zoned) continue;
        *out = t;
        return 0;
    }
    return -1;
}

/* Parse N / +N / -N for size and mtime style predicates.
   Returns the absolute number; sets *cmp_out to -1/0/+1. */
static long long
bf_parse_signed (const char *s, int *cmp_out)
{
    if (s[0] == '+') { *cmp_out =  1; s++; }
    else if (s[0] == '-') { *cmp_out = -1; s++; }
    else                  { *cmp_out = 0; }
    return atoll (s);
}

/* Parse the MODE operand for -perm. Octal modes are accepted directly.
   Symbolic modes intentionally implement the mask subset find needs:
   [ugoa]*[+-=][rwxst]+ clauses, comma-separated. The operator does not
   matter for find's mask comparison; it only separates "who" from bits. */
static int
bf_parse_perm_mode (const char *s, mode_t *out)
{
    if (!s || !*s) return -1;
    int all_octal = 1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '7') { all_octal = 0; break; }
    }
    if (all_octal) {
        char *end;
        long mode = strtol (s, &end, 8);
        if (*end || mode < 0) return -1;
        *out = (mode_t) mode;
        return 0;
    }

    mode_t mode = 0;
    const char *p = s;
    while (*p) {
        int who = 0;
        while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
            if (*p == 'u') who |= 1;
            else if (*p == 'g') who |= 2;
            else if (*p == 'o') who |= 4;
            else who |= 7;
            p++;
        }
        if (who == 0) who = 7;
        if (*p != '+' && *p != '-' && *p != '=') return -1;
        p++;
        if (!*p || *p == ',') return -1;
        while (*p && *p != ',') {
            switch (*p) {
                case 'r':
                    if (who & 1) mode |= S_IRUSR;
                    if (who & 2) mode |= S_IRGRP;
                    if (who & 4) mode |= S_IROTH;
                    break;
                case 'w':
                    if (who & 1) mode |= S_IWUSR;
                    if (who & 2) mode |= S_IWGRP;
                    if (who & 4) mode |= S_IWOTH;
                    break;
                case 'x':
                    if (who & 1) mode |= S_IXUSR;
                    if (who & 2) mode |= S_IXGRP;
                    if (who & 4) mode |= S_IXOTH;
                    break;
                case 's':
                    if (who & 1) mode |= S_ISUID;
                    if (who & 2) mode |= S_ISGID;
                    break;
                case 't':
                    mode |= S_ISVTX;
                    break;
                default:
                    return -1;
            }
            p++;
        }
        if (*p == ',') {
            p++;
            if (!*p) return -1;
        }
    }
    *out = mode;
    return 0;
}

static bf_expr *bf_parse_or (bf_parse *p, bf_ctx *ctx);

/* GNU -printf: the directive letters, and the strftime-style letters
   that may follow %A, %C and %T (plus GNU's @, +, S, T and X with
   fractional seconds). */
#define BF_PRINTF_DIRECTIVES "%aAbcCdDfFgGhHiklmMnpPsStTuUyY"
#define BF_PRINTF_TIMECHARS "@+aAbBcCdDeFgGhHIjklmMnprRsStTuUVwWxXyYzZ"

/* Check FMT as GNU find does when it parses -printf: a lone trailing '%'
   is an error (returns -1); an unknown directive or escape is only
   warned about, and printed literally later. */
static int
bf_printf_validate (const char *fmt, const char **bad)
{
    for (const char *s = fmt; *s; s++)
    {
        if (*s == '\\')
        {
            if (!s[1]) break;
            s++;
            if (!strchr ("abcfnrtv\\", *s) && !(*s >= '0' && *s <= '7'))
                builtin_warning ("unrecognized escape `\\%c'", *s);
            continue;
        }
        if (*s != '%') continue;
        const char *d = s + 1;
        while (*d && strchr ("-+ #0", *d)) d++;
        while (isdigit ((unsigned char) *d)) d++;
        if (*d == '.') { d++; while (isdigit ((unsigned char) *d)) d++; }
        if (!*d)
        {
            if (bad) *bad = s;
            return -1;
        }
        if (!strchr (BF_PRINTF_DIRECTIVES, *d))
            builtin_warning ("unrecognized format directive `%%%c'", *d);
        else if (*d == 'A' || *d == 'C' || *d == 'T')
        {
            if (!d[1])
                builtin_warning ("format directive `%%%c' should be followed by another character", *d);
            else if (!strchr (BF_PRINTF_TIMECHARS, d[1]))
                builtin_warning ("unrecognized format directive `%%%c%c'", *d, d[1]);
            if (d[1]) d++;
        }
        s = d;
    }
    return 0;
}

static bf_expr *
bf_parse_primary (bf_parse *p, bf_ctx *ctx)
{
    const char *t = bf_peek (p);
    if (!t) return NULL;

    if (!strcmp (t, "(")) {
        bf_advance (p);
        bf_expr *inner = bf_parse_or (p, ctx);
        if (!inner || !bf_peek (p) || strcmp (bf_peek (p), ")") != 0)
            { bf_free (inner); builtin_error ("expected )"); return NULL; }
        bf_advance (p);
        return inner;
    }
    if (!strcmp (t, "!") || !strcmp (t, "-not")) {
        bf_advance (p);
        bf_expr *inner = bf_parse_primary (p, ctx);
        if (!inner) return NULL;
        bf_expr *e = bf_alloc (BF_NOT);
        if (!e) { bf_free (inner); return NULL; }
        e->a = inner;
        return e;
    }

    bf_kind k = BF_TRUE;
    int needs_arg = 0;
    int is_action = 0;

    if      (!strcmp (t, "-name"))     { k = BF_NAME;     needs_arg = 1; }
    else if (!strcmp (t, "-iname"))    { k = BF_INAME;    needs_arg = 1; }
    else if (!strcmp (t, "-path") || !strcmp (t, "-wholename"))
                                       { k = BF_PATH;     needs_arg = 1; }
    else if (!strcmp (t, "-ipath") || !strcmp (t, "-iwholename"))
                                       { k = BF_IPATH;    needs_arg = 1; }
    else if (!strcmp (t, "-executable")) { k = BF_ACCESS; }
    else if (!strcmp (t, "-readable")) { k = BF_ACCESS; }
    else if (!strcmp (t, "-writable")) { k = BF_ACCESS; }
    else if (!strcmp (t, "-true"))     { k = BF_TRUE; }
    else if (!strcmp (t, "-false"))    { k = BF_FALSE; }
    else if (!strcmp (t, "-daystart")) { k = BF_TRUE;     ctx->daystart = 1; }
    else if (!strcmp (t, "-regextype")) { k = BF_TRUE;    needs_arg = 1; }
    else if (!strcmp (t, "-type"))     { k = BF_TYPE;     needs_arg = 1; }
    else if (!strcmp (t, "-size"))     { k = BF_SIZE;     needs_arg = 1; }
    else if (!strcmp (t, "-mtime"))    { k = BF_MTIME;    needs_arg = 1; }
    else if (!strcmp (t, "-maxdepth")) { k = BF_MAXDEPTH; needs_arg = 1; is_action = 1; }
    else if (!strcmp (t, "-mindepth")) { k = BF_MINDEPTH; needs_arg = 1; is_action = 1; }
    else if (!strcmp (t, "-depth"))    { k = BF_TRUE;    ctx->postorder = 1; }
    else if (!strcmp (t, "-xdev") || !strcmp (t, "-mount")) { k = BF_XDEV; ctx->xdev = 1; }
    else if (!strcmp (t, "-quit"))     { k = BF_QUIT; }
    else if (!strcmp (t, "-prune"))    { k = BF_PRUNE; }
    else if (!strcmp (t, "-empty"))    { k = BF_EMPTY; }
    else if (!strcmp (t, "-newer") || !strcmp (t, "-anewer") || !strcmp (t, "-cnewer") ||
             (!strncmp (t, "-newer", 6) && strlen (t) == 8))
                                       { k = BF_NEWER;    needs_arg = 1; }
    else if (!strcmp (t, "-samefile")) { k = BF_SAMEFILE; needs_arg = 1; }
    else if (!strcmp (t, "-inum"))     { k = BF_INUM;     needs_arg = 1; }
    else if (!strcmp (t, "-links"))    { k = BF_LINKS;    needs_arg = 1; }
    else if (!strcmp (t, "-mmin"))     { k = BF_MMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-amin"))     { k = BF_AMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-cmin"))     { k = BF_CMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-atime"))    { k = BF_ATIME;    needs_arg = 1; }
    else if (!strcmp (t, "-ctime"))    { k = BF_CTIME;    needs_arg = 1; }
    else if (!strcmp (t, "-regex"))    { k = BF_REGEX;    needs_arg = 1; }
    else if (!strcmp (t, "-iregex"))   { k = BF_IREGEX;   needs_arg = 1; }
    else if (!strcmp (t, "-perm"))     { k = BF_PERM;     needs_arg = 1; }
    else if (!strcmp (t, "-user"))     { k = BF_USER;     needs_arg = 1; }
    else if (!strcmp (t, "-group"))    { k = BF_GROUP;    needs_arg = 1; }
    else if (!strcmp (t, "-uid"))      { k = BF_UID;      needs_arg = 1; }
    else if (!strcmp (t, "-gid"))      { k = BF_GID;      needs_arg = 1; }
    else if (!strcmp (t, "-nouser"))   { k = BF_NOUSER; }
    else if (!strcmp (t, "-nogroup"))  { k = BF_NOGROUP; }
    else if (!strcmp (t, "-delete"))   { k = BF_DELETE;   is_action = 1; ctx->had_action = 1; ctx->postorder = 1; }
    else if (!strcmp (t, "-print"))    { k = BF_PRINT;    is_action = 1; ctx->had_action = 1; }
    else if (!strcmp (t, "-print0"))   { k = BF_PRINT0;   is_action = 1; ctx->had_action = 1; ctx->print0 = 1; }
    else if (!strcmp (t, "-printf"))   { k = BF_PRINTF;   needs_arg = 1; is_action = 1; ctx->had_action = 1; }
    else if (!strcmp (t, "-fprint") || !strcmp (t, "-fprint0") || !strcmp (t, "-fprintf"))
    {
        /* -fprint FILE, -fprint0 FILE, -fprintf FILE FORMAT: like -print,
           -print0 and -printf, into FILE (created, or truncated, even when
           nothing matches). */
        int fmt_arg = !strcmp (t, "-fprintf");
        bf_advance (p);
        const char *file = bf_peek (p);
        const char *fmt = file ? (bf_advance (p), bf_peek (p)) : NULL;
        if (!file || (fmt_arg && !fmt))
            { builtin_error ("missing argument to `%s'", t); return NULL; }
        if (fmt_arg) {
            const char *bad = NULL;
            if (bf_printf_validate (fmt, &bad) != 0)
                { builtin_error ("error: %% at end of format string"); return NULL; }
            bf_advance (p);
        }
        bf_expr *e = bf_alloc (fmt_arg ? BF_PRINTF : !strcmp (t, "-fprint0") ? BF_PRINT0 : BF_PRINT);
        if (!e) return NULL;
        if (fmt_arg && !(e->sval = strdup (fmt))) { bf_free (e); return NULL; }
        e->out = fopen (file, "w");
        if (!e->out) {
            builtin_error ("%s: %s", file, strerror (errno));
            bf_free (e);
            return NULL;
        }
        ctx->had_action = 1;
        return e;
    }
    else if (!strcmp (t, "-exec") || !strcmp (t, "-execdir"))
    {
        /* Consume tokens until `\;` (per-file) or `+` (batched). */
        int is_execdir = !strcmp (t, "-execdir");
        bf_advance (p);
        bf_expr *e = bf_alloc (is_execdir ? BF_EXECDIR : BF_EXEC);
        if (!e) return NULL;
        e->exec_argv = NULL;
        e->exec_argc = 0;
        int cap = 0;
        const char *tok;
        while ((tok = bf_peek (p)) != NULL) {
            if (!strcmp (tok, ";")) { e->exec_batch = 0; bf_advance (p); break; }
            if (!strcmp (tok, "+"))  { e->exec_batch = 1; bf_advance (p); break; }
            if (e->exec_argc >= cap) {
                cap = cap ? cap * 2 : 8;
                char **n = realloc (e->exec_argv, (size_t) cap * sizeof *n);
                if (!n) { bf_free (e); builtin_error ("oom"); return NULL; }
                e->exec_argv = n;
            }
            e->exec_argv[e->exec_argc] = strdup (tok);
            if (!e->exec_argv[e->exec_argc]) { bf_free (e); return NULL; }
            e->exec_argc++;
            bf_advance (p);
        }
        if (e->exec_argc == 0 || (tok == NULL)) {
            bf_free (e);
            builtin_error ("-exec: missing terminator (`;` or `+`)");
            return NULL;
        }
        /* For `+` form, POSIX requires `{}` immediately before `+`. */
        if (e->exec_batch && (e->exec_argc == 0 ||
            strcmp (e->exec_argv[e->exec_argc - 1], "{}") != 0)) {
            bf_free (e);
            builtin_error ("-exec ... +: `{}` must be the last argument before `+`");
            return NULL;
        }
        is_action = 1;
        ctx->had_action = 1;
        return e;
    }
    else
    {
        builtin_error ("unknown predicate: %s", t);
        return NULL;
    }
    bf_advance (p);

    bf_expr *e = bf_alloc (k);
    if (!e) return NULL;
    if (k == BF_ACCESS)
        e->nval = t[1] == 'e' ? X_OK : t[1] == 'r' ? R_OK : W_OK;
    if (k == BF_MTIME || k == BF_MMIN || k == BF_AMIN || k == BF_CMIN ||
        k == BF_ATIME || k == BF_CTIME)
    {
        /* Ages count from the start of the search, or under -daystart
           from the end of today (GNU: "from the beginning of today rather
           than from 24 hours ago"). */
        time_t now = time (NULL);
        e->tval = now;
        if (ctx->daystart) {
            struct tm tm;
            if (localtime_r (&now, &tm)) {
                tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
                tm.tm_mday += 1;
                tm.tm_isdst = -1;
                time_t end = mktime (&tm);
                if (end != (time_t) -1) e->tval = end;
            }
        }
    }

    if (needs_arg)
    {
        const char *arg = bf_peek (p);
        if (!arg) { bf_free (e); builtin_error ("predicate %s needs an argument", t); return NULL; }
        bf_advance (p);
        if (k == BF_SIZE || k == BF_MTIME || k == BF_INUM || k == BF_LINKS ||
            k == BF_MMIN || k == BF_AMIN || k == BF_CMIN ||
            k == BF_ATIME || k == BF_CTIME)
        {
            e->nval = bf_parse_signed (arg, &e->ncmp);
            /* For -size, suffix 'k', 'M', 'c': default is 512-byte blocks
               (POSIX), but we'll accept just bytes (cN), KiB (kN), MiB (MN).
               Time predicates keep nval in user units here; evaluation
               applies the minute/day bucket once so +N/-N match find-style
               truncated age semantics. */
            if (k == BF_INUM || k == BF_LINKS)
            {
                char *end;
                const char *digits = arg + (arg[0] == '+' || arg[0] == '-');
                errno = 0;
                (void) strtoull (digits, &end, 10);
                if (!*digits || *end || errno)
                    { bf_free (e); builtin_error ("invalid argument `%s' to `%s'", arg, t); return NULL; }
            }
            else if (k == BF_SIZE)
            {
                size_t l = strlen (arg);
                char suf = (l > 0) ? arg[l - 1] : 'b';
                if (suf == 'c' || suf == 'k' || suf == 'M')
                {
                    long long mult = (suf == 'c') ? 1 : (suf == 'k') ? 1024 : 1024 * 1024;
                    e->nval *= mult;
                }
                else
                {
                    /* default: 512-byte blocks */
                    e->nval *= 512;
                }
            }
        }
        else if (k == BF_REGEX || k == BF_IREGEX)
        {
            /* No REG_NOSUB: GNU -regex must match the whole path, which
               the evaluator checks from the match offsets. */
            int flags = ctx->regex_bre ? 0 : REG_EXTENDED;
            if (k == BF_IREGEX) flags |= REG_ICASE;
            if (regcomp (&e->re, arg, flags) != 0)
                { bf_free (e); builtin_error ("bad regex: %s", arg); return NULL; }
            e->re_ok = 1;
        }
        else if (k == BF_PERM)
        {
            /* MODE = exact; -MODE = all-bits-set; /MODE = any-bit-set. */
            const char *m = arg;
            char op = 'e';   /* exact */
            if (*m == '-') { op = 'a'; m++; }
            else if (*m == '/') { op = 'n'; m++; }
            mode_t mode = 0;
            if (bf_parse_perm_mode (m, &mode) != 0)
                { bf_free (e); builtin_error ("-perm: bad mode: %s", arg); return NULL; }
            e->nval = mode;
            e->ncmp = (op == 'a') ? -1 : (op == 'n') ? 1 : 0;
        }
        else if (k == BF_USER)
        {
            struct passwd *pw = getpwnam (arg);
            if (!pw) { bf_free (e); builtin_error ("-user: unknown user: %s", arg); return NULL; }
            e->nval = pw->pw_uid;
        }
        else if (k == BF_GROUP)
        {
            struct group *gr = getgrnam (arg);
            if (!gr) { bf_free (e); builtin_error ("-group: unknown group: %s", arg); return NULL; }
            e->nval = gr->gr_gid;
        }
        else if (k == BF_UID || k == BF_GID)
        {
            e->nval = atoll (arg);
        }
        else if (!strcmp (t, "-regextype"))
        {
            /* GNU's names. The BRE family compiles as POSIX basic, the
               rest (and the default, here) as POSIX extended. */
            static const char *const bre[] = {
                "posix-basic", "posix-minimal-basic", "ed", "grep", "sed", NULL
            };
            static const char *const ere[] = {
                "findutils-default", "emacs", "posix-extended", "posix-egrep",
                "egrep", "posix-awk", "awk", "gnu-awk", NULL
            };
            int found = 0;
            for (int i = 0; bre[i]; i++) if (!strcmp (arg, bre[i])) { ctx->regex_bre = 1; found = 1; }
            for (int i = 0; ere[i]; i++) if (!strcmp (arg, ere[i])) { ctx->regex_bre = 0; found = 1; }
            if (!found)
                { bf_free (e); builtin_error ("Unknown regular expression type '%s'; valid types are 'findutils-default', 'ed', 'emacs', 'gnu-awk', 'grep', 'posix-awk', 'awk', 'posix-basic', 'posix-egrep', 'egrep', 'posix-extended', 'posix-minimal-basic', 'sed'.", arg); return NULL; }
        }
        else if (k == BF_MAXDEPTH || k == BF_MINDEPTH)
        {
            int d = atoi (arg);
            if (k == BF_MAXDEPTH) ctx->maxdepth = d;
            else                  ctx->mindepth = d;
        }
        else if (k == BF_NEWER)
        {
            /* -newer = -newermm, -anewer = -neweram, -cnewer = -newercm.
               ncmp holds X, the candidate's time; Y picks the reference. */
            char x = 'm', y = 'm';
            if (!strcmp (t, "-anewer")) x = 'a';
            else if (!strcmp (t, "-cnewer")) x = 'c';
            else if (t[6]) { x = t[6]; y = t[7]; }
            if (x == 'B' || y == 'B')
                { bf_free (e); builtin_error ("%s: birth times are not supported", t); return NULL; }
            if (!strchr ("amc", x) || !strchr ("amct", y))
                { bf_free (e); builtin_error ("invalid predicate `%s'", t); return NULL; }
            e->ncmp = x;
            if (y == 't')
            {
                e->tnsec = 0;
                if (bf_parse_when (arg, &e->tval) != 0)
                {
                    /* Anything else date -d reads ("Mar 5 2024", "1 hour ago"). */
                    struct timespec now;
                    time_t t;
                    long ns;
                    clock_gettime (CLOCK_REALTIME, &now);
                    if (bd_parse_date (arg, &now, &t, &ns, 0) != 0)
                        { bf_free (e); builtin_error ("I cannot figure out how to interpret `%s' as a date or time", arg); return NULL; }
                    e->tval = t;
                    e->tnsec = ns;
                }
            }
            else
            {
                struct stat st;
                int r = ctx->follow == BF_FOLLOW_NONE ? lstat (arg, &st) : stat (arg, &st);
                if (r != 0)
                    { bf_free (e); builtin_error ("'%s': %s", arg, strerror (errno)); return NULL; }
                struct timespec ts = y == 'a' ? st.st_atim : y == 'c' ? st.st_ctim : st.st_mtim;
                e->tval = ts.tv_sec;
                e->tnsec = ts.tv_nsec;
            }
        }
        else if (k == BF_SAMEFILE)
        {
            struct stat st;
            int r = ctx->follow == BF_FOLLOW_NONE ? lstat (arg, &st) : stat (arg, &st);
            if (r != 0)
                { bf_free (e); builtin_error ("'%s': %s", arg, strerror (errno)); return NULL; }
            e->nval = (long long) st.st_ino;
            e->tval = (time_t) st.st_dev;
        }
        else if (k == BF_PRINTF)
        {
            const char *bad = NULL;
            if (bf_printf_validate (arg, &bad) != 0)
                { bf_free (e); builtin_error ("error: %% at end of format string"); return NULL; }
            e->sval = strdup (arg);
        }
        else
        {
            e->sval = strdup (arg);
        }
    }
    (void) is_action;
    return e;
}

static bf_expr *
bf_parse_and (bf_parse *p, bf_ctx *ctx)
{
    bf_expr *lhs = bf_parse_primary (p, ctx);
    if (!lhs) return NULL;
    while (bf_peek (p) && strcmp (bf_peek (p), ")") != 0
                       && strcmp (bf_peek (p), "-o") != 0)
    {
        if (!strcmp (bf_peek (p), "-a")) bf_advance (p);
        bf_expr *rhs = bf_parse_primary (p, ctx);
        if (!rhs) { bf_free (lhs); return NULL; }
        bf_expr *and_node = bf_alloc (BF_AND);
        if (!and_node) { bf_free (lhs); bf_free (rhs); return NULL; }
        and_node->a = lhs; and_node->b = rhs;
        lhs = and_node;
    }
    return lhs;
}

static bf_expr *
bf_parse_or (bf_parse *p, bf_ctx *ctx)
{
    bf_expr *lhs = bf_parse_and (p, ctx);
    if (!lhs) return NULL;
    while (bf_peek (p) && !strcmp (bf_peek (p), "-o"))
    {
        bf_advance (p);
        bf_expr *rhs = bf_parse_and (p, ctx);
        if (!rhs) { bf_free (lhs); return NULL; }
        bf_expr *or_node = bf_alloc (BF_OR);
        if (!or_node) { bf_free (lhs); bf_free (rhs); return NULL; }
        or_node->a = lhs; or_node->b = rhs;
        lhs = or_node;
    }
    return lhs;
}

/* ---- evaluator ---- */

/* lowercase a string into a buf (for -iname). */
static void
bf_strlower (const char *src, char *dst, size_t dstsz)
{
    size_t i;
    for (i = 0; i < dstsz - 1 && src[i]; i++)
        dst[i] = (char) tolower ((unsigned char) src[i]);
    dst[i] = '\0';
}

static int
bf_match_glob (const char *pat, const char *s, int icase)
{
    if (!icase) return fnmatch (pat, s, 0) == 0;
    /* Heap-alloc sized to inputs so paths >4095 bytes don't truncate. */
    size_t dlen = strlen (s) + 1, plen = strlen (pat) + 1;
    char *dst = malloc (dlen);
    char *dpat = malloc (plen);
    int rc = 0;
    if (dst && dpat)
    {
        bf_strlower (s, dst, dlen);
        bf_strlower (pat, dpat, plen);
        rc = fnmatch (dpat, dst, 0) == 0;
    }
    free (dst); free (dpat);
    return rc;
}

static int bf_eval (bf_expr *e, bf_pinfo *p, bf_ctx *ctx);

/* Run a single-shot exec for the `\;` form: substitute every `{}` in the
   template with `path`, fork+execvp+waitpid. Return WEXITSTATUS == 0. */
static int
bf_exec_once (bf_expr *e, const char *path)
{
    /* Build argv with substitutions. */
    char **argv = malloc ((size_t) (e->exec_argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    for (int i = 0; i < e->exec_argc; i++) {
        const char *t = e->exec_argv[i];
        if (strstr (t, "{}")) {
            /* Replace ALL `{}` occurrences with path. */
            size_t plen = strlen (path), tlen = strlen (t);
            size_t out_cap = tlen + plen + 1;
            char *out = malloc (out_cap);
            if (!out) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
            size_t op = 0;
            for (size_t s = 0; s < tlen;) {
                if (t[s] == '{' && t[s+1] == '}') {
                    if (op + plen + 1 > out_cap) {
                        out_cap = (op + plen + 1) * 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    memcpy (out + op, path, plen); op += plen; s += 2;
                } else {
                    if (op + 2 > out_cap) {
                        out_cap *= 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    out[op++] = t[s++];
                }
            }
            out[op] = '\0';
            argv[i] = out;
        } else {
            argv[i] = strdup (t);
            if (!argv[i]) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
        }
    }
    argv[e->exec_argc] = NULL;
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 0;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    for (int i = 0; i <= e->exec_argc; i++) free (argv[i]);
    free (argv);
    return rc;
}

/* Run a single-shot exec after chdir(dir), used by -execdir. `{}` is
   substituted with `arg_path`, normally the matched entry basename. */
static int
bf_exec_once_in_dir (bf_expr *e, const char *dir, const char *arg_path)
{
    char **argv = malloc ((size_t) (e->exec_argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    for (int i = 0; i < e->exec_argc; i++) {
        const char *t = e->exec_argv[i];
        if (strstr (t, "{}")) {
            size_t plen = strlen (arg_path), tlen = strlen (t);
            size_t out_cap = tlen + plen + 1;
            char *out = malloc (out_cap);
            if (!out) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
            size_t op = 0;
            for (size_t s = 0; s < tlen;) {
                if (t[s] == '{' && t[s+1] == '}') {
                    if (op + plen + 1 > out_cap) {
                        out_cap = (op + plen + 1) * 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    memcpy (out + op, arg_path, plen); op += plen; s += 2;
                } else {
                    if (op + 2 > out_cap) {
                        out_cap *= 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    out[op++] = t[s++];
                }
            }
            out[op] = '\0';
            argv[i] = out;
        } else {
            argv[i] = strdup (t);
            if (!argv[i]) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
        }
    }
    argv[e->exec_argc] = NULL;

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 0;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        if (chdir (dir) < 0)
            _exit (126);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    for (int i = 0; i <= e->exec_argc; i++) free (argv[i]);
    free (argv);
    return rc;
}

/* Flush a `+`-form pending batch: build argv from template (with `{}`
   replaced by ALL pending paths), fork+execvp+waitpid. */
static int
bf_exec_flush (bf_expr *e)
{
    if (e->pending_count == 0) return 1;
    /* argv = template[0..argc-2]   (everything except the trailing `{}`)
              + pending_paths[0..count-1]
              + NULL */
    int prefix_n = e->exec_argc - 1;   /* drop the `{}` placeholder */
    size_t total = (size_t) prefix_n + e->pending_count + 1;
    char **argv = malloc (total * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    int n = 0;
    for (int i = 0; i < prefix_n; i++) argv[n++] = e->exec_argv[i];
    for (size_t i = 0; i < e->pending_count; i++) argv[n++] = e->pending_paths[i];
    argv[n] = NULL;
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 1;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
        rc = 0;
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    free (argv);
    /* Reset batch. */
    for (size_t i = 0; i < e->pending_count; i++) free (e->pending_paths[i]);
    e->pending_count = 0;
    e->pending_bytes = 0;
    return rc;
}

/* Recursively flush all BF_EXEC `+` batches in the AST. */
static void
bf_flush_all (bf_expr *e, bf_ctx *ctx)
{
    if (!e) return;
    bf_flush_all (e->a, ctx);
    bf_flush_all (e->b, ctx);
    if (e->kind == BF_EXEC && e->exec_batch && !bf_exec_flush (e)) ctx->exit_status = 1;
}

/* Append a path to a `+`-form node's pending batch. Flush if batch is
   getting large (env limit minus reserved slack). */
static int
bf_exec_batch_append (bf_expr *e, const char *path, bf_ctx *ctx)
{
    /* Use a conservative cap — half ARG_MAX or 64 KiB, whichever smaller. */
    long arg_max = sysconf (_SC_ARG_MAX);
    if (arg_max <= 0) arg_max = 131072;
    size_t cap_bytes = (size_t) arg_max / 2;
    if (cap_bytes > 65536) cap_bytes = 65536;
    size_t plen = strlen (path) + 1;
    if (e->pending_count > 0 && e->pending_bytes + plen > cap_bytes && !bf_exec_flush (e))
        ctx->exit_status = 1;
    if (e->pending_count >= e->pending_cap) {
        size_t nc = e->pending_cap ? e->pending_cap * 2 : 16;
        char **n = realloc (e->pending_paths, nc * sizeof *n);
        if (!n) { builtin_error ("oom in -exec batch"); return 0; }
        e->pending_paths = n;
        e->pending_cap = nc;
    }
    e->pending_paths[e->pending_count] = strdup (path);
    if (!e->pending_paths[e->pending_count]) return 0;
    e->pending_count++;
    e->pending_bytes += plen;
    return 1;   /* `+` form is always-true predicate */
}

static char
bf_type_char (mode_t m)
{
    if (S_ISREG (m))  return 'f';
    if (S_ISDIR (m))  return 'd';
    if (S_ISLNK (m))  return 'l';
    if (S_ISFIFO (m)) return 'p';
    if (S_ISSOCK (m)) return 's';
    if (S_ISBLK (m))  return 'b';
    if (S_ISCHR (m))  return 'c';
    return '?';
}

/* ls -l style mode string, e.g. "-rw-r--r--" (GNU -printf %M). */
static void
bf_mode_string (mode_t m, char *b)
{
    b[0] = S_ISDIR (m) ? 'd' : S_ISLNK (m) ? 'l' : S_ISCHR (m) ? 'c'
         : S_ISBLK (m) ? 'b' : S_ISFIFO (m) ? 'p' : S_ISSOCK (m) ? 's' : '-';
    b[1] = (m & S_IRUSR) ? 'r' : '-';
    b[2] = (m & S_IWUSR) ? 'w' : '-';
    b[3] = (m & S_ISUID) ? ((m & S_IXUSR) ? 's' : 'S') : ((m & S_IXUSR) ? 'x' : '-');
    b[4] = (m & S_IRGRP) ? 'r' : '-';
    b[5] = (m & S_IWGRP) ? 'w' : '-';
    b[6] = (m & S_ISGID) ? ((m & S_IXGRP) ? 's' : 'S') : ((m & S_IXGRP) ? 'x' : '-');
    b[7] = (m & S_IROTH) ? 'r' : '-';
    b[8] = (m & S_IWOTH) ? 'w' : '-';
    b[9] = (m & S_ISVTX) ? ((m & S_IXOTH) ? 't' : 'T') : ((m & S_IXOTH) ? 'x' : '-');
    b[10] = '\0';
}

/* A time for %a/%c/%t (KIND 0) or %Ak/%Ck/%Tk.  GNU adds the fraction,
   ten digits, to @ (epoch), + (date+time), S, T and X, and to the
   ctime-like %a/%c/%t form. */
static void
bf_time_string (char kind, const struct timespec *ts, char *buf, size_t sz)
{
    struct tm tm;
    time_t t = ts->tv_sec;
    char frac[16], tmp[128];
    snprintf (frac, sizeof frac, "%09ld0", (long) ts->tv_nsec);
    if (kind == '@')
    {
        snprintf (buf, sz, "%lld.%s", (long long) t, frac);
        return;
    }
    if (!localtime_r (&t, &tm))
    {
        snprintf (buf, sz, "%lld", (long long) t);
        return;
    }
    const char *f = NULL;
    switch (kind)
    {
        case 0:   f = "%a %b %e %H:%M:%S"; break;
        case '+': f = "%Y-%m-%d+%H:%M:%S"; break;
        case 'S': f = "%S"; break;
        case 'T': f = "%H:%M:%S"; break;
        case 'X': f = "%X"; break;
    }
    if (f)
    {
        if (strftime (tmp, sizeof tmp, f, &tm) == 0) tmp[0] = '\0';
        if (kind == 0)
        {
            char year[16];
            strftime (year, sizeof year, "%Y", &tm);
            snprintf (buf, sz, "%s.%s %s", tmp, frac, year);
        }
        else
            snprintf (buf, sz, "%s.%s", tmp, frac);
        return;
    }
    char one[3] = { '%', kind, '\0' };
    if (strftime (buf, sz, one, &tm) == 0) buf[0] = '\0';
}

/* The file system type of DEV (GNU %F), from /proc/self/mountinfo. */
static void
bf_fstype (dev_t dev, char *buf, size_t sz)
{
    snprintf (buf, sz, "unknown");
    FILE *f = fopen ("/proc/self/mountinfo", "r");
    if (!f) return;
    char *line = NULL;
    size_t cap = 0;
    while (getline (&line, &cap, f) > 0)
    {
        unsigned ma, mi;
        if (sscanf (line, "%*s %*s %u:%u", &ma, &mi) != 2) continue;
        if (ma != major (dev) || mi != minor (dev)) continue;
        char *sep = strstr (line, " - ");
        if (!sep) continue;
        char type[64];
        if (sscanf (sep + 3, "%63s", type) == 1)
            snprintf (buf, sz, "%s", type);
        break;
    }
    free (line);
    fclose (f);
}

/* Print VAL under the directive's flags, width and precision (SPEC, the
   text between '%' and the letter), as GNU prints its string fields:
   only '-', the width and the precision matter. */
static void
bf_put_field (FILE *out, const char *spec, size_t speclen, const char *val)
{
    char fmt[64];
    size_t n = 0, i = 0;
    int left = 0;
    for (; i < speclen && strchr ("-+ #0", spec[i]); i++)
        if (spec[i] == '-') left = 1;
    fmt[n++] = '%';
    if (left) fmt[n++] = '-';
    for (; i < speclen && n < sizeof fmt - 2; i++)
        fmt[n++] = spec[i];
    fmt[n++] = 's';
    fmt[n] = '\0';
    fprintf (out, fmt, val);
}

static int
bf_printf_emit (bf_pinfo *p, const char *fmt, FILE *out)
{
    char buf[PATH_MAX + 64];
    for (const char *s = fmt; *s; s++)
    {
        if (*s == '\\')
        {
            s++;
            switch (*s)
            {
                case '\0': putc ('\\', out); return 1;
                case 'a': putc ('\a', out); break;
                case 'b': putc ('\b', out); break;
                case 'c': fflush (out); return 1;   /* stop this format */
                case 'f': putc ('\f', out); break;
                case 'n': putc ('\n', out); break;
                case 'r': putc ('\r', out); break;
                case 't': putc ('\t', out); break;
                case 'v': putc ('\v', out); break;
                case '\\': putc ('\\', out); break;
                default:
                    if (*s >= '0' && *s <= '7')
                    {
                        int v = 0, n = 0;
                        while (n < 3 && *s >= '0' && *s <= '7') { v = v * 8 + (*s - '0'); s++; n++; }
                        s--;
                        putc (v, out);
                    }
                    else
                    {
                        putc ('\\', out);
                        putc (*s, out);
                    }
                    break;
            }
            continue;
        }
        if (*s != '%')
        {
            putc (*s, out);
            continue;
        }

        const char *spec = s + 1, *d = spec;
        while (*d && strchr ("-+ #0", *d)) d++;
        while (isdigit ((unsigned char) *d)) d++;
        if (*d == '.') { d++; while (isdigit ((unsigned char) *d)) d++; }
        size_t speclen = (size_t) (d - spec);
        const char *val = buf;
        buf[0] = '\0';
        switch (*d)
        {
            case '\0':
                return 1;
            case '%':
                putc ('%', out);
                s = d;
                continue;
            case 'p': val = p->path; break;
            case 'P':
                /* Path with the command-line starting point removed (GNU
                   find %P). For root ".", "./a/b" -> "a/b"; the start
                   itself -> "". */
                val = p->path;
                if (p->root && *p->root)
                {
                    size_t rl = strlen (p->root);
                    if (strncmp (val, p->root, rl) == 0)
                    {
                        val += rl;
                        if (*val == '/') val++;
                    }
                }
                break;
            case 'f': val = p->base; break;
            case 'h':
            {
                const char *slash = strrchr (p->path, '/');
                if (!slash) val = ".";
                else if (slash == p->path) val = "/";
                else snprintf (buf, sizeof buf, "%.*s", (int) (slash - p->path), p->path);
                break;
            }
            case 'H': val = p->root ? p->root : ""; break;
            case 'y': buf[0] = bf_type_char (p->st.st_mode); buf[1] = '\0'; break;
            case 'Y':
            {
                struct stat t;
                if (!S_ISLNK (p->st.st_mode)) buf[0] = bf_type_char (p->st.st_mode);
                else if (stat (p->path, &t) == 0) buf[0] = bf_type_char (t.st_mode);
                else buf[0] = errno == ELOOP ? 'L' : errno == ENOENT ? 'N' : '?';
                buf[1] = '\0';
                break;
            }
            case 's': snprintf (buf, sizeof buf, "%lld", (long long) p->st.st_size); break;
            case 'b': snprintf (buf, sizeof buf, "%lld", (long long) p->st.st_blocks); break;
            case 'k': snprintf (buf, sizeof buf, "%lld", ((long long) p->st.st_blocks + 1) / 2); break;
            case 'd': snprintf (buf, sizeof buf, "%d", p->depth); break;
            case 'D': snprintf (buf, sizeof buf, "%llu", (unsigned long long) p->st.st_dev); break;
            case 'i': snprintf (buf, sizeof buf, "%llu", (unsigned long long) p->st.st_ino); break;
            case 'n': snprintf (buf, sizeof buf, "%llu", (unsigned long long) p->st.st_nlink); break;
            case 'U': snprintf (buf, sizeof buf, "%lu", (unsigned long) p->st.st_uid); break;
            case 'G': snprintf (buf, sizeof buf, "%lu", (unsigned long) p->st.st_gid); break;
            case 'u':
            {
                struct passwd *pw = getpwuid (p->st.st_uid);
                if (pw) snprintf (buf, sizeof buf, "%s", pw->pw_name);
                else snprintf (buf, sizeof buf, "%lu", (unsigned long) p->st.st_uid);
                break;
            }
            case 'g':
            {
                struct group *gr = getgrgid (p->st.st_gid);
                if (gr) snprintf (buf, sizeof buf, "%s", gr->gr_name);
                else snprintf (buf, sizeof buf, "%lu", (unsigned long) p->st.st_gid);
                break;
            }
            case 'm':
            {
                /* Octal permission bits; the flags work as for printf %o. */
                char ofmt[64];
                size_t n = 0;
                ofmt[n++] = '%';
                for (size_t i = 0; i < speclen && n < sizeof ofmt - 2; i++)
                    if (spec[i] != '+' && spec[i] != ' ') ofmt[n++] = spec[i];
                ofmt[n++] = 'o';
                ofmt[n] = '\0';
                fprintf (out, ofmt, (unsigned) (p->st.st_mode & 07777));
                s = d;
                continue;
            }
            case 'M': bf_mode_string (p->st.st_mode, buf); break;
            case 'l':
            {
                if (S_ISLNK (p->st.st_mode))
                {
                    ssize_t n = readlink (p->path, buf, sizeof buf - 1);
                    buf[n < 0 ? 0 : n] = '\0';
                }
                break;
            }
            case 'S':
            {
                double v = p->st.st_size ? (512.0 * (double) p->st.st_blocks) / (double) p->st.st_size : 1.0;
                snprintf (buf, sizeof buf, "%g", v);
                break;
            }
            case 'F': bf_fstype (p->st.st_dev, buf, sizeof buf); break;
            case 'a': bf_time_string (0, &p->st.st_atim, buf, sizeof buf); break;
            case 'c': bf_time_string (0, &p->st.st_ctim, buf, sizeof buf); break;
            case 't': bf_time_string (0, &p->st.st_mtim, buf, sizeof buf); break;
            case 'A':
            case 'C':
            case 'T':
            {
                const struct timespec *ts = *d == 'A' ? &p->st.st_atim
                                          : *d == 'C' ? &p->st.st_ctim : &p->st.st_mtim;
                if (!d[1])
                {
                    fprintf (out, "%%%c", *d);
                    return 1;
                }
                if (!strchr (BF_PRINTF_TIMECHARS, d[1]))
                {
                    /* GNU prints an unknown time letter as %<letter>. */
                    fprintf (out, "%%%c", d[1]);
                    s = d + 1;
                    continue;
                }
                bf_time_string (d[1], ts, buf, sizeof buf);
                d++;
                break;
            }
            default:
                /* Unknown directive: warned about at parse time; printed
                   literally, as GNU does. */
                fputc ('%', out);
                fwrite (spec, 1, speclen, out);
                fputc (*d, out);
                s = d;
                continue;
        }
        bf_put_field (out, spec, speclen, val);
        s = d;
    }
    return 1;
}

static int
bf_eval (bf_expr *e, bf_pinfo *p, bf_ctx *ctx)
{
    if (ctx->quit) return 0;
    if (!e) return 1;
    switch (e->kind)
    {
        case BF_AND:
            return bf_eval (e->a, p, ctx) && bf_eval (e->b, p, ctx);
        case BF_OR:
            return bf_eval (e->a, p, ctx) || bf_eval (e->b, p, ctx);
        case BF_NOT:
            return !bf_eval (e->a, p, ctx);
        case BF_NAME:
            return bf_match_glob (e->sval, p->base, 0);
        case BF_INAME:
            return bf_match_glob (e->sval, p->base, 1);
        case BF_PATH:
            return fnmatch (e->sval, p->path, 0) == 0;
        case BF_IPATH:
            return fnmatch (e->sval, p->path, FNM_CASEFOLD) == 0;
        case BF_ACCESS:
            return access (p->path, (int) e->nval) == 0;
        case BF_TYPE:
        {
            char want = e->sval[0];
            mode_t m = p->st.st_mode;
            switch (want)
            {
                case 'f': return S_ISREG (m);
                case 'd': return S_ISDIR (m);
                case 'l': return S_ISLNK (m);
                case 'c': return S_ISCHR (m);
                case 'b': return S_ISBLK (m);
                case 'p': return S_ISFIFO (m);
                case 's': return S_ISSOCK (m);
            }
            return 0;
        }
        case BF_SIZE:
            switch (e->ncmp)
            {
                case  0: return (long long) p->st.st_size == e->nval;
                case  1: return (long long) p->st.st_size >  e->nval;
                case -1: return (long long) p->st.st_size <  e->nval;
            }
            return 0;
        case BF_MTIME:
        {
            /* GNU find: `-mtime N` divides age by 86400 and compares
               the truncated count, so the operand is in DAYS, not
               seconds. Multiply nval by the bucket size before the
               comparison; case 1 (+N "older than N days") uses
               age >= (N+1)*bucket because truncation makes
               int(age/bucket) > N equivalent to age >= (N+1)*bucket. */
            time_t age = e->tval - p->st.st_mtime;
            long long threshold = (long long) e->nval * 86400;
            switch (e->ncmp)
            {
                case  0: return (long long) age >= threshold &&
                                (long long) age <  threshold + 86400;
                case  1: return (long long) age >= threshold + 86400;
                case -1: return (long long) age <  threshold;
            }
            return 0;
        }
        case BF_NEWER:
        {
            /* GNU find compares full-precision times: a file is newer iff
               its time is strictly greater than the reference's, tie-broken
               by nanoseconds. Second-granularity (st_mtime) wrongly treats
               sub-second-newer files as not newer. */
            struct timespec ts = e->ncmp == 'a' ? p->st.st_atim
                               : e->ncmp == 'c' ? p->st.st_ctim : p->st.st_mtim;
            return ts.tv_sec > e->tval
                   || (ts.tv_sec == e->tval && ts.tv_nsec > e->tnsec);
        }
        case BF_SAMEFILE:
            return (long long) p->st.st_ino == e->nval && p->st.st_dev == (dev_t) e->tval;
        case BF_INUM:
        case BF_LINKS:
        {
            unsigned long long v = e->kind == BF_INUM ? (unsigned long long) p->st.st_ino
                                                      : (unsigned long long) p->st.st_nlink;
            unsigned long long n = (unsigned long long) e->nval;
            return e->ncmp > 0 ? v > n : e->ncmp < 0 ? v < n : v == n;
        }
        case BF_MMIN:
        case BF_AMIN:
        case BF_CMIN:
        case BF_ATIME:
        case BF_CTIME:
        {
            /* GNU find: operand is in MINUTES for -*min and DAYS for
               -*time. Same truncation rule as BF_MTIME above. */
            time_t now = e->tval;
            time_t when = (e->kind == BF_AMIN || e->kind == BF_ATIME)
                              ? p->st.st_atime
                          : (e->kind == BF_CMIN || e->kind == BF_CTIME)
                              ? p->st.st_ctime
                              : p->st.st_mtime;
            time_t age = now - when;
            int bucket = (e->kind == BF_MMIN || e->kind == BF_AMIN || e->kind == BF_CMIN)
                              ? 60 : 86400;
            long long threshold = (long long) e->nval * bucket;
            switch (e->ncmp)
            {
                case  0: return (long long) age >= threshold &&
                                (long long) age <  threshold + bucket;
                case  1: return (long long) age >= threshold + bucket;
                case -1: return (long long) age <  threshold;
            }
            return 0;
        }
        case BF_REGEX:
        case BF_IREGEX:
        {
            regmatch_t m;
            if (!e->re_ok) return 0;
            return regexec (&e->re, p->path, 1, &m, 0) == 0
                   && m.rm_so == 0 && (size_t) m.rm_eo == strlen (p->path);
        }
        case BF_PERM:
        {
            mode_t m = p->st.st_mode & 07777;
            mode_t want = (mode_t) e->nval;
            switch (e->ncmp)
            {
                case  0: return m == want;
                case -1: return (m & want) == want;     /* all bits set */
                case  1: return (m & want) != 0;        /* any bit set */
            }
            return 0;
        }
        case BF_USER:
        case BF_UID:
            return p->st.st_uid == (uid_t) e->nval;
        case BF_GROUP:
        case BF_GID:
            return p->st.st_gid == (gid_t) e->nval;
        case BF_NOUSER:
            return getpwuid (p->st.st_uid) == NULL;
        case BF_NOGROUP:
            return getgrgid (p->st.st_gid) == NULL;
        case BF_DELETE:
        {
            int rc;
            if (!strcmp (p->base, ".") || !strcmp (p->base, "..")) {
                builtin_warning ("refusing to delete %s", p->path);
                ctx->exit_status = 1;
                return 0;
            }
            rc = S_ISDIR (p->st.st_mode) ? rmdir (p->path) : unlink (p->path);
            if (rc < 0) {
                builtin_warning ("%s %s: %s",
                                 S_ISDIR (p->st.st_mode) ? "rmdir" : "unlink",
                                 p->path, strerror (errno));
                ctx->exit_status = 1;
            }
            return rc == 0;
        }
        case BF_EXECDIR:
        {
            /* Like -exec but run from the matched file's parent directory;
               {} is replaced with ./basename. */
            const char *base = strrchr (p->path, '/');
            base = base ? base + 1 : p->path;
            char relbuf[PATH_MAX];
            char dirbuf[PATH_MAX];
            const char *slash = strrchr (p->path, '/');
            if (slash) {
                size_t n = (size_t) (slash - p->path);
                if (n == 0) n = 1;
                if (n >= sizeof dirbuf) return 0;
                memcpy (dirbuf, p->path, n);
                dirbuf[n] = '\0';
            } else {
                snprintf (dirbuf, sizeof dirbuf, ".");
            }
            if (snprintf (relbuf, sizeof relbuf, "./%s", base) >= (int) sizeof relbuf)
                return 0;
            return bf_exec_once_in_dir (e, dirbuf, relbuf);
        }
        case BF_EMPTY:
            if (S_ISREG (p->st.st_mode)) return p->st.st_size == 0;
            if (S_ISDIR (p->st.st_mode)) {
                DIR *d = opendir (p->path);
                if (!d) return 0;
                int empty = 1;
                struct dirent *de;
                while ((de = readdir (d)) != NULL) {
                    if (strcmp (de->d_name, ".") && strcmp (de->d_name, "..")) {
                        empty = 0; break;
                    }
                }
                closedir (d);
                return empty;
            }
            return 0;
        case BF_QUIT:
            ctx->quit = 1;
            return 0;
        case BF_PRUNE:
            if (!ctx->postorder)
                ctx->pruned = 1;
            return 1;       /* always true */
        case BF_PRINT:
        case BF_PRINT0:
        {
            FILE *o = e->out ? e->out : stdout;
            fputs (p->path, o);
            putc (e->kind == BF_PRINT0 ? '\0' : '\n', o);
            return 1;
        }
        case BF_PRINTF:
            return bf_printf_emit (p, e->sval, e->out ? e->out : stdout);
        case BF_EXEC:
            if (e->exec_batch)
                return bf_exec_batch_append (e, p->path, ctx);
            return bf_exec_once (e, p->path);
        case BF_MAXDEPTH:
        case BF_MINDEPTH:
        case BF_XDEV:
        case BF_TRUE:
            return 1;
        case BF_FALSE:
            return 0;
    }
    return 0;
}

/* Per-descent-chain (dev,ino) stack for symlink-loop detection under -L.
   GNU find only detects *cyclic* re-entry: a directory that is an
   ancestor of itself in the current descent chain. Two distinct path
   spellings of the same inode (e.g. `tree/d1/x` and `tree/link-to-d1/x`)
   are NOT a loop — both are walked. The earlier implementation used a
   monotonic seen-set which collapsed those spellings and dropped one of
   the walks; that doesn't match GNU and silently lost output. The
   stack is pushed on directory entry and popped on exit so siblings
   don't pollute each other's history. */
typedef struct {
    int     used, cap;
    dev_t  *dev;
    ino_t  *ino;
} bf_seen;

static int
bf_chain_contains (const bf_seen *s, const struct stat *st)
{
    for (int i = 0; i < s->used; i++)
        if (s->dev[i] == st->st_dev && s->ino[i] == st->st_ino) return 1;
    return 0;
}

static int
bf_chain_push (bf_seen *s, const struct stat *st)
{
    if (s->used == s->cap)
    {
        int nc = s->cap ? s->cap * 2 : 16;
        dev_t *nd = realloc (s->dev, nc * sizeof *nd);
        if (!nd) return 0;
        s->dev = nd;  /* commit first realloc before attempting second */
        ino_t *ni = realloc (s->ino, nc * sizeof *ni);
        if (!ni) return 0;  /* dev grew but ino didn't; cap unchanged so used<cap remains false */
        s->ino = ni; s->cap = nc;
    }
    s->dev[s->used] = st->st_dev;
    s->ino[s->used] = st->st_ino;
    s->used++;
    return 1;
}

static void
bf_chain_pop (bf_seen *s)
{
    if (s->used > 0) s->used--;
}

/* Recursive walker. */
static void
bf_walk (const char *path, int depth, bf_ctx *ctx, bf_seen *seen)
{
    struct stat st;
    /* Remember the command-line starting point so -printf %P can strip it. */
    if (depth == 0)
        ctx->start_path = path;
    /* -L: follow symlinks at every depth.
       -H: follow symlinks only when the path was named on the command
            line (depth == 0).
       -P (default): never follow. */
    int do_stat = (ctx->follow == BF_FOLLOW_ALL)
                || (ctx->follow == BF_FOLLOW_ARGS && depth == 0);
    int sr = do_stat ? stat (path, &st) : lstat (path, &st);
    if (sr != 0)
    {
        /* Symlink-follow miss (-L on a dangling link) falls back to lstat
           so the symlink itself is still reported, mirroring GNU find. */
        if (do_stat && (errno == ENOENT || errno == ELOOP) &&
            lstat (path, &st) == 0)
        {
            /* keep going with the symlink-itself stat */
        }
        else
        {
            /* Missing paths are search errors too. A dangling symlink
               successfully handled by lstat above is still searchable. */
            builtin_warning ("%s: %s", path, strerror (errno));
            ctx->exit_status = 1;
            return;
        }
    }

    if (ctx->maxdepth >= 0 && depth > ctx->maxdepth) return;
    if (depth == 0) {
        ctx->root_dev = st.st_dev;
        ctx->root_dev_valid = 1;
    }

    /* Cycle detection only for directories — files can't loop. Only
       meaningful under -L: with -P/-H we lstat() at depth>0 so a
       symlinked-back-to-ancestor entry is reported as a symlink and
       never descended into. Under -L we follow at every depth, so a
       directory that's already on the current descent chain (an
       ancestor of itself via symlink) would otherwise recurse
       forever. We do NOT dedup against sibling/cousin chains —
       two distinct path-spellings of the same inode are both walked
       (matching GNU find -L). */
    int is_dir = S_ISDIR (st.st_mode);
    int pushed = 0;
    if (is_dir && ctx->follow == BF_FOLLOW_ALL)
    {
        if (bf_chain_contains (seen, &st)) {
            builtin_warning ("%s: filesystem loop detected", path);
            ctx->exit_status = 1;
            return;
        }
        pushed = bf_chain_push (seen, &st);
        if (!pushed) {
            builtin_error ("%s: cannot allocate directory traversal state", path);
            ctx->exit_status = 1;
            return;
        }
    }

    /* Find the basename. */
    const char *base = strrchr (path, '/');
    base = base ? base + 1 : path;

    bf_pinfo info = { .path = path, .base = base, .root = ctx->start_path, .depth = depth, .st = st };
    int saved_pruned = ctx->pruned;
    ctx->pruned = 0;

    if (!ctx->postorder && depth >= ctx->mindepth)
    {
        int matched = bf_eval (ctx->root, &info, ctx);
        if (!ctx->quit && matched && !ctx->had_action)
        {
            /* default action: -print */
            fputs (path, stdout);
            putchar (ctx->print0 ? '\0' : '\n');
        }
    }

    if (is_dir && !ctx->quit && !ctx->pruned
        && (ctx->maxdepth < 0 || depth < ctx->maxdepth)
        && (!ctx->xdev || depth == 0 || !ctx->root_dev_valid
            || st.st_dev == ctx->root_dev))
    {
        DIR *d = opendir (path);
        if (d)
        {
            struct dirent *de;
            while (!ctx->quit && (de = readdir (d)) != NULL)
            {
                const char *n = de->d_name;
                if (!strcmp (n, ".") || !strcmp (n, "..")) continue;
                size_t pl = strlen (path), nl = strlen (n);
                int slash = (pl == 0 || path[pl - 1] != '/') ? 1 : 0;
                char *child = malloc (pl + slash + nl + 1);
                if (!child) continue;
                memcpy (child, path, pl);
                if (slash) child[pl] = '/';
                memcpy (child + pl + slash, n, nl + 1);
                bf_walk (child, depth + 1, ctx, seen);
                free (child);
            }
            closedir (d);
        }
        else
        {
            /* Permission-denied / I/O errors on a directory we already
               reported: warn-and-continue, and flag the run as partial
               (exit 1). ENOENT means the directory vanished between
               stat() and opendir() — silence, mirroring GNU find. */
            if (errno != ENOENT) {
                builtin_warning ("%s: %s", path, strerror (errno));
                ctx->exit_status = 1;
            }
        }
    }

    if (!ctx->quit && ctx->postorder && depth >= ctx->mindepth)
    {
        int matched = bf_eval (ctx->root, &info, ctx);
        if (!ctx->quit && matched && !ctx->had_action)
        {
            /* default action: -print */
            fputs (path, stdout);
            putchar (ctx->print0 ? '\0' : '\n');
        }
    }

    /* Pop the ancestor-chain entry so a sibling subtree reachable via a
       different path-spelling isn't blocked from descending into the
       same inode. */
    if (pushed) bf_chain_pop (seen);
    ctx->pruned = saved_pruned;
}

int
find_builtin (WORD_LIST *list)
{
    bf_reported = 0;
    /* Convert WORD_LIST → argv. */
    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    if (list && !strcmp (list->word->word, "--help")) {
        builtin_help ();
        return EXECUTION_SUCCESS;
    }
	if (argc < 1)
	{
	    builtin_usage ();
	    return EX_USAGE;
	}
    char **argv = malloc ((argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    /* POSIX: -H/-L/-P appear before the path list. Last one wins so a
       caller can layer flags. Anything else falls through to path/expr
       handling below. */
    bf_follow follow = BF_FOLLOW_NONE;
    int opt_start = 0;
    while (opt_start < argc) {
        const char *a = argv[opt_start];
        if      (!strcmp (a, "-H")) follow = BF_FOLLOW_ARGS;
        else if (!strcmp (a, "-L")) follow = BF_FOLLOW_ALL;
        else if (!strcmp (a, "-P")) follow = BF_FOLLOW_NONE;
        else break;
        opt_start++;
    }
    int eff_argc   = argc - opt_start;
    char **eff_argv = argv + opt_start;

    /* Split argv into PATHs (until first arg starting with - or ! or () and EXPR. */
    int n_paths = 0;
    for (int j = 0; j < eff_argc; j++)
    {
        const char *a = eff_argv[j];
        if (a[0] == '-' || !strcmp (a, "(") || !strcmp (a, "!")) break;
        n_paths++;
    }
    /* When no path is given, default to ".". Don't mutate eff_argv[0] —
       it's the first expression token and clobbering it loses the
       predicate. */
    const char *default_path = ".";
    char **paths;
    int paths_count;
    if (n_paths == 0) { paths = (char **) &default_path; paths_count = 1; }
    else               { paths = eff_argv; paths_count = n_paths; }

    bf_ctx ctx = {0};
    ctx.maxdepth = -1;
    ctx.mindepth = 0;
    ctx.follow   = follow;

    bf_parse pp = { .argc = eff_argc - n_paths, .argv = eff_argv + n_paths, .pos = 0 };
    if (pp.argc > 0)
    {
        ctx.root = bf_parse_or (&pp, &ctx);
        if (!ctx.root || pp.pos != pp.argc)
	        {
	            bf_free (ctx.root);
	            if (!bf_reported) {
	                const char *unparsed = (pp.pos < pp.argc) ? pp.argv[pp.pos] : "(end of args)";
	                builtin_error ("parse error in find expression at: %s", unparsed);
	                builtin_usage ();
	            }
	            free (argv);
	            return EXECUTION_FAILURE;
	        }
    }

    bf_seen seen = {0};
    for (int j = 0; j < paths_count && !ctx.quit; j++) {
        ctx.root_dev_valid = 0;
        bf_walk (paths[j], 0, &ctx, &seen);
    }

    /* Flush any pending `-exec ... +` batches. */
    bf_flush_all (ctx.root, &ctx);

    bf_free (ctx.root);
    free (seen.dev);
    free (seen.ino);
    free (argv);
    /* Match GNU/BSD find: 0 on full success, 1 if any path could not be
       descended (permission denied, broken non-ENOENT lstat). */
    return ctx.exit_status ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *find_doc[] = {
    "POSIX-shape find(1) — recursive directory search.",
    "",
    "    bashfind [-H|-L|-P] PATH... [EXPR]",
    "",
    "    -H  follow symlinks only when named on the command line",
    "    -L  follow symlinks at every depth (cycles broken by dev/ino)",
    "    -P  never follow symlinks (default)",
    "",
    "Predicates:",
    "    -name PAT        glob match against basename",
    "    -iname PAT       case-insensitive -name",
    "    -path PAT        glob match against full path (also -wholename)",
    "    -ipath PAT       case-insensitive -path (also -iwholename)",
    "    -type X          X is one of f d l c b p s",
    "    -size N[ckM]     size compare; +N larger / -N smaller",
    "    -mtime N         modified N days ago; +N older / -N newer",
    "    -mmin N          modified N minutes ago; +N older / -N newer",
    "    -amin/-cmin N    access/change time in minutes",
    "    -atime/-ctime N  access/change time in days",
    "    -daystart        later -*min/-*time ages count from the end of today",
    "    -perm MODE       exact mode; -MODE all bits; /MODE any bit",
    "                     MODE may be octal or symbolic (u+x,g-w,a=r)",
    "    -user/-group N   owner/group name",
    "    -uid/-gid N      numeric owner/group id",
    "    -nouser/-nogroup owner/group id has no passwd/group entry",
    "    -regex PAT       regex that must match the whole path (ERE by default)",
    "    -iregex PAT      case-insensitive -regex",
    "    -regextype TYPE  posix-basic, posix-minimal-basic, ed, grep, sed (BRE);",
    "                     posix-extended, posix-egrep, egrep, awk, posix-awk,",
    "                     gnu-awk, emacs, findutils-default (ERE)",
    "    -maxdepth N      limit recursion",
    "    -mindepth N      skip output until depth >= N",
    "    -depth           evaluate each directory after its contents (always true)",
    "    -xdev, -mount    do not descend into directories on other filesystems",
    "    -quit            stop immediately after flushing pending -exec ... + batches",
    "    -prune           skip subtree below this point unless -depth or -delete is used",
    "    -empty           zero-size files / empty directories",
    "    -newer FILE      modified after FILE's mtime",
    "    -anewer/-cnewer FILE, -newerXY REF   X (a, m, c) of the file is newer",
    "                     than Y (a, m, c of REF, or t: REF is a date)",
    "    -samefile FILE   same inode as FILE;  -inum [+-]N;  -links [+-]N",
    "    -executable, -readable, -writable   access(2) allows it",
    "    -true, -false    always true / always false",
    "Operators: -a (implicit), -o, ! / -not, ( )",
    "Actions:",
    "    -print           one path per line (default)",
    "    -print0          NUL-separated paths (pipe to xargs -0)",
    "    -printf FORMAT   GNU directives %% %a %Ak %b %c %Ck %d %D %f %F %g %G %h",
    "                     %H %i %k %l %m %M %n %p %P %s %S %t %Tk %u %U %y %Y with",
    "                     [-][WIDTH][.PREC] (k: strftime letter or @ + S T X);",
    "                     escapes \\a \\b \\c \\f \\n \\r \\t \\v \\\\ \\NNN",
    "    -fprint FILE, -fprint0 FILE, -fprintf FILE FORMAT",
    "                     -print, -print0, -printf into FILE",
    "    -delete          depth-first unlink/rmdir matched paths",
    "    -exec CMD {} \\;  per-file fork+exec (`{}` substituted)",
    "    -exec CMD {} +   batched: queue paths up to ARG_MAX, then exec",
    "    -execdir CMD ... like -exec but cwd is the file's parent dir",
    "",
    "Out of scope: birth times (-newerB*), SELinux %Z, emacs regex syntax.",
    (char *)NULL
};

struct builtin bashfind_struct = {
    "bashfind",
    find_builtin,
    BUILTIN_ENABLED,
    find_doc,
    "bashfind [-H|-L|-P] PATH... [EXPR]",
    0
};
