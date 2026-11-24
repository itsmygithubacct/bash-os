/* bashdu.c — POSIX du(1) as a bash builtin.
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdu [-0AabBcDhklmHLPSs] [-d N|--max-depth=N] [-x] [-X FILE]
 *          [--exclude=PATTERN] [--inodes] [--files0-from=FILE | PATH...]
 *
 *   -0   end each output line with NUL, not newline
 *   -A   apparent size in blocks
 *   -a   report sizes for files too (default: directories only)
 *   -B SIZE  scale sizes by SIZE before printing
 *   -b   apparent size in bytes
 *   -c   print a grand total
 *   -h   human-readable sizes (1.0K, 2.5G, etc.)
 *   -k   1024-byte blocks (POSIX default)
 *   -l   count sizes many times if hard linked
 *   -m   1MiB blocks
 *   -H   follow command-line symbolic links
 *   -L   follow all symbolic links
 *   -P   don't dereference symbolic links (default)
 *   -S   for directories, don't include subdirectory sizes
 *   -s   summary only (top-level totals)
 *   -d N --max-depth=N   only print depth ≤ N
 *   -x   don't cross filesystem boundaries
 *   --exclude=PATTERN, -X FILE|--exclude-from=FILE
 *        skip names matching a shell PATTERN (GNU: the whole path or any
 *        tail of it after a '/')
 *   --inodes  count inodes instead of sizes
 *   --files0-from=FILE  take the NUL-separated operands from FILE (- = stdin)
 *
 * No PATH defaults to '.'. Hard-linked files are counted once
 * (we track (dev, ino) seen-set). Sizes use st_blocks * 512 to
 * match real disk usage including sparse-file holes.
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
#include <inttypes.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "shim-prog-name.h"

/* GNU du's operand diagnostics: "cannot access 'NAME'" for a failed stat,
   "cannot read directory 'NAME'" for a failed open. */
static void
bdu_error (const char *what, const char *path, int error)
{
    char *q = bos_quoteaf (path);
    builtin_error ("%s %s: %s", what, q ? q : path, strerror (error));
    free (q);
}

typedef struct {
    const char **v;
    int n;
    int cap;
} bdu_words;

/* How sizes are printed. The last of -b, -k, -m, -h, --si, -B and
   --block-size given wins, as in GNU du. */
enum { BDU_BLOCKS, BDU_HUMAN, BDU_SI };

typedef struct {
    int aflag, apparent, cflag, count_links, null_terminate, separate_dirs, sflag, xflag;
    int dereference;
    int inodes;
    int fmt;                /* BDU_BLOCKS, BDU_HUMAN or BDU_SI */
    uint64_t block_size;    /* BDU_BLOCKS: output unit in bytes */
    char unit[8];           /* suffix printed after each amount ("K", "kB", "MiB") */
    int max_depth;
    const bdu_words *excludes;
} bdu_opts;

static int
bdu_words_add (bdu_words *w, const char *s)
{
    if (w->n == w->cap) {
        int ncap = w->cap ? w->cap * 2 : 32;
        const char **nv = realloc (w->v, (size_t) ncap * sizeof *nv);
        if (!nv) return -1;
        w->v = nv;
        w->cap = ncap;
    }
    w->v[w->n++] = s;
    return 0;
}

/* (dev, ino) hash set for hardlink dedup. Open addressing, linear probe. */
typedef struct { dev_t d; ino_t i; } bdu_key;
static bdu_key *bdu_seen = NULL;
static size_t bdu_seen_cap = 0;
static size_t bdu_seen_n = 0;

static int
bdu_seen_add (dev_t d, ino_t i)
{
    if (bdu_seen_cap == 0) {
        bdu_seen_cap = 1024;
        bdu_seen = calloc (bdu_seen_cap, sizeof (bdu_key));
        if (!bdu_seen) return -1;
    }
    if (bdu_seen_n * 2 >= bdu_seen_cap) {
        size_t new_cap = bdu_seen_cap * 2;
        bdu_key *nt = calloc (new_cap, sizeof (bdu_key));
        if (!nt) return -1;
        for (size_t k = 0; k < bdu_seen_cap; k++) {
            if (bdu_seen[k].i == 0 && bdu_seen[k].d == 0) continue;
            size_t h = ((size_t) bdu_seen[k].i * 31 + (size_t) bdu_seen[k].d) % new_cap;
            while (nt[h].i != 0 || nt[h].d != 0) h = (h + 1) % new_cap;
            nt[h] = bdu_seen[k];
        }
        free (bdu_seen);
        bdu_seen = nt;
        bdu_seen_cap = new_cap;
    }
    size_t h = ((size_t) i * 31 + (size_t) d) % bdu_seen_cap;
    while (bdu_seen[h].i != 0 || bdu_seen[h].d != 0) {
        if (bdu_seen[h].i == i && bdu_seen[h].d == d) return 1; /* already seen */
        h = (h + 1) % bdu_seen_cap;
    }
    bdu_seen[h].d = d;
    bdu_seen[h].i = i;
    bdu_seen_n++;
    return 0;
}

/* GNU du's -h and --si: below one unit the plain number; otherwise the
   amount in the largest unit that keeps it under BASE, rounded up (never
   down), to one decimal below 10 and to a whole number from 10 on. A
   value that rounds up to BASE moves on to the next unit ("1.0M" for
   1048575 bytes under -h). */
static void
bdu_human_base (uint64_t bytes, unsigned base, char *out, size_t outsz)
{
    static const char unit_1024[] = "KMGTPE", unit_1000[] = "kMGTPE";
    const char *units = base == 1024 ? unit_1024 : unit_1000;
    uint64_t div = base;
    int u = 0;

    if (bytes < base) {
        snprintf (out, outsz, "%" PRIu64, bytes);
        return;
    }
    while (u < 5 && bytes / div >= base) {
        div *= base;
        u++;
    }
    {
        uint64_t whole = bytes / div, rest = bytes % div;
        if (whole < 10) {
            /* tenths, rounded up; 11 * div fits: div <= 2^60 */
            uint64_t tenths = whole * 10 + (rest * 10 + div - 1) / div;
            if (tenths < 100) {
                snprintf (out, outsz, "%" PRIu64 ".%" PRIu64 "%c", tenths / 10, tenths % 10, units[u]);
                return;
            }
            whole = 10, rest = 0;
        }
        uint64_t up = whole + (rest != 0);
        if (up < base || u == 5) {
            snprintf (out, outsz, "%" PRIu64 "%c", up, units[u]);
            return;
        }
        /* rounds up to one of the next unit */
        snprintf (out, outsz, "1.0%c", units[u + 1]);
    }
}

/* GNU du's --exclude match (gnulib exclude_fnmatch without
   EXCLUDE_ANCHORED): PATTERN against the whole path, or against any tail
   that starts after a '/'. */
static int
bdu_excluded (const char *path, const bdu_opts *o)
{
    if (!o->excludes)
        return 0;
    for (int i = 0; i < o->excludes->n; i++) {
        const char *pat = o->excludes->v[i];
        if (fnmatch (pat, path, 0) == 0)
            return 1;
        for (const char *p = path; *p; p++)
            if (*p == '/' && p[1] != '/' && fnmatch (pat, p + 1, 0) == 0)
                return 1;
    }
    return 0;
}

/* Read FILE ("-" = stdin) split on DELIM into WORDS; the strings are
   allocated and kept in *KEEP for the caller to free.  Returns 0, or -1
   after a GNU-style "cannot open" diagnostic. */
static int
bdu_read_list (const char *file, int delim, bdu_words *words, bdu_words *keep,
               bdu_words *lines)
{
    FILE *fp;
    if (!strcmp (file, "-")) {
        int fd = dup (0);
        fp = fd < 0 ? NULL : fdopen (fd, "r");
        if (!fp && fd >= 0)
            close (fd);
    } else {
        fp = fopen (file, "r");
    }
    if (!fp) {
        builtin_error ("cannot open '%s' for reading: %s", file, strerror (errno));
        return -1;
    }
    char *buf = NULL;
    size_t cap = 0;
    ssize_t len;
    intptr_t lineno = 0;
    while ((len = getdelim (&buf, &cap, delim, fp)) >= 0) {
        lineno++;
        if (len > 0 && buf[len - 1] == delim)
            buf[--len] = '\0';
        if (delim == '\n' && len == 0)
            continue;
        char *copy = strdup (buf);
        if (!copy || bdu_words_add (keep, copy) < 0 || bdu_words_add (words, copy) < 0
            || (lines && bdu_words_add (lines, (const char *) lineno) < 0)) {
            free (buf);
            fclose (fp);
            builtin_error ("%s: cannot allocate memory", file);
            return -1;
        }
    }
    free (buf);
    fclose (fp);
    return 0;
}

static void
bdu_print (uint64_t amount, const char *path, const bdu_opts *o)
{
    char h[48];
    if (o->inodes && o->fmt == BDU_BLOCKS) {
        /* -B, -k and -m do not scale inode counts */
        snprintf (h, sizeof h, "%" PRIu64, amount);
    } else if (o->fmt != BDU_BLOCKS) {
        uint64_t bytes = o->inodes || o->apparent ? amount : amount * 512;
        bdu_human_base (bytes, o->fmt == BDU_SI ? 1000 : 1024, h, sizeof h);
    } else {
        uint64_t bytes = o->apparent ? amount : amount * 512;
        uint64_t unit = o->block_size ? o->block_size : 1024;
        snprintf (h, sizeof h, "%" PRIu64 "%s", bytes / unit + (bytes % unit != 0), o->unit);
    }
    printf ("%s\t%s%c", h, path, o->null_terminate ? '\0' : '\n');
}

static int
bdu_parse_depth (const char *arg, int *out)
{
    char *end = NULL;
    long v;

    if (!arg || !*arg)
        return -1;
    errno = 0;
    v = strtol (arg, &end, 10);
    if (errno || !end || *end || v < 0 || v > INT_MAX)
        return -1;
    *out = (int) v;
    return 0;
}

/* GNU du's SIZE for -B, --block-size and the DU_BLOCK_SIZE, BLOCK_SIZE and
   BLOCKSIZE variables (coreutils manual, "Block size", and observed
   coreutils 9.7): "human-readable" or "si", or a positive integer (C
   notation: 0x10 and 010 work) and/or a unit letter K, M, G, T, P or E
   (k, m, g and t also), powers of 1024, followed by "B" for powers of 1000
   or "iB" for powers of 1024. A unit without a number also names the
   suffix printed after each amount ("K", "kB", "MiB"). Returns 0, or -1
   for an invalid argument, -2 for an invalid suffix, -3 for a size that
   does not fit in 64 bits. */
static int
bdu_parse_block_size (const char *arg, bdu_opts *o)
{
    const char *p = arg;
    uint64_t n = 1, mult = 1, base = 1024;
    int have_number = 0, power = 0;
    char *end;

    if (!arg)
        return -1;
    if (!strcmp (arg, "human-readable") || !strcmp (arg, "si")) {
        o->fmt = arg[0] == 'h' ? BDU_HUMAN : BDU_SI;
        return 0;
    }
    while (*p == ' ' || (*p >= '\t' && *p <= '\r'))
        p++;
    if (*p == '-')
        return -1;
    if (isdigit ((unsigned char) *p) || (*p == '+' && isdigit ((unsigned char) p[1]))) {
        uintmax_t v;
        errno = 0;
        v = strtoumax (p, &end, 0);
        if (errno == ERANGE || v > UINT64_MAX)
            return -3;
        n = (uint64_t) v;
        if (n == 0)
            return -1;    /* "0K", "08" and "0x" too: zero comes first */
        have_number = 1;
        p = end;
    } else if (p != arg || !*p || !strchr ("KMGTPEZYkmgtpezy", *p)) {
        return -1;
    }
    if (*p) {
        static const char letters[] = "KMGTPEZY";
        const char *l = strchr (letters, toupper ((unsigned char) *p));
        if (!l || strchr ("pezy", *p))
            return -2;
        power = (int) (l - letters) + 1;
        p++;
        if (p[0] == 'B' && !p[1])
            base = 1000;
        else if (p[0] == 'i' && p[1] == 'B' && !p[2])
            base = 1024;
        else if (*p)
            return -2;
        for (int i = 0; i < power; i++) {
            if (mult > UINT64_MAX / base)
                return -3;
            mult *= base;
        }
    }
    if (n > UINT64_MAX / mult)
        return -3;
    o->fmt = BDU_BLOCKS;
    o->block_size = n * mult;
    o->unit[0] = '\0';
    if (!have_number && power) {
        char letter = "KMGTPEZY"[power - 1];
        if (base == 1000 && letter == 'K')
            letter = 'k';
        snprintf (o->unit, sizeof o->unit, "%c%s", letter,
                  base == 1000 ? "B" : strchr (arg, 'i') ? "iB" : "");
    }
    return 0;
}

static void
bdu_set_unit (bdu_opts *o, uint64_t size)
{
    o->fmt = BDU_BLOCKS;
    o->block_size = size;
    o->unit[0] = '\0';
}

/* Ancestor directories of the entry being walked, to stop at a directory
   loop that -L (or -l, which visits directories again) would follow. */
static bdu_key *bdu_stack = NULL;
static size_t bdu_stack_n = 0, bdu_stack_cap = 0;

static int
bdu_on_stack (dev_t d, ino_t i)
{
    for (size_t k = 0; k < bdu_stack_n; k++)
        if (bdu_stack[k].d == d && bdu_stack[k].i == i)
            return 1;
    return 0;
}

static int
bdu_push (dev_t d, ino_t i)
{
    if (bdu_stack_n == bdu_stack_cap) {
        size_t ncap = bdu_stack_cap ? bdu_stack_cap * 2 : 64;
        bdu_key *nv = realloc (bdu_stack, ncap * sizeof *nv);
        if (!nv) return -1;
        bdu_stack = nv;
        bdu_stack_cap = ncap;
    }
    bdu_stack[bdu_stack_n].d = d;
    bdu_stack[bdu_stack_n++].i = i;
    return 0;
}

/* Recursive walk. Returns total st_blocks (512-byte units) for path,
   counted exactly once via (dev, ino) seen-set for hardlinks. */
static uint64_t
bdu_walk (const char *path, int depth, dev_t root_dev, const bdu_opts *o, int *err)
{
    struct stat st;
    int follow = (o->dereference == 2 || (o->dereference == 1 && depth == 0));
    if (bdu_excluded (path, o))
        return 0;
    if ((follow ? stat (path, &st) : lstat (path, &st)) < 0) {
        bdu_error ("cannot access", path, errno);
        *err = 1;
        return 0;
    }
    if (o->xflag && depth > 0 && st.st_dev != root_dev) return 0;

    /* GNU du counts each file and directory once per run, however it is
       reached: through another hard link, a followed symbolic link, a
       repeated operand or an operand inside another one (observed
       coreutils 9.7: "du -sb DIR DIR/SUB" prints only DIR). -l counts
       every name, and only a directory loop stops it. */
    if (S_ISDIR (st.st_mode) && bdu_on_stack (st.st_dev, st.st_ino))
        return 0;
    if (!o->count_links) {
        int seen = bdu_seen_add (st.st_dev, st.st_ino);
        if (seen == 1) return 0;  /* already counted earlier */
        if (seen < 0) {
            builtin_error ("%s: cannot allocate file accounting state", path);
            *err = 1;
            return 0;
        }
    }

    /* Apparent sizes count only regular files and symbolic links;
       directories and special files add 0 (coreutils NEWS, 9.2: "du
       --apparent now counts apparent sizes only of regular files and
       symbolic links"). Disk usage counts every allocated block. */
    uint64_t total;
    if (o->inodes)
        total = 1;
    else if (o->apparent)
        total = (S_ISREG (st.st_mode) || S_ISLNK (st.st_mode))
            ? (uint64_t) st.st_size : 0;
    else
        total = (uint64_t) st.st_blocks;

    if (S_ISDIR (st.st_mode)) {
        DIR *d = opendir (path);
        if (!d) {
            bdu_error ("cannot read directory", path, errno);
            *err = 1;
        } else if (bdu_push (st.st_dev, st.st_ino) < 0) {
            closedir (d);
            builtin_error ("%s: cannot allocate file accounting state", path);
            *err = 1;
        } else {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
                char child[4096];
                struct stat child_st;
                snprintf (child, sizeof child, "%s/%s", path, de->d_name);
                uint64_t child_total = bdu_walk (child, depth + 1, root_dev, o, err);
                int child_follow = (o->dereference == 2);
                if (o->separate_dirs
                    && (child_follow ? stat (child, &child_st) : lstat (child, &child_st)) == 0
                    && S_ISDIR (child_st.st_mode))
                    continue;
                total += child_total;
            }
            closedir (d);
            bdu_stack_n--;
        }
    }

    /* Print decision. */
    int should_print = 0;
    if (o->sflag) {
        should_print = (depth == 0);
    } else if (S_ISDIR (st.st_mode)) {
        should_print = (o->max_depth < 0 || depth <= o->max_depth);
    } else if (depth == 0) {
        /* A non-directory named directly on the command line is always
           reported (GNU du), regardless of -a. */
        should_print = 1;
    } else {
        /* A file encountered during traversal prints only under -a. */
        should_print = (o->aflag && (o->max_depth < 0 || depth <= o->max_depth));
    }
    if (should_print) {
        bdu_print (total, path, o);
        if (ferror (stdout))
            *err = 1;
    }
    return total;
}

/* -B/--block-size SIZE: GNU's three diagnostics (no Try line), status 1. */
static int
bdu_block_size_arg (const char *arg, const char *opt, bdu_opts *o)
{
    int r = bdu_parse_block_size (arg, o);
    if (r == 0)
        return 0;
    char *q = bos_quote (arg);
    if (r == -2)
        builtin_error ("invalid suffix in %s argument %s", opt, q ? q : arg);
    else if (r == -3)
        builtin_error ("%s argument %s too large", opt, q ? q : arg);
    else
        builtin_error ("invalid %s argument %s", opt, q ? q : arg);
    free (q);
    return -1;
}

/* The unit before any option: the first of DU_BLOCK_SIZE, BLOCK_SIZE and
   BLOCKSIZE that is set, even empty; when that one is invalid, or none is
   set, 512 under POSIXLY_CORRECT, else 1024 (observed coreutils 9.7). */
static const char *
bdu_env (const char *name)
{
    SHELL_VAR *v = find_variable (name);
    return v && exported_p (v) && !array_p (v) && !assoc_p (v) ? value_cell (v) : NULL;
}

static void
bdu_default_block_size (bdu_opts *o)
{
    static const char *const vars[] = { "DU_BLOCK_SIZE", "BLOCK_SIZE", "BLOCKSIZE" };
    bdu_set_unit (o, bdu_env ("POSIXLY_CORRECT") ? 512 : 1024);
    for (size_t i = 0; i < sizeof vars / sizeof vars[0]; i++) {
        const char *v = bdu_env (vars[i]);
        if (v) {
            bdu_opts t = *o;
            if (bdu_parse_block_size (v, &t) == 0)
                *o = t;
            return;
        }
    }
}

/* GNU du's usage errors all exit 1; most end with the help hint. */
static int
bdu_usage_error (const char *fmt, const char *arg)
{
    builtin_error (fmt, arg);
    bos_shim_try_help ("du");
    return EXECUTION_FAILURE;
}

static int
bdu_bad_value (const char *what, const char *arg, int hint)
{
    char *q = bos_quote (arg);
    builtin_error ("invalid %s %s", what, q ? q : arg);
    free (q);
    if (hint) bos_shim_try_help ("du");
    return EXECUTION_FAILURE;
}

int
du_builtin (WORD_LIST *list)
{
    bdu_opts o = { .max_depth = -1 };
    bdu_default_block_size (&o);
    bdu_words paths = {0};
    bdu_words excludes = {0};
    bdu_words owned = {0};          /* strings read from -X/--files0-from */
    bdu_words f0_lines = {0};
    const char *files0 = NULL;
    int rc = EXECUTION_SUCCESS;
    o.excludes = &excludes;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_help ();
            goto out;
        }
        /* --exclude=PATTERN, -X/--exclude-from=FILE, --files0-from=FILE */
        if (strcmp (w, "--exclude") == 0 || strcmp (w, "--exclude-from") == 0
            || strcmp (w, "-X") == 0 || strcmp (w, "--files0-from") == 0) {
            if (!p->next) {
                if (w[1] == 'X') rc = bdu_usage_error ("option requires an argument -- '%s'", "X");
                else rc = bdu_usage_error ("option '%s' requires an argument", w);
                goto out;
            }
            p = p->next;
            if (w[2] == 'f') {
                files0 = p->word->word;
            } else if (w[1] == 'X' || w[9] == '-') {
                if (bdu_read_list (p->word->word, '\n', &excludes, &owned, NULL) < 0) {
                    rc = EXECUTION_FAILURE;
                    goto out;
                }
            } else if (bdu_words_add (&excludes, p->word->word) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
            continue;
        }
        if (strncmp (w, "--exclude=", 10) == 0) {
            if (bdu_words_add (&excludes, w + 10) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
            continue;
        }
        if (strncmp (w, "--exclude-from=", 15) == 0 || (strncmp (w, "-X", 2) == 0 && w[2])) {
            if (bdu_read_list (w + (w[1] == 'X' ? 2 : 15), '\n', &excludes, &owned, NULL) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
            continue;
        }
        if (strncmp (w, "--files0-from=", 14) == 0) {
            files0 = w + 14;
            continue;
        }
        if (strcmp (w, "--inodes") == 0) {
            o.inodes = 1;
            continue;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashdu 1.0 (bash-loadable)");
            goto out;
        }
        if (strcmp (w, "--all") == 0) {
            o.aflag = 1;
            continue;
        }
        if (strcmp (w, "--human-readable") == 0) {
            o.fmt = BDU_HUMAN;
            continue;
        }
        if (strcmp (w, "--si") == 0) {
            o.fmt = BDU_SI;
            continue;
        }
        if (strcmp (w, "--count-links") == 0) {
            o.count_links = 1;
            continue;
        }
        if (strcmp (w, "--null") == 0) {
            o.null_terminate = 1;
            continue;
        }
        if (strcmp (w, "--bytes") == 0) {
            o.apparent = 1;
            bdu_set_unit (&o, 1);
            continue;
        }
        if (strcmp (w, "--apparent-size") == 0) {
            o.apparent = 1;
            continue;
        }
        if (strcmp (w, "--block-size") == 0) {
            if (!p->next) {
                rc = bdu_usage_error ("option '%s' requires an argument", "--block-size");
                goto out;
            }
            if (bdu_block_size_arg (p->next->word->word, "--block-size", &o) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
            p = p->next; continue;
        }
        if (strncmp (w, "--block-size=", 13) == 0) {
            if (bdu_block_size_arg (w + 13, "--block-size", &o) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
            continue;
        }
        if (strcmp (w, "--total") == 0) {
            o.cflag = 1;
            continue;
        }
        if (strcmp (w, "--summarize") == 0) {
            o.sflag = 1;
            continue;
        }
        if (strcmp (w, "--separate-dirs") == 0) {
            o.separate_dirs = 1;
            continue;
        }
        if (strcmp (w, "--one-file-system") == 0) {
            o.xflag = 1;
            continue;
        }
        if (strcmp (w, "--no-dereference") == 0) {
            o.dereference = 0;
            continue;
        }
        if (strcmp (w, "--dereference-args") == 0) {
            o.dereference = 1;
            continue;
        }
        if (strcmp (w, "--dereference") == 0) {
            o.dereference = 2;
            continue;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bdu_words_add (&paths, p->word->word) < 0) {
                    rc = EXECUTION_FAILURE;
                    goto out;
                }
            }
            break;
        }
        if (strcmp (w, "-d") == 0) {
            if (!p->next) {
                rc = bdu_usage_error ("option requires an argument -- '%s'", "d");
                goto out;
            }
            if (bdu_parse_depth (p->next->word->word, &o.max_depth) < 0) {
                rc = bdu_bad_value ("maximum depth", p->next->word->word, 1);
                goto out;
            }
            p = p->next; continue;
        }
        if (strcmp (w, "--max-depth") == 0) {
            if (!p->next) {
                rc = bdu_usage_error ("option '%s' requires an argument", "--max-depth");
                goto out;
            }
            if (bdu_parse_depth (p->next->word->word, &o.max_depth) < 0) {
                rc = bdu_bad_value ("maximum depth", p->next->word->word, 1);
                goto out;
            }
            p = p->next; continue;
        }
        if (strncmp (w, "--max-depth=", 12) == 0) {
            if (bdu_parse_depth (w + 12, &o.max_depth) < 0) {
                rc = bdu_bad_value ("maximum depth", w + 12, 1);
                goto out;
            }
            continue;
        }
        if (w[0] == '-' && w[1] == '-') {
            rc = bdu_usage_error ("unrecognized option '%s'", w);
            goto out;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'A': o.apparent = 1; break;
                case '0': o.null_terminate = 1; break;
                case 'a': o.aflag = 1; break;
                case 'B': {
                    const char *arg = w + i + 1;
                    if (!*arg) {
                        if (!p->next) {
                            rc = bdu_usage_error ("option requires an argument -- '%s'", "B");
                            goto out;
                        }
                        p = p->next;
                        arg = p->word->word;
                    }
                    if (bdu_block_size_arg (arg, "-B", &o) < 0) {
                        rc = EXECUTION_FAILURE;
                        goto out;
                    }
                    goto next_word;
                }
                case 'b': o.apparent = 1; bdu_set_unit (&o, 1); break;
                case 'c': o.cflag = 1; break;
                case 'h': o.fmt = BDU_HUMAN; break;
                case 'k': bdu_set_unit (&o, 1024); break;
                case 'l': o.count_links = 1; break;
                case 'm': bdu_set_unit (&o, 1024 * 1024); break;
                case 'H': o.dereference = 1; break;
                case 'D': o.dereference = 1; break;  /* GNU alias for -H */
                case 'L': o.dereference = 2; break;
                case 'P': o.dereference = 0; break;
                case 'S': o.separate_dirs = 1; break;
                case 's': o.sflag = 1; break;
                case 'x': o.xflag = 1; break;
                case 'd': {
                    const char *arg = w + i + 1;
                    if (!*arg) {
                        if (!p->next) {
                            rc = bdu_usage_error ("option requires an argument -- '%s'", "d");
                            goto out;
                        }
                        p = p->next;
                        arg = p->word->word;
                    }
                    if (bdu_parse_depth (arg, &o.max_depth) < 0) {
                        rc = bdu_bad_value ("maximum depth", arg, 1);
                        goto out;
                    }
                    goto next_word;
                }
                default: {
                    char opt[2] = { w[i], '\0' };
                    rc = bdu_usage_error ("invalid option -- '%s'", opt);
                    goto out;
                }
                }
            }
        } else {
            if (bdu_words_add (&paths, w) < 0) {
                rc = EXECUTION_FAILURE;
                goto out;
            }
        }
    next_word:
        ;
    }
    if (files0) {
        if (paths.n) {
            builtin_error ("extra operand '%s'", paths.v[0]);
            fprintf (stderr, "file operands cannot be combined with --files0-from\n");
            rc = EXECUTION_FAILURE;
            goto out;
        }
        if (bdu_read_list (files0, '\0', &paths, &owned, &f0_lines) < 0) {
            rc = EXECUTION_FAILURE;
            goto out;
        }
    } else if (paths.n == 0 && bdu_words_add (&paths, ".") < 0) {
        rc = EXECUTION_FAILURE;
        goto out;
    }
    if (o.inodes && o.apparent)
        fprintf (stderr, "du: warning: options --apparent-size and -b are ineffective with --inodes\n");
    if (o.sflag && o.aflag) {
        rc = bdu_usage_error ("%s", "cannot both summarize and show all entries");
        goto out;
    }
    if (o.sflag && o.max_depth >= 0) {
        /* GNU allows -s with --max-depth=0 (the same thing), with a warning. */
        if (o.max_depth == 0)
            builtin_error ("warning: summarizing is the same as using --max-depth=0");
        else {
            char depth[32];
            snprintf (depth, sizeof depth, "%d", o.max_depth);
            builtin_error ("warning: summarizing conflicts with --max-depth=%s", depth);
            bos_shim_try_help ("du");
            rc = EXECUTION_FAILURE;
            goto out;
        }
    }

    int err = 0;
    uint64_t grand_total = 0;
    for (int i = 0; i < paths.n; i++) {
        struct stat st;
        if (files0 && !*paths.v[i]) {
            builtin_error ("%s:%ld: invalid zero-length file name",
                           files0,
                           (long) (intptr_t) f0_lines.v[i]);
            err = 1;
            continue;
        }
        int follow = (o.dereference == 1 || o.dereference == 2);
        if ((follow ? stat (paths.v[i], &st) : lstat (paths.v[i], &st)) < 0) {
            bdu_error ("cannot access", paths.v[i], errno);
            err = 1;
            continue;
        }
        grand_total += bdu_walk (paths.v[i], 0, st.st_dev, &o, &err);
    }
    if (o.cflag)
        bdu_print (grand_total, "total", &o);
    if (ferror (stdout))
        err = 1;
    /* Free seen set. */
    free (bdu_seen);
    bdu_seen = NULL;
    bdu_seen_cap = bdu_seen_n = 0;
    free (bdu_stack);
    bdu_stack = NULL;
    bdu_stack_cap = bdu_stack_n = 0;
    rc = err ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
out:
    free (paths.v);
    free (excludes.v);
    for (int i = 0; i < owned.n; i++)
        free ((char *) owned.v[i]);
    free (owned.v);
    free (f0_lines.v);
    return rc;
}

char *du_doc[] = {
    "Estimate disk usage of files and directories.",
    "",
    "    bashdu [-0AabBcDhklmHLPSs] [-d N|--max-depth=N] [-x] [-X FILE] [--exclude=PATTERN]",
    "           [--inodes] [--files0-from=FILE | PATH...]",
    "",
    "    -0   end each output line with NUL, not newline",
    "    -A   apparent size in blocks",
    "    -a   report sizes for files too",
    "    -B SIZE  scale sizes by SIZE before printing",
    "    -b   apparent size in bytes",
    "    -c   print a grand total",
    "    -h   human-readable sizes",
    "    -k   1024-byte blocks (default; 512 with POSIXLY_CORRECT)",
    "    -l   count sizes many times if hard linked",
    "    -m   1MiB blocks",
    "    -H, -D  follow symlinks named on the command line",
    "    -L   always follow symlinks",
    "    -P   don't dereference symbolic links (default)",
    "    -S   for directories, don't include subdirectory sizes",
    "    -s   summary: top-level totals only",
    "    -d N --max-depth=N   limit print depth",
    "    -x   stay on one filesystem",
    "    --exclude=PATTERN    skip files whose path, or a tail of it after a /,",
    "                         matches the shell PATTERN",
    "    -X FILE, --exclude-from=FILE   skip the patterns listed in FILE",
    "    --inodes             count inodes instead of sizes",
    "    --files0-from=FILE   read NUL-separated operands from FILE (- is stdin)",
    "    --help     show usage and exit",
    "    --version  show version and exit",
    "    --all --bytes --apparent-size --block-size=SIZE",
    "    --count-links --dereference --dereference-args --human-readable --null",
    "    --separate-dirs --summarize --no-dereference --one-file-system --total",
    "               GNU-style aliases for -a, -b, -A, -h, -s, -x, and -c",
    "",
    "Hard-linked files counted once (per dev/ino).",
    (char *)NULL
};

struct builtin bashdu_struct = {
    "bashdu",
    du_builtin,
    BUILTIN_ENABLED,
    du_doc,
    "bashdu [-0AabBcDhklmHLPSs] [-d N] [-x] [-X FILE] [--exclude=PATTERN] [--inodes] [--files0-from=FILE | PATH...]",
    0
};
