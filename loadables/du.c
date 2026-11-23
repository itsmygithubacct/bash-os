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
#include <limits.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "gnu-quote.h"

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

typedef struct {
    int aflag, apparent, cflag, count_links, hflag, si, null_terminate, separate_dirs, sflag, xflag;
    int dereference;
    int inodes;
    uint64_t block_size;
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
static bdu_key *bdu_alias = NULL;
static size_t bdu_alias_cap = 0;
static size_t bdu_alias_n = 0;

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

static int
bdu_key_add (bdu_key **tab, size_t *cap, size_t *n, dev_t d, ino_t i)
{
    if (*cap == 0) {
        *cap = 64;
        *tab = calloc (*cap, sizeof (bdu_key));
        if (!*tab) return -1;
    }
    if (*n * 2 >= *cap) {
        size_t new_cap = *cap * 2;
        bdu_key *nt = calloc (new_cap, sizeof (bdu_key));
        if (!nt) return -1;
        for (size_t k = 0; k < *cap; k++) {
            if ((*tab)[k].i == 0 && (*tab)[k].d == 0) continue;
            size_t h = ((size_t) (*tab)[k].i * 31 + (size_t) (*tab)[k].d) % new_cap;
            while (nt[h].i != 0 || nt[h].d != 0) h = (h + 1) % new_cap;
            nt[h] = (*tab)[k];
        }
        free (*tab);
        *tab = nt;
        *cap = new_cap;
    }
    size_t h = ((size_t) i * 31 + (size_t) d) % *cap;
    while ((*tab)[h].i != 0 || (*tab)[h].d != 0) {
        if ((*tab)[h].i == i && (*tab)[h].d == d) return 1;
        h = (h + 1) % *cap;
    }
    (*tab)[h].d = d;
    (*tab)[h].i = i;
    (*n)++;
    return 0;
}

static int
bdu_key_has (const bdu_key *tab, size_t cap, dev_t d, ino_t i)
{
    if (!tab || cap == 0) return 0;
    size_t h = ((size_t) i * 31 + (size_t) d) % cap;
    while (tab[h].i != 0 || tab[h].d != 0) {
        if (tab[h].i == i && tab[h].d == d) return 1;
        h = (h + 1) % cap;
    }
    return 0;
}

static void
bdu_note_alias_target (dev_t d, ino_t i)
{
    (void) bdu_key_add (&bdu_alias, &bdu_alias_cap, &bdu_alias_n, d, i);
}

static void
bdu_human (uint64_t bytes, char *out, size_t outsz)
{
    static const char unit[] = " KMGTPE";
    double v = (double) bytes;
    int u = 0;
    while (v >= 1024.0 && u < 6) { v /= 1024.0; u++; }
    if (u == 0) snprintf (out, outsz, "%" PRIu64, bytes);
    else if (v < 10.0) snprintf (out, outsz, "%.1f%c", v, unit[u]);
    else snprintf (out, outsz, "%.0f%c", v, unit[u]);
}

static void
bdu_human_si (uint64_t bytes, char *out, size_t outsz)
{
    static const char unit[] = " kMGTPE";
    double v = (double) bytes;
    int u = 0;
    while (v >= 1000.0 && u < 6) { v /= 1000.0; u++; }
    if (u == 0) snprintf (out, outsz, "%" PRIu64, bytes);
    else if (v < 10.0) snprintf (out, outsz, "%.1f%c", v, unit[u]);
    else snprintf (out, outsz, "%.0f%c", v, unit[u]);
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
    if (o->inodes) {
        char h[32];
        if (o->hflag)
            bdu_human (amount, h, sizeof h);
        else if (o->si)
            bdu_human_si (amount, h, sizeof h);
        else
            snprintf (h, sizeof h, "%" PRIu64, amount);
        printf ("%s\t%s%c", h, path, o->null_terminate ? '\0' : '\n');
    } else if (o->hflag || o->si) {
        char h[32];
        if (o->si)
            bdu_human_si (o->apparent ? amount : amount * 512, h, sizeof h);
        else
            bdu_human (o->apparent ? amount : amount * 512, h, sizeof h);
        printf ("%s\t%s%c", h, path, o->null_terminate ? '\0' : '\n');
    } else {
        /* GNU default = 1024-byte blocks (512 with POSIXLY_CORRECT). */
        uint64_t out, bytes, unit;
        unit = o->block_size ? o->block_size : (getenv ("POSIXLY_CORRECT") ? 512 : 1024);
        bytes = o->apparent ? amount : amount * 512;
        out = (bytes + unit - 1) / unit;
        printf ("%" PRIu64 "\t%s%c", out, path, o->null_terminate ? '\0' : '\n');
    }
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

static int
bdu_parse_block_size (const char *arg, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;
    uint64_t mult = 1;

    if (!arg || !*arg)
        return -1;
    errno = 0;
    v = strtoull (arg, &end, 10);
    if (errno || !end || end == arg || v == 0)
        return -1;
    if (*end) {
        if ((end[0] == 'K' || end[0] == 'k') && end[1] == '\0')
            mult = 1024;
        else if ((end[0] == 'M' || end[0] == 'm') && end[1] == '\0')
            mult = 1024 * 1024;
        else if ((end[0] == 'G' || end[0] == 'g') && end[1] == '\0')
            mult = 1024ULL * 1024 * 1024;
        else
            return -1;
    }
    if (v > UINT64_MAX / mult)
        return -1;
    *out = (uint64_t) v * mult;
    return 0;
}

/* Recursive walk. Returns total st_blocks (512-byte units) for path,
   counted exactly once via (dev, ino) seen-set for hardlinks. */
static uint64_t
bdu_walk (const char *path, int depth, dev_t root_dev, const bdu_opts *o, int *err)
{
    struct stat st;
    int follow = (o->dereference == 2 || (o->dereference == 1 && depth == 0));
    int followed_symlink = 0;
    if (bdu_excluded (path, o))
        return 0;
    if ((follow ? stat (path, &st) : lstat (path, &st)) < 0) {
        bdu_error ("cannot access", path, errno);
        *err = 1;
        return 0;
    }
    if (follow) {
        struct stat lst;
        if (lstat (path, &lst) == 0 && S_ISLNK (lst.st_mode)) {
            followed_symlink = 1;
            if (!S_ISDIR (st.st_mode))
                bdu_note_alias_target (st.st_dev, st.st_ino);
        }
    }
    if (o->xflag && depth > 0 && st.st_dev != root_dev) return 0;

    /* GNU du also deduplicates symlink aliases when -H/-L dereferences them. */
    int seen = 0;
    int alias_target = bdu_key_has (bdu_alias, bdu_alias_cap, st.st_dev, st.st_ino);
    /* Under -L, remember ordinary files before a later symlink can name
       them too. Discovering aliases only when visiting the link is too late. */
    if (!o->count_links && !S_ISDIR (st.st_mode)
        && (o->dereference == 2 || st.st_nlink > 1 || alias_target || followed_symlink)) {
        seen = bdu_seen_add (st.st_dev, st.st_ino);
        if (seen == 1) return 0;  /* already counted earlier */
        if (seen < 0) {
            builtin_error ("%s: cannot allocate file accounting state", path);
            *err = 1;
            return 0;
        }
    }

    /* GNU du: in apparent-size mode a node's own contribution is its
       st_size only when "usable" — regular files and symlinks. Directories
       and special files contribute 0 (NOT st_blocks); their reported size
       comes purely from summing children. Non-apparent mode always uses the
       allocated block count. Matches coreutils du.c usable_st_size(). */
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

int
du_builtin (WORD_LIST *list)
{
    bdu_opts o = { .max_depth = -1 };
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
                builtin_error ("option '%s' requires an argument", w);
                rc = EXECUTION_FAILURE;
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
            o.hflag = 1;
            continue;
        }
        if (strcmp (w, "--si") == 0) {
            o.si = 1;
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
            o.block_size = 1;
            continue;
        }
        if (strcmp (w, "--apparent-size") == 0) {
            o.apparent = 1;
            continue;
        }
        if (strcmp (w, "--block-size") == 0) {
            if (!p->next) {
                builtin_error ("--block-size requires an argument");
                rc = EX_USAGE;
                goto out;
            }
            if (bdu_parse_block_size (p->next->word->word, &o.block_size) < 0) {
                builtin_error ("invalid block size: %s", p->next->word->word);
                rc = EX_USAGE;
                goto out;
            }
            p = p->next; continue;
        }
        if (strncmp (w, "--block-size=", 13) == 0) {
            if (bdu_parse_block_size (w + 13, &o.block_size) < 0) {
                builtin_error ("invalid block size: %s", w + 13);
                rc = EX_USAGE;
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
                builtin_error ("-d requires an argument");
                rc = EX_USAGE;
                goto out;
            }
            if (bdu_parse_depth (p->next->word->word, &o.max_depth) < 0) {
                builtin_error ("invalid maximum depth: %s", p->next->word->word);
                rc = EX_USAGE;
                goto out;
            }
            p = p->next; continue;
        }
        if (strcmp (w, "--max-depth") == 0) {
            if (!p->next) {
                builtin_error ("--max-depth requires an argument");
                rc = EX_USAGE;
                goto out;
            }
            if (bdu_parse_depth (p->next->word->word, &o.max_depth) < 0) {
                builtin_error ("invalid maximum depth: %s", p->next->word->word);
                rc = EX_USAGE;
                goto out;
            }
            p = p->next; continue;
        }
        if (strncmp (w, "--max-depth=", 12) == 0) {
            if (bdu_parse_depth (w + 12, &o.max_depth) < 0) {
                builtin_error ("invalid maximum depth: %s", w + 12);
                rc = EX_USAGE;
                goto out;
            }
            continue;
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
                            builtin_error ("-B requires an argument");
                            rc = EX_USAGE;
                            goto out;
                        }
                        p = p->next;
                        arg = p->word->word;
                    }
                    if (bdu_parse_block_size (arg, &o.block_size) < 0) {
                        builtin_error ("invalid block size: %s", arg);
                        rc = EX_USAGE;
                        goto out;
                    }
                    goto next_word;
                }
                case 'b': o.apparent = 1; o.block_size = 1; break;
                case 'c': o.cflag = 1; break;
                case 'h': o.hflag = 1; break;
                case 'k': o.block_size = 1024; break;
                case 'l': o.count_links = 1; break;
                case 'm': o.block_size = 1024 * 1024; break;
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
                            builtin_error ("-d requires an argument");
                            rc = EX_USAGE;
                            goto out;
                        }
                        p = p->next;
                        arg = p->word->word;
                    }
                    if (bdu_parse_depth (arg, &o.max_depth) < 0) {
                        builtin_error ("invalid maximum depth: %s", arg);
                        rc = EX_USAGE;
                        goto out;
                    }
                    goto next_word;
                }
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    rc = EX_USAGE;
                    goto out;
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
        builtin_error ("-a and -s are mutually exclusive");
        rc = EX_USAGE;
        goto out;
    }
    if (o.sflag && o.max_depth >= 0) {
        builtin_error ("-s and --max-depth are mutually exclusive");
        rc = EX_USAGE;
        goto out;
    }

    if (o.dereference != 0) {
        for (int i = 0; i < paths.n; i++) {
            struct stat lst, st;
            if (lstat (paths.v[i], &lst) == 0
                && S_ISLNK (lst.st_mode)
                && stat (paths.v[i], &st) == 0
                && !S_ISDIR (st.st_mode))
                bdu_note_alias_target (st.st_dev, st.st_ino);
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
    free (bdu_alias);
    bdu_alias = NULL;
    bdu_alias_cap = bdu_alias_n = 0;
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
