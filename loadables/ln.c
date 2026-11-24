/* ln.c — GNU ln(1) as a bash builtin.
 *
 *   ln [OPTION]... TARGET [LINK_NAME]
 *   ln [OPTION]... TARGET... DIRECTORY
 *   ln [OPTION]... -t DIRECTORY TARGET...
 *
 * Replaces Bash's example loadable, which had only -f/-s/-n and no
 * -r/--relative (guest compatibility pass 1). Options, messages and exit
 * status follow GNU coreutils ln:
 *
 *   -s, --symbolic   symbolic links instead of hard links
 *   -r, --relative   with -s, a target relative to the link's directory
 *   -f, --force      remove existing destinations
 *   -i, --interactive   prompt before removing destinations
 *   -n, --no-dereference (also -h)   treat LINK_NAME as a normal file if
 *                    it is a symbolic link to a directory
 *   -L, --logical / -P, --physical   hard-link a symlink's referent / the
 *                    symlink itself (default -P)
 *   -t, --target-directory=DIR  -T, --no-target-directory
 *   -b, --backup[=CONTROL]  -S, --suffix=SUFFIX   back up destinations
 *   -v, --verbose    print the name of each linked file
 *
 * Exit status 0 on success, 1 if any link failed.
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
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "shim-prog-name.h"
#include "gnu-longopt.h"

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

enum { LN_BK_NONE, LN_BK_SIMPLE, LN_BK_NUMBERED, LN_BK_EXISTING };

typedef struct {
    int sym, rel, force, inter, nodere, logical, verbose, notarget, backup;
    const char *suffix;
} ln_opts;

static void
ln_err (const char *fmt, ...)
{
    va_list ap;
    fflush (stdout);
    fputs ("ln: ", stderr);
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
    fputc ('\n', stderr);
}

static void
ln_hint (void)
{
    fputs ("Try 'ln --help' for more information.\n", stderr);
}

/* GNU's backup-type keywords (synonyms adjacent) and argument matching:
   an exact keyword or an unambiguous prefix; otherwise the "invalid" or
   "ambiguous argument" line, the keyword list and the Try line. */
static const char *const ln_backup_names[] = {
    "none", "off", "simple", "never", "existing", "nil", "numbered", "t", NULL
};
static const int ln_backup_vals[] = {
    LN_BK_NONE, LN_BK_NONE, LN_BK_SIMPLE, LN_BK_SIMPLE,
    LN_BK_EXISTING, LN_BK_EXISTING, LN_BK_NUMBERED, LN_BK_NUMBERED
};

static int
ln_backup_kind (const char *v, int *kind)
{
    const char *context = "backup type";
    int k;

    if (!v || !*v) {
        v = getenv ("VERSION_CONTROL");
        context = "$VERSION_CONTROL";
    }
    if (!v || !*v) { *kind = LN_BK_EXISTING; return 0; }
    k = bos_argmatch (bos_shim_prog_name ("ln"), context, v, ln_backup_names, ln_backup_vals);
    if (k < 0) return -1;
    *kind = k;
    return 0;
}

/* Rename DST to its backup name; *made gets the new name (malloc'd). */
static int
ln_make_backup (const char *dst, const ln_opts *o, char **made)
{
    const char *slash = strrchr (dst, '/');
    const char *base = slash ? slash + 1 : dst;
    int kind = o->backup, highest = 0;
    if (kind == LN_BK_NUMBERED || kind == LN_BK_EXISTING) {
        char *dir = slash ? strndup (dst, (size_t) (slash - dst) ? (size_t) (slash - dst) : 1) : strdup (".");
        DIR *d = dir ? opendir (dir) : NULL;
        size_t bl = strlen (base);
        struct dirent *de;
        while (d && (de = readdir (d)) != NULL) {
            const char *n = de->d_name;
            if (strncmp (n, base, bl) || strncmp (n + bl, ".~", 2)) continue;
            char *end;
            long v = strtol (n + bl + 2, &end, 10);
            if (end != n + bl + 2 && end[0] == '~' && !end[1] && v > highest && v < 1000000000)
                highest = (int) v;
        }
        if (d) closedir (d);
        free (dir);
        if (kind == LN_BK_EXISTING) kind = highest ? LN_BK_NUMBERED : LN_BK_SIMPLE;
    }
    const char *suffix = o->suffix;
    if (!suffix || !*suffix || strchr (suffix, '/')) suffix = "~";
    size_t len = strlen (dst) + strlen (suffix) + 32;
    char *name = malloc (len);
    if (!name) { ln_err ("memory exhausted"); return -1; }
    if (kind == LN_BK_NUMBERED) snprintf (name, len, "%s.~%d~", dst, highest + 1);
    else snprintf (name, len, "%s%s", dst, suffix);
    if (rename (dst, name) < 0) {
        ln_err ("cannot backup '%s': %s", dst, strerror (errno));
        free (name);
        return -1;
    }
    *made = name;
    return 0;
}

/* Absolute, normalized form of PATH, resolving the symbolic links of the
   components that exist (GNU canonicalize -m: missing tails are allowed). */
static char *
ln_canon_missing (const char *path)
{
    char buf[PATH_MAX * 2];
    if (path[0] == '/') {
        if (strlen (path) >= sizeof buf) return NULL;
        strcpy (buf, path);
    } else {
        if (!getcwd (buf, PATH_MAX)) return NULL;
        size_t n = strlen (buf);
        if (n + 1 + strlen (path) >= sizeof buf) return NULL;
        buf[n] = '/';
        strcpy (buf + n + 1, path);
    }
    /* Longest prefix that realpath resolves; the rest is lexical. */
    char out[PATH_MAX * 2];
    size_t cut = strlen (buf);
    char *real;
    for (;;) {
        char save = buf[cut];
        buf[cut] = '\0';
        real = realpath (cut ? buf : "/", NULL);
        buf[cut] = save;
        if (real || cut == 0) break;
        while (cut > 0 && buf[cut - 1] != '/') cut--;   /* back to a '/' */
        if (cut > 0) cut--;                             /* and drop it */
    }
    if (!real) return NULL;
    if (strlen (real) >= sizeof out) { free (real); return NULL; }
    strcpy (out, real);
    free (real);
    const char *rest = buf + cut;
    while (*rest) {
        while (*rest == '/') rest++;
        if (!*rest) break;
        const char *e = strchr (rest, '/');
        size_t n = e ? (size_t) (e - rest) : strlen (rest);
        if (n == 1 && rest[0] == '.') ;
        else if (n == 2 && rest[0] == '.' && rest[1] == '.') {
            char *s = strrchr (out, '/');
            if (s && s != out) *s = '\0'; else strcpy (out, "/");
        } else {
            size_t ol = strlen (out);
            if (ol + 1 + n >= sizeof out) return NULL;
            if (ol > 1) out[ol++] = '/';
            memcpy (out + ol, rest, n);
            out[ol + n] = '\0';
        }
        rest += n;
    }
    return strdup (out);
}

/* Split an absolute, normalized path into its components. */
static int
ln_split (char *path, char **comp, int max)
{
    int n = 0;
    char *save = NULL;
    for (char *t = strtok_r (path, "/", &save); t; t = strtok_r (NULL, "/", &save)) {
        if (n == max) return -1;
        comp[n++] = t;
    }
    return n;
}

/* TARGET (absolute) relative to directory BASE (absolute):
   "../" for each BASE component past the common prefix, then the rest
   of TARGET; "." when they are the same. */
static char *
ln_relpath (const char *target, const char *base)
{
    char *t = strdup (target), *b = strdup (base), *r = NULL;
    char *tc[PATH_MAX / 2], *bc[PATH_MAX / 2];
    if (!t || !b) goto out;
    int nt = ln_split (t, tc, PATH_MAX / 2), nb = ln_split (b, bc, PATH_MAX / 2);
    if (nt < 0 || nb < 0) goto out;
    int k = 0;
    while (k < nt && k < nb && !strcmp (tc[k], bc[k])) k++;
    size_t len = 2 + (size_t) (nb - k) * 3 + strlen (target);
    r = malloc (len);
    if (!r) goto out;
    r[0] = '\0';
    for (int i = k; i < nb; i++) strcat (r, i + 1 < nb || k < nt ? "../" : "..");
    for (int i = k; i < nt; i++) {
        strcat (r, tc[i]);
        if (i + 1 < nt) strcat (r, "/");
    }
    if (!*r) strcpy (r, ".");
out:
    free (t);
    free (b);
    return r;
}

static int
ln_one (const char *src, const char *dst, const ln_opts *o)
{
    struct stat sst, dst_st;
    char *text = NULL, *backup = NULL;
    const char *target = src;
    int rc = 0;

    if (!o->sym) {
        int r = o->logical ? stat (src, &sst) : lstat (src, &sst);
        if (r < 0) {
            ln_err ("failed to access '%s': %s", src, strerror (errno));
            return 1;
        }
        if (S_ISDIR (sst.st_mode)) {
            ln_err ("%s: hard link not allowed for directory", src);
            return 1;
        }
    } else if (o->rel) {
        char *abs_src = ln_canon_missing (src);
        char *dcopy = strdup (dst);
        char *slash = dcopy ? strrchr (dcopy, '/') : NULL;
        const char *ddir = ".";
        if (slash) { if (slash == dcopy) slash[1] = '\0'; else *slash = '\0'; ddir = dcopy; }
        char *abs_dir = ln_canon_missing (ddir);
        if (abs_src && abs_dir) text = ln_relpath (abs_src, abs_dir);
        free (abs_src); free (abs_dir); free (dcopy);
        if (!text) {
            ln_err ("cannot compute a relative name for '%s'", src);
            return 1;
        }
        target = text;
    }

    if (lstat (dst, &dst_st) == 0) {
        if (!o->sym && dst_st.st_dev == sst.st_dev && dst_st.st_ino == sst.st_ino && !o->backup) {
            if (o->force) {
                ln_err ("'%s' and '%s' are the same file", src, dst);
                rc = 1;
                goto out;
            }
        }
        if (o->inter) {
            fflush (stdout);
            fprintf (stderr, "ln: replace '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), a = c;
            while (c != EOF && c != '\n') c = getchar ();
            if (a != 'y' && a != 'Y') goto out;
        }
        if (o->backup || o->force || o->inter) {
            if (S_ISDIR (dst_st.st_mode)) {
                ln_err ("%s: cannot overwrite directory", dst);
                rc = 1;
                goto out;
            }
            if (o->backup) {
                if (ln_make_backup (dst, o, &backup) < 0) { rc = 1; goto out; }
            } else if (unlink (dst) < 0 && errno != ENOENT) {
                ln_err ("cannot remove '%s': %s", dst, strerror (errno));
                rc = 1;
                goto out;
            }
        }
    }

    int r = o->sym ? symlink (target, dst)
                   : linkat (AT_FDCWD, src, AT_FDCWD, dst, o->logical ? AT_SYMLINK_FOLLOW : 0);
    if (r < 0) {
        int e = errno;
        /* coreutils names the source only when it may be the culprit. */
        if (o->sym) ln_err ("failed to create symbolic link '%s': %s", dst, strerror (e));
        else if (e == EMLINK) ln_err ("failed to create hard link to '%s': %s", src, strerror (e));
        else if (e == EEXIST || e == EDQUOT || e == ENOSPC || e == EROFS)
            ln_err ("failed to create hard link '%s': %s", dst, strerror (e));
        else ln_err ("failed to create hard link '%s' => '%s': %s", dst, src, strerror (e));
        if (backup) (void) rename (backup, dst);
        rc = 1;
        goto out;
    }
    if (o->verbose) {
        if (backup) printf ("'%s' ~ '%s' %s '%s'\n", backup, dst, o->sym ? "->" : "=>", target);
        else printf ("'%s' %s '%s'\n", dst, o->sym ? "->" : "=>", target);
    }
out:
    free (text);
    free (backup);
    return rc;
}

int
ln_builtin (WORD_LIST *list)
{
    ln_opts o = {0};
    const char *tdir = NULL;
    const char **ops = NULL;
    int n = 0, cap = 0, rc = 0, endopts = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!endopts && !strcmp (w, "--")) { endopts = 1; continue; }
        if (!endopts && w[0] == '-' && w[1] == '-') {
            const char *v = strchr (w, '=');
            size_t nl = v ? (size_t) (v - w) : strlen (w);
            if (v) v++;
#define LN_IS(s) (nl == strlen (s) && !strncmp (w, s, nl))
            if (LN_IS ("--help")) { builtin_help (); free (ops); return EXECUTION_SUCCESS; }
            else if (LN_IS ("--version")) { puts ("bashln 2.0 (bash-loadable)"); free (ops); return EXECUTION_SUCCESS; }
            else if (LN_IS ("--symbolic")) o.sym = 1;
            else if (LN_IS ("--relative")) o.rel = 1;
            else if (LN_IS ("--force")) { o.force = 1; o.inter = 0; }
            else if (LN_IS ("--interactive")) { o.inter = 1; o.force = 0; }
            else if (LN_IS ("--no-dereference")) o.nodere = 1;
            else if (LN_IS ("--logical")) o.logical = 1;
            else if (LN_IS ("--physical")) o.logical = 0;
            else if (LN_IS ("--verbose")) o.verbose = 1;
            else if (LN_IS ("--no-target-directory")) o.notarget = 1;
            else if (LN_IS ("--directory")) ;
            else if (LN_IS ("--backup")) { if (ln_backup_kind (v, &o.backup) < 0) { free (ops); return EXECUTION_FAILURE; } }
            else if (LN_IS ("--suffix") || LN_IS ("--target-directory")) {
                if (!v) {
                    if (!p->next) { ln_err ("option '%s' requires an argument", w); ln_hint (); free (ops); return EXECUTION_FAILURE; }
                    p = p->next;
                    v = p->word->word;
                }
                if (w[2] == 's') {
                    o.suffix = v;
                    if (!o.backup && ln_backup_kind (NULL, &o.backup) < 0) { free (ops); return EXECUTION_FAILURE; }
                } else {
                    if (tdir) { ln_err ("multiple target directories specified"); free (ops); return EXECUTION_FAILURE; }
                    tdir = v;
                }
            } else {
                ln_err ("unrecognized option '%s'", w);
                ln_hint ();
                free (ops);
                return EXECUTION_FAILURE;
            }
#undef LN_IS
            continue;
        }
        if (!endopts && w[0] == '-' && w[1]) {
            for (int i = 1; w[i]; i++) {
                char c = w[i];
                switch (c) {
                case 's': o.sym = 1; break;
                case 'r': o.rel = 1; break;
                case 'f': o.force = 1; o.inter = 0; break;
                case 'i': o.inter = 1; o.force = 0; break;
                case 'n': case 'h': o.nodere = 1; break;
                case 'L': o.logical = 1; break;
                case 'P': o.logical = 0; break;
                case 'v': o.verbose = 1; break;
                case 'T': o.notarget = 1; break;
                case 'd': case 'F': break;
                case 'b':
                    if (!o.backup && ln_backup_kind (NULL, &o.backup) < 0) { free (ops); return EXECUTION_FAILURE; }
                    break;
                case 'S': case 't': {
                    const char *v;
                    if (w[i + 1]) v = w + i + 1;
                    else if (p->next) { p = p->next; v = p->word->word; }
                    else {
                        ln_err ("option requires an argument -- '%c'", c);
                        ln_hint ();
                        free (ops);
                        return EXECUTION_FAILURE;
                    }
                    if (c == 'S') {
                        o.suffix = v;
                        if (!o.backup && ln_backup_kind (NULL, &o.backup) < 0) { free (ops); return EXECUTION_FAILURE; }
                    } else {
                        if (tdir) { ln_err ("multiple target directories specified"); free (ops); return EXECUTION_FAILURE; }
                        tdir = v;
                    }
                    i = (int) strlen (w) - 1;
                    break;
                }
                default:
                    ln_err ("invalid option -- '%c'", c);
                    ln_hint ();
                    free (ops);
                    return EXECUTION_FAILURE;
                }
            }
            continue;
        }
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            const char **g = realloc (ops, (size_t) cap * sizeof *g);
            if (!g) { ln_err ("memory exhausted"); free (ops); return EXECUTION_FAILURE; }
            ops = g;
        }
        ops[n++] = w;
    }
    if (!o.suffix) o.suffix = getenv ("SIMPLE_BACKUP_SUFFIX");

    if (o.rel && !o.sym) {
        ln_err ("cannot do --relative without --symbolic");
        free (ops);
        return EXECUTION_FAILURE;
    }
    if (tdir && o.notarget) {
        ln_err ("cannot combine --target-directory and --no-target-directory");
        free (ops);
        return EXECUTION_FAILURE;
    }
    if (n == 0) {
        ln_err ("missing file operand");
        ln_hint ();
        free (ops);
        return EXECUTION_FAILURE;
    }
    if (o.notarget) {
        if (n < 2) {
            ln_err ("missing destination file operand after '%s'", ops[0]);
            ln_hint ();
            free (ops);
            return EXECUTION_FAILURE;
        }
        if (n > 2) {
            ln_err ("extra operand '%s'", ops[2]);
            ln_hint ();
            free (ops);
            return EXECUTION_FAILURE;
        }
        rc = ln_one (ops[0], ops[1], &o);
        free (ops);
        return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    int nsrc = n;
    const char *dir = tdir;
    if (!dir) {
        if (n == 1) dir = ".";
        else {
            const char *last = ops[n - 1];
            struct stat st;
            int sr = o.nodere ? lstat (last, &st) : stat (last, &st), se = errno;
            int isdir = sr == 0 && S_ISDIR (st.st_mode);
            if (n > 2 && !isdir) {
                if (sr < 0) ln_err ("target '%s': %s", last, strerror (se));
                else ln_err ("target '%s' is not a directory", last);
                free (ops);
                return EXECUTION_FAILURE;
            }
            nsrc = n - 1;
            if (isdir) dir = last;
            else {
                rc = ln_one (ops[0], last, &o);
                free (ops);
                return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
            }
        }
    } else {
        struct stat st;
        if (stat (dir, &st) < 0 || !S_ISDIR (st.st_mode)) {
            ln_err ("target directory '%s': %s", dir, stat (dir, &st) < 0 ? strerror (errno) : "Not a directory");
            free (ops);
            return EXECUTION_FAILURE;
        }
    }

    for (int i = 0; i < nsrc; i++) {
        const char *src = ops[i];
        size_t end = strlen (src);
        while (end > 1 && src[end - 1] == '/') end--;
        size_t start = end;
        while (start > 0 && src[start - 1] != '/') start--;
        size_t dl = strlen (dir);
        char *dst = malloc (dl + 2 + (end - start));
        if (!dst) { ln_err ("memory exhausted"); rc = 1; break; }
        if (!strcmp (dir, ".") && !tdir)
            snprintf (dst, dl + 2 + (end - start), "%.*s", (int) (end - start), src + start);
        else
            snprintf (dst, dl + 2 + (end - start), "%s%s%.*s", dir,
                      dl && dir[dl - 1] == '/' ? "" : "/", (int) (end - start), src + start);
        rc |= ln_one (src, dst, &o);
        free (dst);
    }
    free (ops);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *ln_doc[] = {
    "Make links between files.",
    "",
    "    ln [OPTION]... TARGET [LINK_NAME]",
    "    ln [OPTION]... TARGET... DIRECTORY",
    "    ln [OPTION]... -t DIRECTORY TARGET...",
    "",
    "Create a link to TARGET named LINK_NAME, links to each TARGET in",
    "DIRECTORY, or a link to TARGET in the current directory. Hard links",
    "by default, symbolic links with -s.",
    "",
    "    -s, --symbolic   make symbolic links instead of hard links",
    "    -r, --relative   with -s, create links relative to the link's directory",
    "    -f, --force      remove existing destination files",
    "    -i, --interactive   prompt whether to remove destinations",
    "    -n, -h, --no-dereference   treat LINK_NAME as a normal file if it is",
    "                     a symbolic link to a directory",
    "    -L, --logical    dereference TARGETs that are symbolic links",
    "    -P, --physical   make hard links directly to symbolic links (default)",
    "    -t, --target-directory=DIRECTORY   create the links in DIRECTORY",
    "    -T, --no-target-directory   treat LINK_NAME as a normal file always",
    "    -b, --backup[=CONTROL]   back up each existing destination file",
    "    -S, --suffix=SUFFIX   override the usual backup suffix (~)",
    "    -v, --verbose    print name of each linked file",
    (char *)NULL
};

struct builtin ln_struct = {
    "ln",
    ln_builtin,
    BUILTIN_ENABLED,
    ln_doc,
    "ln [-bfhinLPrsTv] [-S SUFFIX] [-t DIR] TARGET... [LINK_NAME|DIRECTORY]",
    0
};
