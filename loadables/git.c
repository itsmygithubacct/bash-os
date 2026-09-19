/* SPDX-License-Identifier: MIT */
/* git.c — git, as a bash-os builtin.
 *
 * Phase 0 of the porcelain port: the command surface, and the plumbing that
 * the everyday commands will stand on. The formats live in _git/: objects and
 * the store in odb.c and store.c, repository discovery in repo.c, refs and
 * the reflog in refs.c, lock files in lock.c.
 *
 * Each invocation runs in a forked child. git's error model reports a fatal
 * problem at any depth and stops; in a child that is an exit, so nothing has
 * to unwind the shell, `-C` can change directory without moving the caller,
 * the memory a history walk needs is returned at exit, and an interrupt
 * releases held lock files.
 *
 * Statuses are git's: 0, 1, 128 for a fatal error, 129 for a usage error.
 * Messages are git's too, on stderr, without a bash-os prefix, so a script
 * written for git sees what it expects.
 *
 * Implemented here: rev-parse, cat-file, hash-object, update-ref,
 * symbolic-ref, show-ref, for-each-ref and reflog. Anything else, including
 * an option outside a command's supported set, exits 129 and says so, rather
 * than pretending to have done the work.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

#include "_git_odb.h"
#include "_git_refs.h"
#include "_git_repo.h"
#include "_git_lock.h"

/* The git version whose behaviour this matches, plus what we are. */
#define GIT_VERSION_STRING "git version 2.47.3.bash-os"

#define GIT_EXIT_FATAL 128
#define GIT_EXIT_USAGE 129

static int
git_fatal (const char *format, ...)
{
    va_list args;
    fflush (stdout);
    fputs ("fatal: ", stderr);
    va_start (args, format);
    vfprintf (stderr, format, args);
    va_end (args);
    fputc ('\n', stderr);
    return GIT_EXIT_FATAL;
}

static int
git_usage (const char *usage)
{
    fflush (stdout);
    fprintf (stderr, "usage: %s\n", usage);
    return GIT_EXIT_USAGE;
}

/* One repository plus its object store, opened when a command needs one. */
typedef struct {
    bgit_repo repo;
    bgit_odb odb;
    int open;
} git_context;

static int
git_context_open (git_context *ctx)
{
    if (ctx->open) return 0;
    if (bgit_repo_discover (".", &ctx->repo) < 0)
        return git_fatal ("not a git repository (or any of the parent directories): .git");
    if (bgit_odb_open (&ctx->repo, &ctx->odb) < 0) {
        bgit_repo_release (&ctx->repo);
        return git_fatal ("cannot read the object store");
    }
    /* Every message here is git's, so the store stays quiet. */
    ctx->odb.quiet = 1;
    ctx->open = 1;
    return 0;
}

static void
git_context_close (git_context *ctx)
{
    if (!ctx->open) return;
    bgit_odb_release (&ctx->odb);
    bgit_repo_release (&ctx->repo);
    ctx->open = 0;
}

/* Resolve a name to an object id: a full id, an abbreviation, or a ref. */
static int
git_resolve (git_context *ctx, const char *name, char full[41], char **symref)
{
    if (symref) *symref = NULL;
    int rc = bgit_ref_resolve (&ctx->repo, name, full, symref);
    if (rc == 0) return 0;
    if (symref && *symref) { free (*symref); *symref = NULL; }
    /* Not a ref: try refs/heads, refs/tags and refs/remotes as git does,
       then the object store for an id or abbreviation. */
    static const char *const prefixes[] = {
        "refs/", "refs/tags/", "refs/heads/", "refs/remotes/", NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        char candidate[4096];
        if (snprintf (candidate, sizeof candidate, "%s%s", prefixes[i], name) >=
            (int) sizeof candidate)
            continue;
        if (bgit_ref_read (&ctx->repo, candidate, full) == 0) {
            if (symref) *symref = strdup (candidate);
            return 0;
        }
    }
    if (bgit_all_hex (name) && strlen (name) >= 4 && strlen (name) <= 40) {
        char resolved[41];
        if (bgit_odb_resolve (&ctx->odb, name, resolved) == 0) {
            memcpy (full, resolved, 41);
            return 0;
        }
    }
    return -1;
}

/* ---- init --------------------------------------------------------------- */

static int
git_write_file (const char *path, const char *content)
{
    FILE *f = fopen (path, "w");
    if (!f) return -1;
    fputs (content, f);
    return fclose (f) == 0 ? 0 : -1;
}

static int
git_cmd_init (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git init [-q | --quiet] [--bare] "
                        "[-b <branch-name>] [<directory>]";
    int quiet = 0, bare = 0;
    const char *branch = "master";   /* git's default without configuration */
    const char *where = ".";

    (void) ctx;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "--bare")) bare = 1;
        else if ((!strcmp (w, "-b") || !strcmp (w, "--initial-branch")) && p->next) {
            branch = p->next->word->word;
            p = p->next;
        } else if (!strncmp (w, "--initial-branch=", 17)) branch = w + 17;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else where = w;
    }
    if (!bgit_ref_name_ok (branch))
        return git_fatal ("invalid branch name: '%s'", branch);

    if (mkdir (where, 0777) < 0 && errno != EEXIST)
        return git_fatal ("cannot mkdir %s: %s", where, strerror (errno));
    char git_dir[4096];
    if (snprintf (git_dir, sizeof git_dir, bare ? "%s" : "%s/.git", where) >=
        (int) sizeof git_dir)
        return git_fatal ("path too long: %s", where);
    struct stat st;
    int existed = stat (git_dir, &st) == 0 && S_ISDIR (st.st_mode);
    if (mkdir (git_dir, 0777) < 0 && errno != EEXIST)
        return git_fatal ("cannot mkdir %s: %s", git_dir, strerror (errno));

    static const char *const subdirs[] = {
        "objects", "objects/info", "objects/pack", "refs", "refs/heads",
        "refs/tags", "info", "hooks", NULL
    };
    for (int i = 0; subdirs[i]; i++) {
        char path[4096];
        if (snprintf (path, sizeof path, "%s/%s", git_dir, subdirs[i]) >=
            (int) sizeof path)
            return git_fatal ("path too long: %s", git_dir);
        if (mkdir (path, 0777) < 0 && errno != EEXIST)
            return git_fatal ("cannot mkdir %s: %s", path, strerror (errno));
    }

    char path[4096], content[4096];
    snprintf (path, sizeof path, "%s/HEAD", git_dir);
    snprintf (content, sizeof content, "ref: refs/heads/%s\n", branch);
    if (access (path, F_OK) != 0 && git_write_file (path, content) < 0)
        return git_fatal ("cannot write %s: %s", path, strerror (errno));

    snprintf (path, sizeof path, "%s/config", git_dir);
    snprintf (content, sizeof content,
              "[core]\n"
              "\trepositoryformatversion = 0\n"
              "\tfilemode = true\n"
              "\tbare = %s\n%s",
              bare ? "true" : "false",
              bare ? "" : "\tlogallrefupdates = true\n");
    if (access (path, F_OK) != 0 && git_write_file (path, content) < 0)
        return git_fatal ("cannot write %s: %s", path, strerror (errno));

    snprintf (path, sizeof path, "%s/description", git_dir);
    if (access (path, F_OK) != 0 &&
        git_write_file (path, "Unnamed repository; edit this file "
                              "'description' to name the repository.\n") < 0)
        return git_fatal ("cannot write %s: %s", path, strerror (errno));

    snprintf (path, sizeof path, "%s/info/exclude", git_dir);
    if (access (path, F_OK) != 0 &&
        git_write_file (path,
                        "# git ls-files --others --exclude-from=.git/info/exclude\n"
                        "# Lines that start with '#' are comments.\n") < 0)
        return git_fatal ("cannot write %s: %s", path, strerror (errno));

    if (!quiet) {
        char *absolute = realpath (git_dir, NULL);
        printf ("%s empty Git repository in %s/\n",
                existed ? "Reinitialized existing" : "Initialized",
                absolute ? absolute : git_dir);
        free (absolute);
    }
    return 0;
}

/* ---- rev-parse ---------------------------------------------------------- */

/* The shortest unique abbreviation of at least LEN digits, as git does. */
static void
git_abbrev (git_context *ctx, const char *full, int len, char *out, size_t outsz)
{
    if (len < 4) len = 4;
    for (int n = len; n < 40; n++) {
        char prefix[41];
        memcpy (prefix, full, (size_t) n);
        prefix[n] = '\0';
        char resolved[41];
        if (bgit_odb_resolve (&ctx->odb, prefix, resolved) == 0 &&
            strcmp (resolved, full) == 0) {
            snprintf (out, outsz, "%s", prefix);
            return;
        }
    }
    snprintf (out, outsz, "%s", full);
}

static int
git_cmd_rev_parse (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git rev-parse [--git-dir] [--show-toplevel] "
                        "[--is-inside-work-tree] [--is-bare-repository] "
                        "[--abbrev-ref] [--short[=N]] [--symbolic-full-name] "
                        "[--verify] [-q] <rev>...";
    int quiet = 0, verify = 0, abbrev_ref = 0, symbolic_full = 0, short_len = 0;
    int printed = 0;

    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--git-dir")) {
            /* git prints ".git" at the top of a worktree, and the absolute
               path anywhere else. */
            char cwd[4096], top[4096];
            if (ctx->repo.work_tree && getcwd (cwd, sizeof cwd) &&
                strcmp (cwd, ctx->repo.work_tree) == 0 &&
                snprintf (top, sizeof top, "%s/.git", ctx->repo.work_tree) <
                    (int) sizeof top &&
                strcmp (top, ctx->repo.git_dir) == 0)
                printf (".git\n");
            else
                printf ("%s\n", ctx->repo.git_dir);
            printed = 1;
        } else if (!strcmp (w, "--absolute-git-dir")) {
            printf ("%s\n", ctx->repo.git_dir);
            printed = 1;
        } else if (!strcmp (w, "--show-toplevel")) {
            if (ctx->repo.work_tree) printf ("%s\n", ctx->repo.work_tree);
            printed = 1;
        } else if (!strcmp (w, "--is-inside-work-tree")) {
            printf ("%s\n", ctx->repo.work_tree ? "true" : "false");
            printed = 1;
        } else if (!strcmp (w, "--is-bare-repository")) {
            printf ("%s\n", ctx->repo.bare ? "true" : "false");
            printed = 1;
        } else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) {
            quiet = 1;
        } else if (!strcmp (w, "--verify")) {
            verify = 1;
        } else if (!strcmp (w, "--abbrev-ref") ||
                   !strncmp (w, "--abbrev-ref=", 13)) {
            abbrev_ref = 1;
        } else if (!strcmp (w, "--symbolic-full-name")) {
            symbolic_full = 1;
        } else if (!strcmp (w, "--short")) {
            short_len = 7;
        } else if (!strncmp (w, "--short=", 8)) {
            short_len = atoi (w + 8);
            if (short_len <= 0) return git_usage (usage);
        } else if (w[0] == '-' && w[1]) {
            return git_usage (usage);
        } else {
            char full[41];
            char *symref = NULL;
            if (git_resolve (ctx, w, full, &symref) < 0) {
                free (symref);
                if (verify) {
                    if (quiet) return 1;
                    return git_fatal ("Needed a single revision");
                }
                printf ("%s\n", w);
                fflush (stdout);
                fprintf (stderr,
                         "fatal: ambiguous argument '%s': unknown revision or path not in the working tree.\n"
                         "Use '--' to separate paths from revisions, like this:\n"
                         "'git <command> [<revision>...] -- [<file>...]'\n", w);
                return GIT_EXIT_FATAL;
            }
            if (symbolic_full) {
                if (symref) printf ("%s\n", symref);
            } else if (abbrev_ref) {
                const char *name = symref ? symref : w;
                const char *shortened = name;
                static const char *const strip[] = {
                    "refs/heads/", "refs/tags/", "refs/remotes/", NULL
                };
                for (int i = 0; strip[i]; i++)
                    if (!strncmp (name, strip[i], strlen (strip[i])))
                        shortened = name + strlen (strip[i]);
                printf ("%s\n", shortened);
            } else if (short_len) {
                char abbreviated[41];
                git_abbrev (ctx, full, short_len, abbreviated, sizeof abbreviated);
                printf ("%s\n", abbreviated);
            } else {
                printf ("%s\n", full);
            }
            free (symref);
            printed = 1;
        }
    }
    if (!printed && !args) return git_usage (usage);
    return 0;
}

/* ---- cat-file ----------------------------------------------------------- */

/* git prints a tree entry's mode padded to six digits, with the type its
   mode implies. */
static const char *
git_tree_entry_type (const char *mode)
{
    if (!strncmp (mode, "40000", 5) || !strncmp (mode, "040000", 6)) return "tree";
    if (!strncmp (mode, "160000", 6)) return "commit";
    return "blob";
}

static int
git_print_tree (const unsigned char *data, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        size_t mode_start = pos;
        while (pos < len && data[pos] != ' ') pos++;
        if (pos >= len) return git_fatal ("corrupt tree object");
        size_t mode_len = pos - mode_start;
        char mode[16];
        if (mode_len >= sizeof mode) return git_fatal ("corrupt tree object");
        memcpy (mode, data + mode_start, mode_len);
        mode[mode_len] = '\0';
        pos++;
        size_t name_start = pos;
        while (pos < len && data[pos] != '\0') pos++;
        if (pos >= len) return git_fatal ("corrupt tree object");
        size_t name_len = pos - name_start;
        pos++;
        if (pos + 20 > len) return git_fatal ("corrupt tree object");
        char hex[41];
        bgit_sha_to_hex (data + pos, hex);
        pos += 20;
        printf ("%06lu %s %s\t%.*s\n", strtoul (mode, NULL, 8),
                git_tree_entry_type (mode), hex, (int) name_len,
                (const char *) (data + name_start));
    }
    return 0;
}

static int
git_cmd_cat_file (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git cat-file (-t | -s | -e | -p | <type>) <object>";
    int want_type = 0, want_size = 0, want_exists = 0, pretty = 0;
    const char *as_type = NULL, *name = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-t")) want_type = 1;
        else if (!strcmp (w, "-s")) want_size = 1;
        else if (!strcmp (w, "-e")) want_exists = 1;
        else if (!strcmp (w, "-p")) pretty = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!as_type && !name && bgit_type_valid_name (w) &&
                 !want_type && !want_size && !want_exists && !pretty)
            as_type = w;
        else if (!name) name = w;
        else return git_usage (usage);
    }
    if (!name) return git_usage (usage);
    if (want_type + want_size + want_exists + pretty + (as_type ? 1 : 0) != 1)
        return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    char full[41];
    if (git_resolve (ctx, name, full, NULL) < 0) {
        if (want_exists) return 1;
        return git_fatal ("Not a valid object name %s", name);
    }
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    fflush (stderr);
    if (bgit_odb_read (&ctx->odb, full, &type, &data, &len) < 0) {
        if (want_exists) return 1;
        return git_fatal ("Not a valid object name %s", name);
    }
    int rc = 0;
    if (want_exists) {
        /* nothing to print */
    } else if (want_type) {
        printf ("%s\n", bgit_type_name (type));
    } else if (want_size) {
        printf ("%zu\n", len);
    } else if (as_type) {
        if (strcmp (as_type, bgit_type_name (type)) != 0) {
            free (data);
            return git_fatal ("%s is not a %s", full, as_type);
        }
        fwrite (data, 1, len, stdout);
    } else if (type == BGIT_TREE) {
        rc = git_print_tree (data, len);
    } else {
        fwrite (data, 1, len, stdout);
    }
    free (data);
    return rc;
}

/* ---- hash-object ------------------------------------------------------- */

static int
git_cmd_hash_object (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git hash-object [-t <type>] [-w] [--stdin | "
                        "--stdin-paths] [--literally] [<file>...]";
    const char *type = "blob";
    int write_object = 0, from_stdin = 0, stdin_paths = 0, literally = 0;
    const char *files[64];
    int n_files = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-w")) write_object = 1;
        else if (!strcmp (w, "--stdin")) from_stdin = 1;
        else if (!strcmp (w, "--stdin-paths")) stdin_paths = 1;
        else if (!strcmp (w, "--literally")) literally = 1;
        else if (!strcmp (w, "-t") && p->next) { type = p->next->word->word; p = p->next; }
        else if (!strncmp (w, "-t", 2) && w[2]) type = w + 2;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_files < (int) (sizeof files / sizeof *files)) files[n_files++] = w;
        else return git_fatal ("too many files");
    }
    if (!literally && !bgit_type_valid_name (type))
        return git_fatal ("invalid object type \"%s\"", type);
    if (literally && !bgit_type_printable (type))
        return git_fatal ("invalid object type \"%s\"", type);
    if (!from_stdin && !stdin_paths && n_files == 0) return git_usage (usage);
    if (from_stdin && stdin_paths)
        return git_fatal ("Can't use --stdin-paths with --stdin");

    const char *objects = NULL;
    if (write_object) {
        if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
        objects = ctx->odb.object_dirs[0];
    }

    if (from_stdin) {
        unsigned char *content = NULL;
        size_t len = 0;
        if (bgit_slurp_fd (STDIN_FILENO, &content, &len) < 0)
            return git_fatal ("cannot read standard input: %s", strerror (errno));
        char id[41];
        int rc = bgit_write_object (objects, type, content, len, write_object, id);
        free (content);
        if (rc < 0) return GIT_EXIT_FATAL;
        printf ("%s\n", id);
    }
    if (stdin_paths) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t got;
        while ((got = getline (&line, &cap, stdin)) > 0) {
            while (got > 0 && (line[got - 1] == '\n' || line[got - 1] == '\r'))
                line[--got] = '\0';
            if (!got) continue;
            unsigned char *content = NULL;
            size_t len = 0;
            if (bgit_slurp_file (line, &content, &len) < 0) { free (line); return GIT_EXIT_FATAL; }
            char id[41];
            int rc = bgit_write_object (objects, type, content, len, write_object, id);
            free (content);
            if (rc < 0) { free (line); return GIT_EXIT_FATAL; }
            printf ("%s\n", id);
        }
        free (line);
    }
    for (int i = 0; i < n_files; i++) {
        unsigned char *content = NULL;
        size_t len = 0;
        if (bgit_slurp_file (files[i], &content, &len) < 0)
            return GIT_EXIT_FATAL;
        char id[41];
        int rc = bgit_write_object (objects, type, content, len, write_object, id);
        free (content);
        if (rc < 0) return GIT_EXIT_FATAL;
        printf ("%s\n", id);
    }
    return 0;
}

/* ---- update-ref -------------------------------------------------------- */

static int
git_cmd_update_ref (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git update-ref [-m <reason>] (-d <ref> [<oldvalue>] "
                        "| <ref> <newvalue> [<oldvalue>])";
    const char *message = NULL;
    int delete_ref = 0;
    const char *positional[3] = { NULL, NULL, NULL };
    int n = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-d") || !strcmp (w, "--delete")) delete_ref = 1;
        else if (!strcmp (w, "-m") && p->next) { message = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n < 3) positional[n++] = w;
        else return git_usage (usage);
    }
    if (!positional[0]) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    /* update-ref follows a symbolic ref to the ref it names. */
    const char *refname = positional[0];
    char *target = NULL;
    if (bgit_symref_read (&ctx->repo, refname, &target) == 0) refname = target;

    int rc;
    if (delete_ref) {
        const char *old = positional[1];
        rc = bgit_ref_delete (&ctx->repo, refname, old, message);
    } else {
        if (!positional[1]) { free (target); return git_usage (usage); }
        char new_id[41];
        if (git_resolve (ctx, positional[1], new_id, NULL) < 0) {
            free (target);
            return git_fatal ("%s: not a valid SHA1", positional[1]);
        }
        char old_id[41];
        const char *old = NULL;
        if (positional[2]) {
            if (!*positional[2]) old = "";
            else if (git_resolve (ctx, positional[2], old_id, NULL) < 0) {
                free (target);
                return git_fatal ("%s: not a valid SHA1", positional[2]);
            } else old = old_id;
        }
        rc = bgit_ref_update (&ctx->repo, refname, new_id, old, message);
    }
    free (target);
    return rc < 0 ? GIT_EXIT_FATAL : 0;
}

/* ---- symbolic-ref ------------------------------------------------------ */

static int
git_cmd_symbolic_ref (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git symbolic-ref [-m <reason>] [-q] [--short] "
                        "<name> [<ref>] | --delete <name>";
    int quiet = 0, shorten = 0, delete_ref = 0;
    const char *message = NULL, *name = NULL, *target = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "--short")) shorten = 1;
        else if (!strcmp (w, "-d") || !strcmp (w, "--delete")) delete_ref = 1;
        else if (!strcmp (w, "-m") && p->next) { message = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else if (!target) target = w;
        else return git_usage (usage);
    }
    if (!name) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    if (delete_ref) {
        char path[4096];
        if (bgit_ref_path (&ctx->repo, name, path, sizeof path) < 0)
            return git_fatal ("ref name too long: %s", name);
        if (unlink (path) < 0)
            return git_fatal ("cannot delete %s: %s", name, strerror (errno));
        return 0;
    }
    if (target) {
        if (bgit_symref_write (&ctx->repo, name, target, message) < 0)
            return GIT_EXIT_FATAL;
        return 0;
    }
    char *value = NULL;
    int rc = bgit_symref_read (&ctx->repo, name, &value);
    if (rc != 0) {
        if (quiet) return 1;
        return git_fatal ("ref %s is not a symbolic ref", name);
    }
    const char *print = value;
    if (shorten && !strncmp (value, "refs/heads/", 11)) print = value + 11;
    printf ("%s\n", print);
    free (value);
    return 0;
}

/* ---- show-ref ---------------------------------------------------------- */

static int
git_cmd_show_ref (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git show-ref [--head] [--heads] [--tags] [-q] "
                        "[--verify] [<pattern>...]";
    int head = 0, heads = 0, tags = 0, quiet = 0, verify = 0;
    const char *patterns[32];
    int n_patterns = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--head")) head = 1;
        else if (!strcmp (w, "--heads")) heads = 1;
        else if (!strcmp (w, "--tags")) tags = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "--verify")) verify = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_patterns < (int) (sizeof patterns / sizeof *patterns))
            patterns[n_patterns++] = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    int found = 0;
    if (verify) {
        for (int i = 0; i < n_patterns; i++) {
            char id[41];
            if (bgit_ref_read (&ctx->repo, patterns[i], id) != 0) {
                if (!quiet)
                    fprintf (stderr, "fatal: '%s' - not a valid ref\n", patterns[i]);
                return GIT_EXIT_FATAL;
            }
            if (!quiet) printf ("%s %s\n", id, patterns[i]);
            found = 1;
        }
        return found ? 0 : 1;
    }

    if (head) {
        char id[41];
        if (bgit_ref_resolve (&ctx->repo, "HEAD", id, NULL) == 0) {
            if (!quiet) printf ("%s HEAD\n", id);
            found = 1;
        }
    }
    const char *prefix = heads && !tags ? "refs/heads/"
                       : tags && !heads ? "refs/tags/" : "";
    bgit_ref *refs = NULL;
    size_t count = 0;
    if (bgit_refs_list (&ctx->repo, prefix, &refs, &count) < 0)
        return git_fatal ("cannot read refs");
    for (size_t i = 0; i < count; i++) {
        if (heads && tags &&
            strncmp (refs[i].name, "refs/heads/", 11) != 0 &&
            strncmp (refs[i].name, "refs/tags/", 10) != 0)
            continue;
        if (n_patterns) {
            int matched = 0;
            for (int j = 0; j < n_patterns && !matched; j++) {
                size_t plen = strlen (patterns[j]);
                size_t nlen = strlen (refs[i].name);
                /* git matches a pattern against whole path components from
                   the right: "main" matches refs/heads/main. */
                if (nlen >= plen && strcmp (refs[i].name + nlen - plen, patterns[j]) == 0 &&
                    (nlen == plen || refs[i].name[nlen - plen - 1] == '/'))
                    matched = 1;
            }
            if (!matched) continue;
        }
        if (!quiet) printf ("%s %s\n", refs[i].sha, refs[i].name);
        found = 1;
    }
    bgit_refs_free (refs, count);
    return found ? 0 : 1;
}

/* ---- for-each-ref ------------------------------------------------------ */

static void
git_format_ref (git_context *ctx, const bgit_ref *ref, const char *format)
{
    for (const char *p = format; *p; p++) {
        if (*p != '%') { putchar (*p); continue; }
        if (p[1] == '%') { putchar ('%'); p++; continue; }
        if (p[1] != '(') { putchar (*p); continue; }
        const char *close = strchr (p, ')');
        if (!close) { putchar (*p); continue; }
        size_t len = (size_t) (close - p - 2);
        char field[64];
        if (len >= sizeof field) { p = close; continue; }
        memcpy (field, p + 2, len);
        field[len] = '\0';
        p = close;
        if (!strcmp (field, "refname")) {
            fputs (ref->name, stdout);
        } else if (!strcmp (field, "refname:short") || !strcmp (field, "refname:strip=2")) {
            const char *shortened = ref->name;
            static const char *const strip[] = {
                "refs/heads/", "refs/tags/", "refs/remotes/", NULL
            };
            for (int i = 0; strip[i]; i++)
                if (!strncmp (ref->name, strip[i], strlen (strip[i])))
                    shortened = ref->name + strlen (strip[i]);
            fputs (shortened, stdout);
        } else if (!strcmp (field, "objectname")) {
            fputs (ref->sha, stdout);
        } else if (!strcmp (field, "objectname:short")) {
            char abbreviated[41];
            git_abbrev (ctx, ref->sha, 7, abbreviated, sizeof abbreviated);
            fputs (abbreviated, stdout);
        } else if (!strcmp (field, "objecttype") || !strcmp (field, "objectsize")) {
            enum bgit_type type;
            unsigned char *data = NULL;
            size_t size = 0;
            if (bgit_odb_read (&ctx->odb, ref->sha, &type, &data, &size) == 0) {
                if (!strcmp (field, "objecttype")) fputs (bgit_type_name (type), stdout);
                else printf ("%zu", size);
                free (data);
            }
        }
    }
    putchar ('\n');
}

static int
git_cmd_for_each_ref (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git for-each-ref [--count=<n>] [--format=<format>] "
                        "[<pattern>...]";
    const char *format = "%(objectname) %(objecttype)\t%(refname)";
    long limit = -1;
    const char *patterns[32];
    int n_patterns = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strncmp (w, "--format=", 9)) format = w + 9;
        else if (!strcmp (w, "--format") && p->next) { format = p->next->word->word; p = p->next; }
        else if (!strncmp (w, "--count=", 8)) limit = atol (w + 8);
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_patterns < (int) (sizeof patterns / sizeof *patterns))
            patterns[n_patterns++] = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    bgit_ref *refs = NULL;
    size_t count = 0;
    if (bgit_refs_list (&ctx->repo, "", &refs, &count) < 0)
        return git_fatal ("cannot read refs");
    long printed = 0;
    for (size_t i = 0; i < count; i++) {
        if (n_patterns) {
            int matched = 0;
            for (int j = 0; j < n_patterns && !matched; j++) {
                size_t plen = strlen (patterns[j]);
                if (!strncmp (refs[i].name, patterns[j], plen) &&
                    (refs[i].name[plen] == '\0' || refs[i].name[plen] == '/' ||
                     patterns[j][plen - 1] == '/'))
                    matched = 1;
            }
            if (!matched) continue;
        }
        if (limit >= 0 && printed >= limit) break;
        git_format_ref (ctx, &refs[i], format);
        printed++;
    }
    bgit_refs_free (refs, count);
    return 0;
}

/* ---- reflog ------------------------------------------------------------ */

static int
git_cmd_reflog (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git reflog [show] [<ref>]";
    const char *ref = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "show")) continue;
        if (w[0] == '-' && w[1]) return git_usage (usage);
        if (!ref) ref = w;
        else return git_usage (usage);
    }
    if (!ref) ref = "HEAD";
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    /* A name like "main" means refs/heads/main for a reflog. */
    char resolved[4096];
    snprintf (resolved, sizeof resolved, "%s", ref);
    char probe[4096];
    if (strcmp (ref, "HEAD") != 0 && strncmp (ref, "refs/", 5) != 0 &&
        snprintf (probe, sizeof probe, "refs/heads/%s", ref) < (int) sizeof probe) {
        char id[41];
        if (bgit_ref_read (&ctx->repo, probe, id) == 0)
            snprintf (resolved, sizeof resolved, "%s", probe);
    }

    char **lines = NULL;
    size_t n = 0;
    int rc = bgit_reflog_lines (&ctx->repo, resolved, &lines, &n);
    if (rc < 0) return git_fatal ("cannot read the reflog for %s", ref);
    if (rc > 0) return 0;   /* no reflog: git prints nothing */

    const char *display = resolved;
    static const char *const strip[] = { "refs/heads/", "refs/remotes/", NULL };
    for (int i = 0; strip[i]; i++)
        if (!strncmp (display, strip[i], strlen (strip[i])))
            display = display + strlen (strip[i]);

    /* Newest first, numbered from 0, as git shows them. */
    for (size_t i = n; i > 0; i--) {
        const char *line = lines[i - 1];
        char new_id[41] = "";
        const char *message = strchr (line, '\t');
        if (strlen (line) >= 82) memcpy (new_id, line + 41, 40);
        new_id[40] = '\0';
        char abbreviated[41];
        git_abbrev (ctx, new_id, 7, abbreviated, sizeof abbreviated);
        printf ("%s %s@{%zu}: %s\n", abbreviated, display, n - i,
                message ? message + 1 : "");
    }
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return 0;
}

/* ---- dispatch ---------------------------------------------------------- */

typedef int (*git_command_fn) (git_context *, WORD_LIST *);

static const struct {
    const char *name;
    git_command_fn run;
} git_commands[] = {
    { "cat-file",     git_cmd_cat_file },
    { "for-each-ref", git_cmd_for_each_ref },
    { "hash-object",  git_cmd_hash_object },
    { "init",         git_cmd_init },
    { "reflog",       git_cmd_reflog },
    { "rev-parse",    git_cmd_rev_parse },
    { "show-ref",     git_cmd_show_ref },
    { "symbolic-ref", git_cmd_symbolic_ref },
    { "update-ref",   git_cmd_update_ref },
    { NULL, NULL }
};

static int
git_run (WORD_LIST *list)
{
    /* Global options come before the command, as in git. */
    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--version")) {
            printf ("%s\n", GIT_VERSION_STRING);
            return 0;
        }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            printf ("usage: git [--version] [-C <path>] [--git-dir=<path>] "
                    "[--work-tree=<path>] <command> [<args>]\n\n"
                    "Commands in this build:\n");
            for (int i = 0; git_commands[i].name; i++)
                printf ("   %s\n", git_commands[i].name);
            return 0;
        }
        if (!strcmp (w, "--list-cmds") || !strncmp (w, "--list-cmds=", 12)) {
            for (int i = 0; git_commands[i].name; i++)
                printf ("%s\n", git_commands[i].name);
            return 0;
        }
        if (!strcmp (w, "-C") && list->next) {
            list = list->next;
            if (chdir (list->word->word) < 0)
                return git_fatal ("cannot change to '%s': %s",
                                  list->word->word, strerror (errno));
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--git-dir=", 10)) {
            setenv ("GIT_DIR", w + 10, 1);
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--git-dir") && list->next) {
            setenv ("GIT_DIR", list->next->word->word, 1);
            list = list->next->next;
            continue;
        }
        if (!strncmp (w, "--work-tree=", 12)) {
            setenv ("GIT_WORK_TREE", w + 12, 1);
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--work-tree") && list->next) {
            setenv ("GIT_WORK_TREE", list->next->word->word, 1);
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "--no-pager") || !strcmp (w, "-p") ||
            !strcmp (w, "--paginate")) {
            /* Nothing paginates here; accepted so scripts need no change. */
            list = list->next;
            continue;
        }
        if (w[0] == '-')
            return git_usage ("git [--version] [-C <path>] [--git-dir=<path>] "
                              "[--work-tree=<path>] <command> [<args>]");
        break;
    }
    if (!list) {
        return git_usage ("git [--version] [-C <path>] [--git-dir=<path>] "
                          "[--work-tree=<path>] <command> [<args>]");
    }

    const char *command = list->word->word;
    for (int i = 0; git_commands[i].name; i++) {
        if (strcmp (command, git_commands[i].name) != 0) continue;
        git_context ctx;
        memset (&ctx, 0, sizeof ctx);
        int status = git_commands[i].run (&ctx, list->next);
        git_context_close (&ctx);
        return status;
    }
    fflush (stdout);
    fprintf (stderr, "git: '%s' is not a git command. See 'git --help'.\n",
             command);
    return 1;
}

int
git_builtin (WORD_LIST *list)
{
    /* Each call runs in a child: a fatal error is an exit, -C cannot move the
       caller, and held locks are released when the child dies. */
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) {
        builtin_error ("fork: %s", strerror (errno));
        return GIT_EXIT_FATAL;
    }
    if (pid == 0) {
        bos_prepare_child ();
        int status = git_run (list);
        bgit_lock_release_all ();
        if (fflush (stdout) == EOF && status == 0)
            status = 1;
        fflush (stderr);
        _exit (status);
    }
    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno != EINTR) {
            builtin_error ("waitpid: %s", strerror (errno));
            return GIT_EXIT_FATAL;
        }
    }
    if (WIFSIGNALED (status))
        return 128 + WTERMSIG (status);
    return WEXITSTATUS (status);
}

char *git_doc[] = {
    "Run a git command, in a forked child.",
    "",
    "    git [--version] [-C <path>] [--git-dir=<path>] [--work-tree=<path>]",
    "        <command> [<args>]",
    "",
    "  Commands in this build:",
    "    git init [-q] [--bare] [-b <branch>] [<directory>]",
    "    git rev-parse [--git-dir] [--show-toplevel] [--is-inside-work-tree]",
    "                  [--is-bare-repository] [--abbrev-ref] [--short[=N]]",
    "                  [--symbolic-full-name] [--verify] [-q] <rev>...",
    "    git cat-file (-t | -s | -e | -p | <type>) <object>",
    "    git hash-object [-t <type>] [-w] [--stdin|--stdin-paths] [<file>...]",
    "    git update-ref [-m <reason>] (-d <ref> [<old>] | <ref> <new> [<old>])",
    "    git symbolic-ref [-m <reason>] [-q] [--short] <name> [<ref>]",
    "    git show-ref [--head] [--heads] [--tags] [-q] [--verify] [<pattern>...]",
    "    git for-each-ref [--count=<n>] [--format=<format>] [<pattern>...]",
    "    git reflog [show] [<ref>]",
    "",
    "Object reads cover loose objects, every pack, and the alternates. Refs",
    "cover loose refs, packed-refs and symbolic refs; every change is made",
    "under a lock file and appends a reflog entry, so git reads what this",
    "writes and the other way round.",
    "",
    "Exit statuses are git's: 0, 1, 128 for a fatal error and 129 for a usage",
    "error. A command or option this build does not have exits 129 or 1 and",
    "says so; nothing is silently ignored. `git --list-cmds` prints the",
    "commands that are here.",
    (char *)NULL
};

struct builtin git_struct = {
    "git",
    git_builtin,
    BUILTIN_ENABLED,
    git_doc,
    "git [--version] [-C <path>] [--git-dir=<path>] [--work-tree=<path>] <command> [<args>]",
    0
};
