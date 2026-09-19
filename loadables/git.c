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

#include "_git_config.h"
#include "_git_ignore.h"
#include "_git_index.h"
#include "_git_odb.h"
#include "_git_refs.h"
#include "_git_repo.h"
#include "_git_revision.h"
#include "_git_tree.h"
#include "_git_worktree.h"
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

/* Values from `git -c key=value`, applied over every configuration file. */
#define GIT_MAX_OVERRIDES 32
static const char *git_overrides[GIT_MAX_OVERRIDES];
static size_t git_n_overrides;

/* One repository plus its object store and configuration, opened when a
   command needs them. */
typedef struct {
    bgit_repo repo;
    bgit_odb odb;
    bgit_config cfg;
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
    bgit_config_load (&ctx->cfg, &ctx->repo, git_overrides, git_n_overrides);
    /* Reflog entries record the configured identity. */
    char ident[1024];
    if (bgit_ident (&ctx->cfg, 1, ident, sizeof ident) == 0)
        bgit_refs_set_ident (ident);
    return 0;
}

static void
git_context_close (git_context *ctx)
{
    bgit_config_release (&ctx->cfg);
    if (!ctx->open) return;
    bgit_odb_release (&ctx->odb);
    bgit_repo_release (&ctx->repo);
    ctx->open = 0;
}

/* Resolve a revision: an id, an abbreviation, a ref, or any of those with
   git's suffixes (^, ~, ^{type}, @{n}). */
static int
git_resolve (git_context *ctx, const char *name, char full[41], char **symref)
{
    return bgit_rev_parse (&ctx->repo, &ctx->odb, name, full, symref);
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
        printf ("%06lo %s %s\t%.*s\n", strtoul (mode, NULL, 8),
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

/* ---- the index, trees, and commits ------------------------------------- */

/* The index file: GIT_INDEX_FILE, or the repository's own. */
static int
git_index_path (git_context *ctx, char *out, size_t outsz)
{
    const char *env = getenv ("GIT_INDEX_FILE");
    if (env && *env)
        return snprintf (out, outsz, "%s", env) < (int) outsz ? 0 : -1;
    return snprintf (out, outsz, "%s/index", ctx->repo.git_dir) < (int) outsz
           ? 0 : -1;
}

static int
git_index_load (git_context *ctx, bgit_index_entry **entries, size_t *n)
{
    char path[4096];
    *entries = NULL;
    *n = 0;
    if (git_index_path (ctx, path, sizeof path) < 0) return -1;
    if (access (path, R_OK) != 0) return 0;      /* no index yet */
    return bgit_index_read (path, entries, n);
}

static int
git_index_store (git_context *ctx, bgit_index_entry *entries, size_t n)
{
    char path[4096];
    if (git_index_path (ctx, path, sizeof path) < 0) return -1;
    if (n > 1) qsort (entries, n, sizeof *entries, bgit_index_path_cmp);
    return bgit_index_write (path, entries, n);
}

/* Replace or append one path in the index. */
static int
git_index_put (bgit_index_entry **entries, size_t *n, size_t *cap,
               const bgit_index_entry *entry)
{
    for (size_t i = 0; i < *n; i++) {
        if (strcmp ((*entries)[i].path, entry->path) != 0) continue;
        char *keep = (*entries)[i].path;
        (*entries)[i] = *entry;
        (*entries)[i].path = keep;
        free (entry->path);
        return 0;
    }
    if (*n == *cap) {
        size_t next = *cap ? *cap * 2 : 32;
        bgit_index_entry *grown = realloc (*entries, next * sizeof *grown);
        if (!grown) return -1;
        *entries = grown;
        *cap = next;
    }
    (*entries)[(*n)++] = *entry;
    return 0;
}

static int
git_cmd_update_index (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git update-index [--add] [--remove] "
                        "[--cacheinfo <mode>,<object>,<path>] [--index-info] "
                        "[--] [<file>...]";
    int add = 0, remove = 0, index_info = 0;
    const char *cacheinfo[3] = { NULL, NULL, NULL };
    int n_cacheinfo = 0;
    const char *files[64];
    int n_files = 0;
    int no_more_options = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more_options && !strcmp (w, "--")) { no_more_options = 1; continue; }
        if (!no_more_options && !strcmp (w, "--add")) add = 1;
        else if (!no_more_options && !strcmp (w, "--remove")) remove = 1;
        else if (!no_more_options && !strcmp (w, "--replace")) { /* implied */ }
        else if (!no_more_options && !strcmp (w, "--index-info")) index_info = 1;
        else if (!no_more_options && !strcmp (w, "--cacheinfo")) {
            /* Either one comma-separated argument or three separate ones. */
            if (p->next && strchr (p->next->word->word, ',')) {
                char copy[4096];
                snprintf (copy, sizeof copy, "%s", p->next->word->word);
                p = p->next;
                char *save = NULL;
                for (char *field = strtok_r (copy, ",", &save);
                     field && n_cacheinfo < 3;
                     field = strtok_r (NULL, ",", &save))
                    cacheinfo[n_cacheinfo++] = strdup (field);
            } else {
                for (int i = 0; i < 3; i++) {
                    if (!p->next) return git_usage (usage);
                    p = p->next;
                    cacheinfo[n_cacheinfo++] = p->word->word;
                }
            }
        }
        else if (!no_more_options && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_files < (int) (sizeof files / sizeof *files)) files[n_files++] = w;
        else return git_fatal ("too many files");
    }
    if (n_cacheinfo && n_cacheinfo != 3) return git_usage (usage);
    if (!n_cacheinfo && !index_info && !n_files) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    bgit_index_entry *entries = NULL;
    size_t n = 0, cap = 0;
    if (git_index_load (ctx, &entries, &n) < 0) return GIT_EXIT_FATAL;
    cap = n;
    int status = 0;

    if (n_cacheinfo == 3) {
        bgit_index_entry entry;
        memset (&entry, 0, sizeof entry);
        if (bgit_index_parse_mode (cacheinfo[0], &entry.mode) < 0 ||
            bgit_hex_to_sha (cacheinfo[1], entry.sha) < 0) {
            status = git_fatal ("git update-index: --cacheinfo cannot add %s",
                                cacheinfo[2]);
            goto done;
        }
        entry.path = strdup (cacheinfo[2]);
        size_t len = strlen (cacheinfo[2]);
        entry.flags = (uint16_t) (len > 0xFFF ? 0xFFF : len);
        if (!entry.path || git_index_put (&entries, &n, &cap, &entry) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
    }

    if (index_info) {
        char *line = NULL;
        size_t line_cap = 0;
        while (getline (&line, &line_cap, stdin) > 0) {
            bgit_index_entry entry;
            int is_remove = 0;
            if (bgit_index_info_line_to_entry (line, &entry, &is_remove) < 0) {
                free (line);
                status = git_fatal ("malformed --index-info line");
                goto done;
            }
            if (is_remove) {
                bgit_index_remove_path (&entries, &n, entry.path);
                free (entry.path);
                continue;
            }
            if (git_index_put (&entries, &n, &cap, &entry) < 0) {
                free (line);
                status = GIT_EXIT_FATAL;
                goto done;
            }
        }
        free (line);
    }

    for (int i = 0; i < n_files; i++) {
        struct stat st;
        if (stat (files[i], &st) < 0) {
            if (remove) {
                bgit_index_remove_path (&entries, &n, files[i]);
                continue;
            }
            status = git_fatal ("unable to stat '%s': %s", files[i],
                                strerror (errno));
            goto done;
        }
        unsigned char *content = NULL;
        size_t len = 0;
        if (bgit_slurp_file (files[i], &content, &len) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        char id[41];
        int rc = bgit_write_object (ctx->odb.object_dirs[0], "blob", content,
                                   len, 1, id);
        free (content);
        if (rc < 0) { status = GIT_EXIT_FATAL; goto done; }
        bgit_index_entry entry;
        memset (&entry, 0, sizeof entry);
        bgit_index_entry_set_stat (&entry, &st);
        /* git stores 100644, or 100755 when the file is executable. */
        entry.mode = (st.st_mode & 0111) ? 0100755 : 0100644;
        if (bgit_hex_to_sha (id, entry.sha) < 0) { status = GIT_EXIT_FATAL; goto done; }
        entry.path = strdup (files[i]);
        size_t plen = strlen (files[i]);
        entry.flags = (uint16_t) (plen > 0xFFF ? 0xFFF : plen);
        if (!entry.path || git_index_put (&entries, &n, &cap, &entry) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        (void) add;
    }

    if (git_index_store (ctx, entries, n) < 0) status = GIT_EXIT_FATAL;
done:
    bgit_index_free_entries (entries, n);
    return status;
}

static int
git_cmd_ls_files (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git ls-files [-s | --stage] [-z] [--] [<file>...]";
    int stage = 0, zero = 0, no_more_options = 0;
    const char *patterns[32];
    int n_patterns = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more_options && !strcmp (w, "--")) { no_more_options = 1; continue; }
        if (!no_more_options && (!strcmp (w, "-s") || !strcmp (w, "--stage"))) stage = 1;
        else if (!no_more_options && !strcmp (w, "-z")) zero = 1;
        else if (!no_more_options && !strcmp (w, "--cached")) { /* the default */ }
        else if (!no_more_options && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_patterns < (int) (sizeof patterns / sizeof *patterns))
            patterns[n_patterns++] = w;
        else return git_fatal ("too many paths");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    bgit_index_entry *entries = NULL;
    size_t n = 0;
    if (git_index_load (ctx, &entries, &n) < 0) return GIT_EXIT_FATAL;
    for (size_t i = 0; i < n; i++) {
        if (n_patterns) {
            int matched = 0;
            for (int j = 0; j < n_patterns && !matched; j++) {
                size_t plen = strlen (patterns[j]);
                if (!strcmp (entries[i].path, patterns[j]) ||
                    (!strncmp (entries[i].path, patterns[j], plen) &&
                     (patterns[j][plen - 1] == '/' || entries[i].path[plen] == '/')))
                    matched = 1;
            }
            if (!matched) continue;
        }
        char hex[41];
        bgit_sha_to_hex (entries[i].sha, hex);
        if (stage)
            printf ("%o %s %d\t%s%c", entries[i].mode, hex,
                    (entries[i].flags >> 12) & 0x3, entries[i].path,
                    zero ? '\0' : '\n');
        else
            printf ("%s%c", entries[i].path, zero ? '\0' : '\n');
    }
    bgit_index_free_entries (entries, n);
    return 0;
}

static int
git_cmd_write_tree (git_context *ctx, WORD_LIST *args)
{
    if (args) return git_usage ("git write-tree");
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    bgit_index_entry *entries = NULL;
    size_t n = 0;
    if (git_index_load (ctx, &entries, &n) < 0) return GIT_EXIT_FATAL;
    char tree[41];
    int rc = bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], entries, n, tree);
    bgit_index_free_entries (entries, n);
    if (rc < 0) return GIT_EXIT_FATAL;
    printf ("%s\n", tree);
    return 0;
}

static int
git_cmd_read_tree (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git read-tree <tree-ish>";
    const char *name = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (w[0] == '-' && w[1]) return git_usage (usage);
        if (name) return git_usage (usage);
        name = w;
    }
    if (!name) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    char id[41];
    if (git_resolve (ctx, name, id, NULL) < 0)
        return git_fatal ("Not a valid object name %s", name);
    char tree[41];
    if (bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0)
        return git_fatal ("Not a valid tree object name %s", name);
    bgit_index_entry *entries = NULL;
    size_t n = 0;
    if (bgit_read_tree (&ctx->odb, tree, &entries, &n) < 0)
        return git_fatal ("cannot read tree %s", tree);
    int rc = git_index_store (ctx, entries, n);
    bgit_index_free_entries (entries, n);
    return rc < 0 ? GIT_EXIT_FATAL : 0;
}

static int
git_cmd_commit_tree (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git commit-tree <tree> [(-p <parent>)...] "
                        "[(-m <message>)...] [-F <file>]";
    const char *tree_name = NULL;
    const char *parents[BGIT_MAX_PARENTS];
    int n_parents = 0;
    const char *messages[16];
    int n_messages = 0;
    const char *message_file = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-p") && p->next) {
            if (n_parents >= BGIT_MAX_PARENTS) return git_fatal ("too many parents");
            parents[n_parents++] = p->next->word->word;
            p = p->next;
        } else if (!strcmp (w, "-m") && p->next) {
            if (n_messages >= (int) (sizeof messages / sizeof *messages))
                return git_fatal ("too many messages");
            messages[n_messages++] = p->next->word->word;
            p = p->next;
        } else if (!strcmp (w, "-F") && p->next) {
            message_file = p->next->word->word;
            p = p->next;
        } else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!tree_name) tree_name = w;
        else return git_usage (usage);
    }
    if (!tree_name) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    char tree_id[41], tree[41];
    if (git_resolve (ctx, tree_name, tree_id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, tree_id, BGIT_TREE, tree) < 0)
        return git_fatal ("not a valid object name %s", tree_name);

    char resolved_parents[BGIT_MAX_PARENTS][41];
    for (int i = 0; i < n_parents; i++) {
        char id[41];
        if (git_resolve (ctx, parents[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, resolved_parents[i]) < 0)
            return git_fatal ("not a valid object name %s", parents[i]);
    }

    char author[1024], committer[1024];
    if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0 ||
        bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0)
        return git_fatal ("cannot determine the identity to use");

    /* Body: headers, a blank line, then the message. */
    size_t cap = 4096, len = 0;
    char *body = malloc (cap);
    if (!body) return GIT_EXIT_FATAL;
#define GIT_APPEND(...) do { \
    for (;;) { \
        int wrote = snprintf (body + len, cap - len, __VA_ARGS__); \
        if (wrote < 0) { free (body); return GIT_EXIT_FATAL; } \
        if ((size_t) wrote < cap - len) { len += (size_t) wrote; break; } \
        cap *= 2; \
        char *grown = realloc (body, cap); \
        if (!grown) { free (body); return GIT_EXIT_FATAL; } \
        body = grown; \
    } \
} while (0)
    GIT_APPEND ("tree %s\n", tree);
    for (int i = 0; i < n_parents; i++) GIT_APPEND ("parent %s\n", resolved_parents[i]);
    GIT_APPEND ("author %s\n", author);
    GIT_APPEND ("committer %s\n", committer);
    GIT_APPEND ("\n");
    if (message_file) {
        unsigned char *text = NULL;
        size_t text_len = 0;
        if (bgit_slurp_file (message_file, &text, &text_len) < 0) {
            free (body);
            return GIT_EXIT_FATAL;
        }
        GIT_APPEND ("%.*s", (int) text_len, (const char *) text);
        free (text);
    } else if (n_messages) {
        for (int i = 0; i < n_messages; i++)
            GIT_APPEND ("%s%s\n", i ? "\n" : "", messages[i]);
    } else {
        unsigned char *text = NULL;
        size_t text_len = 0;
        if (bgit_slurp_fd (STDIN_FILENO, &text, &text_len) < 0) {
            free (body);
            return git_fatal ("cannot read the message: %s", strerror (errno));
        }
        GIT_APPEND ("%.*s", (int) text_len, (const char *) text);
        free (text);
    }
#undef GIT_APPEND
    if (len == 0 || body[len - 1] != '\n') {
        /* git ends a commit message with a newline. */
        if (len + 2 > cap) {
            char *grown = realloc (body, len + 2);
            if (!grown) { free (body); return GIT_EXIT_FATAL; }
            body = grown;
        }
        body[len++] = '\n';
    }

    char commit[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                               (const unsigned char *) body, len, 1, commit);
    free (body);
    if (rc < 0) return GIT_EXIT_FATAL;
    printf ("%s\n", commit);
    return 0;
}

struct git_ls_tree_options {
    int name_only;
    int zero;
};

static int
git_ls_tree_entry (void *vctx, const char *mode, const char *type,
                   const char *sha, const char *path)
{
    struct git_ls_tree_options *options = vctx;
    if (options->name_only)
        printf ("%s%c", path, options->zero ? '\0' : '\n');
    else
        printf ("%06lo %s %s\t%s%c", strtoul (mode, NULL, 8), type, sha, path,
                options->zero ? '\0' : '\n');
    return 0;
}

static int
git_cmd_ls_tree (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git ls-tree [-r] [-t] [-z] [--name-only] <tree-ish>";
    struct git_ls_tree_options options = {0};
    int recursive = 0, show_trees = 0;
    const char *name = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-r")) recursive = 1;
        else if (!strcmp (w, "-t")) show_trees = 1;
        else if (!strcmp (w, "-z")) options.zero = 1;
        else if (!strcmp (w, "--name-only") || !strcmp (w, "--name-status"))
            options.name_only = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else return git_usage (usage);
    }
    if (!name) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    char id[41], tree[41];
    if (git_resolve (ctx, name, id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0)
        return git_fatal ("not a tree object");
    if (bgit_tree_walk (&ctx->odb, tree, "", recursive, show_trees,
                        git_ls_tree_entry, &options) < 0)
        return git_fatal ("cannot read tree %s", tree);
    return 0;
}

/* ---- rev-list ---------------------------------------------------------- */

struct git_walk {
    char (*seen)[41];
    size_t n_seen, cap_seen;
    struct { char id[41]; long long date; } *pending;
    size_t n_pending, cap_pending;
};

static long long
git_commit_date (git_context *ctx, const char *sha)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (&ctx->odb, sha, &type, &data, &len) < 0) return 0;
    long long when = 0;
    const char *p = (const char *) data;
    const char *end = p + len;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) break;
        if (line > 10 && !memcmp (p, "committer ", 10)) {
            /* "committer Name <email> <seconds> <zone>" */
            const char *gt = memchr (p, '>', line);
            if (gt) when = strtoll (gt + 1, NULL, 10);
            break;
        }
        if (!nl) break;
        p = nl + 1;
    }
    free (data);
    return when;
}

static int
git_walk_seen (struct git_walk *walk, const char *sha)
{
    for (size_t i = 0; i < walk->n_seen; i++)
        if (!strcmp (walk->seen[i], sha)) return 1;
    if (walk->n_seen == walk->cap_seen) {
        size_t next = walk->cap_seen ? walk->cap_seen * 2 : 64;
        char (*grown)[41] = realloc (walk->seen, next * sizeof *grown);
        if (!grown) return -1;
        walk->seen = grown;
        walk->cap_seen = next;
    }
    memcpy (walk->seen[walk->n_seen++], sha, 41);
    return 0;
}

static int
git_walk_push (git_context *ctx, struct git_walk *walk, const char *sha)
{
    int seen = git_walk_seen (walk, sha);
    if (seen != 0) return seen < 0 ? -1 : 0;
    if (walk->n_pending == walk->cap_pending) {
        size_t next = walk->cap_pending ? walk->cap_pending * 2 : 32;
        void *grown = realloc (walk->pending, next * sizeof *walk->pending);
        if (!grown) return -1;
        walk->pending = grown;
        walk->cap_pending = next;
    }
    memcpy (walk->pending[walk->n_pending].id, sha, 41);
    walk->pending[walk->n_pending].date = git_commit_date (ctx, sha);
    walk->n_pending++;
    return 0;
}

static int
git_cmd_rev_list (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git rev-list [--count] [-n <number> | "
                        "--max-count=<number>] <commit>...";
    int count_only = 0;
    long limit = -1;
    const char *revs[16];
    int n_revs = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--count")) count_only = 1;
        else if (!strcmp (w, "-n") && p->next) { limit = atol (p->next->word->word); p = p->next; }
        else if (!strncmp (w, "--max-count=", 12)) limit = atol (w + 12);
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_revs < (int) (sizeof revs / sizeof *revs)) revs[n_revs++] = w;
        else return git_fatal ("too many revisions");
    }
    if (!n_revs) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    struct git_walk walk;
    memset (&walk, 0, sizeof walk);
    int status = 0;
    for (int i = 0; i < n_revs; i++) {
        char id[41], commit[41];
        if (git_resolve (ctx, revs[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            status = git_fatal ("ambiguous argument '%s': unknown revision or "
                                "path not in the working tree.", revs[i]);
            goto done;
        }
        if (git_walk_push (ctx, &walk, commit) < 0) { status = GIT_EXIT_FATAL; goto done; }
    }

    long emitted = 0;
    while (walk.n_pending) {
        /* Newest first, as git's default order does. */
        size_t best = 0;
        for (size_t i = 1; i < walk.n_pending; i++)
            if (walk.pending[i].date > walk.pending[best].date) best = i;
        char current[41];
        memcpy (current, walk.pending[best].id, 41);
        memmove (walk.pending + best, walk.pending + best + 1,
                 (walk.n_pending - best - 1) * sizeof *walk.pending);
        walk.n_pending--;

        if (limit >= 0 && emitted >= limit) break;
        if (!count_only) printf ("%s\n", current);
        emitted++;

        char parents[BGIT_MAX_PARENTS][41];
        int n = bgit_commit_parents (&ctx->odb, current, parents, BGIT_MAX_PARENTS);
        for (int i = 0; i < n; i++)
            if (git_walk_push (ctx, &walk, parents[i]) < 0) {
                status = GIT_EXIT_FATAL;
                goto done;
            }
    }
    if (count_only) printf ("%ld\n", emitted);
done:
    free (walk.seen);
    free (walk.pending);
    return status;
}

static int
git_cmd_var (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git var (GIT_AUTHOR_IDENT | GIT_COMMITTER_IDENT)";
    if (!args || args->next) return git_usage (usage);
    const char *name = args->word->word;
    bgit_repo repo;
    int have_repo = bgit_repo_discover (".", &repo) == 0;
    bgit_config cfg;
    bgit_config_load (&cfg, have_repo ? &repo : NULL, git_overrides,
                      git_n_overrides);
    char ident[1024];
    int status = 0;
    if (!strcmp (name, "GIT_AUTHOR_IDENT") || !strcmp (name, "GIT_COMMITTER_IDENT")) {
        if (bgit_ident (&cfg, !strcmp (name, "GIT_COMMITTER_IDENT"), ident,
                        sizeof ident) < 0)
            status = git_fatal ("cannot determine the identity to use");
        else
            printf ("%s\n", ident);
    } else {
        fflush (stdout);
        fprintf (stderr, "fatal: %s: unknown variable\n", name);
        status = GIT_EXIT_FATAL;
    }
    bgit_config_release (&cfg);
    if (have_repo) bgit_repo_release (&repo);
    (void) ctx;
    return status;
}

/* ---- add, status and commit -------------------------------------------- */

/* The index, the HEAD tree and the status of everything, in one place. */
struct git_state {
    bgit_index_entry *index;
    size_t n_index, cap_index;
    char head[41];
    char head_tree[41];
    int have_head;
    char *branch;           /* the ref HEAD names, or NULL when detached */
};

static void
git_state_release (struct git_state *state)
{
    bgit_index_free_entries (state->index, state->n_index);
    free (state->branch);
    memset (state, 0, sizeof *state);
}

static int
git_state_load (git_context *ctx, struct git_state *state)
{
    memset (state, 0, sizeof *state);
    if (git_index_load (ctx, &state->index, &state->n_index) < 0) return -1;
    state->cap_index = state->n_index;
    char *symref = NULL;
    if (bgit_ref_resolve (&ctx->repo, "HEAD", state->head, &symref) == 0) {
        state->have_head = 1;
        if (bgit_peel_to_type (&ctx->odb, state->head, BGIT_TREE,
                               state->head_tree) < 0) {
            free (symref);
            return -1;
        }
    }
    if (!symref) {
        /* An unborn branch still names where a commit will go. */
        char *target = NULL;
        if (bgit_symref_read (&ctx->repo, "HEAD", &target) == 0) symref = target;
    }
    state->branch = symref;
    return 0;
}

/* Stage one working-tree file, replacing whatever the index held. */
static int
git_stage_file (git_context *ctx, struct git_state *state, const char *path,
                const struct stat *st)
{
    char full[4096];
    if (snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, path) >=
        (int) sizeof full)
        return -1;
    unsigned char *content = NULL;
    size_t len = 0;
    if (S_ISLNK (st->st_mode)) {
        char target[4096];
        ssize_t got = readlink (full, target, sizeof target);
        if (got < 0) return -1;
        content = malloc ((size_t) got);
        if (!content) return -1;
        memcpy (content, target, (size_t) got);
        len = (size_t) got;
    } else {
        if (bgit_slurp_file (full, &content, &len) < 0) return -1;
    }
    char id[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "blob", content, len,
                               1, id);
    free (content);
    if (rc < 0) return -1;

    bgit_index_entry entry;
    memset (&entry, 0, sizeof entry);
    bgit_index_entry_set_stat (&entry, st);
    entry.mode = bgit_worktree_mode (st);
    if (bgit_hex_to_sha (id, entry.sha) < 0) return -1;
    size_t plen = strlen (path);
    entry.flags = (uint16_t) (plen > 0xFFF ? 0xFFF : plen);
    entry.path = strdup (path);
    if (!entry.path) return -1;
    return git_index_put (&state->index, &state->n_index, &state->cap_index,
                          &entry);
}

struct git_add_ctx {
    git_context *ctx;
    struct git_state *state;
    const bgit_ignore *ignore;
    const char *pathspec;      /* "" for everything */
    int update_only;           /* -u: only what the index already has */
    int dry_run;
    int *changed;
};

/* Is PATH inside the pathspec (a file, a directory, or everything)? */
static int
git_path_in_spec (const char *path, const char *spec)
{
    if (!*spec || !strcmp (spec, ".")) return 1;
    size_t len = strlen (spec);
    if (!strcmp (path, spec)) return 1;
    return !strncmp (path, spec, len) && path[len] == '/';
}

static int
git_add_visit (void *vctx, const char *path, int is_dir, const struct stat *st)
{
    struct git_add_ctx *add = vctx;
    if (is_dir) {
        /* Skip a directory outside the pathspec, or one that is ignored. */
        size_t len = strlen (path);
        if (*add->pathspec && strcmp (add->pathspec, ".") &&
            strncmp (add->pathspec, path, len) != 0 &&
            !git_path_in_spec (path, add->pathspec))
            return 1;
        const bgit_ignore_rule *rule = NULL;
        if (bgit_ignore_match (add->ignore, path, 1, &rule)) return 1;
        return 0;
    }
    if (!git_path_in_spec (path, add->pathspec)) return 0;
    const bgit_ignore_rule *rule = NULL;
    if (bgit_ignore_match (add->ignore, path, 0, &rule)) return 0;

    /* Already staged and unchanged? Then there is nothing to do. */
    for (size_t i = 0; i < add->state->n_index; i++) {
        if (strcmp (add->state->index[i].path, path) != 0) continue;
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", add->ctx->repo.work_tree, path);
        if (bgit_worktree_matches (&add->ctx->odb, full,
                                   &add->state->index[i], st))
            return 0;
        *add->changed = 1;
        if (add->dry_run) return 0;
        return git_stage_file (add->ctx, add->state, path, st) < 0 ? -1 : 0;
    }
    if (add->update_only) return 0;      /* -u leaves new files alone */
    *add->changed = 1;
    if (add->dry_run) return 0;
    return git_stage_file (add->ctx, add->state, path, st) < 0 ? -1 : 0;
}

static int
git_cmd_add (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git add [-A | --all] [-u | --update] [-n | --dry-run] "
                        "[-f | --force] [--] <pathspec>...";
    int all = 0, update_only = 0, dry_run = 0, force = 0, no_more = 0;
    const char *specs[32];
    int n_specs = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && (!strcmp (w, "-A") || !strcmp (w, "--all"))) all = 1;
        else if (!no_more && (!strcmp (w, "-u") || !strcmp (w, "--update"))) update_only = 1;
        else if (!no_more && (!strcmp (w, "-n") || !strcmp (w, "--dry-run"))) dry_run = 1;
        else if (!no_more && (!strcmp (w, "-f") || !strcmp (w, "--force"))) force = 1;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_specs < (int) (sizeof specs / sizeof *specs)) specs[n_specs++] = w;
        else return git_fatal ("too many paths");
    }
    if (!n_specs && !all && !update_only) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    bgit_ignore ignore;
    if (bgit_ignore_load (&ignore, &ctx->repo, &ctx->cfg) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot read the exclude files");
    }

    /* A named file that an ignore rule covers is refused without -f. */
    int status = 0, changed = 0;
    for (int i = 0; i < n_specs && !force; i++) {
        struct stat st;
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, specs[i]);
        if (lstat (full, &st) < 0 || S_ISDIR (st.st_mode)) continue;
        const bgit_ignore_rule *rule = NULL;
        if (!bgit_ignore_match (&ignore, specs[i], 0, &rule)) continue;
        fflush (stdout);
        fprintf (stderr, "The following paths are ignored by one of your "
                         ".gitignore files:\n%s\n", specs[i]);
        status = 1;
        break;
    }

    const char *everything[1] = { "" };
    const char *const *spec_list = n_specs ? specs : everything;
    int spec_count = n_specs ? n_specs : 1;
    for (int i = 0; i < spec_count && !status; i++) {
        struct git_add_ctx add = {
            .ctx = ctx, .state = &state, .ignore = &ignore,
            .pathspec = spec_list[i], .update_only = update_only,
            .dry_run = dry_run, .changed = &changed
        };
        if (bgit_worktree_walk (&ctx->repo, git_add_visit, &add) < 0) {
            status = GIT_EXIT_FATAL;
            break;
        }
        /* A file that has gone is staged as a removal, which is what
           `git add <dir>`, `-A` and `-u` all do. */
        for (size_t j = 0; j < state.n_index;) {
            if (!git_path_in_spec (state.index[j].path, spec_list[i])) { j++; continue; }
            char full[4096];
            snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree,
                      state.index[j].path);
            struct stat st;
            if (lstat (full, &st) == 0) { j++; continue; }
            changed = 1;
            if (dry_run) { j++; continue; }
            char *gone = strdup (state.index[j].path);
            if (!gone) { status = GIT_EXIT_FATAL; break; }
            bgit_index_remove_path (&state.index, &state.n_index, gone);
            free (gone);
        }
    }

    if (!status && changed && !dry_run &&
        git_index_store (ctx, state.index, state.n_index) < 0)
        status = GIT_EXIT_FATAL;
    bgit_ignore_release (&ignore);
    git_state_release (&state);
    return status;
}

/* ---- status ------------------------------------------------------------ */

static void
git_status_letters (const bgit_status_entry *entry, char *x, char *y, char blank)
{
    *x = entry->staged ? (char) entry->staged : blank;
    *y = entry->unstaged ? (char) entry->unstaged : blank;
}

static int
git_cmd_status (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git status [-s | --short | --porcelain[=<version>]] "
                        "[-b | --branch] [-u<mode> | --untracked-files=<mode>] "
                        "[--ignored]";
    int short_format = 0, porcelain = 0, version = 1, branch = 0;
    int untracked_all = 0, want_ignored = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-s") || !strcmp (w, "--short")) short_format = 1;
        else if (!strcmp (w, "--porcelain")) { porcelain = 1; version = 1; }
        else if (!strcmp (w, "--porcelain=v1")) { porcelain = 1; version = 1; }
        else if (!strcmp (w, "--porcelain=v2")) { porcelain = 1; version = 2; }
        else if (!strcmp (w, "-b") || !strcmp (w, "--branch")) branch = 1;
        else if (!strcmp (w, "--ignored")) want_ignored = 1;
        else if (!strcmp (w, "-uall") || !strcmp (w, "--untracked-files=all")) untracked_all = 1;
        else if (!strcmp (w, "-unormal") || !strcmp (w, "--untracked-files=normal")) untracked_all = 0;
        else if (!strcmp (w, "-uno") || !strcmp (w, "--untracked-files=no")) untracked_all = -1;
        else return git_usage (usage);
    }
    if (!short_format && !porcelain)
        return git_fatal ("this build's git status needs --short or "
                          "--porcelain; the long format is not written yet");
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    bgit_status_entry *entries = NULL;
    size_t n = 0;
    if (bgit_status (&ctx->repo, &ctx->odb, &ctx->cfg, state.index,
                     state.n_index, state.have_head ? state.head_tree : NULL,
                     untracked_all > 0, want_ignored, &entries, &n) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot read the working tree");
    }

    const char *branch_name = state.branch;
    if (branch_name && !strncmp (branch_name, "refs/heads/", 11))
        branch_name += 11;
    if (branch && version == 2 && porcelain) {
        printf ("# branch.oid %s\n", state.have_head ? state.head : "(initial)");
        printf ("# branch.head %s\n", branch_name ? branch_name : "(detached)");
    } else if (branch) {
        /* The short format's header, with git's "No commits yet" wording. */
        printf ("## %s%s\n", state.have_head ? "" : "No commits yet on ",
                branch_name ? branch_name : "HEAD (no branch)");
    }

    for (size_t i = 0; i < n; i++) {
        const bgit_status_entry *entry = &entries[i];
        if (entry->ignored) {
            if (version == 2 && porcelain) printf ("! %s\n", entry->path);
            else printf ("!! %s\n", entry->path);
            continue;
        }
        if (entry->untracked) {
            if (untracked_all < 0) continue;
            if (version == 2 && porcelain) printf ("? %s\n", entry->path);
            else printf ("?? %s\n", entry->path);
            continue;
        }
        char x, y;
        if (version == 2 && porcelain) {
            git_status_letters (entry, &x, &y, '.');
            printf ("1 %c%c N... %06o %06o %06o %s %s %s\n", x, y,
                    entry->head_mode, entry->index_mode,
                    entry->unstaged == 'D' ? 0 : (entry->worktree_mode
                        ? entry->worktree_mode : entry->index_mode),
                    entry->head_sha[0] ? entry->head_sha
                        : "0000000000000000000000000000000000000000",
                    entry->index_sha[0] ? entry->index_sha
                        : "0000000000000000000000000000000000000000",
                    entry->path);
        } else {
            git_status_letters (entry, &x, &y, ' ');
            printf ("%c%c %s\n", x, y, entry->path);
        }
    }
    bgit_status_free (entries, n);
    git_state_release (&state);
    return 0;
}

/* ---- commit ------------------------------------------------------------ */

static int
git_cmd_commit (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git commit -q (-m <message> | -F <file>) [-a] "
                        "[--amend] [--allow-empty]";
    const char *messages[16];
    int n_messages = 0;
    const char *message_file = NULL;
    int all = 0, amend = 0, allow_empty = 0, quiet = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-m") && p->next) {
            if (n_messages >= (int) (sizeof messages / sizeof *messages))
                return git_fatal ("too many messages");
            messages[n_messages++] = p->next->word->word;
            p = p->next;
        } else if (!strcmp (w, "-F") && p->next) { message_file = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-a") || !strcmp (w, "--all")) all = 1;
        else if (!strcmp (w, "--amend")) amend = 1;
        else if (!strcmp (w, "--allow-empty")) allow_empty = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "-am") && p->next) {
            all = 1;
            messages[n_messages++] = p->next->word->word;
            p = p->next;
        }
        else return git_usage (usage);
    }
    if (!n_messages && !message_file)
        return git_fatal ("this build's git commit needs -m or -F; it has no "
                          "editor support yet");
    if (!quiet)
        return git_fatal ("this build's git commit needs -q; the summary it "
                          "prints needs the diff machinery, which is not "
                          "written yet");
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    int status = 0;
    if (all) {
        /* -a stages every tracked file that changed or went away. */
        bgit_ignore ignore;
        if (bgit_ignore_load (&ignore, &ctx->repo, &ctx->cfg) < 0) {
            git_state_release (&state);
            return git_fatal ("cannot read the exclude files");
        }
        int changed = 0;
        struct git_add_ctx add = {
            .ctx = ctx, .state = &state, .ignore = &ignore, .pathspec = "",
            .update_only = 1, .dry_run = 0, .changed = &changed
        };
        if (bgit_worktree_walk (&ctx->repo, git_add_visit, &add) < 0)
            status = GIT_EXIT_FATAL;
        for (size_t j = 0; j < state.n_index && !status;) {
            char full[4096];
            snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree,
                      state.index[j].path);
            struct stat st;
            if (lstat (full, &st) == 0) { j++; continue; }
            char *gone = strdup (state.index[j].path);
            if (!gone) { status = GIT_EXIT_FATAL; break; }
            bgit_index_remove_path (&state.index, &state.n_index, gone);
            free (gone);
        }
        bgit_ignore_release (&ignore);
        if (!status && git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
    }
    if (status) { git_state_release (&state); return status; }

    char tree[41];
    if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                         state.n_index, tree) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    /* Nothing staged is not a commit, unless it was asked for. */
    if (!allow_empty && !amend && state.have_head &&
        strcmp (tree, state.head_tree) == 0) {
        git_state_release (&state);
        fflush (stdout);
        fprintf (stderr, "nothing to commit, working tree clean\n");
        return 1;
    }

    char parents[BGIT_MAX_PARENTS][41];
    int n_parents = 0;
    if (amend) {
        if (!state.have_head) {
            git_state_release (&state);
            return git_fatal ("You have nothing to amend.");
        }
        int n = bgit_commit_parents (&ctx->odb, state.head, parents,
                                     BGIT_MAX_PARENTS);
        if (n < 0) { git_state_release (&state); return GIT_EXIT_FATAL; }
        n_parents = n;
    } else if (state.have_head) {
        memcpy (parents[0], state.head, 41);
        n_parents = 1;
    }

    char author[1024], committer[1024];
    if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0 ||
        bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot determine the identity to use");
    }

    size_t cap = 4096, len = 0;
    char *body = malloc (cap);
    if (!body) { git_state_release (&state); return GIT_EXIT_FATAL; }
#define GIT_APPEND(...) do { \
    for (;;) { \
        int wrote = snprintf (body + len, cap - len, __VA_ARGS__); \
        if (wrote < 0) { free (body); git_state_release (&state); return GIT_EXIT_FATAL; } \
        if ((size_t) wrote < cap - len) { len += (size_t) wrote; break; } \
        cap *= 2; \
        char *grown = realloc (body, cap); \
        if (!grown) { free (body); git_state_release (&state); return GIT_EXIT_FATAL; } \
        body = grown; \
    } \
} while (0)
    GIT_APPEND ("tree %s\n", tree);
    for (int i = 0; i < n_parents; i++) GIT_APPEND ("parent %s\n", parents[i]);
    GIT_APPEND ("author %s\n", author);
    GIT_APPEND ("committer %s\n", committer);
    GIT_APPEND ("\n");
    char subject[1024] = "";
    if (message_file) {
        unsigned char *text = NULL;
        size_t text_len = 0;
        if (bgit_slurp_file (message_file, &text, &text_len) < 0) {
            free (body); git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        GIT_APPEND ("%.*s", (int) text_len, (const char *) text);
        const char *nl = memchr (text, '\n', text_len);
        size_t take = nl ? (size_t) (nl - (const char *) text) : text_len;
        if (take >= sizeof subject) take = sizeof subject - 1;
        memcpy (subject, text, take);
        subject[take] = '\0';
        free (text);
    } else {
        for (int i = 0; i < n_messages; i++)
            GIT_APPEND ("%s%s\n", i ? "\n" : "", messages[i]);
        snprintf (subject, sizeof subject, "%s", messages[0]);
    }
    if (len == 0 || body[len - 1] != '\n') GIT_APPEND ("\n");
#undef GIT_APPEND

    char commit[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                               (const unsigned char *) body, len, 1, commit);
    free (body);
    if (rc < 0) { git_state_release (&state); return GIT_EXIT_FATAL; }

    /* The reflog says how the commit was made, as git's does. */
    char reflog[1200];
    snprintf (reflog, sizeof reflog, "commit%s: %s",
              amend ? " (amend)" : state.have_head ? "" : " (initial)", subject);
    const char *ref = state.branch ? state.branch : "HEAD";
    const char *old = state.have_head ? state.head : "";
    if (bgit_ref_update (&ctx->repo, ref, commit, amend ? NULL : old, reflog) < 0)
        status = GIT_EXIT_FATAL;
    /* HEAD's own reflog follows the branch it names. */
    if (!status && state.branch)
        bgit_reflog_append (&ctx->repo, "HEAD", state.have_head ? state.head : NULL,
                            commit, reflog);
    git_state_release (&state);
    return status;
}

/* ---- check-ignore ------------------------------------------------------ */

/* Load the .gitignore of every directory above PATH, once each. */
static int
git_ignore_dirs_for (bgit_ignore *ignore, git_context *ctx, const char *path,
                     char (*loaded)[4096], size_t *n_loaded, size_t max)
{
    char prefix[4096] = "";
    const char *at = path;
    for (;;) {
        const char *slash = strchr (at, '/');
        if (!slash) break;
        size_t len = (size_t) (slash - path);
        if (len >= sizeof prefix) break;
        memcpy (prefix, path, len);
        prefix[len] = '\0';
        int seen = 0;
        for (size_t i = 0; i < *n_loaded && !seen; i++)
            if (!strcmp (loaded[i], prefix)) seen = 1;
        if (!seen && *n_loaded < max) {
            snprintf (loaded[*n_loaded], sizeof loaded[0], "%s", prefix);
            (*n_loaded)++;
            if (bgit_ignore_add_dir (ignore, &ctx->repo, prefix) < 0) return -1;
        }
        at = slash + 1;
    }
    return 0;
}

static int
git_cmd_check_ignore (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git check-ignore [-v] [--non-matching] [--no-index] "
                        "<pathname>...";
    int verbose = 0, non_matching = 0;
    const char *paths[64];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) verbose = 1;
        else if (!strcmp (w, "-n") || !strcmp (w, "--non-matching")) non_matching = 1;
        else if (!strcmp (w, "--no-index")) { /* we never consult the index */ }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (!n_paths) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    bgit_ignore ignore;
    if (bgit_ignore_load (&ignore, &ctx->repo, &ctx->cfg) < 0)
        return git_fatal ("cannot read the exclude files");
    static char loaded[64][4096];
    size_t n_loaded = 0;
    int any = 0, status = 0;
    for (int i = 0; i < n_paths; i++) {
        if (git_ignore_dirs_for (&ignore, ctx, paths[i], loaded, &n_loaded,
                                 sizeof loaded / sizeof loaded[0]) < 0) {
            status = GIT_EXIT_FATAL;
            break;
        }
        struct stat st;
        int is_dir = stat (paths[i], &st) == 0 && S_ISDIR (st.st_mode);
        const bgit_ignore_rule *rule = NULL;
        bgit_ignore_match (&ignore, paths[i], is_dir, &rule);
        /* git reports any rule that matched, a negation included, and its
           status says whether a pattern matched at all. */
        if (rule) any = 1;
        if (!rule && !non_matching) continue;
        if (verbose) {
            if (rule)
                printf ("%s:%ld:%s\t%s\n", rule->source, rule->line,
                        rule->text, paths[i]);
            else
                printf ("::\t%s\n", paths[i]);
        } else {
            printf ("%s\n", paths[i]);
        }
    }
    bgit_ignore_release (&ignore);
    if (status) return status;
    return any ? 0 : 1;
}

/* ---- config ------------------------------------------------------------ */

static int
git_cmd_config (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git config [--global | --local | --file <file>] [-z] "
                        "(--list | --get <key> | --get-all <key> | "
                        "--unset <key> | --add <key> <value> | <key> [<value>])";
    int list = 0, get = 0, get_all = 0, unset = 0, add = 0, zero = 0;
    int global = 0, local = 0;
    const char *file = NULL;
    const char *positional[2] = { NULL, NULL };
    int n = 0;

    (void) ctx;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--list") || !strcmp (w, "-l")) list = 1;
        else if (!strcmp (w, "--get")) get = 1;
        else if (!strcmp (w, "--get-all")) get_all = 1;
        else if (!strcmp (w, "--unset")) unset = 1;
        else if (!strcmp (w, "--add")) add = 1;
        else if (!strcmp (w, "-z") || !strcmp (w, "--null")) zero = 1;
        else if (!strcmp (w, "--global")) global = 1;
        else if (!strcmp (w, "--local")) local = 1;
        else if (!strcmp (w, "--file") && p->next) { file = p->next->word->word; p = p->next; }
        else if (!strncmp (w, "--file=", 7)) file = w + 7;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n < 2) positional[n++] = w;
        else return git_usage (usage);
    }
    if (list + get + get_all + unset + add > 1) return git_usage (usage);
    if (!list && !positional[0]) return git_usage (usage);

    bgit_repo repo;
    int have_repo = bgit_repo_discover (".", &repo) == 0;
    bgit_config cfg;
    if (bgit_config_load (&cfg, have_repo ? &repo : NULL, git_overrides,
                          git_n_overrides) < 0) {
        if (have_repo) bgit_repo_release (&repo);
        return git_fatal ("cannot read configuration");
    }

    int status = 0;
    int writing = add || unset || (!list && !get && !get_all && positional[1]);
    if (writing) {
        char path[4096];
        if (file) {
            snprintf (path, sizeof path, "%s", file);
        } else if (global) {
            if (bgit_config_global_file (path, sizeof path) < 0) {
                status = git_fatal ("$HOME not set");
                goto done;
            }
        } else {
            if (!have_repo) {
                status = git_fatal ("--local can only be used inside a git repository");
                goto done;
            }
            bgit_config_repo_file (&repo, path, sizeof path);
        }
        if (unset)
            status = bgit_config_get (&cfg, positional[0]) == NULL ? 5
                   : (bgit_config_unset_file (path, positional[0]) < 0
                      ? GIT_EXIT_FATAL : 0);
        else if (!positional[1])
            status = git_usage (usage);
        else
            status = bgit_config_set_file (path, positional[0], positional[1],
                                           add) < 0 ? GIT_EXIT_FATAL : 0;
        goto done;
    }

    if (list) {
        for (size_t i = 0; i < cfg.n; i++) {
            /* A key with no value is listed on its own, as git lists it. */
            const char *key = cfg.entries[i].key, *value = cfg.entries[i].value;
            if (zero)
                printf (value ? "%s\n%s%c" : "%s%.0s%c", key, value ? value : "", '\0');
            else
                printf (value ? "%s=%s\n" : "%s%.0s\n", key, value ? value : "");
        }
        goto done;
    }
    if (get_all) {
        const char **values = NULL;
        size_t count = bgit_config_get_all (&cfg, positional[0], &values);
        for (size_t i = 0; i < count; i++)
            printf (zero ? "%s%c" : "%s\n", values[i], '\0');
        free (values);
        status = count ? 0 : 1;
        goto done;
    }
    /* --get, or a bare key, both read the last value. */
    const char *value = bgit_config_get (&cfg, positional[0]);
    if (!value) { status = 1; goto done; }
    printf (zero ? "%s%c" : "%s\n", value, '\0');

done:
    bgit_config_release (&cfg);
    if (have_repo) bgit_repo_release (&repo);
    return status;
}

/* ---- dispatch ---------------------------------------------------------- */

typedef int (*git_command_fn) (git_context *, WORD_LIST *);

static const struct {
    const char *name;
    git_command_fn run;
} git_commands[] = {
    { "add",          git_cmd_add },
    { "cat-file",     git_cmd_cat_file },
    { "check-ignore", git_cmd_check_ignore },
    { "commit-tree",  git_cmd_commit_tree },
    { "commit",       git_cmd_commit },
    { "config",       git_cmd_config },
    { "for-each-ref", git_cmd_for_each_ref },
    { "hash-object",  git_cmd_hash_object },
    { "init",         git_cmd_init },
    { "ls-files",     git_cmd_ls_files },
    { "ls-tree",      git_cmd_ls_tree },
    { "read-tree",    git_cmd_read_tree },
    { "reflog",       git_cmd_reflog },
    { "rev-list",     git_cmd_rev_list },
    { "rev-parse",    git_cmd_rev_parse },
    { "show-ref",     git_cmd_show_ref },
    { "status",       git_cmd_status },
    { "symbolic-ref", git_cmd_symbolic_ref },
    { "update-index", git_cmd_update_index },
    { "update-ref",   git_cmd_update_ref },
    { "var",          git_cmd_var },
    { "write-tree",   git_cmd_write_tree },
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
        if (!strcmp (w, "-c") && list->next) {
            if (git_n_overrides < GIT_MAX_OVERRIDES)
                git_overrides[git_n_overrides++] = list->next->word->word;
            else
                return git_fatal ("too many -c options");
            list = list->next->next;
            continue;
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
    "    git config [--global|--local|--file F] [-z] (--list | --get KEY |",
    "               --get-all KEY | --unset KEY | --add KEY VALUE |",
    "               KEY [VALUE])",
    "    git update-index [--add] [--remove] [--cacheinfo M,OBJ,PATH]",
    "                     [--index-info] [--] [FILE...]",
    "    git ls-files [-s] [-z] [--] [FILE...]",
    "    git write-tree | git read-tree TREE-ISH",
    "    git commit-tree TREE [-p PARENT]... [-m MSG]... [-F FILE]",
    "    git ls-tree [-r] [-t] [-z] [--name-only] TREE-ISH",
    "    git rev-list [--count] [-n N] COMMIT...",
    "    git var GIT_AUTHOR_IDENT|GIT_COMMITTER_IDENT",
    "",
    "Revisions accept git's suffixes: ^ and ^<n> for a parent, ~<n> for n",
    "first-parent steps, ^{} and ^{<type>} to peel, and @{<n>} for a ref's",
    "nth previous value from its reflog.",
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
