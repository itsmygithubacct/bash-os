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
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

#include "_git_checkout.h"
#include "_git_config.h"
#include "_git_diff.h"
#include "_git_ignore.h"
#include "_git_index.h"
#include "_git_merge.h"
#include "_git_odb.h"
#include "_git_pack.h"
#include "_git_patch.h"
#include "_git_proto.h"
#include "_git_refs.h"
#include "_git_transport.h"
#include "_git_rename.h"
#include "_git_repo.h"
#include "_git_revision.h"
#include "_git_tree.h"
#include "_git_worktree.h"
#include "_git_lock.h"

/* The git version whose behaviour this matches, plus what we are. */
#define GIT_VERSION_STRING "git version 2.47.3.bash-os"

/* What the two ends of a connection call each other. */
#define GIT_AGENT_STRING "git/2.47.3.bash-os"

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

/* `-5` means the last five commits, so a count has to be told from a flag. */
static int
git_all_digits (const char *word)
{
    if (!*word) return 0;
    for (const char *p = word; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int
git_usage (const char *usage)
{
    fflush (stdout);
    fprintf (stderr, "usage: %s\n", usage);
    return GIT_EXIT_USAGE;
}

/* What git says when a name is neither a revision nor a path. */
static int
git_fatal_ambiguous (const char *name)
{
    fflush (stdout);
    fprintf (stderr, "fatal: ambiguous argument '%s': unknown revision or path "
                     "not in the working tree.\n", name);
    fprintf (stderr, "Use '--' to separate paths from revisions, like this:\n");
    fprintf (stderr, "'git <command> [<revision>...] -- [<file>...]'\n");
    return GIT_EXIT_FATAL;
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

/* One checkout of this repository: where it is, what it has checked out,
   and the administrative directory that ties the two together. */
struct git_worktree {
    char path[4096];       /* the working tree */
    char admin[4096];      /* the git directory for it; "" for the main one */
    char name[256];        /* what the admin directory is called */
    char head[41];
    char branch[4096];     /* the ref HEAD names, or "" when detached */
};

/* Every worktree of this repository, the main one first; written out
   beside git worktree, which is what makes the rest. */
static int git_worktrees (git_context *ctx, struct git_worktree **out,
                          size_t *n_out);
/* An absolute path for one that may not exist yet, beside it. */
static int git_absolute (const char *path, char *out, size_t outsz);

/* A file inside the git directory, such as MERGE_HEAD, and the things done
   with one. Written out beside git merge, which is what makes them. */
static int git_state_file (git_context *ctx, const char *name, char *out,
                           size_t outsz);
/* The commit id a state file holds, if that file is there at all. */
static int git_read_state_id (git_context *ctx, const char *name, char out[41]);
/* A stopped rebase keeps its state in .git/rebase-merge; status reads it. */
static int git_rebase_in_progress (git_context *ctx);
static int git_rebase_read (git_context *ctx, const char *name, char *out,
                            size_t outsz);
static int git_rebase_list (git_context *ctx, const char *name,
                            char lines[][1200], int max);
static int git_write_state_file (git_context *ctx, const char *name,
                                 const char *content);
static void git_remove_state_file (git_context *ctx, const char *name);

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

/* Read object names from stdin, as `git cat-file --batch` and
   `--batch-check` do, and report each one. */
static int
git_cat_file_batch (git_context *ctx, int with_content)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    clearerr (stdin);
    while ((got = getline (&line, &cap, stdin)) > 0) {
        while (got > 0 && (line[got - 1] == '\n' || line[got - 1] == '\r'))
            line[--got] = '\0';
        if (!got) continue;
        char id[41];
        enum bgit_type type;
        unsigned char *data = NULL;
        size_t len = 0;
        if (git_resolve (ctx, line, id, NULL) < 0 ||
            bgit_odb_read (&ctx->odb, id, &type, &data, &len) < 0) {
            printf ("%s missing\n", line);
            continue;
        }
        printf ("%s %s %zu\n", id, bgit_type_name (type), len);
        if (with_content) {
            fwrite (data, 1, len, stdout);
            putchar ('\n');
        }
        free (data);
    }
    free (line);
    return 0;
}

static int
git_cmd_cat_file (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git cat-file (-t | -s | -e | -p | <type>) <object> "
                        "| (--batch | --batch-check)";
    int want_type = 0, want_size = 0, want_exists = 0, pretty = 0;
    int batch = 0, batch_check = 0;
    const char *as_type = NULL, *name = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--batch")) batch = 1;
        else if (!strcmp (w, "--batch-check")) batch_check = 1;
        else if (!strcmp (w, "-t")) want_type = 1;
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
    if (batch || batch_check) {
        if (name || want_type || want_size || want_exists || pretty)
            return git_usage (usage);
        if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
        return git_cat_file_batch (ctx, batch);
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
        clearerr (stdin);
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
    /* Staging a path that was in dispute settles it: the conflict's stages
       go, and one stage-zero entry takes their place. */
    int unmerged = 0;
    for (size_t i = 0; i < *n; i++)
        if (!strcmp ((*entries)[i].path, entry->path) &&
            (((*entries)[i].flags >> 12) & 3))
            unmerged = 1;
    if (unmerged) {
        char *path = strdup (entry->path);
        if (!path) return -1;
        bgit_index_remove_path (entries, n, path);
        free (path);
    }
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
        clearerr (stdin);
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

/* Ids already named by --objects, so nothing is named twice. A history
   names an object once per tree that holds it, which is many times over,
   so the set is kept sorted and asked by halves. */
struct git_objects {
    char (*ids)[41];
    size_t n, cap;
};

struct git_objects_ctx { struct git_objects *seen; };

static int
git_objects_seen (struct git_objects *seen, const char *sha)
{
    size_t low = 0, high = seen->n;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = memcmp (seen->ids[mid], sha, 40);
        if (cmp < 0) low = mid + 1;
        else if (cmp > 0) high = mid;
        else return 1;
    }
    if (seen->n == seen->cap) {
        size_t next = seen->cap ? seen->cap * 2 : 128;
        char (*grown)[41] = realloc (seen->ids, next * sizeof *grown);
        if (!grown) return 1;          /* out of room: say it was seen */
        seen->ids = grown;
        seen->cap = next;
    }
    memmove (seen->ids[low + 1], seen->ids[low],
             (seen->n - low) * sizeof *seen->ids);
    memcpy (seen->ids[low], sha, 40);
    seen->ids[low][40] = '\0';
    seen->n++;
    return 0;
}

static int
git_objects_visit (void *context, const char *mode, const char *type,
                   const char *sha, const char *path)
{
    (void) mode;
    (void) type;
    struct git_objects_ctx *ctx = context;
    if (!git_objects_seen (ctx->seen, sha)) printf ("%s %s\n", sha, path);
    return 0;
}

static int
git_cmd_rev_list (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git rev-list [--count] [--objects] [-n <number> | "
                        "--max-count=<number>] <commit>... [^<commit>]";
    int count_only = 0, with_objects = 0;
    long limit = -1;
    const char *revs[16], *rev_words[16], *excludes[16], *exclude_words[16];
    int n_revs = 0, n_excludes = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--count")) count_only = 1;
        else if (!strcmp (w, "--objects")) with_objects = 1;
        else if (!strcmp (w, "--all")) revs[n_revs++] = "--all";
        else if (!strcmp (w, "-n") && p->next) { limit = atol (p->next->word->word); p = p->next; }
        else if (!strncmp (w, "--max-count=", 12)) limit = atol (w + 12);
        else if (w[0] == '-' && git_all_digits (w + 1)) limit = atol (w + 1);
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (w[0] == '^' && w[1]) {
            if (n_excludes >= (int) (sizeof excludes / sizeof *excludes))
                return git_fatal ("too many revisions");
            exclude_words[n_excludes] = w;
            excludes[n_excludes++] = w + 1;
        }
        else if (strstr (w, "...")) return git_fatal ("this build's git rev-list "
                                                      "has no A...B range yet");
        else if (strstr (w, "..")) {
            char *range = strdup (w);
            if (!range) return GIT_EXIT_FATAL;
            char *dots = strstr (range, "..");
            *dots = '\0';
            if (n_excludes >= (int) (sizeof excludes / sizeof *excludes) ||
                n_revs >= (int) (sizeof revs / sizeof *revs)) {
                free (range);
                return git_fatal ("too many revisions");
            }
            exclude_words[n_excludes] = w;
            excludes[n_excludes++] = *range ? range : "HEAD";
            rev_words[n_revs] = w;
            revs[n_revs++] = dots[2] ? dots + 2 : "HEAD";
        }
        else if (n_revs < (int) (sizeof revs / sizeof *revs)) {
            rev_words[n_revs] = w;
            revs[n_revs++] = w;
        }
        else return git_fatal ("too many revisions");
    }
    if (!n_revs) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    /* --all stands for every ref there is. */
    bgit_ref *all_refs = NULL;
    size_t n_all = 0;
    for (int i = 0; i < n_revs; i++) {
        if (strcmp (revs[i], "--all")) continue;
        if (bgit_refs_list (&ctx->repo, "refs/", &all_refs, &n_all) < 0)
            return git_fatal ("cannot read refs");
        revs[i] = NULL;
        for (size_t j = 0; j < n_all && n_revs < (int) (sizeof revs / sizeof *revs); j++) {
            rev_words[n_revs] = all_refs[j].name;
            revs[n_revs++] = all_refs[j].name;
        }
        break;
    }

    struct git_walk walk;
    memset (&walk, 0, sizeof walk);
    struct git_objects seen = {0};
    int status = 0;
    /* Mark everything the excluded tips reach, so the walk steps over it. */
    for (int i = 0; i < n_excludes; i++) {
        char id[41], commit[41];
        if (git_resolve (ctx, excludes[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            status = exclude_words[i][0] == '^'
                     ? git_fatal ("bad revision '%s'", exclude_words[i])
                     : git_fatal_ambiguous (exclude_words[i]);
            goto done;
        }
        if (git_walk_push (ctx, &walk, commit) < 0) { status = GIT_EXIT_FATAL; goto done; }
    }
    while (walk.n_pending) {
        char current[41];
        memcpy (current, walk.pending[--walk.n_pending].id, 41);
        char parents[BGIT_MAX_PARENTS][41];
        int count = bgit_commit_parents (&ctx->odb, current, parents,
                                         BGIT_MAX_PARENTS);
        for (int i = 0; i < count; i++)
            if (git_walk_push (ctx, &walk, parents[i]) < 0) {
                status = GIT_EXIT_FATAL;
                goto done;
            }
    }
    for (int i = 0; i < n_revs; i++) {
        if (!revs[i]) continue;
        char id[41], commit[41];
        if (git_resolve (ctx, revs[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            status = git_fatal_ambiguous (rev_words[i]);
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

        /* With --objects the tree each commit holds, and everything under
           it, is named too — each with the path it has there. */
        if (with_objects && !count_only) {
            char tree[41];
            if (bgit_commit_tree (&ctx->odb, current, tree) == 0) {
                struct git_objects_ctx seen_ctx = { &seen };
                if (!git_objects_seen (&seen, tree)) printf ("%s \n", tree);
                bgit_tree_walk (&ctx->odb, tree, "", 1, 1, git_objects_visit,
                                &seen_ctx);
            }
        }

        char parents[BGIT_MAX_PARENTS][41];
        int n = bgit_commit_parents (&ctx->odb, current, parents, BGIT_MAX_PARENTS);
        for (int i = 0; i < n; i++)
            if (git_walk_push (ctx, &walk, parents[i]) < 0) {
                status = GIT_EXIT_FATAL;
                goto done;
            }
    }
    if (count_only) printf ("%ld\n", emitted);
    free (seen.ids);
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
    if (entry->unmerged) {
        /* Which stages survive says what the two sides did. */
        switch (entry->unmerged) {
        case 2 | 4 | 8: *x = 'U'; *y = 'U'; return;   /* both modified */
        case 4 | 8:     *x = 'A'; *y = 'A'; return;   /* both added */
        case 2 | 4:     *x = 'U'; *y = 'D'; return;   /* deleted by them */
        case 2 | 8:     *x = 'D'; *y = 'U'; return;   /* deleted by us */
        case 4:         *x = 'A'; *y = 'U'; return;   /* added by us */
        case 8:         *x = 'U'; *y = 'A'; return;   /* added by them */
        default:        *x = 'D'; *y = 'D'; return;   /* both deleted */
        }
    }
    *x = entry->staged ? (char) entry->staged : blank;
    *y = entry->unstaged ? (char) entry->unstaged : blank;
}

/* What the long format calls an unmerged path. */
static const char *
git_unmerged_label (int stages)
{
    switch (stages) {
    case 2 | 4 | 8: return "both modified:";
    case 4 | 8:     return "both added:";
    case 2 | 4:     return "deleted by them:";
    case 2 | 8:     return "deleted by us:";
    case 4:         return "added by us:";
    case 8:         return "added by them:";
    default:        return "both deleted:";
    }
}

/* The words git puts in front of a path in the long format, in a column
   as wide as the longest of them. */
static const char *
git_status_label (int code)
{
    switch (code) {
    case 'A': return "new file:";
    case 'C': return "copied:";
    case 'D': return "deleted:";
    case 'M': return "modified:";
    case 'R': return "renamed:";
    case 'T': return "typechange:";
    default:  return "unknown:";
    }
}

/* `git status` with no format option: the report written for a person.
   Sections in git's order, each followed by a blank line, and the closing
   sentence that says what, if anything, is there to commit. */
static void
git_status_long (git_context *ctx, struct git_state *state,
                 const bgit_status_entry *entries, size_t n,
                 const char *branch_name, int untracked_mode, int want_ignored)
{
    char quoted[8192];
    /* A rebase in progress speaks for itself, in place of the branch. */
    int rebasing = git_rebase_in_progress (ctx);
    if (rebasing) ;
    else if (branch_name) printf ("On branch %s\n", branch_name);
    else if (state->have_head) {
        char abbreviated[41];
        git_abbrev (ctx, state->head, 7, abbreviated, sizeof abbreviated);
        printf ("HEAD detached at %s\n", abbreviated);
    } else printf ("Unborn HEAD\n");
    if (!state->have_head) printf ("\nNo commits yet\n\n");

    int staged = 0, unstaged = 0, deleted = 0, untracked = 0, ignored = 0;
    int unmerged = 0;
    for (size_t i = 0; i < n; i++) {
        if (entries[i].ignored) ignored = 1;
        else if (entries[i].untracked) untracked = 1;
        else if (entries[i].unmerged) unmerged = 1;
        else {
            if (entries[i].staged) staged = 1;
            if (entries[i].unstaged) unstaged = 1;
            if (entries[i].unstaged == 'D') deleted = 1;
        }
    }
    if (untracked_mode < 0) untracked = 0;

    /* Whatever is under way is said out loud, before anything else. */
    char in_progress[41];
    int merging = git_read_state_id (ctx, "MERGE_HEAD", in_progress);
    int picking = !merging && git_read_state_id (ctx, "CHERRY_PICK_HEAD", in_progress);
    int reverting = !merging && !picking &&
                    git_read_state_id (ctx, "REVERT_HEAD", in_progress);
    if (merging && unmerged) {
        printf ("You have unmerged paths.\n");
        printf ("  (fix conflicts and run \"git commit\")\n");
        printf ("  (use \"git merge --abort\" to abort the merge)\n\n");
    } else if (merging) {
        printf ("All conflicts fixed but you are still merging.\n");
        printf ("  (use \"git commit\" to conclude merge)\n\n");
    } else if (rebasing) {
        char onto[41] = "", head_name[4096] = "", abbreviated[41] = "";
        git_rebase_read (ctx, "onto", onto, sizeof onto);
        git_rebase_read (ctx, "head-name", head_name, sizeof head_name);
        if (*onto) git_abbrev (ctx, onto, 7, abbreviated, sizeof abbreviated);
        printf ("interactive rebase in progress; onto %s\n", abbreviated);

        /* The last two commands done and the next two to do, as git lists
           them, from the same two files. */
        char lines[64][1200];
        int n = git_rebase_list (ctx, "done", lines, 64);
        if (!n) printf ("No commands done.\n");
        else {
            printf ("Last command%s done (%d command%s done):\n",
                    n == 1 ? "" : "s", n, n == 1 ? "" : "s");
            for (int i = n > 2 ? n - 2 : 0; i < n; i++)
                printf ("   %s\n", lines[i]);
            if (n > 2)
                printf ("  (see more in file %s/rebase-merge/done)\n",
                        ctx->repo.git_dir);
        }
        n = git_rebase_list (ctx, "git-rebase-todo", lines, 64);
        if (!n) printf ("No commands remaining.\n");
        else {
            printf ("Next command%s to do (%d remaining command%s):\n",
                    n == 1 ? "" : "s", n, n == 1 ? "" : "s");
            for (int i = 0; i < 2 && i < n; i++) printf ("   %s\n", lines[i]);
            printf ("  (use \"git rebase --edit-todo\" to view and edit)\n");
        }
        const char *shown = head_name;
        if (!strncmp (shown, "refs/heads/", 11)) shown += 11;
        printf ("You are currently rebasing branch '%s' on '%s'.\n", shown,
                abbreviated);
        printf ("  (fix conflicts and then run \"git rebase --continue\")\n");
        printf ("  (use \"git rebase --skip\" to skip this patch)\n");
        printf ("  (use \"git rebase --abort\" to check out the original "
                "branch)\n\n");
    } else if (picking || reverting) {
        const char *verb = picking ? "cherry-pick" : "revert";
        char abbreviated[41];
        git_abbrev (ctx, in_progress, 7, abbreviated, sizeof abbreviated);
        printf ("You are currently %s commit %s.\n",
                picking ? "cherry-picking" : "reverting", abbreviated);
        if (unmerged)
            printf ("  (fix conflicts and run \"git %s --continue\")\n", verb);
        else
            printf ("  (all conflicts fixed: run \"git %s --continue\")\n", verb);
        printf ("  (use \"git %s --skip\" to skip this patch)\n", verb);
        printf ("  (use \"git %s --abort\" to cancel the %s operation)\n\n",
                verb, verb);
    }
    /* git's hints change when a commit is being made from somewhere other
       than the working tree: during a merge or a cherry-pick there is
       nothing simple to unstage to. */
    int from_commit = !merging && !picking;

    if (staged) {
        printf ("Changes to be committed:\n");
        if (from_commit)
            printf (state->have_head
                    ? "  (use \"git restore --staged <file>...\" to unstage)\n"
                    : "  (use \"git rm --cached <file>...\" to unstage)\n");
        for (size_t i = 0; i < n; i++) {
            if (entries[i].untracked || entries[i].ignored ||
                entries[i].unmerged || !entries[i].staged)
                continue;
            if (entries[i].renamed_from && *entries[i].renamed_from) {
                char from[8192];
                printf ("\t%-12s%s -> %s\n",
                        git_status_label (entries[i].staged),
                        bgit_quote_path (entries[i].renamed_from, from,
                                         sizeof from),
                        bgit_quote_path (entries[i].path, quoted,
                                         sizeof quoted));
                continue;
            }
            printf ("\t%-12s%s\n", git_status_label (entries[i].staged),
                    bgit_quote_path (entries[i].path, quoted, sizeof quoted));
        }
        printf ("\n");
    }
    if (unmerged) {
        printf ("Unmerged paths:\n");
        if (from_commit)
            printf (state->have_head
                    ? "  (use \"git restore --staged <file>...\" to unstage)\n"
                    : "  (use \"git rm --cached <file>...\" to unstage)\n");
        printf ("  (use \"git add <file>...\" to mark resolution)\n");
        for (size_t i = 0; i < n; i++) {
            if (!entries[i].unmerged) continue;
            printf ("\t%-17s%s\n", git_unmerged_label (entries[i].unmerged),
                    bgit_quote_path (entries[i].path, quoted, sizeof quoted));
        }
        printf ("\n");
    }
    if (unstaged) {
        printf ("Changes not staged for commit:\n");
        printf (deleted
                ? "  (use \"git add/rm <file>...\" to update what will be committed)\n"
                : "  (use \"git add <file>...\" to update what will be committed)\n");
        printf ("  (use \"git restore <file>...\" to discard changes in working directory)\n");
        for (size_t i = 0; i < n; i++) {
            if (entries[i].untracked || entries[i].ignored ||
                entries[i].unmerged || !entries[i].unstaged)
                continue;
            printf ("\t%-12s%s\n", git_status_label (entries[i].unstaged),
                    bgit_quote_path (entries[i].path, quoted, sizeof quoted));
        }
        printf ("\n");
    }
    if (untracked) {
        printf ("Untracked files:\n");
        printf ("  (use \"git add <file>...\" to include in what will be committed)\n");
        for (size_t i = 0; i < n; i++)
            if (entries[i].untracked)
                printf ("\t%s\n",
                        bgit_quote_path (entries[i].path, quoted, sizeof quoted));
        printf ("\n");
    }
    if (want_ignored && ignored) {
        printf ("Ignored files:\n");
        printf ("  (use \"git add -f <file>...\" to include in what will be committed)\n");
        for (size_t i = 0; i < n; i++)
            if (entries[i].ignored)
                printf ("\t%s\n",
                        bgit_quote_path (entries[i].path, quoted, sizeof quoted));
        printf ("\n");
    }

    if (staged) return;
    if (unstaged || unmerged)
        printf ("no changes added to commit "
                "(use \"git add\" and/or \"git commit -a\")\n");
    else if (untracked)
        printf ("nothing added to commit but untracked files present "
                "(use \"git add\" to track)\n");
    else if (!state->have_head)
        printf ("nothing to commit (create/copy files and use \"git add\" "
                "to track)\n");
    else if (untracked_mode < 0)
        printf ("nothing to commit (use -u to show untracked files)\n");
    else
        printf ("nothing to commit, working tree clean\n");
}

static int
git_cmd_status (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git status [-s | --short | --porcelain[=<version>]] "
                        "[-b | --branch] [-u<mode> | --untracked-files=<mode>] "
                        "[--ignored]";
    int short_format = 0, porcelain = 0, version = 1, branch = 0;
    int untracked_all = 0, want_ignored = 0, find_renames = 1;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-s") || !strcmp (w, "--short")) short_format = 1;
        else if (!strcmp (w, "--porcelain")) { porcelain = 1; version = 1; }
        else if (!strcmp (w, "--porcelain=v1")) { porcelain = 1; version = 1; }
        else if (!strcmp (w, "--porcelain=v2")) { porcelain = 1; version = 2; }
        else if (!strcmp (w, "-b") || !strcmp (w, "--branch")) branch = 1;
        else if (!strcmp (w, "--ignored")) want_ignored = 1;
        else if (!strcmp (w, "--no-renames")) find_renames = 0;
        else if (!strcmp (w, "-uall") || !strcmp (w, "--untracked-files=all")) untracked_all = 1;
        else if (!strcmp (w, "-unormal") || !strcmp (w, "--untracked-files=normal")) untracked_all = 0;
        else if (!strcmp (w, "-uno") || !strcmp (w, "--untracked-files=no")) untracked_all = -1;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    bgit_status_entry *entries = NULL;
    size_t n = 0;
    if (bgit_status (&ctx->repo, &ctx->odb, &ctx->cfg, state.index,
                     state.n_index, state.have_head ? state.head_tree : NULL,
                     untracked_all > 0, want_ignored, find_renames,
                     &entries, &n) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot read the working tree");
    }

    const char *branch_name = state.branch;
    if (branch_name && !strncmp (branch_name, "refs/heads/", 11))
        branch_name += 11;
    if (!short_format && !porcelain) {
        git_status_long (ctx, &state, entries, n, branch_name,
                         untracked_all, want_ignored);
        bgit_status_free (entries, n);
        git_state_release (&state);
        return 0;
    }
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
        if (entry->unmerged && version == 2 && porcelain) {
            /* An unmerged path has its own record, listing every stage. */
            git_status_letters (entry, &x, &y, '.');
            const char *zeros = "0000000000000000000000000000000000000000";
            printf ("u %c%c N... %06o %06o %06o %06o %s %s %s %s\n", x, y,
                    entry->head_mode, entry->index_mode, entry->their_mode,
                    entry->worktree_mode,
                    entry->head_sha[0] ? entry->head_sha : zeros,
                    entry->index_sha[0] ? entry->index_sha : zeros,
                    entry->their_sha[0] ? entry->their_sha : zeros,
                    entry->path);
            continue;
        }
        if (version == 2 && porcelain && entry->renamed_from &&
            *entry->renamed_from) {
            git_status_letters (entry, &x, &y, '.');
            printf ("2 %c%c N... %06o %06o %06o %s %s R%d %s\t%s\n", x, y,
                    entry->head_mode, entry->index_mode,
                    entry->worktree_mode ? entry->worktree_mode
                                         : entry->index_mode,
                    entry->head_sha, entry->index_sha,
                    entry->score * 100 / 60000, entry->path,
                    entry->renamed_from);
            continue;
        }
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
            if (entry->renamed_from && *entry->renamed_from)
                printf ("%c%c %s -> %s\n", x, y, entry->renamed_from,
                        entry->path);
            else printf ("%c%c %s\n", x, y, entry->path);
        }
    }
    bgit_status_free (entries, n);
    git_state_release (&state);
    return 0;
}

/* How a set of changed paths is shown: as a patch, a stat, or just names.
   commit, log, show and diff all take these, so the shape is declared before
   the first of them; the code is written out below, beside git diff. */
struct git_diff_format {
    int patch, stat, numstat, shortstat, summary, name_only, name_status;
    int no_patch;
    int no_renames;
    int context;
};

static void git_diff_format_init (struct git_diff_format *format);
static int git_diff_format_option (struct git_diff_format *format,
                                   const char *word);
static int git_diff_emit (git_context *ctx, FILE *out,
                          const struct git_diff_format *format,
                          const bgit_diff_entry *entries, size_t n,
                          int new_from_worktree, const char *line_prefix);
static void git_find_renames (git_context *ctx,
                              const struct git_diff_format *format,
                              bgit_diff_entry **entries, size_t *n,
                              int from_worktree);

/* ---- commit ------------------------------------------------------------ */

/* "Name <email> 1750000000 +0000" cut down to "Name <email>". */
static void
git_ident_who (const char *ident, char *out, size_t outsz)
{
    snprintf (out, outsz, "%s", ident);
    char *close = strrchr (out, '>');
    if (close) close[1] = '\0';
}

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
    if (!n_messages && !message_file) {
        /* Concluding a merge has a message ready in MERGE_MSG. */
        char merge_msg[4096];
        struct stat st;
        if (git_context_open (ctx) == 0 &&
            snprintf (merge_msg, sizeof merge_msg, "%s/MERGE_MSG",
                      ctx->repo.git_dir) < (int) sizeof merge_msg &&
            lstat (merge_msg, &st) == 0)
            message_file = strdup (merge_msg);
        else
            return git_fatal ("this build's git commit needs -m or -F; it has "
                              "no editor support yet");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    /* A merge that has not settled cannot be committed. */
    for (size_t i = 0; i < state.n_index; i++)
        if ((state.index[i].flags >> 12) & 3) {
            git_state_release (&state);
            fflush (stdout);
            fprintf (stderr, "error: Committing is not possible because you "
                             "have unmerged files.\n");
            fprintf (stderr, "fatal: Exiting because of an unresolved "
                             "conflict.\n");
            return 1;
        }

    /* A merge left in the tree is concluded by this commit. */
    char merging_with[41] = "";
    char merge_head_file[4096];
    if (snprintf (merge_head_file, sizeof merge_head_file, "%s/MERGE_HEAD",
                  ctx->repo.git_dir) < (int) sizeof merge_head_file) {
        struct stat st;
        unsigned char *content = NULL;
        size_t len = 0;
        if (lstat (merge_head_file, &st) == 0 &&
            bgit_slurp_file (merge_head_file, &content, &len) == 0) {
            if (len >= 40) memcpy (merging_with, content, 40);
            merging_with[len >= 40 ? 40 : 0] = '\0';
            free (content);
        }
    }

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
    if (!allow_empty && !amend && !*merging_with && state.have_head &&
        strcmp (tree, state.head_tree) == 0) {
        git_state_release (&state);
        fflush (stdout);
        fprintf (stderr, "nothing to commit, working tree clean\n");
        return 1;
    }

    char parents[BGIT_MAX_PARENTS][41];
    int n_parents = 0;
    if (*merging_with && state.have_head) {
        memcpy (parents[0], state.head, 41);
        memcpy (parents[1], merging_with, 41);
        n_parents = 2;
    } else if (amend) {
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
              *merging_with ? " (merge)" : amend ? " (amend)"
              : state.have_head ? "" : " (initial)", subject);
    const char *ref = state.branch ? state.branch : "HEAD";
    const char *old = state.have_head ? state.head : "";
    if (bgit_ref_update (&ctx->repo, ref, commit, amend ? NULL : old, reflog) < 0)
        status = GIT_EXIT_FATAL;
    /* HEAD's own reflog follows the branch it names. */
    if (!status && state.branch)
        bgit_reflog_append (&ctx->repo, "HEAD", state.have_head ? state.head : NULL,
                            commit, reflog);
    if (!status && *merging_with) {
        git_remove_state_file (ctx, "MERGE_HEAD");
        git_remove_state_file (ctx, "MERGE_MSG");
    }

    /* The summary git prints: where the commit landed, then what it did. */
    if (!status && !quiet) {
        char abbreviated[41];
        git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
        const char *branch = state.branch &&
                             !strncmp (state.branch, "refs/heads/", 11)
                             ? state.branch + 11 : NULL;
        printf ("[%s%s %s] %s\n", branch ? branch : "detached HEAD",
                state.have_head ? "" : " (root-commit)", abbreviated, subject);
        char author_who[1024], committer_who[1024];
        git_ident_who (author, author_who, sizeof author_who);
        git_ident_who (committer, committer_who, sizeof committer_who);
        if (strcmp (author_who, committer_who))
            printf (" Author: %s\n", author_who);

        /* A merge commit gets no stat, just as `git log` shows a merge no
           diff. */
        if (n_parents <= 1) {
            struct git_diff_format format;
            git_diff_format_init (&format);
            format.shortstat = 1;
            format.summary = 1;
            char parent_tree[41] = "";
            int have_parent = n_parents > 0 &&
                              bgit_commit_tree (&ctx->odb, parents[0],
                                                parent_tree) == 0;
            bgit_diff_entry *entries = NULL;
            size_t n_entries = 0;
            if (bgit_diff_trees (&ctx->odb, have_parent ? parent_tree : NULL,
                                 tree, &entries, &n_entries) == 0) {
                git_find_renames (ctx, &format, &entries, &n_entries, 0);
                git_diff_emit (ctx, stdout, &format, entries, n_entries, 0, "");
                bgit_diff_free (entries, n_entries);
            }
        }
    }
    git_state_release (&state);
    return status;
}

/* ---- log and diff ------------------------------------------------------ */

/* One commit, as its object records it. */
struct git_commit {
    char id[41];
    char tree[41];
    char parents[BGIT_MAX_PARENTS][41];
    int n_parents;
    char author_name[256], author_email[256], author_date[64];
    char committer_name[256], committer_email[256], committer_date[64];
    char *message;
};

static void
git_commit_release (struct git_commit *commit)
{
    free (commit->message);
    memset (commit, 0, sizeof *commit);
}

/* "Name <email> 1750000000 +0000" split into its parts. */
static void
git_split_ident (const char *line, size_t len, char *name, size_t name_sz,
                 char *email, size_t email_sz, char *date, size_t date_sz)
{
    const char *open = memchr (line, '<', len);
    const char *close = open ? memchr (open, '>', len - (size_t) (open - line)) : NULL;
    if (!open || !close) return;
    size_t name_len = (size_t) (open - line);
    while (name_len && line[name_len - 1] == ' ') name_len--;
    if (name_len >= name_sz) name_len = name_sz - 1;
    memcpy (name, line, name_len);
    name[name_len] = '\0';
    size_t email_len = (size_t) (close - open - 1);
    if (email_len >= email_sz) email_len = email_sz - 1;
    memcpy (email, open + 1, email_len);
    email[email_len] = '\0';
    const char *rest = close + 1;
    while (rest < line + len && *rest == ' ') rest++;
    size_t date_len = (size_t) (line + len - rest);
    if (date_len >= date_sz) date_len = date_sz - 1;
    memcpy (date, rest, date_len);
    date[date_len] = '\0';
}

static int
git_commit_read (git_context *ctx, const char *id, struct git_commit *commit)
{
    memset (commit, 0, sizeof *commit);
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (&ctx->odb, id, &type, &data, &len) < 0 ||
        type != BGIT_COMMIT) {
        free (data);
        return -1;
    }
    memcpy (commit->id, id, 41);
    const char *p = (const char *) data;
    const char *end = p + len;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) { p = nl ? nl + 1 : end; break; }
        if (line > 5 && !memcmp (p, "tree ", 5)) {
            memcpy (commit->tree, p + 5, 40);
            commit->tree[40] = '\0';
        } else if (line > 7 && !memcmp (p, "parent ", 7) &&
                   commit->n_parents < BGIT_MAX_PARENTS) {
            memcpy (commit->parents[commit->n_parents], p + 7, 40);
            commit->parents[commit->n_parents][40] = '\0';
            commit->n_parents++;
        } else if (line > 7 && !memcmp (p, "author ", 7)) {
            git_split_ident (p + 7, line - 7, commit->author_name,
                             sizeof commit->author_name, commit->author_email,
                             sizeof commit->author_email, commit->author_date,
                             sizeof commit->author_date);
        } else if (line > 10 && !memcmp (p, "committer ", 10)) {
            git_split_ident (p + 10, line - 10, commit->committer_name,
                             sizeof commit->committer_name,
                             commit->committer_email,
                             sizeof commit->committer_email,
                             commit->committer_date,
                             sizeof commit->committer_date);
        }
        if (!nl) { p = end; break; }
        p = nl + 1;
    }
    size_t message_len = (size_t) (end - p);
    commit->message = malloc (message_len + 1);
    if (!commit->message) { free (data); return -1; }
    memcpy (commit->message, p, message_len);
    commit->message[message_len] = '\0';
    free (data);
    return 0;
}

/* git's default date: "Sun Jun 15 12:26:40 2025 +0000", in the commit's own
   zone, which is what the raw "<seconds> <zone>" pair records. */
static void
git_format_date (const char *raw, int keep_raw, char *out, size_t outsz)
{
    long long seconds = 0;
    char zone[8] = "+0000";
    sscanf (raw, "%lld %7s", &seconds, zone);
    if (keep_raw) {
        snprintf (out, outsz, "%lld %s", seconds, zone);
        return;
    }
    int sign = zone[0] == '-' ? -1 : 1;
    int hours = (zone[1] - '0') * 10 + (zone[2] - '0');
    int minutes = (zone[3] - '0') * 10 + (zone[4] - '0');
    time_t shifted = (time_t) (seconds + sign * (hours * 3600 + minutes * 60));
    struct tm tm;
    if (!gmtime_r (&shifted, &tm)) { snprintf (out, outsz, "%s", raw); return; }
    static const char *const days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *const months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    snprintf (out, outsz, "%s %s %2d %02d:%02d:%02d %d %s",
              days[tm.tm_wday], months[tm.tm_mon], tm.tm_mday, tm.tm_hour,
              tm.tm_min, tm.tm_sec, tm.tm_year + 1900, zone);
}

/* The subject is the message's first line. */
static void
git_subject (const struct git_commit *commit, char *out, size_t outsz)
{
    const char *nl = strchr (commit->message, '\n');
    size_t len = nl ? (size_t) (nl - commit->message) : strlen (commit->message);
    if (len >= outsz) len = outsz - 1;
    memcpy (out, commit->message, len);
    out[len] = '\0';
}

static void
git_format_commit (git_context *ctx, FILE *out, const struct git_commit *commit,
                   const char *format, int raw_date)
{
    char buffer[4096];
    for (const char *p = format; *p; p++) {
        if (*p != '%') { fputc (*p, out); continue; }
        p++;
        switch (*p) {
        case 'H': fputs (commit->id, out); break;
        case 'h': {
            char abbreviated[41];
            git_abbrev (ctx, commit->id, 7, abbreviated, sizeof abbreviated);
            fputs (abbreviated, out);
            break;
        }
        case 'T': fputs (commit->tree, out); break;
        case 'P':
            for (int i = 0; i < commit->n_parents; i++)
                fprintf (out, "%s%s", i ? " " : "", commit->parents[i]);
            break;
        case 'p':
            for (int i = 0; i < commit->n_parents; i++) {
                char abbreviated[41];
                git_abbrev (ctx, commit->parents[i], 7, abbreviated,
                            sizeof abbreviated);
                fprintf (out, "%s%s", i ? " " : "", abbreviated);
            }
            break;
        case 'a':
            p++;
            if (*p == 'n') fputs (commit->author_name, out);
            else if (*p == 'e') fputs (commit->author_email, out);
            else if (*p == 'd') {
                git_format_date (commit->author_date, raw_date, buffer, sizeof buffer);
                fputs (buffer, out);
            } else if (*p == 't') {
                git_format_date (commit->author_date, 1, buffer, sizeof buffer);
                fputs (strtok (buffer, " "), out);
            }
            break;
        case 'c':
            p++;
            if (*p == 'n') fputs (commit->committer_name, out);
            else if (*p == 'e') fputs (commit->committer_email, out);
            else if (*p == 'd') {
                git_format_date (commit->committer_date, raw_date, buffer, sizeof buffer);
                fputs (buffer, out);
            } else if (*p == 't') {
                git_format_date (commit->committer_date, 1, buffer, sizeof buffer);
                fputs (strtok (buffer, " "), out);
            }
            break;
        case 's': {
            git_subject (commit, buffer, sizeof buffer);
            fputs (buffer, out);
            break;
        }
        case 'b': {
            /* The body is what follows the blank line after the subject. */
            const char *nl = strchr (commit->message, '\n');
            const char *body = nl ? nl + 1 : "";
            if (*body == '\n') body++;
            fputs (body, out);
            break;
        }
        case 'n': fputc ('\n', out); break;
        case '%': fputc ('%', out); break;
        case '\0': return;
        default: fputc ('%', out); fputc (*p, out); break;
        }
    }
    fputc ('\n', out);
}

/* The commits reachable from REVS but not from EXCLUDES, newest first by
   commit date — which is what `git log A..B` asks for. */
static int
git_collect_commits (git_context *ctx, const char *const *revs, int n_revs,
                     const char *const *excludes, int n_excludes,
                     int first_parent, long limit, char (**out)[41], size_t *n_out)
{
    struct git_walk walk;
    memset (&walk, 0, sizeof walk);
    char (*ordered)[41] = NULL;
    size_t n = 0, cap = 0;

    /* Walk what is excluded first, marking it seen; the main walk then
       steps over all of it, however the two histories meet. */
    for (int i = 0; i < n_excludes; i++) {
        char id[41], commit[41];
        if (git_resolve (ctx, excludes[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            free (walk.seen); free (walk.pending);
            return -1;
        }
        if (git_walk_push (ctx, &walk, commit) < 0) goto fail;
    }
    while (walk.n_pending) {
        char current[41];
        memcpy (current, walk.pending[--walk.n_pending].id, 41);
        char parents[BGIT_MAX_PARENTS][41];
        int count = bgit_commit_parents (&ctx->odb, current, parents,
                                         BGIT_MAX_PARENTS);
        for (int i = 0; i < count; i++)
            if (git_walk_push (ctx, &walk, parents[i]) < 0) goto fail;
    }

    for (int i = 0; i < n_revs; i++) {
        char id[41], commit[41];
        if (git_resolve (ctx, revs[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            free (walk.seen); free (walk.pending); free (ordered);
            return -1;
        }
        if (git_walk_push (ctx, &walk, commit) < 0) goto fail;
    }
    while (walk.n_pending) {
        size_t best = 0;
        for (size_t i = 1; i < walk.n_pending; i++)
            if (walk.pending[i].date > walk.pending[best].date) best = i;
        char current[41];
        memcpy (current, walk.pending[best].id, 41);
        memmove (walk.pending + best, walk.pending + best + 1,
                 (walk.n_pending - best - 1) * sizeof *walk.pending);
        walk.n_pending--;

        if (limit >= 0 && (long) n >= limit) break;
        if (n == cap) {
            size_t next = cap ? cap * 2 : 32;
            char (*grown)[41] = realloc (ordered, next * sizeof *grown);
            if (!grown) goto fail;
            ordered = grown;
            cap = next;
        }
        memcpy (ordered[n++], current, 41);

        char parents[BGIT_MAX_PARENTS][41];
        int count = bgit_commit_parents (&ctx->odb, current, parents,
                                         BGIT_MAX_PARENTS);
        if (first_parent && count > 1) count = 1;
        for (int i = 0; i < count; i++)
            if (git_walk_push (ctx, &walk, parents[i]) < 0) goto fail;
    }
    free (walk.seen);
    free (walk.pending);
    *out = ordered;
    *n_out = n;
    return 0;
fail:
    free (walk.seen);
    free (walk.pending);
    free (ordered);
    return -1;
}

/* A deletion and an addition of the same content are one rename. The list
   is the caller's, so the pairing happens where the list was built and not
   where it is printed. Renames are looked for in what has been recorded:
   comparing against the working tree has nothing to compare ids with. */
static void
git_find_renames (git_context *ctx, const struct git_diff_format *format,
                  bgit_diff_entry **entries, size_t *n, int from_worktree)
{
    if (format->no_renames || from_worktree) return;
    bgit_detect_renames (&ctx->odb, entries, n);
}

/* Was any form of diff asked for? */
static int
git_diff_wanted (const struct git_diff_format *format)
{
    return format->patch || format->stat || format->numstat ||
           format->shortstat || format->summary || format->name_only ||
           format->name_status;
}

/* What a commit changed, against its first parent — or against nothing, for
   a root commit. git shows no diff for a merge unless asked, so nor does
   this. */
static int
git_commit_changes (git_context *ctx, const struct git_commit *commit,
                    const char *const *paths, int n_paths,
                    bgit_diff_entry **out, size_t *n_out)
{
    char parent_tree[41] = "";
    if (commit->n_parents &&
        bgit_commit_tree (&ctx->odb, commit->parents[0], parent_tree) < 0)
        return -1;
    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    if (bgit_diff_trees (&ctx->odb, commit->n_parents ? parent_tree : NULL,
                         commit->tree, &entries, &n) < 0)
        return -1;
    if (n_paths) {
        size_t kept = 0;
        for (size_t i = 0; i < n; i++) {
            int matched = 0;
            for (int j = 0; j < n_paths && !matched; j++)
                if (git_path_in_spec (entries[i].path, paths[j])) matched = 1;
            if (matched) entries[kept++] = entries[i];
            else { free (entries[i].path); free (entries[i].from); }
        }
        n = kept;
    }
    *out = entries;
    *n_out = n;
    return 0;
}

static int
git_commit_diff (git_context *ctx, FILE *out, const struct git_commit *commit,
                 const struct git_diff_format *format,
                 const char *const *paths, int n_paths)
{
    if (commit->n_parents > 1) return 0;
    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    if (git_commit_changes (ctx, commit, paths, n_paths, &entries, &n) < 0)
        return -1;
    git_find_renames (ctx, format, &entries, &n, 0);
    int rc = git_diff_emit (ctx, out, format, entries, n, 0, "");
    bgit_diff_free (entries, n);
    return rc;
}

/* Did this commit change anything the pathspec names? That is what decides
   whether `git log -- <path>` shows it. A merge follows its first parent
   here, which is all this build can make. */
static int
git_commit_touches (git_context *ctx, const struct git_commit *commit,
                    const char *const *paths, int n_paths)
{
    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    if (git_commit_changes (ctx, commit, paths, n_paths, &entries, &n) < 0)
        return 1;
    bgit_diff_free (entries, n);
    return n > 0;
}

/* One commit as `git log` and `git show` print it: the header, the message
   indented by four spaces, then whatever diff was asked for. */
static void
git_print_commit (git_context *ctx, FILE *out, const struct git_commit *commit,
                  int oneline, const char *format, int raw_date,
                  const struct git_diff_format *diff,
                  const char *const *paths, int n_paths)
{
    if (oneline) {
        char abbreviated[41], subject[4096];
        git_abbrev (ctx, commit->id, 7, abbreviated, sizeof abbreviated);
        git_subject (commit, subject, sizeof subject);
        fprintf (out, "%s %s\n", abbreviated, subject);
    } else if (format) {
        git_format_commit (ctx, out, commit, format, raw_date);
    } else {
        char date[128];
        git_format_date (commit->author_date, raw_date, date, sizeof date);
        fprintf (out, "commit %s\n", commit->id);
        if (commit->n_parents > 1) {
            fprintf (out, "Merge:");
            for (int j = 0; j < commit->n_parents; j++) {
                char abbreviated[41];
                git_abbrev (ctx, commit->parents[j], 7, abbreviated,
                            sizeof abbreviated);
                fprintf (out, " %s", abbreviated);
            }
            fputc ('\n', out);
        }
        fprintf (out, "Author: %s <%s>\n", commit->author_name,
                 commit->author_email);
        fprintf (out, "Date:   %s\n\n", date);
        /* Every line is indented by four spaces, a blank one included. */
        const char *line = commit->message;
        while (*line) {
            const char *nl = strchr (line, '\n');
            size_t len = nl ? (size_t) (nl - line) : strlen (line);
            if (!nl && !len) break;
            fprintf (out, "    %.*s\n", (int) len, line);
            if (!nl) break;
            line = nl + 1;
        }
    }
    if (diff && git_diff_wanted (diff)) {
        /* The long format keeps a blank line between message and diff; the
           one-line format runs straight into it. */
        if (!oneline) fputc ('\n', out);
        git_commit_diff (ctx, out, commit, diff, paths, n_paths);
    }
}

/* One commit's block, with git's graph column down its left: the first line
   carries the commit itself, every other line the strand it sits on. This
   build draws a straight history, which is all it can make. */
static void
git_print_graph (const char *block)
{
    int first = 1;
    for (const char *line = block; *line;) {
        const char *nl = strchr (line, '\n');
        size_t len = nl ? (size_t) (nl - line) : strlen (line);
        printf ("%s%.*s\n", first ? "* " : "| ", (int) len, line);
        first = 0;
        if (!nl) break;
        line = nl + 1;
    }
}

static int
git_cmd_log (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git log [--oneline] [--format=<format>] "
                        "[-p] [--stat] [--graph] [-n <number>] [--reverse] "
                        "[--first-parent] [--date=raw] [<revision>...]";
    const char *format = NULL;
    int oneline = 0, reverse = 0, first_parent = 0, raw_date = 0, graph = 0;
    long limit = -1;
    const char *revs[16], *rev_words[16], *excludes[16], *exclude_words[16];
    const char *paths[32];
    int n_revs = 0, n_excludes = 0, n_paths = 0, no_more = 0;
    struct git_diff_format diff;
    git_diff_format_init (&diff);

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (no_more) {
            if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
            else return git_fatal ("too many paths");
            continue;
        }
        if (!strcmp (w, "--oneline")) oneline = 1;
        else if (git_diff_format_option (&diff, w)) ;
        else if (!strncmp (w, "--format=", 9)) format = w + 9;
        else if (!strncmp (w, "--pretty=", 9)) format = w + 9;
        else if (!strcmp (w, "--reverse")) reverse = 1;
        else if (!strcmp (w, "--first-parent")) first_parent = 1;
        else if (!strcmp (w, "--date=raw")) raw_date = 1;
        else if (!strcmp (w, "-n") && p->next) { limit = atol (p->next->word->word); p = p->next; }
        else if (!strncmp (w, "--max-count=", 12)) limit = atol (w + 12);
        else if (w[0] == '-' && git_all_digits (w + 1)) limit = atol (w + 1);
        else if (!strcmp (w, "--all")) {
            rev_words[n_revs] = w;
            revs[n_revs++] = "--all";
        }
        else if (!strcmp (w, "--graph")) graph = 1;
        else if (w[0] == '^' && w[1]) {
            if (n_excludes >= (int) (sizeof excludes / sizeof *excludes))
                return git_fatal ("too many revisions");
            exclude_words[n_excludes] = w;
            excludes[n_excludes++] = w + 1;
        }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (strstr (w, "...")) {
            return git_fatal ("this build's git log has no A...B range yet");
        }
        else if (strstr (w, "..")) {
            /* A..B: what B has and A does not. Either side may be left out,
               and then means HEAD. */
            char *range = strdup (w);
            if (!range) return GIT_EXIT_FATAL;
            char *dots = strstr (range, "..");
            *dots = '\0';
            const char *left = *range ? range : "HEAD";
            const char *right = dots[2] ? dots + 2 : "HEAD";
            if (n_excludes >= (int) (sizeof excludes / sizeof *excludes) ||
                n_revs >= (int) (sizeof revs / sizeof *revs)) {
                free (range);
                return git_fatal ("too many revisions");
            }
            /* Both halves point into `range`, which lives as long as the
               command does: the child exits when it is done. A complaint
               about either half names the range as it was written. */
            exclude_words[n_excludes] = w;
            excludes[n_excludes++] = left;
            rev_words[n_revs] = w;
            revs[n_revs++] = right;
        }
        else if (n_revs < (int) (sizeof revs / sizeof *revs)) {
            rev_words[n_revs] = w;
            revs[n_revs++] = w;
        }
        else return git_fatal ("too many revisions");
    }
    if (format && !strcmp (format, "oneline")) { oneline = 1; format = NULL; }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    /* --all means every ref; otherwise HEAD, unless revisions were named. */
    const char *starts[64], *start_words[64];
    int n_starts = 0;
    int want_all = 0;
    for (int i = 0; i < n_revs; i++)
        if (!strcmp (revs[i], "--all")) want_all = 1;
    bgit_ref *refs = NULL;
    size_t n_refs = 0;
    if (want_all) {
        if (bgit_refs_list (&ctx->repo, "refs/", &refs, &n_refs) < 0)
            return git_fatal ("cannot read refs");
        for (size_t i = 0; i < n_refs && n_starts < (int) (sizeof starts / sizeof *starts); i++) {
            start_words[n_starts] = refs[i].name;
            starts[n_starts++] = refs[i].name;
        }
    }
    for (int i = 0; i < n_revs; i++)
        if (strcmp (revs[i], "--all") && n_starts < (int) (sizeof starts / sizeof *starts)) {
            start_words[n_starts] = rev_words[i];
            starts[n_starts++] = revs[i];
        }
    if (!n_starts) {
        start_words[n_starts] = "HEAD";
        starts[n_starts++] = "HEAD";
    }

    char (*ordered)[41] = NULL;
    size_t n = 0;
    /* With a pathspec the limit counts what is shown, not what is walked. */
    int rc = git_collect_commits (ctx, starts, n_starts, excludes, n_excludes,
                                  first_parent, n_paths ? -1 : limit,
                                  &ordered, &n);
    bgit_refs_free (refs, n_refs);
    if (rc < 0) {
        /* Name what could not be resolved, in the words it was written in:
           a range is reported whole, as git reports it. */
        char id[41];
        for (int i = 0; i < n_excludes; i++)
            if (git_resolve (ctx, excludes[i], id, NULL) < 0)
                return exclude_words[i][0] == '^'
                       ? git_fatal ("bad revision '%s'", exclude_words[i])
                       : git_fatal_ambiguous (exclude_words[i]);
        for (int i = 0; i < n_starts; i++)
            if (strcmp (starts[i], "HEAD") && git_resolve (ctx, starts[i], id, NULL) < 0)
                return git_fatal_ambiguous (start_words[i]);
        char *branch = NULL;
        if (bgit_symref_read (&ctx->repo, "HEAD", &branch) == 0 && branch) {
            const char *name = !strncmp (branch, "refs/heads/", 11) ? branch + 11
                                                                    : branch;
            int fatal = git_fatal ("your current branch '%s' does not have any "
                                   "commits yet", name);
            free (branch);
            return fatal;
        }
        return git_fatal_ambiguous ("HEAD");
    }

    long shown = 0;
    int first = 1;
    for (size_t k = 0; k < n; k++) {
        size_t i = reverse ? n - 1 - k : k;
        struct git_commit commit;
        if (git_commit_read (ctx, ordered[i], &commit) < 0) continue;
        if (n_paths && !git_commit_touches (ctx, &commit, paths, n_paths)) {
            git_commit_release (&commit);
            continue;
        }
        if (limit >= 0 && shown >= limit) { git_commit_release (&commit); break; }
        if (graph && commit.n_parents > 1) {
            git_commit_release (&commit);
            free (ordered);
            return git_fatal ("this build's git log --graph draws a straight "
                              "history only; this one has a merge");
        }
        if (!oneline && !format && !first) printf (graph ? "| \n" : "\n");
        if (graph) {
            /* Capture the block, then set it beside the graph column. */
            char *block = NULL;
            size_t size = 0;
            FILE *capture = open_memstream (&block, &size);
            if (!capture) { git_commit_release (&commit); free (ordered); return GIT_EXIT_FATAL; }
            git_print_commit (ctx, capture, &commit, oneline, format, raw_date,
                              &diff, paths, n_paths);
            fclose (capture);
            git_print_graph (block);
            free (block);
        } else
            git_print_commit (ctx, stdout, &commit, oneline, format, raw_date,
                              &diff, paths, n_paths);
        first = 0;
        shown++;
        git_commit_release (&commit);
    }
    free (ordered);
    return 0;
}

static void
git_diff_format_init (struct git_diff_format *format)
{
    memset (format, 0, sizeof *format);
    format->context = 3;
}

/* Take W if it selects a format, and say whether it did. */
static int
git_diff_format_option (struct git_diff_format *format, const char *w)
{
    if (!strcmp (w, "-p") || !strcmp (w, "-u") || !strcmp (w, "--patch"))
        format->patch = 1;
    else if (!strcmp (w, "--stat")) format->stat = 1;
    else if (!strcmp (w, "--numstat")) format->numstat = 1;
    else if (!strcmp (w, "--shortstat")) format->shortstat = 1;
    else if (!strcmp (w, "--summary")) format->summary = 1;
    else if (!strcmp (w, "--name-only")) format->name_only = 1;
    else if (!strcmp (w, "--name-status")) format->name_status = 1;
    else if (!strcmp (w, "-s") || !strcmp (w, "--no-patch")) format->no_patch = 1;
    else if (!strncmp (w, "-U", 2) && w[2] >= '0' && w[2] <= '9')
        format->context = atoi (w + 2);
    else if (!strncmp (w, "--unified=", 10)) format->context = atoi (w + 10);
    else if (!strcmp (w, "--no-renames")) format->no_renames = 1;
    else if (!strcmp (w, "-M") || !strcmp (w, "--find-renames"))
        format->no_renames = 0;
    else if (!strcmp (w, "--no-color") || !strcmp (w, "--no-ext-diff") ||
             !strcmp (w, "--no-textconv")) {
        /* Already how this build behaves. */
    } else return 0;
    return 1;
}

/* Show a list of changed paths in whichever forms were asked for. The new
   side comes from the working tree when NEW_FROM_WORKTREE, so `git diff`
   reads files rather than blobs that were never written. */
static int
git_diff_emit (git_context *ctx, FILE *out,
               const struct git_diff_format *format,
               const bgit_diff_entry *entries, size_t n, int new_from_worktree,
               const char *line_prefix)
{
    bgit_patch_options options;
    bgit_patch_options_init (&options);
    options.context = format->context;
    options.new_from_worktree = new_from_worktree;
    options.line_prefix = line_prefix ? line_prefix : "";

    int named = format->name_only || format->name_status;
    int stats = format->stat || format->numstat || format->shortstat;
    int patch = format->patch || (!named && !stats && !format->summary &&
                                  !format->no_patch);

    if (named) {
        for (size_t i = 0; i < n; i++) {
            char quoted[8192];
            const char *name = bgit_quote_path (entries[i].path, quoted,
                                                sizeof quoted);
            if (format->name_status && entries[i].status == 'R') {
                char from_quoted[8192];
                fprintf (out, "%sR%d\t%s\t%s\n", options.line_prefix,
                         entries[i].score * 100 / 60000,
                         bgit_quote_path (entries[i].from, from_quoted,
                                          sizeof from_quoted), name);
            } else if (format->name_status)
                fprintf (out, "%s%c\t%s\n", options.line_prefix,
                         entries[i].status, name);
            else fprintf (out, "%s%s\n", options.line_prefix, name);
        }
    }
    if (stats || format->summary) {
        bgit_diffstat_entry *counted = NULL;
        if (stats) {
            if (bgit_diffstat (&ctx->odb, &ctx->repo, entries, n, &options,
                               &counted) < 0)
                return -1;
            if (format->numstat) bgit_numstat_write (out, counted, n);
            if (format->stat) bgit_diffstat_write (out, counted, n,
                                                   options.line_prefix);
            if (format->shortstat) bgit_shortstat_write (out, counted, n,
                                                         options.line_prefix);
            free (counted);
        }
        if (format->summary)
            bgit_diff_summary (out, entries, n, options.line_prefix);
    }
    if (patch &&
        bgit_patch_write (out, &ctx->odb, &ctx->repo, entries, n, &options) < 0)
        return -1;
    return 0;
}

static int
git_cmd_diff (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git diff [-p] [--stat] [--name-only | --name-status] "
                        "[--cached] [<commit> [<commit>]] [-- <path>...]";
    struct git_diff_format format;
    git_diff_format_init (&format);
    int cached = 0, no_more = 0;
    const char *revs[2] = { NULL, NULL };
    int n_revs = 0;
    const char *paths[32];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && (!strcmp (w, "--cached") || !strcmp (w, "--staged"))) cached = 1;
        else if (!no_more && git_diff_format_option (&format, w)) ;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (!no_more && n_revs < 2) revs[n_revs++] = w;
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    int rc = 0;
    if (n_revs == 2) {
        char a[41], b[41], tree_a[41], tree_b[41];
        if (git_resolve (ctx, revs[0], a, NULL) < 0 ||
            git_resolve (ctx, revs[1], b, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, a, BGIT_TREE, tree_a) < 0 ||
            bgit_peel_to_type (&ctx->odb, b, BGIT_TREE, tree_b) < 0) {
            git_state_release (&state);
            return git_fatal ("bad revision");
        }
        rc = bgit_diff_trees (&ctx->odb, tree_a, tree_b, &entries, &n);
    } else if (cached) {
        const char *base = n_revs ? revs[0] : (state.have_head ? "HEAD" : NULL);
        char tree[41] = "";
        if (base) {
            char id[41];
            if (git_resolve (ctx, base, id, NULL) < 0 ||
                bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0) {
                git_state_release (&state);
                return git_fatal ("bad revision");
            }
        }
        rc = bgit_diff_tree_index (&ctx->odb, base ? tree : NULL, state.index,
                                   state.n_index, &entries, &n);
    } else if (n_revs == 1) {
        /* A commit against the working tree: through the index, then on. */
        char id[41], tree[41];
        if (git_resolve (ctx, revs[0], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0) {
            git_state_release (&state);
            return git_fatal ("bad revision");
        }
        bgit_index_entry *files = NULL, *working = NULL;
        size_t n_files = 0, n_working = 0;
        if (bgit_read_tree (&ctx->odb, tree, &files, &n_files) < 0 ||
            bgit_worktree_entries (&ctx->repo, &ctx->odb, NULL, state.index,
                                   state.n_index, &working, &n_working) < 0) {
            bgit_index_free_entries (files, n_files);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        rc = bgit_diff_entries (files, n_files, working, n_working, &entries, &n);
        bgit_index_free_entries (files, n_files);
        bgit_index_free_entries (working, n_working);
    } else {
        rc = bgit_diff_index_worktree (&ctx->repo, &ctx->odb, state.index,
                                       state.n_index, &entries, &n);
    }
    if (rc < 0) {
        git_state_release (&state);
        return git_fatal ("cannot compare");
    }

    if (n_paths) {
        size_t kept = 0;
        for (size_t i = 0; i < n; i++) {
            int matched = 0;
            for (int j = 0; j < n_paths && !matched; j++)
                if (git_path_in_spec (entries[i].path, paths[j])) matched = 1;
            if (matched) entries[kept++] = entries[i];
            else { free (entries[i].path); free (entries[i].from); }
        }
        n = kept;
    }
    /* Only a comparison that ends at the working tree reads files. */
    int from_worktree = !cached && n_revs < 2;
    git_find_renames (ctx, &format, &entries, &n, from_worktree);
    int status = git_diff_emit (ctx, stdout, &format, entries, n,
                                from_worktree, "") < 0 ? GIT_EXIT_FATAL : 0;
    bgit_diff_free (entries, n);
    git_state_release (&state);
    return status;
}

/* ---- show -------------------------------------------------------------- */

/* `git show <tree>` lists the names in it, a subtree marked with a slash. */
static int
git_show_tree_entry (void *context, const char *mode, const char *type,
                     const char *sha, const char *path)
{
    (void) context;
    (void) mode;
    (void) sha;
    printf ("%s%s\n", path, !strcmp (type, "tree") ? "/" : "");
    return 0;
}

/* The header `git show` prints for an annotated tag, then its message.
   TAGGED comes back holding the id of the object the tag points at. */
static void
git_show_tag (const unsigned char *data, size_t len, char *tagged, int raw_date)
{
    char name[256] = "", tagger[512] = "", date[128] = "";
    const char *body = (const char *) data;
    size_t left = len;
    tagged[0] = '\0';
    while (left) {
        const char *nl = memchr (body, '\n', left);
        size_t line_len = nl ? (size_t) (nl - body) : left;
        if (!line_len) { body = nl ? nl + 1 : body + left; left -= line_len + 1; break; }
        if (!strncmp (body, "object ", 7) && line_len >= 47)
            snprintf (tagged, 41, "%.40s", body + 7);
        else if (!strncmp (body, "tag ", 4))
            snprintf (name, sizeof name, "%.*s", (int) line_len - 4, body + 4);
        else if (!strncmp (body, "tagger ", 7)) {
            char who[256] = "", email[256] = "";
            git_split_ident (body + 7, line_len - 7, who, sizeof who,
                             email, sizeof email, date, sizeof date);
            snprintf (tagger, sizeof tagger, "%s <%s>", who, email);
        }
        if (!nl) { left = 0; break; }
        left -= line_len + 1;
        body = nl + 1;
    }

    printf ("tag %s\n", name);
    if (*tagger) {
        char shown[128];
        git_format_date (date, raw_date, shown, sizeof shown);
        printf ("Tagger: %s\n", tagger);
        printf ("Date:   %s\n", shown);
    }
    printf ("\n");
    fwrite (body, 1, left, stdout);
    printf ("\n");
}

static int
git_cmd_show (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git show [-p | -s | --stat] [--oneline] "
                        "[--format=<format>] [<object>...]";
    struct git_diff_format diff;
    git_diff_format_init (&diff);
    const char *format = NULL;
    int oneline = 0, raw_date = 0;
    const char *objects[16];
    int n_objects = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--oneline")) oneline = 1;
        else if (!strncmp (w, "--format=", 9)) format = w + 9;
        else if (!strncmp (w, "--pretty=", 9)) format = w + 9;
        else if (!strcmp (w, "--date=raw")) raw_date = 1;
        else if (git_diff_format_option (&diff, w)) ;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_objects < (int) (sizeof objects / sizeof *objects))
            objects[n_objects++] = w;
        else return git_fatal ("too many objects");
    }
    if (format && !strcmp (format, "oneline")) { oneline = 1; format = NULL; }
    if (!n_objects) objects[n_objects++] = "HEAD";
    /* A patch is what show is for, unless another form was named. */
    if (!git_diff_wanted (&diff) && !diff.no_patch) diff.patch = 1;
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    for (int i = 0; i < n_objects; i++) {
        char id[41];
        if (git_resolve (ctx, objects[i], id, NULL) < 0)
            return git_fatal_ambiguous (objects[i]);
        for (;;) {
            enum bgit_type type;
            unsigned char *data = NULL;
            size_t len = 0;
            if (bgit_odb_read (&ctx->odb, id, &type, &data, &len) < 0)
                return git_fatal ("bad object %s", objects[i]);
            if (type == BGIT_TAG) {
                char tagged[41] = "";
                git_show_tag (data, len, tagged, raw_date);
                free (data);
                if (!tagged[0]) break;
                memcpy (id, tagged, 41);
                continue;               /* on to what the tag points at */
            }
            if (type == BGIT_BLOB) {
                fwrite (data, 1, len, stdout);
                free (data);
                break;
            }
            free (data);
            if (type == BGIT_TREE) {
                printf ("tree %s\n\n", objects[i]);
                bgit_tree_walk (&ctx->odb, id, "", 0, 1, git_show_tree_entry,
                                NULL);
                break;
            }
            if (type != BGIT_COMMIT)
                return git_fatal ("bad object %s", objects[i]);
            struct git_commit commit;
            if (git_commit_read (ctx, id, &commit) < 0)
                return git_fatal ("unable to read %s", id);
            git_print_commit (ctx, stdout, &commit, oneline, format,
                              raw_date, &diff, NULL, 0);
            git_commit_release (&commit);
            break;
        }
    }
    return 0;
}

/* ---- branches, switching, restoring, resetting and tags ----------------- */

/* What HEAD names now, for a reflog message. */
static void
git_head_label (git_context *ctx, struct git_state *state, char *out, size_t outsz)
{
    if (state->branch && !strncmp (state->branch, "refs/heads/", 11))
        snprintf (out, outsz, "%s", state->branch + 11);
    else if (state->have_head) {
        char abbreviated[41];
        git_abbrev (ctx, state->head, 7, abbreviated, sizeof abbreviated);
        snprintf (out, outsz, "%s", abbreviated);
    } else {
        snprintf (out, outsz, "(no branch)");
    }
}

static int
git_cmd_branch (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git branch [-v] [-a | -r] [--show-current] "
                        "[<name> [<start>]] | (-d | -D) <name> "
                        "| (-m | -M) <old> <new>";
    int verbose = 0, show_current = 0, delete_branch = 0, move_branch = 0, force = 0;
    int show_remotes = 0, only_remotes = 0;
    const char *names[2] = { NULL, NULL };
    int n_names = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) verbose = 1;
        else if (!strcmp (w, "--show-current")) show_current = 1;
        else if (!strcmp (w, "-a") || !strcmp (w, "--all")) show_remotes = 1;
        else if (!strcmp (w, "-r") || !strcmp (w, "--remotes")) {
            show_remotes = 1;
            only_remotes = 1;
        }
        else if (!strcmp (w, "-d") || !strcmp (w, "--delete")) delete_branch = 1;
        else if (!strcmp (w, "-D")) { delete_branch = 1; force = 1; }
        else if (!strcmp (w, "-m") || !strcmp (w, "--move")) move_branch = 1;
        else if (!strcmp (w, "-M")) { move_branch = 1; force = 1; }
        else if (!strcmp (w, "-f") || !strcmp (w, "--force")) force = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_names < 2) names[n_names++] = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    int status = 0;

    if (show_current) {
        if (state.branch && !strncmp (state.branch, "refs/heads/", 11))
            printf ("%s\n", state.branch + 11);
        goto done;
    }
    if (delete_branch) {
        if (!n_names) { status = git_usage (usage); goto done; }
        char ref[4096];
        snprintf (ref, sizeof ref, "refs/heads/%s", names[0]);
        char id[41];
        if (bgit_ref_read (&ctx->repo, ref, id) != 0) {
            status = git_fatal ("branch '%s' not found.", names[0]);
            goto done;
        }
        if (state.branch && !strcmp (state.branch, ref)) {
            status = git_fatal ("Cannot delete branch '%s' checked out at '%s'",
                                names[0], ctx->repo.work_tree);
            goto done;
        }
        if (bgit_ref_delete (&ctx->repo, ref, NULL, NULL) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        char abbreviated[41];
        git_abbrev (ctx, id, 7, abbreviated, sizeof abbreviated);
        printf ("Deleted branch %s (was %s).\n", names[0], abbreviated);
        goto done;
    }
    if (move_branch) {
        const char *from = n_names == 2 ? names[0]
                         : (state.branch && !strncmp (state.branch, "refs/heads/", 11)
                            ? state.branch + 11 : NULL);
        const char *to = n_names == 2 ? names[1] : names[0];
        if (!from || !to) { status = git_usage (usage); goto done; }
        char old_ref[4096], new_ref[4096], id[41];
        snprintf (old_ref, sizeof old_ref, "refs/heads/%s", from);
        snprintf (new_ref, sizeof new_ref, "refs/heads/%s", to);
        if (bgit_ref_read (&ctx->repo, old_ref, id) != 0) {
            status = git_fatal ("branch '%s' not found.", from);
            goto done;
        }
        char existing[41];
        if (!force && bgit_ref_read (&ctx->repo, new_ref, existing) == 0) {
            status = git_fatal ("A branch named '%s' already exists.", to);
            goto done;
        }
        char message[1200];
        snprintf (message, sizeof message, "Branch: renamed %s to %s",
                  old_ref, new_ref);
        if (bgit_ref_update (&ctx->repo, new_ref, id, NULL, message) < 0 ||
            bgit_ref_delete (&ctx->repo, old_ref, NULL, NULL) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        if (state.branch && !strcmp (state.branch, old_ref) &&
            bgit_symref_write (&ctx->repo, "HEAD", new_ref, NULL) < 0)
            status = GIT_EXIT_FATAL;
        goto done;
    }
    if (n_names) {
        /* Create a branch at a starting point, HEAD by default. */
        char ref[4096], id[41];
        snprintf (ref, sizeof ref, "refs/heads/%s", names[0]);
        if (!bgit_ref_name_ok (ref)) {
            status = git_fatal ("'%s' is not a valid branch name.", names[0]);
            goto done;
        }
        char existing[41];
        if (!force && bgit_ref_read (&ctx->repo, ref, existing) == 0) {
            status = git_fatal ("a branch named '%s' already exists", names[0]);
            goto done;
        }
        const char *start = names[1] ? names[1] : "HEAD";
        char resolved[41];
        if (git_resolve (ctx, start, resolved, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, resolved, BGIT_COMMIT, id) < 0) {
            status = git_fatal ("not a valid object name: '%s'.", start);
            goto done;
        }
        /* git records the name the start point resolved through. */
        char label[256];
        git_head_label (ctx, &state, label, sizeof label);
        char message[1200];
        snprintf (message, sizeof message, "branch: Created from %s",
                  strcmp (start, "HEAD") ? start : label);
        if (bgit_ref_update (&ctx->repo, ref, id, NULL, message) < 0)
            status = GIT_EXIT_FATAL;
        goto done;
    }

    /* A branch checked out in another worktree is marked, as git marks it. */
    struct git_worktree *trees = NULL;
    size_t n_trees = 0;
    git_worktrees (ctx, &trees, &n_trees);

    /* No arguments: list the branches, and with -a or -r the tracking refs
       that stand for branches at the far end. */
    bgit_ref *refs = NULL;
    size_t n_refs = 0;
    if (!only_remotes && bgit_refs_list (&ctx->repo, "refs/heads/", &refs,
                                         &n_refs) < 0) {
        status = git_fatal ("cannot read refs");
        goto done;
    }
    for (size_t i = 0; i < n_refs; i++) {
        const char *name = refs[i].name + 11;
        int current = state.branch && !strcmp (state.branch, refs[i].name);
        int elsewhere = 0;
        for (size_t w = 0; w < n_trees && !elsewhere; w++)
            if (!current && !strcmp (trees[w].branch, refs[i].name))
                elsewhere = 1;
        const char *mark = current ? "*" : elsewhere ? "+" : " ";
        if (!verbose) {
            printf ("%s %s\n", mark, name);
            continue;
        }
        struct git_commit commit;
        char abbreviated[41], subject[4096] = "";
        git_abbrev (ctx, refs[i].sha, 7, abbreviated, sizeof abbreviated);
        if (git_commit_read (ctx, refs[i].sha, &commit) == 0) {
            git_subject (&commit, subject, sizeof subject);
            git_commit_release (&commit);
        }
        /* git pads the names so the ids line up. */
        size_t width = 0;
        for (size_t j = 0; j < n_refs; j++) {
            size_t len = strlen (refs[j].name + 11);
            if (len > width) width = len;
        }
        printf ("%s %-*s %s %s\n", mark, (int) width, name,
                abbreviated, subject);
    }
    bgit_refs_free (refs, n_refs);

    if (show_remotes) {
        bgit_ref *tracking = NULL;
        size_t n_tracking = 0;
        if (bgit_refs_list (&ctx->repo, "refs/remotes/", &tracking,
                            &n_tracking) == 0) {
            for (size_t i = 0; i < n_tracking; i++) {
                const char *name = tracking[i].name + 13;
                /* A symbolic tracking ref shows what it points at. */
                char *target = NULL;
                if (bgit_symref_read (&ctx->repo, tracking[i].name, &target) == 0 &&
                    target) {
                    printf ("  %s%s -> %s\n", only_remotes ? "" : "remotes/",
                            name, target + 13);
                    free (target);
                    continue;
                }
                free (target);
                if (!verbose) {
                    printf ("  %s%s\n", only_remotes ? "" : "remotes/", name);
                    continue;
                }
                struct git_commit commit;
                char abbreviated[41], subject[4096] = "";
                git_abbrev (ctx, tracking[i].sha, 7, abbreviated,
                            sizeof abbreviated);
                if (git_commit_read (ctx, tracking[i].sha, &commit) == 0) {
                    git_subject (&commit, subject, sizeof subject);
                    git_commit_release (&commit);
                }
                size_t width = 0;
                for (size_t j = 0; j < n_tracking; j++) {
                    size_t len = strlen (tracking[j].name + 13) +
                                 (only_remotes ? 0 : 8);
                    if (len > width) width = len;
                }
                char shown[4096];
                snprintf (shown, sizeof shown, "%s%s",
                          only_remotes ? "" : "remotes/", name);
                printf ("  %-*s %s %s\n", (int) width, shown, abbreviated,
                        subject);
            }
            bgit_refs_free (tracking, n_tracking);
        }
    }
done:
    git_state_release (&state);
    return status;
}

/* Point HEAD straight at a commit, which is what being detached means. */
static int
git_head_detach (git_context *ctx, struct git_state *state, const char *commit,
                 const char *message)
{
    char path[4096];
    if (bgit_ref_path (&ctx->repo, "HEAD", path, sizeof path) < 0) return -1;
    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) return -1;
    char line[42];
    int len = snprintf (line, sizeof line, "%s\n", commit);
    if (bgit_lock_write (&lock, line, (size_t) len) < 0 ||
        bgit_lock_commit (&lock) < 0) {
        bgit_lock_rollback (&lock);
        return -1;
    }
    if (message)
        bgit_reflog_append (&ctx->repo, "HEAD",
                            state->have_head ? state->head : NULL, commit,
                            message);
    return 0;
}

/* Move HEAD to another branch or commit, updating the working tree. */
static int
git_switch_to (git_context *ctx, struct git_state *state, const char *target,
               int detach, int force)
{
    char ref[4096] = "", id[41], commit[41];
    int is_branch = 0;
    snprintf (ref, sizeof ref, "refs/heads/%s", target);
    if (bgit_ref_read (&ctx->repo, ref, id) == 0) is_branch = 1;
    if (!is_branch) {
        if (git_resolve (ctx, target, id, NULL) < 0)
            return git_fatal ("invalid reference: %s", target);
    }
    if (bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0)
        return git_fatal ("reference is not a tree: %s", target);
    char tree[41];
    if (bgit_commit_tree (&ctx->odb, commit, tree) < 0)
        return git_fatal ("cannot read %s", commit);

    char *losing = NULL;
    int rc = bgit_checkout_tree (&ctx->repo, &ctx->odb, tree, &state->index,
                                 &state->n_index, force, &losing);
    if (rc > 0) {
        fflush (stdout);
        fprintf (stderr, "error: Your local changes to the following files "
                         "would be overwritten by checkout:\n\t%s\n"
                         "Please commit your changes or stash them before you "
                         "switch branches.\nAborting\n", losing ? losing : "");
        free (losing);
        return 1;
    }
    if (rc < 0) { free (losing); return GIT_EXIT_FATAL; }
    if (git_index_store (ctx, state->index, state->n_index) < 0)
        return GIT_EXIT_FATAL;

    char from[128], message[1200];
    git_head_label (ctx, state, from, sizeof from);
    snprintf (message, sizeof message, "checkout: moving from %s to %s", from,
              is_branch && !detach ? target : commit);
    if (is_branch && !detach) {
        if (bgit_symref_write (&ctx->repo, "HEAD", ref, NULL) < 0)
            return GIT_EXIT_FATAL;
        bgit_reflog_append (&ctx->repo, "HEAD", state->have_head ? state->head : NULL,
                            commit, message);
    } else if (git_head_detach (ctx, state, commit, message) < 0)
        return GIT_EXIT_FATAL;
    return 0;
}

static int
git_cmd_switch (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git switch [-q] [-c <new-branch>] [-C <new-branch>] "
                        "[--detach] [-f] <branch>";
    const char *create = NULL, *target = NULL;
    int detach = 0, force = 0, force_create = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) continue;
        if ((!strcmp (w, "-c") || !strcmp (w, "--create")) && p->next) {
            create = p->next->word->word; p = p->next;
        } else if (!strcmp (w, "-C") && p->next) {
            create = p->next->word->word; force_create = 1; p = p->next;
        } else if (!strcmp (w, "--detach") || !strcmp (w, "-d")) detach = 1;
        else if (!strcmp (w, "-f") || !strcmp (w, "--force")) force = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!target) target = w;
        else return git_usage (usage);
    }
    if (!create && !target) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    int status = 0;
    if (create) {
        char ref[4096], id[41], commit[41];
        snprintf (ref, sizeof ref, "refs/heads/%s", create);
        char existing[41];
        if (!force_create && bgit_ref_read (&ctx->repo, ref, existing) == 0) {
            status = git_fatal ("a branch named '%s' already exists", create);
            goto done;
        }
        const char *start = target ? target : "HEAD";
        if (git_resolve (ctx, start, id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            status = git_fatal ("invalid reference: %s", start);
            goto done;
        }
        /* switch -c writes the start point as it was typed, so an
           implicit one stays "HEAD"; git branch names the branch instead. */
        char message[1200];
        snprintf (message, sizeof message, "branch: Created from %s", start);
        if (bgit_ref_update (&ctx->repo, ref, commit, NULL, message) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        status = git_switch_to (ctx, &state, create, 0, force);
        goto done;
    }
    status = git_switch_to (ctx, &state, target, detach, force);
done:
    git_state_release (&state);
    return status;
}

static int
git_cmd_checkout (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git checkout [-q] [-b <new-branch>] [--detach] "
                        "[-f] (<branch> | [<tree-ish>] -- <path>...)";
    const char *create = NULL, *target = NULL;
    const char *paths[32];
    int n_paths = 0, detach = 0, force = 0, no_more = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && (!strcmp (w, "-q") || !strcmp (w, "--quiet"))) continue;
        if (!no_more && (!strcmp (w, "-b") || !strcmp (w, "-B")) && p->next) {
            create = p->next->word->word; p = p->next;
        } else if (!no_more && !strcmp (w, "--detach")) detach = 1;
        else if (!no_more && (!strcmp (w, "-f") || !strcmp (w, "--force"))) force = 1;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (!no_more && !target && !n_paths) target = w;
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    int status = 0;

    if (n_paths) {
        /* Restore files from a tree, or from the index. */
        char tree[41] = "";
        int have_tree = 0;
        if (target) {
            char id[41];
            if (git_resolve (ctx, target, id, NULL) < 0 ||
                bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0) {
                status = git_fatal ("invalid reference: %s", target);
                goto done;
            }
            have_tree = 1;
        }
        if (bgit_checkout_paths (&ctx->repo, &ctx->odb, have_tree ? tree : NULL,
                                 &state.index, &state.n_index, paths,
                                 (size_t) n_paths, have_tree, 1) < 0 ||
            git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
        goto done;
    }
    if (create) {
        WORD_LIST *rest = NULL;
        (void) rest;
        char ref[4096], id[41], commit[41];
        snprintf (ref, sizeof ref, "refs/heads/%s", create);
        const char *start = target ? target : "HEAD";
        if (git_resolve (ctx, start, id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
            status = git_fatal ("invalid reference: %s", start);
            goto done;
        }
        char message[1200];
        snprintf (message, sizeof message, "branch: Created from %s", start);
        if (bgit_ref_update (&ctx->repo, ref, commit, NULL, message) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        status = git_switch_to (ctx, &state, create, 0, force);
        goto done;
    }
    if (!target) { status = git_usage (usage); goto done; }
    status = git_switch_to (ctx, &state, target, detach, force);
done:
    git_state_release (&state);
    return status;
}

static int
git_cmd_restore (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git restore [--staged] [--worktree] "
                        "[--source=<tree>] <path>...";
    int staged = 0, worktree = 0, no_more = 0;
    const char *source = NULL;
    const char *paths[32];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && !strcmp (w, "--staged")) staged = 1;
        else if (!no_more && !strcmp (w, "--worktree")) worktree = 1;
        else if (!no_more && !strncmp (w, "--source=", 9)) source = w + 9;
        else if (!no_more && (!strcmp (w, "-s") || !strcmp (w, "--source")) && p->next) {
            source = p->next->word->word; p = p->next;
        }
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (!n_paths) return git_usage (usage);
    if (!staged && !worktree) worktree = 1;      /* git's default */
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    int status = 0;
    char tree[41] = "";
    int have_tree = 0;
    const char *from = source ? source : (staged ? "HEAD" : NULL);
    if (from) {
        char id[41];
        if (git_resolve (ctx, from, id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_TREE, tree) < 0) {
            status = git_fatal ("invalid reference: %s", from);
            goto done;
        }
        have_tree = 1;
    }
    if (bgit_checkout_paths (&ctx->repo, &ctx->odb, have_tree ? tree : NULL,
                             &state.index, &state.n_index, paths,
                             (size_t) n_paths, staged, worktree) < 0 ||
        git_index_store (ctx, state.index, state.n_index) < 0)
        status = GIT_EXIT_FATAL;
done:
    git_state_release (&state);
    return status;
}

static int
git_cmd_reset (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git reset [--soft | --mixed | --hard] [-q] "
                        "[<commit>] [-- <path>...]";
    int soft = 0, hard = 0, no_more = 0;
    const char *commit_name = NULL;
    const char *paths[32];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && !strcmp (w, "--soft")) soft = 1;
        else if (!no_more && !strcmp (w, "--mixed")) { soft = hard = 0; }
        else if (!no_more && !strcmp (w, "--hard")) hard = 1;
        else if (!no_more && (!strcmp (w, "-q") || !strcmp (w, "--quiet"))) continue;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (!no_more && !commit_name && !n_paths) commit_name = w;
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    int status = 0;
    char id[41], commit[41], tree[41];
    const char *target = commit_name ? commit_name : "HEAD";
    if (git_resolve (ctx, target, id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0 ||
        bgit_commit_tree (&ctx->odb, commit, tree) < 0) {
        status = git_fatal_ambiguous (target);
        goto done;
    }

    if (n_paths) {
        /* Only the index moves: the files are left alone. */
        if (bgit_checkout_paths (&ctx->repo, &ctx->odb, tree, &state.index,
                                 &state.n_index, paths, (size_t) n_paths, 1, 0) < 0 ||
            git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
        goto done;
    }

    if (hard) {
        char *losing = NULL;
        int rc = bgit_checkout_tree (&ctx->repo, &ctx->odb, tree, &state.index,
                                     &state.n_index, 1, &losing);
        free (losing);
        if (rc < 0) { status = GIT_EXIT_FATAL; goto done; }
        if (git_index_store (ctx, state.index, state.n_index) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
    } else if (!soft) {
        bgit_index_entry *entries = NULL;
        size_t n = 0;
        if (bgit_read_tree (&ctx->odb, tree, &entries, &n) < 0) {
            status = GIT_EXIT_FATAL;
            goto done;
        }
        /* A mixed reset keeps the files, so each entry takes their stat —
           but the mode stays the one the tree records, not the permissions
           the file happens to have. */
        for (size_t i = 0; i < n; i++) {
            char full[4096];
            snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, entries[i].path);
            struct stat st;
            if (lstat (full, &st) != 0) continue;
            uint32_t mode = entries[i].mode;
            bgit_index_entry_set_stat (&entries[i], &st);
            entries[i].mode = mode;
        }
        int rc = git_index_store (ctx, entries, n);
        bgit_index_free_entries (entries, n);
        if (rc < 0) { status = GIT_EXIT_FATAL; goto done; }
    }

    const char *ref = state.branch ? state.branch : "HEAD";
    char message[1200];
    snprintf (message, sizeof message, "reset: moving to %s", target);
    /* A reset that does not move the branch leaves its log alone; HEAD's
       log records the reset either way, as git does. */
    int moved = !state.have_head || strcmp (state.head, commit) != 0;
    if (moved && bgit_ref_update (&ctx->repo, ref, commit, NULL, message) < 0)
        status = GIT_EXIT_FATAL;
    if (!status && state.branch)
        bgit_reflog_append (&ctx->repo, "HEAD", state.have_head ? state.head : NULL,
                            commit, message);
done:
    git_state_release (&state);
    return status;
}

static int
git_cmd_tag (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git tag [-a] [-m <message>] [-f] <name> [<commit>] "
                        "| -d <name> | -l [<pattern>]";
    int annotate = 0, delete_tag = 0, list = 0, force = 0;
    const char *message = NULL;
    const char *names[2] = { NULL, NULL };
    int n_names = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-a") || !strcmp (w, "--annotate")) annotate = 1;
        else if (!strcmp (w, "-d") || !strcmp (w, "--delete")) delete_tag = 1;
        else if (!strcmp (w, "-l") || !strcmp (w, "--list")) list = 1;
        else if (!strcmp (w, "-f") || !strcmp (w, "--force")) force = 1;
        else if (!strcmp (w, "-m") && p->next) {
            message = p->next->word->word; annotate = 1; p = p->next;
        } else if (!strcmp (w, "-am") && p->next) {
            message = p->next->word->word; annotate = 1; p = p->next;
        } else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_names < 2) names[n_names++] = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    if (delete_tag) {
        if (!n_names) return git_usage (usage);
        char ref[4096], id[41];
        snprintf (ref, sizeof ref, "refs/tags/%s", names[0]);
        if (bgit_ref_read (&ctx->repo, ref, id) != 0)
            return git_fatal ("tag '%s' not found.", names[0]);
        if (bgit_ref_delete (&ctx->repo, ref, NULL, NULL) < 0)
            return GIT_EXIT_FATAL;
        char abbreviated[41];
        git_abbrev (ctx, id, 7, abbreviated, sizeof abbreviated);
        printf ("Deleted tag '%s' (was %s)\n", names[0], abbreviated);
        return 0;
    }
    if (list || !n_names) {
        bgit_ref *refs = NULL;
        size_t n = 0;
        if (bgit_refs_list (&ctx->repo, "refs/tags/", &refs, &n) < 0)
            return git_fatal ("cannot read refs");
        for (size_t i = 0; i < n; i++) {
            const char *name = refs[i].name + 10;
            if (names[0] && fnmatch (names[0], name, 0) != 0) continue;
            printf ("%s\n", name);
        }
        bgit_refs_free (refs, n);
        return 0;
    }

    char ref[4096];
    snprintf (ref, sizeof ref, "refs/tags/%s", names[0]);
    char existing[41];
    if (!force && bgit_ref_read (&ctx->repo, ref, existing) == 0)
        return git_fatal ("tag '%s' already exists", names[0]);
    char id[41], commit[41];
    const char *target = names[1] ? names[1] : "HEAD";
    if (git_resolve (ctx, target, id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0)
        return git_fatal ("Failed to resolve '%s' as a valid ref.", target);

    char pointed[41];
    memcpy (pointed, commit, 41);
    if (annotate) {
        char tagger[1024];
        if (bgit_ident (&ctx->cfg, 1, tagger, sizeof tagger) < 0)
            return git_fatal ("cannot determine the identity to use");
        char body[8192];
        int len = snprintf (body, sizeof body,
                            "object %s\ntype commit\ntag %s\ntagger %s\n\n%s%s",
                            commit, names[0], tagger, message ? message : "",
                            (message && *message &&
                             message[strlen (message) - 1] == '\n') ? "" : "\n");
        if (len < 0 || len >= (int) sizeof body)
            return git_fatal ("tag message too long");
        if (bgit_write_object (ctx->odb.object_dirs[0], "tag",
                               (const unsigned char *) body, (size_t) len, 1,
                               pointed) < 0)
            return GIT_EXIT_FATAL;
    }
    if (bgit_ref_update (&ctx->repo, ref, pointed, NULL, NULL) < 0)
        return GIT_EXIT_FATAL;
    return 0;
}

static int
git_cmd_rm (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git rm [--cached] [-r] [-f] [-q] [--] <path>...";
    int cached = 0, no_more = 0, quiet = 0;
    const char *paths[32];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && !strcmp (w, "--cached")) cached = 1;
        else if (!no_more && (!strcmp (w, "-q") || !strcmp (w, "--quiet"))) quiet = 1;
        else if (!no_more && (!strcmp (w, "-r") || !strcmp (w, "-f") ||
                              !strcmp (w, "--force"))) continue;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (!n_paths) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    int status = 0, removed = 0;
    for (int i = 0; i < n_paths; i++) {
        size_t len = strlen (paths[i]);
        for (size_t j = 0; j < state.n_index;) {
            const char *path = state.index[j].path;
            if (strcmp (path, paths[i]) &&
                !(!strncmp (path, paths[i], len) && path[len] == '/')) {
                j++;
                continue;
            }
            if (!quiet) printf ("rm '%s'\n", path);
            if (!cached) {
                char full[4096];
                snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, path);
                unlink (full);
            }
            char *gone = strdup (path);
            if (!gone) { status = GIT_EXIT_FATAL; break; }
            bgit_index_remove_path (&state.index, &state.n_index, gone);
            free (gone);
            removed = 1;
        }
    }
    if (!removed && !status)
        status = git_fatal ("pathspec '%s' did not match any files", paths[0]);
    if (!status && git_index_store (ctx, state.index, state.n_index) < 0)
        status = GIT_EXIT_FATAL;
    git_state_release (&state);
    return status;
}

/* ---- merge-base -------------------------------------------------------- */

static int
git_cmd_merge_base (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git merge-base [--all] <commit> <commit>... | "
                        "--is-ancestor <commit> <commit> | "
                        "(--independent | --octopus) [--all] <commit>...";
    int all = 0, is_ancestor = 0, independent = 0, octopus = 0;
    const char *names[32];
    int n_names = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) all = 1;
        else if (!strcmp (w, "--is-ancestor")) is_ancestor = 1;
        else if (!strcmp (w, "--independent")) independent = 1;
        else if (!strcmp (w, "--octopus")) octopus = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_names < (int) (sizeof names / sizeof *names)) names[n_names++] = w;
        else return git_fatal ("too many commits");
    }
    if (!n_names || (!independent && n_names < 2)) return git_usage (usage);
    if (is_ancestor && n_names != 2) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    char (*ids)[41] = calloc ((size_t) n_names, sizeof *ids);
    const char **commits = calloc ((size_t) n_names, sizeof *commits);
    if (!ids || !commits) {
        free (ids);
        free (commits);
        return GIT_EXIT_FATAL;
    }
    for (int i = 0; i < n_names; i++) {
        char id[41];
        if (git_resolve (ctx, names[i], id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, ids[i]) < 0) {
            free (ids);
            free (commits);
            return git_fatal ("Not a valid object name %s", names[i]);
        }
        commits[i] = ids[i];
    }

    if (is_ancestor) {
        int reaches = bgit_is_ancestor (&ctx->odb, ids[0], ids[1]);
        free (ids);
        free (commits);
        return reaches < 0 ? GIT_EXIT_FATAL : (reaches ? 0 : 1);
    }

    char (*bases)[41] = NULL;
    size_t n_bases = 0;
    int rc;
    if (independent)
        rc = bgit_independent (&ctx->odb, commits, n_names, &bases, &n_bases);
    else if (octopus)
        rc = bgit_merge_bases_octopus (&ctx->odb, commits, n_names, &bases,
                                       &n_bases);
    else
        rc = bgit_merge_bases_many (&ctx->odb, commits[0], commits + 1,
                                    n_names - 1, &bases, &n_bases);
    free (ids);
    free (commits);
    if (rc < 0) {
        free (bases);
        return GIT_EXIT_FATAL;
    }
    /* Only --all asks for more than the first, and --independent is a list
       by its nature. */
    for (size_t i = 0; i < n_bases; i++) {
        printf ("%s\n", bases[i]);
        if (!all && !independent) break;
    }
    int found = n_bases > 0;
    free (bases);
    return found ? 0 : 1;
}

/* ---- merge ------------------------------------------------------------- */

/* Write CONTENT into the working tree at FULL, as MODE says. */
static int
git_write_worktree_file (const char *full, const char *content, size_t len,
                         uint32_t mode)
{
    unlink (full);
    if (mode == 0120000) {
        char *target = malloc (len + 1);
        if (!target) return -1;
        memcpy (target, content, len);
        target[len] = '\0';
        int rc = symlink (target, full);
        free (target);
        return rc;
    }
    /* The file is created with git's permissions, which the umask then
       narrows, exactly as a checkout does. */
    int fd = open (full, O_WRONLY | O_CREAT | O_TRUNC,
                   mode == 0100755 ? 0777 : 0666);
    if (fd < 0) return -1;
    size_t at = 0;
    while (at < len) {
        ssize_t wrote = write (fd, content + at, len - at);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            close (fd);
            return -1;
        }
        at += (size_t) wrote;
    }
    return close (fd) == 0 ? 0 : -1;
}

/* A file inside the git directory, such as MERGE_HEAD. */
static int
git_state_file (git_context *ctx, const char *name, char *out, size_t outsz)
{
    return snprintf (out, outsz, "%s/%s", ctx->repo.git_dir, name) >= (int) outsz
           ? -1 : 0;
}

static int
git_write_state_file (git_context *ctx, const char *name, const char *content)
{
    char path[4096];
    if (git_state_file (ctx, name, path, sizeof path) < 0) return -1;
    FILE *file = fopen (path, "w");
    if (!file) return -1;
    fputs (content, file);
    return fclose (file) == 0 ? 0 : -1;
}

static void
git_remove_state_file (git_context *ctx, const char *name)
{
    char path[4096];
    if (git_state_file (ctx, name, path, sizeof path) == 0) unlink (path);
}

static int
git_read_state_id (git_context *ctx, const char *name, char out[41])
{
    char path[4096];
    struct stat st;
    if (git_state_file (ctx, name, path, sizeof path) < 0 ||
        lstat (path, &st) < 0)
        return 0;
    unsigned char *content = NULL;
    size_t len = 0;
    if (bgit_slurp_file (path, &content, &len) < 0) return 0;
    int ok = len >= 40;
    if (ok) {
        memcpy (out, content, 40);
        out[40] = '\0';
    }
    free (content);
    return ok;
}

/* The name a merge records for what was merged, as git words it. */
static void
git_merge_label (git_context *ctx, const char *name, const char *id,
                 char *label, size_t label_size, char *subject,
                 size_t subject_size)
{
    char resolved[41];
    char *symref = NULL;
    (void) git_resolve (ctx, name, resolved, &symref);
    if (symref && !strncmp (symref, "refs/heads/", 11)) {
        snprintf (label, label_size, "%s", symref + 11);
        snprintf (subject, subject_size, "Merge branch '%s'", symref + 11);
    } else if (symref && !strncmp (symref, "refs/remotes/", 13)) {
        snprintf (label, label_size, "%s", symref + 13);
        snprintf (subject, subject_size, "Merge remote-tracking branch '%s'",
                  symref + 13);
    } else {
        snprintf (label, label_size, "%s", name);
        snprintf (subject, subject_size, "Merge commit '%s'", id);
    }
    free (symref);
}

/* Nothing is written until every change is known to be safe, which is what
   lets a refused merge leave the working tree as it was. */
static int
git_merge_safe (git_context *ctx, struct git_state *state,
                const bgit_merge_path *paths, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const bgit_merge_path *path = &paths[i];
        int unchanged = path->kind == BGIT_MERGE_CLEAN &&
                        path->mode == path->our_mode &&
                        !strcmp (path->sha, path->our_sha);
        if (unchanged) continue;
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, path->path);
        struct stat st;
        if (lstat (full, &st) < 0) continue;
        const bgit_index_entry *staged = NULL;
        for (size_t j = 0; j < state->n_index; j++)
            if (!strcmp (state->index[j].path, path->path)) staged = &state->index[j];
        if (!staged) {
            fflush (stdout);
            fprintf (stderr, "error: The following untracked working tree files "
                             "would be overwritten by merge:\n\t%s\nPlease move "
                             "or remove them before you merge.\nAborting\n",
                     path->path);
            return -1;
        }
        if (!bgit_worktree_matches (&ctx->odb, full, staged, &st)) {
            fflush (stdout);
            fprintf (stderr, "error: Your local changes to the following files "
                             "would be overwritten by merge:\n\t%s\nPlease commit "
                             "your changes or stash them before you merge.\n"
                             "Aborting\n", path->path);
            return -1;
        }
    }
    return 0;
}

/* Put the merged tree into the working tree and the index. */
static int
git_merge_apply (git_context *ctx, struct git_state *state,
                 const bgit_merge_path *paths, size_t n)
{
    bgit_index_entry *entries = NULL;
    size_t n_entries = 0, capacity = 0;
    for (size_t i = 0; i < n; i++) {
        const bgit_merge_path *path = &paths[i];
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", ctx->repo.work_tree, path->path);

        if (!path->mode && path->kind == BGIT_MERGE_CLEAN) {
            unlink (full);
            continue;
        }
        if (path->text) {
            /* A conflict: the working tree gets the marked-up text. */
            if (git_write_worktree_file (full, path->text, path->len,
                                         path->mode) < 0) {
                bgit_index_free_entries (entries, n_entries);
                return -1;
            }
        } else if (path->mode &&
                   (path->mode != path->our_mode ||
                    strcmp (path->sha, path->our_sha))) {
            if (bgit_checkout_file (&ctx->odb, full, path->sha, path->mode) < 0) {
                bgit_index_free_entries (entries, n_entries);
                return -1;
            }
        }

        /* The index gets one entry, or three when the path is in dispute. */
        struct { uint32_t mode; const char *sha; int stage; } sides[3];
        int n_sides = 0;
        if (path->kind == BGIT_MERGE_CLEAN || path->kind == BGIT_MERGE_AUTO) {
            if (!path->mode) continue;
            sides[n_sides].mode = path->mode;
            sides[n_sides].sha = path->sha;
            sides[n_sides].stage = 0;
            n_sides++;
        } else {
            if (path->base_mode) {
                sides[n_sides].mode = path->base_mode;
                sides[n_sides].sha = path->base_sha;
                sides[n_sides].stage = 1;
                n_sides++;
            }
            if (path->our_mode) {
                sides[n_sides].mode = path->our_mode;
                sides[n_sides].sha = path->our_sha;
                sides[n_sides].stage = 2;
                n_sides++;
            }
            if (path->their_mode) {
                sides[n_sides].mode = path->their_mode;
                sides[n_sides].sha = path->their_sha;
                sides[n_sides].stage = 3;
                n_sides++;
            }
        }
        for (int s = 0; s < n_sides; s++) {
            if (n_entries == capacity) {
                size_t next = capacity ? capacity * 2 : 32;
                bgit_index_entry *grown = realloc (entries, next * sizeof *grown);
                if (!grown) {
                    bgit_index_free_entries (entries, n_entries);
                    return -1;
                }
                entries = grown;
                capacity = next;
            }
            bgit_index_entry *entry = &entries[n_entries];
            memset (entry, 0, sizeof *entry);
            entry->path = strdup (path->path);
            if (!entry->path) {
                bgit_index_free_entries (entries, n_entries);
                return -1;
            }
            entry->mode = sides[s].mode;
            bgit_hex_to_sha (sides[s].sha, entry->sha);
            size_t length = strlen (path->path);
            entry->flags = (uint16_t) ((sides[s].stage << 12) |
                                       (length > 0xFFF ? 0xFFF : length));
            if (!sides[s].stage) {
                struct stat st;
                if (lstat (full, &st) == 0) {
                    uint32_t mode = entry->mode;
                    bgit_index_entry_set_stat (entry, &st);
                    entry->mode = mode;
                }
            }
            n_entries++;
        }
    }
    int rc = git_index_store (ctx, entries, n_entries);
    bgit_index_free_entries (state->index, state->n_index);
    state->index = entries;
    state->n_index = n_entries;
    state->cap_index = capacity;
    return rc;
}

/* The stat of a merge, as git prints it after one. */
static int
git_merge_summary (git_context *ctx, const char *old_tree, const char *new_tree)
{
    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    if (bgit_diff_trees (&ctx->odb, old_tree, new_tree, &entries, &n) < 0)
        return -1;
    struct git_diff_format format;
    git_diff_format_init (&format);
    format.stat = 1;
    format.summary = 1;
    int rc = git_diff_emit (ctx, stdout, &format, entries, n, 0, "");
    bgit_diff_free (entries, n);
    return rc;
}

static int
git_cmd_merge (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git merge [-m <message>] [--no-ff] [--ff-only] "
                        "[--no-commit] [-q] <commit> | --abort";
    const char *message = NULL, *name = NULL;
    int no_ff = 0, ff_only = 0, no_commit = 0, abort_merge = 0, quiet = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-m") && p->next) { message = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "--no-ff")) no_ff = 1;
        else if (!strcmp (w, "--ff")) no_ff = 0;
        else if (!strcmp (w, "--ff-only")) ff_only = 1;
        else if (!strcmp (w, "--no-commit")) no_commit = 1;
        else if (!strcmp (w, "--abort")) abort_merge = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else return git_fatal ("this build's git merge takes one commit");
    }
    if (!abort_merge && !name) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    char merge_head_path[4096];
    if (git_state_file (ctx, "MERGE_HEAD", merge_head_path,
                        sizeof merge_head_path) < 0)
        return GIT_EXIT_FATAL;
    struct stat merging;
    int in_merge = lstat (merge_head_path, &merging) == 0;

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    int status = 0;

    if (abort_merge) {
        if (!in_merge) {
            git_state_release (&state);
            return git_fatal ("There is no merge to abort (MERGE_HEAD missing).");
        }
        /* Put the working tree and index back to HEAD. */
        if (bgit_checkout_tree (&ctx->repo, &ctx->odb, state.head_tree,
                                &state.index, &state.n_index, 1, NULL) < 0 ||
            git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
        /* git aborts a merge by resetting hard to HEAD, and the reflog
           says so. */
        if (!status)
            bgit_reflog_append (&ctx->repo, "HEAD", state.head, state.head,
                                "reset: moving to HEAD");
        git_remove_state_file (ctx, "MERGE_HEAD");
        git_remove_state_file (ctx, "MERGE_MSG");
        git_state_release (&state);
        return status;
    }
    if (in_merge) {
        git_state_release (&state);
        return git_fatal ("You have not concluded your merge (MERGE_HEAD exists).");
    }
    if (!state.have_head) {
        git_state_release (&state);
        return git_fatal ("Non-fast-forward commit does not make sense into an "
                          "empty head");
    }
    for (size_t i = 0; i < state.n_index; i++)
        if ((state.index[i].flags >> 12) & 3) {
            git_state_release (&state);
            return git_fatal ("You have not concluded your merge (MERGE_HEAD "
                              "exists).");
        }

    char their_id[41], their_commit[41];
    if (git_resolve (ctx, name, their_id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, their_id, BGIT_COMMIT, their_commit) < 0) {
        git_state_release (&state);
        return git_fatal ("%s - not something we can merge", name);
    }
    char label[256], subject[1024];
    git_merge_label (ctx, name, their_commit, label, sizeof label,
                     subject, sizeof subject);
    if (message) snprintf (subject, sizeof subject, "%s", message);

    char (*bases)[41] = NULL;
    size_t n_bases = 0;
    const char *twos[1] = { their_commit };
    if (bgit_merge_bases_many (&ctx->odb, state.head, twos, 1, &bases,
                               &n_bases) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (!n_bases) {
        free (bases);
        git_state_release (&state);
        return git_fatal ("refusing to merge unrelated histories");
    }
    if (n_bases > 1) {
        free (bases);
        git_state_release (&state);
        return git_fatal ("this build's git merge needs a single merge base; "
                          "this merge has %zu", n_bases);
    }
    char base[41];
    memcpy (base, bases[0], 41);
    free (bases);

    if (!strcmp (base, their_commit)) {
        git_state_release (&state);
        printf ("Already up to date.\n");
        return 0;
    }
    int fast_forward = !strcmp (base, state.head);
    if (ff_only && !fast_forward) {
        git_state_release (&state);
        return git_fatal ("Not possible to fast-forward, aborting.");
    }

    char their_tree[41];
    if (bgit_commit_tree (&ctx->odb, their_commit, their_tree) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    if (fast_forward && !no_ff) {
        char old_short[41], new_short[41];
        git_abbrev (ctx, state.head, 7, old_short, sizeof old_short);
        git_abbrev (ctx, their_commit, 7, new_short, sizeof new_short);
        if (!quiet) printf ("Updating %s..%s\n", old_short, new_short);
        char *lost = NULL;
        int rc = bgit_checkout_tree (&ctx->repo, &ctx->odb, their_tree,
                                     &state.index, &state.n_index, 0, &lost);
        if (rc > 0) {
            /* Which complaint depends on whether the file in the way is one
               git knows about. */
            int tracked = 0;
            for (size_t i = 0; i < state.n_index && lost; i++)
                if (!strcmp (state.index[i].path, lost)) tracked = 1;
            fflush (stdout);
            if (tracked)
                fprintf (stderr, "error: Your local changes to the following "
                                 "files would be overwritten by merge:\n\t%s\n"
                                 "Please commit your changes or stash them "
                                 "before you merge.\nAborting\n", lost);
            else
                fprintf (stderr, "error: The following untracked working tree "
                                 "files would be overwritten by merge:\n\t%s\n"
                                 "Please move or remove them before you merge.\n"
                                 "Aborting\n", lost ? lost : "");
            free (lost);
            git_state_release (&state);
            return 1;
        }
        if (rc < 0 || git_index_store (ctx, state.index, state.n_index) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        char reflog[1200];
        snprintf (reflog, sizeof reflog, "merge %s: Fast-forward", label);
        const char *ref = state.branch ? state.branch : "HEAD";
        if (bgit_ref_update (&ctx->repo, ref, their_commit, state.head, reflog) < 0)
            status = GIT_EXIT_FATAL;
        if (!status && state.branch)
            bgit_reflog_append (&ctx->repo, "HEAD", state.head, their_commit, reflog);
        if (!status && !quiet) {
            printf ("Fast-forward\n");
            git_merge_summary (ctx, state.head_tree, their_tree);
        }
        git_state_release (&state);
        return status;
    }

    char base_tree[41];
    if (bgit_commit_tree (&ctx->odb, base, base_tree) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    bgit_merge_path *paths = NULL;
    size_t n_paths = 0;
    if (bgit_merge_trees (&ctx->odb, ctx->odb.object_dirs[0], base_tree,
                          state.head_tree, their_tree, "HEAD", label,
                          &paths, &n_paths) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (git_merge_safe (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        fprintf (stderr, "Merge with strategy ort failed.\n");
        return 2;
    }

    int conflicts = 0;
    for (size_t i = 0; i < n_paths; i++) {
        const bgit_merge_path *path = &paths[i];
        if (path->kind == BGIT_MERGE_AUTO || path->kind == BGIT_MERGE_CONTENT ||
            path->kind == BGIT_MERGE_ADD_ADD)
            printf ("Auto-merging %s\n", path->path);
        switch (path->kind) {
        case BGIT_MERGE_CONTENT:
            conflicts++;
            printf ("CONFLICT (content): Merge conflict in %s\n", path->path);
            break;
        case BGIT_MERGE_ADD_ADD:
            conflicts++;
            printf ("CONFLICT (add/add): Merge conflict in %s\n", path->path);
            break;
        case BGIT_MERGE_MODIFY_DELETE:
            conflicts++;
            printf ("CONFLICT (modify/delete): %s deleted in %s and modified in "
                    "%s.  Version %s of %s left in tree.\n", path->path,
                    path->deleted_in_ours ? "HEAD" : label,
                    path->deleted_in_ours ? label : "HEAD",
                    path->deleted_in_ours ? label : "HEAD", path->path);
            break;
        default:
            break;
        }
    }

    if (git_merge_apply (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    if (conflicts) {
        char content[8192];
        snprintf (content, sizeof content, "%s\n", their_commit);
        git_write_state_file (ctx, "MERGE_HEAD", content);
        size_t at = (size_t) snprintf (content, sizeof content,
                                       "%s\n\n# Conflicts:\n", subject);
        for (size_t i = 0; i < n_paths && at < sizeof content; i++)
            if (paths[i].kind != BGIT_MERGE_CLEAN && paths[i].kind != BGIT_MERGE_AUTO)
                at += (size_t) snprintf (content + at, sizeof content - at,
                                         "#\t%s\n", paths[i].path);
        git_write_state_file (ctx, "MERGE_MSG", content);
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        printf ("Automatic merge failed; fix conflicts and then commit the "
                "result.\n");
        return 1;
    }

    char tree[41];
    if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                         state.n_index, tree) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (no_commit) {
        char content[128];
        snprintf (content, sizeof content, "%s\n", their_commit);
        git_write_state_file (ctx, "MERGE_HEAD", content);
        snprintf (content, sizeof content, "%s\n", subject);
        git_write_state_file (ctx, "MERGE_MSG", content);
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        printf ("Automatic merge went well; stopped before committing as "
                "requested\n");
        return 0;
    }

    char author[1024], committer[1024];
    if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0 ||
        bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        return git_fatal ("cannot determine the identity to use");
    }
    char *body = NULL;
    size_t body_len = 0;
    FILE *builder = open_memstream (&body, &body_len);
    if (!builder) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    fprintf (builder, "tree %s\n", tree);
    fprintf (builder, "parent %s\n", state.head);
    fprintf (builder, "parent %s\n", their_commit);
    fprintf (builder, "author %s\n", author);
    fprintf (builder, "committer %s\n", committer);
    fprintf (builder, "\n%s\n", subject);
    fclose (builder);

    char commit[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                (const unsigned char *) body, body_len, 1, commit);
    free (body);
    if (rc < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    char reflog[1200];
    snprintf (reflog, sizeof reflog, "merge %s: Merge made by the 'ort' strategy.",
              label);
    const char *ref = state.branch ? state.branch : "HEAD";
    if (bgit_ref_update (&ctx->repo, ref, commit, state.head, reflog) < 0)
        status = GIT_EXIT_FATAL;
    if (!status && state.branch)
        bgit_reflog_append (&ctx->repo, "HEAD", state.head, commit, reflog);
    if (!status && !quiet) {
        printf ("Merge made by the 'ort' strategy.\n");
        git_merge_summary (ctx, state.head_tree, tree);
    }
    bgit_merge_paths_free (paths, n_paths);
    git_state_release (&state);
    return status;
}

/* ---- packs -------------------------------------------------------------- */

/* One object of a pack being read through: where it starts, what it is,
   and what it turns out to be once any delta is applied. */
struct git_pack_entry {
    uint64_t offset;
    uint64_t data_offset;       /* where the deflated bytes begin */
    uint64_t base_offset;       /* an offset delta's base */
    unsigned char base_sha[20]; /* a reference delta's base */
    int type;                   /* the pack's own numbering */
    int real_type;              /* what a delta turns out to hold */
    uint64_t size;              /* the size the header claims */
    uint64_t end;               /* where this object's bytes stop */
    unsigned char sha[20];
    uint32_t crc;
    int resolved;
};

/* The entry a pack offset names. The scan records them in the order the
   pack holds them, so their offsets are already in order. */
static struct git_pack_entry *
git_pack_at (struct git_pack_entry *entries, size_t n, uint64_t offset)
{
    size_t low = 0, high = n;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (entries[mid].offset < offset) low = mid + 1;
        else if (entries[mid].offset > offset) high = mid;
        else return &entries[mid];
    }
    return NULL;
}

/* What a delta is a delta against, whichever way it names it; NULL for an
   object that stands on its own. */
static struct git_pack_entry *
git_pack_base (struct git_pack_entry *entries, size_t n,
               const struct git_pack_entry *entry)
{
    if (entry->type == BGIT_PACK_OFS_DELTA)
        return git_pack_at (entries, n, entry->base_offset);
    if (entry->type == BGIT_PACK_REF_DELTA)
        for (size_t i = 0; i < n; i++)
            if (entries[i].resolved &&
                !memcmp (entries[i].sha, entry->base_sha, 20))
                return &entries[i];
    return NULL;
}

/* A varint the way a pack writes a delta's base offset: seven bits at a
   time, most significant first, each continuation adding one. */
static int
git_pack_base_offset (const unsigned char *pack, size_t plen, uint64_t at,
                      uint64_t *delta, uint64_t *next)
{
    uint64_t value = 0;
    while (at < plen) {
        unsigned char c = pack[at++];
        value = (value << 7) | (c & 0x7f);
        if (!(c & 0x80)) {
            *delta = value;
            *next = at;
            return 0;
        }
        value += 1;
    }
    return -1;
}

/* Walk the pack once, noting where each object starts and ends. */
static int
git_pack_scan (const unsigned char *pack, size_t plen,
               struct git_pack_entry **out, size_t *n_out)
{
    if (plen < 32 || memcmp (pack, "PACK", 4)) {
        git_fatal ("not a packfile");
        return -1;
    }
    if (bgit_pack_be32 (pack + 4) != 2) {
        git_fatal ("unsupported pack version %u", bgit_pack_be32 (pack + 4));
        return -1;
    }
    size_t n = bgit_pack_be32 (pack + 8);
    struct git_pack_entry *entries = calloc (n ? n : 1, sizeof *entries);
    if (!entries) return -1;

    uint64_t at = 12;
    for (size_t i = 0; i < n; i++) {
        struct git_pack_entry *entry = &entries[i];
        entry->offset = at;
        int type;
        uint64_t size, next;
        if (bgit_pack_read_obj_header (pack, plen - 20, at, &type, &size,
                                       &next) < 0) {
            free (entries);
            git_fatal ("malformed object header at %llu",
                       (unsigned long long) at);
            return -1;
        }
        entry->type = type;
        entry->size = size;
        if (type == BGIT_PACK_OFS_DELTA) {
            uint64_t back = 0, after = 0;
            if (git_pack_base_offset (pack, plen - 20, next, &back, &after) < 0 ||
                back > at) {
                free (entries);
                git_fatal ("malformed delta offset at %llu",
                           (unsigned long long) at);
                return -1;
            }
            entry->base_offset = at - back;
            next = after;
        } else if (type == BGIT_PACK_REF_DELTA) {
            if (next + 20 > plen - 20) {
                free (entries);
                git_fatal ("truncated delta base at %llu",
                           (unsigned long long) at);
                return -1;
            }
            memcpy (entry->base_sha, pack + next, 20);
            next += 20;
        }
        entry->data_offset = next;
        unsigned char *data = NULL;
        size_t len = 0, used = 0;
        if (bgit_pack_inflate (pack + next, (size_t) (plen - 20 - next),
                               (size_t) size, &data, &len, &used) < 0) {
            free (entries);
            git_fatal ("cannot read the object at %llu",
                       (unsigned long long) at);
            return -1;
        }
        free (data);
        entry->end = next + used;
        entry->crc = bgit_pack_crc32 (pack + at, (size_t) (entry->end - at));
        at = entry->end;
    }
    *out = entries;
    *n_out = n;
    return 0;
}

/* The content of one object in the pack, with any delta applied. A pack
   sent over the wire may be thin: a delta in it can lean on an object the
   pack does not carry, which this end is expected to have already. ODB,
   when given, is where those are looked for; THIN, when given, is set if
   one was. */
static int
git_pack_content (const unsigned char *pack, size_t plen,
                  struct git_pack_entry *entries, size_t n, uint64_t offset,
                  int *type_out, unsigned char **out, size_t *len_out, int depth,
                  bgit_odb *odb, int *thin)
{
    if (depth > BGIT_PACK_MAX_DELTA_DEPTH) return -1;
    struct git_pack_entry *entry = git_pack_at (entries, n, offset);
    if (!entry) return -1;

    unsigned char *data = NULL;
    size_t len = 0, used = 0;
    if (bgit_pack_inflate (pack + entry->data_offset,
                           (size_t) (plen - 20 - entry->data_offset),
                           (size_t) entry->size, &data, &len, &used) < 0)
        return -1;
    if (entry->type != BGIT_PACK_OFS_DELTA && entry->type != BGIT_PACK_REF_DELTA) {
        *type_out = entry->type;
        *out = data;
        *len_out = len;
        return 0;
    }

    /* A delta: find its base, then apply. */
    struct git_pack_entry *base_entry = git_pack_base (entries, n, entry);
    unsigned char *base = NULL;
    size_t base_len = 0;
    int base_type = 0;
    if (!base_entry) {
        /* Not in the pack: the far end left it out because this end has
           it. Only a delta that names its base by id can be completed
           that way; one that names an offset has nothing to look up. */
        char hex[41];
        enum bgit_type type;
        if (!odb || entry->type != BGIT_PACK_REF_DELTA) { free (data); return -1; }
        bgit_sha_to_hex (entry->base_sha, hex);
        if (bgit_odb_read (odb, hex, &type, &base, &base_len) < 0) {
            free (data);
            return -1;
        }
        base_type = type == BGIT_COMMIT ? BGIT_PACK_COMMIT
                  : type == BGIT_TREE ? BGIT_PACK_TREE
                  : type == BGIT_BLOB ? BGIT_PACK_BLOB : BGIT_PACK_TAG;
        if (thin) *thin = 1;
    } else if (git_pack_content (pack, plen, entries, n, base_entry->offset,
                                 &base_type, &base, &base_len, depth + 1, odb,
                                 thin) < 0) {
        free (data);
        return -1;
    }
    unsigned char *applied = NULL;
    size_t applied_len = 0;
    int rc = bgit_pack_apply_delta (base, base_len, data, len, &applied,
                                    &applied_len);
    free (base);
    free (data);
    if (rc < 0) return -1;
    *type_out = base_type;
    *out = applied;
    *len_out = applied_len;
    return 0;
}

/* Name every object in the pack, deltas last, until nothing is left. */
static int
git_pack_resolve (const unsigned char *pack, size_t plen,
                  struct git_pack_entry *entries, size_t n, bgit_odb *odb,
                  int *thin)
{
    size_t left = n;
    while (left) {
        size_t settled = 0;
        for (size_t i = 0; i < n; i++) {
            if (entries[i].resolved) continue;
            int type = 0;
            unsigned char *content = NULL;
            size_t len = 0;
            if (git_pack_content (pack, plen, entries, n, entries[i].offset,
                                  &type, &content, &len, 0, odb, thin) < 0)
                continue;             /* its base is not named yet */
            char hex[41];
            int rc = bgit_write_object (NULL, bgit_pack_type_name (type),
                                        content, len, 0, hex);
            free (content);
            if (rc < 0) return -1;
            bgit_hex_to_sha (hex, entries[i].sha);
            entries[i].real_type = type;
            entries[i].resolved = 1;
            settled++;
            left--;
        }
        if (!settled) {
            git_fatal ("the pack has deltas whose bases it does not carry");
            return -1;
        }
    }
    return 0;
}

/* Build a pack holding exactly the objects named, each in full: no
   deltas, which any reader accepts. Gives back the bytes, the entries an
   index is made from, and the pack's own checksum. Returns 0, or -1 with
   git's message already said. */
static int
git_pack_build (bgit_odb *odb, char (*ids)[41], size_t n, unsigned char **out,
                size_t *out_len, struct bgit_pack_idx_entry **entries_out,
                unsigned char checksum[20], char hex[41])
{
    unsigned char *body = NULL;
    size_t body_len = 0, body_cap = 0;
    struct bgit_pack_idx_entry *entries = calloc (n ? n : 1, sizeof *entries);
    if (!entries) return -1;
    unsigned char header[12] = { 'P', 'A', 'C', 'K', 0, 0, 0, 2 };
    header[8] = (unsigned char) ((n >> 24) & 0xff);
    header[9] = (unsigned char) ((n >> 16) & 0xff);
    header[10] = (unsigned char) ((n >> 8) & 0xff);
    header[11] = (unsigned char) (n & 0xff);
    int failed = bgit_pack_buf_append (&body, &body_len, &body_cap, header, 12) < 0;

    for (size_t i = 0; i < n && !failed; i++) {
        enum bgit_type type;
        unsigned char *content = NULL;
        size_t len = 0;
        if (bgit_odb_read (odb, ids[i], &type, &content, &len) < 0) {
            git_fatal ("cannot read %s", ids[i]);
            failed = 1;
            break;
        }
        uint64_t offset = body_len;
        unsigned char object_header[16];
        size_t header_len = 0;
        int packed_type = type == BGIT_COMMIT ? BGIT_PACK_COMMIT
                        : type == BGIT_TREE ? BGIT_PACK_TREE
                        : type == BGIT_BLOB ? BGIT_PACK_BLOB : BGIT_PACK_TAG;
        bgit_pack_encode_obj_header (packed_type, len, object_header, &header_len);
        unsigned char *deflated = NULL;
        size_t deflated_len = 0;
        if (bgit_pack_buf_append (&body, &body_len, &body_cap, object_header,
                                  header_len) < 0 ||
            bgit_deflate (content, len, &deflated, &deflated_len) < 0) {
            free (content);
            failed = 1;
            break;
        }
        free (content);
        if (bgit_pack_buf_append (&body, &body_len, &body_cap, deflated,
                                  deflated_len) < 0)
            failed = 1;
        free (deflated);
        if (failed) break;
        bgit_hex_to_sha (ids[i], entries[i].sha);
        entries[i].off = offset;
        entries[i].crc = bgit_pack_crc32 (body + offset,
                                          (size_t) (body_len - offset));
    }

    if (!failed) {
        bgit_sha1 (body, body_len, checksum);
        bgit_sha_to_hex (checksum, hex);
        if (bgit_pack_buf_append (&body, &body_len, &body_cap, checksum, 20) < 0)
            failed = 1;
    }
    if (failed) {
        free (body);
        free (entries);
        return -1;
    }
    *out = body;
    *out_len = body_len;
    *entries_out = entries;
    return 0;
}

/* git pack-objects: the ids arrive on the input, and the pack is written
   beside its index, named for its own checksum as git names one. */
static int
git_cmd_pack_objects (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git pack-objects [-q] <base-name> < <object-list>";
    const char *base = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) ;
        else if (!strcmp (w, "--stdout"))
            return git_fatal ("this build's git pack-objects writes files, "
                              "not a stream");
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!base) base = w;
        else return git_usage (usage);
    }
    if (!base) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    /* The ids to pack arrive on the input, one to a line; anything after
       the id on a line is a path, which pack-objects ignores. A builtin
       that read the input before this one leaves the end-of-file mark on
       the stream, so clear it before reading a word of the new input. */
    char (*ids)[41] = NULL;
    size_t n = 0, cap = 0;
    char line[4096];
    clearerr (stdin);
    while (fgets (line, sizeof line, stdin)) {
        char *space = strpbrk (line, " \t\n\r");
        if (space) *space = '\0';
        if (strlen (line) != 40) continue;
        if (n == cap) {
            size_t next = cap ? cap * 2 : 64;
            char (*grown)[41] = realloc (ids, next * sizeof *grown);
            if (!grown) { free (ids); return GIT_EXIT_FATAL; }
            ids = grown;
            cap = next;
        }
        memcpy (ids[n], line, 41);
        n++;
    }

    unsigned char *body = NULL;
    size_t body_len = 0;
    struct bgit_pack_idx_entry *entries = NULL;
    unsigned char checksum[20];
    char checksum_hex[41] = "";
    int status = git_pack_build (&ctx->odb, ids, n, &body, &body_len, &entries,
                                 checksum, checksum_hex) < 0 ? GIT_EXIT_FATAL : 0;
    char pack_path[4096], idx_path[4096];
    if (!status) {
        snprintf (pack_path, sizeof pack_path, "%s-%s.pack", base, checksum_hex);
        snprintf (idx_path, sizeof idx_path, "%s-%s.idx", base, checksum_hex);
        FILE *out = fopen (pack_path, "w");
        if (!out || fwrite (body, 1, body_len, out) != body_len ||
            fclose (out) != 0)
            status = git_fatal ("cannot write %s", pack_path);
    }
    if (!status && bgit_pack_write_idx_v2 (idx_path, entries, n, checksum) < 0)
        status = GIT_EXIT_FATAL;
    if (!status) printf ("%s\n", checksum_hex);
    free (body);
    free (entries);
    free (ids);
    return status;
}

static int
git_cmd_index_pack (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git index-pack [-v] [-o <index-file>] <pack-file>";
    const char *pack_path = NULL, *idx_path = NULL;
    (void) ctx;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        /* -v asks for progress, which is for a person watching. */
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) ;
        else if (!strcmp (w, "-o") && p->next) { idx_path = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!pack_path) pack_path = w;
        else return git_usage (usage);
    }
    if (!pack_path) return git_usage (usage);

    size_t plen = 0;
    unsigned char *pack = bgit_pack_slurp (pack_path, &plen);
    if (!pack) return git_fatal ("cannot read %s: %s", pack_path,
                                 strerror (errno));
    struct git_pack_entry *entries = NULL;
    size_t n = 0;
    if (git_pack_scan (pack, plen, &entries, &n) < 0) {
        free (pack);
        return GIT_EXIT_FATAL;
    }
    /* A pack on disk must carry everything it needs; git's index-pack
       completes one only when it is told to. */
    if (git_pack_resolve (pack, plen, entries, n, NULL, NULL) < 0) {
        free (entries);
        free (pack);
        return GIT_EXIT_FATAL;
    }

    struct bgit_pack_idx_entry *idx_entries = calloc (n ? n : 1,
                                                      sizeof *idx_entries);
    if (!idx_entries) {
        free (entries);
        free (pack);
        return GIT_EXIT_FATAL;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy (idx_entries[i].sha, entries[i].sha, 20);
        idx_entries[i].crc = entries[i].crc;
        idx_entries[i].off = entries[i].offset;
    }
    char chosen[4096];
    if (!idx_path) {
        size_t len = strlen (pack_path);
        if (len > 5 && !strcmp (pack_path + len - 5, ".pack"))
            snprintf (chosen, sizeof chosen, "%.*s.idx", (int) (len - 5), pack_path);
        else snprintf (chosen, sizeof chosen, "%s.idx", pack_path);
        idx_path = chosen;
    }
    int status = bgit_pack_write_idx_v2 (idx_path, idx_entries, n,
                                         pack + plen - 20) < 0
                 ? GIT_EXIT_FATAL : 0;
    if (!status) {
        char hex[41];
        bgit_sha_to_hex (pack + plen - 20, hex);
        printf ("%s\n", hex);
    }
    free (idx_entries);
    free (entries);
    free (pack);
    return status;
}

static int
git_cmd_unpack_objects (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git unpack-objects [-q] < <pack-file>";
    const char *pack_path = NULL;
    int quiet = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!pack_path) pack_path = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    unsigned char *pack = NULL;
    size_t plen = 0;
    if (pack_path) {
        pack = bgit_pack_slurp (pack_path, &plen);
        if (!pack) return git_fatal ("cannot read %s: %s", pack_path,
                                     strerror (errno));
    } else if (bgit_slurp_fd (0, &pack, &plen) < 0)
        return git_fatal ("cannot read the pack from the input");

    struct git_pack_entry *entries = NULL;
    size_t n = 0;
    if (git_pack_scan (pack, plen, &entries, &n) < 0 ||
        git_pack_resolve (pack, plen, entries, n, &ctx->odb, NULL) < 0) {
        free (entries);
        free (pack);
        return GIT_EXIT_FATAL;
    }
    int status = 0;
    for (size_t i = 0; i < n && !status; i++) {
        int type = 0;
        unsigned char *content = NULL;
        size_t len = 0;
        if (git_pack_content (pack, plen, entries, n, entries[i].offset, &type,
                              &content, &len, 0, &ctx->odb, NULL) < 0) {
            status = GIT_EXIT_FATAL;
            break;
        }
        char hex[41];
        if (bgit_write_object (ctx->odb.object_dirs[0],
                               bgit_pack_type_name (type), content, len, 1,
                               hex) < 0)
            status = GIT_EXIT_FATAL;
        free (content);
    }
    /* Progress is for a person watching: git keeps it off a pipe. */
    if (!status && !quiet && isatty (STDERR_FILENO))
        fprintf (stderr, "Unpacking objects: 100%% (%zu/%zu), done.\n", n, n);
    free (entries);
    free (pack);
    return status;
}

static int
git_cmd_verify_pack (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git verify-pack [-v] [-s] <idx-file>";
    const char *idx_path = NULL;
    int verbose = 0, stat_only = 0;
    (void) ctx;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) verbose = 1;
        else if (!strcmp (w, "-s") || !strcmp (w, "--stat-only")) stat_only = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!idx_path) idx_path = w;
        else return git_usage (usage);
    }
    if (!idx_path) return git_usage (usage);

    /* The name can be the index, the pack, or neither suffix. */
    char idx_buf[4096], pack_buf[4096];
    size_t len = strlen (idx_path);
    if (len > 4 && !strcmp (idx_path + len - 4, ".idx")) len -= 4;
    else if (len > 5 && !strcmp (idx_path + len - 5, ".pack")) len -= 5;
    snprintf (idx_buf, sizeof idx_buf, "%.*s.idx", (int) len, idx_path);
    snprintf (pack_buf, sizeof pack_buf, "%.*s.pack", (int) len, idx_path);
    idx_path = idx_buf;
    const char *pack_path = pack_buf;

    /* A pack that cannot be read is a failed verification, which git
       reports with 1, not the 128 a broken invocation gets. */
    size_t ilen = 0, plen = 0;
    unsigned char *idx = bgit_pack_slurp (idx_path, &ilen);
    unsigned char *pack = idx ? bgit_pack_slurp (pack_path, &plen) : NULL;
    if (!idx || !pack) {
        free (idx);
        fprintf (stderr, "fatal: Cannot open existing pack file '%s'\n",
                 idx_path);
        return 1;
    }
    int status = 0;
    if (bgit_pack_verify_idx (idx, ilen, NULL) < 0 ||
        bgit_pack_verify_idx_crc32 (idx, ilen, pack, plen) < 0)
        status = 1;

    /* Without an option git says nothing: the status is the answer. */
    if (!status && (verbose || stat_only)) {
        struct git_pack_entry *entries = NULL;
        size_t n = 0;
        size_t *chains = NULL;
        if (git_pack_scan (pack, plen, &entries, &n) < 0 ||
            git_pack_resolve (pack, plen, entries, n, NULL, NULL) < 0)
            status = 1;
        if (!status && !(chains = calloc (n + 1, sizeof *chains)))
            status = GIT_EXIT_FATAL;
        for (size_t i = 0; !status && i < n; i++) {
            /* How many deltas stand between this object and one held
               whole: none for an object that is held whole itself. */
            struct git_pack_entry *base = git_pack_base (entries, n, &entries[i]);
            size_t depth = 0;
            for (struct git_pack_entry *up = base; up;
                 up = git_pack_base (entries, n, up))
                depth++;
            chains[depth]++;
            if (!verbose) continue;
            /* Objects are listed in the order the pack holds them, with
               the size the pack holds — for a delta, that is the delta. */
            char hex[41];
            bgit_sha_to_hex (entries[i].sha, hex);
            printf ("%s %-6s %llu %llu %llu", hex,
                    bgit_pack_type_name (entries[i].real_type),
                    (unsigned long long) entries[i].size,
                    (unsigned long long) (entries[i].end - entries[i].offset),
                    (unsigned long long) entries[i].offset);
            if (depth) {
                char base_hex[41];
                bgit_sha_to_hex (base->sha, base_hex);
                printf (" %zu %s", depth, base_hex);
            }
            printf ("\n");
        }
        if (!status) {
            printf ("non delta: %zu object%s\n", chains[0],
                    chains[0] == 1 ? "" : "s");
            for (size_t d = 1; d <= n; d++)
                if (chains[d])
                    printf ("chain length = %zu: %zu object%s\n", d, chains[d],
                            chains[d] == 1 ? "" : "s");
        }
        free (chains);
        free (entries);
    }
    if (!status && verbose) printf ("%s: ok\n", pack_path);
    free (pack);
    free (idx);
    return status;
}

/* ---- remotes ------------------------------------------------------------ */

/* Write one setting into this repository's own configuration file. */
static int
git_config_write (git_context *ctx, const char *key, const char *value)
{
    char path[4096];
    bgit_config_repo_file (&ctx->repo, path, sizeof path);
    return bgit_config_set_file (path, key, value, 0);
}

/* Where a remote points, as its configuration says. */
static const char *
git_remote_url (git_context *ctx, const char *remote)
{
    char key[4096];
    snprintf (key, sizeof key, "remote.%s.url", remote);
    return bgit_config_get (&ctx->cfg, key);
}

/* http:// and https:// are the URLs this build can reach. */
static int
git_url_is_http (const char *url)
{
    return !strncmp (url, "http://", 7) || !strncmp (url, "https://", 8);
}

/* A path with no protocol in front of it. */
static int
git_local_only (const char *url)
{
    return !strstr (url, "://") && strncmp (url, "git@", 4);
}

/* Somewhere this build can reach: a path, or an address over HTTP. The
   rest — ssh, and git's own port — wait for the phase after this. */
static int
git_can_reach (const char *url)
{
    return git_local_only (url) || git_url_is_http (url);
}

static int
git_cmd_remote (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git remote [-v] | add <name> <url> | remove <name> "
                        "| set-url <name> <url> | get-url <name>";
    const char *verb = NULL, *name = NULL, *url = NULL;
    int verbose = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) verbose = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!verb) verb = w;
        else if (!name) name = w;
        else if (!url) url = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    if (!verb) {
        /* Every remote the configuration names, once each, in order. */
        char seen[64][256];
        size_t n_seen = 0;
        for (size_t i = 0; i < ctx->cfg.n; i++) {
            const char *key = ctx->cfg.entries[i].key;
            if (strncmp (key, "remote.", 7)) continue;
            const char *dot = strrchr (key, '.');
            if (!dot || dot <= key + 7) continue;
            char remote[256];
            size_t len = (size_t) (dot - key - 7);
            if (len >= sizeof remote) continue;
            memcpy (remote, key + 7, len);
            remote[len] = '\0';
            int known = 0;
            for (size_t j = 0; j < n_seen; j++)
                if (!strcmp (seen[j], remote)) known = 1;
            if (known || n_seen >= 64) continue;
            snprintf (seen[n_seen++], sizeof seen[0], "%s", remote);
        }
        /* git lists them by name, whatever order the file holds them in. */
        if (n_seen > 1) qsort (seen, n_seen, sizeof seen[0],
                               (int (*) (const void *, const void *)) strcmp);
        for (size_t i = 0; i < n_seen; i++) {
            if (!verbose) { printf ("%s\n", seen[i]); continue; }
            const char *where = git_remote_url (ctx, seen[i]);
            printf ("%s\t%s (fetch)\n", seen[i], where ? where : "");
            printf ("%s\t%s (push)\n", seen[i], where ? where : "");
        }
        return 0;
    }
    if (!strcmp (verb, "add")) {
        if (!name || !url) return git_usage (usage);
        if (git_remote_url (ctx, name))
            return git_fatal ("remote %s already exists.", name);
        char key[4096], value[4096];
        snprintf (key, sizeof key, "remote.%s.url", name);
        if (git_config_write (ctx, key, url) < 0) return GIT_EXIT_FATAL;
        snprintf (key, sizeof key, "remote.%s.fetch", name);
        snprintf (value, sizeof value, "+refs/heads/*:refs/remotes/%s/*", name);
        return git_config_write (ctx, key, value) < 0 ? GIT_EXIT_FATAL : 0;
    }
    if (!strcmp (verb, "set-url")) {
        if (!name || !url) return git_usage (usage);
        if (!git_remote_url (ctx, name))
            return git_fatal ("No such remote '%s'", name);
        char key[4096];
        snprintf (key, sizeof key, "remote.%s.url", name);
        return git_config_write (ctx, key, url) < 0 ? GIT_EXIT_FATAL : 0;
    }
    if (!strcmp (verb, "get-url")) {
        if (!name) return git_usage (usage);
        const char *where = git_remote_url (ctx, name);
        if (!where) return git_fatal ("No such remote '%s'", name);
        printf ("%s\n", where);
        return 0;
    }
    if (!strcmp (verb, "remove") || !strcmp (verb, "rm")) {
        if (!name) return git_usage (usage);
        if (!git_remote_url (ctx, name)) {
            fflush (stdout);
            fprintf (stderr, "error: No such remote: '%s'\n", name);
            return 2;
        }
        char path[4096], key[4096];
        bgit_config_repo_file (&ctx->repo, path, sizeof path);
        snprintf (key, sizeof key, "remote.%s.url", name);
        bgit_config_unset_file (path, key);
        snprintf (key, sizeof key, "remote.%s.fetch", name);
        bgit_config_unset_file (path, key);
        /* The tracking refs the remote left behind go with it. */
        char prefix[4096];
        snprintf (prefix, sizeof prefix, "refs/remotes/%s/", name);
        bgit_ref *refs = NULL;
        size_t n = 0;
        if (bgit_refs_list (&ctx->repo, prefix, &refs, &n) == 0) {
            for (size_t i = 0; i < n; i++)
                bgit_ref_delete (&ctx->repo, refs[i].name, NULL, NULL);
            bgit_refs_free (refs, n);
        }
        return 0;
    }
    return git_usage (usage);
}

/* Open the repository at the far end of a local remote. */
static int
git_open_remote (const char *url, bgit_repo *repo, bgit_odb *odb)
{
    if (bgit_repo_discover (url, repo) < 0) {
        char inside[4096];
        snprintf (inside, sizeof inside, "%s/.git", url);
        if (bgit_repo_open (inside, repo) < 0 && bgit_repo_open (url, repo) < 0)
            return -1;
    }
    if (bgit_odb_open (repo, odb) < 0) {
        bgit_repo_release (repo);
        return -1;
    }
    odb->quiet = 1;
    return 0;
}

/* ---- speaking the protocol ---------------------------------------------- */

/* What the server side of this build can do. A client reads this first
   and asks only for what it names. */
static int
git_v2_advertise (void)
{
    if (bgit_pkt_writef (1, "version 2\n") < 0 ||
        bgit_pkt_writef (1, "agent=%s\n", GIT_AGENT_STRING) < 0 ||
        bgit_pkt_writef (1, "ls-refs\n") < 0 ||
        bgit_pkt_writef (1, "fetch\n") < 0 ||
        bgit_pkt_writef (1, "object-format=sha1\n") < 0 ||
        bgit_pkt_flush (1) < 0)
        return -1;
    return 0;
}

/* 1 when the client asked about this ref; asking for no prefix at all
   asks for every ref there is. */
static int
git_v2_wanted (const char *name, char **prefixes, size_t n_prefixes)
{
    if (!n_prefixes) return 1;
    for (size_t i = 0; i < n_prefixes; i++)
        if (!strncmp (name, prefixes[i], strlen (prefixes[i]))) return 1;
    return 0;
}

/* What a tag points at, following tags until it reaches something that is
   not one. Returns 0 with OUT set, 1 when SHA is not a tag, or -1. */
static int
git_peel_fully (bgit_odb *odb, const char *sha, char out[41])
{
    char at[41];
    memcpy (at, sha, 41);
    for (int depth = 0; depth < 16; depth++) {
        enum bgit_type type;
        unsigned char *data = NULL;
        size_t len = 0;
        if (bgit_odb_read (odb, at, &type, &data, &len) < 0) return -1;
        free (data);
        if (type != BGIT_TAG) {
            if (!depth) return 1;
            memcpy (out, at, 41);
            return 0;
        }
        char next[41];
        if (bgit_peel_to_type (odb, at, BGIT_UNKNOWN, next) < 0) return -1;
        memcpy (at, next, 41);
    }
    return -1;
}

/* Answer one ls-refs: every ref asked for, in git's order, HEAD first,
   with what HEAD points at and what a tag points at when those were
   asked for. */
static int
git_v2_ls_refs (bgit_repo *repo, bgit_odb *odb, char **prefixes,
                size_t n_prefixes, int want_symrefs, int want_peeled)
{
    char id[41];
    char *symref = NULL;
    if (bgit_ref_resolve (repo, "HEAD", id, &symref) == 0 &&
        git_v2_wanted ("HEAD", prefixes, n_prefixes)) {
        if (want_symrefs && symref) {
            if (bgit_pkt_writef (1, "%s HEAD symref-target:%s\n", id, symref) < 0)
                { free (symref); return -1; }
        } else if (bgit_pkt_writef (1, "%s HEAD\n", id) < 0) {
            free (symref);
            return -1;
        }
    }
    free (symref);

    bgit_ref *refs = NULL;
    size_t n = 0;
    if (bgit_refs_list (repo, "refs/", &refs, &n) < 0) return -1;
    int status = 0;
    for (size_t i = 0; i < n && !status; i++) {
        if (!git_v2_wanted (refs[i].name, prefixes, n_prefixes)) continue;
        char peeled[41];
        if (want_peeled && git_peel_fully (odb, refs[i].sha, peeled) == 0)
            status = bgit_pkt_writef (1, "%s %s peeled:%s\n", refs[i].sha,
                                      refs[i].name, peeled);
        else
            status = bgit_pkt_writef (1, "%s %s\n", refs[i].sha, refs[i].name);
    }
    bgit_refs_free (refs, n);
    if (status < 0) return -1;
    return bgit_pkt_flush (1);
}

/* What one request asked for. A v2 request names a command, then its
   arguments, and every command reads the ones it knows. */
struct git_v2_request {
    char **prefixes;             /* ls-refs: which refs to list */
    size_t n_prefixes;
    int symrefs, peel;
    char (*ids)[41];             /* fetch: wants first, then haves */
    size_t n_wants, n_haves;
    int done;
};

static void
git_v2_request_release (struct git_v2_request *request)
{
    for (size_t i = 0; i < request->n_prefixes; i++) free (request->prefixes[i]);
    free (request->prefixes);
    free (request->ids);
    memset (request, 0, sizeof *request);
}

/* Keep one more id. Wants are kept before haves, and a want cannot
   arrive after a have, so both lists grow from the same array. */
static int
git_v2_keep_id (struct git_v2_request *request, const char *id)
{
    size_t n = request->n_wants + request->n_haves;
    char (*grown)[41] = realloc (request->ids, (n + 1) * sizeof *grown);
    if (!grown) return -1;
    request->ids = grown;
    memcpy (request->ids[n], id, 40);
    request->ids[n][40] = '\0';
    return 0;
}

/* Answer one fetch: the objects the client asked for, less everything it
   says it already has, in a pack sent down the first side-band channel. */
static int
git_v2_fetch (bgit_odb *odb, struct git_v2_request *request)
{
    char (*ids)[41] = request->ids;
    const char **wants = calloc (request->n_wants ? request->n_wants : 1,
                                 sizeof *wants);
    const char **haves = calloc (request->n_haves ? request->n_haves : 1,
                                 sizeof *haves);
    if (!wants || !haves) {
        free (wants);
        free (haves);
        return -1;
    }
    for (size_t i = 0; i < request->n_wants; i++) wants[i] = ids[i];
    for (size_t i = 0; i < request->n_haves; i++)
        haves[i] = ids[request->n_wants + i];

    /* Still negotiating: say which of its haves are here, and that this
       end is ready to send. With nothing in common there is nothing to
       be ready about, and the client asks again with more. */
    int status = 0;
    if (!request->done) {
        size_t common = 0;
        if (bgit_pkt_writef (1, "acknowledgments\n") < 0) status = -1;
        for (size_t i = 0; !status && i < request->n_haves; i++)
            if (bgit_odb_has (odb, haves[i])) {
                common++;
                if (bgit_pkt_writef (1, "ACK %s\n", haves[i]) < 0) status = -1;
            }
        if (!status && !common) {
            if (bgit_pkt_writef (1, "NAK\n") < 0 || bgit_pkt_flush (1) < 0)
                status = -1;
            free (wants);
            free (haves);
            return status;
        }
        if (!status && (bgit_pkt_writef (1, "ready\n") < 0 ||
                        bgit_pkt_delim (1) < 0))
            status = -1;
    }

    char (*send)[41] = NULL;
    size_t n_send = 0;
    if (!status && bgit_reachable_objects (odb, wants, request->n_wants, haves,
                                           request->n_haves, &send, &n_send) < 0)
        status = -1;
    free (wants);
    free (haves);

    unsigned char *body = NULL;
    size_t body_len = 0;
    struct bgit_pack_idx_entry *entries = NULL;
    unsigned char checksum[20];
    char checksum_hex[41] = "";
    if (!status && git_pack_build (odb, send, n_send, &body, &body_len, &entries,
                                   checksum, checksum_hex) < 0)
        status = -1;
    free (send);
    free (entries);

    if (!status && (bgit_pkt_writef (1, "packfile\n") < 0 ||
                    bgit_pkt_write_band (1, 1, body, body_len) < 0 ||
                    bgit_pkt_flush (1) < 0))
        status = -1;
    free (body);
    return status;
}

/* git upload-pack: the far end of a fetch, over protocol v2. git has
   asked for v2 by default since 2.26, and it is all this build speaks, so
   a caller that does not ask for it is told rather than answered wrongly. */
static int
git_cmd_upload_pack (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git upload-pack [--stateless-rpc] [--advertise-refs] "
                        "<directory>";
    const char *dir = NULL;
    int stateless = 0, advertise_only = 0;
    (void) ctx;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--stateless-rpc")) stateless = 1;
        else if (!strcmp (w, "--advertise-refs")) advertise_only = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!dir) dir = w;
        else return git_usage (usage);
    }
    if (!dir) return git_usage (usage);

    const char *protocol = getenv ("GIT_PROTOCOL");
    if (!protocol || !strstr (protocol, "version=2"))
        return git_fatal ("this build's git upload-pack speaks protocol "
                          "version 2 only");

    bgit_repo repo;
    bgit_odb odb;
    if (git_open_remote (dir, &repo, &odb) < 0)
        return git_fatal ("'%s' does not appear to be a git repository", dir);

    int status = 0;
    if ((!stateless || advertise_only) && git_v2_advertise () < 0)
        status = GIT_EXIT_FATAL;
    if (!advertise_only && !status) {
        bgit_pkt_reader reader;
        bgit_pkt_from_fd (&reader, 0);
        /* A request is the command, then the client's own capabilities, a
           divider, the arguments, and a flush. A flush where the command
           would be ends the conversation. */
        for (;;) {
            char *line = NULL;
            int got = bgit_pkt_read_line (&reader, &line);
            if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
            if (got < 0) {
                status = git_fatal ("the request is not a pkt-line stream");
                break;
            }
            char command[64] = "";
            if (!strncmp (line, "command=", 8))
                snprintf (command, sizeof command, "%s", line + 8);
            free (line);

            struct git_v2_request request;
            memset (&request, 0, sizeof request);
            int bad = 0;
            for (;;) {
                got = bgit_pkt_read_line (&reader, &line);
                if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
                if (got == BGIT_PKT_DELIM) continue;
                if (got < 0) { bad = 1; break; }
                if (!strcmp (line, "symrefs")) request.symrefs = 1;
                else if (!strcmp (line, "peel")) request.peel = 1;
                else if (!strcmp (line, "done")) request.done = 1;
                else if (!strncmp (line, "ref-prefix ", 11)) {
                    char **grown = realloc (request.prefixes,
                                            (request.n_prefixes + 1) * sizeof *grown);
                    if (grown) {
                        request.prefixes = grown;
                        grown[request.n_prefixes] = strdup (line + 11);
                        if (grown[request.n_prefixes]) request.n_prefixes++;
                    }
                }
                else if (!strncmp (line, "want ", 5) && strlen (line + 5) >= 40) {
                    if (git_v2_keep_id (&request, line + 5) < 0) bad = 1;
                    else request.n_wants++;
                }
                else if (!strncmp (line, "have ", 5) && strlen (line + 5) >= 40) {
                    if (git_v2_keep_id (&request, line + 5) < 0) bad = 1;
                    else request.n_haves++;
                }
                free (line);
                line = NULL;
                if (bad) break;
            }
            free (line);
            if (!bad && !strcmp (command, "ls-refs"))
                bad = git_v2_ls_refs (&repo, &odb, request.prefixes,
                                      request.n_prefixes, request.symrefs,
                                      request.peel) < 0;
            else if (!bad && !strcmp (command, "fetch"))
                bad = git_v2_fetch (&odb, &request) < 0;
            else if (!bad)
                status = git_fatal ("this build's git upload-pack does not "
                                    "have the '%s' command", command);
            git_v2_request_release (&request);
            if (bad && !status) status = GIT_EXIT_FATAL;
            if (status) break;
            if (got == BGIT_PKT_EOF) break;
        }
    }
    bgit_odb_release (&odb);
    bgit_repo_release (&repo);
    return status;
}

/* A conversation with a far end. Over a path it is a child with a pipe
   each way, the way git starts its own; over HTTP it is a URL, where
   each request is a POST of its own and the answer comes back whole. */
typedef struct {
    bgit_proto_io io;
    bgit_pkt_reader reader;
    git_context *ctx;            /* whose configuration to ask */
    int over_http;
    /* a child at the far end */
    pid_t child;
    int to_far, from_far;
    /* or a URL, and what is being built to send to it */
    char url[4096];
    const char *service;
    char secret[1024];           /* a name and secret, once one is needed */
    const char **headers;        /* what http.extraHeader adds */
    size_t n_headers;
    int follow;                  /* whether this request may be redirected */
    unsigned char *request;
    size_t request_len, request_cap;
    unsigned char *response;
    size_t response_len;
} git_conn;

/* The scheme and host part of a URL, which is what a stored credential
   is matched on. */
static void
git_url_host (const char *url, char *out, size_t outsz)
{
    const char *after = strstr (url, "://");
    after = after ? after + 3 : url;
    const char *at = strchr (after, '@');
    const char *host = at ? at + 1 : after;
    size_t scheme = (size_t) (after - url);
    size_t len = strcspn (host, "/");
    if (scheme + len >= outsz) len = outsz - scheme - 1;
    memcpy (out, url, scheme);
    memcpy (out + scheme, host, len);
    out[scheme + len] = '\0';
}

/* A name and secret for URL, out of the file `credential.helper store`
   keeps them in: a URL to a line, name and secret inside it. Returns 1
   when one was found, and leaves it in OUT. */
static int
git_http_credentials (git_context *ctx, const char *url, char *out, size_t outsz)
{
    const char *helper = bgit_config_get (&ctx->cfg, "credential.helper");
    if (!helper || strncmp (helper, "store", 5)) return 0;
    char path[4096] = "";
    const char *named = strstr (helper, "--file=");
    if (named) snprintf (path, sizeof path, "%s", named + 7);
    else {
        const char *home = getenv ("HOME");
        if (!home) return 0;
        snprintf (path, sizeof path, "%s/.git-credentials", home);
    }
    unsigned char *content = NULL;
    size_t len = 0;
    if (bgit_slurp_file (path, &content, &len) < 0) return 0;

    char want[1024];
    git_url_host (url, want, sizeof want);
    int found = 0;
    char *line = (char *) content;
    char *end = (char *) content + len;
    while (!found && line < end) {
        char *stop = memchr (line, '\n', (size_t) (end - line));
        size_t line_len = stop ? (size_t) (stop - line) : (size_t) (end - line);
        char entry[2048];
        if (line_len && line_len < sizeof entry) {
            memcpy (entry, line, line_len);
            entry[line_len] = '\0';
            /* "<scheme>://<name>:<secret>@<host>" */
            char *at = strrchr (entry, '@');
            const char *after = strstr (entry, "://");
            if (at && after) {
                char host[1024];
                git_url_host (entry, host, sizeof host);
                *at = '\0';
                if (!strcmp (host, want) &&
                    snprintf (out, outsz, "%s", after + 3) < (int) outsz)
                    found = 1;
            }
        }
        line = stop ? stop + 1 : end;
    }
    free (content);
    return found;
}

/* Ask the far end for something over HTTP, with curl doing the talking:
   the builtin when this build has it, and the command otherwise, which
   is how pkg fetches. The answer, and the three digits of status curl
   is asked to add after it, come back through a pipe. */
static int
git_http_ask (git_conn *conn, const char *method, const char *url,
              const char *content_type, const unsigned char *body,
              size_t body_len)
{
    int into[2], back[2];
    if (pipe (into) < 0) return -1;
    if (pipe (back) < 0) {
        close (into[0]);
        close (into[1]);
        return -1;
    }
    char type_header[256] = "", protocol_header[64];
    snprintf (protocol_header, sizeof protocol_header, "Git-Protocol: version=2");
    if (content_type)
        snprintf (type_header, sizeof type_header, "Content-Type: %s",
                  content_type);

    pid_t child = fork ();
    if (child < 0) {
        close (into[0]); close (into[1]);
        close (back[0]); close (back[1]);
        return -1;
    }
    if (!child) {
        close (into[1]);
        close (back[0]);
        if (dup2 (into[0], 0) < 0 || dup2 (back[1], 1) < 0) _exit (127);
        close (into[0]);
        close (back[1]);
        char *argv[64];
        int argc = 0;
        argv[argc++] = "curl";
        argv[argc++] = "-sS";
        argv[argc++] = "-w";
        argv[argc++] = "%{http_code}";
        argv[argc++] = "-H";
        argv[argc++] = protocol_header;
        if (*type_header) {
            argv[argc++] = "-H";
            argv[argc++] = type_header;
        }
        for (size_t i = 0; i < conn->n_headers &&
                           argc + 8 < (int) (sizeof argv / sizeof *argv); i++) {
            argv[argc++] = "-H";
            argv[argc++] = (char *) conn->headers[i];
        }
        /* git follows a redirect on the first request and no other, which
           is what http.followRedirects means by "initial". */
        if (conn->follow) argv[argc++] = "-L";
        if (*conn->secret) {
            argv[argc++] = "-u";
            argv[argc++] = conn->secret;
        }
        if (body) {
            argv[argc++] = "--data-binary";
            argv[argc++] = "@-";
        }
        argv[argc++] = "-X";
        argv[argc++] = (char *) method;
        argv[argc++] = (char *) url;
        argv[argc] = NULL;
        bos_prepare_child ();
        bos_run_builtin ("curl", argv, NULL);
        /* A secret must not reach the command line of another program;
           with the builtin it stays in this process's own memory. */
        if (*conn->secret) _exit (127);
        execvp ("curl", argv);
        _exit (127);
    }
    close (into[0]);
    close (back[1]);
    if (body && body_len) {
        /* curl reads the whole body before it answers, so writing it all
           and then reading cannot deadlock. */
        size_t at = 0;
        while (at < body_len) {
            ssize_t put = write (into[1], body + at, body_len - at);
            if (put < 0) {
                if (errno == EINTR) continue;
                break;
            }
            at += (size_t) put;
        }
    }
    close (into[1]);

    unsigned char *answer = NULL;
    size_t len = 0, cap = 0;
    if (bgit_slurp_fd (back[0], &answer, &len) < 0) {
        close (back[0]);
        waitpid (child, NULL, 0);
        return -1;
    }
    (void) cap;
    close (back[0]);
    int wait_status = 0;
    waitpid (child, &wait_status, 0);
    if (!WIFEXITED (wait_status) || WEXITSTATUS (wait_status)) {
        free (answer);
        git_fatal ("unable to access '%s'", conn->url);
        return -1;
    }
    /* The last three bytes are the status curl was asked to add. */
    if (len < 3) {
        free (answer);
        git_fatal ("unable to access '%s': nothing came back", conn->url);
        return -1;
    }
    int status = (answer[len - 3] - '0') * 100 + (answer[len - 2] - '0') * 10 +
                 (answer[len - 1] - '0');
    len -= 3;
    if (status == 401) {
        free (answer);
        return 401;
    }
    if (status != 200) {
        free (answer);
        git_fatal ("unable to access '%s': the far end said %d", conn->url,
                   status);
        return -1;
    }
    free (conn->response);
    conn->response = answer;
    conn->response_len = len;
    bgit_pkt_from_memory (&conn->reader, conn->response, conn->response_len);
    conn->io.reader = &conn->reader;
    return 0;
}

/* Ask, and if the far end wants a name and secret, find one and ask
   again. The first ask carries none, which is what a far end that wants
   none expects. */
static int
git_http_request (git_conn *conn, const char *method, const char *url,
                  const char *content_type, const unsigned char *body,
                  size_t body_len)
{
    int rc = git_http_ask (conn, method, url, content_type, body, body_len);
    if (rc != 401) return rc;
    if (!*conn->secret && conn->ctx &&
        git_http_credentials (conn->ctx, conn->url, conn->secret,
                              sizeof conn->secret))
        rc = git_http_ask (conn, method, url, content_type, body, body_len);
    if (rc != 401) return rc;
    if (*conn->secret)
        git_fatal ("Authentication failed for '%s'", conn->url);
    else
        git_fatal ("could not read Username for '%s': terminal prompts "
                   "disabled", conn->url);
    return -1;
}

static int
git_http_write (bgit_proto_io *io, const void *data, size_t len)
{
    git_conn *conn = io->context;
    return bgit_pack_buf_append (&conn->request, &conn->request_len,
                                 &conn->request_cap, data, len);
}

static int
git_http_done (bgit_proto_io *io)
{
    git_conn *conn = io->context;
    char url[4200], type[128];
    snprintf (url, sizeof url, "%s/%s", conn->url, conn->service);
    snprintf (type, sizeof type, "application/x-%s-request", conn->service);
    int rc = git_http_request (conn, "POST", url, type, conn->request,
                               conn->request_len);
    conn->request_len = 0;
    return rc < 0 ? -1 : 0;
}

/* What git says when the far end stops without answering. Whatever it
   said for itself has already gone to the same place. */
static int
git_far_end_gone (void)
{
    fflush (stdout);
    fputs ("fatal: Could not read from remote repository.\n\n"
           "Please make sure you have the correct access rights\n"
           "and the repository exists.\n", stderr);
    return GIT_EXIT_FATAL;
}

/* The environment the far end gets: this one, without the variables that
   name this repository's files, plus the protocol to speak. Returns the
   array, or this process's own environment if there is no room for it. */
static char **
git_far_environ (void)
{
    extern char **environ;
    static const char *const leave_behind[] = {
        "GIT_PROTOCOL=", "GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=",
        "GIT_OBJECT_DIRECTORY=", "GIT_ALTERNATE_OBJECT_DIRECTORIES=", NULL
    };
    size_t n = 0;
    while (environ[n]) n++;
    char **env = malloc ((n + 2) * sizeof *env);
    if (!env) return environ;
    size_t at = 0;
    for (size_t i = 0; i < n; i++) {
        int drop = 0;
        for (int k = 0; leave_behind[k] && !drop; k++)
            if (!strncmp (environ[i], leave_behind[k], strlen (leave_behind[k])))
                drop = 1;
        if (!drop) env[at++] = environ[i];
    }
    env[at++] = (char *) "GIT_PROTOCOL=version=2";
    env[at] = NULL;
    return env;
}

/* Start the far end and hold both ends of the conversation: what is
   written to *TO_FAR arrives on its input, and what it answers is read
   from *FROM_FAR. PROGRAM is what to run, or NULL for this build's own
   COMMAND, which is how git runs its own for a path. */
static pid_t
git_start_far_end (const char *program, const char *command, const char *path,
                   int *to_far, int *from_far)
{
    int down[2], up[2];
    if (pipe (down) < 0) return -1;
    if (pipe (up) < 0) {
        close (down[0]);
        close (down[1]);
        return -1;
    }
    pid_t child = fork ();
    if (child < 0) {
        close (down[0]); close (down[1]);
        close (up[0]); close (up[1]);
        return -1;
    }
    if (!child) {
        close (down[1]);
        close (up[0]);
        if (dup2 (down[0], 0) < 0 || dup2 (up[1], 1) < 0) _exit (127);
        close (down[0]);
        close (up[1]);
        /* The far end must be told which protocol to speak, and must not
           inherit what points this end at its own files. The shell keeps
           its own table of variables, so the environment is handed over
           whole rather than changed here. */
        char **env = git_far_environ ();
        /* The shell running it is the one we are inside: a bash-os machine
           need not have another. */
        char script[4096];
        snprintf (script, sizeof script, "%s \"$@\"",
                  program ? program : command);
        execle ("/proc/self/exe", "bash", "--noprofile", "--norc", "-c", script,
                "git-far-end", path, (char *) NULL, env);
        _exit (127);
    }
    close (down[0]);
    close (up[1]);
    *to_far = down[1];
    *from_far = up[0];
    return child;
}

/* Open a conversation with the far end named by URL, and leave it where
   its advertisement starts. SERVICE is the half being asked for, which
   over HTTP is part of the address and over a pipe is the command to
   run. Returns 0, or -1 with git's message said. */
static int
git_conn_open (git_conn *conn, git_context *ctx, const char *url,
               const char *program, const char *service)
{
    memset (conn, 0, sizeof *conn);
    conn->to_far = conn->from_far = -1;
    conn->service = service;
    conn->ctx = ctx;
    /* A far end that stops leaves a pipe with no reader; the write that
       finds out must not take the shell's child with it. */
    signal (SIGPIPE, SIG_IGN);

    if (git_url_is_http (url)) {
        conn->over_http = 1;
        snprintf (conn->url, sizeof conn->url, "%s", url);
        size_t len = strlen (conn->url);
        while (len && conn->url[len - 1] == '/') conn->url[--len] = '\0';
        conn->io.context = conn;
        conn->io.write = git_http_write;
        conn->io.done = git_http_done;
        conn->io.reader = &conn->reader;
        /* Whatever the configuration wants said with every request. */
        conn->n_headers = bgit_config_get_all (&ctx->cfg, "http.extraHeader",
                                               &conn->headers);
        char ask[4300];
        snprintf (ask, sizeof ask, "%s/info/refs?service=%s", conn->url, service);
        conn->follow = 1;
        int rc = git_http_request (conn, "GET", ask, NULL, NULL, 0);
        conn->follow = 0;
        return rc < 0 ? -1 : 0;
    }

    char command[64];
    snprintf (command, sizeof command, "builtin git %s", service + 4);
    conn->child = git_start_far_end (program, command, url, &conn->to_far,
                                     &conn->from_far);
    if (conn->child < 0) {
        git_fatal ("cannot start the far end: %s", strerror (errno));
        return -1;
    }
    bgit_pkt_from_fd (&conn->reader, conn->from_far);
    bgit_proto_io_fd (&conn->io, &conn->reader, conn->to_far);
    return 0;
}

/* End the conversation, and say whether the far end was content.
   Returns 0, or -1. */
static int
git_conn_close (git_conn *conn)
{
    int rc = 0;
    if (conn->over_http) {
        free (conn->request);
        free (conn->response);
        conn->request = conn->response = NULL;
        return 0;
    }
    bgit_pkt_flush (conn->to_far);
    bgit_pkt_release (&conn->reader);
    if (conn->to_far >= 0) close (conn->to_far);
    if (conn->from_far >= 0) close (conn->from_far);
    int wait_status = 0;
    if (conn->child > 0) {
        waitpid (conn->child, &wait_status, 0);
        rc = WIFEXITED (wait_status) && !WEXITSTATUS (wait_status) ? 0 : -1;
    }
    return rc;
}

/* Open a conversation with the half of the far end that sends objects,
   and check it can do what is about to be asked of it. */
static int
git_far_end_open (git_conn *conn, git_context *ctx, const char *url,
                  const char *program, int want_fetch)
{
    if (git_conn_open (conn, ctx, url, program, "git-upload-pack") < 0)
        return -1;
    bgit_proto_caps caps;
    if (bgit_proto_read_caps (conn->io.reader, &caps) < 0) {
        git_far_end_gone ();
        git_conn_close (conn);
        return -1;
    }
    int can = bgit_proto_cap (&caps, "ls-refs") != NULL &&
              (!want_fetch || bgit_proto_cap (&caps, "fetch") != NULL);
    bgit_proto_caps_release (&caps);
    if (!can) {
        git_fatal ("the far end cannot %s", want_fetch ? "send objects"
                                                       : "list refs");
        git_conn_close (conn);
        return -1;
    }
    return 0;
}

/* Keep what a fetch brought back. git explodes a small pack into loose
   objects and keeps a large one as a pack beside a generated index; the
   line between the two is fetch.unpackLimit, a hundred objects. */
static int
git_store_pack_into (bgit_repo *repo, bgit_odb *odb, unsigned char *pack,
                     size_t len)
{
    if (len < 32) return 0;                    /* nothing came back */
    struct git_pack_entry *entries = NULL;
    size_t n = 0;
    int thin = 0;
    if (git_pack_scan (pack, len, &entries, &n) < 0 ||
        git_pack_resolve (pack, len, entries, n, odb, &thin) < 0) {
        free (entries);
        return -1;
    }
    /* A thin pack is not a pack this repository could keep: what its
       deltas lean on is outside it. Written out object by object, every
       one of them is whole. */
    int status = 0;
    if (n < 100 || thin) {
        for (size_t i = 0; !status && i < n; i++) {
            int type = 0;
            unsigned char *content = NULL;
            size_t content_len = 0;
            if (git_pack_content (pack, len, entries, n, entries[i].offset,
                                  &type, &content, &content_len, 0, odb,
                                  NULL) < 0) {
                status = -1;
                break;
            }
            char hex[41];
            if (bgit_write_object (odb->object_dirs[0],
                                   bgit_pack_type_name (type), content,
                                   content_len, 1, hex) < 0)
                status = -1;
            free (content);
        }
        free (entries);
        return status;
    }

    /* Big enough to keep whole: write it where git keeps packs, with the
       index that makes it readable, and let the store see it. */
    struct bgit_pack_idx_entry *idx_entries = calloc (n, sizeof *idx_entries);
    if (!idx_entries) {
        free (entries);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy (idx_entries[i].sha, entries[i].sha, 20);
        idx_entries[i].crc = entries[i].crc;
        idx_entries[i].off = entries[i].offset;
    }
    char hex[41];
    bgit_sha_to_hex (pack + len - 20, hex);
    char dir[4096], pack_path[4096], idx_path[4096];
    snprintf (dir, sizeof dir, "%s/pack", odb->object_dirs[0]);
    mkdir (dir, 0777);
    snprintf (pack_path, sizeof pack_path, "%s/pack-%s.pack", dir, hex);
    snprintf (idx_path, sizeof idx_path, "%s/pack-%s.idx", dir, hex);
    FILE *out = fopen (pack_path, "w");
    if (!out || fwrite (pack, 1, len, out) != len || fclose (out) != 0)
        status = -1;
    if (!status &&
        bgit_pack_write_idx_v2 (idx_path, idx_entries, n, pack + len - 20) < 0)
        status = -1;
    free (idx_entries);
    free (entries);
    /* The store listed the packs when it opened; this is a new one. */
    if (!status) {
        bgit_odb_release (odb);
        if (bgit_odb_open (repo, odb) < 0) return -1;
        odb->quiet = 1;
    }
    return status;
}

static int
git_store_pack (git_context *ctx, unsigned char *pack, size_t len)
{
    return git_store_pack_into (&ctx->repo, &ctx->odb, pack, len);
}

/* The ids of every ref here, which is what the far end is told this end
   already has. */
static int
git_local_haves (git_context *ctx, char (**out)[41], size_t *n_out)
{
    bgit_ref *refs = NULL;
    size_t n = 0;
    if (bgit_refs_list (&ctx->repo, "refs/", &refs, &n) < 0) return -1;
    char (*ids)[41] = calloc (n ? n : 1, sizeof *ids);
    if (!ids) {
        bgit_refs_free (refs, n);
        return -1;
    }
    size_t kept = 0;
    for (size_t i = 0; i < n; i++)
        if (bgit_odb_has (&ctx->odb, refs[i].sha)) {
            memcpy (ids[kept], refs[i].sha, 41);
            kept++;
        }
    bgit_refs_free (refs, n);
    *out = ids;
    *n_out = kept;
    return 0;
}

/* One change a push asks for. */
struct git_push_command {
    char old_id[41], new_id[41];
    char name[4096];
    const char *refused;         /* git's reason, when it is */
};

/* An id of nothing at all: what a push puts where a ref is being made or
   unmade. */
#define GIT_NULL_ID "0000000000000000000000000000000000000000"

/* The first line of a push carries the client's capabilities after a NUL;
   the rest are plain. */
static int
git_push_wants (const unsigned char *line, size_t len, const char *name)
{
    const unsigned char *nul = memchr (line, '\0', len);
    if (!nul) return 0;
    const char *caps = (const char *) nul + 1;
    size_t caps_len = len - (size_t) ((const unsigned char *) caps - line);
    size_t want = strlen (name);
    for (size_t i = 0; i + want <= caps_len; i++)
        if (!memcmp (caps + i, name, want) &&
            (i == 0 || caps[i - 1] == ' ') &&
            (i + want == caps_len || caps[i + want] == ' ' ||
             caps[i + want] == '=' || caps[i + want] == '\n'))
            return 1;
    return 0;
}

/* Put one pkt-line into a buffer, which is how a report is built: the
   report itself is packets, inside the side-band packet that carries it. */
static size_t
git_pkt_into (unsigned char *buf, size_t at, size_t room, const char *text)
{
    size_t len = strlen (text);
    if (at + len + 4 >= room) return at;
    char header[5];
    snprintf (header, sizeof header, "%04x", (unsigned) (len + 4));
    memcpy (buf + at, header, 4);
    memcpy (buf + at + 4, text, len);
    return at + len + 4;
}

/* One thing a push asks the far end to do. */
struct git_push_want {
    char src[4096];          /* the ref here, once it was worked out */
    char dst[4096];          /* the ref over there */
    char id[41];             /* what it is to become; zeros to unmake it */
    char old[41];            /* what the far end says it is now */
    int forced;              /* the refspec said +, or --force did */
    int is_new;
    int forced_update;       /* it was not a fast-forward */
    int remote_refused;      /* the far end said no, rather than this end */
    int sent;
    const char *refused;
};

/* A ref by the name a person would use for it. */
static const char *
git_ref_short (const char *ref)
{
    if (!strncmp (ref, "refs/heads/", 11)) return ref + 11;
    if (!strncmp (ref, "refs/tags/", 10)) return ref + 10;
    if (!strncmp (ref, "refs/remotes/", 13)) return ref + 13;
    return ref;
}

/* The full name of a ref this repository has, for a name as it was
   given: a branch, a tag, or a name that is already full. Returns 1 when
   one was found. */
static int
git_push_source (git_context *ctx, const char *name, char *out, size_t outsz,
                 char id[41])
{
    const char *shapes[] = { "%s", "refs/heads/%s", "refs/tags/%s", NULL };
    for (int i = 0; shapes[i]; i++) {
        char full[4096];
        snprintf (full, sizeof full, shapes[i], name);
        if (strncmp (full, "refs/", 5)) continue;
        if (bgit_ref_read (&ctx->repo, full, id) == 0) {
            snprintf (out, outsz, "%s", full);
            return 1;
        }
    }
    /* Not a ref: a revision may still name something to push. */
    if (git_resolve (ctx, name, id, NULL) == 0) {
        snprintf (out, outsz, "%s", name);
        return 1;
    }
    return 0;
}

static int
git_push_want (git_context *ctx, struct git_push_want **wants, size_t *n,
               size_t *cap, const char *spec, int force, int deleting)
{
    if (*n == *cap) {
        size_t next = *cap ? *cap * 2 : 8;
        struct git_push_want *grown = realloc (*wants, next * sizeof *grown);
        if (!grown) return -1;
        *wants = grown;
        *cap = next;
    }
    struct git_push_want *want = &(*wants)[*n];
    memset (want, 0, sizeof *want);
    want->forced = force;
    if (*spec == '+') {
        want->forced = 1;
        spec++;
    }
    const char *colon = strchr (spec, ':');
    char source[4096] = "", target[4096] = "";
    if (deleting) snprintf (target, sizeof target, "%s", spec);
    else if (!colon) snprintf (source, sizeof source, "%s", spec);
    else {
        snprintf (source, sizeof source, "%.*s", (int) (colon - spec), spec);
        snprintf (target, sizeof target, "%s", colon + 1);
    }

    if (!*source) {
        /* Nothing on the near side: the ref over there is to be unmade. */
        memcpy (want->id, GIT_NULL_ID, 41);
        if (!*target) return git_fatal ("this build's git push needs a ref to "
                                        "delete") < 0 ? -1 : -1;
        snprintf (want->src, sizeof want->src, "%s", target);
    } else if (!git_push_source (ctx, source, want->src, sizeof want->src,
                                 want->id)) {
        git_fatal ("src refspec %s does not match any", source);
        return -1;
    }
    if (!*target) snprintf (target, sizeof target, "%s", want->src);
    if (!strncmp (target, "refs/", 5))
        snprintf (want->dst, sizeof want->dst, "%s", target);
    else
        snprintf (want->dst, sizeof want->dst, "refs/%s/%s",
                  !strncmp (want->src, "refs/tags/", 10) ? "tags" : "heads",
                  target);
    (*n)++;
    return 0;
}

/* git receive-pack: the far end of a push. This is git's first protocol,
   and the one it still uses for a push: the refs this repository has,
   then the changes the other end wants, then a pack, then what became of
   each change. */
static int
git_cmd_receive_pack (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git receive-pack <directory>";
    const char *dir = NULL;
    (void) ctx;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--stateless-rpc")) ;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!dir) dir = w;
        else return git_usage (usage);
    }
    if (!dir) return git_usage (usage);

    bgit_repo repo;
    bgit_odb odb;
    if (git_open_remote (dir, &repo, &odb) < 0)
        return git_fatal ("'%s' does not appear to be a git repository", dir);

    /* What this repository has, and what it can do. The capabilities ride
       on the first ref after a NUL; a repository with no refs at all says
       so under a name no ref could have. */
    static const char capabilities[] =
        "report-status delete-refs side-band-64k ofs-delta "
        "object-format=sha1 agent=" GIT_AGENT_STRING;
    bgit_ref *refs = NULL;
    size_t n_refs = 0;
    int status = 0;
    if (bgit_refs_list (&repo, "refs/", &refs, &n_refs) < 0)
        status = GIT_EXIT_FATAL;
    for (size_t i = 0; !status && i < n_refs + (n_refs ? 0 : 1); i++) {
        char line[8192];
        size_t len = (size_t) snprintf (line, sizeof line, "%s %s",
                                        n_refs ? refs[i].sha : GIT_NULL_ID,
                                        n_refs ? refs[i].name : "capabilities^{}");
        if (!i) {
            line[len++] = '\0';
            memcpy (line + len, capabilities, sizeof capabilities - 1);
            len += sizeof capabilities - 1;
        }
        line[len++] = '\n';
        if (bgit_pkt_write (1, line, len) < 0) status = GIT_EXIT_FATAL;
    }
    if (!status && bgit_pkt_flush (1) < 0) status = GIT_EXIT_FATAL;
    bgit_refs_free (refs, n_refs);

    /* What the other end wants changed: "<old> <new> <ref>" each. */
    bgit_pkt_reader reader;
    bgit_pkt_from_fd (&reader, 0);
    struct git_push_command *commands = NULL;
    size_t n_commands = 0, cap = 0;
    int side_band = 0, wants_report = 0, sending_objects = 0;
    while (!status) {
        const unsigned char *data = NULL;
        int got = bgit_pkt_read (&reader, &data);
        if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
        if (got < 0) { status = GIT_EXIT_FATAL; break; }
        if (!n_commands) {
            side_band = git_push_wants (data, (size_t) got, "side-band-64k");
            wants_report = git_push_wants (data, (size_t) got, "report-status") ||
                           git_push_wants (data, (size_t) got, "report-status-v2");
        }
        if (got < 82 || data[40] != ' ' || data[81] != ' ') continue;
        if (n_commands == cap) {
            size_t next = cap ? cap * 2 : 8;
            struct git_push_command *grown = realloc (commands,
                                                      next * sizeof *grown);
            if (!grown) { status = GIT_EXIT_FATAL; break; }
            commands = grown;
            cap = next;
        }
        struct git_push_command *command = &commands[n_commands];
        memset (command, 0, sizeof *command);
        memcpy (command->old_id, data, 40);
        memcpy (command->new_id, data + 41, 40);
        const unsigned char *end = memchr (data, '\0', (size_t) got);
        size_t name_len = (end ? (size_t) (end - data) : (size_t) got) - 82;
        while (name_len && (data[82 + name_len - 1] == '\n' ||
                            data[82 + name_len - 1] == '\r'))
            name_len--;
        if (name_len >= sizeof command->name) name_len = sizeof command->name - 1;
        memcpy (command->name, data + 82, name_len);
        if (strcmp (command->new_id, GIT_NULL_ID)) sending_objects = 1;
        n_commands++;
    }

    /* Then the pack, which comes only when something is being added. */
    if (!status && n_commands && sending_objects) {
        unsigned char *pack = NULL;
        size_t pack_len = 0;
        /* The packets were read in chunks, so the front of the pack is
           already in hand rather than still on the descriptor. */
        const unsigned char *pending = NULL;
        size_t pending_len = 0;
        bgit_pkt_pending (&reader, &pending, &pending_len);
        if (bgit_pack_read_stream (0, pending, pending_len, &pack, &pack_len) < 0 ||
            git_store_pack_into (&repo, &odb, pack, pack_len) < 0)
            status = GIT_EXIT_FATAL;
        free (pack);
    }

    /* What each change may do. A branch this repository has checked out
       is refused, and so is one that would lose commits. What the far end
       should be told beyond the refusal itself goes down the second
       side-band channel, which is where git puts its "remote:" lines. */
    char aside[8192];
    size_t aside_len = 0;
    char *head = NULL;
    if (!repo.bare) bgit_symref_read (&repo, "HEAD", &head);
    /* A push that would lose commits is the pushing end's to refuse: git
       lets one through here unless it has been told not to. */
    bgit_config far_config;
    bgit_config_load (&far_config, &repo, NULL, 0);
    int deny_non_fast_forwards = bgit_config_bool (&far_config,
                                                   "receive.denyNonFastForwards", 0);
    bgit_config_release (&far_config);
    for (size_t i = 0; !status && i < n_commands; i++) {
        struct git_push_command *command = &commands[i];
        int unmaking = !strcmp (command->new_id, GIT_NULL_ID);
        char current[41] = "";
        int have = bgit_ref_read (&repo, command->name, current) == 0;
        if (head && !strcmp (head, command->name)) {
            command->refused = "branch is currently checked out";
            aside_len += (size_t) snprintf (aside + aside_len,
                                            sizeof aside - aside_len,
                                            "error: refusing to update checked "
                                            "out branch: %s\n", command->name);
        }
        else if (have && strcmp (current, command->old_id))
            command->refused = "fetch first";
        else if (!have && strcmp (command->old_id, GIT_NULL_ID))
            command->refused = "fetch first";
        else if (!unmaking && !bgit_odb_has (&odb, command->new_id))
            command->refused = "missing necessary objects";
        else if (!unmaking && have && deny_non_fast_forwards &&
                 strcmp (current, command->new_id) &&
                 bgit_is_ancestor (&odb, current, command->new_id) <= 0)
            command->refused = "non-fast-forward";
        if (command->refused) continue;
        int wrote = unmaking
            ? bgit_ref_delete (&repo, command->name, have ? current : NULL, NULL)
            : bgit_ref_update (&repo, command->name, command->new_id,
                               have ? current : "", "push");
        if (wrote < 0) command->refused = "failed to update ref";
    }
    free (head);

    /* And what became of each: the report is packets of its own, sent
       down the first side-band channel when one was asked for. */
    if (!status && aside_len && side_band &&
        bgit_pkt_write_band (1, 2, aside, aside_len) < 0)
        status = GIT_EXIT_FATAL;
    if (!status && wants_report) {
        unsigned char report[65000];
        size_t len = git_pkt_into (report, 0, sizeof report, "unpack ok\n");
        for (size_t i = 0; i < n_commands; i++) {
            char line[4300];
            if (commands[i].refused)
                snprintf (line, sizeof line, "ng %s %s\n", commands[i].name,
                          commands[i].refused);
            else snprintf (line, sizeof line, "ok %s\n", commands[i].name);
            len = git_pkt_into (report, len, sizeof report, line);
        }
        if (len + 4 < sizeof report) {
            memcpy (report + len, "0000", 4);
            len += 4;
        }
        if (side_band) {
            if (bgit_pkt_write_band (1, 1, report, len) < 0 ||
                bgit_pkt_flush (1) < 0)
                status = GIT_EXIT_FATAL;
        } else if (write (1, report, len) != (ssize_t) len)
            status = GIT_EXIT_FATAL;
    }
    free (commands);
    bgit_odb_release (&odb);
    bgit_repo_release (&repo);
    return status;
}

/* git ls-remote: what refs the far end has, without fetching anything. */
static int
git_cmd_ls_remote (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git ls-remote [--heads] [--tags] [--symref] "
                        "[--upload-pack=<command>] [<repository>]";
    int heads = 0, tags = 0, symrefs = 0, quiet = 0;
    const char *program = NULL, *where = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--heads") || !strcmp (w, "-h")) heads = 1;
        else if (!strcmp (w, "--tags") || !strcmp (w, "-t")) tags = 1;
        else if (!strcmp (w, "--symref")) symrefs = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strncmp (w, "--upload-pack=", 14)) program = w + 14;
        else if ((!strcmp (w, "-u") || !strcmp (w, "--upload-pack")) && p->next) {
            program = p->next->word->word;
            p = p->next;
        }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!where) where = w;
        else return git_fatal ("this build's git ls-remote does not take "
                               "patterns yet");
    }

    /* Inside a repository a name stands for the URL configured for it,
       as it does for fetch; outside one, only a path can be listed. */
    bgit_repo here;
    const char *url = NULL;
    if (bgit_repo_discover (".", &here) == 0) {
        bgit_repo_release (&here);
        if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
        url = git_remote_url (ctx, where ? where : "origin");
    } else
        /* Outside a repository there is still a configuration: what the
           far end wants said, and where a credential is kept. */
        bgit_config_load (&ctx->cfg, NULL, git_overrides, git_n_overrides);
    /* Without a repository named on the command line, git says which one
       it went to. */
    int named = where != NULL;
    if (url) where = url;
    else if (!where)
        return git_fatal ("No remote configured to list refs from.");

    if (!git_can_reach (where))
        return git_fatal ("this build's git ls-remote takes a path or an http "
                          "URL; ssh is not done yet");
    if (!named && !quiet) fprintf (stderr, "From %s\n", where);

    git_conn conn;
    if (git_far_end_open (&conn, ctx, where, program, 0) < 0) return GIT_EXIT_FATAL;
    int status = 0;

    bgit_proto_ref *refs = NULL;
    size_t n_refs = 0;
    if (!status) {
        const char *prefixes[2];
        size_t n_prefixes = 0;
        if (heads) prefixes[n_prefixes++] = "refs/heads/";
        if (tags) prefixes[n_prefixes++] = "refs/tags/";
        if (bgit_proto_ls_refs (&conn.io, prefixes, n_prefixes, 1, 1,
                                &refs, &n_refs) < 0)
            status = git_far_end_gone ();
    }
    if (!status)
        for (size_t i = 0; i < n_refs; i++) {
            if (symrefs && refs[i].symref)
                printf ("ref: %s\t%s\n", refs[i].symref, refs[i].name);
            printf ("%s\t%s\n", refs[i].id, refs[i].name);
            if (refs[i].peeled[0])
                printf ("%s\t%s^{}\n", refs[i].peeled, refs[i].name);
        }
    bgit_proto_refs_release (refs, n_refs);
    if (git_conn_close (&conn) < 0 && !status) status = git_far_end_gone ();
    return status;
}

/* ---- clone, fetch and push --------------------------------------------- */

/* One branch the far end has. */
struct git_remote_ref {
    char name[4096];      /* refs/heads/... over there */
    char local[4096];     /* refs/remotes/<remote>/... over here */
    char id[41];
    char old[41];
    int updated;
    int is_new;
};

static int
git_remote_heads (bgit_repo *remote, const char *name,
                  struct git_remote_ref **out, size_t *n_out)
{
    bgit_ref *refs = NULL;
    size_t n = 0;
    if (bgit_refs_list (remote, "refs/heads/", &refs, &n) < 0) return -1;
    struct git_remote_ref *list = calloc (n ? n : 1, sizeof *list);
    if (!list) { bgit_refs_free (refs, n); return -1; }
    for (size_t i = 0; i < n; i++) {
        snprintf (list[i].name, sizeof list[i].name, "%s", refs[i].name);
        snprintf (list[i].local, sizeof list[i].local, "refs/remotes/%s/%s",
                  name, refs[i].name + 11);
        memcpy (list[i].id, refs[i].sha, 41);
    }
    bgit_refs_free (refs, n);
    *out = list;
    *n_out = n;
    return 0;
}

/* The summary line a fetch or a push prints for one ref. */
static void
git_report_ref (git_context *ctx, const char *old, const char *id,
                const char *from, const char *to, int width)
{
    char old_short[41], new_short[41];
    git_abbrev (ctx, id, 7, new_short, sizeof new_short);
    if (!old || !*old) {
        fprintf (stderr, " * [new branch]      %-*s -> %s\n", width, from, to);
        return;
    }
    git_abbrev (ctx, old, 7, old_short, sizeof old_short);
    fprintf (stderr, "   %s..%s  %-*s -> %s\n", old_short, new_short, width,
             from, to);
}

/* The same for a push, which has more to say: a tag is not a branch, a
   ref can be unmade, and an update that is not a fast-forward says that
   it was forced. */
static void
git_report_push (git_context *ctx, const struct git_push_want *want)
{
    const char *from = git_ref_short (want->src);
    const char *to = git_ref_short (want->dst);
    /* git pads what stands in brackets to the same eighteen columns,
       whichever of them it is. */
    char what[32];
    if (want->refused) {
        snprintf (what, sizeof what, "[%s]",
                  want->remote_refused ? "remote rejected" : "rejected");
        fprintf (stderr, " ! %-18s%s -> %s (%s)\n", what, from, to,
                 want->refused);
        return;
    }
    if (!strcmp (want->id, GIT_NULL_ID)) {
        fprintf (stderr, " - %-18s%s\n", "[deleted]", to);
        return;
    }
    if (want->is_new) {
        snprintf (what, sizeof what, "[new %s]",
                  strncmp (want->dst, "refs/tags/", 10) ? "branch" : "tag");
        fprintf (stderr, " * %-18s%s -> %s\n", what, from, to);
        return;
    }
    char old_short[41], new_short[41];
    git_abbrev (ctx, want->old, 7, old_short, sizeof old_short);
    git_abbrev (ctx, want->id, 7, new_short, sizeof new_short);
    if (want->forced_update)
        fprintf (stderr, " + %s...%s %s -> %s (forced update)\n", old_short,
                 new_short, from, to);
    else
        fprintf (stderr, "   %s..%s  %s -> %s\n", old_short, new_short, from, to);
}

static int
git_cmd_fetch (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git fetch [-q] [--upload-pack=<command>] [<remote>]";
    const char *name = NULL, *program = NULL;
    int quiet = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strncmp (w, "--upload-pack=", 14)) program = w + 14;
        else if ((!strcmp (w, "-u") || !strcmp (w, "--upload-pack")) && p->next) {
            program = p->next->word->word;
            p = p->next;
        }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!name) name = "origin";
    const char *url = git_remote_url (ctx, name);
    if (!url) return git_fatal ("'%s' does not appear to be a git repository",
                                name);
    if (!git_can_reach (url))
        return git_fatal ("this build's git fetch takes a path or an http "
                          "URL; ssh is not done yet");

    /* The far end is asked over the protocol, the way git asks it, even
       when it is a directory on this machine. */
    git_conn conn;
    if (git_far_end_open (&conn, ctx, url, program, 1) < 0) return GIT_EXIT_FATAL;

    bgit_proto_ref *refs = NULL;
    size_t n_refs = 0;
    const char *prefix = "refs/heads/";
    int status = 0;
    if (bgit_proto_ls_refs (&conn.io, &prefix, 1, 0, 0, &refs, &n_refs) < 0)
        status = git_far_end_gone ();

    struct git_remote_ref *heads = NULL;
    size_t n_heads = 0;
    if (!status) {
        heads = calloc (n_refs ? n_refs : 1, sizeof *heads);
        if (!heads) status = GIT_EXIT_FATAL;
    }
    if (!status) {
        for (size_t i = 0; i < n_refs; i++) {
            snprintf (heads[i].name, sizeof heads[i].name, "%s", refs[i].name);
            snprintf (heads[i].local, sizeof heads[i].local, "refs/remotes/%s/%s",
                      name, refs[i].name + 11);
            memcpy (heads[i].id, refs[i].id, 41);
        }
        n_heads = n_refs;
    }

    /* Ask for what is missing here, saying what is already here so the
       far end sends no more than it must. */
    if (!status && n_heads) {
        const char **wants = calloc (n_heads, sizeof *wants);
        char (*have_ids)[41] = NULL;
        size_t n_wants = 0, n_haves = 0;
        if (!wants || git_local_haves (ctx, &have_ids, &n_haves) < 0)
            status = GIT_EXIT_FATAL;
        for (size_t i = 0; !status && i < n_heads; i++)
            if (!bgit_odb_has (&ctx->odb, heads[i].id))
                wants[n_wants++] = heads[i].id;
        if (!status && n_wants) {
            const char **haves = calloc (n_haves ? n_haves : 1, sizeof *haves);
            if (!haves) status = GIT_EXIT_FATAL;
            for (size_t i = 0; !status && i < n_haves; i++) haves[i] = have_ids[i];
            unsigned char *pack = NULL;
            size_t pack_len = 0;
            if (!status && bgit_proto_fetch (&conn.io, wants, n_wants,
                                             haves, n_haves, &pack, &pack_len) < 0)
                status = git_far_end_gone ();
            if (!status && git_store_pack (ctx, pack, pack_len) < 0)
                status = git_fatal ("cannot store what the far end sent");
            free (pack);
            free (haves);
        }
        free (have_ids);
        free (wants);
    }
    bgit_proto_refs_release (refs, n_refs);

    int width = 10, any = 0;   /* git's own minimum for this column */
    for (size_t i = 0; !status && i < n_heads; i++) {
        char current[41] = "";
        heads[i].is_new = bgit_ref_read (&ctx->repo, heads[i].local, current) != 0;
        if (!heads[i].is_new) memcpy (heads[i].old, current, 41);
        heads[i].updated = heads[i].is_new || strcmp (current, heads[i].id);
        if (heads[i].updated) any = 1;
        int len = (int) strlen (heads[i].name + 11);
        if (len > width) width = len;
    }
    for (size_t i = 0; !status && i < n_heads; i++) {
        if (!heads[i].updated) continue;
        const char *message = heads[i].is_new ? "fetch: storing head"
                                              : "fetch: fast-forward";
        if (bgit_ref_update (&ctx->repo, heads[i].local, heads[i].id, NULL,
                             message) < 0)
            status = GIT_EXIT_FATAL;
    }
    if (!status && any && !quiet) {
        fprintf (stderr, "From %s\n", url);
        for (size_t i = 0; i < n_heads; i++) {
            if (!heads[i].updated) continue;
            char to[4096];
            snprintf (to, sizeof to, "%s/%s", name, heads[i].name + 11);
            git_report_ref (ctx, heads[i].is_new ? NULL : heads[i].old,
                            heads[i].id, heads[i].name + 11, to, width);
        }
    }
    free (heads);
    if (git_conn_close (&conn) < 0 && !status) status = git_far_end_gone ();
    return status;
}

static int
git_cmd_clone (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git clone [-q] [--bare] <source> [<directory>]";
    const char *source = NULL, *where = NULL;
    int quiet = 0, bare = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "--bare")) bare = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!source) source = w;
        else if (!where) where = w;
        else return git_usage (usage);
    }
    if (!source) return git_usage (usage);
    if (!git_can_reach (source))
        return git_fatal ("this build's git clone takes a path or an http "
                          "URL; ssh is not done yet");

    /* Where it lands: the last part of the source, without any .git. */
    char target[4096];
    if (where) snprintf (target, sizeof target, "%s", where);
    else {
        char copy[4096];
        snprintf (copy, sizeof copy, "%s", source);
        size_t len = strlen (copy);
        while (len && copy[len - 1] == '/') copy[--len] = '\0';
        if (len > 4 && !strcmp (copy + len - 4, ".git")) copy[len - 4] = '\0';
        len = strlen (copy);
        while (len && copy[len - 1] == '/') copy[--len] = '\0';
        const char *base = strrchr (copy, '/');
        snprintf (target, sizeof target, "%s", base ? base + 1 : copy);
    }
    if (!*target) return git_fatal ("cannot work out a directory name");

    char absolute[4096];
    if (git_url_is_http (source))
        snprintf (absolute, sizeof absolute, "%s", source);
    else {
        if (git_absolute (source, absolute, sizeof absolute) < 0)
            return git_fatal ("cannot work out where '%s' is", source);

        /* git looks at a local path itself before starting anything, so
           that a missing one is its own message rather than the far
           end's. A URL has no such shortcut: the far end answers. */
        bgit_repo check;
        bgit_odb check_odb;
        if (git_open_remote (absolute, &check, &check_odb) < 0)
            return git_fatal ("repository '%s' does not exist", source);
        bgit_odb_release (&check_odb);
        bgit_repo_release (&check);
    }

    /* A clone has no repository of its own yet, but there is still a
       configuration to read: what the far end wants said, and where a
       credential for it is kept. */
    bgit_config_load (&ctx->cfg, NULL, git_overrides, git_n_overrides);
    git_conn conn;
    if (git_far_end_open (&conn, ctx, absolute, NULL, 1) < 0) return GIT_EXIT_FATAL;

    /* What the far end has: its branches, its tags, and what its HEAD
       points at, which is the branch a clone checks out. */
    bgit_proto_ref *refs = NULL;
    size_t n_refs = 0;
    const char *prefixes[3] = { "refs/heads/", "refs/tags/", "HEAD" };
    if (bgit_proto_ls_refs (&conn.io, prefixes, 3, 1, 0, &refs, &n_refs) < 0) {
        git_far_end_gone ();
        git_conn_close (&conn);
        return GIT_EXIT_FATAL;
    }

    if (!quiet)
        fprintf (stderr, bare ? "Cloning into bare repository '%s'...\n"
                              : "Cloning into '%s'...\n", target);

    /* A fresh repository, then everything the far end has. */
    WORD_LIST *init = make_word_list (make_word ((char *) target), NULL);
    if (bare) init = make_word_list (make_word ("--bare"), init);
    init = make_word_list (make_word ("-q"), init);
    git_context fresh;
    memset (&fresh, 0, sizeof fresh);
    int status = git_cmd_init (&fresh, init);
    dispose_words (init);
    if (!status && chdir (target) < 0)
        status = git_fatal ("cannot enter '%s': %s", target, strerror (errno));
    bgit_config_release (&ctx->cfg);      /* the new repository has its own */
    if (!status && git_context_open (ctx) != 0) status = GIT_EXIT_FATAL;
    if (status) {
        bgit_proto_refs_release (refs, n_refs);
        git_conn_close (&conn);
        return status;
    }

    /* The branches the far end has, and where each lands here. */
    struct git_remote_ref *heads = calloc (n_refs ? n_refs : 1, sizeof *heads);
    size_t n_heads = 0;
    if (!heads) status = GIT_EXIT_FATAL;
    for (size_t i = 0; !status && i < n_refs; i++) {
        if (strncmp (refs[i].name, "refs/heads/", 11)) continue;
        snprintf (heads[n_heads].name, sizeof heads[n_heads].name, "%s",
                  refs[i].name);
        snprintf (heads[n_heads].local, sizeof heads[n_heads].local,
                  "refs/remotes/origin/%s", refs[i].name + 11);
        memcpy (heads[n_heads].id, refs[i].id, 41);
        n_heads++;
    }
    /* A bare clone is where the branches live, not a copy of somewhere
       else's: git writes them as branches and keeps no tracking refs. */
    if (bare)
        for (size_t i = 0; i < n_heads; i++)
            snprintf (heads[i].local, sizeof heads[i].local, "%s", heads[i].name);

    bgit_ref *tags = calloc (n_refs ? n_refs : 1, sizeof *tags);
    size_t n_tags = 0;
    if (!tags) status = GIT_EXIT_FATAL;
    for (size_t i = 0; !status && i < n_refs; i++) {
        if (strncmp (refs[i].name, "refs/tags/", 10)) continue;
        tags[n_tags].name = strdup (refs[i].name);
        if (!tags[n_tags].name) { status = GIT_EXIT_FATAL; break; }
        memcpy (tags[n_tags].sha, refs[i].id, 41);
        n_tags++;
    }

    /* Everything those refs reach, asked for over the connection. A
       clone has nothing yet, so it tells the far end of no haves. */
    const char **roots = calloc (n_heads + n_tags + 1, sizeof *roots);
    if (!status && !roots) status = GIT_EXIT_FATAL;
    size_t n_roots = 0;
    for (size_t i = 0; !status && i < n_heads; i++) roots[n_roots++] = heads[i].id;
    for (size_t i = 0; !status && i < n_tags; i++) roots[n_roots++] = tags[i].sha;
    if (!status && n_roots) {
        unsigned char *pack = NULL;
        size_t pack_len = 0;
        if (bgit_proto_fetch (&conn.io, roots, n_roots, NULL, 0, &pack,
                              &pack_len) < 0)
            status = git_far_end_gone ();
        if (!status && git_store_pack (ctx, pack, pack_len) < 0)
            status = git_fatal ("cannot store what the far end sent");
        free (pack);
    }
    free (roots);

    /* What the far end's HEAD names is what gets checked out. */
    char *head_ref = NULL;
    char head_id[41] = "";
    for (size_t i = 0; i < n_refs; i++) {
        if (strcmp (refs[i].name, "HEAD")) continue;
        if (refs[i].symref) head_ref = strdup (refs[i].symref);
        memcpy (head_id, refs[i].id, 41);
        break;
    }
    bgit_proto_refs_release (refs, n_refs);
    refs = NULL;
    n_refs = 0;

    char message[4096];
    snprintf (message, sizeof message, "clone: from %s", absolute);
    for (size_t i = 0; !status && i < n_heads; i++)
        if (bgit_ref_set (&ctx->repo, heads[i].local, heads[i].id, NULL) < 0)
            status = GIT_EXIT_FATAL;
    for (size_t i = 0; !status && i < n_tags; i++)
        if (bgit_ref_set (&ctx->repo, tags[i].name, tags[i].sha, NULL) < 0)
            status = GIT_EXIT_FATAL;

    char key[4096], value[4096];
    if (!status) {
        if (git_config_write (ctx, "remote.origin.url", absolute) < 0)
            status = GIT_EXIT_FATAL;
        snprintf (value, sizeof value, "+refs/heads/*:refs/remotes/origin/*");
        if (!status && !bare &&
            git_config_write (ctx, "remote.origin.fetch", value) < 0)
            status = GIT_EXIT_FATAL;
    }
    if (!status && head_ref && !strncmp (head_ref, "refs/heads/", 11)) {
        const char *branch = head_ref + 11;
        char tracking[4096];
        snprintf (tracking, sizeof tracking, "refs/remotes/origin/%s", branch);
        if (!bare && bgit_symref_write (&ctx->repo, "refs/remotes/origin/HEAD",
                                        tracking, message) < 0)
            status = GIT_EXIT_FATAL;
        snprintf (key, sizeof key, "branch.%s.remote", branch);
        if (!status && !bare && git_config_write (ctx, key, "origin") < 0)
            status = GIT_EXIT_FATAL;
        snprintf (key, sizeof key, "branch.%s.merge", branch);
        if (!status && !bare && git_config_write (ctx, key, head_ref) < 0)
            status = GIT_EXIT_FATAL;

        if (!status && *head_id) {
            char local[4096];
            snprintf (local, sizeof local, "refs/heads/%s", branch);
            /* The branch is already written where a bare clone keeps it,
               and a bare repository logs no ref updates. */
            if (!bare &&
                bgit_ref_update (&ctx->repo, local, head_id, NULL, message) < 0)
                status = GIT_EXIT_FATAL;
            if (!status && bgit_symref_write (&ctx->repo, "HEAD", local, NULL) < 0)
                status = GIT_EXIT_FATAL;
            if (!status && !bare) {
                /* The working tree and index follow. */
                struct git_state state;
                if (git_state_load (ctx, &state) < 0) status = GIT_EXIT_FATAL;
                else {
                    char tree[41];
                    if (bgit_commit_tree (&ctx->odb, head_id, tree) < 0 ||
                        bgit_checkout_tree (&ctx->repo, &ctx->odb, tree,
                                            &state.index, &state.n_index, 1,
                                            NULL) < 0 ||
                        git_index_store (ctx, state.index, state.n_index) < 0)
                        status = GIT_EXIT_FATAL;
                    bgit_reflog_append (&ctx->repo, "HEAD", NULL, head_id,
                                        message);
                    git_state_release (&state);
                }
            }
        }
    }
    free (head_ref);
    free (heads);
    bgit_refs_free (tags, n_tags);
    bgit_proto_refs_release (refs, n_refs);
    if (git_conn_close (&conn) < 0 && !status) status = git_far_end_gone ();
    if (!status && !quiet) fprintf (stderr, "done.\n");
    return status;
}

static int
git_cmd_push (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git push [-q] [-f|--force] [--delete] [--tags] "
                        "[-n|--dry-run] [-u|--set-upstream] "
                        "[--receive-pack=<command>] [<remote> | <path> "
                        "[<refspec>...]]";
    const char *name = NULL, *program = NULL;
    const char *specs[64];
    size_t n_specs = 0;
    int quiet = 0, force = 0, deleting = 0, with_tags = 0, dry_run = 0;
    int set_upstream = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "-f") || !strcmp (w, "--force")) force = 1;
        else if (!strcmp (w, "--delete") || !strcmp (w, "-d")) deleting = 1;
        else if (!strcmp (w, "--tags")) with_tags = 1;
        else if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) dry_run = 1;
        else if (!strcmp (w, "-u") || !strcmp (w, "--set-upstream")) set_upstream = 1;
        else if (!strncmp (w, "--receive-pack=", 15)) program = w + 15;
        else if (!strcmp (w, "--receive-pack") && p->next) {
            program = p->next->word->word;
            p = p->next;
        }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else if (n_specs < sizeof specs / sizeof *specs) specs[n_specs++] = w;
        else return git_fatal ("this build's git push takes fewer refspecs "
                               "than that");
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    if (!name) {
        if (!state.have_head || !state.branch) {
            git_state_release (&state);
            return git_fatal ("You are not currently on a branch.");
        }
        char key[4096];
        snprintf (key, sizeof key, "branch.%s.remote", state.branch + 11);
        const char *configured = bgit_config_get (&ctx->cfg, key);
        name = configured ? configured : "origin";
    }

    /* A name from the configuration stands for its URL; anything else is
       the path itself, which is what git accepts too. */
    const char *url = git_remote_url (ctx, name);
    int by_name = url != NULL;
    if (!url) url = name;
    if (!git_can_reach (url)) {
        git_state_release (&state);
        return git_fatal ("this build's git push takes a path or an http URL; "
                          "ssh is not done yet");
    }

    /* What to ask for: a refspec each, the tags if they were asked for,
       and the branch this end is on when nothing was named. */
    struct git_push_want *wants = NULL;
    size_t n_wants = 0, cap = 0;
    int status = 0;
    for (size_t i = 0; !status && i < n_specs; i++)
        if (git_push_want (ctx, &wants, &n_wants, &cap, specs[i], force,
                           deleting) < 0)
            status = GIT_EXIT_FATAL;
    if (!status && with_tags) {
        bgit_ref *tags = NULL;
        size_t n_tags = 0;
        if (bgit_refs_list (&ctx->repo, "refs/tags/", &tags, &n_tags) == 0) {
            for (size_t i = 0; !status && i < n_tags; i++)
                if (git_push_want (ctx, &wants, &n_wants, &cap, tags[i].name,
                                   force, 0) < 0)
                    status = GIT_EXIT_FATAL;
            bgit_refs_free (tags, n_tags);
        }
    }
    if (!status && !n_wants && !n_specs) {
        if (!state.have_head || !state.branch) {
            free (wants);
            git_state_release (&state);
            return git_fatal ("You are not currently on a branch.");
        }
        if (git_push_want (ctx, &wants, &n_wants, &cap, state.branch, force, 0) < 0)
            status = GIT_EXIT_FATAL;
    }
    if (status || !n_wants) {
        free (wants);
        git_state_release (&state);
        return status;
    }

    /* The far end is asked over the protocol, which for a push is the
       first one git spoke and the one it still uses. */
    git_conn conn;
    if (git_conn_open (&conn, ctx, url, program, "git-receive-pack") < 0) {
        free (wants);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    bgit_proto_ref *theirs = NULL;
    size_t n_theirs = 0;
    char *capabilities = NULL;
    if (bgit_proto_read_refs_v0 (conn.io.reader, &theirs, &n_theirs,
                                 &capabilities) < 0)
        status = git_far_end_gone ();

    /* What the far end holds for each of them now, which is what the push
       says it is replacing. */
    int refused_any = 0, anything = 0;
    for (size_t i = 0; !status && i < n_wants; i++) {
        struct git_push_want *want = &wants[i];
        for (size_t k = 0; k < n_theirs; k++)
            if (!strcmp (theirs[k].name, want->dst)) {
                memcpy (want->old, theirs[k].id, 41);
                break;
            }
        want->is_new = !*want->old;
        int unmaking = !strcmp (want->id, GIT_NULL_ID);
        if (unmaking && want->is_new) want->refused = "remote ref does not exist";
        else if (!unmaking && !want->is_new && !strcmp (want->old, want->id))
            continue;                              /* already where it goes */
        else if (!unmaking && !want->is_new && !want->forced) {
            /* A push may only move a ref forward unless it is forced, and
               git tells apart a tip this end has never seen from one it
               has seen but not built on. */
            if (!bgit_odb_has (&ctx->odb, want->old))
                want->refused = "fetch first";
            else if (bgit_is_ancestor (&ctx->odb, want->old, want->id) <= 0)
                want->refused = "non-fast-forward";
        }
        if (!unmaking && !want->is_new && !want->refused &&
            bgit_is_ancestor (&ctx->odb, want->old, want->id) <= 0)
            want->forced_update = 1;
        if (want->refused) refused_any = 1;
        anything = 1;
    }
    if (!status && !anything) {
        if (!quiet) fprintf (stderr, "Everything up-to-date\n");
        bgit_proto_refs_release (theirs, n_theirs);
        free (capabilities);
        free (wants);
        if (git_conn_close (&conn) < 0) status = git_far_end_gone ();
        git_state_release (&state);
        return status;
    }

    /* Saying what it would do and doing it are the same up to here. */
    if (!status && dry_run) {
        fflush (stdout);
        fprintf (stderr, "To %s\n", url);
        for (size_t i = 0; i < n_wants; i++)
            if (wants[i].refused || !wants[i].is_new || *wants[i].id)
                git_report_push (ctx, &wants[i]);
        if (refused_any)
            fprintf (stderr, "error: failed to push some refs to '%s'\n", url);
        bgit_proto_refs_release (theirs, n_theirs);
        free (capabilities);
        free (wants);
        if (git_conn_close (&conn) < 0) status = git_far_end_gone ();
        git_state_release (&state);
        return refused_any ? 1 : status;
    }

    /* The changes, with what this end can do, and then a pack holding
       everything the far end does not have yet. */
    int first = 1;
    for (size_t i = 0; !status && i < n_wants; i++) {
        struct git_push_want *want = &wants[i];
        if (want->refused) continue;
        char line[8192];
        size_t len = (size_t) snprintf (line, sizeof line, "%s %s %s",
                                        want->is_new ? GIT_NULL_ID : want->old,
                                        want->id, want->dst);
        if (first) {
            line[len++] = '\0';
            len += (size_t) snprintf (line + len, sizeof line - len,
                                      "report-status side-band-64k agent=%s",
                                      GIT_AGENT_STRING);
            first = 0;
        }
        if (bgit_proto_write (&conn.io, line, len) < 0)
            status = git_far_end_gone ();
        want->sent = 1;
    }
    if (!status && first) {
        /* Everything was refused before it was sent. */
        fflush (stdout);
        fprintf (stderr, "To %s\n", url);
        for (size_t i = 0; i < n_wants; i++)
            if (wants[i].refused) git_report_push (ctx, &wants[i]);
        fprintf (stderr, "error: failed to push some refs to '%s'\n", url);
        bgit_proto_refs_release (theirs, n_theirs);
        free (capabilities);
        free (wants);
        git_conn_close (&conn);
        git_state_release (&state);
        return 1;
    }
    if (!status && bgit_proto_flush (&conn.io) < 0) status = git_far_end_gone ();

    if (!status) {
        const char **stop = calloc (n_theirs ? n_theirs : 1, sizeof *stop);
        const char **roots = calloc (n_wants, sizeof *roots);
        size_t n_roots = 0;
        if (!stop || !roots) status = GIT_EXIT_FATAL;
        for (size_t i = 0; !status && i < n_theirs; i++) stop[i] = theirs[i].id;
        for (size_t i = 0; !status && i < n_wants; i++)
            if (wants[i].sent && strcmp (wants[i].id, GIT_NULL_ID))
                roots[n_roots++] = wants[i].id;
        char (*send)[41] = NULL;
        size_t n_send = 0;
        if (!status && bgit_reachable_objects (&ctx->odb, roots, n_roots, stop,
                                               n_theirs, &send, &n_send) < 0)
            status = GIT_EXIT_FATAL;
        free (stop);
        free (roots);
        unsigned char *pack = NULL;
        size_t pack_len = 0;
        struct bgit_pack_idx_entry *entries = NULL;
        unsigned char checksum[20];
        char checksum_hex[41] = "";
        if (!status && git_pack_build (&ctx->odb, send, n_send, &pack, &pack_len,
                                       &entries, checksum, checksum_hex) < 0)
            status = GIT_EXIT_FATAL;
        free (send);
        free (entries);
        /* The pack goes over as it is, after the commands; over HTTP the
           two together are the one request, which is sent now. */
        if (!status && (bgit_proto_raw (&conn.io, pack, pack_len) < 0 ||
                        bgit_proto_done (&conn.io) < 0))
            status = git_far_end_gone ();
        free (pack);
    }

    /* What the far end made of it: the report arrives as packets inside
       the first side-band channel, and anything it wants said goes to
       the second. */
    int unpacked = 0;
    bgit_proto_aside aside;
    memset (&aside, 0, sizeof aside);
    if (!status) {
        unsigned char *report = NULL;
        size_t report_len = 0, report_cap = 0;
        for (;;) {
            const unsigned char *data = NULL;
            int got = bgit_pkt_read (conn.io.reader, &data);
            if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
            if (got < 0) { status = git_far_end_gone (); break; }
            if (got < 1) continue;
            if (data[0] == 2 || data[0] == 3) {
                bgit_proto_aside_say (&aside, data + 1, (size_t) got - 1);
                continue;
            }
            if (bgit_pack_buf_append (&report, &report_len, &report_cap,
                                      data + 1, (size_t) got - 1) < 0) {
                status = GIT_EXIT_FATAL;
                break;
            }
        }
        bgit_pkt_reader inside;
        bgit_pkt_from_memory (&inside, report, report_len);
        for (; !status;) {
            char *line = NULL;
            int got = bgit_pkt_read_line (&inside, &line);
            if (got < 0) break;
            if (!strncmp (line, "unpack ok", 9)) unpacked = 1;
            else if (!strncmp (line, "unpack ", 7)) {
                fflush (stdout);
                fprintf (stderr, "error: remote unpack failed: %s\n", line + 7);
            }
            else if (!strncmp (line, "ng ", 3)) {
                char *why = strchr (line + 3, ' ');
                if (why) {
                    *why = '\0';
                    for (size_t i = 0; i < n_wants; i++)
                        if (!strcmp (wants[i].dst, line + 3)) {
                            wants[i].refused = strdup (why + 1);
                            wants[i].remote_refused = 1;
                            refused_any = 1;
                        }
                }
            }
            free (line);
        }
        bgit_pkt_release (&inside);
        free (report);
        bgit_proto_aside_flush (&aside);
    }
    if (!status && !unpacked)
        status = git_fatal ("the far end did not say what it did");

    if (!status && !quiet) {
        fflush (stdout);
        fprintf (stderr, "To %s\n", url);
        for (size_t i = 0; i < n_wants; i++)
            git_report_push (ctx, &wants[i]);
    }
    if (!status && refused_any) {
        fprintf (stderr, "error: failed to push some refs to '%s'\n", url);
        status = 1;
    }

    /* What went over is now what the far end has, which is worth
       recording for a remote that has a name to record it under. */
    for (size_t i = 0; status <= 1 && i < n_wants; i++) {
        struct git_push_want *want = &wants[i];
        if (want->refused || !want->sent) continue;
        if (by_name && !strncmp (want->dst, "refs/heads/", 11)) {
            char tracking[4096];
            snprintf (tracking, sizeof tracking, "refs/remotes/%s/%s", name,
                      want->dst + 11);
            if (strcmp (want->id, GIT_NULL_ID))
                bgit_ref_set (&ctx->repo, tracking, want->id, NULL);
            else bgit_ref_delete (&ctx->repo, tracking, NULL, NULL);
        }
        /* -u makes the branch follow where it was just pushed. */
        if (set_upstream && by_name && !strncmp (want->src, "refs/heads/", 11) &&
            strcmp (want->id, GIT_NULL_ID)) {
            char key[4096];
            snprintf (key, sizeof key, "branch.%s.remote", want->src + 11);
            git_config_write (ctx, key, name);
            snprintf (key, sizeof key, "branch.%s.merge", want->src + 11);
            git_config_write (ctx, key, want->dst);
            if (!quiet)
                fprintf (stderr, "branch '%s' set up to track '%s/%s'.\n",
                         want->src + 11, name, git_ref_short (want->dst));
        }
    }
    bgit_proto_refs_release (theirs, n_theirs);
    free (capabilities);
    free (wants);
    if (git_conn_close (&conn) < 0 && !status) status = git_far_end_gone ();
    git_state_release (&state);
    return status;
}

static int
git_cmd_pull (git_context *ctx, WORD_LIST *args)
{
    /* Fetch, then merge what was fetched, which is what pull is. */
    const char *usage = "git pull [<remote>]";
    const char *name = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) continue;
        if (w[0] == '-' && w[1]) return git_usage (usage);
        if (!name) name = w;
        else return git_usage (usage);
    }
    WORD_LIST *fetch_args = name
        ? make_word_list (make_word ((char *) name), NULL) : NULL;
    int status = git_cmd_fetch (ctx, fetch_args);
    dispose_words (fetch_args);
    if (status) return status;

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    if (!state.branch) {
        git_state_release (&state);
        return git_fatal ("You are not currently on a branch.");
    }
    char key[4096];
    const char *branch = state.branch + 11;
    snprintf (key, sizeof key, "branch.%s.remote", branch);
    const char *remote = bgit_config_get (&ctx->cfg, key);
    if (!remote) remote = name ? name : "origin";
    char tracking[4096];
    snprintf (tracking, sizeof tracking, "%s/%s", remote, branch);
    git_state_release (&state);

    WORD_LIST *merge_args = make_word_list (make_word (tracking), NULL);
    status = git_cmd_merge (ctx, merge_args);
    dispose_words (merge_args);
    return status;
}

/* ---- worktree ----------------------------------------------------------- */

/* What a worktree's HEAD file says. */
static void
git_worktree_head (git_context *ctx, const char *git_dir, struct git_worktree *out)
{
    char path[4096], line[4096];
    out->head[0] = out->branch[0] = '\0';
    if (snprintf (path, sizeof path, "%s/HEAD", git_dir) >= (int) sizeof path)
        return;
    FILE *file = fopen (path, "r");
    if (!file) return;
    if (fgets (line, sizeof line, file)) {
        size_t len = strlen (line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!strncmp (line, "ref: ", 5)) {
            snprintf (out->branch, sizeof out->branch, "%s", line + 5);
            char id[41];
            if (bgit_ref_read (&ctx->repo, out->branch, id) == 0)
                memcpy (out->head, id, 41);
        } else if (strlen (line) >= 40) {
            memcpy (out->head, line, 40);
            out->head[40] = '\0';
        }
    }
    fclose (file);
}

/* Every worktree of this repository: the main one first, then the linked
   ones in name order, as git lists them. */
static int
git_worktrees (git_context *ctx, struct git_worktree **out, size_t *n_out)
{
    struct git_worktree *list = calloc (64, sizeof *list);
    if (!list) return -1;
    size_t n = 0;

    /* The main worktree is the one whose git directory is the common one. */
    struct git_worktree *main_tree = &list[n++];
    main_tree->admin[0] = '\0';
    snprintf (main_tree->name, sizeof main_tree->name, "%s", "");
    char main_work[4096] = "";
    if (ctx->repo.work_tree && !strcmp (ctx->repo.git_dir, ctx->repo.common_dir))
        snprintf (main_work, sizeof main_work, "%s", ctx->repo.work_tree);
    else {
        /* Started from a linked worktree: the main one is beside the common
           directory. */
        snprintf (main_work, sizeof main_work, "%s", ctx->repo.common_dir);
        char *slash = strrchr (main_work, '/');
        if (slash) *slash = '\0';
    }
    snprintf (main_tree->path, sizeof main_tree->path, "%s", main_work);
    git_worktree_head (ctx, ctx->repo.common_dir, main_tree);

    char dir[4096];
    if (snprintf (dir, sizeof dir, "%s/worktrees", ctx->repo.common_dir) <
        (int) sizeof dir) {
        DIR *handle = opendir (dir);
        if (handle) {
            char names[64][256];
            size_t n_names = 0;
            struct dirent *entry;
            while ((entry = readdir (handle)) && n_names < 64) {
                if (entry->d_name[0] == '.') continue;
                snprintf (names[n_names++], sizeof names[0], "%s", entry->d_name);
            }
            closedir (handle);
            qsort (names, n_names, sizeof names[0], (int (*) (const void *,
                   const void *)) strcmp);
            for (size_t i = 0; i < n_names && n < 64; i++) {
                struct git_worktree *tree = &list[n];
                snprintf (tree->name, sizeof tree->name, "%s", names[i]);
                snprintf (tree->admin, sizeof tree->admin, "%s/%s", dir, names[i]);
                char gitdir[4096], line[4096];
                snprintf (gitdir, sizeof gitdir, "%s/gitdir", tree->admin);
                FILE *file = fopen (gitdir, "r");
                if (!file) continue;
                if (!fgets (line, sizeof line, file)) { fclose (file); continue; }
                fclose (file);
                size_t len = strlen (line);
                while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                /* The file names the worktree's .git; the tree is above it. */
                char *slash = strrchr (line, '/');
                if (slash) *slash = '\0';
                snprintf (tree->path, sizeof tree->path, "%s", line);
                git_worktree_head (ctx, tree->admin, tree);
                n++;
            }
        }
    }
    *out = list;
    *n_out = n;
    return 0;
}

/* Which worktree, if any, has this branch checked out. */
static const struct git_worktree *
git_worktree_holding (const struct git_worktree *list, size_t n, const char *ref)
{
    for (size_t i = 0; i < n; i++)
        if (!strcmp (list[i].branch, ref)) return &list[i];
    return NULL;
}

/* An absolute path for one that may not exist yet. */
static int
git_absolute (const char *path, char *out, size_t outsz)
{
    if (*path == '/') {
        snprintf (out, outsz, "%s", path);
        return 0;
    }
    char here[4096];
    if (!getcwd (here, sizeof here)) return -1;
    if (snprintf (out, outsz, "%s/%s", here, path) >= (int) outsz) return -1;
    /* Fold away "." and ".." so the path reads as git writes it. */
    char parts[64][256];
    size_t n = 0;
    char copy[4096];
    snprintf (copy, sizeof copy, "%s", out);
    for (char *token = strtok (copy, "/"); token; token = strtok (NULL, "/")) {
        if (!strcmp (token, ".")) continue;
        if (!strcmp (token, "..")) { if (n) n--; continue; }
        if (n < 64) snprintf (parts[n++], sizeof parts[0], "%s", token);
    }
    size_t at = 0;
    out[0] = '\0';
    for (size_t i = 0; i < n; i++)
        at += (size_t) snprintf (out + at, outsz - at, "/%s", parts[i]);
    if (!at) snprintf (out, outsz, "/");
    return 0;
}

static int
git_worktree_add (git_context *ctx, const char *where, const char *start,
                  const char *new_branch, int detach, int force)
{
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    char path[4096];
    if (git_absolute (where, path, sizeof path) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot work out where '%s' is", where);
    }
    const char *base = strrchr (path, '/');
    base = base ? base + 1 : path;
    char name[256];
    snprintf (name, sizeof name, "%s", base);

    /* What will be checked out, and under what name. */
    char branch_ref[4096] = "", id[41], commit[41];
    int creating = 0;
    if (new_branch) {
        snprintf (branch_ref, sizeof branch_ref, "refs/heads/%s", new_branch);
        creating = 1;
    } else if (start) {
        char candidate[4096];
        snprintf (candidate, sizeof candidate, "refs/heads/%s", start);
        if (!detach && bgit_ref_read (&ctx->repo, candidate, id) == 0)
            snprintf (branch_ref, sizeof branch_ref, "%s", candidate);
    } else if (!detach) {
        snprintf (branch_ref, sizeof branch_ref, "refs/heads/%s", name);
        creating = 1;
    }
    const char *from = start ? start : "HEAD";
    if (git_resolve (ctx, from, id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, commit) < 0) {
        git_state_release (&state);
        return git_fatal ("invalid reference: %s", from);
    }

    /* git says what it is preparing on stderr, and where HEAD landed on
       stdout. */
    fflush (stdout);
    if (*branch_ref) {
        const char *shown = branch_ref + 11;
        fprintf (stderr, "Preparing worktree (%s '%s')\n",
                 creating ? "new branch" : "checking out", shown);
    } else {
        char abbreviated[41];
        git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
        fprintf (stderr, "Preparing worktree (detached HEAD %s)\n", abbreviated);
    }

    struct git_worktree *trees = NULL;
    size_t n_trees = 0;
    if (git_worktrees (ctx, &trees, &n_trees) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    const struct git_worktree *holder = *branch_ref
        ? git_worktree_holding (trees, n_trees, branch_ref) : NULL;
    if (holder && !force) {
        char held[4096];
        snprintf (held, sizeof held, "%s", holder->path);
        free (trees);
        git_state_release (&state);
        return git_fatal ("'%s' is already used by worktree at '%s'",
                          branch_ref + 11, held);
    }
    for (size_t i = 0; i < n_trees; i++)
        if (!strcmp (trees[i].path, path)) {
            free (trees);
            git_state_release (&state);
            return git_fatal ("'%s' already exists", where);
        }
    free (trees);

    /* The administrative directory, then the worktree itself. */
    char admin[4096];
    if (snprintf (admin, sizeof admin, "%s/worktrees/%s", ctx->repo.common_dir,
                  name) >= (int) sizeof admin) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    char worktrees_dir[4096];
    snprintf (worktrees_dir, sizeof worktrees_dir, "%s/worktrees",
              ctx->repo.common_dir);
    if ((mkdir (worktrees_dir, 0777) < 0 && errno != EEXIST) ||
        (mkdir (admin, 0777) < 0 && errno != EEXIST) ||
        (mkdir (path, 0777) < 0 && errno != EEXIST)) {
        git_state_release (&state);
        return git_fatal ("cannot create '%s': %s", where, strerror (errno));
    }

    char file[4096], content[8192];
    FILE *out;
    snprintf (file, sizeof file, "%s/.git", path);
    out = fopen (file, "w");
    if (!out) { git_state_release (&state); return GIT_EXIT_FATAL; }
    fprintf (out, "gitdir: %s\n", admin);
    fclose (out);

    snprintf (file, sizeof file, "%s/gitdir", admin);
    out = fopen (file, "w");
    if (!out) { git_state_release (&state); return GIT_EXIT_FATAL; }
    fprintf (out, "%s/.git\n", path);
    fclose (out);

    snprintf (file, sizeof file, "%s/commondir", admin);
    out = fopen (file, "w");
    if (!out) { git_state_release (&state); return GIT_EXIT_FATAL; }
    fprintf (out, "../..\n");
    fclose (out);

    if (creating) {
        char message[1200];
        snprintf (message, sizeof message, "branch: Created from %s", from);
        if (bgit_ref_update (&ctx->repo, branch_ref, commit, "", message) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
    }
    snprintf (file, sizeof file, "%s/HEAD", admin);
    out = fopen (file, "w");
    if (!out) { git_state_release (&state); return GIT_EXIT_FATAL; }
    if (*branch_ref) fprintf (out, "ref: %s\n", branch_ref);
    else fprintf (out, "%s\n", commit);
    fclose (out);

    snprintf (file, sizeof file, "%s/ORIG_HEAD", admin);
    out = fopen (file, "w");
    if (out) { fprintf (out, "%s\n", commit); fclose (out); }

    /* Check the tree out into the new worktree, and write its index. */
    bgit_repo linked;
    memset (&linked, 0, sizeof linked);
    linked.git_dir = strdup (admin);
    linked.common_dir = strdup (ctx->repo.common_dir);
    linked.work_tree = strdup (path);
    if (!linked.git_dir || !linked.common_dir || !linked.work_tree) {
        bgit_repo_release (&linked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    /* The new worktree's own HEAD log starts the way git starts it: the
       entry that created HEAD, then the checkout that filled the tree. */
    bgit_reflog_append (&linked, "HEAD", NULL, commit, "");
    bgit_reflog_append (&linked, "HEAD", commit, commit, "reset: moving to HEAD");

    char tree[41];
    bgit_index_entry *entries = NULL;
    size_t n_entries = 0;
    int status = 0;
    if (bgit_commit_tree (&ctx->odb, commit, tree) < 0 ||
        bgit_checkout_tree (&linked, &ctx->odb, tree, &entries, &n_entries, 1,
                            NULL) < 0)
        status = GIT_EXIT_FATAL;
    if (!status) {
        char index_path[4096];
        snprintf (index_path, sizeof index_path, "%s/index", admin);
        if (n_entries > 1)
            qsort (entries, n_entries, sizeof *entries, bgit_index_path_cmp);
        if (bgit_index_write (index_path, entries, n_entries) < 0)
            status = GIT_EXIT_FATAL;
    }
    bgit_index_free_entries (entries, n_entries);
    bgit_repo_release (&linked);

    if (!status) {
        char abbreviated[41], subject[1024] = "";
        git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
        struct git_commit parsed;
        if (git_commit_read (ctx, commit, &parsed) == 0) {
            git_subject (&parsed, subject, sizeof subject);
            git_commit_release (&parsed);
        }
        printf ("HEAD is now at %s %s\n", abbreviated, subject);
    }
    (void) content;
    git_state_release (&state);
    return status;
}

/* Remove a directory and everything under it. */
static int git_remove_path (const char *full);

static int
git_worktree_remove (git_context *ctx, const char *where, int force)
{
    char path[4096];
    if (git_absolute (where, path, sizeof path) < 0)
        return git_fatal ("cannot work out where '%s' is", where);
    struct git_worktree *trees = NULL;
    size_t n_trees = 0;
    if (git_worktrees (ctx, &trees, &n_trees) < 0) return GIT_EXIT_FATAL;
    const struct git_worktree *found = NULL;
    for (size_t i = 1; i < n_trees; i++)
        if (!strcmp (trees[i].path, path)) found = &trees[i];
    if (!found) {
        free (trees);
        return git_fatal ("'%s' is not a working tree", where);
    }
    char admin[4096];
    snprintf (admin, sizeof admin, "%s", found->admin);
    free (trees);
    (void) force;
    if (git_remove_path (path) < 0 || git_remove_path (admin) < 0)
        return git_fatal ("cannot remove '%s'", where);
    return 0;
}

static int
git_cmd_worktree (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git worktree add [-b <branch>] [--detach] [-f] "
                        "<path> [<commit>] | list [--porcelain] | "
                        "remove [-f] <path> | prune";
    const char *verb = NULL, *where = NULL, *start = NULL, *new_branch = NULL;
    int porcelain = 0, detach = 0, force = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!verb) { verb = w; continue; }
        if (!strcmp (w, "--porcelain")) porcelain = 1;
        else if (!strcmp (w, "--detach")) detach = 1;
        else if (!strcmp (w, "-f") || !strcmp (w, "--force")) force = 1;
        else if (!strcmp (w, "-b") && p->next) { new_branch = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!where) where = w;
        else if (!start) start = w;
        else return git_usage (usage);
    }
    if (!verb) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;

    if (!strcmp (verb, "list")) {
        struct git_worktree *trees = NULL;
        size_t n = 0;
        if (git_worktrees (ctx, &trees, &n) < 0) return GIT_EXIT_FATAL;
        size_t width = 0;
        for (size_t i = 0; i < n; i++) {
            size_t len = strlen (trees[i].path);
            if (len > width) width = len;
        }
        for (size_t i = 0; i < n; i++) {
            char abbreviated[41];
            git_abbrev (ctx, trees[i].head, 7, abbreviated, sizeof abbreviated);
            if (porcelain) {
                printf ("worktree %s\n", trees[i].path);
                printf ("HEAD %s\n", trees[i].head);
                if (*trees[i].branch) printf ("branch %s\n", trees[i].branch);
                else printf ("detached\n");
                printf ("\n");
            } else if (*trees[i].branch) {
                const char *shown = trees[i].branch;
                if (!strncmp (shown, "refs/heads/", 11)) shown += 11;
                printf ("%-*s  %s [%s]\n", (int) width, trees[i].path,
                        abbreviated, shown);
            } else {
                printf ("%-*s  %s (detached HEAD)\n", (int) width,
                        trees[i].path, abbreviated);
            }
        }
        free (trees);
        return 0;
    }
    if (!strcmp (verb, "add")) {
        if (!where) return git_usage (usage);
        return git_worktree_add (ctx, where, start, new_branch, detach, force);
    }
    if (!strcmp (verb, "remove")) {
        if (!where) return git_usage (usage);
        return git_worktree_remove (ctx, where, force);
    }
    if (!strcmp (verb, "prune")) {
        /* An administrative directory whose worktree is gone goes too. */
        struct git_worktree *trees = NULL;
        size_t n = 0;
        if (git_worktrees (ctx, &trees, &n) < 0) return GIT_EXIT_FATAL;
        for (size_t i = 1; i < n; i++) {
            struct stat st;
            if (lstat (trees[i].path, &st) == 0) continue;
            git_remove_path (trees[i].admin);
        }
        free (trees);
        return 0;
    }
    return git_usage (usage);
}

/* ---- rebase ------------------------------------------------------------ */

/* A rebase that stops keeps its state in .git/rebase-merge, in the files
   git keeps it in and under the same names, so `git status` reads it back
   the same way whichever implementation wrote it. */
static int
git_rebase_path (git_context *ctx, const char *name, char *out, size_t outsz)
{
    return snprintf (out, outsz, "%s/rebase-merge%s%s", ctx->repo.git_dir,
                     *name ? "/" : "", name) >= (int) outsz ? -1 : 0;
}

static int
git_rebase_write (git_context *ctx, const char *name, const char *content)
{
    char path[4096];
    if (git_rebase_path (ctx, name, path, sizeof path) < 0) return -1;
    FILE *file = fopen (path, "w");
    if (!file) return -1;
    fputs (content, file);
    return fclose (file) == 0 ? 0 : -1;
}

/* One line of a state file, without its newline. */
static int
git_rebase_read (git_context *ctx, const char *name, char *out, size_t outsz)
{
    char path[4096];
    if (git_rebase_path (ctx, name, path, sizeof path) < 0) return -1;
    FILE *file = fopen (path, "r");
    if (!file) return -1;
    out[0] = '\0';
    if (!fgets (out, (int) outsz, file)) { fclose (file); return -1; }
    fclose (file);
    size_t len = strlen (out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r')) out[--len] = '\0';
    return 0;
}

/* Every line of one of the todo files, comments and blanks left out. */
static int
git_rebase_list (git_context *ctx, const char *name, char lines[][1200], int max)
{
    char path[4096];
    if (git_rebase_path (ctx, name, path, sizeof path) < 0) return 0;
    FILE *file = fopen (path, "r");
    if (!file) return 0;
    int n = 0;
    char line[1200];
    while (n < max && fgets (line, sizeof line, file)) {
        size_t len = strlen (line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!*line || *line == '#') continue;
        snprintf (lines[n++], 1200, "%s", line);
    }
    fclose (file);
    return n;
}

static int
git_rebase_in_progress (git_context *ctx)
{
    char path[4096];
    struct stat st;
    return git_rebase_path (ctx, "", path, sizeof path) == 0 &&
           lstat (path, &st) == 0 && S_ISDIR (st.st_mode);
}

static void
git_rebase_clear (git_context *ctx)
{
    static const char *const names[] = {
        "head-name", "onto", "orig-head", "msgnum", "end", "done",
        "git-rebase-todo", "interactive", "message", "stopped-sha", NULL
    };
    char path[4096];
    for (int i = 0; names[i]; i++)
        if (git_rebase_path (ctx, names[i], path, sizeof path) == 0)
            unlink (path);
    if (git_rebase_path (ctx, "", path, sizeof path) == 0) rmdir (path);
    git_remove_state_file (ctx, "REBASE_HEAD");
}

/* The line a rebase's todo list holds for one commit. */
static void
git_rebase_line (git_context *ctx, const char *commit, char *out, size_t outsz)
{
    char abbreviated[41], subject[1024] = "";
    git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
    struct git_commit parsed;
    if (git_commit_read (ctx, commit, &parsed) == 0) {
        git_subject (&parsed, subject, sizeof subject);
        git_commit_release (&parsed);
    }
    snprintf (out, outsz, "pick %s %s", abbreviated, subject);
}

/* Apply one commit onto HEAD, the way cherry-pick does. Returns 0 when it
   settled, 1 when it did not, -1 on failure. */
static int
git_rebase_apply (git_context *ctx, struct git_state *state, const char *commit,
                  int *empty)
{
    *empty = 0;
    struct git_commit picked;
    if (git_commit_read (ctx, commit, &picked) < 0) return -1;
    if (!picked.n_parents) {
        git_commit_release (&picked);
        return -1;
    }
    char parent_tree[41];
    if (bgit_commit_tree (&ctx->odb, picked.parents[0], parent_tree) < 0) {
        git_commit_release (&picked);
        return -1;
    }
    char abbreviated[41], subject[1024];
    git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
    git_subject (&picked, subject, sizeof subject);
    char label[1200];
    snprintf (label, sizeof label, "%s (%s)", abbreviated, subject);

    bgit_merge_path *paths = NULL;
    size_t n_paths = 0;
    if (bgit_merge_trees (&ctx->odb, ctx->odb.object_dirs[0], parent_tree,
                          state->head_tree, picked.tree, "HEAD", label,
                          &paths, &n_paths) < 0) {
        git_commit_release (&picked);
        return -1;
    }
    if (git_merge_safe (ctx, state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        return -1;
    }
    int conflicts = 0;
    for (size_t i = 0; i < n_paths; i++) {
        const bgit_merge_path *path = &paths[i];
        if (path->kind == BGIT_MERGE_AUTO || path->kind == BGIT_MERGE_CONTENT ||
            path->kind == BGIT_MERGE_ADD_ADD)
            printf ("Auto-merging %s\n", path->path);
        if (path->kind == BGIT_MERGE_CONTENT) {
            conflicts++;
            printf ("CONFLICT (content): Merge conflict in %s\n", path->path);
        } else if (path->kind == BGIT_MERGE_ADD_ADD) {
            conflicts++;
            printf ("CONFLICT (add/add): Merge conflict in %s\n", path->path);
        } else if (path->kind == BGIT_MERGE_MODIFY_DELETE) {
            conflicts++;
            printf ("CONFLICT (modify/delete): %s deleted in %s and modified "
                    "in %s.  Version %s of %s left in tree.\n", path->path,
                    path->deleted_in_ours ? "HEAD" : label,
                    path->deleted_in_ours ? label : "HEAD",
                    path->deleted_in_ours ? label : "HEAD", path->path);
        }
    }
    if (git_merge_apply (ctx, state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        return -1;
    }
    bgit_merge_paths_free (paths, n_paths);
    if (conflicts) {
        git_commit_release (&picked);
        return 1;
    }

    char tree[41];
    if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state->index,
                         state->n_index, tree) < 0) {
        git_commit_release (&picked);
        return -1;
    }
    if (!strcmp (tree, state->head_tree)) {
        /* Everything this commit did is already here: git drops it. */
        *empty = 1;
        git_commit_release (&picked);
        return 0;
    }
    char author[1024];
    snprintf (author, sizeof author, "%s <%s> %s", picked.author_name,
              picked.author_email, picked.author_date);
    char reflog[1200];
    snprintf (reflog, sizeof reflog, "rebase (pick): %s", subject);

    char committer[1024];
    if (bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0) {
        git_commit_release (&picked);
        return -1;
    }
    char *body = NULL;
    size_t body_len = 0;
    FILE *builder = open_memstream (&body, &body_len);
    if (!builder) { git_commit_release (&picked); return -1; }
    fprintf (builder, "tree %s\n", tree);
    fprintf (builder, "parent %s\n", state->head);
    fprintf (builder, "author %s\n", author);
    fprintf (builder, "committer %s\n", committer);
    fprintf (builder, "\n%s", picked.message);
    fclose (builder);
    char written[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                (const unsigned char *) body, body_len, 1,
                                written);
    free (body);
    git_commit_release (&picked);
    if (rc < 0) return -1;
    if (git_head_detach (ctx, state, written, reflog) < 0) return -1;
    /* HEAD has moved, so the state follows it. */
    memcpy (state->head, written, 41);
    memcpy (state->head_tree, tree, 41);
    state->have_head = 1;
    return 0;
}

/* Put the branch back where HEAD now is, and attach HEAD to it again. */
static int
git_rebase_finish (git_context *ctx, struct git_state *state,
                   const char *head_name, const char *onto, int quiet)
{
    char message[1200], branch_message[1200];
    snprintf (message, sizeof message, "rebase (finish): returning to %s",
              head_name);
    snprintf (branch_message, sizeof branch_message, "rebase (finish): %s onto %s",
              head_name, onto);
    if (bgit_ref_update (&ctx->repo, head_name, state->head, NULL,
                         branch_message) < 0 ||
        bgit_symref_write (&ctx->repo, "HEAD", head_name, NULL) < 0)
        return GIT_EXIT_FATAL;
    bgit_reflog_append (&ctx->repo, "HEAD", state->head, state->head, message);
    git_rebase_clear (ctx);
    if (!quiet) {
        fflush (stdout);
        fprintf (stderr, "Successfully rebased and updated %s.\n", head_name);
    }
    return 0;
}

static int
git_cmd_rebase (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git rebase <upstream> [<branch>] | --continue "
                        "| --abort | --skip";
    const char *upstream = NULL, *branch = NULL;
    int continue_it = 0, abort_it = 0, skip_it = 0, quiet = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--continue")) continue_it = 1;
        else if (!strcmp (w, "--abort")) abort_it = 1;
        else if (!strcmp (w, "--skip")) skip_it = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!upstream) upstream = w;
        else if (!branch) branch = w;
        else return git_usage (usage);
    }
    if (!upstream && !continue_it && !abort_it && !skip_it)
        return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    int running = git_rebase_in_progress (ctx);
    int status = 0;

    if (abort_it) {
        if (!running) {
            git_state_release (&state);
            return git_fatal ("No rebase in progress?");
        }
        char head_name[4096], orig[41];
        if (git_rebase_read (ctx, "head-name", head_name, sizeof head_name) < 0 ||
            git_rebase_read (ctx, "orig-head", orig, sizeof orig) < 0) {
            git_state_release (&state);
            return git_fatal ("cannot read the rebase state");
        }
        char tree[41];
        if (bgit_commit_tree (&ctx->odb, orig, tree) < 0 ||
            bgit_checkout_tree (&ctx->repo, &ctx->odb, tree, &state.index,
                                &state.n_index, 1, NULL) < 0 ||
            git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
        if (!status) {
            /* The branch never moved — HEAD was detached for the replay —
               so only HEAD goes back. */
            char message[1200];
            snprintf (message, sizeof message,
                      "rebase (abort): returning to %s", head_name);
            if (bgit_symref_write (&ctx->repo, "HEAD", head_name, NULL) < 0)
                status = GIT_EXIT_FATAL;
            else
                bgit_reflog_append (&ctx->repo, "HEAD", state.head, orig, message);
        }
        git_rebase_clear (ctx);
        git_state_release (&state);
        return status;
    }

    char todo[64][1200];
    int n_todo = 0, done_count = 0;
    char head_name[4096] = "", onto[41] = "", orig[41] = "";
    char done_lines[64][1200];

    if (continue_it || skip_it) {
        if (!running) {
            git_state_release (&state);
            return git_fatal ("No rebase in progress?");
        }
        if (git_rebase_read (ctx, "head-name", head_name, sizeof head_name) < 0 ||
            git_rebase_read (ctx, "onto", onto, sizeof onto) < 0 ||
            git_rebase_read (ctx, "orig-head", orig, sizeof orig) < 0) {
            git_state_release (&state);
            return git_fatal ("cannot read the rebase state");
        }
        for (size_t i = 0; i < state.n_index; i++)
            if ((state.index[i].flags >> 12) & 3) {
                git_state_release (&state);
                fflush (stdout);
                fprintf (stderr, "error: Committing is not possible because "
                                 "you have unmerged files.\n");
                fprintf (stderr, "fatal: Exiting because of an unresolved "
                                 "conflict.\n");
                return 1;
            }
        /* Finish the commit that stopped, unless it is being skipped. */
        char stopped[41];
        if (!skip_it && git_rebase_read (ctx, "stopped-sha", stopped,
                                         sizeof stopped) == 0) {
            struct git_commit picked;
            if (git_commit_read (ctx, stopped, &picked) < 0) {
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            char tree[41];
            if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                                 state.n_index, tree) < 0) {
                git_commit_release (&picked);
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            char author[1024], committer[1024], subject[1024];
            git_subject (&picked, subject, sizeof subject);
            snprintf (author, sizeof author, "%s <%s> %s", picked.author_name,
                      picked.author_email, picked.author_date);
            if (bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0) {
                git_commit_release (&picked);
                git_state_release (&state);
                return git_fatal ("cannot determine the identity to use");
            }
            char *body = NULL;
            size_t body_len = 0;
            FILE *builder = open_memstream (&body, &body_len);
            if (!builder) {
                git_commit_release (&picked);
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            fprintf (builder, "tree %s\n", tree);
            fprintf (builder, "parent %s\n", state.head);
            fprintf (builder, "author %s\n", author);
            fprintf (builder, "committer %s\n", committer);
            fprintf (builder, "\n%s", picked.message);
            fclose (builder);
            char written[41];
            int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                        (const unsigned char *) body, body_len,
                                        1, written);
            free (body);
            git_commit_release (&picked);
            if (rc < 0) {
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            char reflog[1200];
            snprintf (reflog, sizeof reflog, "rebase (continue): %s", subject);
            char old_tree[41];
            memcpy (old_tree, state.head_tree, 41);
            if (git_head_detach (ctx, &state, written, reflog) < 0) {
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            memcpy (state.head, written, 41);
            memcpy (state.head_tree, tree, 41);
            if (!quiet) {
                char abbreviated[41];
                git_abbrev (ctx, written, 7, abbreviated, sizeof abbreviated);
                printf ("[detached HEAD %s] %s\n", abbreviated, subject);
                char author_who[1024], committer_who[1024];
                git_ident_who (author, author_who, sizeof author_who);
                git_ident_who (committer, committer_who, sizeof committer_who);
                if (strcmp (author_who, committer_who))
                    printf (" Author: %s\n", author_who);
                struct git_diff_format format;
                git_diff_format_init (&format);
                format.shortstat = 1;
                format.summary = 1;
                bgit_diff_entry *entries = NULL;
                size_t n_entries = 0;
                if (bgit_diff_trees (&ctx->odb, old_tree, tree, &entries,
                                     &n_entries) == 0) {
                    git_diff_emit (ctx, stdout, &format, entries, n_entries, 0, "");
                    bgit_diff_free (entries, n_entries);
                }
            }
        }
        /* What is left to do. */
        char path[4096];
        if (git_rebase_path (ctx, "git-rebase-todo", path, sizeof path) == 0) {
            FILE *file = fopen (path, "r");
            if (file) {
                char line[1200];
                while (n_todo < 64 && fgets (line, sizeof line, file)) {
                    size_t len = strlen (line);
                    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                        line[--len] = '\0';
                    if (*line) snprintf (todo[n_todo++], sizeof todo[0], "%s", line);
                }
                fclose (file);
            }
        }
        if (git_rebase_path (ctx, "done", path, sizeof path) == 0) {
            FILE *file = fopen (path, "r");
            if (file) {
                char line[1200];
                while (done_count < 64 && fgets (line, sizeof line, file)) {
                    size_t len = strlen (line);
                    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                        line[--len] = '\0';
                    if (*line)
                        snprintf (done_lines[done_count++], sizeof done_lines[0],
                                  "%s", line);
                }
                fclose (file);
            }
        }
    } else {
        if (running) {
            git_state_release (&state);
            return git_fatal ("It seems that there is already a rebase-merge "
                              "directory");
        }
        if (branch) {
            if (git_switch_to (ctx, &state, branch, 0, 0) != 0) {
                git_state_release (&state);
                return GIT_EXIT_FATAL;
            }
            git_state_release (&state);
            if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
        }
        if (!state.have_head || !state.branch) {
            git_state_release (&state);
            return git_fatal ("You are not currently on a branch");
        }
        snprintf (head_name, sizeof head_name, "%s", state.branch);
        memcpy (orig, state.head, 41);

        char id[41];
        if (git_resolve (ctx, upstream, id, NULL) < 0 ||
            bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, onto) < 0) {
            git_state_release (&state);
            return git_fatal ("invalid upstream '%s'", upstream);
        }

        /* What this branch has that the upstream does not, oldest first. */
        const char *starts[1] = { state.head };
        const char *excludes[1] = { onto };
        char (*ordered)[41] = NULL;
        size_t n = 0;
        if (git_collect_commits (ctx, starts, 1, excludes, 1, 0, -1, &ordered,
                                 &n) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        for (size_t i = 0; i < n && n_todo < 64; i++)
            git_rebase_line (ctx, ordered[n - 1 - i], todo[n_todo++],
                             sizeof todo[0]);
        free (ordered);

        /* A branch already sitting on its upstream has nothing to replay. */
        if (bgit_is_ancestor (&ctx->odb, onto, state.head) > 0) {
            const char *shown = head_name;
            if (!strncmp (shown, "refs/heads/", 11)) shown += 11;
            printf ("Current branch %s is up to date.\n", shown);
            git_state_release (&state);
            return 0;
        }
        if (!n_todo) {
            /* Only behind: the branch moves up, reported like any rebase. */
            char tree[41];
            if (bgit_commit_tree (&ctx->odb, onto, tree) < 0 ||
                bgit_checkout_tree (&ctx->repo, &ctx->odb, tree, &state.index,
                                    &state.n_index, 0, NULL) < 0 ||
                git_index_store (ctx, state.index, state.n_index) < 0)
                status = GIT_EXIT_FATAL;
            if (!status) {
                char start_message[1200];
                snprintf (start_message, sizeof start_message,
                          "rebase (start): checkout %s", upstream);
                bgit_reflog_append (&ctx->repo, "HEAD", state.head, onto,
                                    start_message);
                memcpy (state.head, onto, 41);
                memcpy (state.head_tree, tree, 41);
                status = git_rebase_finish (ctx, &state, head_name, onto, quiet);
            }
            git_state_release (&state);
            return status;
        }

        /* Start from the upstream, with HEAD detached, as git does. */
        char tree[41];
        if (bgit_commit_tree (&ctx->odb, onto, tree) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        char *losing = NULL;
        int rc = bgit_checkout_tree (&ctx->repo, &ctx->odb, tree, &state.index,
                                     &state.n_index, 0, &losing);
        if (rc != 0) {
            fflush (stdout);
            fprintf (stderr, "error: cannot rebase: You have unstaged "
                             "changes.\n");
            free (losing);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        char start_message[1200];
        snprintf (start_message, sizeof start_message, "rebase (start): checkout %s",
                  upstream);
        if (git_index_store (ctx, state.index, state.n_index) < 0 ||
            git_head_detach (ctx, &state, onto, start_message) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        memcpy (state.head, onto, 41);
        memcpy (state.head_tree, tree, 41);

        char path[4096];
        if (git_rebase_path (ctx, "", path, sizeof path) < 0 ||
            (mkdir (path, 0777) < 0 && errno != EEXIST)) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        git_rebase_write (ctx, "head-name", "");
        git_rebase_write (ctx, "interactive", "");
    }

    /* Replay what is left, stopping at the first thing that does not settle. */
    char content[8192];
    int started_with = done_count;
    int total = done_count + n_todo;
    for (int i = 0; i < n_todo; i++) {
        char id[41];
        const char *space = strchr (todo[i], ' ');
        const char *second = space ? strchr (space + 1, ' ') : NULL;
        char name[64] = "";
        if (space && second && second - space - 1 < (int) sizeof name) {
            memcpy (name, space + 1, (size_t) (second - space - 1));
            name[second - space - 1] = '\0';
        }
        if (!*name || git_resolve (ctx, name, id, NULL) < 0) {
            git_state_release (&state);
            return git_fatal ("cannot read the rebase todo list");
        }

        fflush (stdout);
        fprintf (stderr, "Rebasing (%d/%d)\r", started_with + i + 1, total);
        int empty = 0;
        int rc = git_rebase_apply (ctx, &state, id, &empty);
        if (rc < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }

        /* Whatever happened, this command is done. */
        size_t at = 0;
        content[0] = '\0';
        for (int j = 0; j < done_count && at < sizeof content; j++)
            at += (size_t) snprintf (content + at, sizeof content - at, "%s\n",
                                     done_lines[j]);
        at += (size_t) snprintf (content + at, sizeof content - at, "%s\n", todo[i]);
        git_rebase_write (ctx, "done", content);
        if (done_count < 64)
            snprintf (done_lines[done_count++], sizeof done_lines[0], "%s", todo[i]);
        at = 0;
        content[0] = '\0';
        for (int j = i + 1; j < n_todo && at < sizeof content; j++)
            at += (size_t) snprintf (content + at, sizeof content - at, "%s\n",
                                     todo[j]);
        git_rebase_write (ctx, "git-rebase-todo", content);

        if (rc == 1) {
            char short_id[41], subject[1024] = "";
            git_abbrev (ctx, id, 7, short_id, sizeof short_id);
            struct git_commit picked;
            if (git_commit_read (ctx, id, &picked) == 0) {
                git_subject (&picked, subject, sizeof subject);
                snprintf (content, sizeof content, "%s", picked.message);
                git_rebase_write (ctx, "message", content);
                git_commit_release (&picked);
            }
            snprintf (content, sizeof content, "%s\n", id);
            git_rebase_write (ctx, "stopped-sha", content);
            git_write_state_file (ctx, "REBASE_HEAD", content);
            snprintf (content, sizeof content, "%s\n", head_name);
            git_rebase_write (ctx, "head-name", content);
            snprintf (content, sizeof content, "%s\n", onto);
            git_rebase_write (ctx, "onto", content);
            snprintf (content, sizeof content, "%s\n", orig);
            git_rebase_write (ctx, "orig-head", content);
            snprintf (content, sizeof content, "%d\n", done_count);
            git_rebase_write (ctx, "msgnum", content);
            snprintf (content, sizeof content, "%d\n", total);
            git_rebase_write (ctx, "end", content);
            git_state_release (&state);
            fflush (stdout);
            fprintf (stderr, "error: could not apply %s... %s\n", short_id,
                     subject);
            fprintf (stderr, "hint: Resolve all conflicts manually, mark them "
                             "as resolved with\n");
            fprintf (stderr, "hint: \"git add/rm <conflicted_files>\", then run "
                             "\"git rebase --continue\".\n");
            fprintf (stderr, "hint: You can instead skip this commit: run "
                             "\"git rebase --skip\".\n");
            fprintf (stderr, "hint: To abort and get back to the state before "
                             "\"git rebase\", run \"git rebase --abort\".\n");
            fprintf (stderr, "Could not apply %s... %s\n", short_id, subject);
            return 1;
        }
    }

    /* Everything replayed: the branch follows HEAD and HEAD follows it. */
    if (!*head_name &&
        git_rebase_read (ctx, "head-name", head_name, sizeof head_name) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot read the rebase state");
    }
    status = git_rebase_finish (ctx, &state, head_name, onto, quiet);
    git_state_release (&state);
    return status;
}

/* ---- stash ------------------------------------------------------------- */

/* A stash is two commits: one for the index as it stood, and one for the
   working tree, whose parents are where HEAD was and that index commit.
   The stack of them is refs/stash's own reflog, which is why stash@{2} is
   just a revision. */
static int
git_stash_commit (git_context *ctx, const char *tree, const char *const *parents,
                  int n_parents, const char *message, int newline,
                  char out[41])
{
    char author[1024], committer[1024];
    if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0 ||
        bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0)
        return git_fatal ("cannot determine the identity to use");
    char *body = NULL;
    size_t body_len = 0;
    FILE *builder = open_memstream (&body, &body_len);
    if (!builder) return -1;
    fprintf (builder, "tree %s\n", tree);
    for (int i = 0; i < n_parents; i++) fprintf (builder, "parent %s\n", parents[i]);
    fprintf (builder, "author %s\n", author);
    fprintf (builder, "committer %s\n", committer);
    /* git ends the index commit's message with a newline and the working
       tree commit's without one; the ids only match if this matches. */
    fprintf (builder, "\n%s%s", message, newline ? "\n" : "");
    fclose (builder);
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                (const unsigned char *) body, body_len, 1, out);
    free (body);
    return rc;
}

/* "On main" or, with no branch, "on (no branch)" — the words git puts in
   front of every stash message. */
static void
git_stash_where (git_context *ctx, const struct git_state *state, char *out,
                 size_t outsz)
{
    (void) ctx;
    if (state->branch && !strncmp (state->branch, "refs/heads/", 11))
        snprintf (out, outsz, "%s", state->branch + 11);
    else
        snprintf (out, outsz, "(no branch)");
}

/* The stash stack, newest first, read from refs/stash's reflog. */
static int
git_stash_entries (git_context *ctx, char ***out, size_t *n_out)
{
    char **lines = NULL;
    size_t n = 0;
    if (bgit_reflog_lines (&ctx->repo, "refs/stash", &lines, &n) < 0) {
        *out = NULL;
        *n_out = 0;
        return 0;
    }
    *out = lines;
    *n_out = n;
    return 0;
}

/* What one reflog line says: the id it recorded and the message. */
static void
git_stash_split (const char *line, char id[41], const char **message)
{
    id[0] = '\0';
    *message = "";
    const char *space = strchr (line, ' ');
    if (!space || space - line < 40) return;
    memcpy (id, space + 1, 40);
    id[40] = '\0';
    const char *tab = strchr (line, '\t');
    if (tab) *message = tab + 1;
}

static int
git_cmd_stash (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git stash [push] [-m <message>] [-q] | list | show "
                        "[-p] [<stash>] | apply [<stash>] | pop [<stash>] | "
                        "drop [<stash>] | clear";
    const char *verb = "push", *message = NULL, *which = NULL;
    int quiet = 0, patch = 0, stat_only = 0;
    int first = 1;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (first && (!strcmp (w, "push") || !strcmp (w, "save") ||
                      !strcmp (w, "list") || !strcmp (w, "show") ||
                      !strcmp (w, "apply") || !strcmp (w, "pop") ||
                      !strcmp (w, "drop") || !strcmp (w, "clear"))) {
            verb = !strcmp (w, "save") ? "push" : w;
            first = 0;
            continue;
        }
        first = 0;
        if (!strcmp (w, "-m") && p->next) { message = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "-p") || !strcmp (w, "--patch")) patch = 1;
        else if (!strcmp (w, "--stat")) stat_only = 1;
        else if (!strcmp (w, "-u") || !strcmp (w, "--include-untracked"))
            return git_fatal ("this build's git stash cannot keep untracked "
                              "files yet");
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!which) which = w;
        else return git_usage (usage);
    }
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    int status = 0;

    if (!strcmp (verb, "list")) {
        char **lines = NULL;
        size_t n = 0;
        git_stash_entries (ctx, &lines, &n);
        for (size_t i = 0; i < n; i++) {
            char id[41];
            const char *text = "";
            git_stash_split (lines[n - 1 - i], id, &text);
            printf ("stash@{%zu}: %s\n", i, text);
        }
        for (size_t i = 0; i < n; i++) free (lines[i]);
        free (lines);
        git_state_release (&state);
        return 0;
    }

    if (!strcmp (verb, "clear")) {
        char log_path[4096], existing[41];
        /* Clearing nothing is not an error, and says nothing. */
        if (bgit_ref_read (&ctx->repo, "refs/stash", existing) == 0)
            bgit_ref_delete (&ctx->repo, "refs/stash", NULL, NULL);
        if (snprintf (log_path, sizeof log_path, "%s/logs/refs/stash",
                      ctx->repo.common_dir) < (int) sizeof log_path)
            unlink (log_path);
        git_state_release (&state);
        return 0;
    }

    if (!strcmp (verb, "push")) {
        if (!state.have_head) {
            git_state_release (&state);
            return git_fatal ("You do not have the initial commit yet");
        }
        /* Nothing changed means nothing to save. */
        bgit_diff_entry *changes = NULL;
        size_t n_changes = 0;
        bgit_index_entry *head_entries = NULL;
        size_t n_head = 0;
        if (bgit_read_tree (&ctx->odb, state.head_tree, &head_entries, &n_head) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        bgit_index_entry *working = NULL;
        size_t n_working = 0;
        if (bgit_worktree_entries (&ctx->repo, &ctx->odb, ctx->odb.object_dirs[0],
                                   state.index, state.n_index, &working,
                                   &n_working) < 0 ||
            bgit_diff_entries (head_entries, n_head, working, n_working,
                               &changes, &n_changes) < 0) {
            bgit_index_free_entries (head_entries, n_head);
            bgit_index_free_entries (working, n_working);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        int dirty = n_changes > 0;
        bgit_diff_free (changes, n_changes);
        if (!dirty) {
            bgit_index_free_entries (head_entries, n_head);
            bgit_index_free_entries (working, n_working);
            git_state_release (&state);
            printf ("No local changes to save\n");
            return 0;
        }

        char branch[256];
        git_stash_where (ctx, &state, branch, sizeof branch);
        struct git_commit head_commit;
        char head_subject[1024] = "", head_short[41];
        if (git_commit_read (ctx, state.head, &head_commit) == 0) {
            git_subject (&head_commit, head_subject, sizeof head_subject);
            git_commit_release (&head_commit);
        }
        git_abbrev (ctx, state.head, 7, head_short, sizeof head_short);

        /* The index as it stands, then the working tree over it. */
        char index_tree[41], work_tree[41];
        if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                             state.n_index, index_tree) < 0 ||
            bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], working,
                             n_working, work_tree) < 0) {
            bgit_index_free_entries (head_entries, n_head);
            bgit_index_free_entries (working, n_working);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        char index_message[1200], work_message[1200];
        snprintf (index_message, sizeof index_message, "index on %s: %s %s",
                  branch, head_short, head_subject);
        if (message)
            snprintf (work_message, sizeof work_message, "On %s: %s", branch,
                      message);
        else
            snprintf (work_message, sizeof work_message, "WIP on %s: %s %s",
                      branch, head_short, head_subject);

        char index_commit[41], work_commit[41];
        const char *index_parents[1] = { state.head };
        if (git_stash_commit (ctx, index_tree, index_parents, 1, index_message,
                              1, index_commit) < 0) {
            bgit_index_free_entries (head_entries, n_head);
            bgit_index_free_entries (working, n_working);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        const char *work_parents[2] = { state.head, index_commit };
        if (git_stash_commit (ctx, work_tree, work_parents, 2, work_message,
                              0, work_commit) < 0) {
            bgit_index_free_entries (head_entries, n_head);
            bgit_index_free_entries (working, n_working);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        if (bgit_ref_update (&ctx->repo, "refs/stash", work_commit, NULL,
                             work_message) < 0)
            status = GIT_EXIT_FATAL;

        /* The working tree and index go back to HEAD; untracked files stay. */
        if (!status &&
            (bgit_checkout_tree (&ctx->repo, &ctx->odb, state.head_tree,
                                 &state.index, &state.n_index, 1, NULL) < 0 ||
             git_index_store (ctx, state.index, state.n_index) < 0))
            status = GIT_EXIT_FATAL;
        /* Putting the tree back is a hard reset, and HEAD's log says so. */
        if (!status)
            bgit_reflog_append (&ctx->repo, "HEAD", state.head, state.head,
                                "reset: moving to HEAD");
        bgit_index_free_entries (head_entries, n_head);
        bgit_index_free_entries (working, n_working);
        if (!status && !quiet)
            printf ("Saved working directory and index state %s\n", work_message);
        git_state_release (&state);
        return status;
    }

    /* The rest work on one entry of the stack. */
    char **lines = NULL;
    size_t n_lines = 0;
    git_stash_entries (ctx, &lines, &n_lines);
    if (!n_lines) {
        free (lines);
        git_state_release (&state);
        return git_fatal ("No stash entries found.");
    }
    size_t wanted = 0;
    if (which) {
        const char *brace = strstr (which, "@{");
        if (brace) wanted = (size_t) strtoul (brace + 2, NULL, 10);
        else if (git_all_digits (which)) wanted = (size_t) strtoul (which, NULL, 10);
    }
    if (wanted >= n_lines) {
        for (size_t i = 0; i < n_lines; i++) free (lines[i]);
        free (lines);
        git_state_release (&state);
        return git_fatal ("%s is not a valid reference",
                          which ? which : "stash@{0}");
    }
    char stash_id[41];
    const char *stash_message = "";
    git_stash_split (lines[n_lines - 1 - wanted], stash_id, &stash_message);
    char kept_message[1200];
    snprintf (kept_message, sizeof kept_message, "%s", stash_message);
    for (size_t i = 0; i < n_lines; i++) free (lines[i]);
    free (lines);

    struct git_commit stash;
    if (git_commit_read (ctx, stash_id, &stash) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    if (!strcmp (verb, "show")) {
        char base_tree[41] = "";
        if (stash.n_parents &&
            bgit_commit_tree (&ctx->odb, stash.parents[0], base_tree) < 0) {
            git_commit_release (&stash);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        bgit_diff_entry *entries = NULL;
        size_t n = 0;
        if (bgit_diff_trees (&ctx->odb, stash.n_parents ? base_tree : NULL,
                             stash.tree, &entries, &n) < 0) {
            git_commit_release (&stash);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        struct git_diff_format format;
        git_diff_format_init (&format);
        if (patch) format.patch = 1;
        else format.stat = 1;
        (void) stat_only;
        git_diff_emit (ctx, stdout, &format, entries, n, 0, "");
        bgit_diff_free (entries, n);
        git_commit_release (&stash);
        git_state_release (&state);
        return 0;
    }

    if (!strcmp (verb, "drop")) {
        if (bgit_reflog_drop (&ctx->repo, "refs/stash", wanted) < 0)
            status = GIT_EXIT_FATAL;
        if (!status && !quiet)
            printf ("Dropped refs/stash@{%zu} (%s)\n", wanted, stash_id);
        git_commit_release (&stash);
        git_state_release (&state);
        return status;
    }

    if (strcmp (verb, "apply") && strcmp (verb, "pop")) {
        git_commit_release (&stash);
        git_state_release (&state);
        return git_usage (usage);
    }

    /* Applying is a three-way merge: what the stash changed against where
       it was taken, brought onto what is here now. */
    char base_tree[41] = "", our_tree[41];
    if ((stash.n_parents &&
         bgit_commit_tree (&ctx->odb, stash.parents[0], base_tree) < 0) ||
        bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                         state.n_index, our_tree) < 0) {
        git_commit_release (&stash);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    bgit_merge_path *paths = NULL;
    size_t n_paths = 0;
    if (bgit_merge_trees (&ctx->odb, ctx->odb.object_dirs[0],
                          stash.n_parents ? base_tree : NULL, our_tree,
                          stash.tree, "Updated upstream", "Stashed changes",
                          &paths, &n_paths) < 0) {
        git_commit_release (&stash);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (git_merge_safe (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&stash);
        git_state_release (&state);
        return 1;
    }
    int conflicts = 0;
    for (size_t i = 0; i < n_paths; i++) {
        const bgit_merge_path *path = &paths[i];
        if (path->kind == BGIT_MERGE_AUTO || path->kind == BGIT_MERGE_CONTENT ||
            path->kind == BGIT_MERGE_ADD_ADD)
            printf ("Auto-merging %s\n", path->path);
        if (path->kind == BGIT_MERGE_CONTENT) {
            conflicts++;
            printf ("CONFLICT (content): Merge conflict in %s\n", path->path);
        } else if (path->kind == BGIT_MERGE_ADD_ADD) {
            conflicts++;
            printf ("CONFLICT (add/add): Merge conflict in %s\n", path->path);
        } else if (path->kind == BGIT_MERGE_MODIFY_DELETE) {
            conflicts++;
            printf ("CONFLICT (modify/delete): %s deleted in %s and modified "
                    "in %s.  Version %s of %s left in tree.\n", path->path,
                    path->deleted_in_ours ? "Updated upstream" : "Stashed changes",
                    path->deleted_in_ours ? "Stashed changes" : "Updated upstream",
                    path->deleted_in_ours ? "Stashed changes" : "Updated upstream",
                    path->path);
        }
    }
    if (git_merge_apply (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&stash);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    /* Without --index the changes come back unstaged: a path HEAD knows is
       put back as HEAD has it, and only what HEAD never had stays staged. */
    if (!conflicts) {
        bgit_index_entry *head_entries = NULL;
        size_t n_head = 0;
        if (bgit_read_tree (&ctx->odb, state.head_tree, &head_entries,
                            &n_head) == 0) {
            for (size_t i = 0; i < state.n_index; i++) {
                for (size_t j = 0; j < n_head; j++) {
                    if (strcmp (state.index[i].path, head_entries[j].path)) continue;
                    memcpy (state.index[i].sha, head_entries[j].sha, 20);
                    state.index[i].mode = head_entries[j].mode;
                    break;
                }
            }
            bgit_index_free_entries (head_entries, n_head);
            if (git_index_store (ctx, state.index, state.n_index) < 0)
                status = GIT_EXIT_FATAL;
        }
    }

    if (!status && !quiet) {
        bgit_status_entry *entries = NULL;
        size_t n = 0;
        struct git_state fresh;
        if (git_state_load (ctx, &fresh) == 0) {
            if (bgit_status (&ctx->repo, &ctx->odb, &ctx->cfg, fresh.index,
                             fresh.n_index, fresh.have_head ? fresh.head_tree : NULL,
                             0, 0, 1, &entries, &n) == 0) {
                const char *branch_name = fresh.branch;
                if (branch_name && !strncmp (branch_name, "refs/heads/", 11))
                    branch_name += 11;
                git_status_long (ctx, &fresh, entries, n, branch_name, 0, 0);
                bgit_status_free (entries, n);
            }
            git_state_release (&fresh);
        }
    }

    if (!conflicts && !strcmp (verb, "pop")) {
        if (bgit_reflog_drop (&ctx->repo, "refs/stash", wanted) < 0)
            status = GIT_EXIT_FATAL;
        else if (!quiet)
            printf ("Dropped refs/stash@{%zu} (%s)\n", wanted, stash_id);
    }
    bgit_merge_paths_free (paths, n_paths);
    git_commit_release (&stash);
    git_state_release (&state);
    return status ? status : (conflicts ? 1 : 0);
}

/* ---- cherry-pick and revert -------------------------------------------- */

/* The summary a picked or reverted commit prints: where it landed, who
   wrote it and when, then what it changed. */
static void
git_pick_summary (git_context *ctx, const struct git_state *state,
                  const char *commit, const char *subject, const char *author,
                  const char *committer, const char *author_date,
                  const char *old_tree, const char *new_tree)
{
    char abbreviated[41];
    git_abbrev (ctx, commit, 7, abbreviated, sizeof abbreviated);
    const char *branch = state->branch && !strncmp (state->branch, "refs/heads/", 11)
                         ? state->branch + 11 : NULL;
    printf ("[%s %s] %s\n", branch ? branch : "detached HEAD", abbreviated,
            subject);
    char author_who[1024], committer_who[1024];
    git_ident_who (author, author_who, sizeof author_who);
    git_ident_who (committer, committer_who, sizeof committer_who);
    if (strcmp (author_who, committer_who))
        printf (" Author: %s\n", author_who);
    char shown[128];
    git_format_date (author_date, 0, shown, sizeof shown);
    printf (" Date: %s\n", shown);

    struct git_diff_format format;
    git_diff_format_init (&format);
    format.shortstat = 1;
    format.summary = 1;
    bgit_diff_entry *entries = NULL;
    size_t n = 0;
    if (bgit_diff_trees (&ctx->odb, old_tree, new_tree, &entries, &n) == 0) {
        git_diff_emit (ctx, stdout, &format, entries, n, 0, "");
        bgit_diff_free (entries, n);
    }
}

/* Write the commit a pick or a revert makes, move the branch, and say so. */
static int
git_pick_commit (git_context *ctx, struct git_state *state, const char *tree,
                 const char *message, const char *author, const char *subject,
                 int reverting, int quiet)
{
    char committer[1024];
    if (bgit_ident (&ctx->cfg, 1, committer, sizeof committer) < 0)
        return git_fatal ("cannot determine the identity to use");
    char *body = NULL;
    size_t body_len = 0;
    FILE *builder = open_memstream (&body, &body_len);
    if (!builder) return GIT_EXIT_FATAL;
    fprintf (builder, "tree %s\n", tree);
    fprintf (builder, "parent %s\n", state->head);
    fprintf (builder, "author %s\n", author);
    fprintf (builder, "committer %s\n", committer);
    fprintf (builder, "\n%s", message);
    if (!*message || message[strlen (message) - 1] != '\n')
        fprintf (builder, "\n");
    fclose (builder);

    char commit[41];
    int rc = bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                (const unsigned char *) body, body_len, 1, commit);
    free (body);
    if (rc < 0) return GIT_EXIT_FATAL;

    char reflog[1200];
    snprintf (reflog, sizeof reflog, "%s: %s",
              reverting ? "revert" : "cherry-pick", subject);
    const char *ref = state->branch ? state->branch : "HEAD";
    char old_tree[41];
    memcpy (old_tree, state->head_tree, 41);
    if (bgit_ref_update (&ctx->repo, ref, commit, state->head, reflog) < 0)
        return GIT_EXIT_FATAL;
    if (state->branch)
        bgit_reflog_append (&ctx->repo, "HEAD", state->head, commit, reflog);
    if (!quiet) {
        /* The date the summary shows is the author's, which a pick keeps. */
        const char *date = strrchr (author, '>');
        git_pick_summary (ctx, state, commit, subject, author, committer,
                          date ? date + 2 : "", old_tree, tree);
    }
    return 0;
}

/* cherry-pick and revert are the same operation with the sides swapped:
   both take the change one commit made against its parent and merge it
   into HEAD, one forwards and one backwards. */
static int
git_cmd_pick (git_context *ctx, WORD_LIST *args, int reverting)
{
    const char *usage = reverting
        ? "git revert [--no-edit] [-n] <commit> | --continue | --abort"
        : "git cherry-pick [-n] <commit> | --continue | --abort";
    const char *name = NULL;
    int abort_it = 0, continue_it = 0, no_commit = 0, quiet = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "--abort")) abort_it = 1;
        else if (!strcmp (w, "--continue")) continue_it = 1;
        else if (!strcmp (w, "-n") || !strcmp (w, "--no-commit")) no_commit = 1;
        else if (!strcmp (w, "--no-edit")) ;      /* nothing here edits */
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (!name) name = w;
        else return git_fatal ("this build's git %s takes one commit",
                               reverting ? "revert" : "cherry-pick");
    }
    if (!name && !abort_it && !continue_it) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    const char *head_file = reverting ? "REVERT_HEAD" : "CHERRY_PICK_HEAD";
    const char *verb = reverting ? "revert" : "cherry-pick";
    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    char pending[41];
    int in_progress = git_read_state_id (ctx, head_file, pending);
    int status = 0;

    if (abort_it) {
        if (!in_progress) {
            git_state_release (&state);
            return git_fatal ("no %s in progress", verb);
        }
        if (bgit_checkout_tree (&ctx->repo, &ctx->odb, state.head_tree,
                                &state.index, &state.n_index, 1, NULL) < 0 ||
            git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
        if (!status) {
            char reflog[1200];
            snprintf (reflog, sizeof reflog, "reset: moving to %s", state.head);
            bgit_reflog_append (&ctx->repo, "HEAD", state.head, state.head, reflog);
        }
        git_remove_state_file (ctx, head_file);
        git_remove_state_file (ctx, "MERGE_MSG");
        git_state_release (&state);
        return status;
    }

    if (continue_it) {
        if (!in_progress) {
            git_state_release (&state);
            return git_fatal ("no %s in progress", verb);
        }
        for (size_t i = 0; i < state.n_index; i++)
            if ((state.index[i].flags >> 12) & 3) {
                git_state_release (&state);
                fflush (stdout);
                fprintf (stderr, "error: Committing is not possible because "
                                 "you have unmerged files.\n");
                fprintf (stderr, "fatal: Exiting because of an unresolved "
                                 "conflict.\n");
                return 1;
            }
        struct git_commit picked;
        if (git_commit_read (ctx, pending, &picked) < 0) {
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        char tree[41];
        if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                             state.n_index, tree) < 0) {
            git_commit_release (&picked);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        /* The message was left in MERGE_MSG when the pick stopped. */
        char message_path[4096];
        unsigned char *message = NULL;
        size_t message_len = 0;
        if (git_state_file (ctx, "MERGE_MSG", message_path,
                            sizeof message_path) < 0 ||
            bgit_slurp_file (message_path, &message, &message_len) < 0) {
            git_commit_release (&picked);
            git_state_release (&state);
            return git_fatal ("cannot read the message left by the %s", verb);
        }
        char author[1024];
        if (reverting) {
            if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0) {
                free (message);
                git_commit_release (&picked);
                git_state_release (&state);
                return git_fatal ("cannot determine the identity to use");
            }
        } else {
            snprintf (author, sizeof author, "%s <%s> %s", picked.author_name,
                      picked.author_email, picked.author_date);
        }
        char subject[1024];
        const char *nl = memchr (message, '\n', message_len);
        size_t take = nl ? (size_t) (nl - (const char *) message) : message_len;
        if (take >= sizeof subject) take = sizeof subject - 1;
        memcpy (subject, message, take);
        subject[take] = '\0';

        /* The reflog of a concluded pick says the commit concluded it. */
        char reflog[1200];
        snprintf (reflog, sizeof reflog, "commit (%s): %s", verb, subject);
        char committer[1024];
        char *body = NULL;
        size_t body_len = 0;
        FILE *builder = NULL;
        if (bgit_ident (&ctx->cfg, 1, committer, sizeof committer) == 0 &&
            (builder = open_memstream (&body, &body_len)) != NULL) {
            fprintf (builder, "tree %s\n", tree);
            fprintf (builder, "parent %s\n", state.head);
            fprintf (builder, "author %s\n", author);
            fprintf (builder, "committer %s\n", committer);
            fprintf (builder, "\n%.*s", (int) message_len, (const char *) message);
            fclose (builder);
        }
        free (message);
        char commit[41];
        if (!body || bgit_write_object (ctx->odb.object_dirs[0], "commit",
                                        (const unsigned char *) body, body_len,
                                        1, commit) < 0) {
            free (body);
            git_commit_release (&picked);
            git_state_release (&state);
            return GIT_EXIT_FATAL;
        }
        free (body);
        const char *ref = state.branch ? state.branch : "HEAD";
        char old_tree[41];
        memcpy (old_tree, state.head_tree, 41);
        if (bgit_ref_update (&ctx->repo, ref, commit, state.head, reflog) < 0)
            status = GIT_EXIT_FATAL;
        if (!status && state.branch)
            bgit_reflog_append (&ctx->repo, "HEAD", state.head, commit, reflog);
        if (!status && !quiet) {
            const char *date = strrchr (author, '>');
            git_pick_summary (ctx, &state, commit, subject, author, committer,
                              date ? date + 2 : "", old_tree, tree);
        }
        git_remove_state_file (ctx, head_file);
        git_remove_state_file (ctx, "MERGE_MSG");
        git_commit_release (&picked);
        git_state_release (&state);
        return status;
    }

    if (in_progress) {
        git_state_release (&state);
        return git_fatal ("a %s is already in progress", verb);
    }
    if (!state.have_head) {
        git_state_release (&state);
        return git_fatal ("cannot %s onto an empty history", verb);
    }
    for (size_t i = 0; i < state.n_index; i++)
        if ((state.index[i].flags >> 12) & 3) {
            git_state_release (&state);
            return git_fatal ("cannot %s: your index contains unmerged files",
                              verb);
        }

    char id[41], target[41];
    if (git_resolve (ctx, name, id, NULL) < 0 ||
        bgit_peel_to_type (&ctx->odb, id, BGIT_COMMIT, target) < 0) {
        git_state_release (&state);
        return git_fatal_ambiguous (name);
    }
    struct git_commit picked;
    if (git_commit_read (ctx, target, &picked) < 0) {
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (!picked.n_parents) {
        git_commit_release (&picked);
        git_state_release (&state);
        return git_fatal ("commit %s is a root commit", target);
    }
    if (picked.n_parents > 1) {
        git_commit_release (&picked);
        git_state_release (&state);
        return git_fatal ("commit %s is a merge but no -m option was given",
                          target);
    }
    char parent_tree[41];
    if (bgit_commit_tree (&ctx->odb, picked.parents[0], parent_tree) < 0) {
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    char subject[1024];
    git_subject (&picked, subject, sizeof subject);
    char abbreviated[41];
    git_abbrev (ctx, target, 7, abbreviated, sizeof abbreviated);

    /* Forwards, the commit's own tree is what is wanted; backwards, its
       parent's is, and the commit itself becomes the base. */
    const char *base_tree = reverting ? picked.tree : parent_tree;
    const char *their_tree = reverting ? parent_tree : picked.tree;
    char their_label[1200];
    if (reverting)
        snprintf (their_label, sizeof their_label, "parent of %s (%s)",
                  abbreviated, subject);
    else
        snprintf (their_label, sizeof their_label, "%s (%s)", abbreviated,
                  subject);

    bgit_merge_path *paths = NULL;
    size_t n_paths = 0;
    if (bgit_merge_trees (&ctx->odb, ctx->odb.object_dirs[0], base_tree,
                          state.head_tree, their_tree, "HEAD", their_label,
                          &paths, &n_paths) < 0) {
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (git_merge_safe (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    int conflicts = 0;
    for (size_t i = 0; i < n_paths; i++) {
        const bgit_merge_path *path = &paths[i];
        if (path->kind == BGIT_MERGE_AUTO || path->kind == BGIT_MERGE_CONTENT ||
            path->kind == BGIT_MERGE_ADD_ADD)
            printf ("Auto-merging %s\n", path->path);
        switch (path->kind) {
        case BGIT_MERGE_CONTENT:
            conflicts++;
            printf ("CONFLICT (content): Merge conflict in %s\n", path->path);
            break;
        case BGIT_MERGE_ADD_ADD:
            conflicts++;
            printf ("CONFLICT (add/add): Merge conflict in %s\n", path->path);
            break;
        case BGIT_MERGE_MODIFY_DELETE:
            conflicts++;
            printf ("CONFLICT (modify/delete): %s deleted in %s and modified "
                    "in %s.  Version %s of %s left in tree.\n", path->path,
                    path->deleted_in_ours ? "HEAD" : their_label,
                    path->deleted_in_ours ? their_label : "HEAD",
                    path->deleted_in_ours ? their_label : "HEAD", path->path);
            break;
        default:
            break;
        }
    }
    if (git_merge_apply (ctx, &state, paths, n_paths) < 0) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }

    /* The message the commit will carry, whichever way this went. */
    char *message = NULL;
    size_t message_len = 0;
    FILE *builder = open_memstream (&message, &message_len);
    if (!builder) {
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (reverting)
        fprintf (builder, "Revert \"%s\"\n\nThis reverts commit %s.\n", subject,
                 target);
    else
        fprintf (builder, "%s", picked.message);
    fclose (builder);
    char new_subject[1024];
    if (reverting) snprintf (new_subject, sizeof new_subject, "Revert \"%s\"",
                             subject);
    else snprintf (new_subject, sizeof new_subject, "%s", subject);

    if (conflicts) {
        char content[128];
        snprintf (content, sizeof content, "%s\n", target);
        git_write_state_file (ctx, head_file, content);
        git_write_state_file (ctx, "MERGE_MSG", message);
        free (message);
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        fflush (stdout);
        /* git says "apply" when picking and "revert" when reverting. */
        fprintf (stderr, "error: could not %s %s... %s\n",
                 reverting ? "revert" : "apply", abbreviated, subject);
        fprintf (stderr, "hint: After resolving the conflicts, mark them with\n");
        fprintf (stderr, "hint: \"git add/rm <pathspec>\", then run\n");
        fprintf (stderr, "hint: \"git %s --continue\".\n", verb);
        fprintf (stderr, "hint: You can instead skip this commit with "
                         "\"git %s --skip\".\n", verb);
        fprintf (stderr, "hint: To abort and get back to the state before "
                         "\"git %s\",\n", verb);
        fprintf (stderr, "hint: run \"git %s --abort\".\n", verb);
        return 1;
    }

    char tree[41];
    if (bgit_write_tree (&ctx->odb, ctx->odb.object_dirs[0], state.index,
                         state.n_index, tree) < 0) {
        free (message);
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    if (no_commit) {
        char content[128];
        snprintf (content, sizeof content, "%s\n", target);
        git_write_state_file (ctx, head_file, content);
        git_write_state_file (ctx, "MERGE_MSG", message);
        free (message);
        bgit_merge_paths_free (paths, n_paths);
        git_commit_release (&picked);
        git_state_release (&state);
        return 0;
    }

    char author[1024];
    if (reverting) {
        if (bgit_ident (&ctx->cfg, 0, author, sizeof author) < 0) {
            free (message);
            bgit_merge_paths_free (paths, n_paths);
            git_commit_release (&picked);
            git_state_release (&state);
            return git_fatal ("cannot determine the identity to use");
        }
    } else {
        snprintf (author, sizeof author, "%s <%s> %s", picked.author_name,
                  picked.author_email, picked.author_date);
    }
    status = git_pick_commit (ctx, &state, tree, message, author, new_subject,
                              reverting, quiet);
    free (message);
    bgit_merge_paths_free (paths, n_paths);
    git_commit_release (&picked);
    git_state_release (&state);
    return status;
}

static int
git_cmd_cherry_pick (git_context *ctx, WORD_LIST *args)
{
    return git_cmd_pick (ctx, args, 0);
}

static int
git_cmd_revert (git_context *ctx, WORD_LIST *args)
{
    return git_cmd_pick (ctx, args, 1);
}

/* ---- merge-file -------------------------------------------------------- */

static int
git_cmd_merge_file (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git merge-file [-p] [-q] [-L <label>]... "
                        "<current> <base> <other>";
    int to_stdout = 0, quiet = 0;
    const char *labels[3] = { NULL, NULL, NULL };
    int n_labels = 0;
    const char *files[3];
    int n_files = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-p") || !strcmp (w, "--stdout")) to_stdout = 1;
        else if (!strcmp (w, "-q") || !strcmp (w, "--quiet")) quiet = 1;
        else if (!strcmp (w, "-L") && p->next) {
            if (n_labels < 3) labels[n_labels++] = p->next->word->word;
            p = p->next;
        }
        else if (w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_files < 3) files[n_files++] = w;
        else return git_usage (usage);
    }
    if (n_files != 3) return git_usage (usage);
    (void) ctx;

    unsigned char *content[3] = { NULL, NULL, NULL };
    size_t sizes[3] = { 0, 0, 0 };
    for (int i = 0; i < 3; i++)
        if (bgit_slurp_file (files[i], &content[i], &sizes[i]) < 0) {
            for (int j = 0; j < i; j++) free (content[j]);
            return git_fatal ("Could not open '%s' for reading", files[i]);
        }

    bgit_merge_result merged;
    int rc = bgit_merge_content ((const char *) content[1], sizes[1],
                                 (const char *) content[0], sizes[0],
                                 (const char *) content[2], sizes[2],
                                 labels[0] ? labels[0] : files[0],
                                 labels[2] ? labels[2] : files[2],
                                 &merged);
    for (int i = 0; i < 3; i++) free (content[i]);
    if (rc < 0) return GIT_EXIT_FATAL;

    if (to_stdout) {
        fwrite (merged.text, 1, merged.len, stdout);
    } else {
        FILE *out = fopen (files[0], "w");
        if (!out) {
            free (merged.text);
            return git_fatal ("Could not open '%s' for writing", files[0]);
        }
        fwrite (merged.text, 1, merged.len, out);
        if (fclose (out) != 0) {
            free (merged.text);
            return git_fatal ("Could not write '%s'", files[0]);
        }
    }
    int conflicts = merged.conflicts;
    free (merged.text);
    (void) quiet;
    /* git exits with the number of conflicts, up to 127. */
    return conflicts > 127 ? 127 : conflicts;
}

/* ---- mv and clean ------------------------------------------------------ */

/* Move one tracked path in the index, keeping everything else about it. */
static int
git_index_rename (struct git_state *state, const char *from, const char *to)
{
    for (size_t i = 0; i < state->n_index; i++) {
        if (strcmp (state->index[i].path, from)) continue;
        char *path = strdup (to);
        if (!path) return -1;
        free (state->index[i].path);
        state->index[i].path = path;
        size_t len = strlen (to);
        state->index[i].flags = (uint16_t) ((state->index[i].flags & ~0xFFF) |
                                            (len > 0xFFF ? 0xFFF : len));
        return 0;
    }
    return -1;
}

/* Every directory above PATH, created as needed, as git creates them. */
static int
git_mkdirs_for (const char *path)
{
    char buf[4096];
    if (snprintf (buf, sizeof buf, "%s", path) >= (int) sizeof buf) return -1;
    char *slash = strrchr (buf, '/');
    if (!slash) return 0;
    *slash = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir (buf, 0777) < 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return mkdir (buf, 0777) == 0 || errno == EEXIST ? 0 : -1;
}

static int
git_is_dir (const char *path)
{
    struct stat st;
    return stat (path, &st) == 0 && S_ISDIR (st.st_mode);
}

static int
git_cmd_mv (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git mv [-v] [-f] [-k] [-n] <source>... <destination>";
    int verbose = 0, force = 0, skip = 0, dry_run = 0, no_more = 0;
    const char *paths[64];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && (!strcmp (w, "-v") || !strcmp (w, "--verbose"))) verbose = 1;
        else if (!no_more && (!strcmp (w, "-f") || !strcmp (w, "--force"))) force = 1;
        else if (!no_more && !strcmp (w, "-k")) skip = 1;
        else if (!no_more && (!strcmp (w, "-n") || !strcmp (w, "--dry-run"))) dry_run = 1;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (n_paths < 2) return git_usage (usage);
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;

    char destination_buffer[4096];
    snprintf (destination_buffer, sizeof destination_buffer, "%s",
              paths[n_paths - 1]);
    size_t destination_len = strlen (destination_buffer);
    while (destination_len > 1 && destination_buffer[destination_len - 1] == '/')
        destination_buffer[--destination_len] = '\0';
    const char *destination = destination_buffer;
    char destination_full[4096];
    snprintf (destination_full, sizeof destination_full, "%s/%s",
              ctx->repo.work_tree, destination);
    int into_directory = git_is_dir (destination_full);
    if (n_paths > 2 && !into_directory) {
        git_state_release (&state);
        return git_fatal ("destination '%s' is not a directory", destination);
    }

    /* git checks every move before making any, so a bad second source
       cannot leave the first one already moved. */
    char (*targets)[4096] = calloc ((size_t) n_paths, sizeof *targets);
    int *skipped = calloc ((size_t) n_paths, sizeof *skipped);
    if (!targets || !skipped) {
        free (targets);
        free (skipped);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    int status = 0, moved = 0;
    for (int i = 0; i < n_paths - 1 && !status; i++) {
        const char *source = paths[i];
        if (into_directory) {
            const char *base = strrchr (source, '/');
            snprintf (targets[i], sizeof targets[i], "%s/%s", destination,
                      base ? base + 1 : source);
        } else {
            snprintf (targets[i], sizeof targets[i], "%s", destination);
        }
        if (dry_run)
            printf ("Checking rename of '%s' to '%s'\n", source, targets[i]);

        /* A source is either a tracked file or a directory holding some. */
        size_t source_len = strlen (source);
        int is_tracked = 0, is_prefix = 0;
        for (size_t j = 0; j < state.n_index; j++) {
            if (!strcmp (state.index[j].path, source)) is_tracked = 1;
            else if (!strncmp (state.index[j].path, source, source_len) &&
                     state.index[j].path[source_len] == '/')
                is_prefix = 1;
        }
        if (!is_tracked && !is_prefix) {
            if (skip) { skipped[i] = 1; continue; }
            status = git_fatal ("bad source, source=%s, destination=%s",
                                source, targets[i]);
            break;
        }
        char target_full[4096];
        snprintf (target_full, sizeof target_full, "%s/%s", ctx->repo.work_tree,
                  targets[i]);
        struct stat st;
        if (lstat (target_full, &st) == 0 && !force) {
            if (skip) { skipped[i] = 1; continue; }
            status = git_fatal ("destination exists, source=%s, destination=%s",
                                source, targets[i]);
            break;
        }
    }

    for (int i = 0; i < n_paths - 1 && !status; i++) {
        if (skipped[i]) continue;
        const char *source = paths[i], *target = targets[i];
        if (verbose || dry_run) printf ("Renaming %s to %s\n", source, target);
        if (dry_run) continue;

        char source_full[4096], target_full[4096];
        snprintf (source_full, sizeof source_full, "%s/%s", ctx->repo.work_tree, source);
        snprintf (target_full, sizeof target_full, "%s/%s", ctx->repo.work_tree, target);
        if (git_mkdirs_for (target_full) < 0 ||
            rename (source_full, target_full) < 0) {
            if (skip) continue;
            status = git_fatal ("renaming '%s' failed: %s", source,
                                strerror (errno));
            break;
        }
        size_t source_len = strlen (source);
        if (git_index_rename (&state, source, target) < 0) {
            /* A directory: every tracked path under it moves with it. */
            for (size_t j = 0; j < state.n_index; j++) {
                const char *path = state.index[j].path;
                if (strncmp (path, source, source_len) || path[source_len] != '/')
                    continue;
                char renamed[4096];
                snprintf (renamed, sizeof renamed, "%s%s", target, path + source_len);
                char *kept = strdup (renamed);
                if (!kept) { status = GIT_EXIT_FATAL; break; }
                free (state.index[j].path);
                state.index[j].path = kept;
                size_t len = strlen (kept);
                state.index[j].flags = (uint16_t) ((state.index[j].flags & ~0xFFF) |
                                                   (len > 0xFFF ? 0xFFF : len));
            }
        }
        moved = 1;
    }
    if (!status && moved) {
        if (state.n_index > 1)
            qsort (state.index, state.n_index, sizeof *state.index,
                   bgit_index_path_cmp);
        if (git_index_store (ctx, state.index, state.n_index) < 0)
            status = GIT_EXIT_FATAL;
    }
    free (targets);
    free (skipped);
    git_state_release (&state);
    return status;
}

/* Remove a file, or a directory and everything in it. */
static int
git_remove_path (const char *full)
{
    struct stat st;
    if (lstat (full, &st) < 0) return -1;
    if (!S_ISDIR (st.st_mode)) return unlink (full);
    DIR *dir = opendir (full);
    if (!dir) return -1;
    struct dirent *entry;
    int rc = 0;
    while ((entry = readdir (dir))) {
        if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, "..")) continue;
        char child[4096];
        if (snprintf (child, sizeof child, "%s/%s", full, entry->d_name) >=
            (int) sizeof child) { rc = -1; continue; }
        if (git_remove_path (child) < 0) rc = -1;
    }
    closedir (dir);
    return rmdir (full) < 0 ? -1 : rc;
}

static int
git_clean_cmp (const void *a, const void *b)
{
    const bgit_status_entry *left = *(const bgit_status_entry *const *) a;
    const bgit_status_entry *right = *(const bgit_status_entry *const *) b;
    return strcmp (left->path, right->path);
}

static int
git_cmd_clean (git_context *ctx, WORD_LIST *args)
{
    const char *usage = "git clean [-d] [-f] [-n] [-q] [-x | -X] [--] <path>...";
    int directories = 0, force = 0, dry_run = 0, quiet = 0;
    int with_ignored = 0, only_ignored = 0, no_more = 0;
    const char *paths[32];
    int n_paths = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!no_more && !strcmp (w, "--")) { no_more = 1; continue; }
        if (!no_more && w[0] == '-' && w[1] && w[1] != '-') {
            for (const char *flag = w + 1; *flag; flag++) {
                switch (*flag) {
                case 'd': directories = 1; break;
                case 'f': force = 1; break;
                case 'n': dry_run = 1; break;
                case 'q': quiet = 1; break;
                case 'x': with_ignored = 1; break;
                case 'X': only_ignored = 1; break;
                default: return git_usage (usage);
                }
            }
        }
        else if (!no_more && !strcmp (w, "--dry-run")) dry_run = 1;
        else if (!no_more && !strcmp (w, "--force")) force = 1;
        else if (!no_more && !strcmp (w, "--quiet")) quiet = 1;
        else if (!no_more && w[0] == '-' && w[1]) return git_usage (usage);
        else if (n_paths < (int) (sizeof paths / sizeof *paths)) paths[n_paths++] = w;
        else return git_fatal ("too many paths");
    }
    if (!force && !dry_run)
        return git_fatal ("clean.requireForce is true and -f not given: "
                          "refusing to clean");
    if (git_context_open (ctx) != 0) return GIT_EXIT_FATAL;
    if (!ctx->repo.work_tree)
        return git_fatal ("this operation must be run in a work tree");

    struct git_state state;
    if (git_state_load (ctx, &state) < 0) return GIT_EXIT_FATAL;
    bgit_status_entry *entries = NULL;
    size_t n = 0;
    if (bgit_status (&ctx->repo, &ctx->odb, &ctx->cfg, state.index, state.n_index,
                     state.have_head ? state.head_tree : NULL, 0,
                     with_ignored || only_ignored, 0, &entries, &n) < 0) {
        git_state_release (&state);
        return git_fatal ("cannot read the working tree");
    }

    /* git reports what it would remove in path order, whether a candidate
       is untracked or ignored; the status walk groups them instead. */
    const bgit_status_entry **candidates = calloc (n ? n : 1, sizeof *candidates);
    if (!candidates) {
        bgit_status_free (entries, n);
        git_state_release (&state);
        return GIT_EXIT_FATAL;
    }
    size_t n_candidates = 0;
    for (size_t i = 0; i < n; i++) {
        const bgit_status_entry *entry = &entries[i];
        if (!entry->untracked && !entry->ignored) continue;
        if (entry->ignored && !with_ignored && !only_ignored) continue;
        if (entry->untracked && only_ignored) continue;
        candidates[n_candidates++] = entry;
    }
    if (n_candidates > 1)
        qsort (candidates, n_candidates, sizeof *candidates, git_clean_cmp);

    int status = 0;
    for (size_t i = 0; i < n_candidates && !status; i++) {
        const bgit_status_entry *entry = candidates[i];
        size_t len = strlen (entry->path);
        int is_directory = len && entry->path[len - 1] == '/';
        int named = 0;
        if (n_paths) {
            for (int j = 0; j < n_paths && !named; j++) {
                char trimmed[4096];
                snprintf (trimmed, sizeof trimmed, "%.*s",
                          (int) (is_directory ? len - 1 : len), entry->path);
                if (git_path_in_spec (trimmed, paths[j])) named = 1;
            }
            if (!named) continue;
        }
        /* Without -d a directory is left alone, unless it was named. */
        if (is_directory && !directories && !named) continue;
        if (!quiet)
            printf ("%s %s\n", dry_run ? "Would remove" : "Removing", entry->path);
        if (dry_run) continue;
        char full[4096];
        snprintf (full, sizeof full, "%s/%.*s", ctx->repo.work_tree,
                  (int) (is_directory ? len - 1 : len), entry->path);
        if (git_remove_path (full) < 0)
            status = git_fatal ("failed to remove %s", entry->path);
    }
    free (candidates);
    bgit_status_free (entries, n);
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
    { "branch",       git_cmd_branch },
    { "cat-file",     git_cmd_cat_file },
    { "check-ignore", git_cmd_check_ignore },
    { "checkout",     git_cmd_checkout },
    { "cherry-pick",  git_cmd_cherry_pick },
    { "clean",        git_cmd_clean },
    { "clone",        git_cmd_clone },
    { "commit",       git_cmd_commit },
    { "commit-tree",  git_cmd_commit_tree },
    { "config",       git_cmd_config },
    { "diff",         git_cmd_diff },
    { "fetch",        git_cmd_fetch },
    { "for-each-ref", git_cmd_for_each_ref },
    { "hash-object",  git_cmd_hash_object },
    { "index-pack",   git_cmd_index_pack },
    { "init",         git_cmd_init },
    { "log",          git_cmd_log },
    { "ls-files",     git_cmd_ls_files },
    { "ls-remote",    git_cmd_ls_remote },
    { "ls-tree",      git_cmd_ls_tree },
    { "merge",        git_cmd_merge },
    { "merge-base",   git_cmd_merge_base },
    { "merge-file",   git_cmd_merge_file },
    { "mv",           git_cmd_mv },
    { "pack-objects", git_cmd_pack_objects },
    { "pull",         git_cmd_pull },
    { "push",         git_cmd_push },
    { "read-tree",    git_cmd_read_tree },
    { "rebase",       git_cmd_rebase },
    { "receive-pack", git_cmd_receive_pack },
    { "reflog",       git_cmd_reflog },
    { "remote",       git_cmd_remote },
    { "reset",        git_cmd_reset },
    { "restore",      git_cmd_restore },
    { "rev-list",     git_cmd_rev_list },
    { "rev-parse",    git_cmd_rev_parse },
    { "revert",       git_cmd_revert },
    { "rm",           git_cmd_rm },
    { "show",         git_cmd_show },
    { "show-ref",     git_cmd_show_ref },
    { "stash",        git_cmd_stash },
    { "status",       git_cmd_status },
    { "switch",       git_cmd_switch },
    { "symbolic-ref", git_cmd_symbolic_ref },
    { "tag",          git_cmd_tag },
    { "unpack-objects", git_cmd_unpack_objects },
    { "update-index", git_cmd_update_index },
    { "update-ref",   git_cmd_update_ref },
    { "upload-pack",  git_cmd_upload_pack },
    { "var",          git_cmd_var },
    { "verify-pack",  git_cmd_verify_pack },
    { "worktree",     git_cmd_worktree },
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
        if (!strcmp (w, "--list-features")) {
            /* What this build can do beyond having a command at all, for
               tests that describe a whole feature. */
            static const char *const features[] = {
                "diff-patch",       /* unified patches, with hunk context */
                "diff-stat",        /* --stat, --numstat, --shortstat */
                NULL
            };
            for (int i = 0; features[i]; i++) printf ("%s\n", features[i]);
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

/* The shell reaps children of its own, so a raw fork has to keep SIGCHLD to
   itself until it has waited, or waitpid loses the race and reports that
   there is no such child. pkg.c guards its children the same way. */
struct git_child_guard {
    struct sigaction old_chld;
    sigset_t oldmask;
};

static int
git_child_guard_begin (struct git_child_guard *guard)
{
    struct sigaction dfl;
    sigset_t block;
    memset (&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset (&dfl.sa_mask);
    if (sigaction (SIGCHLD, &dfl, &guard->old_chld) < 0) return -1;
    sigemptyset (&block);
    sigaddset (&block, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &block, &guard->oldmask) < 0) {
        sigaction (SIGCHLD, &guard->old_chld, NULL);
        return -1;
    }
    return 0;
}

static void
git_child_guard_parent_end (struct git_child_guard *guard)
{
    sigprocmask (SIG_SETMASK, &guard->oldmask, NULL);
    sigaction (SIGCHLD, &guard->old_chld, NULL);
}

static void
git_child_guard_child_end (struct git_child_guard *guard)
{
    sigprocmask (SIG_SETMASK, &guard->oldmask, NULL);
}

int
git_builtin (WORD_LIST *list)
{
    /* Each call runs in a child: a fatal error is an exit, -C cannot move the
       caller, and held locks are released when the child dies. */
    fflush (stdout);
    fflush (stderr);
    struct git_child_guard guard;
    if (git_child_guard_begin (&guard) < 0) {
        builtin_error ("cannot guard SIGCHLD: %s", strerror (errno));
        return GIT_EXIT_FATAL;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        git_child_guard_parent_end (&guard);
        builtin_error ("fork: %s", strerror (errno));
        return GIT_EXIT_FATAL;
    }
    if (pid == 0) {
        git_child_guard_child_end (&guard);
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
            git_child_guard_parent_end (&guard);
            builtin_error ("waitpid: %s", strerror (errno));
            return GIT_EXIT_FATAL;
        }
    }
    git_child_guard_parent_end (&guard);
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
