/* SPDX-License-Identifier: MIT */
/* _git/worktree.c — the working tree: walking it, and comparing it.
 * See worktree.h.
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
#include <dirent.h>
#include <sys/stat.h>

#include "loadables.h"

#include "ignore.h"
#include "index.h"
#include "odb.h"
#include "repo.h"
#include "tree.h"
#include "worktree.h"

uint32_t
bgit_worktree_mode (const struct stat *st)
{
    if (S_ISLNK (st->st_mode)) return 0120000;
    if (S_ISDIR (st->st_mode)) return 040000;
    return (st->st_mode & 0111) ? 0100755 : 0100644;
}

/* A file's content as git would store it: a symbolic link is its target. */
static int
bgit_worktree_read (const char *path, const struct stat *st,
                    unsigned char **out, size_t *len)
{
    if (S_ISLNK (st->st_mode)) {
        size_t size = (size_t) (st->st_size > 0 ? st->st_size : 4096);
        char *buf = malloc (size + 1);
        if (!buf) return -1;
        ssize_t got = readlink (path, buf, size);
        if (got < 0) { free (buf); return -1; }
        *out = (unsigned char *) buf;
        *len = (size_t) got;
        return 0;
    }
    int fd = open (path, O_RDONLY);
    if (fd < 0) return -1;
    int rc = bgit_slurp_fd (fd, out, len);
    close (fd);
    return rc;
}

int
bgit_worktree_matches (bgit_odb *odb, const char *full_path,
                       const bgit_index_entry *entry, const struct stat *st)
{
    (void) odb;
    if (entry->mode != bgit_worktree_mode (st)) return 0;
    /* The index records stat data; when it still agrees, the file is
       unchanged and need not be read. */
    if (entry->size == (uint32_t) st->st_size &&
        entry->mtime_sec == (uint32_t) st->st_mtim.tv_sec &&
        entry->mtime_nsec == (uint32_t) st->st_mtim.tv_nsec &&
        entry->ctime_sec == (uint32_t) st->st_ctim.tv_sec &&
        entry->ctime_nsec == (uint32_t) st->st_ctim.tv_nsec &&
        entry->ino == (uint32_t) st->st_ino)
        return 1;
    unsigned char *content = NULL;
    size_t len = 0;
    if (bgit_worktree_read (full_path, st, &content, &len) < 0) return 0;
    char sha[41];
    int rc = bgit_write_object (NULL, "blob", content, len, 0, sha);
    free (content);
    if (rc < 0) return 0;
    char stored[41];
    bgit_sha_to_hex (entry->sha, stored);
    return strcmp (sha, stored) == 0;
}

/* ---- walking ----------------------------------------------------------- */

static int
bgit_name_cmp (const void *a, const void *b)
{
    return strcmp (*(const char *const *) a, *(const char *const *) b);
}

static int
bgit_walk_at (const bgit_repo *repo, const char *relative, bgit_walk_fn fn,
              void *ctx)
{
    char dir[4096];
    if (snprintf (dir, sizeof dir, "%s%s%s", repo->work_tree,
                  *relative ? "/" : "", relative) >= (int) sizeof dir)
        return -1;
    DIR *handle = opendir (dir);
    if (!handle) return 0;
    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *entry;
    while ((entry = readdir (handle)) != NULL) {
        if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, "..")) continue;
        if (!*relative && !strcmp (entry->d_name, ".git")) continue;
        if (n == cap) {
            size_t next = cap ? cap * 2 : 32;
            char **grown = realloc (names, next * sizeof *grown);
            if (!grown) { closedir (handle); goto oom; }
            names = grown;
            cap = next;
        }
        names[n] = strdup (entry->d_name);
        if (!names[n]) { closedir (handle); goto oom; }
        n++;
    }
    closedir (handle);
    if (n > 1) qsort (names, n, sizeof *names, bgit_name_cmp);

    int rc = 0;
    for (size_t i = 0; i < n && rc >= 0; i++) {
        char path[4096], full[4096];
        if (snprintf (path, sizeof path, "%s%s%s", relative,
                      *relative ? "/" : "", names[i]) >= (int) sizeof path)
            continue;
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
            (int) sizeof full)
            continue;
        struct stat st;
        if (lstat (full, &st) < 0) continue;
        int is_dir = S_ISDIR (st.st_mode);
        int answer = fn (ctx, path, is_dir, &st);
        if (answer < 0) { rc = -1; break; }
        if (is_dir && answer == 0) {
            /* A directory holding its own .git is another repository. */
            char nested[4096];
            if (snprintf (nested, sizeof nested, "%s/.git", full) < (int) sizeof nested &&
                access (nested, F_OK) == 0)
                continue;
            rc = bgit_walk_at (repo, path, fn, ctx);
        }
    }
    for (size_t i = 0; i < n; i++) free (names[i]);
    free (names);
    return rc;
oom:
    for (size_t i = 0; i < n; i++) free (names[i]);
    free (names);
    return -1;
}

int
bgit_worktree_walk (const bgit_repo *repo, bgit_walk_fn fn, void *ctx)
{
    if (!repo->work_tree) return 0;
    return bgit_walk_at (repo, "", fn, ctx);
}

/* ---- status ------------------------------------------------------------ */

struct bgit_status_build {
    bgit_status_entry *entries;
    size_t n, cap;
};

/* An untracked path is its own record: git lists a file that the index no
   longer has and an untracked file of the same name on separate lines. */
static bgit_status_entry *
bgit_status_append (struct bgit_status_build *build, const char *path)
{
    if (build->n == build->cap) {
        size_t next = build->cap ? build->cap * 2 : 32;
        bgit_status_entry *grown = realloc (build->entries, next * sizeof *grown);
        if (!grown) return NULL;
        build->entries = grown;
        build->cap = next;
    }
    bgit_status_entry *entry = &build->entries[build->n];
    memset (entry, 0, sizeof *entry);
    entry->path = strdup (path);
    if (!entry->path) return NULL;
    build->n++;
    return entry;
}

static bgit_status_entry *
bgit_status_at (struct bgit_status_build *build, const char *path)
{
    for (size_t i = 0; i < build->n; i++)
        if (!strcmp (build->entries[i].path, path)) return &build->entries[i];
    if (build->n == build->cap) {
        size_t next = build->cap ? build->cap * 2 : 32;
        bgit_status_entry *grown = realloc (build->entries, next * sizeof *grown);
        if (!grown) return NULL;
        build->entries = grown;
        build->cap = next;
    }
    bgit_status_entry *entry = &build->entries[build->n];
    memset (entry, 0, sizeof *entry);
    entry->path = strdup (path);
    if (!entry->path) return NULL;
    build->n++;
    return entry;
}

struct bgit_untracked_ctx {
    const bgit_repo *repo;
    const bgit_index_entry *index;
    size_t n_index;
    const bgit_ignore *ignore;
    struct bgit_status_build *build;
    int untracked_all;
    int want_ignored;
};

/* Does the index hold this path, or anything under it? */
static int
bgit_index_covers (const bgit_index_entry *index, size_t n, const char *path,
                   int is_dir)
{
    size_t len = strlen (path);
    for (size_t i = 0; i < n; i++) {
        if (!is_dir) {
            if (!strcmp (index[i].path, path)) return 1;
            continue;
        }
        if (!strncmp (index[i].path, path, len) && index[i].path[len] == '/')
            return 1;
    }
    return 0;
}

/* Does this directory hold anything git would report? An empty one, or one
   holding only ignored files, is not mentioned at all. */
static int
bgit_dir_has_content (const bgit_repo *repo, const bgit_ignore *ignore,
                      const char *relative)
{
    char dir[4096];
    if (snprintf (dir, sizeof dir, "%s/%s", repo->work_tree, relative) >=
        (int) sizeof dir)
        return 0;
    DIR *handle = opendir (dir);
    if (!handle) return 0;
    struct dirent *entry;
    int found = 0;
    while (!found && (entry = readdir (handle)) != NULL) {
        if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, "..")) continue;
        char path[4096], full[4096];
        if (snprintf (path, sizeof path, "%s/%s", relative, entry->d_name) >=
            (int) sizeof path)
            continue;
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
            (int) sizeof full)
            continue;
        struct stat st;
        if (lstat (full, &st) < 0) continue;
        int is_dir = S_ISDIR (st.st_mode);
        const bgit_ignore_rule *rule = NULL;
        if (bgit_ignore_match (ignore, path, is_dir, &rule)) continue;
        found = is_dir ? bgit_dir_has_content (repo, ignore, path) : 1;
    }
    closedir (handle);
    return found;
}

static int
bgit_untracked_visit (void *vctx, const char *path, int is_dir,
                      const struct stat *st)
{
    struct bgit_untracked_ctx *ctx = vctx;
    const bgit_ignore_rule *rule = NULL;
    int ignored = bgit_ignore_match (ctx->ignore, path, is_dir, &rule);
    if (ignored) {
        if (ctx->want_ignored) {
            char name[4096];
            snprintf (name, sizeof name, "%s%s", path, is_dir ? "/" : "");
            bgit_status_entry *entry = bgit_status_append (ctx->build, name);
            if (!entry) return -1;
            entry->ignored = 1;
        }
        return 1;      /* nothing below an ignored directory is reported */
    }
    if (is_dir) {
        if (bgit_index_covers (ctx->index, ctx->n_index, path, 1))
            return 0;  /* tracked files inside: look further down */
        if (!bgit_dir_has_content (ctx->repo, ctx->ignore, path))
            return 1;  /* empty, or wholly ignored: git says nothing */
        if (ctx->untracked_all) return 0;
        char name[4096];
        snprintf (name, sizeof name, "%s/", path);
        bgit_status_entry *entry = bgit_status_append (ctx->build, name);
        if (!entry) return -1;
        entry->untracked = 1;
        entry->worktree_mode = bgit_worktree_mode (st);
        return 1;      /* git names the directory, not its contents */
    }
    if (bgit_index_covers (ctx->index, ctx->n_index, path, 0)) return 0;
    bgit_status_entry *entry = bgit_status_append (ctx->build, path);
    if (!entry) return -1;
    entry->untracked = 1;
    entry->worktree_mode = bgit_worktree_mode (st);
    return 0;
}

/* git groups its report: everything tracked first, then untracked, then
   ignored, each group in path order. */
static int
bgit_status_rank (const bgit_status_entry *entry)
{
    return entry->ignored ? 2 : entry->untracked ? 1 : 0;
}

static int
bgit_status_cmp (const void *a, const void *b)
{
    const bgit_status_entry *left = a, *right = b;
    int order = bgit_status_rank (left) - bgit_status_rank (right);
    if (order) return order;
    return strcmp (left->path, right->path);
}

int
bgit_status (const bgit_repo *repo, bgit_odb *odb, const bgit_config *cfg,
             const bgit_index_entry *index, size_t n_index,
             const char *head_tree, int untracked_all, int want_ignored,
             bgit_status_entry **out, size_t *n_out)
{
    struct bgit_status_build build;
    memset (&build, 0, sizeof build);

    /* HEAD against the index: what is staged. */
    bgit_index_entry *head = NULL;
    size_t n_head = 0;
    if (head_tree && bgit_read_tree (odb, head_tree, &head, &n_head) < 0)
        return -1;
    for (size_t i = 0; i < n_head; i++) {
        const bgit_index_entry *staged = NULL;
        for (size_t j = 0; j < n_index; j++)
            if (!strcmp (index[j].path, head[i].path)) { staged = &index[j]; break; }
        bgit_status_entry *entry = bgit_status_at (&build, head[i].path);
        if (!entry) goto oom;
        entry->head_mode = head[i].mode;
        bgit_sha_to_hex (head[i].sha, entry->head_sha);
        if (!staged) {
            entry->staged = 'D';
            continue;
        }
        entry->index_mode = staged->mode;
        bgit_sha_to_hex (staged->sha, entry->index_sha);
        if (memcmp (head[i].sha, staged->sha, 20) != 0 ||
            head[i].mode != staged->mode)
            entry->staged = 'M';
    }
    for (size_t j = 0; j < n_index; j++) {
        int in_head = 0;
        for (size_t i = 0; i < n_head && !in_head; i++)
            if (!strcmp (index[j].path, head[i].path)) in_head = 1;
        if (in_head) continue;
        bgit_status_entry *entry = bgit_status_at (&build, index[j].path);
        if (!entry) goto oom;
        entry->index_mode = index[j].mode;
        bgit_sha_to_hex (index[j].sha, entry->index_sha);
        entry->staged = head_tree ? 'A' : 'A';
    }
    bgit_index_free_entries (head, n_head);
    head = NULL;
    n_head = 0;

    /* The index against the working tree: what is not staged. */
    for (size_t j = 0; j < n_index; j++) {
        char full[4096];
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree,
                      index[j].path) >= (int) sizeof full)
            continue;
        struct stat st;
        bgit_status_entry *entry = NULL;
        if (lstat (full, &st) < 0) {
            entry = bgit_status_at (&build, index[j].path);
            if (!entry) goto oom;
            entry->unstaged = 'D';
        } else if (!bgit_worktree_matches (odb, full, &index[j], &st)) {
            entry = bgit_status_at (&build, index[j].path);
            if (!entry) goto oom;
            entry->unstaged = 'M';
            entry->worktree_mode = bgit_worktree_mode (&st);
        } else {
            continue;
        }
        if (!entry->index_mode) {
            entry->index_mode = index[j].mode;
            bgit_sha_to_hex (index[j].sha, entry->index_sha);
        }
    }

    /* Everything else in the working tree: untracked, or ignored. */
    bgit_ignore ignore;
    if (bgit_ignore_load (&ignore, repo, cfg) < 0) goto oom;
    struct bgit_untracked_ctx ctx = {
        .repo = repo, .index = index, .n_index = n_index, .ignore = &ignore,
        .build = &build, .untracked_all = untracked_all,
        .want_ignored = want_ignored
    };
    int rc = bgit_worktree_walk (repo, bgit_untracked_visit, &ctx);
    bgit_ignore_release (&ignore);
    if (rc < 0) goto oom;

    /* Only what changed is reported; a file that matches everywhere is not
       mentioned, which is what git prints. */
    size_t kept = 0;
    for (size_t i = 0; i < build.n; i++) {
        bgit_status_entry *entry = &build.entries[i];
        if (entry->staged || entry->unstaged || entry->untracked || entry->ignored) {
            if (kept != i) build.entries[kept] = *entry;
            kept++;
        } else {
            free (entry->path);
        }
    }
    build.n = kept;

    if (build.n > 1)
        qsort (build.entries, build.n, sizeof *build.entries, bgit_status_cmp);
    *out = build.entries;
    *n_out = build.n;
    return 0;
oom:
    bgit_index_free_entries (head, n_head);
    bgit_status_free (build.entries, build.n);
    return -1;
}

void
bgit_status_free (bgit_status_entry *entries, size_t n)
{
    for (size_t i = 0; i < n; i++) free (entries[i].path);
    free (entries);
}
