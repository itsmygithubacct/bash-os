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
#include "rename.h"
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
       unchanged and need not be read — unless the entry is racy, written in
       the same tick as the index, when only the content can say. */
    /* Seconds only, which is what git compares: it records the finer part
       and reads it back, but only a build with USE_NSEC — which the stock
       one is not — holds a file against it. What that leaves open, a
       change made in the same second the index was written, is what the
       racy rule below covers. */
    if (!bgit_index_racy (entry) &&
        entry->size == (uint32_t) st->st_size &&
        entry->mtime_sec == (uint32_t) st->st_mtim.tv_sec &&
        entry->ctime_sec == (uint32_t) st->st_ctim.tv_sec &&
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
    /* Where a path already sits, so that finding it again is a lookup and
       not a walk: a status over a few thousand paths looks every one of
       them up at least twice. index+1, with 0 for an empty slot. */
    size_t *slots;
    size_t n_slots;
};

static unsigned long
bgit_status_hash (const char *path)
{
    unsigned long hash = 1469598103934665603UL;      /* FNV-1a */
    for (const unsigned char *p = (const unsigned char *) path; *p; p++) {
        hash ^= *p;
        hash *= 1099511628211UL;
    }
    return hash;
}

static void
bgit_status_place (struct bgit_status_build *build, size_t at)
{
    size_t mask = build->n_slots - 1;
    size_t slot = bgit_status_hash (build->entries[at].path) & mask;
    while (build->slots[slot]) slot = (slot + 1) & mask;
    build->slots[slot] = at + 1;
}

/* Keep the table at least twice the size of what it holds. Returns -1 only
   when there is no memory, and then the caller falls back to a walk. */
static int
bgit_status_room (struct bgit_status_build *build)
{
    if (build->slots && build->n_slots >= (build->n + 1) * 2) return 0;
    size_t want = build->n_slots ? build->n_slots * 2 : 64;
    while (want < (build->n + 1) * 2) want *= 2;
    size_t *grown = calloc (want, sizeof *grown);
    if (!grown) return -1;
    free (build->slots);
    build->slots = grown;
    build->n_slots = want;
    for (size_t i = 0; i < build->n; i++) bgit_status_place (build, i);
    return 0;
}

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
    if (bgit_status_room (build) == 0) bgit_status_place (build, build->n - 1);
    return entry;
}

static bgit_status_entry *
bgit_status_at (struct bgit_status_build *build, const char *path)
{
    if (build->slots) {
        size_t mask = build->n_slots - 1;
        size_t slot = bgit_status_hash (path) & mask;
        while (build->slots[slot]) {
            bgit_status_entry *entry = &build->entries[build->slots[slot] - 1];
            if (!strcmp (entry->path, path)) return entry;
            slot = (slot + 1) & mask;
        }
    } else
        for (size_t i = 0; i < build->n; i++)
            if (!strcmp (build->entries[i].path, path))
                return &build->entries[i];
    return bgit_status_append (build, path);
}

struct bgit_untracked_ctx {
    const bgit_repo *repo;
    const bgit_index_entry *index;
    size_t n_index;
    int index_sorted;
    const bgit_ignore *ignore;
    struct bgit_status_build *build;
    int untracked_all;
    int want_ignored;
};

/* Entries kept in path order — an index, or a tree read out whole — can be
   searched rather than walked, and a status over a few thousand paths is
   otherwise all walking: every path visited would be held against every
   entry there is. Whether they really are in order is worth the one pass
   it takes to find out, because nothing here writes them. */
static int
bgit_entries_sorted (const bgit_index_entry *entries, size_t n)
{
    for (size_t i = 1; i < n; i++)
        if (strcmp (entries[i - 1].path, entries[i].path) > 0) return 0;
    return 1;
}

/* The first entry that does not sort before PATH's first LEN bytes. */
static size_t
bgit_entry_lower_bound (const bgit_index_entry *entries, size_t n,
                        const char *path, size_t len)
{
    size_t low = 0, high = n;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (strncmp (entries[mid].path, path, len) < 0) low = mid + 1;
        else high = mid;
    }
    return low;
}

/* PATH's entry, or NULL. With several stages of it, the first — which is
   what a walk from the start would have found. */
static const bgit_index_entry *
bgit_entry_find (const bgit_index_entry *entries, size_t n, const char *path,
                 int sorted)
{
    if (!sorted) {
        for (size_t i = 0; i < n; i++)
            if (!strcmp (entries[i].path, path)) return &entries[i];
        return NULL;
    }
    size_t at = bgit_entry_lower_bound (entries, n, path, strlen (path));
    return at < n && !strcmp (entries[at].path, path) ? &entries[at] : NULL;
}

/* Does the index hold this path, or anything under it? */
static int
bgit_index_covers (const bgit_index_entry *index, size_t n, const char *path,
                   int is_dir, int sorted)
{
    size_t len = strlen (path);
    if (!sorted) {
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
    size_t at = bgit_entry_lower_bound (index, n, path, len);
    if (at >= n) return 0;
    if (!is_dir) return !strcmp (index[at].path, path);
    return !strncmp (index[at].path, path, len) && index[at].path[len] == '/';
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
        if (bgit_index_covers (ctx->index, ctx->n_index, path, 1,
                               ctx->index_sorted))
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
    if (bgit_index_covers (ctx->index, ctx->n_index, path, 0,
                           ctx->index_sorted))
        return 0;
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

/* A symlink, a file and a submodule are different kinds of thing: a path
   that changed from one to another is a typechange, not a modification. */
static int
bgit_status_kind (uint32_t mode)
{
    return mode == 0120000 ? 1 : mode == 0160000 ? 2 : 0;
}

int
bgit_status (const bgit_repo *repo, bgit_odb *odb, const bgit_config *cfg,
             const bgit_index_entry *index, size_t n_index,
             const char *head_tree, int untracked_all, int want_ignored,
             int find_renames, bgit_status_entry **out, size_t *n_out)
{
    struct bgit_status_build build;
    memset (&build, 0, sizeof build);
    int index_sorted = bgit_entries_sorted (index, n_index);

    /* A path the index holds in more than one stage is unmerged: it is
       reported by which stages exist, not by comparing anything. */
    for (size_t j = 0; j < n_index; j++) {
        int stage = (index[j].flags >> 12) & 3;
        if (!stage) continue;
        bgit_status_entry *entry = bgit_status_at (&build, index[j].path);
        if (!entry) goto oom;
        entry->unmerged |= 1 << stage;
        if (stage == 1) {
            entry->head_mode = index[j].mode;
            bgit_sha_to_hex (index[j].sha, entry->head_sha);
        } else if (stage == 2) {
            entry->index_mode = index[j].mode;
            bgit_sha_to_hex (index[j].sha, entry->index_sha);
        } else {
            entry->their_mode = index[j].mode;
            bgit_sha_to_hex (index[j].sha, entry->their_sha);
        }
        char full[4096];
        struct stat st;
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree,
                      index[j].path) < (int) sizeof full &&
            lstat (full, &st) == 0)
            entry->worktree_mode = bgit_worktree_mode (&st);
    }

    /* HEAD against the index: what is staged. */
    bgit_index_entry *head = NULL;
    size_t n_head = 0;
    if (head_tree && bgit_read_tree (odb, head_tree, &head, &n_head) < 0)
        return -1;
    int head_sorted = bgit_entries_sorted (head, n_head);
    for (size_t i = 0; i < n_head; i++) {
        const bgit_index_entry *staged = bgit_entry_find (index, n_index,
                                                          head[i].path,
                                                          index_sorted);
        if (staged && ((staged->flags >> 12) & 3)) continue;   /* unmerged */
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
        if (bgit_status_kind (head[i].mode) != bgit_status_kind (staged->mode))
            entry->staged = 'T';        /* a file where a symlink was, or back */
        else if (memcmp (head[i].sha, staged->sha, 20) != 0 ||
                 head[i].mode != staged->mode)
            entry->staged = 'M';
    }
    for (size_t j = 0; j < n_index; j++) {
        if ((index[j].flags >> 12) & 3) continue;
        if (bgit_entry_find (head, n_head, index[j].path, head_sorted))
            continue;
        bgit_status_entry *entry = bgit_status_at (&build, index[j].path);
        if (!entry) goto oom;
        entry->index_mode = index[j].mode;
        bgit_sha_to_hex (index[j].sha, entry->index_sha);
        entry->staged = head_tree ? 'A' : 'A';
    }
    bgit_index_free_entries (head, n_head);
    head = NULL;
    n_head = 0;

    /* A staged deletion and a staged addition of the same content are one
       rename: the same pairing git does, and reported the same way. */
    for (size_t i = 0; find_renames && i < build.n; i++) {
        bgit_status_entry *added = &build.entries[i];
        if (added->staged != 'A') continue;
        bgit_status_entry *best = NULL;
        int best_score = 0;
        for (size_t j = 0; j < build.n; j++) {
            bgit_status_entry *gone = &build.entries[j];
            if (gone->staged != 'D' || gone->renamed_from) continue;
            int score = bgit_similarity (odb, gone->head_sha, added->index_sha);
            if (score < BGIT_RENAME_THRESHOLD || score <= best_score) continue;
            best = gone;
            best_score = score;
            if (score == BGIT_RENAME_MAX_SCORE) break;
        }
        if (!best) continue;
        added->staged = 'R';
        added->score = best_score;
        added->renamed_from = strdup (best->path);
        added->head_mode = best->head_mode;
        memcpy (added->head_sha, best->head_sha, 41);
        if (!added->renamed_from) goto oom;
        /* The deletion has been accounted for. */
        best->staged = 0;
        best->renamed_from = strdup ("");
        if (!best->renamed_from) goto oom;
    }
    for (size_t i = 0; i < build.n; i++)
        if (build.entries[i].renamed_from && !*build.entries[i].renamed_from &&
            !build.entries[i].staged && !build.entries[i].unstaged &&
            !build.entries[i].untracked && !build.entries[i].ignored) {
            free (build.entries[i].path);
            free (build.entries[i].renamed_from);
            memmove (&build.entries[i], &build.entries[i + 1],
                     (build.n - i - 1) * sizeof *build.entries);
            build.n--;
            i--;
        }

    /* The index against the working tree: what is not staged. An unmerged
       path is left alone; its stages already say what happened. */
    for (size_t j = 0; j < n_index; j++) {
        if ((index[j].flags >> 12) & 3) continue;
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
            entry->worktree_mode = bgit_worktree_mode (&st);
            entry->unstaged = bgit_status_kind (index[j].mode) !=
                              bgit_status_kind (entry->worktree_mode)
                              ? 'T' : 'M';
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
        .repo = repo, .index = index, .n_index = n_index,
        .index_sorted = index_sorted, .ignore = &ignore,
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
        if (entry->staged || entry->unstaged || entry->untracked ||
            entry->ignored || entry->unmerged) {
            if (kept != i) build.entries[kept] = *entry;
            kept++;
        } else {
            free (entry->path);
        }
    }
    build.n = kept;
    free (build.slots);                 /* the paths have moved; it is done */
    build.slots = NULL;
    build.n_slots = 0;

    if (build.n > 1)
        qsort (build.entries, build.n, sizeof *build.entries, bgit_status_cmp);
    *out = build.entries;
    *n_out = build.n;
    return 0;
oom:
    bgit_index_free_entries (head, n_head);
    free (build.slots);
    bgit_status_free (build.entries, build.n);
    return -1;
}

void
bgit_status_free (bgit_status_entry *entries, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free (entries[i].path);
        free (entries[i].renamed_from);
    }
    free (entries);
}
