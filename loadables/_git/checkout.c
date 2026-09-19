/* SPDX-License-Identifier: MIT */
/* _git/checkout.c — putting a tree into the working tree and the index.
 * See checkout.h.
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

#include "loadables.h"

#include "checkout.h"
#include "index.h"
#include "odb.h"
#include "repo.h"
#include "tree.h"
#include "worktree.h"

/* Create every directory above PATH. */
static int
bgit_checkout_mkdirs (const char *path)
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

int
bgit_checkout_file (bgit_odb *odb, const char *full_path, const char *sha,
                    uint32_t mode)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return -1;
    if (bgit_checkout_mkdirs (full_path) < 0) { free (data); return -1; }
    unlink (full_path);
    int rc = 0;
    if (mode == 0120000) {
        char *target = malloc (len + 1);
        if (!target) { free (data); return -1; }
        memcpy (target, data, len);
        target[len] = '\0';
        rc = symlink (target, full_path) < 0 ? -1 : 0;
        free (target);
    } else {
        int fd = open (full_path, O_WRONLY | O_CREAT | O_TRUNC,
                       mode == 0100755 ? 0777 : 0666);
        if (fd < 0) rc = -1;
        else {
            size_t off = 0;
            while (off < len) {
                ssize_t wrote = write (fd, data + off, len - off);
                if (wrote < 0) {
                    if (errno == EINTR) continue;
                    rc = -1;
                    break;
                }
                off += (size_t) wrote;
            }
            if (close (fd) < 0) rc = -1;
        }
    }
    free (data);
    if (rc < 0)
        builtin_error ("cannot write %s: %s", full_path, strerror (errno));
    return rc;
}

/* Remove a file, and any directory it leaves empty. */
static void
bgit_checkout_remove (const bgit_repo *repo, const char *path)
{
    char full[4096];
    if (snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
        (int) sizeof full)
        return;
    if (unlink (full) < 0) return;
    char *slash = strrchr (full, '/');
    while (slash && (size_t) (slash - full) > strlen (repo->work_tree)) {
        *slash = '\0';
        if (rmdir (full) < 0) break;
        slash = strrchr (full, '/');
    }
}

/* Fill in an index entry from what was just written. */
static int
bgit_checkout_stat (const bgit_repo *repo, bgit_index_entry *entry)
{
    char full[4096];
    if (snprintf (full, sizeof full, "%s/%s", repo->work_tree, entry->path) >=
        (int) sizeof full)
        return -1;
    struct stat st;
    if (lstat (full, &st) < 0) return -1;
    bgit_index_entry_set_stat (entry, &st);
    entry->mode = bgit_worktree_mode (&st);
    return 0;
}

static const bgit_index_entry *
bgit_entry_for (const bgit_index_entry *entries, size_t n, const char *path)
{
    for (size_t i = 0; i < n; i++)
        if (!strcmp (entries[i].path, path)) return &entries[i];
    return NULL;
}

int
bgit_checkout_tree (const bgit_repo *repo, bgit_odb *odb, const char *tree,
                    bgit_index_entry **index, size_t *n, int force, char **lost)
{
    if (lost) *lost = NULL;
    if (!repo->work_tree) {
        builtin_error ("this operation must be run in a work tree");
        return -1;
    }
    bgit_index_entry *target = NULL;
    size_t n_target = 0;
    if (tree && bgit_read_tree (odb, tree, &target, &n_target) < 0) return -1;

    /* Nothing is written until every change is known to be safe. */
    for (size_t i = 0; i < n_target && !force; i++) {
        const bgit_index_entry *staged = bgit_entry_for (*index, *n, target[i].path);
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", repo->work_tree, target[i].path);
        struct stat st;
        int exists = lstat (full, &st) == 0;
        if (!staged && exists) {
            if (lost) *lost = strdup (target[i].path);
            bgit_index_free_entries (target, n_target);
            return 1;          /* an untracked file would be overwritten */
        }
        if (staged && exists && memcmp (staged->sha, target[i].sha, 20) != 0 &&
            !bgit_worktree_matches (odb, full, staged, &st)) {
            if (lost) *lost = strdup (target[i].path);
            bgit_index_free_entries (target, n_target);
            return 1;          /* local changes would be overwritten */
        }
    }
    for (size_t i = 0; i < *n && !force; i++) {
        if (bgit_entry_for (target, n_target, (*index)[i].path)) continue;
        char full[4096];
        snprintf (full, sizeof full, "%s/%s", repo->work_tree, (*index)[i].path);
        struct stat st;
        if (lstat (full, &st) < 0) continue;
        if (!bgit_worktree_matches (odb, full, &(*index)[i], &st)) {
            if (lost) *lost = strdup ((*index)[i].path);
            bgit_index_free_entries (target, n_target);
            return 1;
        }
    }

    /* Remove what the new tree does not have, then write what it does. */
    for (size_t i = 0; i < *n; i++)
        if (!bgit_entry_for (target, n_target, (*index)[i].path))
            bgit_checkout_remove (repo, (*index)[i].path);
    for (size_t i = 0; i < n_target; i++) {
        char full[4096], sha[41];
        snprintf (full, sizeof full, "%s/%s", repo->work_tree, target[i].path);
        bgit_sha_to_hex (target[i].sha, sha);
        const bgit_index_entry *staged = bgit_entry_for (*index, *n, target[i].path);
        struct stat st;
        int exists = lstat (full, &st) == 0;
        if (exists && staged && !memcmp (staged->sha, target[i].sha, 20) &&
            staged->mode == target[i].mode &&
            bgit_worktree_matches (odb, full, staged, &st)) {
            /* Already the right content: leave the file, keep its stat. */
        } else if (bgit_checkout_file (odb, full, sha, target[i].mode) < 0) {
            bgit_index_free_entries (target, n_target);
            return -1;
        }
        if (bgit_checkout_stat (repo, &target[i]) < 0) {
            bgit_index_free_entries (target, n_target);
            return -1;
        }
    }

    bgit_index_free_entries (*index, *n);
    *index = target;
    *n = n_target;
    return 0;
}

int
bgit_checkout_paths (const bgit_repo *repo, bgit_odb *odb, const char *tree,
                     bgit_index_entry **index, size_t *n,
                     const char *const *paths, size_t n_paths,
                     int to_index, int to_worktree)
{
    bgit_index_entry *source = NULL;
    size_t n_source = 0;
    if (tree && bgit_read_tree (odb, tree, &source, &n_source) < 0) return -1;
    const bgit_index_entry *from = tree ? source : *index;
    size_t n_from = tree ? n_source : *n;

    for (size_t p = 0; p < n_paths; p++) {
        size_t len = strlen (paths[p]);
        int matched = 0;
        for (size_t i = 0; i < n_from; i++) {
            const char *path = from[i].path;
            if (strcmp (path, paths[p]) &&
                !(!strncmp (path, paths[p], len) && path[len] == '/'))
                continue;
            matched = 1;
            char full[4096], sha[41];
            snprintf (full, sizeof full, "%s/%s", repo->work_tree, path);
            bgit_sha_to_hex (from[i].sha, sha);
            if (to_worktree &&
                bgit_checkout_file (odb, full, sha, from[i].mode) < 0) {
                bgit_index_free_entries (source, n_source);
                return -1;
            }
            if (to_index) {
                bgit_index_entry entry;
                memset (&entry, 0, sizeof entry);
                entry.mode = from[i].mode;
                memcpy (entry.sha, from[i].sha, 20);
                entry.path = strdup (path);
                if (!entry.path) {
                    bgit_index_free_entries (source, n_source);
                    return -1;
                }
                entry.flags = (uint16_t) (strlen (path) > 0xFFF ? 0xFFF : strlen (path));
                if (to_worktree) bgit_checkout_stat (repo, &entry);
                /* Replace whatever the index held for this path. */
                int replaced = 0;
                for (size_t j = 0; j < *n; j++) {
                    if (strcmp ((*index)[j].path, path)) continue;
                    char *keep = (*index)[j].path;
                    (*index)[j] = entry;
                    (*index)[j].path = keep;
                    free (entry.path);
                    replaced = 1;
                    break;
                }
                if (!replaced) {
                    bgit_index_entry *grown = realloc (*index, (*n + 1) * sizeof *grown);
                    if (!grown) {
                        free (entry.path);
                        bgit_index_free_entries (source, n_source);
                        return -1;
                    }
                    *index = grown;
                    (*index)[(*n)++] = entry;
                }
            } else if (to_worktree) {
                /* The file now matches what the index holds. */
                for (size_t j = 0; j < *n; j++)
                    if (!strcmp ((*index)[j].path, path))
                        bgit_checkout_stat (repo, &(*index)[j]);
            }
        }
        if (!matched) {
            builtin_error ("pathspec '%s' did not match any file(s) known to git",
                           paths[p]);
            bgit_index_free_entries (source, n_source);
            return -1;
        }
    }
    if (*n > 1) qsort (*index, *n, sizeof **index, bgit_index_path_cmp);
    bgit_index_free_entries (source, n_source);
    return 0;
}
