/* SPDX-License-Identifier: MIT */
/* _git/worktree.h — the working tree: walking it, and comparing it.
 *
 * git's status is two comparisons: HEAD against the index (what is staged),
 * and the index against the files on disk (what is not). A file the index
 * does not know about is untracked, unless an ignore rule covers it.
 *
 * The index records each file's stat data, so an unchanged file is usually
 * recognised without reading it. Only a file whose stat data has moved is
 * hashed to see whether its content really changed.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_WORKTREE_H
#define BASH_OS_GIT_WORKTREE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include "config.h"
#include "ignore.h"
#include "index.h"
#include "odb.h"
#include "repo.h"

/* Each file the walk reports, relative to the worktree root. FN returning
   non-zero stops the walk. Directories are reported before their contents,
   and returning 1 from FN for a directory skips it. */
typedef int (*bgit_walk_fn) (void *ctx, const char *path, int is_dir,
                             const struct stat *st);
int bgit_worktree_walk (const bgit_repo *repo, bgit_walk_fn fn, void *ctx);

/* One path's standing in the three places git compares. */
typedef struct {
    char *path;
    int staged;        /* HEAD -> index: 'A', 'M', 'D', or 0 */
    int unstaged;      /* index -> working tree: 'M', 'D', or 0 */
    int untracked;
    int ignored;
    uint32_t head_mode, index_mode, worktree_mode;
    char head_sha[41];
    char index_sha[41];
} bgit_status_entry;

/* Compare HEAD, the index and the working tree. HEAD_TREE may be NULL for
   an unborn branch. With UNTRACKED_ALL every untracked file is listed;
   otherwise a directory holding only untracked files is listed once, with a
   trailing '/', as git does. WANT_IGNORED adds ignored paths.
   Entries come back sorted by path. */
int bgit_status (const bgit_repo *repo, bgit_odb *odb, const bgit_config *cfg,
                 const bgit_index_entry *index, size_t n_index,
                 const char *head_tree, int untracked_all, int want_ignored,
                 bgit_status_entry **out, size_t *n_out);

void bgit_status_free (bgit_status_entry *entries, size_t n);

/* The mode git records for a file: 100755 when it is executable, 120000 for
   a symbolic link, 100644 otherwise. */
uint32_t bgit_worktree_mode (const struct stat *st);

/* 1 when the file at PATH still matches ENTRY, by stat data where that is
   conclusive and by content otherwise. */
int bgit_worktree_matches (bgit_odb *odb, const char *full_path,
                           const bgit_index_entry *entry, const struct stat *st);

#endif /* BASH_OS_GIT_WORKTREE_H */
