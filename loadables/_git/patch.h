/* SPDX-License-Identifier: MIT */
/* _git/patch.h — turning a list of changed paths into what git prints.
 *
 * The name-level diff in diff.h says which paths changed; this writes them
 * out: a unified patch, a diffstat, --numstat, --shortstat, or the summary
 * of created and deleted files that `git commit` ends with.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_PATCH_H
#define BASH_OS_GIT_PATCH_H

#include <stdio.h>

#include "diff.h"
#include "odb.h"
#include "repo.h"

typedef struct {
    int context;          /* lines of context; git's default is 3 */
    int abbrev;           /* how much of an id the index line shows */
    int new_from_worktree;/* the new side is a file on disk, not a blob */
    const char *prefix_old, *prefix_new;   /* "a/" and "b/" */
    const char *line_prefix;               /* what log -p indents with */
    int word_diff;        /* 0 by lines, 1 [-word-]{+by word+}, 2 porcelain */
    int ignore_ws;        /* which whitespace to overlook: see xdiff.h */
    int function_context; /* -W: a hunk covers the definition it sits in */
    int ignore_blank_lines;/* a run of blank lines on its own says nothing */
} bgit_patch_options;

void bgit_patch_options_init (bgit_patch_options *options);

/* Load one side of a change: SIDE is 0 for the old, 1 for the new. Returns
   0 with *data owned by the caller, or -1. A side that does not exist (an
   added or deleted path) comes back empty. */
int bgit_patch_content (bgit_odb *odb, const bgit_repo *repo,
                        const bgit_diff_entry *entry, int side,
                        const bgit_patch_options *options,
                        char **data, size_t *len);

/* Write a unified patch for every entry. */
int bgit_patch_write (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                      const bgit_diff_entry *entries, size_t n,
                      const bgit_patch_options *options);

/* How many lines each path gained and lost, for the stat forms. */
typedef struct {
    const bgit_diff_entry *entry;
    size_t added, removed;
    int binary;
} bgit_diffstat_entry;

/* *N_OUT can come back smaller than N: a modified path whose diff turns out
   to say nothing — which whitespace overlooked can do — is left out of the
   stat altogether, as git leaves it out. */
int bgit_diffstat (bgit_odb *odb, const bgit_repo *repo,
                   const bgit_diff_entry *entries, size_t n,
                   const bgit_patch_options *options,
                   bgit_diffstat_entry **out, size_t *n_out);

/* The forms git prints from those counts.

   How wide a stat is drawn and how many of its lines are shown: 0 in a
   field means the width git works out for itself. */
typedef struct {
    int width;         /* the whole line */
    int name_width;    /* the column the paths sit in */
    int graph_width;   /* the column of + and - marks */
    int count;         /* how many files to show, the rest as " ..." */
} bgit_diffstat_layout;

void bgit_diffstat_write (FILE *out, const bgit_diffstat_entry *stats,
                          size_t n, const char *line_prefix,
                          const bgit_diffstat_layout *layout);
void bgit_numstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n);
void bgit_shortstat_write (FILE *out, const bgit_diffstat_entry *stats,
                           size_t n, const char *line_prefix);
/* " 2 files changed, 3 insertions(+), 1 deletion(-)" */
void bgit_stat_summary (FILE *out, size_t files, size_t added, size_t removed);
/* " create mode 100644 a.txt", as `git commit` and --summary print it. */
void bgit_diff_summary (FILE *out, const bgit_diff_entry *entries, size_t n,
                        const char *line_prefix);

/* A file in the working tree, with a symlink read as git reads one: its
   content is the path it points at. Caller frees *data. */
int bgit_read_worktree_file (const bgit_repo *repo, const char *path,
                            char **data, size_t *len);

/* A path as git shows it, quoted when it holds anything unusual. Returns a
   pointer to BUF or to PATH itself. */
const char *bgit_quote_path (const char *path, char *buf, size_t size);

#endif /* BASH_OS_GIT_PATCH_H */
