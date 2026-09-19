/* SPDX-License-Identifier: MIT */
/* _git/xdiff.h — the line diff behind a patch.
 *
 * Myers' algorithm over lines, in the linear-space divide and conquer form,
 * then the two adjustments git's output depends on: a run of changed lines
 * is slid as far down as it can go while still describing the same edit, and
 * the indent heuristic then picks the position that reads best, which is what
 * git has done by default since 2.14. Hunks carry three lines of context
 * unless asked otherwise, and two changes closer than twice the context
 * become one hunk.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_XDIFF_H
#define BASH_OS_GIT_XDIFF_H

#include <stddef.h>

/* One side of a comparison, split into lines. A file not ending in a
   newline is remembered, so the patch can say so. */
typedef struct {
    const char *text;
    size_t len;
    const char **lines;     /* each line, without its newline */
    size_t *lengths;
    unsigned long *hashes;
    size_t n;
    int missing_newline;
    int binary;
} bgit_xdiff_file;

/* A hunk, as the header describes it: the context is already included. */
typedef struct {
    size_t old_start, old_count;   /* zero-based line numbers */
    size_t new_start, new_count;
} bgit_xdiff_hunk;

typedef struct {
    char *old_changed;             /* one byte per line: was it removed? */
    char *new_changed;             /* one byte per line: was it added? */
    bgit_xdiff_hunk *hunks;
    size_t n_hunks;
    size_t added, removed;
} bgit_xdiff_result;

/* Split TEXT into lines. Caller frees with bgit_xdiff_release. */
int bgit_xdiff_load (bgit_xdiff_file *file, const char *text, size_t len);
void bgit_xdiff_release (bgit_xdiff_file *file);

/* One run of changed lines, as a replacement: COUNT lines of the old file
   from START become COUNT lines of the new file from its own START. */
typedef struct {
    size_t old_start, old_count;
    size_t new_start, new_count;
} bgit_xdiff_change;

/* The runs a result describes, in order. Caller frees *out. */
int bgit_xdiff_changes (const bgit_xdiff_result *result, size_t n_old,
                        size_t n_new, bgit_xdiff_change **out, size_t *n_out);

/* Compare two files with CONTEXT lines of context. Caller frees the result
   with bgit_xdiff_result_release. */
int bgit_xdiff (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                int context, bgit_xdiff_result *out);
void bgit_xdiff_result_release (bgit_xdiff_result *result);

/* The text a hunk header shows after the @@ pair: the nearest line at or
   above START that looks like the start of a definition, searched no further
   up than LIMIT (the previous hunk's, or -1). Returns the line's index, or
   -1 when nothing matched; *TEXT and *LEN describe the trimmed text. */
long bgit_xdiff_function (const bgit_xdiff_file *file, long start, long limit,
                          const char **text, size_t *len);

#endif /* BASH_OS_GIT_XDIFF_H */
