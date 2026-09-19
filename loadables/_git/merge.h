/* SPDX-License-Identifier: MIT */
/* _git/merge.h — where two histories last agreed.
 *
 * The merge base of two commits is their best common ancestor: the commit
 * a three-way merge compares both sides against. Two histories that have
 * merged each other can have several, none of them an ancestor of another,
 * and git reports them all when asked.
 *
 * The walk is git's: paint every commit reachable from the first side with
 * one mark and from the others with a second, oldest last, and a commit
 * carrying both marks is a common ancestor; its own ancestors are then
 * stale and cannot be better. Commits come off the walk newest first, ties
 * in the order they went on, which is what makes the answer the same one
 * git gives when several commits share a date.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_MERGE_H
#define BASH_OS_GIT_MERGE_H

#include <stddef.h>

#include "odb.h"

/* The best common ancestors of ONE and each of TWOS. Caller frees *out. */
int bgit_merge_bases_many (bgit_odb *odb, const char *one,
                           const char *const *twos, int n_twos,
                           char (**out)[41], size_t *n_out);

/* The common ancestors of every commit named, as `merge-base --octopus`
   reduces them. */
int bgit_merge_bases_octopus (bgit_odb *odb, const char *const *commits, int n,
                              char (**out)[41], size_t *n_out);

/* Is ANCESTOR reachable from COMMIT? 1 yes, 0 no, -1 on error. */
int bgit_is_ancestor (bgit_odb *odb, const char *ancestor, const char *commit);

/* Those of COMMITS that no other reaches: `merge-base --independent`. */
int bgit_independent (bgit_odb *odb, const char *const *commits, int n,
                      char (**out)[41], size_t *n_out);

/* The result of merging one file's three versions. */
typedef struct {
    char *text;
    size_t len;
    int conflicts;        /* how many regions neither side could settle */
} bgit_merge_result;

/* Merge OURS and THEIRS over their common BASE, line by line, as git does:
   a region only one side changed is taken from that side, a region both
   changed the same way is taken once, and anything else is written out
   between conflict markers carrying the two labels. Caller frees
   result->text. */
int bgit_merge_content (const char *base, size_t base_len,
                        const char *ours, size_t ours_len,
                        const char *theirs, size_t theirs_len,
                        const char *our_label, const char *their_label,
                        bgit_merge_result *result);

#endif /* BASH_OS_GIT_MERGE_H */
