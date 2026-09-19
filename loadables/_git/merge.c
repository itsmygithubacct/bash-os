/* SPDX-License-Identifier: MIT */
/* _git/merge.c — where two histories last agreed. See merge.h.
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

#include "loadables.h"

#include "merge.h"
#include "odb.h"
#include "revision.h"

#define BGIT_PARENT1 1u
#define BGIT_PARENT2 2u
#define BGIT_STALE   4u
#define BGIT_RESULT  8u

/* What is known about one commit during a walk. */
struct bgit_mark {
    char sha[41];
    unsigned flags;
    long long date;
    int used;
};

/* An open-addressed table of marks, so a big history costs one lookup a
   commit rather than a scan. */
struct bgit_marks {
    struct bgit_mark *slots;
    size_t size, count;
};

static size_t
bgit_mark_hash (const char *sha)
{
    size_t hash = 1469598103934665603ULL % 1000000007ULL;
    for (int i = 0; i < 40 && sha[i]; i++)
        hash = hash * 131 + (unsigned char) sha[i];
    return hash;
}

static int bgit_marks_grow (struct bgit_marks *marks);

static struct bgit_mark *
bgit_marks_at (struct bgit_marks *marks, const char *sha)
{
    if (marks->count * 2 >= marks->size && bgit_marks_grow (marks) < 0)
        return NULL;
    size_t mask = marks->size - 1;
    size_t at = bgit_mark_hash (sha) & mask;
    while (marks->slots[at].used) {
        if (!memcmp (marks->slots[at].sha, sha, 40)) return &marks->slots[at];
        at = (at + 1) & mask;
    }
    marks->slots[at].used = 1;
    memcpy (marks->slots[at].sha, sha, 40);
    marks->slots[at].sha[40] = '\0';
    marks->slots[at].flags = 0;
    marks->slots[at].date = 0;
    marks->count++;
    return &marks->slots[at];
}

static int
bgit_marks_grow (struct bgit_marks *marks)
{
    size_t next = marks->size ? marks->size * 2 : 256;
    struct bgit_mark *slots = calloc (next, sizeof *slots);
    if (!slots) return -1;
    struct bgit_mark *old = marks->slots;
    size_t old_size = marks->size;
    marks->slots = slots;
    marks->size = next;
    marks->count = 0;
    for (size_t i = 0; i < old_size; i++) {
        if (!old[i].used) continue;
        struct bgit_mark *mark = bgit_marks_at (marks, old[i].sha);
        if (!mark) { free (old); return -1; }
        mark->flags = old[i].flags;
        mark->date = old[i].date;
    }
    free (old);
    return 0;
}

static void
bgit_marks_release (struct bgit_marks *marks)
{
    free (marks->slots);
    memset (marks, 0, sizeof *marks);
}

/* The committer date a commit records, which is what orders the walk. */
static long long
bgit_commit_date (bgit_odb *odb, const char *sha)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return 0;
    long long date = 0;
    const char *p = (const char *) data, *end = p + len;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) break;
        if (line > 10 && !memcmp (p, "committer ", 10)) {
            const char *close = memchr (p, '>', line);
            if (close) date = strtoll (close + 1, NULL, 10);
            break;
        }
        if (!nl) break;
        p = nl + 1;
    }
    free (data);
    return date;
}

/* Commits waiting to be walked: newest first, and among commits of the same
   date the one that arrived first, which is the order git's queue keeps. */
struct bgit_queue {
    struct { char sha[41]; long long date; unsigned long counter; } *items;
    size_t n, cap;
    unsigned long counter;
};

static int
bgit_queue_put (struct bgit_queue *queue, const char *sha, long long date)
{
    if (queue->n == queue->cap) {
        size_t next = queue->cap ? queue->cap * 2 : 64;
        void *grown = realloc (queue->items, next * sizeof *queue->items);
        if (!grown) return -1;
        queue->items = grown;
        queue->cap = next;
    }
    memcpy (queue->items[queue->n].sha, sha, 40);
    queue->items[queue->n].sha[40] = '\0';
    queue->items[queue->n].date = date;
    queue->items[queue->n].counter = queue->counter++;
    queue->n++;
    return 0;
}

static int
bgit_queue_get (struct bgit_queue *queue, char out[41])
{
    if (!queue->n) return -1;
    size_t best = 0;
    for (size_t i = 1; i < queue->n; i++) {
        if (queue->items[i].date > queue->items[best].date ||
            (queue->items[i].date == queue->items[best].date &&
             queue->items[i].counter < queue->items[best].counter))
            best = i;
    }
    memcpy (out, queue->items[best].sha, 41);
    memmove (queue->items + best, queue->items + best + 1,
             (queue->n - best - 1) * sizeof *queue->items);
    queue->n--;
    return 0;
}

/* Is anything left that is not already known to be stale? */
static int
bgit_queue_has_fresh (struct bgit_queue *queue, struct bgit_marks *marks)
{
    for (size_t i = 0; i < queue->n; i++) {
        struct bgit_mark *mark = bgit_marks_at (marks, queue->items[i].sha);
        if (mark && !(mark->flags & BGIT_STALE)) return 1;
    }
    return 0;
}

/* A list of ids, kept in the order they were added. */
struct bgit_ids {
    char (*ids)[41];
    size_t n, cap;
};

static int
bgit_ids_add (struct bgit_ids *list, const char *sha)
{
    if (list->n == list->cap) {
        size_t next = list->cap ? list->cap * 2 : 8;
        void *grown = realloc (list->ids, next * sizeof *list->ids);
        if (!grown) return -1;
        list->ids = grown;
        list->cap = next;
    }
    memcpy (list->ids[list->n], sha, 40);
    list->ids[list->n][40] = '\0';
    list->n++;
    return 0;
}

/* Paint down to the common ancestors, as git does: the commits carrying
   both marks, oldest ancestors dropped as stale. */
static int
bgit_paint_down (bgit_odb *odb, const char *one, const char *const *twos,
                 int n_twos, struct bgit_ids *result)
{
    struct bgit_marks marks;
    struct bgit_queue queue;
    memset (&marks, 0, sizeof marks);
    memset (&queue, 0, sizeof queue);
    int rc = -1;

    struct bgit_mark *mark = bgit_marks_at (&marks, one);
    if (!mark) goto done;
    mark->flags |= BGIT_PARENT1;
    if (bgit_queue_put (&queue, one, bgit_commit_date (odb, one)) < 0) goto done;
    for (int i = 0; i < n_twos; i++) {
        mark = bgit_marks_at (&marks, twos[i]);
        if (!mark) goto done;
        mark->flags |= BGIT_PARENT2;
        if (bgit_queue_put (&queue, twos[i], bgit_commit_date (odb, twos[i])) < 0)
            goto done;
    }

    while (bgit_queue_has_fresh (&queue, &marks)) {
        char current[41];
        if (bgit_queue_get (&queue, current) < 0) break;
        mark = bgit_marks_at (&marks, current);
        if (!mark) goto done;
        unsigned flags = mark->flags & (BGIT_PARENT1 | BGIT_PARENT2 | BGIT_STALE);
        if (flags == (BGIT_PARENT1 | BGIT_PARENT2)) {
            if (!(mark->flags & BGIT_RESULT)) {
                mark->flags |= BGIT_RESULT;
                if (bgit_ids_add (result, current) < 0) goto done;
            }
            flags |= BGIT_STALE;     /* its ancestors cannot be better */
        }
        char parents[BGIT_MAX_PARENTS][41];
        int count = bgit_commit_parents (odb, current, parents, BGIT_MAX_PARENTS);
        for (int i = 0; i < count; i++) {
            struct bgit_mark *parent = bgit_marks_at (&marks, parents[i]);
            if (!parent) goto done;
            if ((parent->flags & flags) == flags) continue;
            parent->flags |= flags;
            if (bgit_queue_put (&queue, parents[i],
                                bgit_commit_date (odb, parents[i])) < 0)
                goto done;
        }
    }
    rc = 0;
done:
    bgit_marks_release (&marks);
    free (queue.items);
    return rc;
}

int
bgit_is_ancestor (bgit_odb *odb, const char *ancestor, const char *commit)
{
    if (!memcmp (ancestor, commit, 40)) return 1;
    struct bgit_ids bases;
    memset (&bases, 0, sizeof bases);
    const char *twos[1] = { commit };
    if (bgit_paint_down (odb, ancestor, twos, 1, &bases) < 0) {
        free (bases.ids);
        return -1;
    }
    int found = 0;
    for (size_t i = 0; i < bases.n && !found; i++)
        if (!memcmp (bases.ids[i], ancestor, 40)) found = 1;
    free (bases.ids);
    return found;
}

/* Drop any candidate another candidate already reaches. */
static int
bgit_remove_redundant (bgit_odb *odb, struct bgit_ids *list)
{
    if (list->n < 2) return 0;
    char *drop = calloc (list->n, 1);
    if (!drop) return -1;
    for (size_t i = 0; i < list->n; i++) {
        for (size_t j = 0; j < list->n; j++) {
            if (i == j || drop[i] || drop[j]) continue;
            int reaches = bgit_is_ancestor (odb, list->ids[i], list->ids[j]);
            if (reaches < 0) { free (drop); return -1; }
            if (reaches) { drop[i] = 1; break; }
        }
    }
    size_t kept = 0;
    for (size_t i = 0; i < list->n; i++)
        if (!drop[i]) memcpy (list->ids[kept++], list->ids[i], 41);
    list->n = kept;
    free (drop);
    return 0;
}

int
bgit_merge_bases_many (bgit_odb *odb, const char *one, const char *const *twos,
                       int n_twos, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    /* A commit named on both sides is its own base. */
    for (int i = 0; i < n_twos; i++)
        if (!memcmp (one, twos[i], 40)) {
            struct bgit_ids single;
            memset (&single, 0, sizeof single);
            if (bgit_ids_add (&single, one) < 0) return -1;
            *out = single.ids;
            *n_out = single.n;
            return 0;
        }

    struct bgit_ids result;
    memset (&result, 0, sizeof result);
    if (bgit_paint_down (odb, one, twos, n_twos, &result) < 0 ||
        bgit_remove_redundant (odb, &result) < 0) {
        free (result.ids);
        return -1;
    }
    *out = result.ids;
    *n_out = result.n;
    return 0;
}

int
bgit_merge_bases_octopus (bgit_odb *odb, const char *const *commits, int n,
                          char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    if (n < 1) return 0;
    struct bgit_ids carried;
    memset (&carried, 0, sizeof carried);
    if (bgit_ids_add (&carried, commits[0]) < 0) return -1;

    for (int i = 1; i < n; i++) {
        struct bgit_ids next;
        memset (&next, 0, sizeof next);
        for (size_t j = 0; j < carried.n; j++) {
            char (*bases)[41] = NULL;
            size_t n_bases = 0;
            const char *twos[1] = { carried.ids[j] };
            if (bgit_merge_bases_many (odb, commits[i], twos, 1, &bases,
                                       &n_bases) < 0) {
                free (next.ids);
                free (carried.ids);
                return -1;
            }
            for (size_t k = 0; k < n_bases; k++)
                if (bgit_ids_add (&next, bases[k]) < 0) {
                    free (bases);
                    free (next.ids);
                    free (carried.ids);
                    return -1;
                }
            free (bases);
        }
        free (carried.ids);
        carried = next;
    }
    if (bgit_remove_redundant (odb, &carried) < 0) {
        free (carried.ids);
        return -1;
    }
    *out = carried.ids;
    *n_out = carried.n;
    return 0;
}

int
bgit_independent (bgit_odb *odb, const char *const *commits, int n,
                  char (**out)[41], size_t *n_out)
{
    struct bgit_ids list;
    memset (&list, 0, sizeof list);
    for (int i = 0; i < n; i++)
        if (bgit_ids_add (&list, commits[i]) < 0) {
            free (list.ids);
            return -1;
        }
    if (bgit_remove_redundant (odb, &list) < 0) {
        free (list.ids);
        return -1;
    }
    *out = list.ids;
    *n_out = list.n;
    return 0;
}
