/* SPDX-License-Identifier: MIT */
/* _git/xdiff.c — the line diff behind a patch. See xdiff.h.
 *
 * Three stages, in git's order. First Myers' algorithm decides which lines
 * changed, in the linear-space form so a long file costs memory in the
 * number of lines rather than its square. Then each run of changed lines is
 * slid as far down as the file allows — sliding is possible whenever the
 * line above a run matches its last line — and the indent heuristic scores
 * every position it could have taken, preferring the one whose edges sit at
 * the shallower indentation, which is how a diff comes to start at the line
 * that opens a block rather than the one that closes the block before it.
 * Finally the runs are gathered into hunks: each takes its context, and two
 * runs closer than twice the context become one.
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
#include <ctype.h>

#include "xdiff.h"

int
bgit_xdiff_load (bgit_xdiff_file *file, const char *text, size_t len)
{
    memset (file, 0, sizeof *file);
    file->text = text;
    file->len = len;
    size_t scan = len > 8000 ? 8000 : len;
    for (size_t i = 0; i < scan; i++)
        if (!text[i]) { file->binary = 1; return 0; }

    size_t n = 0;
    for (size_t i = 0; i < len; i++)
        if (text[i] == '\n') n++;
    if (len && text[len - 1] != '\n') { n++; file->missing_newline = 1; }

    file->lines = calloc (n + 1, sizeof *file->lines);
    file->lengths = calloc (n + 1, sizeof *file->lengths);
    file->hashes = calloc (n + 1, sizeof *file->hashes);
    if (!file->lines || !file->lengths || !file->hashes) {
        bgit_xdiff_release (file);
        return -1;
    }
    size_t start = 0, index = 0;
    for (size_t i = 0; i <= len && index < n; i++) {
        if (i < len && text[i] != '\n') continue;
        file->lines[index] = text + start;
        file->lengths[index] = i - start;
        unsigned long hash = 5381;
        for (size_t k = start; k < i; k++)
            hash = hash * 33 + (unsigned char) text[k];
        file->hashes[index] = hash;
        index++;
        start = i + 1;
        if (i == len) break;
    }
    file->n = index;
    return 0;
}

void
bgit_xdiff_release (bgit_xdiff_file *file)
{
    free (file->lines);
    free (file->lengths);
    free (file->hashes);
    file->lines = NULL;
    file->lengths = NULL;
    file->hashes = NULL;
    file->n = 0;
}

void
bgit_xdiff_result_release (bgit_xdiff_result *result)
{
    if (result->old_changed) free (result->old_changed - 1);
    if (result->new_changed) free (result->new_changed - 1);
    free (result->hunks);
    memset (result, 0, sizeof *result);
}

/* ---------------------------------------------------------------- Myers */

static int
bgit_hash_cmp (const void *a, const void *b)
{
    unsigned long left = *(const unsigned long *) a;
    unsigned long right = *(const unsigned long *) b;
    return (left > right) - (left < right);
}

/* Does any line of the other file hash to this? A collision only keeps a
   line in the search, which costs a little work and no correctness. */
static int
bgit_hash_present (const unsigned long *sorted, size_t n, unsigned long hash)
{
    size_t low = 0, high = n;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (sorted[mid] < hash) low = mid + 1;
        else high = mid;
    }
    return low < n && sorted[low] == hash;
}

typedef struct {
    const bgit_xdiff_file *a, *b;
    const size_t *ia, *ib;      /* the lines still in the search, by index */
    char *ca, *cb;              /* changed flags, with a zero either side */
    long *vf, *vb;              /* the furthest-reaching paths, both ways */
    long offset;
} bgit_xd;

static int
bgit_xd_eq (const bgit_xd *x, size_t i, size_t j)
{
    size_t u = x->ia[i], v = x->ib[j];
    return x->a->hashes[u] == x->b->hashes[v] &&
           x->a->lengths[u] == x->b->lengths[v] &&
           !memcmp (x->a->lines[u], x->b->lines[v], x->a->lengths[u]);
}

/* The middle of an optimal edit path between the two ranges: the point where
   the search from the front and the search from the back meet. */
static void
bgit_xd_middle (bgit_xd *x, size_t a0, size_t a1, size_t b0, size_t b1,
                size_t *px, size_t *py)
{
    long n = (long) (a1 - a0), m = (long) (b1 - b0);
    long delta = n - m;
    int odd = (delta & 1) != 0;
    long *vf = x->vf + x->offset, *vb = x->vb + x->offset;
    long dmax = (n + m + 1) / 2 + 1;

    vf[1] = 0;
    vb[1] = 0;
    for (long d = 0; d <= dmax; d++) {
        for (long k = -d; k <= d; k += 2) {
            long fx = (k == -d || (k != d && vf[k - 1] < vf[k + 1]))
                      ? vf[k + 1] : vf[k - 1] + 1;
            long fy = fx - k;
            while (fx < n && fy < m && bgit_xd_eq (x, a0 + fx, b0 + fy)) {
                fx++;
                fy++;
            }
            vf[k] = fx;
            if (odd && k - delta >= -(d - 1) && k - delta <= d - 1 &&
                fx + vb[delta - k] >= n) {
                *px = a0 + (size_t) fx;
                *py = b0 + (size_t) fy;
                return;
            }
        }
        for (long k = -d; k <= d; k += 2) {
            long bx = (k == -d || (k != d && vb[k - 1] < vb[k + 1]))
                      ? vb[k + 1] : vb[k - 1] + 1;
            long by = bx - k;
            while (bx < n && by < m &&
                   bgit_xd_eq (x, a1 - 1 - (size_t) bx, b1 - 1 - (size_t) by)) {
                bx++;
                by++;
            }
            vb[k] = bx;
            if (!odd && delta - k >= -d && delta - k <= d &&
                bx + vf[delta - k] >= n) {
                *px = a1 - (size_t) bx;
                *py = b1 - (size_t) by;
                return;
            }
        }
    }
    /* Unreachable: the two searches always meet by dmax. Split anyway so a
       surprise cannot turn into an endless recursion. */
    *px = a0 + (size_t) (n / 2);
    *py = b0 + (size_t) (m / 2);
}

static void
bgit_xd_compare (bgit_xd *x, size_t a0, size_t a1, size_t b0, size_t b1)
{
    while (a0 < a1 && b0 < b1 && bgit_xd_eq (x, a0, b0)) { a0++; b0++; }
    while (a0 < a1 && b0 < b1 && bgit_xd_eq (x, a1 - 1, b1 - 1)) { a1--; b1--; }
    if (a0 == a1) {
        for (size_t j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
        return;
    }
    if (b0 == b1) {
        for (size_t i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
        return;
    }
    if (a1 - a0 == 1 && b1 - b0 == 1) {
        x->ca[x->ia[a0]] = 1;
        x->cb[x->ib[b0]] = 1;
        return;
    }
    size_t mx, my;
    bgit_xd_middle (x, a0, a1, b0, b1, &mx, &my);
    if ((mx == a0 && my == b0) || (mx == a1 && my == b1)) {
        /* No progress: describe the range as wholly changed rather than
           recurse for ever. */
        for (size_t i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
        for (size_t j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
        return;
    }
    bgit_xd_compare (x, a0, mx, b0, my);
    bgit_xd_compare (x, mx, a1, my, b1);
}

/* ---------------------------------------------------- git's compaction */

#define BGIT_MAX_INDENT 200
#define BGIT_MAX_BLANKS 20
#define BGIT_INDENT_WEIGHT 60
#define BGIT_START_OF_FILE_PENALTY 1
#define BGIT_END_OF_FILE_PENALTY 21
#define BGIT_TOTAL_BLANK_WEIGHT (-30)
#define BGIT_POST_BLANK_WEIGHT 6
#define BGIT_RELATIVE_INDENT_PENALTY (-4)
#define BGIT_RELATIVE_INDENT_WITH_BLANK_PENALTY 10
#define BGIT_RELATIVE_OUTDENT_PENALTY 24
#define BGIT_RELATIVE_OUTDENT_WITH_BLANK_PENALTY 17
#define BGIT_RELATIVE_DEDENT_PENALTY 23
#define BGIT_RELATIVE_DEDENT_WITH_BLANK_PENALTY 17

/* How far a line is indented, counting a tab to the next multiple of eight.
   A line that is nothing but whitespace has no indentation at all: -1. */
static int
bgit_indent_of (const char *line, size_t len)
{
    int indent = 0;
    for (size_t i = 0; i < len; i++) {
        char c = line[i];
        if (!isspace ((unsigned char) c)) return indent;
        if (c == ' ') indent += 1;
        else if (c == '\t') indent += 8 - indent % 8;
        if (indent >= BGIT_MAX_INDENT) return BGIT_MAX_INDENT;
    }
    return -1;
}

typedef struct {
    int end_of_file;
    int indent;
    int pre_blank, pre_indent;
    int post_blank, post_indent;
} bgit_split_measure;

typedef struct {
    int effective_indent;
    int penalty;
} bgit_split_score;

static void
bgit_measure_split (const bgit_xdiff_file *file, long split,
                    bgit_split_measure *m)
{
    memset (m, 0, sizeof *m);
    if (split >= (long) file->n) {
        m->end_of_file = 1;
        m->indent = -1;
    } else {
        m->indent = bgit_indent_of (file->lines[split], file->lengths[split]);
    }

    m->pre_indent = -1;
    for (long i = split - 1; i >= 0; i--) {
        m->pre_indent = bgit_indent_of (file->lines[i], file->lengths[i]);
        if (m->pre_indent != -1) break;
        m->pre_blank += 1;
        if (m->pre_blank == BGIT_MAX_BLANKS) { m->pre_indent = 0; break; }
    }

    m->post_indent = -1;
    for (long i = split + 1; i < (long) file->n; i++) {
        m->post_indent = bgit_indent_of (file->lines[i], file->lengths[i]);
        if (m->post_indent != -1) break;
        m->post_blank += 1;
        if (m->post_blank == BGIT_MAX_BLANKS) { m->post_indent = 0; break; }
    }
}

static void
bgit_score_add_split (const bgit_split_measure *m, bgit_split_score *s)
{
    if (m->pre_indent == -1 && m->pre_blank == 0)
        s->penalty += BGIT_START_OF_FILE_PENALTY;
    if (m->end_of_file)
        s->penalty += BGIT_END_OF_FILE_PENALTY;

    int post_blank = (m->indent == -1) ? 1 + m->post_blank : 0;
    int total_blank = m->pre_blank + post_blank;
    s->penalty += BGIT_TOTAL_BLANK_WEIGHT * total_blank;
    s->penalty += BGIT_POST_BLANK_WEIGHT * post_blank;

    int indent = (m->indent != -1) ? m->indent : m->post_indent;
    int any_blanks = total_blank != 0;
    s->effective_indent += indent;

    if (indent == -1 || m->pre_indent == -1 || indent == m->pre_indent) {
        /* Nothing more to say about this split. */
    } else if (indent > m->pre_indent) {
        s->penalty += any_blanks ? BGIT_RELATIVE_INDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_INDENT_PENALTY;
    } else if (m->post_indent != -1 && m->post_indent > m->indent) {
        /* Less indented than the line above but more than the line below:
           this looks like the start of a block, not the end of one. */
        s->penalty += any_blanks ? BGIT_RELATIVE_OUTDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_OUTDENT_PENALTY;
    } else {
        s->penalty += any_blanks ? BGIT_RELATIVE_DEDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_DEDENT_PENALTY;
    }
}

static int
bgit_score_cmp (const bgit_split_score *a, const bgit_split_score *b)
{
    int indents = (a->effective_indent > b->effective_indent) -
                  (a->effective_indent < b->effective_indent);
    return BGIT_INDENT_WEIGHT * indents + (a->penalty - b->penalty);
}

/* A run of changed lines, as compaction moves it about. */
typedef struct { long start, end; } bgit_group;

static void
bgit_group_init (const char *changed, bgit_group *g)
{
    g->start = g->end = 0;
    while (changed[g->end]) g->end++;
}

static int
bgit_group_next (const char *changed, long n, bgit_group *g)
{
    if (g->end == n) return -1;
    g->start = g->end + 1;
    for (g->end = g->start; changed[g->end]; g->end++)
        ;
    return 0;
}

static int
bgit_group_previous (const char *changed, bgit_group *g)
{
    if (g->start == 0) return -1;
    g->end = g->start - 1;
    for (g->start = g->end; changed[g->start - 1]; g->start--)
        ;
    return 0;
}

static int
bgit_lines_match (const bgit_xdiff_file *file, long i, long j)
{
    return file->hashes[i] == file->hashes[j] &&
           file->lengths[i] == file->lengths[j] &&
           !memcmp (file->lines[i], file->lines[j], file->lengths[i]);
}

static int
bgit_group_slide_up (const bgit_xdiff_file *file, char *changed, bgit_group *g)
{
    if (g->start > 0 && bgit_lines_match (file, g->start - 1, g->end - 1)) {
        changed[--g->start] = 1;
        changed[--g->end] = 0;
        while (changed[g->start - 1]) g->start--;
        return 0;
    }
    return -1;
}

static int
bgit_group_slide_down (const bgit_xdiff_file *file, char *changed,
                       bgit_group *g)
{
    if (g->end < (long) file->n && bgit_lines_match (file, g->start, g->end)) {
        changed[g->start++] = 0;
        changed[g->end++] = 1;
        while (changed[g->end]) g->end++;
        return 0;
    }
    return -1;
}

/* Move each run of changes in FILE to where it reads best, keeping the runs
   in the other file in step so the two descriptions stay paired. */
static void
bgit_compact (const bgit_xdiff_file *file, char *changed,
              const bgit_xdiff_file *other, char *other_changed)
{
    bgit_group g, go;
    bgit_group_init (changed, &g);
    bgit_group_init (other_changed, &go);

    for (;;) {
        if (g.end == g.start) goto next;

        long size, earliest_end, matching_other;
        do {
            size = g.end - g.start;
            matching_other = -1;
            while (!bgit_group_slide_up (file, changed, &g))
                if (bgit_group_previous (other_changed, &go)) break;
            earliest_end = g.end;
            if (go.end > go.start) matching_other = g.end;
            for (;;) {
                if (bgit_group_slide_down (file, changed, &g)) break;
                if (bgit_group_next (other_changed, (long) other->n, &go)) break;
                if (go.end > go.start) matching_other = g.end;
            }
        } while (size != g.end - g.start);

        if (g.end == earliest_end) {
            /* The run cannot move, so there is nothing to choose. */
        } else if (matching_other != -1) {
            /* Line the run up with the last run in the other file it can
               sit beside: a replacement reads better than a delete and an
               add that have drifted apart. */
            while (go.end == go.start) {
                if (bgit_group_slide_up (file, changed, &g)) break;
                if (bgit_group_previous (other_changed, &go)) break;
            }
        } else {
            long best_shift = -1;
            bgit_split_score best = {0, 0};
            for (long shift = earliest_end; shift <= g.end; shift++) {
                bgit_split_measure m;
                bgit_split_score score = {0, 0};
                bgit_measure_split (file, shift, &m);
                bgit_score_add_split (&m, &score);
                bgit_measure_split (file, shift - size, &m);
                bgit_score_add_split (&m, &score);
                if (best_shift == -1 || bgit_score_cmp (&score, &best) <= 0) {
                    best = score;
                    best_shift = shift;
                }
            }
            while (g.end > best_shift) {
                if (bgit_group_slide_up (file, changed, &g)) break;
                if (bgit_group_previous (other_changed, &go)) break;
            }
        }

    next:
        if (bgit_group_next (changed, (long) file->n, &g)) break;
        if (bgit_group_next (other_changed, (long) other->n, &go)) break;
    }
}

/* ------------------------------------------------------------- the hunks */

int
bgit_xdiff (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
            int context, bgit_xdiff_result *out)
{
    memset (out, 0, sizeof *out);
    if (context < 0) context = 0;

    /* One spare byte at each end, so a scan may look just past either. */
    char *ca = calloc (old->n + 2, 1);
    char *cb = calloc (new_file->n + 2, 1);
    long *vf = calloc (2 * (old->n + new_file->n) + 4, sizeof *vf);
    long *vb = calloc (2 * (old->n + new_file->n) + 4, sizeof *vb);
    if (!ca || !cb || !vf || !vb) {
        free (ca); free (cb); free (vf); free (vb);
        return -1;
    }
    out->old_changed = ca + 1;
    out->new_changed = cb + 1;

    /* A line that appears nowhere in the other file can be in no match, so
       it is marked changed here and left out of the search — git reduces
       the problem the same way before running the algorithm, and it is what
       makes two equally short answers come out the same way round. */
    size_t *ia = malloc ((old->n + 1) * sizeof *ia);
    size_t *ib = malloc ((new_file->n + 1) * sizeof *ib);
    unsigned long *sorted_a = malloc ((old->n + 1) * sizeof *sorted_a);
    unsigned long *sorted_b = malloc ((new_file->n + 1) * sizeof *sorted_b);
    if (!ia || !ib || !sorted_a || !sorted_b) {
        free (ia); free (ib); free (sorted_a); free (sorted_b);
        free (vf); free (vb);
        bgit_xdiff_result_release (out);
        return -1;
    }
    memcpy (sorted_a, old->hashes, old->n * sizeof *sorted_a);
    memcpy (sorted_b, new_file->hashes, new_file->n * sizeof *sorted_b);
    qsort (sorted_a, old->n, sizeof *sorted_a, bgit_hash_cmp);
    qsort (sorted_b, new_file->n, sizeof *sorted_b, bgit_hash_cmp);
    size_t na = 0, nb = 0;
    for (size_t i = 0; i < old->n; i++) {
        if (bgit_hash_present (sorted_b, new_file->n, old->hashes[i]))
            ia[na++] = i;
        else out->old_changed[i] = 1;
    }
    for (size_t j = 0; j < new_file->n; j++) {
        if (bgit_hash_present (sorted_a, old->n, new_file->hashes[j]))
            ib[nb++] = j;
        else out->new_changed[j] = 1;
    }
    free (sorted_a);
    free (sorted_b);

    bgit_xd x = {old, new_file, ia, ib, out->old_changed, out->new_changed,
                 vf, vb, (long) (old->n + new_file->n) + 1};
    bgit_xd_compare (&x, 0, na, 0, nb);
    free (vf);
    free (vb);
    free (ia);
    free (ib);

    bgit_compact (old, out->old_changed, new_file, out->new_changed);
    bgit_compact (new_file, out->new_changed, old, out->old_changed);

    for (size_t i = 0; i < old->n; i++) out->removed += !!out->old_changed[i];
    for (size_t j = 0; j < new_file->n; j++) out->added += !!out->new_changed[j];
    if (!out->added && !out->removed) return 0;

    /* Gather the runs of change, then give each hunk its context, merging
       two hunks whose context would overlap. */
    size_t capacity = 8;
    bgit_xdiff_hunk *hunks = calloc (capacity, sizeof *hunks);
    if (!hunks) { bgit_xdiff_result_release (out); return -1; }
    size_t n_hunks = 0;
    size_t i = 0, j = 0;
    while (i < old->n || j < new_file->n) {
        int changed = (i < old->n && out->old_changed[i]) ||
                      (j < new_file->n && out->new_changed[j]);
        if (!changed) { i++; j++; continue; }
        size_t i0 = i, j0 = j;
        while (i < old->n && out->old_changed[i]) i++;
        while (j < new_file->n && out->new_changed[j]) j++;

        size_t s1 = i0 > (size_t) context ? i0 - context : 0;
        size_t s2 = j0 > (size_t) context ? j0 - context : 0;
        size_t e1 = i + context < old->n ? i + context : old->n;
        size_t e2 = j + context < new_file->n ? j + context : new_file->n;
        if (n_hunks &&
            s1 <= hunks[n_hunks - 1].old_start + hunks[n_hunks - 1].old_count) {
            bgit_xdiff_hunk *last = &hunks[n_hunks - 1];
            last->old_count = e1 - last->old_start;
            last->new_count = e2 - last->new_start;
            continue;
        }
        if (n_hunks == capacity) {
            capacity *= 2;
            bgit_xdiff_hunk *grown = realloc (hunks, capacity * sizeof *grown);
            if (!grown) { free (hunks); bgit_xdiff_result_release (out); return -1; }
            hunks = grown;
        }
        hunks[n_hunks].old_start = s1;
        hunks[n_hunks].old_count = e1 - s1;
        hunks[n_hunks].new_start = s2;
        hunks[n_hunks].new_count = e2 - s2;
        n_hunks++;
    }
    out->hunks = hunks;
    out->n_hunks = n_hunks;
    return 0;
}

int
bgit_xdiff_changes (const bgit_xdiff_result *result, size_t n_old, size_t n_new,
                    bgit_xdiff_change **out, size_t *n_out)
{
    size_t capacity = 8, n = 0;
    bgit_xdiff_change *changes = calloc (capacity, sizeof *changes);
    if (!changes) return -1;
    size_t i = 0, j = 0;
    while (i < n_old || j < n_new) {
        int changed = (i < n_old && result->old_changed[i]) ||
                      (j < n_new && result->new_changed[j]);
        if (!changed) { i++; j++; continue; }
        size_t i0 = i, j0 = j;
        while (i < n_old && result->old_changed[i]) i++;
        while (j < n_new && result->new_changed[j]) j++;
        if (n == capacity) {
            capacity *= 2;
            bgit_xdiff_change *grown = realloc (changes, capacity * sizeof *grown);
            if (!grown) { free (changes); return -1; }
            changes = grown;
        }
        changes[n].old_start = i0;
        changes[n].old_count = i - i0;
        changes[n].new_start = j0;
        changes[n].new_count = j - j0;
        n++;
    }
    *out = changes;
    *n_out = n;
    return 0;
}

long
bgit_xdiff_function (const bgit_xdiff_file *file, long start, long limit,
                     const char **text, size_t *len)
{
    for (long i = start; i > limit && i >= 0 && i < (long) file->n; i--) {
        const char *line = file->lines[i];
        size_t length = file->lengths[i];
        if (!length) continue;
        unsigned char first = (unsigned char) line[0];
        if (!isalpha (first) && first != '_' && first != '$') continue;
        if (length > 80) length = 80;
        while (length > 0 && isspace ((unsigned char) line[length - 1])) length--;
        *text = line;
        *len = length;
        return i;
    }
    return -1;
}
