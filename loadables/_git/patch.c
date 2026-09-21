/* SPDX-License-Identifier: MIT */
/* _git/patch.c — turning a list of changed paths into what git prints.
 * See patch.h.
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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "loadables.h"

#include "patch.h"
#include "xdiff.h"

void
bgit_patch_options_init (bgit_patch_options *options)
{
    memset (options, 0, sizeof *options);
    options->context = 3;
    options->abbrev = 7;
    options->prefix_old = "a/";
    options->prefix_new = "b/";
    options->line_prefix = "";
}

const char *
bgit_quote_path (const char *path, char *buf, size_t size)
{
    int special = 0;
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char) *p;
        if (c < 0x20 || c == 0x7f || c >= 0x80 || c == '"' || c == '\\')
            special = 1;
    }
    if (!special) return path;

    size_t at = 0;
    if (at + 1 < size) buf[at++] = '"';
    for (const char *p = path; *p && at + 5 < size; p++) {
        unsigned char c = (unsigned char) *p;
        const char *escape = NULL;
        switch (c) {
        case '"': escape = "\\\""; break;
        case '\\': escape = "\\\\"; break;
        case '\a': escape = "\\a"; break;
        case '\b': escape = "\\b"; break;
        case '\f': escape = "\\f"; break;
        case '\n': escape = "\\n"; break;
        case '\r': escape = "\\r"; break;
        case '\t': escape = "\\t"; break;
        case '\v': escape = "\\v"; break;
        default: break;
        }
        if (escape) {
            at += (size_t) snprintf (buf + at, size - at, "%s", escape);
        } else if (c < 0x20 || c == 0x7f || c >= 0x80) {
            at += (size_t) snprintf (buf + at, size - at, "\\%03o", c);
        } else {
            buf[at++] = (char) c;
        }
    }
    if (at + 2 < size) buf[at++] = '"';
    buf[at] = '\0';
    return buf;
}

/* Read a file in the working tree, following git's view of a symlink: its
   content is the path it points at. */
static int
bgit_read_worktree_file (const bgit_repo *repo, const char *path,
                         char **data, size_t *len)
{
    char full[4096];
    if (!repo || !repo->work_tree ||
        snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
        (int) sizeof full)
        return -1;
    struct stat st;
    if (lstat (full, &st) < 0) return -1;
    if (S_ISLNK (st.st_mode)) {
        size_t size = (size_t) st.st_size + 1;
        char *target = malloc (size + 1);
        if (!target) return -1;
        ssize_t got = readlink (full, target, size);
        if (got < 0) { free (target); return -1; }
        target[got] = '\0';
        *data = target;
        *len = (size_t) got;
        return 0;
    }
    int fd = open (full, O_RDONLY);
    if (fd < 0) return -1;
    size_t size = (size_t) st.st_size, at = 0;
    char *buf = malloc (size + 1);
    if (!buf) { close (fd); return -1; }
    while (at < size) {
        ssize_t got = read (fd, buf + at, size - at);
        if (got < 0) {
            if (errno == EINTR) continue;
            free (buf);
            close (fd);
            return -1;
        }
        if (!got) break;
        at += (size_t) got;
    }
    close (fd);
    buf[at] = '\0';
    *data = buf;
    *len = at;
    return 0;
}

int
bgit_patch_content (bgit_odb *odb, const bgit_repo *repo,
                    const bgit_diff_entry *entry, int side,
                    const bgit_patch_options *options,
                    char **data, size_t *len)
{
    *data = NULL;
    *len = 0;
    const char *sha = side ? entry->new_sha : entry->old_sha;
    if (side ? entry->status == 'D'
             : (entry->status == 'A' || !*entry->old_sha)) {
        *data = malloc (1);
        if (!*data) return -1;
        (*data)[0] = '\0';
        return 0;
    }
    /* A submodule has no blob. What git shows for one is the line that
       names the commit it points at. */
    if ((side ? entry->new_mode : entry->old_mode) == 0160000) {
        char line[80];
        int wrote = snprintf (line, sizeof line, "Subproject commit %s\n", sha);
        if (wrote < 0 || wrote >= (int) sizeof line) return -1;
        *data = malloc ((size_t) wrote + 1);
        if (!*data) return -1;
        memcpy (*data, line, (size_t) wrote + 1);
        *len = (size_t) wrote;
        return 0;
    }
    if (side && options->new_from_worktree)
        return bgit_read_worktree_file (repo, entry->path, data, len);

    enum bgit_type type;
    unsigned char *content = NULL;
    size_t size = 0;
    if (bgit_odb_read (odb, sha, &type, &content, &size) < 0) return -1;
    *data = (char *) content;
    *len = size;
    return 0;
}

/* The header lines every changed path starts with. */
static void
bgit_patch_header (FILE *out, const bgit_diff_entry *entry,
                   const bgit_patch_options *options, int identical)
{
    char quoted[8192];
    const char *name = bgit_quote_path (entry->path, quoted, sizeof quoted);
    const char *lp = options->line_prefix;
    char from_quoted[8192];
    const char *from = entry->from
        ? bgit_quote_path (entry->from, from_quoted, sizeof from_quoted) : name;
    fprintf (out, "%sdiff --git %s%s %s%s\n", lp, options->prefix_old, from,
             options->prefix_new, name);

    if (entry->status == 'R') {
        /* The percentage is the score out of git's sixty thousand. */
        fprintf (out, "%ssimilarity index %d%%\n", lp,
                 entry->score * 100 / 60000);
        fprintf (out, "%srename from %s\n", lp, from);
        fprintf (out, "%srename to %s\n", lp, name);
    }
    if (entry->status == 'A')
        fprintf (out, "%snew file mode %06o\n", lp, entry->new_mode);
    else if (entry->status == 'D')
        fprintf (out, "%sdeleted file mode %06o\n", lp, entry->old_mode);
    else if (entry->old_mode != entry->new_mode) {
        fprintf (out, "%sold mode %06o\n", lp, entry->old_mode);
        fprintf (out, "%snew mode %06o\n", lp, entry->new_mode);
    }
    if (identical) return;   /* nothing moved but the name or the mode */

    int abbrev = options->abbrev;
    char zeros[41];
    memset (zeros, '0', sizeof zeros);
    zeros[abbrev] = '\0';
    const char *old_id = entry->status == 'A' ? zeros : entry->old_sha;
    const char *new_id = entry->status == 'D' ? zeros : entry->new_sha;
    fprintf (out, "%sindex %.*s..%.*s", lp, abbrev, old_id, abbrev, new_id);
    if ((entry->status == 'M' || entry->status == 'R') &&
        entry->old_mode == entry->new_mode)
        fprintf (out, " %06o", entry->new_mode);
    fputc ('\n', out);
}

static void
bgit_patch_range (FILE *out, size_t start, size_t count)
{
    if (count == 1) fprintf (out, "%zu", start + 1);
    else fprintf (out, "%zu,%zu", count ? start + 1 : start, count);
}

static void
bgit_patch_line (FILE *out, const char *lp, char sign,
                 const bgit_xdiff_file *file, size_t index)
{
    fprintf (out, "%s%c", lp, sign);
    fwrite (file->lines[index], 1, file->lengths[index], out);
    fputc ('\n', out);
    if (file->missing_newline && index + 1 == file->n)
        fprintf (out, "%s\\ No newline at end of file\n", lp);
}

/* A symlink, a file and a submodule are different kinds of thing, so a path
   that changed from one to another is shown as a deletion and an addition. */
static int
bgit_mode_kind (uint32_t mode)
{
    return mode == 0120000 ? 1 : mode == 0160000 ? 2 : 0;
}

static int
bgit_patch_single (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                   const bgit_diff_entry *entry,
                   const bgit_patch_options *options)
{
    char *old_data = NULL, *new_data = NULL;
    size_t old_len = 0, new_len = 0;
    if (bgit_patch_content (odb, repo, entry, 0, options, &old_data, &old_len) < 0)
        return -1;
    if (bgit_patch_content (odb, repo, entry, 1, options, &new_data, &new_len) < 0) {
        free (old_data);
        return -1;
    }

    int identical = (entry->status == 'M' || entry->status == 'R') &&
                    !strcmp (entry->old_sha, entry->new_sha);
    bgit_patch_header (out, entry, options, identical);
    if (identical) {
        free (old_data);
        free (new_data);
        return 0;
    }

    bgit_xdiff_file old_file, new_file;
    if (bgit_xdiff_load (&old_file, old_data, old_len) < 0 ||
        bgit_xdiff_load (&new_file, new_data, new_len) < 0) {
        bgit_xdiff_release (&old_file);
        free (old_data);
        free (new_data);
        return -1;
    }
    const char *lp = options->line_prefix;
    if (old_file.binary || new_file.binary) {
        char quoted[8192];
        const char *name = bgit_quote_path (entry->path, quoted, sizeof quoted);
        fprintf (out, "%sBinary files %s%s and %s%s differ\n", lp,
                 entry->status == 'A' ? "" : options->prefix_old,
                 entry->status == 'A' ? "/dev/null" : name,
                 entry->status == 'D' ? "" : options->prefix_new,
                 entry->status == 'D' ? "/dev/null" : name);
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
        return 0;
    }

    bgit_xdiff_result result;
    if (bgit_xdiff (&old_file, &new_file, options->context, &result) < 0) {
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
        return -1;
    }

    if (result.n_hunks) {
        char quoted[8192], from_quoted[8192];
        const char *name = bgit_quote_path (entry->path, quoted, sizeof quoted);
        /* A rename's old side is named where it used to live. */
        const char *from = entry->from
            ? bgit_quote_path (entry->from, from_quoted, sizeof from_quoted)
            : name;
        if (entry->status == 'A')
            fprintf (out, "%s--- /dev/null\n", lp);
        else
            fprintf (out, "%s--- %s%s\n", lp, options->prefix_old, from);
        if (entry->status == 'D')
            fprintf (out, "%s+++ /dev/null\n", lp);
        else
            fprintf (out, "%s+++ %s%s\n", lp, options->prefix_new, name);
    }

    for (size_t h = 0; h < result.n_hunks; h++) {
        const bgit_xdiff_hunk *hunk = &result.hunks[h];
        fprintf (out, "%s@@ -", lp);
        bgit_patch_range (out, hunk->old_start, hunk->old_count);
        fprintf (out, " +");
        bgit_patch_range (out, hunk->new_start, hunk->new_count);
        fprintf (out, " @@");
        const char *text = NULL;
        size_t length = 0;
        /* Each hunk looks as far up as it needs to, and two hunks inside the
           same definition both name it, as git's headers do. */
        long line = bgit_xdiff_function (&old_file, (long) hunk->old_start - 1,
                                         -1, &text, &length);
        if (line >= 0 && length) {
            fputc (' ', out);
            fwrite (text, 1, length, out);
        }
        fputc ('\n', out);

        size_t i = hunk->old_start, j = hunk->new_start;
        size_t end_old = i + hunk->old_count, end_new = j + hunk->new_count;
        while (i < end_old || j < end_new) {
            int changed = (i < end_old && result.old_changed[i]) ||
                          (j < end_new && result.new_changed[j]);
            if (!changed) {
                bgit_patch_line (out, lp, ' ', &old_file, i);
                i++;
                j++;
                continue;
            }
            while (i < end_old && result.old_changed[i])
                bgit_patch_line (out, lp, '-', &old_file, i++);
            while (j < end_new && result.new_changed[j])
                bgit_patch_line (out, lp, '+', &new_file, j++);
        }
    }

    bgit_xdiff_result_release (&result);
    bgit_xdiff_release (&old_file);
    bgit_xdiff_release (&new_file);
    free (old_data);
    free (new_data);
    return 0;
}

static int
bgit_patch_one (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                const bgit_diff_entry *entry, const bgit_patch_options *options)
{
    if (entry->status == 'M' &&
        bgit_mode_kind (entry->old_mode) != bgit_mode_kind (entry->new_mode)) {
        bgit_diff_entry removed = *entry, added = *entry;
        removed.status = 'D';
        added.status = 'A';
        return bgit_patch_single (out, odb, repo, &removed, options) < 0 ||
               bgit_patch_single (out, odb, repo, &added, options) < 0 ? -1 : 0;
    }
    return bgit_patch_single (out, odb, repo, entry, options);
}

int
bgit_patch_write (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                  const bgit_diff_entry *entries, size_t n,
                  const bgit_patch_options *options)
{
    for (size_t i = 0; i < n; i++)
        if (bgit_patch_one (out, odb, repo, &entries[i], options) < 0)
            return -1;
    return 0;
}

int
bgit_diffstat (bgit_odb *odb, const bgit_repo *repo,
               const bgit_diff_entry *entries, size_t n,
               const bgit_patch_options *options, bgit_diffstat_entry **out)
{
    bgit_diffstat_entry *stats = calloc (n ? n : 1, sizeof *stats);
    if (!stats) return -1;
    for (size_t i = 0; i < n; i++) {
        stats[i].entry = &entries[i];
        if (entries[i].status == 'M' &&
            !strcmp (entries[i].old_sha, entries[i].new_sha))
            continue;                       /* a mode change counts as nothing */
        char *old_data = NULL, *new_data = NULL;
        size_t old_len = 0, new_len = 0;
        if (bgit_patch_content (odb, repo, &entries[i], 0, options,
                                &old_data, &old_len) < 0 ||
            bgit_patch_content (odb, repo, &entries[i], 1, options,
                                &new_data, &new_len) < 0) {
            free (old_data);
            free (stats);
            return -1;
        }
        bgit_xdiff_file old_file, new_file;
        bgit_xdiff_load (&old_file, old_data, old_len);
        bgit_xdiff_load (&new_file, new_data, new_len);
        if (old_file.binary || new_file.binary) {
            stats[i].binary = 1;
            stats[i].removed = old_len;
            stats[i].added = new_len;
        } else {
            bgit_xdiff_result result;
            if (bgit_xdiff (&old_file, &new_file, 0, &result) == 0) {
                stats[i].added = result.added;
                stats[i].removed = result.removed;
                bgit_xdiff_result_release (&result);
            }
        }
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
    }
    *out = stats;
    return 0;
}

/* ------------------------------------------------------------ the forms */

static int
bgit_decimal_width (size_t value)
{
    int width = 1;
    while (value >= 10) { value /= 10; width++; }
    return width;
}

/* git scales the graph as if it were one column narrower, then adds one, so
   that any change at all shows at least one mark. */
static int
bgit_scale_linear (size_t count, int width, size_t max_change)
{
    if (!count) return 0;
    return 1 + (int) (count * (size_t) (width - 1) / max_change);
}

static void
bgit_show_graph (FILE *out, char mark, int count)
{
    while (count-- > 0) fputc (mark, out);
}

void
bgit_stat_summary (FILE *out, size_t files, size_t added, size_t removed)
{
    if (!files) {
        fprintf (out, " 0 files changed\n");
        return;
    }
    fprintf (out, " %zu file%s changed", files, files == 1 ? "" : "s");
    if (added || !removed)
        fprintf (out, ", %zu insertion%s(+)", added, added == 1 ? "" : "s");
    if (removed || !added)
        fprintf (out, ", %zu deletion%s(-)", removed, removed == 1 ? "" : "s");
    fputc ('\n', out);
}

/* What the stat calls a path: a rename shows where it came from too. */
static const char *
bgit_stat_name (const bgit_diff_entry *entry, char *quoted, size_t quoted_size,
                char *both, size_t both_size)
{
    const char *name = bgit_quote_path (entry->path, quoted, quoted_size);
    if (!entry->from) return name;
    char from_quoted[8192];
    const char *from = bgit_quote_path (entry->from, from_quoted,
                                        sizeof from_quoted);
    snprintf (both, both_size, "%s => %s", from, name);
    return both;
}

void
bgit_diffstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n,
                     const char *line_prefix,
                     const bgit_diffstat_layout *layout)
{
    if (!n) return;
    char quoted[8192];
    /* Only the lines that will be shown decide how wide the columns are,
       while the summary underneath counts every file. */
    size_t shown = n;
    if (layout && layout->count > 0 && (size_t) layout->count < n)
        shown = (size_t) layout->count;
    size_t max_change = 0, max_len = 0, added = 0, removed = 0;
    for (size_t i = 0; i < n; i++) {
        if (i < shown) {
            char both[8192];
            const char *name = bgit_stat_name (stats[i].entry, quoted,
                                               sizeof quoted, both,
                                               sizeof both);
            size_t len = strlen (name);
            if (len > max_len) max_len = len;
            if (!stats[i].binary) {
                size_t change = stats[i].added + stats[i].removed;
                if (change > max_change) max_change = change;
            }
        }
        if (stats[i].binary) continue;
        added += stats[i].added;
        removed += stats[i].removed;
    }

    int width = layout && layout->width > 0 ? layout->width : 80;
    int number_width = bgit_decimal_width (max_change);
    int name_width = layout && layout->name_width > 0 &&
                     (size_t) layout->name_width < max_len
                     ? layout->name_width : (int) max_len;
    int graph_width = (int) max_change;
    if (width < 16 + 6 + number_width) width = 16 + 6 + number_width;
    if (name_width + number_width + 6 + graph_width > width) {
        if (graph_width > width * 3 / 8 - number_width - 6) {
            graph_width = width * 3 / 8 - number_width - 6;
            if (graph_width < 6) graph_width = 6;
        }
        /* A graph width of its own is a ceiling: it leaves room for the
           names before they are fitted, and holds after they have been. */
        if (layout && layout->graph_width > 0 &&
            layout->graph_width < graph_width)
            graph_width = layout->graph_width;
        if (name_width > width - number_width - 6 - graph_width)
            name_width = width - number_width - 6 - graph_width;
        else
            graph_width = width - number_width - 6 - name_width;
    }
    if (layout && layout->graph_width > 0 && layout->graph_width < graph_width)
        graph_width = layout->graph_width;

    for (size_t i = 0; i < shown; i++) {
        char both[8192];
        const char *name = bgit_stat_name (stats[i].entry, quoted, sizeof quoted,
                                           both, sizeof both);
        size_t len = strlen (name);
        char shortened[8192];
        if ((int) len > name_width && name_width > 3) {
            /* Too long to show whole: git keeps the end of the path, and
               then as much of it as starts at a directory of its own. */
            const char *tail = name + len - (size_t) name_width + 3;
            const char *slash = strchr (tail, '/');
            snprintf (shortened, sizeof shortened, "...%s",
                      slash ? slash : tail);
            name = shortened;
        }
        fprintf (out, "%s %-*s |", line_prefix, name_width, name);
        if (stats[i].binary) {
            fprintf (out, " %*s %zu -> %zu bytes\n", number_width, "Bin",
                     stats[i].removed, stats[i].added);
            continue;
        }
        size_t change = stats[i].added + stats[i].removed;
        fprintf (out, " %*zu%s", number_width, change, change ? " " : "");
        int add = (int) stats[i].added, del = (int) stats[i].removed;
        if ((size_t) graph_width <= max_change && max_change) {
            int total = bgit_scale_linear (change, graph_width, max_change);
            if (total < 2 && add && del) total = 2;
            if (stats[i].added < stats[i].removed) {
                add = bgit_scale_linear (stats[i].added, graph_width, max_change);
                del = total - add;
            } else {
                del = bgit_scale_linear (stats[i].removed, graph_width, max_change);
                add = total - del;
            }
        }
        bgit_show_graph (out, '+', add);
        bgit_show_graph (out, '-', del);
        fputc ('\n', out);
    }
    /* What was left out is one line of its own, as git marks it. */
    if (shown < n) fprintf (out, "%s ...\n", line_prefix);
    fprintf (out, "%s", line_prefix);
    bgit_stat_summary (out, n, added, removed);
}

void
bgit_numstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n)
{
    char quoted[8192];
    for (size_t i = 0; i < n; i++) {
        const char *name = bgit_quote_path (stats[i].entry->path, quoted,
                                            sizeof quoted);
        if (stats[i].binary) fprintf (out, "-\t-\t%s\n", name);
        else fprintf (out, "%zu\t%zu\t%s\n", stats[i].added, stats[i].removed,
                      name);
    }
}

void
bgit_shortstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n,
                      const char *line_prefix)
{
    if (!n) return;
    size_t added = 0, removed = 0;
    for (size_t i = 0; i < n; i++) {
        if (stats[i].binary) continue;
        added += stats[i].added;
        removed += stats[i].removed;
    }
    fprintf (out, "%s", line_prefix);
    bgit_stat_summary (out, n, added, removed);
}

void
bgit_diff_summary (FILE *out, const bgit_diff_entry *entries, size_t n,
                   const char *line_prefix)
{
    char quoted[8192];
    for (size_t i = 0; i < n; i++) {
        const char *name = bgit_quote_path (entries[i].path, quoted,
                                            sizeof quoted);
        if (entries[i].status == 'R')
            fprintf (out, "%s rename %s => %s (%d%%)\n", line_prefix,
                     entries[i].from, name, entries[i].score * 100 / 60000);
        else if (entries[i].status == 'A')
            fprintf (out, "%s create mode %06o %s\n", line_prefix,
                     entries[i].new_mode, name);
        else if (entries[i].status == 'D')
            fprintf (out, "%s delete mode %06o %s\n", line_prefix,
                     entries[i].old_mode, name);
        else if (entries[i].old_mode != entries[i].new_mode)
            fprintf (out, "%s mode change %06o => %06o %s\n", line_prefix,
                     entries[i].old_mode, entries[i].new_mode, name);
    }
}
