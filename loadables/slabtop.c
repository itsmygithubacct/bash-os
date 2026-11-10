/* SPDX-License-Identifier: MIT */
/* slabtop.c — procps-shape slab cache viewer over /proc/slabinfo.
 *
 *   slabtop [-d SEC] [-o|--once] [-s CHAR] [-h|--help] [-V|--version]
 *
 * Batch mode prints the procps summary/header/table to stdout. Interactive
 * mode uses the shared _bl_screen + _bl_key TUI primitives.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "loadables.h"
#include "_bl_key_bl_key.h"
#include "_bl_screen_screen.h"
#include "_bl_proc_slabinfo.h"

typedef enum {
    SLAB_SORT_ACTIVE = 'a',
    SLAB_SORT_OBJS_PER_SLAB = 'b',
    SLAB_SORT_CACHE_SIZE = 'c',
    SLAB_SORT_SLABS = 'l',
    SLAB_SORT_ACTIVE_SLABS = 'v',
    SLAB_SORT_NAME = 'n',
    SLAB_SORT_OBJECTS = 'o',
    SLAB_SORT_PAGES_PER_SLAB = 'p',
    SLAB_SORT_OBJECT_SIZE = 's',
    SLAB_SORT_USE = 'u'
} slab_sort;

static slab_sort slab_current_sort = SLAB_SORT_OBJECTS;
static unsigned long long slab_page_size = 4096;

static unsigned long long
slab_total_slabs(const blp_slabinfo_row *r)
{
    return r->num_slabs;
}

static unsigned long long
slab_active_slabs(const blp_slabinfo_row *r)
{
    return r->active_slabs;
}

static unsigned long long
slab_cache_bytes(const blp_slabinfo_row *r)
{
    return slab_total_slabs(r) * r->pages_per_slab * slab_page_size;
}

/* --once follows procps-ng 4: USE is truncated to a whole percent, sorting
   uses that value and equal rows keep their slabinfo order.  The interactive
   display keeps its documented contract: one decimal of the exact ratio, and
   tied rows ordered by name. */
static int slab_batch;

static double
slab_use_pct(const blp_slabinfo_row *r)
{
    if (!r->num_objs)
        return 0.0;
    if (slab_batch)
        return (unsigned int) (100 * ((float) r->active_objs / r->num_objs));
    return (100.0 * (double) r->active_objs) / (double) r->num_objs;
}

static unsigned long long
slab_sort_value(const blp_slabinfo_row *r, slab_sort sort)
{
    switch (sort) {
    case SLAB_SORT_ACTIVE:        return r->active_objs;
    case SLAB_SORT_OBJS_PER_SLAB: return r->objs_per_slab;
    case SLAB_SORT_CACHE_SIZE:    return slab_cache_bytes(r);
    case SLAB_SORT_SLABS:         return slab_total_slabs(r);
    case SLAB_SORT_ACTIVE_SLABS:  return slab_active_slabs(r);
    case SLAB_SORT_OBJECTS:       return r->num_objs;
    case SLAB_SORT_PAGES_PER_SLAB:return r->pages_per_slab;
    case SLAB_SORT_OBJECT_SIZE:   return r->obj_size;
    case SLAB_SORT_USE:           return slab_batch ? (unsigned int) slab_use_pct(r)
                                      : r->num_objs ? 10000ULL * r->active_objs / r->num_objs : 0;
    case SLAB_SORT_NAME:          return 0;
    }
    return r->num_objs;
}

static int
slab_cmp_rows(const void *a, const void *b)
{
    const blp_slabinfo_row *ra = (const blp_slabinfo_row *) a;
    const blp_slabinfo_row *rb = (const blp_slabinfo_row *) b;

    if (slab_current_sort == SLAB_SORT_NAME)
        return strcoll(ra->name, rb->name);

    unsigned long long va = slab_sort_value(ra, slab_current_sort);
    unsigned long long vb = slab_sort_value(rb, slab_current_sort);
    if (va < vb)
        return 1;
    if (va > vb)
        return -1;
    return slab_batch ? 0 : strcmp(ra->name, rb->name);
}

static int
slab_valid_sort(const char *s, slab_sort *out)
{
    if (!s || !s[0] || s[1])
        return 0;
    switch (s[0]) {
    case 'a': case 'b': case 'c': case 'l': case 'v':
    case 'n': case 'o': case 'p': case 's': case 'u':
        *out = (slab_sort) s[0];
        return 1;
    default:
        return 0;
    }
}

static const char *
slab_sort_name(slab_sort sort)
{
    switch (sort) {
    case SLAB_SORT_ACTIVE:         return "active objects";
    case SLAB_SORT_OBJS_PER_SLAB:  return "objects per slab";
    case SLAB_SORT_CACHE_SIZE:     return "cache size";
    case SLAB_SORT_SLABS:          return "slabs";
    case SLAB_SORT_ACTIVE_SLABS:   return "active slabs";
    case SLAB_SORT_NAME:           return "name";
    case SLAB_SORT_OBJECTS:        return "objects";
    case SLAB_SORT_PAGES_PER_SLAB: return "pages per slab";
    case SLAB_SORT_OBJECT_SIZE:    return "object size";
    case SLAB_SORT_USE:            return "cache utilization";
    }
    return "objects";
}

static slab_sort
slab_next_sort(slab_sort sort)
{
    switch (sort) {
    case SLAB_SORT_ACTIVE:         return SLAB_SORT_OBJS_PER_SLAB;
    case SLAB_SORT_OBJS_PER_SLAB:  return SLAB_SORT_CACHE_SIZE;
    case SLAB_SORT_CACHE_SIZE:     return SLAB_SORT_SLABS;
    case SLAB_SORT_SLABS:          return SLAB_SORT_ACTIVE_SLABS;
    case SLAB_SORT_ACTIVE_SLABS:   return SLAB_SORT_NAME;
    case SLAB_SORT_NAME:           return SLAB_SORT_OBJECTS;
    case SLAB_SORT_OBJECTS:        return SLAB_SORT_PAGES_PER_SLAB;
    case SLAB_SORT_PAGES_PER_SLAB: return SLAB_SORT_OBJECT_SIZE;
    case SLAB_SORT_OBJECT_SIZE:    return SLAB_SORT_USE;
    case SLAB_SORT_USE:            return SLAB_SORT_ACTIVE;
    }
    return SLAB_SORT_OBJECTS;
}

static void
slab_usage(FILE *fp)
{
    fputs("\n"
          "Usage:\n"
          " slabtop [options]\n"
          "\n"
          "Options:\n"
          " -d, --delay <secs>  delay updates\n"
          " -o, --once          only display once, then exit\n"
          " -s, --sort <char>   specify sort criteria by character (see below)\n"
          "\n"
          " -h, --help     display this help and exit\n"
          " -V, --version  output version information and exit\n"
          "\n"
          "The following are valid sort criteria:\n"
          " a: sort by number of active objects\n"
          " b: sort by objects per slab\n"
          " c: sort by cache size\n"
          " l: sort by number of slabs\n"
          " v: sort by (non display) number of active slabs\n"
          " n: sort by name\n"
          " o: sort by number of objects (the default)\n"
          " p: sort by (non display) pages per slab\n"
          " s: sort by object size\n"
          " u: sort by cache utilization\n"
          "\n"
          "For more details see slabtop(1).\n", fp);
}

static int
slab_load(blp_slabinfo *slabs)
{
    char path[512], line[4096];
    FILE *fp;
    int major, minor, err = 0;

    memset(slabs, 0, sizeof(*slabs));
    fp = fopen(blp_proc_path("slabinfo", path, sizeof path), "r");
    if (!fp) {
        err = errno;
        goto fail;
    }
    if (!fgets(line, sizeof line, fp) ||
        sscanf(line, "slabinfo - version: %d.%d", &major, &minor) != 2 || major != 2) {
        err = ERANGE;
        goto fail;
    }
    while (fgets(line, sizeof line, fp)) {
        blp_slabinfo_row r = {0};
        unsigned int a, n, size, per, pages, active, total;
        if (line[0] == '#')
            continue;
        if (sscanf(line, " %127s %u %u %u %u %u : tunables %*u %*u %*u : slabdata %u %u %*u",
                   r.name, &a, &n, &size, &per, &pages, &active, &total) < 8) {
            err = ERANGE;
            goto fail;
        }
        r.active_objs = a; r.num_objs = n; r.obj_size = size;
        r.objs_per_slab = per; r.pages_per_slab = pages;
        r.active_slabs = active; r.num_slabs = total;
        if (slabs->len == slabs->cap) {
            size_t cap = slabs->cap ? slabs->cap * 2 : 128;
            blp_slabinfo_row *rows = realloc(slabs->rows, cap * sizeof(*rows));
            if (!rows) {
                err = ENOMEM;
                goto fail;
            }
            slabs->rows = rows;
            slabs->cap = cap;
        }
        slabs->rows[slabs->len++] = r;
    }
    if (ferror(fp)) {
        err = errno ? errno : EIO;
        goto fail;
    }
    fclose(fp);
    qsort(slabs->rows, slabs->len, sizeof(slabs->rows[0]), slab_cmp_rows);
    return 0;
fail:
    if (fp)
        fclose(fp);
    blp_free_slabinfo(slabs);
    fprintf(stderr, "slabtop: Unable to create slabinfo structure: %s\n", strerror(err));
    return -1;
}

typedef struct {
    unsigned long long active_objs, total_objs;
    size_t active_caches;
} slab_summary;

static slab_summary
slab_summarize(const blp_slabinfo *slabs)
{
    slab_summary s = {0, 0, 0};
    for (size_t i = 0; i < slabs->len; i++) {
        s.active_objs += slabs->rows[i].active_objs;
        s.total_objs += slabs->rows[i].num_objs;
        if (slabs->rows[i].active_objs)
            s.active_caches++;
    }
    return s;
}

static void
slab_print_table(FILE *fp, const blp_slabinfo *slabs)
{
    unsigned int active_objs = 0, total_objs = 0;
    unsigned int active_slabs = 0, total_slabs = 0;
    unsigned long active_size = 0, total_size = 0;
    unsigned long long min_obj = INT_MAX, max_obj = 0;
    size_t active_caches = 0;

    for (size_t i = 0; i < slabs->len; i++) {
        const blp_slabinfo_row *r = &slabs->rows[i];
        unsigned long long ts = slab_total_slabs(r);
        unsigned long long as = slab_active_slabs(r);
        active_objs += r->active_objs;
        total_objs += r->num_objs;
        active_slabs += as;
        total_slabs += ts;
        active_size += r->active_objs * r->obj_size;
        total_size += r->num_objs * r->obj_size;
        if (r->num_objs)
            active_caches++;
        if (r->obj_size < min_obj)
            min_obj = r->obj_size;
        if (r->obj_size > max_obj)
            max_obj = r->obj_size;
    }

    double obj_pct = 100.0 * active_objs / total_objs;
    double slab_pct = 100.0 * active_slabs / total_slabs;
    double cache_pct = 100.0 * active_caches / slabs->len;
    double size_pct = 100.0 * active_size / total_size;
    unsigned long long avg_obj = total_objs ? total_size / total_objs : 0;

    fprintf(fp, " %-35s: %u / %u (%.1f%%)\n", "Active / Total Objects (% used)", active_objs, total_objs, obj_pct);
    fprintf(fp, " %-35s: %u / %u (%.1f%%)\n", "Active / Total Slabs (% used)", active_slabs, total_slabs, slab_pct);
    fprintf(fp, " %-35s: %zu / %zu (%.1f%%)\n", "Active / Total Caches (% used)", active_caches, slabs->len, cache_pct);
    fprintf(fp, " %-35s: %.2fK / %.2fK (%.1f%%)\n", "Active / Total Size (% used)", (double) active_size / 1024, (double) total_size / 1024, size_pct);
    fprintf(fp, " %-35s: %.2fK / %.2fK / %.2fK\n\n", "Minimum / Average / Maximum Object", (double) min_obj / 1024, (double) avg_obj / 1024, (double) max_obj / 1024);
    fprintf(fp, "%-78s\n", "  OBJS ACTIVE  USE OBJ SIZE  SLABS OBJ/SLAB CACHE SIZE NAME");

    for (size_t i = 0; i < slabs->len; i++) {
        const blp_slabinfo_row *r = &slabs->rows[i];
        fprintf(fp, "%6llu %6llu %3u%% %7.2fK %6llu %8llu %9lluK %-23s\n",
                r->num_objs, r->active_objs, (unsigned int) slab_use_pct(r),
                (double) r->obj_size / 1024.0, slab_total_slabs(r),
                r->objs_per_slab, slab_cache_bytes(r) / 1024, r->name);
    }
}

static int
slab_run_once(void)
{
    blp_slabinfo slabs;
    slab_batch = 1;
    if (slab_load(&slabs) < 0)
        return EXECUTION_FAILURE;
    slab_print_table(stdout, &slabs);
    blp_free_slabinfo(&slabs);
    return EXECUTION_SUCCESS;
}

static void
slab_draw(bls_win *w, const blp_slabinfo *slabs, int err, const char *errmsg, int delay)
{
    int max_rows = bls_lines() - 8;
    if (max_rows < 0)
        max_rows = 0;

    bls_erase(w);
    bls_attron(w, BLS_A_BOLD);
    bls_printw(w, "slabtop - sort %c (%s)  every %ds", (char) slab_current_sort,
               slab_sort_name(slab_current_sort), delay);
    bls_attroff(w, BLS_A_BOLD);

    if (err) {
        bls_mvaddstr(w, 2, 0, errmsg);
        bls_mvaddstr(w, 4, 0, "q/ESC exits");
        bls_refresh(w);
        return;
    }

    slab_summary summary = slab_summarize(slabs);
    double obj_pct = summary.total_objs ?
        100.0 * (double) summary.active_objs / (double) summary.total_objs : 0.0;
    double cache_pct = slabs->len ?
        100.0 * (double) summary.active_caches / (double) slabs->len : 0.0;
    bls_move(w, 2, 0);
    bls_printw(w, "Active / Total Objects (%% used)    : %llu / %llu (%.1f%%)",
               summary.active_objs, summary.total_objs, obj_pct);
    bls_move(w, 3, 0);
    bls_printw(w, "Active / Total Caches (%% used)     : %zu / %zu (%.1f%%)",
               summary.active_caches, slabs->len, cache_pct);
    bls_mvaddstr(w, 4, 0, "  OBJS ACTIVE  USE OBJ SIZE  SLABS OBJ/SLAB CACHE SIZE NAME");
    for (size_t i = 0; i < slabs->len && (int) i < max_rows; i++) {
        const blp_slabinfo_row *r = &slabs->rows[i];
        bls_move(w, 5 + (int) i, 0);
        bls_printw(w, "%6llu %6llu %5.1f%% %7.2fK %6llu %8llu %9.2fK %s",
                   r->num_objs, r->active_objs, slab_use_pct(r),
                   (double) r->obj_size / 1024.0, slab_total_slabs(r),
                   r->objs_per_slab, (double) slab_cache_bytes(r) / 1024.0,
                   r->name);
    }
    bls_mvaddstr(w, bls_lines() - 1, 0, "q/ESC exits, s cycles sort");
    bls_refresh(w);
}

static int
slab_run_interactive(int delay)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
        return slab_run_once();
    if (bls_init() < 0)
        return slab_run_once();

    slab_batch = 0;
    bls_win *w = bls_stdscr();
    for (;;) {
        blp_slabinfo slabs;
        int err = 0;
        char errmsg[160] = "";
        if (slab_load(&slabs) < 0) {
            err = 1;
            snprintf(errmsg, sizeof errmsg, "slabtop: Unable to create slabinfo structure");
        }
        slab_draw(w, &slabs, err, errmsg, delay);
        if (!err)
            blp_free_slabinfo(&slabs);

        bls_timeout(delay * 1000);
        int key = bls_getch();
        if (key == 'q' || key == BL_KEY_ESC || key == BLS_KEY_NONE)
            break;
        if (key == 's')
            slab_current_sort = slab_next_sort(slab_current_sort);
    }
    bls_end();
    return EXECUTION_SUCCESS;
}

static int
slab_arg_missing(const char *opt)
{
    if (opt[0] == '-' && opt[1] == '-')
        fprintf(stderr, "slabtop: option '%s' requires an argument\n", opt);
    else
        fprintf(stderr, "slabtop: option requires an argument -- '%s'\n", opt + 1);
    slab_usage(stderr);
    return EXECUTION_FAILURE;
}

static int
slab_invalid_option(const char *opt)
{
    if (opt[0] == '-' && opt[1] == '-' && opt[2])
        fprintf(stderr, "slabtop: unrecognized option '%s'\n", opt);
    else if (opt[0] == '-' && opt[1])
        fprintf(stderr, "slabtop: invalid option -- '%c'\n", opt[1]);
    else
        fprintf(stderr, "slabtop: invalid option -- '%s'\n", opt);
    slab_usage(stderr);
    return EXECUTION_FAILURE;
}

int
slabtop_builtin(WORD_LIST *list)
{
    int once = 0;
    int delay = 3;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0)
        slab_page_size = (unsigned long long) ps;
    slab_current_sort = SLAB_SORT_OBJECTS;

    while (list) {
        const char *w = list->word->word;
        if (!w || !*w || w[0] != '-')
            return slab_invalid_option(w ? w : "");
        if (!strcmp(w, "--")) {
            list = list->next;
            break;
        }
        if (!strcmp(w, "-h") || !strcmp(w, "--help")) {
            slab_usage(stdout);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp(w, "-V") || !strcmp(w, "--version")) {
            puts("slabtop from procps-ng 4.0.4");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp(w, "-o") || !strcmp(w, "--once")) {
            once = 1;
            list = list->next;
            continue;
        }
        if (!strcmp(w, "-d") || !strcmp(w, "--delay")) {
            list = list->next;
            if (!list)
                return slab_arg_missing(w);
            delay = atoi(list->word->word);
            if (delay < 1)
                delay = 1;
            list = list->next;
            continue;
        }
        if (!strncmp(w, "--delay=", 8)) {
            delay = atoi(w + 8);
            if (delay < 1)
                delay = 1;
            list = list->next;
            continue;
        }
        if (!strcmp(w, "-s") || !strcmp(w, "--sort")) {
            slab_sort sort;
            list = list->next;
            if (!list)
                return slab_arg_missing(w);
            if (!slab_valid_sort(list->word->word, &sort))
                return slab_invalid_option(list->word->word);
            slab_current_sort = sort;
            list = list->next;
            continue;
        }
        if (!strncmp(w, "--sort=", 7)) {
            slab_sort sort;
            if (!slab_valid_sort(w + 7, &sort))
                return slab_invalid_option(w + 7);
            slab_current_sort = sort;
            list = list->next;
            continue;
        }
        return slab_invalid_option(w);
    }

    if (list)
        return slab_invalid_option(list->word->word);

    return once ? slab_run_once() : slab_run_interactive(delay);
}

char *slabtop_doc[] = {
    "Display kernel slab cache information from /proc/slabinfo.",
    "",
    "    slabtop [options]",
    "",
    "    -d, --delay <secs>  delay updates",
    "    -o, --once          only display once, then exit",
    "    -s, --sort <char>   sort by a/b/c/l/v/n/o/p/s/u",
    "    -h, --help          display help and exit",
    "    -V, --version       output version information and exit",
    (char *) NULL
};

struct builtin slabtop_struct = {
    "slabtop",
    slabtop_builtin,
    BUILTIN_ENABLED,
    slabtop_doc,
    "slabtop [-d SEC] [-o] [-s CHAR] [-h|-V]",
    0
};
