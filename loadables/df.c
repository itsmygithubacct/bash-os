/* bashdf.c — POSIX df(1) as a bash builtin.
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdf [-ahHiklmPT] [-t TYPE] [-x TYPE] [FILE...]
 *
 *   -a   show all filesystems, including pseudo filesystems
 *   -h   human-readable sizes (1.0K, 2.5G, etc.)
 *   -H   SI human-readable sizes, powers of 1000 (1.0k, 2.5G, etc.)
 *   -i   list inode usage instead of block usage
 *   -k   1024-byte blocks (POSIX default; we follow this even without -k)
 *   -m   1024K-byte (1M) blocks
 *   -l   limit listing to local filesystems
 *   -P   POSIX output format: 6 columns, no breaks
 *   -t   limit listing to filesystems of type TYPE
 *   -T   print filesystem type column
 *   -x   exclude filesystems of type TYPE
 *
 * No FILE: enumerate /proc/mounts and report each mounted filesystem.
 * With FILE: report the FS containing each path.
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
#include <inttypes.h>
#include <math.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct {
    int aflag, hflag, Hflag, iflag, kflag, lflag, mflag, Pflag, Tflag;
    int totalflag, output_count, block_explicit;
    const char *type_filter;
    const char *exclude_type;
    uint64_t block_size;
    char block_suffix;
    char block_label[32];
    int output_fields[16];
} bdf_opts;

typedef struct {
    const char **v;
    int n;
    int cap;
} bdf_words;

enum {
    BDF_OUT_SOURCE,
    BDF_OUT_FSTYPE,
    BDF_OUT_SIZE,
    BDF_OUT_USED,
    BDF_OUT_AVAIL,
    BDF_OUT_PCENT,
    BDF_OUT_FILE,
    BDF_OUT_TARGET,
    BDF_OUT_ITOTAL,
    BDF_OUT_IUSED,
    BDF_OUT_IAVAIL,
    BDF_OUT_IPCENT
};

typedef struct {
    const char *fs;
    const char *type;
    const char *path;
    const char *file;
    uint64_t total, used, avail;
    uint64_t inodes, iused, ifree;
    int use_pct, iuse_pct;
} bdf_row;

extern char *df_doc[];

static void
bdf_print_help (void)
{
    for (char **lp = df_doc; *lp; lp++)
        puts (*lp);
}

static int
bdf_words_add (bdf_words *w, const char *s)
{
    if (w->n == w->cap) {
        int ncap = w->cap ? w->cap * 2 : 32;
        const char **nv = realloc (w->v, (size_t) ncap * sizeof *nv);
        if (!nv) return -1;
        w->v = nv;
        w->cap = ncap;
    }
    w->v[w->n++] = s;
    return 0;
}

/* Decode any backslash-octal escapes in /proc/mounts entries. */
static void
bdf_unescape (char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\\' && r[1] >= '0' && r[1] <= '7'
            && r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int
bdf_is_remote_type (const char *type)
{
    return strcmp (type, "9p") == 0
        || strcmp (type, "nfs") == 0
        || strcmp (type, "nfs4") == 0
        || strcmp (type, "cifs") == 0
        || strcmp (type, "smbfs") == 0
        || strcmp (type, "sshfs") == 0
        || strcmp (type, "fuse.sshfs") == 0
        || strcmp (type, "fuse.virtiofs") == 0
        || strcmp (type, "virtiofs") == 0;
}

static int
bdf_type_selected (const bdf_opts *o, const char *type)
{
    return o->type_filter == NULL || strcmp (o->type_filter, type) == 0;
}

static int
bdf_type_excluded (const bdf_opts *o, const char *type)
{
    return o->exclude_type != NULL && strcmp (o->exclude_type, type) == 0;
}

static void
bdf_human (uint64_t bytes, int si, char *out, size_t outsz)
{
    const char *unit = si ? " kMGTPE" : " KMGTPE";
    const double base = si ? 1000.0 : 1024.0;
    double v = (double) bytes;
    int u = 0;
    while (v >= base && u < 6) { v /= base; u++; }
    if (u == 0) { snprintf (out, outsz, "%" PRIu64, bytes); return; }
    /* GNU df -h/-H rounds UP (ceiling) at the display precision, so the
       shown figure is never smaller than the true size: one decimal below
       10, integer at/above 10. */
    if (v < 10.0) {
        double r = ceil (v * 10.0) / 10.0;
        if (r < 10.0) { snprintf (out, outsz, "%.1f%c", r, unit[u]); return; }
        v = r;                                  /* carried into the >=10 range */
    }
    v = ceil (v);
    if (v >= base && u < 6)                      /* carried into the next unit */
        snprintf (out, outsz, "1.0%c", unit[u + 1]);
    else
        snprintf (out, outsz, "%.0f%c", v, unit[u]);
}

static uint64_t
bdf_div_ceil (uint64_t n, uint64_t d)
{
    if (d == 0)
        return 0;
    return n / d + (n % d != 0);
}

static const char *
bdf_block_label (const bdf_opts *o)
{
    if (o->block_label[0])
        return o->block_label;
    if (o->mflag)
        return "1M-blocks";
    if (o->Pflag)
        return "1024-blocks";
    return "1K-blocks";
}

static uint64_t
bdf_block_size (const bdf_opts *o)
{
    if (o->block_explicit && o->block_size)
        return o->block_size;
    if (o->mflag)
        return 1024ULL * 1024ULL;
    return 1024;
}

static void
bdf_block_value (uint64_t bytes, const bdf_opts *o, char *out, size_t outsz)
{
    uint64_t v = bdf_div_ceil (bytes, bdf_block_size (o));
    if (o->block_suffix)
        snprintf (out, outsz, "%" PRIu64 "%c", v, o->block_suffix);
    else
        snprintf (out, outsz, "%" PRIu64, v);
}

static int
bdf_parse_block_size (const char *arg, bdf_opts *o)
{
    char *end = NULL;
    uint64_t n = 1, mult = 1;
    char suffix = '\0';

    if (arg == NULL || *arg == '\0')
        return -1;
    errno = 0;
    if (arg[0] >= '0' && arg[0] <= '9') {
        unsigned long long parsed = strtoull (arg, &end, 10);
        if (errno || parsed == 0)
            return -1;
        n = (uint64_t) parsed;
    } else {
        end = (char *) arg;
    }
    if (*end) {
        char c = *end++;
        if (*end == 'B' && end[1] == '\0')
            end++;
        if (*end != '\0')
            return -1;
        switch (c) {
        case 'K': case 'k': mult = 1024ULL; suffix = 'K'; break;
        case 'M': case 'm': mult = 1024ULL * 1024ULL; suffix = 'M'; break;
        case 'G': case 'g': mult = 1024ULL * 1024ULL * 1024ULL; suffix = 'G'; break;
        case 'T': case 't': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'T'; break;
        case 'P': case 'p': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'P'; break;
        case 'E': case 'e': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'E'; break;
        case 'B': mult = 1; suffix = '\0'; break;
        default: return -1;
        }
    }
    if (n > UINT64_MAX / mult)
        return -1;
    o->block_size = n * mult;
    o->block_explicit = 1;
    o->mflag = 0;
    o->block_suffix = suffix;
    if (suffix)
        snprintf (o->block_label, sizeof o->block_label, "%" PRIu64 "%c-blocks", n, suffix);
    else
        snprintf (o->block_label, sizeof o->block_label, "%" PRIu64 "B-blocks", n);
    return 0;
}

static int
bdf_field_id (const char *name)
{
    if (strcmp (name, "source") == 0) return BDF_OUT_SOURCE;
    if (strcmp (name, "fstype") == 0) return BDF_OUT_FSTYPE;
    if (strcmp (name, "size") == 0) return BDF_OUT_SIZE;
    if (strcmp (name, "used") == 0) return BDF_OUT_USED;
    if (strcmp (name, "avail") == 0) return BDF_OUT_AVAIL;
    if (strcmp (name, "pcent") == 0) return BDF_OUT_PCENT;
    if (strcmp (name, "file") == 0) return BDF_OUT_FILE;
    if (strcmp (name, "target") == 0) return BDF_OUT_TARGET;
    if (strcmp (name, "itotal") == 0) return BDF_OUT_ITOTAL;
    if (strcmp (name, "iused") == 0) return BDF_OUT_IUSED;
    if (strcmp (name, "iavail") == 0) return BDF_OUT_IAVAIL;
    if (strcmp (name, "ipcent") == 0) return BDF_OUT_IPCENT;
    return -1;
}

static int
bdf_output_add (bdf_opts *o, int id)
{
    if (o->output_count >= (int) (sizeof o->output_fields / sizeof o->output_fields[0]))
        return -1;
    o->output_fields[o->output_count++] = id;
    return 0;
}

static int
bdf_parse_output (const char *spec, bdf_opts *o)
{
    char *copy, *tok, *save;

    o->output_count = 0;
    if (spec == NULL) {
        int defaults[] = { BDF_OUT_SOURCE, BDF_OUT_SIZE, BDF_OUT_USED,
                           BDF_OUT_AVAIL, BDF_OUT_PCENT, BDF_OUT_TARGET };
        for (size_t i = 0; i < sizeof defaults / sizeof defaults[0]; i++)
            if (bdf_output_add (o, defaults[i]) < 0)
                return -1;
        return 0;
    }
    /* strtok_r skips empty fields, but GNU df rejects them. */
    if (*spec == '\0' || *spec == ',' || spec[strlen (spec) - 1] == ','
        || strstr (spec, ",,") != NULL)
        return -1;

    copy = strdup (spec);
    if (copy == NULL)
        return -1;
    for (tok = strtok_r (copy, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        int id = bdf_field_id (tok);
        if (id < 0 || bdf_output_add (o, id) < 0) {
            free (copy);
            return -1;
        }
    }
    free (copy);
    return o->output_count > 0 ? 0 : -1;
}

static int
bdf_find_mount_info (const char *path, char *fs, size_t fssz,
                     char *type, size_t typesz, char *mnt, size_t mntsz)
{
    struct stat pst;
    if (stat (path, &pst) < 0)
        return -1;
    char *resolved = realpath (path, NULL);
    if (resolved == NULL)
        return -1;

    FILE *mp = fopen ("/proc/mounts", "r");
    if (!mp) mp = fopen ("/proc/self/mounts", "r");
    if (!mp) {
        free (resolved);
        return -1;
    }

    int found = 0;
    size_t best_len = 0;
    char line[4096];
    while (fgets (line, sizeof line, mp)) {
        char dev[512], cur_mnt[512], cur_type[64];
        struct stat mst;
        if (sscanf (line, "%511s %511s %63s", dev, cur_mnt, cur_type) != 3)
            continue;
        bdf_unescape (dev);
        bdf_unescape (cur_mnt);
        bdf_unescape (cur_type);
        size_t len = strlen (cur_mnt);
        /* Bind mounts can share st_dev with unrelated mount points. Only
           consider mount points containing the canonical operand, with a
           component boundary (and '/' containing every absolute path). */
        if (strncmp (resolved, cur_mnt, len) != 0
            || (len != 1 && resolved[len] != '\0' && resolved[len] != '/'))
            continue;
        if (stat (cur_mnt, &mst) < 0 || mst.st_dev != pst.st_dev)
            continue;
        if (!found || len >= best_len) {
            snprintf (fs, fssz, "%s", dev);
            snprintf (type, typesz, "%s", cur_type);
            snprintf (mnt, mntsz, "%s", cur_mnt);
            best_len = len;
            found = 1;
        }
    }
    fclose (mp);
    free (resolved);
    return found ? 0 : -1;
}

static int
bdf_fill_row (const char *path, const char *fs, const char *type, bdf_row *row)
{
    struct statvfs vfs;
    uint64_t bsize;

    if (statvfs (path, &vfs) < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }

    bsize = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
    memset (row, 0, sizeof *row);
    row->fs = fs;
    row->type = type;
    row->path = path;
    row->file = path;
    row->total = (uint64_t) vfs.f_blocks * bsize;
    row->avail = (uint64_t) vfs.f_bavail * bsize;
    row->used = row->total - (uint64_t) vfs.f_bfree * bsize;
    if (row->used + row->avail > 0)
        row->use_pct = (int) ((row->used * 100 + row->used + row->avail - 1) / (row->used + row->avail));
    row->inodes = (uint64_t) vfs.f_files;
    row->ifree = (uint64_t) vfs.f_favail;
    row->iused = row->inodes >= (uint64_t) vfs.f_ffree ? row->inodes - (uint64_t) vfs.f_ffree : 0;
    if (row->iused + row->ifree > 0)
        row->iuse_pct = (int) ((row->iused * 100 + row->iused + row->ifree - 1) / (row->iused + row->ifree));
    return 0;
}

static void
bdf_format_space (uint64_t bytes, const bdf_opts *o, char *out, size_t outsz)
{
    if (o->hflag || o->Hflag)
        bdf_human (bytes, o->Hflag, out, outsz);
    else
        bdf_block_value (bytes, o, out, outsz);
}

/* GNU df's size header is human_readable(block_size) with ceiling autoscaling,
   not the digits the user typed.  An exact multiple of 1000 is an SI unit
   ("1kB"); an exact multiple of 1024 is a binary unit ("1K", "1M"). */
static void
bdf_header_amount (uint64_t n, int base1024, int human_b, char *out, size_t outsz)
{
    unsigned base = base1024 ? 1024u : 1000u;
    uint64_t amt = n;
    unsigned tenths = 0;
    int rounding = 0;
    int exponent = 0;
    char scratch[64];
    char *p = scratch + sizeof scratch;
    static const char powers[] = " KMGTPEZYRQ";

    *--p = '\0';
    if (base <= amt) {
        do {
            unsigned r10 = (unsigned) (amt % base) * 10u + tenths;
            unsigned r2 = (r10 % base) * 2u + (unsigned) (rounding >> 1);
            amt /= base;
            tenths = r10 / base;
            rounding = (r2 < base)
                ? ((r2 + (unsigned) rounding) != 0)
                : 2 + (base < r2 + (unsigned) rounding);
            exponent++;
        } while (base <= amt && exponent < 10);
        if (amt < 10 && rounding > 0) {
            tenths++;
            rounding = 0;
            if (tenths == 10) {
                amt++;
                tenths = 0;
            }
        }
        if (amt < 10 && tenths != 0) {
            *--p = (char) ('0' + tenths);
            *--p = '.';
            tenths = 0;
            rounding = 0;
        }
    }
    if ((int) tenths + rounding > 0) {
        amt++;
        if (amt == base && exponent < 10) {
            exponent++;
            amt = 1;
        }
    }
    do {
        *--p = (char) ('0' + (int) (amt % 10));
    } while ((amt /= 10) != 0);
    {
        char suffix[4];
        int sn = 0;
        if (exponent)
            suffix[sn++] = (!base1024 && exponent == 1) ? 'k' : powers[exponent];
        if (human_b)
            suffix[sn++] = 'B';
        suffix[sn] = '\0';
        snprintf (out, outsz, "%s%s", p, suffix);
    }
}

static void
bdf_blocks_header (const bdf_opts *o, char *out, size_t outsz)
{
    uint64_t n, q1000, q1024;
    int div1000, div1024, base1024;
    char num[64];

    /* -P keeps the historical POSIX label ("1024-blocks", or the -B/-m label). */
    if (o->Pflag && !o->output_count) {
        snprintf (out, outsz, "%s", bdf_block_label (o));
        return;
    }
    /* A suffixed -B (1K, 2M) already spells GNU's binary unit. */
    if (o->block_suffix && o->block_label[0]) {
        snprintf (out, outsz, "%s", o->block_label);
        return;
    }
    n = bdf_block_size (o);
    if (n == 0) {
        snprintf (out, outsz, "0B-blocks");
        return;
    }
    q1000 = q1024 = n;
    do {
        div1000 = q1000 % 1000 == 0;
        q1000 /= 1000;
        div1024 = q1024 % 1024 == 0;
        q1024 /= 1024;
    } while (div1000 && div1024);
    base1024 = 0;
    if (div1000 < div1024)
        base1024 = 1;
    if (div1024 < div1000)
        base1024 = 0;
    bdf_header_amount (n, base1024, !base1024, num, sizeof num);
    snprintf (out, outsz, "%s-blocks", num);
}

static void
bdf_field_geom (int field, int *min_width, int *align_right)
{
    switch (field) {
    case BDF_OUT_SOURCE: *min_width = 14; *align_right = 0; break;
    case BDF_OUT_FSTYPE: *min_width = 4; *align_right = 0; break;
    case BDF_OUT_SIZE:
    case BDF_OUT_USED:
    case BDF_OUT_AVAIL:
    case BDF_OUT_ITOTAL:
    case BDF_OUT_IUSED:
    case BDF_OUT_IAVAIL:
        *min_width = 5; *align_right = 1; break;
    case BDF_OUT_PCENT:
    case BDF_OUT_IPCENT:
        *min_width = 4; *align_right = 1; break;
    default:
        *min_width = 0; *align_right = 0; break;
    }
}

static void
bdf_header_text (int field, const bdf_opts *o, char *out, size_t outsz)
{
    switch (field) {
    case BDF_OUT_SOURCE: snprintf (out, outsz, "Filesystem"); break;
    case BDF_OUT_FSTYPE: snprintf (out, outsz, "Type"); break;
    case BDF_OUT_SIZE:
        if (o->hflag || o->Hflag)
            snprintf (out, outsz, "Size");
        else
            bdf_blocks_header (o, out, outsz);
        break;
    case BDF_OUT_USED: snprintf (out, outsz, "Used"); break;
    case BDF_OUT_AVAIL:
        if (o->output_count || o->hflag || o->Hflag)
            snprintf (out, outsz, "Avail");
        else
            snprintf (out, outsz, "Available");
        break;
    case BDF_OUT_PCENT:
        snprintf (out, outsz, "%s", (o->Pflag && !o->output_count) ? "Capacity" : "Use%");
        break;
    case BDF_OUT_FILE: snprintf (out, outsz, "File"); break;
    case BDF_OUT_TARGET: snprintf (out, outsz, "Mounted on"); break;
    case BDF_OUT_ITOTAL: snprintf (out, outsz, "Inodes"); break;
    case BDF_OUT_IUSED: snprintf (out, outsz, "IUsed"); break;
    case BDF_OUT_IAVAIL: snprintf (out, outsz, "IFree"); break;
    case BDF_OUT_IPCENT: snprintf (out, outsz, "IUse%"); break;
    default: snprintf (out, outsz, "?"); break;
    }
}

static void
bdf_output_value (const bdf_row *row, const bdf_opts *o, int field, char *out, size_t outsz)
{
    switch (field) {
    case BDF_OUT_SOURCE: snprintf (out, outsz, "%s", row->fs); break;
    case BDF_OUT_FSTYPE: snprintf (out, outsz, "%s", row->type); break;
    case BDF_OUT_SIZE: bdf_format_space (row->total, o, out, outsz); break;
    case BDF_OUT_USED: bdf_format_space (row->used, o, out, outsz); break;
    case BDF_OUT_AVAIL: bdf_format_space (row->avail, o, out, outsz); break;
    case BDF_OUT_PCENT: snprintf (out, outsz, "%d%%", row->use_pct); break;
    case BDF_OUT_FILE: snprintf (out, outsz, "%s", row->file); break;
    case BDF_OUT_TARGET: snprintf (out, outsz, "%s", row->path); break;
    case BDF_OUT_ITOTAL: snprintf (out, outsz, "%" PRIu64, row->inodes); break;
    case BDF_OUT_IUSED: snprintf (out, outsz, "%" PRIu64, row->iused); break;
    case BDF_OUT_IAVAIL: snprintf (out, outsz, "%" PRIu64, row->ifree); break;
    case BDF_OUT_IPCENT: snprintf (out, outsz, "%d%%", row->iuse_pct); break;
    default: snprintf (out, outsz, "?"); break;
    }
}

/* GNU df column minima (coreutils 9.7 field_data) and one-space separation.
   Numeric columns are right-aligned. The width is the minimum grown to the
   widest rendered cell, including the header and a --total row. The last
   column is not padded. */
#define BDF_TABLE_COLS 16

typedef struct {
    int field;
    int align_right;
    int width;
} bdf_col;

typedef struct {
    bdf_col cols[BDF_TABLE_COLS];
    int ncols;
    char **cells;
    int nrows;
    int cap;
} bdf_table;

static void
bdf_table_free (bdf_table *t)
{
    if (!t->cells)
        return;
    for (int i = 0; i < t->nrows * t->ncols; i++)
        free (t->cells[i]);
    free (t->cells);
    t->cells = NULL;
    t->nrows = t->cap = 0;
}

static int
bdf_table_store (bdf_table *t, char **src)
{
    char **nv, **dst;
    int ncap;

    if (t->nrows == t->cap) {
        ncap = t->cap ? t->cap * 2 : 8;
        nv = realloc (t->cells, (size_t) ncap * (size_t) t->ncols * sizeof *nv);
        if (!nv)
            return -1;
        t->cells = nv;
        t->cap = ncap;
    }
    dst = t->cells + (size_t) t->nrows * (size_t) t->ncols;
    for (int i = 0; i < t->ncols; i++) {
        dst[i] = strdup (src[i]);
        if (!dst[i]) {
            while (i > 0)
                free (dst[--i]);
            return -1;
        }
        if ((int) strlen (dst[i]) > t->cols[i].width)
            t->cols[i].width = (int) strlen (dst[i]);
    }
    t->nrows++;
    return 0;
}

static int
bdf_table_begin (bdf_table *t, const bdf_opts *o)
{
    int fields[BDF_TABLE_COLS];
    int n = 0;
    char *headers[BDF_TABLE_COLS];
    char text[64];
    int rc;

    if (o->output_count) {
        n = o->output_count;
        if (n > BDF_TABLE_COLS)
            n = BDF_TABLE_COLS;
        for (int i = 0; i < n; i++)
            fields[i] = o->output_fields[i];
    } else {
        fields[n++] = BDF_OUT_SOURCE;
        if (o->Tflag)
            fields[n++] = BDF_OUT_FSTYPE;
        if (o->iflag) {
            fields[n++] = BDF_OUT_ITOTAL;
            fields[n++] = BDF_OUT_IUSED;
            fields[n++] = BDF_OUT_IAVAIL;
            fields[n++] = BDF_OUT_IPCENT;
        } else {
            fields[n++] = BDF_OUT_SIZE;
            fields[n++] = BDF_OUT_USED;
            fields[n++] = BDF_OUT_AVAIL;
            fields[n++] = BDF_OUT_PCENT;
        }
        fields[n++] = BDF_OUT_TARGET;
    }
    t->ncols = n;
    for (int i = 0; i < n; i++) {
        int min_width = 0, align_right = 0;
        bdf_field_geom (fields[i], &min_width, &align_right);
        t->cols[i].field = fields[i];
        t->cols[i].align_right = align_right;
        t->cols[i].width = min_width;
    }
    for (int i = 0; i < n; i++) {
        bdf_header_text (fields[i], o, text, sizeof text);
        headers[i] = strdup (text);
        if (!headers[i]) {
            while (i > 0)
                free (headers[--i]);
            t->ncols = 0;
            return -1;
        }
    }
    rc = bdf_table_store (t, headers);
    for (int i = 0; i < n; i++)
        free (headers[i]);
    if (rc < 0)
        t->ncols = 0;
    return rc;
}

static void
bdf_cell_text (const bdf_row *row, const bdf_opts *o, int field, char *out, size_t outsz)
{
    if (!o->output_count && o->iflag && (o->hflag || o->Hflag)) {
        uint64_t n = 0;
        int inode = 1;
        if (field == BDF_OUT_ITOTAL)
            n = row->inodes;
        else if (field == BDF_OUT_IUSED)
            n = row->iused;
        else if (field == BDF_OUT_IAVAIL)
            n = row->ifree;
        else
            inode = 0;
        if (inode) {
            bdf_human (n, o->Hflag, out, outsz);
            return;
        }
    }
    bdf_output_value (row, o, field, out, outsz);
}

static int
bdf_table_add_row (bdf_table *t, const bdf_opts *o, const bdf_row *row)
{
    char *src[BDF_TABLE_COLS];
    int rc;

    for (int i = 0; i < t->ncols; i++) {
        int field = t->cols[i].field;
        if (field == BDF_OUT_SOURCE || field == BDF_OUT_FSTYPE
            || field == BDF_OUT_FILE || field == BDF_OUT_TARGET) {
            const char *s = "";
            if (field == BDF_OUT_SOURCE)
                s = row->fs ? row->fs : "";
            else if (field == BDF_OUT_FSTYPE)
                s = row->type ? row->type : "";
            else if (field == BDF_OUT_FILE)
                s = row->file ? row->file : "";
            else
                s = row->path ? row->path : "";
            src[i] = strdup (s);
        } else {
            char val[64];
            bdf_cell_text (row, o, field, val, sizeof val);
            src[i] = strdup (val);
        }
        if (!src[i]) {
            while (i > 0)
                free (src[--i]);
            return -1;
        }
    }
    rc = bdf_table_store (t, src);
    for (int i = 0; i < t->ncols; i++)
        free (src[i]);
    return rc;
}

static void
bdf_table_print (const bdf_table *t)
{
    for (int r = 0; r < t->nrows; r++) {
        char **cells = t->cells + (size_t) r * (size_t) t->ncols;
        for (int c = 0; c < t->ncols; c++) {
            int fill = t->cols[c].width - (int) strlen (cells[c]);
            if (c)
                putchar (' ');
            if (fill < 0)
                fill = 0;
            if (t->cols[c].align_right)
                for (; 0 < fill; fill--)
                    putchar (' ');
            fputs (cells[c], stdout);
            if (c + 1 < t->ncols)
                for (; 0 < fill; fill--)
                    putchar (' ');
        }
        putchar ('\n');
    }
}

static void
bdf_total_add (bdf_row *total, const bdf_row *row)
{
    total->fs = "total";
    total->type = "-";
    total->path = "-";
    total->file = "-";
    total->total += row->total;
    total->used += row->used;
    total->avail += row->avail;
    total->inodes += row->inodes;
    total->iused += row->iused;
    total->ifree += row->ifree;
    if (total->used + total->avail > 0)
        total->use_pct = (int) ((total->used * 100 + total->used + total->avail - 1) /
                                (total->used + total->avail));
    if (total->iused + total->ifree > 0)
        total->iuse_pct = (int) ((total->iused * 100 + total->iused + total->ifree - 1) /
                                 (total->iused + total->ifree));
}

static int
bdf_one (const char *path, const char *fs, const char *type, const char *target,
         const bdf_opts *o, bdf_table *table, int *header_emitted, bdf_row *total)
{
    bdf_row row;

    if (bdf_fill_row (path, fs, type, &row) < 0)
        return -1;
    row.path = target;
    if (table->ncols == 0 && bdf_table_begin (table, o) < 0)
        return -1;
    if (bdf_table_add_row (table, o, &row) < 0)
        return -1;
    *header_emitted = 1;
    if (total)
        bdf_total_add (total, &row);
    return 0;
}

static int
bdf_emit (bdf_table *table, const bdf_opts *o, int header_emitted, bdf_row *total)
{
    int rc = 0;

    if (header_emitted && o->totalflag && bdf_table_add_row (table, o, total) < 0)
        rc = -1;
    bdf_table_print (table);
    bdf_table_free (table);
    return rc;
}

int
df_builtin (WORD_LIST *list)
{
    bdf_opts o = {0};
    bdf_words positional = {0};
    o.block_size = 1024;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            bdf_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashdf 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--human-readable") == 0) {
            o.hflag = 1;
            o.Hflag = 0;
            continue;
        }
        if (strcmp (w, "--si") == 0) {
            o.Hflag = 1;
            o.hflag = 0;
            continue;
        }
        if (strcmp (w, "--print-type") == 0) {
            o.Tflag = 1;
            continue;
        }
        if (strcmp (w, "--all") == 0) {
            o.aflag = 1;
            continue;
        }
        if (strcmp (w, "--local") == 0) {
            o.lflag = 1;
            continue;
        }
        if (strcmp (w, "--total") == 0) {
            o.totalflag = 1;
            continue;
        }
        if (strcmp (w, "--output") == 0) {
            if (bdf_parse_output (NULL, &o) < 0) {
                builtin_error ("--output: invalid field list");
                return EXECUTION_FAILURE;
            }
            continue;
        }
        if (strncmp (w, "--output=", 9) == 0) {
            if (bdf_parse_output (w + 9, &o) < 0) {
                builtin_error ("--output: invalid field list");
                return EXECUTION_FAILURE;
            }
            continue;
        }
        if (strncmp (w, "--block-size=", 13) == 0) {
            if (bdf_parse_block_size (w + 13, &o) < 0) {
                builtin_error ("--block-size: invalid size");
                return EXECUTION_FAILURE;
            }
            continue;
        }
        if (strcmp (w, "--block-size") == 0) {
            if (p->next == NULL || bdf_parse_block_size (p->next->word->word, &o) < 0) {
                builtin_error ("--block-size: invalid size");
                return EXECUTION_FAILURE;
            }
            p = p->next;
            continue;
        }
        if (strncmp (w, "--type=", 7) == 0) {
            if (w[7] == '\0') {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            o.type_filter = w + 7;
            continue;
        }
        if (strcmp (w, "--type") == 0) {
            if (p->next == NULL) {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            p = p->next;
            o.type_filter = p->word->word;
            if (o.type_filter[0] == '\0') {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (strncmp (w, "--exclude-type=", 15) == 0) {
            if (w[15] == '\0') {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            o.exclude_type = w + 15;
            continue;
        }
        if (strcmp (w, "--exclude-type") == 0) {
            if (p->next == NULL) {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            p = p->next;
            o.exclude_type = p->word->word;
            if (o.exclude_type[0] == '\0') {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bdf_words_add (&positional, p->word->word) < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'a': o.aflag = 1; break;
                case 'h': o.hflag = 1; o.Hflag = 0; break;
                case 'H': o.Hflag = 1; o.hflag = 0; break;
                case 'i': o.iflag = 1; break;
                case 'k':
                    o.kflag = 1;
                    o.mflag = 0;
                    o.block_explicit = 0;
                    o.block_suffix = '\0';
                    o.block_label[0] = '\0';
                    break;
                case 'm':
                    o.mflag = 1;
                    o.block_explicit = 0;
                    o.block_suffix = '\0';
                    o.block_label[0] = '\0';
                    break;
                case 'B':
                    if (w[i + 1]) {
                        if (bdf_parse_block_size (w + i + 1, &o) < 0) {
                            builtin_error ("-B: invalid size");
                            return EXECUTION_FAILURE;
                        }
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL || bdf_parse_block_size (p->next->word->word, &o) < 0) {
                            builtin_error ("-B: invalid size");
                            return EXECUTION_FAILURE;
                        }
                        p = p->next;
                    }
                    break;
                case 'l': o.lflag = 1; break;
                case 'P': o.Pflag = 1; break;
                case 't':
                    if (w[i + 1]) {
                        o.type_filter = w + i + 1;
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL) {
                            builtin_error ("-t: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        p = p->next;
                        o.type_filter = p->word->word;
                        if (o.type_filter[0] == '\0') {
                            builtin_error ("-t: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                    }
                    break;
                case 'T': o.Tflag = 1; break;
                case 'x':
                    if (w[i + 1]) {
                        o.exclude_type = w + i + 1;
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL) {
                            builtin_error ("-x: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        p = p->next;
                        o.exclude_type = p->word->word;
                        if (o.exclude_type[0] == '\0') {
                            builtin_error ("-x: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                    }
                    break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
        } else {
            if (bdf_words_add (&positional, w) < 0) {
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }

    int header_emitted = 0;
    int rc = EXECUTION_SUCCESS;
    bdf_row total = {0};
    bdf_row *totalp = o.totalflag ? &total : NULL;
    bdf_table table = {0};

    if (positional.n > 0) {
        /* Per-path mode. */
        for (int i = 0; i < positional.n; i++) {
            char fs[512], type[64], mnt[512];
            struct stat st;
            if (stat (positional.v[i], &st) < 0) {
                builtin_error ("%s: %s", positional.v[i], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            const char *display_fs = positional.v[i];
            const char *display_type = "";
            const char *display_path = positional.v[i];
            if (bdf_find_mount_info (positional.v[i], fs, sizeof fs, type, sizeof type, mnt, sizeof mnt) == 0) {
                display_fs = fs;
                display_type = type;
                display_path = mnt;
            }
            if (!bdf_type_selected (&o, display_type))
                continue;
            if (bdf_type_excluded (&o, display_type))
                continue;
            if (bdf_one (positional.v[i], display_fs, display_type, display_path,
                         &o, &table, &header_emitted, totalp) < 0)
                rc = EXECUTION_FAILURE;
        }
        if (!header_emitted && rc == EXECUTION_SUCCESS) {
            builtin_error ("no file systems processed");
            rc = EXECUTION_FAILURE;
        }
        if (bdf_emit (&table, &o, header_emitted, &total) < 0)
            rc = EXECUTION_FAILURE;
        free (positional.v);
        return rc;
    }
    free (positional.v);

    /* Enumerate /proc/mounts. */
    FILE *mp = fopen ("/proc/mounts", "r");
    if (!mp) mp = fopen ("/proc/self/mounts", "r");
    if (!mp) {
        builtin_error ("/proc/mounts: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[4096];
    while (fgets (line, sizeof line, mp)) {
        char dev[512], mnt[512], type[64];
        if (sscanf (line, "%511s %511s %63s", dev, mnt, type) != 3) continue;
        bdf_unescape (dev);
        bdf_unescape (mnt);
        bdf_unescape (type);
        if (o.lflag && bdf_is_remote_type (type))
            continue;
        if (!bdf_type_selected (&o, type))
            continue;
        if (bdf_type_excluded (&o, type))
            continue;
        /* Skip pseudo filesystems with no meaningful disk usage unless -a asks for all entries. */
        if (!o.aflag
            && (strcmp (type, "proc") == 0 || strcmp (type, "sysfs") == 0
            || strcmp (type, "cgroup") == 0 || strcmp (type, "cgroup2") == 0
            || strcmp (type, "devpts") == 0 || strcmp (type, "rpc_pipefs") == 0
            || strcmp (type, "binfmt_misc") == 0 || strcmp (type, "mqueue") == 0
            || strcmp (type, "pstore") == 0 || strcmp (type, "configfs") == 0
            || strcmp (type, "debugfs") == 0 || strcmp (type, "fusectl") == 0
            || strcmp (type, "securityfs") == 0 || strcmp (type, "tracefs") == 0
            || strcmp (type, "bpf") == 0 || strcmp (type, "autofs") == 0))
            continue;
        if (bdf_one (mnt, dev, type, mnt, &o, &table, &header_emitted, totalp) < 0)
            rc = EXECUTION_FAILURE;
    }
    fclose (mp);
    if (bdf_emit (&table, &o, header_emitted, &total) < 0)
        rc = EXECUTION_FAILURE;
    return rc;
}

char *df_doc[] = {
    "Report filesystem disk space usage.",
    "",
    "    bashdf [-ahHiklmPT] [-B SIZE] [-t TYPE] [-x TYPE] [FILE...]",
    "",
    "    -a   show all filesystems",
    "    -h   human-readable sizes (powers of 1024)",
    "    -H   SI human-readable sizes (powers of 1000)",
    "    -B SIZE  scale block output by SIZE (for example 1, K, M, G)",
    "    -i   list inode usage",
    "    -k   1024-byte blocks (POSIX default)",
    "    -m   1M-byte blocks",
    "    -l   limit listing to local filesystems",
    "    -P   POSIX output format",
    "    -t TYPE  limit listing to filesystem type",
    "    -T   print filesystem type",
    "    -x TYPE  exclude filesystem type",
    "    --help     show usage and exit",
    "    --version  show version and exit",
    "    --all         show all filesystems",
    "    --human-readable  human-readable sizes (powers of 1024)",
    "    --si            SI human-readable sizes (powers of 1000)",
    "    --block-size=SIZE  scale block output by SIZE",
    "    --output[=LIST] select output columns (source,size,used,avail,pcent,target,...)",
    "    --total       show a grand-total row",
    "    --local       limit listing to local filesystems",
    "    --type=TYPE   limit listing to filesystem type",
    "    --exclude-type=TYPE  exclude filesystem type",
    "    --print-type  print filesystem type",
    "",
    "No FILE: enumerate /proc/mounts. Pseudo-filesystems",
    "(proc/sysfs/cgroup/etc.) are filtered out.",
    (char *)NULL
};

struct builtin bashdf_struct = {
    "bashdf",
    df_builtin,
    BUILTIN_ENABLED,
    df_doc,
    "bashdf [-ahHiklmPT] [-B SIZE] [-t TYPE] [-x TYPE] [FILE...]",
    0
};
