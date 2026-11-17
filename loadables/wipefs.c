/* SPDX-License-Identifier: MIT */
/* wipefs.c — list or erase filesystem, swap and partition-table signatures.
 *
 *   wipefs device              # table of detected signatures
 *   wipefs -a device           # erase every detected signature
 *   wipefs -a -n device        # report what -a would erase, write nothing
 *   wipefs -o OFFSET device    # erase the signature at OFFSET
 *
 * Output, option handling and the order of signatures follow util-linux
 * wipefs(8): a DEVICE OFFSET TYPE UUID LABEL table when listing, and one
 * "N bytes were erased at offset ..." line per erased magic string.
 * Recognised: vfat, swap, xfs, ext2/3/4, iso9660, ntfs, btrfs, and the dos
 * and gpt partition tables. Works on a regular file or a block device.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
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
#include <stdint.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "loadables.h"

struct wsig {
    unsigned long long offset;
    size_t len;
    const char *type;
    int is_pt;
    char uuid[40];
    char label[260];
};

#define WMAX 16

static unsigned le16 (const unsigned char *p) { return p[0] | p[1] << 8; }
static uint32_t le32 (const unsigned char *p) { return le16 (p) | (uint32_t) le16 (p + 2) << 16; }
static uint64_t le64 (const unsigned char *p) { return le32 (p) | (uint64_t) le32 (p + 4) << 32; }
static unsigned be16 (const unsigned char *p) { return p[0] << 8 | p[1]; }
static uint32_t be32 (const unsigned char *p) { return (uint32_t) be16 (p) << 16 | be16 (p + 2); }
static int pow2 (unsigned long v) { return v && !(v & (v - 1)); }

static int
rd (int fd, unsigned long long off, void *buf, size_t len)
{
    return pread (fd, buf, len, (off_t) off) == (ssize_t) len;
}

static void
uuid_text (char *out, const unsigned char *u)
{
    snprintf (out, 40, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

/* A fixed-width on-disk name: up to the first NUL, trailing blanks dropped. */
static void
name_text (char *out, size_t outlen, const unsigned char *src, size_t n)
{
    size_t k = 0;
    while (k < n && k + 1 < outlen && src[k]) { out[k] = (char) src[k]; k++; }
    while (k && out[k - 1] == ' ') k--;
    out[k] = 0;
}

static struct wsig *
add (struct wsig *list, int *count, unsigned long long offset, size_t len, const char *type, int is_pt)
{
    if (*count >= WMAX) return NULL;
    struct wsig *s = &list[(*count)++];
    memset (s, 0, sizeof *s);
    s->offset = offset; s->len = len; s->type = type; s->is_pt = is_pt;
    return s;
}

/* The magic strings of a FAT boot sector, in the order libblkid tries them;
   erasing goes through all that are present. */
static int
probe_vfat (int fd, struct wsig *list, int *count, int every)
{
    static const struct { const char *magic; size_t len; unsigned off; } magics[] = {
        { "MSWIN", 5, 0x52 }, { "FAT32   ", 8, 0x52 }, { "MSDOS", 5, 0x36 }, { "FAT16   ", 8, 0x36 },
        { "FAT12   ", 8, 0x36 }, { "FAT     ", 8, 0x36 }, { "\353", 1, 0 }, { "\351", 1, 0 }, { "\125\252", 2, 0x1fe },
    };
    unsigned char b[512];
    if (!rd (fd, 0, b, sizeof b)) return 0;
    unsigned sector = le16 (b + 11), reserved = le16 (b + 14), media = b[21];
    if (!(sector == 512 || sector == 1024 || sector == 2048 || sector == 4096)) return 0;
    if (!pow2 (b[13]) || !reserved || !b[16] || !(media >= 0xf8 || media == 0xf0)) return 0;
    int found = 0;
    for (size_t i = 0; i < sizeof magics / sizeof magics[0]; i++) {
        if (memcmp (b + magics[i].off, magics[i].magic, magics[i].len)) continue;
        struct wsig *s = add (list, count, magics[i].off, magics[i].len, "vfat", 0);
        if (!s) break;
        int fat32 = le16 (b + 22) == 0;
        const unsigned char *serial = b + (fat32 ? 67 : 39);
        if (b[fat32 ? 66 : 38] == 0x29) {
            snprintf (s->uuid, sizeof s->uuid, "%02X%02X-%02X%02X", serial[3], serial[2], serial[1], serial[0]);
            name_text (s->label, sizeof s->label, b + (fat32 ? 71 : 43), 11);
            if (!strcmp (s->label, "NO NAME")) s->label[0] = 0;
        }
        found = 1;
        if (!every) break;
    }
    return found;
}

static void
probe_swap (int fd, struct wsig *list, int *count)
{
    static const unsigned pages[] = { 4096, 8192, 16384, 32768, 65536 };
    unsigned char m[10], h[1204];
    for (size_t i = 0; i < sizeof pages / sizeof pages[0]; i++) {
        if (!rd (fd, pages[i] - 10, m, 10)) continue;
        int v2 = !memcmp (m, "SWAPSPACE2", 10);
        if (!v2 && memcmp (m, "SWAP-SPACE", 10)) continue;
        /* As libblkid: a v2 header must have version 1 in either byte order
           and a nonzero last page, else it is not swap at all; UUID and label
           are read only when the padding words at 1196 and 1200 are zero. */
        int ids = 0;
        if (v2) {
            if (!rd (fd, 0, h, sizeof h)) continue;
            int big = le32 (h + 1024) != 1;
            if (big && be32 (h + 1024) != 1) continue;
            if ((big ? be32 (h + 1028) : le32 (h + 1028)) == 0) continue;
            ids = !le32 (h + 1196) && !le32 (h + 1200);
        }
        struct wsig *s = add (list, count, pages[i] - 10, 10, "swap", 0);
        if (s && ids) {
            static const unsigned char zero[16];
            if (memcmp (h + 1036, zero, 16)) uuid_text (s->uuid, h + 1036);
            name_text (s->label, sizeof s->label, h + 1052, 16);
        }
        return;
    }
}

static void
probe_xfs (int fd, struct wsig *list, int *count)
{
    unsigned char b[264];
    if (!rd (fd, 0, b, sizeof b) || memcmp (b, "XFSB", 4)) return;
    unsigned long block = be32 (b + 4), sect = be16 (b + 102), inode = be16 (b + 104);
    if (!pow2 (block) || block < 512 || block > 65536 || !pow2 (sect) || sect < 512 || sect > 32768
        || !pow2 (inode) || inode < 256 || inode > 2048)
        return;
    struct wsig *s = add (list, count, 0, 4, "xfs", 0);
    if (s) { uuid_text (s->uuid, b + 32); name_text (s->label, sizeof s->label, b + 108, 12); }
}

/* ext2/3/4 by feature flags, as libblkid tells them apart. */
static void
probe_ext (int fd, struct wsig *list, int *count)
{
    unsigned char sb[0x100];
    if (!rd (fd, 1024, sb, sizeof sb) || le16 (sb + 0x38) != 0xef53) return;
    uint32_t compat = le32 (sb + 0x5c), incompat = le32 (sb + 0x60), ro_compat = le32 (sb + 0x64);
    const char *type = (incompat & 0x8) ? "jbd"
        : ((incompat & ~0x16u) || (ro_compat & ~0x7u)) ? "ext4"
        : (compat & 0x4) ? "ext3" : "ext2";
    struct wsig *s = add (list, count, 0x438, 2, type, 0);
    if (s) {
        static const unsigned char zero[16];
        if (memcmp (sb + 0x68, zero, 16)) uuid_text (s->uuid, sb + 0x68);
        name_text (s->label, sizeof s->label, sb + 0x78, 16);
    }
}

static void
probe_iso (int fd, struct wsig *list, int *count)
{
    unsigned char b[2048];
    if (!rd (fd, 0x8000, b, sizeof b) || memcmp (b + 1, "CD001", 5)) return;
    struct wsig *s = add (list, count, 0x8001, 5, "iso9660", 0);
    if (!s) return;
    name_text (s->label, sizeof s->label, b + 40, 32);
    /* The volume's modification date, or its creation date, as libblkid prints it. */
    for (int at = 830; at >= 813; at -= 17) {
        const unsigned char *d = b + at;
        int digits = 1;
        for (int i = 0; i < 16; i++) if (d[i] < '0' || d[i] > '9') digits = 0;
        if (!digits || !memcmp (d, "0000000000000000", 16)) continue;
        snprintf (s->uuid, sizeof s->uuid, "%.4s-%.2s-%.2s-%.2s-%.2s-%.2s-%.2s",
                  d, d + 4, d + 6, d + 8, d + 10, d + 12, d + 14);
        break;
    }
}

static void
probe_ntfs (int fd, struct wsig *list, int *count)
{
    unsigned char b[512];
    if (!rd (fd, 0, b, sizeof b) || memcmp (b + 3, "NTFS    ", 8)) return;
    unsigned sector = le16 (b + 11);
    if (sector < 256 || sector > 4096 || !pow2 (sector) || !b[13] || le16 (b + 14) || b[16]) return;
    struct wsig *s = add (list, count, 3, 8, "ntfs", 0);
    if (s) snprintf (s->uuid, sizeof s->uuid, "%016llX", (unsigned long long) le64 (b + 72));
}

static void
probe_btrfs (int fd, struct wsig *list, int *count)
{
    unsigned char b[0x12b + 256];
    if (!rd (fd, 0x10000, b, sizeof b) || memcmp (b + 0x40, "_BHRfS_M", 8)) return;
    struct wsig *s = add (list, count, 0x10040, 8, "btrfs", 0);
    if (s) { uuid_text (s->uuid, b + 0x20); name_text (s->label, sizeof s->label, b + 0x12b, 256); }
}

/* Partition tables: a GPT header at the second sector with its backup at
   the last one and the protective MBR mark, or else a DOS table. */
static void
probe_tables (int fd, unsigned long long size, struct wsig *list, int *count, int have_fs)
{
    unsigned char b[512], h[512];
    int mbr = rd (fd, 0, b, sizeof b) && b[510] == 0x55 && b[511] == 0xaa;
    for (unsigned sector = 512; sector <= 4096; sector *= 2) {
        if (!rd (fd, sector, h, sizeof h) || memcmp (h, "EFI PART", 8)) continue;
        add (list, count, sector, 8, "gpt", 1);
        if (size >= 2ULL * sector && rd (fd, size - sector, h, sizeof h) && !memcmp (h, "EFI PART", 8))
            add (list, count, size - sector, 8, "gpt", 1);
        if (mbr) add (list, count, 0x1fe, 2, "PMBR", 1);
        return;
    }
    if (!mbr || have_fs) return;
    for (int i = 0; i < 4; i++) {
        const unsigned char *e = b + 446 + 16 * i;
        if ((e[0] & 0x7f) != 0) return;         /* a boot flag is 0x00 or 0x80 */
    }
    for (int i = 0; i < 4; i++) {
        const unsigned char *e = b + 446 + 16 * i;
        if (e[4] && le32 (e + 12)) { add (list, count, 0x1fe, 2, "dos", 1); return; }
    }
}

/* Signatures in libblkid's probing order. EVERY also returns the further
   magic strings of one filesystem, which only erasing needs. */
static int
probe (int fd, unsigned long long size, struct wsig *list, int every)
{
    int count = 0;
    int fat = probe_vfat (fd, list, &count, every);
    probe_swap (fd, list, &count);
    probe_xfs (fd, list, &count);
    probe_ext (fd, list, &count);
    probe_iso (fd, list, &count);
    probe_ntfs (fd, list, &count);
    probe_btrfs (fd, list, &count);
    /* As libblkid, a 55AA sector 0 that is a FAT, exFAT or NTFS boot
       sector is not a DOS partition table; other filesystems leave it be. */
    int boot = fat;
    for (int i = 0; i < count; i++)
        if (!strcmp (list[i].type, "ntfs") || !strcmp (list[i].type, "exfat")) boot = 1;
    probe_tables (fd, size, list, &count, boot);
    return count;
}

static int
wipefs_try (void)
{
    fprintf (stderr, "Try 'wipefs --help' for more information.\n");
    return EXECUTION_FAILURE;
}

/* One row of the listing; the table covers every device named. */
struct wrow { char name[256]; char off[24]; struct wsig sig; };

static void
print_table (const struct wrow *rows, int count, int headings, int parsable)
{
    if (!count) return;
    if (parsable) {
        if (headings) puts ("# offset,uuid,label,type");
        for (int i = 0; i < count; i++)
            printf ("%s,%s,%s,%s\n", rows[i].off, rows[i].sig.uuid, rows[i].sig.label, rows[i].sig.type);
        return;
    }
    int w[4] = { 6, 6, 4, 4 };                 /* DEVICE OFFSET TYPE UUID */
    if (!headings) w[0] = w[1] = w[2] = w[3] = 0;
    for (int i = 0; i < count; i++) {
        int n;
        if ((n = (int) strlen (rows[i].name)) > w[0]) w[0] = n;
        if ((n = (int) strlen (rows[i].off)) > w[1]) w[1] = n;
        if ((n = (int) strlen (rows[i].sig.type)) > w[2]) w[2] = n;
        if ((n = (int) strlen (rows[i].sig.uuid)) > w[3]) w[3] = n;
    }
    if (headings)
        printf ("%-*s %-*s %-*s %-*s LABEL\n", w[0], "DEVICE", w[1], "OFFSET", w[2], "TYPE", w[3], "UUID");
    for (int i = 0; i < count; i++)
        printf ("%-*s %-*s %-*s %-*s %s\n", w[0], rows[i].name, w[1], rows[i].off, w[2], rows[i].sig.type,
                w[3], rows[i].sig.uuid, rows[i].sig.label);
}

/* Zero one magic string and say so, in util-linux's words. */
static int
erase (int fd, const char *dev, const struct wsig *s, int noact, int quiet)
{
    unsigned char magic[16], zero[16] = { 0 };
    size_t len = s->len > sizeof magic ? sizeof magic : s->len;
    if (!rd (fd, s->offset, magic, len)) {
        builtin_error ("%s: failed to read signature: %s", dev, strerror (errno));
        return -1;
    }
    if (!noact && pwrite (fd, zero, len, (off_t) s->offset) != (ssize_t) len) {
        builtin_error ("%s: failed to erase %s magic string at offset 0x%08llx: %s",
                       dev, s->type, s->offset, strerror (errno));
        return -1;
    }
    if (quiet) return 0;
    printf (len == 1 ? "%s: %zu byte was erased at offset 0x%08llx (%s): "
                     : "%s: %zu bytes were erased at offset 0x%08llx (%s): ",
            dev, len, s->offset, s->type);
    for (size_t i = 0; i < len; i++)
        printf (i + 1 < len ? "%02x " : "%02x\n", magic[i]);
    return 0;
}

int
wipefs_builtin (WORD_LIST *list)
{
    int all = 0, noact = 0, quiet = 0, force = 0, headings = 1, parsable = 0, options = 1;
    int noffsets = 0, ndev = 0;
    unsigned long long offsets[WMAX];
    const char *devices[256];

    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (!options || w[0] != '-' || !w[1]) {
            if (ndev >= 256) { builtin_error ("too many devices"); return EXECUTION_FAILURE; }
            devices[ndev++] = w;
            continue;
        }
        const char *value = NULL;
        if (!strcmp (w, "--")) { options = 0; continue; }
        if (!strcmp (w, "--help")) {
            extern char *wipefs_doc[];
            for (char **lp = wipefs_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (w[1] == '-') {
            if (!strcmp (w, "--all")) all = 1;
            else if (!strcmp (w, "--no-act")) noact = 1;
            else if (!strcmp (w, "--quiet")) quiet = 1;
            else if (!strcmp (w, "--force")) force = 1;
            else if (!strcmp (w, "--noheadings")) headings = 0;
            else if (!strcmp (w, "--parsable")) parsable = 1;
            else if (!strncmp (w, "--offset=", 9)) value = w + 9;
            else if (!strcmp (w, "--offset") && list->next) { list = list->next; value = list->word->word; }
            else { builtin_error ("unrecognized option '%s'", w); return wipefs_try (); }
        } else {
            for (const char *c = w + 1; *c && !value; c++) {
                if (*c == 'a') all = 1;
                else if (*c == 'n') noact = 1;
                else if (*c == 'q') quiet = 1;
                else if (*c == 'f') force = 1;
                else if (*c == 'i') headings = 0;
                else if (*c == 'p') parsable = 1;
                else if (*c == 'o') {
                    if (c[1]) value = c + 1;
                    else if (list->next) { list = list->next; value = list->word->word; }
                    else { builtin_error ("option requires an argument -- 'o'"); return wipefs_try (); }
                }
                else { builtin_error ("invalid option -- '%c'", *c); return wipefs_try (); }
            }
        }
        if (value) {
            char *end = NULL;
            errno = 0;
            unsigned long long v = strtoull (value, &end, 0);
            if (errno || end == value || *end || noffsets >= WMAX) {
                builtin_error ("invalid offset argument: '%s'", value);
                return EXECUTION_FAILURE;
            }
            offsets[noffsets++] = v;
        }
    }
    if (!ndev) { builtin_error ("no device specified"); return wipefs_try (); }
    if (all && noffsets) {
        builtin_error ("mutually exclusive arguments: --all --offset");
        return EXECUTION_FAILURE;
    }

    int wipe = all || noffsets, rc = EXECUTION_SUCCESS, nrows = 0, maxrows = 0;
    struct wrow *rows = NULL;
    for (int d = 0; d < ndev; d++) {
        const char *dev = devices[d];
        struct stat st;
        /* Erasing opens for writing even when -n keeps it from writing, and
           an in-use block device is refused unless forced. The first device
           that cannot be opened ends the command. */
        int flags = wipe ? O_RDWR : O_RDONLY;
        if (wipe && !force && stat (dev, &st) == 0 && S_ISBLK (st.st_mode)) flags |= O_EXCL;
        int fd = open (dev, flags | O_CLOEXEC);
        if (fd < 0 || fstat (fd, &st) < 0) {
            builtin_error ("error: %s: probing initialization failed: %s", dev, strerror (errno));
            if (fd >= 0) close (fd);
            rc = EXECUTION_FAILURE;
            break;
        }
        unsigned long long size = (unsigned long long) st.st_size;
        if (S_ISBLK (st.st_mode)) { uint64_t bytes = 0; if (ioctl (fd, BLKGETSIZE64, &bytes) == 0) size = bytes; }

        struct wsig sigs[WMAX];
        if (!wipe) {
            int found = probe (fd, size, sigs, 0);
            close (fd);
            if (nrows + found > maxrows) {
                struct wrow *grown = realloc (rows, (size_t) (nrows + found + 16) * sizeof *rows);
                if (!grown) { builtin_error ("out of memory"); rc = EXECUTION_FAILURE; break; }
                rows = grown; maxrows = nrows + found + 16;
            }
            char *copy = strdup (dev);
            for (int i = 0; i < found; i++) {
                snprintf (rows[nrows].name, sizeof rows[nrows].name, "%s", copy ? basename (copy) : dev);
                snprintf (rows[nrows].off, sizeof rows[nrows].off, "0x%llx", sigs[i].offset);
                rows[nrows++].sig = sigs[i];
            }
            free (copy);
            continue;
        }
        int count = probe (fd, size, sigs, !noact), reread = 0;
        for (int k = 0; k < noffsets; k++) {
            int known = 0;
            for (int i = 0; i < count; i++) if (sigs[i].offset == offsets[k]) known = 1;
            if (!known) {
                builtin_error ("%s: offset 0x%llx not found", dev, offsets[k]);
                rc = EXECUTION_FAILURE;
            }
        }
        for (int i = 0; i < count; i++) {
            int wanted = all;
            for (int k = 0; k < noffsets; k++) if (sigs[i].offset == offsets[k]) wanted = 1;
            if (!wanted) continue;
            if (erase (fd, dev, &sigs[i], noact, quiet) < 0) { rc = EXECUTION_FAILURE; break; }
            if (sigs[i].is_pt) reread = 1;
        }
        if (!noact) fsync (fd);
        if (reread && !noact && S_ISBLK (st.st_mode)) {
            errno = 0;
            ioctl (fd, BLKRRPART);
            if (!quiet) printf ("%s: calling ioctl to re-read partition table: %s\n", dev, strerror (errno));
        }
        close (fd);
    }
    print_table (rows, nrows, headings, parsable);
    free (rows);
    if (fflush (stdout) == EOF) rc = EXECUTION_FAILURE;
    return rc;
}

char *wipefs_doc[] = {
    "List or erase filesystem, swap and partition-table signatures.",
    "",
    "    wipefs device          table of detected signatures",
    "    wipefs -a device       erase every detected signature",
    "    wipefs -o OFF device   erase the signature at offset OFF",
    "    -n  write nothing      -q  no erase messages    -f  erase a device in use",
    "    -i  no table heading   -p  parsable listing",
    "",
    "Recognises vfat, swap, xfs, ext2/3/4, iso9660, ntfs, btrfs, dos and gpt.",
    (char *) NULL
};

struct builtin wipefs_struct = {
    "wipefs",
    wipefs_builtin,
    BUILTIN_ENABLED,
    wipefs_doc,
    "wipefs [-anqfip] [-o OFFSET] device...",
    0
};
