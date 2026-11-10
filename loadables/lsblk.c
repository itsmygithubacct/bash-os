/* bashlsblk.c — list block devices walking /sys/class/block.
 *
 *   bashlsblk [-a] [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]
 *
 *   default      tree form in MAJ:MIN order, each device followed by its
 *                partitions and holders (ASCII branch characters)
 *   -l           list form — the same order, without tree art
 *   -d           nodeps    — top-level devices only
 *   -f           --fs      — the util-linux filesystem column set, from
 *                            the udev database, else by probing the node
 *   DEV          restrict output to the named device(s). A block device
 *                node selects its MAJ:MIN; otherwise DEV may be a bare
 *                basename (`vda`) or a /sys path, whose trailing component
 *                matches the kernel or device-mapper name.
 *
 * Scope (ML-T1-05, paired with bashblkid):
 *   - Enumerates /sys/class/block (the canonical "every kobject with a
 *     block major:minor" view).
 *   - Reads NAME (dm/name for device-mapper), MAJ:MIN (sys/dev), SIZE
 *     (sys/size, 512-byte sectors), RO (sys/ro), TYPE (util-linux rules:
 *     part, dm/uuid prefix, loop, md/level, SCSI device/type), and a
 *     bounded Debian-shaped column set via -o.
 *   - Builds parent->children edges by inspecting each entry's
 *     `/sys/class/block/<name>` symlink target: a partition's resolved
 *     path ends in `…/block/<DISK>/<NAME>`, so the parent disk name is
 *     the second-to-last path component.  A stacked device hangs under
 *     its first slave.
 *   - Lays tables out like libsmartcols (column widths from cells,
 *     headings and width hints; right-aligned numeric columns).
 *
 * Does NOT do:
 *   - lvm / dm-crypt / md topology beyond the single-parent map.
 *   - JSON / full util-linux column vocabulary / --sort.
 *   - UTF-8 tree art; terminal-width truncation.
 *
 * Exit codes (lsblk(8) convention):
 *   0    success
 *   1    operational error (open/read failure under /sys)
 *   2    usage error
 *   32   no DEV operand found
 *   64   some DEV operands not found
 *
 * Source counterparts:
 *   research/refs/busybox/util-linux/lsblk.c   (382 LoC — minimal
 *      reference; same /sys-walk-then-print structure we use here)
 *   research/refs/util-linux/lsblk-cmd/lsblk.c (2909 LoC — canonical
 *      reference, used for column-set ordering)
 *
 * --- LICENSE --- MIT, same boilerplate as bashfsck.c / bashblkid.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#include "loadables.h"

#define BLB_MAX_DEVS    256
#define BLB_NAME_MAX    64
#define BLB_PARENT_MAX  64
#define BLB_MAJMIN_MAX  16
#define BLB_TYPE_MAX    32
#define BLB_FSTYPE_MAX  16
#define BLB_FSVER_MAX   32
#define BLB_LABEL_MAX   128
#define BLB_UUID_MAX    40
#define BLB_MOUNT_MAX   256
#define BLB_PARTLABEL_MAX 128
#define BLB_PATH_MAX    1024
#define BLB_PROBE_LEN   (128 * 1024)
#define BLB_COL_MAX     32

typedef struct {
    char     name[BLB_NAME_MAX];
    char     dmname[BLB_NAME_MAX];       /* dm/name of a dm-N device, else "" */
    char     parent[BLB_PARENT_MAX];     /* "" for top-level disks */
    char     majmin[BLB_MAJMIN_MAX];     /* "MAJ:MIN" or "?" */
    unsigned int maj, min;
    int      have_devno;
    char     type[BLB_TYPE_MAX];         /* util-linux TYPE: disk / part / loop / rom / dm / ... */
    char     fstype[BLB_FSTYPE_MAX];     /* ext4 / vfat / ... or "" */
    char     fsver[BLB_FSVER_MAX];
    char     label[BLB_LABEL_MAX];
    char     uuid[BLB_UUID_MAX];
    char     mountpoint[BLB_MOUNT_MAX];
    char     mountpoints[BLB_MOUNT_MAX];
    char     partlabel[BLB_PARTLABEL_MAX];
    char     partuuid[BLB_UUID_MAX];
    int      have_vfs;                   /* statvfs of the mountpoint succeeded */
    int      is_swap;                    /* active swap: mountpoint "[SWAP]" */
    uint64_t fsavail;
    uint64_t fsblocks, fsbfree;
    uint64_t size_bytes;                 /* size-in-sectors × 512 */
    int      ro;                         /* 1 if /sys/.../ro reads "1" */
    int      removable;                  /* 1 if /sys/.../removable reads "1" */
    int      hidden;                     /* 1 if /sys/.../hidden reads "1" — skipped */
} blb_dev;

typedef enum {
    BLB_COL_NAME,
    BLB_COL_MAJMIN,
    BLB_COL_RM,
    BLB_COL_SIZE,
    BLB_COL_RO,
    BLB_COL_TYPE,
    BLB_COL_FSTYPE,
    BLB_COL_FSVER,
    BLB_COL_LABEL,
    BLB_COL_UUID,
    BLB_COL_PARTLABEL,
    BLB_COL_PARTUUID,
    BLB_COL_MOUNTPOINT,
    BLB_COL_MOUNTPOINTS,
    BLB_COL_FSAVAIL,
    BLB_COL_FSUSE_PCT
} blb_col_id;

/* Width hints and alignment follow util-linux lsblk's column table: a hint
   of 1 or more is a minimum width, a fractional hint only matters on a
   terminal that must be shrunk to fit. */
typedef struct {
    const char *name;
    blb_col_id id;
    double whint;
    int right;
} blb_col_def;

static const blb_col_def blb_cols[] = {
    { "NAME",        BLB_COL_NAME,        0.25, 0 },
    { "MAJ:MIN",     BLB_COL_MAJMIN,      6,    0 },
    { "RM",          BLB_COL_RM,          1,    1 },
    { "SIZE",        BLB_COL_SIZE,        5,    1 },
    { "RO",          BLB_COL_RO,          1,    1 },
    { "TYPE",        BLB_COL_TYPE,        4,    0 },
    { "FSTYPE",      BLB_COL_FSTYPE,      0.1,  0 },
    { "FSVER",       BLB_COL_FSVER,       0.1,  0 },
    { "LABEL",       BLB_COL_LABEL,       0.1,  0 },
    { "UUID",        BLB_COL_UUID,        36,   0 },
    { "PARTLABEL",   BLB_COL_PARTLABEL,   0.1,  0 },
    { "PARTUUID",    BLB_COL_PARTUUID,    36,   0 },
    { "MOUNTPOINT",  BLB_COL_MOUNTPOINT,  0.1,  0 },
    { "MOUNTPOINTS", BLB_COL_MOUNTPOINTS, 0.1,  0 },
    { "FSAVAIL",     BLB_COL_FSAVAIL,     5,    1 },
    { "FSUSE%",      BLB_COL_FSUSE_PCT,   3,    1 },
    { NULL, 0, 0, 0 }
};

static const char *
blb_sys_block_dir (void)
{
    const char *e = getenv ("BASHLSBLK_SYS_BLOCK_DIR");
    return (e && *e) ? e : "/sys/class/block";
}

static const char *
blb_dev_root (void)
{
    const char *e = getenv ("BASHLSBLK_DEV_ROOT");
    return (e && *e) ? e : "/dev";
}

static const char *
blb_proc_mounts (void)
{
    const char *e = getenv ("BASHLSBLK_PROC_MOUNTS");
    return (e && *e) ? e : "/proc/self/mounts";
}

static const char *
blb_proc_swaps (void)
{
    const char *e = getenv ("BASHLSBLK_PROC_SWAPS");
    return (e && *e) ? e : "/proc/swaps";
}

static int
blb_join2 (char *out, size_t outsz, const char *a, const char *b)
{
    int n = snprintf (out, outsz, "%s/%s", a, b);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

/* ---------- read helpers ---------- */

static int
blb_read_str (const char *base, const char *leaf, char *out, size_t outsz)
{
    char path[BLB_PATH_MAX];
    int n = snprintf (path, sizeof path, "%s/%s", base, leaf);
    if (n < 0 || (size_t) n >= sizeof path) return -1;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, out, outsz - 1);
    close (fd);
    if (r < 0) return -1;
    out[r] = '\0';
    /* trim trailing newline + whitespace */
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == ' '
                  || out[r - 1] == '\t' || out[r - 1] == '\r')) {
        out[--r] = '\0';
    }
    return 0;
}

static int
blb_read_int (const char *base, const char *leaf, long long *out)
{
    char buf[64];
    if (blb_read_str (base, leaf, buf, sizeof buf) < 0) return -1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll (buf, &end, 10);
    if (errno != 0 || end == buf) return -1;
    *out = v;
    return 0;
}

static int
blb_exists (const char *base, const char *leaf)
{
    char path[BLB_PATH_MAX];
    int n = snprintf (path, sizeof path, "%s/%s", base, leaf);
    if (n < 0 || (size_t) n >= sizeof path) return 0;
    struct stat st;
    return (stat (path, &st) == 0);
}

/* ---------- classification ---------- */

/* Resolve /sys/class/block/<name> and pick the parent disk if any.
 * Returns 1 if a parent was extracted into out_parent, 0 otherwise.
 *
 * Disk readlink target shape:    …/devices/.../block/<DISK>
 * Partition readlink target:     …/devices/.../block/<DISK>/<PART>
 *
 * So the parent name is the second-to-last segment IF and only IF that
 * segment is "block". For a disk the second-to-last segment is the bus
 * directory (e.g. "virtio2"), which is NOT "block". This is robust to
 * the various sysfs topologies (virtio-blk / nvme / scsi / loop / ram).
 */
static int
blb_resolve_parent (const char *name, char *out_parent, size_t outsz)
{
    char link_path[BLB_PATH_MAX];
    char parent_path[BLB_PATH_MAX];
    if (snprintf (link_path, sizeof link_path, "%s/%s",
                  blb_sys_block_dir (), name) >= (int) sizeof link_path)
        return 0;

    if (snprintf (parent_path, sizeof parent_path, "%s/parent",
                  link_path) < (int) sizeof parent_path
        && blb_read_str (link_path, "parent", out_parent, outsz) == 0
        && out_parent[0] != '\0')
        return 1;

    char target[BLB_PATH_MAX];
    ssize_t n = readlink (link_path, target, sizeof target - 1);
    if (n < 0) return 0;
    target[n] = '\0';

    /* Walk backwards to find the last and second-to-last components. */
    char *last_slash = strrchr (target, '/');
    if (!last_slash || last_slash == target) return 0;
    *last_slash = '\0';
    char *prev_slash = strrchr (target, '/');
    if (!prev_slash) return 0;
    char *parent_seg = prev_slash + 1;

    if (strcmp (parent_seg, "block") == 0) {
        /* Top-level disk — its target ends in `…/block/<NAME>`. */
        return 0;
    }
    char parent_base[BLB_PATH_MAX];
    if (snprintf (parent_base, sizeof parent_base, "%s/%s",
                  blb_sys_block_dir (), parent_seg) >= (int) sizeof parent_base)
        return 0;
    struct stat st;
    if (stat (parent_base, &st) < 0)
        return 0;
    /* Partition: parent_seg IS the parent disk. */
    size_t plen = strlen (parent_seg);
    if (plen >= outsz) return 0;
    memcpy (out_parent, parent_seg, plen + 1);
    return 1;
}

/* SCSI peripheral device types, as util-linux names them. */
static const char *
blb_scsi_type_name (long long type)
{
    switch (type) {
    case 0x00: return "disk";
    case 0x01: return "tape";
    case 0x02: return "printer";
    case 0x03: return "processor";
    case 0x04: return "worm";
    case 0x05: return "rom";
    case 0x06: return "scanner";
    case 0x07: return "mo-disk";
    case 0x08: return "changer";
    case 0x09: return "comm";
    case 0x0c: return "raid";
    case 0x0d: return "enclosure";
    case 0x0e: return "rbc";
    case 0x11: return "osd";
    case 0x7f: return "no-lun";
    }
    return NULL;
}

/* TYPE as util-linux lsblk derives it: partitions are "part"; a dm device
 * is named by its dm/uuid subsystem prefix (kpartx "part1-..." is "part"),
 * else "dm"; loop and md by name (md by md/level when known); anything else
 * by its SCSI device/type, defaulting to "disk".  Lower case throughout. */
static void
blb_classify (blb_dev *d)
{
    char base[BLB_PATH_MAX], buf[256];
    long long scsi = 0;
    const char *type = NULL;
    snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), d->name);

    d->type[0] = '\0';
    if (blb_exists (base, "partition")) {
        type = "part";
    } else if (strncmp (d->name, "dm-", 3) == 0) {
        if (blb_read_str (base, "dm/uuid", buf, sizeof buf) == 0 && buf[0]) {
            buf[strcspn (buf, "-")] = '\0';
            if (strncasecmp (buf, "part", 4) == 0)
                buf[4] = '\0';
            if (buf[0])
                snprintf (d->type, sizeof d->type, "%.31s", buf);
        }
        if (!d->type[0])
            type = "dm";
    } else if (strncmp (d->name, "loop", 4) == 0) {
        type = "loop";
    } else if (strncmp (d->name, "md", 2) == 0) {
        if (blb_read_str (base, "md/level", buf, sizeof buf) == 0 && buf[0])
            snprintf (d->type, sizeof d->type, "%.31s", buf);
        else
            type = "md";
    } else {
        if (blb_read_int (base, "device/type", &scsi) == 0)
            type = blb_scsi_type_name (scsi);
        if (!type)
            type = "disk";
    }
    if (type)
        snprintf (d->type, sizeof d->type, "%s", type);
    for (char *p = d->type; *p; p++)
        *p = (char) tolower ((unsigned char) *p);
}

static uint16_t
blb_le16 (const unsigned char *p)
{
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static uint32_t
blb_le32 (const unsigned char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static uint64_t
blb_le64 (const unsigned char *p)
{
    return (uint64_t) blb_le32 (p)
         | ((uint64_t) blb_le32 (p + 4) << 32);
}

static void
blb_trim (char *s)
{
    size_t n = strlen (s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\0'))
        s[--n] = '\0';
}

static void
blb_copy_fixed (char *dst, size_t dstlen, const unsigned char *src, size_t n)
{
    size_t i = 0;
    if (dstlen == 0) return;
    if (n + 1 > dstlen) n = dstlen - 1;
    for (i = 0; i < n; i++) {
        if (src[i] == 0) break;
        dst[i] = (char) src[i];
    }
    dst[i] = '\0';
    blb_trim (dst);
}

static void
blb_uuid_be (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void
blb_uuid_gpt (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void
blb_serial4 (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX, "%02X%02X-%02X%02X",
              u[3], u[2], u[1], u[0]);
}

static void
blb_serial8 (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX, "%02X%02X%02X%02X%02X%02X%02X%02X",
              u[7], u[6], u[5], u[4], u[3], u[2], u[1], u[0]);
}

static int
blb_guid_zero (const unsigned char *u)
{
    for (int i = 0; i < 16; i++)
        if (u[i] != 0)
            return 0;
    return 1;
}

static void
blb_copy_utf16le_ascii (char *dst, size_t dstlen,
                        const unsigned char *src, size_t nbytes)
{
    size_t di = 0;
    if (dstlen == 0) return;
    for (size_t i = 0; i + 1 < nbytes && di + 1 < dstlen; i += 2) {
        unsigned char lo = src[i];
        unsigned char hi = src[i + 1];
        if (lo == 0 && hi == 0) break;
        if (hi != 0 || lo < 0x20 || lo > 0x7e) {
            dst[di++] = '?';
            continue;
        }
        dst[di++] = (char) lo;
    }
    dst[di] = '\0';
    blb_trim (dst);
}

static ssize_t
blb_read_probe (const char *path, unsigned char *buf)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while (total < (ssize_t) BLB_PROBE_LEN) {
        ssize_t r = read (fd, buf + total, BLB_PROBE_LEN - (size_t) total);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close (fd);
            errno = e;
            return -1;
        }
        if (r == 0) break;
        total += r;
    }
    close (fd);
    return total;
}

static void
blb_probe_super (const char *name, blb_dev *d)
{
    static unsigned char buf[BLB_PROBE_LEN];
    char path[BLB_PATH_MAX];

    if (blb_join2 (path, sizeof path, blb_dev_root (), name) < 0)
        return;
    ssize_t n = blb_read_probe (path, buf);
    if (n <= 0)
        return;

    if ((size_t) n >= 1024 + 0x100 && blb_le16 (buf + 1024 + 0x38) == 0xef53) {
        const unsigned char *sb = buf + 1024;
        uint32_t compat = blb_le32 (sb + 0x5c);
        uint32_t incompat = blb_le32 (sb + 0x60);
        uint32_t ro_compat = blb_le32 (sb + 0x64);
        /* Journal-free ext4 still has features unsupported by ext3. */
        const char *t = (incompat & 0x8) ? "jbd" :
            ((incompat & ~0x16u) || (ro_compat & ~0x7u)) ? "ext4" :
            (compat & 0x4) ? "ext3" : "ext2";
        snprintf (d->fstype, sizeof d->fstype, "%s", t);
        snprintf (d->fsver, sizeof d->fsver, "1.0");
        blb_uuid_be (d->uuid, sb + 0x68);
        blb_copy_fixed (d->label, sizeof d->label, sb + 0x78, 16);
        return;
    }
    if ((size_t) n >= 128 && memcmp (buf, "XFSB", 4) == 0) {
        snprintf (d->fstype, sizeof d->fstype, "xfs");
        blb_uuid_be (d->uuid, buf + 32);
        blb_copy_fixed (d->label, sizeof d->label, buf + 108, 12);
        return;
    }
    if ((size_t) n >= 65536 + 72 && memcmp (buf + 65536 + 64, "_BHRfS_M", 8) == 0) {
        snprintf (d->fstype, sizeof d->fstype, "btrfs");
        blb_uuid_be (d->uuid, buf + 65536 + 32);
        if ((size_t) n >= 65536 + 0x300)
            blb_copy_fixed (d->label, sizeof d->label, buf + 65536 + 299, 256);
        return;
    }
    if ((size_t) n >= 1024 + 512 && blb_le32 (buf + 1024) == 0xF2F52010u) {
        const unsigned char *sb = buf + 1024;
        snprintf (d->fstype, sizeof d->fstype, "f2fs");
        blb_uuid_be (d->uuid, sb + 108);
        size_t li = 0;
        for (int i = 0; i < 64 && li + 1 < sizeof d->label; i++) {
            unsigned char lo = sb[124 + i * 2];
            unsigned char hi = sb[124 + i * 2 + 1];
            if (lo == 0 && hi == 0) break;
            if (hi != 0 || lo < 0x20 || lo > 0x7e) break;
            d->label[li++] = (char) lo;
        }
        d->label[li] = '\0';
        blb_trim (d->label);
        return;
    }
    if ((size_t) n >= 512 && memcmp (buf + 3, "NTFS    ", 8) == 0
        && buf[510] == 0x55 && buf[511] == 0xaa) {
        snprintf (d->fstype, sizeof d->fstype, "ntfs");
        blb_serial8 (d->uuid, buf + 72);
        return;
    }
    if ((size_t) n >= 512 && memcmp (buf + 3, "EXFAT   ", 8) == 0
        && buf[510] == 0x55 && buf[511] == 0xaa) {
        snprintf (d->fstype, sizeof d->fstype, "exfat");
        blb_serial4 (d->uuid, buf + 100);
        return;
    }
    if ((size_t) n >= 512 && buf[510] == 0x55 && buf[511] == 0xaa) {
        uint16_t bytes_per_sector = blb_le16 (buf + 11);
        uint16_t reserved = blb_le16 (buf + 14);
        if ((bytes_per_sector == 512 || bytes_per_sector == 1024
             || bytes_per_sector == 2048 || bytes_per_sector == 4096)
            && reserved != 0
            && ((buf[66] == 0x29 && (memcmp (buf + 82, "FAT32   ", 8) == 0
                                     || memcmp (buf + 82, "FAT     ", 8) == 0))
                || buf[38] == 0x29)) {
            snprintf (d->fstype, sizeof d->fstype, "vfat");
            if (buf[66] == 0x29) {
                blb_serial4 (d->uuid, buf + 67);
                blb_copy_fixed (d->label, sizeof d->label, buf + 71, 11);
                snprintf (d->fsver, sizeof d->fsver, "FAT32");
            } else {
                blb_serial4 (d->uuid, buf + 39);
                blb_copy_fixed (d->label, sizeof d->label, buf + 43, 11);
                snprintf (d->fsver, sizeof d->fsver, "FAT16");
            }
            if (strcmp (d->label, "NO NAME") == 0)
                d->label[0] = '\0';
            return;
        }
    }
    static const size_t page_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
    for (size_t i = 0; i < sizeof page_sizes / sizeof page_sizes[0]; i++) {
        size_t off = page_sizes[i];
        if (off < 10 || off > (size_t) n) continue;
        if (memcmp (buf + off - 10, "SWAPSPACE2", 10) == 0
            || memcmp (buf + off - 10, "SWAP-SPACE", 10) == 0) {
            snprintf (d->fstype, sizeof d->fstype, "swap");
            if ((size_t) n >= 1052 + 16) {
                blb_uuid_be (d->uuid, buf + 1036);
                blb_copy_fixed (d->label, sizeof d->label, buf + 1052, 16);
            }
            return;
        }
    }
}

static int
blb_read_partition_no (const char *name)
{
    char base[BLB_PATH_MAX];
    long long v = 0;
    if (snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), name) >= (int) sizeof base)
        return 0;
    if (blb_read_int (base, "partition", &v) < 0 || v <= 0 || v > 65535)
        return 0;
    return (int) v;
}

static void
blb_probe_part_gpt (blb_dev *d)
{
    if (!d->parent[0])
        return;
    int partno = blb_read_partition_no (d->name);
    if (partno <= 0)
        return;
    char parent_path[BLB_PATH_MAX];
    if (blb_join2 (parent_path, sizeof parent_path, blb_dev_root (), d->parent) < 0)
        return;
    static unsigned char buf[BLB_PROBE_LEN];
    ssize_t n = blb_read_probe (parent_path, buf);
    if (n <= 0 || (size_t) n < 512 + 92)
        return;
    if (memcmp (buf + 512, "EFI PART", 8) != 0)
        return;
    uint64_t ents_lba = blb_le64 (buf + 512 + 72);
    uint32_t nents = blb_le32 (buf + 512 + 80);
    uint32_t entsz = blb_le32 (buf + 512 + 84);
    if (ents_lba == 0 || nents == 0 || entsz < 56 || entsz > 4096)
        return;
    if ((uint32_t) partno > nents)
        return;
    uint64_t off64 = ents_lba * 512ULL + (uint64_t) (partno - 1) * entsz;
    if (off64 + entsz > (uint64_t) n)
        return;
    const unsigned char *e = buf + off64;
    if (blb_guid_zero (e) || blb_guid_zero (e + 16))
        return;
    blb_uuid_gpt (d->partuuid, e + 16);
    if (entsz > 56)
        blb_copy_utf16le_ascii (d->partlabel, sizeof d->partlabel, e + 56, entsz - 56);
}

static void
blb_unescape_mount (const char *in, char *out, size_t outsz)
{
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < outsz; i++) {
        if (in[i] == '\\'
            && in[i + 1] >= '0' && in[i + 1] <= '7'
            && in[i + 2] >= '0' && in[i + 2] <= '7'
            && in[i + 3] >= '0' && in[i + 3] <= '7') {
            int v = (in[i + 1] - '0') * 64 + (in[i + 2] - '0') * 8 + (in[i + 3] - '0');
            out[oi++] = (char) v;
            i += 3;
        } else {
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
}

static int
blb_mount_dev_matches (const char *field, const blb_dev *d)
{
    char devpath[BLB_PATH_MAX];
    if (blb_join2 (devpath, sizeof devpath, blb_dev_root (), d->name) == 0
        && strcmp (field, devpath) == 0)
        return 1;
    if (strncmp (field, "/dev/", 5) == 0 && strcmp (field + 5, d->name) == 0)
        return 1;
    if (strcmp (field, d->name) == 0)
        return 1;
    if (d->dmname[0] && strncmp (field, "/dev/mapper/", 12) == 0
        && strcmp (field + 12, d->dmname) == 0)
        return 1;
    struct stat st;
    unsigned int maj, min;
    if (sscanf (d->majmin, "%u:%u", &maj, &min) == 2
        && stat (field, &st) == 0 && S_ISBLK (st.st_mode)
        && major (st.st_rdev) == maj && minor (st.st_rdev) == min)
        return 1;
    return 0;
}

static void
blb_load_mountpoint (blb_dev *d)
{
    FILE *f = fopen (blb_proc_mounts (), "r");
    if (!f) return;
    char line[2048];
    while (fgets (line, sizeof line, f)) {
        char src[512], mnt[512], usrc[512], umnt[512];
        if (sscanf (line, "%511s %511s", src, mnt) != 2) continue;
        blb_unescape_mount (src, usrc, sizeof usrc);
        if (!blb_mount_dev_matches (usrc, d)) continue;
        blb_unescape_mount (mnt, umnt, sizeof umnt);
        snprintf (d->mountpoint, sizeof d->mountpoint, "%s", umnt);
        /* util-linux displays the most recent mount first. */
        char previous[BLB_MOUNT_MAX];
        memcpy (previous, d->mountpoints, sizeof previous);
        if (previous[0]) {
            size_t used = strlen (umnt);
            if (used + 1 < sizeof d->mountpoints)
                snprintf (d->mountpoints, sizeof d->mountpoints, "%s\n%.*s",
                          umnt, (int) (sizeof d->mountpoints - used - 2), previous);
            else
                snprintf (d->mountpoints, sizeof d->mountpoints, "%s", umnt);
        } else
            snprintf (d->mountpoints, sizeof d->mountpoints, "%s", umnt);
    }
    fclose (f);
    /* An unmounted device in use as swap shows "[SWAP]", as in util-linux. */
    if (!d->mountpoints[0] && (f = fopen (blb_proc_swaps (), "r"))) {
        if (fgets (line, sizeof line, f))     /* heading */
            while (fgets (line, sizeof line, f)) {
                char src[512], usrc[512];
                if (sscanf (line, "%511s", src) != 1) continue;
                blb_unescape_mount (src, usrc, sizeof usrc);
                if (!blb_mount_dev_matches (usrc, d)) continue;
                d->is_swap = 1;
                snprintf (d->mountpoint, sizeof d->mountpoint, "[SWAP]");
                snprintf (d->mountpoints, sizeof d->mountpoints, "[SWAP]");
                break;
            }
        fclose (f);
    }
}

/* FSAVAIL is f_bavail; FSUSE% is (f_blocks - f_bfree) / f_blocks, as in
 * util-linux. */
static void
blb_load_fs_usage (blb_dev *d)
{
    if (!d->mountpoint[0] || d->is_swap)
        return;
    struct statvfs vfs;
    if (statvfs (d->mountpoint, &vfs) < 0)
        return;
    d->have_vfs = 1;
    d->fsavail = (uint64_t) vfs.f_bavail * (uint64_t) vfs.f_frsize;
    d->fsblocks = (uint64_t) vfs.f_blocks;
    d->fsbfree = (uint64_t) vfs.f_bfree;
}

/* udev encodes unsafe bytes of the *_ENC values as \xHH. */
static void
blb_unhexmangle (const char *in, char *out, size_t outsz)
{
    size_t oi = 0;
    if (outsz == 0) return;
    for (size_t i = 0; in[i] && oi + 1 < outsz; i++) {
        if (in[i] == '\\' && in[i + 1] == 'x'
            && isxdigit ((unsigned char) in[i + 2])
            && isxdigit ((unsigned char) in[i + 3])) {
            char hex[3] = { in[i + 2], in[i + 3], '\0' };
            out[oi++] = (char) strtol (hex, NULL, 16);
            i += 3;
        } else
            out[oi++] = in[i];
    }
    out[oi] = '\0';
}

/* util-linux lsblk takes filesystem and partition properties from the udev
 * database whenever udev knows the device: an entry without ID_FS_* values
 * means "no filesystem", not "probe the node" (a freshly written superblock
 * stays invisible until udev has processed the change).  Returns 1 when the
 * database has an entry (its values, possibly none, are then the device's
 * properties), 0 when there is none and the node may be probed instead. */
static int
blb_load_udev (blb_dev *d)
{
    const char *root = getenv ("BASHLSBLK_UDEV_DATA_DIR");
    char path[BLB_PATH_MAX], line[1024];
    int have_label_enc = 0, have_uuid_enc = 0;
    if (!root || !*root) {
        /* A redirected sysfs fixture must not inherit the host's udev tags. */
        const char *sys = getenv ("BASHLSBLK_SYS_BLOCK_DIR");
        if (sys && *sys) return 0;
        root = "/run/udev/data";
    }
    if (!d->have_devno) return 0;
    if (snprintf (path, sizeof path, "%s/b%u:%u", root, d->maj, d->min) >= (int) sizeof path)
        return 0;
    FILE *f = fopen (path, "r");
    if (!f) return 0;
    d->fstype[0] = d->fsver[0] = d->label[0] = d->uuid[0] = '\0';
    d->partlabel[0] = d->partuuid[0] = '\0';
    while (fgets (line, sizeof line, f)) {
        line[strcspn (line, "\r\n")] = 0;
        if (strncmp (line, "E:", 2) != 0) continue;
        const char *kv = line + 2, *v = strchr (kv, '=');
        if (!v) continue;
        size_t klen = (size_t) (v - kv);
        v++;
#define BLB_KEY(k) (klen == sizeof (k) - 1 && strncmp (kv, k, klen) == 0)
        if (BLB_KEY ("ID_FS_TYPE"))
            snprintf (d->fstype, sizeof d->fstype, "%s", v);
        else if (BLB_KEY ("ID_FS_VERSION"))
            snprintf (d->fsver, sizeof d->fsver, "%s", v);
        else if (BLB_KEY ("ID_FS_LABEL_ENC")) {
            blb_unhexmangle (v, d->label, sizeof d->label);
            have_label_enc = 1;
        } else if (BLB_KEY ("ID_FS_LABEL") && !have_label_enc)
            snprintf (d->label, sizeof d->label, "%s", v);
        else if (BLB_KEY ("ID_FS_UUID_ENC")) {
            blb_unhexmangle (v, d->uuid, sizeof d->uuid);
            have_uuid_enc = 1;
        } else if (BLB_KEY ("ID_FS_UUID") && !have_uuid_enc)
            snprintf (d->uuid, sizeof d->uuid, "%s", v);
        else if (BLB_KEY ("ID_PART_ENTRY_NAME"))
            blb_unhexmangle (v, d->partlabel, sizeof d->partlabel);
        else if (BLB_KEY ("ID_PART_ENTRY_UUID"))
            snprintf (d->partuuid, sizeof d->partuuid, "%s", v);
#undef BLB_KEY
    }
    fclose (f);
    return 1;
}

/* A stacked device's slaves identify its underlying devices.  The current
 * single-parent model chooses a stable first slave for tree presentation. */
static void
blb_resolve_slave (blb_dev *d)
{
    char path[BLB_PATH_MAX], first[BLB_NAME_MAX] = "";
    if (d->parent[0]) return;
    if (snprintf (path, sizeof path, "%s/%s/slaves", blb_sys_block_dir (), d->name) >= (int) sizeof path) return;
    DIR *dir = opendir (path);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir (dir))) {
        if (entry->d_name[0] == '.' || strlen (entry->d_name) >= sizeof first) continue;
        if (!first[0] || strcmp (entry->d_name, first) < 0) strcpy (first, entry->d_name);
    }
    closedir (dir);
    if (strcmp (first, d->name) != 0) strcpy (d->parent, first);
}

/* ---------- enumerate ---------- */

static int
blb_load_one (const char *name, blb_dev *d)
{
    memset (d, 0, sizeof *d);
    size_t nlen = strlen (name);
    if (nlen >= sizeof d->name) return -1;
    memcpy (d->name, name, nlen + 1);

    blb_resolve_parent (d->name, d->parent, sizeof d->parent);

    char base[BLB_PATH_MAX];
    snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), name);

    /* size: sectors × 512. Missing/unreadable -> 0. */
    long long sec = 0;
    if (blb_read_int (base, "size", &sec) == 0 && sec > 0) {
        d->size_bytes = (uint64_t) sec * 512ULL;
    }

    /* MAJ:MIN from /sys/class/block/<name>/dev. */
    if (blb_read_str (base, "dev", d->majmin, sizeof d->majmin) < 0) {
        strncpy (d->majmin, "?", sizeof d->majmin - 1);
    } else {
        char tail;
        if (sscanf (d->majmin, "%u:%u%c", &d->maj, &d->min, &tail) == 2)
            d->have_devno = 1;
    }

    /* A device-mapper device is shown by its mapping name (dm/name). */
    if (strncmp (d->name, "dm-", 3) == 0
        && (blb_read_str (base, "dm/name", d->dmname, sizeof d->dmname) < 0
            || strchr (d->dmname, '/')))
        d->dmname[0] = '\0';

    /* ro / removable / hidden — each optional. */
    long long v = 0;
    if (blb_read_int (base, "ro", &v) == 0) d->ro = (v != 0);
    if (blb_read_int (base, "removable", &v) == 0)
        d->removable = (v != 0);
    else if (d->parent[0]) {
        /* Partition sysfs directories normally omit removable; the property
         * belongs to the whole disk.  Retain an explicit partition value
         * when a synthetic tree supplies one. */
        char parent_base[BLB_PATH_MAX];
        if (blb_join2 (parent_base, sizeof parent_base, blb_sys_block_dir (),
                       d->parent) == 0
            && blb_read_int (parent_base, "removable", &v) == 0)
            d->removable = (v != 0);
    }
    if (blb_read_int (base, "hidden", &v) == 0) d->hidden = (v != 0);

    blb_classify (d);
    blb_resolve_slave (d);
    /* Without a udev database entry, fall back to reading the node. */
    if (!blb_load_udev (d)) {
        blb_probe_super (d->name, d);
        blb_probe_part_gpt (d);
    }
    blb_load_mountpoint (d);
    blb_load_fs_usage (d);
    return 0;
}

/* util-linux sorts by MAJ:MIN by default, comparing the dev_t numbers,
 * and keeps every child under its parent (also in list, raw and pairs
 * output); the tree walk below preserves this order among siblings. */
static int
blb_cmp_dev (const void *a, const void *b)
{
    const blb_dev *da = (const blb_dev *) a;
    const blb_dev *db = (const blb_dev *) b;
    if (da->have_devno != db->have_devno) return db->have_devno - da->have_devno;
    if (da->have_devno) {
        dev_t xa = makedev (da->maj, da->min), xb = makedev (db->maj, db->min);
        if (xa != xb) return xa < xb ? -1 : 1;
    }
    return strcmp (da->name, db->name);
}

static int
blb_load_all (blb_dev *devs, int max, int *out_n)
{
    const char *sys_block = blb_sys_block_dir ();
    DIR *d = opendir (sys_block);
    if (!d) {
        builtin_error ("opendir %s: %s", sys_block, strerror (errno));
        return -1;
    }
    int n = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] == '.') continue;
        if (n >= max) break;
        if (blb_load_one (de->d_name, &devs[n]) < 0) continue;
        if (devs[n].hidden) continue;     /* skip device-mapper hidden kobjects */
        n++;
    }
    closedir (d);
    qsort (devs, n, sizeof *devs, blb_cmp_dev);
    *out_n = n;
    return 0;
}
/* ---------- size formatter (util-linux size_to_human_string) ---------- */

/* One-letter 1024-based suffix and at most one decimal, rounded half up:
 * 512B, 1.5K, 1M, 11.9G; a trailing ".0" is dropped. */
static void
blb_format_size (uint64_t bytes, char *out, size_t outsz)
{
    static const char letters[] = "BKMGTPE";
    int exp = 60;
    for (int shift = 10; shift <= 60; shift += 10)
        if (bytes < (1ULL << shift)) {
            exp = shift - 10;
            break;
        }
    char c = letters[exp / 10];
    uint64_t dec = exp ? bytes >> exp : bytes;
    uint64_t frac = exp ? bytes & ((1ULL << exp) - 1) : 0;
    if (frac) {
        if (frac >= UINT64_MAX / 1000)
            frac = ((frac / 1024) * 1000) >> (exp - 10);
        else
            frac = (frac * 1000) >> exp;
        frac = ((frac + 50) / 100) * 10;
        if (frac == 100) {
            dec++;
            frac = 0;
        }
    }
    if (frac) {
        const struct lconv *l = localeconv ();
        const char *dp = l && l->decimal_point && *l->decimal_point ? l->decimal_point : ".";
        char num[48];
        int len = snprintf (num, sizeof num, "%llu%s%02llu",
                            (unsigned long long) dec, dp, (unsigned long long) frac);
        if (len > 0 && num[len - 1] == '0')
            num[len - 1] = '\0';
        snprintf (out, outsz, "%s%c", num, c);
    } else
        snprintf (out, outsz, "%llu%c", (unsigned long long) dec, c);
}

/* ---------- printing ---------- */

typedef struct {
    int list;        /* -l, -P, -r: no tree art */
    int nodeps;      /* -d */
    int fs;          /* -f */
    int all;         /* -a */
    int show_header; /* default 1 */
    int pairs;       /* -P */
    int raw;         /* -r */
    const char *outarg; /* last -o/--output */
    blb_col_id cols[BLB_COL_MAX];
    int ncols;
} blb_opts;

static const blb_col_def *
blb_col (blb_col_id id)
{
    for (int i = 0; blb_cols[i].name; i++)
        if (blb_cols[i].id == id)
            return &blb_cols[i];
    return &blb_cols[0];
}

static int
blb_col_lookup (const char *name, blb_col_id *out)
{
    for (int i = 0; blb_cols[i].name; i++) {
        if (strcmp (blb_cols[i].name, name) == 0) {
            *out = blb_cols[i].id;
            return 0;
        }
    }
    return -1;
}

static void
blb_supported_columns_stderr (void)
{
    fputs ("supported columns: ", stderr);
    for (int i = 0; blb_cols[i].name; i++) {
        if (i) fputc (',', stderr);
        fputs (blb_cols[i].name, stderr);
    }
    fputc ('\n', stderr);
}

static void
blb_add_col (blb_opts *opt, blb_col_id id)
{
    if (opt->ncols >= BLB_COL_MAX)
        return;
    opt->cols[opt->ncols++] = id;
}

/* util-linux: -f selects the filesystem column set, otherwise the default
 * set; -o LIST replaces the selection and -o +LIST appends to it. */
static void
blb_add_default_cols (blb_opts *opt)
{
    static const blb_col_id fs[] = {
        BLB_COL_NAME, BLB_COL_FSTYPE, BLB_COL_FSVER, BLB_COL_LABEL, BLB_COL_UUID,
        BLB_COL_FSAVAIL, BLB_COL_FSUSE_PCT, BLB_COL_MOUNTPOINTS
    };
    static const blb_col_id dflt[] = {
        BLB_COL_NAME, BLB_COL_MAJMIN, BLB_COL_RM, BLB_COL_SIZE, BLB_COL_RO,
        BLB_COL_TYPE, BLB_COL_MOUNTPOINTS
    };
    const blb_col_id *set = opt->fs ? fs : dflt;
    size_t n = opt->fs ? sizeof fs / sizeof fs[0] : sizeof dflt / sizeof dflt[0];
    for (size_t i = 0; i < n; i++)
        blb_add_col (opt, set[i]);
}

static int
blb_parse_cols (blb_opts *opt, const char *spec)
{
    if (!spec || !*spec) {
        builtin_error ("-o/--output requires a column list");
        return -1;
    }
    int append = (spec[0] == '+');
    if (append)
        spec++;
    else
        opt->ncols = 0;

    char tmp[512];
    if (strlen (spec) >= sizeof tmp) {
        builtin_error ("-o/--output column list too long");
        return -1;
    }
    strcpy (tmp, spec);
    for (char *p = tmp; *p; p++)
        *p = (char) toupper ((unsigned char) *p);

    char *save = NULL;
    for (char *tok = strtok_r (tmp, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen (tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
        if (!*tok) continue;
        blb_col_id id;
        if (blb_col_lookup (tok, &id) < 0) {
            builtin_error ("unknown column: %s", tok);
            blb_supported_columns_stderr ();
            return -1;
        }
        blb_add_col (opt, id);
    }
    if (opt->ncols == 0) {
        builtin_error ("-o/--output produced no columns");
        return -1;
    }
    return 0;
}

static void
blb_print_help (void)
{
    puts ("List block devices (lsblk).");
    puts ("");
    puts ("    bashlsblk [-a] [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]");
    puts ("    bashlsblk -h | --help");
    puts ("");
    puts ("Walks /sys/class/block. Default output is a tree in MAJ:MIN order,");
    puts ("each device followed by its partitions and holders, indented with");
    puts ("ASCII branch characters.");
    puts ("");
    puts ("    -a    --all; also list empty devices and RAM disks (major 1)");
    puts ("    -l    list form (flat)");
    puts ("    -d    --nodeps; print disks only, suppress partitions");
    puts ("    -f    --fs; NAME FSTYPE FSVER LABEL UUID FSAVAIL FSUSE% MOUNTPOINTS");
    puts ("    -n    --noheadings; suppress the column header row");
    puts ("    -P    --pairs; emit key=\"value\" rows");
    puts ("    -r    --raw; emit space-separated rows");
    puts ("    -o    --output LIST; select columns, or +COL to append to defaults");
    puts ("    DEV   restrict to named device(s): a block device node, or a");
    puts ("          basename or /sys path naming the kernel or dm name");
    puts ("");
    puts ("Default columns: NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS.");
    puts ("Columns: NAME MAJ:MIN RM SIZE RO TYPE FSTYPE FSVER LABEL UUID");
    puts ("         PARTLABEL PARTUUID MOUNTPOINT MOUNTPOINTS FSAVAIL FSUSE%.");
    puts ("Exit codes: 0 success, 1 sysfs error, 2 usage, 32 no DEV found,");
    puts ("            64 some DEV not found.");
}

/* `parsable` is raw or pairs output, where MAJ:MIN is not aligned. */
static const char *
blb_col_value (const blb_dev *d, const char *prefix, blb_col_id id, int parsable,
               char *buf, size_t bufsz)
{
    switch (id) {
    case BLB_COL_NAME:
        snprintf (buf, bufsz, "%s%s", prefix, d->dmname[0] ? d->dmname : d->name);
        return buf;
    case BLB_COL_MAJMIN:
        if (!d->have_devno)
            return d->majmin;
        snprintf (buf, bufsz, parsable ? "%u:%u" : "%3u:%-3u", d->maj, d->min);
        return buf;
    case BLB_COL_RM:
        snprintf (buf, bufsz, "%d", d->removable);
        return buf;
    case BLB_COL_SIZE:
        blb_format_size (d->size_bytes, buf, bufsz);
        return buf;
    case BLB_COL_RO:
        snprintf (buf, bufsz, "%d", d->ro);
        return buf;
    case BLB_COL_TYPE:
        return d->type;
    case BLB_COL_FSTYPE:
        return d->fstype;
    case BLB_COL_FSVER:
        return d->fsver;
    case BLB_COL_LABEL:
        return d->label;
    case BLB_COL_UUID:
        return d->uuid;
    case BLB_COL_PARTLABEL:
        return d->partlabel;
    case BLB_COL_PARTUUID:
        return d->partuuid;
    case BLB_COL_MOUNTPOINT:
        return d->mountpoint;
    case BLB_COL_MOUNTPOINTS:
        return d->mountpoints;
    case BLB_COL_FSAVAIL:
        if (!d->have_vfs) return "";
        blb_format_size (d->fsavail, buf, bufsz);
        return buf;
    case BLB_COL_FSUSE_PCT:
        if (!d->have_vfs || d->fsblocks == 0) return "";
        snprintf (buf, bufsz, "%.0f%%",
                  (double) (d->fsblocks - d->fsbfree) / (double) d->fsblocks * 100.0);
        return buf;
    }
    return "";
}

/* Raw output (util-linux fputs_nonblank): blanks, backslashes and
 * non-printable bytes as \xHH. */
static void
blb_print_raw_value (const char *value)
{
    for (const unsigned char *p = (const unsigned char *) value; *p; p++) {
        if (isblank (*p) || *p == '\\' || !isprint (*p) || iscntrl (*p))
            printf ("\\x%02x", *p);
        else
            putchar (*p);
    }
}

/* Pairs output (util-linux fputs_quoted): quotes, backslashes, backquotes,
 * dollars and non-printable bytes as \xHH; spaces stay. */
static void
blb_print_pair_value (const char *value)
{
    putchar ('"');
    for (const unsigned char *p = (const unsigned char *) value; *p; p++) {
        if (*p == '"' || *p == '\\' || *p == '`' || *p == '$'
            || !isprint (*p) || iscntrl (*p))
            printf ("\\x%02x", *p);
        else
            putchar (*p);
    }
    putchar ('"');
}

/* Display width of the first n bytes of an encoded (printable) string. */
static size_t
blb_str_width (const char *s, size_t n)
{
    size_t width = 0;
    mbstate_t st;
    memset (&st, 0, sizeof st);
    while (n > 0 && *s) {
        wchar_t wc;
        size_t k = mbrtowc (&wc, s, n, &st);
        if (k == 0 || k == (size_t) -1 || k == (size_t) -2) {
            width++; s++; n--;
            memset (&st, 0, sizeof st);
            continue;
        }
        int w = wcwidth (wc);
        width += w > 0 ? (size_t) w : 0;
        s += k; n -= k;
    }
    return width;
}

/* Table output (libsmartcols mbs_safe_encode): control characters,
 * undecodable bytes and a backslash before 'x' become \xHH, except a
 * newline in a wrapping column (MOUNTPOINTS), which starts a new line of
 * the cell.  Returns the display width of the widest line. */
static size_t
blb_safe_encode (const char *s, char *out, size_t outsz, int keep_nl)
{
    size_t oi = 0, width = 0, maxw = 0;
    mbstate_t st;
    memset (&st, 0, sizeof st);
    if (outsz == 0) return 0;
    for (const char *p = s; *p && oi + 5 < outsz; ) {
        unsigned char c = (unsigned char) *p;
        if (c == '\n' && keep_nl) {
            out[oi++] = '\n';
            if (width > maxw) maxw = width;
            width = 0;
            p++;
            continue;
        }
        if ((c == '\\' && p[1] == 'x') || iscntrl (c)) {
            oi += (size_t) snprintf (out + oi, outsz - oi, "\\x%02x", c);
            width += 4;
            p++;
            continue;
        }
        wchar_t wc;
        size_t n = mbrtowc (&wc, p, MB_CUR_MAX, &st);
        if (n == 0)
            break;
        if (n == (size_t) -1 || n == (size_t) -2 || !iswprint ((wint_t) wc)) {
            size_t k = (n == (size_t) -1 || n == (size_t) -2) ? 1 : n;
            for (size_t j = 0; j < k && p[j] && oi + 5 < outsz; j++) {
                oi += (size_t) snprintf (out + oi, outsz - oi, "\\x%02x", (unsigned char) p[j]);
                width += 4;
            }
            p += k;
            memset (&st, 0, sizeof st);
            continue;
        }
        if (oi + n >= outsz)
            break;
        memcpy (out + oi, p, n);
        oi += n;
        int w = wcwidth (wc);
        width += w > 0 ? (size_t) w : 0;
        p += n;
    }
    out[oi] = '\0';
    return width > maxw ? width : maxw;
}

typedef struct {
    int idx;
    char prefix[160];
} blb_row;

/* Depth-first walk: each device is followed by its children (partitions,
 * and holders through their slaves), siblings in the sorted order. */
static void
blb_walk (const blb_dev *devs, int n, const blb_opts *opt, int idx,
          const char *prefix, int depth, unsigned char *active,
          blb_row *rows, int *nrows)
{
    if (depth >= BLB_MAX_DEVS || active[idx] || *nrows >= BLB_MAX_DEVS) return;
    active[idx] = 1;
    rows[*nrows].idx = idx;
    snprintf (rows[*nrows].prefix, sizeof rows[*nrows].prefix, "%s", opt->list ? "" : prefix);
    (*nrows)++;
    if (!opt->nodeps) {
        int last = -1;
        for (int j = 0; j < n; j++)
            if (!active[j] && strcmp (devs[j].parent, devs[idx].name) == 0) last = j;
        for (int j = 0; j < n; j++) {
            char next[160];
            if (active[j] || strcmp (devs[j].parent, devs[idx].name) != 0) continue;
            if (depth == 0) snprintf (next, sizeof next, "%s", j == last ? "`-" : "|-");
            else {
                size_t len = strlen (prefix);
                if (len + 3 >= sizeof next) continue;
                memcpy (next, prefix, len + 1);
                if (len >= 2) { next[len-2] = prefix[len-2] == '`' ? ' ' : '|'; next[len-1] = ' '; }
                strcat (next, j == last ? "`-" : "|-");
            }
            blb_walk (devs, n, opt, j, next, depth + 1, active, rows, nrows);
        }
    }
    active[idx] = 0;
}

#define BLB_CELL_MAX (BLB_MOUNT_MAX * 4 + 256)

static int
blb_emit (const blb_dev *devs, int n, const blb_opts *opt)
{
    static blb_row rows[BLB_MAX_DEVS];
    unsigned char active[BLB_MAX_DEVS] = { 0 };
    int nrows = 0;
    for (int i = 0; i < n; i++) {
        int parent_found = 0;
        for (int j = 0; j < n; j++)
            if (strcmp (devs[i].parent, devs[j].name) == 0) parent_found = 1;
        if (!parent_found) blb_walk (devs, n, opt, i, "", 0, active, rows, &nrows);
    }
    if (nrows == 0)
        return 0;   /* an empty table prints nothing, not even headings */

    int parsable = opt->pairs || opt->raw;
    char buf[BLB_CELL_MAX];
    if (parsable) {
        /* Raw output keeps its heading line (unless -n); pairs have none. */
        if (opt->raw && opt->show_header) {
            for (int c = 0; c < opt->ncols; c++) {
                blb_print_raw_value (blb_col (opt->cols[c])->name);
                if (c + 1 < opt->ncols) putchar (' ');
            }
            putchar ('\n');
        }
        for (int r = 0; r < nrows; r++) {
            for (int c = 0; c < opt->ncols; c++) {
                const char *v = blb_col_value (&devs[rows[r].idx], "", opt->cols[c], 1, buf, sizeof buf);
                if (opt->pairs) {
                    printf ("%s=", blb_col (opt->cols[c])->name);
                    blb_print_pair_value (v);
                } else
                    blb_print_raw_value (v);
                if (c + 1 < opt->ncols) putchar (' ');
            }
            putchar ('\n');
        }
        return 0;
    }

    /* libsmartcols layout: a column is as wide as its widest cell, its
     * heading (when shown) and an absolute width hint; cells are padded
     * to it, right-aligned columns on the left; a left-aligned last column
     * is not padded; one space separates columns. */
    char **cells = calloc ((size_t) nrows * (size_t) opt->ncols, sizeof *cells);
    size_t *widths = calloc ((size_t) nrows * (size_t) opt->ncols, sizeof *widths);
    if (!cells || !widths) {
        free (cells); free (widths);
        builtin_error ("out of memory");
        return -1;
    }
    size_t colw[BLB_COL_MAX];
    for (int c = 0; c < opt->ncols; c++) {
        const blb_col_def *def = blb_col (opt->cols[c]);
        size_t wmin = opt->show_header ? strlen (def->name) : 0, w = 0, wmax = 0;
        int no_header = !opt->show_header;
        if (!wmin) wmin = 1;
        for (int r = 0; r < nrows; r++) {
            const char *v = blb_col_value (&devs[rows[r].idx], rows[r].prefix,
                                           opt->cols[c], 0, buf, sizeof buf);
            char enc[BLB_CELL_MAX];
            size_t len = blb_safe_encode (v, enc, sizeof enc,
                                          opt->cols[c] == BLB_COL_MOUNTPOINTS);
            cells[r * opt->ncols + c] = strdup (enc);
            widths[r * opt->ncols + c] = len;
            if (len > wmax) wmax = len;
            if (len > w) w = len;
        }
        if (w < wmin)
            w = wmin;
        else if (def->whint >= 1 && w < (size_t) def->whint && wmin < (size_t) def->whint)
            w = (size_t) def->whint;
        if (wmax == 0 && no_header && wmin == 1 && w <= 1)
            w = 0;
        colw[c] = w;
    }
    /* A multi-line cell continues on following lines, the other columns
     * there blank (the tree column keeps its vertical lines). */
    for (int r = opt->show_header ? -1 : 0; r < nrows; r++) {
        const char *rest[BLB_COL_MAX];
        int more = 1;
        for (int c = 0; c < opt->ncols; c++)
            rest[c] = r < 0 ? blb_col (opt->cols[c])->name : cells[r * opt->ncols + c];
        for (int line = 0; more; line++) {
            more = 0;
            for (int c = 0; c < opt->ncols; c++) {
                const blb_col_def *def = blb_col (opt->cols[c]);
                const char *v = rest[c] ? rest[c] : "";
                char art[160];
                size_t vlen;
                if (line > 0 && opt->cols[c] == BLB_COL_NAME && r >= 0 && !opt->list) {
                    /* continuation tree art: own branch becomes a vertical line */
                    const blb_row *row = &rows[r];
                    snprintf (art, sizeof art, "%s", row->prefix);
                    size_t al = strlen (art);
                    if (al >= 2) { art[al-2] = art[al-2] == '`' ? ' ' : '|'; art[al-1] = ' '; }
                    int kids = 0;
                    for (int k = r + 1; k < nrows && !opt->nodeps; k++)
                        if (strcmp (devs[rows[k].idx].parent, devs[row->idx].name) == 0) kids = 1;
                    if (kids && al + 2 < sizeof art) strcat (art, "| ");
                    v = art;
                    vlen = strlen (art);
                    rest[c] = NULL;
                } else {
                    const char *nl = strchr (v, '\n');
                    vlen = nl ? (size_t) (nl - v) : strlen (v);
                    rest[c] = nl ? nl + 1 : NULL;
                    if (nl) more = 1;
                    if (line > 0 && opt->cols[c] == BLB_COL_NAME) vlen = 0;
                }
                size_t len = blb_str_width (v, vlen), w = colw[c];
                int last = c + 1 == opt->ncols;
                /* The last column is not filled: an empty cell prints
                   nothing, a left-aligned one no trailing padding. */
                if (last && (vlen == 0 || (len < w && !def->right)))
                    w = len;
                if (def->right)
                    for (size_t i = len; i < w; i++) putchar (' ');
                fwrite (v, 1, vlen, stdout);
                if (!def->right)
                    for (size_t i = len; i < w; i++) putchar (' ');
                if (!last) putchar (' ');
            }
            putchar ('\n');
        }
    }
    for (int i = 0; i < nrows * opt->ncols; i++) free (cells[i]);
    free (cells);
    free (widths);
    return 0;
}

/* ---------- filter: restrict to named devices ---------- */

/* An operand that is a block device node selects the device with its
 * MAJ:MIN; any other operand is matched by its last path component against
 * the kernel name or the device-mapper name. */
static int
blb_operand_index (const blb_dev *devs, int n, const char *w)
{
    struct stat st;
    if (stat (w, &st) == 0 && S_ISBLK (st.st_mode)) {
        for (int i = 0; i < n; i++)
            if (devs[i].have_devno && devs[i].maj == major (st.st_rdev)
                && devs[i].min == minor (st.st_rdev))
                return i;
        return -1;
    }
    const char *base = strrchr (w, '/');
    base = base ? base + 1 : w;
    for (int i = 0; i < n; i++)
        if (strcmp (base, devs[i].name) == 0
            || (devs[i].dmname[0] && strcmp (base, devs[i].dmname) == 0))
            return i;
    return -1;
}

/* Keep the named devices and all their descendants, in sorted order.
 * Reports each unmatched operand like util-linux; *failed counts them. */
static int
blb_filter (blb_dev *devs, int n, char **wants, int nwants, int *failed)
{
    unsigned char keep[BLB_MAX_DEVS] = { 0 };
    *failed = 0;
    for (int k = 0; k < nwants; k++) {
        int i = blb_operand_index (devs, n, wants[k]);
        if (i < 0) {
            fprintf (stderr, "lsblk: %s: not a block device\n", wants[k]);
            (*failed)++;
        } else
            keep[i] = 1;
    }
    int changed;
    do {
        changed = 0;
        for (int i = 0; i < n; i++) {
            if (keep[i] || !devs[i].parent[0]) continue;
            for (int j = 0; j < n; j++)
                if (keep[j] && strcmp (devs[i].parent, devs[j].name) == 0) {
                    keep[i] = 1;
                    changed = 1;
                    break;
                }
        }
    } while (changed);
    int total = 0;
    for (int i = 0; i < n; i++)
        if (keep[i]) {
            if (total != i) devs[total] = devs[i];
            total++;
        }
    return total;
}

/* Without operands or -a, util-linux skips empty devices (unbound loops)
 * and RAM disks (major 1). */
static int
blb_drop_empty (blb_dev *devs, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (devs[i].size_bytes == 0 || (devs[i].have_devno && devs[i].maj == 1))
            continue;
        if (total != i) devs[total] = devs[i];
        total++;
    }
    return total;
}

/* ---------- builtin ---------- */

int
lsblk_builtin (WORD_LIST *list)
{
    blb_opts opt;
    memset (&opt, 0, sizeof opt);
    opt.show_header = 1;
    char *wants[BLB_MAX_DEVS];
    int nwants = 0;
    int n_pos_max = (int) (sizeof wants / sizeof wants[0]);

    /* Argument parse: flags, -o LIST, --, then positionals. */
    while (list) {
        const char *w = list->word->word;
        if (strcmp (w, "--") == 0) {
            for (list = list->next; list; list = list->next) {
                if (nwants < n_pos_max) wants[nwants++] = list->word->word;
            }
            break;
        }
        if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0) {
            blb_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "-a") == 0 || strcmp (w, "--all") == 0) {
            opt.all = 1;
        } else if (strcmp (w, "-l") == 0 || strcmp (w, "--list") == 0) {
            opt.list = 1;
        } else if (strcmp (w, "-d") == 0 || strcmp (w, "--nodeps") == 0) {
            opt.nodeps = 1;
        } else if (strcmp (w, "-f") == 0 || strcmp (w, "--fs") == 0) {
            opt.fs = 1;
        } else if (strcmp (w, "-n") == 0 || strcmp (w, "--noheadings") == 0) {
            opt.show_header = 0;
        } else if (strcmp (w, "-P") == 0 || strcmp (w, "--pairs") == 0) {
            opt.pairs = 1;
            opt.raw = 0;
            opt.list = 1;
        } else if (strcmp (w, "-r") == 0 || strcmp (w, "--raw") == 0) {
            opt.raw = 1;
            opt.pairs = 0;
            opt.list = 1;
        } else if (strcmp (w, "-o") == 0 || strcmp (w, "--output") == 0) {
            if (!list->next) {
                builtin_error ("%s requires a column list", w);
                blb_supported_columns_stderr ();
                return EX_USAGE;
            }
            list = list->next;
            opt.outarg = list->word->word;
        } else if (strncmp (w, "--output=", 9) == 0) {
            opt.outarg = w + 9;
        } else if (strncmp (w, "-o", 2) == 0 && w[2] != '\0') {
            opt.outarg = w + 2;
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        } else {
            if (nwants < n_pos_max) wants[nwants++] = (char *) w;
        }
        list = list->next;
    }
    blb_add_default_cols (&opt);
    if (opt.outarg && blb_parse_cols (&opt, opt.outarg) < 0)
        return EX_USAGE;

    static blb_dev devs[BLB_MAX_DEVS];
    int n = 0, failed = 0;
    if (blb_load_all (devs, BLB_MAX_DEVS, &n) < 0) {
        return EXECUTION_FAILURE;
    }

    if (nwants > 0) {
        n = blb_filter (devs, n, wants, nwants, &failed);
        /* lsblk(8): 32 when no operand was found, 64 when only some were. */
        if (failed == nwants)
            return 32;
    } else if (!opt.all)
        n = blb_drop_empty (devs, n);

    if (blb_emit (devs, n, &opt) < 0)
        return EXECUTION_FAILURE;
    if (fflush (stdout) != 0 || ferror (stdout))
        return EXECUTION_FAILURE;
    return failed ? 64 : EXECUTION_SUCCESS;
}

char *lsblk_doc[] = {
    "List block devices (lsblk).",
    "",
    "    bashlsblk [-a] [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]",
    "    bashlsblk -h | --help",
    "",
    "Walks /sys/class/block. Default output is a tree in MAJ:MIN order, each",
    "device followed by its partitions and holders, indented with ASCII",
    "branch characters.",
    "",
    "    -a    --all; also list empty devices and RAM disks (major 1)",
    "    -l    list form (flat)",
    "    -d    --nodeps; print disks only, suppress partitions",
    "    -f    --fs; the NAME FSTYPE FSVER LABEL UUID FSAVAIL FSUSE%",
    "          MOUNTPOINTS columns, from the udev database or, without an",
    "          entry there, from the matching /dev node",
    "    -n    --noheadings; suppress the column header row",
    "    -P    --pairs; emit key=\"value\" rows",
    "    -r    --raw; emit space-separated rows",
    "    -o    --output LIST; select supported columns; +COL appends",
    "    DEV   restrict to named device(s). A block device node selects",
    "          the device with its MAJ:MIN; otherwise DEV may be a",
    "          basename (`vda`) or a /sys path, whose trailing component",
    "          matches the kernel or device-mapper name. Partitions and",
    "          holders of a matched device are also shown.",
    "",
    "Default columns: NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS.",
    "Columns: NAME MAJ:MIN RM SIZE RO TYPE FSTYPE FSVER LABEL UUID",
    "PARTLABEL PARTUUID MOUNTPOINT/MOUNTPOINTS FSAVAIL FSUSE%. Sizes are",
    "human-readable powers-of-1024.",
    "",
    "Exit codes:",
    "    0    success",
    "    1    operational error (sysfs unavailable)",
    "    2    usage error",
    "    32   no DEV operand found",
    "    64   some DEV operands not found",
    (char *)NULL
};

struct builtin bashlsblk_struct = {
    "bashlsblk",
    lsblk_builtin,
    BUILTIN_ENABLED,
    lsblk_doc,
    "bashlsblk [-a] [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]",
    0
};
