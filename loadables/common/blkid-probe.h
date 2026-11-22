/* SPDX-License-Identifier: MIT
 * Low-level blkid operations. The caller owns all descriptors and option
 * storage. libblkid reads the nominated device directly and checks collisions. */
#ifndef BASHOS_BLKID_PROBE_H
#define BASHOS_BLKID_PROBE_H

#include <blkid/blkid.h>
#include <sys/sysmacros.h>
#include "util-size.h"

typedef struct {
    int probe, topology, raw, no_details;
    blkid_loff_t offset, size;
    const char *types, *usages, *hint;
} bblk_low_opts;

static void
bblk_low_escaped(const char *text, const char *special, int raw)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        unsigned c = *p;
        if (!raw) {
            if (c >= 128) { fputs("M-", stdout); c -= 128; }
            if (c < 32 || c == 127) { putchar('^'); c ^= 64; }
            else if (strchr(special, c)) putchar('\\');
        }
        putchar(c);
    }
}

static void
bblk_json_string(const char *text, int lower)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        switch (*p) {
        case '"': case '\\': putchar('\\'); putchar(*p); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 32) printf("\\u%04x", *p);
            else putchar(lower && *p < 128 ? tolower(*p) : *p);
        }
    }
    putchar('"');
}

static int
bblk_low_udev(const char *key, const char *value)
{
    size_t len = 4 * strlen(value) + 1;
    char *encoded = calloc(len, 1);
    if (!encoded) return -1;
    blkid_encode_string(value, encoded, len);
    if (!strncmp(key, "LABEL", 5) || !strcmp(key, "UUID") || !strcmp(key, "UUID_SUB")) {
        char *safe = calloc(len, 1);
        if (!safe) { free(encoded); return -1; }
        blkid_safe_string(value, safe, len);
        printf("ID_FS_%s=%s\nID_FS_%s_ENC=%s\n", key, safe, key, encoded);
        free(safe);
    } else if (!strcmp(key, "PTUUID") || !strcmp(key, "PTTYPE")) {
        printf("ID_PART_TABLE_%s=%s\n", key + 2, value);
    } else if (!strncmp(key, "PART_ENTRY_", 11)) {
        int encode = !strcmp(key, "PART_ENTRY_NAME") || !strcmp(key, "PART_ENTRY_TYPE");
        printf("ID_%s=%s\n", key, encode ? encoded : value);
    } else if (strstr(key, "_SECTOR_SIZE") || strstr(key, "_IO_SIZE") ||
               !strcmp(key, "ALIGNMENT_OFFSET")) {
        printf("ID_IOLIMIT_%s=%s\n", key, value);
    } else {
        int encode = !strcmp(key, "TYPE") || !strcmp(key, "VERSION") ||
                     (strlen(key) > 3 && !strcmp(key + strlen(key) - 3, "_ID"));
        printf("ID_FS_%s=%s\n", key, encode ? encoded : value);
    }
    free(encoded);
    return 0;
}

static int
bblk_low_output(blkid_probe pr, int count, const char *path, const bblk_opts *opt,
                int raw, int first)
{
    const char *fmt = opt->fmt;
    int emitted = 0;
    if (!strcmp(fmt, "json")) fputs("{\n", stdout);
    if (count && !first && (!strcmp(fmt, "udev") || !strcmp(fmt, "export"))) putchar('\n');
    if (count && !strcmp(fmt, "device")) { puts(path); return 0; }
    for (int i = 0; i < count; i++) {
        const char *key, *value;
        if (blkid_probe_get_value(pr, i, &key, &value, NULL) != 0 ||
            !bblk_wanted(opt->tags, key)) continue;
        if (!strcmp(fmt, "value")) puts(value);
        else if (!strcmp(fmt, "udev")) {
            if (bblk_low_udev(key, value) < 0) return 4;
        } else if (!strcmp(fmt, "export")) {
            if (!emitted) printf("DEVNAME=%s\n", path);
            printf("%s=", key);
            bblk_low_escaped(value, " \\\"'$" "\x60" "<>", raw);
            putchar('\n');
        } else if (!strcmp(fmt, "json")) {
            fputs(emitted ? ",\n   " : "   ", stdout);
            bblk_json_string(key, 1);
            fputs(": ", stdout);
            if (*value) bblk_json_string(value, 0);
            else fputs("null", stdout);
        } else {
            if (!emitted) printf("%s:", path);
            printf(" %s=\"", key);
            bblk_low_escaped(value, "\"\\", raw);
            putchar('"');
        }
        emitted++;
    }
    if (!strcmp(fmt, "json")) fputs("\n}\n", stdout);
    else if (count && !strcmp(fmt, "default")) putchar('\n');
    return count ? 0 : 2;
}

static int
bblk_low_filters(blkid_probe pr, const bblk_low_opts *low)
{
    const char *list = low->types ? low->types : low->usages;
    if (!list) return 0;
    if (low->types && low->usages) {
        fputs("blkid: mutually exclusive arguments: --match-types --usages\n", stderr);
        return -1;
    }
    int how = BLKID_FLTR_ONLYIN;
    if (!strncmp(list, "no", 2)) { how = BLKID_FLTR_NOTIN; list += 2; }
    if (!*list) { fputs("blkid: empty probe filter\n", stderr); return -1; }
    size_t count = 1;
    for (const char *p = list; *p; p++) if (*p == ',') count++;
    char *copy = strdup(list);
    char **types = calloc(count + 1, sizeof(*types));
    int rc = -1, mask = 0;
    if (!copy || !types) goto done;
    char *next = copy;
    for (size_t i = 0; i < count; i++) {
        types[i] = strsep(&next, ",");
        if (low->types) continue;
        if (!strcmp(types[i], "filesystem")) mask |= BLKID_USAGE_FILESYSTEM;
        else if (!strcmp(types[i], "raid")) mask |= BLKID_USAGE_RAID;
        else if (!strcmp(types[i], "crypto")) mask |= BLKID_USAGE_CRYPTO;
        else if (!strcmp(types[i], "other")) mask |= BLKID_USAGE_OTHER;
        else { fprintf(stderr, "blkid: unknown keyword in -u <list> argument: '%s'\n", types[i]); goto done; }
    }
    rc = low->types ? blkid_probe_filter_superblocks_type(pr, how, types)
                    : blkid_probe_filter_superblocks_usage(pr, how, mask);
done:
    free(types);
    free(copy);
    return rc;
}

static void
bblk_ambiguous(blkid_probe pr, const char *path, const char *fmt)
{
    if (strcmp(fmt, "udev")) {
        fprintf(stderr, "blkid: %s: ambivalent result (probably more filesystems on the device, use wipefs(8) to see more details)\n", path);
        return;
    }
    int count = 0;
    while (blkid_do_probe(pr) == 0) {
        const char *usage, *type, *version = NULL;
        if (blkid_probe_lookup_value(pr, "USAGE", &usage, NULL) ||
            blkid_probe_lookup_value(pr, "TYPE", &type, NULL)) continue;
        blkid_probe_lookup_value(pr, "VERSION", &version, NULL);
        printf("%s%s:%s", count++ ? " " : "ID_FS_AMBIVALENT=", usage, type);
        if (version) {
            char encoded[1024] = "";
            blkid_encode_string(version, encoded, sizeof(encoded));
            printf(":%s", encoded);
        }
    }
    if (count) putchar('\n');
}

static int
bblk_low_scan(blkid_probe pr, const bblk_low_opts *low, mode_t mode)
{
    if (low->topology) {
        blkid_probe_enable_superblocks(pr, 0);
        blkid_probe_enable_partitions(pr, 0);
        blkid_probe_enable_topology(pr, 1);
        int rc = blkid_do_fullprobe(pr);
        if (rc < 0 || !low->probe) return rc;
    }
    blkid_probe_enable_partitions(pr, 1);
    if (!S_ISCHR(mode) && blkid_probe_get_size(pr) <= 1440 * 1024 &&
        blkid_probe_is_wholedisk(pr)) {
        blkid_probe_enable_superblocks(pr, 0);
        int rc = blkid_do_fullprobe(pr);
        if (rc < 0) return rc;
        if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0) return 0;
    }
    blkid_probe_set_partitions_flags(pr, low->no_details ? 0 : BLKID_PARTS_ENTRY_DETAILS);
    blkid_probe_enable_superblocks(pr, 1);
    return blkid_do_safeprobe(pr);
}

static int
bblk_probe_path(blkid_probe pr, const char *path, const bblk_low_opts *low,
                const bblk_opts *opt, int first, mode_t mode)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { fprintf(stderr, "blkid: error: %s: %s\n", path, strerror(errno)); return 2; }
    int rc = 2;
    errno = 0;
    if (blkid_probe_set_device(pr, fd, low->offset, low->size)) {
        if (errno) fprintf(stderr, "blkid: error: %s: %s\n", path, strerror(errno));
    } else {
        int result = bblk_low_scan(pr, low, mode);
        if (result == -2) { bblk_ambiguous(pr, path, opt->fmt); rc = 8; }
        else if (result >= 0)
            rc = bblk_low_output(pr, result == 0 ? blkid_probe_numof_values(pr) : 0,
                                 path, opt, low->raw, first);
    }
    close(fd);
    return rc;
}

static int
bblk_low_command(const bblk_low_opts *low, const bblk_opts *opt, size_t n, const char **paths)
{
    if (!n) { fputs("blkid: The low-level probing mode requires a device\n", stderr); return 4; }
    blkid_probe pr = blkid_new_probe();
    if (!pr) return 4;
    int rc = 4, seen = 0;
    if (low->hint && blkid_probe_set_hint(pr, low->hint, 0) != 0) {
        fprintf(stderr, "blkid: Failed to use probing hint: %s\n", low->hint);
        goto done;
    }
    blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_DEFAULT | BLKID_SUBLKS_USAGE |
                                      BLKID_SUBLKS_VERSION | BLKID_SUBLKS_FSINFO);
    if (bblk_low_filters(pr, low) != 0) goto done;
    rc = 2;
    for (size_t i = 0; i < n; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0) continue;
        if (!S_ISBLK(st.st_mode) && !S_ISREG(st.st_mode)) {
            if (!S_ISCHR(st.st_mode)) continue;
            char node[128];
            snprintf(node, sizeof(node), "/sys/dev/char/%u:%u/subsystem",
                     major(st.st_rdev), minor(st.st_rdev));
            char *subsystem = realpath(node, NULL);
            int ubi = subsystem && !strcmp(strrchr(subsystem, '/'), "/ubi");
            free(subsystem);
            if (!ubi) continue;
        }
        rc = bblk_probe_path(pr, paths[i], low, opt, !seen++, st.st_mode);
        if (rc) break;
    }
done:
    blkid_free_probe(pr);
    return rc;
}
#endif
