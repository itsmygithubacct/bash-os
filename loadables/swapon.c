/* SPDX-License-Identifier: MIT */
/* swapon.c — enable a swap area (and list active ones), as a bash builtin.
 *
 *   swapon [--show[=COLS]] [--raw] [--noheadings] [--bytes]
 *                                # table of active swap areas (util-linux --show)
 *   swapon -s | --summary        # /proc/swaps-style summary (util-linux -s)
 *   swapon [-p PRIO] [-d] device # enable a swap area (needs root)
 *
 *   -p PRIO   signed 16-bit priority; 0..32767 sets SWAP_FLAG_PREFER
 *   -d        discard freed pages where supported
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/swap.h>

#include "loadables.h"

#ifndef SWAP_FLAG_PREFER
#  define SWAP_FLAG_PREFER     0x8000
#endif
#ifndef SWAP_FLAG_PRIO_SHIFT
#  define SWAP_FLAG_PRIO_SHIFT 0
#endif
#ifndef SWAP_FLAG_DISCARD
#  define SWAP_FLAG_DISCARD    0x10000
#endif

/* ---- listing: util-linux swapon --show / --summary over /proc/swaps ---- */

typedef struct
{
    char *path, *type;
    unsigned long long size, used;    /* KiB */
    int prio;
} sw_entry;

/* libmount unmangle: "\ooo" octal escapes, as the kernel writes them. */
static void
sw_unmangle (char *s)
{
    char *d = s;
    while (*s) {
        if (s[0] == '\\' && s[1] >= '0' && s[1] <= '7' && s[2] >= '0' && s[2] <= '7'
            && s[3] >= '0' && s[3] <= '7') {
            *d++ = (char) (64 * (s[1] & 7) + 8 * (s[2] & 7) + (s[3] & 7));
            s += 4;
        } else
            *d++ = *s++;
    }
    *d = '\0';
}

/* Parse /proc/swaps as libmount does: skip blank, '#' and "Filename\t"
   header lines; report unparsable lines and go on. NULL when unreadable. */
static sw_entry *
sw_read (size_t *count)
{
    FILE *fp = fopen ("/proc/swaps", "re");
    char *line = NULL;
    size_t cap = 0, n = 0, lineno = 0, alloc = 0;
    sw_entry *v = NULL;

    *count = 0;
    if (!fp)
        return NULL;
    while (getline (&line, &cap, fp) >= 0) {
        char *s = line, *nl = strchr (line, '\n');
        lineno++;
        if (nl)
            *nl = '\0';
        size_t l = strlen (line);
        if (l && line[l - 1] == '\r')
            line[l - 1] = '\0';
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s || *s == '#' || !strncmp (s, "Filename\t", 9))
            continue;
        char *src = NULL, *type = NULL;
        unsigned long long size, used;
        int prio;
        if (sscanf (s, "%ms %ms %llu %llu %d", &src, &type, &size, &used, &prio) != 5) {
            free (src);
            free (type);
            builtin_error ("%s: parse error at line %zu -- ignored", "/proc/swaps", lineno);
            continue;
        }
        sw_unmangle (src);
        size_t sl = strlen (src);
        if (sl > 10 && !strcmp (src + sl - 10, " (deleted)"))
            src[sl - 10] = '\0';
        if (n == alloc) {
            alloc = alloc ? alloc * 2 : 8;
            v = xrealloc (v, alloc * sizeof *v);
        }
        v[n].path = src;
        v[n].type = type;
        v[n].size = size;
        v[n].used = used;
        v[n].prio = prio;
        n++;
    }
    free (line);
    fclose (fp);
    *count = n;
    return v ? v : xmalloc (sizeof *v);
}

static void
sw_free (sw_entry *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free (v[i].path);
        free (v[i].type);
    }
    free (v);
}

/* util-linux size_to_human_string (SIZE_SUFFIX_1LETTER) */
static void
sw_human (unsigned long long bytes, char *buf, size_t sz)
{
    static const char letters[] = "BKMGTPE";
    int exp, shft;
    unsigned long long dec, frac;

    for (shft = 10; shft <= 60; shft += 10)
        if (bytes < (1ULL << shft))
            break;
    exp = shft - 10;
    char c = letters[exp ? exp / 10 : 0];
    dec = exp ? bytes / (1ULL << exp) : bytes;
    frac = exp ? bytes % (1ULL << exp) : 0;
    if (frac) {
        if (frac >= ULLONG_MAX / 1000)
            frac = ((frac / 1024) * 1000) / (1ULL << (exp - 10));
        else
            frac = (frac * 1000) / (1ULL << exp);
        frac = ((frac + 50) / 100) * 10;
        if (frac == 100) {
            dec++;
            frac = 0;
        }
    }
    if (frac) {
        int len = snprintf (buf, sz, "%llu.%02llu", dec, frac);
        if (len > 0 && (size_t) len < sz && buf[len - 1] == '0')
            buf[--len] = '\0';
        if (len > 0 && (size_t) len < sz)
            snprintf (buf + len, sz - len, "%c", c);
    } else
        snprintf (buf, sz, "%llu%c", dec, c);
}

/* swap-area UUID / LABEL from a v1 header, as blkid reports them. */
static void
sw_probe (const char *path, char *uuid, size_t usz, char *label, size_t lsz)
{
    static const unsigned pages[] = { 4096, 8192, 16384, 32768, 65536 };
    unsigned char *buf;
    *uuid = *label = '\0';
    if (access (path, R_OK) != 0)
        return;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    buf = xmalloc (65536);
    ssize_t got = read (fd, buf, 65536);
    close (fd);
    for (size_t i = 0; got > 0 && i < sizeof pages / sizeof pages[0]; i++) {
        if ((size_t) got < pages[i] || memcmp (buf + pages[i] - 10, "SWAPSPACE2", 10))
            continue;
        const unsigned char *u = buf + 1024 + 12, *lab = buf + 1024 + 28;
        int zero = 1;
        for (int k = 0; k < 16; k++)
            zero &= !u[k];
        if (!zero)
            snprintf (uuid, usz, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
                      u[10], u[11], u[12], u[13], u[14], u[15]);
        if (lab[0]) {
            size_t len = strnlen ((const char *) lab, 16);
            while (len && (lab[len - 1] == ' ' || lab[len - 1] == '\t' || lab[len - 1] == '\n'))
                len--;
            if (len >= lsz)
                len = lsz - 1;
            memcpy (label, lab, len);
            label[len] = '\0';
        }
        break;
    }
    free (buf);
}

static int
sw_summary (void)
{
    size_t n;
    sw_entry *v = sw_read (&n);
    if (!v)
        return -1;
    if (n)
        printf ("%s\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n", "Filename");
    for (size_t i = 0; i < n; i++) {
        int srclen = (int) strlen (v[i].path), tlen = (int) strlen (v[i].type);
        printf ("%s%*s%s%s\t%llu%s\t%llu%s\t%d\n", v[i].path, srclen < 40 ? 40 - srclen : 1, " ",
                v[i].type, tlen < 8 ? "\t" : "", v[i].size, v[i].size < 10000000 ? "\t" : "",
                v[i].used, v[i].used < 10000000 ? "\t" : "", v[i].prio);
    }
    sw_free (v, n);
    return 0;
}

enum { SC_NAME, SC_TYPE, SC_SIZE, SC_USED, SC_PRIO, SC_UUID, SC_LABEL, SC_COUNT };
static const struct { const char *name; int right; } sw_cols[SC_COUNT] = {
    { "NAME", 0 }, { "TYPE", 0 }, { "SIZE", 1 }, { "USED", 1 }, { "PRIO", 1 },
    { "UUID", 0 }, { "LABEL", 0 },
};

static void
sw_put_raw (const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char) *s;
        if (c <= ' ' || c == '\\' || c == 0x7f)
            printf ("\\x%02x", c);
        else
            putchar (c);
    }
}

/* libsmartcols table (non-terminal output: no truncation). */
static int
sw_table (const int *cols, int ncols, int raw, int noheadings, int bytes)
{
    size_t n;
    sw_entry *v = sw_read (&n);
    if (!v)
        return -1;
    char **cells = xmalloc ((n * ncols + 1) * sizeof *cells);
    for (size_t r = 0; r < n; r++) {
        char uuid[40] = "", label[17] = "";
        int probed = 0;
        for (int i = 0; i < ncols; i++) {
            char buf[64];
            const char *val = NULL;
            switch (cols[i]) {
            case SC_NAME: val = v[r].path; break;
            case SC_TYPE: val = v[r].type; break;
            case SC_SIZE: case SC_USED: {
                unsigned long long b = (cols[i] == SC_SIZE ? v[r].size : v[r].used) * 1024ULL;
                if (bytes)
                    snprintf (buf, sizeof buf, "%llu", b);
                else
                    sw_human (b, buf, sizeof buf);
                val = buf;
                break;
            }
            case SC_PRIO: snprintf (buf, sizeof buf, "%d", v[r].prio); val = buf; break;
            case SC_UUID: case SC_LABEL:
                if (!probed++)
                    sw_probe (v[r].path, uuid, sizeof uuid, label, sizeof label);
                val = cols[i] == SC_UUID ? uuid : label;
                if (!*val)
                    val = NULL;
                break;
            }
            cells[r * ncols + i] = val ? savestring (val) : NULL;
        }
    }
    if (n && raw) {
        if (!noheadings) {
            for (int i = 0; i < ncols; i++) {
                if (i) putchar (' ');
                sw_put_raw (sw_cols[cols[i]].name);
            }
            putchar ('\n');
        }
        for (size_t r = 0; r < n; r++) {
            for (int i = 0; i < ncols; i++) {
                if (i) putchar (' ');
                sw_put_raw (cells[r * ncols + i] ? cells[r * ncols + i] : "");
            }
            putchar ('\n');
        }
    } else if (n) {
        size_t width[2 * SC_COUNT];
        for (int i = 0; i < ncols; i++) {
            width[i] = noheadings ? 0 : strlen (sw_cols[cols[i]].name);
            for (size_t r = 0; r < n; r++)
                if (cells[r * ncols + i] && strlen (cells[r * ncols + i]) > width[i])
                    width[i] = strlen (cells[r * ncols + i]);
        }
        for (size_t r = noheadings ? 1 : 0; r <= n; r++) {
            for (int i = 0; i < ncols; i++) {
                const char *val = r ? cells[(r - 1) * ncols + i] : sw_cols[cols[i]].name;
                int last = i + 1 == ncols;
                if (!val) val = "";
                if (i) putchar (' ');
                if (last && !*val) break;
                if (sw_cols[cols[i]].right) printf ("%*s", (int) width[i], val);
                else if (last) fputs (val, stdout);
                else printf ("%-*s", (int) width[i], val);
            }
            putchar ('\n');
        }
    }
    for (size_t i = 0; i < n * ncols; i++)
        free (cells[i]);
    free (cells);
    sw_free (v, n);
    return 0;
}

/* Existing path → realpath. LABEL=/UUID=/PARTLABEL=/PARTUUID= →
 * /dev/disk/by-*. A missing plain path is copied. Empty and an unresolved
 * tag return NULL (cannot find). Same rule as swapoff. */
static char *
sw_resolve (const char *spec)
{
    const char *kind = NULL;
    size_t skip = 0;
    if (!spec || !*spec)
        return NULL;
    if (!strncmp (spec, "UUID=", 5)) { kind = "uuid"; skip = 5; }
    else if (!strncmp (spec, "LABEL=", 6)) { kind = "label"; skip = 6; }
    else if (!strncmp (spec, "PARTUUID=", 9)) { kind = "partuuid"; skip = 9; }
    else if (!strncmp (spec, "PARTLABEL=", 10)) { kind = "partlabel"; skip = 10; }
    if (kind) {
        char by[PATH_MAX];
        int n = snprintf (by, sizeof by, "/dev/disk/by-%s/%s", kind, spec + skip);
        if (n < 0 || (size_t) n >= sizeof by)
            return NULL;
        return realpath (by, NULL);
    }
    char *rp = realpath (spec, NULL);
    return rp ? rp : strdup (spec);
}

static void
sw_tryhelp (void)
{
    fprintf (stderr, "Try '%s --help' for more information.\n", "swapon");
}

/* Signed 16-bit, as util-linux strtos16_or_err. Exits the option parse
 * with status 1; a bad priority does not reach swapon(2). */
static int
sw_priority (const char *str, int *out)
{
    char *end = NULL;
    if (!str)
        str = "";
    errno = 0;
    long num = strtol (str, &end, 10);
    if (!*str || errno || end == str || *end)
        ;
    else if (num < -32768 || num > 32767)
        errno = ERANGE;
    else {
        *out = (int) num;
        return 0;
    }
    if (errno)
        builtin_error ("failed to parse priority: '%s': %s", str, strerror (errno));
    else
        builtin_error ("failed to parse priority: '%s'", str);
    return -1;
}

#define SW_SIG_SZ 10
#define SW_SIG "SWAPSPACE2"

static int
sw_signature (const char *buf, int *suspend)
{
    if (!memcmp (buf, SW_SIG, SW_SIG_SZ)) {
        *suspend = 0;
        return 1;
    }
    if (!memcmp (buf, "S1SUSPEND", 9) || !memcmp (buf, "S2SUSPEND", 9) ||
        !memcmp (buf, "ULSUSPEND", 9) ||
        !memcmp (buf, "\xed\xc3\x02\xe9\x98\x56\xe5\x0c", 8) ||
        !memcmp (buf, "LINHIB0001", 10)) {
        *suspend = 1;
        return 1;
    }
    return 0;
}

/* Open and validate before the syscall. 0 = call swapon; -1 = skip it.
 * The qualified guest does not warn about mode 0600, so there is no
 * permissions warning here; a non-root regular-file owner is a warning
 * and still reaches the syscall. */
static int
sw_checks (const char *path)
{
    struct stat st;
    unsigned char *buf = NULL;
    unsigned page = 0;
    int suspend = 0, fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("cannot open %s: %s", path, strerror (errno));
        return -1;
    }
    if (fstat (fd, &st) < 0) {
        builtin_error ("stat of %s failed: %s", path, strerror (errno));
        close (fd);
        return -1;
    }
    if (S_ISREG (st.st_mode) && st.st_uid != 0)
        builtin_error ("%s: insecure file owner %d, 0 (root) suggested.", path, (int) st.st_uid);
    if (S_ISREG (st.st_mode) && st.st_blocks * 512L < st.st_size) {
        builtin_error ("%s: skipping - it appears to have holes.", path);
        close (fd);
        return -1;
    }
    buf = xmalloc (65536);
    ssize_t got = read (fd, buf, 65536);
    close (fd);
    for (unsigned p = 0x1000; got > 0 && p <= 0x10000; p <<= 1) {
        if (p == 0x8000)
            continue;
        if ((size_t) got < p - SW_SIG_SZ)
            break;
        if (sw_signature ((const char *) buf + p - SW_SIG_SZ, &suspend)) {
            page = p;
            break;
        }
    }
    free (buf);
    if (!page) {
        builtin_error ("%s: read swap header failed", path);
        return -1;
    }
    if (suspend) {
        builtin_error ("%s: software suspend data detected. Rewriting the swap signature.", path);
        fd = open (path, O_WRONLY | O_CLOEXEC);
        if (fd < 0 || lseek (fd, (off_t) page - SW_SIG_SZ, SEEK_SET) < 0 ||
            write (fd, SW_SIG, SW_SIG_SZ) != SW_SIG_SZ) {
            builtin_error ("%s: write signature failed: %s", path, strerror (errno));
            if (fd >= 0)
                close (fd);
            return -1;
        }
        close (fd);
    } else if ((unsigned) getpagesize () != page)
        builtin_error ("%s: swap format pagesize does not match. (Use --fixpgsz to reinitialize it.)", path);
    return 0;
}

static int
sw_one (const char *spec, int prio, int discard)
{
    char *path = sw_resolve (spec);
    int flags = 0, rc;
    if (!path) {
        builtin_error ("cannot find the device for %s", spec);
        return -1;
    }
    if (sw_checks (path) < 0) {
        free (path);
        return -1;
    }
    if (prio >= 0)
        flags |= SWAP_FLAG_PREFER | (prio & 0x7fff);
    if (discard)
        flags |= SWAP_FLAG_DISCARD;
    rc = swapon (path, flags);
    if (rc < 0)
        builtin_error ("%s: swapon failed: %s", path, strerror (errno));
    free (path);
    return rc < 0 ? -1 : 0;
}

/* --show=COLS: comma-separated, case-insensitive column names. */
static int
sw_columns (const char *arg, int *cols, int *ncols)
{
    *ncols = 0;
    for (const char *p = arg;;) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen (p);
        int id = -1;
        if (!len)
            return -1;
        for (int i = 0; i < SC_COUNT; i++)
            if (strlen (sw_cols[i].name) == len && !strncasecmp (sw_cols[i].name, p, len))
                id = i;
        if (id < 0) {
            builtin_error ("unknown column: %.*s", (int) len, p);
            return -1;
        }
        if (*ncols >= 2 * SC_COUNT)
            return -1;
        cols[(*ncols)++] = id;
        if (!comma)
            return 0;
        p = comma + 1;
    }
}

int
swapon_builtin (WORD_LIST *list)
{
    int prio = -1, discard = 0, show = 0, summary = 0, raw = 0, noheadings = 0, bytes = 0;
    int cols[2 * SC_COUNT], ncols = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *swapon_doc[]; for (char **lp = swapon_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-s") || !strcmp (w, "--summary")) { summary = 1; list = list->next; continue; }
        if (!strcmp (w, "--show")) { show = 1; list = list->next; continue; }
        if (!strncmp (w, "--show=", 7)) {
            if (sw_columns (w + 7, cols, &ncols) < 0) return EXECUTION_FAILURE;
            show = 1; list = list->next; continue;
        }
        if (!strcmp (w, "--raw")) { raw = 1; list = list->next; continue; }
        if (!strcmp (w, "--noheadings")) { noheadings = 1; list = list->next; continue; }
        if (!strcmp (w, "--bytes")) { bytes = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--discard")) { discard = 1; list = list->next; continue; }
        if (!strcmp (w, "-p") || !strcmp (w, "--priority") || !strncmp (w, "--priority=", 11) ||
            (w[0] == '-' && w[1] == 'p' && w[2])) {
            const char *arg = NULL;
            if (!strncmp (w, "--priority=", 11))
                arg = w + 11;
            else if (w[0] == '-' && w[1] == 'p' && w[2])
                arg = w + 2;
            else if (!list->next) {
                if (w[1] == '-')
                    builtin_error ("option '--priority' requires an argument");
                else
                    builtin_error ("option requires an argument -- 'p'");
                sw_tryhelp ();
                return 1;
            } else {
                list = list->next;
                arg = list->word->word;
            }
            if (!arg || sw_priority (arg, &prio) < 0)
                return 1;
            list = list->next;
            continue;
        }
        if (w[1] == '-')
            builtin_error ("unrecognized option '%s'", w);
        else
            builtin_error ("invalid option -- '%c'", w[1]);
        sw_tryhelp ();
        return 1;
    }

    /* util-linux: -s prints the summary at once; no operand means --show.
       An unreadable /proc/swaps fails silently with status 255, as there. */
    if (summary)
        return sw_summary () < 0 ? 255 : EXECUTION_SUCCESS;
    if (show || !list) {
        if (!ncols) {
            static const int defaults[] = { SC_NAME, SC_TYPE, SC_SIZE, SC_USED, SC_PRIO };
            memcpy (cols, defaults, sizeof defaults);
            ncols = 5;
        }
        return sw_table (cols, ncols, raw, noheadings, bytes) < 0 ? 255 : EXECUTION_SUCCESS;
    }

    int rc = 0;
    for (WORD_LIST *p = list; p; p = p->next)
        rc |= sw_one (p->word->word, prio, discard);
    return rc < 0 ? 255 : rc;
}

char *swapon_doc[] = {
    "Enable a swap area, or list the active ones.",
    "",
    "    swapon [--show[=COLS]] [--raw] [--noheadings] [--bytes]",
    "                            table of active swap areas (NAME TYPE SIZE USED PRIO;",
    "                            also UUID LABEL); nothing when none are active",
    "    swapon -s|--summary     /proc/swaps-style summary",
    "    swapon [-p PRIO] [-d] device",
    "",
    "    -p PRIO  swap priority (0..32767) sets a preference; -32768..-1 does not",
    "    -d       discard freed pages",
    "",
    "An existing path or LABEL=/UUID=/PARTLABEL=/PARTUUID= is resolved before",
    "swapon(2). A missing path is not enabled. Enabling a swap area requires root.",
    (char *) NULL
};

struct builtin swapon_struct = {
    "swapon",
    swapon_builtin,
    BUILTIN_ENABLED,
    swapon_doc,
    "swapon [-s|--show[=COLS]] [-p PRIO] [-d] [device...]",
    0
};
