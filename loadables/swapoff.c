/* SPDX-License-Identifier: MIT */
/* swapoff.c — disable a swap area, as a bash builtin.
 *
 * Status bits match util-linux 2.41: 0 ok, 2 ENOMEM, 4 swapoff(2) failure,
 * 16 usage or EPERM, 32 every -a entry failed, 64 some -a entries failed.
 * cannot-find returns -1, which leaves the process status 255.
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
#include <limits.h>
#include <sys/swap.h>

#include "loadables.h"

#define SWAPOFF_EX_OK       0
#define SWAPOFF_EX_ENOMEM   2
#define SWAPOFF_EX_FAILURE  4
#define SWAPOFF_EX_USAGE    16
#define SWAPOFF_EX_ALLERR   32
#define SWAPOFF_EX_SOMEOK   64

/* Existing path → realpath. LABEL=/UUID=/PARTLABEL=/PARTUUID= →
 * /dev/disk/by-*. A missing plain path is copied. Empty and an unresolved
 * tag return NULL. Same rule as swapon. */
static char *
so_resolve (const char *spec)
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
so_unmangle (char *s)
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

static void
so_tryhelp (void)
{
    fprintf (stderr, "Try '%s --help' for more information.\n", "swapoff");
}

/* quiet: -a suppresses the swapoff-failed warning (except ENOMEM).
 * canonic: the path is already the one swapoff(2) should see.
 * 16 means stop the whole command (EPERM). */
static int
do_swapoff (const char *orig, int quiet, int canonic, int verbose)
{
    char *owned = NULL;
    const char *special = orig;
    if (verbose)
        printf ("swapoff %s\n", orig);
    if (!canonic) {
        owned = so_resolve (orig);
        if (!owned) {
            builtin_error ("cannot find the device for %s", orig);
            return -1;
        }
        special = owned;
    }
    if (swapoff (special) == 0) {
        free (owned);
        return SWAPOFF_EX_OK;
    }
    if (errno == EPERM) {
        free (owned);
        builtin_error ("Not superuser.");
        return SWAPOFF_EX_USAGE;
    }
    if (errno == ENOMEM) {
        builtin_error ("%s: swapoff failed: %s", orig, strerror (errno));
        free (owned);
        return SWAPOFF_EX_ENOMEM;
    }
    if (!quiet)
        builtin_error ("%s: swapoff failed: %s", orig, strerror (errno));
    free (owned);
    return SWAPOFF_EX_FAILURE;
}

struct so_ent { char *path; };

/* Snapshot /proc/swaps. Parse errors are reported and skipped. An unreadable
 * table yields no entries (util-linux then still walks fstab). A read error
 * discards the snapshot. *saw is 1 when the file opened. */
static int
so_read_swaps (struct so_ent **out, size_t *count)
{
    FILE *fp = fopen ("/proc/swaps", "r");
    char *line = NULL;
    size_t cap = 0, n = 0, alloc = 0, lineno = 0;
    struct so_ent *v = NULL;
    *out = NULL;
    *count = 0;
    if (!fp)
        return 0;
    ssize_t length;
    while ((length = getline (&line, &cap, fp)) >= 0) {
        char *s = line, *nl = strchr (line, '\n');
        char *src = NULL, *type = NULL;
        unsigned long long size, used;
        int prio;
        lineno++;
        if (memchr (line, 0, (size_t) length)) {
            builtin_error ("%s: parse error at line %zu -- ignored", "/proc/swaps", lineno);
            continue;
        }
        if (nl)
            *nl = '\0';
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s || *s == '#' || !strncmp (s, "Filename\t", 9))
            continue;
        if (sscanf (s, "%ms %ms %llu %llu %d", &src, &type, &size, &used, &prio) != 5) {
            free (src);
            free (type);
            builtin_error ("%s: parse error at line %zu -- ignored", "/proc/swaps", lineno);
            continue;
        }
        free (type);
        (void) size;
        (void) used;
        (void) prio;
        so_unmangle (src);
        {
            size_t sl = strlen (src);
            if (sl > 10 && !strcmp (src + sl - 10, " (deleted)"))
                src[sl - 10] = '\0';
        }
        if (n == alloc) {
            alloc = alloc ? alloc * 2 : 8;
            v = xrealloc (v, alloc * sizeof *v);
        }
        v[n++].path = src;
    }
    free (line);
    if (ferror (fp)) {
        for (size_t i = 0; i < n; i++)
            free (v[i].path);
        free (v);
        v = NULL;
        n = 0;
    }
    fclose (fp);
    *out = v;
    *count = n;
    return 0;
}

static int
so_active (struct so_ent *v, size_t n, const char *path)
{
    for (size_t i = 0; i < n; i++)
        if (!strcmp (v[i].path, path))
            return 1;
    return 0;
}

/* fstab swap entries that are not in the snapshot. Return value is ignored
 * by util-linux except that EPERM still aborts. */
static int
so_fstab (struct so_ent *active, size_t nactive, int verbose)
{
    FILE *fp = fopen ("/etc/fstab", "r");
    char *line = NULL;
    size_t cap = 0;
    if (!fp)
        return 0;
    while (getline (&line, &cap, fp) >= 0) {
        char *hash = strchr (line, '#');
        char *spec, *mnt, *type, *save = NULL;
        if (hash)
            *hash = '\0';
        spec = strtok_r (line, " \t\n", &save);
        mnt = strtok_r (NULL, " \t\n", &save);
        type = strtok_r (NULL, " \t\n", &save);
        (void) mnt;
        if (!spec || !type || strcmp (type, "swap"))
            continue;
        char *resolved = so_resolve (spec);
        if (!resolved) {
            builtin_error ("cannot find the device for %s", spec);
            continue;
        }
        if (!so_active (active, nactive, resolved)) {
            int rc = do_swapoff (spec, 1, 0, verbose);
            free (resolved);
            if (rc == SWAPOFF_EX_USAGE) {
                free (line);
                fclose (fp);
                return rc;
            }
        } else
            free (resolved);
    }
    free (line);
    fclose (fp);
    return 0;
}

static int
swapoff_all (int verbose)
{
    struct so_ent *v = NULL;
    size_t n = 0, nsucc = 0, nerrs = 0;
    int rc;
    so_read_swaps (&v, &n);
    for (size_t i = n; i-- > 0; ) {
        rc = do_swapoff (v[i].path, 1, 1, verbose);
        if (rc == SWAPOFF_EX_USAGE) {
            for (size_t k = 0; k < n; k++)
                free (v[k].path);
            free (v);
            return rc;
        }
        if (rc == SWAPOFF_EX_OK)
            nsucc++;
        else
            nerrs++;
    }
    rc = so_fstab (v, n, verbose);
    for (size_t k = 0; k < n; k++)
        free (v[k].path);
    free (v);
    if (rc == SWAPOFF_EX_USAGE)
        return rc;
    if (nerrs == 0)
        return SWAPOFF_EX_OK;
    if (nsucc == 0)
        return SWAPOFF_EX_ALLERR;
    return SWAPOFF_EX_SOMEOK;
}

static int
so_help (void)
{
    extern char *swapoff_doc[];
    for (char **lp = swapoff_doc; *lp; lp++)
        puts (*lp);
    return fflush (stdout) == 0 && !ferror (stdout) ? 0 : 1;
}

int
swapoff_builtin (WORD_LIST *list)
{
    int all = 0, verbose = 0, status = 0;
    const char **operands = NULL, **labels = NULL, **uuids = NULL;
    size_t nops = 0, nl = 0, nu = 0, cap = 0;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) {
            list = list->next;
            break;
        }
        if (w[0] != '-' || !w[1]) {
            if (nops == cap) {
                cap = cap ? cap * 2 : 8;
                operands = xrealloc (operands, cap * sizeof *operands);
            }
            operands[nops++] = w;
            list = list->next;
            continue;
        }
        if (w[1] == '-') {
            if (!strcmp (w, "--all")) all = 1;
            else if (!strcmp (w, "--verbose")) verbose = 1;
            else if (!strcmp (w, "--help")) {
                free (operands); free (labels); free (uuids);
                return so_help ();
            }
            else {
                builtin_error ("unrecognized option '%s'", w);
                so_tryhelp ();
                free (operands);
                return SWAPOFF_EX_USAGE;
            }
            list = list->next;
            continue;
        }
        for (const char *p = w + 1; *p; p++) {
            const char *arg = NULL;
            if (*p == 'a') { all = 1; continue; }
            if (*p == 'v') { verbose = 1; continue; }
            if (*p == 'h') { free (operands); free (labels); free (uuids); return so_help (); }
            if (*p == 'L' || *p == 'U') {
                if (p[1])
                    arg = p + 1;
                else if (list->next) {
                    list = list->next;
                    arg = list->word->word;
                }
                if (!arg) {
                    builtin_error ("option requires an argument -- '%c'", *p);
                    so_tryhelp ();
                    free (operands); free (labels); free (uuids);
                    return SWAPOFF_EX_USAGE;
                }
                if (*p == 'L') {
                    labels = xrealloc (labels, (nl + 1) * sizeof *labels);
                    labels[nl++] = arg;
                } else {
                    uuids = xrealloc (uuids, (nu + 1) * sizeof *uuids);
                    uuids[nu++] = arg;
                }
                break;
            }
            builtin_error ("invalid option -- '%c'", *p);
            so_tryhelp ();
            free (operands); free (labels); free (uuids);
            return SWAPOFF_EX_USAGE;
        }
        list = list->next;
    }
    while (list) {
        if (nops == cap) {
            cap = cap ? cap * 2 : 8;
            operands = xrealloc (operands, cap * sizeof *operands);
        }
        operands[nops++] = list->word->word;
        list = list->next;
    }

    if (!all && !nl && !nu && !nops) {
        builtin_error ("bad usage");
        so_tryhelp ();
        free (operands);
        return SWAPOFF_EX_USAGE;
    }

    for (size_t i = 0; i < nl; i++) {
        char spec[PATH_MAX];
        snprintf (spec, sizeof spec, "LABEL=%s", labels[i]);
        int rc = do_swapoff (spec, 0, 0, verbose);
        if (rc == SWAPOFF_EX_USAGE) {
            free (operands); free (labels); free (uuids);
            return rc;
        }
        status |= rc;
    }
    for (size_t i = 0; i < nu; i++) {
        char spec[PATH_MAX];
        snprintf (spec, sizeof spec, "UUID=%s", uuids[i]);
        int rc = do_swapoff (spec, 0, 0, verbose);
        if (rc == SWAPOFF_EX_USAGE) {
            free (operands); free (labels); free (uuids);
            return rc;
        }
        status |= rc;
    }
    for (size_t i = 0; i < nops; i++) {
        int rc = do_swapoff (operands[i], 0, 0, verbose);
        if (rc == SWAPOFF_EX_USAGE) {
            free (operands); free (labels); free (uuids);
            return rc;
        }
        status |= rc;
    }
    if (all) {
        int rc = swapoff_all (verbose);
        if (rc == SWAPOFF_EX_USAGE) {
            free (operands); free (labels); free (uuids);
            return rc;
        }
        status |= rc;
    }
    free (operands);
    free (labels);
    free (uuids);
    return status < 0 ? 255 : status;
}

char *swapoff_doc[] = {
    "Disable a swap area.",
    "",
    "    swapoff [-a|--all] [spec...]",
    "",
    "Each spec is resolved before swapoff(2). An existing path is canonicalized.",
    "LABEL=/UUID=/PARTLABEL=/PARTUUID= use /dev/disk/by-*. A missing path is passed through.",
    "An empty spec does not call swapoff.",
    "-a reads /proc/swaps backwards, keeps duplicates, then walks fstab swap entries.",
    "A parse error is reported and the rest of the table is still attempted.",
    "-a may be combined with specs; the specs are disabled first.",
    "Requires root.",
    (char *) NULL
};

struct builtin swapoff_struct = {
    "swapoff",
    swapoff_builtin,
    BUILTIN_ENABLED,
    swapoff_doc,
    "swapoff [-a] [device...]",
    0
};
