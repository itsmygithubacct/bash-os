/* SPDX-License-Identifier: MIT */
/* sysctl.c — sysctl(8) over /proc/sys file I/O.
 *
 *   sysctl KEY [KEY ...]              # read
 *   sysctl -w KEY=VALUE [...]         # write (procps also accepts
 *                                         # KEY=VALUE without -w)
 *   sysctl -a                         # dump all readable keys
 *   sysctl -p [FILE ...]              # load sysctl.conf-shaped files
 *   sysctl --system                   # load standard locations in
 *                                         # the procps-ng order
 *   sysctl -n                         # value only (suppress name = )
 *   sysctl -e                         # ignore unknown keys
 *   sysctl -q                         # quiet (no print on write)
 *
 * Source counterparts (read for shape, not ported):
 *   research/refs/procps-ng/src/sysctl.c
 *   research/refs/busybox/procps/sysctl.c
 *   research/refs/toybox/toys/posix/sysctl.c
 *
 * sysctl(2) the syscall was deprecated and removed in Linux 5.5; the
 * surviving interface is plain /proc/sys file I/O. The first separator
 * selects dotted or slash notation, as in procps-ng.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <regex.h>

#include "loadables.h"

#define BSC_PROC_SYS  "/proc/sys"
#define BSC_PATH_MAX  4096
#define BSC_VAL_MAX   65536

/* Flag bits — packed into a single int for easy threading. */
#define BSC_F_SHOW_KEYS      (1 << 0)
#define BSC_F_SHOW_KEY_ERROR (1 << 1)
#define BSC_F_QUIET          (1 << 2)
#define BSC_F_WRITE          (1 << 3)
#define BSC_F_PRELOAD        (1 << 4)
#define BSC_F_SYSTEM         (1 << 5)
#define BSC_F_DUMP_ALL       (1 << 6)
#define BSC_F_NAMES_ONLY     (1 << 7)
#define BSC_F_IGNORE_PERM    (1 << 8)

/* -r/--pattern: when set, only keys whose dotted name matches this
 * POSIX extended regex are read/written (procps-ng semantics). Reset at
 * each builtin invocation; valid only for the duration of one call. */
static const char *bsc_pattern = NULL;

/* Mirror procps-ng pattern_match(): REG_EXTENDED|REG_NOSUB over the dotted
 * key name. A pattern that fails to compile matches nothing. */
static int
bsc_pattern_match (const char *key)
{
    if (!bsc_pattern)
        return 1;
    regex_t re;
    if (regcomp (&re, bsc_pattern, REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    int rc = regexec (&re, key, 0, NULL, 0);
    regfree (&re);
    return rc == 0;
}

/* --- key/path mapping ----------------------------------------------- */

/* procps treats the first separator as the notation selector.  In dotted
 * notation both separators are exchanged; slash notation is already a path.
 * Apply this only to the key, never to the /proc/sys prefix. */
static void
bsc_swap_separators (char *name, char old, char desired)
{
    char *p = strpbrk (name, "./");
    if (!p || *p == desired)
        return;
    for (; *p; p++) {
        if (*p == old) *p = desired;
        else if (*p == desired) *p = old;
    }
}

/* Convert a filesystem path under /proc/sys back to dotted key form.
 *
 * Input:  "/proc/sys/kernel/ostype"
 * Output: "kernel.ostype"
 *
 * Writes into OUT (capacity OUTSZ).  Returns 0 on success, -1 on
 * overflow.
 */
static int
bsc_path_to_key (const char *path, char *out, size_t outsz)
{
    const char *p = path;
    size_t pfxlen = strlen (BSC_PROC_SYS "/");

    if (strncmp (p, BSC_PROC_SYS "/", pfxlen) != 0) {
        if (strlen (p) + 1 > outsz) return -1;
        strcpy (out, p);
        return 0;
    }
    p += pfxlen;
    size_t plen = strlen (p);
    if (plen + 1 > outsz) return -1;
    memcpy (out, p, plen + 1);
    bsc_swap_separators (out, '/', '.');
    return 0;
}

/* --- per-key read / write ------------------------------------------- */

static int bsc_dump_dir (const char *, int);

static int
bsc_read_key (const char *display_name, const char *fspath, int flags)
{
    struct stat st;
    if (stat (fspath, &st) < 0) {
        if (errno == EACCES && (flags & BSC_F_DUMP_ALL))
            return EXECUTION_SUCCESS;
        if (!(flags & BSC_F_SHOW_KEY_ERROR))
            return EXECUTION_SUCCESS;
        builtin_error ("cannot stat %s: %s", fspath, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (!(st.st_mode & S_IRUSR))
        return EXECUTION_SUCCESS;
    if (S_ISDIR (st.st_mode))
        return bsc_dump_dir (fspath, flags);
    if (!bsc_pattern_match (display_name))
        return EXECUTION_SUCCESS;
    if (flags & BSC_F_NAMES_ONLY) {
        printf ("%s\n", display_name);
        return EXECUTION_SUCCESS;
    }

    int fd = open (fspath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            if (!(flags & BSC_F_SHOW_KEY_ERROR))
                return EXECUTION_SUCCESS;
            if (flags & BSC_F_SHOW_KEY_ERROR)
                builtin_error ("\"%s\" is an unknown key", display_name);
            return EXECUTION_FAILURE;
        }
        if (errno == EACCES && (flags & BSC_F_DUMP_ALL))
            return EXECUTION_SUCCESS;
        if (errno == EACCES)
            builtin_error ("permission denied on key '%s'", display_name);
        else if (errno != EIO)
            builtin_error ("reading key \"%s\": %s", display_name, strerror (errno));
        return EXECUTION_FAILURE;
    }

    FILE *fp = fdopen (fd, "r");
    if (!fp) {
        int saved = errno;
        close (fd);
        builtin_error ("reading key \"%s\": %s", display_name, strerror (saved));
        return EXECUTION_FAILURE;
    }
    char *line = NULL;
    size_t capacity = 0;
    ssize_t n;
    int rc = EXECUTION_SUCCESS;
    errno = 0;
    while ((n = getline (&line, &capacity, fp)) > 0) {
        if (flags & BSC_F_SHOW_KEYS) {
            printf ("%s = ", display_name);
            fwrite (line, 1, (size_t)n, stdout);
            if (line[n - 1] != '\n') putchar ('\n');
        } else
            fwrite (line, 1, (size_t)n, stdout);
    }
    if (ferror (fp)) {
        int saved = errno;
        if (saved == EACCES && (flags & BSC_F_DUMP_ALL)) {
            free (line);
            fclose (fp);
            return EXECUTION_SUCCESS;
        }
        if (saved == EACCES)
            builtin_error ("permission denied on key '%s'", display_name);
        else if (saved != EIO)
            builtin_error ("reading key \"%s\"", display_name);
        rc = EXECUTION_FAILURE;
    }
    free (line);
    fclose (fp);
    return rc;
}

static int
bsc_write_key (const char *display_name, const char *fspath,
               const char *value, int flags)
{
    /* -r/--pattern also gates writes (procps-ng filters set keys too). */
    if (!bsc_pattern_match (display_name))
        return EXECUTION_SUCCESS;

    int fd = open (fspath, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT && !(flags & BSC_F_SHOW_KEY_ERROR))
            return EXECUTION_SUCCESS;
        if ((flags & BSC_F_IGNORE_PERM) && (errno == EACCES || errno == EPERM || errno == EROFS)) {
            builtin_error ("permission denied on key \"%s\", ignoring", display_name);
            return EXECUTION_SUCCESS;
        }
        if (errno == ENOENT) {
            /* Use the actual translated path used by open, including
             * interface names containing dots and slash notation. */
            builtin_error ("cannot stat %s: %s", fspath, strerror (ENOENT));
        } else if (errno == EACCES)
            builtin_error ("permission denied on key \"%s\"", display_name);
        else
            builtin_error ("setting key \"%s\": %s", display_name, strerror (errno));
        return EXECUTION_FAILURE;
    }
    size_t vlen = strlen (value);
    ssize_t w = write (fd, value, vlen);
    int saved = errno;
    close (fd);
    if (w < 0 || (size_t)w != vlen) {
        if (w < 0 && (flags & BSC_F_IGNORE_PERM) &&
            (saved == EACCES || saved == EPERM))
            return EXECUTION_SUCCESS;
        builtin_error ("setting key \"%s\": %s", display_name,
                       w < 0 ? strerror (saved) : "short write");
        return EXECUTION_FAILURE;
    }
    if (!(flags & BSC_F_QUIET)) {
        if (flags & BSC_F_NAMES_ONLY)
            printf ("%s\n", display_name);
        else if (flags & BSC_F_SHOW_KEYS)
            printf ("%s = %s\n", display_name, value);
        else
            printf ("%s\n", value);
    }
    return EXECUTION_SUCCESS;
}

/* --- recursive dump (-a) -------------------------------------------- */

static int
bsc_dump_dir (const char *path, int flags)
{
    DIR *d = opendir (path);
    if (!d) {
        if (errno == EACCES) return EXECUTION_SUCCESS; /* skip silently */
        builtin_error ("opendir '%s': %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    struct dirent *e;
    while ((e = readdir (d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;

        char childpath[BSC_PATH_MAX];
        int n = snprintf (childpath, sizeof childpath, "%s/%s",
                          path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof childpath) continue;

        struct stat st;
        if (lstat (childpath, &st) < 0) continue;

        if (S_ISDIR (st.st_mode)) {
            if (bsc_dump_dir (childpath, flags) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
        } else if (S_ISREG (st.st_mode)) {
            char keybuf[BSC_PATH_MAX];
            if (bsc_path_to_key (childpath, keybuf, sizeof keybuf) < 0)
                continue;
            /* Suppress per-key ENOENT/EACCES warnings during dump-all
             * — many entries are write-only. */
            int sub_flags = flags & ~BSC_F_SHOW_KEY_ERROR;
            (void) bsc_read_key (keybuf, childpath, sub_flags);
        }
    }
    closedir (d);
    return rc;
}

/* --- argv-side single-token apply ----------------------------------- */

static int
bsc_apply_token (char *raw, int flags)
{
    /* RAW = "KEY" or "KEY=VALUE" or "KEY = VALUE" (preload form).  We
     * normalise to: display_name = the dotted KEY portion; value =
     * pointer into RAW past '=' (write mode); fspath = "/proc/sys/.../KEY".
     *
     * RAW is mutated in place (NUL inserted at '='). */
    char *eq = strchr (raw, '=');
    int writing = (flags & BSC_F_WRITE) ? 1 : 0;
    char *value = NULL;

    if (eq) {
        writing = 1;
        *eq = '\0';
        value = eq + 1;
        /* Trim any trailing whitespace from key (preload-file slack). */
        char *k_end = eq;
        while (k_end > raw &&
               (k_end[-1] == ' ' || k_end[-1] == '\t'))
            *--k_end = '\0';
        /* Trim leading whitespace from value. */
        while (*value == ' ' || *value == '\t') value++;
    } else if (writing) {
        builtin_error ("command line(0): invalid syntax, continuing...");
        return EXECUTION_FAILURE;
    }

    if (raw[0] == '\0') {
        builtin_error ("empty key");
        return EXECUTION_FAILURE;
    }

    /* display_name = the dotted key as supplied (without value). */
    char display_name[BSC_PATH_MAX];
    if (strlen (raw) + 1 > sizeof display_name) {
        builtin_error ("key too long");
        return EXECUTION_FAILURE;
    }
    strcpy (display_name, raw);
    bsc_swap_separators (display_name, '/', '.');

    /* Build /proc/sys/<key-with-slashes>. */
    char fspath[BSC_PATH_MAX];
    int n = snprintf (fspath, sizeof fspath, "%s/%s", BSC_PROC_SYS, raw);
    if (n < 0 || (size_t)n >= sizeof fspath) {
        builtin_error ("key path too long: %s", raw);
        return EXECUTION_FAILURE;
    }
    bsc_swap_separators (fspath + strlen (BSC_PROC_SYS "/"), '.', '/');

    if (writing)
        return bsc_write_key (display_name, fspath, value, flags);
    else
        return bsc_read_key (display_name, fspath, flags);
}

/* --- preload file (-p / --system) ----------------------------------- */

/* Parse a whole file before applying it, as procps reports syntax errors
 * before write errors.  Keep the assignments in their original order. */
struct bsc_line { char *text; struct bsc_line *next; };

static int
bsc_load_file (const char *path, int flags, int optional, int announce,
               struct bsc_line ***tail)
{
    FILE *fp = fopen (path, "re");
    if (!fp) {
        if (optional && errno == ENOENT) return EXECUTION_SUCCESS;
        builtin_error ("cannot open \"%s\": %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (announce && !(flags & BSC_F_QUIET)) printf ("* Applying %s ...\n", path);
    char *line = NULL;
    size_t capacity = 0, lineno = 0;
    ssize_t length;
    int rc = EXECUTION_SUCCESS;
    while ((length = getline (&line, &capacity, fp)) >= 0) {
        lineno++;
        while (length > 0 && (line[length-1] == '\n' || line[length-1] == '\r'))
            line[--length] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        if (!strchr (p, '=')) {
            builtin_error ("%s(%zu): invalid syntax, continuing...", path, lineno);
            rc = EXECUTION_FAILURE;
            continue;
        }
        struct bsc_line *item = malloc (sizeof *item);
        if (!item || !(item->text = strdup (p))) {
            free (item);
            builtin_error ("out of memory");
            rc = EXECUTION_FAILURE;
            break;
        }
        size_t end = strlen (item->text);
        while (end && (item->text[end-1] == ' ' || item->text[end-1] == '\t'))
            item->text[--end] = '\0';
        item->next = NULL;
        **tail = item;
        *tail = &item->next;
    }
    if (ferror (fp)) { builtin_error ("read '%s': %s", path, strerror (errno)); rc = EXECUTION_FAILURE; }
    free (line);
    fclose (fp);
    return rc;
}

static int
bsc_apply_lines (struct bsc_line *head, int flags)
{
    int rc = EXECUTION_SUCCESS;
    while (head) {
        struct bsc_line *item = head;
        char *p = item->text;
        int line_flags = flags | BSC_F_WRITE | BSC_F_PRELOAD;
        if (*p == '-') { p++; line_flags |= BSC_F_IGNORE_PERM; }
        if (bsc_apply_token (p, line_flags) != EXECUTION_SUCCESS &&
            !(line_flags & BSC_F_IGNORE_PERM)) rc = EXECUTION_FAILURE;
        head = item->next;
        free (item->text);
        free (item);
    }
    return rc;
}

struct bsc_config { char *name; char *path; };

static int
bsc_cmp_config (const void *a, const void *b)
{
    return strcmp (((const struct bsc_config *)a)->name,
                   ((const struct bsc_config *)b)->name);
}

/* Select the first occurrence of each basename in priority order, then
 * apply the selected files in global lexical basename order. */
static int
bsc_load_system (int flags)
{
    static const char *dirs[] = { "/etc/sysctl.d", "/run/sysctl.d",
        "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d", NULL };
    struct bsc_config *files = NULL;
    size_t n = 0, cap = 0;
    int rc = EXECUTION_SUCCESS;
    struct bsc_line *head = NULL, **tail = &head;
    for (int i = 0; dirs[i]; i++) {
        DIR *d = opendir (dirs[i]);
        if (!d) {
            if (errno != ENOENT) { builtin_error ("opendir '%s': %s", dirs[i], strerror (errno)); rc = EXECUTION_FAILURE; }
            continue;
        }
        struct dirent *e;
        while ((e = readdir (d))) {
            size_t len = strlen (e->d_name), j;
            if (len < 5 || strcmp (e->d_name + len - 5, ".conf")) continue;
            for (j = 0; j < n; j++) if (!strcmp (files[j].name, e->d_name)) break;
            if (j != n) continue;
            char path[BSC_PATH_MAX];
            int pn = snprintf (path, sizeof path, "%s/%s", dirs[i], e->d_name);
            if (pn < 0 || (size_t)pn >= sizeof path) { rc = EXECUTION_FAILURE; continue; }
            if (n == cap) {
                size_t newcap = cap ? cap * 2 : 16;
                struct bsc_config *tmp = realloc (files, newcap * sizeof *tmp);
                if (!tmp) { rc = EXECUTION_FAILURE; break; }
                files = tmp; cap = newcap;
            }
            files[n].name = strdup (e->d_name);
            files[n].path = strdup (path);
            if (!files[n].name || !files[n].path) {
                free (files[n].name); free (files[n].path); rc = EXECUTION_FAILURE; break;
            }
            n++;
        }
        closedir (d);
    }
    if (n > 1) qsort (files, n, sizeof *files, bsc_cmp_config);
    for (size_t i = 0; i < n; i++) {
        if (bsc_load_file (files[i].path, flags, 0, 1, &tail) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
        free (files[i].name); free (files[i].path);
    }
    free (files);
    struct stat st;
    if (stat ("/etc/sysctl.conf", &st) == 0 && S_ISREG (st.st_mode) &&
        bsc_load_file ("/etc/sysctl.conf", flags, 1, 1, &tail) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
    if (bsc_apply_lines (head, flags & ~BSC_F_SHOW_KEY_ERROR) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
    return rc;
}

/* --- builtin entry point -------------------------------------------- */

int
sysctl_builtin (WORD_LIST *list)
{
    /* Defaults match procps-ng: show keys + warn on unknown. */
    int flags = BSC_F_SHOW_KEYS | BSC_F_SHOW_KEY_ERROR;
    bsc_pattern = NULL;   /* reset -r/--pattern from any prior invocation */

    /* Phase 1: collect leading flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }

        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            printf ("Usage: sysctl [-eNnq] [-r PATTERN] {-a | -p [FILE]... | "
                    "--system | [-w] KEY[=VAL]...}\n");
            printf ("  -a  dump all readable keys under /proc/sys\n");
            printf ("  -w  write mode (KEY=VAL is implicit -w too)\n");
            printf ("  -p  load conf file(s); default /etc/sysctl.conf\n");
            printf ("  --system  load standard sysctl.d locations in order\n");
            printf ("  -n, --values  print values without 'KEY = ' prefix\n");
            printf ("  -N, --names   print key names only (no values)\n");
            printf ("  -r, --pattern EXPR  only keys whose name matches EXPR (regex)\n");
            printf ("  -e  ignore 'unknown key' errors\n");
            printf ("  -q  quiet (do not echo on write)\n");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--system")) { flags |= BSC_F_SYSTEM; list = list->next; continue; }
        if (!strcmp (w, "-a") || !strcmp (w, "-A")) {
            flags |= BSC_F_DUMP_ALL; list = list->next; continue;
        }
        if (!strcmp (w, "-w")) { flags |= BSC_F_WRITE; list = list->next; continue; }
        if (!strcmp (w, "-p")) { flags |= BSC_F_PRELOAD; list = list->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--values")) { flags &= ~BSC_F_SHOW_KEYS; list = list->next; continue; }
        if (!strcmp (w, "-N") || !strcmp (w, "--names")) { flags |= BSC_F_NAMES_ONLY; list = list->next; continue; }
        if (!strcmp (w, "-e")) { flags &= ~BSC_F_SHOW_KEY_ERROR; list = list->next; continue; }
        if (!strcmp (w, "-q")) { flags |= BSC_F_QUIET; list = list->next; continue; }
        if (!strcmp (w, "-r") || !strcmp (w, "--pattern")) {
            if (!list->next) { builtin_error ("-r needs a pattern"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            bsc_pattern = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--pattern=", 10)) { bsc_pattern = w + 10; list = list->next; continue; }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    /* Phase 2: dispatch. */
    if (flags & BSC_F_SYSTEM)
        return bsc_load_system (flags);

    if (flags & BSC_F_PRELOAD) {
        struct bsc_line *head = NULL, **tail = &head;
        int rc = EXECUTION_SUCCESS;
        if (!list) {
            if (bsc_load_file ("/etc/sysctl.conf", flags, 0, 0, &tail) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
        }
        while (list) {
            if (strcmp (list->word->word, "-p") &&
                bsc_load_file (list->word->word, flags, 0, 0, &tail) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
            list = list->next;
        }
        if (bsc_apply_lines (head, flags) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
        return rc;
    }

    if (flags & BSC_F_DUMP_ALL) {
        return bsc_dump_dir (BSC_PROC_SYS, flags);
    }

    if (!list) {
        builtin_error ("missing key (try -a or -p)");
        return EX_USAGE;
    }

    /* Per-token apply (read or write). */
    int rc = EXECUTION_SUCCESS;
    while (list) {
        /* Apply needs a writable copy: bsc_apply_token mutates buf. */
        const char *src = list->word->word;
        size_t L = strlen (src);
        if (L + 1 > BSC_PATH_MAX) {
            builtin_error ("token too long: %.40s...", src);
            rc = EXECUTION_FAILURE;
            list = list->next;
            continue;
        }
        char buf[BSC_PATH_MAX];
        memcpy (buf, src, L + 1);
        if (bsc_apply_token (buf, flags) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
        list = list->next;
    }
    return rc;
}

char *sysctl_doc[] = {
    "Read and write kernel parameters via /proc/sys.",
    "",
    "    sysctl KEY [KEY ...]            # read",
    "    sysctl [-w] KEY=VALUE [...]     # write",
    "    sysctl -a                       # dump all readable keys",
    "    sysctl -p [FILE ...]            # load sysctl.conf-shape file",
    "    sysctl --system                 # load standard locations",
    "",
    "Flags: -n/--values value-only, -N/--names names-only,",
    "       -r/--pattern EXPR filter keys by regex, -e ignore unknown,",
    "       -q quiet on write.",
    "",
    "KEY syntax: dotted (kernel.ostype) — internally mapped onto",
    "/proc/sys/kernel/ostype.  sysctl(2) the syscall was removed in",
    "Linux 5.5; this builtin uses plain file I/O.",
    (char *)NULL
};

struct builtin sysctl_struct = {
    "sysctl",
    sysctl_builtin,
    BUILTIN_ENABLED,
    sysctl_doc,
    "sysctl [-eNnq] [-r PATTERN] {-a | -p [FILE]... | --system | [-w] KEY[=VAL]...}",
    0
};
