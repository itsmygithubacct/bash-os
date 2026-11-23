/* SPDX-License-Identifier: MIT */
/* getfacl.c — display POSIX.1e file access control lists, as a bash builtin.
 *
 *   getfacl [-adcpRnesE] [--omit-header] file...
 *
 *   -a            access ACL only (default shows access and default ACLs)
 *   -d            show the default ACL (directories)
 *   --omit-header suppress the "# file/owner/group" comment header
 *
 * Reads the system.posix_acl_access xattr; if the file has no extended ACL
 * the three base entries are synthesised from the mode bits, exactly like
 * getfacl(1).
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
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdint.h>
#include <dirent.h>

#include "loadables.h"

#define ACL_USER_OBJ  0x01
#define ACL_USER      0x02
#define ACL_GROUP_OBJ 0x04
#define ACL_GROUP     0x08
#define ACL_MASK      0x10
#define ACL_OTHER     0x20
#define ACL_UNDEFINED_ID  ((uint32_t) -1)

static uint16_t rd16 (const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32 (const unsigned char *p) { return (uint32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24)); }

static void
perm_str (unsigned p, char out[4])
{
    out[0] = (p & 4) ? 'r' : '-';
    out[1] = (p & 2) ? 'w' : '-';
    out[2] = (p & 1) ? 'x' : '-';
    out[3] = '\0';
}

/* -n numeric ids; -e/-E effective-rights comments always/never (0: only
   when the mask removes a permission). */
static int gf_numeric, gf_effective;

static void
print_entry (uint16_t tag, uint16_t perm, uint32_t id, int mask, int prefix)
{
    char ps[4]; perm_str (perm, ps);
    if (prefix) fputs ("default:", stdout);
    switch (tag) {
        case ACL_USER_OBJ:  printf ("user::%s", ps); break;
        case ACL_GROUP_OBJ: printf ("group::%s", ps); break;
        case ACL_MASK:      printf ("mask::%s", ps); break;
        case ACL_OTHER:     printf ("other::%s", ps); break;
        case ACL_USER: {
            struct passwd *pw = gf_numeric ? NULL : getpwuid ((uid_t) id);
            if (pw) printf ("user:%s:%s", pw->pw_name, ps);
            else    printf ("user:%u:%s", id, ps);
            break;
        }
        case ACL_GROUP: {
            struct group *gr = gf_numeric ? NULL : getgrgid ((gid_t) id);
            if (gr) printf ("group:%s:%s", gr->gr_name, ps);
            else    printf ("group:%u:%s", id, ps);
            break;
        }
    }
    if (mask >= 0 && gf_effective >= 0
        && (tag == ACL_USER || tag == ACL_GROUP || tag == ACL_GROUP_OBJ)
        && (gf_effective > 0 || (perm & mask) != perm)) {
        perm_str (perm & mask, ps);
        printf ("\t#effective:%s", ps);
    }
    putchar ('\n');
}

static int gf_absolute, gf_warned, gf_skip_base;

static int
show_file (const char *path, int omit_header, int selection)
{
    struct stat st;
    if (stat (path, &st) < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

    /* -s: skip files whose ACL is only the three base entries. */
    if (gf_skip_base) {
        unsigned char probe[8192];
        ssize_t an = getxattr (path, "system.posix_acl_access", probe, sizeof probe);
        ssize_t dn = getxattr (path, "system.posix_acl_default", probe, sizeof probe);
        if (an <= 4 + 3 * 8 && dn <= 4) return 0;
    }

    if (!omit_header) {
        struct passwd *pw = gf_numeric ? NULL : getpwuid (st.st_uid);
        struct group  *gr = gf_numeric ? NULL : getgrgid (st.st_gid);
        const char *shown = path;
        /* GNU: absolute names lose their leading '/' unless -p. */
        if (!gf_absolute && shown[0] == '/') {
            while (shown[0] == '/') shown++;
            if (!*shown) shown = "/";
            if (!gf_warned) {
                fflush (stdout);
                fputs ("getfacl: Removing leading '/' from absolute path names\n", stderr);
                gf_warned = 1;
            }
        }
        printf ("# file: %s\n", shown);
        if (pw) printf ("# owner: %s\n", pw->pw_name); else printf ("# owner: %u\n", st.st_uid);
        if (gr) printf ("# group: %s\n", gr->gr_name); else printf ("# group: %u\n", st.st_gid);
        if (st.st_mode & 07000)
            printf ("# flags: %c%c%c\n", st.st_mode & S_ISUID ? 's' : '-',
                    st.st_mode & S_ISGID ? 's' : '-', st.st_mode & S_ISVTX ? 't' : '-');
    }

    for (int want_default = 0; want_default <= 1; want_default++) {
        if (!(selection & (want_default ? 2 : 1))) continue;
        const char *xname = want_default ? "system.posix_acl_default" : "system.posix_acl_access";
        unsigned char buf[8192];
        ssize_t n = getxattr (path, xname, buf, sizeof buf);

        if (n >= 8 && rd32 (buf) == 2) {
            int mask = -1;
            for (ssize_t off = 4; off + 8 <= n; off += 8)
                if (rd16 (buf + off) == ACL_MASK) mask = rd16 (buf + off + 2);
            /* decode binary entries (8 bytes each after the 4-byte version) */
            for (ssize_t off = 4; off + 8 <= n; off += 8)
                print_entry (rd16 (buf + off), rd16 (buf + off + 2), rd32 (buf + off + 4),
                             mask, want_default && selection == 3);
        } else if (!want_default) {
            /* no extended ACL → synthesise the three base entries from the mode */
            char ps[4];
            perm_str ((st.st_mode >> 6) & 7, ps); printf ("user::%s\n", ps);
            perm_str ((st.st_mode >> 3) & 7, ps); printf ("group::%s\n", ps);
            perm_str ( st.st_mode       & 7, ps); printf ("other::%s\n", ps);
        }
    }
    printf ("\n");
    return 0;
}

/* -R: the operand, then everything below it; symbolic links below the
   operand are skipped (GNU's default walk). */
static int
show_tree (const char *path, int omit_header, int selection, int recursive, int top)
{
    struct stat st;
    if (!top && lstat (path, &st) == 0 && S_ISLNK (st.st_mode)) return 0;
    int rc = show_file (path, omit_header, selection) < 0 ? -1 : 0;
    if (!recursive || stat (path, &st) < 0 || !S_ISDIR (st.st_mode)) return rc;
    DIR *d = opendir (path);
    if (!d) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        size_t len = strlen (path) + strlen (de->d_name) + 2;
        char *child = malloc (len);
        if (!child) { closedir (d); builtin_error ("out of memory"); return -1; }
        snprintf (child, len, "%s%s%s", path, path[strlen (path) - 1] == '/' ? "" : "/", de->d_name);
        if (show_tree (child, omit_header, selection, recursive, 0) < 0) rc = -1;
        free (child);
    }
    closedir (d);
    return rc;
}

int
getfacl_builtin (WORD_LIST *list)
{
    int omit_header = 0, selection = 0, recursive = 0;
    gf_absolute = 0; gf_warned = 0; gf_numeric = 0; gf_effective = 0; gf_skip_base = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *getfacl_doc[]; for (char **lp = getfacl_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-a") || !strcmp (w, "--access")) { selection |= 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--default")) { selection |= 2; list = list->next; continue; }
        if (!strcmp (w, "-c") || !strcmp (w, "--omit-header")) { omit_header = 1; list = list->next; continue; }
        /* -p/--absolute-names controls leading-'/' stripping in the "# file:"
           name, NOT the header — it must NOT suppress the header (GNU getfacl). */
        if (!strcmp (w, "-p") || !strcmp (w, "--absolute-names")) { gf_absolute = 1; list = list->next; continue; }
        if (!strcmp (w, "-R") || !strcmp (w, "--recursive")) { recursive = 1; list = list->next; continue; }
        if (!strcmp (w, "-P") || !strcmp (w, "--physical") || !strcmp (w, "-L") || !strcmp (w, "--logical")) { list = list->next; continue; }
        if (!strcmp (w, "--numeric")) { gf_numeric = 1; list = list->next; continue; }
        if (!strcmp (w, "--all-effective")) { gf_effective = 1; list = list->next; continue; }
        if (!strcmp (w, "--no-effective")) { gf_effective = -1; list = list->next; continue; }
        if (!strcmp (w, "--skip-base")) { gf_skip_base = 1; list = list->next; continue; }
        /* Short options, alone or clustered: -nc, -cR, -Rp, -ac ... */
        if (w[1] != '-' && strspn (w + 1, "adcpRPLneEs") == strlen (w + 1)) {
            for (const char *c = w + 1; *c; c++)
                switch (*c) {
                case 'a': selection |= 1; break;
                case 'd': selection |= 2; break;
                case 'c': omit_header = 1; break;
                case 'p': gf_absolute = 1; break;
                case 'R': recursive = 1; break;
                case 'n': gf_numeric = 1; break;
                case 'e': gf_effective = 1; break;
                case 'E': gf_effective = -1; break;
                case 's': gf_skip_base = 1; break;
                }
            list = list->next;
            continue;
        }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (!list) { builtin_error ("no files specified"); builtin_usage (); return EX_USAGE; }
    if (!selection) selection = 3;
    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (show_tree (p->word->word, omit_header, selection, recursive, 1) < 0) rc = EXECUTION_FAILURE;
    return rc;
}

char *getfacl_doc[] = {
    "Display POSIX.1e file access control lists.",
    "",
    "    getfacl [-adcpRnesE] [--omit-header] file...",
    "",
    "    -a  access ACL only   -d  default ACL only (directories)",
    "    Without -a/-d, show both ACLs; default entries have default: prefixes.",
    "    -c, --omit-header  suppress the # file/owner/group header",
    "    -R, --recursive    list directories' contents too",
    "    -p, --absolute-names  keep a leading '/' in the # file: name",
    "    -n, --numeric      numeric user and group ids",
    "    -e, --all-effective  #effective comment on every masked entry",
    "    -E, --no-effective   no #effective comments",
    "    -s, --skip-base    skip files that have only the base ACL entries",
    "",
    "Files with no extended ACL show base entries derived from the mode.",
    (char *) NULL
};

struct builtin getfacl_struct = {
    "getfacl",
    getfacl_builtin,
    BUILTIN_ENABLED,
    getfacl_doc,
    "getfacl [-adcpRnesE] [--omit-header] file...",
    0
};
