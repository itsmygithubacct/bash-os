/* SPDX-License-Identifier: MIT */
/* setfacl.c — set POSIX.1e file access control lists, as a bash builtin.
 *
 *   setfacl -m ACL  file...     modify/add entries
 *   setfacl -x ACL  file...     remove entries
 *   setfacl -b      file...     remove all extended ACL entries
 *   setfacl --set ACL file...   replace the ACL entirely
 *   setfacl -d/-k/-R, --restore=FILE   default ACLs, recursion, restore
 *
 * ACL spec is a comma list of:  u:user:perms  g:group:perms  u::perms
 * g::perms  o::perms  m::perms  (perms = rwx letters or an octal digit).
 *
 * Reads/writes the system.posix_acl_access xattr; the kernel keeps the file
 * mode in sync. Requires write access (usually ownership) to the file.
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
#include <ctype.h>
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
#define XACCESS "system.posix_acl_access"
#define XDEFAULT "system.posix_acl_default"

typedef struct { uint16_t tag; uint16_t perm; uint32_t id; } aclent;

#define MAXENT 256
static aclent ents[MAXENT];
static int nent;

static void wr16 (unsigned char *p, uint16_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; }
static void wr32 (unsigned char *p, uint32_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }
static uint16_t rd16 (const unsigned char *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t rd32 (const unsigned char *p) { return (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24)); }

static int add_or_replace (uint16_t tag, uint32_t id, uint16_t perm) {
    for (int i = 0; i < nent; i++)
        if (ents[i].tag == tag && (tag != ACL_USER && tag != ACL_GROUP ? 1 : ents[i].id == id)) {
            ents[i].perm = perm; return 0;
        }
    if (nent >= MAXENT) { builtin_error ("too many ACL entries"); return -1; }
    ents[nent].tag = tag; ents[nent].id = id; ents[nent].perm = perm; nent++;
    return 0;
}
/* Like GNU setfacl, removing an entry the ACL does not have is no error. */
static int remove_ent (uint16_t tag, uint32_t id, int has_id) {
    int w = 0;
    for (int i = 0; i < nent; i++) {
        int match = (ents[i].tag == tag) && (!has_id || ents[i].id == id);
        if (!match) ents[w++] = ents[i];
    }
    nent = w;
    return 0;
}

/* Load the current ACL into ents[]: from the xattr if present, else the three
   base entries from the mode. */
static int load_current (const char *path) {
    nent = 0;
    unsigned char buf[8192];
    ssize_t n = getxattr (path, XACCESS, buf, sizeof buf);
    if (n >= 8 && rd32 (buf) == 2) {
        if ((n - 4) % 8 || (n - 4) / 8 > MAXENT) { errno = E2BIG; return -1; }
        for (ssize_t off = 4; off + 8 <= n; off += 8) {
            ents[nent].tag = rd16 (buf+off); ents[nent].perm = rd16 (buf+off+2); ents[nent].id = rd32 (buf+off+4); nent++;
        }
        return 0;
    }
    if (n < 0 && errno != ENODATA) return -1;
    if (n >= 0) { errno = EINVAL; return -1; }
    struct stat st;
    if (stat (path, &st) < 0) return -1;
    add_or_replace (ACL_USER_OBJ,  ACL_UNDEFINED_ID, (st.st_mode>>6)&7);
    add_or_replace (ACL_GROUP_OBJ, ACL_UNDEFINED_ID, (st.st_mode>>3)&7);
    add_or_replace (ACL_OTHER,     ACL_UNDEFINED_ID,  st.st_mode    &7);
    return 0;
}

/* Parse a perm string ("rwx", "r-x", or an octal digit) → bits, or -1. */
static int parse_perm (const char *s) {
    if (s[0] >= '0' && s[0] <= '7' && s[1] == '\0') return s[0]-'0';
    int p = 0;
    for (const char *c = s; *c; c++) {
        switch (*c) {
            case 'r': p |= 4; break; case 'w': p |= 2; break;
            case 'x': p |= 1; break; case '-': break;
            default: return -1;
        }
    }
    return p;
}

/* Parse one ACL entry token. removing=1 means perms may be omitted. */
static int explicit_mask;
static int parse_one (char *tok, int removing) {
    /* split on ':' into up to 3 fields */
    char *f[3] = {0,0,0}; int nf = 0;
    char *p = tok;
    f[nf++] = p;
    while (*p && nf < 3) { if (*p == ':') { *p = '\0'; f[nf++] = p+1; } p++; }
    /* also handle the case of trailing ':' giving empty perms */
    const char *type = f[0];
    const char *name = (nf >= 2) ? f[1] : "";
    const char *perms = (nf >= 3) ? f[2] : "";

    if (nf < 2 || (removing ? nf != 2 : nf != 3 || !*perms) ||
        (nf == 3 && strchr (perms, ':'))) {
        builtin_error ("invalid ACL entry"); return -1;
    }
    uint16_t tag; uint32_t id = ACL_UNDEFINED_ID;
    int named = (name && *name);

    if (!strcmp (type, "u") || !strcmp (type, "user"))       tag = named ? ACL_USER : ACL_USER_OBJ;
    else if (!strcmp (type, "g") || !strcmp (type, "group")) tag = named ? ACL_GROUP : ACL_GROUP_OBJ;
    else if (!strcmp (type, "o") || !strcmp (type, "other")) tag = ACL_OTHER;
    else if (!strcmp (type, "m") || !strcmp (type, "mask"))  tag = ACL_MASK;
    else { builtin_error ("invalid ACL type: %s", type); return -1; }

    if (named && tag != ACL_USER && tag != ACL_GROUP) {
        builtin_error ("invalid ACL qualifier: %s", name); return -1;
    }
    if (named) {
        if (tag == ACL_USER) {
            if (name[0] >= '0' && name[0] <= '9') {
                char *end; unsigned long value;
                errno = 0; value = strtoul (name, &end, 10);
                if (errno || *end || value >= ACL_UNDEFINED_ID) { builtin_error ("invalid ACL id: %s", name); return -1; }
                id = (uint32_t) value;
            }
            else { struct passwd *pw = getpwnam (name); if (!pw) { builtin_error ("unknown user: %s", name); return -1; } id = pw->pw_uid; }
        } else if (tag == ACL_GROUP) {
            if (name[0] >= '0' && name[0] <= '9') {
                char *end; unsigned long value;
                errno = 0; value = strtoul (name, &end, 10);
                if (errno || *end || value >= ACL_UNDEFINED_ID) { builtin_error ("invalid ACL id: %s", name); return -1; }
                id = (uint32_t) value;
            }
            else { struct group *gr = getgrnam (name); if (!gr) { builtin_error ("unknown group: %s", name); return -1; } id = gr->gr_gid; }
        }
    }

    if (removing) return remove_ent (tag, id, named);

    int perm = parse_perm (perms);
    if (perm < 0) { builtin_error ("invalid permissions: %s", perms); return -1; }
    if (tag == ACL_MASK) explicit_mask = 1;
    return add_or_replace (tag, id, (uint16_t) perm);
}

static int parse_spec (const char *spec, int removing) {
    if (!*spec || *spec == ',' || spec[strlen (spec)-1] == ',' || strstr (spec, ",,")) {
        builtin_error ("invalid ACL specification"); return -1;
    }
    char *dup = strdup (spec); if (!dup) return -1;
    int rc = 0;
    char *save = NULL, *tok = strtok_r (dup, ",", &save);
    while (tok) { rc = parse_one (tok, removing); if (rc < 0) break; tok = strtok_r (NULL, ",", &save); }
    free (dup);
    return rc;
}

/* Recompute an existing or required mask unless this operation specifies one. */
static int fix_mask (void) {
    int has_named = 0, has_mask = 0; unsigned u = 0;
    for (int i = 0; i < nent; i++) {
        if (ents[i].tag == ACL_USER || ents[i].tag == ACL_GROUP) has_named = 1;
        if (ents[i].tag == ACL_USER || ents[i].tag == ACL_GROUP || ents[i].tag == ACL_GROUP_OBJ) u |= ents[i].perm;
        if (ents[i].tag == ACL_MASK) has_mask = 1;
    }
    if (!explicit_mask && (has_named || has_mask)) return add_or_replace (ACL_MASK, ACL_UNDEFINED_ID, (uint16_t) u);
    return 0;
}

static int tag_order (uint16_t t) {
    switch (t) { case ACL_USER_OBJ: return 0; case ACL_USER: return 1; case ACL_GROUP_OBJ: return 2;
                 case ACL_GROUP: return 3; case ACL_MASK: return 4; case ACL_OTHER: return 5; } return 6;
}

static int encode_and_set (const char *path, const char *xname) {
    /* canonical order: USER_OBJ, USER(by id), GROUP_OBJ, GROUP(by id), MASK, OTHER */
    for (int i = 0; i < nent; i++)
        for (int j = i+1; j < nent; j++) {
            int oi = tag_order (ents[i].tag), oj = tag_order (ents[j].tag);
            if (oj < oi || (oj == oi && ents[j].id < ents[i].id)) { aclent t = ents[i]; ents[i] = ents[j]; ents[j] = t; }
        }
    unsigned char buf[4 + MAXENT*8];
    wr32 (buf, 2);
    int off = 4;
    for (int i = 0; i < nent; i++) {
        wr16 (buf+off, ents[i].tag); wr16 (buf+off+2, ents[i].perm); wr32 (buf+off+4, ents[i].id); off += 8;
    }
    if (setxattr (path, xname, buf, off, 0) < 0) {
        /* A minimal ACL is just the mode: GNU setfacl falls back to chmod
           where the file system has no ACL support. */
        struct stat st;
        if (!strcmp (xname, XACCESS) && (errno == EOPNOTSUPP || errno == ENOSYS) && nent == 3 && stat (path, &st) == 0) {
            mode_t mode = st.st_mode & 07000;
            for (int i = 0; i < nent; i++)
                mode |= ents[i].tag == ACL_USER_OBJ ? (mode_t) ents[i].perm << 6
                      : ents[i].tag == ACL_GROUP_OBJ ? (mode_t) ents[i].perm << 3
                      : (mode_t) ents[i].perm;
            if (chmod (path, mode) == 0)
                return 0;
        }
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    return 0;
}

/* Default ACL: the xattr, or (GNU) the access ACL's base entries when the
   directory has none yet. */
static int load_default (const char *path) {
    unsigned char buf[8192];
    ssize_t n = getxattr (path, XDEFAULT, buf, sizeof buf);
    if (n >= 8 && rd32 (buf) == 2) {
        if ((n - 4) % 8 || (n - 4) / 8 > MAXENT) { errno = E2BIG; return -1; }
        nent = 0;
        for (ssize_t off = 4; off + 8 <= n; off += 8) {
            ents[nent].tag = rd16 (buf+off); ents[nent].perm = rd16 (buf+off+2); ents[nent].id = rd32 (buf+off+4); nent++;
        }
        return 0;
    }
    if (n < 0 && errno != ENODATA) return -1;
    if (load_current (path) < 0) return -1;
    int w = 0;
    for (int i = 0; i < nent; i++)
        if (ents[i].tag == ACL_USER_OBJ || ents[i].tag == ACL_GROUP_OBJ || ents[i].tag == ACL_OTHER) ents[w++] = ents[i];
    nent = w;
    return 0;
}

/* Split SPEC into access and default parts: "d:"/"default:" entries (or
   every entry under -d) go to the default ACL. Both results are malloc'd
   comma lists, possibly empty. */
static int split_spec (const char *spec, int all_default, char **acc, char **def) {
    size_t n = strlen (spec) + 1;
    *acc = calloc (1, n); *def = calloc (1, n);
    char *dup = strdup (spec);
    if (!*acc || !*def || !dup) { free (*acc); free (*def); free (dup); builtin_error ("out of memory"); return -1; }
    if (!*spec || *spec == ',' || spec[strlen (spec)-1] == ',' || strstr (spec, ",,")) {
        free (dup); builtin_error ("invalid ACL specification"); return -1;
    }
    char *save = NULL;
    for (char *tok = strtok_r (dup, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        int d = all_default;
        while (*tok == ' ' || *tok == '\t' || *tok == '\n') tok++;
        if (!strncmp (tok, "d:", 2)) { d = 1; tok += 2; }
        else if (!strncmp (tok, "default:", 8)) { d = 1; tok += 8; }
        char *dst = d ? *def : *acc;
        if (*dst) strcat (dst, ",");
        strcat (dst, tok);
    }
    free (dup);
    return 0;
}

typedef struct {
    const char *mod, *del, *setspec;
    int do_b, do_k, dflag, recursive, no_mask, force_mask, logical;
} sf_ops;

static int sf_apply_acl (const char *path, int is_default, const char *setspec,
                         const char *del, const char *mod, int strip, const sf_ops *o) {
    explicit_mask = 0;
    if (setspec) {
        nent = 0;
        if (parse_spec (setspec, 0) < 0) return 2;
    } else {
        if ((is_default ? load_default (path) : load_current (path)) < 0) {
            builtin_error ("%s: %s", path, strerror (errno)); return 1;
        }
        if (strip) {
            int w = 0;
            for (int i = 0; i < nent; i++)
                if (ents[i].tag == ACL_USER_OBJ || ents[i].tag == ACL_GROUP_OBJ || ents[i].tag == ACL_OTHER) ents[w++] = ents[i];
            nent = w;
        }
        if (del && *del && parse_spec (del, 1) < 0) return 2;
        if (mod && *mod && parse_spec (mod, 0) < 0) return 2;
    }
    if (o->no_mask && !o->force_mask) explicit_mask = 1;
    if (o->force_mask) explicit_mask = 0;
    if (fix_mask () < 0) return 1;
    return encode_and_set (path, is_default ? XDEFAULT : XACCESS) < 0 ? 1 : 0;
}

static int sf_one (const char *path, const sf_ops *o, const char *am, const char *dm,
                   const char *ax, const char *dx, const char *as, const char *ds, int top) {
    struct stat st;
    if ((top || o->logical ? stat (path, &st) : lstat (path, &st)) < 0) {
        builtin_error ("%s: %s", path, strerror (errno)); return 1;
    }
    int isdir = S_ISDIR (st.st_mode), rc = 0;
    if (S_ISLNK (st.st_mode)) return 0;     /* -R skips symlinks below the top */
    int want_default = (dm && *dm) || (dx && *dx) || (ds && *ds);
    if (want_default && !isdir) {
        if (top && !o->recursive) {
            fflush (stdout);
            fprintf (stderr, "setfacl: %s: Only directories can have default ACLs\n", path);
            return 1;
        }
        want_default = 0;
    }
    int want_access = o->do_b || (am && *am) || (ax && *ax) || (as && *as);
    if (want_access) {
        int r = sf_apply_acl (path, 0, as && *as ? as : NULL, ax, am, o->do_b, o);
        if (r == 2) return 2;
        rc |= r;
    }
    if (isdir && (o->do_b || o->do_k) && !want_default) {
        if (removexattr (path, XDEFAULT) < 0 && errno != ENODATA && errno != EOPNOTSUPP) {
            builtin_error ("%s: %s", path, strerror (errno)); rc = 1;
        }
    }
    if (want_default) {
        int r = sf_apply_acl (path, 1, ds && *ds ? ds : NULL, dx, dm, o->do_k, o);
        if (r == 2) return 2;
        rc |= r;
    }
    if (o->recursive && isdir) {
        DIR *d = opendir (path);
        if (!d) { builtin_error ("%s: %s", path, strerror (errno)); return 1; }
        struct dirent *de;
        while ((de = readdir (d)) != NULL) {
            if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
            size_t len = strlen (path) + strlen (de->d_name) + 2;
            char *child = malloc (len);
            if (!child) { closedir (d); builtin_error ("out of memory"); return 1; }
            snprintf (child, len, "%s%s%s", path, path[strlen (path) - 1] == '/' ? "" : "/", de->d_name);
            int r = sf_one (child, o, am, dm, ax, dx, as, ds, 0);
            free (child);
            if (r == 2) { closedir (d); return 2; }
            rc |= r;
        }
        closedir (d);
    }
    return rc;
}

/* --restore=FILE: apply getfacl output. Records start at "# file: NAME";
   "default:" lines are the default ACL; #effective comments are ignored. */
static int sf_restore (const char *file, const sf_ops *base) {
    FILE *fp = !strcmp (file, "-") ? stdin : fopen (file, "r");
    if (!fp) { builtin_error ("%s: %s", file, strerror (errno)); return 1; }
    char line[4096], name[4096] = "";
    size_t accl = 4096, defl = 4096;
    char *acc = calloc (1, accl), *def = calloc (1, defl);
    int rc = 0, lineno = 0, have = 0;
    sf_ops o = *base;
    o.no_mask = 1;          /* the saved mask is restored as written */
    if (!acc || !def) { builtin_error ("out of memory"); rc = 1; goto out; }
    for (;;) {
        char *got = fgets (line, sizeof line, fp);
        if (got) lineno++;
        char *nl = got ? strchr (line, '\n') : NULL;
        if (nl) *nl = '\0';
        if (!got || !*line) {
            if (have) {
                if (!*acc) { builtin_error ("%s: line %d: missing ACL", file, lineno); rc = 1; }
                else {
                    struct stat st;
                    int r = 0;
                    if (stat (name, &st) < 0) { builtin_error ("%s: %s", name, strerror (errno)); r = 1; }
                    else {
                        r = sf_apply_acl (name, 0, acc, NULL, NULL, 0, &o);
                        if (!r && S_ISDIR (st.st_mode)) {
                            if (*def) r = sf_apply_acl (name, 1, def, NULL, NULL, 0, &o);
                            else if (removexattr (name, XDEFAULT) < 0 && errno != ENODATA && errno != EOPNOTSUPP)
                                { builtin_error ("%s: %s", name, strerror (errno)); r = 1; }
                        }
                    }
                    if (r == 2) { rc = 1; goto out; }
                    rc |= r;
                }
            }
            have = 0; acc[0] = def[0] = '\0'; name[0] = '\0';
            if (!got) break;
            continue;
        }
        if (!strncmp (line, "# file: ", 8)) { snprintf (name, sizeof name, "%s", line + 8); have = 1; continue; }
        if (line[0] == '#') continue;
        if (!have) { builtin_error ("%s: line %d: missing file name", file, lineno); rc = 1; goto out; }
        char *hash = strchr (line, '#');
        if (hash) *hash = '\0';
        size_t e = strlen (line);
        while (e && (line[e-1] == ' ' || line[e-1] == '\t')) line[--e] = '\0';
        int d = 0;
        char *ent = line;
        if (!strncmp (ent, "default:", 8)) { d = 1; ent += 8; }
        char **dst = d ? &def : &acc;
        size_t *cap = d ? &defl : &accl;
        size_t need = strlen (*dst) + strlen (ent) + 2;
        if (need > *cap) {
            char *g = realloc (*dst, need * 2);
            if (!g) { builtin_error ("out of memory"); rc = 1; goto out; }
            *dst = g; *cap = need * 2;
        }
        if (**dst) strcat (*dst, ",");
        strcat (*dst, ent);
    }
out:
    free (acc); free (def);
    if (fp != stdin) fclose (fp);
    return rc;
}

static const char *sf_value (WORD_LIST **lp, const char *w, const char *longname) {
    size_t ll = strlen (longname);
    if (!strncmp (w, longname, ll) && w[ll] == '=') return w + ll + 1;
    if ((*lp)->next) { *lp = (*lp)->next; return (*lp)->word->word; }
    builtin_error ("%s requires an argument", w);
    return NULL;
}

/* -M/-X/--set-file FILE: ACL entries one or more per line, '#' comments
   and blank lines ignored ("-" is standard input), as acl's setfacl reads
   them. Returns the entries joined with commas, NULL on error. */
static char *
sf_read_spec_file (const char *path, const char *prev)
{
    FILE *fp = strcmp (path, "-") ? fopen (path, "r") : stdin;
    if (!fp) { builtin_error ("%s: %s", path, strerror (errno)); return NULL; }
    size_t cap = 256, len = 0;
    char *out = xmalloc (cap);
    out[0] = '\0';
    if (prev && *prev) {
        len = strlen (prev);
        while (cap < len + 2) cap *= 2;
        out = xrealloc (out, cap);
        memcpy (out, prev, len + 1);
    }
    char *line = NULL; size_t lc = 0; ssize_t rd;
    while ((rd = getline (&line, &lc, fp)) != -1) {
        char *h = strchr (line, '#');
        if (h) *h = '\0';
        for (char *t = strtok (line, " \t\r\n,"); t; t = strtok (NULL, " \t\r\n,")) {
            size_t tl = strlen (t);
            while (cap < len + tl + 2) cap *= 2;
            out = xrealloc (out, cap);
            if (len) out[len++] = ',';
            memcpy (out + len, t, tl + 1);
            len += tl;
        }
    }
    free (line);
    if (fp != stdin) fclose (fp); else clearerr (stdin);
    return out;
}

int
setfacl_builtin (WORD_LIST *list)
{
    sf_ops o = {0};
    const char *restore = NULL;
    /* Entry lists read from -M/-X/--set-file live until the next call. */
    static char *file_mod, *file_del, *file_set;
    free (file_mod); free (file_del); free (file_set);
    file_mod = file_del = file_set = NULL;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *setfacl_doc[]; for (char **lp = setfacl_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (w[1] == '-') {
            const char **slot = NULL;
            if (!strncmp (w, "--modify", 8) && (!w[8] || w[8] == '=')) slot = &o.mod;
            else if (!strncmp (w, "--remove", 8) && (!w[8] || w[8] == '=')) slot = &o.del;
            else if (!strncmp (w, "--set", 5) && (!w[5] || w[5] == '=')) slot = &o.setspec;
            else if (!strncmp (w, "--restore", 9) && (!w[9] || w[9] == '=')) slot = &restore;
            if (slot) {
                const char *v = sf_value (&list, w, !strncmp (w, "--modify", 8) ? "--modify"
                                         : !strncmp (w, "--remove", 8) ? "--remove"
                                         : !strncmp (w, "--set", 5) && w[5] != 't' ? "--set" : "--restore");
                if (!v) return EX_USAGE;
                *slot = v; list = list->next; continue;
            }
            if (!strncmp (w, "--modify-file", 13) || !strncmp (w, "--remove-file", 13) || !strncmp (w, "--set-file", 10)) {
                int kind = w[2] == 'm' ? 'M' : w[4] == 'm' ? 'X' : 'S';
                const char *name = kind == 'M' ? "--modify-file" : kind == 'X' ? "--remove-file" : "--set-file";
                if (strncmp (w, name, strlen (name)) || (w[strlen (name)] && w[strlen (name)] != '=')) {
                    builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
                }
                const char *v = sf_value (&list, w, name);
                if (!v) return EX_USAGE;
                char **slot = kind == 'M' ? &file_mod : kind == 'X' ? &file_del : &file_set;
                const char **ospec = kind == 'M' ? &o.mod : kind == 'X' ? &o.del : &o.setspec;
                char *r = sf_read_spec_file (v, *ospec);
                if (!r) return EX_USAGE;
                free (*slot); *slot = r; *ospec = r;
                list = list->next; continue;
            }
            if (!strcmp (w, "--remove-all")) o.do_b = 1;
            else if (!strcmp (w, "--remove-default")) o.do_k = 1;
            else if (!strcmp (w, "--default")) o.dflag = 1;
            else if (!strcmp (w, "--recursive")) o.recursive = 1;
            else if (!strcmp (w, "--no-mask")) o.no_mask = 1;
            else if (!strcmp (w, "--mask")) o.force_mask = 1;
            else if (!strcmp (w, "--physical")) o.logical = 0;
            else if (!strcmp (w, "--logical")) o.logical = 1;
            else { builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        int consumed = 0;
        for (int i = 1; w[i] && !consumed; i++) {
            switch (w[i]) {
            case 'b': o.do_b = 1; break;
            case 'k': o.do_k = 1; break;
            case 'd': o.dflag = 1; break;
            case 'R': o.recursive = 1; break;
            case 'n': o.no_mask = 1; break;
            case 'P': o.logical = 0; break;
            case 'L': o.logical = 1; break;
            case 'm': case 'x': case 'M': case 'X': {
                const char *v;
                if (w[i+1]) v = w + i + 1;
                else if (list->next) { list = list->next; v = list->word->word; }
                else { builtin_error ("-%c requires an argument", w[i]); return EX_USAGE; }
                if (w[i] == 'm') o.mod = v;
                else if (w[i] == 'x') o.del = v;
                else {
                    char **slot = w[i] == 'M' ? &file_mod : &file_del;
                    const char **ospec = w[i] == 'M' ? &o.mod : &o.del;
                    char *r = sf_read_spec_file (v, *ospec);
                    if (!r) return EX_USAGE;
                    free (*slot); *slot = r; *ospec = r;
                }
                consumed = 1;
                break;
            }
            default:
                builtin_error ("unknown option: -%c", w[i]); builtin_usage (); return EX_USAGE;
            }
        }
        list = list->next;
    }

    if (restore) {
        if (list) { builtin_error ("--restore takes no file operands"); return EX_USAGE; }
        return sf_restore (restore, &o) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }
    if (!o.mod && !o.del && !o.setspec && !o.do_b && !o.do_k) { builtin_error ("need one of -m, -x, -b, -k, --set, --restore"); builtin_usage (); return EX_USAGE; }
    if (!list) { builtin_error ("no files specified"); builtin_usage (); return EX_USAGE; }

    char *am = NULL, *dm = NULL, *ax = NULL, *dx = NULL, *as = NULL, *ds = NULL;
    int rc = EXECUTION_SUCCESS;
    if ((o.mod && split_spec (o.mod, o.dflag, &am, &dm) < 0) ||
        (o.del && split_spec (o.del, o.dflag, &ax, &dx) < 0) ||
        (o.setspec && split_spec (o.setspec, o.dflag, &as, &ds) < 0)) { rc = EX_USAGE; goto out; }
    for (WORD_LIST *p = list; p; p = p->next) {
        int r = sf_one (p->word->word, &o, am, dm, ax, dx, as, ds, 1);
        if (r == 2) { rc = EX_USAGE; break; }
        if (r) rc = EXECUTION_FAILURE;
    }
out:
    free (am); free (dm); free (ax); free (dx); free (as); free (ds);
    return rc;
}

char *setfacl_doc[] = {
    "Set POSIX.1e file access control lists.",
    "",
    "    setfacl -m ACL file...     add/modify entries",
    "    setfacl -x ACL file...     remove entries",
    "    setfacl -b file...         remove all extended entries",
    "    setfacl --set ACL file...  replace the ACL",
    "    setfacl -M FILE | -X FILE | --set-file=FILE file...",
    "                     the -m / -x / --set entries read from FILE (- is stdin);",
    "                     one or more per line, # comments ignored",
    "    setfacl -k file...         remove the default ACL",
    "    setfacl --restore=FILE     apply getfacl output (\"-\": stdin)",
    "",
    "    -d, --default    -m/-x/--set apply to the default ACL (or prefix an",
    "                     entry with d: / default:); directories only",
    "    -R, --recursive  apply to directories and their contents; symbolic",
    "                     links below the operands are skipped unless -L",
    "    -n, --no-mask    do not recalculate the mask; --mask always does",
    "    -b also removes a directory's default ACL.",
    "",
    "ACL: comma list of u:user:perms g:group:perms u::perms g::perms",
    "     o::perms m::perms  (perms = rwx letters or an octal digit).",
    (char *) NULL
};

struct builtin setfacl_struct = {
    "setfacl",
    setfacl_builtin,
    BUILTIN_ENABLED,
    setfacl_doc,
    "setfacl [-bkndRLP] [-m ACL] [-x ACL] [--set ACL] file... | --restore=FILE",
    0
};
