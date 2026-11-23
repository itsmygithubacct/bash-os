/* SPDX-License-Identifier: MIT */
/* pax.c — upstream bash-os bashpax.c, vendored 2026-09-05 with the injector-visible
 * symbols renamed bashpax_builtin/bashpax_doc -> pax_builtin/pax_doc so the
 * command name is the POSIX one (third_party/bashy-box/SNAPSHOT.md). */
/* bashpax.c - POSIX ustar list/create/extract subset.
 *
 * D06 archive-format expansion: typeflag-aware extraction (directories,
 * symlinks, hardlinks), parent-dir creation, mtime preservation, ustar
 * checksum validation, and truncation detection on read; directory and
 * symlink emit on write. POSIX PAX headers ('x','g') and GNU long-name /
 * long-link headers ('L','K') are consumed on read. FIFO metadata is
 * supported along with character/block device metadata.
 * Sees `D04` hardening pass for the original
 * `..` rejection (which still applies to all member names and link
 * targets).
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <stdint.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <signal.h>
#include "loadables.h"
#include "pax-stream.h"
#include "child-wait.h"

static unsigned long octal(const char *s, size_t n){
    char b[32]; size_t j=0;
    for(size_t i=0;i<n&&j<sizeof(b)-1;i++) if(s[i]>='0'&&s[i]<='7') b[j++]=s[i];
    b[j]=0; return j?strtoul(b,NULL,8):0;
}
/* Write v as n-1 octal digits. A value that does not fit is clamped to the
   field's maximum — write_member has already emitted the exact value in a PAX
   extended header for the fields that can overflow (size, uid, gid). */
static void put_octal(char *dst, size_t n, unsigned long v){
    unsigned long max = (1UL << (3 * (n - 1))) - 1;
    if(v > max) v = max;
    snprintf(dst,n,"%0*lo",(int)n-1,v); dst[n-1]='\0';
}
#define PAX_EXT_SIZE 1
#define PAX_EXT_UID  2
#define PAX_EXT_GID  4
#define PAX_EXT_MTIME 8
/* Which numeric fields of st overflow their ustar octal field. */
static int pax_numeric_ext(const struct stat *st, int regular){
    int f = 0;
    if(regular && (unsigned long long)st->st_size > 077777777777ULL) f |= PAX_EXT_SIZE;   /* 11 octal digits */
    if((unsigned long)st->st_uid > 07777777UL) f |= PAX_EXT_UID;                            /* 7 octal digits */
    if((unsigned long)st->st_gid > 07777777UL) f |= PAX_EXT_GID;
    if(st->st_mtime < 0 || (unsigned long long)st->st_mtime > 077777777777ULL) f |= PAX_EXT_MTIME;
    return f;
}
/* Skip N bytes of the archive. fseek only works on a seekable file; on a
   pipe (cat x.tar | pax -r, ssh host cat x.tar | pax) it fails and leaves
   the stream where it was, so every later header read is misaligned. */
static int skip_bytes(FILE *f, unsigned long n){
    if(n == 0) return 0;
    unsigned char sink[4096];
    while(n){
        size_t want = n > sizeof sink ? sizeof sink : (size_t)n;
        size_t got = fread(sink, 1, want, f);
        if(got == 0){ builtin_error("archive truncated in member body"); return -1; }
        n -= got;
    }
    return 0;
}
static int zero_block(const unsigned char *b){ for(int i=0;i<512;i++) if(b[i]) return 0; return 1; }
static void name_from_hdr(char *out, unsigned char *h){
    char name[101], pref[156];
    memcpy(name,h,100); name[100]=0;
    memcpy(pref,h+345,155); pref[155]=0;
    if(pref[0]) snprintf(out,257,"%s/%s",pref,name); else snprintf(out,257,"%s",name);
}
static int unsafe_path(const char *name){
    if(!name||!*name||name[0]=='/') return 1;
    const char *p=name;
    while(*p){
        while(*p=='/') p++;
        const char *q=p;
        while(*q&&*q!='/') q++;
        if(q-p==2&&p[0]=='.'&&p[1]=='.') return 1;
        p=q;
    }
    return 0;
}

/* ustar checksum: sum of all 512 header bytes with the 8-byte checksum
   field treated as ASCII spaces during the sum. Returns 1 if the stored
   value matches, 0 if it does not. */
static int hdr_checksum_ok(const unsigned char *h){
    unsigned long stored = octal((const char *)h+148, 8);
    unsigned long sum = 0;
    for(int i=0;i<512;i++) sum += (i>=148 && i<156) ? (unsigned char)' ' : h[i];
    return sum == stored;
}

/* ---- tar --transform ---------------------------------------------------- */
#define XF_REG  1   /* member names */
#define XF_SYM  2   /* symlink targets */
#define XF_HARD 4   /* hardlink targets */
struct bashos_pax_xform {
    regex_t re;
    char *repl;
    int global, nth, scope;
    struct bashos_pax_xform *next;
};

void bashos_pax_xform_free(struct bashos_pax_xform **list){
    while(*list){
        struct bashos_pax_xform *next = (*list)->next;
        regfree(&(*list)->re); free((*list)->repl); free(*list);
        *list = next;
    }
}

/* One delimited field of s/REGEX/REPL/: "\DELIM" stands for DELIM, other
   escapes are kept for regcomp and the replacement. */
static const char *xform_field(const char *p, char delim, char **out){
    size_t n = strlen(p);
    char *buf = malloc(n + 1), *w = buf;
    if(!buf) return NULL;
    while(*p && *p != delim){
        if(*p == '\\' && p[1] == delim){ *w++ = delim; p += 2; continue; }
        if(*p == '\\' && p[1]){ *w++ = *p++; }
        *w++ = *p++;
    }
    *w = 0;
    if(*p != delim){ free(buf); return NULL; }
    *out = buf;
    return p + 1;
}

int bashos_pax_xform_add(struct bashos_pax_xform **list, const char *expr){
    const char *p = expr;
    while(*p){
        while(*p == ';') p++;
        if(!*p) break;
        if(*p != 's' || !p[1]){ builtin_error("Invalid transform expression"); return -1; }
        char delim = p[1];
        char *regex = NULL, *repl = NULL;
        p = xform_field(p + 2, delim, &regex);
        if(p) p = xform_field(p, delim, &repl);
        if(!p){ free(regex); builtin_error("Invalid transform expression"); return -1; }
        int cflags = 0, global = 0, nth = 0, scope = 0, unscope = 0;
        for(; *p && *p != ';'; p++){
            switch(*p){
            case 'g': global = 1; break;
            case 'i': cflags |= REG_ICASE; break;
            case 'x': cflags |= REG_EXTENDED; break;
            case 'r': scope |= XF_REG; break;
            case 'R': unscope |= XF_REG; break;
            case 's': scope |= XF_SYM; break;
            case 'S': unscope |= XF_SYM; break;
            case 'h': scope |= XF_HARD; break;
            case 'H': unscope |= XF_HARD; break;
            default:
                if(*p >= '0' && *p <= '9'){ nth = nth * 10 + (*p - '0'); break; }
                builtin_error("Unknown flag in transform expression: %c", *p);
                free(regex); free(repl); return -1;
            }
        }
        struct bashos_pax_xform *x = calloc(1, sizeof *x);
        if(!x){ free(regex); free(repl); builtin_error("out of memory"); return -1; }
        int err = regcomp(&x->re, regex, cflags);
        free(regex);
        if(err){
            char msg[128]; regerror(err, &x->re, msg, sizeof msg);
            builtin_error("Invalid transform expression: %s", msg);
            free(repl); free(x); return -1;
        }
        x->repl = repl; x->global = global; x->nth = nth;
        x->scope = (scope ? scope : XF_REG | XF_SYM | XF_HARD) & ~unscope;
        struct bashos_pax_xform **tail = list;
        while(*tail) tail = &(*tail)->next;
        *tail = x;
    }
    return 0;
}

static int xform_put(char **buf, size_t *len, size_t *cap, const char *s, size_t n){
    if(*len + n + 1 > *cap){
        size_t nc = *cap ? *cap : 64;
        while(nc < *len + n + 1) nc *= 2;
        char *q = realloc(*buf, nc);
        if(!q) return -1;
        *buf = q; *cap = nc;
    }
    memcpy(*buf + *len, s, n); *len += n; (*buf)[*len] = 0;
    return 0;
}

/* NAME rewritten by every rule whose scope includes SCOPE (malloc'd), or
   NULL when out of memory. */
static char *xform_apply(const struct bashos_pax_xform *x, const char *name, int scope){
    char *cur = strdup(name);
    for(; cur && x; x = x->next){
        if(!(x->scope & scope)) continue;
        char *out = NULL; size_t len = 0, cap = 0;
        size_t pos = 0, n = strlen(cur);
        int count = 0, failed = 0;
        regmatch_t m[10];
        if(xform_put(&out, &len, &cap, "", 0) < 0){ free(cur); return NULL; }
        while(pos <= n && regexec(&x->re, cur + pos, 10, m, pos ? REG_NOTBOL : 0) == 0){
            size_t so = pos + (size_t)m[0].rm_so, eo = pos + (size_t)m[0].rm_eo;
            count++;
            failed |= xform_put(&out, &len, &cap, cur + pos, so - pos);
            if(x->nth && count < x->nth) failed |= xform_put(&out, &len, &cap, cur + so, eo - so);
            else {
                for(const char *r = x->repl; *r; r++){
                    if(*r == '&') failed |= xform_put(&out, &len, &cap, cur + so, eo - so);
                    else if(*r == '\\' && r[1] >= '0' && r[1] <= '9'){
                        int g = *++r - '0';
                        if(m[g].rm_so >= 0)
                            failed |= xform_put(&out, &len, &cap, cur + pos + m[g].rm_so,
                                                (size_t)(m[g].rm_eo - m[g].rm_so));
                    } else if(*r == '\\' && r[1] == 'n'){ r++; failed |= xform_put(&out, &len, &cap, "\n", 1); }
                    else if(*r == '\\' && r[1]){ r++; failed |= xform_put(&out, &len, &cap, r, 1); }
                    else failed |= xform_put(&out, &len, &cap, r, 1);
                }
            }
            if(eo == so){   /* an empty match: keep the next character and move on */
                if(so < n) failed |= xform_put(&out, &len, &cap, cur + so, 1);
                pos = so + 1;
            } else pos = eo;
            if(!x->global && (!x->nth || count >= x->nth)) break;
        }
        if(pos < n) failed |= xform_put(&out, &len, &cap, cur + pos, n - pos);
        free(cur);
        if(failed){ free(out); return NULL; }
        cur = out;
    }
    return cur;
}

/* --exclude: a pattern excludes NAME when it matches the whole name or any
   part after a '/' (GNU's unanchored default; '*' matches '/'). */
static int name_excluded(const char **pats, size_t npats, const char *path){
    if(!npats) return 0;
    char name[4096];
    snprintf(name, sizeof name, "%s", path);
    size_t n = strlen(name);
    while(n > 1 && name[n-1] == '/') name[--n] = '\0';
    for(size_t i = 0; i < npats; i++){
        for(const char *p = name; p; p = strchr(p, '/') ? strchr(p, '/') + 1 : NULL){
            if(!*p) break;
            if(fnmatch(pats[i], p, FNM_LEADING_DIR) == 0) return 1;
        }
    }
    return 0;
}

/* ---- POSIX ACLs (tar --acls) ---------------------------------------------
   Linux keeps an ACL in the system.posix_acl_* xattr as a 4-byte version (2)
   and 8-byte entries {u16 tag, u16 perm, u32 id}; GNU tar archives it as
   acl_to_text() output (one "tag:qualifier:rwx" per line). */
#define ACL_EA_VERSION 2
#define ACL_TAG_USER_OBJ  0x01
#define ACL_TAG_USER      0x02
#define ACL_TAG_GROUP_OBJ 0x04
#define ACL_TAG_GROUP     0x08
#define ACL_TAG_MASK      0x10
#define ACL_TAG_OTHER     0x20

/* The ACL in xattr KEY of PATH as text (malloc'd), or NULL when it has none. */
static char *acl_text(const char *path, const char *key){
    unsigned char buf[4096];
    ssize_t n = getxattr(path, key, buf, sizeof buf);
    if(n < 4 || (n - 4) % 8) return NULL;
    uint32_t version; memcpy(&version, buf, 4);
    if(version != ACL_EA_VERSION) return NULL;
    char *out = NULL; size_t len = 0, cap = 0;
    for(ssize_t i = 4; i < n; i += 8){
        uint16_t tag, perm; uint32_t id;
        memcpy(&tag, buf + i, 2); memcpy(&perm, buf + i + 2, 2); memcpy(&id, buf + i + 4, 4);
        const char *kind = tag == ACL_TAG_USER_OBJ || tag == ACL_TAG_USER ? "user" :
                           tag == ACL_TAG_GROUP_OBJ || tag == ACL_TAG_GROUP ? "group" :
                           tag == ACL_TAG_MASK ? "mask" : tag == ACL_TAG_OTHER ? "other" : NULL;
        if(!kind){ free(out); return NULL; }
        char qual[64] = "";
        if(tag == ACL_TAG_USER){
            struct passwd *pw = getpwuid((uid_t)id);
            snprintf(qual, sizeof qual, "%s", pw ? pw->pw_name : "");
            if(!pw) snprintf(qual, sizeof qual, "%lu", (unsigned long)id);
        } else if(tag == ACL_TAG_GROUP){
            struct group *gr = getgrgid((gid_t)id);
            snprintf(qual, sizeof qual, "%s", gr ? gr->gr_name : "");
            if(!gr) snprintf(qual, sizeof qual, "%lu", (unsigned long)id);
        }
        char line[128];
        int l = snprintf(line, sizeof line, "%s:%s:%c%c%c\n", kind, qual,
                         perm & 4 ? 'r' : '-', perm & 2 ? 'w' : '-', perm & 1 ? 'x' : '-');
        if(xform_put(&out, &len, &cap, line, (size_t)l) < 0){ free(out); return NULL; }
    }
    return out;
}

static int acl_entry_cmp(const void *a, const void *b){
    const unsigned char *x = a, *y = b;
    uint16_t tx, ty; uint32_t ix, iy;
    memcpy(&tx, x, 2); memcpy(&ty, y, 2); memcpy(&ix, x + 4, 4); memcpy(&iy, y + 4, 4);
    return tx != ty ? (tx < ty ? -1 : 1) : ix != iy ? (ix < iy ? -1 : 1) : 0;
}

/* Set xattr KEY of PATH from ACL text (lines or commas). Returns 0 or -1. */
static int acl_set_text(const char *path, const char *key, const char *text){
    unsigned char buf[4 + 8 * 256];
    size_t n = 4;
    uint32_t version = ACL_EA_VERSION; memcpy(buf, &version, 4);
    const char *p = text;
    while(*p){
        while(*p == '\n' || *p == ',' || *p == ' ' || *p == '\t') p++;
        if(!*p) break;
        if(*p == '#'){ while(*p && *p != '\n') p++; continue; }
        const char *e = p; while(*e && *e != '\n' && *e != ','){ e++; }
        char entry[256]; size_t el = (size_t)(e - p);
        if(el >= sizeof entry || n + 8 > sizeof buf){ errno = EINVAL; return -1; }
        memcpy(entry, p, el); entry[el] = 0; p = e;
        char *c1 = strchr(entry, ':'), *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        if(!c2){ errno = EINVAL; return -1; }
        *c1 = *c2 = 0;
        const char *tagname = entry, *qual = c1 + 1, *perms = c2 + 1;
        char *c3 = strchr(perms, ':'); if(c3) *c3 = 0;    /* ":effective" comments */
        uint16_t tag = 0, perm = 0; uint32_t id = 0xffffffffu;
        if(!strcmp(tagname, "user") || !strcmp(tagname, "u")) tag = *qual ? ACL_TAG_USER : ACL_TAG_USER_OBJ;
        else if(!strcmp(tagname, "group") || !strcmp(tagname, "g")) tag = *qual ? ACL_TAG_GROUP : ACL_TAG_GROUP_OBJ;
        else if(!strcmp(tagname, "mask") || !strcmp(tagname, "m")) tag = ACL_TAG_MASK;
        else if(!strcmp(tagname, "other") || !strcmp(tagname, "o")) tag = ACL_TAG_OTHER;
        else { errno = EINVAL; return -1; }
        if(tag == ACL_TAG_USER || tag == ACL_TAG_GROUP){
            char *end; unsigned long v = strtoul(qual, &end, 10);
            if(*qual && !*end) id = (uint32_t)v;
            else if(tag == ACL_TAG_USER){ struct passwd *pw = getpwnam(qual); if(!pw){ errno = EINVAL; return -1; } id = pw->pw_uid; }
            else { struct group *gr = getgrnam(qual); if(!gr){ errno = EINVAL; return -1; } id = gr->gr_gid; }
        }
        for(const char *q = perms; *q; q++){
            if(*q == 'r') perm |= 4; else if(*q == 'w') perm |= 2; else if(*q == 'x') perm |= 1;
            else if(*q != '-'){ errno = EINVAL; return -1; }
        }
        memcpy(buf + n, &tag, 2); memcpy(buf + n + 2, &perm, 2); memcpy(buf + n + 4, &id, 4);
        n += 8;
    }
    if(n == 4) return 0;
    qsort(buf + 4, (n - 4) / 8, 8, acl_entry_cmp);
    return setxattr(path, key, buf, n, 0);
}

/* ---- sparse members (tar -S) --------------------------------------------- */
struct sparse_seg { unsigned long long off, len; };
struct sparse_map { struct sparse_seg *v; size_t n, cap; };

static int sparse_add(struct sparse_map *m, unsigned long long off, unsigned long long len){
    if(m->n == m->cap){
        size_t cap = m->cap ? m->cap * 2 : 8;
        struct sparse_seg *v = realloc(m->v, cap * sizeof *v);
        if(!v) return -1;
        m->v = v; m->cap = cap;
    }
    m->v[m->n].off = off; m->v[m->n].len = len; m->n++;
    return 0;
}

/* The data segments of FD (size SIZE) when it has holes; 0 when it is
   stored whole, 1 with MAP filled (ending, as GNU's does, with a
   zero-length segment at SIZE when the file ends in a hole). */
static int sparse_scan(int fd, off_t size, struct sparse_map *m){
    off_t pos = 0;
    while(pos < size){
        off_t data = lseek(fd, pos, SEEK_DATA);
        if(data < 0){ if(errno == ENXIO) break; return 0; }
        off_t hole = lseek(fd, data, SEEK_HOLE);
        if(hole < 0) return 0;
        if(sparse_add(m, (unsigned long long)data, (unsigned long long)(hole - data)) < 0) return -1;
        pos = hole;
    }
    lseek(fd, 0, SEEK_SET);
    if(m->n == 1 && m->v[0].off == 0 && m->v[0].len == (unsigned long long)size){ m->n = 0; return 0; }
    if(!m->n || m->v[m->n-1].off + m->v[m->n-1].len < (unsigned long long)size)
        if(sparse_add(m, (unsigned long long)size, 0) < 0) return -1;
    return 1;
}

struct pax_meta {
    char *path, *linkpath, *uname, *gname;
    unsigned long size, uid, gid;
    time_t mtime;
    int has_size, has_mtime, has_uid, has_gid;
    int typeflag;
    /* GNU.sparse.* (PAX sparse formats 0.1 and 1.0) and SCHILY.acl.* */
    char *sparse_name, *sparse_map, *acl_access, *acl_default;
    unsigned long long sparse_realsize;
    int sparse_major, sparse_minor, has_sparse_realsize, has_sparse_major;
};

static void pax_meta_free(struct pax_meta *m){
    free(m->path); free(m->linkpath); free(m->uname); free(m->gname);
    free(m->sparse_name); free(m->sparse_map); free(m->acl_access); free(m->acl_default);
    memset(m, 0, sizeof *m);
}

static int pax_dup_field(char **dst, const char *src){
    if(!src) return 0;
    free(*dst);
    return (*dst = strdup(src)) ? 0 : -1;
}

static int pax_meta_copy(struct pax_meta *dst, const struct pax_meta *src){
    pax_meta_free(dst);
    if(src->path){ dst->path = strdup(src->path); if(!dst->path) return -1; }
    if(src->linkpath){ dst->linkpath = strdup(src->linkpath); if(!dst->linkpath) return -1; }
    if(src->uname){ dst->uname = strdup(src->uname); if(!dst->uname) return -1; }
    if(src->gname){ dst->gname = strdup(src->gname); if(!dst->gname) return -1; }
    dst->size = src->size; dst->mtime = src->mtime;
    dst->uid = src->uid; dst->gid = src->gid;
    dst->has_size = src->has_size; dst->has_mtime = src->has_mtime;
    dst->has_uid = src->has_uid; dst->has_gid = src->has_gid;
    dst->typeflag = src->typeflag;
    if(pax_dup_field(&dst->sparse_name, src->sparse_name) < 0 || pax_dup_field(&dst->sparse_map, src->sparse_map) < 0 ||
       pax_dup_field(&dst->acl_access, src->acl_access) < 0 || pax_dup_field(&dst->acl_default, src->acl_default) < 0)
        return -1;
    dst->sparse_realsize = src->sparse_realsize; dst->has_sparse_realsize = src->has_sparse_realsize;
    dst->sparse_major = src->sparse_major; dst->sparse_minor = src->sparse_minor;
    dst->has_sparse_major = src->has_sparse_major;
    return 0;
}

/* Move the fields LOCAL sets onto EFF (a copy of the global header). */
static void pax_meta_merge(struct pax_meta *eff, struct pax_meta *local){
#define MOVE(f) if(local->f){ free(eff->f); eff->f = local->f; local->f = NULL; }
    MOVE(path) MOVE(linkpath) MOVE(uname) MOVE(gname)
    MOVE(sparse_name) MOVE(sparse_map) MOVE(acl_access) MOVE(acl_default)
#undef MOVE
    if(local->has_size){ eff->size = local->size; eff->has_size = 1; }
    if(local->has_mtime){ eff->mtime = local->mtime; eff->has_mtime = 1; }
    if(local->has_uid){ eff->uid = local->uid; eff->has_uid = 1; }
    if(local->has_gid){ eff->gid = local->gid; eff->has_gid = 1; }
    if(local->typeflag) eff->typeflag = local->typeflag;
    if(local->has_sparse_realsize){ eff->sparse_realsize = local->sparse_realsize; eff->has_sparse_realsize = 1; }
    if(local->has_sparse_major){ eff->sparse_major = local->sparse_major; eff->sparse_minor = local->sparse_minor; eff->has_sparse_major = 1; }
}

static int pax_parse_decimal_ulong(const char *s, unsigned long *out){
    char *e; errno = 0; unsigned long v = strtoul(s, &e, 10);
    if(errno || e == s || (*e && *e != '\n')) return -1;
    *out = v; return 0;
}

static int pax_parse_time(const char *s, time_t *out){
    char *e;
    errno = 0;
    long long v = strtoll(s, &e, 10);
    if(errno || e == s || (long long)(time_t)v != v) return -1;
    if(*e == '.'){
        const char *fraction = ++e;
        while(*e >= '0' && *e <= '9') e++;
        if(e == fraction) return -1;
    }
    if(*e && *e != '\n') return -1;
    *out = (time_t)v;
    return 0;
}

static int pax_set_string(char **dst, const char *val, size_t n){
    char *p = malloc(n + 1);
    if(!p) return -1;
    memcpy(p, val, n); p[n] = 0;
    free(*dst); *dst = p; return 0;
}

static int pax_parse_records(const char *body, size_t len, struct pax_meta *m){
    size_t pos = 0;
    while(pos < len && body[pos]){
        char *e; errno = 0; unsigned long reclen = strtoul(body + pos, &e, 10);
        if(errno || e == body + pos || *e != ' ' || reclen == 0 || pos + reclen > len){
            builtin_error("malformed pax extended header record");
            return -1;
        }
        char *line = (char *)body + pos;
        char *kv = e + 1;
        char *nl = line + reclen - 1;
        if(*nl != '\n'){
            builtin_error("malformed pax extended header record: missing newline");
            return -1;
        }
        char *eq = memchr(kv, '=', (size_t)(nl - kv));
        if(eq){
            size_t klen = (size_t)(eq - kv), vlen = (size_t)(nl - eq - 1);
            const char *val = eq + 1;
            if(klen == 4 && !memcmp(kv, "path", 4)){
                if(pax_set_string(&m->path, val, vlen) < 0) return -1;
            } else if(klen == 8 && !memcmp(kv, "linkpath", 8)){
                if(pax_set_string(&m->linkpath, val, vlen) < 0) return -1;
            } else if(klen == 4 && !memcmp(kv, "size", 4)){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                if(pax_parse_decimal_ulong(tmp, &m->size) < 0) return -1;
                m->has_size = 1;
            } else if(klen == 5 && !memcmp(kv, "mtime", 5)){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                if(pax_parse_time(tmp, &m->mtime) < 0) return -1;
                m->has_mtime = 1;
            } else if(klen == 3 && (!memcmp(kv, "uid", 3) || !memcmp(kv, "gid", 3))){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                if(kv[0] == 'u'){ if(pax_parse_decimal_ulong(tmp, &m->uid) < 0) return -1; m->has_uid = 1; }
                else { if(pax_parse_decimal_ulong(tmp, &m->gid) < 0) return -1; m->has_gid = 1; }
            } else if(klen == 5 && !memcmp(kv, "uname", 5)){
                if(pax_set_string(&m->uname, val, vlen) < 0) return -1;
            } else if(klen == 5 && !memcmp(kv, "gname", 5)){
                if(pax_set_string(&m->gname, val, vlen) < 0) return -1;
            } else if(klen == 8 && !memcmp(kv, "typeflag", 8) && vlen){
                m->typeflag = (unsigned char)val[0];
            } else if(klen == 15 && !memcmp(kv, "GNU.sparse.name", 15)){
                if(pax_set_string(&m->sparse_name, val, vlen) < 0) return -1;
            } else if(klen == 14 && !memcmp(kv, "GNU.sparse.map", 14)){
                if(pax_set_string(&m->sparse_map, val, vlen) < 0) return -1;
                if(!m->has_sparse_major){ m->sparse_major = 0; m->sparse_minor = 1; m->has_sparse_major = 1; }
            } else if((klen == 19 && !memcmp(kv, "GNU.sparse.realsize", 19)) ||
                      (klen == 15 && !memcmp(kv, "GNU.sparse.size", 15))){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                char *e2; errno = 0; m->sparse_realsize = strtoull(tmp, &e2, 10);
                if(errno || *e2) return -1;
                m->has_sparse_realsize = 1;
            } else if((klen == 16 && !memcmp(kv, "GNU.sparse.major", 16)) ||
                      (klen == 16 && !memcmp(kv, "GNU.sparse.minor", 16))){
                int v = vlen ? atoi(val) : 0;
                if(kv[12] == 'a') m->sparse_major = v; else m->sparse_minor = v;
                m->has_sparse_major = 1;
            } else if(klen == 17 && !memcmp(kv, "SCHILY.acl.access", 17)){
                if(pax_set_string(&m->acl_access, val, vlen) < 0) return -1;
            } else if(klen == 18 && !memcmp(kv, "SCHILY.acl.default", 18)){
                if(pax_set_string(&m->acl_default, val, vlen) < 0) return -1;
            }
        }
        pos += reclen;
    }
    return 0;
}

static void trim_gnu_long_body(char *body, unsigned long sz){
    while(sz > 0 && (body[sz - 1] == '\0' || body[sz - 1] == '\n'))
        body[--sz] = '\0';
}

static int read_padded_body(FILE *f, unsigned long sz, char **out){
    char *body = calloc(sz + 1, 1);
    if(!body) return -1;
    if(sz && fread(body, 1, sz, f) != sz){ free(body); return -1; }
    unsigned long pad = (512 - (sz % 512)) % 512;
    if(pad && skip_bytes(f, pad) < 0){ free(body); return -1; }
    *out = body; return 0;
}

/* Create any missing parent directories of path (think mkdir -p). */
static int mkpath_parents(const char *path, mode_t dir_mode){
    char buf[512]; size_t n = strlen(path);
    if(n >= sizeof buf) return -1;
    memcpy(buf, path, n+1);
    /* A directory archive member commonly ends in '/'.  That separator
       names the member itself, not a parent to create with dir_mode. */
    while(n > 1 && buf[n-1] == '/') buf[--n] = 0;
    for(char *p = buf+1; *p; p++){
        if(*p == '/'){ *p = 0;
            if(mkdir(buf, dir_mode) < 0 && errno != EEXIST) return -1;
            *p = '/'; }
    }
    return 0;
}

static int set_mtime(const char *path, time_t mtime, int is_symlink){
    struct timespec ts[2];
    ts[0].tv_sec = 0; ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = mtime; ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, is_symlink ? AT_SYMLINK_NOFOLLOW : 0);
}


/* Ustar device numbers are octal ASCII, optionally padded with spaces or
   NUL. Reject malformed fields before a privileged filesystem operation. */
static int pax_device_number(const unsigned char *s, size_t len, unsigned long *out){
    unsigned long n = 0; int digits = 0, ended = 0;
    for(size_t i = 0; i < len; i++){
        if(s[i] >= '0' && s[i] <= '7'){
            if(ended || n > (ULONG_MAX - (unsigned long)(s[i] - '0')) / 8){ errno = EINVAL; return -1; }
            n = n * 8 + (unsigned long)(s[i] - '0'); digits = 1;
        } else if(s[i] == 0 || s[i] == ' '){
            if(digits || s[i] == 0) ended = 1;
        } else { errno = EINVAL; return -1; }
    }
    *out = n; return 0;
}

/* Create a device under a directory-fd walk that refuses symlink parents.
   Build a sibling first so EPERM, bad device numbers and timestamp errors
   leave any existing destination untouched. */
static int pax_device_replace(const char *path, mode_t mode, dev_t dev, time_t mtime){
    char *copy = strdup(path), *save = NULL;
    int dfd = -1, rc = -1, saved;
    if(!copy) return -1;
    char *base = strrchr(copy, '/');
    if(base) *base++ = 0; else base = copy;
    if(!*base || !strcmp(base, ".") || !strcmp(base, "..")){ errno = EINVAL; goto out; }
    dfd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(dfd < 0) goto out;
    if(base != copy){
        for(char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)){
            if(!strcmp(part, ".")) continue;
            if(!strcmp(part, "..")){ errno = EINVAL; goto out; }
            int next = openat(dfd, part, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(next < 0 && errno == ENOENT){
                if(mkdirat(dfd, part, 0755) < 0 && errno != EEXIST) goto out;
                next = openat(dfd, part, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            }
            if(next < 0) goto out;
            close(dfd); dfd = next;
        }
    }
    static unsigned long sequence;
    char tmp[80]; int made = 0, tfd = -1;
    for(unsigned i = 0; i < 128; i++){
        snprintf(tmp, sizeof tmp, ".pax-node-%ld-%lu", (long)getpid(), ++sequence);
        mode_t mask = umask(0);
        int r = mkdirat(dfd, tmp, 0700); saved = errno;
        umask(mask); errno = saved;
        if(r == 0){ made = 1; break; }
        if(errno != EEXIST) goto out;
    }
    if(!made){ errno = EEXIST; goto out; }
    tfd = openat(dfd, tmp, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat tempstat;
    if(tfd < 0 || fstat(tfd, &tempstat) < 0 || tempstat.st_uid != geteuid() ||
       (tempstat.st_mode & 0777) != 0700){
        saved = errno ? errno : EACCES; if(tfd >= 0) close(tfd);
        unlinkat(dfd, tmp, AT_REMOVEDIR); errno = saved; goto out;
    }
    mode_t mask = umask(0);
    int made_node = mknodat(tfd, "node", mode, dev); saved = errno;
    umask(mask); errno = saved;
    struct timespec ts[2] = {{0, UTIME_OMIT}, {mtime, 0}};
    if(made_node < 0 || utimensat(tfd, "node", ts, AT_SYMLINK_NOFOLLOW) < 0 ||
       renameat(tfd, "node", dfd, base) < 0){
        saved = errno; if(made_node == 0) unlinkat(tfd, "node", 0);
        close(tfd); unlinkat(dfd, tmp, AT_REMOVEDIR); errno = saved; goto out;
    }
    close(tfd);
    if(unlinkat(dfd, tmp, AT_REMOVEDIR) < 0) goto out;
    rc = 0;
out:
    saved = errno; if(dfd >= 0) close(dfd); free(copy); errno = saved; return rc;
}

/* One member in GNU tar's verbose listing: mode string, owner/group, size
   or device numbers, modification time, name and link target. The
   owner/group/size field starts 19 columns wide and only grows. */
static void tar_verbose_line(const unsigned char *h, int typeflag, unsigned mode, unsigned long sz,
                             time_t mtime, const char *name, const char *ln, int *ugswidth){
    char perms[11], owner[80], group[80], size[64], when[32];
    perms[0] = typeflag == '5' ? 'd' : typeflag == '2' ? 'l' : typeflag == '3' ? 'c' :
               typeflag == '4' ? 'b' : typeflag == '6' ? 'p' : typeflag == '1' ? 'h' : '-';
    static const char rwx[] = "rwxrwxrwx";
    for(int i = 0; i < 9; i++) perms[1+i] = (mode & (0400u >> i)) ? rwx[i] : '-';
    if(mode & 04000) perms[3] = (mode & 0100) ? 's' : 'S';
    if(mode & 02000) perms[6] = (mode & 0010) ? 's' : 'S';
    if(mode & 01000) perms[9] = (mode & 0001) ? 't' : 'T';
    perms[10] = 0;
    snprintf(owner, sizeof owner, "%.32s", (const char *)h+265);
    snprintf(group, sizeof group, "%.32s", (const char *)h+297);
    if(!owner[0]) snprintf(owner, sizeof owner, "%lu", octal((char *)h+108, 8));
    if(!group[0]) snprintf(group, sizeof group, "%lu", octal((char *)h+116, 8));
    if(typeflag == '3' || typeflag == '4')
        snprintf(size, sizeof size, "%lu,%lu", octal((char *)h+329, 8), octal((char *)h+337, 8));
    else snprintf(size, sizeof size, "%lu", sz);
    struct tm tm;
    if(!localtime_r(&mtime, &tm) || !strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tm))
        snprintf(when, sizeof when, "%lld", (long long)mtime);
    int pad = (int)(strlen(owner) + 1 + strlen(group) + 1 + strlen(size));
    if(pad > *ugswidth) *ugswidth = pad;
    printf("%s %s/%s %*s %s %s%s", perms, owner, group,
           (int)(*ugswidth - pad + strlen(size)), size, when, name,
           typeflag == '5' && name[strlen(name)-1] != '/' ? "/" : "");
    if(typeflag == '2') printf(" -> %s", ln);
    else if(typeflag == '1') printf(" link to %s", ln);
    putchar('\n');
}

/* The owner an extracted member gets with same_owner: the archived user
   and group names when they exist here (GNU tar), else the archived ids. */
static void pax_member_owner(const unsigned char *h, const struct pax_meta *eff, int numeric,
                             uid_t *uid, gid_t *gid){
    char name[33];
    *uid = (uid_t)(eff->has_uid ? eff->uid : octal((const char *)h+108, 8));
    *gid = (gid_t)(eff->has_gid ? eff->gid : octal((const char *)h+116, 8));
    if(numeric) return;
    const char *un = eff->uname, *gn = eff->gname;
    if(!un){ snprintf(name, sizeof name, "%.32s", (const char *)h+265); un = name; }
    struct passwd *pw = *un ? getpwnam(un) : NULL;
    if(pw) *uid = pw->pw_uid;
    if(!gn){ snprintf(name, sizeof name, "%.32s", (const char *)h+297); gn = name; }
    struct group *gr = *gn ? getgrnam(gn) : NULL;
    if(gr) *gid = gr->gr_gid;
}

/* Give NAME the archived owner. Returns 0, or -1 after reporting the
   failure (counted like GNU tar's other per-member errors). */
static int pax_chown(const char *name, uid_t uid, gid_t gid,
                     const struct bashos_pax_read_options *options, int is_symlink){
    if((is_symlink ? lchown(name, uid, gid) : chown(name, uid, gid)) == 0) return 0;
    builtin_error("%s: Cannot change ownership to uid %lu, gid %lu: %s", name,
                  (unsigned long)uid, (unsigned long)gid, strerror(errno));
    if(options->member_errors) ++*options->member_errors;
    return -1;
}

static int pax_restore_owner(const char *name, const unsigned char *h, const struct pax_meta *eff,
                             const struct bashos_pax_read_options *options, int is_symlink){
    uid_t uid; gid_t gid;
    pax_member_owner(h, eff, options->numeric_owner, &uid, &gid);
    return pax_chown(name, uid, gid, options, is_symlink);
}

static void pax_set_acls(const char *name, const char *access, const char *dflt);

/* Directory owner and times are set once the members inside it have been
   extracted (as GNU tar does), so later members do not disturb them. */
struct pax_delayed { char *name, *acl_access, *acl_default; time_t mtime; mode_t mode; uid_t uid; gid_t gid; int owner; };
struct pax_delayed_list { struct pax_delayed *v; size_t n, cap; };

static int pax_inside(const char *dir, const char *name){
    size_t len = strlen(dir);
    return !strncmp(name, dir, len) && name[len] == '/';
}

/* Finish the pending directories that do not contain NAME (all when NULL). */
static int pax_finish_dirs(struct pax_delayed_list *l, const char *name,
                           const struct bashos_pax_read_options *options){
    int rc = 0;
    while(l->n && !(name && pax_inside(l->v[l->n-1].name, name))){
        struct pax_delayed *d = &l->v[--l->n];
        if(d->owner){
            if(pax_chown(d->name, d->uid, d->gid, options, 0) < 0) rc = -1;
            else if(d->mode & 07000) chmod(d->name, d->mode & 07777);
        }
        if(d->acl_access || d->acl_default) pax_set_acls(d->name, d->acl_access, d->acl_default);
        set_mtime(d->name, d->mtime, 0);
        free(d->name); free(d->acl_access); free(d->acl_default);
    }
    return rc;
}

static int pax_delay_dir(struct pax_delayed_list *l, const char *name, time_t mtime, mode_t mode,
                         const unsigned char *h, const struct pax_meta *eff,
                         const struct bashos_pax_read_options *options){
    if(l->n == l->cap){
        size_t cap = l->cap ? l->cap * 2 : 16;
        struct pax_delayed *v = realloc(l->v, cap * sizeof *v);
        if(!v) return -1;
        l->v = v; l->cap = cap;
    }
    struct pax_delayed *d = &l->v[l->n];
    memset(d, 0, sizeof *d);
    if(!(d->name = strdup(name))) return -1;
    size_t len = strlen(d->name);
    while(len > 1 && d->name[len-1] == '/') d->name[--len] = 0;
    d->mtime = mtime; d->mode = mode; d->owner = options->same_owner;
    if(options->acls && ((eff->acl_access && !(d->acl_access = strdup(eff->acl_access))) ||
                         (eff->acl_default && !(d->acl_default = strdup(eff->acl_default)))))
        return -1;
    if(d->owner) pax_member_owner(h, eff, options->numeric_owner, &d->uid, &d->gid);
    l->n++;
    return 0;
}

/* GNU.sparse.map (format 0.1): "OFFSET,SIZE,OFFSET,SIZE...". */
static int sparse_map_from_record(const char *text, struct sparse_map *m){
    const char *p = text;
    while(p && *p){
        char *e; errno = 0;
        unsigned long long off = strtoull(p, &e, 10);
        if(errno || e == p || *e != ',') return -1;
        p = e + 1;
        unsigned long long len = strtoull(p, &e, 10);
        if(errno || e == p || (*e && *e != ',')) return -1;
        if(sparse_add(m, off, len) < 0) return -1;
        p = *e ? e + 1 : e;
    }
    return 0;
}

/* Format 1.0: the map heads the member body as decimal lines (count, then
   offset/size pairs), padded to a block. *USED is the bytes it took. */
static int sparse_map_from_body(FILE *f, struct sparse_map *m, unsigned long *used){
    char block[513]; unsigned long long nums[2]; int have = 0;
    long long count = -1;
    char digits[32]; size_t nd = 0;
    *used = 0;
    for(;;){
        if(fread(block, 1, 512, f) != 512) return -1;
        *used += 512;
        for(int i = 0; i < 512; i++){
            char c = block[i];
            if(c >= '0' && c <= '9'){ if(nd + 1 >= sizeof digits) return -1; digits[nd++] = c; continue; }
            if(c != '\n') return -1;
            if(!nd) return -1;
            digits[nd] = 0; nd = 0;
            unsigned long long v = strtoull(digits, NULL, 10);
            if(count < 0){ count = (long long)v; if(count == 0) return 0; continue; }
            nums[have++] = v;
            if(have == 2){
                if(sparse_add(m, nums[0], nums[1]) < 0) return -1;
                have = 0;
                if((long long)m->n == count) return 0;
            }
        }
    }
}

/* Old GNU format ('S'): four map entries in the header, more in extension
   blocks that precede the data; the data holds only the segments. */
static int sparse_map_from_gnu_header(FILE *f, const unsigned char *h, struct sparse_map *m,
                                      unsigned long long *realsize){
    *realsize = octal((const char *)h + 483, 12);
    const unsigned char *e = h + 386;
    int extended = h[482];
    for(int i = 0; i < 4; i++, e += 24){
        if(!e[0]) break;
        if(sparse_add(m, octal((const char *)e, 12), octal((const char *)e + 12, 12)) < 0) return -1;
    }
    while(extended){
        unsigned char x[512];
        if(fread(x, 1, 512, f) != 512) return -1;
        e = x;
        for(int i = 0; i < 21; i++, e += 24){
            if(!e[0]) break;
            if(sparse_add(m, octal((const char *)e, 12), octal((const char *)e + 12, 12)) < 0) return -1;
        }
        extended = x[504];
    }
    return 0;
}

/* Write a sparse member's segments (DATA bytes in F) to O; a seekable O
   gets holes, a pipe gets zeros. Returns 0, or -1 on a short archive. */
static int sparse_write(FILE *f, FILE *o, const struct sparse_map *m, unsigned long data,
                        unsigned long long realsize){
    struct stat ost;
    int seekable = fstat(fileno(o), &ost) == 0 && S_ISREG(ost.st_mode);
    unsigned long long pos = 0;
    unsigned char buf[16384];
    for(size_t i = 0; i < m->n; i++){
        const struct sparse_seg *g = &m->v[i];
        if(g->off < pos || g->len > data) return -1;
        if(seekable){ if(fseeko(o, (off_t)g->off, SEEK_SET) < 0) return -1; }
        else { memset(buf, 0, sizeof buf);
               for(unsigned long long z = g->off - pos; z; ){ size_t w = z > sizeof buf ? sizeof buf : (size_t)z;
                   if(fwrite(buf, 1, w, o) != w) return -1; z -= w; } }
        for(unsigned long long left = g->len; left; ){
            size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
            size_t got = fread(buf, 1, want, f);
            if(!got) return -1;
            if(fwrite(buf, 1, got, o) != got) return -1;
            left -= got;
        }
        data -= (unsigned long)g->len;
        pos = g->off + g->len;
    }
    if(data && skip_bytes(f, data) < 0) return -1;
    if(seekable){ if(fflush(o) || ftruncate(fileno(o), (off_t)realsize) < 0) return -1; }
    else { memset(buf, 0, sizeof buf);
           for(unsigned long long z = realsize > pos ? realsize - pos : 0; z; ){ size_t w = z > sizeof buf ? sizeof buf : (size_t)z;
               if(fwrite(buf, 1, w, o) != w) return -1; z -= w; } }
    return 0;
}

/* tar --to-command: run COMMAND with the member on its stdin. Returns 0, or
   -1 after GNU's "Child returned status N" (counted as a member error). */
static int pax_to_command(FILE *f, const struct bashos_pax_read_options *options, const char *name,
                          const unsigned char *h, const struct pax_meta *eff, unsigned mode,
                          unsigned long long realsize, time_t mtime, const struct sparse_map *map,
                          unsigned long data){
    int p[2];
    if(pipe(p) < 0){ builtin_error("pipe: %s", strerror(errno)); return -1; }
    bos_child_wait child_wait;
    if(bos_child_wait_begin(&child_wait) < 0){
        builtin_error("SIGCHLD setup: %s", strerror(errno)); close(p[0]); close(p[1]); return -1;
    }
    maybe_make_export_env();
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if(pid < 0){
        builtin_error("fork: %s", strerror(errno)); bos_child_wait_end(&child_wait);
        close(p[0]); close(p[1]); return -1;
    }
    if(pid == 0){
        /* The shell's exported variables plus GNU tar's TAR_* set. */
        bos_child_wait_child(&child_wait);
        dup2(p[0], 0); close(p[0]); close(p[1]);
        size_t n = 0;
        while(export_env && export_env[n]) n++;
        char **envp = calloc(n + 16, sizeof *envp);
        if(!envp) _exit(127);
        size_t k = 0;
        for(size_t i = 0; i < n; i++) if(strncmp(export_env[i], "TAR_", 4)) envp[k++] = export_env[i];
        char uname[33], gname[33];
        snprintf(uname, sizeof uname, "%.32s", (const char *)h + 265);
        snprintf(gname, sizeof gname, "%.32s", (const char *)h + 297);
#define PUT(...) do { char b[8192]; snprintf(b, sizeof b, __VA_ARGS__); envp[k++] = strdup(b); } while(0)
        PUT("TAR_FILETYPE=f");
        PUT("TAR_MODE=%04o", mode & 07777);
        PUT("TAR_FILENAME=%s", name);
        PUT("TAR_REALNAME=%s", name);
        PUT("TAR_UNAME=%s", eff->uname ? eff->uname : uname);
        PUT("TAR_GNAME=%s", eff->gname ? eff->gname : gname);
        PUT("TAR_UID=%lu", eff->has_uid ? eff->uid : octal((const char *)h + 108, 8));
        PUT("TAR_GID=%lu", eff->has_gid ? eff->gid : octal((const char *)h + 116, 8));
        PUT("TAR_SIZE=%llu", realsize);
        PUT("TAR_MTIME=%lld", (long long)mtime);
        PUT("TAR_ARCHIVE=%s", options->archive ? options->archive : "-");
        PUT("TAR_FORMAT=pax");
        PUT("TAR_VOLUME=1");
        PUT("TAR_BLOCKING_FACTOR=20");
        PUT("TAR_VERSION=1.35");
#undef PUT
        char *argv[] = { "sh", "-c", (char *)options->to_command, NULL };
        execve("/bin/sh", argv, envp);
        _exit(127);
    }
    close(p[0]);
    void (*old)(int) = signal(SIGPIPE, SIG_IGN);
    FILE *o = fdopen(p[1], "wb");
    int bad = !o;
    if(o){
        if(map){ if(sparse_write(f, o, map, data, realsize) < 0) bad = 2; }
        else {
            unsigned char buf[16384]; unsigned long left = data;
            while(left){
                size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
                size_t got = fread(buf, 1, want, f);
                if(!got){ bad = 2; break; }
                fwrite(buf, 1, got, o);   /* the command may stop reading early */
                left -= got;
            }
        }
        fclose(o);
    } else close(p[1]);
    signal(SIGPIPE, old);
    int status = 0;
    while(waitpid(pid, &status, 0) < 0 && errno == EINTR) ;
    bos_child_wait_end(&child_wait);
    if(bad == 2){ builtin_error("%s: archive truncated in member body", name); return -2; }
    if(WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    if(WIFEXITED(status)) builtin_error("%ld: Child returned status %d", (long)pid, WEXITSTATUS(status));
    else builtin_error("%ld: Child terminated on signal %d", (long)pid, WTERMSIG(status));
    if(options->member_errors) ++*options->member_errors;
    return -1;
}

/* --acls on extract. A failure is reported as GNU tar's warning. */
static void pax_set_acls(const char *name, const char *access, const char *dflt){
    if(access && acl_set_text(name, "system.posix_acl_access", access) < 0)
        builtin_error("%s: Warning: Cannot set POSIX ACLs: %s", name, strerror(errno));
    if(dflt && acl_set_text(name, "system.posix_acl_default", dflt) < 0)
        builtin_error("%s: Warning: Cannot set default POSIX ACLs: %s", name, strerror(errno));
}

int bashos_pax_read(FILE *f, const struct bashos_pax_read_options *options){
    int ugswidth = 19;
    int extract = options->extract, verbose = options->verbose;
    mode_t mask = umask(0); umask(mask);
    unsigned char *found = calloc(options->count ? options->count : 1, 1);
    if(!found){ builtin_error("out of memory"); return 1; }
    unsigned char h[512]; int rc=EXECUTION_SUCCESS; int zero_seen=0;
    struct pax_meta global = {0}, local = {0};
    struct pax_delayed_list dirs = {0};
    int warned_slash = 0;
    while(1){
        size_t got = fread(h,1,512,f);
        if(got == 0){
            if(!zero_seen){ builtin_error("archive truncated: no end-of-archive marker"); rc = EXECUTION_FAILURE; }
            break;
        }
        if(got != 512){ builtin_error("archive truncated: short header read (%zu of 512)", got); rc = EXECUTION_FAILURE; break; }
        if(zero_block(h)){ zero_seen = 1; break; }
        if(memcmp(h+257,"ustar",5)){ builtin_error("bad ustar magic"); rc=EXECUTION_FAILURE; break; }
        if(!hdr_checksum_ok(h)){ builtin_error("bad ustar header checksum"); rc=EXECUTION_FAILURE; break; }

        char hdrname[257]; name_from_hdr(hdrname, h);
        unsigned long sz = octal((char*)h+124,12);
        unsigned mode = octal((char*)h+100,8);
        time_t mtime = (time_t)octal((char*)h+136, 12);
        int typeflag = h[156] ? h[156] : '0';
        char linkname[101]; memcpy(linkname, h+157, 100); linkname[100]=0;
        long body_padded = ((long)sz+511L)/512L*512L;
        int has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7');

        if(typeflag == 'x' || typeflag == 'g'){
            char *body = NULL;
            if(read_padded_body(f, sz, &body) < 0){
                builtin_error("%s: archive truncated in pax extended header", hdrname);
                rc = EXECUTION_FAILURE; break;
            }
            struct pax_meta *target = typeflag == 'g' ? &global : &local;
            if(typeflag == 'x') pax_meta_free(&local);
            if(pax_parse_records(body, (size_t)sz, target) < 0) rc = EXECUTION_FAILURE;
            free(body);
            continue;
        }
        if(typeflag == 'L' || typeflag == 'K'){
            char *body = NULL;
            if(read_padded_body(f, sz, &body) < 0){
                builtin_error("%s: archive truncated in GNU extended header", hdrname);
                rc = EXECUTION_FAILURE; break;
            }
            trim_gnu_long_body(body, sz);
            if(typeflag == 'L'){
                pax_meta_free(&local);
                if(pax_set_string(&local.path, body, strlen(body)) < 0) rc = EXECUTION_FAILURE;
            } else {
                if(pax_set_string(&local.linkpath, body, strlen(body)) < 0) rc = EXECUTION_FAILURE;
            }
            free(body);
            continue;
        }

        struct pax_meta eff = {0};
        if(pax_meta_copy(&eff, &global) < 0){ rc = EXECUTION_FAILURE; break; }
        pax_meta_merge(&eff, &local);
        pax_meta_free(&local);

        const char *name = eff.path ? eff.path : hdrname;
        const char *ln = eff.linkpath ? eff.linkpath : linkname;
        const char *unstripped_link = ln;
        if(eff.has_size){ if(eff.size > (unsigned long)LONG_MAX - 1024UL){ builtin_error("%s: member size out of range", name); rc = EXECUTION_FAILURE; pax_meta_free(&eff); break; }
            sz = eff.size; body_padded = ((long)sz+511L)/512L*512L; has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7'); }
        if(eff.has_mtime) mtime = eff.mtime;
        if(eff.typeflag){ typeflag = eff.typeflag; has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7'); }

        /* Sparse members: 1 = map known (old GNU 'S' header or format 0.1),
           2 = map at the start of the body (format 1.0). */
        int sparse = 0;
        unsigned long long realsize = sz;
        struct sparse_map smap = {0};
        if(typeflag == 'S'){
            if(sparse_map_from_gnu_header(f, h, &smap, &realsize) < 0){
                builtin_error("%s: archive truncated in sparse header", name); rc = EXECUTION_FAILURE;
                free(smap.v); pax_meta_free(&eff); break;
            }
            sparse = 1; typeflag = '0'; has_body = 1;
        } else if(eff.has_sparse_major && (typeflag == '0' || typeflag == '7')){
            sparse = eff.sparse_major >= 1 ? 2 : 1;
            if(eff.has_sparse_realsize) realsize = eff.sparse_realsize;
            if(sparse == 1 && sparse_map_from_record(eff.sparse_map ? eff.sparse_map : "", &smap) < 0){
                builtin_error("%s: malformed sparse map", name); rc = EXECUTION_FAILURE; sparse = 0;
            }
            if(eff.sparse_name) name = eff.sparse_name;
        }
        if(options->xforms){
            char *t = xform_apply(options->xforms, name, XF_REG);
            char *tl = (typeflag == '1' || typeflag == '2') ?
                       xform_apply(options->xforms, ln, typeflag == '1' ? XF_HARD : XF_SYM) : NULL;
            if(!t || ((typeflag == '1' || typeflag == '2') && !tl)){
                free(t); free(tl); free(smap.v); pax_meta_free(&eff);
                builtin_error("out of memory"); rc = EXECUTION_FAILURE; break;
            }
            free(eff.path); eff.path = t; name = t;
            if(tl){ free(eff.linkpath); eff.linkpath = tl; ln = unstripped_link = tl; }
        }

        int selected = options->count == 0;
        for(size_t i = 0; i < options->count; i++){
            const char *wanted = options->members[i]; size_t len = strlen(wanted);
            while(len && wanted[len-1] == '/') len--;
            if(options->wildcards ? fnmatch(wanted, name, FNM_LEADING_DIR) == 0 :
               !strncmp(name, wanted, len) && (name[len] == 0 || name[len] == '/')){
                selected = 1; found[i] = 1;
            }
        }
        if(selected && name_excluded(options->excludes, options->nexcludes, name)) selected = 0;
        if(!selected){
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            free(smap.v); pax_meta_free(&eff); continue;
        }
        if(!extract){
            if(verbose && options->tar_mode)
                tar_verbose_line(h, typeflag, mode, (unsigned long)realsize, mtime, name, ln, &ugswidth);
            else if(verbose && (typeflag == '3' || typeflag == '4'))
                printf("%c %06o %lu,%lu %s\n", typeflag, mode,
                       octal((char *)h+329, 8), octal((char *)h+337, 8), name);
            else if(verbose) printf("%c %06o %lu %s\n", typeflag, mode, (unsigned long)realsize, name);
            else printf("%s%s\n", name, options->tar_mode && typeflag == '5' && name[strlen(name)-1] != '/' ? "/" : "");
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            free(smap.v); pax_meta_free(&eff); continue;
        }
        if(options->tar_mode && !options->absolute_names && (name[0] == '/' || (typeflag == '1' && ln[0] == '/'))){
            if(!warned_slash++) builtin_error("Removing leading `/' from member names");
            while(*name == '/') name++;
            if(typeflag == '1') while(*ln == '/') ln++;
            unstripped_link = ln;
            if(!*name) name = ".";
        }
        for(unsigned i = 0; i < options->strip; i++){
            const char *slash = strchr(name, '/');
            name = slash ? slash + 1 : "";
        }
        if(typeflag == '1') for(unsigned i = 0; i < options->strip; i++){
            const char *slash = strchr(ln, '/');
            ln = slash ? slash + 1 : "";
        }
        if(!*name){
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            free(smap.v); pax_meta_free(&eff); continue;
        }
        if(options->tar_mode && !options->preserve) mode &= ~mask;
        unsigned long map_bytes = 0;
        if(sparse == 2 && has_body){
            if(sparse_map_from_body(f, &smap, &map_bytes) < 0 || map_bytes > sz){
                builtin_error("%s: malformed sparse map", name); rc = EXECUTION_FAILURE;
                free(smap.v); pax_meta_free(&eff); break;
            }
            sparse = 1;
            body_padded -= (long)map_bytes;
        }
        if(options->to_stdout && sparse && has_body){
            if(sparse_write(f, stdout, &smap, sz - map_bytes, realsize) < 0 ||
               skip_bytes(f, (512 - sz % 512) % 512) < 0){
                builtin_error("%s: archive truncated in member body", name); rc = 1;
            }
            free(smap.v); pax_meta_free(&eff); if(rc) break; continue;
        }
        if(options->to_command){
            int r = 0;
            if(has_body && (typeflag == '0' || typeflag == '7')){
                r = pax_to_command(f, options, name, h, &eff, mode, realsize, mtime, sparse ? &smap : NULL,
                                   sz - map_bytes);
                if(r == -1) rc = EXECUTION_FAILURE;
                if(r != -2 && skip_bytes(f, (512 - sz % 512) % 512) < 0) r = -2;
            } else if(skip_bytes(f, body_padded) < 0) r = -2;
            free(smap.v); pax_meta_free(&eff);
            if(r == -2){ rc = 1; break; }
            continue;
        }
        if(options->to_stdout){
            unsigned char data[16384]; unsigned long left = sz;
            while(left){
                size_t want = left > sizeof data ? sizeof data : (size_t)left;
                size_t got = fread(data, 1, want, f);
                if(!got || (has_body && fwrite(data, 1, got, stdout) != got)){ rc = 1; break; }
                left -= got;
            }
            if(left || skip_bytes(f, (512 - sz % 512) % 512) < 0) rc = 1;
            free(smap.v); pax_meta_free(&eff); if(rc) break; continue;
        }
        if(options->tar_mode && verbose) fprintf(stderr, "%s\n", name);
        if(pax_finish_dirs(&dirs, name, options) < 0) rc = EXECUTION_FAILURE;

        if(!options->absolute_names && unsafe_path(name)){
            builtin_error("%s: unsafe archive path", name); rc = EXECUTION_FAILURE;
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            free(smap.v); pax_meta_free(&eff);
            continue;
        }

        switch(typeflag){
        case '5': {  /* directory */
            if(mkpath_parents(name, 0755) < 0){
                builtin_error("%s: mkdir parent: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            if(mkdir(name, mode & 0777) < 0 && errno != EEXIST){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            if(pax_delay_dir(&dirs, name, mtime, mode, h, &eff, options) < 0){
                builtin_error("out of memory"); rc = EXECUTION_FAILURE;
            }
            break;
        }
        case '2': {  /* symlink */
            if(ln[0]==0 || (!options->absolute_names && (ln[0]=='/' || unsafe_path(ln)))){
                builtin_error("%s: unsafe or empty symlink target '%s'", name, ln); rc = EXECUTION_FAILURE; break;
            }
            mkpath_parents(name, 0755);
            unlink(name);
            if(symlink(ln, name) < 0){
                builtin_error("%s: symlink: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            if(options->same_owner && pax_restore_owner(name, h, &eff, options, 1) < 0) rc = EXECUTION_FAILURE;
            set_mtime(name, mtime, 1);
            break;
        }
        case '1': {  /* hardlink */
            if(unstripped_link[0]==0 || ln[0]==0 || (!options->absolute_names &&
               (unstripped_link[0]=='/' || unsafe_path(unstripped_link) || ln[0]=='/' || unsafe_path(ln)))){
                builtin_error("%s: unsafe or empty hardlink target '%s'", name, ln); rc = EXECUTION_FAILURE; break;
            }
            struct stat existing, target;
            /* Repeated archive operands can link a name to itself, or to
               an already-linked destination. Keep that inode in place. */
            if(lstat(name, &existing) == 0 && lstat(ln, &target) == 0 &&
               S_ISREG(existing.st_mode) && S_ISREG(target.st_mode) &&
               existing.st_dev == target.st_dev && existing.st_ino == target.st_ino)
                break;
            mkpath_parents(name, 0755);
            unlink(name);
            if(link(ln, name) < 0){
                builtin_error("%s: link to %s: %s", name, ln, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            break;
        }
        case '3': case '4': {
            unsigned long devmajor = 0, devminor = 0;
            int result = -1;
            if(pax_device_number(h+329, 8, &devmajor) == 0 &&
               pax_device_number(h+337, 8, &devminor) == 0){
                dev_t device = makedev(devmajor, devminor);
                if(major(device) != devmajor || minor(device) != devminor) errno = EOVERFLOW;
                else result = pax_device_replace(name,
                       (typeflag == '3' ? S_IFCHR : S_IFBLK) | (mode & 07777), device, mtime);
            }
            if(result < 0){
                if(options->tar_mode) builtin_error("%s: Cannot mknod: %s", name, strerror(errno));
                else builtin_error("%s: %s", name, strerror(errno));
                if(options->member_errors) ++*options->member_errors;
                rc = 1;
            }
            else if(options->same_owner && pax_restore_owner(name, h, &eff, options, 1) < 0) rc = 1;
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            break;
        }
        case '6': {  /* FIFO: retain the pre-existing extraction behavior. */
            if(mkpath_parents(name, 0755) < 0){
                builtin_error("%s: mkdir parent: %s", name, strerror(errno)); rc = 1;
                if(skip_bytes(f, body_padded) < 0) rc = 1; break;
            }
            if(unlink(name) < 0 && errno != ENOENT){
                builtin_error("%s: %s", name, strerror(errno)); rc = 1;
                if(skip_bytes(f, body_padded) < 0) rc = 1; break;
            }
            mode_t saved_mask = umask(0);
            int result = mkfifo(name, mode & 0777), saved_errno = errno;
            umask(saved_mask);
            if(result < 0){
                if(options->tar_mode) builtin_error("%s: Cannot mkfifo: %s", name, strerror(saved_errno));
                else builtin_error("%s: %s", name, strerror(saved_errno));
                if(options->member_errors) ++*options->member_errors;
                rc = 1;
            }
            else {
                if(options->same_owner && pax_restore_owner(name, h, &eff, options, 0) < 0) rc = 1;
                if(set_mtime(name, mtime, 0) < 0){ builtin_error("%s: %s", name, strerror(errno)); rc = 1; }
            }
            if(skip_bytes(f, body_padded) < 0) rc = 1;
            break;
        }
        case 'x': case 'g':
            builtin_error("%s: extended header typeflag '%c' not supported", name, typeflag);
            rc = EXECUTION_FAILURE;
            skip_bytes(f, body_padded);
            break;
        case '0': case '\0': case '7':
        default: {
            mkpath_parents(name, 0755);
            if(unlink(name) < 0 && errno != ENOENT && errno != EISDIR){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE;
                skip_bytes(f, body_padded); break;
            }
            FILE *o = fopen(name, "wb");
            if(!o){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE;
                skip_bytes(f, body_padded); break;
            }
            unsigned long left = sparse ? 0 : sz; unsigned char buf[4096]; int short_body = 0;
            if(sparse && sparse_write(f, o, &smap, sz - map_bytes, realsize) < 0) short_body = 1;
            while(left){
                size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
                size_t n = fread(buf,1,want,f);
                if(n==0){ short_body = 1; break; }
                if(fwrite(buf,1,n,o) != n){ builtin_error("%s: write error", name); rc = 1; }
                left -= n;
            }
            if(fclose(o)){ builtin_error("%s: close error", name); rc = 1; }
            if(short_body){ builtin_error("%s: archive truncated in member body", name); rc = EXECUTION_FAILURE; break; }
            /* chown first: it clears set-id bits, which only an owner-
               preserving extraction keeps. */
            int owned = options->same_owner && pax_restore_owner(name, h, &eff, options, 0) == 0;
            if(options->same_owner && !owned) rc = EXECUTION_FAILURE;
            /* tar -p keeps set-id bits (GNU does even when the chown
               failed); pax keeps them only with the owner restored. */
            mode_t keep = (options->tar_mode && options->preserve) || owned ? 07777 : 0777;
            chmod(name, mode & keep);
            if(options->acls) pax_set_acls(name, eff.acl_access, NULL);
            set_mtime(name, mtime, 0);
            unsigned long pad = (512 - (sz % 512)) % 512;
            if(pad && skip_bytes(f, pad) < 0){ builtin_error("archive truncated in padding"); rc = 1; }
            break;
        }
        }
        free(smap.v);
        pax_meta_free(&eff);
    }
    if(pax_finish_dirs(&dirs, NULL, options) < 0) rc = EXECUTION_FAILURE;
    free(dirs.v);
    pax_meta_free(&global); pax_meta_free(&local);
    int warned_pattern = 0;
    for(size_t i = 0; i < options->count; i++) if(!found[i]){
        /* GNU tar's hint for a pattern used as a plain member name. */
        if(options->tar_mode && !options->wildcards && !warned_pattern &&
           strpbrk(options->members[i], "*?[")){
            builtin_error("Pattern matching characters used in file names");
            builtin_error("Use --wildcards to enable pattern matching, or --no-wildcards to suppress this warning");
            warned_pattern = 1;
        }
        builtin_error("%s: %s", options->members[i], options->tar_mode ? "Not found in archive" : "not found in archive");
        if(options->tar_mode && options->member_errors) ++*options->member_errors;
        rc = 1;
    }
    free(found);
    if(ferror(f) || ferror(stdout)) rc = 1;
    return rc;
}

/* Build a ustar header for `path` and write it. Body bytes (regular
   files only) are written by the caller. */
/* Owner names for the header being written (tar --owner/--group). */
static const char *hdr_uname, *hdr_gname;

static int write_header(FILE *out, const char *path, const struct stat *st, char typeflag, const char *linktarget){
    unsigned char h[512]; memset(h, 0, sizeof h);
    const char *base = path;
    size_t plen = strlen(path);
    if(plen > 100){
        const char *slash = strrchr(path, '/');
        if(slash && strlen(slash+1) <= 100){
            size_t pl = slash - path;
            if(pl > 155){ builtin_error("%s: name too long for ustar (prefix > 155)", path); return -1; }
            memcpy(h+345, path, pl);
            base = slash + 1;
        } else {
            builtin_error("%s: name too long for ustar (no split point fitting 100/155)", path); return -1;
        }
    }
    size_t blen = strlen(base);
    memcpy(h, base, blen > 100 ? 100 : blen);

    unsigned long body_size = (typeflag=='0' || typeflag=='x' || typeflag=='g') ? (unsigned long)st->st_size : 0UL;
    put_octal((char*)h+100, 8, (unsigned long)(st->st_mode & 07777));
    put_octal((char*)h+108, 8, (unsigned long)st->st_uid);
    put_octal((char*)h+116, 8, (unsigned long)st->st_gid);
    put_octal((char*)h+124, 12, body_size);
    put_octal((char*)h+136, 12, (unsigned long)st->st_mtime);
    memset(h+148, ' ', 8);
    h[156] = typeflag;
    if(linktarget && (typeflag=='2' || typeflag=='1')){
        size_t llen = strlen(linktarget);
        if(llen > 100){ builtin_error("%s: link target too long for ustar (>100)", path); return -1; }
        memcpy(h+157, linktarget, llen);
    }
    if(typeflag == '3' || typeflag == '4'){
        unsigned long maj = major(st->st_rdev), min = minor(st->st_rdev);
        if(maj > 07777777UL || min > 07777777UL){
            builtin_error("%s: device number too large for ustar", path); return -1;
        }
        put_octal((char *)h+329, 8, maj); put_octal((char *)h+337, 8, min);
    }
    memcpy(h+257, "ustar", 6); memcpy(h+263, "00", 2);
    if(typeflag != 'x' && typeflag != 'g'){
        if(hdr_uname) memcpy(h+265, hdr_uname, strnlen(hdr_uname, 31));
        if(hdr_gname) memcpy(h+297, hdr_gname, strnlen(hdr_gname, 31));
    }
    unsigned sum = 0; for(int i=0;i<512;i++) sum += h[i];
    snprintf((char*)h+148, 8, "%06o", sum); h[154]='\0'; h[155]=' ';
    return fwrite(h, 1, 512, out) == 512 ? 0 : -1;
}

static int append_bytes(char **buf, size_t *len, size_t *cap, const char *s, size_t n){
    if(*len + n + 1 > *cap){
        size_t nc = *cap ? *cap * 2 : 128;
        while(nc < *len + n + 1) nc *= 2;
        char *p = realloc(*buf, nc);
        if(!p) return -1;
        *buf = p; *cap = nc;
    }
    memcpy(*buf + *len, s, n);
    *len += n; (*buf)[*len] = 0;
    return 0;
}

static int append_pax_record(char **buf, size_t *len, size_t *cap, const char *key, const char *val){
    size_t kvlen = strlen(key) + 1 + strlen(val) + 1;
    char tmp[64];
    int digits = 1, reclen;
    do {
        reclen = digits + 1 + (int)kvlen;
        snprintf(tmp, sizeof tmp, "%d", reclen);
        digits = (int)strlen(tmp);
    } while(reclen != digits + 1 + (int)kvlen);
    if(append_bytes(buf, len, cap, tmp, strlen(tmp)) < 0) return -1;
    if(append_bytes(buf, len, cap, " ", 1) < 0) return -1;
    if(append_bytes(buf, len, cap, key, strlen(key)) < 0) return -1;
    if(append_bytes(buf, len, cap, "=", 1) < 0) return -1;
    if(append_bytes(buf, len, cap, val, strlen(val)) < 0) return -1;
    return append_bytes(buf, len, cap, "\n", 1);
}

static const char *pax_fallback_name(const char *path){
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    return *b && strlen(b) <= 100 ? b : "pax-member";
}

static int ustar_name_ok(const char *path){
    size_t plen = strlen(path);
    if(plen <= 100) return 1;
    const char *slash = strrchr(path, '/');
    return slash && strlen(slash + 1) <= 100 && (size_t)(slash - path) <= 155;
}

/* Emit a PAX extended header ('x') for the records the ustar header cannot
   hold: the path when want_path, the link target when given, each numeric
   field flagged in numext, and EXTRA (records already formatted: sparse and
   ACL keys). name is the member's path, used to name the header. */
static int write_pax_ext(FILE *out, const char *name, int want_path, const char *linktarget, const struct stat *st, int numext,
                         const char *extra){
    char *body = NULL; size_t len = 0, cap = 0; char num[32];
    if(want_path && append_pax_record(&body, &len, &cap, "path", name) < 0){ free(body); return -1; }
    if(linktarget && append_pax_record(&body, &len, &cap, "linkpath", linktarget) < 0){ free(body); return -1; }
    if(numext & PAX_EXT_SIZE){ snprintf(num, sizeof num, "%llu", (unsigned long long)st->st_size); if(append_pax_record(&body, &len, &cap, "size", num) < 0){ free(body); return -1; } }
    if(numext & PAX_EXT_UID){ snprintf(num, sizeof num, "%lu", (unsigned long)st->st_uid); if(append_pax_record(&body, &len, &cap, "uid", num) < 0){ free(body); return -1; } }
    if(numext & PAX_EXT_GID){ snprintf(num, sizeof num, "%lu", (unsigned long)st->st_gid); if(append_pax_record(&body, &len, &cap, "gid", num) < 0){ free(body); return -1; } }
    if(numext & PAX_EXT_MTIME){ snprintf(num, sizeof num, "%lld", (long long)st->st_mtime); if(append_pax_record(&body, &len, &cap, "mtime", num) < 0){ free(body); return -1; } }
    if(extra && *extra && append_bytes(&body, &len, &cap, extra, strlen(extra)) < 0){ free(body); return -1; }
    if(!body) return 0;
    struct stat xst = *st;
    xst.st_mode = 0644;
    xst.st_size = (off_t)len;
    xst.st_uid = 0; xst.st_gid = 0;           /* the header record itself must fit ustar */
    char xname[160];
    snprintf(xname, sizeof xname, "PaxHeaders/%.88s", pax_fallback_name(name));
    const char *saved_u = hdr_uname, *saved_g = hdr_gname;
    hdr_uname = hdr_gname = NULL;
    int bad = write_header(out, xname, &xst, 'x', NULL) < 0;
    hdr_uname = saved_u; hdr_gname = saved_g;
    if(bad){ free(body); return -1; }
    fwrite(body, 1, len, out);
    long pad = (512 - ((long)len % 512)) % 512;
    for(long i = 0; i < pad; i++) fputc(0, out);
    free(body);
    return 0;
}

/* path_join3 is defined later; forward-declare it for the directory recursion
   in write_member below. */
static int path_join3(char *out, size_t outsz, const char *a, const char *b);

/* Parse an explicit archive timestamp without changing any input file. */
int bashos_pax_set_mtime(struct bashos_pax_write_context *ctx, const char *seconds){
    const char *digits = seconds + (*seconds == '-' || *seconds == '+');
    char *end;
    if(*digits < '0' || *digits > '9') return -1;
    errno = 0;
    long long value = strtoll(seconds, &end, 10);
    if(errno || *end || (long long)(time_t)value != value) return -1;
    ctx->mtime = (time_t)value;
    ctx->override_mtime = 1;
    return 0;
}

struct bashos_pax_hardlink {
    dev_t device;
    ino_t inode;
    char *path;
    struct bashos_pax_hardlink *next;
};

/* -u: the members already in the archive, with their times. */
struct bashos_pax_archived {
    char *name;
    time_t mtime;
    struct bashos_pax_archived *next;
};

void bashos_pax_write_clear(struct bashos_pax_write_context *ctx){
    while(ctx->links){
        struct bashos_pax_hardlink *next = ctx->links->next;
        free(ctx->links->path); free(ctx->links); ctx->links = next;
    }
    while(ctx->archived){
        struct bashos_pax_archived *next = ctx->archived->next;
        free(ctx->archived->name); free(ctx->archived); ctx->archived = next;
    }
}

static int remember_hardlink(struct bashos_pax_write_context *ctx, const struct stat *st, const char *path){
    if(st->st_nlink < 2) return 0;
    struct bashos_pax_hardlink *entry = malloc(sizeof *entry);
    if(!entry){ builtin_error("out of memory tracking hardlinks"); return 1; }
    entry->path = strdup(path);
    if(!entry->path){ free(entry); builtin_error("out of memory tracking hardlinks"); return 1; }
    entry->device = st->st_dev; entry->inode = st->st_ino;
    entry->next = ctx->links; ctx->links = entry;
    return 0;
}

static int member_excluded(const struct bashos_pax_write_context *ctx, const char *path){
    return name_excluded(ctx->excludes, ctx->nexcludes, path);
}

/* -u: whether the archive already has NAME at least as new as MTIME. */
static int archived_current(const struct bashos_pax_write_context *ctx, const char *name, time_t mtime){
    size_t n = strlen(name);
    while(n > 1 && name[n-1] == '/') n--;
    for(const struct bashos_pax_archived *a = ctx->archived; a; a = a->next)
        if(strlen(a->name) == n && !memcmp(a->name, name, n) && a->mtime >= mtime) return 1;
    return 0;
}

static int cmp_names(const void *a, const void *b){
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The name PATH is stored under: --transform rules, then (tar without -P)
   without its leading '/'. A bare "/" is stored as "./", as GNU tar does. */
static char *archive_name(const struct bashos_pax_write_context *ctx, const char *path, int scope){
    char *t = ctx->xforms ? xform_apply(ctx->xforms, path, scope) : strdup(path);
    if(!t || !ctx->strip_slash || t[0] != '/') return t;
    const char *p = t;
    while(*p == '/') p++;
    char *r = strdup(*p ? p : (scope == XF_REG ? "./" : ""));
    free(t);
    return r;
}

static char *owner_name(uid_t uid){
    static uid_t cached = (uid_t)-1; static char name[33];
    if(uid != cached){
        struct passwd *pw = getpwuid(uid);
        snprintf(name, sizeof name, "%s", pw && strlen(pw->pw_name) <= 31 ? pw->pw_name : "");
        cached = uid;
    }
    return name;
}

static char *group_name(gid_t gid){
    static gid_t cached = (gid_t)-1; static char name[33];
    if(gid != cached){
        struct group *gr = getgrgid(gid);
        snprintf(name, sizeof name, "%s", gr && strlen(gr->gr_name) <= 31 ? gr->gr_name : "");
        cached = gid;
    }
    return name;
}

/* --acls: the SCHILY.acl.* records for PATH (malloc'd, possibly ""). */
static char *acl_records(const char *path, int is_dir){
    char *out = NULL; size_t len = 0, cap = 0;
    if(append_bytes(&out, &len, &cap, "", 0) < 0) return NULL;
    char *a = acl_text(path, "system.posix_acl_access");
    char *d = is_dir ? acl_text(path, "system.posix_acl_default") : NULL;
    int bad = (a && append_pax_record(&out, &len, &cap, "SCHILY.acl.access", a) < 0) ||
              (d && append_pax_record(&out, &len, &cap, "SCHILY.acl.default", d) < 0);
    free(a); free(d);
    if(bad){ free(out); return NULL; }
    return out;
}

/* Write a regular file's bytes [OFF, OFF+LEN) from IN. */
static int copy_range(FILE *in, FILE *out, const char *path, off_t off, unsigned long long len){
    unsigned char buf[16384];
    if(fseeko(in, off, SEEK_SET) < 0){ builtin_error("%s: %s", path, strerror(errno)); return 1; }
    while(len){
        size_t want = len > sizeof buf ? sizeof buf : (size_t)len;
        size_t r = fread(buf, 1, want, in);
        if(!r){ builtin_error("%s: short read", path); return 1; }
        if(fwrite(buf, 1, r, out) != r) return 1;
        len -= r;
    }
    return 0;
}

static int write_member_named(FILE *out, const char *path, const char *arc, struct stat *st,
                              struct bashos_pax_write_context *ctx);

static int write_member(FILE *out, const char *path, struct bashos_pax_write_context *ctx){
    struct stat st;
    if(member_excluded(ctx, path)) return 0;
    if(lstat(path, &st) < 0){ builtin_error("%s: %s", path, strerror(errno)); return 1; }
    char *arc = archive_name(ctx, path, XF_REG);
    if(!arc){ builtin_error("out of memory"); return 1; }
    int rc = write_member_named(out, path, arc, &st, ctx);
    free(arc);
    return rc;
}

static int write_member_named(FILE *out, const char *path, const char *arc, struct stat *stp,
                              struct bashos_pax_write_context *ctx){
    struct stat st = *stp;
    if(ctx->override_mtime) st.st_mtime = ctx->mtime;
    if(ctx->override_uid) st.st_uid = (uid_t)ctx->uid;
    if(ctx->override_gid) st.st_gid = (gid_t)ctx->gid;
    /* ustar's uname/gname: the owner's names, as GNU tar and pax store,
       unless -o uname:=/gname:= (tar --owner/--group/--numeric-owner) set them. */
    hdr_uname = ctx->set_uname ? ctx->uname : owner_name(st.st_uid);
    hdr_gname = ctx->set_gname ? ctx->gname : group_name(st.st_gid);
    int skip_header = !*arc || (ctx->update && archived_current(ctx, arc, st.st_mtime));
    const char *stored_path = ustar_name_ok(arc) ? arc : pax_fallback_name(arc);
    int need_path_ext = !ustar_name_ok(arc);
    char *extra = NULL;
    if(ctx->acls && !skip_header && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))){
        if(!(extra = acl_records(path, S_ISDIR(st.st_mode)))){ builtin_error("out of memory"); return 1; }
    }
    int has_extra = extra && *extra;

    int numext = pax_numeric_ext(&st, S_ISREG(st.st_mode));

    if(S_ISDIR(st.st_mode)){
        if(!skip_header){
            if((need_path_ext || numext || has_extra) && write_pax_ext(out, arc, need_path_ext, NULL, &st, numext, extra) < 0){ free(extra); return 1; }
            if(write_header(out, stored_path, &st, '5', NULL) < 0){ free(extra); return 1; }
        }
        free(extra);
        if(ctx->no_recurse) return 0;
        DIR *d = opendir(path);
        if(!d){ builtin_error("%s: %s", path, strerror(errno)); return 1; }
        int rc = 0; struct dirent *de;
        char **names = NULL; size_t nn = 0, cap = 0;
        while((de = readdir(d)) != NULL){
            if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            if(nn == cap){
                char **g = realloc(names, (cap = cap ? cap * 2 : 64) * sizeof *names);
                if(!g){ builtin_error("out of memory"); rc = 1; break; }
                names = g;
            }
            if(!(names[nn] = strdup(de->d_name))){ builtin_error("out of memory"); rc = 1; break; }
            nn++;
        }
        closedir(d);
        if(ctx->sort_names && nn) qsort(names, nn, sizeof *names, cmp_names);
        for(size_t i = 0; i < nn; i++){
            char child[1024];
            if(path_join3(child, sizeof child, path, names[i]) < 0){ builtin_error("%s/%s: path too long", path, names[i]); rc = 1; }
            else rc |= write_member(out, child, ctx);
            free(names[i]);
        }
        free(names);
        return rc;
    }
    if(skip_header){ free(extra); return 0; }
    if(S_ISLNK(st.st_mode)){
        char tgt[1024] = {0};
        ssize_t r = readlink(path, tgt, sizeof tgt - 1);
        if(r < 0){ builtin_error("%s: readlink: %s", path, strerror(errno)); return 1; }
        tgt[r] = 0;
        char *t = ctx->xforms ? xform_apply(ctx->xforms, tgt, XF_SYM) : strdup(tgt);
        if(!t){ builtin_error("out of memory"); return 1; }
        int need_link_ext = strlen(t) > 100;
        int rc = ((need_path_ext || need_link_ext || numext) && write_pax_ext(out, arc, need_path_ext, need_link_ext ? t : NULL, &st, numext, NULL) < 0) ||
                 write_header(out, stored_path, &st, '2', need_link_ext ? "" : t) < 0;
        free(t);
        return rc;
    }
    if(S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)){
        if((need_path_ext || numext) && write_pax_ext(out, arc, need_path_ext, NULL, &st, numext, NULL) < 0) return 1;
        return write_header(out, stored_path, &st, S_ISFIFO(st.st_mode) ? '6' :
                            S_ISCHR(st.st_mode) ? '3' : '4', NULL) < 0 ? 1 : 0;
    }
    if(!S_ISREG(st.st_mode)){
        builtin_error("%s: unsupported file type for ustar", path); free(extra); return 1;
    }

    for(struct bashos_pax_hardlink *entry = ctx->links; entry; entry = entry->next){
        if(entry->device != st.st_dev || entry->inode != st.st_ino) continue;
        int need_link_ext = strlen(entry->path) > 100;
        numext = pax_numeric_ext(&st, 0); /* Hardlinks have no body/size record. */
        int rc = ((need_path_ext || need_link_ext || numext) &&
                  write_pax_ext(out, arc, need_path_ext, need_link_ext ? entry->path : NULL, &st, numext, NULL) < 0) ||
                 write_header(out, stored_path, &st, '1', need_link_ext ? "" : entry->path) < 0;
        free(extra);
        return rc;
    }

    FILE *in = fopen(path, "rb");
    if(!in){ builtin_error("%s: %s", path, strerror(errno)); free(extra); return 1; }
    /* -S: a file with holes is stored as a GNU PAX 1.0 sparse member: the
       real name and size in GNU.sparse.* records, a map, then only the data. */
    struct sparse_map map = {0};
    int sparse = 0;
    if(ctx->sparse && (unsigned long long)st.st_blocks * 512ULL < (unsigned long long)st.st_size)
        sparse = sparse_scan(fileno(in), st.st_size, &map);
    if(sparse < 0){ builtin_error("out of memory"); fclose(in); free(extra); free(map.v); return 1; }
    int failed = 0;
    if(sparse){
        char *mapbuf = NULL, *recs = NULL; size_t ml = 0, mc = 0, rl = 0, rcap = 0;
        char num[64];
        unsigned long long data = 0;
        snprintf(num, sizeof num, "%zu\n", map.n);
        failed |= append_bytes(&mapbuf, &ml, &mc, num, strlen(num)) < 0;
        for(size_t i = 0; i < map.n; i++){
            snprintf(num, sizeof num, "%llu\n%llu\n", map.v[i].off, map.v[i].len);
            failed |= append_bytes(&mapbuf, &ml, &mc, num, strlen(num)) < 0;
            data += map.v[i].len;
        }
        size_t mapblocks = (ml + 511) / 512 * 512;
        snprintf(num, sizeof num, "%llu", (unsigned long long)st.st_size);
        failed |= append_pax_record(&recs, &rl, &rcap, "GNU.sparse.major", "1") < 0 ||
                  append_pax_record(&recs, &rl, &rcap, "GNU.sparse.minor", "0") < 0 ||
                  append_pax_record(&recs, &rl, &rcap, "GNU.sparse.name", arc) < 0 ||
                  append_pax_record(&recs, &rl, &rcap, "GNU.sparse.realsize", num) < 0 ||
                  (has_extra && append_bytes(&recs, &rl, &rcap, extra, strlen(extra)) < 0);
        /* The ustar name: DIR/GNUSparseFile.0/BASE, as GNU tar writes it. */
        char sname[4096];
        const char *slash = strrchr(arc, '/');
        if(slash) snprintf(sname, sizeof sname, "%.*s/GNUSparseFile.0/%s", (int)(slash - arc), arc, slash + 1);
        else snprintf(sname, sizeof sname, "GNUSparseFile.0/%s", arc);
        struct stat sst = st;
        sst.st_size = (off_t)(mapblocks + data);
        int snumext = pax_numeric_ext(&sst, 1);
        int sneed = !ustar_name_ok(sname);
        if(failed || write_pax_ext(out, sname, sneed, NULL, &sst, snumext, recs) < 0 ||
           write_header(out, sneed ? pax_fallback_name(sname) : sname, &sst, '0', NULL) < 0) failed = 1;
        if(!failed){
            fwrite(mapbuf, 1, ml, out);
            for(size_t i = ml; i < mapblocks; i++) fputc(0, out);
            for(size_t i = 0; i < map.n && !failed; i++)
                if(map.v[i].len) failed = copy_range(in, out, path, (off_t)map.v[i].off, map.v[i].len);
            long pad = (512 - (long)(data % 512)) % 512;
            for(long i = 0; i < pad; i++) fputc(0, out);
        }
        free(mapbuf); free(recs);
    } else {
        if(((need_path_ext || numext || has_extra) && write_pax_ext(out, arc, need_path_ext, NULL, &st, numext, extra) < 0) ||
           write_header(out, stored_path, &st, '0', NULL) < 0) failed = 1;
        if(!failed){
            unsigned char buf[4096]; size_t r;
            off_t remaining = st.st_size;
            while(remaining > 0){
                size_t want = remaining > (off_t)sizeof buf ? sizeof buf : (size_t)remaining;
                r = fread(buf, 1, want, in);
                if(!r){ builtin_error("%s: short read", path); failed = 1; break; }
                if(fwrite(buf, 1, r, out) != r){ failed = 1; break; }
                remaining -= (off_t)r;
            }
            if(!failed){
                long pad = (512 - ((long)st.st_size % 512)) % 512;
                for(long i = 0; i < pad; i++) fputc(0, out);
            }
        }
    }
    free(map.v); free(extra);
    if(ferror(in)) failed = 1;
    if(fclose(in)) failed = 1;
    if(failed || ferror(out)) return 1;
    char *hard = archive_name(ctx, path, XF_HARD);
    if(!hard){ builtin_error("out of memory"); return 1; }
    int rc = remember_hardlink(ctx, &st, hard);
    free(hard);
    return rc;
}

int bashos_pax_write_member_context(FILE *out, const char *path, struct bashos_pax_write_context *ctx){
    return write_member(out, path, ctx) || ferror(out);
}

int bashos_pax_write_member(FILE *out, const char *path, int no_recurse){
    struct bashos_pax_write_context ctx = { .no_recurse = no_recurse };
    int rc = bashos_pax_write_member_context(out, path, &ctx);
    bashos_pax_write_clear(&ctx);
    return rc;
}

static int pax_list_extract(const char *archive, int extract, int verbose, int same_owner){
    FILE *f = archive && strcmp(archive, "-") ? fopen(archive,"rb") : stdin;
    if(!f){ builtin_error("%s: %s", archive ? archive : "stdin", strerror(errno)); return 1; }
    struct bashos_pax_read_options options = { .extract = extract, .verbose = verbose,
                                               .same_owner = same_owner };
    int rc = bashos_pax_read(f, &options);
    if(f != stdin && fclose(f)) rc = 1;
    return rc;
}

/* -a: position OUT at the archive's end-of-archive marker (the first
   all-zero header block), so new members replace it. With ctx->update,
   remember each member's name and time for -u. */
int bashos_pax_seek_end(FILE *out, const char *archive, struct bashos_pax_write_context *ctx){
    unsigned char h[512];
    off_t pos = 0;
    char *pending = NULL;          /* path from a preceding 'x' or 'L' header */
    for(;;){
        if(fseeko(out, pos, SEEK_SET) < 0){ builtin_error("%s: %s", archive, strerror(errno)); free(pending); return -1; }
        size_t got = fread(h, 1, sizeof h, out);
        if(got == 0) break;                 /* empty archive or no marker */
        if(got != sizeof h){ builtin_error("%s: truncated archive", archive); free(pending); return -1; }
        if(zero_block(h)) break;
        if(!hdr_checksum_ok(h)){ builtin_error("%s: not a ustar archive", archive); free(pending); return -1; }
        unsigned long sz = octal((char *)h+124, 12);
        char t = (char)h[156];
        if(ctx && ctx->update && (t == 'x' || t == 'L') && sz < (1UL << 20)){
            char *body = NULL;
            if(read_padded_body(out, sz, &body) == 0){
                struct pax_meta m = {0};
                if(t == 'L'){ trim_gnu_long_body(body, sz); free(pending); pending = strdup(body); }
                else if(pax_parse_records(body, sz, &m) == 0 && (m.path || m.sparse_name)){
                    free(pending); pending = strdup(m.sparse_name ? m.sparse_name : m.path);
                }
                pax_meta_free(&m);
                free(body);
            }
        } else if(ctx && ctx->update && t != 'g'){
            char name[257]; name_from_hdr(name, h);
            struct bashos_pax_archived *a = malloc(sizeof *a);
            if(a && (a->name = pending ? pending : strdup(name))){
                pending = NULL;
                size_t n = strlen(a->name);
                while(n > 1 && a->name[n-1] == '/') a->name[--n] = 0;
                a->mtime = (time_t)octal((char *)h+136, 12);
                a->next = ctx->archived; ctx->archived = a;
            } else free(a);
            free(pending); pending = NULL;
        }
        if(t == '1' || t == '2' || t == '3' || t == '4' || t == '5' || t == '6') sz = 0;
        pos += 512 + (off_t)((sz + 511) / 512) * 512;
    }
    free(pending);
    if(fseeko(out, pos, SEEK_SET) < 0){ builtin_error("%s: %s", archive, strerror(errno)); return -1; }
    return 0;
}

/* tar --delete. Each member is its header plus the 'x'/'L'/'K' headers that
   precede it; global 'g' headers are kept. */
int bashos_pax_delete(FILE *in, FILE *out, const struct bashos_pax_read_options *options){
    unsigned char h[512];
    unsigned char *found = calloc(options->count ? options->count : 1, 1);
    char *prefix = NULL; size_t plen = 0, pcap = 0;   /* buffered extension headers */
    char *pending = NULL;
    int rc = 0;
    if(!found){ builtin_error("out of memory"); return 2; }
    for(;;){
        size_t got = fread(h, 1, sizeof h, in);
        if(got == 0 || zero_block(h)) break;
        if(got != sizeof h || memcmp(h+257, "ustar", 5) || !hdr_checksum_ok(h)){
            builtin_error("This does not look like a tar archive"); rc = 2; break;
        }
        unsigned long sz = octal((char *)h+124, 12);
        char t = (char)h[156];
        int has_data = !(t == '1' || t == '2' || t == '3' || t == '4' || t == '5' || t == '6');
        unsigned long padded = has_data ? (sz + 511) / 512 * 512 : 0;
        char *body = NULL;
        /* Old GNU sparse ('S'): extension blocks follow the header. */
        char *ext = NULL; size_t elen = 0, ecap = 0;
        if(t == 'S'){
            int extended = h[482];
            unsigned char x[512];
            while(extended){
                if(fread(x, 1, 512, in) != 512 || append_bytes(&ext, &elen, &ecap, (char *)x, 512) < 0){ rc = 2; break; }
                extended = x[504];
            }
            if(rc){ free(ext); builtin_error("archive truncated"); break; }
        }
        if(padded){
            if(!(body = malloc(padded)) || fread(body, 1, padded, in) != padded){
                free(body); free(ext); builtin_error("archive truncated"); rc = 2; break;
            }
        }
        if(t == 'g'){
            if(fwrite(h, 1, 512, out) != 512 || (padded && fwrite(body, 1, padded, out) != padded)) rc = 2;
            free(body); free(ext); continue;
        }
        if(t == 'x' || t == 'L' || t == 'K'){
            if(t == 'x'){
                struct pax_meta m = {0};
                if(pax_parse_records(body, sz, &m) == 0 && (m.path || m.sparse_name)){
                    free(pending); pending = strdup(m.sparse_name ? m.sparse_name : m.path);
                }
                pax_meta_free(&m);
            } else if(t == 'L'){
                char *copy = malloc(sz + 1);
                if(copy){ memcpy(copy, body, sz); copy[sz] = 0; trim_gnu_long_body(copy, sz); free(pending); pending = copy; }
            }
            if(append_bytes(&prefix, &plen, &pcap, (char *)h, 512) < 0 ||
               (padded && append_bytes(&prefix, &plen, &pcap, body, padded) < 0)){ free(body); free(ext); rc = 2; break; }
            free(body); free(ext); continue;
        }
        char hdrname[257]; name_from_hdr(hdrname, h);
        const char *name = pending ? pending : hdrname;
        int drop = 0;
        for(size_t i = 0; i < options->count; i++){
            const char *wanted = options->members[i]; size_t len = strlen(wanted);
            while(len && wanted[len-1] == '/') len--;
            if(options->wildcards ? fnmatch(wanted, name, FNM_LEADING_DIR) == 0 :
               !strncmp(name, wanted, len) && (name[len] == 0 || name[len] == '/')){
                drop = 1; found[i] = 1;
            }
        }
        if(!drop && ((plen && fwrite(prefix, 1, plen, out) != plen) || fwrite(h, 1, 512, out) != 512 ||
                     (elen && fwrite(ext, 1, elen, out) != elen) ||
                     (padded && fwrite(body, 1, padded, out) != padded))) rc = 2;
        free(body); free(ext); free(pending); pending = NULL; plen = 0;
    }
    unsigned char zero[1024] = {0};
    if(rc != 2 && fwrite(zero, 1, sizeof zero, out) != sizeof zero) rc = 2;
    free(prefix); free(pending);
    for(size_t i = 0; i < options->count; i++) if(!found[i]){
        builtin_error("%s: Not found in archive", options->members[i]); if(!rc) rc = 1;
    }
    free(found);
    return rc;
}

static int pax_write(const char *archive, WORD_LIST *files, struct bashos_pax_write_context *ctx, int append){
    if(append && !archive){ builtin_error("-a needs -f ARCHIVE"); return EX_USAGE; }
    FILE *out = archive ? fopen(archive, append ? "r+b" : "wb") : stdout;
    if(!out && append && errno == ENOENT) out = fopen(archive, "w+b");
    if(!out){ builtin_error("%s: %s", archive, strerror(errno)); return EXECUTION_FAILURE; }
    if(append && bashos_pax_seek_end(out, archive, ctx) < 0){ fclose(out); bashos_pax_write_clear(ctx); return EXECUTION_FAILURE; }
    int rc = 0;
    for(; files; files = files->next) rc |= bashos_pax_write_member_context(out, files->word->word, ctx);
    bashos_pax_write_clear(ctx);
    unsigned char z[1024]; memset(z, 0, sizeof z);
    fwrite(z, 1, sizeof z, out);
    if(out != stdout) fclose(out);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int copy_file_bytes(const char *src, const char *dst, const struct stat *st){
    FILE *in = fopen(src, "rb");
    if(!in){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
    mkpath_parents(dst, 0755);
    FILE *out = fopen(dst, "wb");
    if(!out){ builtin_error("%s: %s", dst, strerror(errno)); fclose(in); return 1; }
    unsigned char buf[8192]; size_t n; int rc = 0;
    while((n = fread(buf, 1, sizeof buf, in)) > 0){
        if(fwrite(buf, 1, n, out) != n){ builtin_error("%s: write: %s", dst, strerror(errno)); rc = 1; break; }
    }
    if(ferror(in)){ builtin_error("%s: read: %s", src, strerror(errno)); rc = 1; }
    fclose(in);
    if(fclose(out) != 0){ builtin_error("%s: close: %s", dst, strerror(errno)); rc = 1; }
    if(!rc){
        chmod(dst, st->st_mode & 0777);
        set_mtime(dst, st->st_mtime, 0);
    }
    return rc;
}

static int path_join3(char *out, size_t outsz, const char *a, const char *b){
    size_t al = strlen(a);
    int slash = (al && a[al-1] != '/');
    return snprintf(out, outsz, "%s%s%s", a, slash ? "/" : "", b) < (int)outsz ? 0 : -1;
}

static int copy_tree(const char *src, const char *dstroot){
    if(unsafe_path(src)){ builtin_error("%s: unsafe copy-mode path", src); return 1; }
    char dst[1024];
    if(path_join3(dst, sizeof dst, dstroot, src) < 0){ builtin_error("%s: destination path too long", src); return 1; }

    struct stat st;
    if(lstat(src, &st) < 0){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
    if(S_ISDIR(st.st_mode)){
        if(mkpath_parents(dst, 0755) < 0){ builtin_error("%s: mkdir parent: %s", dst, strerror(errno)); return 1; }
        if(mkdir(dst, st.st_mode & 0777) < 0 && errno != EEXIST){ builtin_error("%s: %s", dst, strerror(errno)); return 1; }
        DIR *d = opendir(src);
        if(!d){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
        int rc = 0; struct dirent *de;
        while((de = readdir(d)) != NULL){
            if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char child[1024];
            if(path_join3(child, sizeof child, src, de->d_name) < 0){ builtin_error("%s/%s: path too long", src, de->d_name); rc = 1; continue; }
            rc |= copy_tree(child, dstroot);
        }
        closedir(d);
        set_mtime(dst, st.st_mtime, 0);
        return rc;
    }
    if(S_ISLNK(st.st_mode)){
        char tgt[512];
        ssize_t r = readlink(src, tgt, sizeof tgt - 1);
        if(r < 0){ builtin_error("%s: readlink: %s", src, strerror(errno)); return 1; }
        tgt[r] = 0;
        if(tgt[0] == '/' || unsafe_path(tgt)){ builtin_error("%s: unsafe symlink target '%s'", src, tgt); return 1; }
        mkpath_parents(dst, 0755);
        unlink(dst);
        if(symlink(tgt, dst) < 0){ builtin_error("%s: symlink: %s", dst, strerror(errno)); return 1; }
        set_mtime(dst, st.st_mtime, 1);
        return 0;
    }
    if(S_ISREG(st.st_mode)) return copy_file_bytes(src, dst, &st);
    builtin_error("%s: unsupported file type for copy mode", src);
    return 1;
}

static int pax_copy(WORD_LIST *files){
    int count = 0;
    WORD_LIST *last = NULL;
    for(WORD_LIST *p = files; p; p = p->next){ count++; last = p; }
    if(count < 2){ builtin_error("-rw copy mode needs FILE... DIRECTORY"); return EX_USAGE; }
    const char *dstroot = last->word->word;
    struct stat dstst;
    if(stat(dstroot, &dstst) < 0 || !S_ISDIR(dstst.st_mode)){
        builtin_error("%s: destination is not a directory", dstroot);
        return EXECUTION_FAILURE;
    }
    int rc = 0;
    for(WORD_LIST *p = files; p && p != last; p = p->next)
        rc |= copy_tree(p->word->word, dstroot);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int pax_number(const char *s, unsigned long *out){
    char *end;
    if(*s < '0' || *s > '9') return -1;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if(errno || *end || v > 07777777UL) return -1;
    *out = v;
    return 0;
}

/* The value of an option letter: the rest of its word (-fARCHIVE), else
   the next word (-f ARCHIVE, -wf ARCHIVE). */
static const char *pax_optarg(WORD_LIST **list, const char **c){
    const char *v = c[0] + 1;
    *c += strlen(*c) - 1;
    if(*v) return v;
    if(!(*list)->next) return NULL;
    *list = (*list)->next;
    return (*list)->word->word;
}

static int pax_set_option(const char *kv, struct bashos_pax_write_context *writer,
                          const char **excl, size_t *nexcl){
    int bad = 0;
    if(!strncmp(kv, "mtime:=", 7)) bad = bashos_pax_set_mtime(writer, kv + 7) < 0;
    else if(!strncmp(kv, "uid:=", 5)) { bad = pax_number(kv + 5, &writer->uid) < 0; writer->override_uid = 1; }
    else if(!strncmp(kv, "gid:=", 5)) { bad = pax_number(kv + 5, &writer->gid) < 0; writer->override_gid = 1; }
    else if(!strncmp(kv, "uname:=", 7)) { bad = strlen(kv + 7) > 31; snprintf(writer->uname, sizeof writer->uname, "%s", kv + 7); writer->set_uname = 1; }
    else if(!strncmp(kv, "gname:=", 7)) { bad = strlen(kv + 7) > 31; snprintf(writer->gname, sizeof writer->gname, "%s", kv + 7); writer->set_gname = 1; }
    else if(!strncmp(kv, "exclude:=", 9)) { bad = *nexcl == 64 || !kv[9]; if(!bad) excl[(*nexcl)++] = kv + 9; }
    else if(!strcmp(kv, "sort:=name")) writer->sort_names = 1;
    else if(!strcmp(kv, "sort:=none")) writer->sort_names = 0;
    else if(!strncmp(kv, "transform:=", 11)) return bashos_pax_xform_add(&writer->xforms, kv + 11);
    else if(!strcmp(kv, "strip-slash")) writer->strip_slash = 1;
    else if(!strcmp(kv, "sparse")) writer->sparse = 1;
    else if(!strcmp(kv, "acls")) writer->acls = 1;
    else bad = 1;
    if(bad) builtin_error("-o requires mtime:=EPOCH, uid:=N, gid:=N, uname:=NAME, gname:=NAME, exclude:=PATTERN, sort:=name|none, transform:=s/RE/REPL/, strip-slash, sparse or acls");
    return bad ? -1 : 0;
}

/* POSIX utility-syntax options: letters group (-wvf ARCHIVE, -rf ARCHIVE),
   and an option-argument is the rest of the word or the next word. */
int pax_builtin(WORD_LIST *list){
    int read_mode=0, write_mode=0, verbose=0, append=0, same_owner=0;
    const char *archive=NULL; WORD_LIST *files=NULL;
    struct bashos_pax_write_context writer = {0};
    const char *excl[64]; size_t nexcl = 0;
    for(; list; list = list->next){
        const char *w=list->word->word;
        if(!strcmp(w,"--")){ files=list->next; break; }
        if(w[0] != '-' || !w[1]){ files=list; break; }
        for(const char *c = w + 1; *c; c++){
            const char *v;
            switch(*c){
            case 'r': read_mode=1; break;
            case 'w': write_mode=1; break;
            case 'v': verbose=1; break;
            case 'd': writer.no_recurse=1; break;
            case 'a': append=1; break;
            case 'u': writer.update=1; break;
            case 'f': case 'o': case 'x': case 'b': case 'p': {
                char letter = *c;
                if(!(v = pax_optarg(&list, &c))){
                    builtin_error("option requires an argument -- '%c'", letter);
                    return EX_USAGE;
                }
                if(letter == 'f') archive = v;
                else if(letter == 'o'){ if(pax_set_option(v, &writer, excl, &nexcl) < 0) return EX_USAGE; }
                else if(letter == 'x'){
                    /* Archives are written as ustar, with pax extended
                       headers only for values ustar cannot hold. */
                    if(strcmp(v, "ustar") && strcmp(v, "pax")){
                        builtin_error("%s: unsupported archive format (ustar and pax only)", v);
                        return EX_USAGE;
                    }
                }
                else if(letter == 'b'){
                    unsigned long blocksize;
                    if(pax_number(v, &blocksize) < 0 || !blocksize || blocksize % 512){
                        builtin_error("%s: invalid block size", v); return EX_USAGE;
                    }
                }
                else {
                    /* -p a/m/p are accepted (times and modes are always
                       restored); e and o also restore the archived owner. */
                    for(const char *q = v; *q; q++){
                        if(*q == 'e' || *q == 'o') same_owner = 1;
                        else if(*q != 'a' && *q != 'm' && *q != 'p'){
                            builtin_error("%s: invalid -p string", v); return EX_USAGE;
                        }
                    }
                }
                break;
            }
            default:
                builtin_error("unknown option -- '%c'", *c);
                return EX_USAGE;
            }
        }
    }
    int mode = read_mode && write_mode ? 3 : write_mode ? 1 : read_mode ? 2 : 0;
    writer.excludes = excl; writer.nexcludes = nexcl;
    if(mode==1){
        if(writer.update && !append){ builtin_error("-u requires -a"); bashos_pax_xform_free(&writer.xforms); return EX_USAGE; }
        int rc = pax_write(archive && strcmp(archive, "-") ? archive : NULL,files,&writer,append);
        bashos_pax_xform_free(&writer.xforms);
        return rc;
    }
    bashos_pax_xform_free(&writer.xforms);
    if(append){ builtin_error("-a requires -w"); return EX_USAGE; }
    if(writer.override_mtime){ builtin_error("mtime override requires -w"); return EX_USAGE; }
    if(mode==2) return pax_list_extract(archive,1,verbose,same_owner);
    if(mode==3) return pax_copy(files);
    return pax_list_extract(archive,0,verbose,0);
}

char *pax_doc[] = {
    "POSIX pax ustar subset: list, -w create, -r extract, -rw copy.",
    "With -w, -o mtime:=EPOCH_SECONDS sets the archived modification time;",
    "-o uid:=N, gid:=N, uname:=NAME, gname:=NAME set the archived owner;",
    "-o exclude:=PATTERN skips matching members (unanchored, as tar --exclude);",
    "-o sort:=name archives directory entries in byte order; -a appends to ARCHIVE;",
    "-a -u appends only files newer than their archived copy.",
    "-o transform:=s/RE/REPL/FLAGS rewrites names as tar --transform; -o strip-slash",
    "stores absolute names without their leading '/'; -o sparse stores files with",
    "holes as GNU PAX 1.0 sparse members; -o acls stores POSIX ACLs (SCHILY.acl.*).",
    "Members are stored with their owner's user and group names.",
    "Option letters group as POSIX allows (pax -wf ARCHIVE FILE..., pax -rvf ARCHIVE).",
    "-x ustar|pax names the write format (ustar, with pax headers only when needed);",
    "-b BLOCKSIZE is accepted; -r -p o (or -p e) restores the archived owner and group.",
    "    bashpax [-v] [-f ARCHIVE] | bashpax -w [-x ustar] -f ARCHIVE FILE... | bashpax -r [-p o] -f ARCHIVE | bashpax -rw FILE... DIR",
    (char*)NULL
};
struct builtin bashpax_struct = {"bashpax",pax_builtin,BUILTIN_ENABLED,pax_doc,"bashpax [-r|-w] [-aduv] [-f ARCHIVE] [-o OPTION] [-p STRING] [-x FORMAT] [FILE...]",0};
struct builtin pax_struct    = {"pax",   pax_builtin,BUILTIN_ENABLED,pax_doc,"pax [-r|-w] [-aduv] [-f ARCHIVE] [-o OPTION] [-p STRING] [-x FORMAT] [FILE...]",0};
