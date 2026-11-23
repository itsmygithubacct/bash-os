/* SPDX-License-Identifier: MIT */
/* cp: copy files and directories, as a bash builtin.
 *
 * Written for bash-os from the GNU coreutils manual, POSIX.1-2024 and the
 * observed behaviour of GNU coreutils 9.7 cp: its options, diagnostics,
 * prompts, -v and --debug reports and exit status.
 *
 *   cp [OPTION]... [-T] SOURCE DEST
 *   cp [OPTION]... SOURCE... DIRECTORY
 *   cp [OPTION]... -t DIRECTORY SOURCE...
 *
 * A recursive copy recreates FIFOs, sockets and device nodes instead of
 * reading them, unless --copy-contents is given; without -R every source
 * that is not a directory is read as data (so "cp /dev/null x" works).
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include "loadables.h"
#include "gnu-longopt.h"
#include "gnu-quote.h"

#ifndef FICLONE
#  define FICLONE _IOW (0x94, 9, int)
#endif

enum { CP_DEREF_UNSET, CP_DEREF_NEVER, CP_DEREF_ARGS, CP_DEREF_ALWAYS };
enum { CP_ASK_UNSET, CP_ASK_USER, CP_ASK_NO };
enum { CP_UPDATE_ALL, CP_UPDATE_NONE, CP_UPDATE_NONE_FAIL, CP_UPDATE_OLDER };
enum { CP_SPARSE_NEVER, CP_SPARSE_AUTO, CP_SPARSE_ALWAYS };
enum { CP_REFLINK_AUTO, CP_REFLINK_ALWAYS, CP_REFLINK_NEVER };
enum { CP_P_MODE, CP_P_TIME, CP_P_OWNER, CP_P_LINKS, CP_P_CONTEXT, CP_P_XATTR, CP_P_ALL };

/* What becomes of a non-directory source. */
enum { CP_AS_DATA, CP_AS_SYMLINK, CP_AS_SPECIAL, CP_AS_HARDLINK, CP_AS_SYMBOLIC };

/* A source file already copied: later sources with the same identity are
   linked to its copy when hard links are preserved. */
typedef struct cp_seen {
    dev_t sdev, ddev;
    ino_t sino, dino;
    int follow;
    char *dst;
    struct cp_seen *next;
} cp_seen;

/* A file identity, optionally with a name (top-level destinations written
   by this command; top-level source names already handled). */
typedef struct cp_mark {
    dev_t dev;
    ino_t ino;
    char *name;
    struct cp_mark *next;
} cp_mark;

/* The source directories being copied, innermost first. */
typedef struct cp_chain {
    dev_t dev;
    ino_t ino;
    const struct cp_chain *up;
} cp_chain;

typedef struct {
    int recursive, deref, ask, update, force, remove_dest, verbose, debug;
    int hard_link, sym_link, xdev, notarget, parents, copy_contents, keep_dir_symlink;
    int attr_only, sparse, reflink;
    int backup_wanted, backup;
    const char *backup_control, *suffix;
    int p_mode, p_owner, p_time, p_links, p_xattr, p_context, need_context;
    int quiet_attrs, no_mode, context_seen;
    int posixly;
    mode_t umask;
    /* State of one invocation. */
    cp_seen *seen;
    cp_mark *made, *names;
    const cp_chain *chain;
    dev_t root_dev;
    int abort_arg, top_in_dir;
    cp_mark *dirs;              /* directories this command created */
    const char *top_src, *top_dst;
    char *backup_note;
} cp_ctx;

/* ---- diagnostics -------------------------------------------------------- */

static char *cp_quotes[4];
static unsigned cp_quote_next;

/* NAME quoted as GNU quotes file names; valid for the next three calls. */
static const char *
cp_q (const char *name)
{
    unsigned slot = cp_quote_next++ % 4;
    free (cp_quotes[slot]);
    cp_quotes[slot] = bos_quoteaf (name);
    return cp_quotes[slot] ? cp_quotes[slot] : name;
}

static void
cp_quotes_free (void)
{
    for (int i = 0; i < 4; i++) {
        free (cp_quotes[i]);
        cp_quotes[i] = NULL;
    }
}

/* Standard output. When it is not a terminal GNU cp's reports sit in a
   4 KiB stdio buffer until it fills, a diagnostic is printed, or cp exits,
   so prompts and diagnostics on a shared stderr come out ahead of them.
   bash keeps stdout line-buffered, so the builtin holds them itself. */
static char cp_obuf[4096];
static size_t cp_olen;
static int cp_ohold;

static void
cp_oflush (void)
{
    if (cp_olen) {
        fwrite (cp_obuf, 1, cp_olen, stdout);
        cp_olen = 0;
    }
    fflush (stdout);
}

static void
cp_out (const char *fmt, ...)
{
    char small[1024], *text = small;
    va_list ap;
    int n;

    va_start (ap, fmt);
    n = vsnprintf (small, sizeof small, fmt, ap);
    va_end (ap);
    if (n < 0)
        return;
    if (n >= (int) sizeof small) {
        if (!(text = malloc ((size_t) n + 1)))
            return;
        va_start (ap, fmt);
        vsnprintf (text, (size_t) n + 1, fmt, ap);
        va_end (ap);
    }
    if (!cp_ohold)
        fputs (text, stdout);
    else {
        size_t len = (size_t) n, off = 0;
        while (len - off > 0) {
            size_t room = sizeof cp_obuf - cp_olen, take = len - off < room ? len - off : room;
            memcpy (cp_obuf + cp_olen, text + off, take);
            cp_olen += take;
            off += take;
            if (cp_olen == sizeof cp_obuf)
                cp_oflush ();
        }
    }
    if (text != small)
        free (text);
}

/* A diagnostic with the builtin's prefix; ERRNUM adds ": strerror". */
static void
cp_err (int errnum, const char *fmt, ...)
{
    char small[512], *text = small;
    va_list ap;
    int n;

    cp_oflush ();
    va_start (ap, fmt);
    n = vsnprintf (small, sizeof small, fmt, ap);
    va_end (ap);
    if (n >= (int) sizeof small && (text = malloc ((size_t) n + 1)) != NULL) {
        va_start (ap, fmt);
        vsnprintf (text, (size_t) n + 1, fmt, ap);
        va_end (ap);
    } else if (n >= (int) sizeof small)
        text = small;
    if (errnum)
        builtin_error ("%s: %s", text, strerror (errnum));
    else
        builtin_error ("%s", text);
    if (text != small)
        free (text);
}

static void
cp_mode_text (mode_t mode, char out[10])
{
    static const char letters[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++)
        out[i] = (mode & (0400 >> i)) ? letters[i] : '-';
    if (mode & S_ISUID)
        out[2] = (mode & S_IXUSR) ? 's' : 'S';
    if (mode & S_ISGID)
        out[5] = (mode & S_IXGRP) ? 's' : 'S';
    if (mode & S_ISVTX)
        out[8] = (mode & S_IXOTH) ? 't' : 'T';
    out[9] = '\0';
}

/* One line from standard input; affirmative when it starts with y or Y. */
static int
cp_yes (void)
{
    int first = -1;
    for (;;) {
        char ch;
        ssize_t n = read (0, &ch, 1);
        if (n < 0 && errno == EINTR) {
            QUIT;
            continue;
        }
        if (n <= 0)
            break;
        if (first < 0)
            first = (unsigned char) ch;
        if (ch == '\n')
            break;
    }
    return first == 'y' || first == 'Y';
}

/* -i: ask before replacing DST (whose lstat is DL). */
static int
cp_confirm (const cp_ctx *c, const char *dst, const struct stat *dl)
{
    char modes[10];

    if (!cp_ohold)
        fflush (stdout);
    if (!S_ISLNK (dl->st_mode) && faccessat (AT_FDCWD, dst, W_OK, AT_EACCESS) != 0
        && errno == EACCES) {
        cp_mode_text (dl->st_mode, modes);
        if (c->force || c->remove_dest)
            fprintf (stderr, "cp: replace %s, overriding mode %04lo (%s)? ", cp_q (dst),
                     (unsigned long) (dl->st_mode & 07777), modes);
        else
            fprintf (stderr, "cp: unwritable %s (mode %04lo, %s); try anyway? ", cp_q (dst),
                     (unsigned long) (dl->st_mode & 07777), modes);
    } else
        fprintf (stderr, "cp: overwrite %s? ", cp_q (dst));
    fflush (stderr);
    return cp_yes ();
}

/* "'SRC' -> 'DST'", with the backup made for it. */
static void
cp_verbose (cp_ctx *c, const char *src, const char *dst)
{
    if (c->verbose) {
        if (c->backup_note)
            cp_out ("%s -> %s (backup: %s)\n", cp_q (src), cp_q (dst), cp_q (c->backup_note));
        else
            cp_out ("%s -> %s\n", cp_q (src), cp_q (dst));
    }
    free (c->backup_note);
    c->backup_note = NULL;
}

static int
cp_remove (cp_ctx *c, const char *dst)
{
    if (unlink (dst) < 0) {
        cp_err (errno, "cannot remove %s", cp_q (dst));
        return -1;
    }
    if (c->verbose)
        cp_out ("removed %s\n", cp_q (dst));
    return 0;
}

static int
cp_make_backup (cp_ctx *c, const char *dst)
{
    char *name = bos_backup_name (dst, c->backup, c->suffix);
    if (!name || rename (dst, name) < 0) {
        cp_err (errno, "cannot backup %s", cp_q (dst));
        free (name);
        return -1;
    }
    free (c->backup_note);
    c->backup_note = name;
    return 0;
}

/* ---- names -------------------------------------------------------------- */

static int
cp_same (const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* DIR/NAME, with DIR's trailing slashes folded into the one separator. */
static char *
cp_join (const char *dir, const char *name)
{
    size_t dl = strlen (dir), nl = strlen (name);
    while (dl > 1 && dir[dl - 1] == '/')
        dl--;
    int sep = !(dl == 1 && dir[0] == '/') && dl > 0;
    char *path = malloc (dl + sep + nl + 1);
    if (!path) {
        cp_err (0, "memory exhausted");
        return NULL;
    }
    memcpy (path, dir, dl);
    if (sep)
        path[dl++] = '/';
    memcpy (path + dl, name, nl + 1);
    return path;
}

/* The last component of NAME, ignoring trailing slashes. */
static char *
cp_last (const char *name)
{
    size_t end = strlen (name), start;
    while (end > 1 && name[end - 1] == '/')
        end--;
    start = end;
    while (start > 0 && name[start - 1] != '/')
        start--;
    char *base = strndup (name + start, end - start);
    if (!base)
        cp_err (0, "memory exhausted");
    return base;
}

/* The directory holding NAME, as a new string. */
static char *
cp_parent (const char *name)
{
    size_t end = strlen (name);
    while (end > 1 && name[end - 1] == '/')
        end--;
    while (end > 0 && name[end - 1] != '/')
        end--;
    if (end == 0)
        return strdup (".");
    while (end > 1 && name[end - 1] == '/')
        end--;
    return strndup (name, end);
}

static cp_mark *
cp_mark_find (cp_mark *list, dev_t dev, ino_t ino, const char *name)
{
    for (; list; list = list->next)
        if (list->dev == dev && list->ino == ino && (!name || !strcmp (list->name, name)))
            return list;
    return NULL;
}

static void
cp_mark_add (cp_mark **list, dev_t dev, ino_t ino, const char *name)
{
    cp_mark *m = malloc (sizeof *m);
    if (!m)
        return;
    m->dev = dev;
    m->ino = ino;
    m->name = name ? strdup (name) : NULL;
    m->next = *list;
    *list = m;
}

static void
cp_marks_free (cp_mark **list)
{
    while (*list) {
        cp_mark *next = (*list)->next;
        free ((*list)->name);
        free (*list);
        *list = next;
    }
}

/* ---- hard links between sources ---------------------------------------- */

static cp_seen *
cp_seen_find (cp_ctx *c, const struct stat *src)
{
    for (cp_seen *e = c->seen; e; e = e->next) {
        struct stat st;
        if (e->sdev == src->st_dev && e->sino == src->st_ino
            && (e->follow ? stat (e->dst, &st) : lstat (e->dst, &st)) == 0
            && st.st_dev == e->ddev && st.st_ino == e->dino)
            return e;
    }
    return NULL;
}

static void
cp_seen_add (cp_ctx *c, const struct stat *src, const char *dst)
{
    struct stat st;
    int follow = S_ISREG (src->st_mode);
    if ((follow ? stat (dst, &st) : lstat (dst, &st)) < 0)
        return;
    cp_seen *e = malloc (sizeof *e);
    if (!e || !(e->dst = strdup (dst))) {
        free (e);
        return;
    }
    e->sdev = src->st_dev;
    e->sino = src->st_ino;
    e->ddev = st.st_dev;
    e->dino = st.st_ino;
    e->follow = follow;
    e->next = c->seen;
    c->seen = e;
}

/* A later operand that writes to a path copied earlier in this command
   must not reuse the stale entry. */
static void
cp_seen_forget (cp_ctx *c, const char *dst, const struct stat *src)
{
    for (cp_seen **slot = &c->seen; *slot;) {
        cp_seen *e = *slot;
        if (!strcmp (e->dst, dst) && (e->sdev != src->st_dev || e->sino != src->st_ino)) {
            *slot = e->next;
            free (e->dst);
            free (e);
        } else
            slot = &e->next;
    }
}

/* ---- attributes --------------------------------------------------------- */

static int
cp_copy_acl (const char *src, const char *dst, const char *xname)
{
    unsigned char buf[8192];
    ssize_t n = getxattr (src, xname, buf, sizeof buf);
    if (n < 0) {
        if (errno != ENODATA && errno != EOPNOTSUPP && errno != ENOTSUP) {
            cp_err (errno, "preserving permissions for %s", cp_q (dst));
            return -1;
        }
        /* No ACL on the source: drop one the destination inherited. */
        if (removexattr (dst, xname) < 0 && errno != ENODATA && errno != EOPNOTSUPP
            && errno != ENOTSUP) {
            cp_err (errno, "preserving permissions for %s", cp_q (dst));
            return -1;
        }
        return 0;
    }
    if (setxattr (dst, xname, buf, (size_t) n, 0) < 0) {
        cp_err (errno, "preserving permissions for %s", cp_q (dst));
        return -1;
    }
    return 0;
}

/* Extended attributes other than ACLs, best effort under -a and
   --preserve=all. */
static int
cp_copy_xattrs (const cp_ctx *c, const char *src, const char *dst, int nofollow)
{
    char names[8192], value[16384];
    ssize_t len = nofollow ? llistxattr (src, names, sizeof names)
                           : listxattr (src, names, sizeof names);
    int rc = 0;
    if (len <= 0)
        return 0;
    for (char *name = names; name < names + len; name += strlen (name) + 1) {
        if (!strncmp (name, "system.posix_acl_", 17) || !strncmp (name, "security.", 9))
            continue;
        ssize_t n = nofollow ? lgetxattr (src, name, value, sizeof value)
                             : getxattr (src, name, value, sizeof value);
        if (n < 0)
            continue;
        if ((nofollow ? lsetxattr (dst, name, value, (size_t) n, 0)
                      : setxattr (dst, name, value, (size_t) n, 0)) < 0
            && !c->quiet_attrs && errno != ENOTSUP && errno != EOPNOTSUPP) {
            cp_err (errno, "setting attribute %s for %s", cp_q (name), cp_q (dst));
            rc = -1;
        }
    }
    return rc;
}

static int
cp_set_times (const char *dst, const struct stat *st, int nofollow)
{
    struct timespec ts[2] = { st->st_atim, st->st_mtim };
    if (utimensat (AT_FDCWD, dst, ts, nofollow ? AT_SYMLINK_NOFOLLOW : 0) == 0)
        return 0;
    if (errno == ENOSYS && !nofollow) {
        /* Kernels without utimensat. */
        struct timeval tv[2];
        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;
        if (utimes (dst, tv) == 0)
            return 0;
    }
    cp_err (errno, "preserving times for %s", cp_q (dst));
    return -1;
}

/* -p and --preserve for DST, a copy of SRC (whose attributes are ST). SRC
   may be NULL (--parents directories): then ACLs and xattrs are skipped.
   NOFOLLOW is set for symbolic links. */
static int
cp_attributes (const cp_ctx *c, const char *src, const char *dst, const struct stat *st,
               int nofollow)
{
    int rc = 0;
    if (c->p_time && cp_set_times (dst, st, nofollow) < 0)
        rc = -1;
    /* chown can clear set-ID bits, so the mode comes afterwards. */
    if (c->p_owner) {
        int r = nofollow ? lchown (dst, st->st_uid, st->st_gid) : chown (dst, st->st_uid, st->st_gid);
        if (r < 0 && errno == EPERM)
            r = nofollow ? lchown (dst, (uid_t) -1, st->st_gid) : chown (dst, (uid_t) -1, st->st_gid);
        if (r < 0 && errno != EPERM && errno != EINVAL) {
            cp_err (errno, "failed to preserve ownership for %s", cp_q (dst));
            rc = -1;
        }
    }
    if (nofollow)
        return rc;
    if (c->p_xattr && src && cp_copy_xattrs (c, src, dst, 0) < 0)
        rc = -1;
    if (c->p_mode) {
        if (chmod (dst, st->st_mode & 07777) < 0) {
            cp_err (errno, "preserving permissions for %s", cp_q (dst));
            rc = -1;
        } else if (src) {
            if (cp_copy_acl (src, dst, "system.posix_acl_access") < 0)
                rc = -1;
            if (S_ISDIR (st->st_mode) && cp_copy_acl (src, dst, "system.posix_acl_default") < 0)
                rc = -1;
        }
    }
    return rc;
}

/* ---- data --------------------------------------------------------------- */

typedef struct {
    const char *offload, *reflink, *sparse;
} cp_report;

static char cp_buffer[128 * 1024];

static int
cp_all_zero (const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return 0;
    return 1;
}

/* Write LEN bytes, or skip whole zero blocks when HOLES (the file size is
   fixed up afterwards). */
static int
cp_put (int fd, const char *buf, size_t len, int holes, const char *dst)
{
    enum { BLOCK = 4096 };
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (holes) {
            if (n > BLOCK)
                n = BLOCK;
            if (n == BLOCK && cp_all_zero (buf + off, n)) {
                if (lseek (fd, (off_t) n, SEEK_CUR) < 0) {
                    cp_err (errno, "cannot lseek %s", cp_q (dst));
                    return -1;
                }
                off += n;
                continue;
            }
        }
        ssize_t w = write (fd, buf + off, n);
        if (w < 0) {
            if (errno == EINTR) {
                QUIT;
                continue;
            }
            cp_err (errno, "error writing %s", cp_q (dst));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* Copy up to LEN bytes (LEN < 0: to end of file) from the current offsets.
   *OFFLOAD is 1 while copy_file_range may be tried, 0 once it must not
   be. Returns the bytes copied, or -1. */
static off_t
cp_range (int sfd, int dfd, off_t len, int *offload, int holes, cp_report *r,
          const char *src, const char *dst)
{
    off_t done = 0;
#if defined (SYS_copy_file_range)
    while (*offload && (len < 0 || done < len)) {
        size_t want = len < 0 ? (size_t) 1 << 30 : (size_t) (len - done);
        ssize_t n = syscall (SYS_copy_file_range, sfd, NULL, dfd, NULL, want, 0);
        if (n > 0) {
            done += n;
            r->offload = "yes";
            QUIT;
            continue;
        }
        if (n == 0) {
            if (done == 0 && strcmp (r->offload, "yes") != 0) {
                /* Nothing came back: the source may not support it (or is
                   empty); read it to be sure. */
                r->offload = "unknown";
                *offload = 0;
                break;
            }
            return done;
        }
        if (errno == EINTR) {
            QUIT;
            continue;
        }
        if (errno == ENOSYS || errno == EXDEV || errno == EINVAL || errno == EOPNOTSUPP
            || errno == ENOTSUP || errno == EBADF || errno == EPERM || errno == ETXTBSY) {
            if (strcmp (r->offload, "yes") != 0)
                r->offload = "unsupported";
            *offload = 0;
            break;
        }
        cp_err (errno, "error copying %s to %s", cp_q (src), cp_q (dst));
        return -1;
    }
#else
    *offload = 0;
    r->offload = "unsupported";
#endif
    while (len < 0 || done < len) {
        size_t want = sizeof cp_buffer;
        if (len >= 0 && (off_t) want > len - done)
            want = (size_t) (len - done);
        ssize_t n = read (sfd, cp_buffer, want);
        if (n < 0) {
            if (errno == EINTR) {
                QUIT;
                continue;
            }
            cp_err (errno, "error reading %s", cp_q (src));
            return -1;
        }
        if (n == 0)
            break;
        if (cp_put (dfd, cp_buffer, (size_t) n, holes, dst) < 0)
            return -1;
        done += n;
        QUIT;
    }
    return done;
}

static int
cp_zero_fill (int dfd, off_t len, const char *dst)
{
    memset (cp_buffer, 0, sizeof cp_buffer);
    while (len > 0) {
        size_t n = len > (off_t) sizeof cp_buffer ? sizeof cp_buffer : (size_t) len;
        if (cp_put (dfd, cp_buffer, n, 0, dst) < 0)
            return -1;
        len -= (off_t) n;
    }
    return 0;
}

/* The bytes of SFD into DFD: a clone, extent by extent for sparse sources,
   or a plain copy, with holes per --sparse. Returns 0, -1, or -2 when
   --reflink=always could not clone. */
static int
cp_data (const cp_ctx *c, int sfd, int dfd, const char *src, const char *dst,
         const struct stat *ss, const struct stat *ds, cp_report *r)
{
    int dst_regular = S_ISREG (ds->st_mode);
    int looks_sparse = S_ISREG (ss->st_mode) && (off_t) ss->st_blocks * 512 < ss->st_size;
    int zeros = c->sparse == CP_SPARSE_ALWAYS && dst_regular;
    int never_holes = c->sparse == CP_SPARSE_NEVER || !dst_regular;
    int try_clone = dst_regular && c->reflink != CP_REFLINK_NEVER && c->sparse != CP_SPARSE_NEVER;
    int offload = !(c->sparse != CP_SPARSE_AUTO || c->reflink == CP_REFLINK_NEVER);

    r->offload = "unknown";
    r->reflink = try_clone || !dst_regular ? "unsupported" : "no";
    r->sparse = "no";
    if (try_clone) {
        if (ioctl (dfd, FICLONE, sfd) == 0) {
            r->reflink = "yes";
            r->sparse = "unknown";
            return 0;
        }
        if (c->reflink == CP_REFLINK_ALWAYS) {
            cp_err (errno, "failed to clone %s from %s", cp_q (dst), cp_q (src));
            r->sparse = "unknown";
            return -2;
        }
    }
    if (!offload)
        r->offload = "avoided";

    off_t written = 0, end = ss->st_size;
    int extents = 0;
    if (looks_sparse) {
        off_t first = lseek (sfd, 0, SEEK_DATA);
        if (first >= 0 || errno == ENXIO) {
            extents = 1;
            r->sparse = zeros ? "SEEK_HOLE + zeros" : "SEEK_HOLE";
            off_t pos = 0;
            for (;;) {
                off_t data = pos == 0 ? first : lseek (sfd, pos, SEEK_DATA);
                if (data < 0) {
                    if (errno == ENXIO)
                        break;
                    cp_err (errno, "cannot lseek %s", cp_q (src));
                    return -1;
                }
                off_t hole = lseek (sfd, data, SEEK_HOLE);
                if (hole < 0 || lseek (sfd, data, SEEK_SET) < 0) {
                    cp_err (errno, "cannot lseek %s", cp_q (src));
                    return -1;
                }
                if (data > written) {
                    if (never_holes) {
                        if (cp_zero_fill (dfd, data - written, dst) < 0)
                            return -1;
                    } else if (lseek (dfd, data, SEEK_SET) < 0) {
                        cp_err (errno, "cannot lseek %s", cp_q (dst));
                        return -1;
                    }
                }
                off_t n = cp_range (sfd, dfd, hole - data, &offload, zeros, r, src, dst);
                if (n < 0)
                    return -1;
                written = data + n;
                pos = hole;
                if (n < hole - data || hole >= end)
                    break;
                QUIT;
            }
        } else if (lseek (sfd, 0, SEEK_SET) < 0) {
            cp_err (errno, "cannot lseek %s", cp_q (src));
            return -1;
        }
    }
    if (!extents) {
        if (zeros)
            r->sparse = "zeros";
        off_t n = cp_range (sfd, dfd, -1, &offload, zeros, r, src, dst);
        if (n < 0)
            return -1;
        written = n;
        end = n;
    }
    /* The file ends in a hole (or a skipped zero block): set its size. */
    if (dst_regular && !c->attr_only) {
        off_t at = lseek (dfd, 0, SEEK_CUR);
        if (extents && written < end && never_holes) {
            if (cp_zero_fill (dfd, end - written, dst) < 0)
                return -1;
        } else if ((extents && written < end) || (at >= 0 && at > written) || (zeros && at > written)) {
            if (ftruncate (dfd, extents ? end : at) < 0) {
                cp_err (errno, "cannot extend %s", cp_q (dst));
                return -1;
            }
        } else if (!extents && at > written) {
            if (ftruncate (dfd, at) < 0) {
                cp_err (errno, "cannot extend %s", cp_q (dst));
                return -1;
            }
        }
    }
    return 0;
}

/* ---- one file ----------------------------------------------------------- */

static int cp_copy (cp_ctx *c, const char *src, const char *dst, int top);

/* Copy a source as data into DST (regular files, and special files read
   as data). DL is DST's lstat when EXISTS. */
static int
cp_regular (cp_ctx *c, const char *src, const char *dst, const struct stat *ss,
            int exists, const struct stat *dl)
{
    struct stat sfst, dfst;
    int rc = 0, created = 0;

    if (exists && c->p_links && S_ISREG (dl->st_mode) && dl->st_nlink > 1 && !c->attr_only) {
        /* Keep the other names of the old destination as they are. */
        if (unlink (dst) < 0 && errno != ENOENT) {
            cp_err (errno, "cannot remove %s", cp_q (dst));
            return -1;
        }
        exists = 0;
    }
    cp_verbose (c, src, dst);

    int sfd = open (src, O_RDONLY | O_NOCTTY);
    if (sfd < 0) {
        cp_err (errno, "cannot open %s for reading", cp_q (src));
        return -1;
    }
    if (fstat (sfd, &sfst) < 0) {
        cp_err (errno, "cannot fstat %s", cp_q (src));
        close (sfd);
        return -1;
    }

    mode_t create_mode = c->no_mode ? 0666
                         : c->p_mode ? (ss->st_mode & S_IRWXU)
                         : (ss->st_mode & 0777);
    int dfd = -1;
    if (exists) {
        /* No O_TRUNC yet: DST may lead back to SRC. */
        dfd = open (dst, O_WRONLY | O_NOCTTY);
        if (dfd < 0 && errno == ENOENT && c->posixly && S_ISLNK (dl->st_mode))
            /* POSIXLY_CORRECT: create the target of a dangling symlink. */
            dfd = open (dst, O_WRONLY | O_CREAT | O_NOCTTY, create_mode);
        if (dfd < 0 && c->force) {
            if (cp_remove (c, dst) < 0) {
                close (sfd);
                return -1;
            }
            exists = 0;
        } else if (dfd < 0) {
            int e = errno;
            if (e == EISDIR)
                cp_err (0, "cannot overwrite directory %s with non-directory %s", cp_q (dst), cp_q (src));
            else
                cp_err (e, "cannot create regular file %s", cp_q (dst));
            close (sfd);
            return -1;
        }
    }
    if (!exists) {
        dfd = open (dst, O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY, create_mode);
        if (dfd < 0) {
            int e = errno;
            size_t len = strlen (dst);
            if (len && dst[len - 1] == '/' && (e == EISDIR || e == ENOENT))
                e = ENOTDIR;
            cp_err (e, "cannot create regular file %s", cp_q (dst));
            close (sfd);
            return -1;
        }
        created = 1;
    }
    if (fstat (dfd, &dfst) < 0) {
        cp_err (errno, "cannot fstat %s", cp_q (dst));
        close (sfd);
        close (dfd);
        return -1;
    }
    if (cp_same (&sfst, &dfst)) {
        cp_err (0, "%s and %s are the same file", cp_q (src), cp_q (dst));
        close (sfd);
        close (dfd);
        return -1;
    }
    if (!created && !c->attr_only && S_ISREG (dfst.st_mode) && ftruncate (dfd, 0) < 0) {
        cp_err (errno, "cannot truncate %s", cp_q (dst));
        close (sfd);
        close (dfd);
        return -1;
    }

    cp_report report = { 0, 0, 0 };
    if (!c->attr_only) {
        rc = cp_data (c, sfd, dfd, src, dst, &sfst, &dfst, &report);
        if (c->debug && (rc == 0 || rc == -2))
            cp_out ("copy offload: %s, reflink: %s, sparse detection: %s\n",
                    report.offload, report.reflink, report.sparse);
        /* A file made only to be cloned into goes again. */
        if (rc == -2 && created)
            unlink (dst);
    }
    if (close (sfd) < 0) {
        cp_err (errno, "failed to close %s", cp_q (src));
        rc = -1;
    }
    if (close (dfd) < 0) {
        cp_err (errno, "failed to close %s", cp_q (dst));
        rc = -1;
    }
    if (rc < 0)
        return -1;
    if ((c->p_mode || c->p_owner || c->p_time || c->p_xattr) && S_ISREG (dfst.st_mode)
        && cp_attributes (c, src, dst, ss, 0) < 0)
        return -1;
    return 0;
}

static int
cp_symlink_copy (cp_ctx *c, const char *src, const char *dst, const struct stat *ss,
                 int exists)
{
    size_t size = ss->st_size > 0 ? (size_t) ss->st_size + 1 : 256;
    char *target = NULL;
    ssize_t n;

    for (;;) {
        char *grown = realloc (target, size);
        if (!grown) {
            free (target);
            cp_err (0, "memory exhausted");
            return -1;
        }
        target = grown;
        n = readlink (src, target, size);
        if (n < 0) {
            cp_err (errno, "cannot read symbolic link %s", cp_q (src));
            free (target);
            return -1;
        }
        if ((size_t) n < size)
            break;
        size *= 2;
    }
    target[n] = '\0';
    if (exists && cp_remove (c, dst) < 0) {
        free (target);
        return -1;
    }
    cp_verbose (c, src, dst);
    if (symlink (target, dst) < 0) {
        cp_err (errno, "cannot create symbolic link %s", cp_q (dst));
        free (target);
        return -1;
    }
    free (target);
    if ((c->p_owner || c->p_time) && cp_attributes (c, src, dst, ss, 1) < 0)
        return -1;
    return 0;
}

static int
cp_special (cp_ctx *c, const char *src, const char *dst, const struct stat *ss, int exists)
{
    mode_t perm = c->no_mode ? ((ss->st_mode & 07000) | 0666) : c->p_mode ? (ss->st_mode & S_IRWXU) : (ss->st_mode & 07777);
    int fifo = S_ISFIFO (ss->st_mode);

    if (exists && cp_remove (c, dst) < 0)
        return -1;
    cp_verbose (c, src, dst);
    if (mknod (dst, (ss->st_mode & S_IFMT) | perm, ss->st_rdev) < 0) {
        int e = errno;
        if (fifo && e == EPERM && mkfifo (dst, perm) == 0)
            goto made;
        cp_err (e, fifo ? "cannot create fifo %s" : "cannot create special file %s", cp_q (dst));
        return -1;
    }
made:
    if ((c->p_mode || c->p_owner || c->p_time || c->p_xattr) && cp_attributes (c, src, dst, ss, 0) < 0)
        return -1;
    return 0;
}

/* -l and -s, and hard links that mirror links between sources. */
static int
cp_link (cp_ctx *c, const char *src, const char *dst, int symbolic, int follow, int exists,
         const char *target)
{
    const char *what = symbolic ? "symbolic link" : "hard link";
    int replace = exists && (c->force || c->remove_dest || target);

    if (exists && c->remove_dest && cp_remove (c, dst) < 0)
        return -1;
    if (replace && !c->remove_dest) {
        /* Make the new link beside DST and rename it over, so DST never
           disappears. */
        char *dir = cp_parent (dst), *tmp = NULL;
        int rc = -1;
        if (dir && (tmp = malloc (strlen (dir) + 32))) {
            for (int attempt = 0; attempt < 100 && rc < 0; attempt++) {
                snprintf (tmp, strlen (dir) + 32, "%s/.cp-link-%ld-%d", dir, (long) getpid (), attempt);
                rc = symbolic ? symlink (target ? target : src, tmp)
                              : linkat (AT_FDCWD, target ? target : src, AT_FDCWD, tmp,
                                        follow ? AT_SYMLINK_FOLLOW : 0);
                if (rc < 0 && errno != EEXIST)
                    break;
            }
            if (rc == 0 && rename (tmp, dst) < 0) {
                int e = errno;
                unlink (tmp);
                errno = e;
                rc = -1;
            }
        }
        int e = errno;
        free (dir);
        free (tmp);
        if (rc < 0) {
            if (symbolic)
                cp_err (e, "cannot create symbolic link %s to %s", cp_q (dst), cp_q (src));
            else
                cp_err (e, "cannot create hard link %s to %s", cp_q (dst), cp_q (target ? target : src));
            return -1;
        }
    } else {
        int rc = symbolic ? symlink (src, dst)
                          : linkat (AT_FDCWD, target ? target : src, AT_FDCWD, dst,
                                    follow ? AT_SYMLINK_FOLLOW : 0);
        if (rc < 0) {
            int e = errno;
            if (symbolic)
                cp_err (e, "cannot create %s %s to %s", what, cp_q (dst), cp_q (src));
            else
                cp_err (e, "cannot create %s %s to %s", what, cp_q (dst), cp_q (target ? target : src));
            return -1;
        }
    }
    cp_verbose (c, src, dst);
    return 0;
}

/* Do A and B name the same directory entry (same last component in the
   same directory)? */
static int
cp_same_name (const char *a, const char *b)
{
    if (!strcmp (a, b))
        return 1;
    char *ba = cp_last (a), *bb = cp_last (b), *pa = cp_parent (a), *pb = cp_parent (b);
    struct stat sa, sb;
    int same = ba && bb && pa && pb && !strcmp (ba, bb) && stat (pa, &sa) == 0
               && stat (pb, &sb) == 0 && cp_same (&sa, &sb);
    free (ba);
    free (bb);
    free (pa);
    free (pb);
    return same;
}

/* Would replacing DST (lstat DL, stat DS when DS_OK) lose SRC's data? A
   backup keeps it unless moving DST aside also takes SRC's name away. */
static int
cp_conflict (const cp_ctx *c, int as, const char *src, const char *dst, const struct stat *ss,
             const struct stat *dl, const struct stat *ds, int ds_ok)
{
    struct stat sl, sf;
    int have_sl = lstat (src, &sl) == 0;

    if (as == CP_AS_DATA) {
        if (!ds_ok || !cp_same (ds, ss))
            return 0;
        if (c->backup != BOS_BACKUP_NONE)
            return cp_same_name (src, dst) || !have_sl || S_ISLNK (sl.st_mode);
        if (c->remove_dest && (S_ISLNK (dl->st_mode) || dl->st_nlink > 1))
            return 0;
        return 1;
    }
    /* The same entry, or one of the two leads to the other. */
    int same = (have_sl && cp_same (dl, &sl))
               || (!S_ISLNK (dl->st_mode) && stat (src, &sf) == 0 && cp_same (dl, &sf))
               || (have_sl && !S_ISLNK (sl.st_mode) && ds_ok && cp_same (ds, &sl));
    if (!same)
        return 0;
    return c->backup == BOS_BACKUP_NONE || cp_same_name (src, dst);
}

static int
cp_dir (cp_ctx *c, const char *src, const char *dst, const struct stat *ss, int top);

/* Copy SRC to DST. Returns 0, 1 when an existing DST was kept (-n, -u),
   or -1 after a diagnostic. */
static int
cp_copy (cp_ctx *c, const char *src, const char *dst, int top)
{
    struct stat ss, dl, ds;
    int follow = c->deref == CP_DEREF_ALWAYS || (c->deref == CP_DEREF_ARGS && top);

    if ((follow ? stat (src, &ss) : lstat (src, &ss)) < 0) {
        cp_err (errno, "cannot stat %s", cp_q (src));
        return -1;
    }
    if (top)
        c->root_dev = ss.st_dev;
    free (c->backup_note);
    c->backup_note = NULL;
    if (S_ISDIR (ss.st_mode))
        return cp_dir (c, src, dst, &ss, top);

    int as = c->hard_link ? CP_AS_HARDLINK
             : c->sym_link ? CP_AS_SYMBOLIC
             : S_ISLNK (ss.st_mode) ? CP_AS_SYMLINK
             : (c->recursive && !c->copy_contents && !S_ISREG (ss.st_mode)) ? CP_AS_SPECIAL
             : CP_AS_DATA;

    if (as == CP_AS_SYMBOLIC && src[0] != '/') {
        /* A relative target is only right beside the current directory. */
        char *dir = cp_parent (dst);
        struct stat here, there;
        int bad = dir && stat (dir, &there) == 0 && stat (".", &here) == 0 && !cp_same (&here, &there);
        free (dir);
        if (bad) {
            cp_err (0, "%s: can make relative symbolic links only in current directory", dst);
            return -1;
        }
    }

    int exists = lstat (dst, &dl) == 0;
    if (!exists && errno != ENOENT) {
        cp_err (errno, "cannot stat %s", cp_q (dst));
        return -1;
    }
    int ds_ok = 0;
    if (exists) {
        if (S_ISLNK (dl.st_mode))
            ds_ok = stat (dst, &ds) == 0;
        else {
            ds = dl;
            ds_ok = 1;
        }
    }

    /* Links between sources (-d, -a, --preserve=links). */
    int track = c->p_links && !c->hard_link && !c->sym_link
                && (ss.st_nlink > 1 || c->deref == CP_DEREF_ALWAYS || c->deref == CP_DEREF_ARGS);
    cp_seen *earlier = track ? cp_seen_find (c, &ss) : NULL;

    if (exists) {
        if (as == CP_AS_DATA && !earlier && S_ISLNK (dl.st_mode) && !ds_ok && !c->remove_dest
            && c->backup == BOS_BACKUP_NONE && !c->posixly) {
            cp_err (0, "not writing through dangling symlink %s", cp_q (dst));
            return -1;
        }
        if (c->ask == CP_ASK_NO || c->update == CP_UPDATE_NONE) {
            if (c->debug)
                cp_out ("skipped %s\n", cp_q (dst));
            return 1;
        }
        if (c->update == CP_UPDATE_NONE_FAIL) {
            cp_err (0, "not replacing %s", cp_q (dst));
            return -1;
        }
        if (c->update == CP_UPDATE_OLDER) {
            const struct stat *cur = (as == CP_AS_DATA && ds_ok) ? &ds : &dl;
            if (cur->st_mtim.tv_sec > ss.st_mtim.tv_sec
                || (cur->st_mtim.tv_sec == ss.st_mtim.tv_sec
                    && cur->st_mtim.tv_nsec >= ss.st_mtim.tv_nsec)) {
                if (c->debug)
                    cp_out ("skipped %s\n", cp_q (dst));
                return 1;
            }
        }
        if (S_ISDIR (dl.st_mode)
            || (as == CP_AS_DATA && S_ISLNK (dl.st_mode) && ds_ok && S_ISDIR (ds.st_mode))) {
            cp_err (0, "cannot overwrite directory %s with non-directory %s", cp_q (dst), cp_q (src));
            return -1;
        }
        if (c->force && c->backup != BOS_BACKUP_NONE && as != CP_AS_SPECIAL && !earlier
            && !strcmp (src, dst)) {
            /* cp -fb FILE FILE: the copy becomes FILE's backup. */
            char *name = bos_backup_name (dst, c->backup, c->suffix);
            if (!name) {
                cp_err (errno, "cannot backup %s", cp_q (dst));
                return -1;
            }
            int kind = c->backup;
            c->backup = BOS_BACKUP_NONE;
            int rc = cp_copy (c, src, name, top);
            c->backup = kind;
            free (name);
            return rc < 0 ? -1 : 0;
        }
        if (as == CP_AS_HARDLINK) {
            if (cp_same (&dl, &ss))
                return 0;       /* already that link */
        } else if (earlier) {
            if (cp_same (&dl, &ss) && !S_ISLNK (dl.st_mode)) {
                cp_err (0, "%s and %s are the same file", cp_q (src), cp_q (dst));
                return -1;
            }
            struct stat now;
            if ((earlier->follow ? stat (dst, &now) : lstat (dst, &now)) == 0
                && now.st_dev == earlier->ddev && now.st_ino == earlier->dino)
                return 0;       /* already linked */
        } else if (cp_conflict (c, as, src, dst, &ss, &dl, &ds, ds_ok)) {
            cp_err (0, "%s and %s are the same file", cp_q (src), cp_q (dst));
            return -1;
        }
        if (c->ask == CP_ASK_USER && !cp_confirm (c, dst, &dl)) {
            if (c->debug)
                cp_out ("skipped %s\n", cp_q (dst));
            return -1;
        }
        if (top && cp_mark_find (c->made, dl.st_dev, dl.st_ino, NULL)) {
            cp_err (0, "will not overwrite just-created %s with %s", cp_q (dst), cp_q (src));
            return -1;
        }
        if (c->backup != BOS_BACKUP_NONE && !c->attr_only) {
            if (cp_make_backup (c, dst) < 0)
                return -1;
            exists = 0;
        } else if (c->remove_dest && as != CP_AS_HARDLINK && as != CP_AS_SYMBOLIC) {
            if (cp_remove (c, dst) < 0)
                return -1;
            exists = 0;
        }
    }
    if (!top)
        cp_seen_forget (c, dst, &ss);

    int rc;
    if (earlier) {
        if (exists && !c->remove_dest && cp_remove (c, dst) < 0)
            return -1;
        rc = cp_link (c, src, dst, 0, earlier->follow, 0, earlier->dst);
    } else switch (as) {
    case CP_AS_HARDLINK:
        rc = cp_link (c, src, dst, 0, follow, exists, NULL);
        break;
    case CP_AS_SYMBOLIC:
        rc = cp_link (c, src, dst, 1, 0, exists, NULL);
        break;
    case CP_AS_SYMLINK:
        rc = cp_symlink_copy (c, src, dst, &ss, exists);
        break;
    case CP_AS_SPECIAL:
        rc = cp_special (c, src, dst, &ss, exists);
        break;
    default:
        rc = cp_regular (c, src, dst, &ss, exists, &dl);
        break;
    }
    if (rc == 0 && track && !earlier)
        cp_seen_add (c, &ss, dst);
    return rc;
}

static int
cp_entry_order (const void *a, const void *b)
{
    const struct { ino_t ino; char *name; } *x = a, *y = b;
    return x->ino < y->ino ? -1 : x->ino > y->ino;
}

/* Is DST spelled as a place inside SRC: is one of the directories named
   on DST's way down SRC itself? Links are not followed, except to the
   target directory DST was put in (IN_DIR). */
static int
cp_inside (const char *src, const char *dst, int in_dir)
{
    struct stat ss, st;
    size_t len = strlen (src);
    while (len > 1 && src[len - 1] == '/')
        len--;
    char *name = strndup (src, len), *path = strdup (dst);
    int inside = 0;
    if (name && path && lstat (name, &ss) == 0) {
        for (;;) {
            char *up = cp_parent (path);
            if (!up)
                break;
            if ((in_dir ? stat (up, &st) : lstat (up, &st)) == 0 && cp_same (&st, &ss))
                inside = 1;
            in_dir = 0;
            int last = !strcmp (up, ".") || !strcmp (up, "/");
            free (path);
            path = up;
            if (inside || last)
                break;
        }
    }
    free (name);
    free (path);
    return inside;
}

static int
cp_dir (cp_ctx *c, const char *src, const char *dst, const struct stat *ss, int top)
{
    struct stat dl;
    int rc = 0, created = 0;
    mode_t made_mode = 0;

    if (!c->recursive) {
        cp_err (0, "-r not specified; omitting directory %s", cp_q (src));
        return -1;
    }
    for (const cp_chain *up = c->chain; up; up = up->up)
        if (up->dev == ss->st_dev && up->ino == ss->st_ino) {
            cp_err (0, "cannot copy cyclic symbolic link %s", cp_q (src));
            return -1;
        }
    cp_mark *made = cp_mark_find (c->dirs, ss->st_dev, ss->st_ino, NULL);
    if (made) {
        /* A directory this command made is now a source: the copy is
           inside what it copies. */
        if (cp_inside (c->top_src, c->top_dst, c->top_in_dir))
            cp_err (0, "cannot copy a directory, %s, into itself, %s", cp_q (c->top_src),
                    cp_q (c->top_dst));
        else
            cp_err (0, "will not create hard link %s to directory %s", cp_q (dst), cp_q (made->name));
        c->abort_arg = 1;
        return -1;
    }

    int have = lstat (dst, &dl) == 0, lstat_errno = errno;
    if (have) {
        if (S_ISLNK (dl.st_mode) && c->copy_contents && c->keep_dir_symlink) {
            struct stat target;
            if (stat (dst, &target) == 0 && S_ISDIR (target.st_mode)) {
                dl = target;
            }
        }
    }
    if (have && !S_ISDIR (dl.st_mode)) {
        if (c->backup == BOS_BACKUP_NONE) {
            cp_err (0, "cannot overwrite non-directory %s with directory %s", cp_q (dst), cp_q (src));
            return -1;
        }
        /* -b moves the file aside; the -v line does not mention it. */
        if (cp_make_backup (c, dst) < 0)
            return -1;
        free (c->backup_note);
        c->backup_note = NULL;
        have = 0;
        lstat_errno = ENOENT;
    }
    if (have) {
        if (cp_same (&dl, ss)) {
            cp_err (0, "%s and %s are the same file", cp_q (src), cp_q (dst));
            return -1;
        }
    } else if (lstat_errno != ENOENT) {
        cp_err (lstat_errno, "cannot stat %s", cp_q (dst));
        return -1;
    } else {
        mode_t mode = c->no_mode ? ((ss->st_mode & 07000) | 0777) : c->p_mode ? (ss->st_mode & (07000 | S_IRWXU))
                      : (ss->st_mode & 07777);
        if (mkdir (dst, mode) < 0) {
            cp_err (errno, "cannot create directory %s", cp_q (dst));
            return -1;
        }
        created = 1;
        if (lstat (dst, &dl) < 0) {
            cp_err (errno, "cannot stat %s", cp_q (dst));
            return -1;
        }
        made_mode = dl.st_mode & 07777;
        /* Fill the copy before giving it a mode without owner access. */
        if ((made_mode & S_IRWXU) != S_IRWXU && chmod (dst, made_mode | S_IRWXU) < 0) {
            cp_err (errno, "setting permissions for %s", cp_q (dst));
            rc = -1;
        }
        cp_verbose (c, src, dst);
    }
    (void) top;
    if (created)
        cp_mark_add (&c->dirs, dl.st_dev, dl.st_ino, dst);

    if (rc == 0 && !(c->xdev && ss->st_dev != c->root_dev)) {
        DIR *dir = opendir (src);
        if (!dir) {
            cp_err (errno, "cannot access %s", cp_q (src));
            rc = -1;
        } else {
            struct cp_entry { ino_t ino; char *name; } *list = NULL;
            size_t count = 0, cap = 0;
            struct dirent *de;
            for (;;) {
                errno = 0;
                de = readdir (dir);
                if (!de) {
                    if (errno) {
                        cp_err (errno, "cannot access %s", cp_q (src));
                        rc = -1;
                    }
                    break;
                }
                if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, ".."))
                    continue;
                if (count == cap) {
                    size_t ncap = cap ? cap * 2 : 32;
                    struct cp_entry *grown = realloc (list, ncap * sizeof *list);
                    if (!grown) {
                        cp_err (0, "memory exhausted");
                        rc = -1;
                        break;
                    }
                    list = grown;
                    cap = ncap;
                }
                if (!(list[count].name = strdup (de->d_name))) {
                    cp_err (0, "memory exhausted");
                    rc = -1;
                    break;
                }
                list[count++].ino = de->d_ino;
            }
            if (closedir (dir) < 0) {
                cp_err (errno, "cannot access %s", cp_q (src));
                rc = -1;
            }
            /* GNU walks a directory in inode order. */
            qsort (list, count, sizeof *list, cp_entry_order);
            cp_chain here = { ss->st_dev, ss->st_ino, c->chain };
            c->chain = &here;
            for (size_t i = 0; i < count; i++) {
                QUIT;
                if (!c->abort_arg) {
                    char *s = cp_join (src, list[i].name), *d = s ? cp_join (dst, list[i].name) : NULL;
                    if (!s || !d || cp_copy (c, s, d, 0) < 0)
                        rc = -1;
                    free (s);
                    free (d);
                }
                free (list[i].name);
            }
            c->chain = here.up;
            free (list);
        }
    }

    if (c->p_mode || c->p_owner || c->p_time || c->p_xattr) {
        if (cp_attributes (c, src, dst, ss, 0) < 0)
            rc = -1;
    } else if (created && (made_mode & S_IRWXU) != S_IRWXU && chmod (dst, made_mode) < 0) {
        cp_err (errno, "setting permissions for %s", cp_q (dst));
        rc = -1;
    }
    if (c->p_mode == 0 && (c->p_owner || c->p_time || c->p_xattr) && created
        && (made_mode & S_IRWXU) != S_IRWXU && chmod (dst, made_mode) < 0) {
        cp_err (errno, "setting permissions for %s", cp_q (dst));
        rc = -1;
    }
    return rc;
}

/* ---- operands ----------------------------------------------------------- */

/* One command-line source. INTO_DIR: DST was formed inside a target
   directory, so a repeated source name is only a warning. */
static int
cp_top (cp_ctx *c, const char *src, const char *dst, int into_dir)
{
    struct stat ss;
    int follow = c->deref == CP_DEREF_ALWAYS || c->deref == CP_DEREF_ARGS;
    int src_ok = (follow ? stat (src, &ss) : lstat (src, &ss)) == 0;

    if (into_dir && src_ok) {
        char *parent = cp_parent (src), *base = cp_last (src);
        struct stat ps;
        /* The directory itself, not where a symbolic link to it leads. */
        if (parent && base && lstat (parent, &ps) == 0) {
            if (cp_mark_find (c->names, ps.st_dev, ps.st_ino, base)) {
                cp_err (0, "warning: source %s %s specified more than once",
                        S_ISDIR (ss.st_mode) ? "directory" : "file", cp_q (src));
                free (parent);
                free (base);
                return 0;
            }
            cp_mark_add (&c->names, ps.st_dev, ps.st_ino, base);
        }
        free (parent);
        free (base);
    }
    c->top_src = src;
    c->top_dst = dst;
    c->top_in_dir = into_dir;
    c->abort_arg = 0;
    int rc = cp_copy (c, src, dst, 1);
    if (rc == 0 && src_ok && !S_ISDIR (ss.st_mode)) {
        struct stat dl;
        if (lstat (dst, &dl) == 0)
            cp_mark_add (&c->made, dl.st_dev, dl.st_ino, NULL);
    }
    return rc < 0 ? -1 : 0;
}

/* --parents: DEST/SRC, creating the missing directories of SRC's name with
   its directories' modes, which are applied deepest first afterwards so
   read-only parents can still be filled. */
typedef struct cp_parent_dir {
    char *path;
    struct stat source;
    mode_t mode;
    struct cp_parent_dir *next;
} cp_parent_dir;

static int
cp_with_parents (cp_ctx *c, const char *src, const char *dest)
{
    size_t start = 0, end = strlen (src), dn = strlen (dest);
    while (src[start] == '/')
        start++;
    while (end > start && src[end - 1] == '/')
        end--;
    while (dn > 1 && dest[dn - 1] == '/')
        dn--;
    size_t base = dn + (dn == 0 || dest[dn - 1] != '/');
    size_t tail = end - start;
    char *dst = malloc (base + tail + 1), *prefix = strdup (src);
    if (!dst || !prefix) {
        cp_err (0, "memory exhausted");
        free (dst);
        free (prefix);
        return -1;
    }
    memcpy (dst, dest, dn);
    if (base > dn)
        dst[dn] = '/';
    memcpy (dst + base, src + start, tail);
    dst[base + tail] = '\0';

    cp_parent_dir *made = NULL;
    int rc = 0;
    for (size_t i = start; i < end; i++) {
        if (src[i] != '/' || i == start || src[i - 1] == '/')
            continue;
        size_t cut = base + i - start;
        dst[cut] = '\0';
        prefix[i] = '\0';
        struct stat st;
        if (stat (prefix, &st) < 0) {
            cp_err (errno, "failed to get attributes of %s", cp_q (prefix));
            rc = -1;
        } else if (!S_ISDIR (st.st_mode)) {
            cp_err (ENOTDIR, "failed to get attributes of %s", cp_q (prefix));
            rc = -1;
        } else {
            struct stat dst_st;
            if (stat (dst, &dst_st) == 0) {
                if (!S_ISDIR (dst_st.st_mode)) {
                    cp_err (0, "%s exists but is not a directory", cp_q (dst));
                    rc = -1;
                }
            } else if (errno != ENOENT) {
                cp_err (errno, "cannot stat %s", cp_q (dst));
                rc = -1;
            } else {
                cp_parent_dir *p = malloc (sizeof *p);
                if (!p || !(p->path = strdup (dst))) {
                    free (p);
                    cp_err (0, "memory exhausted");
                    rc = -1;
                } else {
                    p->source = st;
                    p->mode = (st.st_mode & (0777 | S_ISVTX)) & ~c->umask;
                    if (mkdir (dst, p->mode | S_IRWXU) < 0) {
                        cp_err (errno, "cannot make directory %s", cp_q (dst));
                        free (p->path);
                        free (p);
                        rc = -1;
                    } else {
                        p->next = made;
                        made = p;
                        /* Keep set-group-ID inherited from the destination's
                           directory, but copy no source set-ID bits. */
                        struct stat now;
                        if (stat (dst, &now) < 0) {
                            cp_err (errno, "cannot stat %s", cp_q (dst));
                            rc = -1;
                        } else {
                            p->mode |= now.st_mode & S_ISGID;
                            if (chmod (dst, p->mode | S_IRWXU) < 0) {
                                cp_err (errno, "setting permissions for %s", cp_q (dst));
                                rc = -1;
                            }
                        }
                        if (c->verbose)
                            cp_out ("%s -> %s\n", prefix, dst);
                    }
                }
            }
        }
        prefix[i] = '/';
        dst[cut] = '/';
        if (rc < 0)
            break;
    }
    if (rc == 0)
        rc = cp_top (c, src, dst, 0);
    while (made) {
        cp_parent_dir *p = made;
        made = p->next;
        if (c->p_mode || c->p_owner || c->p_time) {
            if (cp_attributes (c, NULL, p->path, &p->source, 0) < 0)
                rc = -1;
        } else if (chmod (p->path, p->mode) < 0) {
            cp_err (errno, "setting permissions for %s", cp_q (p->path));
            rc = -1;
        }
        free (p->path);
        free (p);
    }
    free (prefix);
    free (dst);
    return rc;
}

/* ---- options ------------------------------------------------------------ */

enum {
    CP_OPT_ATTR_ONLY = BOS_OPT_FIRST, CP_OPT_BACKUP, CP_OPT_COPY_CONTENTS, CP_OPT_CONTEXT,
    CP_OPT_DEBUG, CP_OPT_NO_PRESERVE, CP_OPT_PARENTS, CP_OPT_PRESERVE, CP_OPT_REFLINK,
    CP_OPT_REMOVE_DEST, CP_OPT_SPARSE, CP_OPT_STRIP, CP_OPT_UPDATE, CP_OPT_KEEP_DIR_SYMLINK
};

/* In GNU's order, which its ambiguity diagnostics list. */
static const struct bos_longopt cp_longopts[] = {
    { "archive", BOS_NO_ARG, 'a' },
    { "attributes-only", BOS_NO_ARG, CP_OPT_ATTR_ONLY },
    { "backup", BOS_OPT_ARG, CP_OPT_BACKUP },
    { "copy-contents", BOS_NO_ARG, CP_OPT_COPY_CONTENTS },
    { "context", BOS_OPT_ARG, CP_OPT_CONTEXT },
    { "debug", BOS_NO_ARG, CP_OPT_DEBUG },
    { "dereference", BOS_NO_ARG, 'L' },
    { "force", BOS_NO_ARG, 'f' },
    { "interactive", BOS_NO_ARG, 'i' },
    { "link", BOS_NO_ARG, 'l' },
    { "no-clobber", BOS_NO_ARG, 'n' },
    { "no-dereference", BOS_NO_ARG, 'P' },
    { "no-preserve", BOS_REQ_ARG, CP_OPT_NO_PRESERVE },
    { "no-target-directory", BOS_NO_ARG, 'T' },
    { "one-file-system", BOS_NO_ARG, 'x' },
    { "parents", BOS_NO_ARG, CP_OPT_PARENTS },
    { "preserve", BOS_OPT_ARG, CP_OPT_PRESERVE },
    { "recursive", BOS_NO_ARG, 'R' },
    { "remove-destination", BOS_NO_ARG, CP_OPT_REMOVE_DEST },
    { "reflink", BOS_OPT_ARG, CP_OPT_REFLINK },
    { "sparse", BOS_REQ_ARG, CP_OPT_SPARSE },
    { "strip-trailing-slashes", BOS_NO_ARG, CP_OPT_STRIP },
    { "suffix", BOS_REQ_ARG, 'S' },
    { "symbolic-link", BOS_NO_ARG, 's' },
    { "target-directory", BOS_REQ_ARG, 't' },
    { "update", BOS_OPT_ARG, CP_OPT_UPDATE },
    { "verbose", BOS_NO_ARG, 'v' },
    { "keep-directory-symlink", BOS_NO_ARG, CP_OPT_KEEP_DIR_SYMLINK },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

static const char *const cp_update_names[] = { "all", "none", "none-fail", "older", NULL };
static const int cp_update_vals[] = { CP_UPDATE_ALL, CP_UPDATE_NONE, CP_UPDATE_NONE_FAIL, CP_UPDATE_OLDER };
static const char *const cp_sparse_names[] = { "never", "auto", "always", NULL };
static const int cp_sparse_vals[] = { CP_SPARSE_NEVER, CP_SPARSE_AUTO, CP_SPARSE_ALWAYS };
static const char *const cp_reflink_names[] = { "auto", "always", "never", NULL };
static const int cp_reflink_vals[] = { CP_REFLINK_AUTO, CP_REFLINK_ALWAYS, CP_REFLINK_NEVER };
static const char *const cp_attr_names[] = {
    "mode", "timestamps", "ownership", "links", "context", "xattr", "all", NULL
};
static const int cp_attr_vals[] = {
    CP_P_MODE, CP_P_TIME, CP_P_OWNER, CP_P_LINKS, CP_P_CONTEXT, CP_P_XATTR, CP_P_ALL
};
/* --preserve=LIST (ON) or --no-preserve=LIST. */
static int
cp_attr_list (cp_ctx *c, const char *option, const char *list, int on)
{
    char *copy = strdup (list);
    if (!copy) {
        cp_err (0, "memory exhausted");
        return -1;
    }
    char *item = copy;
    for (;;) {
        char *comma = strchr (item, ',');
        if (comma)
            *comma = '\0';
        int which = bos_argmatch ("cp", option, item, cp_attr_names, cp_attr_vals);
        if (which < 0) {
            free (copy);
            return -1;
        }
        switch (which) {
        case CP_P_MODE:
            c->p_mode = on;
            c->no_mode = !on;
            break;
        case CP_P_TIME:
            c->p_time = on;
            break;
        case CP_P_OWNER:
            c->p_owner = on;
            break;
        case CP_P_LINKS:
            c->p_links = on;
            break;
        case CP_P_CONTEXT:
            c->p_context = on;
            c->need_context = on;
            break;
        case CP_P_XATTR:
            c->p_xattr = on;
            break;
        default:
            /* "all" asks for a security context only where there is one. */
            c->p_mode = c->p_time = c->p_owner = c->p_links = c->p_xattr = c->p_context = on;
            c->no_mode = !on;
            break;
        }
        if (!comma)
            break;
        item = comma + 1;
    }
    free (copy);
    return 0;
}

static void
cp_cleanup (cp_ctx *c)
{
    while (c->seen) {
        cp_seen *next = c->seen->next;
        free (c->seen->dst);
        free (c->seen);
        c->seen = next;
    }
    cp_marks_free (&c->made);
    cp_marks_free (&c->dirs);
    cp_marks_free (&c->names);
    free (c->backup_note);
    c->backup_note = NULL;
    cp_quotes_free ();
    cp_oflush ();
    cp_ohold = 0;
}

int
cp_builtin (WORD_LIST *list)
{
    cp_ctx c;
    bos_getopt g;
    const char *target_dir = NULL;
    int opt, rc = EXECUTION_SUCCESS;

    memset (&c, 0, sizeof c);
    c.sparse = CP_SPARSE_AUTO;
    c.reflink = CP_REFLINK_AUTO;
    c.backup = BOS_BACKUP_NONE;
    c.posixly = getenv ("POSIXLY_CORRECT") != NULL;
    cp_olen = 0;
    cp_ohold = !isatty (1);

    bos_getopt_init (&g, "cp", "abdfHilLnpPrRsS:t:TuvxZ", cp_longopts, list);
    while ((opt = bos_getopt_next (&g)) != -1) {
        switch (opt) {
        case 'a':
            c.deref = CP_DEREF_NEVER;
            c.p_mode = c.p_owner = c.p_time = c.p_links = c.p_xattr = 1;
            if (!c.context_seen)
                c.p_context = 1;
            c.no_mode = 0;
            c.quiet_attrs = 1;
            c.recursive = 1;
            break;
        case 'b':
            c.backup_wanted = 1;
            c.backup_control = NULL;
            break;
        case 'd':
            c.deref = CP_DEREF_NEVER;
            c.p_links = 1;
            break;
        case 'f':
            c.force = 1;
            break;
        case 'H':
            c.deref = CP_DEREF_ARGS;
            break;
        case 'i':
            c.ask = CP_ASK_USER;
            break;
        case 'l':
            c.hard_link = 1;
            break;
        case 'L':
            c.deref = CP_DEREF_ALWAYS;
            break;
        case 'n':
            c.ask = CP_ASK_NO;
            break;
        case 'p':
            c.p_mode = c.p_owner = c.p_time = 1;
            c.no_mode = 0;
            break;
        case 'P':
            c.deref = CP_DEREF_NEVER;
            break;
        case 'r':
        case 'R':
            c.recursive = 1;
            break;
        case 's':
            c.sym_link = 1;
            break;
        case 'S':
            c.backup_wanted = 1;
            c.suffix = g.optarg;
            break;
        case 't':
            if (target_dir) {
                cp_err (0, "multiple target directories specified");
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            target_dir = g.optarg;
            break;
        case 'T':
            c.notarget = 1;
            break;
        case 'u':
            c.update = CP_UPDATE_OLDER;
            break;
        case 'v':
            c.verbose = 1;
            break;
        case 'x':
            c.xdev = 1;
            break;
        case 'Z':
        case CP_OPT_CONTEXT:
            if (opt == CP_OPT_CONTEXT && g.optarg)
                cp_err (0, "warning: ignoring --context; it requires an SELinux-enabled kernel");
            c.context_seen = 1;
            c.p_context = 0;
            break;
        case CP_OPT_ATTR_ONLY:
            c.attr_only = 1;
            break;
        case CP_OPT_BACKUP:
            c.backup_wanted = 1;
            c.backup_control = g.optarg;
            break;
        case CP_OPT_COPY_CONTENTS:
            c.copy_contents = 1;
            break;
        case CP_OPT_DEBUG:
            c.debug = c.verbose = 1;
            break;
        case CP_OPT_NO_PRESERVE:
            if (cp_attr_list (&c, "--no-preserve", g.optarg, 0) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case CP_OPT_PARENTS:
            c.parents = 1;
            break;
        case CP_OPT_PRESERVE:
            if (!g.optarg) {
                c.p_mode = c.p_owner = c.p_time = 1;
                c.no_mode = 0;
            } else if (cp_attr_list (&c, "--preserve", g.optarg, 1) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case CP_OPT_REFLINK:
            if (!g.optarg)
                c.reflink = CP_REFLINK_ALWAYS;
            else if ((c.reflink = bos_argmatch ("cp", "--reflink", g.optarg, cp_reflink_names,
                                                cp_reflink_vals)) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case CP_OPT_REMOVE_DEST:
            c.remove_dest = 1;
            break;
        case CP_OPT_SPARSE:
            if ((c.sparse = bos_argmatch ("cp", "--sparse", g.optarg, cp_sparse_names,
                                          cp_sparse_vals)) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case CP_OPT_STRIP:
            /* Accepted; GNU 9.7 names files as given either way. */
            break;
        case CP_OPT_UPDATE:
            if (!g.optarg)
                c.update = CP_UPDATE_OLDER;
            else if ((c.update = bos_argmatch ("cp", "--update", g.optarg, cp_update_names,
                                               cp_update_vals)) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case CP_OPT_KEEP_DIR_SYMLINK:
            c.keep_dir_symlink = 1;
            break;
        case BOS_OPT_HELP:
            builtin_help ();
            bos_getopt_free (&g);
            return EXECUTION_SUCCESS;
        case BOS_OPT_VERSION:
            printf ("cp (bash-os builtin) 9.7\n");
            bos_getopt_free (&g);
            return sh_chkwrite (EXECUTION_SUCCESS);
        default:
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
    }

    if (c.hard_link && c.sym_link) {
        cp_err (0, "cannot make both hard and symbolic links");
        bos_try_help ("cp");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (c.backup_wanted
        && (c.ask == CP_ASK_NO || c.update == CP_UPDATE_NONE || c.update == CP_UPDATE_NONE_FAIL)) {
        cp_err (0, "--backup is mutually exclusive with -n or --update=none-fail");
        bos_try_help ("cp");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (c.reflink == CP_REFLINK_ALWAYS && c.sparse != CP_SPARSE_AUTO) {
        cp_err (0, "--reflink can be used only with --sparse=auto");
        bos_try_help ("cp");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (c.backup_wanted) {
        c.backup = bos_backup_kind ("cp", c.backup_control);
        if (c.backup < 0) {
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
        c.suffix = bos_backup_suffix (c.suffix);
    }
    if (c.need_context) {
        cp_err (0, "cannot preserve security context without an SELinux-enabled kernel");
        bos_getopt_free (&g);
        return EXECUTION_FAILURE;
    }
    if (c.deref == CP_DEREF_UNSET)
        c.deref = c.recursive && !c.hard_link ? CP_DEREF_NEVER : CP_DEREF_ALWAYS;
    c.umask = umask (0);
    umask (c.umask);

    int n = g.noperands;
    char **ops = g.operands;
    if (n <= (target_dir ? 0 : 1)) {
        if (n == 0)
            cp_err (0, "missing file operand");
        else
            cp_err (0, "missing destination file operand after %s", cp_q (ops[0]));
        bos_try_help ("cp");
        bos_getopt_free (&g);
        cp_cleanup (&c);
        return EXECUTION_FAILURE;
    }

    const char *dir = NULL;
    int nsrc = n;
    if (c.notarget) {
        if (target_dir) {
            cp_err (0, "cannot combine --target-directory (-t) and --no-target-directory (-T)");
            bos_getopt_free (&g);
            cp_cleanup (&c);
            return EXECUTION_FAILURE;
        }
        if (n > 2) {
            cp_err (0, "extra operand %s", cp_q (ops[2]));
            bos_try_help ("cp");
            bos_getopt_free (&g);
            cp_cleanup (&c);
            return EXECUTION_FAILURE;
        }
    } else if (target_dir) {
        struct stat st;
        int sr = stat (target_dir, &st);
        if (sr < 0 || !S_ISDIR (st.st_mode)) {
            cp_err (sr < 0 ? errno : ENOTDIR, "target directory %s", cp_q (target_dir));
            bos_getopt_free (&g);
            cp_cleanup (&c);
            return EXECUTION_FAILURE;
        }
        dir = target_dir;
    } else {
        struct stat st;
        const char *last = ops[n - 1];
        int sr = stat (last, &st), se = errno;
        nsrc = n - 1;
        if (sr == 0 && S_ISDIR (st.st_mode))
            dir = last;
        else if (n > 2) {
            cp_err (sr == 0 ? ENOTDIR : se, "target %s", cp_q (last));
            bos_getopt_free (&g);
            cp_cleanup (&c);
            return EXECUTION_FAILURE;
        } else if (c.parents) {
            cp_err (0, "with --parents, the destination must be a directory");
            bos_try_help ("cp");
            bos_getopt_free (&g);
            cp_cleanup (&c);
            return EXECUTION_FAILURE;
        }
    }

    if (!dir) {
        if (cp_top (&c, ops[0], ops[1], 0) < 0)
            rc = EXECUTION_FAILURE;
    } else {
        for (int i = 0; i < nsrc; i++) {
            const char *src = ops[i];
            QUIT;
            if (c.parents) {
                if (cp_with_parents (&c, src, dir) < 0)
                    rc = EXECUTION_FAILURE;
                continue;
            }
            char *base = cp_last (src), *dst = base ? cp_join (dir, base) : NULL;
            if (!dst || cp_top (&c, src, dst, 1) < 0)
                rc = EXECUTION_FAILURE;
            free (base);
            free (dst);
        }
    }
    bos_getopt_free (&g);
    cp_cleanup (&c);
    return sh_chkwrite (rc);
}

char *cp_doc[] = {
    "Copy files and directories.",
    "",
    "    cp [OPTION]... [-T] SOURCE DEST",
    "    cp [OPTION]... SOURCE... DIRECTORY",
    "    cp [OPTION]... -t DIRECTORY SOURCE...",
    "",
    "Copy SOURCE to DEST, or multiple SOURCE(s) to DIRECTORY.",
    "",
    "    -a, --archive          same as -dR --preserve=all",
    "        --attributes-only  don't copy the file data, just the attributes",
    "        --backup[=CONTROL] make a backup of each existing destination file",
    "    -b                     like --backup but does not accept an argument",
    "        --copy-contents    copy contents of special files when recursive",
    "    -d                     same as --no-dereference --preserve=links",
    "        --debug            explain how a file is copied.  Implies -v",
    "    -f, --force            if an existing destination file cannot be",
    "                           opened, remove it and try again (ignored with -n)",
    "    -i, --interactive      prompt before overwrite (overrides a previous -n)",
    "    -H                     follow command-line symbolic links in SOURCE",
    "    -l, --link             hard link files instead of copying",
    "    -L, --dereference      always follow symbolic links in SOURCE",
    "    -n, --no-clobber       (deprecated) silently skip existing files",
    "    -P, --no-dereference   never follow symbolic links in SOURCE",
    "    -p                     same as --preserve=mode,ownership,timestamps",
    "        --preserve[=ATTR_LIST]  preserve the specified attributes",
    "        --no-preserve=ATTR_LIST  don't preserve the specified attributes",
    "        --parents          use full source file name under DIRECTORY",
    "    -R, -r, --recursive    copy directories recursively",
    "        --reflink[=WHEN]   control clone/CoW copies (auto, always, never)",
    "        --remove-destination  remove each existing destination file before",
    "                           attempting to open it (contrast with --force)",
    "        --sparse=WHEN      control creation of sparse files (auto, always,",
    "                           never)",
    "        --strip-trailing-slashes  remove any trailing slashes from each",
    "                           SOURCE argument",
    "    -s, --symbolic-link    make symbolic links instead of copying",
    "    -S, --suffix=SUFFIX    override the usual backup suffix",
    "    -t, --target-directory=DIRECTORY  copy all SOURCE arguments into",
    "                           DIRECTORY",
    "    -T, --no-target-directory  treat DEST as a normal file",
    "        --update[=UPDATE]  control which existing files are updated;",
    "                           UPDATE={all,none,none-fail,older(default)}",
    "    -u                     equivalent to --update[=older]",
    "    -v, --verbose          explain what is being done",
    "        --keep-directory-symlink  follow existing symlinks to directories",
    "    -x, --one-file-system  stay on this file system",
    "    -Z, --context[=CTX]    SELinux context (ignored without SELinux)",
    "",
    "ATTR_LIST is a comma-separated list of: mode, ownership, timestamps,",
    "links, context, xattr, all.  Recursive copies recreate FIFOs, sockets",
    "and device nodes unless --copy-contents is given.  The backup suffix is",
    "'~' unless set with --suffix or SIMPLE_BACKUP_SUFFIX; VERSION_CONTROL or",
    "--backup selects none/off, numbered/t, existing/nil or simple/never.",
    (char *)NULL
};

struct builtin cp_struct = {
    "cp",
    cp_builtin,
    BUILTIN_ENABLED,
    cp_doc,
    "cp [-abdfHilLnpPrRsTuvxZ] [-S SUFFIX] [-t DIR] SOURCE... DEST",
    0
};
