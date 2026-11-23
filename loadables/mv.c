/* SPDX-License-Identifier: MIT */
/* mv — move (rename) files, as a bash builtin.
 *
 *   mv [OPTION]... [-T] SOURCE DEST
 *   mv [OPTION]... SOURCE... DIRECTORY
 *   mv [OPTION]... -t DIRECTORY SOURCE...
 *
 * Written for bash-os from the coreutils manual ("mv invocation", "Backup
 * options", "Target directory", "Trailing slashes"), POSIX.1-2024 mv, and
 * observed behaviour of GNU coreutils 9.7 mv; it grew out of bash-os's own
 * earlier MIT "bashmv". Options, messages and exit status follow GNU mv:
 * --backup[=CONTROL]/-b/-S, --debug, --exchange, -f/-i/-n (the last one
 * wins), --no-copy, --strip-trailing-slashes, -t/-T,
 * --update[=all|none|none-fail|older]/-u, -v, -Z (accepted; there are no
 * SELinux contexts to set), --help and --version.
 *
 * A rename(2) that fails with EXDEV becomes a copy that keeps file types
 * (regular files, directories, symbolic links, FIFOs, sockets and device
 * nodes), modes, owners where permitted, timestamps, extended attributes
 * and hard links between moved files, followed by removal of exactly the
 * source entries that were copied. Nothing is removed unless the whole
 * operand was copied.
 *
 * Exit status 0 on success, 1 if any operand failed or on bad usage.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

#include "loadables.h"
#include "gnu-quote.h"
#include "gnu-longopt.h"

#define MV_PATH_LIMIT 4095      /* longest full path name handed to the kernel */

#ifndef RENAME_NOREPLACE
#  define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#  define RENAME_EXCHANGE (1 << 1)
#endif

enum { MV_PROMPT_DEFAULT, MV_FORCE, MV_INTERACTIVE, MV_NO_CLOBBER };
enum { MV_UPDATE_ALL, MV_UPDATE_NONE, MV_UPDATE_NONE_FAIL, MV_UPDATE_OLDER };
enum {
    MV_OPT_BACKUP = BOS_OPT_FIRST, MV_OPT_DEBUG, MV_OPT_EXCHANGE, MV_OPT_NO_COPY,
    MV_OPT_STRIP, MV_OPT_UPDATE
};

/* A destination this invocation produced, or a copied multiply-linked
   source and the copy that later links to it should share. */
typedef struct mv_link {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    char *path;
    struct mv_link *next;
} mv_link;

/* A copied source entry, removed (in this order) once the copy is done. */
typedef struct mv_source {
    dev_t dev;
    ino_t ino;
    mode_t type;
    char *path;
    struct mv_source *next;
} mv_source;

typedef struct {
    mv_source *head, *tail;
} mv_removals;

typedef struct {
    int prompt, update, backup, backup_kind, verbose, debug, exchange, no_copy;
    const char *suffix;
    mv_link *links, *written;
} mv_opts;

/* ------------------------------------------------------------------ */
/* messages */

static char *
mv_q (const char *name)
{
    char *q = bos_quoteaf (name);
    return q ? q : strdup (name);
}

/* Standard output as a C program's: line buffered on a terminal, else
   written in whole blocks. Diagnostics flush it first and prompts do not,
   which fixes how -v lines interleave with them on a shared stream. */
#define MV_BLOCK 4096
static struct {
    char buf[MV_BLOCK];
    size_t len;
    int line;
} mv_out;

static void
mv_out_flush (void)
{
    if (mv_out.len)
        fwrite (mv_out.buf, 1, mv_out.len, stdout);
    mv_out.len = 0;
    fflush (stdout);
}

static void
mv_out_write (const char *s, size_t n)
{
    while (n > 0) {
        size_t k = MV_BLOCK - mv_out.len;
        if (k > n)
            k = n;
        memcpy (mv_out.buf + mv_out.len, s, k);
        mv_out.len += k;
        s += k;
        n -= k;
        if (mv_out.len == MV_BLOCK || (mv_out.line && memchr (s - k, '\n', k)))
            mv_out_flush ();
    }
}

static void mv_printf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));
static void
mv_printf (const char *format, ...)
{
    char small[512], *text = small;
    va_list ap;
    va_start (ap, format);
    int n = vsnprintf (small, sizeof small, format, ap);
    va_end (ap);
    if (n < 0)
        return;
    if ((size_t) n >= sizeof small) {
        if (!(text = malloc ((size_t) n + 1)))
            return;
        va_start (ap, format);
        vsnprintf (text, (size_t) n + 1, format, ap);
        va_end (ap);
    }
    mv_out_write (text, (size_t) n);
    if (text != small)
        free (text);
}

#define MV_ERROR(...) do { mv_out_flush (); builtin_error (__VA_ARGS__); } while (0)

static void
mv_error1 (const char *format, const char *a, int error)
{
    char *qa = mv_q (a);
    if (error)
        MV_ERROR (format, qa ? qa : a, strerror (error));
    else
        MV_ERROR (format, qa ? qa : a);
    free (qa);
}

static void
mv_error2 (const char *format, const char *a, const char *b, int error)
{
    char *qa = mv_q (a), *qb = mv_q (b);
    if (error)
        MV_ERROR (format, qa ? qa : a, qb ? qb : b, strerror (error));
    else
        MV_ERROR (format, qa ? qa : a, qb ? qb : b);
    free (qa);
    free (qb);
}

/* -v output; stdout stays buffered like GNU's. */
static void
mv_say (const char *what, const char *a, const char *arrow, const char *b, const char *backup)
{
    char *qa = mv_q (a), *qb = b ? mv_q (b) : NULL, *qk = backup ? mv_q (backup) : NULL;
    if (what && *what)
        mv_printf ("%s ", what);
    mv_printf ("%s", qa ? qa : a);
    if (b)
        mv_printf (" %s %s", arrow, qb ? qb : b);
    if (backup)
        mv_printf (" (backup: %s)", qk ? qk : backup);
    mv_out_write ("\n", 1);
    free (qa);
    free (qb);
    free (qk);
}

/* ------------------------------------------------------------------ */
/* small helpers */

static int
mv_rename2 (const char *from, const char *to, unsigned int flags)
{
#ifdef SYS_renameat2
    return (int) syscall (SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, flags);
#else
    (void) from; (void) to; (void) flags;
    errno = ENOSYS;
    return -1;
#endif
}

/* DIR/NAME without doubling DIR's trailing slashes. NULL (after a
   diagnostic) when the result would be longer than the kernel accepts:
   a silently truncated name could designate some other file. */
static char *
mv_join (const char *dir, const char *name, size_t name_length)
{
    size_t dir_length = strlen (dir);
    while (dir_length > 1 && dir[dir_length - 1] == '/')
        dir_length--;
    size_t sep = dir_length > 0 && dir[dir_length - 1] == '/' ? 0 : 1;
    if (dir_length + sep + name_length > MV_PATH_LIMIT) {
        char *qd = mv_q (dir);
        MV_ERROR ("cannot move into %s: %s", qd ? qd : dir, strerror (ENAMETOOLONG));
        free (qd);
        return NULL;
    }
    char *path = malloc (dir_length + sep + name_length + 1);
    if (!path) {
        MV_ERROR ("memory exhausted");
        return NULL;
    }
    memcpy (path, dir, dir_length);
    if (sep)
        path[dir_length] = '/';
    memcpy (path + dir_length + sep, name, name_length);
    path[dir_length + sep + name_length] = '\0';
    return path;
}

/* The last component of NAME, ignoring trailing slashes. */
static const char *
mv_base (const char *name, size_t *length)
{
    const char *end = name + strlen (name);
    while (end > name + 1 && end[-1] == '/')
        end--;
    const char *base = end;
    while (base > name && base[-1] != '/')
        base--;
    *length = (size_t) (end - base);
    return base;
}

/* Whether A and B are the same directory entry (and not just two links
   to one file): equal last components in the same directory. */
static int
mv_same_name (const char *a, const char *b)
{
    size_t la, lb;
    const char *ba = mv_base (a, &la), *bb = mv_base (b, &lb);
    if (la != lb || memcmp (ba, bb, la) != 0)
        return 0;
    char *da = ba == a ? strdup (".") : strndup (a, (size_t) (ba - a));
    char *db = bb == b ? strdup (".") : strndup (b, (size_t) (bb - b));
    struct stat sa, sb;
    int same = da && db && stat (da, &sa) == 0 && stat (db, &sb) == 0 &&
               sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
    free (da);
    free (db);
    return same;
}

static void
mv_mode_string (mode_t mode, char out[10])
{
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++)
        out[i] = (mode & (0400 >> i)) ? rwx[i] : '-';
    if (mode & S_ISUID) out[2] = out[2] == 'x' ? 's' : 'S';
    if (mode & S_ISGID) out[5] = out[5] == 'x' ? 's' : 'S';
    if (mode & S_ISVTX) out[8] = out[8] == 'x' ? 't' : 'T';
    out[9] = '\0';
}

/* One line from standard input, read a byte at a time so nothing after it
   is consumed; affirmative when it starts with 'y' or 'Y'. */
static int
mv_yes (void)
{
    char c;
    int first = -1;
    for (;;) {
        ssize_t n = read (0, &c, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || c == '\n')
            break;
        if (first < 0)
            first = (unsigned char) c;
    }
    return first == 'y' || first == 'Y';
}

static int
mv_ask (const char *dst, const struct stat *ds, int unwritable)
{
    char *qd = mv_q (dst);
    if (unwritable) {
        char perms[10];
        mv_mode_string (ds->st_mode, perms);
        fprintf (stderr, "mv: replace %s, overriding mode %04lo (%s)? ", qd ? qd : dst,
                 (unsigned long) (ds->st_mode & 07777), perms);
    } else
        fprintf (stderr, "mv: overwrite %s? ", qd ? qd : dst);
    fflush (stderr);
    free (qd);
    return mv_yes ();
}

static int
mv_remember (mv_link **head, const struct stat *src, const char *dst)
{
    struct stat st;
    if (lstat (dst, &st) < 0) {
        mv_error1 ("cannot stat %s: %s", dst, errno);
        return -1;
    }
    mv_link *entry = malloc (sizeof *entry);
    if (!entry || !(entry->path = strdup (dst))) {
        free (entry);
        MV_ERROR ("memory exhausted");
        return -1;
    }
    entry->source_dev = src->st_dev;
    entry->source_ino = src->st_ino;
    entry->destination_dev = st.st_dev;
    entry->destination_ino = st.st_ino;
    entry->next = *head;
    *head = entry;
    return 0;
}

static void
mv_forget (mv_link **head, mv_link *keep)
{
    while (*head != keep) {
        mv_link *entry = *head;
        *head = entry->next;
        free (entry->path);
        free (entry);
    }
}

/* A copy made earlier in this invocation of the file SRC names. */
static mv_link *
mv_find_link (const mv_opts *o, const struct stat *src)
{
    for (mv_link *entry = o->links; entry; entry = entry->next) {
        struct stat dst;
        if (entry->source_dev == src->st_dev && entry->source_ino == src->st_ino &&
            lstat (entry->path, &dst) == 0 &&
            dst.st_dev == entry->destination_dev && dst.st_ino == entry->destination_ino)
            return entry;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* copying across file systems */

static int mv_copy_tree (const char *src, const char *dst, mv_opts *o,
                         mv_removals *removals, int top);

/* Owner and group where permitted (a non-root mover keeps its own); EPERM
   is not an error, as for cp -a. */
static int
mv_keep_owner (const char *dst, const struct stat *sst, int is_link)
{
    int (*own) (const char *, uid_t, gid_t) = is_link ? lchown : chown;
    if (own (dst, sst->st_uid, sst->st_gid) == 0)
        return 0;
    if (errno == EPERM || errno == EINVAL) {
        if (own (dst, (uid_t) -1, sst->st_gid) == 0 || errno == EPERM || errno == EINVAL)
            return 0;
    }
    mv_error1 ("failed to preserve ownership for %s: %s", dst, errno);
    return -1;
}

/* Extended attributes (ACLs and capabilities among them), best effort. */
static void
mv_keep_xattrs (const char *src, const char *dst)
{
    ssize_t size = llistxattr (src, NULL, 0);
    if (size <= 0)
        return;
    char *names = malloc ((size_t) size);
    if (!names)
        return;
    size = llistxattr (src, names, (size_t) size);
    for (ssize_t at = 0; size > 0 && at < size; at += (ssize_t) strlen (names + at) + 1) {
        const char *name = names + at;
        ssize_t length = lgetxattr (src, name, NULL, 0);
        if (length < 0)
            continue;
        char *value = malloc ((size_t) length + 1);
        if (!value)
            continue;
        length = lgetxattr (src, name, value, (size_t) length);
        if (length >= 0)
            (void) lsetxattr (dst, name, value, (size_t) length, 0);
        free (value);
    }
    free (names);
}

static int
mv_keep_times (const char *dst, const struct stat *sst)
{
    struct timespec ts[2] = { sst->st_atim, sst->st_mtim };
    if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) == 0)
        return 0;
    mv_error1 ("preserving times for %s: %s", dst, errno);
    return -1;
}

static int
mv_keep_mode (const char *dst, const struct stat *sst)
{
    if (chmod (dst, sst->st_mode & 07777) == 0)
        return 0;
    mv_error1 ("preserving permissions for %s: %s", dst, errno);
    return -1;
}

/* Owner, then attributes, then mode (chown clears set-ID bits and file
   capabilities), then times. */
static int
mv_keep_metadata (const char *src, const char *dst, const struct stat *sst)
{
    int rc = mv_keep_owner (dst, sst, 0);
    mv_keep_xattrs (src, dst);
    if (mv_keep_mode (dst, sst) < 0)
        rc = -1;
    if (mv_keep_times (dst, sst) < 0)
        rc = -1;
    return rc;
}

static int
mv_write_all (int fd, const char *buf, size_t n)
{
    while (n > 0) {
        ssize_t w = write (fd, buf, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += w;
        n -= (size_t) w;
    }
    return 0;
}

/* Copy LENGTH bytes (or to end of file when LENGTH < 0) from the current
   offsets. Returns 0, or -1 with *reading telling which side failed. */
static int
mv_copy_bytes (int sfd, int dfd, off_t length, int *reading)
{
    static char buf[128 * 1024];
    while (length != 0) {
        size_t want = sizeof buf;
        if (length > 0 && (off_t) want > length)
            want = (size_t) length;
        ssize_t n = read (sfd, buf, want);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            *reading = 1;
            return -1;
        }
        if (n == 0)
            break;
        if (mv_write_all (dfd, buf, (size_t) n) < 0) {
            *reading = 0;
            return -1;
        }
        if (length > 0)
            length -= n;
    }
    return 0;
}

/* The data of a regular file; holes stay holes. */
static int
mv_copy_data (int sfd, int dfd, const struct stat *sst, int *reading, int *sparse)
{
    *sparse = sst->st_size > 0 && (off_t) sst->st_blocks * 512 < sst->st_size;
    if (!*sparse)
        return mv_copy_bytes (sfd, dfd, -1, reading);
    off_t at = 0;
    int data_seen = 0;
    while (at < sst->st_size) {
        off_t data = lseek (sfd, at, SEEK_DATA);
        if (data < 0) {
            if (errno == ENXIO)
                break;
            if (errno == EINVAL || errno == ENOTSUP) {
                /* No hole detection here: plain copy from AT. */
                if (lseek (sfd, at, SEEK_SET) < 0 || lseek (dfd, at, SEEK_SET) < 0) {
                    *reading = 1;
                    return -1;
                }
                return mv_copy_bytes (sfd, dfd, -1, reading);
            }
            *reading = 1;
            return -1;
        }
        off_t hole = lseek (sfd, data, SEEK_HOLE);
        if (hole < 0 || lseek (sfd, data, SEEK_SET) < 0) {
            *reading = 1;
            return -1;
        }
        if (lseek (dfd, data, SEEK_SET) < 0) {
            *reading = 0;
            return -1;
        }
        if (mv_copy_bytes (sfd, dfd, hole - data, reading) < 0)
            return -1;
        data_seen = 1;
        at = hole;
    }
    if (!data_seen)
        *sparse = 2;    /* nothing but holes: no data was offered for copying */
    if (ftruncate (dfd, sst->st_size) < 0) {
        *reading = 0;
        return -1;
    }
    return 0;
}

static int
mv_copy_regular (const char *src, const char *dst, const struct stat *sst, const mv_opts *o)
{
    int sfd = open (src, O_RDONLY | O_NOCTTY | O_NOFOLLOW);
    if (sfd < 0) {
        mv_error1 ("cannot open %s for reading: %s", src, errno);
        return -1;
    }
    int dfd = open (dst, O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY, S_IRUSR | S_IWUSR);
    if (dfd < 0) {
        int error = errno;
        close (sfd);
        mv_error1 ("cannot create regular file %s: %s", dst, error);
        return -1;
    }
    int rc = 0, reading = 0, sparse = 0;
    if (mv_copy_data (sfd, dfd, sst, &reading, &sparse) < 0) {
        if (reading)
            mv_error1 ("error reading %s: %s", src, errno);
        else
            mv_error1 ("error writing %s: %s", dst, errno);
        rc = -1;
    }
    if (close (sfd) < 0 && rc == 0) {
        mv_error1 ("failed to close %s: %s", src, errno);
        rc = -1;
    }
    if (close (dfd) < 0 && rc == 0) {
        mv_error1 ("failed to close %s: %s", dst, errno);
        rc = -1;
    }
    if (rc == 0 && o->debug)
        mv_printf ("copy offload: %s, reflink: unsupported, sparse detection: %s\n",
                sparse == 2 ? "unknown" : "unsupported", sparse ? "SEEK_HOLE" : "no");
    if (rc == 0 && mv_keep_metadata (src, dst, sst) < 0)
        rc = -1;
    if (rc < 0)
        unlink (dst);   /* no partial copy of a file is left behind */
    return rc;
}

static int
mv_copy_symlink (const char *src, const char *dst, const struct stat *sst)
{
    size_t size = sst->st_size > 0 ? (size_t) sst->st_size + 1 : 256;
    char *target = NULL;
    ssize_t n;
    for (;;) {
        char *bigger = realloc (target, size);
        if (!bigger) {
            free (target);
            MV_ERROR ("memory exhausted");
            return -1;
        }
        target = bigger;
        n = readlink (src, target, size);
        if (n < 0) {
            mv_error1 ("cannot read symbolic link %s: %s", src, errno);
            free (target);
            return -1;
        }
        if ((size_t) n < size)
            break;
        size *= 2;
    }
    target[n] = '\0';
    if (symlink (target, dst) < 0) {
        mv_error1 ("cannot create symbolic link %s: %s", dst, errno);
        free (target);
        return -1;
    }
    free (target);
    int rc = mv_keep_owner (dst, sst, 1);
    if (mv_keep_times (dst, sst) < 0)
        rc = -1;
    if (rc < 0)
        unlink (dst);
    return rc;
}

/* FIFOs, sockets and device nodes are made anew. */
static int
mv_copy_special (const char *src, const char *dst, const struct stat *sst)
{
    if (S_ISFIFO (sst->st_mode)) {
        if (mkfifo (dst, S_IRUSR | S_IWUSR) < 0) {
            mv_error1 ("cannot create fifo %s: %s", dst, errno);
            return -1;
        }
    } else if (mknod (dst, (sst->st_mode & S_IFMT) | S_IRUSR | S_IWUSR, sst->st_rdev) < 0) {
        mv_error1 ("cannot create special file %s: %s", dst, errno);
        return -1;
    }
    int rc = mv_keep_metadata (src, dst, sst);
    if (rc < 0)
        unlink (dst);
    return rc;
}

typedef struct {
    char *name;
    ino_t ino;
    size_t order;
    mv_removals removals;
} mv_entry;

static int
mv_entry_cmp (const void *a, const void *b)
{
    const mv_entry *x = *(const mv_entry *const *) a, *y = *(const mv_entry *const *) b;
    if (x->ino != y->ino)
        return x->ino < y->ino ? -1 : 1;
    return x->order < y->order ? -1 : x->order > y->order;
}

static int
mv_copy_dir (const char *src, const char *dst, const struct stat *sst, mv_opts *o,
             mv_removals *removals)
{
    if (mkdir (dst, S_IRWXU) < 0) {
        mv_error1 ("cannot create directory %s: %s", dst, errno);
        return -1;
    }
    if (o->verbose)
        mv_say ("created directory", dst, NULL, NULL, NULL);
    /* Fill the new directory with owner access whatever the umask, then
       give it the source's own permissions at the end. */
    int rc = 0;
    if (chmod (dst, (sst->st_mode & 0777) | S_IRWXU) < 0) {
        mv_error1 ("preserving permissions for %s: %s", dst, errno);
        return -1;
    }

    /* Read the whole listing first, so no directory stays open while
       the tree below it is copied. Entries are copied in inode order, as
       GNU mv does, and removed later in the order the directory listed
       them. */
    mv_entry *entries = NULL;
    size_t count = 0, cap = 0;
    DIR *d = opendir (src);
    if (!d) {
        mv_error1 ("cannot access %s: %s", src, errno);
        rc = -1;
    } else {
        for (;;) {
            errno = 0;
            struct dirent *de = readdir (d);
            if (!de) {
                if (errno) {
                    mv_error1 ("reading directory %s: %s", src, errno);
                    rc = -1;
                }
                break;
            }
            if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, ".."))
                continue;
            if (count == cap) {
                size_t ncap = cap ? cap * 2 : 32;
                mv_entry *nv = realloc (entries, ncap * sizeof *nv);
                if (!nv) {
                    MV_ERROR ("memory exhausted");
                    rc = -1;
                    break;
                }
                entries = nv;
                cap = ncap;
            }
            mv_entry *e = &entries[count];
            memset (e, 0, sizeof *e);
            e->ino = de->d_ino;
            e->order = count;
            if (!(e->name = strdup (de->d_name))) {
                MV_ERROR ("memory exhausted");
                rc = -1;
                break;
            }
            count++;
        }
        if (closedir (d) < 0) {
            mv_error1 ("cannot access %s: %s", src, errno);
            rc = -1;
        }
    }
    mv_entry **by_inode = count ? malloc (count * sizeof *by_inode) : NULL;
    if (count && !by_inode) {
        MV_ERROR ("memory exhausted");
        rc = -1;
    }
    /* A failed entry does not stop its siblings; nothing is removed
       unless every entry was copied. */
    if (rc == 0 && count) {
        for (size_t i = 0; i < count; i++)
            by_inode[i] = &entries[i];
        qsort (by_inode, count, sizeof *by_inode, mv_entry_cmp);
        for (size_t i = 0; i < count; i++) {
            QUIT;
            mv_entry *e = by_inode[i];
            size_t length = strlen (e->name);
            char *sc = mv_join (src, e->name, length);
            char *dc = sc ? mv_join (dst, e->name, length) : NULL;
            if (!sc || !dc || mv_copy_tree (sc, dc, o, &e->removals, 0) < 0)
                rc = -1;
            free (sc);
            free (dc);
        }
    }
    for (size_t i = 0; i < count; i++) {
        if (entries[i].removals.head) {
            if (removals->tail)
                removals->tail->next = entries[i].removals.head;
            else
                removals->head = entries[i].removals.head;
            removals->tail = entries[i].removals.tail;
        }
        free (entries[i].name);
    }
    free (entries);
    free (by_inode);

    if (mv_keep_owner (dst, sst, 0) < 0)
        rc = -1;
    mv_keep_xattrs (src, dst);
    if (mv_keep_mode (dst, sst) < 0)
        rc = -1;
    if (mv_keep_times (dst, sst) < 0)
        rc = -1;
    return rc;
}

static int
mv_note_source (mv_removals *removals, const char *src, const struct stat *sst)
{
    mv_source *source = malloc (sizeof *source);
    if (!source || !(source->path = strdup (src))) {
        free (source);
        MV_ERROR ("memory exhausted");
        return -1;
    }
    source->dev = sst->st_dev;
    source->ino = sst->st_ino;
    source->type = sst->st_mode & S_IFMT;
    source->next = NULL;
    if (removals->tail)
        removals->tail->next = source;
    else
        removals->head = source;
    removals->tail = source;
    return 0;
}

/* Copy SRC to DST (which does not exist), recording the source entries in
   postorder. TOP: the caller printed the -v line of a non-directory. */
static int
mv_copy_tree (const char *src, const char *dst, mv_opts *o, mv_removals *removals, int top)
{
    struct stat sst;
    if (lstat (src, &sst) < 0) {
        mv_error1 ("cannot stat %s: %s", src, errno);
        return -1;
    }
    int rc;
    /* Earlier names of a file may already be gone, so even st_nlink == 1
       can be the last link of a file copied earlier in this command. A
       new link to that copy gets no -v line. */
    mv_link *entry = S_ISDIR (sst.st_mode) ? NULL : mv_find_link (o, &sst);
    if (o->verbose && !top && !S_ISDIR (sst.st_mode) && !entry)
        mv_say ("copied", src, "->", dst, NULL);
    if (entry) {
        rc = link (entry->path, dst);
        if (rc < 0)
            mv_error2 ("cannot create hard link %s to %s: %s", dst, entry->path, errno);
    }
    else if (S_ISDIR (sst.st_mode))
        rc = mv_copy_dir (src, dst, &sst, o, removals);
    else if (S_ISREG (sst.st_mode))
        rc = mv_copy_regular (src, dst, &sst, o);
    else if (S_ISLNK (sst.st_mode))
        rc = mv_copy_symlink (src, dst, &sst);
    else
        rc = mv_copy_special (src, dst, &sst);
    if (rc < 0)
        return -1;
    if (!entry && !S_ISDIR (sst.st_mode) && sst.st_nlink > 1 &&
        mv_remember (&o->links, &sst, dst) < 0)
        return -1;
    return mv_note_source (removals, src, &sst);
}

/* Remove the copied sources, children before their directory. An entry
   that is no longer the file that was copied stays, and so do the
   directories above anything that could not be removed. */
static int
mv_remove_sources (mv_removals *removals, const mv_opts *o)
{
    int rc = 0;
    const char **failed = NULL;
    size_t nfailed = 0;
    for (mv_source *source = removals->head; source; source = source->next) {
        int skip = 0;
        size_t length = strlen (source->path);
        for (size_t i = 0; i < nfailed && !skip; i++)
            skip = strncmp (failed[i], source->path, length) == 0 && failed[i][length] == '/';
        if (skip)
            goto failed;
        struct stat st;
        if (lstat (source->path, &st) < 0) {
            mv_error1 ("cannot remove %s: %s", source->path, errno);
            goto failed;
        }
        if (st.st_dev != source->dev || st.st_ino != source->ino ||
            (st.st_mode & S_IFMT) != source->type) {
            mv_error1 ("cannot remove %s: it was replaced during the move", source->path, 0);
            goto failed;
        }
        if ((S_ISDIR (st.st_mode) ? rmdir (source->path) : unlink (source->path)) < 0) {
            mv_error1 ("cannot remove %s: %s", source->path, errno);
            goto failed;
        }
        if (o->verbose)
            mv_say (S_ISDIR (st.st_mode) ? "removed directory" : "removed", source->path,
                    NULL, NULL, NULL);
        continue;
    failed:
        rc = -1;
        {
            const char **nf = realloc (failed, (nfailed + 1) * sizeof *nf);
            if (!nf)
                break;
            failed = nf;
            failed[nfailed++] = source->path;
        }
    }
    free (failed);
    return rc;
}

static int
mv_xdev (const char *src, const char *dst, const struct stat *sst, mv_opts *o,
         const char *backup)
{
    /* A destination still present (no backup was made) is removed first;
       rename's rules hold, so only an empty directory goes. */
    struct stat ds;
    int present = lstat (dst, &ds) == 0;
    if (present && (o->prompt == MV_NO_CLOBBER || o->update == MV_UPDATE_NONE ||
                    o->update == MV_UPDATE_NONE_FAIL))
        return 1;       /* it appeared after the no-clobber check */
    if (present && (S_ISDIR (ds.st_mode) ? rmdir (dst) : unlink (dst)) < 0) {
        int error = errno;
        char *qs = mv_q (src), *qd = mv_q (dst);
        MV_ERROR ("inter-device move failed: %s to %s; unable to remove target: %s",
                  qs ? qs : src, qd ? qd : dst, strerror (error));
        free (qs);
        free (qd);
        return -1;
    }
    if (o->verbose && !S_ISDIR (sst->st_mode) && !mv_find_link (o, sst))
        mv_say ("copied", src, "->", dst, backup);

    mv_removals removals = { NULL, NULL };
    mv_link *old_links = o->links;
    int rc = mv_copy_tree (src, dst, o, &removals, 1);
    if (rc < 0)
        /* A failed copy must not stand in for a later link to the same
           file, which still needs its own data copied. */
        mv_forget (&o->links, old_links);
    else
        rc = mv_remove_sources (&removals, o);
    while (removals.head) {
        mv_source *source = removals.head;
        removals.head = source->next;
        free (source->path);
        free (source);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* one operand */

/* Put a backup made for DST back after the move failed. */
static void
mv_unbackup (const char *dst, const char *backup, const mv_opts *o)
{
    struct stat st;
    if (!backup || lstat (dst, &st) == 0 || errno != ENOENT)
        return;
    if (rename (backup, dst) == 0 && o->verbose) {
        char *qb = mv_q (backup), *qd = mv_q (dst);
        mv_printf ("%s -> %s (unbackup)\n", qb ? qb : backup, qd ? qd : dst);
        free (qb);
        free (qd);
    }
}

/* 0 moved, 1 skipped, -1 failed. */
static int
mv_one (const char *src, const char *dst, mv_opts *o, int stripped)
{
    struct stat ss, ds;
    if (lstat (src, &ss) < 0) {
        mv_error1 ("cannot stat %s: %s", src, errno);
        return -1;
    }
    /* An empty DEST names the working directory, as it does for GNU mv. */
    const char *dst_sys = *dst ? dst : ".";
    int dst_exists = lstat (dst_sys, &ds) == 0;
    if (!dst_exists && errno != ENOENT) {
        mv_error1 ("cannot stat %s: %s", dst, errno);
        return -1;
    }
    /* GNU: a SOURCE that lost its trailing slashes must still be a
       directory when it is renamed to a name of its own. */
    if (stripped && !S_ISDIR (ss.st_mode)) {
        mv_error2 ("cannot move %s to %s: %s", src, dst, ENOTDIR);
        return -1;
    }
    if (o->exchange && !dst_exists) {
        mv_error2 ("cannot exchange %s and %s: Unknown error -1", src, dst, 0);
        return -1;
    }
    char *backup = NULL;
    if (dst_exists) {
        if (o->prompt == MV_NO_CLOBBER || o->update == MV_UPDATE_NONE)
            return 1;
        if (o->update == MV_UPDATE_NONE_FAIL) {
            mv_error1 ("not replacing %s", dst, 0);
            return -1;
        }
        int same = ss.st_dev == ds.st_dev && ss.st_ino == ds.st_ino;
        if (!same && S_ISLNK (ss.st_mode) && !S_ISLNK (ds.st_mode)) {
            struct stat target;
            same = stat (src, &target) == 0 &&
                   target.st_dev == ds.st_dev && target.st_ino == ds.st_ino;
        }
        if (same && (!o->backup || mv_same_name (src, dst))) {
            mv_error2 ("%s and %s are the same file", src, dst, 0);
            return -1;
        }
        if (o->update == MV_UPDATE_OLDER && !S_ISDIR (ss.st_mode) &&
            (ds.st_mtim.tv_sec > ss.st_mtim.tv_sec ||
             (ds.st_mtim.tv_sec == ss.st_mtim.tv_sec && ds.st_mtim.tv_nsec >= ss.st_mtim.tv_nsec)))
            return 1;
        if (o->prompt != MV_FORCE) {
            int unwritable = !S_ISLNK (ds.st_mode) &&
                             faccessat (AT_FDCWD, dst, W_OK, AT_EACCESS) != 0;
            if ((o->prompt == MV_INTERACTIVE || (unwritable && isatty (0))) &&
                !mv_ask (dst, &ds, unwritable))
                return -1;
        }
        if (!S_ISDIR (ds.st_mode))
            for (mv_link *entry = o->written; entry; entry = entry->next)
                if (!strcmp (entry->path, dst) &&
                    ds.st_dev == entry->destination_dev && ds.st_ino == entry->destination_ino) {
                    mv_error2 ("will not overwrite just-created %s with %s", dst, src, 0);
                    return -1;
                }
        if (!o->exchange && !o->backup) {
            if (S_ISDIR (ds.st_mode) && !S_ISDIR (ss.st_mode)) {
                mv_error2 ("cannot overwrite directory %s with non-directory %s", dst, src, 0);
                return -1;
            }
            if (!S_ISDIR (ds.st_mode) && S_ISDIR (ss.st_mode)) {
                mv_error2 ("cannot overwrite non-directory %s with directory %s", dst, src, 0);
                return -1;
            }
        }
        if (o->backup) {
            backup = bos_backup_name (dst, o->backup_kind, o->suffix);
            if (!backup) {
                mv_error1 ("cannot backup %s: %s", dst, errno ? errno : ENOMEM);
                return -1;
            }
            if (rename (dst, backup) < 0) {
                mv_error1 ("cannot backup %s: %s", dst, errno);
                free (backup);
                return -1;
            }
        }
    }

    if (o->exchange) {
        if (mv_rename2 (src, dst_sys, RENAME_EXCHANGE) < 0) {
            mv_error2 ("cannot exchange %s and %s: %s", src, dst, errno);
            return -1;
        }
        if (o->verbose)
            mv_say ("exchanged", src, "<->", dst, NULL);
        return 0;
    }

    int rc;
    if (!dst_exists && (o->prompt == MV_NO_CLOBBER || o->update == MV_UPDATE_NONE ||
                        o->update == MV_UPDATE_NONE_FAIL)) {
        /* Never replace a destination that appeared since the check. */
        rc = mv_rename2 (src, dst_sys, RENAME_NOREPLACE);
        if (rc < 0 && errno == EEXIST) {
            if (o->update == MV_UPDATE_NONE_FAIL && o->prompt != MV_NO_CLOBBER) {
                mv_error1 ("not replacing %s", dst, 0);
                return -1;
            }
            return 1;
        }
        if (rc < 0 && (errno == ENOSYS || errno == EINVAL))
            rc = rename (src, dst_sys);
    } else
        rc = rename (src, dst_sys);
    if (rc == 0) {
        if (o->verbose)
            mv_say ("renamed", src, "->", dst, backup);
        free (backup);
        return 0;
    }
    int error = errno;
    if (error == EXDEV && !o->no_copy)
        rc = mv_xdev (src, dst, &ss, o, backup);
    else {
        if (error == EINVAL && S_ISDIR (ss.st_mode))
            mv_error2 ("cannot move %s to a subdirectory of itself, %s", src, dst, 0);
        else if (error == ENOTEMPTY || error == EEXIST)
            mv_error1 ("cannot overwrite %s: %s", dst, error);
        else
            mv_error2 ("cannot move %s to %s: %s", src, dst, error);
        rc = -1;
    }
    if (rc < 0)
        mv_unbackup (dst, backup, o);
    free (backup);
    return rc;
}

/* ------------------------------------------------------------------ */

static void
mv_usage (void)
{
    fputs (
"Usage: mv [OPTION]... [-T] SOURCE DEST\n"
"  or:  mv [OPTION]... SOURCE... DIRECTORY\n"
"  or:  mv [OPTION]... -t DIRECTORY SOURCE...\n"
"Rename SOURCE to DEST, or move SOURCE(s) to DIRECTORY.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n"
"      --backup[=CONTROL]       make a backup of each existing destination file\n"
"  -b                           like --backup but does not accept an argument\n"
"      --debug                  explain how a file is copied.  Implies -v\n"
"      --exchange               exchange source and destination\n"
"  -f, --force                  do not prompt before overwriting\n"
"  -i, --interactive            prompt before overwrite\n"
"  -n, --no-clobber             do not overwrite an existing file\n"
"If you specify more than one of -i, -f, -n, only the final one takes effect.\n"
"      --no-copy                do not copy if renaming fails\n"
"      --strip-trailing-slashes  remove any trailing slashes from each SOURCE\n"
"                                 argument\n"
"  -S, --suffix=SUFFIX          override the usual backup suffix\n"
"  -t, --target-directory=DIRECTORY  move all SOURCE arguments into DIRECTORY\n"
"  -T, --no-target-directory    treat DEST as a normal file\n"
"      --update[=UPDATE]        control which existing files are updated;\n"
"                                 UPDATE={all,none,none-fail,older(default)}\n"
"  -u                           equivalent to --update[=older].  See below\n"
"  -v, --verbose                explain what is being done\n"
"  -Z, --context                set SELinux security context of destination\n"
"                                 file to default type\n"
"      --help        display this help and exit\n"
"      --version     output version information and exit\n"
"\n"
"UPDATE controls which existing files in the destination are replaced.\n"
"'all' is the default operation when an --update option is not specified,\n"
"and results in all existing files in the destination being replaced.\n"
"'none' is like the --no-clobber option, in that no files in the\n"
"destination are replaced, and skipped files do not induce a failure.\n"
"'none-fail' also ensures no files are replaced in the destination,\n"
"but any skipped files are diagnosed and induce a failure.\n"
"'older' is the default operation when --update is specified, and results\n"
"in files being replaced if they're older than the corresponding source file.\n"
"\n"
"The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX.\n"
"The version control method may be selected via the --backup option or through\n"
"the VERSION_CONTROL environment variable.  Here are the values:\n"
"\n"
"  none, off       never make backups (even if --backup is given)\n"
"  numbered, t     make numbered backups\n"
"  existing, nil   numbered if numbered backups exist, simple otherwise\n"
"  simple, never   always make simple backups\n", stdout);
}

static const struct bos_longopt mv_longopts[] = {
    { "backup", BOS_OPT_ARG, MV_OPT_BACKUP },
    { "context", BOS_NO_ARG, 'Z' },
    { "debug", BOS_NO_ARG, MV_OPT_DEBUG },
    { "exchange", BOS_NO_ARG, MV_OPT_EXCHANGE },
    { "force", BOS_NO_ARG, 'f' },
    { "interactive", BOS_NO_ARG, 'i' },
    { "no-clobber", BOS_NO_ARG, 'n' },
    { "no-copy", BOS_NO_ARG, MV_OPT_NO_COPY },
    { "no-target-directory", BOS_NO_ARG, 'T' },
    { "strip-trailing-slashes", BOS_NO_ARG, MV_OPT_STRIP },
    { "suffix", BOS_REQ_ARG, 'S' },
    { "target-directory", BOS_REQ_ARG, 't' },
    { "update", BOS_OPT_ARG, MV_OPT_UPDATE },
    { "verbose", BOS_NO_ARG, 'v' },
    { "help", BOS_NO_ARG, BOS_OPT_HELP },
    { "version", BOS_NO_ARG, BOS_OPT_VERSION },
    { NULL, 0, 0 }
};

static const char *const mv_update_names[] = { "all", "none", "none-fail", "older", NULL };
static const int mv_update_vals[] = {
    MV_UPDATE_ALL, MV_UPDATE_NONE, MV_UPDATE_NONE_FAIL, MV_UPDATE_OLDER
};

static void
mv_free_links (mv_link *entry)
{
    while (entry) {
        mv_link *next = entry->next;
        free (entry->path);
        free (entry);
        entry = next;
    }
}

int
mv_builtin (WORD_LIST *list)
{
    mv_opts o;
    memset (&o, 0, sizeof o);
    const char *backup_control = NULL, *target_dir = NULL;
    int notarget = 0, strip = 0, c;
    bos_getopt g;

    mv_out.len = 0;
    mv_out.line = isatty (1);
    bos_getopt_init (&g, "mv", "bfinS:t:TuvZ", mv_longopts, list);
    while ((c = bos_getopt_next (&g)) != -1) {
        switch (c) {
        case 'b':
            o.backup = 1;
            break;
        case MV_OPT_BACKUP:
            o.backup = 1;
            if (g.optarg)
                backup_control = g.optarg;
            break;
        case MV_OPT_DEBUG:
            o.debug = o.verbose = 1;
            break;
        case MV_OPT_EXCHANGE:
            o.exchange = 1;
            break;
        case 'f':
            o.prompt = MV_FORCE;
            break;
        case 'i':
            o.prompt = MV_INTERACTIVE;
            break;
        case 'n':
            o.prompt = MV_NO_CLOBBER;
            break;
        case MV_OPT_NO_COPY:
            o.no_copy = 1;
            break;
        case MV_OPT_STRIP:
            strip = 1;
            break;
        case 'S':
            o.backup = 1;
            o.suffix = g.optarg;
            break;
        case 't':
            if (target_dir) {
                MV_ERROR ("multiple target directories specified");
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            target_dir = g.optarg;
            break;
        case 'T':
            notarget = 1;
            break;
        case 'u':
            o.update = MV_UPDATE_OLDER;
            break;
        case MV_OPT_UPDATE:
            if (!g.optarg)
                o.update = MV_UPDATE_OLDER;
            else if ((o.update = bos_argmatch ("mv", "--update", g.optarg, mv_update_names,
                                               mv_update_vals)) < 0) {
                bos_getopt_free (&g);
                return EXECUTION_FAILURE;
            }
            break;
        case 'v':
            o.verbose = 1;
            break;
        case 'Z':
            break;      /* no SELinux: the default context is the only one */
        case BOS_OPT_HELP:
            mv_usage ();
            bos_getopt_free (&g);
            return sh_chkwrite (EXECUTION_SUCCESS);
        case BOS_OPT_VERSION:
            puts ("mv (bash-os) 1.0");
            bos_getopt_free (&g);
            return sh_chkwrite (EXECUTION_SUCCESS);
        default:
            bos_getopt_free (&g);
            return EXECUTION_FAILURE;
        }
    }

    char **operands = g.operands;
    int n = g.noperands;
    int status = EXECUTION_FAILURE, early = 0;

    if (n == 0 || (n == 1 && !target_dir)) {
        if (n == 0)
            MV_ERROR ("missing file operand");
        else
            mv_error1 ("missing destination file operand after %s", operands[0], 0);
        bos_try_help ("mv");
        goto out;
    }
    if (target_dir && notarget) {
        MV_ERROR ("cannot combine --target-directory (-t) and --no-target-directory (-T)");
        goto out;
    }
    if (notarget && n > 2) {
        mv_error1 ("extra operand %s", operands[2], 0);
        bos_try_help ("mv");
        goto out;
    }

    const char *dest;
    int nsrc, into_dir = 0;
    struct stat st;
    if (target_dir) {
        dest = target_dir;
        nsrc = n;
        int r = stat (dest, &st);
        if (r < 0 || !S_ISDIR (st.st_mode)) {
            mv_error1 ("target directory %s: %s", dest, r < 0 ? errno : ENOTDIR);
            goto out;
        }
        into_dir = 1;
    } else {
        dest = operands[n - 1];
        nsrc = n - 1;
        if (!notarget) {
            int r = stat (dest, &st);
            into_dir = r == 0 && S_ISDIR (st.st_mode);
            if (n > 2 && !into_dir) {
                mv_error1 ("target %s: %s", dest, r < 0 ? errno : ENOTDIR);
                goto out;
            }
        }
    }

    /* Like GNU, SOURCE DEST first tries a rename that cannot replace
       anything, before the backup settings are even checked; when it
       works, the move is done whatever those checks then report. */
    if (n == 2 && !target_dir && !notarget && !o.exchange)
        early = mv_rename2 (operands[0], operands[1], RENAME_NOREPLACE) == 0;

    if (o.backup && (o.exchange || o.prompt == MV_NO_CLOBBER ||
                     o.update == MV_UPDATE_NONE || o.update == MV_UPDATE_NONE_FAIL)) {
        MV_ERROR ("cannot combine --backup with --exchange, -n, or --update=none-fail");
        bos_try_help ("mv");
        goto out;
    }
    if (o.backup) {
        o.backup_kind = bos_backup_kind ("mv", backup_control);
        if (o.backup_kind < 0)
            goto out;
        if (o.backup_kind == BOS_BACKUP_NONE)
            o.backup = 0;
        o.suffix = bos_backup_suffix (o.suffix);
    }

    status = EXECUTION_SUCCESS;
    if (early) {
        if (o.verbose) {
            const char *src = operands[0];
            char *src_buf = NULL;
            size_t length = strlen (src);
            if (strip) {
                while (length > 1 && src[length - 1] == '/')
                    length--;
                if ((src_buf = strndup (src, length)))
                    src = src_buf;
            }
            mv_say ("renamed", src, "->", operands[1], NULL);
            free (src_buf);
        }
        goto out;
    }
    for (int i = 0; i < nsrc; i++) {
        QUIT;
        const char *src = operands[i];
        char *src_buf = NULL;
        int stripped = 0;
        if (strip) {
            size_t length = strlen (src);
            while (length > 1 && src[length - 1] == '/') {
                length--;
                stripped = 1;
            }
            if (stripped && !(src = src_buf = strndup (src, length))) {
                MV_ERROR ("memory exhausted");
                status = EXECUTION_FAILURE;
                break;
            }
        }
        char *dst_buf = NULL;
        const char *dst = dest;
        if (into_dir) {
            size_t length;
            const char *base = mv_base (src, &length);
            dst_buf = mv_join (dest, base, length);
            if (!dst_buf) {
                status = EXECUTION_FAILURE;
                free (src_buf);
                continue;
            }
            dst = dst_buf;
        }
        int moved = mv_one (src, dst, &o, stripped && !into_dir);
        if (moved < 0)
            status = EXECUTION_FAILURE;
        else if (moved == 0 && !o.exchange) {
            struct stat ds;
            /* Remember what was made, so a later operand cannot replace it. */
            if (lstat (dst, &ds) == 0 && mv_remember (&o.written, &ds, dst) < 0) {
                status = EXECUTION_FAILURE;
                free (dst_buf);
                free (src_buf);
                break;
            }
        }
        free (dst_buf);
        free (src_buf);
    }

out:
    mv_out_flush ();
    bos_getopt_free (&g);
    mv_free_links (o.links);
    mv_free_links (o.written);
    return sh_chkwrite (status);
}

char *mv_doc[] = {
    "Move (rename) files.",
    "",
    "    mv [OPTION]... [-T] SRC DST",
    "    mv [OPTION]... SRC... DIR",
    "    mv [OPTION]... -t DIR SRC...",
    "",
    "    -b   make a backup of each existing destination (--backup[=CONTROL])",
    "    -S SUFFIX   backup suffix (default ~ or $SIMPLE_BACKUP_SUFFIX)",
    "    -f   force: do not prompt before overwriting",
    "    -i   interactive: prompt before overwrite",
    "    -n   no-clobber: never overwrite",
    "    -u   replace only older destinations (--update[=all|none|none-fail|older])",
    "    -v   verbose: explain what is being done",
    "    -t DIR   move every SRC into DIR (--target-directory)",
    "    -T   treat DST as a normal file (--no-target-directory)",
    "    -Z   accepted; no SELinux context is set",
    "",
    "    Long-only: --debug, --exchange, --no-copy, --strip-trailing-slashes.",
    "    'mv --help' describes every option.",
    "",
    "    A move to another file system copies the files (types, modes, owners,",
    "    times, extended attributes and hard links) and then removes the sources.",
    "    Exit status 0 on success, 1 if any move failed or on bad usage.",
    (char *)NULL
};

struct builtin mv_struct = {
    "mv",
    mv_builtin,
    BUILTIN_ENABLED,
    mv_doc,
    "mv [-bfinTuvZ] [-S SUFFIX] [-t DIR] [--update[=WHEN]] SRC... DST",
    0
};
