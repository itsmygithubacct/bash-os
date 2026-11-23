/* bashcp.c — POSIX cp(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashcp [-abdfilnprRsTuvx] [-HLP] [-S SUFFIX] {SOURCE... DEST | -t DIR SOURCE...}
 *
 *   -a      archive: same as -dpR (preserve symlinks-as-symlinks, preserve
 *           metadata, recursive). Matches GNU coreutils cp -a semantics.
 *   -f      force: remove dest only if opening it for write fails
 *   -i      interactive: prompt before overwrite (refused unless tty)
 *   -p      preserve mode/owner/group/timestamps
 *   -R, -r  recursive
 *   -v      verbose: print each completed copy
 *   -H      follow symlinks given on the command line; preserve nested
 *   -L      always follow symlinks
 *   -P      don't follow symlinks
 *           (default: follow unless recursive; -l always follows)
 *   -b, -S, --backup[=CONTROL], --suffix   back up replaced files
 *   -d      same as --no-dereference --preserve=links
 *   -l, -s  hard / symbolic links instead of copies
 *   -T      treat DEST as a normal file;  -u, --update[=WHEN]
 *   -x      stay on the source file system
 *   GNU long forms: --archive --preserve[=LIST] --no-preserve=LIST
 *   --recursive --verbose --dereference --no-dereference --link
 *   --symbolic-link --one-file-system --no-target-directory
 *   --remove-destination --attributes-only --sparse=WHEN --reflink[=WHEN]
 *
 * Multiple SOURCE → DEST must be a directory. Single SOURCE → DEST
 * is either a target file or, if it's a directory, the file is
 * copied into it as basename(SOURCE).
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/ioctl.h>

#include "loadables.h"

typedef struct bcp_link {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    char *path;
    int follow;
    struct bcp_link *next;
} bcp_link;

typedef struct bcp_dir {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    struct bcp_dir *parent;
} bcp_dir;

enum { BCP_UPDATE_ALL, BCP_UPDATE_OLDER, BCP_UPDATE_NONE };
enum { BCP_BACKUP_NONE, BCP_BACKUP_SIMPLE, BCP_BACKUP_NUMBERED, BCP_BACKUP_EXISTING };
enum { BCP_SPARSE_AUTO, BCP_SPARSE_ALWAYS, BCP_SPARSE_NEVER };
enum { BCP_REFLINK_NEVER, BCP_REFLINK_AUTO, BCP_REFLINK_ALWAYS };

typedef struct {
    int fflag, iflag, nflag, pflag, rflag, vflag;
    int Hflag, Lflag, Pflag, aflag, parents;
    /* What -p/-a/--preserve keep; pflag is "any of mode, owner, times". */
    int pmode, powner, ptime, plinks;
    int nomode;             /* --no-preserve=mode: create 0666/0777 & ~umask */
    int update;             /* -u/--update[=WHEN] */
    int link_mode;          /* 'l' (-l) or 's' (-s), else 0 */
    int backup;             /* -b/--backup[=CONTROL] */
    const char *suffix;     /* -S/--suffix, else $SIMPLE_BACKUP_SUFFIX or ~ */
    int sparse, reflink;
    int remove_dest, attr_only, xflag, Tflag;
    dev_t top_dev;          /* -x: the file system of the current operand */
    bcp_link *links;
    bcp_dir *directories;
} bcp_opts;

typedef struct {
    const char **v;
    int n;
    int cap;
} bcp_words;

static int
bcp_words_add (bcp_words *words, const char *word)
{
    if (words->n == words->cap) {
        int new_cap = words->cap ? words->cap * 2 : 16;
        const char **nv = realloc (words->v, (size_t) new_cap * sizeof (*words->v));
        if (!nv) {
            builtin_error ("realloc: %s", strerror (errno));
            return -1;
        }
        words->v = nv;
        words->cap = new_cap;
    }
    words->v[words->n++] = word;
    return 0;
}

/* Forward decls. */
static int bcp_one (const char *src, const char *dst,
                    bcp_opts *o, int top_level_source);

static bcp_link *
bcp_find_link (const bcp_opts *o, const struct stat *src)
{
    for (bcp_link *entry = o->links; entry; entry = entry->next) {
        struct stat st;
        if (entry->source_dev == src->st_dev && entry->source_ino == src->st_ino &&
            (entry->follow ? stat (entry->path, &st) : lstat (entry->path, &st)) == 0 &&
            st.st_dev == entry->destination_dev && st.st_ino == entry->destination_ino)
            return entry;
    }
    return NULL;
}

static int
bcp_remember_link (bcp_opts *o, const struct stat *src, const char *dst)
{
    struct stat st;
    int follow = S_ISREG (src->st_mode);
    if ((follow ? stat (dst, &st) : lstat (dst, &st)) < 0) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        return -1;
    }
    bcp_link *entry = malloc (sizeof *entry);
    if (!entry) { builtin_error ("out of memory"); return -1; }
    entry->path = strdup (dst);
    if (!entry->path) { free (entry); builtin_error ("out of memory"); return -1; }
    entry->source_dev = src->st_dev;
    entry->source_ino = src->st_ino;
    entry->destination_dev = st.st_dev;
    entry->destination_ino = st.st_ino;
    entry->follow = follow;
    entry->next = o->links;
    o->links = entry;
    return 0;
}

static int
bcp_copy_link (const char *src, const char *dst, const struct stat *sst,
               const bcp_link *entry, const bcp_opts *o)
{
    struct stat st;
    if (lstat (dst, &st) == 0) {
        if (o->nflag) return 1;
        if (st.st_dev == sst->st_dev && st.st_ino == sst->st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
        if (st.st_dev == entry->destination_dev && st.st_ino == entry->destination_ino)
            return 0;
        if (o->iflag) {
            fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), answer = c;
            while (c != EOF && c != '\n') c = getchar ();
            if (answer != 'y' && answer != 'Y') return -1;
        }
        if (unlink (dst) < 0) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            return -1;
        }
    } else if (errno != ENOENT) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        return -1;
    }
    if (linkat (AT_FDCWD, entry->path, AT_FDCWD, dst,
                entry->follow ? AT_SYMLINK_FOLLOW : 0) < 0) {
        if (o->nflag && errno == EEXIST) return 1;
        builtin_error ("link %s -> %s: %s", entry->path, dst, strerror (errno));
        return -1;
    }
    if (o->vflag) printf ("'%s' -> '%s'\n", src, dst);
    return 0;
}

static int
bcp_all_zero (const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return 0;
    return 1;
}

/* Fast path: read+write loop. No sendfile dependency — keep portable.
   With HOLES, blocks of zeros become holes (GNU --sparse); the final size
   is set with ftruncate so a trailing hole is kept. */
static int
bcp_copy_data (int sfd, int dfd, const char *src, const char *dst, int holes)
{
    enum { BLK = 4096 };
    char buf[64 * 1024];
    ssize_t n;
    off_t total = 0;
    int ended_in_hole = 0;
    while ((n = read (sfd, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        total += n;
        if (holes) {
            while (off < n) {
                size_t len = (size_t) (n - off) < BLK ? (size_t) (n - off) : BLK;
                if (len == BLK && bcp_all_zero (buf + off, len)) {
                    if (lseek (dfd, (off_t) len, SEEK_CUR) < 0) {
                        fprintf (stderr, "cp: cannot lseek '%s': %s\n", dst, strerror (errno));
                        return -1;
                    }
                    ended_in_hole = 1;
                    off += (ssize_t) len;
                    continue;
                }
                ssize_t w = write (dfd, buf + off, len);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    fprintf (stderr, "cp: error writing '%s': %s\n", dst, strerror (errno));
                    return -1;
                }
                ended_in_hole = 0;
                off += w;
            }
            continue;
        }
        while (off < n) {
            ssize_t w = write (dfd, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                /* GNU's line, without the shell's source prefix. */
                fprintf (stderr, "cp: error writing '%s': %s\n", dst, strerror (errno));
                return -1;
            }
            off += w;
        }
    }
    if (n < 0) {
        fprintf (stderr, "cp: error reading '%s': %s\n", src, strerror (errno));
        return -1;
    }
    if (holes && ended_in_hole && ftruncate (dfd, total) < 0) {
        fprintf (stderr, "cp: cannot extend '%s': %s\n", dst, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bcp_apply_metadata (const char *dst, const struct stat *st, const bcp_opts *o)
{
    int rc = 0;
    /* chown can clear set-ID bits, so apply the final mode afterwards. */
    if (o->powner && chown (dst, st->st_uid, st->st_gid) < 0) {
        if (errno != EPERM) {
            builtin_error ("chown %s: %s", dst, strerror (errno));
            rc = -1;
        }
    }
    if (o->pmode && chmod (dst, st->st_mode & 07777) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (!o->ptime)
        return rc;
    struct timespec ts[2];
    ts[0].tv_sec  = st->st_atim.tv_sec;
    ts[0].tv_nsec = st->st_atim.tv_nsec;
    ts[1].tv_sec  = st->st_mtim.tv_sec;
    ts[1].tv_nsec = st->st_mtim.tv_nsec;
    /* Regular-file copies follow destination symlinks, just like chown and
       chmod above. Symlink copies use their own metadata path. */
    if (utimensat (AT_FDCWD, dst, ts, 0) < 0) {
        if (errno == ENOSYS) {
            /* Fall back only when the kernel lacks utimensat, not on I/O
               errors from a supported operation. */
            struct timeval tv[2];
            tv[0].tv_sec = ts[0].tv_sec; tv[0].tv_usec = ts[0].tv_nsec / 1000;
            tv[1].tv_sec = ts[1].tv_sec; tv[1].tv_usec = ts[1].tv_nsec / 1000;
            if (utimes (dst, tv) == 0) return rc;
        }
        builtin_error ("preserve times %s: %s", dst, strerror (errno));
        rc = -1;
    }
    return rc;
}

#ifndef FICLONE
#  define FICLONE _IOW (0x94, 9, int)
#endif

/* The backup made for the copy being reported; GNU -v appends it. */
static char bcp_backup_note[4096 + 48];

static void
bcp_verbose (const char *src, const char *dst)
{
    if (bcp_backup_note[0])
        printf ("'%s' -> '%s' (backup: '%s')\n", src, dst, bcp_backup_note);
    else
        printf ("'%s' -> '%s'\n", src, dst);
    bcp_backup_note[0] = '\0';
}

/* GNU backup names: simple "DST~" (or the -S suffix), numbered
   "DST.~N~", or "existing": numbered when numbered backups already exist. */
static int
bcp_make_backup (const char *dst, const bcp_opts *o)
{
    const char *slash = strrchr (dst, '/');
    const char *base = slash ? slash + 1 : dst;
    size_t dirlen = slash ? (size_t) (slash - dst) : 0;
    int highest = 0;
    int kind = o->backup;

    if (kind == BCP_BACKUP_NUMBERED || kind == BCP_BACKUP_EXISTING) {
        char *dir = dirlen ? strndup (dst, dirlen) : strdup (slash ? "/" : ".");
        DIR *d = dir ? opendir (dir) : NULL;
        size_t bl = strlen (base);
        struct dirent *de;
        while (d && (de = readdir (d)) != NULL) {
            const char *n = de->d_name;
            if (strncmp (n, base, bl) != 0 || strncmp (n + bl, ".~", 2) != 0)
                continue;
            char *end;
            long v = strtol (n + bl + 2, &end, 10);
            if (end != n + bl + 2 && end[0] == '~' && end[1] == '\0' && v > highest && v < 1000000000)
                highest = (int) v;
        }
        if (d)
            closedir (d);
        free (dir);
        if (kind == BCP_BACKUP_EXISTING)
            kind = highest ? BCP_BACKUP_NUMBERED : BCP_BACKUP_SIMPLE;
    }
    const char *suffix = o->suffix;
    if (!suffix || !*suffix || strchr (suffix, '/'))
        suffix = "~";
    size_t len = strlen (dst) + 32 + strlen (suffix);
    char *name = malloc (len);
    if (!name) {
        builtin_error ("out of memory");
        return -1;
    }
    if (kind == BCP_BACKUP_NUMBERED)
        snprintf (name, len, "%s.~%d~", dst, highest + 1);
    else
        snprintf (name, len, "%s%s", dst, suffix);
    int rc = rename (dst, name);
    if (rc < 0)
        builtin_error ("cannot backup '%s': %s", dst, strerror (errno));
    else
        snprintf (bcp_backup_note, sizeof bcp_backup_note, "%s", name);
    free (name);
    return rc;
}

/* Make way for a new DST: -b renames it, --remove-destination unlinks it. */
static int
bcp_clear_destination (const char *dst, const bcp_opts *o, int *exists)
{
    if (!*exists)
        return 0;
    if (o->backup != BCP_BACKUP_NONE) {
        if (bcp_make_backup (dst, o) < 0)
            return -1;
        *exists = 0;
    } else if (o->remove_dest) {
        if (unlink (dst) < 0 && errno != ENOENT) {
            builtin_error ("cannot remove '%s': %s", dst, strerror (errno));
            return -1;
        }
        *exists = 0;
    }
    return 0;
}

/* Copy a regular file. dst is a full path — no path-joining here. */
static int
bcp_copy_regular (const char *src, const char *dst,
                  const struct stat *sst, const bcp_opts *o)
{
    /* Detect dst exists; honor -f / -i. */
    struct stat dst_st;
    int dst_exists = (lstat (dst, &dst_st) == 0);
    if (dst_exists) {
        if (o->nflag) return 1;
        /* Refuse identical-inode (cp file file). */
        if (dst_st.st_dev == sst->st_dev && dst_st.st_ino == sst->st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
        if (o->iflag) {
            fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), answer = c;
            while (c != EOF && c != '\n') c = getchar ();
            if (answer != 'y' && answer != 'Y') return -1;
        }
        if (S_ISLNK (dst_st.st_mode)) {
            struct stat target_st;
            if (stat (dst, &target_st) < 0) {
                builtin_error ("stat destination %s: %s", dst, strerror (errno));
                return -1;
            }
            if (target_st.st_dev == sst->st_dev && target_st.st_ino == sst->st_ino) {
                builtin_error ("'%s' and '%s' are the same file", src, dst);
                return -1;
            }
            if (S_ISDIR (target_st.st_mode)) {
                builtin_error ("%s: existing destination symlink target is a directory", dst);
                return -1;
            }
        } else if (S_ISDIR (dst_st.st_mode)) {
            builtin_error ("%s: existing destination is a directory", dst);
            return -1;
        }
    }
    /* Open the source before replacing dest. -f must not unlink an
       existing destination when the source cannot be read. */
    int sfd = open (src, O_RDONLY);
    if (sfd < 0) {
        builtin_error ("open %s: %s", src, strerror (errno));
        return -1;
    }
    if (dst_exists && !S_ISDIR (dst_st.st_mode) && !o->attr_only &&
        bcp_clear_destination (dst, o, &dst_exists) < 0) {
        close (sfd);
        return -1;
    }
    if (dst_exists &&
        o->plinks && S_ISREG (dst_st.st_mode) && dst_st.st_nlink > 1) {
        if (unlink (dst) < 0 && errno != ENOENT) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            close (sfd);
            return -1;
        }
    }
    /* Open without truncating: dst may be a symlink back to src, and the
       lstat check above compares the link's inode rather than its target. */
    mode_t create_mode = o->nomode ? 0666 : sst->st_mode & 0777;
    int dfd = open (dst, O_WRONLY | O_CREAT | (o->nflag ? O_EXCL : 0), create_mode);
    /* -f is a retry after a failed write-open, not unconditional removal.
       Keep openable symlinks, hardlinks and destination modes intact. The
       source is already open and same-file checks precede any unlink. */
    if (dfd < 0 && o->fflag && !o->nflag && dst_exists) {
        if (unlink (dst) < 0) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            close (sfd);
            return -1;
        }
        dfd = open (dst, O_WRONLY | O_CREAT | O_EXCL, create_mode);
    }
    if (dfd < 0) {
        if (o->nflag && errno == EEXIST) { close (sfd); return 1; }
        builtin_error ("open %s for write: %s", dst, strerror (errno));
        close (sfd);
        return -1;
    }
    struct stat opened_src, opened_dst;
    if (fstat (sfd, &opened_src) < 0 || fstat (dfd, &opened_dst) < 0) {
        builtin_error ("stat open file: %s", strerror (errno));
        close (sfd);
        close (dfd);
        return -1;
    }
    if (opened_src.st_dev == opened_dst.st_dev &&
        opened_src.st_ino == opened_dst.st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        close (sfd);
        close (dfd);
        return -1;
    }
    /* Truncate a regular file; a device, fifo or socket is simply written into. */
    int dst_regular = S_ISREG (opened_dst.st_mode);
    if (!o->attr_only && dst_regular && ftruncate (dfd, 0) < 0) {
        builtin_error ("truncate %s: %s", dst, strerror (errno));
        close (sfd);
        close (dfd);
        return -1;
    }
    int rc = 0, copied = o->attr_only;
    if (!copied && dst_regular && o->reflink != BCP_REFLINK_NEVER) {
        if (ioctl (dfd, FICLONE, sfd) == 0)
            copied = 1;
        else if (o->reflink == BCP_REFLINK_ALWAYS) {
            builtin_error ("failed to clone '%s' from '%s': %s", dst, src, strerror (errno));
            rc = -1;
            copied = 1;
        }
    }
    /* --sparse=auto makes holes only where the source has them. */
    int holes = dst_regular && (o->sparse == BCP_SPARSE_ALWAYS ||
        (o->sparse == BCP_SPARSE_AUTO && (off_t) opened_src.st_blocks * 512 < opened_src.st_size));
    if (!copied)
        rc = bcp_copy_data (sfd, dfd, src, dst, holes);
    if (close (sfd) < 0) {
        builtin_error ("close %s: %s", src, strerror (errno));
        rc = -1;
    }
    if (close (dfd) < 0) {
        builtin_error ("close %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (rc < 0) return -1;
    if (o->pflag && dst_regular && bcp_apply_metadata (dst, sst, o) < 0) return -1;
    if (o->vflag)
        bcp_verbose (src, dst);  /* GNU cp -v writes to stdout */
    return 0;
}

static int
bcp_copy_symlink (const char *src, const char *dst, const struct stat *sst,
                  const bcp_opts *o)
{
    char target[4096];
    ssize_t n = readlink (src, target, sizeof target - 1);
    if (n < 0) {
        builtin_error ("readlink %s: %s", src, strerror (errno));
        return -1;
    }
    target[n] = '\0';
    /* Replace existing entries. Use symlink-to-temp + rename so the
       replacement is atomic (no window where dst doesn't exist). */
    struct stat ds;
    int dst_exists = (lstat (dst, &ds) == 0);
    if (dst_exists && o->nflag) return 1;
    if (dst_exists && ds.st_dev == sst->st_dev && ds.st_ino == sst->st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        return -1;
    }
    if (dst_exists && o->iflag) {
        fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
        fflush (stderr);
        int c = getchar (), answer = c;
        while (c != EOF && c != '\n') c = getchar ();
        if (answer != 'y' && answer != 'Y') return -1;
    }
    if (dst_exists && !S_ISDIR (ds.st_mode) && bcp_clear_destination (dst, o, &dst_exists) < 0)
        return -1;
    if (dst_exists) {
        char tmp_path[4096 + 32];
        int wlen = snprintf (tmp_path, sizeof tmp_path,
                             "%s.bcptmp.XXXXXX", dst);
        if (wlen < 0 || (size_t) wlen + sizeof "/link" > sizeof tmp_path) {
            builtin_error ("symlink %s: dst path too long for atomic replace", dst);
            return -1;
        }
        /* Reserve a private directory atomically. A predictable temporary
           name must never unlink an unrelated entry beside the destination. */
        if (!mkdtemp (tmp_path)) {
            builtin_error ("temporary directory for %s: %s", dst, strerror (errno));
            return -1;
        }
        size_t dirlen = strlen (tmp_path);
        memcpy (tmp_path + dirlen, "/link", sizeof "/link");
        int failed = 0;
        if (symlink (target, tmp_path) < 0) {
            builtin_error ("symlink %s -> %s: %s", tmp_path, target, strerror (errno));
            failed = 1;
        } else if (rename (tmp_path, dst) < 0) {
            builtin_error ("rename %s -> %s: %s", tmp_path, dst, strerror (errno));
            unlink (tmp_path);
            failed = 1;
        }
        tmp_path[dirlen] = '\0';
        if (rmdir (tmp_path) < 0) {
            builtin_error ("rmdir %s: %s", tmp_path, strerror (errno));
            failed = 1;
        }
        if (failed) return -1;
    } else if (symlink (target, dst) < 0) {
        if (o->nflag && errno == EEXIST) return 1;
        builtin_error ("symlink %s -> %s: %s", dst, target, strerror (errno));
        return -1;
    }
    if (o->pflag) {
        /* lchown for symlink owner. */
        if (o->powner && lchown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
            builtin_error ("lchown %s: %s", dst, strerror (errno));
            return -1;
        }
        struct timespec ts[2] = { sst->st_atim, sst->st_mtim };
        if (o->ptime && utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
            builtin_error ("utimensat %s: %s", dst, strerror (errno));
            return -1;
        }
    }
    if (o->vflag)
        bcp_verbose (src, dst);  /* GNU cp -v writes to stdout */
    return 0;
}

static int
bcp_copy_dir (const char *src, const char *dst, const struct stat *sst,
              bcp_opts *o)
{
    if (!o->rflag) {
        builtin_error ("-r not specified; omitting directory '%s'", src);
        return -1;
    }
    for (const bcp_dir *parent = o->directories; parent; parent = parent->parent) {
        if (sst->st_dev == parent->source_dev && sst->st_ino == parent->source_ino) {
            builtin_error ("%s: cyclic directory traversal", src);
            return -1;
        }
        if (sst->st_dev == parent->destination_dev && sst->st_ino == parent->destination_ino) {
            builtin_error ("cannot copy a directory into itself: %s", src);
            return -1;
        }
    }
    /* mkdir if not present. */
    struct stat ds;
    int created = 0;
    mode_t final_mode = 0;
    int rc = 0;
    if (lstat (dst, &ds) < 0) {
        if (errno != ENOENT) {
            builtin_error ("stat %s: %s", dst, strerror (errno));
            return -1;
        }
        mode_t mask = umask (0);
        umask (mask);
        final_mode = (o->nomode ? 0777 : sst->st_mode & 0777) & ~mask;
        if (mkdir (dst, final_mode | S_IRWXU) < 0) {
            builtin_error ("mkdir %s: %s", dst, strerror (errno));
            return -1;
        }
        created = 1;
        /* Populate read-only trees before applying their final mode. chmod
           also restores owner access when the caller's umask removed it. */
        if (chmod (dst, final_mode | S_IRWXU) < 0) {
            builtin_error ("chmod %s: %s", dst, strerror (errno));
            rc = -1;
            goto restore_mode;
        }
        if (o->vflag)
            bcp_verbose (src, dst);  /* GNU cp -v writes to stdout */
    } else if (!S_ISDIR (ds.st_mode)) {
        builtin_error ("'%s' exists and is not a directory", dst);
        return -1;
    } else if (ds.st_dev == sst->st_dev && ds.st_ino == sst->st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        return -1;
    }
    if (created && lstat (dst, &ds) < 0) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        rc = -1;
        goto restore_mode;
    }
    /* -x: a directory on another file system is created but not entered. */
    if (o->xflag && sst->st_dev != o->top_dev)
        goto restore_mode;
    DIR *dir = opendir (src);
    if (!dir) {
        builtin_error ("opendir %s: %s", src, strerror (errno));
        rc = -1;
        goto restore_mode;
    }
    bcp_dir current = { sst->st_dev, ds.st_dev, sst->st_ino, ds.st_ino,
                        o->directories };
    o->directories = &current;
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir (dir);
        if (!de) {
            if (errno) {
                builtin_error ("readdir %s: %s", src, strerror (errno));
                rc = -1;
            }
            break;
        }
        if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
            continue;
        size_t src_len = strlen (src), dst_len = strlen (dst);
        while (src_len && src[src_len - 1] == '/') src_len--;
        while (dst_len && dst[dst_len - 1] == '/') dst_len--;
        size_t sn = src_len + strlen (de->d_name) + 2;
        size_t dn = dst_len + strlen (de->d_name) + 2;
        if (sn > 4096 || dn > 4096) {
            builtin_error ("path too long while copying %s", de->d_name);
            rc = -1;
            continue;
        }
        /* Keep long paths off each recursive stack frame. */
        char *src_child = malloc (sn), *dst_child = malloc (dn);
        if (!src_child || !dst_child) {
            builtin_error ("out of memory");
            free (src_child);
            free (dst_child);
            rc = -1;
            break;
        }
        snprintf (src_child, sn, "%.*s/%s", (int) src_len, src, de->d_name);
        snprintf (dst_child, dn, "%.*s/%s", (int) dst_len, dst, de->d_name);
        if (bcp_one (src_child, dst_child, o, 0) < 0) rc = -1;
        free (src_child);
        free (dst_child);
    }
    o->directories = current.parent;
    if (closedir (dir) < 0) {
        builtin_error ("closedir %s: %s", src, strerror (errno));
        rc = -1;
    }
restore_mode:
    if (created && chmod (dst, final_mode) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (o->pflag && bcp_apply_metadata (dst, sst, o) < 0) rc = -1;
    return rc;
}

/* -l / -s: make a hard or symbolic link instead of copying data. */
static int
bcp_make_link (const char *src, const char *dst, const bcp_opts *o, int follow)
{
    struct stat cur;
    int exists = lstat (dst, &cur) == 0;
    const char *what = o->link_mode == 's' ? "symbolic link" : "hard link";

    if (o->link_mode == 's' && src[0] != '/' && strchr (dst, '/')) {
        /* GNU: a relative target only resolves beside the current directory. */
        const char *d = dst;
        while (d[0] == '.' && d[1] == '/')
            d += 2;
        if (strchr (d, '/')) {
            builtin_error ("%s: can make relative symbolic links only in current directory", dst);
            return -1;
        }
    }
    if (exists) {
        if (o->nflag)
            return 0;
        if (S_ISDIR (cur.st_mode)) {
            builtin_error ("cannot overwrite directory '%s' with non-directory", dst);
            return -1;
        }
        if (o->link_mode == 'l') {
            struct stat sst;
            if ((follow ? stat (src, &sst) : lstat (src, &sst)) == 0 &&
                sst.st_dev == cur.st_dev && sst.st_ino == cur.st_ino)
                return 0;   /* already that link */
        }
        if (o->backup != BCP_BACKUP_NONE) {
            if (bcp_make_backup (dst, o) < 0)
                return -1;
        } else if (o->fflag || o->remove_dest) {
            if (unlink (dst) < 0) {
                builtin_error ("cannot remove '%s': %s", dst, strerror (errno));
                return -1;
            }
        }
    }
    int rc = o->link_mode == 's'
        ? symlink (src, dst)
        : linkat (AT_FDCWD, src, AT_FDCWD, dst, follow ? AT_SYMLINK_FOLLOW : 0);
    if (rc < 0) {
        builtin_error ("cannot create %s '%s' to '%s': %s", what, dst, src, strerror (errno));
        return -1;
    }
    if (o->vflag)
        bcp_verbose (src, dst);
    return 0;
}

/* Top-level dispatcher per source. dst must be a complete target path
   (file or directory entry name); caller resolves dir-into. */
static int
bcp_one (const char *src, const char *dst, bcp_opts *o, int top_level_source)
{
    struct stat sst;
    /* GNU: with no -H/-L/-P, follow unless recursive; -l always follows. */
    int follow = o->Lflag || (top_level_source && o->Hflag)
                 || (!o->Pflag && !o->Hflag && (!o->rflag || o->link_mode == 'l'));
    int rc;
    if (follow) rc = stat (src, &sst);
    else        rc = lstat (src, &sst);
    if (rc < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    if (top_level_source)
        o->top_dev = sst.st_dev;
    bcp_backup_note[0] = '\0';
    if (S_ISDIR (sst.st_mode))    return bcp_copy_dir     (src, dst, &sst, o);
    /* -u/--update: keep a destination that is not older than the source. */
    if (o->update != BCP_UPDATE_ALL) {
        struct stat cur;
        if (lstat (dst, &cur) == 0 && !S_ISDIR (cur.st_mode)) {
            if (o->update == BCP_UPDATE_NONE)
                return 0;
            if (cur.st_mtim.tv_sec > sst.st_mtim.tv_sec ||
                (cur.st_mtim.tv_sec == sst.st_mtim.tv_sec && cur.st_mtim.tv_nsec >= sst.st_mtim.tv_nsec))
                return 0;
        }
    }
    if (o->link_mode)
        return bcp_make_link (src, dst, o, follow);
    if (S_ISREG (sst.st_mode) || S_ISLNK (sst.st_mode)) {
        /* -n skips existing entries before same-file checks or link tracking.
           GNU still diagnoses a dangling destination when copying regular
           data through it. Directories continue to merge. */
        struct stat dst_st;
        if (o->nflag && lstat (dst, &dst_st) == 0) {
            struct stat target;
            if (S_ISREG (sst.st_mode) && S_ISLNK (dst_st.st_mode) && stat (dst, &target) < 0) {
                builtin_error ("not writing through dangling symlink '%s'", dst);
                return -1;
            }
            return 0;
        }
        /* A later operand must not overwrite a result from this invocation:
           it may already be the backing file for preserved hard links. */
        for (bcp_link **slot = &o->links; *slot;) {
            bcp_link *written = *slot;
            if (!strcmp (written->path, dst) &&
                (written->source_dev != sst.st_dev || written->source_ino != sst.st_ino)) {
                if (top_level_source) {
                    builtin_error ("will not overwrite just-copied '%s' with '%s'", dst, src);
                    return -1;
                }
                /* Directory operands may merge. This path will no longer
                   represent the cached source after its contents change. */
                *slot = written->next;
                free (written->path);
                free (written);
            } else {
                slot = &written->next;
            }
        }
        /* Scope link tracking to this invocation, including multiple source
           operands. Dereferencing may expose aliases whose link count is 1. */
        int preserve_link = o->plinks && (sst.st_nlink > 1 || o->Hflag || o->Lflag);
        bcp_link *entry = preserve_link ? bcp_find_link (o, &sst) : NULL;
        if (entry) rc = bcp_copy_link (src, dst, &sst, entry, o);
        else rc = S_ISLNK (sst.st_mode) ? bcp_copy_symlink (src, dst, &sst, o)
                                  : bcp_copy_regular (src, dst, &sst, o);
        if (rc == 0 && (preserve_link || top_level_source))
            rc = bcp_remember_link (o, &sst, dst);
        return rc;
    }
    /* Other (fifo, sock, dev) — refuse for now. */
    builtin_error ("%s: unsupported file type", src);
    return -1;
}

/* --parents retains the source spelling below DEST (without leading /).
   Create only missing parent directories and restore their source-derived
   modes after copying, deepest first, so read-only parents can be populated. */
typedef struct bcp_parent {
    char *path;
    struct stat source;
    mode_t mode;
    struct bcp_parent *next;
} bcp_parent;

static int
bcp_copy_parents (const char *src, const char *dest, bcp_opts *o)
{
    size_t start = 0, end = strlen (src), dn = strlen (dest);
    while (src[start] == '/') start++;
    while (end > start && src[end - 1] == '/') end--;
    while (dn > 1 && dest[dn - 1] == '/') dn--;
    size_t base = dn + (dn == 0 || dest[dn - 1] != '/');
    size_t tail = end - start;
    if (base + tail + 1 > 4096) {
        builtin_error ("destination path too long: %s", dest);
        return -1;
    }
    char *dst = malloc (base + tail + 1), *prefix = strdup (src);
    if (!dst || !prefix) {
        builtin_error ("out of memory");
        free (dst);
        free (prefix);
        return -1;
    }
    memcpy (dst, dest, dn);
    if (base > dn) dst[dn] = '/';
    memcpy (dst + base, src + start, tail);
    dst[base + tail] = '\0';
    bcp_parent *parents = NULL;
    int rc = 0;
    mode_t mask = umask (0);
    umask (mask);
    for (size_t i = start; i < end; i++) {
        if (src[i] != '/' || i == start || src[i - 1] == '/') continue;
        size_t cut = base + i - start;
        dst[cut] = '\0';
        prefix[i] = '\0';
        struct stat st;
        if (stat (dst, &st) == 0) {
            if (!S_ISDIR (st.st_mode)) {
                builtin_error ("'%s' is not a directory", dst);
                rc = -1;
            }
        } else if (errno != ENOENT) {
            builtin_error ("stat %s: %s", dst, strerror (errno));
            rc = -1;
        } else if (stat (prefix, &st) < 0) {
            builtin_error ("stat %s: %s", prefix, strerror (errno));
            rc = -1;
        } else if (!S_ISDIR (st.st_mode)) {
            builtin_error ("'%s' is not a directory", prefix);
            rc = -1;
        } else {
            bcp_parent *parent = malloc (sizeof *parent);
            if (!parent || !(parent->path = strdup (dst))) {
                free (parent);
                builtin_error ("out of memory");
                rc = -1;
            } else {
                parent->source = st;
                parent->mode = (st.st_mode & (0777 | S_ISVTX)) & ~mask;
                if (mkdir (dst, parent->mode | S_IRWXU) < 0) {
                    builtin_error ("mkdir %s: %s", dst, strerror (errno));
                    free (parent->path);
                    free (parent);
                    rc = -1;
                } else {
                    parent->next = parents;
                    parents = parent;
                    /* Keep setgid inherited from the destination directory,
                       but do not copy source set-ID bits without -p. */
                    struct stat created;
                    if (stat (dst, &created) < 0) {
                        builtin_error ("stat %s: %s", dst, strerror (errno));
                        rc = -1;
                    } else {
                        parent->mode |= created.st_mode & S_ISGID;
                        if (chmod (dst, parent->mode | S_IRWXU) < 0) {
                            builtin_error ("chmod %s: %s", dst, strerror (errno));
                            rc = -1;
                        }
                    }
                    if (o->vflag) printf ("%s -> %s\n", prefix, dst);
                }
            }
        }
        prefix[i] = '/';
        dst[cut] = '/';
        if (rc < 0) break;
    }
    if (rc == 0) rc = bcp_one (src, dst, o, 1);
    while (parents) {
        bcp_parent *parent = parents;
        parents = parent->next;
        if (o->pflag) {
            if (bcp_apply_metadata (parent->path, &parent->source, o) < 0) rc = -1;
        } else if (chmod (parent->path, parent->mode) < 0) {
            builtin_error ("chmod %s: %s", parent->path, strerror (errno));
            rc = -1;
        }
        free (parent->path);
        free (parent);
    }
    free (prefix);
    free (dst);
    return rc;
}

/* --preserve=LIST and --no-preserve=LIST. */
static int
bcp_preserve_list (bcp_opts *o, const char *list, int on)
{
    char *copy = strdup (list), *save = NULL;
    int rc = 0;
    if (!copy) {
        builtin_error ("out of memory");
        return -1;
    }
    for (char *t = strtok_r (copy, ",", &save); t; t = strtok_r (NULL, ",", &save)) {
        if (!strcmp (t, "mode")) { o->pmode = on; o->nomode = !on; }
        else if (!strcmp (t, "ownership")) o->powner = on;
        else if (!strcmp (t, "timestamps")) o->ptime = on;
        else if (!strcmp (t, "links")) o->plinks = on;
        else if (!strcmp (t, "all")) { o->pmode = o->powner = o->ptime = o->plinks = on; o->nomode = !on; }
        else if (!strcmp (t, "context") || !strcmp (t, "xattr")) ;  /* none kept here */
        else {
            builtin_error ("invalid argument '%s' for '--%spreserve'", t, on ? "" : "no-");
            rc = -1;
            break;
        }
    }
    free (copy);
    return rc;
}

static int
bcp_backup_kind (const char *v, int *kind)
{
    if (!v || !*v) v = getenv ("VERSION_CONTROL");
    if (!v || !*v || !strcmp (v, "existing") || !strcmp (v, "nil")) *kind = BCP_BACKUP_EXISTING;
    else if (!strcmp (v, "simple") || !strcmp (v, "never")) *kind = BCP_BACKUP_SIMPLE;
    else if (!strcmp (v, "numbered") || !strcmp (v, "t")) *kind = BCP_BACKUP_NUMBERED;
    else if (!strcmp (v, "none") || !strcmp (v, "off")) *kind = BCP_BACKUP_NONE;
    else {
        builtin_error ("invalid argument '%s' for 'backup type'", v);
        return -1;
    }
    return 0;
}

/* One GNU long option (without its "--"). 0 handled, 1 not a long option
   this function owns, -1 error. VALUE is the text after '=', or NULL. */
static int
bcp_long_option (bcp_opts *o, const char *name, const char *value, WORD_LIST **pp)
{
#define BCP_IS(n) (!strcmp (name, n))
    if (BCP_IS ("archive")) {
        o->pmode = o->powner = o->ptime = o->plinks = 1;
        o->aflag = o->rflag = 1;
        o->Hflag = o->Lflag = 0;
        o->Pflag = 1;
    } else if (BCP_IS ("preserve")) {
        if (value) return bcp_preserve_list (o, value, 1);
        o->pmode = o->powner = o->ptime = 1;
    } else if (BCP_IS ("no-preserve")) {
        if (!value) { builtin_error ("option '--no-preserve' requires an argument"); return -1; }
        return bcp_preserve_list (o, value, 0);
    } else if (BCP_IS ("recursive")) o->rflag = 1;
    else if (BCP_IS ("verbose")) o->vflag = 1;
    else if (BCP_IS ("dereference")) { o->Lflag = 1; o->Hflag = o->Pflag = 0; }
    else if (BCP_IS ("no-dereference")) { o->Pflag = 1; o->Hflag = o->Lflag = 0; }
    else if (BCP_IS ("link")) o->link_mode = 'l';
    else if (BCP_IS ("symbolic-link")) o->link_mode = 's';
    else if (BCP_IS ("one-file-system")) o->xflag = 1;
    else if (BCP_IS ("no-target-directory")) o->Tflag = 1;
    else if (BCP_IS ("remove-destination")) o->remove_dest = 1;
    else if (BCP_IS ("attributes-only")) o->attr_only = 1;
    else if (BCP_IS ("strip-trailing-slashes") || BCP_IS ("copy-contents") || BCP_IS ("debug")
             || BCP_IS ("context")) ;
    else if (BCP_IS ("update")) {
        if (!value || !strcmp (value, "older")) o->update = BCP_UPDATE_OLDER;
        else if (!strcmp (value, "all")) o->update = BCP_UPDATE_ALL;
        else if (!strcmp (value, "none") || !strcmp (value, "none-fail")) o->update = BCP_UPDATE_NONE;
        else { builtin_error ("invalid argument '%s' for '--update'", value); return -1; }
    } else if (BCP_IS ("backup")) {
        return bcp_backup_kind (value, &o->backup);
    } else if (BCP_IS ("suffix")) {
        if (!value) {
            if (!*pp || !(*pp)->next) { builtin_error ("option '--suffix' requires an argument"); return -1; }
            *pp = (*pp)->next;
            value = (*pp)->word->word;
        }
        o->suffix = value;
        if (o->backup == BCP_BACKUP_NONE && bcp_backup_kind (NULL, &o->backup) < 0) return -1;
    } else if (BCP_IS ("sparse")) {
        if (value && !strcmp (value, "auto")) o->sparse = BCP_SPARSE_AUTO;
        else if (value && !strcmp (value, "always")) o->sparse = BCP_SPARSE_ALWAYS;
        else if (value && !strcmp (value, "never")) o->sparse = BCP_SPARSE_NEVER;
        else { builtin_error ("invalid argument '%s' for '--sparse'", value ? value : ""); return -1; }
    } else if (BCP_IS ("reflink")) {
        if (!value || !strcmp (value, "always")) o->reflink = BCP_REFLINK_ALWAYS;
        else if (!strcmp (value, "auto")) o->reflink = BCP_REFLINK_AUTO;
        else if (!strcmp (value, "never")) o->reflink = BCP_REFLINK_NEVER;
        else { builtin_error ("invalid argument '%s' for '--reflink'", value); return -1; }
    } else
        return 1;
#undef BCP_IS
    return 0;
}

int
cp_builtin (WORD_LIST *list)
{
    bcp_opts o = {0};
    /* Parse flags + collect SOURCE list + DEST. */
    bcp_words positional = {0};
    const char *target_dir = NULL;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            free (positional.v);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashcp 1.0 (bash-loadable)");
            free (positional.v);
            return EXECUTION_SUCCESS;
        }
        if (!strncmp (w, "--target-directory=", 19)) {
            if (target_dir) goto duplicate_target;
            target_dir = w + 19;
            continue;
        }
        if (!strcmp (w, "--target-directory")) w = "-t";
        if (!strcmp (w, "--parents")) { o.parents = 1; continue; }
        if (!strcmp (w, "--no-clobber")) w = "-n";
        if (!strcmp (w, "--interactive")) { o.iflag = 1; o.nflag = 0; continue; }
        if (!strcmp (w, "--force")) { o.fflag = 1; continue; }
        if (w[0] == '-' && w[1] == '-' && w[2]) {
            char name[64];
            const char *eq = strchr (w + 2, '=');
            size_t nl = eq ? (size_t) (eq - (w + 2)) : strlen (w + 2);
            if (nl < sizeof name) {
                memcpy (name, w + 2, nl);
                name[nl] = '\0';
                int r = bcp_long_option (&o, name, eq ? eq + 1 : NULL, &p);
                if (r < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
                if (r == 0)
                    continue;
            }
            builtin_error ("unrecognized option '%s'", w);
            builtin_usage ();
            free (positional.v);
            return EXECUTION_FAILURE;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bcp_words_add (&positional, p->word->word) < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'a':
                    /* Archive: -dpR. Reset earlier dereference flags;
                       later -H/-L/-P may select a different symlink mode. */
                    o.pmode = o.powner = o.ptime = o.plinks = 1;
                    o.aflag = 1;
                    o.rflag = 1;
                    o.Hflag = 0;
                    o.Lflag = 0;
                    o.Pflag = 1;
                    break;
                case 'f': o.fflag = 1; break;
                case 'i': o.iflag = 1; o.nflag = 0; break;
                case 'n':
#ifdef BASHOS_CP_WARN_NO_CLOBBER
                    builtin_warning ("behavior of -n is non-portable and may change in future; use --update=none instead");
#endif
                    o.nflag = 1; o.iflag = 0; break;
                case 'p': o.pmode = o.powner = o.ptime = 1; break;
                case 'd': o.Pflag = 1; o.Hflag = o.Lflag = 0; o.plinks = 1; break;
                case 'l': o.link_mode = 'l'; break;
                case 's': o.link_mode = 's'; break;
                case 'u': o.update = BCP_UPDATE_OLDER; break;
                case 'x': o.xflag = 1; break;
                case 'T': o.Tflag = 1; break;
                case 'Z': break;    /* SELinux context: nothing to set */
                case 'b':
                    if (o.backup == BCP_BACKUP_NONE && bcp_backup_kind (NULL, &o.backup) < 0) {
                        free (positional.v);
                        return EXECUTION_FAILURE;
                    }
                    break;
                case 'S': {
                    const char *v;
                    if (w[i + 1]) v = w + i + 1;
                    else if (p->next) { p = p->next; v = p->word->word; }
                    else {
                        builtin_error ("option requires an argument -- 'S'");
                        free (positional.v);
                        return EXECUTION_FAILURE;
                    }
                    o.suffix = v;
                    if (o.backup == BCP_BACKUP_NONE && bcp_backup_kind (NULL, &o.backup) < 0) {
                        free (positional.v);
                        return EXECUTION_FAILURE;
                    }
                    i += strlen (w + i + 1);
                    break;
                }
                case 'R': case 'r': o.rflag = 1; break;
                case 'H': o.Hflag = 1; o.Lflag = 0; o.Pflag = 0; break;
                case 'L': o.Lflag = 1; o.Hflag = 0; o.Pflag = 0; break;
                case 'P': o.Hflag = 0; o.Lflag = 0; o.Pflag = 1; break;
                case 't':
                    if (target_dir) goto duplicate_target;
                    if (w[i + 1]) {
                        target_dir = w + i + 1;
                    } else if (p->next) {
                        p = p->next;
                        target_dir = p->word->word;
                    } else {
                        builtin_error ("option -t requires a directory");
                        free (positional.v);
                        return EXECUTION_FAILURE;
                    }
                    i += strlen (w + i + 1); /* -t consumes the rest of this word */
                    break;
                case 'v': o.vflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    free (positional.v);
                    return EX_USAGE;
                }
            }
        } else {
            if (bcp_words_add (&positional, w) < 0) {
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }
    o.pflag = o.pmode || o.powner || o.ptime;
    if (!o.suffix) o.suffix = getenv ("SIMPLE_BACKUP_SUFFIX");
    if (o.Tflag && target_dir) {
        builtin_error ("cannot combine --target-directory (-t) and --no-target-directory (-T)");
        free (positional.v);
        return EXECUTION_FAILURE;
    }
    if (o.Tflag && positional.n > 2) {
        builtin_error ("extra operand '%s'", positional.v[2]);
        free (positional.v);
        return EXECUTION_FAILURE;
    }
    if (positional.n < (target_dir ? 1 : 2)) {
        builtin_error ("missing file operand");
        builtin_usage ();
        free (positional.v);
        return target_dir ? EXECUTION_FAILURE : EX_USAGE;
    }
    const char *dest = target_dir ? target_dir : positional.v[positional.n - 1];
    int nsrc = target_dir ? positional.n : positional.n - 1;

    /* Is DEST a directory? */
    struct stat dst_st;
    int dst_is_dir = !o.Tflag && (stat (dest, &dst_st) == 0 && S_ISDIR (dst_st.st_mode));

    if ((target_dir || nsrc > 1 || o.parents) && !dst_is_dir) {
        builtin_error ("target '%s' is not a directory", dest);
        free (positional.v);
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    for (int i = 0; i < nsrc; i++) {
        const char *src = positional.v[i];
        if (o.parents) {
            if (bcp_copy_parents (src, dest, &o) < 0) rc = EXECUTION_FAILURE;
            continue;
        }
        char dst_buf[4096];
        const char *dst;
        if (dst_is_dir) {
            /* A trailing slash affects source symlink resolution, but is
               not an empty basename. Keep src intact for stat/open. */
            size_t end = strlen (src);
            while (end > 1 && src[end - 1] == '/') end--;
            size_t start = end;
            while (start > 0 && src[start - 1] != '/') start--;
            int len = snprintf (dst_buf, sizeof dst_buf, "%s/%.*s", dest,
                                (int) (end - start), src + start);
            if (len < 0 || (size_t) len >= sizeof dst_buf) {
                builtin_error ("destination path too long: %s", dest);
                rc = EXECUTION_FAILURE;
                continue;
            }
            dst = dst_buf;
        } else {
            dst = dest;
        }
        if (bcp_one (src, dst, &o, 1) < 0) rc = EXECUTION_FAILURE;
    }
    free (positional.v);
    while (o.links) {
        bcp_link *next = o.links->next;
        free (o.links->path);
        free (o.links);
        o.links = next;
    }
    return rc;

duplicate_target:
    builtin_error ("multiple target directories specified");
    free (positional.v);
    return EXECUTION_FAILURE;
}

char *cp_doc[] = {
    "Copy files and directories.",
    "",
    "    bashcp [-abdfilnprRsTuvx] [-HLP] [-S SUFFIX] SOURCE... DEST",
    "    bashcp [-abdfilnprRsTuvx] [-HLP] [-S SUFFIX] -t DIR SOURCE...",
    "",
    "    -a   archive: same as -dpR (clone symlinks as symlinks,",
    "         preserve hard links and metadata, recursive)",
    "    -f   force: remove dest only if opening it for write fails",
    "    -i   interactive: prompt before overwrite",
    "    -n, --no-clobber   skip existing destinations; last -i/-n wins",
    "    -p   preserve mode/owner/group/timestamps",
    "    --parents   retain source paths under an existing destination directory",
    "    -R, -r   recursive",
    "    -t DIR, --target-directory=DIR   copy all sources into DIR",
    "    -v   verbose: print each completed copy",
    "    -b, --backup[=CONTROL]   back up each replaced file (none, simple,",
    "         numbered, existing; default $VERSION_CONTROL or existing)",
    "    -S SUFFIX, --suffix=SUFFIX   simple backup suffix (default ~)",
    "    -d   same as --no-dereference --preserve=links",
    "    -l, --link   hard-link files instead of copying (follows symlinks)",
    "    -s, --symbolic-link   make symbolic links instead of copying",
    "    -T, --no-target-directory   treat DEST as a normal file",
    "    -u, --update[=all|none|older]   replace only older destinations",
    "    -x, --one-file-system   stay on the source file systems",
    "    --archive, --recursive, --verbose, --dereference, --no-dereference",
    "    --preserve[=mode,ownership,timestamps,links,all], --no-preserve=LIST",
    "    --remove-destination   remove each existing destination first",
    "    --attributes-only   copy metadata only, not file data",
    "    --sparse=auto|always|never   create holes for runs of zeros",
    "    --reflink[=auto|always|never]   clone data when the file system can",
    "    -H   follow symlinks named on the command line",
    "    -L   always follow symlinks",
    "    -P   don't follow symlinks",
    "         (default: follow unless recursive)",
    (char *)NULL
};

struct builtin bashcp_struct = {
    "bashcp",
    cp_builtin,
    BUILTIN_ENABLED,
    cp_doc,
    "bashcp [-abdfilnprRsTuvx] [-HLP] [-S SUFFIX] {SOURCE... DEST | -t DIR SOURCE...}",
    0
};
