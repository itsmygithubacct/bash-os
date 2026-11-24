/* SPDX-License-Identifier: MIT */
/* gzip file and filter interface backed by zlib. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include "loadables.h"
#include "gzip-stream.h"
#include "gnu-longopt.h"

/* name: -1 default (save name/time when compressing, use the file's own
   name and time when decompressing), 0 for -n, 1 for -N. */
struct gzip_options { int decode, stdout_mode, keep, force, test, name, level, quiet, verbose, list, recursive, rsyncable;
                      const char *suffix; };

/* -l totals across operands. */
struct gzip_list_state { int first, failed_total; long long total_in, total_out, header_bytes; };

/* The gzip member header at the start of FD (pread, offset 0): its length,
   stored modification time and stored file name. -2 without the gzip magic
   number, -3 when shorter than it, -1 for a header this reader cannot follow. */
static int gzip_header(int fd, long long *len, unsigned long *mtime, char *name, size_t namesz)
{
    unsigned char b[8192];
    ssize_t n = pread(fd, b, sizeof b, 0);
    if (n < 2) return -3;
    if (b[0] != 0x1f || b[1] != 0x8b) return -2;
    if (n < 10 || b[2] != 8) return -1;
    int flags = b[3];
    size_t pos = 10;
    *mtime = b[4] | (unsigned long)b[5] << 8 | (unsigned long)b[6] << 16 | (unsigned long)b[7] << 24;
    if (name && namesz) name[0] = 0;
    if (flags & 4) {
        if (pos + 2 > (size_t)n) return -1;
        pos += 2 + (b[pos] | b[pos + 1] << 8);
    }
    for (int field = 8; field <= 16; field <<= 1) {
        if (!(flags & field)) continue;
        size_t start = pos;
        while (pos < (size_t)n && b[pos]) pos++;
        if (pos >= (size_t)n) return -1;
        if (field == 8 && name && namesz) snprintf(name, namesz, "%.*s", (int)(pos - start), (const char *)b + start);
        pos++;
    }
    if (flags & 2) pos += 2;
    if (pos > (size_t)n) return -1;
    *len = (long long)pos;
    return 0;
}

static void gzip_ratio(FILE *f, long long num, long long den)
{
    fprintf(f, "%5.1f%%", den == 0 ? 0.0 : 100.0 * (double)num / (double)den);
}

/* Copy FD to a new temporary file, rewound, for byte counting. */
static FILE *gzip_spool(int fd)
{
    FILE *t = tmpfile();
    if (!t) { builtin_error("temporary file: %s", strerror(errno)); return NULL; }
    unsigned char b[32768];
    for (;;) {
        ssize_t n = read(fd, b, sizeof b);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); fclose(t); return NULL; }
        if (!n) break;
        if (fwrite(b, 1, (size_t)n, t) != (size_t)n) { builtin_error("temporary file: write error"); fclose(t); return NULL; }
    }
    if (fflush(t) || lseek(fileno(t), 0, SEEK_SET) < 0) { fclose(t); return NULL; }
    return t;
}

static int gzip_copy_out(int from, int to)
{
    unsigned char b[32768];
    if (lseek(from, 0, SEEK_SET) < 0) return 1;
    for (;;) {
        ssize_t n = read(from, b, sizeof b);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return 1;
        if (!n) return 0;
        if (bgz_write(to, b, (size_t)n)) return 1;
    }
}

static long long gzip_fd_size(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) ? (long long)st.st_size : -1;
}

static int gzip_same_input(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static int gzip_tree(const char *dir, const struct gzip_options *o, struct gzip_list_state *ls);
static int gzip_list_one(const char *file, const struct gzip_options *o, struct gzip_list_state *ls, int in_tree);

/* IN_TREE: reached through -r, where suffix mismatches are skipped silently
   (reported with -v) without changing the exit status, as GNU gzip does. */
static int gzip_one(const char *file, const struct gzip_options *o, struct gzip_list_state *ls, int in_tree)
{
    int from_stdin = !strcmp(file, "-");
    struct stat dirst;
    /* As GNU gzip, a missing NAME to decompress also means NAME.gz; a
       failure names NAME.gz. */
    if (!from_stdin && !o->list && (o->decode || o->test) && lstat(file, &dirst) < 0 && errno == ENOENT) {
        size_t len = strlen(file), slen = strlen(o->suffix);
        int has = (len > slen && !strcmp(file + len - slen, o->suffix))
                  || (!strcmp(o->suffix, ".gz") && len > 4 && !strcmp(file + len - 4, ".tgz"));
        if (!has) {
            char *alt = malloc(len + slen + 1);
            if (!alt) { builtin_error("out of memory"); return 1; }
            sprintf(alt, "%s%s", file, o->suffix);
            int r = gzip_one(alt, o, ls, in_tree);
            free(alt);
            return r;
        }
    }
    if (!from_stdin && (o->force ? stat(file, &dirst) : lstat(file, &dirst)) == 0 && S_ISDIR(dirst.st_mode)) {
        if (o->recursive) return gzip_tree(file, o, ls);
        if (!o->quiet) builtin_error("%s is a directory -- ignored", file);
        return 2;
    }
    if (o->list) return gzip_list_one(file, o, ls, in_tree);
    int filter = from_stdin || o->stdout_mode || o->test;
    struct stat entry;
    int followed_link = !filter && o->force && lstat(file, &entry) == 0 && S_ISLNK(entry.st_mode);
    /* GNU treats an unforced named-input symlink as an open error, even
       under -q. Filters and explicit -f may follow the input link. */
    int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    if (!filter && !o->force) flags |= O_NOFOLLOW;
    int in = from_stdin ? 0 : open(file, flags);
    if (in < 0) { builtin_error("%s: %s", file, strerror(errno)); return 1; }
    struct stat st;
    if (fstat(in, &st)) { if (in) close(in); return 1; }
    if (!filter && (!S_ISREG(st.st_mode) || (!o->force && st.st_nlink > 1))) {
        if (in_tree && !S_ISREG(st.st_mode)) { close(in); return 0; }
        if (!o->quiet) builtin_error("%s: not a regular file with a single link -- unchanged", file);
        close(in); return 2;
    }
    struct stat lst;
    if (!o->force && ((from_stdin && o->decode && isatty(0)) || (filter && !o->decode && !o->test && isatty(1)))) {
        builtin_error("refusing compressed data on a terminal; use -f to override");
        if (in) close(in); return 1;
    }
    char *dest = NULL, *temp = NULL;
    FILE *spool_in = NULL, *spool_out = NULL;
    int out = o->test ? -1 : 1, rc = 0;
    long long header_len = 0;
    unsigned long stored_mtime = 0;
    char stored_name[1024] = "";
    int bad_header = 0, warned = 0;
    if (o->decode && S_ISREG(st.st_mode) &&
        (bad_header = gzip_header(in, &header_len, &stored_mtime, stored_name, sizeof stored_name)) < 0)
        header_len = 0;
    if (!filter) {
        size_t len = strlen(file), slen = strlen(o->suffix);
        size_t cut = slen;
        int tgz = 0;
        if (o->decode) {
            if (len <= cut || strcmp(file + len - cut, o->suffix)) {
                if (!strcmp(o->suffix, ".gz") && len > 4 && !strcmp(file + len - 4, ".tgz")) { cut = 4; tgz = 1; }
                else {
                    if (o->verbose || (!in_tree && !o->quiet)) builtin_error("%s: unknown suffix -- ignored", file);
                    rc = in_tree ? 0 : 2; goto done;
                }
            }
            /* -N: the stored name, in the input's directory. */
            const char *stored = strrchr(stored_name, '/');
            stored = stored ? stored + 1 : stored_name;
            const char *slash = strrchr(file, '/');
            size_t dirlen = slash ? (size_t)(slash - file) + 1 : 0;
            if (o->name == 1 && *stored && strcmp(stored, ".") && strcmp(stored, "..")) {
                dest = malloc(dirlen + strlen(stored) + 1);
                if (dest) { memcpy(dest, file, dirlen); strcpy(dest + dirlen, stored); }
            } else {
                dest = malloc(len + 5);
                if (dest) { memcpy(dest, file, len - cut); strcpy(dest + len - cut, tgz ? ".tar" : ""); }
            }
        } else {
            if (len >= slen && !strcmp(file + len - slen, o->suffix)) {
                if (o->verbose || (!in_tree && !o->quiet))
                    builtin_error("%s: already has suffix %s -- unchanged", file, o->suffix);
                rc = in_tree ? 0 : 2; goto done;
            }
            dest = malloc(len + slen + 1);
            if (dest) { strcpy(dest, file); strcat(dest, o->suffix); }
        }
        if (!dest) { rc = 1; goto done; }
    }
    /* After the suffix check and before the output check, as GNU gzip. */
    if (bad_header == -2 || bad_header == -3) {
        fputc('\n', stderr);
        builtin_error("%s: %s", file, bad_header == -2 ? "not in gzip format" : "unexpected end of file");
        rc = 1; goto done;
    }
    if (!filter) {
        if (!o->force && lstat(dest, &lst) == 0) {
            if (!o->quiet) builtin_error("%s already exists -- unchanged", dest);
            rc = 2; goto done;
        }
        temp = malloc(strlen(dest) + 16);
        if (!temp) { rc = 1; goto done; }
        sprintf(temp, "%s.XXXXXX", dest);
        out = mkstemp(temp);
        if (out < 0) { builtin_error("%s: %s", dest, strerror(errno)); rc = 1; goto done; }
    }
    const char *base = strrchr(file, '/'); base = base ? base + 1 : file;
    unsigned long mtime = 0;
    int save_name = o->name != 0 && !from_stdin;
    /* -v needs both byte counts: spool a stream input or output. */
    int src = in, dst = out;
    long long bytes_in = gzip_fd_size(in), bytes_out = -1;
    if (o->verbose && !o->test && bytes_in < 0) {
        if (!(spool_in = gzip_spool(in))) { rc = 1; goto done; }
        src = fileno(spool_in);
        bytes_in = gzip_fd_size(src);
        if (o->decode && gzip_header(src, &header_len, &stored_mtime, NULL, 0) < 0) header_len = 0;
    }
    if (o->verbose && !o->test && filter) {
        if (!(spool_out = tmpfile())) { builtin_error("temporary file: %s", strerror(errno)); rc = 1; goto done; }
        dst = fileno(spool_out);
    }
    /* GNU names the file before working on it, once the header checks out. */
    if (o->verbose && !from_stdin && (!o->decode || header_len)) { fprintf(stderr, "%s:\t", file); fflush(stderr); }
    rc = o->decode ? bgz_decode_named(src, dst, &mtime, from_stdin ? "stdin" : file) :
        bgz_encode_flags(src, dst, o->level, save_name ? base : NULL,
                         save_name ? (unsigned long)st.st_mtime : 0, o->rsyncable);
    /* GNU gzip: data after the last member that is not another member is
       ignored with a warning (exit status 2) once everything before it
       decoded; zero padding is ignored silently unless -v. */
    if (rc == BGZ_TRAILING_GARBAGE || rc == BGZ_TRAILING_ZEROS) {
        int garbage = rc == BGZ_TRAILING_GARBAGE;
        rc = 0;
        if (garbage || o->verbose) {
            warned = 1;
            if (!o->quiet) {
                fflush(stdout);
                fputc('\n', stderr);
                builtin_error("%s: decompression OK, trailing %s ignored",
                              from_stdin ? "stdin" : file, garbage ? "garbage" : "zero bytes");
            }
        }
    }
    if (o->verbose && !rc && !o->test) bytes_out = gzip_fd_size(dst);
    if (spool_out && !rc && gzip_copy_out(dst, out)) rc = 1;
    if (o->verbose && !rc) {
        if (!from_stdin && o->decode && !header_len) fprintf(stderr, "%s:\t", file);
        if (o->test) fputs(" OK", stderr);
        else if (bytes_out >= 0 && bytes_in >= 0 && !(from_stdin && o->decode)) {
            long long header = o->decode ? header_len + 8 : 10 + (save_name ? (long long)strlen(base) + 1 : 0) + 8;
            if (o->decode) gzip_ratio(stderr, bytes_out - (bytes_in - header), bytes_out);
            else gzip_ratio(stderr, bytes_in - (bytes_out - header), bytes_in);
        }
        if (!o->test && !from_stdin)
            fprintf(stderr, " -- %s %s", o->keep ? "created" : "replaced with", filter ? "stdout" : dest);
        if (!(from_stdin && o->decode && !o->test)) fputc('\n', stderr);
    }
    if (!filter) {
        struct timespec times[2] = { st.st_atim, st.st_mtim };
        /* GNU decompression keeps the input's own time unless -N. */
        if (o->decode && o->name == 1 && mtime) { times[1].tv_sec = (time_t)mtime; times[1].tv_nsec = 0; }
        if (fchmod(out, st.st_mode & 0777) || futimens(out, times)) rc = 1;
        if (close(out)) rc = 1;
        out = -1;
        if (!rc) {
            /* Publish only complete streams. -f replaces the directory entry,
               never follows an existing destination symlink. */
            if (o->force ? rename(temp, dest) : link(temp, dest)) {
                builtin_error("%s: %s", dest, strerror(errno)); rc = 1;
            } else if (!o->keep) {
                struct stat current;
                int unchanged = lstat(file, &lst) == 0;
                if (followed_link)
                    unchanged = unchanged && gzip_same_input(&lst, &entry) &&
                        fstat(in, &current) == 0 && gzip_same_input(&current, &st);
                else
                    unchanged = unchanged && gzip_same_input(&lst, &st);
                if (!unchanged) {
                    builtin_error("%s changed while processing -- input retained", file); rc = 1;
                } else if (unlink(file)) { builtin_error("%s: %s", file, strerror(errno)); rc = 1; }
            }
        }
    }
done:
    if (spool_in) fclose(spool_in);
    if (spool_out) fclose(spool_out);
    if (!from_stdin && close(in)) rc = 1;
    if (temp) { unlink(temp); free(temp); }
    free(dest);
    return rc ? rc : warned ? 2 : 0;
}

/* -r: every entry below DIR, in directory order, symlinks not followed. */
static int gzip_tree(const char *dir, const struct gzip_options *o, struct gzip_list_state *ls)
{
    DIR *d = opendir(dir);
    if (!d) { builtin_error("%s: %s", dir, strerror(errno)); return 1; }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        size_t len = strlen(dir);
        char *path = malloc(len + strlen(de->d_name) + 2);
        if (!path) { builtin_error("out of memory"); rc = 1; break; }
        sprintf(path, "%s%s%s", dir, len && dir[len - 1] == '/' ? "" : "/", de->d_name);
        struct stat st;
        int result;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) result = gzip_tree(path, o, ls);
        else result = gzip_one(path, o, ls, 1);
        if (result == 1 || !rc) rc = result;
        free(path);
    }
    closedir(d);
    return rc;
}

/* -l: GNU gzip's listing of the stored sizes, from the header and the
   trailer's CRC and length. */
static int gzip_list_one(const char *file, const struct gzip_options *o, struct gzip_list_state *ls, int in_tree)
{
    size_t len = strlen(file), slen = strlen(o->suffix);
    int has_suffix = len > slen && !strcmp(file + len - slen, o->suffix);
    int tgz = !has_suffix && !strcmp(o->suffix, ".gz") && len > 4 && !strcmp(file + len - 4, ".tgz");
    if (in_tree && !has_suffix && !tgz) return 0;
    int from_stdin = !strcmp(file, "-");
    char *opened = NULL;
    int fd = from_stdin ? 0 : open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && !has_suffix && !tgz) {
        /* As GNU gzip, NAME also means NAME.gz; report that name. */
        opened = malloc(len + slen + 1);
        if (!opened) { builtin_error("out of memory"); return 1; }
        sprintf(opened, "%s%s", file, o->suffix);
        fd = open(opened, O_RDONLY | O_CLOEXEC);
    }
    const char *shown = opened ? opened : file;
    if (fd < 0) { builtin_error("%s: %s", shown, strerror(errno)); free(opened); return 1; }
    FILE *spool = NULL;
    if (gzip_fd_size(fd) < 0) {
        spool = gzip_spool(fd);
        if (!spool) { if (!from_stdin) close(fd); free(opened); return 1; }
    }
    int src = spool ? fileno(spool) : fd;
    long long header_len, size = gzip_fd_size(src);
    unsigned long stamp;
    char stored[1024];
    unsigned char trailer[8];
    int rc = 0;
    int bad = gzip_header(src, &header_len, &stamp, stored, sizeof stored);
    if (bad < 0 || size < 18 || pread(src, trailer, 8, size - 8) != 8) {
        fputc('\n', stderr);
        builtin_error("%s: %s", shown, bad == -3 || (bad == 0 && size < 18) ? "unexpected end of file" : "not in gzip format");
        ls->header_bytes = 0;   /* as GNU gzip's totals then count */
        rc = 1;
        goto out;
    }
    unsigned long crc = trailer[0] | (unsigned long)trailer[1] << 8 | (unsigned long)trailer[2] << 16 | (unsigned long)trailer[3] << 24;
    long long out_size = trailer[4] | (long long)trailer[5] << 8 | (long long)trailer[6] << 16 | (long long)trailer[7] << 24;
    char name[4096];
    const char *base = strrchr(stored, '/');
    base = base ? base + 1 : stored;
    const char *slash = strrchr(shown, '/');
    int dirlen = slash ? (int)(slash - shown) + 1 : 0;
    if (from_stdin) snprintf(name, sizeof name, "stdout");
    else if (o->name == 1 && *base) snprintf(name, sizeof name, "%.*s%s", dirlen, shown, base);
    else {
        size_t sl = strlen(shown), cut = 0;
        if (sl > slen && !strcmp(shown + sl - slen, o->suffix)) cut = slen;
        else if (tgz) cut = 4;
        snprintf(name, sizeof name, "%.*s%s", (int)(sl - cut), shown, tgz ? ".tar" : "");
    }
    if (ls->first) {
        ls->first = 0;
        if (o->verbose) fputs("method  crc     date  time  ", stdout);
        if (!o->quiet) printf("%19s %19s  ratio uncompressed_name\n", "compressed", "uncompressed");
    }
    if (o->verbose) {
        static const char months[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        struct stat st;
        time_t when = stamp ? (time_t)stamp : (fstat(src, &st) == 0 ? st.st_mtime : 0);
        struct tm tm;
        printf("%5s %08lx ", "defla", crc);
        if (localtime_r(&when, &tm)) printf("%s%3d %02d:%02d ", months[tm.tm_mon], tm.tm_mday, tm.tm_hour, tm.tm_min);
        else fputs("??? ?? ??:?? ", stdout);
    }
    printf("%19lld %19lld ", size, out_size);
    ls->total_in += size; ls->total_out += out_size;
    ls->header_bytes = header_len + 8;
    gzip_ratio(stdout, out_size - (size - ls->header_bytes), out_size);
    printf(" %s\n", name);
out:
    if (spool) fclose(spool);
    if (!from_stdin) close(fd);
    free(opened);
    return rc;
}

int gzip_builtin(WORD_LIST *list)
{
    struct gzip_options o = { .level = 6, .suffix = ".gz", .name = -1 };
    struct gzip_list_state ls = { .first = 1 };
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc(count + 1, sizeof *files);
    if (!files) { builtin_error("out of memory"); return 1; }
    size_t used = 0;
    int rc = 0, c;
    enum { GZ_OPT_RSYNCABLE = BOS_OPT_FIRST };
    static const struct bos_longopt longopts[] = {
        { "stdout", BOS_NO_ARG, 'c' }, { "to-stdout", BOS_NO_ARG, 'c' },
        { "decompress", BOS_NO_ARG, 'd' }, { "uncompress", BOS_NO_ARG, 'd' },
        { "force", BOS_NO_ARG, 'f' }, { "help", BOS_NO_ARG, BOS_OPT_HELP },
        { "keep", BOS_NO_ARG, 'k' }, { "list", BOS_NO_ARG, 'l' },
        { "no-name", BOS_NO_ARG, 'n' }, { "name", BOS_NO_ARG, 'N' },
        { "quiet", BOS_NO_ARG, 'q' }, { "silent", BOS_NO_ARG, 'q' },
        { "recursive", BOS_NO_ARG, 'r' }, { "rsyncable", BOS_NO_ARG, GZ_OPT_RSYNCABLE },
        { "suffix", BOS_REQ_ARG, 'S' }, { "test", BOS_NO_ARG, 't' },
        { "verbose", BOS_NO_ARG, 'v' }, { "version", BOS_NO_ARG, BOS_OPT_VERSION },
        { "fast", BOS_NO_ARG, '1' }, { "best", BOS_NO_ARG, '9' },
        { NULL, 0, 0 }
    };
    /* GNU gzip's getopt_long: permuted operands, unambiguous prefixes,
       glibc's diagnostics and gzip's own `gzip --help' hint, status 1. */
    bos_getopt g;
    bos_getopt_init(&g, "gzip", "cdfklnNqrtvS:123456789", longopts, list);
    g.no_hint = 1;
    while ((c = bos_getopt_next(&g)) != -1) {
        switch (c) {
            case 'c': o.stdout_mode = 1; break;
            case 'd': o.decode = 1; break;
            case 'k': o.keep = 1; break;
            case 'f': o.force = 1; break;
            case 't': o.test = o.decode = 1; break;
            case 'n': o.name = 0; break;
            case 'N': o.name = 1; break;
            case 'q': o.quiet = 1; o.verbose = 0; break;
            case 'v': o.verbose = 1; o.quiet = 0; break;
            case 'l': o.list = o.decode = 1; break;
            case 'r': o.recursive = 1; break;
            case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': o.level = c - '0'; break;
            case 'S': o.suffix = g.optarg; break;
            case GZ_OPT_RSYNCABLE: o.rsyncable = 1; break;
            case BOS_OPT_HELP:
                puts("Usage: gzip [-cdfklnNqrtv1-9] [-S SUFFIX] [--rsyncable] [FILE...]\nCompress files to .gz, or filter stdin. -d decompresses, -c writes stdout,\n-k keeps input, -f overwrites, -t checks integrity, -n omits name/time,\n-N restores the stored name/time, -l lists sizes, -r recurses, -v reports ratios.\n--rsyncable makes rsync-friendly output.");
                bos_getopt_free(&g); goto done;
            case BOS_OPT_VERSION:
                puts("gzip (bash-os) 0.1.1"); bos_getopt_free(&g); goto done;
            default:
                fflush(stdout);
                fputs("Try `gzip --help' for more information.\n", stderr);
                bos_getopt_free(&g); rc = 1; goto done;
        }
    }
    for (int i = 0; i < g.noperands; i++) files[used++] = g.operands[i];
    bos_getopt_free(&g);
    if (!*o.suffix) { builtin_error("invalid suffix ''"); rc = 1; goto done; }
    if (!used) files[used++] = "-";
    for (size_t i = 0; i < used; i++) {
        int result = gzip_one(files[i], &o, &ls, 0);
        if (result == 1 || !rc) rc = result;
    }
    if (o.list && used > 1 && !o.quiet && !ls.first && ls.total_in > 0 && ls.total_out > 0) {
        if (o.verbose) fputs("                            ", stdout);
        printf("%19lld %19lld ", ls.total_in, ls.total_out);
        gzip_ratio(stdout, ls.total_out - (ls.total_in - ls.header_bytes), ls.total_out);
        puts(" (totals)");
    }
done:
    free(files);
    if (fflush(stdout) || ferror(stdout)) { clearerr(stdout); rc = 1; }
    return rc;
}

char *gzip_doc[] = {
    "Compress/decompress gzip files or stdin, including concatenated members.",
    "-c stdout, -d decompress, -k keep, -f force, -t test, -n no name/time,",
    "-N restore the stored name and time when decompressing (by default the",
    "suffix is removed and the compressed file's time is kept, as GNU gzip),",
    "-l list compressed/uncompressed sizes and ratio (-lv adds method, CRC, date),",
    "-r recurse into directories, -v report each file's ratio on stderr,",
    "-1..-9 compression level, -S suffix, -q quiet. Checks CRC and truncation.",
    "--rsyncable resets the compressor at content-defined points (rsync-friendly).",
    "Trailing garbage after the last member is ignored with GNU's warning",
    "\"decompression OK, trailing garbage ignored\" and exit status 2.", NULL
};
struct builtin gzip_struct = {
    "gzip", gzip_builtin, BUILTIN_ENABLED, gzip_doc, "gzip [-cdfklnNqrtv1-9] [-S SUFFIX] [--rsyncable] [FILE...]", 0
};
