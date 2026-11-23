/* SPDX-License-Identifier: MIT */
/* split.c — POSIX split(1) as a bash builtin.
 *
 *   split [-l N | -b SIZE | -C SIZE | -n CHUNKS] [-a SUFLEN] [-d | -x]
 *         [--additional-suffix=SUFFIX] [--filter=COMMAND] [INPUT [PREFIX]]
 *
 * Splits INPUT (or stdin) into pieces named PREFIX{aa,ab,ac,...}.
 * Default: -l 1000 lines per piece, -a 2 (suffix length), PREFIX=x.
 * -d / --numeric-suffixes[=FROM] and -x / --hex-suffixes[=FROM] use
 * decimal or hexadecimal suffixes; --additional-suffix appends a fixed
 * string (no '/') after the generated suffix, as GNU split does.
 *
 * --filter=COMMAND writes each piece to the standard input of
 * "$SHELL -c COMMAND" (/bin/sh without SHELL) with FILE set to the piece's
 * name, instead of creating the file. As in GNU split, a filter that stops
 * reading is not an error (SIGPIPE is blocked and EPIPE ignored), and one
 * that fails ends split at once with its exit status, or 128+N for signal
 * N other than SIGPIPE: "with FILE=xaa, exit 1 from command: false".
 *
 * SIZE accepts GNU byte units: b (512), K..Q (powers of 1024),
 * KB..QB (powers of 1000), and KiB..QiB (powers of 1024).
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
#include <ctype.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#include "loadables.h"
#include "command-run.h"
#include "gnu-quote.h"
#include "longopt-normalize.h"

static long long
bs_parse_count (const char *s)
{
    char *end;
    errno = 0;
    long long n = strtoll (s, &end, 10);
    if (errno == ERANGE || end == s || n <= 0) return -1;
    return *end == '\0' ? n : -1;
}

static int
bs_parse_size (const char *s, uintmax_t *size)
{
    const char *number = s;
    char *end;
    while (isspace ((unsigned char) *number)) number++;
    if (*number == '-') return -1;
    errno = 0;
    uintmax_t n = strtoumax (s, &end, 10);
    if (end == s) {
        /* A unit by itself means one; whitespace/signs still need digits. */
        if (!*s || !strchr ("bkmKMGTPEZYRQ", *s)) return -1;
        n = 1;
    } else if (errno && errno != ERANGE) {
        return -1;
    }
    if (!n) return -1;

    unsigned int power = 0;
    uintmax_t base = 1024;
    if (*end == 'b' && end[1] == '\0') {
        base = 512;
        power = 1;
    } else if (*end) {
        const char *units = "KMGTPEZYRQ";
        int unit = *end == 'k' ? 'K' : *end == 'm' ? 'M' : *end;
        const char *position = strchr (units, unit);
        if (!position) return -1;
        power = (unsigned int) (position - units) + 1;
        end++;
        if (!strcmp (end, "B")) base = 1000;
        else if (*end && strcmp (end, "iB")) return -1;
    }
    /* GNU accepts overflowing sizes as an unbounded chunk. Saturation keeps
       the streaming counters unsigned and never wraps a large size to zero. */
    while (power--) n = n > UINTMAX_MAX / base ? UINTMAX_MAX : n * base;
    *size = n;
    return 0;
}

/* --additional-suffix for the current invocation ("" when unset). */
static const char *bs_extra_suffix = "";
/* -t SEP record separator, -e (--elide-empty-files) and --verbose. */
static int bs_sep = '\n';
static int bs_elide;
static int bs_verbose;

/* Compose PREFIX + a fixed-width suffix from `index` + the additional
   suffix. NUMERIC is 0 for lowercase letters, or the digit base (10 or
   16). Returns -1 if index exceeds capacity. */
static int
bs_make_name (char *out, size_t cap, const char *prefix, int suflen, long index,
              int numeric)
{
    static const char digits[] = "0123456789abcdef";
    size_t plen = strlen (prefix), xlen = strlen (bs_extra_suffix);
    if (plen + (size_t) suflen + xlen + 1 > cap) return -1;
    memcpy (out, prefix, plen);
    long max = 1;
    int base = numeric ? numeric : 26;
    for (int i = 0; i < suflen; i++) max *= base;
    if (index >= max) return -1;
    for (int i = suflen - 1; i >= 0; i--) {
        out[plen + i] = numeric ? digits[index % base] : 'a' + (char) (index % base);
        index /= base;
    }
    memcpy (out + plen + suflen, bs_extra_suffix, xlen + 1);
    return 0;
}

/* stdin's FILE belongs to the persistent shell. A private stream so a later
   redirection is not stuck at EOF from this invocation. */
static FILE *
bs_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
    if (!in) {
        int error = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (error));
    }
    return in;
}

/* --filter=COMMAND state for the current invocation. Every running filter
   keeps its pipe stream and child here until bs_close_output reaps it. */
static const char *bs_filter;
static int bs_filter_status;            /* first failing filter's status */
static struct bs_child { FILE *fp; pid_t pid; } *bs_children;
static size_t bs_n_children, bs_cap_children;
static int bs_masked, bs_pipe_was_pending;
static sigset_t bs_oldmask;

/* GNU: a filter that exits early must not end split, so EPIPE is ignored. */
static int
bs_ignorable (void)
{
    return bs_filter && errno == EPIPE;
}

static FILE *
bs_filter_open (const char *name)
{
    if (!bs_masked) {
        /* Block SIGCHLD so Bash's reaper cannot take a filter's status, and
           SIGPIPE so a closed filter yields EPIPE instead of a signal. */
        sigset_t block, pending;
        sigemptyset (&block);
        sigaddset (&block, SIGCHLD);
        sigaddset (&block, SIGPIPE);
        sigpending (&pending);
        bs_pipe_was_pending = sigismember (&pending, SIGPIPE);
        if (sigprocmask (SIG_BLOCK, &block, &bs_oldmask) < 0) {
            builtin_error ("sigprocmask: %s", strerror (errno));
            return NULL;
        }
        bs_masked = 1;
    }
    if (bs_n_children == bs_cap_children) {
        size_t cap = bs_cap_children ? bs_cap_children * 2 : 4;
        struct bs_child *grown = realloc (bs_children, cap * sizeof *grown);
        if (!grown) { builtin_error ("out of memory"); return NULL; }
        bs_children = grown;
        bs_cap_children = cap;
    }
    const char *shell = getenv ("SHELL");
    if (!shell || !*shell) shell = "/bin/sh";
    int pfd[2];
    if (pipe2 (pfd, O_CLOEXEC) < 0) {
        builtin_error ("failed to create pipe: %s", strerror (errno));
        return NULL;
    }
    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) {
        builtin_error ("fork system call failed: %s", strerror (errno));
        close (pfd[0]); close (pfd[1]);
        return NULL;
    }
    if (pid == 0) {
        /* Bash's own setenv binds a shell variable, so the filter's
           environment is built here: the exports, then FILE=NAME. */
        size_t n_env = 0, k = 0;
        bos_prepare_child ();
        if (dup2 (pfd[0], STDIN_FILENO) < 0) _exit (127);
        while (export_env && export_env[n_env]) n_env++;
        char **env = malloc ((n_env + 2) * sizeof *env);
        char *file_entry = malloc (strlen (name) + 6);
        if (!env || !file_entry) _exit (127);
        for (size_t i = 0; i < n_env; i++)
            if (strncmp (export_env[i], "FILE=", 5))
                env[k++] = export_env[i];
        sprintf (file_entry, "FILE=%s", name);
        env[k++] = file_entry;
        env[k] = NULL;
        sigprocmask (SIG_SETMASK, &bs_oldmask, NULL);
        char *argv[] = { (char *) shell, (char *) "-c", (char *) bs_filter, NULL };
        execve (shell, argv, env);
        fprintf (stderr, "split: failed to run command: \"%s -c %s\": %s\n",
                 shell, bs_filter, strerror (errno));
        _exit (127);
    }
    close (pfd[0]);
    FILE *out = fdopen (pfd[1], "w");
    if (!out) {
        builtin_error ("open pipe: %s", strerror (errno));
        close (pfd[1]);
        int status;
        while (waitpid (pid, &status, 0) < 0 && errno == EINTR) { }
        return NULL;
    }
    bs_children[bs_n_children].fp = out;
    bs_children[bs_n_children].pid = pid;
    bs_n_children++;
    return out;
}

/* Close a filter's pipe and wait for it; report a failure as GNU does. */
static int
bs_filter_close (FILE *out, const char *name)
{
    pid_t pid = -1;
    for (size_t i = 0; i < bs_n_children; i++)
        if (bs_children[i].fp == out) {
            pid = bs_children[i].pid;
            bs_children[i] = bs_children[--bs_n_children];
            break;
        }
    int rc = 0;
    if (fclose (out) == EOF && !bs_ignorable ()) {
        builtin_error ("write %s: %s", name, strerror (errno ? errno : EIO));
        rc = -1;
    }
    int status;
    if (pid < 0) return rc;
    while (waitpid (pid, &status, 0) < 0)
        if (errno != EINTR) {
            builtin_error ("waiting for child process: %s", strerror (errno));
            return -1;
        }
    int failed = 0;
    if (WIFSIGNALED (status) && WTERMSIG (status) != SIGPIPE) {
        const char *sig = signal_name (WTERMSIG (status));
        if (sig && !strncmp (sig, "SIG", 3)) sig += 3;
        builtin_error ("with FILE=%s, signal %s from command: %s", name,
                       sig ? sig : "?", bs_filter);
        failed = 128 + WTERMSIG (status);
    } else if (WIFEXITED (status) && WEXITSTATUS (status) != 0) {
        builtin_error ("with FILE=%s, exit %d from command: %s", name,
                       WEXITSTATUS (status), bs_filter);
        failed = WEXITSTATUS (status);
    }
    if (failed) {
        if (!bs_filter_status) bs_filter_status = failed;
        rc = -1;
    }
    return rc;
}

/* End of the invocation, including an interrupt: reap every filter still
   running, drop a SIGPIPE this call caused, and restore the signal mask. */
static void
bs_filter_cleanup (void *unused)
{
    (void) unused;
    while (bs_n_children > 0) {
        struct bs_child c = bs_children[--bs_n_children];
        int status;
        fclose (c.fp);
        while (waitpid (c.pid, &status, 0) < 0 && errno == EINTR) { }
    }
    free (bs_children);
    bs_children = NULL;
    bs_cap_children = 0;
    if (bs_masked) {
        sigset_t pending, pipe_only;
        sigemptyset (&pipe_only);
        sigaddset (&pipe_only, SIGPIPE);
        struct timespec zero = { 0, 0 };
        if (!bs_pipe_was_pending && sigpending (&pending) == 0 &&
            sigismember (&pending, SIGPIPE))
            sigtimedwait (&pipe_only, NULL, &zero);
        sigprocmask (SIG_SETMASK, &bs_oldmask, NULL);
        bs_masked = 0;
    }
    bs_filter = NULL;
}

/* Open without truncation until we know this is not the input, including
   a hard link or a symlink to it. fdopen("w") does not truncate the fd.
   With --filter the piece goes to a new filter process instead. */
static FILE *
bs_open_output (const char *name, const struct stat *input)
{
    if (bs_verbose) {
        /* GNU: quotef for the filter's FILE=, quoteaf for a created file. */
        int plain = name[0] && strspn (name, "abcdefghijklmnopqrstuvwxyz"
                                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+-,:@%^")
                                == strlen (name);
        char *q = bs_filter && plain ? NULL : bos_quoteaf (name);
        if (bs_filter)
            printf ("executing with FILE=%s\n", q ? q : name);
        else
            printf ("creating file %s\n", q ? q : name);
        free (q);
        fflush (stdout);
    }
    if (bs_filter)
        return bs_filter_open (name);
    int fd = open (name, O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        builtin_error ("create %s: %s", name, strerror (errno));
        return NULL;
    }
    struct stat output;
    if (fstat (fd, &output) < 0) {
        builtin_error ("stat %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    if (output.st_dev == input->st_dev && output.st_ino == input->st_ino) {
        builtin_error ("%s would overwrite the input", name);
        close (fd);
        return NULL;
    }
    if (S_ISREG (output.st_mode) && ftruncate (fd, 0) < 0) {
        builtin_error ("truncate %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    FILE *out = fdopen (fd, "w");
    if (!out) {
        builtin_error ("open %s: %s", name, strerror (errno));
        close (fd);
    }
    return out;
}

static int
bs_close_output (FILE *out, const char *name)
{
    if (bs_filter)
        return bs_filter_close (out, name);
    if (fclose (out) == EOF) {
        builtin_error ("write %s: %s", name, strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

/* Whole input in memory: -n needs the total size before writing. */
static unsigned char *
bs_slurp (FILE *in, size_t *size)
{
    size_t cap = 65536, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { builtin_error ("out of memory"); return NULL; }
    for (;;) {
        if (len == cap) {
            unsigned char *grown = cap > SIZE_MAX / 2 ? NULL : realloc (buf, cap * 2);
            if (!grown) { free (buf); builtin_error ("out of memory"); return NULL; }
            buf = grown;
            cap *= 2;
        }
        size_t r = fread (buf + len, 1, cap - len, in);
        len += r;
        if (r == 0) break;
    }
    *size = len;
    return buf;
}

/* Write one -n piece. Index IDX names the file; with K set, only piece K
   goes to standard output and nothing is created. */
static int
bs_put_piece (const unsigned char *data, size_t n, int to_stdout,
              char *namebuf, size_t namecap, const char *prefix, int suflen,
              long idx, int numeric, const struct stat *input_stat, FILE **open_out,
              int append)
{
    if (to_stdout) {
        if (n && fwrite (data, 1, n, stdout) != n) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            return -1;
        }
        return 0;
    }
    if (!append || !*open_out) {
        if (*open_out && bs_close_output (*open_out, namebuf) < 0) { *open_out = NULL; return -1; }
        *open_out = NULL;
        /* -e: an empty piece is not created; a later append opens it. */
        if (bs_elide && n == 0)
            return 0;
        if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
            builtin_error ("split: suffix exhausted (try larger -a)");
            return -1;
        }
        *open_out = bs_open_output (namebuf, input_stat);
        if (!*open_out) return -1;
    }
    if (n && fwrite (data, 1, n, *open_out) != n && !bs_ignorable ()) {
        builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

/* GNU split -n CHUNKS: N, K/N, l/N, l/K/N, r/N, r/K/N. */
static int
bs_split_chunks (FILE *fin, int mode, uintmax_t k, uintmax_t n, char *namebuf,
                 size_t namecap, const char *prefix, int suflen, long start,
                 int numeric, const struct stat *input_stat)
{
    size_t size;
    unsigned char *data = bs_slurp (fin, &size);
    if (!data) return -1;
    if (ferror (fin)) { free (data); return 0; }   /* reported by the caller */
    FILE *out = NULL;
    int rc = 0;
    if (mode == 'b') {
        uintmax_t base = size / n, rem = size % n;
        for (uintmax_t c = 1; c <= n && rc == 0; c++) {
            uintmax_t from = (c - 1) * base + (c - 1 < rem ? c - 1 : rem);
            uintmax_t to = c * base + (c < rem ? c : rem);
            if (k && c != k) continue;
            rc = bs_put_piece (data + from, (size_t) (to - from), k != 0, namebuf, namecap,
                               prefix, suflen, start + (long) (c - 1), numeric,
                               input_stat, &out, 0);
        }
    } else if (mode == 'l') {
        /* GNU's lines_chunk_split: piece C ends at the first newline at or
           after its byte boundary (the boundaries of plain -n N), so a long
           line can leave later pieces empty; the last piece takes the rest. */
        uintmax_t base = size / n, rem = size % n, chunk_no = 1;
        uintmax_t chunk_end = base + (rem ? 1 : 0);   /* one past the boundary byte */
        size_t pos = 0;
        if (!k) rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                                   start, numeric, input_stat, &out, 0);
        while (rc == 0 && pos < size) {
            size_t look = chunk_end > pos + 1 ? (size_t) chunk_end - 1 : pos;
            if (chunk_no == n) look = size;
            const unsigned char *nl = look < size ? memchr (data + look, bs_sep, size - look) : NULL;
            size_t stop = nl ? (size_t) (nl - data) + 1 : size;
            if (!k || k == chunk_no)
                rc = bs_put_piece (data + pos, stop - pos, k != 0, namebuf, namecap, prefix,
                                   suflen, start + (long) (chunk_no - 1), numeric,
                                   input_stat, &out, 1);
            pos = stop;
            if (rc || pos >= size) break;
            /* Advance to the piece the next line starts in, creating any
               piece a long line skipped over. */
            do {
                chunk_no++;
                if (k && chunk_no > k) goto done;
                chunk_end = chunk_no == n ? size
                    : chunk_no * base + (chunk_no < rem ? chunk_no : rem);
                if (!k)
                    rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                                       start + (long) (chunk_no - 1), numeric,
                                       input_stat, &out, 0);
            } while (rc == 0 && chunk_end <= pos && chunk_no < n);
        }
        while (rc == 0 && !k && chunk_no < n) {
            chunk_no++;
            rc = bs_put_piece (data, 0, 0, namebuf, namecap, prefix, suflen,
                               start + (long) (chunk_no - 1), numeric, input_stat, &out, 0);
        }
    } else {
        /* Round robin: line I goes to piece I mod N. All N files exist. */
        FILE **outs = NULL;
        char **names = NULL;
        if (!k) {
            outs = calloc ((size_t) n, sizeof *outs);
            names = calloc ((size_t) n, sizeof *names);
            if (!outs || !names) { builtin_error ("out of memory"); rc = -1; }
            for (uintmax_t c = 0; rc == 0 && c < n; c++) {
                names[c] = malloc (namecap);
                if (!names[c]) { builtin_error ("out of memory"); rc = -1; break; }
                if (bs_make_name (names[c], namecap, prefix, suflen, start + (long) c, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = -1;
                    break;
                }
                if (bs_elide) continue;   /* opened on its first line */
                outs[c] = bs_open_output (names[c], input_stat);
                if (!outs[c]) rc = -1;
            }
        }
        size_t pos = 0;
        uintmax_t line = 0;
        while (rc == 0 && pos < size) {
            const unsigned char *nl = memchr (data + pos, bs_sep, size - pos);
            size_t stop = nl ? (size_t) (nl - data) + 1 : size;
            uintmax_t c = line++ % n;
            if (!k && !outs[c]) {
                outs[c] = bs_open_output (names[c], input_stat);
                if (!outs[c]) { rc = -1; break; }
            }
            FILE *dst = k ? (c + 1 == k ? stdout : NULL) : outs[c];
            if (dst && fwrite (data + pos, 1, stop - pos, dst) != stop - pos &&
                !bs_ignorable ()) {
                builtin_error ("write %s: %s", k ? "error" : names[c], strerror (errno ? errno : EIO));
                rc = -1;
            }
            pos = stop;
        }
        for (uintmax_t c = 0; outs && c < n; c++)
            if (outs[c] && bs_close_output (outs[c], names[c]) < 0) rc = -1;
        for (uintmax_t c = 0; names && c < n; c++) free (names[c]);
        free (outs);
        free (names);
    }
done:
    if (out && bs_close_output (out, namebuf) < 0) rc = -1;
    if (k && fflush (stdout) == EOF) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        rc = -1;
    }
    free (data);
    return rc;
}

/* Parse -n CHUNKS. Returns 0 and the mode ('b', 'l' or 'r'), K and N. */
static int
bs_parse_chunks (const char *v, int *mode, uintmax_t *k, uintmax_t *n)
{
    *mode = 'b';
    *k = 0;
    if ((v[0] == 'l' || v[0] == 'r') && v[1] == '/') { *mode = v[0]; v += 2; }
    const char *slash = strchr (v, '/');
    char *end;
    if (slash) {
        if (*v < '0' || *v > '9') return -1;
        errno = 0;
        *k = strtoumax (v, &end, 10);
        if (errno || end != slash) return -1;
        if (*k == 0) return -2;
        v = slash + 1;
    }
    if (*v < '0' || *v > '9') return -1;
    errno = 0;
    *n = strtoumax (v, &end, 10);
    if (errno || *end || *n == 0 || *n > 100000000) return -1;
    if (*k > *n) return -2;
    return 0;
}

static int bs_split (WORD_LIST *list);

int
split_builtin (WORD_LIST *list)
{
    /* GNU split's long options, with abbreviations and permuted operands. */
    static const struct lon_option longopts[] = {
        { "bytes",              LON_REQUIRED, "-b" },
        { "lines",              LON_REQUIRED, "-l" },
        { "line-bytes",         LON_REQUIRED, "-C" },
        { "number",             LON_REQUIRED, "-n" },
        { "elide-empty-files",  LON_NONE,     "-e" },
        { "unbuffered",         LON_NONE,     "-u" },
        { "suffix-length",      LON_REQUIRED, "-a" },
        { "additional-suffix",  LON_REQUIRED, NULL },
        { "filter",             LON_REQUIRED, NULL },
        { "numeric-suffixes",   LON_OPTIONAL, NULL },
        { "hex-suffixes",       LON_OPTIONAL, NULL },
        { "separator",          LON_REQUIRED, "-t" },
        { "verbose",            LON_NONE,     NULL },
        { "help",               LON_NONE,     NULL },
        { NULL, 0, NULL }
    };
    WORD_LIST *args;
    if (lon_normalize (list, longopts, "0123456789C:a:b:del:n:t:ux", 1, &args) < 0)
        return EXECUTION_FAILURE;
    bs_filter = NULL;
    bs_filter_status = 0;
    begin_unwind_frame ("bashsplit-filter");
    add_unwind_protect (bs_filter_cleanup, NULL);
    int rc = bs_split (args);
    run_unwind_frame ("bashsplit-filter");
    if (args) dispose_words (args);
    /* GNU split exits with a failing filter's own status. */
    if (rc != EXECUTION_SUCCESS && bs_filter_status)
        rc = bs_filter_status;
    return rc;
}

static int
bs_split (WORD_LIST *list)
{
    long line_chunk = 1000;     /* -l N default */
    uintmax_t byte_chunk = 0;   /* -b SIZE; 0 = use lines */
    int suflen = 2;             /* -a */
    int numeric = 0;
    long start = 0;
    const char *prefix = "x";
    const char *input = NULL;
    const char *chunks = NULL;

    bs_extra_suffix = "";
    bs_sep = '\n';
    bs_elide = 0;
    bs_verbose = 0;
    int have_sep = 0;
    uintmax_t line_bytes = 0;   /* -C SIZE; 0 = off */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_help (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--verbose")) { bs_verbose = 1; list = list->next; continue; }
        if (!strcmp (w, "--numeric-suffixes")) {
            numeric = 10;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--hex-suffixes")) {
            numeric = 16;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--numeric-suffixes=", 19) || !strncmp (w, "--hex-suffixes=", 15)) {
            int base = w[2] == 'n' ? 10 : 16;
            const char *from = w + (base == 10 ? 19 : 15), *p = from;
            long value = 0;
            /* GNU treats an explicitly empty starting value as zero. */
            for (; *p; p++) {
                int d = isdigit ((unsigned char) *p) ? *p - '0'
                    : base == 16 && isxdigit ((unsigned char) *p) ? tolower ((unsigned char) *p) - 'a' + 10
                    : -1;
                if (d < 0 || value > (LONG_MAX - d) / base)
                    goto invalid_start;
                value = value * base + d;
            }
            numeric = base;
            start = value;
            list = list->next;
            continue;
invalid_start:
            builtin_error ("invalid start value for numerical suffix: %s", from);
            return EXECUTION_FAILURE;
        }
        if (!strncmp (w, "--additional-suffix=", 20)) {
            const char *v = w + 20;
            if (strchr (v, '/')) {
                builtin_error ("invalid suffix '%s', contains directory separator", v);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            bs_extra_suffix = v;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--filter=", 9)) {
            bs_filter = w + 9;
            list = list->next;
            continue;
        }
        /* Obsolete -N: N lines per piece. */
        if (w[1] >= '0' && w[1] <= '9' && strspn (w + 1, "0123456789") == strlen (w + 1)) {
            long long value = bs_parse_count (w + 1);
            if (value <= 0 || value > LONG_MAX) {
                builtin_error ("invalid number of lines: '%s'", w + 1);
                return EXECUTION_FAILURE;
            }
            line_chunk = (long) value;
            byte_chunk = 0;
            line_bytes = 0;
            list = list->next;
            continue;
        }
        /* A cluster of short options; one that takes a value ends it. */
        int next_word = 0;
        for (const char *c = w + 1; *c; c++) {
            if (*c == 'd') { numeric = 10; continue; }
            if (*c == 'x') { numeric = 16; continue; }
            if (*c == 'e') { bs_elide = 1; continue; }
            if (*c == 'u') { continue; }   /* unbuffered: output is unchanged */
            if (!strchr ("lbCnat", *c)) {
                builtin_error ("invalid option -- '%c'", *c);
                lon_try_help ();
                return EXECUTION_FAILURE;
            }
            char opt = *c;
            const char *v = c[1] ? c + 1 : NULL;
            if (!v) {
                if (!list->next) {
                    builtin_error ("option requires an argument -- '%c'", opt);
                    lon_try_help ();
                    return EXECUTION_FAILURE;
                }
                v = list->next->word->word;
                next_word = 1;
            }
            if (opt == 'l') {
                long long value = bs_parse_count (v);
                if (value <= 0 || value > LONG_MAX) {
                    builtin_error ("-l: invalid line count: %s", v);
                    builtin_usage ();
                    return EXECUTION_FAILURE;
                }
                line_chunk = (long) value;
                byte_chunk = 0;
                line_bytes = 0;
            } else if (opt == 'b') {
                if (bs_parse_size (v, &byte_chunk) < 0) { builtin_error ("-b: bad SIZE: %s", v); builtin_usage (); return EXECUTION_FAILURE; }
                line_bytes = 0;
            } else if (opt == 'C') {
                if (bs_parse_size (v, &line_bytes) < 0) {
                    builtin_error ("invalid number of bytes: '%s'", v);
                    return EXECUTION_FAILURE;
                }
                byte_chunk = 0;
            } else if (opt == 'n') {
                chunks = v;
            } else if (opt == 'a') {
                long long value = bs_parse_count (v);
                if (value < 1 || value > 6) { builtin_error ("-a: SUFLEN must be in 1..6"); builtin_usage (); return EXECUTION_FAILURE; }
                suflen = (int) value;
            } else {   /* -t SEP */
                int sep;
                if (!strcmp (v, "\\0"))
                    sep = '\0';
                else if (!v[0]) {
                    builtin_error ("empty record separator");
                    return EXECUTION_FAILURE;
                } else if (v[1]) {
                    char *q = bos_quote (v);
                    builtin_error ("multi-character separator %s", q ? q : v);
                    free (q);
                    return EXECUTION_FAILURE;
                } else
                    sep = (unsigned char) v[0];
                if (have_sep && sep != bs_sep) {
                    builtin_error ("multiple separator characters specified");
                    return EXECUTION_FAILURE;
                }
                have_sep = 1;
                bs_sep = sep;
            }
            break;
        }
        list = list->next;
        if (next_word) list = list->next;
    }
    if (list) { input = list->word->word; list = list->next; }
    if (list) { prefix = list->word->word; list = list->next; }
    if (list) {
        char *q = bos_quote (list->word->word);
        builtin_error ("extra operand %s", q ? q : list->word->word);
        free (q);
        lon_try_help ();
        return EXECUTION_FAILURE;
    }

    if (numeric) {
        long capacity = 1;
        for (int i = 0; i < suflen; i++) capacity *= numeric;
        if (start >= capacity) {
            builtin_error ("numerical suffix start value is too large for the suffix length");
            return EXECUTION_FAILURE;
        }
    }

    int from_stdin = !input || !strcmp (input, "-");
    FILE *fin = from_stdin ? bs_open_stdin () : fopen (input, "r");
    if (!fin) {
        if (!from_stdin) {
            /* GNU: split: cannot open 'NAME' for reading: REASON */
            int error = errno;
            char *q = bos_quoteaf (input);
            builtin_error ("cannot open %s for reading: %s", q ? q : input, strerror (error));
            free (q);
        }
        return EXECUTION_FAILURE;
    }

    struct stat input_stat;
    if (fstat (fileno (fin), &input_stat) < 0) {
        builtin_error ("stat input: %s", strerror (errno));
        fclose (fin);
        return EXECUTION_FAILURE;
    }
    size_t namecap = strlen (prefix) + (size_t) suflen + strlen (bs_extra_suffix) + 1;
    char *namebuf = malloc (namecap);
    if (!namebuf) {
        builtin_error ("out of memory");
        fclose (fin);
        return EXECUTION_FAILURE;
    }
    long idx = start;
    int rc = EXECUTION_SUCCESS;

    if (chunks) {
        int mode;
        uintmax_t k, n;
        int bad = bs_parse_chunks (chunks, &mode, &k, &n);
        if (bad == -2) {
            builtin_error ("invalid chunk number: '%ju'", k);
            rc = EXECUTION_FAILURE;
        } else if (bad == 0 && k && bs_filter) {
            builtin_error ("--filter does not process a chunk extracted to stdout");
            builtin_usage ();
            rc = EXECUTION_FAILURE;
        } else if (bad < 0) {
            const char *num = chunks;
            if ((num[0] == 'l' || num[0] == 'r') && num[1] == '/') num += 2;
            const char *slash = strrchr (num, '/');
            builtin_error ("invalid number of chunks: '%s'", slash ? slash + 1 : num);
            rc = EXECUTION_FAILURE;
        } else if (bs_split_chunks (fin, mode, k, n, namebuf, namecap, prefix, suflen,
                                    start, numeric, &input_stat) < 0)
            rc = EXECUTION_FAILURE;
    } else if (byte_chunk > 0) {
        /* Byte-based splitting. */
        unsigned char buf[8192];
        uintmax_t left_in_chunk = 0;
        FILE *fout = NULL;
        for (;;) {
            /* Read BEFORE opening the next output file. GNU split never
               creates an empty trailing piece: a file is opened only once we
               have a byte to put in it, so an empty input (or an input whose
               size is an exact multiple of the chunk) produces no spurious
               zero-length file. */
            uintmax_t cap_chunk = (left_in_chunk > 0) ? left_in_chunk : byte_chunk;
            size_t want = sizeof buf > cap_chunk ? (size_t) cap_chunk : sizeof buf;
            size_t r = fread (buf, 1, want, fin);
            if (r == 0) break;
            if (fout == NULL) {
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
                    rc = EXECUTION_FAILURE;
                    break;
                }
                left_in_chunk = byte_chunk;
            }
            if (fwrite (buf, 1, r, fout) != r && !bs_ignorable ()) {
                builtin_error ("write %s: %s", namebuf, strerror (errno));
                rc = EXECUTION_FAILURE;
                break;
            }
            left_in_chunk -= r;
            if (left_in_chunk == 0) {
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
    } else if (line_bytes > 0) {
        /* -C SIZE: whole records while they fit in SIZE bytes; a record
           longer than SIZE fills pieces of SIZE bytes and its remainder
           starts the next piece, as GNU split does. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        uintmax_t used = 0;
        FILE *fout = NULL;
        while (rc == EXECUTION_SUCCESS && (n = getdelim (&line, &cap, bs_sep, fin)) != -1) {
            const char *rp = line;
            uintmax_t left = (uintmax_t) n;
            /* GNU sizes a final unterminated record as if it had its
               separator: one that would exactly fill the piece moves on. */
            uintmax_t pad = line[n - 1] != bs_sep;
            while (left > 0) {
                if (fout && used + left + (rp == line ? pad : 0) > line_bytes) {
                    int failed = bs_close_output (fout, namebuf);
                    fout = NULL;
                    used = 0;
                    idx++;
                    if (failed) { rc = EXECUTION_FAILURE; break; }
                }
                if (!fout) {
                    if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
                        builtin_error ("split: suffix exhausted (try larger -a)");
                        rc = EXECUTION_FAILURE;
                        break;
                    }
                    fout = bs_open_output (namebuf, &input_stat);
                    if (!fout) { rc = EXECUTION_FAILURE; break; }
                }
                size_t take = left > line_bytes - used ? (size_t) (line_bytes - used) : (size_t) left;
                if (fwrite (rp, 1, take, fout) != take && !bs_ignorable ()) {
                    builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
                    rc = EXECUTION_FAILURE;
                    break;
                }
                rp += take;
                left -= take;
                used += take;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
        free (line);
    } else {
        /* Line-based splitting. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        long lines_in_chunk = 0;
        FILE *fout = NULL;
        while ((n = getdelim (&line, &cap, bs_sep, fin)) != -1) {
            if (lines_in_chunk == 0) {
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx, numeric) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
                    rc = EXECUTION_FAILURE;
                    break;
                }
            }
            if (fwrite (line, 1, (size_t) n, fout) != (size_t) n && !bs_ignorable ()) {
                builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
                rc = EXECUTION_FAILURE;
                break;
            }
            lines_in_chunk++;
            if (lines_in_chunk >= line_chunk) {
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                lines_in_chunk = 0;
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
        free (line);
    }

    if (ferror (fin)) {
        /* GNU names the input ("-" for standard input): split: DIR: Is a directory */
        int error = errno ? errno : EIO;
        const char *name = from_stdin ? "-" : input;
        int plain = name[0] && strspn (name, "abcdefghijklmnopqrstuvwxyz"
                                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+-,@%^")
                                == strlen (name);
        char *q = plain ? NULL : bos_quoteaf (name);
        builtin_error ("%s: %s", q ? q : name, strerror (error));
        free (q);
        rc = EXECUTION_FAILURE;
    }
    if (fclose (fin) == EOF) {
        builtin_error ("close input: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    free (namebuf);
    return rc;
}

char *split_doc[] = {
    "Split a file into pieces (POSIX split).",
    "",
    "    split [-l N | -b SIZE | -C SIZE | -n CHUNKS] [-a SUFLEN] [-d | -x]",
    "          [-e] [-t SEP] [-u] [--verbose] [--additional-suffix=SUFFIX]",
    "          [--filter=COMMAND] [INPUT [PREFIX]]",
    "",
    "    -l N, --lines=N  N lines per piece (default 1000); -N is the same",
    "    -b SIZE, --bytes=SIZE  SIZE bytes per piece; b=512, K=1024, KB=1000, KiB=1024",
    "                Units K, M, G, T, P, E, Z, Y, R, Q; k/m also accepted",
    "    -C SIZE, --line-bytes=SIZE  at most SIZE bytes of whole records per",
    "                piece; a longer record is cut into SIZE-byte pieces",
    "    -n CHUNKS, --number=CHUNKS  N, K/N, l/N, l/K/N, r/N or r/K/N pieces,",
    "                as GNU split; with K, piece K goes to standard output",
    "    -e, --elide-empty-files  do not create empty pieces with -n",
    "    -t SEP, --separator=SEP  record separator for -l, -C and -n l/ r/",
    "                (one byte; '\\0' is NUL)",
    "    -u, --unbuffered  accepted; output is the same",
    "    --verbose   print \"creating file 'NAME'\" before each piece",
    "    -a SUFLEN, --suffix-length=SUFLEN  suffix length (default 2)",
    "    -d, --numeric-suffixes[=FROM]  decimal suffixes (from FROM, default 0)",
    "    -x, --hex-suffixes[=FROM]      hexadecimal suffixes (FROM in hex)",
    "    --additional-suffix=SUFFIX     append SUFFIX (no '/') to every name",
    "    --filter=COMMAND  write each piece to \"$SHELL -c COMMAND\" (default",
    "                /bin/sh) with FILE set to its name; no file is created",
    "",
    "Long options take any unambiguous prefix, as --opt=VALUE or --opt VALUE.",
    "INPUT defaults to stdin (or `-`). Output files are named",
    "PREFIXaa, PREFIXab, ... where PREFIX defaults to `x`.",
    (char *)NULL
};

struct builtin split_struct = {
    "split",
    split_builtin,
    BUILTIN_ENABLED,
    split_doc,
    "split [-l N | -b SIZE | -C SIZE | -n CHUNKS] [-a SUFLEN] [-d|-x] [-e] [-t SEP] [-u] [--verbose] [--additional-suffix=S] [--filter=COMMAND] [INPUT [PREFIX]]",
    0
};
