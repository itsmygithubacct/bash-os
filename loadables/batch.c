/* SPDX-License-Identifier: MIT */
/* batch.c - small batch(1)-shaped wrapper for bash-os.
 *
 * batch reads a script from stdin and queues it for immediate execution
 * by cron. bash-os does not yet track system load, so "low load" is
 * interpreted as now.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>

#include "loadables.h"

static const char *
bb_spool_root (void)
{
    const char *s = getenv ("BASHCRON_SPOOL_DIR");
    return (s && *s) ? s : "/var/spool/cron";
}

static int
bb_mkdir_p (const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen (path);
    if (len == 0 || len >= sizeof tmp)
        return -1;
    memcpy (tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int
bb_read_stdin (char **out, size_t *outlen)
{
    clearerr (stdin);
    size_t cap = 4096, len = 0;
    char *buf = malloc (cap);
    if (!buf)
        return -1;
    for (;;) {
        if (len + 2048 + 1 > cap) {
            cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) {
                free (buf);
                return -1;
            }
            buf = nb;
        }
        size_t n = fread (buf + len, 1, 2048, stdin);
        len += n;
        if (n < 2048) {
            if (ferror (stdin)) {
                free (buf);
                return -1;
            }
            break;
        }
    }
    buf[len] = '\0';
    *out = buf;
    *outlen = len;
    return 0;
}

int
batch_builtin (WORD_LIST *list)
{
    if (list) {
        builtin_error ("batch takes no arguments");
        return EX_USAGE;
    }

    char *script = NULL;
    size_t len = 0;
    if (bb_read_stdin (&script, &len) < 0) {
        builtin_error ("read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    char dir[PATH_MAX], path[PATH_MAX], jobid[128];
    if (snprintf (dir, sizeof dir, "%s/atjobs", bb_spool_root ()) >= (int) sizeof dir ||
        bb_mkdir_p (dir) < 0) {
        free (script);
        builtin_error ("mkdir atjobs: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    /* One stable locked append-only journal per wall-clock second.  A clock
       rollback can revisit an older second, so a single current-second
       counter is insufficient.  A short trailing record was never published
       and may be discarded after an interrupted writer. */
    char counter[32], tmp[PATH_MAX], state[8];
    int rootfd = -1, dirfd = -1, lockfd = -1, fd = -1;
    FILE *f = NULL;
    time_t run_at = time (NULL);
    unsigned long seq;
    struct stat st;
    ssize_t n;
    int saved;
    if (run_at == (time_t) -1) goto fail;
    if (snprintf (counter, sizeof counter, "%lld", (long long) run_at) >= (int) sizeof counter) {
        errno = ENAMETOOLONG;
        goto fail;
    }
    rootfd = open (bb_spool_root (), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) goto fail;
    if (mkdirat (rootfd, ".batch-sequence.d", 0700) < 0 && errno != EEXIST) goto fail;
    dirfd = openat (rootfd, ".batch-sequence.d", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) goto fail;
    /* Preserve the directory entry before reserving and publishing a job. */
    if (fsync (rootfd) < 0) goto fail;
    close (rootfd); rootfd = -1;
    lockfd = openat (dirfd, counter, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || flock (lockfd, LOCK_EX) < 0) goto fail;
    if (fstat (lockfd, &st) < 0) goto fail;
    if (!S_ISREG (st.st_mode) || st.st_size < 0 || st.st_size > 7000006) {
        errno = EINVAL;
        goto fail;
    }
    off_t complete = st.st_size - st.st_size % 7;
    if (complete != st.st_size && ftruncate (lockfd, complete) < 0) goto fail;
    seq = (unsigned long) (complete / 7);
    if (seq) {
        char expected[8];
        n = pread (lockfd, state, 7, complete - 7);
        snprintf (expected, sizeof expected, "%06lu\n", seq - 1);
        if (n != 7 || memcmp (state, expected, 7)) { errno = EINVAL; goto fail; }
    }
    if (seq >= 1000000UL) { errno = EOVERFLOW; goto fail; }
    snprintf (state, sizeof state, "%06lu\n", seq);
    n = pwrite (lockfd, state, 7, complete);
    if (n != 7) {
        saved = n < 0 ? errno : EIO;
        (void) ftruncate (lockfd, complete);
        errno = saved;
        goto fail;
    }
    /* Reserve the sequence before publishing the job, including when the
       process dies between these two steps. */
    if (fsync (lockfd) < 0 || fsync (dirfd) < 0) goto fail;
    close (dirfd); dirfd = -1;
    snprintf (jobid, sizeof jobid, "%lld.%ld.%06lu", (long long) run_at, (long) getpid (), seq);
    if (snprintf (path, sizeof path, "%s/%s.job", dir, jobid) >= (int) sizeof path ||
        snprintf (tmp, sizeof tmp, "%s/.batch.XXXXXX", dir) >= (int) sizeof tmp) {
        errno = ENAMETOOLONG;
        goto fail;
    }
    fd = mkstemp (tmp);
    if (fd < 0) goto fail;
    f = fdopen (fd, "w");
    if (!f) { saved = errno; close (fd); unlink (tmp); errno = saved; goto fail; }
    int bad = fprintf (f, "# run_at=%lld\n", (long long) run_at) < 0;
    if (len && fwrite (script, 1, len, f) != len) bad = 1;
    if (len == 0 || script[len - 1] != '\n')
        if (fputc ('\n', f) == EOF) bad = 1;
    if (fclose (f) != 0) bad = 1;
    if (bad) { saved = errno; unlink (tmp); errno = saved; goto fail; }
    if (link (tmp, path) < 0) { saved = errno; unlink (tmp); errno = saved; goto fail; }
    if (unlink (tmp) < 0) builtin_warning ("remove job temp: %s", strerror (errno));
    close (lockfd);
    free (script);
    printf ("job %s scheduled for %lld\n", jobid, (long long) run_at);
    return EXECUTION_SUCCESS;

fail:
    saved = errno;
    if (lockfd >= 0) close (lockfd);
    if (dirfd >= 0) close (dirfd);
    if (rootfd >= 0) close (rootfd);
    free (script);
    builtin_error ("queue job: %s", strerror (saved));
    return EXECUTION_FAILURE;
}

char *batch_doc[] = {
    "Schedule a job for low-load execution (currently immediate).",
    "",
    "    batch < script",
    "",
    "Jobs are written to ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/atjobs.",
    "Jobid format is <seconds-since-epoch>.<pid>.<seq>; cron's atjobs",
    "scanner processes batch jobs with the same fire time in submission",
    "order (FIFO), including jobs from different shell processes.",
    (char *)NULL
};

struct builtin batch_struct = {
    "batch",
    batch_builtin,
    BUILTIN_ENABLED,
    batch_doc,
    "batch",
    0
};
