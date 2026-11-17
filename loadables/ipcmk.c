/* SPDX-License-Identifier: MIT */
/* ipcmk.c -- create System V and named POSIX IPC resources as a bash builtin.
 *
 * Command line, creation calls, output and diagnostics follow util-linux
 * 2.41 ipcmk(1):
 *   ipcmk -M SIZE [-p MODE]     shmget(random key, SIZE, MODE | IPC_CREAT)
 *   ipcmk -S NSEMS [-p MODE]    semget(random key, NSEMS, MODE | IPC_CREAT)
 *   ipcmk -Q [-p MODE]          msgget(random key, MODE | IPC_CREAT)
 *   ipcmk -n NAME (-m SIZE|-s|-q) [-p MODE]  named POSIX IPC, O_CREAT
 * Several kinds may be requested in one call; they are created in the
 * order shm, POSIX shm, queue, POSIX queue, semaphore, POSIX semaphore.
 * The libc and the kernel decide which POSIX names are valid, and a name
 * that already exists is opened, not refused.
 *
 * One addition: when the line naming a new object cannot be written, or a
 * later step of creating it fails, the object this call created is removed
 * again. An object that already existed is never removed.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mqueue.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/random.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "loadables.h"

struct ipcmk_long {
    const char *name;
    int has_arg;
    int val;
};

static const struct ipcmk_long ipcmk_longopts[] = {
    { "shmem", 1, 'M' },
    { "posix-shmem", 1, 'm' },
    { "semaphore", 1, 'S' },
    { "posix-semaphore", 0, 's' },
    { "queue", 0, 'Q' },
    { "posix-mqueue", 0, 'q' },
    { "mode", 1, 'p' },
    { "name", 1, 'n' },
    { "version", 0, 'V' },
    { "help", 0, 'h' },
};
#define IPCMK_NLONG ((int) (sizeof ipcmk_longopts / sizeof ipcmk_longopts[0]))

struct ipcmk_request {
    int permission;
    const char *name;
    uintmax_t size;
    int nsems;
    int ask_shm, ask_msg, ask_sem, ask_pshm, ask_pmsg, ask_psem;
};

static int
ipcmk_try_help (void)
{
    fprintf (stderr, "Try 'ipcmk --help' for more information.\n");
    return EXECUTION_FAILURE;
}

/* A failed call in the style of err(3): the message, then errno's text. */
static int
ipcmk_err (const char *message, int error)
{
    fprintf (stderr, "ipcmk: %s: %s\n", message, strerror (error));
    return EXECUTION_FAILURE;
}

/* Flush before reporting success: a lost identifier would orphan the object. */
static int
ipcmk_output_ok (void)
{
    return fflush (stdout) == 0 && !ferror (stdout);
}

static int
ipcmk_write_error (void)
{
    clearerr (stdout);
    fprintf (stderr, "ipcmk: write error\n");
    return EXECUTION_FAILURE;
}

static int
ipcmk_scale (uintmax_t *x, unsigned base, int pwr)
{
    while (pwr--) {
        if (*x > UINTMAX_MAX / base)
            return -ERANGE;
        *x *= base;
    }
    return 0;
}

/* util-linux parse_size(): base-0 integer, optional .fraction, optional
 * K/M/G/T/P/E/Z/Y suffix followed by nothing (1024), "iB" (1024) or "B"
 * (1000). Returns 0 or a negative errno. */
static int
ipcmk_parse_size (const char *str, uintmax_t *out)
{
    static const char suf[] = "KMGTPEZY", suf2[] = "kmgtpezy";
    const char *p = str;
    char *end = NULL;
    uintmax_t x, frac = 0;
    unsigned base = 1024;
    int pwr = 0, frac_zeros = 0;

    if (!str || !*str)
        return -EINVAL;
    while (isspace ((unsigned char) *p))
        p++;
    if (*p == '-')
        return -EINVAL;

    errno = 0;
    x = strtoumax (str, &end, 0);
    if (end == str || (errno != 0 && (x == UINTMAX_MAX || x == 0)))
        return errno ? -errno : -EINVAL;
    if (!end || !*end)
        goto done;
    p = end;

check_suffix:
    if (*p && p[1] == 'i' && (p[2] == 'B' || p[2] == 'b') && !p[3])
        base = 1024;
    else if (*p && (p[1] == 'B' || p[1] == 'b') && !p[2])
        base = 1000;
    else if (*p && p[1]) {
        if (frac == 0 && *p == '.') {
            const char *f = p + 1;
            for (; *f == '0'; f++)
                frac_zeros++;
            p = f;
            if (isdigit ((unsigned char) *f)) {
                errno = 0;
                frac = strtoumax (f, &end, 0);
                if (end == f || (errno != 0 && (frac == UINTMAX_MAX || frac == 0)))
                    return errno ? -errno : -EINVAL;
                p = end;
            }
            if (!*p)
                return -EINVAL;     /* a fraction needs a size suffix */
            goto check_suffix;
        }
        return -EINVAL;
    }

    {
        const char *sp = strchr (suf, *p);
        if (sp)
            pwr = (int) (sp - suf) + 1;
        else if ((sp = strchr (suf2, *p)))
            pwr = (int) (sp - suf2) + 1;
        else
            return -EINVAL;
    }
    if (ipcmk_scale (&x, base, pwr) < 0)
        return -ERANGE;

    if (frac && pwr) {
        uintmax_t frac_div = 10, frac_poz = 1, frac_base = 1;

        ipcmk_scale (&frac_base, base, pwr);
        while (frac_div < frac) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        for (int i = 0; i < frac_zeros; i++) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        do {
            unsigned seg = (unsigned) (frac % 10);
            uintmax_t seg_div = frac_div / frac_poz;

            frac /= 10;
            frac_poz *= 10;
            if (seg && seg_div / seg)
                x += frac_base / (seg_div / seg);
        } while (frac);
    }

done:
    *out = x;
    return 0;
}

static void
ipcmk_print_help (void)
{
    puts ("");
    puts ("Usage:");
    puts (" ipcmk [options]");
    puts ("");
    puts ("Create various IPC resources.");
    puts ("");
    puts ("Options:");
    puts (" -M, --shmem <size>       create shared memory segment of size <size>");
    puts (" -m, --posix-shmem <size> create POSIX shared memory segment of size <size>");
    puts (" -S, --semaphore <number> create semaphore array with <number> elements");
    puts (" -s, --posix-semaphore    create POSIX semaphore");
    puts (" -Q, --queue              create message queue");
    puts (" -q, --posix-mqueue       create POSIX message queue");
    puts (" -p, --mode <mode>        permission for the resource (default is 0644)");
    puts (" -n, --name <name>        name of the POSIX resource");
    puts ("");
    puts (" -h, --help               display this help");
    puts (" -V, --version            display version");
    puts ("");
    puts ("POSIX kinds require -n <name>; their permissions are filtered by umask.");
    puts ("Sizes accept K, M, G, ... suffixes (KiB is 1024, KB is 1000).");
    puts ("Every requested resource is created; resources persist until removed.");
}

/* One parsed option. Returns 0 to continue, -2 after --help or --version,
   or the exit status of a usage error. */
static int
ipcmk_option (struct ipcmk_request *r, int c, const char *arg)
{
    int rc;

    switch (c) {
    case 'M':
    case 'm':
        rc = ipcmk_parse_size (arg, &r->size);
        if (rc < 0) {
            fprintf (stderr, "ipcmk: failed to parse size: '%s': %s\n", arg, strerror (-rc));
            return EXECUTION_FAILURE;
        }
        if (c == 'M')
            r->ask_shm = 1;
        else
            r->ask_pshm = 1;
        break;
    case 'Q':
        r->ask_msg = 1;
        break;
    case 'q':
        r->ask_pmsg = 1;
        break;
    case 'S': {
        char *end = NULL;
        intmax_t number = 0;

        errno = 0;
        if (*arg)
            number = strtoimax (arg, &end, 10);
        if (!*arg || errno || end == arg || *end)
            ;
        else if (number < INT32_MIN || number > INT32_MAX)
            errno = ERANGE;
        else {
            r->nsems = (int) number;
            r->ask_sem = 1;
            break;
        }
        if (errno == ERANGE)
            fprintf (stderr, "ipcmk: failed to parse elements: '%s': %s\n", arg, strerror (ERANGE));
        else
            fprintf (stderr, "ipcmk: failed to parse elements: '%s'\n", arg);
        return EXECUTION_FAILURE;
    }
    case 's':
        r->ask_psem = 1;
        break;
    case 'p': {
        char *end = NULL;
        unsigned long value;

        /* errno is often still 0 here, which reads "Success". */
        errno = 0;
        value = strtoul (arg, &end, 8);
        if (errno || end == arg || *end)
            return ipcmk_err ("failed to parse mode", errno);
        r->permission = (int) value;
        break;
    }
    case 'n':
        r->name = arg;
        break;
    case 'h':
        ipcmk_print_help ();
        return -2;
    case 'V':
        puts ("ipcmk from util-linux 2.41");
        return -2;
    }
    return 0;
}

static key_t
ipcmk_random_key (void)
{
    key_t key = 0;
    size_t have = 0;

    while (have < sizeof key) {
        ssize_t n = getrandom ((char *) &key + have, sizeof key - have, GRND_NONBLOCK);
        if (n > 0)
            have += (size_t) n;
        else if (n < 0 && errno == EINTR)
            continue;
        else
            break;
    }
    if (have < sizeof key) {
        struct timespec now;
        clock_gettime (CLOCK_MONOTONIC, &now);
        key = (key_t) ((unsigned long) now.tv_nsec ^ ((unsigned long) now.tv_sec << 20)
                       ^ ((unsigned long) getpid () << 8));
    }
    return key;
}

/* Each creator asks for an exclusive object first so that this call knows
   whether the object is its own; an existing key or name is then taken the
   way plain IPC_CREAT / O_CREAT takes it. */
static int
ipcmk_shm (const struct ipcmk_request *r)
{
    key_t key = ipcmk_random_key ();
    int owned = 1;
    int id = shmget (key, (size_t) r->size, r->permission | IPC_CREAT | IPC_EXCL);

    if (id < 0 && errno == EEXIST) {
        owned = 0;
        id = shmget (key, (size_t) r->size, r->permission | IPC_CREAT);
    }
    if (id < 0)
        return ipcmk_err ("create share memory failed", errno);
    printf ("Shared memory id: %d\n", id);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        shmctl (id, IPC_RMID, NULL);
    return ipcmk_write_error ();
}

static int
ipcmk_msg (const struct ipcmk_request *r)
{
    key_t key = ipcmk_random_key ();
    int owned = 1;
    int id = msgget (key, r->permission | IPC_CREAT | IPC_EXCL);

    if (id < 0 && errno == EEXIST) {
        owned = 0;
        id = msgget (key, r->permission | IPC_CREAT);
    }
    if (id < 0)
        return ipcmk_err ("create message queue failed", errno);
    printf ("Message queue id: %d\n", id);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        msgctl (id, IPC_RMID, NULL);
    return ipcmk_write_error ();
}

static int
ipcmk_sem (const struct ipcmk_request *r)
{
    key_t key = ipcmk_random_key ();
    int owned = 1;
    int id = semget (key, r->nsems, r->permission | IPC_CREAT | IPC_EXCL);

    if (id < 0 && errno == EEXIST) {
        owned = 0;
        id = semget (key, r->nsems, r->permission | IPC_CREAT);
    }
    if (id < 0)
        return ipcmk_err ("create semaphore failed", errno);
    printf ("Semaphore id: %d\n", id);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        semctl (id, 0, IPC_RMID);
    return ipcmk_write_error ();
}

static int
ipcmk_posix_shm (const struct ipcmk_request *r)
{
    static const char failed[] = "create POSIX shared memory failed";
    mode_t mode = (mode_t) r->permission;
    int owned = 1, saved;
    int fd = shm_open (r->name, O_RDWR | O_CREAT | O_EXCL, mode);

    if (fd < 0 && errno == EEXIST) {
        owned = 0;
        fd = shm_open (r->name, O_RDWR | O_CREAT, mode);
    }
    if (fd < 0)
        return ipcmk_err (failed, errno);
    if (ftruncate (fd, (off_t) r->size) < 0) {
        saved = errno;
        close (fd);
        if (owned)
            shm_unlink (r->name);
        return ipcmk_err (failed, saved);
    }
    close (fd);
    printf ("POSIX shared memory name: %s\n", r->name);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        shm_unlink (r->name);
    return ipcmk_write_error ();
}

static int
ipcmk_posix_msg (const struct ipcmk_request *r)
{
    mode_t mode = (mode_t) r->permission;
    int owned = 1;
    mqd_t mq = mq_open (r->name, O_RDWR | O_CREAT | O_EXCL, mode, (struct mq_attr *) NULL);

    if (mq == (mqd_t) -1 && errno == EEXIST) {
        owned = 0;
        mq = mq_open (r->name, O_RDWR | O_CREAT, mode, (struct mq_attr *) NULL);
    }
    if (mq == (mqd_t) -1)
        return ipcmk_err ("create POSIX message queue failed", errno);
    mq_close (mq);
    printf ("POSIX message queue name: %s\n", r->name);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        mq_unlink (r->name);
    return ipcmk_write_error ();
}

static int
ipcmk_posix_sem (const struct ipcmk_request *r)
{
    mode_t mode = (mode_t) r->permission;
    int owned = 1;
    sem_t *sem = sem_open (r->name, O_CREAT | O_EXCL, mode, 0U);

    if (sem == SEM_FAILED && errno == EEXIST) {
        owned = 0;
        sem = sem_open (r->name, O_CREAT, mode, 0U);
    }
    if (sem == SEM_FAILED)
        return ipcmk_err ("create POSIX semaphore failed", errno);
    sem_close (sem);
    printf ("POSIX semaphore name: %s\n", r->name);
    if (ipcmk_output_ok ())
        return EXECUTION_SUCCESS;
    if (owned)
        sem_unlink (r->name);
    return ipcmk_write_error ();
}

int
ipcmk_builtin (WORD_LIST *list)
{
    struct ipcmk_request r;
    int ddash = 0, rc;

    memset (&r, 0, sizeof r);
    r.permission = 0644;
    clearerr (stdout);

    /* GNU getopt_long with argument permutation; operands are ignored. */
    for (; list; list = list->next) {
        const char *w = list->word ? list->word->word : NULL;

        if (!w || ddash || w[0] != '-' || w[1] == '\0')
            continue;
        if (!strcmp (w, "--")) {
            ddash = 1;
            continue;
        }
        if (w[1] == '-') {
            const char *name = w + 2, *eq = strchr (name, '=');
            const char *arg = NULL;
            size_t nl = eq ? (size_t) (eq - name) : strlen (name);
            int hit = -1, nhits = 0;

            for (int i = 0; i < IPCMK_NLONG; i++) {
                if (strncmp (ipcmk_longopts[i].name, name, nl))
                    continue;
                if (strlen (ipcmk_longopts[i].name) == nl) {
                    hit = i;
                    nhits = 1;
                    break;
                }
                if (hit < 0)
                    hit = i;
                nhits++;
            }
            if (nhits == 0) {
                fprintf (stderr, "ipcmk: unrecognized option '%s'\n", w);
                return ipcmk_try_help ();
            }
            if (nhits > 1) {
                /* glibc getopt names the whole word, "=VALUE" included. */
                fprintf (stderr, "ipcmk: option '%s' is ambiguous; possibilities:", w);
                for (int i = 0; i < IPCMK_NLONG; i++)
                    if (!strncmp (ipcmk_longopts[i].name, name, nl))
                        fprintf (stderr, " '--%s'", ipcmk_longopts[i].name);
                fputc ('\n', stderr);
                return ipcmk_try_help ();
            }
            if (ipcmk_longopts[hit].has_arg) {
                if (eq)
                    arg = eq + 1;
                else if (list->next && list->next->word && list->next->word->word) {
                    list = list->next;
                    arg = list->word->word;
                } else {
                    fprintf (stderr, "ipcmk: option '--%s' requires an argument\n",
                             ipcmk_longopts[hit].name);
                    return ipcmk_try_help ();
                }
            } else if (eq) {
                fprintf (stderr, "ipcmk: option '--%s' doesn't allow an argument\n",
                         ipcmk_longopts[hit].name);
                return ipcmk_try_help ();
            }
            rc = ipcmk_option (&r, ipcmk_longopts[hit].val, arg);
            if (rc == -2)
                return ipcmk_output_ok () ? EXECUTION_SUCCESS : ipcmk_write_error ();
            if (rc)
                return rc;
            continue;
        }
        for (const char *p = w + 1; *p; p++) {
            const char *arg = NULL;

            if (!strchr ("hMmQqSspnV", *p)) {
                fprintf (stderr, "ipcmk: invalid option -- '%c'\n", *p);
                return ipcmk_try_help ();
            }
            if (strchr ("MmSpn", *p)) {
                if (p[1])
                    arg = p + 1;
                else if (list->next && list->next->word && list->next->word->word) {
                    list = list->next;
                    arg = list->word->word;
                } else {
                    fprintf (stderr, "ipcmk: option requires an argument -- '%c'\n", *p);
                    return ipcmk_try_help ();
                }
            }
            rc = ipcmk_option (&r, *p, arg);
            if (rc == -2)
                return ipcmk_output_ok () ? EXECUTION_SUCCESS : ipcmk_write_error ();
            if (rc)
                return rc;
            if (arg)
                break;
        }
    }

    if (!r.ask_shm && !r.ask_msg && !r.ask_sem && !r.ask_pshm && !r.ask_pmsg && !r.ask_psem) {
        fprintf (stderr, "ipcmk: bad usage\n");
        return ipcmk_try_help ();
    }
    if ((r.ask_pshm || r.ask_pmsg || r.ask_psem) && r.name == NULL) {
        fprintf (stderr, "ipcmk: name is required for POSIX IPC\n");
        return ipcmk_try_help ();
    }

    if (r.ask_shm && (rc = ipcmk_shm (&r)) != EXECUTION_SUCCESS)
        return rc;
    if (r.ask_pshm && (rc = ipcmk_posix_shm (&r)) != EXECUTION_SUCCESS)
        return rc;
    if (r.ask_msg && (rc = ipcmk_msg (&r)) != EXECUTION_SUCCESS)
        return rc;
    if (r.ask_pmsg && (rc = ipcmk_posix_msg (&r)) != EXECUTION_SUCCESS)
        return rc;
    if (r.ask_sem && (rc = ipcmk_sem (&r)) != EXECUTION_SUCCESS)
        return rc;
    if (r.ask_psem && (rc = ipcmk_posix_sem (&r)) != EXECUTION_SUCCESS)
        return rc;
    return EXECUTION_SUCCESS;
}

char *ipcmk_doc[] = {
    "Create System V or named POSIX IPC resources.",
    "",
    "    ipcmk [-p mode] -M size",
    "    ipcmk [-p mode] -S number",
    "    ipcmk [-p mode] -Q",
    "",
    "    ipcmk [-p mode] -n /name (-m size|-s|-q)",
    "POSIX permissions are filtered by umask; semaphore initial value is zero.",
    "Several kinds may be given at once. System V keys are random; an existing",
    "POSIX name is opened, not refused, as util-linux ipcmk does.",
    "Successful resources persist until explicitly removed or unlinked.",
    (char *) NULL
};

struct builtin ipcmk_struct = {
    "ipcmk",
    ipcmk_builtin,
    BUILTIN_ENABLED,
    ipcmk_doc,
    "ipcmk [-p mode] (-M size|-S number|-Q|-n /name (-m size|-s|-q))",
    0
};
