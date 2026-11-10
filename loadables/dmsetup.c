/* SPDX-License-Identifier: MIT */
/* dmsetup.c — low-level device-mapper control, as a bash builtin.
 *
 * Every command speaks the kernel DM ioctl ABI on /dev/mapper/control
 * directly; there is no libdevmapper. Queries (`ls`, `info`, `table`,
 * `status`, `deps`, `targets`, `version`) are unprivileged in this code.
 * Mutating commands (`create`, `load`/`reload`, `remove`, `remove_all`,
 * `suspend`, `resume`, `rename`, `message`, `clear`, `wipe_table`) fail
 * closed unless uid 0 also opts in with BASHOS_DMSETUP_ALLOW_MUTATE=1,
 * and that check runs before the control device is opened.
 *
 * Requests follow libdevmapper's layout: one struct dm_ioctl header with
 * the payload at data_start, target specs padded to 8 bytes with `next`
 * relative to the spec, and a doubling retry whenever the kernel answers
 * with DM_BUFFER_FULL_FLAG. Responses are bounds-checked before use.
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
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <regex.h>
#include <langinfo.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>

#include "loadables.h"

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

/* Bit 2 of dm_ioctl.flags: dropped from the kernel's uapi header, still set
   on every request by libdevmapper ("FIXME" in _do_dm_ioctl). */
#ifndef DM_EXISTS_FLAG
#  define DM_EXISTS_FLAG 0x00000004
#endif

#define DMS_CONTROL     "/dev/mapper/control"
#define DMS_DIR         "/dev/mapper"
#define DMS_INITIAL_BUF 16384          /* libdevmapper's starting size */
#define DMS_MAX_BUF     (64u << 20)    /* stop doubling here */
#define DMS_MAX_TABLE   (16u << 20)    /* largest --table/inline text accepted */
/* libdevmapper refuses any single allocation above this, which bounds the
   DM_TABLE_LOAD argument it builds ("Huge memory allocation ... rejected"). */
#define DMS_MAX_ALLOC   50000000u
#define DMS_LIBRARY_VERSION "bash-os dm-ioctl shim"
/* remove --retry: libdevmapper's DM_IOCTL_RETRIES and DM_RETRY_USLEEP_DELAY */
#define DMS_REMOVE_RETRIES 25
#define DMS_RETRY_DELAY_NS 200000000L
/* udev synchronisation cookies (libdevmapper's libdm-common.h values) */
#define DMS_COOKIE_MAGIC                0x0D4D
#define DMS_UDEV_FLAGS_SHIFT            16
#define DMS_UDEV_DISABLE_DM_RULES_FLAG  0x0001
#define DMS_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG 0x0002
#define DMS_UDEV_DISABLE_LIBRARY_FALLBACK 0x0020
#define DMS_UDEV_PRIMARY_SOURCE_FLAG    0x0040
#define DMS_UDEV_WAIT_SECONDS           30
/* libdevmapper's DM_DEVICE_UID / GID / MODE. Applied only when this
   process creates the node; an existing correct node is left alone. */
#define DMS_DEVICE_MODE                 0600

struct dms_opts {
    int readonly, notable, noflush, nolockfs, inactive, force, deferred, retry;
    int showkeys, setuuid, has_major, has_minor;
    int columns, noheadings, tree, noudevsync, noudevrules, verifyudev;
    int add_on_create, add_on_resume;
    unsigned long major, minor;
    uid_t dev_uid;
    gid_t dev_gid;
    mode_t dev_mode;
    const char *uuid, *table, *target;
    const char *fields, *sort, *select, *separator;
    const char **pos;                   /* positional words, verb first */
    int npos;
};

struct dms_spec {
    unsigned long long start, length;
    char type[DM_MAX_TYPE_NAME];
    char *params;                       /* owned, except the wipe target's "" */
    size_t params_len;
};

/* Parsed table lines, plus the size of the DM_TABLE_LOAD argument that
   libdevmapper would allocate for them (it refuses more than 50 MB). */
struct dms_table {
    struct dms_spec *v;
    size_t n, cap;
    size_t alloc;
};

static void
dms_usage (void)
{
    fputs ("Usage:\n\n", stderr);
    fputs ("dmsetup\n", stderr);
    fputs ("\t[--version] [-h|--help]\n", stderr);
    fputs ("\thelp\n", stderr);
    fputs ("\tcreate <dev_name> [-u|--uuid <uuid>] [-r|--readonly] [-n|--notable]\n"
           "\t       [-j|--major <major> -m|--minor <minor>] [--table <table>|<table_file>]\n", stderr);
    fputs ("\tremove [-f|--force] [--deferred] <device>...\n", stderr);
    fputs ("\tremove_all [-f|--force]\n", stderr);
    fputs ("\tsuspend [--noflush] [--nolockfs] <device>...\n", stderr);
    fputs ("\tresume <device>...\n", stderr);
    fputs ("\tload <device> [-r|--readonly] [--table <table>|<table_file>]\n", stderr);
    fputs ("\tclear <device>...\n", stderr);
    fputs ("\treload <device> [-r|--readonly] [--table <table>|<table_file>]\n", stderr);
    fputs ("\twipe_table <device>...\n", stderr);
    fputs ("\trename <device> [--setuuid] <new_name_or_uuid>\n", stderr);
    fputs ("\tmessage <device> <sector> <message>\n", stderr);
    fputs ("\tls [--target <target_type>]\n", stderr);
    fputs ("\tinfo [<device>...]\n", stderr);
    fputs ("\tdeps [--inactive] [<device>...]\n", stderr);
    fputs ("\tstatus [--target <target_type>] [--inactive] [<device>...]\n", stderr);
    fputs ("\ttable [--target <target_type>] [--inactive] [--showkeys] [<device>...]\n", stderr);
    fputs ("\ttargets\n", stderr);
    fputs ("\tversion\n", stderr);
    fputs ("<device> may be a name, or omitted when -u|--uuid names it.\n", stderr);
}

/* ---- small sysfs reader ---- */

static int
dms_read_first_line (const char *path, char *buf, size_t n)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, buf, n - 1);
    close (fd);
    if (r < 0) return -1;
    buf[r > 0 ? r : 0] = '\0';
    size_t l = strlen (buf);
    while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) buf[--l] = '\0';
    return 0;
}

/* ---- ioctl plumbing ---- */

static const char *
dms_cmd_name (unsigned long req, uint32_t flags)
{
    switch (req) {
    case DM_VERSION: return "version";
    case DM_REMOVE_ALL: return "remove_all";
    case DM_LIST_DEVICES: return "names";
    case DM_DEV_CREATE: return "create";
    case DM_DEV_REMOVE: return "remove";
    case DM_DEV_RENAME: return "rename";
    case DM_DEV_SUSPEND: return (flags & DM_SUSPEND_FLAG) ? "suspend" : "resume";
    case DM_DEV_STATUS: return "info";
    case DM_TABLE_LOAD: return "reload";
    case DM_TABLE_CLEAR: return "clear";
    case DM_TABLE_DEPS: return "deps";
    case DM_TABLE_STATUS: return (flags & DM_STATUS_TABLE_FLAG) ? "table" : "status";
    case DM_LIST_VERSIONS: return "versions";
    case DM_TARGET_MSG: return "message";
    }
    return "unknown";
}

/* libdevmapper's wording when the control node cannot be opened: the open
   failure, the communication failure (with a hint for root), then the
   version check that every task performs first. */
static void
dms_report_open_error (int error)
{
    fprintf (stderr, "%s: open failed: %s\n", DMS_CONTROL, strerror (error));
    fputs ("Failure to communicate with kernel device-mapper driver.\n", stderr);
    if (geteuid () == 0)
        fputs ("Check that device-mapper is available in the kernel.\n", stderr);
    fprintf (stderr, "Incompatible libdevmapper %s and kernel driver (unknown version).\n",
             DMS_LIBRARY_VERSION);
}

/* Number named NAME in a "NUMBER NAME" listing such as /proc/devices or
   /proc/misc, or -1. */
static long
dms_proc_number (const char *path, const char *name)
{
    FILE *fp = fopen (path, "re");
    if (!fp) return -1;
    char line[256], what[128];
    long found = -1, num;
    while (fgets (line, sizeof line, fp))
        if (sscanf (line, "%ld %127s", &num, what) == 2 && !strcmp (what, name)) {
            found = num;
            break;
        }
    fclose (fp);
    return found;
}

static int dms_mutation_opted_in (void);

/* Like libdevmapper's _create_control: when root has opted in to
   mutations, (re)create a missing or wrong control node from the misc
   major and the device-mapper minor the kernel publishes. */
static void
dms_ensure_control (void)
{
    if (!dms_mutation_opted_in ()) return;
    long maj = dms_proc_number ("/proc/devices", "misc");
    long min = dms_proc_number ("/proc/misc", "device-mapper");
    if (maj < 0 || min < 0) return;
    dev_t want = makedev ((unsigned) maj, (unsigned) min);
    struct stat st;
    if (lstat (DMS_CONTROL, &st) == 0) {
        if (S_ISCHR (st.st_mode) && st.st_rdev == want) return;
        if (unlink (DMS_CONTROL) < 0) return;
    } else if (errno != ENOENT)
        return;
    mode_t old = umask (0022);
    if (mkdir (DMS_DIR, 0755) < 0 && errno != EEXIST) {
        umask (old);
        return;
    }
    umask (0177);
    if (mknod (DMS_CONTROL, S_IFCHR | S_IRUSR | S_IWUSR, want) < 0 && errno != EEXIST)
        fprintf (stderr, "%s: mknod failed: %s\n", DMS_CONTROL, strerror (errno));
    umask (old);
}

static int
dms_open_control (int quiet)
{
    dms_ensure_control ();
    int fd = open (DMS_CONTROL, O_RDWR | O_CLOEXEC);
    if (fd < 0 && !quiet) dms_report_open_error (errno);
    return fd;
}

static int
dms_set_id (struct dm_ioctl *io, const char *name, const char *uuid)
{
    if (name && *name) {
        if (strlen (name) >= sizeof io->name) {
            fprintf (stderr, "Name \"%s\" too long.\n", name);
            return -1;
        }
        strcpy (io->name, name);
    }
    if (uuid && *uuid) {
        if (strlen (uuid) >= sizeof io->uuid) {
            fprintf (stderr, "dmsetup: uuid \"%s\" too long\n", uuid);
            return -1;
        }
        strcpy (io->uuid, uuid);
    }
    return 0;
}

/* A device number for the next requests, as libdevmapper sends one
   (with DM_PERSISTENT_DEV_FLAG) whenever its task has a major and minor.
   With omit_name the name is left out of the request, as libdevmapper
   does for such a resume, but still names the device in diagnostics. */
static struct {
    int set, omit_name;
    uint64_t dev;
} dms_req;

static void
dms_req_by_dev (long maj, long min, int omit_name)
{
    dms_req.set = 1;
    dms_req.omit_name = omit_name;
    dms_req.dev = (uint64_t) makedev ((unsigned) maj, (unsigned) min);
}

static void
dms_req_clear (void)
{
    memset (&dms_req, 0, sizeof dms_req);
}

static struct dm_ioctl *
dms_alloc (size_t bytes, const char *name, const char *uuid, uint32_t flags,
           const void *payload, size_t payload_len)
{
    size_t need = sizeof (struct dm_ioctl) + payload_len;
    if (bytes < need) bytes = need;
    struct dm_ioctl *io = calloc (1, bytes);
    if (!io) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return NULL;
    }
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = DM_VERSION_MINOR;
    io->version[2] = DM_VERSION_PATCHLEVEL;
    io->data_size = (uint32_t) bytes;
    io->data_start = sizeof (struct dm_ioctl);
    io->flags = flags | DM_EXISTS_FLAG;   /* libdevmapper sets it on every request */
    if (dms_req.set) {
        io->dev = dms_req.dev;
        io->flags |= DM_PERSISTENT_DEV_FLAG;
        if (dms_req.omit_name) name = NULL;
    }
    if (dms_set_id (io, name, uuid) < 0) {
        free (io);
        return NULL;
    }
    if (payload_len) memcpy ((char *) io + io->data_start, payload, payload_len);
    return io;
}

/* libdevmapper's "%s ioctl on %s %s%s%.0d%s%.0d%s%s failed: %s": the device
   number follows the uuid whenever the request names a major. */
static void
dms_report_dev (unsigned long req, uint32_t flags, const char *name, const char *uuid,
                long maj, long min, int err)
{
    char devno[64] = "";
    if (maj > 0)
        snprintf (devno, sizeof devno, "(%ld:%ld)", maj, min > 0 ? min : 0);
    fprintf (stderr, "device-mapper: %s ioctl on %s %s%s failed: %s\n",
             dms_cmd_name (req, flags), name ? name : "", uuid ? uuid : "", devno, strerror (err));
}

static void
dms_report (unsigned long req, uint32_t flags, const char *name, const char *uuid, int err)
{
    if (dms_req.set)
        dms_report_dev (req, flags, name, uuid, (long) major ((dev_t) dms_req.dev),
                        (long) minor ((dev_t) dms_req.dev), err);
    else
        dms_report_dev (req, flags, name, uuid, 0, 0, err);
}

/* Run one DM ioctl. With grow set, start at DMS_INITIAL_BUF and double while
   the kernel reports DM_BUFFER_FULL_FLAG. Returns the response buffer, or NULL
   with *errp set (0 when a message has already been printed). Device-absent
   (ENXIO) errors are left for the caller to word when quiet_enxio is set. */
static struct dm_ioctl *
dms_run (int fd, unsigned long req, const char *name, const char *uuid, uint32_t flags,
         const void *payload, size_t payload_len, int grow, int quiet_enxio, int *errp)
{
    size_t bytes = grow ? DMS_INITIAL_BUF : 0;
    *errp = 0;
    /* The payload can itself exceed the initial response buffer. Track the
       actual allocation so a full response always doubles that allocation. */
    if (grow) {
        if (payload_len > DMS_MAX_BUF - sizeof (struct dm_ioctl)) {
            fprintf (stderr, "dmsetup: %s response exceeds %u bytes\n",
                     dms_cmd_name (req, flags), DMS_MAX_BUF);
            return NULL;
        }
        size_t need = sizeof (struct dm_ioctl) + payload_len;
        if (bytes < need) bytes = need;
    }
    for (;;) {
        struct dm_ioctl *io = dms_alloc (bytes, name, uuid, flags, payload, payload_len);
        if (!io) return NULL;
        if (ioctl (fd, req, io) < 0) {
            int e = errno;
            free (io);
            if (!(quiet_enxio && e == ENXIO)) dms_report (req, flags, name, uuid, e);
            *errp = e;
            return NULL;
        }
        if (!(io->flags & DM_BUFFER_FULL_FLAG)) {
            /* never trust a returned size beyond what was allocated */
            size_t have = bytes > sizeof (struct dm_ioctl) + payload_len
                ? bytes : sizeof (struct dm_ioctl) + payload_len;
            /* ctl_ioctl copies only offsetof(data) bytes for a header-only
               reply, not sizeof(struct dm_ioctl), which includes tail padding.
               Normalize that valid empty payload to our aligned data area.
               Consumers still validate any advertised records or DATA_OUT. */
            if (io->data_size == offsetof (struct dm_ioctl, data)
                && io->data_start == sizeof (struct dm_ioctl))
                io->data_size = io->data_start;
            /* Name and UUID are fixed arrays. A missing NUL would make
               later %s walks leave the header. Records and the next-offset
               chain are 8-byte aligned; an odd data_start is not a record. */
            if (io->data_start < sizeof (struct dm_ioctl) || io->data_start > have
                || io->data_size > have || io->data_size < io->data_start
                || (io->data_start & 7U)
                || !memchr (io->name, '\0', sizeof io->name)
                || !memchr (io->uuid, '\0', sizeof io->uuid)) {
                fprintf (stderr, "dmsetup: malformed %s response (data_start %u, data_size %u)\n",
                         dms_cmd_name (req, flags), io->data_start, io->data_size);
                free (io);
                return NULL;
            }
            return io;
        }
        free (io);
        if (!grow || bytes >= DMS_MAX_BUF) {
            fprintf (stderr, "dmsetup: %s response exceeds %u bytes\n",
                     dms_cmd_name (req, flags), DMS_MAX_BUF);
            return NULL;
        }
        bytes = bytes > DMS_MAX_BUF / 2 ? DMS_MAX_BUF : bytes * 2;
    }
}

static int
dms_simple (int fd, unsigned long req, const char *name, const char *uuid, uint32_t flags)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, req, name, uuid, flags, NULL, 0, 0, 0, &err);
    if (!io) return EXECUTION_FAILURE;
    free (io);
    return EXECUTION_SUCCESS;
}

/* ---- udev synchronisation (libdevmapper's notification cookies) ---- */

union dms_semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

struct dms_sync {
    int semid;
    uint32_t cookie;
};

/* Every dmsetup process prints this once when udev is up and
   DM_DISABLE_UDEV is set. The wording is libdevmapper's. */
static void
dms_udev_bypass_warning (void)
{
    if (!getenv ("DM_DISABLE_UDEV")) return;
    if (access ("/run/udev/control", F_OK) < 0 &&
        access ("/dev/.udev/queue.bin", F_OK) < 0)
        return;
    fputs ("Udev is running and DM_DISABLE_UDEV environment variable is set. "
           "Bypassing udev, device-mapper library will manage device nodes "
           "in device directory.\n", stderr);
}

/* Flags stored in the cookie, before PRIMARY_SOURCE is added on a
   uevent ioctl. DM_DISABLE_UDEV clears library fallback and tells udev
   rules not to create the node. --verifyudev also leaves fallback on.
   --noudevsync does not: it only skips the wait. */
static uint16_t
dms_cookie_flags (const struct dms_opts *o)
{
    uint16_t flags = DMS_UDEV_DISABLE_LIBRARY_FALLBACK;
    if (o->noudevrules)
        flags |= DMS_UDEV_DISABLE_DM_RULES_FLAG | DMS_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;
    if (o->verifyudev)
        flags &= ~DMS_UDEV_DISABLE_LIBRARY_FALLBACK;
    if (getenv ("DM_DISABLE_UDEV")) {
        flags &= ~DMS_UDEV_DISABLE_LIBRARY_FALLBACK;
        flags |= DMS_UDEV_DISABLE_DM_RULES_FLAG | DMS_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;
    }
    return flags;
}

/* libdevmapper synchronises with udev only while udevd is listening
   (its control socket exists), unless --noudevsync or DM_DISABLE_UDEV. */
static int
dms_udev_sync_enabled (const struct dms_opts *o)
{
    if (o->noudevsync || getenv ("DM_DISABLE_UDEV")) return 0;
    return access ("/run/udev/control", F_OK) == 0
        || access ("/dev/.udev/queue.bin", F_OK) == 0;
}

/* cookie_set is true once dm_task_set_cookie has run. A create with no
   table never sets it. Library fallback disabled means udev owns the
   node: do not mknod and do not apply -U/-G/-M. */
static int
dms_rely_on_udev (const struct dms_opts *o, int cookie_set)
{
    if (!cookie_set) return 0;
    return (dms_cookie_flags (o) & DMS_UDEV_DISABLE_LIBRARY_FALLBACK) != 0;
}

static int
dms_check_udev (const struct dms_opts *o, int cookie_set)
{
    if (!cookie_set) return 0;
    return (dms_cookie_flags (o) & DMS_UDEV_DISABLE_DM_RULES_FLAG) == 0;
}

/* Create the cookie semaphore with libdevmapper's count of two: one
   for udev's "dmsetup udevcomplete" and one this process removes before
   waiting for zero. Without synchronisation semid stays -1. */
static int
dms_sync_begin (const struct dms_opts *o, struct dms_sync *sy)
{
    sy->semid = -1;
    sy->cookie = 0;
    if (!dms_udev_sync_enabled (o)) return 0;
    int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fputs ("Failed to open /dev/urandom to create random cookie value\n", stderr);
        return -1;
    }
    for (;;) {
        uint16_t base;
        if (read (fd, &base, sizeof base) != (ssize_t) sizeof base) {
            fprintf (stderr, "/dev/urandom: read failed: %s\n", strerror (errno));
            close (fd);
            return -1;
        }
        if (!base) continue;
        uint32_t cookie = ((uint32_t) DMS_COOKIE_MAGIC << DMS_UDEV_FLAGS_SHIFT) | base;
        int id = semget ((key_t) cookie, 1, 0600 | IPC_CREAT | IPC_EXCL);
        if (id < 0) {
            int e = errno;
            if (e == EEXIST) continue;
            close (fd);
            if (e == ENOSYS) {
                fputs ("Kernel not configured for semaphores (System V IPC). "
                       "Not using udev synchronisation code.\n", stderr);
                return 0;
            }
            if (e == ENOSPC)
                fputs ("Limit for the maximum number of semaphores reached. You can "
                       "check and set the limits in /proc/sys/kernel/sem.\n", stderr);
            else if (e == ENOMEM)
                fputs ("Not enough memory to create notification semaphore\n", stderr);
            else
                fprintf (stderr, "Failed to create notification semaphore: %s\n", strerror (e));
            return -1;
        }
        union dms_semun arg;
        arg.val = 2;
        if (semctl (id, 0, SETVAL, arg) < 0) {
            fprintf (stderr, "semid %d: semctl failed: %s\n", id, strerror (errno));
            semctl (id, 0, IPC_RMID);
            close (fd);
            return -1;
        }
        close (fd);
        sy->semid = id;
        sy->cookie = cookie;
        return 0;
    }
}

/* One decrement: what udev's rules do, and what libdevmapper does itself
   when the request failed or the kernel generated no uevent. */
static void
dms_sync_complete (struct dms_sync *sy)
{
    if (sy->semid < 0) return;
    struct sembuf sb = { 0, -1, IPC_NOWAIT };
    if (semop (sy->semid, &sb, 1) < 0 && errno != EAGAIN)
        fprintf (stderr, "Could not signal waiting process using notification semaphore "
                 "identified by cookie value %" PRIu32 " (0x%x)\n", sy->cookie, sy->cookie);
}

/* Drop this process's count and wait (bounded) for udev to finish. */
static void
dms_sync_wait (struct dms_sync *sy)
{
    if (sy->semid < 0) return;
    dms_sync_complete (sy);
    struct timespec now, end;
    clock_gettime (CLOCK_MONOTONIC, &end);
    end.tv_sec += DMS_UDEV_WAIT_SECONDS;
    for (;;) {
        clock_gettime (CLOCK_MONOTONIC, &now);
        struct timespec left = { end.tv_sec - now.tv_sec, end.tv_nsec - now.tv_nsec };
        if (left.tv_nsec < 0) { left.tv_sec--; left.tv_nsec += 1000000000L; }
        if (left.tv_sec < 0) left.tv_sec = left.tv_nsec = 0;
        struct sembuf zero = { 0, 0, 0 };
        if (semtimedop (sy->semid, &zero, 1, &left) == 0) break;
        if (errno == EINTR) continue;
        if (errno == EIDRM) { sy->semid = -1; return; }
        if (errno == EAGAIN)
            fprintf (stderr, "dmsetup: udev did not complete cookie 0x%x within %d seconds\n",
                     sy->cookie, DMS_UDEV_WAIT_SECONDS);
        else
            fprintf (stderr, "Could not set wait state for notification semaphore identified "
                     "by cookie value %" PRIu32 " (0x%x): %s\n", sy->cookie, sy->cookie,
                     strerror (errno));
        break;
    }
    semctl (sy->semid, 0, IPC_RMID);
    sy->semid = -1;
}

/* Resume, remove and rename make the kernel emit a uevent. Send them the
   way libdevmapper does: event_nr carries the primary-source and
   library-fallback-disabled udev flags and, when udev runs, the cookie,
   which this waits for. tries > 1 repeats EBUSY failures (remove
   --retry), reporting each failed attempt as libdevmapper does. */
static struct dm_ioctl *
dms_run_uevent (int fd, const struct dms_opts *o, unsigned long req, const char *name,
                const char *uuid, uint32_t flags, const void *payload, size_t plen,
                int tries, int *errp)
{
    struct dms_sync sy;
    *errp = 0;
    if (dms_sync_begin (o, &sy) < 0) return NULL;
    uint32_t udev_flags = DMS_UDEV_PRIMARY_SOURCE_FLAG | dms_cookie_flags (o);
    struct dm_ioctl *io = NULL;
    for (int attempt = 1; ; attempt++) {
        io = dms_alloc (0, name, uuid, flags, payload, plen);
        if (!io) break;
        io->event_nr = (sy.cookie & 0xffffu) | (udev_flags << DMS_UDEV_FLAGS_SHIFT);
        if (ioctl (fd, req, io) == 0) break;
        int e = errno;
        free (io);
        io = NULL;
        dms_report (req, flags, name, uuid, e);
        *errp = e;
        if (e != EBUSY || attempt >= tries) break;
        struct timespec delay = { 0, DMS_RETRY_DELAY_NS };
        while (nanosleep (&delay, &delay) < 0 && errno == EINTR) ;
    }
    if (!io || !(io->flags & DM_UEVENT_GENERATED_FLAG)) dms_sync_complete (&sy);
    dms_sync_wait (&sy);
    return io;
}

/* /dev/mapper/NAME. libdevmapper builds the same path from its dev dir. */
static int
dms_node_path (char *path, size_t n, const char *name)
{
    if (!name || !*name || strchr (name, '/')) return -1;
    int w = snprintf (path, n, "%s/%s", DMS_DIR, name);
    if (w < 0 || (size_t) w >= n) return -1;
    return 0;
}

/* Create the node only when libdevmapper would. A correct existing node
   is not chowned: udev's ownership stays. Missing nodes are mknod'd with
   the task uid/gid/mode (defaults 0, 0, 0600) and then chowned. */
static int
dms_add_node (const struct dms_opts *o, const char *name, dev_t dev, int cookie_set)
{
    if (dms_rely_on_udev (o, cookie_set)) return 0;
    char path[PATH_MAX];
    if (dms_node_path (path, sizeof path, name) < 0) return -1;
    struct stat info, linfo;
    if (stat (path, &info) >= 0) {
        if (!S_ISBLK (info.st_mode)) {
            fprintf (stderr, "A non-block device file at '%s' is already present\n", path);
            return -1;
        }
        if (info.st_rdev == dev) return 0;
        if (unlink (path) < 0 && errno != ENOENT) {
            fprintf (stderr, "%s: unlink failed: %s\n", path, strerror (errno));
            return -1;
        }
    } else {
        if (errno == ENOENT && lstat (path, &linfo) == 0 && S_ISLNK (linfo.st_mode)) {
            if (unlink (path) < 0 && errno != ENOENT) {
                fprintf (stderr, "%s: unlink failed: %s\n", path, strerror (errno));
                return -1;
            }
        }
        if (dms_check_udev (o, cookie_set) && dms_udev_sync_enabled (o))
            fprintf (stderr, "%s not set up by udev: Falling back to direct node creation.\n", path);
    }

    mode_t old = umask (0);
    if (mknod (path, S_IFBLK | o->dev_mode, dev) < 0 && errno != EEXIST) {
        fprintf (stderr, "%s: mknod for %s failed: %s\n", path, name, strerror (errno));
        umask (old);
        return -1;
    }
    umask (old);
    if (chown (path, o->dev_uid, o->dev_gid) < 0) {
        fprintf (stderr, "%s: chown failed: %s\n", path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
dms_rm_node (const struct dms_opts *o, const char *name, int cookie_set)
{
    if (dms_rely_on_udev (o, cookie_set)) return 0;
    char path[PATH_MAX];
    struct stat info;
    if (dms_node_path (path, sizeof path, name) < 0) return -1;
    if (lstat (path, &info) < 0) return 0;
    if (dms_check_udev (o, cookie_set) && dms_udev_sync_enabled (o))
        fprintf (stderr, "Node %s was not removed by udev. "
                 "Falling back to direct node removal.\n", path);
    if (unlink (path) < 0 && errno != ENOENT) {
        fprintf (stderr, "%s: unlink failed: %s\n", path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
dms_rename_node (const struct dms_opts *o, const char *old_name, const char *new_name,
                 int cookie_set)
{
    if (dms_rely_on_udev (o, cookie_set)) return 0;
    char oldpath[PATH_MAX], newpath[PATH_MAX];
    struct stat info;
    if (dms_node_path (oldpath, sizeof oldpath, old_name) < 0) return -1;
    if (dms_node_path (newpath, sizeof newpath, new_name) < 0) return -1;
    if (lstat (newpath, &info) == 0) {
        if (!S_ISLNK (info.st_mode) && !S_ISBLK (info.st_mode)) {
            fprintf (stderr, "A non-block device file at '%s' is already present\n", newpath);
            return -1;
        }
        if (unlink (newpath) < 0 && errno != ENOENT) {
            fprintf (stderr, "Unable to unlink device node for '%s'\n", new_name);
            return -1;
        }
    } else if (dms_check_udev (o, cookie_set) && dms_udev_sync_enabled (o))
        fprintf (stderr, "The node %s should have been renamed to %s by udev "
                 "but new node is not present. Falling back to direct node rename.\n",
                 oldpath, newpath);
    if (rename (oldpath, newpath) < 0 && errno != ENOENT) {
        fprintf (stderr, "Unable to rename device node from '%s' to '%s'\n",
                 old_name, new_name);
        return -1;
    }
    return 0;
}

static const char *
dms_node_name (const char *name, const struct dm_ioctl *io)
{
    if (name && *name) return name;
    if (io && io->name[0]) return io->name;
    return NULL;
}

/* Resume adds the node (unless --addnodeoncreate). Remove drops it.
   Both no-op while udev owns nodes. */
static int
dms_nodes_after (const struct dms_opts *o, unsigned long req, uint32_t flags,
                 const char *name, const struct dm_ioctl *io)
{
    const char *node = dms_node_name (name, io);
    if (!node) return 0;
    if (req == DM_DEV_REMOVE)
        return dms_rm_node (o, node, 1);
    if (req == DM_DEV_SUSPEND && !(flags & DM_SUSPEND_FLAG) && !o->add_on_create)
        return dms_add_node (o, node, (dev_t) io->dev, 1);
    return 0;
}

static int
dms_uevent_simple (int fd, const struct dms_opts *o, unsigned long req, const char *name,
                   const char *uuid, uint32_t flags)
{
    int err;
    struct dm_ioctl *io = dms_run_uevent (fd, o, req, name, uuid, flags, NULL, 0, 1, &err);
    if (!io) return EXECUTION_FAILURE;
    int nodes = dms_nodes_after (o, req, flags, name, io);
    free (io);
    return nodes < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* Response iteration, bounded by the reported data_size. */
static const char *
dms_data (const struct dm_ioctl *io)
{
    return (const char *) io + io->data_start;
}

static const char *
dms_end (const struct dm_ioctl *io)
{
    return (const char *) io + io->data_size;
}

static int
dms_bad_response (const struct dm_ioctl *io, const char *what)
{
    fprintf (stderr, "dmsetup: malformed %s response from the kernel\n", what);
    (void) io;
    return -1;
}

/* Status replies use offsets from the data area (unlike TABLE_LOAD).
   Bound each string by its own record, and reject overlapping records before
   a caller prints parameters or uses lengths to build a replacement table.
   The last record may end before its alignment padding in data_size. */
static const struct dm_target_spec *
dms_target (const struct dm_ioctl *io, size_t off, uint32_t index, const char *what)
{
    size_t total = (size_t) (dms_end (io) - dms_data (io));
    if (off > total || total - off <= sizeof (struct dm_target_spec))
        goto bad;
    const struct dm_target_spec *ts = (const struct dm_target_spec *) (dms_data (io) + off);
    size_t stop = total;
    if (index + 1 < io->target_count) {
        if (ts->next <= off + sizeof *ts || ts->next >= total || (ts->next & 7U))
            goto bad;
        stop = ts->next;
    }
    if (!memchr (ts->target_type, '\0', sizeof ts->target_type)
        || !memchr (ts + 1, '\0', stop - off - sizeof *ts))
        goto bad;
    return ts;
bad:
    dms_bad_response (io, what);
    return NULL;
}

/* Walk DM_LIST_DEVICES records. cb returns nonzero to stop with failure. */
typedef int (*dms_name_cb) (int fd, const char *name, uint64_t dev, void *arg);

static int
dms_each_name (const struct dm_ioctl *io, int fd, dms_name_cb cb, void *arg, int *count)
{
    const char *p = dms_data (io), *end = dms_end (io);
    int rc = 0;
    *count = 0;
    if (p == end) return 0;  /* kernel's empty list has no payload */
    for (;;) {
        const struct dm_name_list *nl = (const struct dm_name_list *) p;
        if ((size_t) (end - p) < sizeof *nl) return dms_bad_response (io, "names");
        size_t span = (size_t) (end - p);
        if (nl->next) {
            if (nl->next < sizeof *nl || nl->next >= span || (nl->next & 7U))
                return dms_bad_response (io, "names");
            span = nl->next;
        }
        size_t room = span - offsetof (struct dm_name_list, name);
        if (!memchr (nl->name, '\0', room)) return dms_bad_response (io, "names");
        if (nl->dev == 0 && nl->next == 0 && nl->name[0] == '\0' && *count == 0)
            return 0;   /* the kernel's empty list is one zeroed record */
        ++*count;
        if (cb (fd, nl->name, nl->dev, arg)) rc = 1;
        if (nl->next == 0) break;
        p += nl->next;
    }
    return rc;
}

static struct dm_ioctl *
dms_list (int fd)
{
    int err;
    return dms_run (fd, DM_LIST_DEVICES, NULL, NULL, 0, NULL, 0, 1, 0, &err);
}

static void
dms_no_device (void)
{
    fputs ("Device does not exist.\n", stderr);
}

/* ---- table text parsing and DM_TABLE_LOAD construction ---- */

static size_t
dms_align8 (size_t n)
{
    return (n + 7U) & ~(size_t) 7U;
}

static int
dms_parse_u64 (const char **pp, unsigned long long *out)
{
    const char *p = *pp;
    if (*p < '0' || *p > '9') return -1;
    unsigned long long v = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned d = (unsigned) (*p - '0');
        if (v > (~0ULL - d) / 10) return -1;
        v = v * 10 + d;
        p++;
    }
    if (*p && *p != ' ' && *p != '\t') return -1;
    *out = v;
    *pp = p;
    return 0;
}

static void
dms_table_free (struct dms_table *t)
{
    for (size_t i = 0; i < t->n; i++) free (t->v[i].params);
    free (t->v);
    memset (t, 0, sizeof *t);
}

/* libdevmapper's dmsetup _parse_line: the line ends at its first NUL,
   surrounding white space and blank or '#' lines are skipped, the fields
   are read with sscanf ("%llu %llu %s %n", so a too-large number
   saturates and is left for the kernel to reject) and a '#' starts a
   comment in the parameters. */
static int
dms_table_line (struct dms_table *t, char *buf, const char *src, size_t lineno)
{
    size_t l = strlen (buf);
    while (l && isspace ((unsigned char) buf[l - 1])) buf[--l] = '\0';
    char *p = buf;
    while (*p && isspace ((unsigned char) *p)) p++;
    if (!*p || *p == '#') return 0;

    unsigned long long start, length;
    int used = 0;
    char *ttype = malloc (strlen (p) + 1);
    if (!ttype) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    if (sscanf (p, "%llu %llu %s %n", &start, &length, ttype, &used) < 3) {
        fprintf (stderr, "Invalid format on line %zu of table %s.\n", lineno, src);
        free (ttype);
        return -1;
    }
    p += used;
    char *comment = strchr (p, '#');
    if (comment) *comment = '\0';
    if (strlen (ttype) >= DM_MAX_TYPE_NAME) {
        fprintf (stderr, "Target type name %s is too long.\n", ttype);
        free (ttype);
        return -1;
    }
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 8;
        struct dms_spec *nv = realloc (t->v, cap * sizeof *nv);
        if (!nv) {
            fprintf (stderr, "dmsetup: out of memory\n");
            free (ttype);
            return -1;
        }
        t->v = nv;
        t->cap = cap;
    }
    struct dms_spec *sp = &t->v[t->n];
    memset (sp, 0, sizeof *sp);
    sp->start = start;
    sp->length = length;
    strcpy (sp->type, ttype);
    free (ttype);
    sp->params_len = strlen (p);
    if (!(sp->params = strdup (p))) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    t->n++;
    /* libdevmapper's _flatten: spec, parameters, NUL and alignment slack */
    t->alloc += sizeof (struct dm_target_spec) + sp->params_len + 1 + 8;
    return 0;
}

/* Lines of an in-memory table (--table or an inline argument). */
static int
dms_table_from_text (struct dms_table *t, char *text, const char *src)
{
    size_t lineno = 0;
    for (char *line = text; line; ) {
        char *nl = strchr (line, '\n');
        if (nl) *nl++ = '\0';
        if (dms_table_line (t, line, src, ++lineno) < 0) return -1;
        line = nl;
    }
    return 0;
}

/* Lines read from a descriptor, one at a time like getline(3), so comment
   padding costs no memory. A read error ends the table like EOF. */
static int
dms_table_from_fd (struct dms_table *t, int fd, const char *src)
{
    size_t cap = 4096, len = 0, lineno = 0;
    char *buf = malloc (cap);
    if (!buf) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    int rc = 0, eof = 0;
    size_t scan = 0;
    for (;;) {
        char *nl = memchr (buf + scan, '\n', len - scan);
        if (!nl && !eof) {
            scan = len;
            if (cap - len < 4096) {
                if (cap > SIZE_MAX / 2) { fprintf (stderr, "dmsetup: out of memory\n"); rc = -1; break; }
                char *nb = realloc (buf, cap * 2);
                if (!nb) { fprintf (stderr, "dmsetup: out of memory\n"); rc = -1; break; }
                buf = nb;
                cap *= 2;
            }
            ssize_t r = read (fd, buf + len, cap - len - 1);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) eof = 1;
            else len += (size_t) r;
            continue;
        }
        if (!nl && !len) break;
        size_t take = nl ? (size_t) (nl - buf) + 1 : len;
        char saved = buf[take];
        buf[take] = '\0';
        if (nl) *nl = '\0';
        rc = dms_table_line (t, buf, src, ++lineno);
        buf[take] = saved;
        if (rc < 0) break;
        memmove (buf, buf + take, len - take);
        len -= take;
        scan = 0;
    }
    free (buf);
    return rc;
}

/* Build the DM_TABLE_LOAD payload: specs back to back, each padded to 8
   bytes, `next` the distance from this spec to the following one. */
static int
dms_table_size (const struct dms_spec *specs, size_t n, size_t *len)
{
    size_t total = 0;
    for (size_t i = 0; i < n; i++) {
        size_t one = dms_align8 (sizeof (struct dm_target_spec) + specs[i].params_len + 1);
        if (one > DMS_MAX_BUF - sizeof (struct dm_ioctl)
            || total > DMS_MAX_BUF - sizeof (struct dm_ioctl) - one) {
            fprintf (stderr, "dmsetup: table too large\n");
            return -1;
        }
        total += one;
    }
    *len = total;
    return 0;
}

static char *
dms_table_payload (const struct dms_spec *specs, size_t n, size_t *len)
{
    size_t total;
    if (dms_table_size (specs, n, &total) < 0) return NULL;
    char *buf = calloc (1, total ? total : 1);
    if (!buf) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return NULL;
    }
    char *p = buf;
    for (size_t i = 0; i < n; i++) {
        size_t one = dms_align8 (sizeof (struct dm_target_spec) + specs[i].params_len + 1);
        struct dm_target_spec *ts = (struct dm_target_spec *) p;
        ts->sector_start = specs[i].start;
        ts->length = specs[i].length;
        ts->status = 0;
        ts->next = (uint32_t) one;
        memcpy (ts->target_type, specs[i].type, strlen (specs[i].type) + 1);
        memcpy (p + sizeof *ts, specs[i].params, specs[i].params_len + 1);
        p += one;
    }
    *len = total;
    return buf;
}

/* DM_TABLE_LOAD of the parsed table. With maj > 0 the request names the
   device by number alone, as libdevmapper's load inside create does; the
   name still appears in diagnostics. */
static int
dms_load_table (int fd, const char *name, const char *uuid, const struct dms_table *t,
                uint32_t flags, long maj, long min)
{
    if (t->alloc > DMS_MAX_ALLOC) {
        fprintf (stderr, "Huge memory allocation (size %zu) rejected - metadata corruption?\n",
                 t->alloc);
        fputs ("Couldn't create ioctl argument.\n", stderr);
        return EXECUTION_FAILURE;
    }
    size_t len = 0;
    char *payload = dms_table_payload (t->v, t->n, &len);
    if (!payload) return EXECUTION_FAILURE;
    if (maj > 0) {
        flags |= DM_PERSISTENT_DEV_FLAG;
        dms_req_by_dev (maj, min, 1);
    }
    struct dm_ioctl *io = dms_alloc (0, name, maj > 0 ? NULL : uuid, flags, payload, len);
    dms_req_clear ();
    free (payload);
    if (!io) return EXECUTION_FAILURE;
    io->target_count = (uint32_t) t->n;
    int rc = EXECUTION_SUCCESS;
    if (ioctl (fd, DM_TABLE_LOAD, io) < 0) {
        dms_report_dev (DM_TABLE_LOAD, flags, name, uuid, maj, min, errno);
        rc = EXECUTION_FAILURE;
    }
    free (io);
    return rc;
}

/* The table for create/load: --table, a table-file operand, or stdin when
   it is not a terminal. A positional operand is always a filename, including
   text that contains spaces. *have is 0 when none was supplied.
   Diagnostics name the source as libdevmapper does: "" for text,
   the file name, or "on stdin". */
static int
dms_read_table (const struct dms_opts *o, const char *arg, struct dms_table *t, int *have)
{
    memset (t, 0, sizeof *t);
    t->alloc = sizeof (struct dm_ioctl);
    *have = 1;
    const char *text = o->table;
    if (!text && arg) {
        int fd = open (arg, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf (stderr, "Couldn't open '%s' for reading.\n", arg);
            return -1;
        }
        int rc = dms_table_from_fd (t, fd, arg);
        close (fd);
        return rc;
    }
    if (text) {
        if (strlen (text) > DMS_MAX_TABLE) {
            fprintf (stderr, "dmsetup: table text exceeds %u bytes\n", DMS_MAX_TABLE);
            return -1;
        }
        char *copy = strdup (text);
        if (!copy) {
            fprintf (stderr, "dmsetup: out of memory\n");
            return -1;
        }
        int rc = dms_table_from_text (t, copy, "");
        free (copy);
        return rc;
    }
    if (!isatty (0)) return dms_table_from_fd (t, 0, "on stdin");
    *have = 0;
    return 0;
}

/* ---- queries ---- */

static int
dms_status_one (int fd, const char *name, const char *uuid, uint32_t flags, struct dm_ioctl **out)
{
    int err;
    *out = dms_run (fd, DM_DEV_STATUS, name, uuid, flags, NULL, 0, 0, 1, &err);
    if (!*out && err == ENXIO) dms_no_device ();
    return *out ? 0 : -1;
}

/* Read-ahead is in KiB in sysfs and 512-byte sectors in BLKRAGET. Like
   libdevmapper, sysfs first and the mapper node only when sysfs lacks it. */
static int
dms_read_ahead (dev_t dev, const char *name, unsigned long *sectors)
{
    char path[512], buf[64], *end;
    unsigned long kb;
    snprintf (path, sizeof path, "/sys/dev/block/%u:%u/bdi/read_ahead_kb",
              major (dev), minor (dev));
    if (dms_read_first_line (path, buf, sizeof buf) == 0) {
        errno = 0;
        kb = strtoul (buf, &end, 10);
        if (!errno && end != buf && *end == '\0' && kb <= ULONG_MAX / 2) {
            *sectors = kb * 2;
            return 0;
        }
        return -1;
    }
    /* Do not follow a response name outside the mapper directory or query a
       stale node that belongs to a different device. */
    if (!name[0] || strchr (name, '/')) return -1;
    if (snprintf (path, sizeof path, "/dev/mapper/%s", name) >= (int) sizeof path)
        return -1;
    int node = open (path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (node < 0) {
        /* libdevmapper's fallback reports the node it could not open */
        fprintf (stderr, "%s: open failed: %s\n", path, strerror (errno));
        return -1;
    }
    struct stat st;
    int rc = fstat (node, &st) == 0 && S_ISBLK (st.st_mode) && st.st_rdev == dev
        && ioctl (node, BLKRAGET, sectors) == 0 ? 0 : -1;
    close (node);
    return rc;
}

static int
dms_info_print (int fd, const char *name, const char *uuid)
{
    struct dm_ioctl *io;
    if (dms_status_one (fd, name, uuid, 0, &io) < 0) return EXECUTION_FAILURE;
    dev_t dev = (dev_t) io->dev;
    const char *tables = (io->flags & DM_ACTIVE_PRESENT_FLAG)
        ? ((io->flags & DM_INACTIVE_PRESENT_FLAG) ? "LIVE & INACTIVE" : "LIVE")
        : ((io->flags & DM_INACTIVE_PRESENT_FLAG) ? "INACTIVE" : "None");
    printf ("Name:              %s\n", io->name);
    printf ("State:             %s%s%s\n", (io->flags & DM_SUSPEND_FLAG) ? "SUSPENDED" : "ACTIVE",
            (io->flags & DM_READONLY_FLAG) ? " (READ-ONLY)" : "",
            (io->flags & DM_DEFERRED_REMOVE) ? " (DEFERRED REMOVE)" : "");
    unsigned long read_ahead;
    if (dms_read_ahead (dev, io->name, &read_ahead) == 0)
        printf ("Read Ahead:        %lu\n", read_ahead);
    printf ("Tables present:    %s\n", tables);
    printf ("Open count:        %d\n", io->open_count);
    printf ("Event number:      %u\n", io->event_nr);
    printf ("Major, minor:      %u, %u\n", major (dev), minor (dev));
    if (io->flags & DM_ACTIVE_PRESENT_FLAG)
        printf ("Number of targets: %u\n", io->target_count);
    if (io->uuid[0]) printf ("UUID: %s\n", io->uuid);
    putchar ('\n');
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_list_cb_info (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev; (void) arg;
    return dms_info_print (fd, name, NULL) != EXECUTION_SUCCESS;
}

/* Hide the key field of crypt table lines unless --showkeys. Keyring
   references (":size:type:desc") and "-" are not secrets and stay. */
static void
dms_print_params (const char *type, const char *params, int table_mode, int showkeys)
{
    if (!table_mode || showkeys || strcmp (type, "crypt") != 0) {
        fputs (params, stdout);
        return;
    }
    const char *k = strchr (params, ' ');
    if (!k) { fputs (params, stdout); return; }
    k++;
    size_t klen = strcspn (k, " ");
    fwrite (params, 1, (size_t) (k - params), stdout);
    if (klen && k[0] != ':' && strncmp (k, "-", klen) != 0)
        for (size_t i = 0; i < klen; i++) putchar ('0');
    else
        fwrite (k, 1, klen, stdout);
    fputs (k + klen, stdout);
}

struct dms_table_arg {
    int table_mode, prefix;
    const struct dms_opts *o;
    const char *uuid;
};

/* Fetch a device's table (or status) and print each target. With
   only_count set, return the number of targets of type o->target instead. */
static int
dms_table_print (int fd, const char *name, const struct dms_table_arg *a, int *only_count)
{
    int err;
    uint32_t flags = (a->table_mode ? DM_STATUS_TABLE_FLAG : 0)
        | (a->o->inactive ? DM_QUERY_INACTIVE_TABLE_FLAG : 0);
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_STATUS, name, a->uuid, flags, NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return EXECUTION_FAILURE;
    }

    size_t off = 0;
    int matched = 0, rc = EXECUTION_SUCCESS;
    for (uint32_t i = 0; i < io->target_count; i++) {
        const struct dm_target_spec *ts = dms_target (io, off, i, dms_cmd_name (DM_TABLE_STATUS, flags));
        if (!ts) {
            rc = EXECUTION_FAILURE;
            break;
        }
        const char *params = (const char *) (ts + 1);
        if (!a->o->target || !strcmp (a->o->target, ts->target_type)) {
            matched++;
            if (!only_count) {
                if (a->prefix) printf ("%s: ", name);
                printf ("%llu %llu %s ", (unsigned long long) ts->sector_start,
                        (unsigned long long) ts->length, ts->target_type);
                dms_print_params (ts->target_type, params, a->table_mode, a->o->showkeys);
                putchar ('\n');
            }
        }
        off = ts->next;
    }
    if (!only_count && a->prefix && io->target_count == 0 && !a->o->target)
        printf ("%s: \n", name);
    if (only_count) *only_count = matched;
    free (io);
    return rc;
}

static int
dms_list_cb_table (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev;
    return dms_table_print (fd, name, arg, NULL) != EXECUTION_SUCCESS;
}

static int
dms_deps_print (int fd, const char *name, const char *uuid, int prefix, int inactive)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_DEPS, name, uuid,
                                   inactive ? DM_QUERY_INACTIVE_TABLE_FLAG : 0,
                                   NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return EXECUTION_FAILURE;
    }
    const char *p = dms_data (io), *end = dms_end (io);
    /* No selected table: the kernel returns only the fixed header. */
    if (p == end && !(io->flags & (inactive ? DM_INACTIVE_PRESENT_FLAG : DM_ACTIVE_PRESENT_FLAG))) {
        if (prefix) printf ("%s: ", name);
        printf ("0 dependencies\t:\n");
        free (io);
        return EXECUTION_SUCCESS;
    }
    const struct dm_target_deps *deps = (const struct dm_target_deps *) p;
    if ((size_t) (end - p) < sizeof *deps
        || deps->count > ((size_t) (end - p) - sizeof *deps) / sizeof deps->dev[0]) {
        dms_bad_response (io, "deps");
        free (io);
        return EXECUTION_FAILURE;
    }
    if (prefix) printf ("%s: ", name);
    printf ("%u dependencies\t:", deps->count);
    for (uint32_t i = 0; i < deps->count; i++) {
        dev_t dev = (dev_t) deps->dev[i];
        printf (" (%u, %u)", major (dev), minor (dev));
    }
    putchar ('\n');
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_list_cb_deps (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev;
    return dms_deps_print (fd, name, NULL, 1, *(int *) arg) != EXECUTION_SUCCESS;
}

struct dms_ls_arg {
    const struct dms_opts *o;
    int failed;
};

static int
dms_list_cb_ls (int fd, const char *name, uint64_t dev, void *arg)
{
    struct dms_ls_arg *la = arg;
    if (la->o->target) {
        struct dms_table_arg ta = { 1, 0, la->o, NULL };
        int n = 0;
        if (dms_table_print (fd, name, &ta, &n) != EXECUTION_SUCCESS) {
            la->failed = 1;
            return 1;
        }
        if (n == 0) return 0;
    }
    printf (la->o->target ? "%s\t(%u, %u)\n" : "%s\t(%u:%u)\n",
            name, major ((dev_t) dev), minor ((dev_t) dev));
    return 0;
}

static int
dms_ls_tree (int fd);

static int
dms_ls_cmd (const struct dms_opts *o)
{
    int fd = dms_open_control (0);
    if (fd < 0) return EXECUTION_FAILURE;
    if (o->tree && !o->target) {
        int rc = dms_ls_tree (fd);
        close (fd);
        return rc;
    }
    struct dm_ioctl *io = dms_list (fd);
    int rc = EXECUTION_FAILURE, count = 0;
    if (io) {
        struct dms_ls_arg la = { o, 0 };
        int r = dms_each_name (io, fd, dms_list_cb_ls, &la, &count);
        if (r >= 0 && !la.failed) {
            rc = EXECUTION_SUCCESS;
            if (count == 0) printf ("No devices found\n");
        }
        free (io);
    }
    close (fd);
    return rc;
}

/* Run cb for every device the kernel lists. */
static int
dms_for_all (int fd, dms_name_cb cb, void *arg)
{
    struct dm_ioctl *io = dms_list (fd);
    if (!io) return EXECUTION_FAILURE;
    int count = 0;
    int r = dms_each_name (io, fd, cb, arg, &count);
    if (r == 0 && count == 0) printf ("No devices found\n");
    free (io);
    return r == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
dms_targets_cmd (int fd)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_LIST_VERSIONS, NULL, NULL, 0, NULL, 0, 1, 0, &err);
    if (!io) return EXECUTION_FAILURE;
    const char *p = dms_data (io), *end = dms_end (io);
    int rc = EXECUTION_SUCCESS;
    while (p < end) {
        if ((size_t) (end - p) <= sizeof (struct dm_target_versions)) {
            dms_bad_response (io, "versions");
            rc = EXECUTION_FAILURE;
            break;
        }
        const struct dm_target_versions *tv = (const struct dm_target_versions *) p;
        size_t span = (size_t) (end - p);
        if (tv->next) {
            if (tv->next <= sizeof *tv || tv->next >= span || (tv->next & 7U)) {
                dms_bad_response (io, "versions");
                rc = EXECUTION_FAILURE;
                break;
            }
            span = tv->next;
        }
        if (!memchr (tv->name, '\0', span - offsetof (struct dm_target_versions, name))) {
            dms_bad_response (io, "versions");
            rc = EXECUTION_FAILURE;
            break;
        }
        if (tv->name[0])
            printf ("%-16s v%u.%u.%u\n", tv->name, tv->version[0], tv->version[1], tv->version[2]);
        if (tv->next == 0) break;
        p += tv->next;
    }
    free (io);
    return rc;
}

/* The library line names this implementation; the driver line needs the
   control node, and without it the command fails as libdevmapper's does. */
static int
dms_version_cmd (void)
{
    printf ("Library version:   %s\n", DMS_LIBRARY_VERSION);
    int fd = dms_open_control (0);
    if (fd < 0) return EXECUTION_FAILURE;
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_VERSION, NULL, NULL, 0, NULL, 0, 0, 0, &err);
    close (fd);
    if (!io) return EXECUTION_FAILURE;
    printf ("Driver version:    %u.%u.%u\n", io->version[0], io->version[1], io->version[2]);
    free (io);
    return EXECUTION_SUCCESS;
}

/* ---- device snapshots for reports and the tree ---- */

struct dms_dev {
    char name[DM_NAME_LEN], uuid[DM_UUID_LEN];
    uint32_t flags, open_count, target_count, event_nr;
    uint64_t dev;
    int deps_ok;
    uint32_t ndeps;
    uint64_t *deps;
};

struct dms_devset {
    struct dms_dev *v;
    size_t n, cap;
    int loaded;
};

static void
dms_dev_free (struct dms_dev *d)
{
    free (d->deps);
    d->deps = NULL;
    d->ndeps = 0;
    d->deps_ok = 0;
}

static void
dms_devset_free (struct dms_devset *s)
{
    for (size_t i = 0; i < s->n; i++) dms_dev_free (&s->v[i]);
    free (s->v);
    memset (s, 0, sizeof *s);
}

/* DM_DEV_STATUS of one device. Returns 1 when it exists, 0 when the kernel
   reports no such device, -1 on another failure (already reported). */
static int
dms_dev_status (int fd, const char *name, const char *uuid, struct dms_dev *d)
{
    int err;
    memset (d, 0, sizeof *d);
    struct dm_ioctl *io = dms_run (fd, DM_DEV_STATUS, name, uuid, 0, NULL, 0, 0, 1, &err);
    if (!io) return err == ENXIO ? 0 : -1;
    snprintf (d->name, sizeof d->name, "%s", io->name);
    snprintf (d->uuid, sizeof d->uuid, "%s", io->uuid);
    d->flags = io->flags;
    d->open_count = (uint32_t) io->open_count;
    d->target_count = io->target_count;
    d->event_nr = io->event_nr;
    d->dev = io->dev;
    free (io);
    return 1;
}

/* Live-table dependencies (device numbers), as DM_TABLE_DEPS returns them. */
static int
dms_dev_deps (int fd, struct dms_dev *d)
{
    if (d->deps_ok) return 0;
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_DEPS, d->name, NULL, 0, NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return -1;
    }
    const char *p = dms_data (io), *end = dms_end (io);
    d->ndeps = 0;
    if (p != end) {
        const struct dm_target_deps *deps = (const struct dm_target_deps *) p;
        if ((size_t) (end - p) < sizeof *deps
            || deps->count > ((size_t) (end - p) - sizeof *deps) / sizeof deps->dev[0]) {
            dms_bad_response (io, "deps");
            free (io);
            return -1;
        }
        if (deps->count) {
            d->deps = calloc (deps->count, sizeof *d->deps);
            if (!d->deps) {
                fprintf (stderr, "dmsetup: out of memory\n");
                free (io);
                return -1;
            }
            memcpy (d->deps, deps->dev, deps->count * sizeof *d->deps);
        }
        d->ndeps = deps->count;
    }
    d->deps_ok = 1;
    free (io);
    return 0;
}

struct dms_collect {
    struct dms_devset *set;
    int failed;
};

static int
dms_collect_cb (int fd, const char *name, uint64_t dev, void *arg)
{
    struct dms_collect *c = arg;
    (void) dev;
    struct dms_devset *s = c->set;
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 16;
        struct dms_dev *nv = realloc (s->v, cap * sizeof *nv);
        if (!nv) {
            fprintf (stderr, "dmsetup: out of memory\n");
            c->failed = 1;
            return 1;
        }
        s->v = nv;
        s->cap = cap;
    }
    struct dms_dev *d = &s->v[s->n];
    int r = dms_dev_status (fd, name, NULL, d);
    if (r == 0) return 0;               /* removed while listing */
    if (r < 0 || dms_dev_deps (fd, d) < 0) {
        dms_dev_free (d);
        c->failed = 1;
        return 1;
    }
    s->n++;
    return 0;
}

/* Every device with its status and dependencies, in the kernel's order. */
static int
dms_devset_load (int fd, struct dms_devset *s)
{
    if (s->loaded) return 0;
    struct dm_ioctl *io = dms_list (fd);
    if (!io) return -1;
    struct dms_collect c = { s, 0 };
    int count = 0;
    int r = dms_each_name (io, fd, dms_collect_cb, &c, &count);
    free (io);
    if (r < 0 || c.failed) return -1;
    s->loaded = 1;
    return 0;
}

static const struct dms_dev *
dms_devset_find (const struct dms_devset *s, uint64_t dev)
{
    for (size_t i = 0; i < s->n; i++)
        if (s->v[i].dev == dev) return &s->v[i];
    return NULL;
}

static int
dms_devset_uses (const struct dms_dev *parent, uint64_t dev)
{
    for (uint32_t i = 0; i < parent->ndeps; i++)
        if (parent->deps[i] == dev) return 1;
    return 0;
}

/* ---- ls --tree ---- */

#define DMS_TREE_MAX 64

/* dmsetup draws with UTF-8 line characters in a UTF-8 locale, else ASCII. */
static const char *dms_tree_sym[2][3] = {
    { "|  ", "`-", "|-" },
    { "\342\224\202  ", "\342\224\224\342\224\200", "\342\224\234\342\224\200" },
};

static void
dms_tree_node (const struct dms_devset *s, uint64_t dev, int depth, int last, unsigned char *more)
{
    const struct dms_dev *d = dms_devset_find (s, dev);
    const char *codeset = nl_langinfo (CODESET);
    const char *const *sym = dms_tree_sym[codeset && !strcmp (codeset, "UTF-8")];
    if (depth) {
        putchar (' ');
        for (int i = 1; i < depth; i++) fputs (more[i] ? sym[0] : "   ", stdout);
        fputs (last ? sym[1] : sym[2], stdout);
    }
    printf ("%s (%u:%u)\n", d ? d->name : "", major ((dev_t) dev), minor ((dev_t) dev));
    if (!d || depth + 1 >= DMS_TREE_MAX) return;
    more[depth] = !last;
    for (uint32_t i = 0; i < d->ndeps; i++)
        dms_tree_node (s, d->deps[i], depth + 1, i + 1 == d->ndeps, more);
}

/* dmsetup's default tree: each mapped device no other mapped device uses,
   then what it uses, down to the underlying block devices. */
static int
dms_ls_tree (int fd)
{
    struct dms_devset s;
    memset (&s, 0, sizeof s);
    if (dms_devset_load (fd, &s) < 0) {
        dms_devset_free (&s);
        return EXECUTION_FAILURE;
    }
    if (s.n == 0) printf ("No devices found\n");
    unsigned char more[DMS_TREE_MAX] = { 0 };
    for (size_t i = 0; i < s.n; i++) {
        int used = 0;
        for (size_t j = 0; j < s.n && !used; j++)
            if (j != i && dms_devset_uses (&s.v[j], s.v[i].dev)) used = 1;
        if (!used) dms_tree_node (&s, s.v[i].dev, 0, 1, more);
    }
    dms_devset_free (&s);
    return EXECUTION_SUCCESS;
}

/* ---- info -c: libdevmapper's report fields, options, sorting, selection ---- */

enum {
    RF_NAME, RF_MANGLED_NAME, RF_UNMANGLED_NAME, RF_UUID, RF_MANGLED_UUID, RF_UNMANGLED_UUID,
    RF_READ_AHEAD, RF_BLKDEVNAME, RF_ATTR, RF_TABLES, RF_SUSPENDED, RF_READONLY, RF_DEVNO,
    RF_MAJOR, RF_MINOR, RF_OPEN, RF_SEGMENTS, RF_EVENTS, RF_DEVICE_COUNT, RF_DEVS_USED,
    RF_DEVNOS_USED, RF_BLKDEVS_USED, RF_REF_COUNT, RF_NAMES_USING, RF_DEVNOS_USING,
    RF_UNSUPPORTED, RF_HELP
};

struct dms_rfield {
    const char *id, *head;
    unsigned char width, num, section, kind;
    const char *desc;
};

static const char *const dms_rsection[][2] = {
    { "Mapped Device Name", "name_" },
    { "Mapped Device Information", "info_" },
    { "Mapped Device Relationship Information", "deps_" },
    { "Mapped Device Name Components", "splitname_" },
    { "Mapped Device Statistics", "stats_" },
    { "Mapped Device Statistics Region Information", "region_" },
    { "Special", "" },
};
#define DMS_SEC_SPECIAL 6

#define U RF_UNSUPPORTED
static const struct dms_rfield dms_rfields[] = {
    { "name", "Name", 16, 0, 0, RF_NAME, "Name of mapped device." },
    { "mangled_name", "MangledName", 16, 0, 0, RF_MANGLED_NAME, "Mangled name of mapped device." },
    { "unmangled_name", "UnmangledName", 16, 0, 0, RF_UNMANGLED_NAME, "Unmangled name of mapped device." },
    { "uuid", "UUID", 32, 0, 0, RF_UUID, "Unique (optional) identifier for mapped device." },
    { "mangled_uuid", "MangledUUID", 32, 0, 0, RF_MANGLED_UUID, "Mangled unique (optional) identifier for mapped device." },
    { "unmangled_uuid", "UnmangledUUID", 32, 0, 0, RF_UNMANGLED_UUID, "Unmangled unique (optional) identifier for mapped device." },
    { "read_ahead", "RAhead", 6, 1, 0, RF_READ_AHEAD, "Read ahead value." },
    { "blkdevname", "BlkDevName", 16, 0, 1, RF_BLKDEVNAME, "Name of block device." },
    { "attr", "Stat", 4, 0, 1, RF_ATTR, "(L)ive, (I)nactive, (s)uspended, (r)ead-only, read-(w)rite." },
    { "tables_loaded", "Tables", 6, 0, 1, RF_TABLES, "Which of the live and inactive table slots are filled." },
    { "suspended", "Suspended", 9, 0, 1, RF_SUSPENDED, "Whether the device is suspended." },
    { "readonly", "Read-only", 9, 0, 1, RF_READONLY, "Whether the device is read-only or writeable." },
    { "devno", "DevNo", 5, 0, 1, RF_DEVNO, "Device major and minor numbers" },
    { "major", "Maj", 3, 1, 1, RF_MAJOR, "Block device major number." },
    { "minor", "Min", 3, 1, 1, RF_MINOR, "Block device minor number." },
    { "open", "Open", 4, 1, 1, RF_OPEN, "Number of references to open device, if requested." },
    { "segments", "Targ", 4, 1, 1, RF_SEGMENTS, "Number of segments in live table, if present." },
    { "events", "Event", 6, 1, 1, RF_EVENTS, "Number of most recent event." },
    { "device_count", "#Devs", 5, 1, 2, RF_DEVICE_COUNT, "Number of devices used by this one." },
    { "devs_used", "DevNamesUsed", 16, 0, 2, RF_DEVS_USED, "List of names of mapped devices used by this one." },
    { "devnos_used", "DevNosUsed", 16, 0, 2, RF_DEVNOS_USED, "List of device numbers of devices used by this one." },
    { "blkdevs_used", "BlkDevNamesUsed", 16, 0, 2, RF_BLKDEVS_USED, "List of names of block devices used by this one." },
    { "device_ref_count", "#Refs", 5, 1, 2, RF_REF_COUNT, "Number of mapped devices referencing this one." },
    { "names_using_dev", "RefNames", 8, 0, 2, RF_NAMES_USING, "List of names of mapped devices using this one." },
    { "devnos_using_dev", "RefDevNos", 9, 0, 2, RF_DEVNOS_USING, "List of device numbers of mapped devices using this one." },
    { "subsystem", "Subsys", 6, 0, 3, U, "Userspace subsystem responsible for this device." },
    { "vg_name", "VG", 4, 0, 3, U, "LVM Volume Group name." },
    { "lv_name", "LV", 4, 0, 3, U, "LVM Logical Volume name." },
    { "lv_layer", "LVLayer", 7, 0, 3, U, "LVM device layer." },
    { "read_count", "Reads", 5, 1, 4, U, "Count of reads completed." },
    { "reads_merged_count", "RdMrges", 5, 1, 4, U, "Count of read requests merged." },
    { "read_sector_count", "RdSectors", 5, 1, 4, U, "Count of sectors read." },
    { "read_time", "RdTime", 5, 1, 4, U, "Accumulated duration of all read requests (ns)." },
    { "write_count", "Writes", 5, 1, 4, U, "Count of writes completed." },
    { "writes_merged_count", "WrMerges", 5, 1, 4, U, "Count of write requests merged." },
    { "write_sector_count", "WrSectors", 5, 1, 4, U, "Count of sectors written." },
    { "write_time", "WrTime", 5, 1, 4, U, "Accumulated duration of all writes (ns)." },
    { "in_progress_count", "InProgress", 5, 1, 4, U, "Count of requests currently in progress." },
    { "io_ticks", "IoTicks", 5, 1, 4, U, "Nanoseconds spent servicing requests." },
    { "queue_ticks", "QueueTicks", 5, 1, 4, U, "Total nanoseconds spent in queue." },
    { "read_ticks", "RdTicks", 5, 1, 4, U, "Nanoseconds spent servicing reads." },
    { "write_ticks", "WrTicks", 5, 1, 4, U, "Nanoseconds spent servicing writes." },
    { "reads_merged_per_sec", "RMrg/s", 5, 1, 4, U, "Read requests merged per second." },
    { "writes_merged_per_sec", "WMrg/s", 5, 1, 4, U, "Write requests merged per second." },
    { "reads_per_sec", "R/s", 5, 1, 4, U, "Reads per second." },
    { "writes_per_sec", "W/s", 5, 1, 4, U, "Writes per second." },
    { "read_size_per_sec", "RSz/s", 5, 1, 4, U, "Size of data read per second." },
    { "write_size_per_sec", "WSz/s", 5, 1, 4, U, "Size of data written per second." },
    { "avg_request_size", "AvgRqSz", 5, 1, 4, U, "Average request size." },
    { "queue_size", "QSize", 5, 1, 4, U, "Average queue size." },
    { "await", "AWait", 5, 1, 4, U, "Average wait time." },
    { "read_await", "RdAWait", 5, 1, 4, U, "Average read wait time." },
    { "write_await", "WrAWait", 5, 1, 4, U, "Average write wait time." },
    { "throughput", "Throughput", 5, 1, 4, U, "Throughput." },
    { "service_time", "SvcTm", 5, 1, 4, U, "Service time." },
    { "util", "Util%", 5, 1, 4, U, "Utilization." },
    { "hist_count", "#Histogram Counts", 5, 0, 4, U, "Latency histogram counts." },
    { "hist_count_bounds", "Histogram Counts", 5, 0, 4, U, "Latency histogram counts with bin boundaries." },
    { "hist_count_ranges", "Histogram Counts", 5, 0, 4, U, "Latency histogram counts with bin ranges." },
    { "hist_percent", "Histogram", 5, 0, 4, U, "Relative latency histogram." },
    { "hist_percent_bounds", "Histogram", 5, 0, 4, U, "Relative latency histogram with bin boundaries." },
    { "hist_percent_ranges", "Histogram", 5, 0, 4, U, "Relative latency histogram with bin ranges." },
    { "interval_ns", "IntervalNSec", 5, 1, 4, U, "Sampling interval in nanoseconds." },
    { "interval", "Interval", 5, 0, 4, U, "Sampling interval." },
    { "region_id", "RgID", 4, 1, 5, U, "Region ID." },
    { "region_start", "RgStart", 5, 1, 5, U, "Region start." },
    { "region_len", "RSize", 5, 1, 5, U, "Region length." },
    { "area_id", "ArID", 4, 1, 5, U, "Area ID." },
    { "area_start", "ArStart", 5, 1, 5, U, "Area offset from start of device." },
    { "area_len", "ASize", 5, 1, 5, U, "Area length." },
    { "area_offset", "ArOff", 5, 1, 5, U, "Area offset from start of region." },
    { "area_count", "#Areas", 5, 1, 5, U, "Area count." },
    { "group_id", "GrpID", 5, 1, 5, U, "Group ID." },
    { "program_id", "ProgID", 6, 0, 5, U, "Program ID." },
    { "user_data", "UserData", 8, 0, 5, U, "Auxiliary data." },
    { "precise", "Precise", 7, 0, 5, U, "Set if nanosecond precision counters are enabled." },
    { "hist_bins", "#Bins", 5, 1, 5, U, "The number of histogram bins configured." },
    { "hist_bounds", "Histogram Bounds", 5, 0, 5, U, "Latency histogram bin boundaries." },
    { "hist_ranges", "Histogram Ranges", 5, 0, 5, U, "Latency histogram bin ranges." },
    { "stats_name", "StatsName", 9, 0, 5, U, "Stats name of current object." },
    { "obj_type", "ObjType", 7, 0, 5, U, "Type of stats object being reported." },
    { "selected", "Selected", 8, 1, DMS_SEC_SPECIAL, U, "Set if item passes selection criteria." },
    { "help", "Help", 4, 0, DMS_SEC_SPECIAL, RF_HELP, "Show help." },
    { "?", "?", 1, 0, DMS_SEC_SPECIAL, RF_HELP, "Show help." },
};
#undef U
#define DMS_NFIELDS (sizeof dms_rfields / sizeof dms_rfields[0])

/* libdevmapper's field listing (for "help", "?" and unknown fields). */
static void
dms_report_help (void)
{
    size_t id_len = 0;
    for (size_t f = 0; f < DMS_NFIELDS; f++)
        if (strlen (dms_rfields[f].id) > id_len) id_len = strlen (dms_rfields[f].id);
    for (size_t t = 0; t < DMS_SEC_SPECIAL; t++)
        if (strlen (dms_rsection[t][1]) + 3 > id_len) id_len = strlen (dms_rsection[t][1]) + 3;
    int last = -1;
    for (size_t f = 0; f < DMS_NFIELDS; f++) {
        int sec = dms_rfields[f].section;
        if (sec != last) {
            if (last >= 0) fputs (" \n", stderr);
            const char *desc = dms_rsection[sec][0];
            fprintf (stderr, "%s Fields\n", desc);
            for (size_t i = 0; i < strlen (desc) + 7; i++) fputc ('-', stderr);
            fputc ('\n', stderr);
            if (sec != DMS_SEC_SPECIAL)
                fprintf (stderr, "  %sall%-*s - %s\n", dms_rsection[sec][1],
                         (int) (id_len - 3 - strlen (dms_rsection[sec][1])), "",
                         "All fields in this section.");
            last = sec;
        }
        fprintf (stderr, "  %-*s - %s\n", (int) id_len, dms_rfields[f].id, dms_rfields[f].desc);
    }
}

/* A field name: its id, optionally with its section prefix, any case. */
static int
dms_field_lookup (const char *w, size_t len)
{
    for (size_t f = 0; f < DMS_NFIELDS; f++) {
        const char *id = dms_rfields[f].id, *pre = dms_rsection[dms_rfields[f].section][1];
        size_t il = strlen (id), pl = strlen (pre);
        if (len == il && !strncasecmp (w, id, len)) return (int) f;
        if (pl && len == pl + il && !strncasecmp (w, pre, pl) && !strncasecmp (w + pl, id, il))
            return (int) f;
    }
    return -1;
}

static int
dms_section_all (const char *w, size_t len)
{
    for (int t = 0; t < DMS_SEC_SPECIAL; t++) {
        const char *pre = dms_rsection[t][1];
        size_t pl = strlen (pre);
        if (len == pl + 3 && !strncasecmp (w, pre, pl) && !strncasecmp (w + pl, "all", 3)) return t;
    }
    return -1;
}

struct dms_rspec {
    int fields[256], nfields;
    int keys[32], desc[32], nkeys;
    struct dms_sel *sel;
    const char *sep;
    int aligned, headings;
    int need_deps, need_set;
};

static int
dms_unrecognised (const char *what, const char *w, size_t len)
{
    dms_report_help ();
    fputs (" \n", stderr);
    fprintf (stderr, "Unrecognised %s: %.*s\n", what, (int) len, w);
    return -1;
}

static int
dms_field_unsupported (int f)
{
    fprintf (stderr, "dmsetup: report field %s is not supported by this implementation\n",
             dms_rfields[f].id);
    return -1;
}

static int
dms_note_field (struct dms_rspec *r, int f)
{
    if (dms_rfields[f].kind == RF_UNSUPPORTED) return dms_field_unsupported (f);
    if (dms_rfields[f].section == 2) r->need_deps = 1;
    if (dms_rfields[f].kind == RF_DEVS_USED || dms_rfields[f].kind >= RF_REF_COUNT) r->need_set = 1;
    return 0;
}

/* -o list. Returns 0, 1 when help was shown, -1 on error. */
static int
dms_parse_fields (struct dms_rspec *r, const char *spec)
{
    for (const char *p = spec; *p; ) {
        while (*p == ',' || isspace ((unsigned char) *p)) p++;
        if (!*p) break;
        const char *w = p;
        while (*p && *p != ',' && !isspace ((unsigned char) *p)) p++;
        size_t len = (size_t) (p - w);
        int t = dms_section_all (w, len);
        if (t >= 0) {
            for (size_t f = 0; f < DMS_NFIELDS; f++)
                if (dms_rfields[f].section == t) {
                    if (dms_note_field (r, (int) f) < 0) return -1;
                    if (r->nfields < 256) r->fields[r->nfields++] = (int) f;
                }
            continue;
        }
        int f = dms_field_lookup (w, len);
        if (f < 0) return dms_unrecognised ("field", w, len);
        if (dms_rfields[f].kind == RF_HELP) {
            dms_report_help ();
            return 1;
        }
        if (dms_note_field (r, f) < 0) return -1;
        if (r->nfields < 256) r->fields[r->nfields++] = f;
    }
    return 0;
}

static int
dms_parse_sort (struct dms_rspec *r, const char *spec)
{
    for (const char *p = spec; *p; ) {
        while (*p == ',' || isspace ((unsigned char) *p)) p++;
        if (!*p) break;
        int desc = 0;
        if (*p == '+' || *p == '-') desc = *p++ == '-';
        const char *w = p;
        while (*p && *p != ',' && !isspace ((unsigned char) *p)) p++;
        size_t len = (size_t) (p - w);
        int f = dms_field_lookup (w, len);
        if (f < 0 || dms_rfields[f].kind == RF_HELP) return dms_unrecognised ("field", w, len);
        if (dms_note_field (r, f) < 0) return -1;
        if (r->nkeys < 32) {
            r->keys[r->nkeys] = f;
            r->desc[r->nkeys++] = desc;
        }
    }
    return 0;
}

/* Selection: comparisons (= != =~ !~ < <= > >=) joined by && (or ,) and
   || (or #), with ! and parentheses. */
enum { SEL_CMP, SEL_AND, SEL_OR, SEL_NOT };

struct dms_sel {
    int kind, field, op;
    char *value;
    long long num;
    regex_t re;
    int has_re;
    struct dms_sel *a, *b;
};

static void
dms_sel_free (struct dms_sel *s)
{
    if (!s) return;
    dms_sel_free (s->a);
    dms_sel_free (s->b);
    if (s->has_re) regfree (&s->re);
    free (s->value);
    free (s);
}

struct dms_selp {
    const char *p, *start;
    struct dms_rspec *r;
    int err;
};

static void
dms_sel_space (struct dms_selp *sp)
{
    while (isspace ((unsigned char) *sp->p)) sp->p++;
}

static struct dms_sel *dms_sel_or (struct dms_selp *sp);

static struct dms_sel *
dms_sel_syntax (struct dms_selp *sp)
{
    if (!sp->err) fprintf (stderr, "Selection syntax error at '%s'.\n", sp->p);
    sp->err = 1;
    return NULL;
}

static struct dms_sel *
dms_sel_new (int kind)
{
    struct dms_sel *s = calloc (1, sizeof *s);
    if (!s) fprintf (stderr, "dmsetup: out of memory\n");
    if (s) s->kind = kind;
    return s;
}

static struct dms_sel *
dms_sel_cmp (struct dms_selp *sp)
{
    dms_sel_space (sp);
    const char *w = sp->p;
    while (isalnum ((unsigned char) *sp->p) || *sp->p == '_') sp->p++;
    size_t len = (size_t) (sp->p - w);
    if (!len) return dms_sel_syntax (sp);
    int f = dms_field_lookup (w, len);
    if (f < 0 || dms_rfields[f].kind == RF_HELP) {
        dms_unrecognised ("selection field", w, len);
        sp->err = 1;
        return NULL;
    }
    if (dms_note_field (sp->r, f) < 0) {
        sp->err = 1;
        return NULL;
    }
    dms_sel_space (sp);
    static const char *const ops[] = { "=~", "!~", "!=", "==", "<=", ">=", "=", "<", ">", NULL };
    int op = -1;
    for (int i = 0; ops[i]; i++)
        if (!strncmp (sp->p, ops[i], strlen (ops[i]))) {
            op = i;
            sp->p += strlen (ops[i]);
            break;
        }
    if (op < 0) return dms_sel_syntax (sp);
    if (op == 3) op = 6;                /* "==" is "=" */
    dms_sel_space (sp);
    const char *v = sp->p;
    size_t vl;
    if (*v == '"' || *v == '\'') {
        const char *q = strchr (v + 1, *v);
        if (!q) return dms_sel_syntax (sp);
        v++;
        vl = (size_t) (q - v);
        sp->p = q + 1;
    } else {
        while (*sp->p && !isspace ((unsigned char) *sp->p) && *sp->p != ')' && *sp->p != ','
               && *sp->p != '#' && strncmp (sp->p, "&&", 2) && strncmp (sp->p, "||", 2))
            sp->p++;
        vl = (size_t) (sp->p - v);
    }
    struct dms_sel *s = dms_sel_new (SEL_CMP);
    if (!s) { sp->err = 1; return NULL; }
    s->field = f;
    s->op = op;
    s->value = strndup (v, vl);
    if (!s->value) { free (s); sp->err = 1; return NULL; }
    if (op == 0 || op == 1) {
        if (regcomp (&s->re, s->value, REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf (stderr, "Failed to parse regex: %s\n", s->value);
            dms_sel_free (s);
            sp->err = 1;
            return NULL;
        }
        s->has_re = 1;
    } else if (dms_rfields[f].num) {
        char *end;
        errno = 0;
        s->num = strtoll (s->value, &end, 10);
        if (errno || end == s->value || *end) {
            fprintf (stderr, "Failed to parse numeric value \"%s\" for field %s.\n",
                     s->value, dms_rfields[f].id);
            dms_sel_free (s);
            sp->err = 1;
            return NULL;
        }
    }
    return s;
}

static struct dms_sel *
dms_sel_unary (struct dms_selp *sp)
{
    dms_sel_space (sp);
    if (*sp->p == '!' && sp->p[1] != '=' && sp->p[1] != '~') {
        sp->p++;
        struct dms_sel *a = dms_sel_unary (sp);
        if (!a) return NULL;
        struct dms_sel *s = dms_sel_new (SEL_NOT);
        if (!s) { dms_sel_free (a); sp->err = 1; return NULL; }
        s->a = a;
        return s;
    }
    if (*sp->p == '(') {
        sp->p++;
        struct dms_sel *a = dms_sel_or (sp);
        if (!a) return NULL;
        dms_sel_space (sp);
        if (*sp->p != ')') { dms_sel_free (a); return dms_sel_syntax (sp); }
        sp->p++;
        return a;
    }
    return dms_sel_cmp (sp);
}

static struct dms_sel *
dms_sel_and (struct dms_selp *sp)
{
    struct dms_sel *a = dms_sel_unary (sp);
    while (a) {
        dms_sel_space (sp);
        if (!strncmp (sp->p, "&&", 2)) sp->p += 2;
        else if (*sp->p == ',') sp->p++;
        else break;
        struct dms_sel *b = dms_sel_unary (sp);
        if (!b) { dms_sel_free (a); return NULL; }
        struct dms_sel *s = dms_sel_new (SEL_AND);
        if (!s) { dms_sel_free (a); dms_sel_free (b); sp->err = 1; return NULL; }
        s->a = a;
        s->b = b;
        a = s;
    }
    return a;
}

static struct dms_sel *
dms_sel_or (struct dms_selp *sp)
{
    struct dms_sel *a = dms_sel_and (sp);
    while (a) {
        dms_sel_space (sp);
        if (!strncmp (sp->p, "||", 2)) sp->p += 2;
        else if (*sp->p == '#') sp->p++;
        else break;
        struct dms_sel *b = dms_sel_and (sp);
        if (!b) { dms_sel_free (a); return NULL; }
        struct dms_sel *s = dms_sel_new (SEL_OR);
        if (!s) { dms_sel_free (a); dms_sel_free (b); sp->err = 1; return NULL; }
        s->a = a;
        s->b = b;
        a = s;
    }
    return a;
}

static int
dms_parse_select (struct dms_rspec *r, const char *spec)
{
    struct dms_selp sp = { spec, spec, r, 0 };
    dms_sel_space (&sp);
    if (!*sp.p) return 0;
    r->sel = dms_sel_or (&sp);
    if (!r->sel) return -1;
    dms_sel_space (&sp);
    if (*sp.p) {
        dms_sel_syntax (&sp);
        dms_sel_free (r->sel);
        r->sel = NULL;
        return -1;
    }
    return 0;
}

/* libdevmapper's default name mangling: characters outside its whitelist
   become \xNN; unmangling decodes those sequences. */
static void
dms_mangle (const char *in, char *out, size_t n, int unmangle)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 5 < n; p++) {
        unsigned c = (unsigned char) *p;
        if (unmangle) {
            unsigned v;
            if (p[0] == '\\' && p[1] == 'x' && sscanf (p + 2, "%2x", &v) == 1
                && isxdigit ((unsigned char) p[2]) && isxdigit ((unsigned char) p[3])) {
                out[o++] = (char) v;
                p += 3;
            } else
                out[o++] = (char) c;
        } else if (isalnum (c) || strchr ("#+-.:=@_", (int) c))
            out[o++] = (char) c;
        else
            o += (size_t) snprintf (out + o, n - o, "\\x%02x", c);
    }
    out[o] = '\0';
}

/* The kernel's name of a block device, from its sysfs link. */
static int
dms_blkdev_name (uint64_t dev, char *buf, size_t n)
{
    char path[128], link[PATH_MAX];
    snprintf (path, sizeof path, "/sys/dev/block/%u:%u", major ((dev_t) dev), minor ((dev_t) dev));
    ssize_t l = readlink (path, link, sizeof link - 1);
    if (l <= 0) {
        fprintf (stderr, "Could not resolve block device name for %u:%u.\n",
                 major ((dev_t) dev), minor ((dev_t) dev));
        return -1;
    }
    link[l] = '\0';
    const char *b = strrchr (link, '/');
    snprintf (buf, n, "%s", b ? b + 1 : link);
    return 0;
}

/* Append to a growing comma-separated list. */
static void
dms_list_add (char **buf, size_t *len, const char *item)
{
    size_t il = strlen (item);
    char *nb = realloc (*buf, *len + il + 2);
    if (!nb) return;
    if (*len) nb[(*len)++] = ',';
    memcpy (nb + *len, item, il + 1);
    *len += il;
    *buf = nb;
}

/* The value of field f for device d, as text (malloc'd) and, for number
   fields, as *num. */
static char *
dms_field_value (int f, const struct dms_dev *d, const struct dms_devset *set, long long *num)
{
    char buf[PATH_MAX];
    char *list = NULL;
    size_t llen = 0;
    long long v = 0;
    buf[0] = '\0';
    switch (dms_rfields[f].kind) {
    case RF_NAME: snprintf (buf, sizeof buf, "%s", d->name); break;
    case RF_MANGLED_NAME: dms_mangle (d->name, buf, sizeof buf, 0); break;
    case RF_UNMANGLED_NAME: dms_mangle (d->name, buf, sizeof buf, 1); break;
    case RF_UUID: snprintf (buf, sizeof buf, "%s", d->uuid); break;
    case RF_MANGLED_UUID: dms_mangle (d->uuid, buf, sizeof buf, 0); break;
    case RF_UNMANGLED_UUID: dms_mangle (d->uuid, buf, sizeof buf, 1); break;
    case RF_READ_AHEAD: {
        unsigned long ra = 0;
        if (dms_read_ahead ((dev_t) d->dev, d->name, &ra) < 0) ra = 0;
        v = (long long) ra;
        break;
    }
    case RF_BLKDEVNAME:
        if (dms_blkdev_name (d->dev, buf, sizeof buf) < 0) goto failed;
        break;
    case RF_ATTR:
        snprintf (buf, sizeof buf, "%c%c%c%c",
                  (d->flags & DM_ACTIVE_PRESENT_FLAG) ? 'L' : '-',
                  (d->flags & DM_INACTIVE_PRESENT_FLAG) ? 'I' : '-',
                  (d->flags & DM_SUSPEND_FLAG) ? 's' : '-',
                  (d->flags & DM_READONLY_FLAG) ? 'r' : 'w');
        break;
    case RF_TABLES:
        snprintf (buf, sizeof buf, "%s", (d->flags & DM_ACTIVE_PRESENT_FLAG)
                  ? ((d->flags & DM_INACTIVE_PRESENT_FLAG) ? "Both" : "Live")
                  : ((d->flags & DM_INACTIVE_PRESENT_FLAG) ? "Inactive" : "None"));
        break;
    case RF_SUSPENDED:
        snprintf (buf, sizeof buf, "%s", (d->flags & DM_SUSPEND_FLAG) ? "Suspended" : "Active");
        break;
    case RF_READONLY:
        snprintf (buf, sizeof buf, "%s", (d->flags & DM_READONLY_FLAG) ? "Read-only" : "Writeable");
        break;
    case RF_DEVNO:
        snprintf (buf, sizeof buf, "%u:%u", major ((dev_t) d->dev), minor ((dev_t) d->dev));
        break;
    case RF_MAJOR: v = major ((dev_t) d->dev); break;
    case RF_MINOR: v = minor ((dev_t) d->dev); break;
    case RF_OPEN: v = (int32_t) d->open_count; break;
    case RF_SEGMENTS: v = (int32_t) d->target_count; break;
    case RF_EVENTS: v = d->event_nr; break;
    case RF_DEVICE_COUNT: v = d->ndeps; break;
    case RF_DEVS_USED:
    case RF_DEVNOS_USED:
    case RF_BLKDEVS_USED:
        for (uint32_t i = 0; i < d->ndeps; i++) {
            char item[PATH_MAX];
            uint64_t dep = d->deps[i];
            if (dms_rfields[f].kind == RF_DEVS_USED) {
                const struct dms_dev *c = set ? dms_devset_find (set, dep) : NULL;
                if (!c) continue;
                snprintf (item, sizeof item, "%s", c->name);
            } else if (dms_rfields[f].kind == RF_DEVNOS_USED)
                snprintf (item, sizeof item, "%u:%u", major ((dev_t) dep), minor ((dev_t) dep));
            else if (dms_blkdev_name (dep, item, sizeof item) < 0)
                goto failed;
            dms_list_add (&list, &llen, item);
        }
        break;
    case RF_REF_COUNT:
    case RF_NAMES_USING:
    case RF_DEVNOS_USING:
        for (size_t i = 0; set && i < set->n; i++) {
            const struct dms_dev *p = &set->v[i];
            if (p->dev == d->dev || !dms_devset_uses (p, d->dev)) continue;
            v++;
            char item[DM_NAME_LEN + 32];
            if (dms_rfields[f].kind == RF_NAMES_USING) snprintf (item, sizeof item, "%s", p->name);
            else snprintf (item, sizeof item, "%u:%u", major ((dev_t) p->dev), minor ((dev_t) p->dev));
            dms_list_add (&list, &llen, item);
        }
        break;
    }
    *num = v;
    if (dms_rfields[f].num) snprintf (buf, sizeof buf, "%lld", v);
    if (list) return list;
    return strdup (buf);
failed:
    free (list);
    fprintf (stderr, "_do_report_object: report function failed for field %s\n", dms_rfields[f].id);
    return NULL;
}

static int
dms_sel_eval (const struct dms_sel *s, const struct dms_dev *d, const struct dms_devset *set)
{
    switch (s->kind) {
    case SEL_AND: return dms_sel_eval (s->a, d, set) && dms_sel_eval (s->b, d, set);
    case SEL_OR: return dms_sel_eval (s->a, d, set) || dms_sel_eval (s->b, d, set);
    case SEL_NOT: return !dms_sel_eval (s->a, d, set);
    }
    long long num;
    char *val = dms_field_value (s->field, d, set, &num);
    if (!val) return 0;
    int r, numeric = dms_rfields[s->field].num;
    long long c = numeric ? (num > s->num) - (num < s->num) : strcmp (val, s->value);
    switch (s->op) {
    case 0: r = regexec (&s->re, val, 0, NULL, 0) == 0; break;
    case 1: r = regexec (&s->re, val, 0, NULL, 0) != 0; break;
    case 2: r = c != 0; break;
    case 4: r = c <= 0; break;
    case 5: r = c >= 0; break;
    case 7: r = c < 0; break;
    case 8: r = c > 0; break;
    default: r = c == 0; break;
    }
    free (val);
    return r;
}

struct dms_rrow {
    char **cell;
    char **key;
    long long *knum;
};

struct dms_report {
    struct dms_rspec spec;
    struct dms_rrow *rows;
    size_t n, cap;
    struct dms_devset set;
    int fd;
};

static void
dms_report_free (struct dms_report *rp)
{
    for (size_t i = 0; i < rp->n; i++) {
        for (int f = 0; f < rp->spec.nfields; f++) free (rp->rows[i].cell[f]);
        for (int k = 0; k < rp->spec.nkeys; k++) free (rp->rows[i].key[k]);
        free (rp->rows[i].cell);
        free (rp->rows[i].key);
        free (rp->rows[i].knum);
    }
    free (rp->rows);
    dms_sel_free (rp->spec.sel);
    dms_devset_free (&rp->set);
}

/* Set up the report from -o/-O/-S/--noheadings/--separator before the
   command runs, as dmsetup does. Returns 0, 1 after help, -1 on error. */
static int
dms_report_init (struct dms_report *rp, const struct dms_opts *o)
{
    static const char defaults[] = "name,major,minor,attr,open,segments,events,uuid";
    memset (rp, 0, sizeof *rp);
    struct dms_rspec *r = &rp->spec;
    r->aligned = 1;
    r->headings = 1;
    r->sep = " ";
    if (o->noheadings) {
        r->sep = ":";
        r->aligned = 0;
        r->headings = 0;
    }
    if (o->separator) {
        r->sep = o->separator;
        r->aligned = 0;
    }
    int rc;
    if (!o->fields)
        rc = dms_parse_fields (r, defaults);
    else if (o->fields[0] == '+') {
        rc = dms_parse_fields (r, defaults);
        if (rc == 0) rc = dms_parse_fields (r, o->fields + 1);
    } else
        rc = dms_parse_fields (r, o->fields);
    if (rc == 0 && o->sort) rc = dms_parse_sort (r, o->sort);
    if (rc == 0 && o->select) rc = dms_parse_select (r, o->select);
    return rc;
}

static int
dms_report_add (struct dms_report *rp, struct dms_dev *d)
{
    struct dms_rspec *r = &rp->spec;
    if ((r->need_deps || r->need_set) && dms_dev_deps (rp->fd, d) < 0) return -1;
    if (r->need_set && dms_devset_load (rp->fd, &rp->set) < 0) return -1;
    const struct dms_devset *set = r->need_set ? &rp->set : NULL;
    if (r->sel && !dms_sel_eval (r->sel, d, set)) return 0;
    if (rp->n == rp->cap) {
        size_t cap = rp->cap ? rp->cap * 2 : 8;
        struct dms_rrow *nv = realloc (rp->rows, cap * sizeof *nv);
        if (!nv) {
            fprintf (stderr, "dmsetup: out of memory\n");
            return -1;
        }
        rp->rows = nv;
        rp->cap = cap;
    }
    struct dms_rrow *row = &rp->rows[rp->n];
    row->cell = calloc ((size_t) r->nfields + 1, sizeof *row->cell);
    row->key = calloc ((size_t) r->nkeys + 1, sizeof *row->key);
    row->knum = calloc ((size_t) r->nkeys + 1, sizeof *row->knum);
    if (!row->cell || !row->key || !row->knum) {
        free (row->cell);
        free (row->key);
        free (row->knum);
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    long long num;
    rp->n++;
    for (int f = 0; f < r->nfields; f++)
        if (!(row->cell[f] = dms_field_value (r->fields[f], d, set, &num))) {
            rp->n--;
            for (int g = 0; g < f; g++) free (row->cell[g]);
            free (row->cell);
            free (row->key);
            free (row->knum);
            return -1;
        }
    for (int k = 0; k < r->nkeys; k++)
        row->key[k] = dms_field_value (r->keys[k], d, set, &row->knum[k]);
    return 0;
}

static const struct dms_rspec *dms_sort_spec;

static int
dms_row_cmp (const void *pa, const void *pb)
{
    const struct dms_rrow *a = pa, *b = pb;
    for (int k = 0; k < dms_sort_spec->nkeys; k++) {
        int c;
        if (dms_rfields[dms_sort_spec->keys[k]].num)
            c = (a->knum[k] > b->knum[k]) - (a->knum[k] < b->knum[k]);
        else
            c = strcmp (a->key[k] ? a->key[k] : "", b->key[k] ? b->key[k] : "");
        if (c) return dms_sort_spec->desc[k] ? -c : c;
    }
    return 0;
}

/* Buffered output: sorted rows, each column as wide as its definition or
   its widest value, numbers right-aligned; nothing at all without rows. */
static void
dms_report_output (struct dms_report *rp)
{
    const struct dms_rspec *r = &rp->spec;
    if (!rp->n) return;
    if (r->nkeys) {
        dms_sort_spec = r;
        qsort (rp->rows, rp->n, sizeof *rp->rows, dms_row_cmp);
    }
    int width[256];
    for (int f = 0; f < r->nfields; f++) {
        width[f] = dms_rfields[r->fields[f]].width;
        for (size_t i = 0; i < rp->n; i++) {
            int l = rp->rows[i].cell[f] ? (int) strlen (rp->rows[i].cell[f]) : 0;
            if (l > width[f]) width[f] = l;
        }
    }
    if (r->headings) {
        for (int f = 0; f < r->nfields; f++) {
            if (f) fputs (r->sep, stdout);
            const char *h = dms_rfields[r->fields[f]].head;
            if (r->aligned) printf ("%-*.*s", width[f], width[f], h);
            else fputs (h, stdout);
        }
        putchar ('\n');
    }
    for (size_t i = 0; i < rp->n; i++) {
        for (int f = 0; f < r->nfields; f++) {
            const char *v = rp->rows[i].cell[f] ? rp->rows[i].cell[f] : "";
            if (f) fputs (r->sep, stdout);
            if (!r->aligned) fputs (v, stdout);
            else if (dms_rfields[r->fields[f]].num) printf ("%*.*s", width[f], width[f], v);
            else printf ("%-*.*s", width[f], width[f], v);
        }
        putchar ('\n');
    }
}

struct dms_report_arg {
    struct dms_report *rp;
    int failed;
};

static int
dms_list_cb_report (int fd, const char *name, uint64_t dev, void *arg)
{
    struct dms_report_arg *ra = arg;
    (void) dev;
    struct dms_dev d;
    int r = dms_dev_status (fd, name, NULL, &d);
    if (r == 0) return 0;
    if (r < 0 || dms_report_add (ra->rp, &d) < 0) {
        dms_dev_free (&d);
        ra->failed = 1;
        return 1;
    }
    dms_dev_free (&d);
    return 0;
}

/* info -c [-o ...] [--sort ...] [--select ...] [<device>...] */
static int
dms_info_columns (int fd, const struct dms_opts *o, struct dms_report *rp)
{
    rp->fd = fd;
    int rc = EXECUTION_SUCCESS;
    if (o->npos > 1 || o->uuid) {
        int count = o->npos > 1 ? o->npos - 1 : 1;
        for (int i = 0; i < count; i++) {
            struct dms_dev d;
            int r = o->npos > 1 ? dms_dev_status (fd, o->pos[i + 1], NULL, &d)
                                : dms_dev_status (fd, NULL, o->uuid, &d);
            if (r == 0) dms_no_device ();
            if (r <= 0 || dms_report_add (rp, &d) < 0) {
                dms_dev_free (&d);
                rc = EXECUTION_FAILURE;
                break;
            }
            dms_dev_free (&d);
        }
    } else {
        struct dms_report_arg ra = { rp, 0 };
        if (dms_for_all (fd, dms_list_cb_report, &ra) != EXECUTION_SUCCESS || ra.failed)
            rc = EXECUTION_FAILURE;
    }
    return rc;
}

/* ---- mutations ---- */

static int
dms_mutation_opted_in (void)
{
    const char *allow = getenv ("BASHOS_DMSETUP_ALLOW_MUTATE");
    return geteuid () == 0 && allow && strcmp (allow, "1") == 0;
}

static int
dms_mutating_allowed (const char *verb)
{
    if (dms_mutation_opted_in ()) return 1;
    fprintf (stderr, "dmsetup: %s requires root and BASHOS_DMSETUP_ALLOW_MUTATE=1\n", verb);
    return 0;
}

/* Total length of a device's live table, 0 if it has none, -1 on error. */
static long long
dms_device_size (int fd, const char *name, const char *uuid)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_STATUS, name, uuid, DM_STATUS_TABLE_FLAG,
                                   NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return -1;
    }
    size_t off = 0;
    unsigned long long total = 0;
    for (uint32_t i = 0; i < io->target_count; i++) {
        const struct dm_target_spec *ts = dms_target (io, off, i, "table");
        if (!ts) {
            free (io);
            return -1;
        }
        if (ts->sector_start != total || !ts->length || ts->length > (unsigned long long) LLONG_MAX - total) {
            dms_bad_response (io, "table geometry");
            free (io);
            return -1;
        }
        total += ts->length;
        off = ts->next;
    }
    free (io);
    return (long long) total;
}

/* libdevmapper's _error_device: replace the live table with one error
   target covering the same size, then resume (clearing on failure). A
   device without a table fails without a message, as there. */
static int
dms_error_device (int fd, const struct dms_opts *o, const char *name, const char *uuid,
                  uint32_t resume_flags)
{
    long long size = dms_device_size (fd, name, uuid);
    if (size <= 0) return EXECUTION_FAILURE;
    struct dms_spec sp;
    memset (&sp, 0, sizeof sp);
    sp.start = 0;
    sp.length = (unsigned long long) size;
    strcpy (sp.type, "error");
    sp.params = (char *) "";
    sp.params_len = 0;
    struct dms_table t = { &sp, 1, 1, sizeof (struct dm_ioctl) + sizeof (struct dm_target_spec) + 9 };
    if (dms_load_table (fd, name, uuid, &t, o->readonly ? DM_READONLY_FLAG : 0, 0, 0)
        != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    if (dms_uevent_simple (fd, o, DM_DEV_SUSPEND, name, uuid, resume_flags) != EXECUTION_SUCCESS) {
        dms_simple (fd, DM_TABLE_CLEAR, name, uuid, 0);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Arguments after the verb: the device, unless -u names it, then the rest. */
static int
dms_device_arg (const struct dms_opts *o, const char *verb, const char **name, int *next)
{
    (void) verb;
    if (o->uuid) {
        *name = NULL;
        *next = 1;
        return 0;
    }
    if (o->npos >= 2) {
        *name = o->pos[1];
        *next = 2;
        return 0;
    }
    fputs ("No device specified.\n", stderr);
    return -1;
}

/* With -u, the uuid identifies the device and the name is not sent. */
static const char *
dms_id_uuid (const struct dms_opts *o, const char *name)
{
    return name ? NULL : o->uuid;
}

/* create: DM_DEV_CREATE, then (with a table) the load and the resume.
   Like libdevmapper's _create_and_load_v4, the load names the new device
   number in its diagnostic and a failed load or resume removes the device
   again. Only the resume waits for udev. */
static int
dms_create_cmd (int fd, const struct dms_opts *o)
{
    if (o->npos < 2) {
        fprintf (stderr, "dmsetup: create requires a device name\n");
        return EXECUTION_FAILURE;
    }
    if (o->npos > 3) {
        fprintf (stderr, "dmsetup: create: too many arguments\n");
        return EXECUTION_FAILURE;
    }
    const char *name = o->pos[1];
    if (strchr (name, '/')) {
        fprintf (stderr, "Name \"%s\" invalid. It contains \"/\".\n", name);
        return EXECUTION_FAILURE;
    }

    struct dms_table t;
    int have = 0;
    memset (&t, 0, sizeof t);
    if (!o->notable && dms_read_table (o, o->npos > 2 ? o->pos[2] : NULL, &t, &have) < 0) {
        dms_table_free (&t);
        return EXECUTION_FAILURE;
    }

    uint32_t flags = o->has_major ? DM_PERSISTENT_DEV_FLAG : 0;
    uint32_t ro = o->readonly ? DM_READONLY_FLAG : 0;
    struct dm_ioctl *io = dms_alloc (0, name, o->uuid, flags, NULL, 0);
    int rc = EXECUTION_FAILURE;
    if (!io) goto out;
    /* libdevmapper's create task falls back to the driver's own major
       (the kernel takes only the minor); the later resume does not. */
    long cmaj = o->major;
    if (o->has_major) {
        long dm_major = dms_proc_number ("/proc/devices", "device-mapper");
        if (dm_major > 0) cmaj = dm_major;
        io->dev = (uint64_t) makedev ((unsigned) cmaj, (unsigned) o->minor);
    }
    /* With a table to load, the create carries the task's udev flags.
       PRIMARY_SOURCE is added only on the later resume. */
    if (t.n)
        io->event_nr = (uint32_t) dms_cookie_flags (o) << DMS_UDEV_FLAGS_SHIFT;
    if (ioctl (fd, DM_DEV_CREATE, io) < 0) {
        dms_report_dev (DM_DEV_CREATE, flags, name, o->uuid,
                        o->has_major ? cmaj : 0, (long) o->minor, errno);
        free (io);
        goto out;
    }
    long maj = (long) major ((dev_t) io->dev), min = (long) minor ((dev_t) io->dev);
    dev_t created = (dev_t) io->dev;
    free (io);
    rc = EXECUTION_SUCCESS;
    /* --addnodeoncreate makes the node at create time. A table sets the
       cookie, so udev still owns that node unless fallback is enabled. */
    if (o->add_on_create && dms_add_node (o, name, created, t.n > 0) < 0) {
        if (dms_uevent_simple (fd, o, DM_DEV_REMOVE, name, NULL, 0) != EXECUTION_SUCCESS)
            fputs ("Failed to revert device creation.\n", stderr);
        rc = EXECUTION_FAILURE;
        goto out;
    }
    if (t.n) {
        rc = dms_load_table (fd, name, NULL, &t, ro, maj, min);
        /* The resume and the revert reuse the create's task: a requested
           major and minor go with them, and the resume then omits the name. */
        if (rc == EXECUTION_SUCCESS) {
            if (o->has_major) dms_req_by_dev (o->major, o->minor, 1);
            rc = dms_uevent_simple (fd, o, DM_DEV_SUSPEND, name, NULL, ro);
            dms_req_clear ();
        }
        if (rc != EXECUTION_SUCCESS) {
            if (o->has_major) dms_req_by_dev (o->major, o->minor, 0);
            if (dms_uevent_simple (fd, o, DM_DEV_REMOVE, name, NULL, 0) != EXECUTION_SUCCESS)
                fputs ("Failed to revert device creation.\n", stderr);
            dms_req_clear ();
        }
    }
out:
    dms_table_free (&t);
    return rc;
}

static int
dms_load_cmd (int fd, const struct dms_opts *o, const char *verb)
{
    const char *name;
    int next;
    if (dms_device_arg (o, verb, &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos > next + 1) {
        fprintf (stderr, "dmsetup: %s: too many arguments\n", verb);
        return EXECUTION_FAILURE;
    }
    struct dms_table t;
    int have = 0;
    int rc = EXECUTION_FAILURE;
    if (dms_read_table (o, o->npos > next ? o->pos[next] : NULL, &t, &have) == 0) {
        if (!have)
            fprintf (stderr, "dmsetup: %s requires a table (--table, a file, or stdin)\n", verb);
        else
            rc = dms_load_table (fd, name, dms_id_uuid (o, name), &t,
                                 o->readonly ? DM_READONLY_FLAG : 0, 0, 0);
    }
    dms_table_free (&t);
    return rc;
}

/* Apply one per-device operation to each named device (or the -u device).
   Like dmsetup's repeatable commands, the first failure ends the command. */
static int
dms_each_device (int fd, const struct dms_opts *o, const char *verb,
                 int (*op) (int, const struct dms_opts *, const char *, const char *))
{
    (void) verb;
    if (o->npos < 2) {
        if (!o->uuid) {
            fputs ("No device specified.\n", stderr);
            return EXECUTION_FAILURE;
        }
        return op (fd, o, NULL, o->uuid);
    }
    for (int i = 1; i < o->npos; i++)
        if (op (fd, o, o->pos[i], NULL) != EXECUTION_SUCCESS) return EXECUTION_FAILURE;
    return EXECUTION_SUCCESS;
}

/* --noflush/--nolockfs as request flags; remove --force implies both. */
static uint32_t
dms_flush_flags (const struct dms_opts *o, int forced)
{
    return ((o->noflush || forced) ? DM_NOFLUSH_FLAG : 0)
        | ((o->nolockfs || forced) ? DM_SKIP_LOCKFS_FLAG : 0);
}

static int
dms_op_remove (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    uint32_t flags = dms_flush_flags (o, o->force);
    if (o->force) dms_error_device (fd, o, name, uuid, flags);   /* best effort, as dmsetup */
    if (o->deferred) flags |= DM_DEFERRED_REMOVE;
    int err;
    struct dm_ioctl *io = dms_run_uevent (fd, o, DM_DEV_REMOVE, name, uuid, flags, NULL, 0,
                                          o->retry ? DMS_REMOVE_RETRIES : 1, &err);
    if (!io) return EXECUTION_FAILURE;
    int nodes = dms_nodes_after (o, DM_DEV_REMOVE, flags, name, io);
    free (io);
    return nodes < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
dms_op_suspend (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    return dms_simple (fd, DM_DEV_SUSPEND, name, uuid, DM_SUSPEND_FLAG | dms_flush_flags (o, 0));
}

static int
dms_op_resume (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    return dms_uevent_simple (fd, o, DM_DEV_SUSPEND, name, uuid, dms_flush_flags (o, 0));
}

static int
dms_op_clear (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    (void) o;
    return dms_simple (fd, DM_TABLE_CLEAR, name, uuid, 0);
}

static int
dms_op_wipe (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    return dms_error_device (fd, o, name, uuid, dms_flush_flags (o, 0));
}

static int
dms_list_cb_wipe (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev;
    dms_error_device (fd, arg, name, NULL, dms_flush_flags (arg, 1));
    return 0;
}

static int
dms_remove_all_cmd (int fd, const struct dms_opts *o)
{
    if (o->npos > 1) {
        fprintf (stderr, "dmsetup: remove_all takes no device arguments\n");
        return EXECUTION_FAILURE;
    }
    if (o->force) {
        struct dm_ioctl *io = dms_list (fd);
        if (!io) return EXECUTION_FAILURE;
        int count;
        int r = dms_each_name (io, fd, dms_list_cb_wipe, (void *) o, &count);
        free (io);
        if (r < 0) return EXECUTION_FAILURE;
    }
    return dms_simple (fd, DM_REMOVE_ALL, NULL, NULL, 0);
}

/* libdevmapper's dm_task_set_newname / dm_task_set_newuuid checks. */
static int
dms_rename_cmd (int fd, const struct dms_opts *o)
{
    const char *name;
    int next;
    if (dms_device_arg (o, "rename", &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos != next + 1) {
        fprintf (stderr, "dmsetup: rename requires a device and a new %s\n",
                 o->setuuid ? "uuid" : "name");
        return EXECUTION_FAILURE;
    }
    const char *newid = o->pos[next];
    if (o->setuuid) {
        if (strlen (newid) >= DM_UUID_LEN) {
            fprintf (stderr, "Uuid \"%s\" too long\n", newid);
            return EXECUTION_FAILURE;
        }
    } else if (strchr (newid, '/')) {
        fprintf (stderr, "Name \"%s\" invalid. It contains \"/\".\n", newid);
        return EXECUTION_FAILURE;
    } else if (strlen (newid) >= DM_NAME_LEN) {
        fprintf (stderr, "Name \"%s\" too long\n", newid);
        return EXECUTION_FAILURE;
    } else if (!*newid) {
        fputs ("Non empty new name is required.\n", stderr);
        return EXECUTION_FAILURE;
    }
    int err;
    struct dm_ioctl *io = dms_run_uevent (fd, o, DM_DEV_RENAME, name, dms_id_uuid (o, name),
                                          o->setuuid ? DM_UUID_FLAG : 0, newid, strlen (newid) + 1,
                                          1, &err);
    if (!io) return EXECUTION_FAILURE;
    int nodes = 0;
    if (!o->setuuid && name)
        nodes = dms_rename_node (o, name, newid, 1);
    free (io);
    return nodes < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
dms_message_cmd (int fd, const struct dms_opts *o)
{
    const char *name;
    int next;
    if (dms_device_arg (o, "message", &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos < next + 2) {
        fprintf (stderr, "dmsetup: message requires a device, a sector and a message\n");
        return EXECUTION_FAILURE;
    }
    const char *sp = o->pos[next];
    unsigned long long sector;
    if (dms_parse_u64 (&sp, &sector) < 0 || *sp) {
        fprintf (stderr, "dmsetup: invalid sector: %s\n", o->pos[next]);
        return EXECUTION_FAILURE;
    }

    size_t mlen = 0;
    for (int i = next + 1; i < o->npos; i++) mlen += strlen (o->pos[i]) + 1;
    size_t plen = dms_align8 (sizeof (struct dm_target_msg) + mlen);
    struct dm_target_msg *msg = calloc (1, plen);
    if (!msg) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return EXECUTION_FAILURE;
    }
    msg->sector = sector;
    char *w = msg->message;
    for (int i = next + 1; i < o->npos; i++) {
        size_t l = strlen (o->pos[i]);
        memcpy (w, o->pos[i], l);
        w += l;
        *w++ = (i + 1 < o->npos) ? ' ' : '\0';
    }

    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TARGET_MSG, name, dms_id_uuid (o, name), 0,
                                   msg, plen, 1, 0, &err);
    free (msg);
    if (!io) return EXECUTION_FAILURE;
    int rc = EXECUTION_SUCCESS;
    if (io->flags & DM_DATA_OUT_FLAG) {
        const char *resp = dms_data (io), *end = dms_end (io);
        const char *z = memchr (resp, '\0', (size_t) (end - resp));
        if (!z) {
            dms_bad_response (io, "message");
            rc = EXECUTION_FAILURE;
        } else if (z > resp) {
            fputs (resp, stdout);
            if (z[-1] != '\n') putchar ('\n');
        }
    }
    free (io);
    return rc;
}

/* ---- option parsing ---- */

static int
dms_opt_value (const char *w, const char **eq)
{
    *eq = strchr (w, '=');
    return w[0] == '-' && w[1] == '-' && *eq;
}

static int
dms_parse_ulong (const char *opt, const char *s, unsigned long *out)
{
    char *end;
    errno = 0;
    if (*s < '0' || *s > '9') goto bad;
    *out = strtoul (s, &end, 10);
    if (errno || *end || *out > 0xfffffUL) goto bad;
    return 0;
bad:
    fprintf (stderr, "dmsetup: invalid %s: %s\n", opt, s);
    return -1;
}

/* libdevmapper: octal, non-zero, no trailing junk. atoi for uid and gid. */
static int
dms_parse_mode (const char *s, mode_t *out)
{
    char *end;
    errno = 0;
    long v = strtol (s, &end, 8);
    if (errno || end == s || *end || v == 0) {
        fprintf (stderr, "Invalid argument for --mode: %s. %s\n",
                 s, errno ? strerror (errno) : "");
        return -1;
    }
    *out = (mode_t) v;
    return 0;
}

static int
dms_parse_args (WORD_LIST *list, struct dms_opts *o, int *early)
{
    int n = 0;
    for (WORD_LIST *p = list; p; p = p->next) n++;
    o->pos = calloc ((size_t) n + 1, sizeof *o->pos);
    if (!o->pos) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    *early = -1;
    int opts_done = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word ? p->word->word : NULL;
        if (!w) continue;
        /* Once the device and sector have been read, all remaining words
           belong to the target, even if they look like dmsetup options. */
        if (o->npos && !strcmp (o->pos[0], "message")
            && o->npos >= (o->uuid ? 2 : 3)) {
            o->pos[o->npos++] = w;
            continue;
        }
        if (opts_done || w[0] != '-' || !w[1]) {
            o->pos[o->npos++] = w;
            continue;
        }
        if (!strcmp (w, "--")) { opts_done = 1; continue; }
        if (!strcmp (w, "--version")) { *early = 1; return 0; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) { *early = 0; return 0; }

        if (!strcmp (w, "-r") || !strcmp (w, "--readonly")) { o->readonly = 1; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--notable")) { o->notable = 1; continue; }
        if (!strcmp (w, "--noflush")) { o->noflush = 1; continue; }
        if (!strcmp (w, "--nolockfs")) { o->nolockfs = 1; continue; }
        if (!strcmp (w, "--inactive")) { o->inactive = 1; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--force")) { o->force = 1; continue; }
        if (!strcmp (w, "--deferred")) { o->deferred = 1; continue; }
        if (!strcmp (w, "--showkeys")) { o->showkeys = 1; continue; }
        if (!strcmp (w, "--setuuid")) { o->setuuid = 1; continue; }
        if (!strcmp (w, "--retry")) { o->retry = 1; continue; }
        if (!strcmp (w, "-c") || !strcmp (w, "-C") || !strcmp (w, "--columns")) { o->columns = 1; continue; }
        if (!strcmp (w, "--noheadings")) { o->noheadings = 1; continue; }
        if (!strcmp (w, "--tree")) { o->tree = 1; continue; }
        if (!strcmp (w, "--noudevsync")) { o->noudevsync = 1; continue; }
        if (!strcmp (w, "--noudevrules")) { o->noudevrules = 1; continue; }
        if (!strcmp (w, "--verifyudev")) { o->verifyudev = 1; continue; }
        if (!strcmp (w, "--addnodeoncreate")) { o->add_on_create = 1; continue; }
        if (!strcmp (w, "--addnodeonresume")) { o->add_on_resume = 1; continue; }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose") || !strcmp (w, "--noopencount")
            || !strcmp (w, "--concise") || !strcmp (w, "-y")
            || !strcmp (w, "--yes") || !strcmp (w, "--ignorelockingfailure")
            || !strcmp (w, "--checks"))
            continue;

        /* options with a value: "--opt value" or "--opt=value" */
        const char *eq;
        char key[32];
        const char *val;
        if (dms_opt_value (w, &eq)) {
            size_t kl = (size_t) (eq - w);
            if (kl >= sizeof key) kl = sizeof key - 1;
            memcpy (key, w, kl);
            key[kl] = '\0';
            val = eq + 1;
        } else {
            snprintf (key, sizeof key, "%s", w);
            val = NULL;
        }
        static const char *const valued[] = {
            "-u", "--uuid", "--table", "--target", "-j", "--major", "-m", "--minor",
            "--manglename", "--udevcookie", "--readahead", "-o", "--options", "-O", "--sort",
            "-S", "--select", "--headings", "--separator", "--exec", "-U", "--uid",
            "-G", "--gid", "-M", "--mode", "--count", "--interval", NULL
        };
        int known = 0;
        for (int i = 0; valued[i]; i++) if (!strcmp (key, valued[i])) known = 1;
        if (!known) {
            fprintf (stderr, "dmsetup: unrecognized option '%s'\n", w);
            fputs ("Couldn't process command line.\n", stderr);
            return -1;
        }
        if (!val) {
            if (!p->next || !p->next->word || !p->next->word->word) {
                fprintf (stderr, "dmsetup: option %s requires an argument\n", w);
                fputs ("Couldn't process command line.\n", stderr);
                return -1;
            }
            p = p->next;
            val = p->word->word;
        }
        if (!strcmp (key, "-u") || !strcmp (key, "--uuid")) o->uuid = val;
        else if (!strcmp (key, "-o") || !strcmp (key, "--options")) o->fields = val;
        else if (!strcmp (key, "-O") || !strcmp (key, "--sort")) o->sort = val;
        else if (!strcmp (key, "-S") || !strcmp (key, "--select")) o->select = val;
        else if (!strcmp (key, "--separator")) o->separator = val;
        else if (!strcmp (key, "--table")) o->table = val;
        else if (!strcmp (key, "--target")) o->target = val;
        else if (!strcmp (key, "-j") || !strcmp (key, "--major")) {
            if (dms_parse_ulong ("major", val, &o->major) < 0) return -1;
            o->has_major = 1;
        } else if (!strcmp (key, "-m") || !strcmp (key, "--minor")) {
            if (dms_parse_ulong ("minor", val, &o->minor) < 0) return -1;
            o->has_minor = 1;
        } else if (!strcmp (key, "-U") || !strcmp (key, "--uid"))
            o->dev_uid = (uid_t) atoi (val);
        else if (!strcmp (key, "-G") || !strcmp (key, "--gid"))
            o->dev_gid = (gid_t) atoi (val);
        else if (!strcmp (key, "-M") || !strcmp (key, "--mode")) {
            if (dms_parse_mode (val, &o->dev_mode) < 0) return -1;
        }
    }
    if (o->add_on_create && o->add_on_resume) {
        fputs ("--addnodeonresume and --addnodeoncreate are incompatible.\n", stderr);
        fputs ("Couldn't process command line.\n", stderr);
        return -1;
    }
    if (o->has_major != o->has_minor) {
        fputs ("Please specify both major number and minor number.\n", stderr);
        fputs ("Couldn't process command line.\n", stderr);
        return -1;
    }
    return 0;
}

static int
dms_is_mutating (const char *verb)
{
    static const char *const verbs[] = {
        "create", "load", "reload", "remove", "remove_all", "suspend", "resume",
        "rename", "message", "clear", "wipe_table", NULL
    };
    for (int i = 0; verbs[i]; i++) if (!strcmp (verb, verbs[i])) return 1;
    return 0;
}

#define DMS_FAILED_EARLY (-2)   /* failed before the command: no "Command failed." */

static int
dms_dispatch (const struct dms_opts *o)
{
    const char *verb = o->pos[0];

    if (!strcmp (verb, "help")) { dms_usage (); return EXECUTION_SUCCESS; }
    if (!strcmp (verb, "version")) return dms_version_cmd ();
    if (!strcmp (verb, "ls")) return dms_ls_cmd (o);

    /* Where a command takes device names, a name given with -u wins, as in
       dmsetup's _set_task_device. */
    if (!strcmp (verb, "info")) {
        struct dms_report rp;
        if (o->columns) {
            int r = dms_report_init (&rp, o);
            if (r != 0) {
                dms_report_free (&rp);
                return r > 0 ? EXECUTION_SUCCESS : DMS_FAILED_EARLY;
            }
        }
        int fd = dms_open_control (0);
        if (fd < 0) {
            if (o->columns) dms_report_free (&rp);
            return EXECUTION_FAILURE;
        }
        int rc;
        if (o->columns) {
            rc = dms_info_columns (fd, o, &rp);
            if (rc != EXECUTION_SUCCESS) fputs ("Command failed.\n", stderr);
            dms_report_output (&rp);
            dms_report_free (&rp);
            close (fd);
            return rc == EXECUTION_SUCCESS ? rc : DMS_FAILED_EARLY;
        }
        if (o->npos > 1) {
            rc = EXECUTION_SUCCESS;
            for (int i = 1; i < o->npos && rc == EXECUTION_SUCCESS; i++)
                rc = dms_info_print (fd, o->pos[i], NULL);
        } else if (o->uuid)
            rc = dms_info_print (fd, NULL, o->uuid);
        else
            rc = dms_for_all (fd, dms_list_cb_info, NULL);
        close (fd);
        return rc;
    }

    if (!strcmp (verb, "table") || !strcmp (verb, "status") || !strcmp (verb, "deps")
        || !strcmp (verb, "targets")) {
        int fd = dms_open_control (0);
        if (fd < 0) return EXECUTION_FAILURE;
        int rc = EXECUTION_SUCCESS;
        if (!strcmp (verb, "targets"))
            rc = dms_targets_cmd (fd);
        else if (!strcmp (verb, "deps")) {
            int inactive = o->inactive;
            if (o->npos > 1) {
                for (int i = 1; i < o->npos && rc == EXECUTION_SUCCESS; i++)
                    rc = dms_deps_print (fd, o->pos[i], NULL, 0, inactive);
            } else if (o->uuid)
                rc = dms_deps_print (fd, NULL, o->uuid, 0, inactive);
            else
                rc = dms_for_all (fd, dms_list_cb_deps, &inactive);
        } else {
            struct dms_table_arg ta = { !strcmp (verb, "table"), 0, o, NULL };
            if (o->npos > 1) {
                for (int i = 1; i < o->npos && rc == EXECUTION_SUCCESS; i++)
                    rc = dms_table_print (fd, o->pos[i], &ta, NULL);
            } else if (o->uuid) {
                ta.uuid = o->uuid;
                rc = dms_table_print (fd, NULL, &ta, NULL);
            } else {
                ta.prefix = 1;
                rc = dms_for_all (fd, dms_list_cb_table, &ta);
            }
        }
        close (fd);
        return rc;
    }

    if (!dms_is_mutating (verb)) {
        fputs ("Unknown command.\n", stderr);
        dms_usage ();
        return EXECUTION_FAILURE;
    }
    if (!dms_mutating_allowed (verb)) return EXECUTION_FAILURE;

    int fd = dms_open_control (0);
    if (fd < 0) return EXECUTION_FAILURE;
    int rc;
    if (!strcmp (verb, "create")) rc = dms_create_cmd (fd, o);
    else if (!strcmp (verb, "load") || !strcmp (verb, "reload")) rc = dms_load_cmd (fd, o, verb);
    else if (!strcmp (verb, "remove")) rc = dms_each_device (fd, o, verb, dms_op_remove);
    else if (!strcmp (verb, "remove_all")) rc = dms_remove_all_cmd (fd, o);
    else if (!strcmp (verb, "suspend")) rc = dms_each_device (fd, o, verb, dms_op_suspend);
    else if (!strcmp (verb, "resume")) rc = dms_each_device (fd, o, verb, dms_op_resume);
    else if (!strcmp (verb, "clear")) rc = dms_each_device (fd, o, verb, dms_op_clear);
    else if (!strcmp (verb, "wipe_table")) rc = dms_each_device (fd, o, verb, dms_op_wipe);
    else if (!strcmp (verb, "rename")) rc = dms_rename_cmd (fd, o);
    else rc = dms_message_cmd (fd, o);
    close (fd);
    return rc;
}

int
dmsetup_builtin (WORD_LIST *list)
{
    struct dms_opts o;
    memset (&o, 0, sizeof o);
    o.dev_mode = DMS_DEVICE_MODE;
    dms_udev_bypass_warning ();
    dms_req_clear ();
    int early;
    int rc;
    if (dms_parse_args (list, &o, &early) < 0) {
        rc = EXECUTION_FAILURE;
    } else if (early == 1) {
        rc = dms_version_cmd ();
    } else if (early == 0) {
        dms_usage ();
        rc = EXECUTION_SUCCESS;
    } else if (o.npos == 0) {
        dms_usage ();
        rc = EXECUTION_FAILURE;
    } else {
        rc = dms_dispatch (&o);
        if (rc == DMS_FAILED_EARLY) rc = EXECUTION_FAILURE;
        else if (rc != EXECUTION_SUCCESS) fputs ("Command failed.\n", stderr);
    }
    free (o.pos);
    fflush (stdout);
    return sh_chkwrite (rc);
}

char *dmsetup_doc[] = {
    "Low-level device-mapper control.",
    "",
    "    dmsetup ls|info|table|status|deps|targets|version [ARGS...]",
    "    dmsetup create|load|reload|remove|remove_all|suspend|resume|rename|message|clear|wipe_table ...",
    "",
    "Speaks the DM ioctl ABI on /dev/mapper/control directly. Tables come from",
    "--table, a table file or stdin (one \"start length type params\" per line).",
    "Mutating commands require root and BASHOS_DMSETUP_ALLOW_MUTATE=1.",
    (char *) NULL
};

struct builtin dmsetup_struct = {
    "dmsetup",
    dmsetup_builtin,
    BUILTIN_ENABLED,
    dmsetup_doc,
    "dmsetup COMMAND [ARGS...]",
    0
};
