/* SPDX-License-Identifier: MIT */
/* opus-dmsetup-fixture.c — LD_PRELOAD device-mapper fixture for dmsetup.
 *
 * Interposes open()/close()/ioctl()/geteuid() so that /dev/mapper/control
 * becomes an in-memory mapper model. The production builtin runs unchanged:
 * every request it builds reaches this file exactly as it would reach the
 * kernel, is logged byte for byte, validated the way drivers/md/dm-ioctl.c
 * validates it, and answered with kernel-shaped responses. No real device
 * is ever touched.
 *
 * Environment:
 *   DMSFIX_STATE   initial devices, lines of
 *                    dev NAME UUID|- MINOR OPEN_COUNT SUSPENDED(0|1)
 *                    live|inactive START LENGTH TYPE [PARAMS...]
 *                    bulk COUNT       (COUNT devices "bulkNNNNN", one linear target)
 *   DMSFIX_LOG     append one record per open/close/ioctl (request hex + result)
 *   DMSFIX_STATS   written at exit: "ioctls N", "opens N", "closes N"
 *   DMSFIX_FAIL    comma list CMD[@NAME]=ERRNO, CMD a libdm command name or *
 *   DMSFIX_OPEN_ERRNO  make opening the control node fail with this errno
 *   DMSFIX_EUID    value returned by geteuid()
 *   DMSFIX_MALFORM response fault (see malform calls below)
 *   DMSFIX_FULL    command that always returns DM_BUFFER_FULL_FLAG
 *
 * --- LICENSE --- MIT, same boilerplate as the bash-os loadables.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/dm-ioctl.h>

#define CONTROL "/dev/mapper/control"
#define MAXFD 64
#define DM_MAJOR 253

struct tgt { unsigned long long start, len; char type[DM_MAX_TYPE_NAME]; char *params; };
struct table { struct tgt *t; unsigned n; int present; int readonly; };
struct dev {
    char name[DM_NAME_LEN], uuid[DM_UUID_LEN];
    unsigned minor, event_nr;
    int open_count, suspended, deferred, readonly;
    struct table live, inactive;
};

static struct dev *devs;
static unsigned ndevs, capdevs, next_minor = 0;
static int ctl_fds[MAXFD], nctl;
static int inited;
static FILE *logf;
static unsigned long n_ioctls, n_opens, n_closes;

static int (*real_open) (const char *, int, ...);
static int (*real_close) (int);
static int (*real_ioctl) (int, unsigned long, ...);
static uid_t (*real_geteuid) (void);

static void
die (const char *m)
{
    fprintf (stderr, "dmsfix: %s\n", m);
    abort ();
}

static void *
xcalloc (size_t n, size_t s)
{
    void *p = calloc (n, s ? s : 1);
    if (!p) die ("out of memory");
    return p;
}

static struct dev *
add_dev (const char *name, const char *uuid, unsigned minor)
{
    if (ndevs == capdevs) {
        capdevs = capdevs ? capdevs * 2 : 16;
        devs = realloc (devs, capdevs * sizeof *devs);
        if (!devs) die ("out of memory");
    }
    struct dev *d = &devs[ndevs++];
    memset (d, 0, sizeof *d);
    snprintf (d->name, sizeof d->name, "%s", name);
    if (uuid) snprintf (d->uuid, sizeof d->uuid, "%s", uuid);
    d->minor = minor;
    if (minor >= next_minor) next_minor = minor + 1;
    return d;
}

static void
table_add (struct table *tb, unsigned long long s, unsigned long long l, const char *type, const char *params)
{
    tb->t = realloc (tb->t, (tb->n + 1) * sizeof *tb->t);
    if (!tb->t) die ("out of memory");
    struct tgt *t = &tb->t[tb->n++];
    t->start = s;
    t->len = l;
    snprintf (t->type, sizeof t->type, "%s", type);
    t->params = strdup (params);
    tb->present = 1;
}

static void
table_free (struct table *tb)
{
    for (unsigned i = 0; i < tb->n; i++) free (tb->t[i].params);
    free (tb->t);
    memset (tb, 0, sizeof *tb);
}

static void
load_state (void)
{
    const char *path = getenv ("DMSFIX_STATE");
    if (!path) return;
    FILE *f = fopen (path, "r");
    if (!f) die ("cannot open DMSFIX_STATE");
    char line[8192];
    struct dev *cur = NULL;
    while (fgets (line, sizeof line, f)) {
        line[strcspn (line, "\n")] = '\0';
        char name[DM_NAME_LEN], uuid[DM_UUID_LEN], type[DM_MAX_TYPE_NAME];
        unsigned minor, susp;
        int oc, n = 0;
        unsigned long long s, l;
        if (sscanf (line, "dev %127s %128s %u %d %u", name, uuid, &minor, &oc, &susp) == 5) {
            cur = add_dev (name, strcmp (uuid, "-") ? uuid : NULL, minor);
            cur->open_count = oc;
            cur->suspended = (int) susp;
        } else if (sscanf (line, "bulk %u", &minor) == 1) {
            for (unsigned i = 0; i < minor; i++) {
                char nm[32], pr[32];
                snprintf (nm, sizeof nm, "bulk%05u", i);
                struct dev *d = add_dev (nm, NULL, next_minor);
                snprintf (pr, sizeof pr, "7:%u 0", i % 8);
                table_add (&d->live, 0, 2048, "linear", pr);
            }
        } else if (cur && (sscanf (line, "live %llu %llu %15s %n", &s, &l, type, &n) == 3
                           || sscanf (line, "inactive %llu %llu %15s %n", &s, &l, type, &n) == 3)) {
            table_add (line[0] == 'l' ? &cur->live : &cur->inactive, s, l, type, line + n);
        } else if (line[0] && line[0] != '#') {
            die ("bad DMSFIX_STATE line");
        }
    }
    fclose (f);
}

static void
write_stats (void)
{
    const char *path = getenv ("DMSFIX_STATS");
    if (!path) return;
    FILE *f = fopen (path, "w");
    if (!f) return;
    fprintf (f, "ioctls %lu\nopens %lu\ncloses %lu\nopen_now %d\ndevices %u\n",
             n_ioctls, n_opens, n_closes, nctl, ndevs);
    for (unsigned i = 0; i < ndevs; i++) {
        struct dev *d = &devs[i];
        fprintf (f, "dev %s %s %u %d susp=%d ro=%d live=%u inactive=%d\n", d->name,
                 d->uuid[0] ? d->uuid : "-", d->minor, d->open_count, d->suspended,
                 d->live.readonly, d->live.n, d->inactive.present);
        for (unsigned j = 0; j < d->live.n; j++)
            fprintf (f, "  live %llu %llu %s %s\n", d->live.t[j].start, d->live.t[j].len,
                     d->live.t[j].type, d->live.t[j].params);
    }
    fclose (f);
}

static void
init (void)
{
    if (inited) return;
    inited = 1;
    real_open = dlsym (RTLD_NEXT, "open");
    real_close = dlsym (RTLD_NEXT, "close");
    real_ioctl = dlsym (RTLD_NEXT, "ioctl");
    real_geteuid = dlsym (RTLD_NEXT, "geteuid");
    const char *lp = getenv ("DMSFIX_LOG");
    if (lp) {
        logf = fopen (lp, "a");
        if (logf) setvbuf (logf, NULL, _IOLBF, 0);
    }
    load_state ();
    atexit (write_stats);
}

/* ---- syscall interposition ---- */

static int
is_ctl (int fd)
{
    for (int i = 0; i < nctl; i++) if (ctl_fds[i] == fd) return 1;
    return 0;
}

static int
ctl_open (int flags)
{
    const char *e = getenv ("DMSFIX_OPEN_ERRNO");
    n_opens++;
    if (e && (!getenv ("DMSFIX_OPEN_ONCE") || n_opens == 1)) {
        if (logf) fprintf (logf, "open errno=%s\n", e);
        errno = atoi (e);
        return -1;
    }
    int fd = real_open ("/dev/null", O_RDWR | (flags & O_CLOEXEC));
    if (fd >= 0 && nctl < MAXFD) ctl_fds[nctl++] = fd;
    if (logf) fprintf (logf, "open fd=%d cloexec=%d\n", fd, (flags & O_CLOEXEC) != 0);
    return fd;
}

#define OPEN_WRAPPER(fn)                                                 \
    int fn (const char *path, int flags, ...)                            \
    {                                                                    \
        init ();                                                         \
        mode_t mode = 0;                                                 \
        if (flags & (O_CREAT | O_TMPFILE)) {                             \
            va_list ap; va_start (ap, flags);                            \
            mode = va_arg (ap, mode_t); va_end (ap);                     \
        }                                                                \
        if (path && !strcmp (path, CONTROL)) return ctl_open (flags);    \
        return real_open (path, flags, mode);                            \
    }
OPEN_WRAPPER (open)
OPEN_WRAPPER (open64)

int
__open_2 (const char *path, int flags)
{
    return open (path, flags);
}

int
__open64_2 (const char *path, int flags)
{
    return open (path, flags);
}

int
close (int fd)
{
    init ();
    for (int i = 0; i < nctl; i++)
        if (ctl_fds[i] == fd) {
            ctl_fds[i] = ctl_fds[--nctl];
            n_closes++;
            if (logf) fprintf (logf, "close fd=%d\n", fd);
            break;
        }
    return real_close (fd);
}

uid_t
geteuid (void)
{
    init ();
    const char *e = getenv ("DMSFIX_EUID");
    return e ? (uid_t) strtoul (e, NULL, 10) : real_geteuid ();
}

/* ---- the mapper model ---- */

static const char *
cmd_name (unsigned nr, uint32_t flags)
{
    switch (nr) {
    case DM_VERSION_CMD: return "version";
    case DM_REMOVE_ALL_CMD: return "remove_all";
    case DM_LIST_DEVICES_CMD: return "names";
    case DM_DEV_CREATE_CMD: return "create";
    case DM_DEV_REMOVE_CMD: return "remove";
    case DM_DEV_RENAME_CMD: return "rename";
    case DM_DEV_SUSPEND_CMD: return (flags & DM_SUSPEND_FLAG) ? "suspend" : "resume";
    case DM_DEV_STATUS_CMD: return "info";
    case DM_TABLE_LOAD_CMD: return "reload";
    case DM_TABLE_CLEAR_CMD: return "clear";
    case DM_TABLE_DEPS_CMD: return "deps";
    case DM_TABLE_STATUS_CMD: return (flags & DM_STATUS_TABLE_FLAG) ? "table" : "status";
    case DM_LIST_VERSIONS_CMD: return "versions";
    case DM_TARGET_MSG_CMD: return "message";
    }
    return "?";
}

static int
injected (const char *cmd, const char *name)
{
    const char *spec = getenv ("DMSFIX_FAIL");
    if (!spec) return 0;
    char *copy = strdup (spec), *save = NULL;
    int err = 0;
    for (char *it = strtok_r (copy, ",", &save); it && !err; it = strtok_r (NULL, ",", &save)) {
        char *eq = strchr (it, '=');
        if (!eq) continue;
        *eq = '\0';
        char *at = strchr (it, '@');
        if (at) *at++ = '\0';
        if (strcmp (it, "*") && strcmp (it, cmd)) continue;
        if (at && (!name || strcmp (at, name))) continue;
        err = atoi (eq + 1);
    }
    free (copy);
    return err;
}

static int
malform (const char *what)
{
    const char *m = getenv ("DMSFIX_MALFORM");
    return m && !strcmp (m, what);
}

static struct dev *
find (struct dm_ioctl *io)
{
    if (io->uuid[0]) {
        for (unsigned i = 0; i < ndevs; i++) if (!strcmp (devs[i].uuid, io->uuid)) return &devs[i];
        return NULL;
    }
    if (io->name[0]) {
        for (unsigned i = 0; i < ndevs; i++) if (!strcmp (devs[i].name, io->name)) return &devs[i];
        return NULL;
    }
    for (unsigned i = 0; i < ndevs; i++)
        if (makedev (DM_MAJOR, devs[i].minor) == io->dev) return &devs[i];
    return NULL;
}

static void
dev_status (struct dm_ioctl *io, struct dev *d)
{
    io->flags &= ~(DM_SUSPEND_FLAG | DM_READONLY_FLAG | DM_ACTIVE_PRESENT_FLAG
                   | DM_INACTIVE_PRESENT_FLAG | DM_DEFERRED_REMOVE);
    if (d->suspended) io->flags |= DM_SUSPEND_FLAG;
    if (d->live.readonly) io->flags |= DM_READONLY_FLAG;
    if (d->live.present) io->flags |= DM_ACTIVE_PRESENT_FLAG;
    if (d->inactive.present) io->flags |= DM_INACTIVE_PRESENT_FLAG;
    if (d->deferred) io->flags |= DM_DEFERRED_REMOVE;
    io->dev = makedev (DM_MAJOR, d->minor);
    io->open_count = d->open_count;
    io->event_nr = d->event_nr;
    io->target_count = d->live.n;
    /* like the kernel's find_device, report both identifiers */
    snprintf (io->name, sizeof io->name, "%s", d->name);
    snprintf (io->uuid, sizeof io->uuid, "%s", d->uuid);
}

static void
remove_dev (struct dev *d)
{
    table_free (&d->live);
    table_free (&d->inactive);
    unsigned i = (unsigned) (d - devs);
    memmove (&devs[i], &devs[i + 1], (ndevs - i - 1) * sizeof *devs);
    ndevs--;
}

static const char *const known_types[] = {
    "linear", "zero", "error", "striped", "crypt", "snapshot", "mirror", "thin",
    "delay", "flakey", "raid", NULL
};

static int
valid_target (const char *type, const char *params)
{
    int known = 0;
    for (int i = 0; known_types[i]; i++) if (!strcmp (type, known_types[i])) known = 1;
    if (!known) return 0;
    if (!strcmp (type, "linear")) {
        unsigned a, b;
        unsigned long long off;
        char extra;
        return sscanf (params, "%u:%u %llu %c", &a, &b, &off, &extra) == 3;
    }
    if (!strcmp (type, "zero") || !strcmp (type, "error")) return params[0] == '\0';
    return 1;
}

/* Parse DM_TABLE_LOAD's target specs as dm-ioctl.c populate_table does. */
static int
do_load (struct dm_ioctl *io, struct dev *d)
{
    char *data = (char *) io + io->data_start, *end = (char *) io + io->data_size;
    struct table tb;
    memset (&tb, 0, sizeof tb);
    if (io->target_count == 0) return EINVAL;
    size_t next = 0;
    char *last = data;
    unsigned long long expect = 0;
    for (unsigned i = 0; i < io->target_count; i++) {
        struct dm_target_spec *ts = (struct dm_target_spec *) (last + next);
        if ((char *) ts < data || (char *) (ts + 1) > end || (char *) ts < last
            || ((uintptr_t) ((char *) ts - data) & 7)) {
            table_free (&tb);
            return EINVAL;   /* stricter than x86 kernels: specs must stay 8-aligned */
        }
        char *params = (char *) (ts + 1);
        if (!memchr (params, '\0', (size_t) (end - params))
            || !memchr (ts->target_type, '\0', sizeof ts->target_type)) {
            table_free (&tb);
            return EINVAL;
        }
        if (ts->length == 0 || ts->sector_start != expect
            || !valid_target (ts->target_type, params)) {
            table_free (&tb);
            return EINVAL;
        }
        expect = ts->sector_start + ts->length;
        table_add (&tb, ts->sector_start, ts->length, ts->target_type, params);
        last = (char *) ts;
        next = ts->next;
    }
    tb.readonly = (io->flags & DM_READONLY_FLAG) != 0;
    table_free (&d->inactive);
    d->inactive = tb;
    d->inactive.present = 1;
    return 0;
}

static int
put_target_specs (struct dm_ioctl *io, struct table *tb, int table_mode)
{
    char *data = (char *) io + io->data_start;
    size_t room = io->data_size - io->data_start, off = 0, used = 0;
    io->target_count = 0;
    for (unsigned i = 0; i < tb->n; i++) {
        const char *params = table_mode ? tb->t[i].params : "";
        size_t one = (sizeof (struct dm_target_spec) + strlen (params) + 1 + 7) & ~(size_t) 7;
        if (off + one > room) {
            io->flags |= DM_BUFFER_FULL_FLAG;
            return 0;
        }
        struct dm_target_spec *ts = (struct dm_target_spec *) (data + off);
        memset (ts, 0, one);
        ts->sector_start = tb->t[i].start;
        ts->length = tb->t[i].len;
        snprintf (ts->target_type, sizeof ts->target_type, "%s", tb->t[i].type);
        strcpy ((char *) (ts + 1), params);
        used = off + sizeof *ts + strlen (params) + 1;
        off += one;
        ts->next = (uint32_t) off;      /* from the start of the data area */
        io->target_count++;
    }
    /* retrieve_status reports bytes through the last NUL, excluding padding. */
    io->data_size = tb->n ? (uint32_t) (io->data_start + used) : offsetof (struct dm_ioctl, data);
    if (malform ("table") && io->target_count > 1)
        ((struct dm_target_spec *) data)->next = 0;     /* a loop back to itself */
    if (malform ("status") && io->target_count) {
        struct dm_target_spec *ts = (struct dm_target_spec *) data;
        memset (ts + 1, 'x', room - sizeof *ts);        /* unterminated params */
        io->data_size = (uint32_t) (io->data_start + room);
    }
    if (io->target_count > 1) {
        struct dm_target_spec *ts = (struct dm_target_spec *) data;
        if (malform ("table-cross-params"))
            memset (ts + 1, 'x', ts->next - sizeof *ts);
        if (malform ("table-overlap")) ts->next = 8;
        if (malform ("table-gap")) ts->sector_start = 1;
        if (malform ("table-overflow")) ts->length = UINT64_MAX;
        if (malform ("table-type")) memset (ts->target_type, 'x', sizeof ts->target_type);
    }
    return 0;
}

static int
do_names (struct dm_ioctl *io)
{
    char *data = (char *) io + io->data_start;
    size_t room = io->data_size - io->data_start, off = 0;
    if (ndevs == 0) {
        if (room < sizeof (struct dm_name_list)) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
        memset (data, 0, sizeof (struct dm_name_list));
        /* list_devices writes a zero dev internally but copies no payload. */
        io->data_size = io->data_start;
        return 0;
    }
    struct dm_name_list *prev = NULL;
    for (unsigned i = 0; i < ndevs; i++) {
        struct dev *d = &devs[i];
        /* the 5.13+ record: name, then aligned event_nr, flags and uuid */
        size_t nameoff = offsetof (struct dm_name_list, name);
        size_t evoff = (nameoff + strlen (d->name) + 1 + 7) & ~(size_t) 7;
        size_t uuidlen = d->uuid[0] ? strlen (d->uuid) + 1 : 0;
        size_t one = (evoff + 8 + uuidlen + 7) & ~(size_t) 7;
        if (off + one > room) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
        struct dm_name_list *nl = (struct dm_name_list *) (data + off);
        memset (nl, 0, one);
        nl->dev = makedev (DM_MAJOR, d->minor);
        strcpy (nl->name, d->name);
        uint32_t *ev = (uint32_t *) ((char *) nl + evoff);
        ev[0] = d->event_nr;
        ev[1] = d->uuid[0] ? DM_NAME_LIST_FLAG_HAS_UUID : DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID;
        if (uuidlen) strcpy ((char *) (ev + 2), d->uuid);
        if (prev) prev->next = (uint32_t) ((char *) nl - (char *) prev);
        prev = nl;
        off += one;
    }
    io->data_size = (uint32_t) (io->data_start + off);
    if (malform ("names")) ((struct dm_name_list *) data)->next = 0x7ffffff0;
    if (malform ("names-short")) io->data_size = io->data_start + 1;
    if (malform ("names-next-end")) ((struct dm_name_list *) data)->next = off;
    if (malform ("names-cross") && ndevs > 1) {
        struct dm_name_list *nl = (struct dm_name_list *) data;
        memset (nl->name, 'x', nl->next - offsetof (struct dm_name_list, name));
    }
    if (malform ("unaligned") && off + 1 <= room) {
        memmove (data + 1, data, off);
        io->data_start++;
        io->data_size++;
    }
    return 0;
}

static int
do_deps (struct dm_ioctl *io, struct table *tb)
{
    if (!tb->present) {
        io->data_size = offsetof (struct dm_ioctl, data);
        return 0;
    }
    uint64_t devv[256];
    unsigned n = 0;
    for (unsigned i = 0; i < tb->n; i++) {
        const char *p = tb->t[i].params;
        while (*p) {
            unsigned a, b;
            int used = 0;
            if (sscanf (p, "%u:%u%n", &a, &b, &used) == 2 && used && (p[used] == ' ' || !p[used])) {
                uint64_t dv = makedev (a, b);
                int dup = 0;
                for (unsigned k = 0; k < n; k++) if (devv[k] == dv) dup = 1;
                if (!dup && n < 256) devv[n++] = dv;
            }
            p += strcspn (p, " ");
            p += strspn (p, " ");
        }
    }
    size_t need = sizeof (struct dm_target_deps) + n * sizeof (uint64_t);
    if (io->data_size - io->data_start < need) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
    struct dm_target_deps *deps = (struct dm_target_deps *) ((char *) io + io->data_start);
    deps->count = malform ("deps") ? 0x10000000 : n;
    for (unsigned k = 0; k < n; k++) deps->dev[k] = devv[k];
    io->data_size = (uint32_t) (io->data_start + need);
    return 0;
}

static int
do_versions (struct dm_ioctl *io)
{
    static const struct { const char *n; unsigned v[3]; } tv[] = {
        { "linear", { 1, 5, 0 } }, { "zero", { 1, 2, 0 } }, { "error", { 1, 7, 0 } },
        { "striped", { 1, 7, 0 } }, { "crypt", { 1, 27, 0 } },
    };
    char *data = (char *) io + io->data_start;
    size_t room = io->data_size - io->data_start, off = 0;
    struct dm_target_versions *prev = NULL;
    for (unsigned i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        size_t one = (sizeof (struct dm_target_versions) + strlen (tv[i].n) + 1 + 7) & ~(size_t) 7;
        if (off + one > room) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
        struct dm_target_versions *v = (struct dm_target_versions *) (data + off);
        memset (v, 0, one);
        memcpy (v->version, tv[i].v, sizeof v->version);
        strcpy (v->name, tv[i].n);
        if (prev) prev->next = (uint32_t) ((char *) v - (char *) prev);
        prev = v;
        off += one;
    }
    io->data_size = (uint32_t) (io->data_start + off);
    if (malform ("versions")) ((struct dm_target_versions *) data)->next = 0x7ffffff0;
    if (malform ("versions-short")) io->data_size = io->data_start + 1;
    if (malform ("versions-next-end")) ((struct dm_target_versions *) data)->next = off;
    if (malform ("versions-short-next"))
        io->data_size = io->data_start + ((struct dm_target_versions *) data)->next + 1;
    if (malform ("versions-cross")) {
        struct dm_target_versions *v = (struct dm_target_versions *) data;
        memset (v->name, 'x', v->next - offsetof (struct dm_target_versions, name));
    }
    return 0;
}

static int
do_message (struct dm_ioctl *io, struct dev *d)
{
    char *data = (char *) io + io->data_start, *end = (char *) io + io->data_size;
    struct dm_target_msg *m = (struct dm_target_msg *) data;
    if ((char *) (m + 1) > end || !memchr (m->message, '\0', (size_t) (end - m->message)))
        return EINVAL;
    if (!d->live.present) return EINVAL;
    int hit = 0;
    for (unsigned i = 0; i < d->live.n; i++)
        if (m->sector >= d->live.t[i].start && m->sector < d->live.t[i].start + d->live.t[i].len)
            hit = 1;
    if (!hit) return EINVAL;
    char out[4096];
    unsigned big;
    if (!strcmp (m->message, "ping")) snprintf (out, sizeof out, "pong sector=%llu", (unsigned long long) m->sector);
    else if (!strcmp (m->message, "silent")) out[0] = '\0';
    else if (sscanf (m->message, "dump %u", &big) == 1) {
        size_t need = (size_t) big + 1;
        if (io->data_size - io->data_start < need) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
        for (unsigned i = 0; i < big; i++) data[i] = (char) ('a' + i % 26);
        data[big] = '\0';
        io->flags |= DM_DATA_OUT_FLAG;
        io->data_size = io->data_start + need;
        return 0;
    } else return EINVAL;
    size_t need = strlen (out) + 1;
    if (io->data_size - io->data_start < need) { io->flags |= DM_BUFFER_FULL_FLAG; return 0; }
    if (out[0] || malform ("message")) {
        if (malform ("message")) memset (data, 'z', io->data_size - io->data_start);
        else memcpy (data, out, need);
        io->flags |= DM_DATA_OUT_FLAG;
        if (!malform ("message")) io->data_size = io->data_start + need;
    } else io->data_size = offsetof (struct dm_ioctl, data);
    return 0;
}

static int
handle (unsigned nr, struct dm_ioctl *io)
{
    if (io->version[0] != DM_VERSION_MAJOR) return EINVAL;
    if (io->data_size < sizeof *io || io->data_start < sizeof *io || io->data_start > io->data_size)
        return EINVAL;
    if (!memchr (io->name, '\0', sizeof io->name) || !memchr (io->uuid, '\0', sizeof io->uuid))
        return EINVAL;
    if (nr != DM_DEV_CREATE_CMD && io->name[0] && io->uuid[0]) return EINVAL;

    uint32_t in_flags = io->flags;
    int e = injected (cmd_name (nr, in_flags), io->name[0] ? io->name : (io->uuid[0] ? io->uuid : NULL));
    if (e) return e;
    io->flags &= ~(DM_BUFFER_FULL_FLAG | DM_DATA_OUT_FLAG);
    io->version[1] = 48;
    io->version[2] = 0;

    if (nr == DM_VERSION_CMD) return 0;
    if (nr == DM_LIST_DEVICES_CMD) return do_names (io);
    if (nr == DM_LIST_VERSIONS_CMD) return do_versions (io);
    if (nr == DM_REMOVE_ALL_CMD) {
        for (unsigned i = ndevs; i-- > 0;)
            if (devs[i].open_count == 0) remove_dev (&devs[i]);
        io->data_size = 0; /* remove_all copies no result, even the header */
        return 0;
    }
    if (nr == DM_DEV_CREATE_CMD) {
        if (!io->name[0] || strchr (io->name, '/')) return EINVAL;
        for (unsigned i = 0; i < ndevs; i++)
            if (!strcmp (devs[i].name, io->name) || (io->uuid[0] && !strcmp (devs[i].uuid, io->uuid)))
                return EBUSY;
        unsigned minor = next_minor;
        if (in_flags & DM_PERSISTENT_DEV_FLAG) {
            if (major (io->dev) != DM_MAJOR) return EINVAL;
            minor = minor (io->dev);
            for (unsigned i = 0; i < ndevs; i++) if (devs[i].minor == minor) return EBUSY;
        }
        struct dev *d = add_dev (io->name, io->uuid[0] ? io->uuid : NULL, minor);
        dev_status (io, d);
        io->data_size = sizeof *io;
        return 0;
    }

    struct dev *d = find (io);
    if (!d) return ENXIO;
    switch (nr) {
    case DM_DEV_REMOVE_CMD:
        if (d->open_count) {
            if (in_flags & DM_DEFERRED_REMOVE) { d->deferred = 1; dev_status (io, d); return 0; }
            return EBUSY;
        }
        dev_status (io, d);
        remove_dev (d);
        io->data_size = sizeof *io;
        return 0;
    case DM_DEV_RENAME_CMD: {
        char *nn = (char *) io + io->data_start, *end = (char *) io + io->data_size;
        if (nn >= end || !memchr (nn, '\0', (size_t) (end - nn))) return EINVAL;
        if (in_flags & DM_UUID_FLAG) {
            if (strlen (nn) >= DM_UUID_LEN) return EINVAL;
            if (d->uuid[0]) return EINVAL;
            for (unsigned i = 0; i < ndevs; i++) if (!strcmp (devs[i].uuid, nn)) return EBUSY;
            snprintf (d->uuid, sizeof d->uuid, "%s", nn);
        } else {
            if (!nn[0] || strlen (nn) >= DM_NAME_LEN || strchr (nn, '/')) return EINVAL;
            for (unsigned i = 0; i < ndevs; i++) if (!strcmp (devs[i].name, nn)) return EBUSY;
            snprintf (d->name, sizeof d->name, "%s", nn);
        }
        d->event_nr++;
        dev_status (io, d);
        io->data_size = sizeof *io;
        return 0;
    }
    case DM_DEV_SUSPEND_CMD:
        if (in_flags & DM_SUSPEND_FLAG) d->suspended = 1;
        else {
            if (d->inactive.present) {
                table_free (&d->live);
                d->live = d->inactive;
                memset (&d->inactive, 0, sizeof d->inactive);
                d->event_nr++;
            }
            d->suspended = 0;
        }
        dev_status (io, d);
        io->data_size = sizeof *io;
        return 0;
    case DM_DEV_STATUS_CMD:
        dev_status (io, d);
        io->data_size = sizeof *io;
        if (malform ("header")) io->data_size = 0x7fffffff;
        if (malform ("header-strings")) {
            memset (io->name, 'X', sizeof io->name);
            memset (io->uuid, 'Y', sizeof io->uuid);
        }
        return 0;
    case DM_TABLE_LOAD_CMD: {
        int r = do_load (io, d);
        if (r) return r;
        dev_status (io, d);
        io->data_size = sizeof *io;
        return 0;
    }
    case DM_TABLE_CLEAR_CMD:
        table_free (&d->inactive);
        dev_status (io, d);
        io->data_size = sizeof *io;
        return 0;
    case DM_TABLE_DEPS_CMD: {
        struct table *tb = (in_flags & DM_QUERY_INACTIVE_TABLE_FLAG) ? &d->inactive : &d->live;
        dev_status (io, d);
        return do_deps (io, tb);
    }
    case DM_TABLE_STATUS_CMD: {
        struct table *tb = (in_flags & DM_QUERY_INACTIVE_TABLE_FLAG) ? &d->inactive : &d->live;
        dev_status (io, d);
        return put_target_specs (io, tb, (in_flags & DM_STATUS_TABLE_FLAG) != 0);
    }
    case DM_TARGET_MSG_CMD:
        return do_message (io, d);
    }
    return ENOTTY;
}

static void
log_hex (const void *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) {
        fputc (hx[b[i] >> 4], logf);
        fputc (hx[b[i] & 15], logf);
    }
}

int
ioctl (int fd, unsigned long req, ...)
{
    init ();
    va_list ap;
    va_start (ap, req);
    void *arg = va_arg (ap, void *);
    va_end (ap);
    if (!is_ctl (fd)) return real_ioctl (fd, req, arg);

    n_ioctls++;
    struct dm_ioctl *io = arg;
    unsigned nr = _IOC_NR (req);
    if (_IOC_TYPE (req) != DM_IOCTL || _IOC_SIZE (req) != sizeof *io) {
        errno = ENOTTY;
        return -1;
    }
    size_t insize = io->data_size;
    if (logf) {
        fprintf (logf, "ioctl nr=%u cmd=%s size=%zu hex=", nr, cmd_name (nr, io->flags), insize);
        log_hex (io, insize < sizeof *io ? sizeof *io : insize);
        fputc ('\n', logf);
    }
    /* answer in a private copy as the kernel does (copy_params), then copy
       back only the header and the reported data, never past the caller's size */
    if (insize < sizeof *io) {
        if (logf) fprintf (logf, "result nr=%u errno=%d\n", nr, EINVAL);
        errno = EINVAL;
        return -1;
    }
    struct dm_ioctl *k = xcalloc (1, insize);
    memcpy (k, io, insize);
    int e = handle (nr, k);
    if (!e) {
        /* ctl_ioctl initializes header-only output to offsetof(data), 305 on
           the tested ABI, not sizeof(dm_ioctl), 312. VERSION is special and
           only writes version[]. Keep malformed lengths intact. */
        if (k->data_size == sizeof *k && nr != DM_LIST_DEVICES_CMD)
            k->data_size = offsetof (struct dm_ioctl, data);
        const char *full = getenv ("DMSFIX_FULL");
        if (full && !strcmp (full, cmd_name (nr, io->flags)))
            k->flags |= DM_BUFFER_FULL_FLAG;
        if (k->flags & DM_BUFFER_FULL_FLAG)
            k->data_size = offsetof (struct dm_ioctl, data);
        size_t back = k->data_size <= insize ? k->data_size : insize;
        if (malform ("header")) back = sizeof *k;
        if (nr == DM_VERSION_CMD) back = sizeof k->version;
        memcpy (io, k, back);
    }
    if (logf) fprintf (logf, "result nr=%u errno=%d flags=%#x data_size=%u targets=%u\n",
                       nr, e, k->flags, k->data_size, k->target_count);
    free (k);
    if (e) {
        errno = e;
        return -1;
    }
    return 0;
}
