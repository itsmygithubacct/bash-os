/* SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

/* screen.c - bash-screen multiplexer SERVER as a bash builtin
 *                 (Phase 3 metadata/control surface).
 *
 * Stage 50.B v1 implements the metadata-backed control verbs for
 * windows/panes, attach state, send-keys, capture-pane/scrollback,
 * send-mouse, and the private state-dir contract. Stage 50.D adds the
 * first live pty relay loop: run with an explicit command creates a
 * daemon supervisor with one pty-backed pane, attach relays stdin/stdout
 * through a Unix socket, and
 * send-keys writes to the same live master path when available. Stage
 * 50.D.B layers target-aware window/pane routing on top of that state.
 *
 * State directory: /tmp/.screen/<NAME>/
 *     pid            ← server pid (sentinel for "session is up")
 *     sock           ← attach control socket alias
 *     master.fd      ← Unix stream socket for live pty relay clients
 *     active         ← active <window>:<pane> focus pointer
 *     qsock          ← query socket (state / find / scrollback dump)
 *     info           ← human-readable metadata
 *     windows/<idx>/ ← per-window state (Stage 9)
 *         pid
 *         name
 *         vt-handle      ← Stage 50.C metadata placeholder, not a live pty
 *         vt-generation  ← last observed vt generation (metadata-only)
 *         vt-dirty       ← relay dirtiness bit (metadata-only)
 *         panes/<pidx>/  (Stage 18)
 *             pid
 *             geom        — "rows cols"
 *             scrollback  — ring buffer (Stages 5 + 12)
 *             pty.fd      — live pty socket path or metadata placeholder
 *     attachers/<pid>    ← per-client last-seen metadata
 *     relay-status       ← live relay status / diagnostics
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
#include <dirent.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <zlib.h>

#if __has_include ("_libssh_libssh.h")
#  include "_libssh_libssh.h"
#  define BSCREEN_HAVE_LIBSSH 1
#elif __has_include ("_libssh/libssh.h")
#  include "_libssh/libssh.h"
#  define BSCREEN_HAVE_LIBSSH 1
#else
#  define BSCREEN_HAVE_LIBSSH 0
#endif

#include "loadables.h"

/* Default state directory. Override via BASHSCREEN_STATE_DIR env.
 *
 * Security review 2026-05-07 #3: define the private-dir contract NOW
 * before Stages 50.B/5/9/12/17/18 land socket / pid / scrollback files
 * here. The contract is: when the state dir already exists, it MUST
 * be owned by the calling uid and have mode 0700. A world-writable
 * /tmp/.screen is rejected so an attacker can't create the
 * directory first and then exploit symlink/race conditions on the
 * future per-session subdirs.
 */
#define BSCREEN_DEFAULT_STATE_DIR "/tmp/.screen"
#define BSCREEN_WINDOW_NAME_MAX 64
#define BSCREEN_CLUSTER_DEFAULT_DIR "/var/lib/cluster"
#define BSCREEN_REMOTE_MAGIC "BSCR"
#define BSCREEN_REMOTE_VERSION 1
#define BSCREEN_REMOTE_FRAME_PTY 1
#define BSCREEN_REMOTE_FRAME_QUERY 2
#define BSCREEN_REMOTE_FRAME_CONTROL 3
#define BSCREEN_DEFAULT_DETACH_KEY '\001'
#define BSCREEN_DEFAULT_ROAM_KEY 'r'
#define BSCREEN_CONTROL_ROAM "roam"

typedef enum {
    BSCREEN_RELAY_ERROR = -1,
    BSCREEN_RELAY_EOF = 0,
    BSCREEN_RELAY_DETACH = 1,
    BSCREEN_RELAY_ROAM = 2
} bscreen_relay_result;

struct bs_remote_frame_header {
    char magic[4];
    unsigned char version;
    unsigned char type;
    unsigned char len_be[4];
};

static void
bs_remote_u32_pack (unsigned char out[4], uint32_t v)
{
    out[0] = (unsigned char) ((v >> 24) & 0xff);
    out[1] = (unsigned char) ((v >> 16) & 0xff);
    out[2] = (unsigned char) ((v >> 8) & 0xff);
    out[3] = (unsigned char) (v & 0xff);
}

static uint32_t
bs_remote_u32_unpack (const unsigned char in[4])
{
    return ((uint32_t) in[0] << 24) |
           ((uint32_t) in[1] << 16) |
           ((uint32_t) in[2] << 8) |
           (uint32_t) in[3];
}

static void
bs_remote_frame_init (struct bs_remote_frame_header *h,
                      unsigned char type, uint32_t len)
{
    memcpy (h->magic, BSCREEN_REMOTE_MAGIC, sizeof h->magic);
    h->version = BSCREEN_REMOTE_VERSION;
    h->type = type;
    bs_remote_u32_pack (h->len_be, len);
}

static int
bs_remote_frame_valid (const struct bs_remote_frame_header *h,
                       uint32_t *len_out)
{
    if (memcmp (h->magic, BSCREEN_REMOTE_MAGIC, sizeof h->magic) != 0)
        return 0;
    if (h->version != BSCREEN_REMOTE_VERSION)
        return 0;
    if (h->type != BSCREEN_REMOTE_FRAME_PTY &&
        h->type != BSCREEN_REMOTE_FRAME_QUERY &&
        h->type != BSCREEN_REMOTE_FRAME_CONTROL)
        return 0;
    if (len_out)
        *len_out = bs_remote_u32_unpack (h->len_be);
    return 1;
}

static size_t
bs_remote_frame_build (char *out, size_t out_sz, unsigned char type,
                       const char *payload)
{
    struct bs_remote_frame_header h;
    size_t len = payload ? strlen (payload) : 0;
    if (out_sz < sizeof h + len)
        return 0;
    bs_remote_frame_init (&h, type, (uint32_t) len);
    memcpy (out, &h, sizeof h);
    if (len)
        memcpy (out + sizeof h, payload, len);
    return sizeof h + len;
}

static int
bs_remote_control_roam_frame (const char *buf, ssize_t n, size_t *frame_len)
{
    struct bs_remote_frame_header h;
    uint32_t len = 0;
    size_t need;
    if (n < (ssize_t) sizeof h)
        return 0;
    memcpy (&h, buf, sizeof h);
    if (!bs_remote_frame_valid (&h, &len) ||
        h.type != BSCREEN_REMOTE_FRAME_CONTROL)
        return 0;
    need = sizeof h + (size_t) len;
    if (len != sizeof BSCREEN_CONTROL_ROAM - 1 ||
        n < (ssize_t) need ||
        memcmp (buf + sizeof h, BSCREEN_CONTROL_ROAM, len) != 0)
        return 0;
    if (frame_len)
        *frame_len = need;
    return 1;
}

static const char *
bscreen_state_dir (void)
{
    const char *override = getenv ("BASHSCREEN_STATE_DIR");
    return override && *override ? override : BSCREEN_DEFAULT_STATE_DIR;
}

static const char *
bscreen_cluster_state_dir (void)
{
    const char *override = getenv ("BASHCLUSTER_STATE_DIR");
    if (override && *override) return override;
    override = getenv ("BASHCLUSTER_DIR");
    return override && *override ? override : BSCREEN_CLUSTER_DEFAULT_DIR;
}

static int bs_attach_live_relay (const char *sdir);
static int bs_relay_write_all (int fd, const char *buf, ssize_t n);
static int bs_session_path (char *out, size_t n, const char *root, const char *name);
static int bs_remote_ssh_attach (const char *hostport, const char *key,
                                 const char *session);
static unsigned char bs_detach_key (void);
static unsigned char bs_roam_key (void);
static int bs_key_match (unsigned char ch, unsigned char key);
static long bs_roam_reconnect_count (void);

/* Validate a private state directory. All screen state directories
 * are owned by the caller, mode 0700, and are checked with lstat so a
 * symlink is never accepted as a directory. */
static int
bs_validate_private_dir (const char *path, mode_t mode, const char *what)
{
    struct stat st;
    if (lstat (path, &st) < 0)
      {
        builtin_error ("screen: lstat %s: %s", path, strerror (errno));
        return -1;
      }
    if (!S_ISDIR (st.st_mode)) {
        builtin_error ("screen: %s %s is not a directory "
                       "(mode=0%o)",
                       what, path, (unsigned) (st.st_mode & 07777));
        return -1;
    }
    if (st.st_uid != geteuid ()) {
        builtin_error ("screen: %s %s is owned by uid %u, "
                       "not the caller (uid %u) — refusing to use it",
                       what, path, (unsigned) st.st_uid,
                       (unsigned) geteuid ());
        return -1;
    }
    if ((st.st_mode & 07777) != mode) {
        builtin_error ("screen: %s %s has mode 0%o, "
                       "expected 0%o — refuse to expose session state "
                       "to other users",
                       what, path, (unsigned) (st.st_mode & 07777),
                       (unsigned) mode);
        return -1;
    }
    return 0;
}

/* Validate (or create) the state-dir parent. Returns 0 if it's safe
 * to use, -1 if a security check failed (with builtin_error already
 * called). If mkdir races with another process, the path is rechecked
 * with lstat before use.
 */
static int
bscreen_validate_state_dir (const char *path)
{
    struct stat st;
    if (lstat (path, &st) < 0) {
        if (errno != ENOENT) {
            builtin_error ("screen: lstat %s: %s",
                           path, strerror (errno));
            return -1;
        }
        if (mkdir (path, 0700) < 0 && errno != EEXIST) {
            builtin_error ("screen: mkdir %s: %s",
                           path, strerror (errno));
            return -1;
        }
    }
    return bs_validate_private_dir (path, 0700, "state dir");
}

static const char *
bs_word (WORD_LIST **args)
{
    if (!args || !*args) return NULL;
    const char *w = (*args)->word->word;
    *args = (*args)->next;
    return w;
}

static int
bs_name_ok (const char *name)
{
    if (!name || !*name || strlen (name) > 96) return 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '-' ))
            return 0;
    return 1;
}

static const char *
bs_window_name_capped (const char *name, char out[BSCREEN_WINDOW_NAME_MAX + 1])
{
    const char *src = name && *name ? name : "bash";
    size_t len = strlen (src);
    if (len <= BSCREEN_WINDOW_NAME_MAX)
        return src;
    memcpy (out, src, BSCREEN_WINDOW_NAME_MAX);
    out[BSCREEN_WINDOW_NAME_MAX] = '\0';
    return out;
}

static int
bs_mkdir_if_needed (const char *path, mode_t mode)
{
    if (mkdir (path, mode) < 0 && errno != EEXIST) {
        builtin_error ("screen: mkdir %s: %s", path, strerror (errno));
        return -1;
    }
    return bs_validate_private_dir (path, mode, "state subdir");
}

static int
bs_write_file (const char *path, const char *value)
{
    char tmp[1024];
    int n = snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ());
    if (n < 0 || (size_t) n >= sizeof tmp) {
        builtin_error ("screen: temp path too long for %s", path);
        return -1;
    }

    FILE *f = fopen (tmp, "w");
    if (!f) {
        builtin_error ("screen: write %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (fputs (value ? value : "", f) < 0 || fflush (f) == EOF ||
        fsync (fileno (f)) < 0) {
        int saved = errno;
        fclose (f);
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: write %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (fclose (f) == EOF) {
        int saved = errno;
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: close %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (rename (tmp, path) < 0) {
        int saved = errno;
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: rename %s -> %s: %s", tmp, path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bs_session_exists (const char *sdir)
{
    char file[512];
    struct stat st;
    if (bs_validate_private_dir (sdir, 0700, "session dir") < 0)
        return 0;
    snprintf (file, sizeof file, "%s/pid", sdir);
    return lstat (file, &st) == 0 && S_ISREG (st.st_mode) &&
           st.st_uid == geteuid ();
}

static int
bs_read_file (const char *path, char *buf, size_t n)
{
    FILE *f = fopen (path, "r");
    if (!f) return -1;
    if (!fgets (buf, (int)n, f)) { fclose (f); return -1; }
    fclose (f);
    buf[strcspn (buf, "\r\n")] = '\0';
    return 0;
}

static int
bs_cluster_members_path (char *out, size_t n)
{
    int rc = snprintf (out, n, "%s/members", bscreen_cluster_state_dir ());
    if (rc < 0 || (size_t) rc >= n) {
        builtin_error ("screen: cluster members path too long");
        return -1;
    }
    return 0;
}

static int
bs_cluster_node_id (char *out, size_t n)
{
    char path[1024];
    int rc = snprintf (path, sizeof path, "%s/node_id", bscreen_cluster_state_dir ());
    if (rc < 0 || (size_t) rc >= sizeof path)
        return -1;
    return bs_read_file (path, out, n);
}

static int
bs_valid_cluster_token (const char *s)
{
    if (!s || !*s || strlen (s) > 128) return 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' ||
               *p == '-' || *p == ':' || *p == '/' || *p == '@' ))
            return 0;
    return 1;
}

static int
bs_cluster_lookup_member (const char *node, char *hostport, size_t hostport_sz,
                          char *key, size_t key_sz)
{
    char path[1024], line[1024];
    FILE *f;

    if (!node || !*node) {
        builtin_error ("screen: remote target needs NODE/SESSION");
        return -1;
    }
    if (bs_cluster_members_path (path, sizeof path) < 0)
        return -1;
    f = fopen (path, "r");
    if (!f) {
        builtin_error ("screen: cluster members unavailable at %s", path);
        return -1;
    }
    while (fgets (line, sizeof line, f)) {
        char mnode[129], mhost[129], mkey[256];
        char *p = line;
        mnode[0] = mhost[0] = '\0';
        mkey[0] = '-'; mkey[1] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        if (sscanf (p, "%128s %128s %255s", mnode, mhost, mkey) < 2)
            continue;
        if (!strcmp (mnode, node)) {
            fclose (f);
            if (!bs_valid_cluster_token (mnode) || !bs_valid_cluster_token (mhost)) {
                builtin_error ("screen: unsafe cluster member line for %s", node);
                return -1;
            }
            snprintf (hostport, hostport_sz, "%s", mhost);
            snprintf (key, key_sz, "%s", mkey[0] ? mkey : "-");
            return 0;
        }
    }
    fclose (f);
    builtin_error ("screen: no such cluster member: %s", node);
    return -1;
}

static int
bs_cluster_print_node_sessions (const char *node, const char *hostport,
                                const char *key)
{
    const char *root = bscreen_state_dir ();
    DIR *d;
    char local_node[129] = "";

    if (!bs_valid_cluster_token (node) || !bs_valid_cluster_token (hostport)) {
        builtin_error ("screen: unsafe cluster member: %s %s",
                       node ? node : "(null)", hostport ? hostport : "(null)");
        return -1;
    }

    /* Host-safe first slice: the fixture can advertise sessions in
     * $BASHCLUSTER_STATE_DIR/sessions/<node>. When that file is absent
     * for the local node, fall back to the local screen state dir.
     * This keeps discovery deterministic without requiring a second host
     * or SSH daemon. */
    {
        char sessions_path[1024], line[256];
        FILE *sf;
        int rc = snprintf (sessions_path, sizeof sessions_path, "%s/sessions/%s",
                           bscreen_cluster_state_dir (), node);
        if (rc >= 0 && (size_t) rc < sizeof sessions_path &&
            (sf = fopen (sessions_path, "r")) != NULL) {
            while (fgets (line, sizeof line, sf)) {
                line[strcspn (line, "\r\n")] = '\0';
                if (!line[0] || line[0] == '#') continue;
                if (!bs_name_ok (line)) continue;
                printf ("%s/%s\t%s\tkey=%s\n", node, line, hostport,
                        (key && *key) ? key : "-");
            }
            fclose (sf);
            return 0;
        }
    }

    if (bs_cluster_node_id (local_node, sizeof local_node) < 0 ||
        strcmp (local_node, node) != 0)
        return 0;

    if (bscreen_validate_state_dir (root) < 0)
        return -1;
    d = opendir (root);
    if (!d)
        return 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        char pidpath[512];
        struct stat st;
        if (ent->d_name[0] == '.') continue;
        if (!bs_name_ok (ent->d_name)) continue;
        snprintf (pidpath, sizeof pidpath, "%s/%s/pid", root, ent->d_name);
        if (stat (pidpath, &st) == 0 && S_ISREG (st.st_mode))
            printf ("%s/%s\t%s\tkey=%s\n", node, ent->d_name, hostport,
                    (key && *key) ? key : "-");
    }
    closedir (d);
    return 0;
}

static int
bscreen_cluster_list_cmd (void)
{
    char path[1024], line[1024];
    FILE *f;

    if (bs_cluster_members_path (path, sizeof path) < 0)
        return EXECUTION_FAILURE;
    f = fopen (path, "r");
    if (!f)
        return EXECUTION_SUCCESS;

    while (fgets (line, sizeof line, f)) {
        char node[129], hostport[129], key[256];
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        key[0] = '-'; key[1] = '\0';
        if (sscanf (p, "%128s %128s %255s", node, hostport, key) < 2)
            continue;
        if (bs_cluster_print_node_sessions (node, hostport, key) < 0) {
            fclose (f);
            return EXECUTION_FAILURE;
        }
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bs_resolve_remote_target (const char *verb, const char *target,
                          const char *key_override,
                          char *node, size_t node_sz,
                          char *session, size_t session_sz,
                          char *hostport, size_t hostport_sz,
                          char *key, size_t key_sz)
{
    const char *slash;
    size_t node_len, session_len;

    if (!target || !(slash = strchr (target, '/')) || slash == target || !slash[1]) {
        builtin_error ("%s: target must be NODE/SESSION", verb);
        return EX_USAGE;
    }
    node_len = (size_t) (slash - target);
    session_len = strlen (slash + 1);
    if (node_len >= node_sz || session_len >= session_sz) {
        builtin_error ("%s: target too long", verb);
        return EX_USAGE;
    }
    memcpy (node, target, node_len);
    node[node_len] = '\0';
    snprintf (session, session_sz, "%s", slash + 1);
    if (!bs_valid_cluster_token (node) || !bs_name_ok (session)) {
        builtin_error ("%s: unsafe target: %s", verb, target);
        return EX_USAGE;
    }
    if (bs_cluster_lookup_member (node, hostport, hostport_sz, key, key_sz) < 0)
        return EXECUTION_FAILURE;
    if (key_override && *key_override)
        snprintf (key, key_sz, "%s", key_override);
    return EXECUTION_SUCCESS;
}

static int
bscreen_attach_remote_cmd (const char *target, const char *key_override, int dry_run)
{
    char node[129], session[129], hostport[129], key[256];
    int resolved = bs_resolve_remote_target ("attach --remote", target, key_override,
                                             node, sizeof node, session, sizeof session,
                                             hostport, sizeof hostport, key, sizeof key);
    if (resolved != EXECUTION_SUCCESS)
        return resolved;

    if (dry_run) {
        printf ("node=%s\nsession=%s\nhostport=%s\nkey=%s\ncommand=screen attach %s -r\n",
                node, session, hostport, key, session);
        return EXECUTION_SUCCESS;
    }

    if ((getenv ("BASHSCREEN_REMOTE_LOOPBACK") &&
         strcmp (getenv ("BASHSCREEN_REMOTE_LOOPBACK"), "0") != 0) ||
        !strcmp (hostport, "local") || !strcmp (hostport, "localhost:0")) {
        char sdir[512];
        const char *root = bscreen_state_dir ();
        if (bscreen_validate_state_dir (root) < 0)
            return EXECUTION_FAILURE;
        if (bs_session_path (sdir, sizeof sdir, root, session) < 0)
            return EX_USAGE;
        if (bs_attach_live_relay (sdir) >= 0)
            return EXECUTION_SUCCESS;
        builtin_error ("attach --remote: loopback relay unavailable for %s/%s",
                       node, session);
        return EXECUTION_FAILURE;
    }

    return bs_remote_ssh_attach (hostport, key, session);
}

static int
bs_parse_remote_hostport (const char *hostport, char *host, size_t host_sz,
                          char *port, size_t port_sz, char *user,
                          size_t user_sz)
{
    char tmp[256];
    const char *hp;
    const char *at, *colon;

    if (!hostport || !*hostport || !bs_valid_cluster_token (hostport))
        return -1;
    snprintf (tmp, sizeof tmp, "%s", hostport);
    hp = tmp;
    user[0] = '\0';

    at = strchr (hp, '@');
    if (at) {
        size_t ul = (size_t) (at - hp);
        if (ul == 0 || ul >= user_sz)
            return -1;
        memcpy (user, hp, ul);
        user[ul] = '\0';
        hp = at + 1;
    }

    colon = strrchr (hp, ':');
    if (colon && strchr (hp, ':') == colon) {
        size_t hl = (size_t) (colon - hp);
        if (hl == 0 || hl >= host_sz || strlen (colon + 1) >= port_sz)
            return -1;
        memcpy (host, hp, hl);
        host[hl] = '\0';
        snprintf (port, port_sz, "%s", colon + 1);
    } else {
        if (strlen (hp) >= host_sz)
            return -1;
        snprintf (host, host_sz, "%s", hp);
        snprintf (port, port_sz, "22");
    }

    if (!host[0] || !port[0])
        return -1;
    for (const char *p = port; *p; p++)
        if (*p < '0' || *p > '9')
            return -1;
    return 0;
}

#if BSCREEN_HAVE_LIBSSH
static int bs_remote_libssh_initialized;

static int
bs_remote_libssh_init (void)
{
    if (bs_remote_libssh_initialized)
        return 0;
    if (ssh_init () != SSH_OK) {
        builtin_error ("attach --remote: libssh init failed");
        return -1;
    }
    bs_remote_libssh_initialized = 1;
    return 0;
}

static int
bs_remote_set_crypto_env (ssh_session ssh)
{
    const char *c = getenv ("BASHSSH_CIPHERS");
    const char *m = getenv ("BASHSSH_MACS");
    const char *k = getenv ("BASHSSH_KEX");
    const char *rk = getenv ("BASHSSH_REKEY");

    if ((c && *c && (ssh_options_set (ssh, SSH_OPTIONS_CIPHERS_C_S, c) != SSH_OK
                 || ssh_options_set (ssh, SSH_OPTIONS_CIPHERS_S_C, c) != SSH_OK))
        || (m && *m && (ssh_options_set (ssh, SSH_OPTIONS_HMAC_C_S, m) != SSH_OK
                    || ssh_options_set (ssh, SSH_OPTIONS_HMAC_S_C, m) != SSH_OK))
        || (k && *k && ssh_options_set (ssh, SSH_OPTIONS_KEY_EXCHANGE, k) != SSH_OK)) {
        builtin_error ("attach --remote: rejected SSH crypto allow-list: %s",
                       ssh_get_error (ssh));
        return -1;
    }
    if (rk && *rk) {
        uint64_t rd = (uint64_t) strtoull (rk, NULL, 10);
        if (rd > 0)
            ssh_options_set (ssh, SSH_OPTIONS_REKEY_DATA, &rd);
    }
    return 0;
}

static int
bs_remote_known_host_check (ssh_session ssh, const char *host)
{
    int mode = 0; /* 0=accept-new, 1=yes, 2=no */
    const char *m = getenv ("BASHSSH_STRICT_HOST_KEY_CHECKING");
    if (m && (!strcmp (m, "yes") || !strcmp (m, "strict")))
        mode = 1;
    else if (m && (!strcmp (m, "no") || !strcmp (m, "off")))
        mode = 2;

    enum ssh_known_hosts_e kh = ssh_session_is_known_server (ssh);
    if (kh == SSH_KNOWN_HOSTS_OK)
        return 0;
    if (kh == SSH_KNOWN_HOSTS_CHANGED) {
        if (mode == 2) {
            fprintf (stderr, "screen: WARNING: host key changed for %s; accepting (StrictHostKeyChecking=no)\n",
                     host);
            return ssh_session_update_known_hosts (ssh) == SSH_OK ? 0 : -1;
        }
        builtin_error ("attach --remote: host key CHANGED for %s", host);
        return -1;
    }
    if (kh == SSH_KNOWN_HOSTS_UNKNOWN || kh == SSH_KNOWN_HOSTS_NOT_FOUND) {
        if (mode == 1) {
            builtin_error ("attach --remote: unknown host key for %s", host);
            return -1;
        }
        if (ssh_session_update_known_hosts (ssh) == SSH_OK)
            return 0;
        builtin_error ("attach --remote: could not update known_hosts for %s: %s",
                       host, ssh_get_error (ssh));
        return -1;
    }
    builtin_error ("attach --remote: host key error for %s: %s",
                   host, ssh_get_error (ssh));
    return -1;
}

static int
bs_remote_channel_write_all (ssh_channel ch, const char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        int wr = ssh_channel_write (ch, buf + off, (uint32_t) (n - off));
        if (wr == SSH_ERROR)
            return -1;
        if (wr == SSH_AGAIN || wr == 0)
            continue;
        off += (size_t) wr;
    }
    return 0;
}

static int
bs_remote_channel_send_control_roam (ssh_channel ch)
{
    char frame[sizeof (struct bs_remote_frame_header) + sizeof BSCREEN_CONTROL_ROAM - 1];
    size_t len = bs_remote_frame_build (frame, sizeof frame,
                                        BSCREEN_REMOTE_FRAME_CONTROL,
                                        BSCREEN_CONTROL_ROAM);
    if (!len)
        return -1;
    return bs_remote_channel_write_all (ch, frame, len);
}

static int
bs_remote_channel_relay (ssh_session ssh, ssh_channel ch)
{
    bscreen_relay_result result = BSCREEN_RELAY_EOF;
    int sfd = ssh_get_fd (ssh);
    int stdin_open = 1;
    int is_tty = isatty (STDIN_FILENO);
    int raw_set = 0;
    int escape_pending = 0;
    unsigned char detach_key = bs_detach_key ();
    unsigned char roam_key = bs_roam_key ();
    struct termios orig;
    char buf[8192];

    if (is_tty && tcgetattr (STDIN_FILENO, &orig) == 0) {
        struct termios raw = orig;
        cfmakeraw (&raw);
        if (tcsetattr (STDIN_FILENO, TCSANOW, &raw) == 0)
            raw_set = 1;
    }

    for (;;) {
        fd_set rfds;
        int maxfd = sfd;
        struct timeval tv;
        FD_ZERO (&rfds);
        if (stdin_open) {
            FD_SET (STDIN_FILENO, &rfds);
            if (STDIN_FILENO > maxfd) maxfd = STDIN_FILENO;
        }
        if (sfd >= 0)
            FD_SET (sfd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR)
                continue;
            result = BSCREEN_RELAY_ERROR;
            break;
        }

        if (stdin_open && FD_ISSET (STDIN_FILENO, &rfds)) {
            ssize_t nr = read (STDIN_FILENO, buf, sizeof buf);
            if (nr > 0) {
                ssize_t start = 0;
                int stop_stdin = 0;
                for (ssize_t i = 0; i < nr; i++) {
                    unsigned char uch = (unsigned char) buf[i];
                    if (escape_pending) {
                        if (i > start &&
                            bs_remote_channel_write_all (ch, buf + start, (size_t) (i - start)) < 0) {
                            result = BSCREEN_RELAY_ERROR;
                            goto out;
                        }
                        escape_pending = 0;
                        start = i + 1;
                        if (bs_key_match (uch, 'd')) {
                            ssh_channel_send_eof (ch);
                            stdin_open = 0;
                            result = BSCREEN_RELAY_DETACH;
                            stop_stdin = 1;
                            break;
                        }
                        if (bs_key_match (uch, roam_key)) {
                            if (bs_remote_channel_send_control_roam (ch) < 0)
                                result = BSCREEN_RELAY_ERROR;
                            else {
                                ssh_channel_send_eof (ch);
                                stdin_open = 0;
                                result = BSCREEN_RELAY_ROAM;
                            }
                            stop_stdin = 1;
                            break;
                        }
                        {
                            char literal[2] = { (char) detach_key, (char) uch };
                            if (bs_remote_channel_write_all (ch, literal, sizeof literal) < 0) {
                                result = BSCREEN_RELAY_ERROR;
                                goto out;
                            }
                        }
                    } else if (uch == detach_key) {
                        if (i > start &&
                            bs_remote_channel_write_all (ch, buf + start, (size_t) (i - start)) < 0) {
                            result = BSCREEN_RELAY_ERROR;
                            goto out;
                        }
                        escape_pending = 1;
                        start = i + 1;
                    }
                }
                if (stop_stdin && result == BSCREEN_RELAY_ERROR)
                    goto out;
                if (!stop_stdin && nr > start &&
                    bs_remote_channel_write_all (ch, buf + start, (size_t) (nr - start)) < 0) {
                    result = BSCREEN_RELAY_ERROR;
                    break;
                }
            } else {
                if (escape_pending) {
                    char lit = (char) detach_key;
                    (void) bs_remote_channel_write_all (ch, &lit, 1);
                    escape_pending = 0;
                }
                ssh_channel_send_eof (ch);
                stdin_open = 0;
            }
        }

        int avail = ssh_channel_poll_timeout (ch, 0, 0);
        if (avail == SSH_ERROR) {
            result = BSCREEN_RELAY_ERROR;
            break;
        }
        while (avail > 0) {
            uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
            int rr = ssh_channel_read (ch, buf, chunk, 0);
            if (rr <= 0)
                break;
            if (bs_relay_write_all (STDOUT_FILENO, buf, rr) < 0)
                break;
            avail -= rr;
        }

        avail = ssh_channel_poll_timeout (ch, 0, 1);
        if (avail == SSH_ERROR) {
            result = BSCREEN_RELAY_ERROR;
            break;
        }
        while (avail > 0) {
            uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
            int rr = ssh_channel_read (ch, buf, chunk, 1);
            if (rr <= 0)
                break;
            if (bs_relay_write_all (STDERR_FILENO, buf, rr) < 0)
                break;
            avail -= rr;
        }

        if (ssh_channel_is_eof (ch) || !ssh_channel_is_open (ch))
            break;
    }

out:
    if (raw_set)
        tcsetattr (STDIN_FILENO, TCSANOW, &orig);
    return result;
}

static int
bs_remote_ssh_attach (const char *hostport, const char *key, const char *session)
{
    char host[129], port[16], user[129], cmd[256], start_line[512];
    int port_i, batch = 1, no = 0, strict_yes = SSH_STRICT_HOSTKEY_YES;
    int pubkey = SSH_PUBKEY_AUTH_ALL;
    bool identities_only = true;
    ssh_session ssh = NULL;
    ssh_channel ch = NULL;
    int rc = EXECUTION_FAILURE;
    long reconnects;
    int attempt = 0;
    bscreen_relay_result relay_rc = BSCREEN_RELAY_ERROR;

    if (bs_parse_remote_hostport (hostport, host, sizeof host, port, sizeof port,
                                  user, sizeof user) < 0) {
        builtin_error ("attach --remote: bad hostport: %s", hostport ? hostport : "(null)");
        return EX_USAGE;
    }
    port_i = atoi (port);
    if (port_i <= 0 || port_i > 65535) {
        builtin_error ("attach --remote: bad port in %s", hostport);
        return EX_USAGE;
    }
    if (bs_remote_libssh_init () < 0)
        return EXECUTION_FAILURE;
    reconnects = bs_roam_reconnect_count ();

retry:
    ssh = ssh_new ();
    if (!ssh) {
        builtin_error ("attach --remote: ssh_new failed");
        return EXECUTION_FAILURE;
    }
    const char *no_agent = "/nonexistent/screen-agent.sock";
    if (ssh_options_set (ssh, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PORT, &port_i) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_BATCH_MODE, &batch) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_yes) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_IDENTITIES_ONLY, &identities_only) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_IDENTITY_AGENT, no_agent) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PASSWORD_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_KBDINT_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_GSSAPI_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PUBKEY_AUTH, &pubkey) != SSH_OK ||
        (user[0] && ssh_options_set (ssh, SSH_OPTIONS_USER, user) != SSH_OK) ||
        bs_remote_set_crypto_env (ssh) < 0) {
        builtin_error ("attach --remote: SSH options failed: %s", ssh_get_error (ssh));
        goto out;
    }
    {
        const char *khf = getenv ("BASHSSH_KNOWN_HOSTS");
        if (khf && *khf &&
            (ssh_options_set (ssh, SSH_OPTIONS_KNOWNHOSTS, khf) != SSH_OK ||
             ssh_options_set (ssh, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null") != SSH_OK)) {
            builtin_error ("attach --remote: known_hosts option failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
    }
    if (ssh_connect (ssh) != SSH_OK) {
        builtin_error ("attach --remote: connect %s:%s: %s", host, port,
                       ssh_get_error (ssh));
        relay_rc = BSCREEN_RELAY_EOF;
        goto maybe_retry;
    }
    if (bs_remote_known_host_check (ssh, host) < 0)
        goto out;

    if (key && key[0] && strcmp (key, "-")) {
        ssh_key auth_key = NULL;
        if (ssh_pki_import_privkey_file (key, NULL, NULL, NULL, &auth_key) != SSH_OK) {
            builtin_error ("attach --remote: identity %s: %s", key,
                           ssh_get_error (ssh));
            goto out;
        }
        int auth_rc = ssh_userauth_publickey (ssh, NULL, auth_key);
        ssh_key_free (auth_key);
        if (auth_rc != SSH_AUTH_SUCCESS) {
            builtin_error ("attach --remote: public-key auth failed for %s: %s",
                           host, ssh_get_error (ssh));
            goto out;
        }
    } else if (ssh_userauth_publickey_auto (ssh, NULL, NULL) != SSH_AUTH_SUCCESS) {
        builtin_error ("attach --remote: public-key auth failed for %s: %s",
                       host, ssh_get_error (ssh));
        goto out;
    }

    ch = ssh_channel_new (ssh);
    if (!ch || ssh_channel_open_session (ch) != SSH_OK) {
        builtin_error ("attach --remote: channel open failed: %s",
                       ssh_get_error (ssh));
        goto out;
    }
    {
        int cols = 80, rows = 24;
        struct winsize ws;
        const char *term = getenv ("TERM");
        if (isatty (STDIN_FILENO) && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            cols = ws.ws_col;
            rows = ws.ws_row;
        }
        if (ssh_channel_request_pty_size (ch, term && *term ? term : "xterm",
                                          cols, rows) != SSH_OK) {
            builtin_error ("attach --remote: pty request failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
        if (ssh_channel_request_shell (ch) != SSH_OK) {
            builtin_error ("attach --remote: shell request failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
    }
    {
        const char *remote_bash = getenv ("BASHSCREEN_REMOTE_BASH");
        const char *remote_state = getenv ("BASHSCREEN_REMOTE_STATE_DIR");
        if (!remote_state || !*remote_state)
            remote_state = getenv ("BASHSCREEN_STATE_DIR");
        if (remote_state && *remote_state && !bs_valid_cluster_token (remote_state)) {
            builtin_error ("attach --remote: unsafe remote state dir");
            goto out;
        }
        if (remote_bash && *remote_bash) {
            if (!bs_valid_cluster_token (remote_bash)) {
                builtin_error ("attach --remote: unsafe BASHSCREEN_REMOTE_BASH");
                goto out;
            }
            snprintf (cmd, sizeof cmd, "%s -c 'screen attach %s -r'",
                      remote_bash, session);
        } else {
            snprintf (cmd, sizeof cmd, "screen attach %s -r", session);
        }
        if (remote_state && *remote_state)
            snprintf (start_line, sizeof start_line,
                      "BASHSCREEN_STATE_DIR=%s exec %s\n", remote_state, cmd);
        else
            snprintf (start_line, sizeof start_line, "exec %s\n", cmd);
    }
    if (bs_remote_channel_write_all (ch, start_line, strlen (start_line)) < 0) {
        builtin_error ("attach --remote: failed to start remote command");
        goto out;
    }
    relay_rc = bs_remote_channel_relay (ssh, ch);
    if (relay_rc == BSCREEN_RELAY_ERROR)
        goto out;
    if (relay_rc == BSCREEN_RELAY_EOF && attempt < reconnects)
        goto maybe_retry;
    rc = ssh_channel_get_exit_status (ch);
    for (int i = 0; i < 100 && rc < 0; i++) {
        ssh_channel_poll_timeout (ch, 10, 0);
        rc = ssh_channel_get_exit_status (ch);
    }
    if (rc < 0) rc = 0;

out:
    if (ch) {
        ssh_channel_close (ch);
        ssh_channel_free (ch);
    }
    if (ssh) {
        ssh_disconnect (ssh);
        ssh_free (ssh);
    }
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

maybe_retry:
    if (ch) {
        ssh_channel_close (ch);
        ssh_channel_free (ch);
        ch = NULL;
    }
    if (ssh) {
        ssh_disconnect (ssh);
        ssh_free (ssh);
        ssh = NULL;
    }
    if (relay_rc == BSCREEN_RELAY_EOF && attempt++ < reconnects) {
        usleep (250000);
        goto retry;
    }
    goto out;
}
#else
static int
bs_remote_ssh_attach (const char *hostport, const char *key, const char *session)
{
    (void) hostport; (void) key; (void) session;
    builtin_error ("attach --remote: libssh transport is not compiled in");
    return EXECUTION_FAILURE;
}
#endif

static int
bs_append_file (const char *path, const char *buf, size_t len)
{
    FILE *f = fopen (path, "a");
    if (!f) return -1;
    if (len && fwrite (buf, 1, len, f) != len) {
        int saved = errno;
        fclose (f);
        errno = saved;
        return -1;
    }
    if (fclose (f) == EOF) return -1;
    return 0;
}

/* Stage 50.F scrollback compression + GC (2026-05-11).
 *
 * Long-running screen sessions can grow per-pane scrollback
 * without bound. To cap memory, the loadable folds aging history
 * into gzip blobs and drops the oldest blob when total bytes
 * exceed a configurable cap.
 *
 * Layout (per-pane):
 *     <pane_dir>/scrollback           live append-only tail
 *     <pane_dir>/blobs/000000.gz      oldest compressed slab
 *     <pane_dir>/blobs/000001.gz      ...
 *     <pane_dir>/blobs/.last-gc       mtime gates GC rate-limit
 *
 * Compression triggers when the live scrollback reaches
 * BASHSCREEN_COMPRESS_AFTER_LINES newlines. The entire live file
 * is gzipped into the next blob and then truncated; the next
 * appends start a fresh tail. GC drops the oldest blob whenever
 * total bytes (live + blobs) exceed BASHSCREEN_MAX_BYTES, and is
 * rate-limited by BASHSCREEN_GC_INTERVAL_SEC (mtime of
 * blobs/.last-gc). Set the interval to 0 to run GC every time.
 *
 * The session-level scrollback (<sdir>/scrollback) is treated as
 * just another pane scrollback for this purpose — its blobs live
 * at <sdir>/blobs/.
 */
#define BSCREEN_DEFAULT_COMPRESS_LINES 1024L
#define BSCREEN_DEFAULT_MAX_BYTES      (4L * 1024L * 1024L)
#define BSCREEN_DEFAULT_GC_INTERVAL    60L
#define BSCREEN_GC_INTERVAL_MAX        86400L

static long
bs_env_long (const char *name, long defv)
{
    const char *v = getenv (name);
    if (!v || !*v) return defv;
    char *end = NULL;
    long n = strtol (v, &end, 10);
    if (end == v || (*end != '\0' && *end != '\n') || n < 0) return defv;
    return n;
}

static long bs_compress_threshold (void) { return bs_env_long ("BASHSCREEN_COMPRESS_AFTER_LINES", BSCREEN_DEFAULT_COMPRESS_LINES); }
static long bs_max_bytes          (void) { return bs_env_long ("BASHSCREEN_MAX_BYTES",            BSCREEN_DEFAULT_MAX_BYTES); }

static unsigned char
bs_env_key (const char *name, unsigned char defv)
{
    const char *v = getenv (name);
    if (!v || !*v)
        return defv;
    if (v[0] == '^' && v[1] && !v[2]) {
        unsigned char c = (unsigned char) v[1];
        if (c >= 'a' && c <= 'z')
            c = (unsigned char) (c - 'a' + 'A');
        return (unsigned char) (c & 0x1f);
    }
    return (unsigned char) v[0];
}

static unsigned char bs_detach_key (void) { return bs_env_key ("BASHSCREEN_DETACH_KEY", BSCREEN_DEFAULT_DETACH_KEY); }
static unsigned char bs_roam_key   (void) { return bs_env_key ("BASHSCREEN_ROAM_KEY",   BSCREEN_DEFAULT_ROAM_KEY); }

static int
bs_key_match (unsigned char ch, unsigned char key)
{
    if (ch == key)
        return 1;
    if (key >= 'a' && key <= 'z' && ch == (unsigned char) (key - 'a' + 'A'))
        return 1;
    return 0;
}

static long
bs_roam_reconnect_count (void)
{
    long n = bs_env_long ("BASHSCREEN_ROAM_RECONNECT", 0);
    if (n > 16)
        return 16;
    return n;
}

/* Round 1778631147 Doc 5: BASHSCREEN_GC_INTERVAL_SEC accepts integers
 * but a negative or absurdly large value previously slid through as
 * either "use the default" (negative — bs_env_long rejected) or "wait
 * forever" (huge). Clamp to [0, BSCREEN_GC_INTERVAL_MAX] and emit a
 * single warning per process when the raw env value lands out of
 * range. Garbage / unset env keeps the original default-fallthrough. */
static long
bs_gc_interval_sec (void)
{
    static int warned = 0;
    const char *v = getenv ("BASHSCREEN_GC_INTERVAL_SEC");
    if (!v || !*v) return BSCREEN_DEFAULT_GC_INTERVAL;
    char *end = NULL;
    long n = strtol (v, &end, 10);
    if (end == v || (*end != '\0' && *end != '\n')) return BSCREEN_DEFAULT_GC_INTERVAL;
    if (n < 0) {
        if (!warned) {
            warned = 1;
            builtin_warning ("BASHSCREEN_GC_INTERVAL_SEC=%ld out of range [0,%ld]; clamped to 0",
                             n, BSCREEN_GC_INTERVAL_MAX);
        }
        return 0;
    }
    if (n > BSCREEN_GC_INTERVAL_MAX) {
        if (!warned) {
            warned = 1;
            builtin_warning ("BASHSCREEN_GC_INTERVAL_SEC=%ld out of range [0,%ld]; clamped to %ld",
                             n, BSCREEN_GC_INTERVAL_MAX, BSCREEN_GC_INTERVAL_MAX);
        }
        return BSCREEN_GC_INTERVAL_MAX;
    }
    return n;
}

/* Derive blobs dir from a scrollback file path. sb_path MUST end in
 * "/scrollback"; on success, out is "<parent-dir>/blobs". */
static int
bs_scrollback_blobs_dir (const char *sb_path, char *out, size_t n)
{
    static const char suffix[] = "/scrollback";
    size_t slen = sizeof suffix - 1;
    size_t len = strlen (sb_path);
    if (len < slen || strcmp (sb_path + len - slen, suffix) != 0) {
        errno = EINVAL;
        return -1;
    }
    size_t prefix_len = len - slen;
    int rc = snprintf (out, n, "%.*s/blobs", (int) prefix_len, sb_path);
    if (rc < 0 || (size_t) rc >= n) return -1;
    return 0;
}

static long
bs_count_newlines (const char *path)
{
    FILE *f = fopen (path, "r");
    if (!f) return -1;
    long n = 0;
    int ch;
    while ((ch = fgetc (f)) != EOF) if (ch == '\n') n++;
    fclose (f);
    return n;
}

/* Largest valid 6+ digit "NNN.gz" blob index in dir, or -1 if none. */
static int
bs_max_blob_idx (const char *blobs_dir)
{
    DIR *d = opendir (blobs_dir);
    if (!d) return -1;
    int max = -1;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (v > max) max = (int) v;
    }
    closedir (d);
    return max;
}

/* Sum of byte sizes across live scrollback + all blobs. */
static long
bs_total_scrollback_bytes (const char *sb_path, const char *blobs_dir)
{
    long total = 0;
    struct stat st;
    if (stat (sb_path, &st) == 0) total += (long) st.st_size;
    DIR *d = opendir (blobs_dir);
    if (!d) return total;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        if (strtol (ent->d_name, &end, 10) == 0 && end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        char p[1024];
        int rc = snprintf (p, sizeof p, "%s/%s", blobs_dir, ent->d_name);
        if (rc < 0 || (size_t) rc >= sizeof p) continue;
        if (stat (p, &st) == 0) total += (long) st.st_size;
    }
    closedir (d);
    return total;
}

/* Find the oldest blob (smallest numeric index) in blobs_dir. Returns
 * 0 on success with name copied into out (sized >= 64), -1 if no blob. */
static int
bs_find_oldest_blob (const char *blobs_dir, char *out, size_t outsz)
{
    DIR *d = opendir (blobs_dir);
    if (!d) return -1;
    long min = -1;
    char picked[64] = "";
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (min < 0 || v < min) {
            min = v;
            snprintf (picked, sizeof picked, "%s", ent->d_name);
        }
    }
    closedir (d);
    if (min < 0) return -1;
    snprintf (out, outsz, "%s", picked);
    return 0;
}

/* Sorted ascending blob name list. Caller frees the returned array
 * (and each entry). Returns count, or 0 with *out_names NULL on empty
 * or alloc failure. */
static int
bs_list_blobs_sorted (const char *blobs_dir, char ***out_names)
{
    *out_names = NULL;
    DIR *d = opendir (blobs_dir);
    if (!d) return 0;
    int cap = 32, n = 0;
    long *idxs = malloc ((size_t) cap * sizeof *idxs);
    char **names = malloc ((size_t) cap * sizeof *names);
    if (!idxs || !names) { free (idxs); free (names); closedir (d); return 0; }
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (n >= cap) {
            int nc = cap * 2;
            long *ni = realloc (idxs, (size_t) nc * sizeof *ni);
            char **nn = realloc (names, (size_t) nc * sizeof *nn);
            if (!ni || !nn) {
                if (ni) idxs = ni;
                if (nn) names = nn;
                for (int i = 0; i < n; i++) free (names[i]);
                free (idxs); free (names); closedir (d); return 0;
            }
            idxs = ni; names = nn; cap = nc;
        }
        idxs[n] = v;
        names[n] = strdup (ent->d_name);
        if (!names[n]) {
            for (int i = 0; i < n; i++) free (names[i]);
            free (idxs); free (names); closedir (d); return 0;
        }
        n++;
    }
    closedir (d);
    for (int i = 1; i < n; i++) {
        long iv = idxs[i]; char *in = names[i];
        int j = i;
        while (j > 0 && idxs[j-1] > iv) {
            idxs[j] = idxs[j-1]; names[j] = names[j-1];
            j--;
        }
        idxs[j] = iv; names[j] = in;
    }
    free (idxs);
    *out_names = names;
    return n;
}

/* Compress the entire live scrollback into the next blob and
 * truncate the live file. Caller must have already verified that
 * compression is warranted.
 *
 * Round 1778567182 / Stage 50.F robustness pass: the prior version
 * left several silent-failure traps that produced size-32, wrong-
 * magic blobs on the guest while passing host-side syntax gates.
 * Each step below is now explicitly checked, AND the finished tmp
 * file is sniffed for the gzip magic (1f 8b) BEFORE the atomic
 * rename — so a half-written stream can never end up at the final
 * path under any failure mode (short write, zlib internal error,
 * fclose-without-fsync followed by power loss / OOM at flush, or
 * a concurrent writer racing to the same tmp name).
 *
 * Round 1778567182 / Doc 1 follow-up (2026-05-11): the magic-byte
 * sniff catches half-written headers, but a blob whose header is
 * correct yet whose deflate body lost the payload (zlib internal
 * Z_BUF_ERROR swallowed by gzclose's flush ladder under static-musl
 * link) would still pass and surface as count=0 at the reader. We
 * now ALSO run a roundtrip gzread immediately after gzclose: open
 * the tmp blob with gzopen("rb") and read the first chunk back. If
 * the writer ingested any uncompressed bytes (`uncompressed_total
 * > 0`) but the roundtrip reads zero, that's a header-only blob —
 * exactly the failure shape Round 1778567182 / Doc 1 traced and
 * the case-9 diagnostic in 199-screen-scrollback-gc.sh asserts
 * against. Reject and unlink the tmp before publishing.
 *
 * Cost: one extra gzopen + gzread + gzclose on a file that's
 * almost always <8 KiB after compression. Negligible vs the
 * deflate work that already ran.
 *
 * The fopen(in,"rb") -> gzopen(out,"wb") -> fread/gzwrite loop is
 * stdio-buffered on both sides. We explicitly fflush() the bash
 * stdio path used for appends earlier in the call chain
 * (bs_append_file's fclose() is the flush), but the writer here
 * MUST NOT rely on any I/O ordering between this process and a
 * concurrent relay-loop writer in the bash-os daemon. The tmp
 * name carries getpid() to keep parallel compresses from clobber-
 * ing each other's tmp; the rename is the single atomic publish. */
static int
bs_compress_scrollback_now (const char *sb_path)
{
    char blobs_dir[1024], blob_path[1024], blob_tmp[1100];
    if (bs_scrollback_blobs_dir (sb_path, blobs_dir, sizeof blobs_dir) < 0) return -1;
    if (bs_mkdir_if_needed (blobs_dir, 0700) < 0) return -1;
    int idx = bs_max_blob_idx (blobs_dir) + 1;
    int rc = snprintf (blob_path, sizeof blob_path, "%s/%06d.gz", blobs_dir, idx);
    if (rc < 0 || (size_t) rc >= sizeof blob_path) return -1;
    rc = snprintf (blob_tmp, sizeof blob_tmp, "%s.tmp.%ld", blob_path, (long) getpid ());
    if (rc < 0 || (size_t) rc >= sizeof blob_tmp) return -1;

    /* Pre-clear any stale tmp from a previous interrupted compress
     * with the same pid (recycled after a fork-exec ladder). */
    unlink (blob_tmp);

    FILE *in = fopen (sb_path, "rb");
    if (!in) return -1;

    /* gzopen("wb") opens the file with mode "wb" (truncating) and
     * sets compression level 6 / gzip wrapper format by default —
     * the resulting stream MUST start with the two-byte gzip magic
     * 1f 8b. If a non-gzip blob ever appears at the final path,
     * the post-write magic check below catches it and aborts the
     * publish rather than serving corrupted data to capture-pane. */
    gzFile gz = gzopen (blob_tmp, "wb");
    if (!gz) { fclose (in); return -1; }
    char buf[8192];
    size_t r;
    int err = 0;
    long uncompressed_total = 0;
    while ((r = fread (buf, 1, sizeof buf, in)) > 0) {
        int w = gzwrite (gz, buf, (unsigned int) r);
        /* gzwrite returns the input bytes written or 0 on error.
         * Anything other than `r` means a short / failed write. */
        if (w <= 0 || (size_t) w != r) { err = 1; break; }
        uncompressed_total += (long) r;
    }
    /* If fread terminated on a stream error (not EOF), flag it. */
    if (!err && ferror (in)) err = 1;
    fclose (in);

    /* gzclose flushes any pending deflate output, writes the
     * gzip trailer (CRC32 + ISIZE), and fclose()s the underlying
     * FILE*. Z_OK means the trailer reached the kernel; anything
     * else (Z_ERRNO, Z_BUF_ERROR, Z_STREAM_ERROR, Z_MEM_ERROR)
     * means the file on disk may be truncated, header-only, or
     * otherwise unreadable as a gzip member. */
    int gzc = gzclose (gz);
    if (gzc != Z_OK || err) {
        unlink (blob_tmp);
        return -1;
    }

    /* TRAP: prior versions trusted gzclose==Z_OK as proof of a
     * well-formed file. In practice — under guest-side I/O
     * pressure, an interrupted syscall during gzclose's internal
     * fflush(), or a static-libz build link that silently lost
     * the gzip wrapper — the tmp file could end up size>0 but
     * NOT starting with 1f 8b. capture-pane then served bytes
     * that never decompressed to anything, manifesting as
     * count=0 results in the -N seam-bridge test cases. Verify
     * the magic explicitly before publishing. */
    {
        int vfd = open (blob_tmp, O_RDONLY);
        if (vfd < 0) {
            unlink (blob_tmp);
            return -1;
        }
        unsigned char magic[2] = { 0, 0 };
        ssize_t mr = read (vfd, magic, sizeof magic);
        close (vfd);
        if (mr != 2 || magic[0] != 0x1f || magic[1] != 0x8b) {
            unlink (blob_tmp);
            return -1;
        }
    }

    /* Round 1778567182 / Doc 1: roundtrip gzread verification.
     * If the writer ingested any uncompressed bytes but the blob
     * decompresses to zero, the deflate body is empty — exactly
     * the failure mode `199-screen-scrollback-gc.sh` case 9
     * (the Round-11 diagnostic) asserts against. We reject those
     * blobs before publishing so capture-pane never has to walk
     * a header-only entry. Reading only the first chunk is enough
     * for the assertion: if any uncompressed payload exists, the
     * first gzread MUST return > 0. */
    if (uncompressed_total > 0) {
        gzFile rgz = gzopen (blob_tmp, "rb");
        if (!rgz) {
            unlink (blob_tmp);
            return -1;
        }
        char rb[64];
        int rback = gzread (rgz, rb, sizeof rb);
        gzclose (rgz);
        if (rback <= 0) {
            unlink (blob_tmp);
            return -1;
        }
    }

    if (rename (blob_tmp, blob_path) < 0) {
        unlink (blob_tmp);
        return -1;
    }
    int fd = open (sb_path, O_WRONLY | O_TRUNC);
    if (fd >= 0) close (fd);
    (void) uncompressed_total;  /* kept for debug breakpoints; not used */
    return 0;
}

static int
bs_maybe_compress_scrollback (const char *sb_path)
{
    long threshold = bs_compress_threshold ();
    if (threshold <= 0) return 0;
    struct stat st;
    if (stat (sb_path, &st) < 0) return 0;
    if ((long) st.st_size < threshold) return 0;
    long nlines = bs_count_newlines (sb_path);
    if (nlines < threshold) return 0;
    return bs_compress_scrollback_now (sb_path);
}

static int
bs_maybe_gc_scrollback (const char *sb_path)
{
    char blobs_dir[1024];
    if (bs_scrollback_blobs_dir (sb_path, blobs_dir, sizeof blobs_dir) < 0) return 0;
    struct stat dst;
    if (stat (blobs_dir, &dst) < 0) return 0;

    long interval = bs_gc_interval_sec ();
    char tspath[1100];
    int rc = snprintf (tspath, sizeof tspath, "%s/.last-gc", blobs_dir);
    if (rc < 0 || (size_t) rc >= sizeof tspath) return 0;
    if (interval > 0) {
        struct stat ts;
        if (stat (tspath, &ts) == 0) {
            time_t now = time (NULL);
            if (now - ts.st_mtime < interval) return 0;
        }
    }

    long cap_bytes = bs_max_bytes ();
    if (cap_bytes > 0) {
        for (;;) {
            long total = bs_total_scrollback_bytes (sb_path, blobs_dir);
            if (total <= cap_bytes) break;
            char victim[64];
            if (bs_find_oldest_blob (blobs_dir, victim, sizeof victim) < 0) break;
            char vpath[1100];
            rc = snprintf (vpath, sizeof vpath, "%s/%s", blobs_dir, victim);
            if (rc < 0 || (size_t) rc >= sizeof vpath) break;
            if (unlink (vpath) < 0) break;
        }
    }
    int fd = open (tspath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close (fd);
    return 0;
}

/* Maintain a scrollback file: compress if it has grown past the
 * threshold, then GC oldest blobs back under the byte cap. Safe to
 * call after every append; rate-limited internally. */
static void
bs_pane_scrollback_maintain (const char *sb_path)
{
    bs_maybe_compress_scrollback (sb_path);
    bs_maybe_gc_scrollback (sb_path);
}

/* Stream a single gzipped blob to stdout. */
static int
bs_stream_blob (const char *blob_path)
{
    gzFile gz = gzopen (blob_path, "rb");
    if (!gz) return -1;
    char buf[8192];
    int n;
    while ((n = gzread (gz, buf, sizeof buf)) > 0) {
        char *p = buf;
        size_t left = (size_t) n;
        while (left > 0) {
            ssize_t w = write (STDOUT_FILENO, p, left);
            if (w < 0) {
                if (errno == EINTR) continue;
                gzclose (gz);
                return -1;
            }
            p += w; left -= (size_t) w;
        }
    }
    gzclose (gz);
    return 0;
}

static int
bs_session_path (char *out, size_t n, const char *root, const char *name)
{
    if (bscreen_validate_state_dir (root) < 0)
        return -1;
    if (!bs_name_ok (name)) {
        builtin_error ("screen: unsafe or empty session name: %s", name ? name : "(null)");
        return -1;
    }
    snprintf (out, n, "%s/%s", root, name);
    return 0;
}

static int
bs_next_numeric_dir (const char *parent)
{
    DIR *d = opendir (parent);
    int max = -1;
    if (!d) return 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v > max) max = (int)v;
    }
    closedir (d);
    return max + 1;
}

/* Recursive rm -rf of PATH. Refuses empty, "/", or paths containing
 * "..". Doesn't descend through symlinks (lstat-based; symlinks are
 * unlinked, not followed). Used by win-kill to drop a window dir tree.
 * Returns 0 on success, -1 on error. Stage 9 (2026-05-07). */
static int
bs_rm_rf (const char *path)
{
    if (!path || !*path || !strcmp (path, "/")) return -1;
    if (strstr (path, "/../") || strstr (path, "/..")) return -1;

    struct stat st;
    if (lstat (path, &st) < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (S_ISDIR (st.st_mode)) {
        DIR *d = opendir (path);
        if (!d) return -1;
        struct dirent *ent;
        char child[1024];
        int rc = 0;
        while ((ent = readdir (d)) != NULL) {
            if (!strcmp (ent->d_name, ".") || !strcmp (ent->d_name, "..")) continue;
            int n = snprintf (child, sizeof child, "%s/%s", path, ent->d_name);
            if (n < 0 || (size_t) n >= sizeof child) { rc = -1; break; }
            if (bs_rm_rf (child) < 0) { rc = -1; break; }
        }
        closedir (d);
        if (rc < 0) return -1;
        if (rmdir (path) < 0) return -1;
        return 0;
    }
    return unlink (path);
}

/* Does the window directory <sdir>/windows/<idx>/ exist?
 * Used by win-switch / win-rename / win-kill to validate the index. */
static int
bs_window_exists (const char *sdir, const char *idx)
{
    if (!idx || !*idx) return 0;
    for (const char *p = idx; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char path[1024];
    snprintf (path, sizeof path, "%s/windows/%s", sdir, idx);
    struct stat st;
    return (stat (path, &st) == 0 && S_ISDIR (st.st_mode));
}

/* Does <sdir>/windows/<win>/panes/<pane>/ exist?
 * Stage 18 v1 (2026-05-07). */
static int
bs_pane_exists (const char *sdir, const char *win, const char *pane)
{
    if (!bs_window_exists (sdir, win)) return 0;
    if (!pane || !*pane) return 0;
    for (const char *p = pane; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char path[1024];
    snprintf (path, sizeof path, "%s/windows/%s/panes/%s", sdir, win, pane);
    struct stat st;
    return (stat (path, &st) == 0 && S_ISDIR (st.st_mode));
}

static void
bs_read_active_pair (const char *sdir, char *win, size_t wsz, char *pane, size_t psz)
{
    char file[512], active[128] = "0:0";
    snprintf (file, sizeof file, "%s/active", sdir);
    if (bs_read_file (file, active, sizeof active) == 0) {
        char *colon = strchr (active, ':');
        if (colon) {
            *colon = '\0';
            snprintf (win, wsz, "%s", active);
            snprintf (pane, psz, "%s", colon + 1);
            return;
        }
    }
    snprintf (file, sizeof file, "%s/active-window", sdir);
    strcpy (win, "0");
    bs_read_file (file, win, wsz);
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    strcpy (pane, "0");
    bs_read_file (file, pane, psz);
}

static int
bs_write_active_pair (const char *sdir, const char *win, const char *pane)
{
    char file[512], val[128];
    snprintf (file, sizeof file, "%s/active-window", sdir);
    if (bs_write_file (file, win) < 0) return -1;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    if (bs_write_file (file, pane) < 0) return -1;
    snprintf (file, sizeof file, "%s/active", sdir);
    snprintf (val, sizeof val, "%s:%s\n", win, pane);
    return bs_write_file (file, val);
}

static int
bs_parse_target (const char *target, char *win, size_t wsz, char *pane, size_t psz)
{
    if (!target || !*target) return -1;
    const char *colon = strchr (target, ':');
    if (!colon) {
        snprintf (pane, psz, "%s", target);
        return 0;
    }
    size_t wl = (size_t)(colon - target);
    if (wl == 0 || wl >= wsz) return -1;
    memcpy (win, target, wl);
    win[wl] = '\0';
    snprintf (pane, psz, "%s", colon + 1);
    return *pane ? 0 : -1;
}

static int
bs_init_window_vt_metadata (const char *wdir)
{
    char file[512];
    snprintf (file, sizeof file, "%s/vt-handle", wdir);
    if (bs_write_file (file, "pending\n") < 0) return -1;
    snprintf (file, sizeof file, "%s/vt-generation", wdir);
    if (bs_write_file (file, "0\n") < 0) return -1;
    snprintf (file, sizeof file, "%s/vt-dirty", wdir);
    if (bs_write_file (file, "0\n") < 0) return -1;
    return 0;
}

static int
bs_parse_geom (const char *geom, long *r, long *c, long *rr, long *cc)
{
    char *end = NULL;
    const char *p = geom;
    *r = strtol (p, &end, 10); if (end == p || *end != ' ') return -1; p = end + 1;
    *c = strtol (p, &end, 10); if (end == p || *end != ' ') return -1; p = end + 1;
    *rr = strtol (p, &end, 10); if (end == p || *end != ' ') return -1; p = end + 1;
    *cc = strtol (p, &end, 10);
    if (end == p || (*end != '\0' && *end != '\n')) return -1;
    return (*r < 0 || *c < 0 || *rr < 0 || *cc < 0) ? -1 : 0;
}

static int
bs_create_window (const char *sdir, const char *wname)
{
    char parent[512], path[512], file[512], val[64];
    snprintf (parent, sizeof parent, "%s/windows", sdir);
    if (bs_mkdir_if_needed (parent, 0700) < 0) return -1;
    int idx = bs_next_numeric_dir (parent);
    snprintf (path, sizeof path, "%s/%d", parent, idx);
    if (bs_mkdir_if_needed (path, 0700) < 0) return -1;
    snprintf (file, sizeof file, "%s/name", path);
    /* Cap window name bytes to bound state-dir metadata size. */
    char wname_buf[BSCREEN_WINDOW_NAME_MAX + 1];
    const char *wname_eff = bs_window_name_capped (wname, wname_buf);
    if (bs_write_file (file, wname_eff) < 0) return -1;
    snprintf (file, sizeof file, "%s/pid", path);
    snprintf (val, sizeof val, "%ld\n", (long)getpid ());
    if (bs_write_file (file, val) < 0) return -1;
    if (bs_init_window_vt_metadata (path) < 0) return -1;
    snprintf (file, sizeof file, "%s/panes", path);
    if (bs_mkdir_if_needed (file, 0700) < 0) return -1;
    snprintf (path, sizeof path, "%s/windows/%d/panes/0", sdir, idx);
    if (bs_mkdir_if_needed (path, 0700) < 0) return -1;
    snprintf (file, sizeof file, "%s/name", path);
    if (bs_write_file (file, "0") < 0) return -1;
    snprintf (file, sizeof file, "%s/geom", path);
    if (bs_write_file (file, "0 0 24 80") < 0) return -1;
    snprintf (file, sizeof file, "%s/scrollback", path);
    if (bs_write_file (file, "") < 0) return -1;
    snprintf (file, sizeof file, "%s/pty.fd", path);
    if (bs_write_file (file, "metadata\n") < 0) return -1;
    return idx;
}

#define BSCREEN_MAX_CLIENTS 16

typedef struct {
    int fd;
    int prefix;
} bscreen_client;

static volatile sig_atomic_t bs_relay_stop = 0;

static void
bs_relay_signal_stop (int sig)
{
    (void) sig;
    bs_relay_stop = 1;
}

static void
bs_relay_sigchld_default (void)
{
    struct sigaction dfl;
    memset (&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset (&dfl.sa_mask);
    sigaction (SIGCHLD, &dfl, NULL);
}

static int
bs_relay_sigchld_block (sigset_t *oldmask)
{
    sigset_t block;
    sigemptyset (&block);
    sigaddset (&block, SIGCHLD);
    return sigprocmask (SIG_BLOCK, &block, oldmask);
}

static void
bs_relay_sigchld_restore (sigset_t *oldmask)
{
    sigprocmask (SIG_SETMASK, oldmask, NULL);
}

static int
bs_relay_wait_child_nonblock (pid_t child, int *status)
{
    pid_t w;
    sigset_t oldmask;

    if (bs_relay_sigchld_block (&oldmask) < 0)
        return -1;

    do {
        w = waitpid (child, status, WNOHANG);
    } while (w < 0 && errno == EINTR);

    bs_relay_sigchld_restore (&oldmask);

    if (w == child) return 1;
    if (w == 0) return 0;
    if (w < 0 && errno == ECHILD) return 1;
    return -1;
}

static void
bs_relay_reap_child_bounded (pid_t child)
{
    int status = 0;
    int state = bs_relay_wait_child_nonblock (child, &status);
    if (state != 0) return;

    kill (child, SIGHUP);
    for (int i = 0; i < 20; i++) {
        usleep (50000);
        state = bs_relay_wait_child_nonblock (child, &status);
        if (state != 0) return;
    }

    kill (child, SIGTERM);
    for (int i = 0; i < 10; i++) {
        usleep (50000);
        state = bs_relay_wait_child_nonblock (child, &status);
        if (state != 0) return;
    }

    kill (child, SIGKILL);
    for (int i = 0; i < 10; i++) {
        usleep (50000);
        state = bs_relay_wait_child_nonblock (child, &status);
        if (state != 0) return;
    }
}

static int
bs_relay_socket_path (char *out, size_t n, const char *sdir)
{
    int rc = snprintf (out, n, "%s/master.fd", sdir);
    if (rc < 0 || (size_t) rc >= n) {
        builtin_error ("screen: relay socket path too long");
        return -1;
    }
    return 0;
}

static int
bs_connect_relay (const char *sdir)
{
    char sockpath[512];
    if (bs_relay_socket_path (sockpath, sizeof sockpath, sdir) < 0) return -1;
    int fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset (&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen (sockpath) >= sizeof sa.sun_path) {
        close (fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy (sa.sun_path, sockpath);
    if (connect (fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close (fd);
        return -1;
    }
    return fd;
}

static int
bs_spawn_pty_child (char **argv, int *master_out, pid_t *pid_out)
{
    int master = posix_openpt (O_RDWR | O_NOCTTY);
    if (master < 0) return -1;
    if (grantpt (master) < 0 || unlockpt (master) < 0) {
        close (master);
        return -1;
    }
    char slave_path[128];
    if (ptsname_r (master, slave_path, sizeof slave_path) != 0) {
        close (master);
        return -1;
    }
    bs_relay_sigchld_default ();
    sigset_t oldmask;
    if (bs_relay_sigchld_block (&oldmask) < 0) {
        close (master);
        return -1;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bs_relay_sigchld_restore (&oldmask);
        close (master);
        return -1;
    }
    if (pid == 0) {
        bs_relay_sigchld_restore (&oldmask);
        setsid ();
        int slave = open (slave_path, O_RDWR | O_NOCTTY);
        if (slave < 0) _exit (126);
        ioctl (slave, TIOCSCTTY, 0);
        dup2 (slave, 0);
        dup2 (slave, 1);
        dup2 (slave, 2);
        if (slave > 2) close (slave);
        close (master);
        execvp (argv[0], argv);
        _exit (127);
    }
    bs_relay_sigchld_restore (&oldmask);
    *master_out = master;
    *pid_out = pid;
    return 0;
}

static int
bs_make_relay_listener (const char *sdir)
{
    char sockpath[512], aliaspath[512];
    if (bs_relay_socket_path (sockpath, sizeof sockpath, sdir) < 0) return -1;
    unlink (sockpath);
    snprintf (aliaspath, sizeof aliaspath, "%s/sock", sdir);
    unlink (aliaspath);

    int fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset (&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen (sockpath) >= sizeof sa.sun_path) {
        close (fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy (sa.sun_path, sockpath);
    if (bind (fd, (struct sockaddr *)&sa, sizeof sa) < 0 ||
        listen (fd, 16) < 0) {
        int saved = errno;
        close (fd);
        unlink (sockpath);
        errno = saved;
        return -1;
    }
    chmod (sockpath, 0600);
    symlink ("master.fd", aliaspath);
    return fd;
}

static int
bs_relay_peer_allowed (int fd)
{
#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof cred;
    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        return 0;
    if (len < sizeof cred)
        return 0;
    return cred.uid == geteuid ();
#else
    (void) fd;
    return 1;
#endif
}

static void
bs_relay_remove_client (bscreen_client *clients, int idx)
{
    if (clients[idx].fd >= 0) close (clients[idx].fd);
    clients[idx].fd = -1;
    clients[idx].prefix = 0;
}

static int
bs_relay_write_all (int fd, const char *buf, ssize_t n)
{
    ssize_t off = 0;
    while (off < n) {
        ssize_t wr = write (fd, buf + off, (size_t)(n - off));
        if (wr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (wr == 0) return -1;
        off += wr;
    }
    return 0;
}

static int
bs_send_control_roam_fd (int fd)
{
    char frame[sizeof (struct bs_remote_frame_header) + sizeof BSCREEN_CONTROL_ROAM - 1];
    size_t len = bs_remote_frame_build (frame, sizeof frame,
                                        BSCREEN_REMOTE_FRAME_CONTROL,
                                        BSCREEN_CONTROL_ROAM);
    if (!len)
        return -1;
    return bs_relay_write_all (fd, frame, (ssize_t) len);
}

static void
bs_relay_broadcast (bscreen_client *clients, const char *buf, ssize_t n)
{
    for (int i = 0; i < BSCREEN_MAX_CLIENTS; i++) {
        if (clients[i].fd < 0) continue;
        if (bs_relay_write_all (clients[i].fd, buf, n) < 0)
            bs_relay_remove_client (clients, i);
    }
}

static int
bs_relay_create_window (const char *sdir)
{
    int idx = bs_create_window (sdir, "bash");
    if (idx < 0) return -1;
    char val[64];
    snprintf (val, sizeof val, "%d", idx);
    return bs_write_active_pair (sdir, val, "0");
}

static int
bs_relay_cycle_window (const char *sdir)
{
    char parent[512], afile[512], active_buf[64] = "0";
    snprintf (parent, sizeof parent, "%s/windows", sdir);
    snprintf (afile, sizeof afile, "%s/active-window", sdir);
    bs_read_file (afile, active_buf, sizeof active_buf);
    int active = (int) strtol (active_buf, NULL, 10);

    DIR *d = opendir (parent);
    if (!d) return -1;
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    if (n == 0) return -1;
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j - 1] > x) { idxs[j] = idxs[j - 1]; j--; }
        idxs[j] = x;
    }

    int next = idxs[0];
    for (int i = 0; i < n; i++) {
        if (idxs[i] > active) { next = idxs[i]; break; }
    }
    char val[64];
    snprintf (val, sizeof val, "%d", next);
    return bs_write_active_pair (sdir, val, "0");
}

static int
bs_relay_write_master (const char *sdir, int master, bscreen_client *client, const char *buf, ssize_t n)
{
    ssize_t start = 0;
    unsigned char detach_key = bs_detach_key ();
    unsigned char roam_key = bs_roam_key ();
    for (ssize_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char) buf[i];
        size_t frame_len = 0;
        if (bs_remote_control_roam_frame (buf + i, n - i, &frame_len)) {
            if (i > start && bs_relay_write_all (master, buf + start, i - start) < 0)
                return 3;
            (void) frame_len;
            client->prefix = 0;
            return 4;
        }
        if (client->prefix) {
            if (i > start && bs_relay_write_all (master, buf + start, i - start) < 0)
                return 3;
            client->prefix = 0;
            start = i + 1;
            if (bs_key_match (ch, 'd')) return 1;
            if (bs_key_match (ch, roam_key)) return 4;
            if (ch == 'k' || ch == 'K') return 2;
            if (ch == 'c' || ch == 'C') { bs_relay_create_window (sdir); continue; }
            if (ch == 'n' || ch == 'N') { bs_relay_cycle_window (sdir); continue; }
            if (ch == '?') {
                const char help[] = "\r\n^A d detach  ^A r roam  ^A k kill  ^A ? help\r\n";
                bs_relay_write_all (client->fd, help, sizeof help - 1);
                continue;
            }
            char literal[2] = { (char) detach_key, (char) ch };
            if (bs_relay_write_all (master, literal, sizeof literal) < 0)
                return 3;
        } else if (ch == detach_key) {
            if (i > start && bs_relay_write_all (master, buf + start, i - start) < 0)
                return 3;
            client->prefix = 1;
            start = i + 1;
            continue;
        }
    }
    if (n > start && bs_relay_write_all (master, buf + start, n - start) < 0)
        return 3;
    return 0;
}

static void
bs_relay_drain_master (const char *sdir, int master, bscreen_client *clients, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = master;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc = poll (&pfd, 1, timeout_ms);
    if (rc <= 0 || !(pfd.revents & POLLIN)) return;

    char file[512], buf[4096];
    ssize_t nr = read (master, buf, sizeof buf);
    if (nr <= 0) return;
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    bs_append_file (file, buf, (size_t) nr);
    bs_pane_scrollback_maintain (file);
    snprintf (file, sizeof file, "%s/windows/0/panes/0/scrollback", sdir);
    bs_append_file (file, buf, (size_t) nr);
    bs_pane_scrollback_maintain (file);
    bs_relay_broadcast (clients, buf, nr);
}

static void
bs_relay_loop (const char *sdir, char **argv)
{
    bs_relay_stop = 0;
    signal (SIGPIPE, SIG_IGN);
    signal (SIGHUP, bs_relay_signal_stop);
    signal (SIGTERM, bs_relay_signal_stop);
    bs_relay_sigchld_default ();
    int master = -1, listener = -1;
    pid_t child = -1;
    char file[512], val[128];
    bscreen_client clients[BSCREEN_MAX_CLIENTS];
    for (int i = 0; i < BSCREEN_MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].prefix = 0;
    }

    if (bs_spawn_pty_child (argv, &master, &child) < 0) {
        snprintf (file, sizeof file, "%s/relay-status", sdir);
        bs_write_file (file, "live-relay failed to spawn pty child\n");
        _exit (126);
    }
    listener = bs_make_relay_listener (sdir);
    if (listener < 0) {
        bs_relay_reap_child_bounded (child);
        snprintf (file, sizeof file, "%s/relay-status", sdir);
        bs_write_file (file, "live-relay failed to create socket\n");
        _exit (126);
    }

    snprintf (file, sizeof file, "%s/pid", sdir);
    snprintf (val, sizeof val, "%ld\n", (long)getpid ());
    bs_write_file (file, val);
    snprintf (file, sizeof file, "%s/pty-child-pid", sdir);
    snprintf (val, sizeof val, "%ld\n", (long)child);
    bs_write_file (file, val);
    snprintf (file, sizeof file, "%s/relay-status", sdir);
    bs_write_file (file, "live-relay running: Stage 50.D poll relay loop\n");

    while (!bs_relay_stop) {
        struct pollfd pfds[2 + BSCREEN_MAX_CLIENTS];
        int slots[2 + BSCREEN_MAX_CLIENTS];
        int nfds = 0;
        pfds[nfds].fd = master;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        slots[nfds++] = -1;
        pfds[nfds].fd = listener;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        slots[nfds++] = -2;
        for (int i = 0; i < BSCREEN_MAX_CLIENTS; i++) {
            if (clients[i].fd >= 0) {
                pfds[nfds].fd = clients[i].fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                slots[nfds++] = i;
            }
        }
        int rc = poll (pfds, (nfds_t) nfds, 75);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        int child_status = 0;
        int child_state = bs_relay_wait_child_nonblock (child, &child_status);
        if (child_state != 0) break;
        if (rc == 0) continue;
        if (pfds[1].revents & POLLIN) {
            int cfd = accept (listener, NULL, NULL);
            if (cfd >= 0) {
                if (!bs_relay_peer_allowed (cfd)) {
                    close (cfd);
                    continue;
                }
                int placed = 0;
                for (int i = 0; i < BSCREEN_MAX_CLIENTS; i++) {
                    if (clients[i].fd < 0) {
                        clients[i].fd = cfd;
                        clients[i].prefix = 0;
                        placed = 1;
                        break;
                    }
                }
                if (!placed) close (cfd);
            }
        }
        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (pfds[0].revents & POLLIN) {
            char buf[4096];
            ssize_t nr = read (master, buf, sizeof buf);
            if (nr <= 0) break;
            snprintf (file, sizeof file, "%s/scrollback", sdir);
            bs_append_file (file, buf, (size_t) nr);
            bs_pane_scrollback_maintain (file);
            snprintf (file, sizeof file, "%s/windows/0/panes/0/scrollback", sdir);
            bs_append_file (file, buf, (size_t) nr);
            bs_pane_scrollback_maintain (file);
            bs_relay_broadcast (clients, buf, nr);
        }
        for (int p = 2; p < nfds; p++) {
            int i = slots[p];
            if (i < 0 || clients[i].fd < 0) continue;
            if (pfds[p].revents & POLLIN) {
                char buf[4096];
                ssize_t nr = read (clients[i].fd, buf, sizeof buf);
                if (nr <= 0) {
                    bs_relay_remove_client (clients, i);
                    continue;
                }
                int action = bs_relay_write_master (sdir, master, &clients[i], buf, nr);
                if (action == 1) {
                    bs_relay_drain_master (sdir, master, clients, 250);
                    bs_relay_remove_client (clients, i);
                }
                else if (action == 2) {
                    bs_relay_reap_child_bounded (child);
                    bs_rm_rf (sdir);
                    _exit (0);
                } else if (action == 4) {
                    bs_relay_remove_client (clients, i);
                } else if (action == 3) break;
            }
            if (clients[i].fd >= 0 && (pfds[p].revents & (POLLHUP | POLLERR | POLLNVAL)))
                bs_relay_remove_client (clients, i);
        }
    }

    for (int i = 0; i < BSCREEN_MAX_CLIENTS; i++)
        if (clients[i].fd >= 0) close (clients[i].fd);
    close (listener);
    close (master);
    bs_relay_reap_child_bounded (child);
    bs_rm_rf (sdir);
    _exit (0);
}

static int
bs_relay_send_words (const char *sdir, WORD_LIST *args)
{
    int fd = bs_connect_relay (sdir);
    if (fd < 0) return -1;
    const char *w;
    int first = 1;
    while ((w = bs_word (&args)) != NULL) {
        if (!first) write (fd, " ", 1);
        write (fd, w, strlen (w));
        first = 0;
    }
    write (fd, "\n", 1);
    close (fd);
    return 0;
}

static int
bs_attach_live_relay (const char *sdir)
{
    bscreen_relay_result result = BSCREEN_RELAY_EOF;
    signal (SIGPIPE, SIG_IGN);
    int fd = bs_connect_relay (sdir);
    if (fd < 0) return BSCREEN_RELAY_ERROR;
    struct termios saved_tio, raw_tio;
    int raw_enabled = 0;
    int escape_pending = 0;
    unsigned char detach_key = bs_detach_key ();
    unsigned char roam_key = bs_roam_key ();
    if (isatty (STDIN_FILENO) && tcgetattr (STDIN_FILENO, &saved_tio) == 0) {
        raw_tio = saved_tio;
        raw_tio.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw_tio.c_oflag &= ~(OPOST);
        raw_tio.c_cflag |= CS8;
        raw_tio.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
        raw_tio.c_cc[VMIN] = 1;
        raw_tio.c_cc[VTIME] = 0;
        if (tcsetattr (STDIN_FILENO, TCSANOW, &raw_tio) == 0)
            raw_enabled = 1;
    }
    char scrollback[512];
    snprintf (scrollback, sizeof scrollback, "%s/scrollback", sdir);
    FILE *sf = fopen (scrollback, "r");
    if (sf) {
        char rbuf[4096];
        size_t nr;
        while ((nr = fread (rbuf, 1, sizeof rbuf, sf)) > 0) {
            size_t off = 0;
            while (off < nr) {
                ssize_t wr = write (1, rbuf + off, nr - off);
                if (wr < 0) {
                    if (errno == EINTR) continue;
                    fclose (sf);
                    if (raw_enabled) tcsetattr (STDIN_FILENO, TCSANOW, &saved_tio);
                    close (fd);
                    return BSCREEN_RELAY_ERROR;
                }
                if (wr == 0) break;
                off += (size_t) wr;
            }
        }
        fclose (sf);
    }
    for (;;) {
        fd_set rfds;
        FD_ZERO (&rfds);
        FD_SET (0, &rfds);
        FD_SET (fd, &rfds);
        int maxfd = fd > 0 ? fd : 0;
        int rc = select (maxfd + 1, &rfds, NULL, NULL, NULL);
            if (rc < 0) {
                if (errno == EINTR) continue;
                if (raw_enabled) tcsetattr (STDIN_FILENO, TCSANOW, &saved_tio);
                close (fd);
                return BSCREEN_RELAY_ERROR;
            }
        if (FD_ISSET (0, &rfds)) {
            char buf[1024];
            ssize_t nr = read (0, buf, sizeof buf);
            if (nr <= 0) {
                if (escape_pending) {
                    char lit = (char) detach_key;
                    (void) bs_relay_write_all (fd, &lit, 1);
                    escape_pending = 0;
                }
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                while (poll (&pfd, 1, 500) > 0 && (pfd.revents & POLLIN)) {
                    char rbuf[4096];
                    ssize_t rr = read (fd, rbuf, sizeof rbuf);
                    if (rr <= 0) break;
                    ssize_t roff = 0;
                    while (roff < rr) {
                        ssize_t wr = write (1, rbuf + roff, (size_t)(rr - roff));
                        if (wr < 0) {
                            if (errno == EINTR) continue;
                            if (raw_enabled) tcsetattr (STDIN_FILENO, TCSANOW, &saved_tio);
                            close (fd);
                            return BSCREEN_RELAY_ERROR;
                        }
                        if (wr == 0) break;
                        roff += wr;
                    }
                    pfd.revents = 0;
                }
                break;
            }
            ssize_t start = 0;
            for (ssize_t i = 0; i < nr; i++) {
                unsigned char ch = (unsigned char) buf[i];
                if (escape_pending) {
                    if (i > start && bs_relay_write_all (fd, buf + start, i - start) < 0) {
                        result = BSCREEN_RELAY_ERROR;
                        goto done;
                    }
                    escape_pending = 0;
                    start = i + 1;
                    if (bs_key_match (ch, 'd')) {
                        result = BSCREEN_RELAY_DETACH;
                        goto done;
                    }
                    if (bs_key_match (ch, roam_key)) {
                        if (bs_send_control_roam_fd (fd) < 0)
                            result = BSCREEN_RELAY_ERROR;
                        else
                            result = BSCREEN_RELAY_ROAM;
                        goto done;
                    }
                    {
                        char literal[2] = { (char) detach_key, (char) ch };
                        if (bs_relay_write_all (fd, literal, sizeof literal) < 0) {
                            result = BSCREEN_RELAY_ERROR;
                            goto done;
                        }
                    }
                } else if (ch == detach_key) {
                    if (i > start && bs_relay_write_all (fd, buf + start, i - start) < 0) {
                        result = BSCREEN_RELAY_ERROR;
                        goto done;
                    }
                    escape_pending = 1;
                    start = i + 1;
                }
            }
            if (nr > start && bs_relay_write_all (fd, buf + start, nr - start) < 0) {
                result = BSCREEN_RELAY_ERROR;
                goto done;
            }
        }
        if (FD_ISSET (fd, &rfds)) {
            char buf[4096];
            ssize_t nr = read (fd, buf, sizeof buf);
            if (nr <= 0) break;
            ssize_t off = 0;
            while (off < nr) {
                ssize_t wr = write (1, buf + off, (size_t)(nr - off));
                if (wr < 0) {
                    if (errno == EINTR) continue;
                    if (raw_enabled) tcsetattr (STDIN_FILENO, TCSANOW, &saved_tio);
                    close (fd);
                    return BSCREEN_RELAY_ERROR;
                }
                if (wr == 0) break;
                off += wr;
            }
        }
    }
done:
    if (raw_enabled) tcsetattr (STDIN_FILENO, TCSANOW, &saved_tio);
    close (fd);
    return result;
}

static int
bscreen_run_cmd (WORD_LIST *args)
{
    const char *name = NULL;
    const char *cmd_string = NULL;
    const char *cmd_argv[128];
    int cmd_argc = 0;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "-n") || !strcmp (w, "-S")) name = bs_word (&args);
        else if (!strcmp (w, "-d") || !strcmp (w, "--detached")) ;
        else if (!strcmp (w, "-c")) { cmd_string = bs_word (&args); break; }
        else if (!name) name = w;
        else if (cmd_argc < (int)(sizeof cmd_argv / sizeof cmd_argv[0]) - 1) cmd_argv[cmd_argc++] = w;
    }
    while (!cmd_string && (w = bs_word (&args)) != NULL &&
           cmd_argc < (int)(sizeof cmd_argv / sizeof cmd_argv[0]) - 1)
        cmd_argv[cmd_argc++] = w;
    if (!name) name = "default";
    int live_requested = (cmd_string != NULL || cmd_argc > 0);
    char *relay_argv[130];
    if (cmd_string) {
        const char *shell = getenv ("SHELL");
        if (!shell || !*shell) shell = "/bin/sh";
        relay_argv[0] = (char *) shell;
        relay_argv[1] = "-c";
        relay_argv[2] = (char *) cmd_string;
        relay_argv[3] = NULL;
    } else if (cmd_argc > 0) {
        for (int i = 0; i < cmd_argc; i++) relay_argv[i] = (char *) cmd_argv[i];
        relay_argv[cmd_argc] = NULL;
    } else {
        relay_argv[0] = NULL;
    }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], val[128];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (bs_mkdir_if_needed (sdir, 0700) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    snprintf (val, sizeof val, "%ld\n", (long)getpid ());
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/info", sdir);
    if (bs_write_file (file, "screen phase3 v1\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active-window", sdir);
    if (bs_write_file (file, "0\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    if (bs_write_file (file, "0\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active", sdir);
    if (bs_write_file (file, "0:0\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    if (bs_write_file (file, "") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/relay-status", sdir);
    if (bs_create_window (sdir, "bash") < 0) return EXECUTION_FAILURE;
    if (!live_requested) {
        if (bs_write_file (file, "live-relay unimplemented: Stage 50.C metadata scaffolding only\n") < 0)
            return EXECUTION_FAILURE;
        /* Metadata-only fast path: no relay process was forked, so the
         * pid file we wrote at line ~1494 still holds our caller's
         * getpid(). Leaving that intact lets a subsequent `screen
         * kill NAME` SIGHUP the caller (test discovered this via
         * 277-screen-pty-fd-leak.sh's subshell sub_rc=129). Stamp
         * "0" as a sentinel — kill's `pid > 1` guard at line ~1559
         * then skips the SIGHUP and only removes the state dir. */
        char pidfile[512];
        snprintf (pidfile, sizeof pidfile, "%s/pid", sdir);
        (void) bs_write_file (pidfile, "0\n");
        printf ("%s\n", name);
        return EXECUTION_SUCCESS;
    }
    if (bs_write_file (file, "live-relay starting: Stage 50.D\n") < 0)
        return EXECUTION_FAILURE;
    pid_t relay = fork ();
    if (relay < 0) {
        builtin_error ("screen: fork relay: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (relay == 0) {
        int devnull = open ("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2 (devnull, STDIN_FILENO);
            dup2 (devnull, STDOUT_FILENO);
            dup2 (devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close (devnull);
        }
        bs_relay_loop (sdir, relay_argv);
        _exit (0);
    }
    snprintf (file, sizeof file, "%s/windows/0/panes/0/pty.fd", sdir);
    if (bs_write_file (file, "master.fd\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    snprintf (val, sizeof val, "%ld\n", (long)relay);
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    printf ("%s\n", name);
    return EXECUTION_SUCCESS;
}

static int
bscreen_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("kill: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, F_OK) < 0) {
        builtin_error ("kill: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    char pidbuf[64];
    if (bs_read_file (file, pidbuf, sizeof pidbuf) == 0) {
        char *end = NULL;
        long pid = strtol (pidbuf, &end, 10);
        if (end != pidbuf && pid > 1) kill ((pid_t) pid, SIGHUP);
    }
    if (bs_rm_rf (sdir) < 0) {
        builtin_error ("kill: failed to remove %s: %s", sdir, strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("killed %s\n", name);
    return EXECUTION_SUCCESS;
}

static int
bscreen_attach_cmd (WORD_LIST *args)
{
    int force_detach = 0, detach_only = 0, multi = 0, live_request = 0, remote = 0, dry_run = 0;
    const char *name = NULL, *w, *key_override = NULL;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "-d")) detach_only = 1;
        else if (!strcmp (w, "-x")) multi = 1;
        else if (!strcmp (w, "-r")) live_request = 1;
        else if (!strcmp (w, "-rd") || !strcmp (w, "-dr")) force_detach = 1;
        else if (!strcmp (w, "--remote")) remote = 1;
        else if (!strcmp (w, "--dry-run")) dry_run = 1;
        else if (!strcmp (w, "--key")) {
            key_override = bs_word (&args);
            if (!key_override) { builtin_error ("attach --key needs FILE"); return EX_USAGE; }
        }
        else if (!name) name = w;
        else { builtin_error ("attach: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!name) { builtin_error ("attach: NAME [-r|-rd|-x|-d] [--remote --key FILE] [--dry-run]"); return EX_USAGE; }
    if (remote)
        return bscreen_attach_remote_cmd (name, key_override, dry_run);
    if (dry_run) { builtin_error ("attach: --dry-run requires --remote"); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], adir[512], val[256], active_win[64] = "0", active_pane[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) {
        builtin_error ("attach: no such session: %s", name);
        return EXECUTION_FAILURE;
    }

    snprintf (adir, sizeof adir, "%s/attachers", sdir);
    if (bs_mkdir_if_needed (adir, 0700) < 0) return EXECUTION_FAILURE;

    if (force_detach || detach_only) {
        snprintf (file, sizeof file, "%s/detach", sdir);
        snprintf (val, sizeof val, "%ld\n", (long)getpid ());
        if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
        if (!multi) bs_rm_rf (adir);
        if (detach_only) { printf ("detached %s\n", name); return EXECUTION_SUCCESS; }
        if (bs_mkdir_if_needed (adir, 0700) < 0) return EXECUTION_FAILURE;
    } else if (!multi && !live_request) {
        DIR *d = opendir (adir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                closedir (d);
                builtin_error ("attach: session already attached: %s", name);
                return EXECUTION_FAILURE;
            }
            closedir (d);
        }
    }

    snprintf (file, sizeof file, "%s/active-window", sdir);
    bs_read_file (file, active_win, sizeof active_win);
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    bs_read_file (file, active_pane, sizeof active_pane);
    snprintf (file, sizeof file, "%s/%ld", adir, (long)getpid ());
    snprintf (val, sizeof val,
              "pid %ld\nmode %s\nwindow %s\npane %s\n"
              "last-seen-vt pending\nlast-seen-generation 0\n"
              "relay %s\n",
              (long)getpid (), multi ? "multi" : "single", active_win, active_pane,
              live_request ? "live" : "metadata");
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    if (live_request) {
        if (bs_attach_live_relay (sdir) >= 0) return EXECUTION_SUCCESS;
        builtin_error ("attach: live relay unavailable for %s", name);
        return EXECUTION_FAILURE;
    }
    printf ("attached %s %s\n", name, multi ? "multi" : "single");
    return EXECUTION_SUCCESS;
}

static int
bscreen_roam_cmd (WORD_LIST *args)
{
    int dry_run = 0;
    const char *target = NULL, *key_override = NULL, *w;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "--dry-run")) dry_run = 1;
        else if (!strcmp (w, "--key")) {
            key_override = bs_word (&args);
            if (!key_override) { builtin_error ("roam --key needs FILE"); return EX_USAGE; }
        }
        else if (!target) target = w;
        else { builtin_error ("roam: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!target) { builtin_error ("roam: NODE/SESSION [--key FILE] [--dry-run]"); return EX_USAGE; }

    if (dry_run) {
        char node[129], session[129], hostport[129], key[256], from[129] = "local";
        int resolved = bs_resolve_remote_target ("roam", target, key_override,
                                                 node, sizeof node, session, sizeof session,
                                                 hostport, sizeof hostport, key, sizeof key);
        if (resolved != EXECUTION_SUCCESS)
            return resolved;
        (void) bs_cluster_node_id (from, sizeof from);
        printf ("from=%s\nto=%s/%s\nhostport=%s\nkey=%s\ncommand=screen attach %s -r\n",
                from, node, session, hostport, key, session);
        return EXECUTION_SUCCESS;
    }

    return bscreen_attach_remote_cmd (target, key_override, 0);
}

static int
bscreen_state_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("state: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (!bs_session_exists (sdir)) { builtin_error ("state: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (file, sizeof file, "%s/active-window", sdir); bs_read_file (file, active, sizeof active);
    printf ("session %s\nactive-window %s\n", name, active);
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *f = fopen (file, "r");
    if (f) { int ch; while ((ch = fgetc (f)) != EOF) putchar (ch); fclose (f); }
    return EXECUTION_SUCCESS;
}

static int
bscreen_find_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *pat = bs_word (&args);
    if (!name || !pat) { builtin_error ("find: NAME PATTERN"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], line[1024];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("find: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *f = fopen (file, "r");
    int row = 0;
    if (f) {
        while (fgets (line, sizeof line, f)) {
            row++;
            char *m = strstr (line, pat);
            if (m) printf ("%d %ld\n", row, (long)(m - line + 1));
        }
        fclose (f);
    }
    return EXECUTION_SUCCESS;
}

/* Stage 9 v1 (2026-05-07): win-list now marks the active window with a
 * trailing "*" and emits rows in numeric order, not directory order. */
static int
bscreen_win_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("win-list: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char path[512], parent[512], afile[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (path, sizeof path, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (path)) { builtin_error ("win-list: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (parent, sizeof parent, "%s/windows", path);
    snprintf (afile,  sizeof afile,  "%s/active-window", path);
    bs_read_file (afile, active, sizeof active);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_SUCCESS;
    /* Collect numeric children, sort ascending. */
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    /* Insertion sort — n is small (<=256). */
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    char nfile[512], wname[128];
    int active_idx = (int) strtol (active, NULL, 10);
    for (int i = 0; i < n; i++) {
        snprintf (nfile, sizeof nfile, "%s/%d/name", parent, idxs[i]);
        strcpy (wname, "bash"); bs_read_file (nfile, wname, sizeof wname);
        printf ("%d %s%s\n", idxs[i], wname, idxs[i] == active_idx ? " *" : "");
    }
    return EXECUTION_SUCCESS;
}

/* V42-11 helper-exec hardening — screen win-create -c CMD used to
   route the operator-supplied CMD through popen("r"), which spawns
   /bin/sh -c CMD and interprets every shell metacharacter. The new
   path rejects metachars up-front, tokenises CMD on ASCII whitespace,
   and runs it via fork+execvp through a pipe so command substitution,
   redirections, pipelines, and quoting can no longer fire. The
   metadata `cmd` file still records CMD verbatim so the operator
   surface is unchanged — only the execution path is sealed.

   Reject set: ; | & $ ` < > ( ) { } [ ] * ? ! ~ " ' \ \n \r \t and
   any control byte. The allowed set is anything outside that list,
   including alphanumerics, `. _ - / + = , : @ #` etc., so common
   commands (`bash`, `htop`, `tail -f /var/log/messages`, `cat /tmp/x`)
   keep working. */
static int
bs_cmd_metachar_unsafe (const char *cmd)
{
    if (!cmd) return 1;
    for (const unsigned char *p = (const unsigned char *) cmd; *p; p++) {
        unsigned char c = *p;
        if (c == ';' || c == '|' || c == '&' || c == '$' || c == '`' ||
            c == '<' || c == '>' || c == '(' || c == ')' || c == '{' ||
            c == '}' || c == '[' || c == ']' || c == '*' || c == '?' ||
            c == '!' || c == '~' || c == '"' || c == '\'' || c == '\\' ||
            c == '\n' || c == '\r' || c < 0x20)
            return 1;
    }
    return 0;
}

/* Tokenise `cmd` on ASCII whitespace into a NULL-terminated argv.
   On success, *argv_out points to a malloc'd char** whose backing
   string buffer is *buf_out (free both with a single free() each).
   Returns argc, or -1 on allocation failure / empty argv.
   Assumes bs_cmd_metachar_unsafe(cmd) already returned 0. */
static int
bs_cmd_tokenize (const char *cmd, char ***argv_out, char **buf_out)
{
    *argv_out = NULL;
    *buf_out = NULL;
    if (!cmd || !*cmd) return -1;
    size_t len = strlen (cmd);
    char *buf = malloc (len + 1);
    if (!buf) return -1;
    memcpy (buf, cmd, len + 1);

    int argc = 0;
    int in_token = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ' ' || buf[i] == '\t') in_token = 0;
        else if (!in_token) { argc++; in_token = 1; }
    }
    if (argc == 0) { free (buf); return -1; }

    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) { free (buf); return -1; }

    int ai = 0;
    in_token = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ' ' || buf[i] == '\t') {
            buf[i] = '\0';
            in_token = 0;
        } else if (!in_token) {
            argv[ai++] = &buf[i];
            in_token = 1;
        }
    }
    argv[ai] = NULL;
    *argv_out = argv;
    *buf_out = buf;
    return argc;
}

/* Replacement for the prior popen("r") scrollback-capture pipeline.
   Validates `cmd`, tokenises it, fork+execvp's the child with stdout
   redirected through a pipe, drains the pipe into `sb_path`, and
   waitpid's the child with bs's existing SIGCHLD discipline.
   Returns 0 on success, -1 on validation failure (metachars present),
   -2 on tokenise/pipe/fork failure. The win-create itself does not
   fail on a -1/-2 result; the pane is still created without scrollback. */
static int
bs_capture_cmd_scrollback (const char *cmd, const char *sb_path)
{
    if (bs_cmd_metachar_unsafe (cmd)) {
        /* Silent refusal: write a sibling `cmd-refused` marker file
           instead of `builtin_warning` so callers that do `2>&1`
           (e.g. tests/bash-os/163-screen-50db-windows.sh) don't
           see the diagnostic mixed into their captured stdout. The
           metadata `cmd` file (written by the caller before this
           helper runs) still records the requested CMD verbatim, so
           operators can inspect both files to learn which CMD was
           requested and that it was refused. */
        char marker[600];
        const char *slash = strrchr (sb_path, '/');
        if (slash) {
            size_t plen = (size_t) (slash - sb_path);
            if (plen + sizeof ("/cmd-refused") < sizeof marker) {
                memcpy (marker, sb_path, plen);
                strcpy (marker + plen, "/cmd-refused");
                bs_write_file (marker, "shell-metacharacters\n");
            }
        }
        return -1;
    }
    char **argv = NULL;
    char *buf = NULL;
    int argc = bs_cmd_tokenize (cmd, &argv, &buf);
    if (argc <= 0) return -2;

    int pipefd[2];
    if (pipe (pipefd) < 0) { free (argv); free (buf); return -2; }

    bs_relay_sigchld_default ();
    sigset_t oldmask;
    if (bs_relay_sigchld_block (&oldmask) < 0) {
        close (pipefd[0]); close (pipefd[1]);
        free (argv); free (buf); return -2;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bs_relay_sigchld_restore (&oldmask);
        close (pipefd[0]); close (pipefd[1]);
        free (argv); free (buf); return -2;
    }
    if (pid == 0) {
        bs_relay_sigchld_restore (&oldmask);
        close (pipefd[0]);
        if (pipefd[1] != STDOUT_FILENO) {
            dup2 (pipefd[1], STDOUT_FILENO);
            close (pipefd[1]);
        }
        /* Leave stderr attached so a missing binary error is visible. */
        execvp (argv[0], argv);
        _exit (127);
    }
    bs_relay_sigchld_restore (&oldmask);
    close (pipefd[1]);

    char rbuf[512];
    ssize_t nr;
    while ((nr = read (pipefd[0], rbuf, sizeof rbuf)) > 0)
        bs_append_file (sb_path, rbuf, (size_t) nr);
    close (pipefd[0]);

    int st = 0;
    while (waitpid (pid, &st, 0) < 0 && errno == EINTR) { /* retry */ }

    free (argv);
    free (buf);
    return 0;
}

static int
bscreen_win_create_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *wname = NULL, *cmd = NULL, *w;
    if (!name) { builtin_error ("win-create: NAME [WIN]"); return EX_USAGE; }
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "-c")) { cmd = bs_word (&args); break; }
        else if (!wname) wname = w;
        else { builtin_error ("win-create: unexpected '%s'", w); return EX_USAGE; }
    }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], pane_dir[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("win-create: no such session: %s", name); return EXECUTION_FAILURE; }
    int idx = bs_create_window (sdir, wname ? wname : "bash");
    if (idx < 0) return EXECUTION_FAILURE;
    snprintf (pane_dir, sizeof pane_dir, "%s/windows/%d/panes/0", sdir, idx);
    snprintf (file, sizeof file, "%s/pty.fd", pane_dir);
    bs_write_file (file, "metadata\n");
    if (cmd && *cmd) {
        snprintf (file, sizeof file, "%s/cmd", pane_dir);
        bs_write_file (file, cmd);
        char sb_path[512];
        snprintf (sb_path, sizeof sb_path, "%s/scrollback", pane_dir);
        if (bs_capture_cmd_scrollback (cmd, sb_path) == 0)
            bs_pane_scrollback_maintain (sb_path);
    }
    printf ("%d\n", idx);
    return EXECUTION_SUCCESS;
}

/* Stage 9 v1: validates that the requested window index exists before
 * writing active-window. Previously accepted any string. */
static int
bscreen_win_switch_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args);
    if (!name || !idx) { builtin_error ("win-switch: NAME INDEX"); return EX_USAGE; }
    char sdir[512], file[512], val[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-switch: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/active-window", sdir);
    snprintf (val, sizeof val, "%s\n", idx);
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    return bs_write_active_pair (sdir, idx, "0") == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 9 v1: win-rename NAME IDX NEWNAME — overwrite the window's
 * `name` metadata file. NEWNAME is constrained to the same charset as
 * session names (alphanumeric + . _ -) for path-safety even though it's
 * a content field, not a path component. */
static int
bscreen_win_rename_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args), *new_name = bs_word (&args);
    if (!name || !idx || !new_name) {
        builtin_error ("win-rename: NAME INDEX NEWNAME");
        return EX_USAGE;
    }
    if (!bs_name_ok (new_name)) {
        builtin_error ("win-rename: unsafe NEWNAME (alphanumeric + . _ - only)");
        return EX_USAGE;
    }
    char sdir[512], file[512];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-rename: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/name", sdir, idx);
    /* Cap window name bytes to bound state-dir metadata size. */
    char new_name_buf[BSCREEN_WINDOW_NAME_MAX + 1];
    const char *new_name_eff = bs_window_name_capped (new_name, new_name_buf);
    return bs_write_file (file, new_name_eff) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 9 v1: win-kill NAME IDX — drop the window dir tree. If the
 * killed window was the active one, advances to the lowest remaining
 * index (or leaves active-window pointing at "0" if no windows are
 * left, mirroring GNU screen's "session ends if last window closes"
 * — but the *session* lifetime is the run-loop's job, not ours). */
static int
bscreen_win_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args);
    if (!name || !idx) { builtin_error ("win-kill: NAME INDEX"); return EX_USAGE; }
    char sdir[512], wpath[512], afile[512], active[64] = "0";
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-kill: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    snprintf (wpath, sizeof wpath, "%s/windows/%s", sdir, idx);
    if (bs_rm_rf (wpath) < 0) {
        builtin_error ("win-kill: failed to remove %s: %s", wpath, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* If we just removed the active window, point active at the lowest
     * surviving index. */
    snprintf (afile, sizeof afile, "%s/active-window", sdir);
    bs_read_file (afile, active, sizeof active);
    if (!strcmp (active, idx)) {
        char parent[512]; snprintf (parent, sizeof parent, "%s/windows", sdir);
        DIR *d = opendir (parent);
        int next = -1;
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char *end = NULL;
                long v = strtol (ent->d_name, &end, 10);
                if (end && *end == '\0' && (next < 0 || v < next)) next = (int) v;
            }
            closedir (d);
        }
        char val[64];
        snprintf (val, sizeof val, "%d\n", next < 0 ? 0 : next);
        if (bs_write_file (afile, val) < 0) return EXECUTION_FAILURE;
        snprintf (val, sizeof val, "%d", next < 0 ? 0 : next);
        if (bs_write_active_pair (sdir, val, "0") < 0) return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_win_cycle_cmd (WORD_LIST *args, int dir)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error (dir > 0 ? "win-next: NAME" : "win-prev: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], parent[512], afile[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error (dir > 0 ? "win-next: no such session: %s" : "win-prev: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (parent, sizeof parent, "%s/windows", sdir);
    snprintf (afile, sizeof afile, "%s/active-window", sdir);
    bs_read_file (afile, active, sizeof active);
    int active_idx = (int) strtol (active, NULL, 10);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_FAILURE;
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    if (n == 0) return EXECUTION_SUCCESS;
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    int pos = -1;
    for (int i = 0; i < n; i++)
        if (idxs[i] == active_idx) { pos = i; break; }
    if (pos < 0) pos = 0;
    int next_pos = dir > 0 ? (pos + 1) % n : (pos + n - 1) % n;
    char val[64];
    snprintf (val, sizeof val, "%d\n", idxs[next_pos]);
    if (bs_write_file (afile, val) != 0) return EXECUTION_FAILURE;
    printf ("%d\n", idxs[next_pos]);
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1 (2026-05-07): pane-list now sorts numerically and marks
 * the active pane with a trailing " *". Defaults WIN to active-window
 * when omitted (rather than the constant "0") so it matches operator
 * intent on multi-window sessions. */
static int
bscreen_pane_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    if (!name) { builtin_error ("pane-list: NAME [WIN]"); return EX_USAGE; }
    char sdir[512], parent[512], afile[512], abuf[64], pbuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!win) {
        snprintf (afile, sizeof afile, "%s/active-window", sdir);
        strcpy (abuf, "0"); bs_read_file (afile, abuf, sizeof abuf);
        win = abuf;
    }
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("pane-list: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    snprintf (afile, sizeof afile, "%s/active-pane", sdir);
    strcpy (pbuf, "0"); bs_read_file (afile, pbuf, sizeof pbuf);
    int active_pane = (int) strtol (pbuf, NULL, 10);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_SUCCESS;
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    char nfile[512], geom[128];
    for (int i = 0; i < n; i++) {
        snprintf (nfile, sizeof nfile, "%s/%d/geom", parent, idxs[i]);
        strcpy (geom, "0 0 24 80"); bs_read_file (nfile, geom, sizeof geom);
        printf ("%d %s%s\n", idxs[i], geom, idxs[i] == active_pane ? " *" : "");
    }
    return EXECUTION_SUCCESS;
}

/* Stage 18 v4: validates the requested WIN exists, then splits the
 * currently active pane's geometry instead of assigning a fixed
 * placeholder rectangle. `h` creates left/right panes; `v` creates
 * top/bottom panes. A one-cell gap is left for the eventual border. */
static int
bscreen_pane_split_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args), *dirarg = bs_word (&args);
    if (!name) { builtin_error ("pane-split: NAME [WIN] [h|v]"); return EX_USAGE; }
    if (!win) win = "0";
    if (!dirarg) dirarg = "h";
    if (strcmp (dirarg, "h") && strcmp (dirarg, "v") &&
        strcmp (dirarg, "H") && strcmp (dirarg, "V")) {
        builtin_error ("pane-split: direction must be h or v (got '%s')", dirarg);
        return EX_USAGE;
    }
    char sdir[512], parent[512], path[512], file[512], active[64] = "0";
    char oldfile[512], geom[128], oldgeom[128], newgeom[128];
    long r, c, rr, cc;
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("pane-split: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    bs_read_file (file, active, sizeof active);
    if (!bs_pane_exists (sdir, win, active)) strcpy (active, "0");
    if (!bs_pane_exists (sdir, win, active)) {
        builtin_error ("pane-split: no active pane in window %s", win);
        return EXECUTION_FAILURE;
    }
    snprintf (oldfile, sizeof oldfile, "%s/windows/%s/panes/%s/geom", sdir, win, active);
    strcpy (geom, "0 0 24 80");
    bs_read_file (oldfile, geom, sizeof geom);
    if (bs_parse_geom (geom, &r, &c, &rr, &cc) < 0) {
        builtin_error ("pane-split: active pane GEOM must be four non-negative ints");
        return EXECUTION_FAILURE;
    }
    snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    bs_mkdir_if_needed (parent, 0700);
    int idx = bs_next_numeric_dir (parent);
    snprintf (path, sizeof path, "%s/%d", parent, idx);
    if (bs_mkdir_if_needed (path, 0700) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/name", path);
    if (bs_write_file (file, dirarg) < 0) return EXECUTION_FAILURE;
    if (dirarg[0] == 'v' || dirarg[0] == 'V') {
        if (rr < 3) { builtin_error ("pane-split: pane too short to split vertically"); return EXECUTION_FAILURE; }
        snprintf (oldgeom, sizeof oldgeom, "%ld %ld %ld %ld", r, c, rr / 2, cc);
        snprintf (newgeom, sizeof newgeom, "%ld %ld %ld %ld", r + rr / 2 + 1, c, rr - rr / 2 - 1, cc);
    } else {
        if (cc < 3) { builtin_error ("pane-split: pane too narrow to split horizontally"); return EXECUTION_FAILURE; }
        snprintf (oldgeom, sizeof oldgeom, "%ld %ld %ld %ld", r, c, rr, cc / 2);
        snprintf (newgeom, sizeof newgeom, "%ld %ld %ld %ld", r, c + cc / 2 + 1, rr, cc - cc / 2 - 1);
    }
    if (bs_write_file (oldfile, oldgeom) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/geom", path);
    if (bs_write_file (file, newgeom) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/scrollback", path);
    if (bs_write_file (file, "") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/pty.fd", path);
    if (bs_write_file (file, "metadata\n") < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    snprintf (geom, sizeof geom, "%d\n", idx);
    if (bs_write_file (file, geom) < 0) return EXECUTION_FAILURE;
    snprintf (geom, sizeof geom, "%d", idx);
    if (bs_write_active_pair (sdir, win, geom) < 0) return EXECUTION_FAILURE;
    printf ("%d\n", idx);
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1: pane-select NAME PANE [WIN]. Validates that PANE exists
 * in WIN (default = active-window). Previously wrote any string to
 * active-pane regardless. */
static int
bscreen_pane_select_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *pane = bs_word (&args), *win = bs_word (&args);
    if (!name || !pane) { builtin_error ("pane-select: NAME PANE [WIN]"); return EX_USAGE; }
    char sdir[512], file[512], val[64], abuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!win) {
        snprintf (file, sizeof file, "%s/active-window", sdir);
        strcpy (abuf, "0"); bs_read_file (file, abuf, sizeof abuf);
        win = abuf;
    }
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-select: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    snprintf (val, sizeof val, "%s\n", pane);
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    return bs_write_active_pair (sdir, win, pane) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bscreen_pane_select_dir_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane = bs_word (&args), *dir = bs_word (&args);
    if (!name || !win || !pane || !dir) {
        builtin_error ("pane-select-dir: NAME WIN PANE U|D|L|R");
        return EX_USAGE;
    }
    char sdir[512], file[512], geom[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-select-dir: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    strcpy (geom, "0 0 24 80"); bs_read_file (file, geom, sizeof geom);
    long r, c, rr, cc;
    if (bs_parse_geom (geom, &r, &c, &rr, &cc) < 0) {
        builtin_error ("pane-select-dir: active pane GEOM must be four non-negative ints");
        return EXECUTION_FAILURE;
    }
    char parent[512]; snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    DIR *d = opendir (parent);
    if (!d) return EXECUTION_FAILURE;
    int best = -1;
    long best_dist = 999999;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.' || !strcmp (ent->d_name, pane)) continue;
        char *end = NULL;
        long idx = strtol (ent->d_name, &end, 10);
        if (!end || *end != '\0') continue;
        snprintf (file, sizeof file, "%s/%s/geom", parent, ent->d_name);
        strcpy (geom, "");
        if (bs_read_file (file, geom, sizeof geom) < 0) continue;
        long pr, pc, prr, pcc, dist = 0;
        if (bs_parse_geom (geom, &pr, &pc, &prr, &pcc) < 0) continue;
        switch (dir[0]) {
        case 'U': case 'u':
            if (pr + prr > r || !(pc < c + cc && pc + pcc > c)) continue;
            dist = r - (pr + prr); break;
        case 'D': case 'd':
            if (pr < r + rr || !(pc < c + cc && pc + pcc > c)) continue;
            dist = pr - (r + rr); break;
        case 'L': case 'l':
            if (pc + pcc > c || !(pr < r + rr && pr + prr > r)) continue;
            dist = c - (pc + pcc); break;
        case 'R': case 'r':
            if (pc < c + cc || !(pr < r + rr && pr + prr > r)) continue;
            dist = pc - (c + cc); break;
        default:
            closedir (d);
            builtin_error ("pane-select-dir: direction must be U, D, L, or R");
            return EX_USAGE;
        }
        if (dist < best_dist) { best_dist = dist; best = (int) idx; }
    }
    closedir (d);
    if (best < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    snprintf (geom, sizeof geom, "%d\n", best);
    if (bs_write_file (file, geom) < 0) return EXECUTION_FAILURE;
    snprintf (geom, sizeof geom, "%d", best);
    if (bs_write_active_pair (sdir, win, geom) < 0) return EXECUTION_FAILURE;
    printf ("%d\n", best);
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1: pane-resize NAME WIN PANE GEOM. GEOM is "R C RR CC"
 * (row, col, rows, cols) — same shape pane-split writes initially. */
static int
bscreen_pane_resize_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args), *pane = bs_word (&args);
    if (!name || !win || !pane) {
        builtin_error ("pane-resize: NAME WIN PANE GEOM");
        return EX_USAGE;
    }
    /* GEOM is the rest of the argv joined with spaces — accept either
     * a single quoted string or four positional ints. */
    char geom[128]; geom[0] = '\0';
    size_t off = 0;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        size_t wn = strlen (w);
        if (off + wn + 2 > sizeof geom) {
            builtin_error ("pane-resize: GEOM too long");
            return EX_USAGE;
        }
        if (off) geom[off++] = ' ';
        memcpy (geom + off, w, wn);
        off += wn;
        geom[off] = '\0';
    }
    if (!*geom) {
        builtin_error ("pane-resize: GEOM required (e.g. \"0 0 12 40\")");
        return EX_USAGE;
    }
    /* Validate GEOM = four space-separated non-negative ints. */
    {
        const char *p = geom;
        for (int i = 0; i < 4; i++) {
            char *end = NULL;
            long v = strtol (p, &end, 10);
            if (end == p || v < 0 || (i < 3 ? *end != ' ' : (*end != '\0' && *end != '\n'))) {
                builtin_error ("pane-resize: GEOM must be four non-negative ints \"R C RR CC\"");
                return EX_USAGE;
            }
            p = end + (i < 3 ? 1 : 0);
        }
    }
    char sdir[512], file[512];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-resize: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    return bs_write_file (file, geom) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 18 v2 metadata helper for tmux resize-pane -U/-D/-L/-R.
 * This deliberately adjusts only the target pane's stored geometry;
 * full tree redistribution belongs to the later render-loop work. */
static int
bscreen_pane_resize_dir_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane = bs_word (&args), *dir = bs_word (&args);
    const char *amount_s = bs_word (&args);
    if (!name || !win || !pane || !dir) {
        builtin_error ("pane-resize-dir: NAME WIN PANE U|D|L|R [N]");
        return EX_USAGE;
    }
    char *end = NULL;
    long amount = amount_s ? strtol (amount_s, &end, 10) : 1;
    if (amount <= 0 || (amount_s && (!end || *end != '\0'))) {
        builtin_error ("pane-resize-dir: N must be a positive integer");
        return EX_USAGE;
    }
    char sdir[512], file[512], geom[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-resize-dir: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    strcpy (geom, "0 0 24 80");
    bs_read_file (file, geom, sizeof geom);
    char *p = geom;
    long r, c, rr, cc;
    r = strtol (p, &end, 10); if (end == p || *end != ' ') goto bad_geom; p = end + 1;
    c = strtol (p, &end, 10); if (end == p || *end != ' ') goto bad_geom; p = end + 1;
    rr = strtol (p, &end, 10); if (end == p || *end != ' ') goto bad_geom; p = end + 1;
    cc = strtol (p, &end, 10);
    if (end == p || (*end != '\0' && *end != '\n') || r < 0 || c < 0 || rr < 0 || cc < 0)
        goto bad_geom;
    switch (dir[0]) {
    case 'U': case 'u': rr = rr > amount ? rr - amount : 1; break;
    case 'D': case 'd': rr += amount; break;
    case 'L': case 'l': cc = cc > amount ? cc - amount : 1; break;
    case 'R': case 'r': cc += amount; break;
    default:
        builtin_error ("pane-resize-dir: direction must be U, D, L, or R");
        return EX_USAGE;
    }
    snprintf (geom, sizeof geom, "%ld %ld %ld %ld", r, c, rr, cc);
    return bs_write_file (file, geom) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

bad_geom:
    builtin_error ("pane-resize-dir: stored GEOM must be four non-negative ints \"R C RR CC\"");
    return EXECUTION_FAILURE;
}

/* Stage 18 v2 metadata helper for tmux swap-pane. The loadable stores
 * pane content separately later; for now the visible operation is the
 * pane geometry exchange used by the shell fallback. */
static int
bscreen_pane_swap_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane_a = bs_word (&args), *pane_b = bs_word (&args);
    if (!name || !win || !pane_a || !pane_b) {
        builtin_error ("pane-swap: NAME WIN PANE_A PANE_B");
        return EX_USAGE;
    }
    char sdir[512], file_a[512], file_b[512], geom_a[128], geom_b[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane_a)) {
        builtin_error ("pane-swap: no such pane %s in window %s of session %s",
                       pane_a, win, name);
        return EXECUTION_FAILURE;
    }
    if (!bs_pane_exists (sdir, win, pane_b)) {
        builtin_error ("pane-swap: no such pane %s in window %s of session %s",
                       pane_b, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file_a, sizeof file_a, "%s/windows/%s/panes/%s/geom", sdir, win, pane_a);
    snprintf (file_b, sizeof file_b, "%s/windows/%s/panes/%s/geom", sdir, win, pane_b);
    strcpy (geom_a, "0 0 24 80"); bs_read_file (file_a, geom_a, sizeof geom_a);
    strcpy (geom_b, "0 0 24 80"); bs_read_file (file_b, geom_b, sizeof geom_b);
    if (bs_write_file (file_a, geom_b) < 0) return EXECUTION_FAILURE;
    return bs_write_file (file_b, geom_a) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 18 v1: pane-kill NAME WIN PANE. Drops the pane dir tree; if it
 * was the active pane (and active-window matches WIN), advances
 * active-pane to the lowest surviving pane in that window (or 0 if no
 * panes left — the operator's run-loop owns kill-window-when-empty). */
static int
bscreen_pane_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args), *pane = bs_word (&args);
    if (!name || !win || !pane) { builtin_error ("pane-kill: NAME WIN PANE"); return EX_USAGE; }
    char sdir[512], ppath[512], afile[512], abuf[64], wbuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-kill: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (ppath, sizeof ppath, "%s/windows/%s/panes/%s", sdir, win, pane);
    if (bs_rm_rf (ppath) < 0) {
        builtin_error ("pane-kill: failed to remove %s: %s", ppath, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* If the killed pane was the active one (and we're killing in the
     * active window), advance to the lowest surviving sibling. */
    snprintf (afile, sizeof afile, "%s/active-pane", sdir);
    strcpy (abuf, ""); bs_read_file (afile, abuf, sizeof abuf);
    char wfile[512]; snprintf (wfile, sizeof wfile, "%s/active-window", sdir);
    strcpy (wbuf, ""); bs_read_file (wfile, wbuf, sizeof wbuf);
    if (!strcmp (abuf, pane) && !strcmp (wbuf, win)) {
        char parent[512]; snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
        DIR *d = opendir (parent);
        int next = -1;
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char *end = NULL;
                long v = strtol (ent->d_name, &end, 10);
                if (end && *end == '\0' && (next < 0 || v < next)) next = (int) v;
            }
            closedir (d);
        }
        char val[64];
        snprintf (val, sizeof val, "%d\n", next < 0 ? 0 : next);
        if (bs_write_file (afile, val) < 0) return EXECUTION_FAILURE;
        snprintf (val, sizeof val, "%d", next < 0 ? 0 : next);
        if (bs_write_active_pair (sdir, win, val) < 0) return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_send_keys_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("send-keys: NAME KEYS..."); return EX_USAGE; }
    const char *target = NULL;
    if (args && args->word && args->word->word &&
        (!strcmp (args->word->word, "-p") || !strcmp (args->word->word, "-t"))) {
        args = args->next;
        if (!args || !args->word || !args->word->word) {
            builtin_error ("send-keys: -p requires WIN:PANE or PANE");
            return EX_USAGE;
        }
        target = args->word->word;
        args = args->next;
    }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], win[64], pane[64], pane_file[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) { builtin_error ("send-keys: no such session: %s", name); return EXECUTION_FAILURE; }
    bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
    if (target && bs_parse_target (target, win, sizeof win, pane, sizeof pane) < 0) {
        builtin_error ("send-keys: invalid target: %s", target);
        return EX_USAGE;
    }
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("send-keys: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }
    if (!target && bs_relay_send_words (sdir, args) == 0) return EXECUTION_SUCCESS;
    snprintf (pane_file, sizeof pane_file, "%s/windows/%s/panes/%s/scrollback", sdir, win, pane);
    FILE *pf = fopen (pane_file, "a");
    if (!pf) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *f = fopen (file, "a");
    if (!f) { fclose (pf); return EXECUTION_FAILURE; }
    const char *w;
    int first = 1;
    while ((w = bs_word (&args)) != NULL) {
        if (!first) { fputc (' ', f); fputc (' ', pf); }
        fputs (w, f);
        fputs (w, pf);
        first = 0;
    }
    fputc ('\n', f);
    fputc ('\n', pf);
    fclose (f);
    fclose (pf);
    bs_pane_scrollback_maintain (file);
    bs_pane_scrollback_maintain (pane_file);
    return EXECUTION_SUCCESS;
}

static int
bscreen_send_mouse_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("send-mouse: NAME [WIN PANE] BUTTON ROW COL [ACTION]"); return EX_USAGE; }
    const char *words[6];
    int n = 0;
    const char *w;
    while ((w = bs_word (&args)) != NULL && n < 6) words[n++] = w;
    if (bs_word (&args) != NULL) { builtin_error ("send-mouse: too many arguments"); return EX_USAGE; }
    if (n != 3 && n != 4 && n != 5 && n != 6) {
        builtin_error ("send-mouse: NAME [WIN PANE] BUTTON ROW COL [ACTION]");
        return EX_USAGE;
    }

    const char *win = NULL, *pane = NULL, *button, *row, *col, *action = "press";
    if (n >= 5) {
        win = words[0]; pane = words[1]; button = words[2]; row = words[3]; col = words[4];
        if (n == 6) action = words[5];
    } else {
        button = words[0]; row = words[1]; col = words[2];
        if (n == 4) action = words[3];
    }

    char *end = NULL;
    long r = strtol (row, &end, 10);
    if (!end || *end || r < 0) { builtin_error ("send-mouse: invalid row: %s", row); return EX_USAGE; }
    long c = strtol (col, &end, 10);
    if (!end || *end || c < 0) { builtin_error ("send-mouse: invalid col: %s", col); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) { builtin_error ("send-mouse: no such session: %s", name); return EXECUTION_FAILURE; }
    if (win && pane && !bs_pane_exists (sdir, win, pane)) {
        builtin_error ("send-mouse: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }

    snprintf (file, sizeof file, "%s/mouse", sdir);
    FILE *mf = fopen (file, "a");
    if (!mf) return EXECUTION_FAILURE;
    if (win && pane) fprintf (mf, "%s %s %s %ld %ld %s\n", win, pane, button, r, c, action);
    else fprintf (mf, "%s %ld %ld %s\n", button, r, c, action);
    fclose (mf);

    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *sf = fopen (file, "a");
    if (!sf) return EXECUTION_FAILURE;
    if (win && pane) fprintf (sf, "mouse %s %s %s %ld %ld %s\n", win, pane, button, r, c, action);
    else fprintf (sf, "mouse %s %ld %ld %s\n", button, r, c, action);
    fclose (sf);
    bs_pane_scrollback_maintain (file);
    return EXECUTION_SUCCESS;
}

static int
bscreen_capture_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("capture-pane: NAME"); return EX_USAGE; }
    int limit = 0;
    const char *target = NULL;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if ((!strcmp (w, "-N") || !strcmp (w, "-n")) && args) {
            limit = atoi (bs_word (&args));
        } else if ((!strcmp (w, "-t") || !strcmp (w, "-p")) && args) {
            target = bs_word (&args);
        } else {
            builtin_error ("capture-pane: unexpected '%s'", w);
            return EX_USAGE;
        }
    }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], win[64], pane[64];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("capture-pane: no such session: %s", name); return EXECUTION_FAILURE; }
    if (target) {
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        if (bs_parse_target (target, win, sizeof win, pane, sizeof pane) < 0) {
            builtin_error ("capture-pane: invalid target: %s", target);
            return EX_USAGE;
        }
    }
    if (target && bs_pane_exists (sdir, win, pane))
        snprintf (file, sizeof file, "%s/windows/%s/panes/%s/scrollback", sdir, win, pane);
    else
        snprintf (file, sizeof file, "%s/scrollback", sdir);

    /* Stage 50.F: read compressed blobs (oldest first) before the
     * live scrollback so callers see the full history transparently. */
    char blobs_dir[1024];
    int has_blobs = 0;
    char **blob_names = NULL;
    int n_blobs = 0;
    if (bs_scrollback_blobs_dir (file, blobs_dir, sizeof blobs_dir) == 0) {
        struct stat bd;
        if (stat (blobs_dir, &bd) == 0 && S_ISDIR (bd.st_mode)) {
            has_blobs = 1;
            n_blobs = bs_list_blobs_sorted (blobs_dir, &blob_names);
        }
    }

    if (limit <= 0) {
        for (int i = 0; i < n_blobs; i++) {
            char bp[1100];
            snprintf (bp, sizeof bp, "%s/%s", blobs_dir, blob_names[i]);
            bs_stream_blob (bp);
        }
        FILE *f = fopen (file, "r");
        if (f) {
            int ch; while ((ch = fgetc (f)) != EOF) putchar (ch);
            fclose (f);
        }
    } else {
        /* Stage 50.F -N path (v3.5 -- Round 1778564979 Doc 2,
         * screen-capture-N-cross-blob, 2026-05-12).
         *
         * v3.3 produced empty guest output: mixed FILE-star vs fd I/O
         * and shared realloc ownership between getline and the
         * bs_ring_feed helper. v3.4 collapsed to one I/O shape
         * (single buffer then write to fd 1) which was algorithmically
         * correct on paper but still produced count=0 in the v3.3
         * sweep for cases 4, 9, and 10. The doc explicitly fences
         * this round to "decompress and concat from oldest needed
         * blob forward" rather than decompressing every blob
         * unconditionally.
         *
         * v3.5 algorithm:
         *   1. Read live tail into buf first.
         *   2. Count newlines in buf. If already at-or-above limit,
         *      jump straight to the suffix walk.
         *   3. Otherwise, walk blobs newest-to-oldest, decompressing
         *      each in front of buf until cumulative newline count
         *      reaches limit. Older blobs are NEVER touched.
         *   4. Walk back from end-of-buf to find the start of the
         *      last limit lines; write that suffix to fd 1.
         *
         * The oldest-needed-blob-first concat shape matches the
         * doc's instruction and bounds the buffer size to whatever
         * fits the requested suffix -- important for very long
         * scrollback histories where the v3.4 decompress-all could
         * allocate hundreds of MB on the guest.
         *
         * BASHSCREEN_DEBUG_CAPTURE=1 (env var) emits a single
         * diagnostic line to stderr so operator sweeps can see at
         * a glance whether the blob walk fired and what byte counts
         * resulted. Stays silent otherwise.
         */
        const char *dbg_env = getenv ("BASHSCREEN_DEBUG_CAPTURE");
        int dbg = (dbg_env && *dbg_env && *dbg_env != '0');

        size_t bcap = 0, blen = 0;
        char *buf = NULL;
        size_t live_bytes = 0;

        /* Step 1 -- live tail first. */
        FILE *f = fopen (file, "r");
        if (f) {
            char rdbuf[8192];
            size_t nr;
            while ((nr = fread (rdbuf, 1, sizeof rdbuf, f)) > 0) {
                if (blen + nr + 1 > bcap) {
                    size_t nc = bcap ? bcap * 2 : 8192;
                    while (nc < blen + nr + 1) nc *= 2;
                    char *p = realloc (buf, nc);
                    if (!p) { break; }
                    buf = p; bcap = nc;
                }
                memcpy (buf + blen, rdbuf, nr);
                blen += nr;
            }
            fclose (f);
            live_bytes = blen;
        }

        /* Newline count for current `buf`. A trailing '\n' counts as
         * the end of the final line, not as an extra empty line. */
        int nl_count = 0;
        for (size_t k = 0; k < blen; k++)
            if (buf[k] == '\n') nl_count++;
        if (blen > 0 && buf && buf[blen - 1] != '\n') nl_count++;

        /* Step 2/3 — walk blobs newest→oldest if needed. We
         * decompress each blob into a temporary slab, then PREPEND
         * it to `buf` (memmove existing content right, copy slab
         * into the new head). Stops as soon as nl_count >= limit. */
        int blobs_used = 0;
        for (int i = n_blobs - 1; i >= 0 && nl_count < limit; i--) {
            char bp[1100];
            snprintf (bp, sizeof bp, "%s/%s", blobs_dir, blob_names[i]);
            gzFile gz = gzopen (bp, "rb");
            if (!gz) {
                builtin_warning ("capture-pane: failed to open %s",
                                 blob_names[i]);
                continue;
            }
            /* Decompress this blob into a fresh slab so we can
             * PREPEND atomically. Two-pass realloc would have to
             * memmove the entire current buf on every chunk; one
             * full-slab + one memmove is the cheaper shape. */
            size_t scap = 8192, slen = 0;
            char *slab = malloc (scap);
            int gerr = 0;
            if (!slab) {
                gerr = 1;
            } else {
                char rdbuf[8192];
                int nr;
                while ((nr = gzread (gz, rdbuf, sizeof rdbuf)) > 0) {
                    if (slen + (size_t) nr > scap) {
                        size_t nc = scap * 2;
                        while (nc < slen + (size_t) nr) nc *= 2;
                        char *p = realloc (slab, nc);
                        if (!p) { gerr = 1; break; }
                        slab = p; scap = nc;
                    }
                    memcpy (slab + slen, rdbuf, (size_t) nr);
                    slen += (size_t) nr;
                }
            }
            gzclose (gz);
            if (gerr) {
                builtin_warning ("capture-pane: oom decompressing %s",
                                 blob_names[i]);
                free (slab);
                continue;
            }
            /* Prepend slab to buf: grow buf, memmove existing right,
             * copy slab into the head. */
            if (slen > 0) {
                if (blen + slen + 1 > bcap) {
                    size_t nc = bcap ? bcap : 8192;
                    while (nc < blen + slen + 1) nc *= 2;
                    char *p = realloc (buf, nc);
                    if (!p) { free (slab); continue; }
                    buf = p; bcap = nc;
                }
                if (blen > 0) memmove (buf + slen, buf, blen);
                memcpy (buf, slab, slen);
                blen += slen;
                for (size_t k = 0; k < slen; k++)
                    if (slab[k] == '\n') nl_count++;
            }
            free (slab);
            blobs_used++;
        }

        if (dbg) {
            fprintf (stderr,
                "screen capture-N: limit=%d blobs_seen=%d "
                "live_bytes=%zu total=%zu nl=%d\n",
                limit, blobs_used, live_bytes, blen, nl_count);
        }

        /* Step 4 — walk backwards from end of `buf` to locate the
         * start of the last `limit` lines, then write that suffix
         * directly to fd 1. Identical shape to v3.4's tail walk so
         * regression risk is bounded to the prepend logic above.
         *
         * Round 1778571667 / Doc 1 (2026-05-12, v3.6): defensively
         * fflush(stdout) before the raw write() ladder. Static-musl
         * bash buffers stdout fully when fd 1 is a pipe (the shape
         * used by `out=$(...)` capture); any stdio output from the
         * surrounding bash invocation that landed in the FILE*'s
         * buffer would otherwise be flushed AFTER our raw write()
         * bytes when the builtin returns — interleaving the output
         * across the seam between bash's stdout buffer and the kernel
         * pipe, and producing exactly the count=0 shape seen in cases
         * 4/7/8 across five prior fix rounds. The fflush() is cheap
         * (typical bash stdout buffer is empty at builtin entry) and
         * makes the -N branch's output order deterministic regardless
         * of caller-side stdio activity. */
        fflush (stdout);
        if (blen > 0 && buf) {
            ssize_t cursor = (ssize_t) blen - 1;
            int seen = 0;
            ssize_t start_off = 0;
            if (buf[cursor] == '\n') cursor--;
            while (cursor >= 0) {
                if (buf[cursor] == '\n') {
                    seen++;
                    if (seen >= limit) {
                        start_off = cursor + 1;
                        break;
                    }
                }
                cursor--;
            }
            if (seen < limit) start_off = 0;
            size_t out_len = blen - (size_t) start_off;
            const char *p = buf + start_off;
            size_t left = out_len;
            while (left > 0) {
                ssize_t w = write (STDOUT_FILENO, p, left);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                p += w; left -= (size_t) w;
            }
        }
        free (buf);
    }
    for (int i = 0; i < n_blobs; i++) free (blob_names[i]);
    free (blob_names);
    (void) has_blobs;
    return EXECUTION_SUCCESS;
}

/* `screen list` — enumerate active sessions. Skeleton just scans
   the state directory and prints names of subdirs that contain a
   readable `pid` file. Empty output when no sessions. Refuses to
   touch a state dir that fails the private-dir contract. */
static int
bscreen_list_cmd (WORD_LIST *args)
{
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "--cluster"))
            return bscreen_cluster_list_cmd ();
        builtin_error ("list: unexpected '%s'", w);
        return EX_USAGE;
    }
    const char *root = bscreen_state_dir ();
    /* Walk the contract first; if the dir doesn't exist yet we
       create it (0700) to lock in the contract for any subsequent
       writes by the multiplexer server. */
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    DIR *d = opendir (root);
    if (!d) {
        if (errno == ENOENT) return EXECUTION_SUCCESS;  /* no sessions yet */
        builtin_error ("opendir %s: %s", root, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char pidpath[512];
        snprintf (pidpath, sizeof pidpath, "%s/%s/pid", root, ent->d_name);
        struct stat st;
        if (stat (pidpath, &st) == 0 && S_ISREG (st.st_mode))
            printf ("%s\n", ent->d_name);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
bscreen_relay_status_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("relay-status: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], line[256];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("relay-status: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/relay-status", sdir);
    if (bs_read_file (file, line, sizeof line) < 0)
        strcpy (line, "live-relay unavailable");
    printf ("%s\n", line);
    return EXECUTION_SUCCESS;
}

static int
bscreen_vt_info_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    const char *win = bs_word (&args);
    if (!name) { builtin_error ("vt-info: NAME [WIN]"); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], active[64] = "0";
    char handle[128] = "pending", gen[64] = "0", dirty[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("vt-info: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    if (!win) {
        snprintf (file, sizeof file, "%s/active-window", sdir);
        bs_read_file (file, active, sizeof active);
        win = active;
    }
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("vt-info: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/vt-handle", sdir, win);
    bs_read_file (file, handle, sizeof handle);
    snprintf (file, sizeof file, "%s/windows/%s/vt-generation", sdir, win);
    bs_read_file (file, gen, sizeof gen);
    snprintf (file, sizeof file, "%s/windows/%s/vt-dirty", sdir, win);
    bs_read_file (file, dirty, sizeof dirty);

    printf ("window %s\nvt-handle %s\nvt-generation %s\nvt-dirty %s\nrelay live-available-via-attach-r\n",
            win, handle, gen, dirty);
    return EXECUTION_SUCCESS;
}

static int
bscreen_client_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("client-list: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], adir[512], file[512], line[256];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("client-list: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    snprintf (adir, sizeof adir, "%s/attachers", sdir);
    DIR *d = opendir (adir);
    if (!d) return EXECUTION_SUCCESS;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf (file, sizeof file, "%s/%s", adir, ent->d_name);
        FILE *f = fopen (file, "r");
        if (!f) continue;
        printf ("client %s\n", ent->d_name);
        while (fgets (line, sizeof line, f)) fputs (line, stdout);
        fclose (f);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

/* `screen state-dir` — print the current state directory path
   (handy for shell scripts wiring up against screen). Bonus
   skeleton verb not in the original surface table. */
static int
bscreen_state_dir_cmd (WORD_LIST *args)
{
    (void) args;
    printf ("%s\n", bscreen_state_dir ());
    return EXECUTION_SUCCESS;
}

static int
bs_remote_frame_type_id (const char *s)
{
    if (!s) return -1;
    if (!strcmp (s, "pty")) return BSCREEN_REMOTE_FRAME_PTY;
    if (!strcmp (s, "query")) return BSCREEN_REMOTE_FRAME_QUERY;
    if (!strcmp (s, "control")) return BSCREEN_REMOTE_FRAME_CONTROL;
    return -1;
}

static const char *
bs_remote_frame_type_name (int type)
{
    switch (type) {
    case BSCREEN_REMOTE_FRAME_PTY: return "pty";
    case BSCREEN_REMOTE_FRAME_QUERY: return "query";
    case BSCREEN_REMOTE_FRAME_CONTROL: return "control";
    default: return "unknown";
    }
}

static int
bs_read_exact_fd (int fd, void *buf, size_t n)
{
    char *p = (char *) buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read (fd, p + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        off += (size_t) r;
    }
    return 0;
}

static int
bscreen_remote_frame_cmd (WORD_LIST *args)
{
    const char *sub = bs_word (&args);
    if (!sub) { builtin_error ("remote-frame: encode TYPE PAYLOAD | decode"); return EX_USAGE; }
    if (!strcmp (sub, "encode")) {
        const char *type_s = bs_word (&args);
        const char *payload = bs_word (&args);
        int type = bs_remote_frame_type_id (type_s);
        struct bs_remote_frame_header h;
        if (type < 0 || !payload || bs_word (&args) != NULL) {
            builtin_error ("remote-frame encode: TYPE PAYLOAD");
            return EX_USAGE;
        }
        size_t len = strlen (payload);
        if (len > UINT32_MAX) {
            builtin_error ("remote-frame encode: payload too large");
            return EXECUTION_FAILURE;
        }
        bs_remote_frame_init (&h, (unsigned char) type, (uint32_t) len);
        fflush (stdout);
        if (bs_relay_write_all (STDOUT_FILENO, (const char *) &h, sizeof h) < 0 ||
            bs_relay_write_all (STDOUT_FILENO, payload, (ssize_t) len) < 0)
            return EXECUTION_FAILURE;
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (sub, "decode")) {
        struct bs_remote_frame_header h;
        uint32_t len = 0;
        char *payload;
        if (bs_word (&args) != NULL) {
            builtin_error ("remote-frame decode: no arguments");
            return EX_USAGE;
        }
        if (bs_read_exact_fd (STDIN_FILENO, &h, sizeof h) < 0 ||
            !bs_remote_frame_valid (&h, &len) ||
            len > (1024u * 1024u)) {
            builtin_error ("remote-frame decode: invalid frame");
            return EXECUTION_FAILURE;
        }
        payload = malloc ((size_t) len + 1);
        if (!payload) return EXECUTION_FAILURE;
        if (bs_read_exact_fd (STDIN_FILENO, payload, len) < 0) {
            free (payload);
            builtin_error ("remote-frame decode: short payload");
            return EXECUTION_FAILURE;
        }
        payload[len] = '\0';
        printf ("type=%s\nlen=%u\npayload=%s\n",
                bs_remote_frame_type_name (h.type), (unsigned) len, payload);
        free (payload);
        return EXECUTION_SUCCESS;
    }
    builtin_error ("remote-frame: unknown subcommand: %s", sub);
    return EX_USAGE;
}

int
screen_builtin (WORD_LIST *list)
{
    if (list && list->word && list->word->word) {
        const char *w = list->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("screen 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
    }
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (cmd, "list") || !strcmp (cmd, "ls"))
                                    return bscreen_list_cmd      (args);
    if (!strcmp (cmd, "state-dir")) return bscreen_state_dir_cmd (args);
    if (!strcmp (cmd, "run"))       return bscreen_run_cmd       (args);
    if (!strcmp (cmd, "kill"))      return bscreen_kill_cmd      (args);
    if (!strcmp (cmd, "attach"))    return bscreen_attach_cmd    (args);
    if (!strcmp (cmd, "roam"))      return bscreen_roam_cmd      (args);
    if (!strcmp (cmd, "state"))     return bscreen_state_cmd     (args);
    if (!strcmp (cmd, "find"))      return bscreen_find_cmd      (args);
    if (!strcmp (cmd, "win-create")) return bscreen_win_create_cmd (args);
    if (!strcmp (cmd, "win-switch")) return bscreen_win_switch_cmd (args);
    if (!strcmp (cmd, "win-list"))   return bscreen_win_list_cmd   (args);
    if (!strcmp (cmd, "win-rename")) return bscreen_win_rename_cmd (args);
    if (!strcmp (cmd, "win-kill"))   return bscreen_win_kill_cmd   (args);
    if (!strcmp (cmd, "win-next"))   return bscreen_win_cycle_cmd  (args, 1);
    if (!strcmp (cmd, "win-prev"))   return bscreen_win_cycle_cmd  (args, -1);
    if (!strcmp (cmd, "pane-split")) return bscreen_pane_split_cmd (args);
    if (!strcmp (cmd, "pane-select")) return bscreen_pane_select_cmd (args);
    if (!strcmp (cmd, "pane-select-dir")) return bscreen_pane_select_dir_cmd (args);
    if (!strcmp (cmd, "pane-list"))  return bscreen_pane_list_cmd  (args);
    if (!strcmp (cmd, "pane-resize")) return bscreen_pane_resize_cmd (args);
    if (!strcmp (cmd, "pane-resize-dir")) return bscreen_pane_resize_dir_cmd (args);
    if (!strcmp (cmd, "pane-swap"))  return bscreen_pane_swap_cmd   (args);
    if (!strcmp (cmd, "pane-display")) return bscreen_pane_list_cmd (args);
    if (!strcmp (cmd, "pane-kill"))  return bscreen_pane_kill_cmd  (args);
    if (!strcmp (cmd, "send-keys"))  return bscreen_send_keys_cmd  (args);
    if (!strcmp (cmd, "capture-pane")) return bscreen_capture_cmd  (args);
    if (!strcmp (cmd, "scrollback")) return bscreen_capture_cmd    (args);
    if (!strcmp (cmd, "send-mouse")) return bscreen_send_mouse_cmd (args);
    if (!strcmp (cmd, "vt-info"))    return bscreen_vt_info_cmd    (args);
    if (!strcmp (cmd, "client-list")) return bscreen_client_list_cmd (args);
    if (!strcmp (cmd, "relay-status")) return bscreen_relay_status_cmd (args);
    if (!strcmp (cmd, "remote-frame")) return bscreen_remote_frame_cmd (args);
    builtin_error ("unknown verb: %s "
                   "(try list/state-dir; reserved: run/kill/attach/state/find/"
                   "win-*/pane-*/send-keys/capture-pane/scrollback/send-mouse/"
                   "vt-info/client-list/relay-status/roam)",
                   cmd);
    return EX_USAGE;
}

char *screen_doc[] = {
    "bash-screen multiplexer server (Stage 50/Phase 3 v1).",
    "",
    "    screen list|ls [--cluster]        enumerate local or cluster sessions",
    "    screen state-dir                  print state directory",
    "",
    "Implemented Phase 3 v1 surface:",
    "    run -n NAME [-d] [CMD...]            create metadata; CMD starts live relay",
    "    kill NAME                             terminate session",
    "    attach NAME [-r|-rd|-x|-d]            record/detach attachers",
    "    attach NODE/SESSION --remote [--key FILE]",
    "                                          resolve cluster member; SSH relay gated",
    "    roam NODE/SESSION [--key FILE] [--dry-run]",
    "                                          reattach via cluster resolver; ^A r roams",
    "    state NAME                            render current grid",
    "    find NAME PATTERN                     search rendered grid",
    "    win-create | win-switch | win-list    Stage 9 windows",
    "    win-rename NAME IDX NEWNAME           rename a window (Stage 9 v1)",
    "    win-kill NAME IDX                     drop a window (Stage 9 v1);",
    "    win-next NAME | win-prev NAME         cycle active window",
    "                                          re-points active to lowest surviving idx",
    "    pane-split | pane-select | pane-list  Stage 18 panes",
    "    pane-select-dir NAME WIN PANE D       select adjacent pane by geometry",
    "    pane-resize NAME WIN PANE GEOM        rewrite pane geom (Stage 18 v1)",
    "    pane-resize-dir NAME WIN PANE D [N]   metadata directional resize (Stage 18 v2)",
    "    pane-swap NAME WIN PANE_A PANE_B      exchange pane geometry (Stage 18 v2)",
    "    pane-display NAME [WIN]               alias for pane-list",
    "    pane-kill NAME WIN PANE               drop a pane (Stage 18 v1);",
    "                                          re-points active-pane to lowest survivor",
    "    send-keys | capture-pane [-N LINES]   Stages 9/18",
    "    scrollback NAME [-N LINES]            Stages 5 + 12",
    "    send-mouse NAME [WIN PANE] BUTTON ROW COL [ACTION]  Stage 8",
    "    vt-info NAME [WIN]                    Stage 50.C vt metadata scaffold",
    "    client-list NAME                      Stage 50.C client last-seen metadata",
    "    relay-status NAME                     Stage 50.D live relay diagnostic",
    "    --help | --version                    print this synopsis or version",
    "",
    "State dir defaults to /tmp/.screen, override with",
    "BASHSCREEN_STATE_DIR. Cluster discovery reads BASHCLUSTER_STATE_DIR",
    "(or BASHCLUSTER_DIR) members + sessions/<node> fixtures. See",
    "Roam keys use BASHSCREEN_DETACH_KEY (default ^A), BASHSCREEN_ROAM_KEY",
    "(default r), and BASHSCREEN_ROAM_RECONNECT (0..16, default 0). See",
    "research/bash-os/MASTER-UNFINISHED-",
    "WORK-IMPLEMENTATION.md §Stage 50 for the full layout.",
    (char *) NULL
};

struct builtin screen_struct = {
    "screen",
    screen_builtin,
    BUILTIN_ENABLED,
    screen_doc,
    "screen <verb> [args...] [--help|--version]",
    0
};
