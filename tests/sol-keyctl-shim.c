/* SPDX-License-Identifier: MIT
 * Closed syscall fixture: includes the production implementation verbatim.
 * Nothing here forwards a syscall to a live keyring, even on invalid input.
 */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include "loadables.h"

static long fixture_syscall (long, ...);
static void *fixture_malloc (size_t);
static void *fixture_realloc (void *, size_t);
static void fixture_free (void *);
static ssize_t fixture_read (int, void *, size_t);
#define syscall fixture_syscall
#define malloc fixture_malloc
#define realloc fixture_realloc
#define free fixture_free
#define read fixture_read
#ifndef KEYCTL_SOURCE
#define KEYCTL_SOURCE "../loadables/keyctl.c"
#endif
#include KEYCTL_SOURCE
#undef syscall
#undef malloc
#undef realloc
#undef free
#undef read

static int live_allocs, alloc_attempts, alloc_fail_at, input_error;
static void *fixture_malloc (size_t n)
{
    if (++alloc_attempts == alloc_fail_at) { errno = ENOMEM; return NULL; }
    void *p = malloc (n);
    if (p) live_allocs++;
    return p;
}
static void *fixture_realloc (void *p, size_t n)
{
    if (++alloc_attempts == alloc_fail_at) { errno = ENOMEM; return NULL; }
    return realloc (p, n);
}
static void fixture_free (void *p)
{
    if (p) live_allocs--;
    free (p);
}
static ssize_t fixture_read (int fd, void *p, size_t n)
{
    if (input_error) {
        int e = input_error;
        input_error = 0;
        errno = e;
        return -1;
    }
    return read (fd, p, n);
}

struct fixture_key {
    char type[32], name[4096];
    unsigned char *data;
    size_t len;
    int linked, revoked;
};
static struct fixture_key keys[16];
static int joined, calls, bad, next_key, read_mode;
static long last_ring, expected_ring = KEY_SPEC_SESSION_KEYRING;
static char fail_op[16];
static char session_name[4096];
static int session_named;
static int fail_errno;

static long error (int e) { errno = e; return -1; }
static int fail (const char *op)
{
    if (!strcmp (op, fail_op)) { errno = fail_errno; return 1; }
    return 0;
}
static int ring_ok (long ring)
{
    last_ring = ring;
    if (!joined) { bad++; errno = EPERM; return 0; }
    if (ring != expected_ring && ring != 9001) {
        bad++; errno = EACCES; return 0;
    }
    return 1;
}

static long fixture_syscall (long nr, ...)
{
    va_list ap;
    calls++;
    va_start (ap, nr);
    if (nr == SYS_add_key) {
        const char *type = va_arg (ap, const char *);
        const char *name = va_arg (ap, const char *);
        const void *data = va_arg (ap, const void *);
        size_t len = va_arg (ap, size_t);
        long ring = va_arg (ap, long);
        va_end (ap);
        if (!ring_ok (ring) || fail ("add")) return -1;
        if (!*type || strlen (type) > 31 || strlen (name) > 4095 ||
            len > 1048575) { bad++; return error (EINVAL); }
        /* Match user key type's independent payload/description limits. */
        if (!strcmp (type, "user") && (!*name || !len || len > 32767))
            return error (EINVAL);
        int i;
        for (i = 0; i < next_key; i++)
            if (keys[i].linked && !keys[i].revoked &&
                !strcmp (type, keys[i].type) && !strcmp (name, keys[i].name)) break;
        if (i == next_key) {
            if (next_key == 16) return error (EDQUOT);
            next_key++;
        }
        struct fixture_key *k = &keys[i];
        unsigned char *copy = malloc (len ? len : 1);
        if (!copy) return error (ENOMEM);
        memcpy (copy, data, len);
        free (k->data);
        k->data = copy; k->len = len; k->linked = 1; k->revoked = 0;
        strcpy (k->type, type); strcpy (k->name, name);
        return 10001 + i;
    }
    if (nr != SYS_keyctl) { va_end (ap); bad++; return error (ENOSYS); }
    int cmd = va_arg (ap, int);
    unsigned long a1 = va_arg (ap, unsigned long);
    unsigned long a2 = va_arg (ap, unsigned long);
    unsigned long a3 = va_arg (ap, unsigned long);
    unsigned long a4 = va_arg (ap, unsigned long);
    va_end (ap);
    if (a4) { bad++; return error (EINVAL); }
    if (cmd == KEYCTL_JOIN_SESSION_KEYRING) {
        if (a2 || a3) { bad++; return error (EINVAL); }
        if (fail ("session")) return -1;
        if (a1 && (strlen ((char *)a1) > 4095 || *(char *)a1 == '.')) {
            bad++; return error (EINVAL);
        }
        session_named = a1 != 0;
        if (a1) strcpy (session_name, (char *)a1);
        joined = 1;
        return 9001;
    }
    if (cmd == KEYCTL_SEARCH) {
        if (!ring_ok ((long)a1) || fail ("search")) return -1;
        for (int i = 0; i < next_key; i++)
            if (keys[i].linked && !keys[i].revoked &&
                !strcmp (keys[i].type, (char *)a2) &&
                !strcmp (keys[i].name, (char *)a3)) return 10001 + i;
        return error (ENOKEY);
    }
    if (cmd == KEYCTL_CLEAR) {
        if (a2 || a3) { bad++; return error (EINVAL); }
        if (!ring_ok ((long)a1) || fail ("clear")) return -1;
        for (int i = 0; i < next_key; i++) keys[i].linked = 0;
        return 0;
    }
    if (!joined) { bad++; return error (EPERM); }
    long index = (long)a1 - 10001;
    if (index < 0 || index >= next_key) return error (ENOKEY);
    struct fixture_key *k = &keys[index];
    if (cmd == KEYCTL_REVOKE) {
        if (a2 || a3) { bad++; return error (EINVAL); }
        if (fail ("revoke")) return -1;
        k->revoked = 1;
        return 0;
    }
    if (cmd == KEYCTL_READ) {
        if (fail (a2 ? "read" : "probe")) return -1;
        if (k->revoked) return error (EKEYREVOKED);
        if (!a2) {
            if (read_mode == 1 || read_mode == 3) return 1;
            if (read_mode == 4) return 0;
            return k->len + (read_mode == 2 ? 4 : 0);
        }
        if (read_mode == 3) return a3 + 1;
        if (read_mode == 5) { k->revoked = 1; return error (EKEYREVOKED); }
        if (a3 >= k->len) memcpy ((void *)a2, k->data, k->len);
        return k->len;
    }
    bad++;
    return error (EINVAL);
}

int keyctl_fixture_builtin (WORD_LIST *list)
{
    const char *a[4]; int n = 0;
    for (; list && n < 4; list = list->next) a[n++] = list->word->word;
    if (list || !n) return 2;
    if (!strcmp (a[0], "reset") && n == 1) {
        if (live_allocs) return 1;
        for (int i = 0; i < next_key; i++) free (keys[i].data);
        memset (keys, 0, sizeof keys);
        joined = calls = bad = next_key = read_mode = 0;
        session_named = 0; session_name[0] = 0;
        last_ring = 0; expected_ring = KEY_SPEC_SESSION_KEYRING;
        fail_op[0] = 0; fail_errno = 0;
        alloc_attempts = alloc_fail_at = input_error = 0;
    } else if (!strcmp (a[0], "fail") && n == 3) {
        snprintf (fail_op, sizeof fail_op, "%s", a[1]); fail_errno = atoi (a[2]);
    } else if (!strcmp (a[0], "mode") && n == 2) {
        read_mode = atoi (a[1]);
    } else if (!strcmp (a[0], "ring") && n == 2) {
        expected_ring = strtol (a[1], NULL, 10);
    } else if (!strcmp (a[0], "alloc-fail") && n == 2) {
        alloc_fail_at = alloc_attempts + atoi (a[1]);
    } else if (!strcmp (a[0], "input-error") && n == 2) {
        input_error = atoi (a[1]);
    } else if (!strcmp (a[0], "memory") && n == 1) {
        printf ("live=%d\n", live_allocs);
    } else if (!strcmp (a[0], "stats") && n == 1) {
        int linked = 0, revoked = 0;
        for (int i = 0; i < next_key; i++) {
            linked += keys[i].linked; revoked += keys[i].revoked;
        }
        printf ("calls=%d bad=%d joined=%d linked=%d revoked=%d ring=%ld\n",
                calls, bad, joined, linked, revoked, last_ring);
    } else if (!strcmp (a[0], "session-name") && n == 1) {
        printf ("%s\n", session_named ? session_name : "<anonymous>");
    } else if (!strcmp (a[0], "check") && n == 1) {
        return bad || live_allocs ? 1 : 0;
    } else return 2;
    return 0;
}
static char *fixture_doc[] = { "Closed keyring fixture control.", NULL };
struct builtin keyctl_fixture_struct = {
    "keyctl_fixture", keyctl_fixture_builtin, BUILTIN_ENABLED, fixture_doc,
    "keyctl_fixture reset|fail|mode|ring|stats|check", 0
};
