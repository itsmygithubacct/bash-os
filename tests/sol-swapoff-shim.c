/* SPDX-License-Identifier: MIT
 * Private fixture boundary for the real loadable. This library never forwards
 * swapoff. A seccomp backstop also denies raw swapoff/swapon system calls.
 */
#define _GNU_SOURCE 1
#include <config.h>
#undef _FILE_OFFSET_BITS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "loadables.h"

static FILE *(*real_fopen)(const char *, const char *);
static int (*real_fclose)(FILE *);
static char *source, **expected;
static size_t expected_count, calls, bad, opens, closes;
static FILE *live;
static int open_error, read_error, close_error;
static struct { char *path; int error; } failures[16];
static size_t failure_count;

__attribute__((constructor)) static void guard (void)
{
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapoff, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapon, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };
    struct sock_fprog program = { sizeof insns / sizeof *insns, insns };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) _exit(96);
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fclose = dlsym(RTLD_NEXT, "fclose");
    if (!real_fopen || !real_fclose) _exit(97);
}

int swapoff (const char *path)
{
    if (live) bad++;  /* Enumeration must be closed before any mutation. */
    if (!expected_count || strcmp(path, expected[calls % expected_count])) bad++;
    calls++;
    for (size_t i = 0; i < failure_count; i++) if (!strcmp(path, failures[i].path)) {
        errno = failures[i].error; return -1;
    }
    return 0;
}

struct read_cookie { FILE *file; int delivered; };
static ssize_t cookie_read (void *data, char *buf, size_t size)
{
    struct read_cookie *cookie = data;
    if (cookie->delivered) { errno = EIO; return -1; }
    cookie->delivered = 1;
    return fread(buf, 1, size, cookie->file);
}
static int cookie_close (void *data)
{
    struct read_cookie *cookie = data;
    int rc = real_fclose(cookie->file);
    free(cookie);
    return rc;
}

FILE *fopen (const char *path, const char *mode)
{
    if (strcmp(path, "/proc/swaps")) return real_fopen(path, mode);
    opens++;
    if (!source || live || strcmp(mode, "r")) _exit(98);
    if (open_error) { errno = open_error; return NULL; }
    FILE *file = real_fopen(source, mode);
    if (!file) return NULL;
    if (read_error) {
        struct read_cookie *cookie = calloc(1, sizeof *cookie);
        if (!cookie) _exit(99);
        cookie->file = file;
        cookie_io_functions_t io = { .read = cookie_read, .close = cookie_close };
        file = fopencookie(cookie, "r", io);
        if (!file) _exit(99);
    }
    live = file;
    return file;
}

/* Cover builds whose large-file configuration redirects fopen to fopen64. */
FILE *fopen64 (const char *path, const char *mode)
{
    return fopen(path, mode);
}

int fclose (FILE *file)
{
    int fixture = file == live;
    if (fixture) { live = NULL; closes++; }
    int rc = real_fclose(file);
    if (fixture && close_error) { errno = close_error; return EOF; }
    return rc;
}

static void clear_expected (void)
{
    for (size_t i = 0; i < expected_count; i++) free(expected[i]);
    free(expected); expected = NULL; expected_count = 0;
}

int swapoff_fixture_builtin (WORD_LIST *list)
{
    if (!list) return 2;
    const char *cmd = list->word->word;
    list = list->next;
    if (!strcmp(cmd, "reset") && !list) {
        if (live) return 95;
        clear_expected(); free(source); source = NULL;
        for (size_t i = 0; i < failure_count; i++) free(failures[i].path);
        failure_count = 0;
        calls = bad = opens = closes = 0;
        open_error = read_error = close_error = 0;
    } else if (!strcmp(cmd, "guard") && !list) {
        errno = 0;
        if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER ||
            syscall(__NR_swapoff, NULL) != -1 || errno != EPERM) return 96;
    } else if (!strcmp(cmd, "source") && list && !list->next) {
        free(source); source = strdup(list->word->word);
        if (!source) return 99;
    } else if (!strcmp(cmd, "expect")) {
        clear_expected();
        for (WORD_LIST *p = list; p; p = p->next) expected_count++;
        expected = calloc(expected_count ? expected_count : 1, sizeof *expected);
        if (!expected) return 99;
        size_t i = 0;
        for (; list; list = list->next) {
            expected[i] = strdup(list->word->word);
            if (!expected[i++]) return 99;
        }
    } else if (!strcmp(cmd, "fail") && list && list->next && !list->next->next && failure_count < 16) {
        failures[failure_count].path = strdup(list->word->word);
        if (!failures[failure_count].path) return 99;
        failures[failure_count++].error = atoi(list->next->word->word);
    } else if (!strcmp(cmd, "fault") && list && list->next && !list->next->next) {
        int value = atoi(list->next->word->word);
        if (!strcmp(list->word->word, "open")) open_error = value;
        else if (!strcmp(list->word->word, "read")) read_error = value;
        else if (!strcmp(list->word->word, "close")) close_error = value;
        else return 2;
    } else if (!strcmp(cmd, "check") && list && list->next && list->next->next && !list->next->next->next) {
        size_t want_calls = strtoull(list->word->word, NULL, 10);
        size_t want_opens = strtoull(list->next->word->word, NULL, 10);
        size_t want_closes = strtoull(list->next->next->word->word, NULL, 10);
        if (calls != want_calls || opens != want_opens || closes != want_closes || live || bad) {
            builtin_error("fixture: calls=%zu bad=%zu opens=%zu closes=%zu live=%d",
                          calls, bad, opens, closes, live != NULL);
            return 94;
        }
        calls = opens = closes = 0;
    } else return 2;
    return 0;
}
static char *fixture_doc[] = { "Private swapoff interception and expected request oracle.", NULL };
struct builtin swapoff_fixture_struct = {
    "swapoff_fixture", swapoff_fixture_builtin, BUILTIN_ENABLED, fixture_doc,
    "swapoff_fixture reset|source|expect|fail|fault|check", 0
};
