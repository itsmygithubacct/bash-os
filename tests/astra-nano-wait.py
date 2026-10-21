#!/usr/bin/env python3
"""Extract production input/prompt functions into a bounded interface fixture.

Usage: astra-nano-wait.py SOURCE.c OUTPUT.c
Compile OUTPUT.c as C11 (optionally with ASan/UBSan), then run it.
Only render and input interfaces are mocked. The signal mask and ppoll
handoff are real, using signals delivered solely to the fixture itself.
No terminal, external process or user input is required.
"""
import hashlib
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text()
def function(name, optional=False):
    match = re.search(r'static (?:int|void)\n' + name + r' \([^;]*?\)\n\{.*?\n\}', source, re.S)
    if not match and optional:
        return ''
    assert match, name
    return match[0]

header = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t bn_term_signal;
static int bn_unread = -1;
static const char *const *bn_keyq;
static size_t bn_keyq_n, bn_keyq_pos;
static char bn_status[256];
static int bn_status_until;
#define BN_BYTE_EOF (-1)
#define BN_BYTE_TIMEOUT (-2)
#define BN_BYTE_INTR (-3)
#define BN_ESC_WAIT_MS 100
static int render_signal, race_signal, reads, waits, failures;
static void verify(int ok, const char *label) {
    if (!ok) { fprintf(stderr, "FAIL %s\n", label); failures++; }
}
static void bn_render(void) { bn_term_signal = render_signal; }
static long bn_grapheme_prev(const char *s, size_t n, long p) {
    (void)s; (void)n; return p ? p - 1 : 0;
}
static ssize_t input_read(int fd, void *buf, size_t n) {
    (void)fd; (void)buf; (void)n; reads++; return 0;
}
static int input_poll(struct pollfd *p, nfds_t n, int ms) {
    (void)p; (void)n; (void)ms; waits++; return 0;
}
static int input_ppoll(struct pollfd *p, nfds_t n,
                       const struct timespec *t, const sigset_t *mask) {
    (void)p; (void)n; (void)t; waits++;
    sigset_t current;
    assert(sigprocmask(SIG_SETMASK, NULL, &current) == 0);
    verify(sigismember(&current, SIGHUP) == 1 &&
           sigismember(&current, SIGTERM) == 1, "termination blocked before wait");
    verify(mask && sigismember(mask, SIGHUP) == 0 &&
           sigismember(mask, SIGTERM) == 0, "wait atomically restores caller mask");
    verify(mask && sigismember(mask, SIGCHLD) == 1,
           "helper's blocked SIGCHLD preserved");
    assert(race_signal);
    /* Signal arrives after the flag check, before the atomic wait. */
    assert(raise(race_signal) == 0);
    const struct timespec bounded = {0, 20000000};
    return ppoll(NULL, 0, &bounded, mask);
}
#define read input_read
#define poll input_poll
#define ppoll input_ppoll
'''
names = ['bn_on_term', 'bn_poll', 'bn_next_byte', 'bn_frame_key',
         'bn_read_key', 'bn_modal_prompt', 'bn_prompt_key']
body = '\n\n'.join(function(n, n in ('bn_poll', 'bn_frame_key')) for n in names)
main = r'''
int main(void) {
    sigset_t initial, chld, after;
    sigemptyset(&chld); sigaddset(&chld, SIGCHLD);
    assert(sigprocmask(SIG_BLOCK, &chld, &initial) == 0);
    struct sigaction sa = {0}; sa.sa_handler = bn_on_term;
    sigemptyset(&sa.sa_mask);
    assert(sigaction(SIGHUP, &sa, NULL) == 0);
    assert(sigaction(SIGTERM, &sa, NULL) == 0);
    for (int i = 0; i < 2; i++) {
        int sig = i ? SIGTERM : SIGHUP;
        char text[16] = "", key[16];
        render_signal = sig; reads = waits = 0; bn_term_signal = 0;
        verify(bn_modal_prompt("Prompt: ", text, sizeof text) == -1,
               "modal prompt cancels signal delivered during render");
        verify(reads == 0 && waits == 0, "modal prompt does not wait after render cancellation");
        bn_term_signal = 0;
        verify(bn_prompt_key("Answer: ") == 0, "single-key prompt cancels");
        verify(reads == 0 && waits == 0, "single-key prompt does not wait after cancellation");
        bn_term_signal = sig; bn_unread = 'x';
        verify(bn_next_byte(-1) == BN_BYTE_INTR && bn_unread == 'x',
               "pushback preserved when termination is pending");
        bn_unread = -1;
        const char *keys[] = {"y"}; bn_keyq = keys; bn_keyq_n = 1; bn_keyq_pos = 0;
        verify(bn_read_key(key, sizeof key) == 0 && bn_keyq_pos == 0,
               "queued key preserved when termination is pending");
        bn_keyq = NULL;
        bn_term_signal = 0; race_signal = sig; reads = waits = 0;
        verify(bn_next_byte(-1) == BN_BYTE_INTR, "signal at wait boundary interrupts first byte");
        verify(waits == 1 && reads == 0, "atomic wait avoids entering read");
        bn_term_signal = 0; reads = waits = 0;
        verify(bn_next_byte(100) == BN_BYTE_INTR, "signal at wait boundary interrupts continuation");
        verify(waits == 1 && reads == 0, "continuation wait avoids read");
        assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
        verify(sigismember(&after, SIGHUP) == 0 && sigismember(&after, SIGTERM) == 0 &&
               sigismember(&after, SIGCHLD) == 1, "caller mask restored on cancellation");
    }
    assert(sigprocmask(SIG_SETMASK, &initial, NULL) == 0);
    if (!failures) puts("PASS render cancellation, queued input and atomic wait for HUP/TERM");
    return failures != 0;
}
'''
Path(sys.argv[2]).write_text(header + body + main)
print('Extracted production functions; source sha256:', hashlib.sha256(source.encode()).hexdigest())
