/* SPDX-License-Identifier: MIT */
/* Guest-only, source-included mechanics. Syscalls below are injected; this is
 * not evidence of real-device authentication or kernel erasure. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#define BASHOS_AUTH_MAX_SECRET 4096
#define UNUSED __attribute__((unused))
static volatile sig_atomic_t ba_sig_caught, ba_sig_signo;
static void ba_sig_handler(int signal) { ba_sig_caught = 1; ba_sig_signo = signal; }
static unsigned char arena[BASHOS_AUTH_MAX_SECRET];
static struct termios original_term, current_term;
static jmp_buf escaped;
static int mode, get_calls, hides, installs, restores, prompts, reads, closed, freed, raised, exit_code;
static size_t position;
static unsigned char *result;
static size_t result_size;
static int result_code, failures;
enum { NORMAL, BACKSPACE, OPEN_ERROR, GET_ERROR, MAP_ERROR, LOCK_ERROR, ADVISE_ERROR,
       SIGNAL1_ERROR, SIGNAL2_ERROR, SIGNAL3_ERROR, HIDE_ERROR, HIDE_IGNORED, VERIFY_ERROR,
       PROMPT_SHORT, INPUT_ERROR, INPUT_EOF, INPUT_LONG, CANCEL,
       RESTORE_ERROR, RESTORE_IGNORED, RESTORE_GET_ERROR, RESTORE_SIGNAL_ERROR };
static const char *names[] = {"normal", "backspace", "open-error", "get-error", "map-error", "lock-error", "advice-error",
 "signal1-error", "signal2-error", "signal3-error", "hide-error", "hide-ignored", "verify-error",
 "prompt-short", "input-error", "input-eof", "input-long", "cancel", "restore-error", "restore-ignored",
 "restore-get-error", "restore-signal-error"};
static void ba_free_secret_buf(unsigned char *buffer) { if (buffer) { memset(buffer, 0, sizeof arena); freed++; } }
static UNUSED int f_open(const char *name, int flags, ...) {
 (void)name; (void)flags; if (mode == OPEN_ERROR) { errno = ENOTTY; return -1; } return 42;
}
static UNUSED int f_isatty(int fd) { (void)fd; return 0; }
static UNUSED int f_close(int fd) { if (fd == 42) closed++; return 0; }
static UNUSED int f_get(int fd, struct termios *term) {
 (void)fd; get_calls++;
 if ((mode == GET_ERROR && get_calls == 1) || (mode == VERIFY_ERROR && get_calls == 2) ||
     (mode == RESTORE_GET_ERROR && get_calls == 3)) { errno = EIO; return -1; }
 *term = current_term; return 0;
}
static UNUSED int f_set(int fd, int action, const struct termios *term) {
 (void)fd;
 if (action == TCSAFLUSH && !(term->c_lflag & ICANON)) {
  hides++;
  if (mode == HIDE_ERROR) { errno = EACCES; return -1; }
  if (mode != HIDE_IGNORED) current_term = *term;
 } else {
  if (mode == RESTORE_ERROR) { errno = EIO; return -1; }
  if (mode != RESTORE_IGNORED) current_term = *term;
 }
 return 0;
}
static UNUSED void *f_map(void *address, size_t length, int prot, int flags, int fd, off_t offset) {
 (void)address; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
 if (mode == MAP_ERROR) { errno = ENOMEM; return MAP_FAILED; } return arena;
}
static UNUSED int f_lock(const void *address, size_t length) {
 (void)address; (void)length; if (mode == LOCK_ERROR) { errno = ENOMEM; return -1; } return 0;
}
static UNUSED int f_advise(void *address, size_t length, int advice) {
 (void)address; (void)length; (void)advice;
 if (mode == ADVISE_ERROR) { errno = EINVAL; return -1; } return 0;
}
static UNUSED int f_action(int signal, const struct sigaction *action, struct sigaction *old) {
 (void)signal; (void)action;
 if (old) {
  installs++;
  if (mode >= SIGNAL1_ERROR && mode <= SIGNAL3_ERROR && installs == mode - SIGNAL1_ERROR + 1) {
   errno = EINVAL; return -1;
  }
  memset(old, 0, sizeof *old); old->sa_handler = SIG_DFL;
 } else {
  restores++;
  if (mode == RESTORE_SIGNAL_ERROR) { errno = EINVAL; return -1; }
 }
 return 0;
}
static UNUSED int f_poll(struct pollfd *watch, nfds_t count, int timeout) {
 (void)count; (void)timeout;
 if (mode == CANCEL) { ba_sig_handler(SIGINT); errno = EINTR; return -1; }
 watch->revents = POLLIN; return 1;
}
static UNUSED ssize_t f_read(int fd, void *out, size_t length) {
 (void)fd; (void)length; reads++;
 if (mode == CANCEL) { ba_sig_handler(SIGINT); errno = EINTR; return -1; }
 if (mode == INPUT_ERROR) { errno = EIO; return -1; }
 if (mode == INPUT_EOF) return 0;
 if (mode == INPUT_LONG) { *(unsigned char *)out = 'x'; position++; return 1; }
 const char *input = mode == BACKSPACE ? "secrX\bet\n" : "secret\n";
 if (position >= strlen(input)) return 0;
 *(unsigned char *)out = (unsigned char)input[position++]; return 1;
}
static UNUSED ssize_t f_write(int fd, const void *data, size_t length) {
 (void)fd; (void)data;
 if (length > 1) {
  prompts++;
  if (mode == PROMPT_SHORT) return (ssize_t)length - 1;
 }
 return (ssize_t)length;
}
static UNUSED int f_raise(int signal) { raised = signal; return 0; }
static UNUSED __attribute__((noreturn)) void f_exit(int status) { exit_code = status; longjmp(escaped, 1); }
#define open(...) f_open(__VA_ARGS__)
#define close(...) f_close(__VA_ARGS__)
#define isatty(...) f_isatty(__VA_ARGS__)
#define tcgetattr(...) f_get(__VA_ARGS__)
#define tcsetattr(...) f_set(__VA_ARGS__)
#define mmap(...) f_map(__VA_ARGS__)
#define mlock(...) f_lock(__VA_ARGS__)
#define madvise(...) f_advise(__VA_ARGS__)
#define sigaction(...) f_action(__VA_ARGS__)
#define poll(...) f_poll(__VA_ARGS__)
#define read(...) f_read(__VA_ARGS__)
#define write(...) f_write(__VA_ARGS__)
#define raise(...) f_raise(__VA_ARGS__)
#define _exit(...) f_exit(__VA_ARGS__)
#include "reader.inc"
#undef open
#undef close
#undef isatty
#undef tcgetattr
#undef tcsetattr
#undef mmap
#undef mlock
#undef madvise
#undef sigaction
#undef poll
#undef read
#undef write
#undef raise
#undef _exit

static int matching_file(const char *name, const char *expected) {
 char buffer[256]; int fd = open(name, O_RDONLY | O_CLOEXEC);
 if (fd < 0) return 0;
 ssize_t n = read(fd, buffer, sizeof buffer - 1); close(fd);
 if (n <= 0) return 0;
 buffer[n] = 0; buffer[strcspn(buffer, "\r\n")] = 0;
 return !strcmp(buffer, expected);
}
static int guest_guard(const char *uuid) {
 char cwd[256], cmd[8192]; uid_t r,e,s; gid_t gr,ge,gs;
 if (strlen(uuid) != 36 || getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs) || r || e || s || gr || ge || gs ||
     !getcwd(cwd,sizeof cwd) || strcmp(cwd,"/tmp/parity-case") ||
     !getenv("HOME") || strcmp(getenv("HOME"),"/tmp/parity-home") ||
     !matching_file("/sys/class/dmi/id/sys_vendor","QEMU") ||
     !matching_file("/etc/bashos-parity-vm",uuid) || !matching_file("/run/bashos-parity-vm-identity",uuid)) return 0;
 int fd = open("/proc/1/cmdline",O_RDONLY|O_CLOEXEC); if (fd < 0) return 0;
 ssize_t n = read(fd,cmd,sizeof cmd);close(fd);
 return n > 0 && memmem(cmd,(size_t)n,uuid,strlen(uuid)) &&
  memmem(cmd,(size_t)n,"/opt/bashos-parity/harness/guest.py",strlen("/opt/bashos-parity/harness/guest.py"));
}
int main(int argc, char **argv) {
 if (argc != 2 || !guest_guard(argv[1])) return 125;
 failures = 0;
 for (mode = NORMAL; mode <= RESTORE_SIGNAL_ERROR; mode++) {
  get_calls=hides=installs=restores=prompts=reads=closed=freed=raised=exit_code=0;
  position=result_size=0;result=NULL;result_code=-999;
  memset(arena,0,sizeof arena); memset(&original_term,0,sizeof original_term);
  original_term.c_lflag=ECHO|ICANON; original_term.c_cc[VMIN]=1;
  current_term=original_term;ba_sig_caught=ba_sig_signo=0;
  if (setjmp(escaped)==0) result_code=ba_read_password("fixture password: ",&result,&result_size);
  int fatal_expected=mode>=RESTORE_ERROR;
  int ok;
  if (mode==NORMAL || mode==BACKSPACE) {
   ok=result_code==0 && result==arena && result_size==6 && !memcmp(result,"secret",6) &&
      current_term.c_lflag==original_term.c_lflag && installs==3 && restores==3 && closed==1 && !exit_code;
   ba_free_secret_buf(result);
  } else {
   ok=(fatal_expected ? exit_code==126 : result_code<0 && !exit_code) && result==NULL && result_size==0;
   if (mode!=OPEN_ERROR) ok=ok && closed==1;
   if (mode>=LOCK_ERROR) ok=ok && freed==1;
   if (mode>=GET_ERROR && mode<=VERIFY_ERROR) ok=ok && prompts==0 && reads==0;
   if (mode==CANCEL) ok=ok && raised==SIGINT;
   if (!fatal_expected) ok=ok && current_term.c_lflag==original_term.c_lflag;
  }
  if (!ok) failures++;
  printf("{\"id\":\"%s\",\"status\":\"%s\",\"rc\":%d,\"fatal_exit\":%d,\"reads\":%d,\"prompts\":%d,\"freed\":%d}\n",
         names[mode],ok?"PASS":"FAIL",result_code,exit_code,reads,prompts,freed);
 }
 printf("{\"controls\":%zu,\"failures\":%d,\"authentication_coverage\":false}\n",sizeof names/sizeof names[0],failures);
 return failures ? 1 : 0;
}
