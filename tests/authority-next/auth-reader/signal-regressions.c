/* SPDX-License-Identifier: MIT */
/* Guest-only source mechanics: exact reader + caller bodies, syscall/barrier
 * injection and modeled Bash unwinding. No authentication or erasure credit. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include "bashos_auth.h"
#define BASHOS_AUTH_MAX_SECRET 4096
#define UNUSED __attribute__((unused))
#define EX_USAGE 2
#define EXECUTION_SUCCESS 0
#define EXECUTION_FAILURE 1
typedef struct { char *word; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
static unsigned char arena[BASHOS_AUTH_MAX_SECRET], stored[BASHOS_AUTH_MAX_SECRET];
static struct termios original_term, current_term;
static sigset_t active_mask, pending_set, entry_mask;
static struct sigaction actions[NSIG];
static jmp_buf escaped;
static void (*unwind_fn)(void *);
static void *unwind_arg;
static int mode, get_calls, hides, installs, restores, prompts, reads, closed, freed, exit_code;
static int block_calls, setmask_calls, pending_calls, unsafe_delivery, handler_calls[NSIG];
static int live, sealed, bound, flushes, jumped, result_code, failures, injected, writes;
static size_t position;
enum { NORMAL, BACKSPACE, OPEN_ERROR, GET_ERROR, MAP_ERROR, LOCK_ERROR, ADVISE_ERROR,
 SIGNAL1_ERROR, SIGNAL2_ERROR, SIGNAL3_ERROR, HIDE_ERROR, HIDE_IGNORED, VERIFY_ERROR,
 PROMPT_SHORT, INPUT_ERROR, INPUT_EOF, INPUT_LONG, CANCEL,
 RESTORE_ERROR, RESTORE_IGNORED, RESTORE_GET_ERROR, RESTORE_SIGNAL_ERROR,
 MASK_ENTRY_ERROR, MASK_INPUT_ERROR, MASK_HANDOFF_ERROR, MASK_CLEANUP_ERROR, MASK_RESTORE_ERROR,
 PENDING_ERROR, NEW_ERROR, WRITE_ERROR, SEAL_ERROR, BIND_ERROR, BIND_UNWIND,
 RESTORE1_SIGNAL, RESTORE2_SIGNAL, RESTORE3_SIGNAL, CLOSE_SIGNAL, RESTORE_TERM_SIGNAL,
 WRITE_SIGNAL, BLOCKED_ENTRY_SIGNAL, INPUT_MULTI_CANCEL, NONCANCEL_PENDING, RAISE_ERROR, MODE_COUNT };
static const char *names[] = {"normal","backspace","open-error","get-error","map-error","lock-error","advice-error",
 "signal1-error","signal2-error","signal3-error","hide-error","hide-ignored","verify-error",
 "prompt-short","input-error","input-eof","input-long","cancel","restore-error","restore-ignored",
 "restore-get-error","restore-signal-error","mask-entry-error","mask-input-error","mask-handoff-error",
 "mask-cleanup-error","mask-restore-error","pending-error","new-error","write-error","seal-error",
 "bind-error","bind-unwind","restore1-signal","restore2-signal","restore3-signal","close-signal",
 "restore-terminal-signal","write-signal","blocked-entry-signal","input-multiple-cancel",
 "noncancel-pending","raise-error"};
_Static_assert(sizeof names / sizeof names[0] == MODE_COUNT, "case inventory");
static int has_plaintext(void) { for (size_t i=0;i<sizeof arena;i++) if (arena[i]) return 1; return 0; }
static UNUSED void ba_free_secret_buf(unsigned char *p) { if (p) { memset(p,0,sizeof arena);freed++; } }
static void f_run(void) { void (*fn)(void *)=unwind_fn;void *arg=unwind_arg;unwind_fn=NULL;unwind_arg=NULL;if(fn)fn(arg); }
static void original_handler(int n) {
 handler_calls[n]++;
 if (has_plaintext() || current_term.c_lflag!=original_term.c_lflag ||
     !closed || restores!=installs || (live && !bound)) unsafe_delivery=1;
 if (mode>=RESTORE1_SIGNAL && mode<=RESTORE3_SIGNAL) { f_run();jumped=2;longjmp(escaped,1); }
}
static void deliver(void) {
 for(int n=1;n<NSIG;n++) if(sigismember(&pending_set,n)==1 && sigismember(&active_mask,n)==0) {
  sigdelset(&pending_set,n);
  if(actions[n].sa_handler!=SIG_DFL && actions[n].sa_handler!=SIG_IGN) actions[n].sa_handler(n);
 }
}
static void inject(int n) { sigaddset(&pending_set,n);deliver(); }
static UNUSED int f_mask(int how,const sigset_t *set,sigset_t *old) {
 if(how==SIG_BLOCK) {
  block_calls++;
  if ((mode==MASK_ENTRY_ERROR && block_calls==1) || (mode==MASK_HANDOFF_ERROR && block_calls==2) ||
      (mode==MASK_CLEANUP_ERROR && block_calls==3)) {errno=EINVAL;return -1;}
 } else if(how==SIG_SETMASK) {
  setmask_calls++;
  if((mode==MASK_INPUT_ERROR && setmask_calls==1) || (mode==MASK_RESTORE_ERROR && setmask_calls==2)) {
   errno=EINVAL;return -1;
  }
 }
 if(old)*old=active_mask;
 if(set) {
  if(how==SIG_SETMASK)active_mask=*set;
  else for(int n=1;n<NSIG;n++) if(sigismember(set,n)==1) {
   if(how==SIG_BLOCK)sigaddset(&active_mask,n);else sigdelset(&active_mask,n);
  }
 }
 deliver();return 0;
}
static UNUSED int f_pending(sigset_t *out) {
 pending_calls++;if(mode==PENDING_ERROR){errno=EIO;return -1;}*out=pending_set;return 0;
}
static UNUSED int f_open(const char *name,int flags,...) {
 (void)name;(void)flags;if(mode==OPEN_ERROR){errno=ENOTTY;return -1;}return 42;
}
static UNUSED int f_isatty(int fd){(void)fd;return 0;}
static UNUSED int f_close(int fd){if(fd==42)closed++;if(mode==CLOSE_SIGNAL&&!injected++){inject(SIGTERM);}return 0;}
static UNUSED int f_get(int fd,struct termios *term) {
 (void)fd;get_calls++;
 if((mode==GET_ERROR&&get_calls==1)||(mode==VERIFY_ERROR&&get_calls==2)||
    (mode==RESTORE_GET_ERROR&&get_calls==3)){errno=EIO;return -1;}
 *term=current_term;return 0;
}
static UNUSED int f_set(int fd,int action,const struct termios *term) {
 (void)fd;
 if(action==TCSAFLUSH && !(term->c_lflag&ICANON)) {
  hides++;if(mode==HIDE_ERROR){errno=EACCES;return -1;}
  if(mode!=HIDE_IGNORED)current_term=*term;
 } else {
  if(action==TCSAFLUSH)flushes++;
  if(mode==RESTORE_ERROR){errno=EIO;return -1;}
  if(mode!=RESTORE_IGNORED)current_term=*term;
  if(mode==RESTORE_TERM_SIGNAL && !injected++){inject(SIGTERM);}
 }
 return 0;
}
static UNUSED void *f_map(void *address,size_t length,int prot,int flags,int fd,off_t offset) {
 (void)address;(void)length;(void)prot;(void)flags;(void)fd;(void)offset;
 if(mode==MAP_ERROR){errno=ENOMEM;return MAP_FAILED;}return arena;
}
static UNUSED int f_lock(const void *address,size_t length) {
 (void)address;(void)length;if(mode==LOCK_ERROR){errno=ENOMEM;return -1;}return 0;
}
static UNUSED int f_advise(void *address,size_t length,int advice) {
 (void)address;(void)length;(void)advice;if(mode==ADVISE_ERROR){errno=EINVAL;return -1;}return 0;
}
static UNUSED int f_action(int n,const struct sigaction *action,struct sigaction *old) {
 if(old) {
  installs++;
  if(mode>=SIGNAL1_ERROR && mode<=SIGNAL3_ERROR && installs==mode-SIGNAL1_ERROR+1) {
   installs--;errno=EINVAL;return -1;
  }
  *old=actions[n];
 } else {
  restores++;
  if(mode==RESTORE_SIGNAL_ERROR){errno=EINVAL;return -1;}
 }
 actions[n]=*action;
 if(!old && mode>=RESTORE1_SIGNAL && mode<=RESTORE3_SIGNAL && restores==mode-RESTORE1_SIGNAL+1)
  inject(n);
 return 0;
}
static UNUSED int f_poll(struct pollfd *watch,nfds_t count,int timeout) {
 (void)count;(void)timeout;
 if(mode==CANCEL || mode==INPUT_MULTI_CANCEL || mode==RAISE_ERROR) {
  inject(SIGINT);if(mode==INPUT_MULTI_CANCEL){inject(SIGTERM);inject(SIGHUP);}errno=EINTR;return -1;
 }
 watch->revents=POLLIN;return 1;
}
static UNUSED ssize_t f_read(int fd,void *out,size_t length) {
 (void)fd;(void)length;reads++;
 if(mode==INPUT_ERROR){errno=EIO;return -1;}
 if(mode==INPUT_EOF)return 0;
 if(mode==INPUT_LONG){*(unsigned char *)out='x';position++;return 1;}
 const char *input=mode==BACKSPACE?"secrX\bet\n":"secret\n";
 if(position>=strlen(input))return 0;
 *(unsigned char *)out=(unsigned char)input[position++];
 if(mode==NONCANCEL_PENDING && !injected++)inject(SIGUSR1);
 return 1;
}
static UNUSED ssize_t f_write(int fd,const void *data,size_t length) {
 (void)fd;(void)data;if(length>1){prompts++;if(mode==PROMPT_SHORT)return (ssize_t)length-1;}return (ssize_t)length;
}
static UNUSED int f_raise(int n){if(mode==RAISE_ERROR){errno=EIO;return -1;}inject(n);return 0;}
static UNUSED __attribute__((noreturn)) void f_exit(int status){exit_code=status;longjmp(escaped,1);}
static UNUSED int f_ioctl(int fd,unsigned long request,void *arg) {
 (void)fd;
 if(request==BASHOS_AUTH_IOC_NEW_SECRET) {
  if(mode==NEW_ERROR){errno=EIO;return -1;}((struct bashos_auth_handle *)arg)->id=7;live=1;return 0;
 }
 if(request==BASHOS_AUTH_IOC_WRITE_SECRET) {
  if(mode==WRITE_ERROR){errno=EIO;return -1;}
  if(mode==WRITE_SIGNAL&&!injected++)inject(SIGTERM);
  struct bashos_auth_secret_write *w=arg;
  if(w->len!=6 || memcmp((void *)(uintptr_t)w->user_ptr,"secret",6)){errno=EINVAL;return -1;}
  memcpy(stored,(void *)(uintptr_t)w->user_ptr,w->len);writes++;return 0;
 }
 if(request==BASHOS_AUTH_IOC_SEAL_SECRET){if(mode==SEAL_ERROR){errno=EIO;return -1;}sealed=1;return 0;}
 if(request==BASHOS_AUTH_IOC_CLEAR_SECRET){memset(stored,0,sizeof stored);live=sealed=0;return 0;}
 errno=EINVAL;return -1;
}
static UNUSED int ba_parse_fd(const char *s,int *fd){(void)s;*fd=12;return 0;}
static UNUSED void builtin_error(const char *format,...){(void)format;}
static UNUSED void *builtin_bind_variable(char *name,char *value,int flags) {
 (void)name;(void)value;(void)flags;
 if(mode==BIND_ERROR)return NULL;
 if(mode==BIND_UNWIND){f_run();jumped=3;longjmp(escaped,1);}
 if(has_plaintext())unsafe_delivery=1;
 bound=1;return &bound;
}
#define open(...) f_open(__VA_ARGS__)
#define close(...) f_close(__VA_ARGS__)
#define isatty(...) f_isatty(__VA_ARGS__)
#define tcgetattr(...) f_get(__VA_ARGS__)
#define tcsetattr(...) f_set(__VA_ARGS__)
#define mmap(...) f_map(__VA_ARGS__)
#define mlock(...) f_lock(__VA_ARGS__)
#define madvise(...) f_advise(__VA_ARGS__)
#define sigaction(...) f_action(__VA_ARGS__)
#define sigprocmask(...) f_mask(__VA_ARGS__)
#define sigpending(...) f_pending(__VA_ARGS__)
#define poll(...) f_poll(__VA_ARGS__)
#define read(...) f_read(__VA_ARGS__)
#define write(...) f_write(__VA_ARGS__)
#define raise(...) f_raise(__VA_ARGS__)
#define _exit(...) f_exit(__VA_ARGS__)
#define ioctl(...) f_ioctl(__VA_ARGS__)
#define begin_unwind_frame(name) ((void)(name))
#define add_unwind_protect(fn,arg) do {unwind_fn=(fn);unwind_arg=(arg);} while(0)
#define run_unwind_frame(name) do {(void)(name);f_run();} while(0)
#include "reader-command.inc"
#undef open
#undef close
#undef isatty
#undef tcgetattr
#undef tcsetattr
#undef mmap
#undef mlock
#undef madvise
#undef sigaction
#undef sigprocmask
#undef sigpending
#undef poll
#undef read
#undef write
#undef raise
#undef _exit
#undef ioctl
#undef begin_unwind_frame
#undef add_unwind_protect
#undef run_unwind_frame

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

static int masks_equal(const sigset_t *a,const sigset_t *b) {
 for(int n=1;n<NSIG;n++) {
  if(sigismember(a,n)!=sigismember(b,n))return 0;
 }
 return 1;
}
int main(int argc,char **argv) {
 if(argc!=2 || !guest_guard(argv[1]))return 125;
 WORD_DESC words[]={{"12"},{"-p"},{"fixture password: "},{"H"}};
 WORD_LIST list[4];for(int i=0;i<4;i++){list[i].word=&words[i];list[i].next=i==3?NULL:&list[i+1];}
 for(mode=NORMAL;mode<MODE_COUNT;mode++) {
  get_calls=hides=installs=restores=prompts=reads=closed=freed=exit_code=0;
  block_calls=setmask_calls=pending_calls=unsafe_delivery=live=sealed=bound=flushes=jumped=injected=writes=0;
  result_code=-999;position=0;unwind_fn=NULL;unwind_arg=NULL;
  memset(arena,0,sizeof arena);memset(stored,0,sizeof stored);memset(handler_calls,0,sizeof handler_calls);
  memset(&original_term,0,sizeof original_term);original_term.c_lflag=ECHO|ICANON;original_term.c_cc[VMIN]=1;
  current_term=original_term;sigemptyset(&entry_mask);sigemptyset(&pending_set);
  if(mode==BLOCKED_ENTRY_SIGNAL){sigaddset(&entry_mask,SIGTERM);sigaddset(&pending_set,SIGTERM);}
  active_mask=entry_mask;
  for(int n=1;n<NSIG;n++){memset(&actions[n],0,sizeof actions[n]);actions[n].sa_handler=original_handler;sigemptyset(&actions[n].sa_mask);}
  ba_sig_caught=0;
  if(setjmp(escaped)==0)result_code=ba_read_secret_cmd(list);
  int fatal_expected=(mode>=RESTORE_ERROR&&mode<=RESTORE_SIGNAL_ERROR)||mode==MASK_HANDOFF_ERROR||
   mode==MASK_CLEANUP_ERROR||mode==MASK_RESTORE_ERROR||mode==RAISE_ERROR;
  int committed=mode==NORMAL||mode==BACKSPACE||mode==BLOCKED_ENTRY_SIGNAL||
   (mode>=RESTORE1_SIGNAL&&mode<=RESTORE3_SIGNAL)||mode==CLOSE_SIGNAL;
  int ok=!has_plaintext()&&!unsafe_delivery;
  if(fatal_expected)ok=ok&&exit_code==126;
  else if(committed)ok=ok&&bound&&live&&sealed&&writes==1&&!exit_code&&
   ((mode>=RESTORE1_SIGNAL&&mode<=RESTORE3_SIGNAL)?jumped==2:result_code==0);
  else ok=ok&&!bound&&!live&&!exit_code&&(mode==BIND_UNWIND?jumped==3:result_code==1);
  if(!fatal_expected) {
   ok=ok&&masks_equal(&active_mask,&entry_mask)&&current_term.c_lflag==original_term.c_lflag&&restores==installs;
   if(mode!=OPEN_ERROR&&mode!=MASK_ENTRY_ERROR)ok=ok&&closed==1;
  }
  if(mode==CANCEL)ok=ok&&handler_calls[SIGINT]==1&&flushes>=1;
  if(mode==INPUT_MULTI_CANCEL)ok=ok&&handler_calls[SIGINT]==1&&handler_calls[SIGTERM]==1&&handler_calls[SIGHUP]==1;
  if(mode==BLOCKED_ENTRY_SIGNAL)ok=ok&&handler_calls[SIGTERM]==0&&sigismember(&pending_set,SIGTERM)==1;
  if(mode==RESTORE_TERM_SIGNAL||mode==WRITE_SIGNAL)ok=ok&&handler_calls[SIGTERM]==1&&flushes>=1;
  if(mode==NONCANCEL_PENDING)ok=ok&&handler_calls[SIGUSR1]==1;
  if(mode>=GET_ERROR&&mode<=VERIFY_ERROR)ok=ok&&prompts==0&&reads==0;
  if(!ok)failures++;
  printf("{\"id\":\"%s\",\"status\":\"%s\",\"rc\":%d,\"fatal_exit\":%d,\"unsafe_delivery\":%d,\"bound\":%d,\"live\":%d,\"freed\":%d,\"flushes\":%d,\"installs\":%d,\"restores\":%d,\"jumped\":%d}\n",
   names[mode],ok?"PASS":"FAIL",result_code,exit_code,unsafe_delivery,bound,live,freed,flushes,installs,restores,jumped);
 }
 printf("{\"controls\":%d,\"failures\":%d,\"authentication_coverage\":false}\n",MODE_COUNT,failures);
 return failures?1:0;
}
