/* SPDX-License-Identifier: MIT */
/* Include production su and its real account, password, environment and
 * credential helpers. Only syscall/device/account file boundaries are replaced. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "_monocypher_monocypher-ed25519.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
static pid_t owner;
static int root_route, owned, pty_mode, fail, login_expected, keep_expected, real_exec;
static int stage, ttyfd=-1, authfd=-1, tty_changed, quiet, range_fallback;
static int *events;
enum { MINT, CONSUME, GROUPS, GID, UID, EXEC, WIPE, PROMPT, TOKEN_WIPE, PHC_WIPE, EVENT_COUNT };
static uid_t target_uid=4242, seen_uid;
static gid_t target_gid=4343, seen_gid;
static const char *password="fixture-password", *shell="/bin/sh", *command="exit 37";
static const char *shadow_phc;
static size_t password_pos;
static char workdir[PATH_MAX], initial_dir[PATH_MAX];
static struct termios tty_original;
/* Independent libargon2 oracle is checked by sol-su-check.py. */
static const char phc[] = "$argon2id$v=19$m=1024,t=1,p=1$666978747572652d73616c74$a1be8013f0f002242ca9f6f0886c2f80e0a98caf8435fb970b21b5e7d2d7209d";
static FILE *fixture_fopen(const char *path,const char *mode) {
  char text[2048];
  if (!strcmp(path,"/fixture/passwd"))
    snprintf(text,sizeof text,"fixture:x:%u:%u:Fixture:%s:%s\n",target_uid,target_gid,workdir,shell);
  else if (!strcmp(path,"/fixture/shadow"))
    snprintf(text,sizeof text,"fixture:%s:20000:0:99999:7:::\n",shadow_phc);
  else if (!strcmp(path,"/etc/group"))
    snprintf(text,sizeof text,"extra:x:%u:fixture\nprimary:x:%u:fixture\n",owned?target_gid:4444,target_gid);
  else return fopen(path,mode);
  if(fail==20){errno=EACCES;return NULL;}
  FILE *f=tmpfile();CHECK(f);CHECK(fputs(text,f)>=0);rewind(f);return f;
}
static uid_t fixture_getuid(void) { return root_route ? 0 : 1000; }
static uid_t fixture_geteuid(void) { return fail==9?1000:0; }
static int fixture_setgroups(size_t n,const gid_t *g) {
  CHECK(getpid()!=owner);CHECK(stage++==0);CHECK(events[CONSUME]);events[GROUPS]++;
  CHECK(n==2 && g[0]==(owned?target_gid:4444) && g[1]==target_gid);
  if(fail==3){errno=EPERM;return -1;}return 0;
}
static int fixture_setresgid(gid_t r,gid_t e,gid_t s) {
  CHECK(stage++==1);events[GID]++;CHECK(r==target_gid && r==e && e==s);
  if(fail==4){errno=EPERM;return -1;}seen_gid=r;return owned?setresgid(r,e,s):0;
}
static int fixture_setresuid(uid_t r,uid_t e,uid_t s) {
  CHECK(stage++==2);events[UID]++;CHECK(r==target_uid && r==e && e==s);
  if(fail==5){errno=EPERM;return -1;}seen_uid=r;return owned?setresuid(r,e,s):0;
}
static int fixture_getresuid(uid_t *r,uid_t *e,uid_t *s) { *r=*e=*s=seen_uid+(fail==6);return 0; }
static int fixture_getresgid(gid_t *r,gid_t *e,gid_t *s) { *r=*e=*s=seen_gid;return 0; }
#define fopen fixture_fopen
#define geteuid fixture_geteuid
#define setgroups fixture_setgroups
#define setresgid fixture_setresgid
#define setresuid fixture_setresuid
#define getresuid fixture_getresuid
#define getresgid fixture_getresgid
#include "common/bashcred_privdrop.h"
#undef geteuid
#undef setgroups
#undef setresgid
#undef setresuid
#undef getresuid
#undef getresgid
#include "../loadables/_bashauth/passwd_lookup.c"
#undef fopen

static int fixture_open(const char *path,int flags,...) {
  if (!strcmp(path,"/dev/bashos-auth")) {
    CHECK(flags==(O_RDWR|O_CLOEXEC));
    if(fail==1){errno=ENOENT;return -1;}
    authfd=open("/dev/null",flags);return authfd;
  }
  if (!strcmp(path,"/dev/tty") && !pty_mode) {
    if(fail==10){errno=ENXIO;return -1;}
    ttyfd=open("/dev/null",flags);return ttyfd;
  }
  return open(path,flags,0600);
}
static int fixture_tcgetattr(int fd,struct termios *t) {
  if(pty_mode)return tcgetattr(fd,t);
  CHECK(fd==ttyfd);memset(t,0,sizeof *t);t->c_lflag=ECHO|ICANON;tty_original=*t;return 0;
}
static int fixture_tcsetattr(int fd,int action,const struct termios *t) {
  if(pty_mode)return tcsetattr(fd,action,t);
  CHECK(fd==ttyfd);
  if(action==TCSAFLUSH) { CHECK(!(t->c_lflag&(ECHO|ICANON)));tty_changed=1; }
  else { CHECK(!memcmp(t,&tty_original,sizeof *t));tty_changed=0; }
  return 0;
}
static ssize_t fixture_read(int fd,void *buf,size_t len) {
  if(pty_mode || fd!=ttyfd)return read(fd,buf,len);
  CHECK(tty_changed && len==1);
  if(fail==11){errno=EIO;return -1;}
  if(password_pos==strlen(password)){*(char *)buf='\n';password_pos++;return 1;}
  CHECK(password_pos<strlen(password));*(char *)buf=password[password_pos++];return 1;
}
static ssize_t fixture_write(int fd,const void *buf,size_t len) {
  if(pty_mode || fd!=ttyfd)return write(fd,buf,len);
  if(len>1){CHECK(len==10 && !memcmp(buf,"Password: ",10));events[PROMPT]++;}return len;
}
static int fixture_close(int fd) {
  if(fd==ttyfd){CHECK(!tty_changed);ttyfd=-1;}
  if(fd==authfd)authfd=-1;
  return close(fd);
}
static int fixture_munmap(void *p,size_t n) {
  CHECK(n==4096);for(size_t i=0;i<n;i++)CHECK(((unsigned char *)p)[i]==0);
  events[WIPE]++;return munmap(p,n);
}
#define open fixture_open
#define close fixture_close
#define read fixture_read
#define write fixture_write
#define tcgetattr fixture_tcgetattr
#define tcsetattr fixture_tcsetattr
#define munmap fixture_munmap
#include "../loadables/_bashauth/secure_read.c"
#undef read
#undef write
#undef tcgetattr
#undef tcsetattr
#undef munmap
#undef close
#undef open
#include "../loadables/_bashauth/pwverify.c"
#include "../loadables/_bashauth/cred_exec.c"
static int fixture_ioctl(int fd,unsigned long op,...);
static int fixture_execve(const char *p,char *const *argv,char *const *env);
static void fixture_crypto_wipe(void *p,size_t n);
static long fixture_syscall(long n,...) {
  CHECK(n==SYS_close_range);
  if(range_fallback){errno=ENOSYS;return -1;}
  return syscall(n,3U,~0U,0U);
}
static pid_t fixture_fork(void) { if(fail==12){errno=EAGAIN;return -1;}return fork(); }
static pid_t fixture_waitpid(pid_t p,int *status,int flags) {
  if(fail==13){fail=0;errno=EINTR;return -1;}return waitpid(p,status,flags);
}
static struct dirent *fixture_readdir(DIR *d) {
  if(fail==14 && getpid()!=owner){errno=EIO;return NULL;}
  return readdir(d);
}
#define getuid fixture_getuid
#define fopen fixture_fopen
#define open fixture_open
#define close fixture_close
#define ioctl fixture_ioctl
#define execve fixture_execve
#define syscall fixture_syscall
#define fork fixture_fork
#define waitpid fixture_waitpid
#define readdir fixture_readdir
#define crypto_wipe fixture_crypto_wipe
#define tcgetattr fixture_tcgetattr
#define tcsetattr fixture_tcsetattr
#include SU_SOURCE
#undef tcgetattr
#undef tcsetattr
#undef crypto_wipe
#undef getuid
#undef fopen
#undef open
#undef close
#undef ioctl
#undef execve
#undef syscall
#undef fork
#undef waitpid
#undef readdir

static void fixture_crypto_wipe(void *p,size_t n) {
  crypto_wipe(p,n);
  for(size_t i=0;i<n;i++)CHECK(((unsigned char *)p)[i]==0);
  if(n==sizeof(struct bsu_auth_token_req))events[TOKEN_WIPE]++;
  else { CHECK(n==512);events[PHC_WIPE]++; }
}
static int fixture_ioctl(int fd,unsigned long op,...) {
  va_list ap;va_start(ap,op);struct bsu_auth_token_req *r=va_arg(ap,void *);va_end(ap);
  CHECK(fd==authfd && (fcntl(fd,F_GETFD)&FD_CLOEXEC));
  CHECK(r->uid==target_uid && r->gid==target_gid && r->purpose==2);
  CHECK(!strcmp(r->user,"fixture") && r->flags==0 && r->reserved==0);
  if(op==BSU_AUTH_IOC_MINT_TOKEN) {
    events[MINT]++;CHECK(r->expires_sec==5);
    for(int i=0;i<32;i++)CHECK(!r->token[i]);
    if(fail==2){errno=EACCES;return -1;}
    memset(r->token,0xa7,32);return 0;
  }
  CHECK(op==BSU_AUTH_IOC_CONSUME_TOKEN);events[CONSUME]++;CHECK(r->expires_sec==0);
  for(int i=0;i<32;i++)CHECK(r->token[i]==0xa7);
  if(fail==7){errno=EACCES;return -1;}return 0;
}
static const char *envvalue(char *const *env,const char *key) {
  size_t n=strlen(key);for(;*env;env++)if(!strncmp(*env,key,n)&&(*env)[n]=='=')return *env+n+1;return NULL;
}
static int fixture_execve(const char *p,char *const *argv,char *const *env) {
  events[EXEC]++;CHECK(stage==3 && seen_uid==target_uid && seen_gid==target_gid);
  CHECK(authfd==-1 && ttyfd==-1);CHECK(!strcmp(p,shell));
  const char *base=strrchr(shell,'/');char login[512];snprintf(login,sizeof login,"-%s",base?base+1:shell);
  CHECK(!strcmp(argv[0],login_expected?login:shell));
  if(command) { CHECK(!strcmp(argv[1],"-c") && !strcmp(argv[2],command) && !argv[3]); }
  else if(login_expected)CHECK(!strcmp(argv[1],"-i") && !argv[2]);
  else CHECK(!argv[1]);
  CHECK(!strcmp(envvalue(env,"USER"),"fixture"));CHECK(!strcmp(envvalue(env,"LOGNAME"),"fixture"));
  CHECK(!strcmp(envvalue(env,"HOME"),workdir));CHECK(!strcmp(envvalue(env,"SHELL"),shell));
  CHECK(!strcmp(envvalue(env,"PATH"),"/bin:/bash-os:/usr/bin"));
  CHECK(!strcmp(envvalue(env,"TERM"),"fixture-term"));
  CHECK(!!envvalue(env,"SAFE")==keep_expected);
  const char *bad[]={"LD_PRELOAD","BASH_ENV","PYTHONPATH","SHELLOPTS","PS4","BASHSU_SECRET",NULL};
  for(int i=0;bad[i];i++)CHECK(!envvalue(env,bad[i]));
  char cwd[PATH_MAX];CHECK(getcwd(cwd,sizeof cwd));CHECK(!strcmp(cwd,login_expected?workdir:initial_dir));
  for(int fd=3;fd<=511;fd++)CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
  sigset_t mask;CHECK(sigprocmask(SIG_SETMASK,NULL,&mask)==0);
  for(int sig=1;sig<NSIG;sig++)CHECK(!sigismember(&mask,sig));
  struct sigaction sa;CHECK(sigaction(SIGPIPE,NULL,&sa)==0 && sa.sa_handler==SIG_DFL);
  if(real_exec)return execve(p,argv,env);
  _exit(37);
}
void builtin_error(const char *fmt,...) {
  if(quiet)return;va_list ap;va_start(ap,fmt);vfprintf(stderr,fmt,ap);va_end(ap);fputc('\n',stderr);
}
void builtin_warning(const char *fmt,...) { (void)fmt; }
static int dispatch(int n,char **args) {
  WORD_LIST list[8];WORD_DESC words[8];CHECK(n<=8);
  for(int i=0;i<n;i++){words[i].word=args[i];list[i].word=&words[i];list[i].next=i+1<n?&list[i+1]:NULL;}
  return su_builtin(n?list:NULL);
}
static int call(void) {
  char *args[8];int n=0;args[n++]=login_expected?"--login":"--no-login";
  if(keep_expected)args[n++]="--keep-env";
  if(command){args[n++]="-c";args[n++]=(char *)command;}
  args[n++]="fixture";return dispatch(n,args);
}
static int fd_count(void) { DIR *d=opendir("/proc/self/fd");CHECK(d);int n=0;while(readdir(d))n++;closedir(d);return n; }
static void reset(void) { memset(events,0,EVENT_COUNT*sizeof *events);stage=0;password_pos=0;fail=0;root_route=0;owned=0;real_exec=0;login_expected=0;keep_expected=0;shadow_phc=phc;password="fixture-password";command="exit 37";shell="/bin/sh"; }
static void run_checks(void) {
  int before=fd_count();
  int fd=open("/dev/null",O_RDONLY);CHECK(fd>=3);CHECK(dup2(fd,511)==511);
  signal(SIGPIPE,SIG_IGN);sigset_t blocked,old;sigemptyset(&blocked);sigaddset(&blocked,SIGUSR1);CHECK(!sigprocmask(SIG_BLOCK,&blocked,&old));
  for(int i=0;i<6;i++){reset();root_route=i==0;login_expected=i%2;keep_expected=i==2;range_fallback=i==3;
    if(i>=4)command=NULL;
    CHECK(call()==37);CHECK(events[MINT]==1 && events[CONSUME]==1 && events[EXEC]==1);CHECK(events[WIPE]==!root_route);
    CHECK(events[TOKEN_WIPE]==2 && events[PHC_WIPE]==!root_route);
    CHECK(fcntl(511,F_GETFD)>=0);CHECK(getuid()==1000 || getuid()==0);
  }
  range_fallback=0;CHECK(!sigprocmask(SIG_SETMASK,&old,NULL));signal(SIGPIPE,SIG_DFL);close(511);close(fd);
  reset();fail=14;range_fallback=1;
  fd=open("/dev/null",O_RDONLY);CHECK(fd>=3);
  CHECK(call()==1);CHECK(!events[EXEC]);CHECK(fcntl(fd,F_GETFD)>=0);
  close(fd);CHECK(fd_count()==before);
  range_fallback=0;
  for(int f=1;f<=13;f++) {
    if(f==8)continue;
    reset();fail=f;int rc=call();CHECK(rc==(f==10||f==11?2:f==13?37:1));
    if(f!=13)CHECK(!events[EXEC]);
    if(f==1 || f==2 || f==7)CHECK(!events[GROUPS]);
    if(f==2)CHECK(events[TOKEN_WIPE]==1);
    if(f==7)CHECK(events[TOKEN_WIPE]==2);
    CHECK(fd_count()==before);
  }
  reset();password="wrong";CHECK(call()==1);CHECK(!events[MINT] && events[WIPE]==1);
  char lock[PATH_MAX+64];snprintf(lock,sizeof lock,"%s/fail.4242",workdir);CHECK(access(lock,F_OK)==0);
  reset();CHECK(call()==37);CHECK(access(lock,F_OK)<0);
  for(int i=0;i<5;i++){reset();password="wrong";CHECK(call()==1);}
  reset();CHECK(call()==1);CHECK(!events[PROMPT] && !events[MINT]);CHECK(!unlink(lock));
  const char *invalid[]={"!","*","","malformed",NULL};
  for(int i=0;invalid[i];i++){reset();shadow_phc=invalid[i];CHECK(call()==2);CHECK(!events[MINT]);}
  reset();char *longpw=malloc(4098);CHECK(longpw);memset(longpw,'x',4097);longpw[4097]=0;password=longpw;CHECK(call()==2);CHECK(events[WIPE]==1 && !events[MINT]);free(longpw);
  reset();char *bad[]={"--invalid"};CHECK(dispatch(1,bad)==2);bad[0]="-c";CHECK(dispatch(1,bad)==2);bad[0]="../bad";CHECK(dispatch(1,bad)==2);bad[0]="missing";CHECK(dispatch(1,bad)==1);
  reset();fail=20;CHECK(call()==1);
  reset();owned=real_exec=1;root_route=1;target_uid=getuid();target_gid=getgid();
  CHECK(call()==37);command="kill -TERM $$";CHECK(call()==143);command="exit 0";CHECK(call()==0);
  shell="/missing/sol-su-shell";CHECK(call()==126);shell="/dev/null";CHECK(call()==126);
  CHECK(fd_count()==before);
  printf("sol-su: production auth, denial, transition, environment, argv, status and cleanup fixtures passed\n");
}
int main(int argc,char **argv) {
  owner=getpid();events=mmap(NULL,EVENT_COUNT*sizeof *events,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);CHECK(events!=MAP_FAILED);
  CHECK(getcwd(initial_dir,sizeof initial_dir));
  snprintf(workdir,sizeof workdir,"%s/su-XXXXXX",getenv("SOL_SU_TMPDIR")?getenv("SOL_SU_TMPDIR"):"/tmp");CHECK(mkdtemp(workdir));
  setenv("PHCLIB_PASSWD","/fixture/passwd",1);setenv("PHCLIB_SHADOW","/fixture/shadow",1);setenv("BPW_LOCK_DIR",workdir,1);
  setenv("PATH","",1);setenv("TERM","fixture-term",1);setenv("SAFE","kept",1);setenv("BASH_ENV","evil",1);setenv("PS4","evil",1);setenv("BASHSU_SECRET","fixture",1);
  reset();
  if(argc==2 && !strcmp(argv[1],"--phc"))puts(phc);
  else if(argc==2 && (!strcmp(argv[1],"--pty") || !strcmp(argv[1],"--pty-cancel"))) {
    pty_mode=1;CHECK(call()==(!strcmp(argv[1],"--pty")?37:143));puts("pty passed");
  }
  else if(argc==4 && !strcmp(argv[1],"--work")) {
    int n=atoi(argv[3]);CHECK(n>0);quiet=1;
    for(int i=0;i<n;i++) {
      reset();quiet=1;
      if(!strcmp(argv[2],"auth")) {
        CHECK(bsu_verify_user_interactive("fixture")==0);CHECK(events[WIPE]==1 && events[PHC_WIPE]==1 && events[PROMPT]==1 && !events[MINT]);
        CHECK(ttyfd==-1 && !tty_changed);
      } else { CHECK(!strcmp(argv[2],"child"));root_route=owned=real_exec=1;target_uid=getuid();target_gid=getgid();command="exit 37";CHECK(call()==37);CHECK(events[EXEC]==1 && events[MINT]==1 && events[CONSUME]==1); }
    }
    printf("validated %s %d\n",argv[2],n);
  } else { CHECK(argc==1);run_checks(); }
  CHECK(rmdir(workdir)==0);return 0;
}
