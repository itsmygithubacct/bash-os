/* SPDX-License-Identifier: MIT */
/* Compile-time boundaries only: production doas parser, dispatcher, child,
 * credential helper, digest and sudoedit code are included verbatim. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
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
#include <unistd.h>
#include "_bashos_auth_uapi.h"

static int root_route = 1, owned, fail_step, transition_step;
static uid_t target_uid = 4242;
static gid_t target_gid = 4343, seen_groups[64];
static size_t seen_ngroups;
static uid_t fake_uid;
static gid_t fake_gid;
static pid_t parent_pid;
static int expected_group = 4343, check_exec, expected_exit = 37;
static int auth_calls, handoff_calls, verify_calls, decision = BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC;
static int auth_error, handoff_error, approval = BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;
static int missing_handle, bad_version, tty_mode, wait_error, fork_error, range_fallback;
static int edit_case, copyback_calls, expected_mode = BASHOS_AUTH_PRIVCMD_MODE_EXEC;
static unsigned expected_flags;
static char private_dir[PATH_MAX], temp_paths[2][PATH_MAX];
static int copyback_fds[2];
static char expected_argv[8192];
static unsigned expected_argc, expected_bytes;
static unsigned char first_digest[32];
static int quiet;
static int *verified;
static int emit_digest;
static int post_verify_deny;
static int checks;
static int io_read_fail, io_write_fail, io_read_eintr, io_write_eintr;
static int group_probe;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } checks++; } while (0)

static FILE *fixture_fopen(const char *path, const char *mode)
{
  char rows[1024];
  if (!strcmp(path,"/etc/passwd")) {
    snprintf(rows,sizeof rows,"root:x:0:0:Root:/root:/bin/sh\nfixture:x:%u:%u:Fixture:/tmp:/bin/sh\n",target_uid,target_gid);
    FILE *f = tmpfile(); CHECK(f); CHECK(fputs(rows,f)>=0); rewind(f); return f;
  }
  if (!strcmp(path,"/etc/group")) {
    FILE *f = tmpfile(); CHECK(f);
    if(group_probe) {
      int n = group_probe==2 ? 63 : 64;
      for(int i=0;i<n;i++) {
        unsigned g = 8000u+(unsigned)i;
        if(group_probe==3 && i==0) g=(unsigned)target_gid;
        if(group_probe==3 && i==1) g=7000u;
        CHECK(fprintf(f,"g%d:x:%u:fixture\n",i,g)>0);
      }
    }
    else if(owned) { snprintf(rows,sizeof rows,"owned:x:%u:fixture\n",target_gid);CHECK(fputs(rows,f)>=0); }
    else CHECK(fputs("extra:x:4444:fixture\nchosen:x:4545:fixture\n",f)>=0);
    rewind(f); return f;
  }
  return fopen(path,mode);
}
static uid_t fixture_geteuid(void) { return root_route ? 0 : getuid(); }
static int fixture_setgroups(size_t n,const gid_t *g) {
  CHECK(getpid()!=parent_pid); CHECK(transition_step++==0); CHECK(n<=64);
  if(fail_step==1) {errno=EPERM;return -1;} seen_ngroups=n; memcpy(seen_groups,g,n*sizeof *g); return 0;
}
static int fixture_setresgid(gid_t r,gid_t e,gid_t s) {
  CHECK(transition_step++==1); CHECK(r==e && e==s); if(fail_step==2){errno=EPERM;return -1;}
  fake_gid=r; return owned ? setresgid(r,e,s) : 0;
}
static int fixture_setresuid(uid_t r,uid_t e,uid_t s) {
  CHECK(transition_step++==2); CHECK(r==e && e==s); if(fail_step==3){errno=EPERM;return -1;}
  fake_uid=r; return owned ? setresuid(r,e,s) : 0;
}
static int fixture_getresuid(uid_t *r,uid_t *e,uid_t *s) { *r=*e=*s=fake_uid+(fail_step==4); return 0; }
static int fixture_getresgid(gid_t *r,gid_t *e,gid_t *s) { *r=*e=*s=fake_gid; return 0; }
#define fopen fixture_fopen
#define geteuid fixture_geteuid
#define setgroups fixture_setgroups
#define setresuid fixture_setresuid
#define setresgid fixture_setresgid
#define getresuid fixture_getresuid
#define getresgid fixture_getresgid
#include "common/bashcred_privdrop.h"
#undef fopen
#undef setgroups
#undef setresuid
#undef setresgid
#undef getresuid
#undef getresgid

static int fixture_open(const char *p,int flags,...) {
  if(!strcmp(p,"/dev/bashos-auth")) return open("/dev/null",flags);
  return open(p,flags,0600);
}
static int fixture_isatty(int fd) { return tty_mode; }
static pid_t fixture_waitpid(pid_t pid,int *status,int flags) {
  pid_t w=waitpid(pid,status,flags);
  if(wait_error){errno=ECHILD;return -1;} return w;
}
static pid_t fixture_fork(void) { if(fork_error){errno=EAGAIN;return -1;} return fork(); }
static long fixture_syscall(long n,...) {
  va_list ap; va_start(ap,n);
#ifdef SYS_close_range
  if(n==SYS_close_range) {
    unsigned first=va_arg(ap,unsigned),last=va_arg(ap,unsigned),flags=va_arg(ap,unsigned);
    va_end(ap); CHECK(first==3 && last==~0U && flags==0);
    if(range_fallback){errno=ENOSYS;return -1;}
    return syscall(n,first,last,flags);
  }
#endif
  va_end(ap); CHECK(0); return -1;
}
static const char *find_env(char **env,const char *name) {
  size_t n=strlen(name); for(;*env;env++) if(!strncmp(*env,name,n)&&(*env)[n]=='=') return *env+n+1; return NULL;
}
static void assert_blob(const void *blob,unsigned bytes,unsigned argc) {
  CHECK(bytes==expected_bytes && argc==expected_argc);
  CHECK(!bytes || !memcmp(blob,expected_argv,bytes));
}
static ssize_t fixture_status_read(int fd,void *buf,size_t n) {
  if(io_read_eintr>0){io_read_eintr--;errno=EINTR;return -1;}
  if(io_read_fail>0){char sink; io_read_fail--; for(;;){ssize_t nread=read(fd,&sink,1); if(nread<0 && errno==EINTR) continue; break;} errno=EIO; return -1;}
  return read(fd,buf,n);
}
static ssize_t fixture_status_write(int fd,const void *buf,size_t n) {
  if(io_write_eintr>0){io_write_eintr--;errno=EINTR;return -1;}
  if(io_write_fail>0){io_write_fail--;errno=EIO;return -1;}
  return write(fd,buf,n);
}
static int fixture_execve(const char *p,char *const *a,char *const *e) {
  if(group_probe) {
    int have_pw=0,have_sel=0;
    CHECK(transition_step==3); CHECK(fake_gid==(gid_t)expected_group);
    CHECK(seen_ngroups>0 && seen_ngroups<=64);
    for(size_t i=0;i<seen_ngroups;i++) {
      if(seen_groups[i]==target_gid) have_pw=1;
      if(seen_groups[i]==(gid_t)expected_group) have_sel=1;
    }
    CHECK(have_pw && have_sel);
    _exit(expected_exit);
  }
  if(!check_exec) {
    if(owned) {
      CHECK(fake_uid==getuid() && fake_gid==getgid());CHECK(seen_ngroups==1 && seen_groups[0]==getgid());
      char id[32];snprintf(id,sizeof id,"%u",getuid());CHECK(!strcmp(find_env((char **)e,"SUDO_UID"),id));
      snprintf(id,sizeof id,"%u",getgid());CHECK(!strcmp(find_env((char **)e,"SUDO_GID"),id));
      CHECK(!strcmp(find_env((char **)e,"USER"),"fixture"));CHECK(!strcmp(find_env((char **)e,"HOME"),"/tmp"));
      CHECK(!find_env((char **)e,"BASH_ENV"));for(int fd=3;fd<512;fd++)CHECK(fcntl(fd,F_GETFD)<0 && errno==EBADF);
    }
    return execve(p,a,e);
  }
  CHECK(transition_step==3); CHECK(fake_uid==target_uid && fake_gid==(gid_t)expected_group);
  /* The passwd primary group stays supplementary when -g picks another. */
  CHECK(seen_ngroups==3 && seen_groups[0]==4444 && seen_groups[1]==4545 && seen_groups[2]==4343);
  CHECK(!strcmp(p,"/usr/bin/printf")); CHECK(!strcmp(a[1],"literal ' ; $(no)\n")); CHECK(!strcmp(a[2],"")); CHECK(!a[3]);
  CHECK(!strcmp(find_env((char **)e,"USER"),"fixture"));
  CHECK(!strcmp(find_env((char **)e,"HOME"),"/tmp"));
  CHECK(!strcmp(find_env((char **)e,"PATH"),"/bin:/bash-os:/usr/bin"));
  CHECK(!strcmp(find_env((char **)e,"SAFE"),"value"));
  const char *bad[]={"LD_PRELOAD","BASH_ENV","PYTHONPATH","SHELLOPTS","PS4","UNSAFE",NULL};
  for(int i=0;bad[i];i++) CHECK(!find_env((char **)e,bad[i]));
  char id[32]; snprintf(id,sizeof id,"%u",getuid()); CHECK(!strcmp(find_env((char **)e,"SUDO_UID"),id));
  for(int fd=3;fd<512;fd++) CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
  sigset_t mask; CHECK(sigprocmask(SIG_SETMASK,NULL,&mask)==0); CHECK(!sigismember(&mask,SIGUSR1));
  struct sigaction sa; CHECK(sigaction(SIGTERM,NULL,&sa)==0 && sa.sa_handler==SIG_DFL);
  _exit(expected_exit);
}
static int fixture_ioctl(int fd,unsigned long op,...) {
  va_list ap;va_start(ap,op);void *v=va_arg(ap,void *);va_end(ap);
  CHECK(fcntl(fd,F_GETFD)&FD_CLOEXEC);
  if(op==BASHOS_AUTH_IOC_VERSION) {
    struct bashos_auth_version *r=v; r->abi_major=BASHOS_AUTH_ABI_MAJOR;r->abi_minor=BASHOS_AUTH_ABI_MINOR;
    r->features=BASHOS_AUTH_FEAT_PRIVCMD; if(bad_version) r->reserved[0]=1; return 0;
  }
  if(op==BASHOS_AUTH_IOC_PRIVCMD_AUTHZ) {
    struct bashos_auth_privcmd *r=v;auth_calls++;
    CHECK(r->size==sizeof *r && r->mode==(unsigned)expected_mode);
    CHECK(r->flags==expected_flags && r->target_uid==target_uid && r->target_gid==(unsigned)expected_group);
    CHECK(!strcmp(r->target_user,"fixture"));
    assert_blob((void *)(uintptr_t)r->argv_user_ptr,r->argv_bytes,r->argc);
    if(auth_calls==1) memcpy(first_digest,r->request_digest,32); else CHECK(!memcmp(first_digest,r->request_digest,32));
    CHECK(r->decision==0 && r->handle_id==0 && r->policy_generation==0);
    if(auth_error==1 || (auth_error==2 && auth_calls>1)){errno=EACCES;return -1;}
    if (emit_digest) { for (int i=0;i<32;i++) printf("%02x",r->request_digest[i]); puts(""); }
    if (r->mode==BASHOS_AUTH_PRIVCMD_MODE_VALIDATE || r->mode==BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP)
      CHECK(r->envc==0 && r->env_bytes==0 && r->env_user_ptr==0 && r->argc==0 && r->argv_user_ptr==0);
    else {
      const char env[]="BASHOS_CALLER_SAFE=caller\0BASHOS_CALLER_LD_PRELOAD=caller\0BASHOS_CALLER_BASH_ENV=caller\0";
      CHECK(r->envc==3 && r->env_bytes==sizeof env-1);
      CHECK(!memcmp((void *)(uintptr_t)r->env_user_ptr,env,sizeof env-1));
    }
    r->decision=decision; r->handle_id=missing_handle?0:auth_calls;
    if (decision==BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED && *verified)
      r->decision=post_verify_deny ? BASHOS_AUTH_PRIVCMD_DECISION_DENY : (r->mode==BASHOS_AUTH_PRIVCMD_MODE_VALIDATE ? BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK : BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC);
    r->policy_generation=7; r->timestamp_timeout=60;
    if(edit_case && auth_calls>1) {
      if(edit_case==2) r->decision=BASHOS_AUTH_PRIVCMD_DECISION_DENY;
      if(edit_case==3) r->decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;
    }
    return 0;
  }
  if(op==BASHOS_AUTH_IOC_EXEC_VERIFY) {
    struct bashos_auth_exec_verify_req *r=v; verify_calls++;
    CHECK(r->size==sizeof *r && r->target_uid==target_uid && r->policy_generation==7);
    CHECK(!memcmp(r->request_digest,first_digest,32));
    if(fail_step==6){errno=EACCES;return -1;} *verified=1;return 0;
  }
  if(op==BASHOS_AUTH_IOC_EXEC_INTERACTIVE) {
    struct bashos_auth_exec_handoff_req *r=v;
    CHECK(r->mode==BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE);
    assert_blob((void *)(uintptr_t)r->argv_user_ptr,r->argv_bytes,r->argc);
    _exit(expected_exit); /* model kernel replacement, only in owned child */
  }
  if(op==BASHOS_AUTH_IOC_EXEC_HANDOFF) {
    struct bashos_auth_exec_handoff_req *r=v; handoff_calls++;
    CHECK(r->size==sizeof *r && r->handle.handle_id==(unsigned)auth_calls);
    assert_blob((void *)(uintptr_t)r->argv_user_ptr,r->argv_bytes,r->argc);
    if(edit_case && r->flags==BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN) {
      char *out=(void *)(uintptr_t)r->sudoedit_temp_paths_user_ptr; size_t bytes=0;
      for(int i=0;i<2;i++) {snprintf(temp_paths[i],sizeof temp_paths[i],"%s/edit%d",private_dir,i);
        int t=open(temp_paths[i],O_CREAT|O_WRONLY|O_TRUNC,0600);CHECK(t>=0);CHECK(write(t,"edit",4)==4);close(t);
        size_t n=strlen(temp_paths[i])+1;memcpy(out+bytes,temp_paths[i],n);bytes+=n;}
      r->sudoedit_temp_paths_bytes=bytes;r->sudoedit_temp_count=2;r->approval_status=BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;
      if(edit_case==7) { CHECK(unlink(temp_paths[1])==0);CHECK(symlink("/dev/null",temp_paths[1])==0); }
      return 0;
    }
    if(edit_case && r->flags==BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_COPYBACK) {
      copyback_calls++;CHECK(r->sudoedit_temp_fds_count==2);
      unsigned *fds=(void *)(uintptr_t)r->sudoedit_temp_fds_user_ptr;
      for(int i=0;i<2;i++){char buf[4];copyback_fds[i]=fds[i];CHECK(read(fds[i],buf,4)==4 && !memcmp(buf,"edit",4));}
      if(edit_case==4){errno=ENOSYS;return -1;} if(edit_case==5){r->approval_status=BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED;return 0;}
    }
    if(handoff_error){errno=EACCES;return -1;}r->approval_status=approval;r->exit_code=expected_exit;return 0;
  }
  CHECK(0);return -1;
}
static uid_t fixture_getuid(void) { return root_route && transition_step ? fake_uid : getuid(); }
static gid_t fixture_getgid(void) { return root_route && transition_step ? fake_gid : getgid(); }
#define getuid fixture_getuid
#define getgid fixture_getgid
static int fixture_execvp(const char *file,char *const *args) {
  if(edit_case) for(int fd=3;fd<512;fd++) CHECK(fcntl(fd,F_GETFD)<0 && errno==EBADF);
  return execvp(file,args);
}
#define execvp fixture_execvp
#define open fixture_open
#define fopen fixture_fopen
#define ioctl fixture_ioctl
#define isatty fixture_isatty
#define waitpid fixture_waitpid
#define fork fixture_fork
#define execve fixture_execve
#define syscall fixture_syscall
#define read fixture_status_read
#define write fixture_status_write
/* Keep the genuine no-new-privileges helper; inject its failure at the
 * boundary while credential syscall substitutions above stay inside the helper. */
static int fixture_nnp(char *err,size_t len) { if(fail_step==5){errno=EPERM;snprintf(err,len,"injected nnp failure");return -1;} return bc_no_new_privs(err,len); }
#define bc_no_new_privs fixture_nnp
#include DOAS_SOURCE
#undef getuid
#undef getgid
#undef open
#undef fopen
#undef ioctl
#undef isatty
#undef waitpid
#undef fork
#undef execve
#undef execvp
#undef syscall
#undef read
#undef write
#undef geteuid
#undef bc_no_new_privs
#include "../loadables/sudo.c"
#include SUDOEDIT_SOURCE

char **export_env;
void maybe_make_export_env(void) { }
void builtin_error(const char *fmt,...) { if(quiet)return;va_list ap;va_start(ap,fmt);vfprintf(stderr,fmt,ap);va_end(ap);fputc('\n',stderr); }

static int dispatch(int sudo,int n,char **args) {
  WORD_LIST *list=calloc(n?n:1,sizeof *list);WORD_DESC *words=calloc(n?n:1,sizeof *words); CHECK(list && words);
  for(int i=0;i<n;i++){words[i].word=args[i];list[i].word=&words[i];list[i].next=i+1<n?&list[i+1]:NULL;}
  int rc=sudo?sudo_builtin(n?list:NULL):doas_builtin(n?list:NULL);free(list);free(words);return rc;
}
static int call(int sudo,const char *a,const char *b,const char *c,const char *d,const char *e) {
  char *args[5]={(char *)a,(char *)b,(char *)c,(char *)d,(char *)e};int n=0;while(n<5 && args[n])n++;return dispatch(sudo,n,args);
}
static void blob(unsigned n,const char **args) {
  expected_bytes=0;expected_argc=n;
  for(unsigned i=0;i<n;i++){size_t len=strlen(args[i])+1;CHECK(expected_bytes+len<=sizeof expected_argv);memcpy(expected_argv+expected_bytes,args[i],len);expected_bytes+=len;}
}
static int fd_count(void) {
  DIR *d=opendir("/proc/self/fd");CHECK(d);int n=0;while(readdir(d))n++;closedir(d);return n;
}
static void defaults(void) {
  post_verify_deny=0;*verified=0;auth_calls=handoff_calls=verify_calls=copyback_calls=0;decision=BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC;
  auth_error=handoff_error=missing_handle=bad_version=tty_mode=wait_error=fork_error=fail_step=edit_case=0;
  approval=BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED;expected_flags=0;expected_group=4343;expected_mode=BASHOS_AUTH_PRIVCMD_MODE_EXEC;expected_exit=37;
  io_read_fail=io_write_fail=io_read_eintr=io_write_eintr=0;group_probe=0;
}
static void root_tests(void) {
  root_route=1;check_exec=1;
  setenv("UNSAFE","caller secret",1);setenv("BASH_ENV","evil",1);
  char *args[]={"-u","fixture","SAFE=value","LD_PRELOAD=evil","PYTHONPATH=evil","SHELLOPTS=xtrace","PS4=evil","/usr/bin/printf","literal ' ; $(no)\n",""};
  int inherited=open("/dev/null",O_RDONLY);CHECK(inherited>=3);CHECK(dup2(inherited,511)==511);
  signal(SIGTERM,SIG_IGN);sigset_t mask,old;sigemptyset(&mask);sigaddset(&mask,SIGUSR1);CHECK(sigprocmask(SIG_BLOCK,&mask,&old)==0);
  for(int i=0;i<3;i++) CHECK(dispatch(1,10,args)==37);
  CHECK(fcntl(511,F_GETFD)>=0);CHECK(sigprocmask(SIG_SETMASK,&old,NULL)==0);signal(SIGTERM,SIG_DFL);close(511);close(inherited);
  range_fallback=1; CHECK(dispatch(1,10,args)==37); range_fallback=0;
  expected_group=4545; char *gargs[]={"-u","fixture","-g","chosen","SAFE=value","/usr/bin/printf","literal ' ; $(no)\n",""}; CHECK(dispatch(1,8,gargs)==37);expected_group=4343;
  for(int i=1;i<=5;i++){fail_step=i;CHECK(dispatch(1,10,args)==126);}fail_step=0;
  fork_error=1;CHECK(dispatch(1,10,args)==1);fork_error=0;
  CHECK(call(0,"-u","missing","/usr/bin/true",NULL,NULL)==1);
  const char *bad_users[]={"4294967296","4294971538","4294967295","18446744073709551616",NULL};
  for(int i=0;bad_users[i];i++) CHECK(call(0,"-u",bad_users[i],"/usr/bin/true",NULL,NULL)==1);
  const char *bad_groups[]={"#4294967296","#-1","#+1","# 1","#4294967295","#18446744073709551616","#",NULL};
  for(int i=0;bad_groups[i];i++) CHECK(call(1,"-u","fixture","-g",bad_groups[i],"/bin/true")==1);
  CHECK(call(0,"-u","fixture",NULL,NULL,NULL)==2);
  CHECK(call(1,"-s","-i",NULL,NULL,NULL)==2);
  for(int s=0;s<2;s++){CHECK(call(s,"--invalid-fixture-option",NULL,NULL,NULL,NULL)==2);CHECK(call(s,"-u",NULL,NULL,NULL,NULL)==2);}
  check_exec=0;
  char *shell_args[]={"-u","fixture","-s","/usr/bin/test","literal ' ; $(no)\n","=","literal ' ; $(no)\n"};
  CHECK(dispatch(0,7,shell_args)==0);
  char *empty_args[]={"-u","fixture","-s","/usr/bin/test","","=",""};CHECK(dispatch(1,7,empty_args)==0);
  CHECK(call(0,"-u4242","/bin/true",NULL,NULL,NULL)==0);
  CHECK(call(1,"--user=#4242","/bin/true",NULL,NULL,NULL)==0);
  for(int sudo=0;sudo<2;sudo++) {
    fflush(stdout);int saved=dup(STDOUT_FILENO),full=open("/dev/full",O_WRONLY);CHECK(saved>=0 && full>=0);
    CHECK(dup2(full,STDOUT_FILENO)==STDOUT_FILENO);CHECK(call(sudo,"--version",NULL,NULL,NULL,NULL)==1);
    CHECK(dup2(saved,STDOUT_FILENO)==STDOUT_FILENO);close(saved);close(full);CHECK(call(sudo,"--version",NULL,NULL,NULL,NULL)==0);
  }
  CHECK(call(0,"-u","fixture","/not/a/command",NULL,NULL)==127);
  CHECK(call(0,"-u","fixture","/dev/null",NULL,NULL)==126);
  CHECK(call(0,"-u","fixture","sh","-c","exit 23")==23);
  CHECK(call(0,"-u","fixture","/bin/sh","-c","kill -TERM $$")==143);
  CHECK(call(0,"-u","fixture","/bin/echo","literal ' ; $(no)\n",NULL)==0);
  /* Actual owned-child IDs: no elevation, current uid/gid and live exec. */
  owned=1;target_uid=getuid();target_gid=getgid();
  char command[512];snprintf(command,sizeof command,"test \"$(/usr/bin/id -u)\" = %u && test \"$(/usr/bin/id -g)\" = %u",getuid(),getgid());
  CHECK(call(0,"-u","fixture","/bin/sh","-c",command)==0);
  CHECK(getuid()==target_uid && getgid()==target_gid); owned=0;target_uid=4242;target_gid=4343;
}
static void authority_tests(void) {
  root_route=0;bad_version=1;CHECK(bda_open_authority_if_available()<0 && errno==EPROTO);defaults();
  const char *av[]={"/bin/true","literal ' ; $(no)\n",""};blob(3,av);
  char *args[]={"-n","-u","fixture","/bin/true","literal ' ; $(no)\n",""};
  for(int i=0;i<3;i++){defaults();CHECK(dispatch(i%2,6,args)==37);CHECK(auth_calls==1 && handoff_calls==1);}
  defaults();decision=BASHOS_AUTH_PRIVCMD_DECISION_DENY;CHECK(dispatch(0,6,args)==1);CHECK(handoff_calls==0);
  defaults();decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;CHECK(dispatch(0,6,args)==1);CHECK(handoff_calls==0 && verify_calls==0);
  defaults();auth_error=1;CHECK(dispatch(0,6,args)==1);CHECK(!handoff_calls);
  defaults();missing_handle=1;CHECK(dispatch(0,6,args)==1);CHECK(!handoff_calls);
  defaults();handoff_error=1;CHECK(dispatch(0,6,args)==1);
  defaults();approval=BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED;CHECK(dispatch(0,6,args)==1);
  defaults();decision=BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK;CHECK(dispatch(0,6,args)==1);CHECK(!handoff_calls);
  defaults();decision=BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT;CHECK(dispatch(0,6,args)==1);CHECK(!handoff_calls);
  defaults();decision=999;CHECK(dispatch(0,6,args)==1);CHECK(!handoff_calls);
  defaults();approval=999;CHECK(dispatch(0,6,args)==1);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;
  char *interactive[]={"-u","fixture","/bin/true","literal ' ; $(no)\n",""};
  CHECK(dispatch(0,5,interactive)==37);CHECK(*verified==1);
  defaults();decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;CHECK(dispatch(0,5,interactive)==1);CHECK(!*verified && !handoff_calls);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_DENY;CHECK(dispatch(0,5,interactive)==125);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;fail_step=6;CHECK(dispatch(0,5,interactive)==126);CHECK(!*verified);
  defaults();expected_group=4545;expected_flags=BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP;
  char *gargs[]={"-n","-u","fixture","-g","#4545","/bin/true","literal ' ; $(no)\n",""};CHECK(dispatch(1,8,gargs)==37);
  defaults();blob(0,NULL);expected_mode=BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;decision=BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK;CHECK(call(1,"-u","fixture","-v",NULL,NULL)==0);
  defaults();blob(0,NULL);expected_mode=BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP;expected_flags=BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL;decision=BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK;CHECK(call(1,"-u","fixture","-K",NULL,NULL)==0);
  defaults();blob(0,NULL);expected_mode=BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;tty_mode=1;
  CHECK(call(1,"-u","fixture","-v",NULL,NULL)==0);CHECK(auth_calls==2 && *verified);
  defaults();blob(0,NULL);expected_mode=BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;tty_mode=1;auth_error=2;
  CHECK(call(1,"-u","fixture","-v",NULL,NULL)==1);CHECK(auth_calls==2 && *verified);
  defaults();blob(0,NULL);expected_mode=BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;tty_mode=1;post_verify_deny=1;
  CHECK(call(1,"-u","fixture","-v",NULL,NULL)==1);CHECK(auth_calls==2 && *verified);
  defaults();struct bashos_auth_privcmd r={0};r.target_uid=4242;r.policy_generation=7;memcpy(r.request_digest,first_digest,32);bda_opts o={0};
  int fd=open("/dev/null",O_RDWR|O_CLOEXEC);CHECK(fd>=0);
  CHECK(bda_run_verify_once(fd,&o,&r)==0);fail_step=6;CHECK(bda_run_verify_once(fd,&o,&r)==126);fail_step=0;
  wait_error=1;CHECK(bda_run_verify_once(fd,&o,&r)==1);wait_error=0;
  close(fd);
}
static void edit_tests(void) {
  const char *av[]={"/private/original1","/private/original2"};blob(2,av);root_route=0;setenv("SUDO_EDITOR","/bin/true",1);
  for(int i=1;i<=7;i++) {
    setenv("SUDO_EDITOR",i==6?"/bin/false":"/bin/true",1);
    defaults();edit_case=i;expected_mode=BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT;decision=BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT;
    int before=fd_count();int rc=call(1,"-u","fixture","-e",av[0],av[1]);CHECK(rc==(i==1?0:1));
    CHECK(copyback_calls==((i==2 || i==3 || i==6 || i==7)?0:1));CHECK(fd_count()==before);
    for(int t=0;t<2;t++){CHECK(access(temp_paths[t],F_OK)<0);if(copyback_calls)CHECK(fcntl(copyback_fds[t],F_GETFD)<0);}
  }
}
static void copyback_tests(void) {
  /* Exercise the shared protected copyback itself: original survives each
   * rejected identity/mode/link/symlink or bad source, and success leaks no fd. */
  char target[PATH_MAX],other[PATH_MAX],src[PATH_MAX];snprintf(target,sizeof target,"%s/original",private_dir);snprintf(other,sizeof other,"%s/other",private_dir);snprintf(src,sizeof src,"%s/src",private_dir);
  int source=open(src,O_CREAT|O_RDWR|O_TRUNC,0600);CHECK(source>=0);CHECK(write(source,"new",3)==3);
  int bad_source=open(src,O_WRONLY);CHECK(bad_source>=0);
  for(int i=0;i<6;i++) {
    unlink(target);unlink(other);int f=open(target,O_CREAT|O_RDWR|O_TRUNC,0600);CHECK(f>=0);CHECK(write(f,"old",3)==3);
    bashos_sudoedit_identity id;CHECK(bashos_sudoedit_capture_identity(f,&id)==0);close(f);
    if(i==1)CHECK(chmod(target,0644)==0);
    if(i==2)CHECK(link(target,other)==0);
    if(i==3){CHECK(rename(target,other)==0);CHECK(symlink(other,target)==0);}
    if(i==4){CHECK(rename(target,other)==0);f=open(target,O_CREAT|O_RDWR,0600);CHECK(f>=0);CHECK(write(f,"old",3)==3);close(f);}
    int before=fd_count();int rc=bashos_sudoedit_atomic_copyback(target,i==5?bad_source:source,&id);
    CHECK((rc==BASHOS_SE_OK)==(i==0));CHECK(fd_count()==before);
    f=open(target,O_RDONLY);CHECK(f>=0);char b[4]={0};CHECK(read(f,b,3)==3);CHECK(!strcmp(b,i==0?"new":"old"));close(f);
    DIR *d=opendir(private_dir);CHECK(d);struct dirent *entry;while((entry=readdir(d)))CHECK(strncmp(entry->d_name,".sudoedit.",10));closedir(d);
  }
  close(bad_source);close(source);unlink(target);unlink(other);unlink(src);
}
static void group_tests(void) {
  char *args[]={"-u","fixture","-g","#7000","/bin/true"};
  root_route=1;check_exec=0;expected_group=7000;
  group_probe=1;
  for(int sudo=0;sudo<2;sudo++) CHECK(dispatch(sudo,5,args)==37);
  group_probe=2;
  for(int sudo=0;sudo<2;sudo++) CHECK(dispatch(sudo,5,args)==37);
  group_probe=3;
  for(int sudo=0;sudo<2;sudo++) CHECK(dispatch(sudo,5,args)==37);
  group_probe=0;expected_group=4343;
}
static void status_tests(void) {
  const char *av[]={"/bin/true","literal ' ; $(no)\n",""};
  char *interactive[]={"-u","fixture","/bin/true","literal ' ; $(no)\n",""};
  root_route=0;blob(3,av);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_read_fail=1;
  CHECK(dispatch(0,5,interactive)==1 && *verified==1);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_read_fail=1;
  CHECK(dispatch(1,5,interactive)==1 && *verified==1);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_read_eintr=1;
  CHECK(dispatch(0,5,interactive)==37 && *verified==1);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_write_fail=1;
  CHECK(dispatch(0,5,interactive)==125 && !*verified);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_write_fail=1;
  CHECK(dispatch(1,5,interactive)==125 && !*verified);
  defaults();tty_mode=1;decision=BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED;io_write_eintr=1;
  CHECK(dispatch(0,5,interactive)==37 && *verified==1);
}
int main(int argc,char **argv) {
  parent_pid=getpid();verified=mmap(NULL,sizeof *verified,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);CHECK(verified!=MAP_FAILED);
  snprintf(private_dir,sizeof private_dir,"%s/sol-doas-XXXXXX",getenv("SOL_DOAS_TMPDIR")?getenv("SOL_DOAS_TMPDIR"):"/tmp");CHECK(mkdtemp(private_dir));setenv("PATH","",1);unsetenv("SHELL");
  char *exports[]={"SAFE=caller","LD_PRELOAD=caller","BASH_ENV=caller",NULL};export_env=exports;
  if(argc==3 && !strcmp(argv[1],"--work")) {
    quiet=1;int n=atoi(argv[2]);CHECK(n>0);
    for(int i=0;i<n;i++) {defaults(); if(getenv("SOL_DOAS_WORK") && !strcmp(getenv("SOL_DOAS_WORK"),"child")){root_route=1;check_exec=0;owned=1;target_uid=getuid();target_gid=getgid();CHECK(call(0,"-u","fixture","/bin/true",NULL,NULL)==0);}
      else if(getenv("SOL_DOAS_WORK") && !strcmp(getenv("SOL_DOAS_WORK"),"auth")){struct bashos_auth_privcmd r={0};r.target_uid=4242;r.policy_generation=7;bda_opts o={0};int fd=open("/dev/null",O_RDWR|O_CLOEXEC);CHECK(fd>=0);CHECK(bda_run_verify_once(fd,&o,&r)==0);close(fd);}
      else {root_route=0;const char *av[]={"/bin/true"};blob(1,av);CHECK(call(0,"-n","-u","fixture","/bin/true",NULL)==37);CHECK(auth_calls==1 && handoff_calls==1);}}
    CHECK(rmdir(private_dir)==0);printf("validated %s %d\n",getenv("SOL_DOAS_WORK"),n);return 0;
  }
  if(argc==2 && !strcmp(argv[1],"--digest")) {
    defaults();root_route=0;quiet=1;emit_digest=1;const char *av[]={"/bin/true"};blob(1,av);
    CHECK(call(0,"-n","-u","fixture","/bin/true",NULL)==37);CHECK(rmdir(private_dir)==0);return 0;
  }
  CHECK(argc==1 || (argc==2 && (!strcmp(argv[1],"root") || !strcmp(argv[1],"authority") || !strcmp(argv[1],"edit") || !strcmp(argv[1],"copyback") || !strcmp(argv[1],"groups") || !strcmp(argv[1],"status"))));
  if(argc==1 || !strcmp(argv[1],"root")){defaults();root_tests();}
  if(argc==1 || !strcmp(argv[1],"authority")){defaults();authority_tests();}
  if(argc==1 || !strcmp(argv[1],"edit")){defaults();edit_tests();}
  if(argc==1 || !strcmp(argv[1],"copyback")){defaults();copyback_tests();}
  if(argc==1 || !strcmp(argv[1],"groups")){defaults();group_tests();}
  if(argc==1 || !strcmp(argv[1],"status")){defaults();status_tests();}
  CHECK(rmdir(private_dir)==0);
  printf("sol-doas: %d parent assertions passed; child assertions fail through status; no skipped fixtures\n",checks);return 0;
}
