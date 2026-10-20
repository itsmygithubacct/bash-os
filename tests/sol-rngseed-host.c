/* SPDX-License-Identifier: MIT */
/* Links production rngseed.c. Every entropy-credit ioctl is intercepted, even
   when run as root. Build through tests/sol-rngseed-build.sh under a build gate. */
#define _GNU_SOURCE 1
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include "loadables.h"
#include "bashgetopt.h"

WORD_LIST *loptend;
void reset_internal_getopt (void) {}
int internal_getopt (WORD_LIST *l, char *o) {
  (void)o;
  if (l && !strcmp(l->word->word, "--")) l = l->next;
  else if (l && l->word->word[0] == '-') { loptend = l; return '?'; }
  loptend = l; return -1;
}
void builtin_error (const char *fmt, ...) {
  va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); fputc('\n', stderr); va_end(a);
}
void builtin_usage (void) { fputs("usage: rngseed load|save FILE\n", stderr); }
extern int rngseed_builtin (WORD_LIST *);
static int run(int n, ...) {
  WORD_LIST ls[4] = {0}; WORD_DESC ws[4] = {0};
  va_list a; va_start(a,n);
  for (int i=0; i<n; i++) { ws[i].word = va_arg(a,char *); ls[i].word=&ws[i]; ls[i].next=i+1<n?&ls[i+1]:0; }
  va_end(a); return rngseed_builtin(n?ls:0);
}

/* Production calls only: test fixture IO runs with armed=0. */
static int armed, credit_count, random_calls, random_bytes, random_flags;
static int seedfd=-1, tempfd=-1, dirfd_=-1, devfd=-1;
static int short_io, read_calls, write_calls, real_random, pool=256;
static int credit_ok, credit_bits, credit_size, credit_valid, consumed;
static char fault[40], events[32768], seedpath[4096];
static unsigned char credited[4096];
static size_t evlen;
static void event(char c) { if (evlen+1<sizeof events) {events[evlen++]=c; events[evlen]=0;} }
static int isfault(const char *s) { return !strcmp(fault,s); }
static int fail(const char *s, int e) { if (!isfault(s)) return 0; errno=e; return 1; }
static void reset(const char *f) {
  armed=1; credit_count=random_calls=random_bytes=read_calls=write_calls=0;
  random_flags=-1; credit_ok=1; credit_valid=0; consumed=0; short_io=0;
  evlen=0; events[0]=0; seedfd=tempfd=dirfd_=devfd=-1;
  snprintf(fault,sizeof fault,"%s",f); real_random=0; pool=256;
}
int __real_open(const char *,int,...);
int __wrap_open(const char *p,int flags,...) {
  mode_t m=0; if(flags&O_CREAT) { va_list a;va_start(a,flags);m=va_arg(a,int);va_end(a); }
  if (armed && !strcmp(p,"/dev/urandom")) {
    event('D'); if(fail("device",EACCES)) return -1;
    return devfd=__real_open("/dev/null",flags,m);
  }
  int fd=__real_open(p,flags,m); if(armed && (flags&O_DIRECTORY)) dirfd_=fd;
  return fd;
}
int __real_openat(int,const char *,int,...);
int __wrap_openat(int d,const char *p,int flags,...) {
  mode_t m=0; if(flags&O_CREAT) {va_list a;va_start(a,flags);m=va_arg(a,int);va_end(a);}
  if(armed && fail(flags&O_CREAT?"create":"open-seed",EACCES)) return -1;
  int fd=__real_openat(d,p,flags,m);
  if(armed && fd>=0) {if(flags&O_CREAT) {tempfd=fd;event('T');} else {seedfd=fd;event('O');}}
  return fd;
}
FILE *__real_fopen(const char *,const char *);
FILE *__wrap_fopen(const char *p,const char *m) {
  if(!strcmp(p,"/proc/sys/kernel/random/poolsize")) {
    if(pool<0) {errno=ENOENT;return NULL;}
    FILE *f=tmpfile(); if(!f) abort(); fprintf(f,"%d\n",pool); rewind(f); return f;
  }
  return __real_fopen(p,m);
}
ssize_t __real_getrandom(void *,size_t,unsigned);
ssize_t __wrap_getrandom(void *b,size_t n,unsigned flags) {
  random_calls++; random_flags=flags; if(armed) event('G');
  if(armed && fail("random",EIO)) return -1;
  if(armed && fail("eagain",EAGAIN)) return -1;
  if(armed && isfault("random-zero")) return 0;
  if(armed && short_io && random_calls==1) {errno=EINTR;return -1;}
  if(armed && short_io && n>17) n=17;
  ssize_t r;
  if(real_random) r=__real_getrandom(b,n,flags);
  else {for(size_t i=0;i<n;i++) ((unsigned char *)b)[i]=(unsigned char)(0xa5+random_bytes+i); r=(ssize_t)n;}
  if(r>0) random_bytes+=(int)r;
  return r;
}
/* No __real_ioctl declaration or call exists: impossible to credit the host. */
int __wrap_ioctl(int fd,unsigned long request,...) {
  va_list a;va_start(a,request);struct rand_pool_info *p=va_arg(a,void *);va_end(a);
  if(fd!=devfd || request!=RNDADDENTROPY) abort();
  credit_count++; event('C'); credit_bits=p->entropy_count;credit_size=p->buf_size;
  if(p->buf_size<32 || p->buf_size>4096) abort();
  memcpy(credited,p->buf,p->buf_size);
  credit_valid=consumed && strchr(events,'S') && access(seedpath,F_OK)!=0;
  if(!credit_ok) {errno=EPERM;return -1;} return 0;
}
ssize_t __real_read(int,void *,size_t);
ssize_t __wrap_read(int fd,void *b,size_t n) {
  if(armed && fd==seedfd) {
    read_calls++;event('R');if(fail("read",EIO))return -1;
    if(short_io && read_calls==1) {errno=EINTR;return -1;}
    if(short_io && n>23)n=23;
  }
  return __real_read(fd,b,n);
}
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_write(int fd,const void *b,size_t n) {
  if(armed && fd==tempfd) {
    write_calls++;event('W');if(fail("write",ENOSPC))return -1;
    if(isfault("write-zero"))return 0;
    if(short_io && write_calls==1) {errno=EINTR;return -1;}
    if(short_io && n>19)n=19;
  }
  return __real_write(fd,b,n);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
  if(armed) {
    if(fd==dirfd_) {event('S');if(fail(consumed && !credit_count?"consume-sync":"dir-sync",EIO))return -1;}
    else if(fd==tempfd) {event('F');if(fail("file-sync",EIO))return -1;}
  }
  return __real_fsync(fd);
}
int __real_close(int);
int __wrap_close(int fd) {
  int t=armed && fd==tempfd, s=armed && fd==seedfd;
  if(t)event('X');
  int rc=__real_close(fd);
  if(armed) {if(fd==tempfd)tempfd=-1;if(fd==seedfd)seedfd=-1;if(fd==devfd)devfd=-1;}
  if(t && fail("close",EIO))return -1;
  if(s && fail("read-close",EIO))return -1;
  return rc;
}
int __real_fchmod(int,mode_t);
int __wrap_fchmod(int fd,mode_t m) {if(armed && fail("chmod",EPERM))return -1;return __real_fchmod(fd,m);}
int __real_renameat(int,const char *,int,const char *);
int __wrap_renameat(int a,const char *b,int c,const char *d) {
  if(armed) {event('N');if(fail("rename",EACCES))return -1;}
  return __real_renameat(a,b,c,d);
}
int __real_unlinkat(int,const char *,int);
int __wrap_unlinkat(int d,const char *p,int flags) {
  if(armed && strncmp(p,".rngseed-",9)) {event('U');if(fail("unlink",EACCES))return -1;consumed=1;}
  return __real_unlinkat(d,p,flags);
}
int __real_flock(int,int);
int __wrap_flock(int fd,int op) {if(armed && fail("lock",EWOULDBLOCK))return -1;return __real_flock(fd,op);}

int __real_fstat(int,struct stat *);
int __wrap_fstat(int fd,struct stat *st) {
  if(armed && fail("stat",EIO))return -1;
  int rc=__real_fstat(fd,st);
  if(!rc && armed && isfault("owner"))st->st_uid=geteuid()+1;
  return rc;
}

static int fails, checks;
#define CHECK(c,msg) do {checks++;if(!(c)){fprintf(stderr,"FAIL: %s [events=%s]\n",msg,events);fails++;}}while(0)
static void fixture(int n) {
  armed=0;unlink(seedpath);
  FILE *f=fopen(seedpath,"wb");if(!f)abort();
  for(int i=0;i<n;i++)fputc((i*7+3)&255,f);
  if(fclose(f) || chmod(seedpath,0600))abort();
}
static int content(int n,int fresh) {
  armed=0;struct stat st;
  if(stat(seedpath,&st) || st.st_size!=n || (st.st_mode&07777)!=0600)return 0;
  FILE *f=fopen(seedpath,"rb");if(!f)abort();int ok=1;
  for(int i=0;i<n;i++)if(fgetc(f)!=((fresh?0xa5+i:i*7+3)&255))ok=0;
  if(fgetc(f)!=EOF)ok=0;
  fclose(f);return ok;
}
static int temps(const char *d) {DIR *p=opendir(d);if(!p)abort();int n=0;struct dirent *e;while((e=readdir(p)))if(!strncmp(e->d_name,".rngseed-",9))n++;closedir(p);return n;}
static int fds(void) {DIR *p=opendir("/proc/self/fd");if(!p)abort();int n=0;while(readdir(p))n++;closedir(p);return n;}
static void correctness(const char *d) {
  int before=fds(),rc;
  armed=0;unlink(seedpath);reset("");
  CHECK(run(2,"load",seedpath)==0 && !credit_count && !random_calls,"missing file first boot has no entropy operations");
  reset("");short_io=1;rc=run(2,"save",seedpath);
  CHECK(rc==0 && random_flags==0 && random_bytes==512 && random_calls>2,"save fills blocking random across EINTR/short reads");
  CHECK(strstr(events,"FXNS") && write_calls>2,"all writes precede file fsync/close/rename/directory fsync");
  CHECK(content(512,1) && !temps(d),"save exact bytes, mode 0600, no temporary file");
  unsigned char prior[512],now[512];armed=0;
  FILE *f=fopen(seedpath,"rb");if(fread(prior,1,512,f)!=512)abort();fclose(f);
  reset("");real_random=1;rc=run(2,"save",seedpath);armed=0;
  f=fopen(seedpath,"rb");if(fread(now,1,512,f)!=512)abort();fclose(f);
  CHECK(!rc && memcmp(prior,now,512),"second save obtains fresh random bytes");
  fixture(512);reset("");rc=run(2,"save",seedpath);
  CHECK(!rc && !strcmp(events,"GTWFXNS"),"exact ordinary save ordering");
  fixture(512);reset("");rc=run(2,"load",seedpath);
  CHECK(!rc && !strcmp(events,"ORRUSDCGTWFXNS"),"exact ordinary load ordering");
  int sizes[]={0,10,31,32,512,4096,4097,8192};
  for(size_t i=0;i<sizeof sizes/sizeof *sizes;i++) {
    int n=sizes[i],valid=n>=32&&n<=4096;fixture(n);reset("");short_io=1;
    rc=run(2,"load",seedpath);
    CHECK(rc==(valid?0:1),"seed length bounds");
    if(valid) {
      CHECK(credit_count==1 && credit_valid && credit_size==n && credit_bits==256,"credit exact bounded buffer only after durable consumption");
      int ok=1;for(int j=0;j<n;j++)if(credited[j]!=((j*7+3)&255))ok=0;
      CHECK(ok && random_flags==GRND_NONBLOCK && random_bytes==n,"credit exact original; replacement uses nonblocking random");
      CHECK(strstr(events,"USDCG") && strstr(events,"FXNS"),"consume/sync/device/credit/random and write/sync/close/rename/sync ordering");
      CHECK(content(n,1),"load refresh bytes and private mode");
    } else CHECK(!credit_count && content(n,0),"corrupt size rejected untouched, no credit");
  }
  int pools[]={64,10000,0,-1};
  for(size_t i=0;i<4;i++) {
    fixture(32);reset("");pool=pools[i];rc=run(2,"load",seedpath);
    CHECK(rc==0 && credit_bits==(pool==64?64:256),"poolsize clamps credit, missing/invalid pool falls back to seed bits");
  }
  fixture(512);reset("");credit_ok=0;rc=run(2,"load",seedpath);
  CHECK(rc==1 && credit_count==1 && !random_calls && content(512,0) && !temps(d),"failed credit durably restores identical seed without random refresh");
  const char *pre[]={"open-seed","read","stat","read-close","owner","lock","unlink","consume-sync"};
  for(size_t i=0;i<sizeof pre/sizeof *pre;i++) {
    fixture(512);reset(pre[i]);rc=run(2,"load",seedpath);
    CHECK(rc==1 && !credit_count && !temps(d),"read/permission/lock/consumption failure prevents credit");
    CHECK(isfault("consume-sync") ? access(seedpath,F_OK)!=0 : content(512,0),"pre-credit failure retains uncredited original unless consumption already happened");
  }
  fixture(512);reset("device");rc=run(2,"load",seedpath);
  CHECK(rc==1 && !credit_count && content(512,0),"device-open failure restores original");
  const char *post[]={"random","random-zero","eagain","create","chmod","write","write-zero","file-sync","close","rename","dir-sync"};
  for(size_t i=0;i<sizeof post/sizeof *post;i++) {
    fixture(512);reset(post[i]);rc=run(2,"load",seedpath);
    CHECK(rc==(isfault("eagain")?0:1) && credit_count==1,"post-credit failure reported (EAGAIN is consumed success)");
    armed=0;int exists=access(seedpath,F_OK)==0;
    CHECK((!exists || content(512,1)) && !temps(d),"failed refresh never leaves spent bytes or temporary files");
    if(!exists) {reset("");rc=run(2,"load",seedpath);CHECK(!rc && !credit_count,"second load cannot reuse consumed seed");}
  }
  fixture(512);reset("create");credit_ok=0;rc=run(2,"load",seedpath);
  CHECK(rc==1 && credit_count==1 && access(seedpath,F_OK)!=0 && !temps(d),"failed credit plus failed restoration reports failure and leaves no seed");
  /* A failed save must retain the previous uncredited seed until rename. */
  const char *savefault[]={"random","random-zero","create","chmod","write","write-zero","file-sync","close","rename","dir-sync"};
  for(size_t i=0;i<sizeof savefault/sizeof *savefault;i++) {
    fixture(512);reset(savefault[i]);rc=run(2,"save",seedpath);
    CHECK(rc==1 && !credit_count && content(512,!strcmp(savefault[i],"dir-sync")) && !temps(d),"save failure closes/removes temp and preserves old file until rename");
  }
  fixture(512);armed=0;chmod(seedpath,0644);reset("");rc=run(2,"load",seedpath);
  CHECK(rc==1 && !credit_count,"world-readable seeds rejected");
  armed=0;unlink(seedpath);symlink("target",seedpath);reset("");
  CHECK(run(2,"load",seedpath)==1 && !credit_count,"symlink seed rejected");
  armed=0;unlink(seedpath);mkfifo(seedpath,0600);reset("");
  CHECK(run(2,"load",seedpath)==1 && !credit_count,"FIFO seed rejected without blocking");
  fixture(512);char linkpath[8192];snprintf(linkpath,sizeof linkpath,"%s/link",d);link(seedpath,linkpath);reset("");
  CHECK(run(2,"load",seedpath)==1 && !credit_count,"multiply linked seed rejected");armed=0;unlink(linkpath);
  char tmp[sizeof seedpath+8],target[8192];snprintf(tmp,sizeof tmp,"%s.tmp",seedpath);snprintf(target,sizeof target,"%s/target",d);
  FILE *v=fopen(target,"wb");fputs("safe",v);fclose(v);symlink(target,tmp);reset("");
  CHECK(run(2,"save",seedpath)==0,"preexisting predictable temp symlink cannot redirect save");armed=0;
  char buf[8]={0};v=fopen(target,"rb");size_t got=fread(buf,1,sizeof buf,v);fclose(v);CHECK(got==4&&!strcmp(buf,"safe"),"symlink target untouched");unlink(tmp);unlink(target);
  /* A separate open file description simulates another cooperating process. */
  int lockfd=open(d,O_RDONLY|O_DIRECTORY);if(flock(lockfd,LOCK_EX|LOCK_NB))abort();reset("");
  CHECK(run(2,"load",seedpath)==1 && !credit_count,"directory lock excludes overlapping load");armed=0;close(lockfd);
  reset("");CHECK(run(0)==EX_USAGE && run(1,"save")==EX_USAGE && run(3,"save",seedpath,"extra")==EX_USAGE && run(2,"frob",seedpath)==EX_USAGE && run(2,"-x",seedpath)==EX_USAGE,"argument failures");
  CHECK(run(3,"--","save",seedpath)==0,"option terminator accepted");
  CHECK(run(2,"save","")==1 && run(2,"save","/")==1,"empty basename rejected");
  armed=0;unlink(seedpath);
  int saved=dup(STDERR_FILENO),full=open("/dev/full",O_WRONLY);fflush(stderr);dup2(full,STDERR_FILENO);close(full);reset("");
  rc=run(2,"load",seedpath);fflush(stderr);dup2(saved,STDERR_FILENO);close(saved);clearerr(stderr);
  CHECK(rc==1 && !credit_count,"first boot diagnostic output failure reported");
  armed=0;CHECK(fds()==before && !temps(d),"repeated success/failure calls leave no FDs or temporary files");
}

/* Bench validation uses the independent byte formula above on EVERY pass.
   Real kernel randomness has no fixed content oracle; check return count only. */
static int batch(const char *kind,int count,const char *d) {
  unsigned long long checksum=0, operation_ns=0;
  struct timespec start,end;
  for(int i=0;i<count;i++) {
    if(!strcmp(kind,"save-shim") || !strcmp(kind,"load-shim")) {
      if(kind[0]=='l')fixture(512);
      reset("");clock_gettime(CLOCK_MONOTONIC,&start);int rc=run(2,kind[0]=='l'?"load":"save",seedpath);
      clock_gettime(CLOCK_MONOTONIC,&end);
      operation_ns+=(end.tv_sec-start.tv_sec)*1000000000ULL+end.tv_nsec-start.tv_nsec;
      int ok=!rc && random_bytes==512 && random_flags==(kind[0]=='l'?GRND_NONBLOCK:0) &&
        (kind[0]!='l' || (credit_count==1 && credit_valid && credit_bits==256 && credit_size==512));
      if(kind[0]=='l')for(int j=0;j<512;j++)if(credited[j]!=((j*7+3)&255))ok=0;
      if(!ok || !content(512,1) || temps(d))return 1;
      checksum+=512;
    } else if(!strcmp(kind,"random-system") || !strcmp(kind,"random-shim")) {
      unsigned char b[512];armed=0;real_random=!strcmp(kind,"random-system");random_bytes=0;
      clock_gettime(CLOCK_MONOTONIC,&start);
      int off=0;while(off<512) {ssize_t r=__wrap_getrandom(b+off,512-off,0);if(r<0&&errno==EINTR)continue;if(r<=0)return 1;off+=(int)r;}
      clock_gettime(CLOCK_MONOTONIC,&end);
      operation_ns+=(end.tv_sec-start.tv_sec)*1000000000ULL+end.tv_nsec-start.tv_nsec;
      if(random_bytes!=512)return 1;
      if(!real_random)for(int j=0;j<512;j++)if(b[j]!=((0xa5+j)&255))return 1;
      checksum+=512;
    } else return 2;
  }
  printf("{\"status\":\"pass\",\"case\":\"%s\",\"passes\":%d,\"bytes_validated\":%llu,\"operation_ns\":%llu}\n",kind,count,checksum,operation_ns);
  return 0;
}
int main(int argc,char **argv) {
  umask(0);char d[4096];
  const char *base=getenv("TMPDIR");if(!base)base="/tmp";
  if(snprintf(d,sizeof d,"%s/rngseed-host-XXXXXX",base)>=(int)sizeof d || !mkdtemp(d))return 2;
  if(snprintf(seedpath,sizeof seedpath,"%s/seed",d)>=(int)sizeof seedpath)return 2;
  int rc;
  if(argc==4 && !strcmp(argv[1],"--batch"))rc=batch(argv[2],atoi(argv[3]),d);
  else {correctness(d);printf("rngseed-host: %d checks, %d failures\n",checks,fails);rc=fails?1:0;}
  armed=0;unlink(seedpath);if(rmdir(d)) {perror("rmdir");return 1;}return rc;
}
