/* SPDX-License-Identifier: MIT
 * Guest-only x86_64 syscall observer for the private top proc fixture.
 * The tracee is our direct child; the controller never traces other tasks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXFD 1024
#define MAXDATA 65536
#define HELPER "/opt/bashos-parity/harness/helpers/farm600-top-proc-lifecycle-reviewed.py"
static char paths[MAXFD][256];
static const char *scenario, *role;
static pid_t child;
static int epoch, vanished;

static int wait_one(pid_t p, int *st) {
    pid_t r; do r=waitpid(p,st,0); while(r<0 && errno==EINTR);
    return r==p;
}
static int peek_bytes(pid_t p, unsigned long at, unsigned char *out, size_t n) {
    for(size_t i=0;i<n;) {
        unsigned long address=at+i;
        unsigned long aligned=address & ~(unsigned long)(sizeof(long)-1);
        size_t offset=(size_t)(address-aligned);
        errno=0; long word=ptrace(PTRACE_PEEKDATA,p,(void *)aligned,0);
        if(word==-1 && errno) return -1;
        size_t k=sizeof(word)-offset;
        if(k>n-i) k=n-i;
        memcpy(out+i,(unsigned char *)&word+offset,k); i+=k;
    }
    return 0;
}
static int peek_string(pid_t p, unsigned long at, char *out, size_t cap) {
    for(size_t i=0;i<cap;i++) {
        unsigned char ch;
        if(peek_bytes(p,at+i,&ch,1)<0) return -1;
        out[i]=(char)ch;
        if(!ch) return 0;
    }
    return -1;
}
static void hex(const unsigned char *s,size_t n) {
    static const char h[]="0123456789abcdef";
    for(size_t i=0;i<n;i++) { putchar(h[s[i]>>4]); putchar(h[s[i]&15]); }
}
static void path_hex(const char *s) { hex((const unsigned char *)s,strlen(s)); }

/* Run a separately guarded guest helper while the tracee is stopped. */
static int action(const char *name) {
    int pipefd[2], status; char buf[4097]; size_t used=0;
    if(pipe(pipefd)<0) return -1;
    pid_t p=fork();
    if(p<0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if(p==0) {
        close(pipefd[0]);
        if(dup2(pipefd[1],1)<0 || dup2(pipefd[1],2)<0) _exit(126);
        close(pipefd[1]);
        execl("/usr/bin/python3","python3",HELPER,name,scenario,role,(char *)0);
        _exit(127);
    }
    close(pipefd[1]);
    for(;;) {
        ssize_t n=read(pipefd[0],buf+used,sizeof(buf)-1-used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) { close(pipefd[0]); wait_one(p,&status); return -1; }
        if(!n) break;
        used+=(size_t)n;
        if(used==sizeof(buf)-1) { close(pipefd[0]); kill(p,SIGKILL); wait_one(p,&status); return -1; }
    }
    close(pipefd[0]);
    if(!wait_one(p,&status)) return -1;
    printf("{\"kind\":\"action\",\"name\":\"%s\",\"status\":%d,\"output_hex\":\"",name,
           WIFEXITED(status)?WEXITSTATUS(status):-1);
    hex((unsigned char *)buf,used); puts("\"}"); fflush(stdout);
    return WIFEXITED(status) && WEXITSTATUS(status)==0 ? 0 : -1;
}
static int has_name(const unsigned char *buf,size_t n,const char *target) {
    /* linux_dirent64: ino(8), off(8), reclen(2), type(1), name... */
    for(size_t i=0;i<n;) {
        if(n-i<20) return -1;
        uint16_t len; memcpy(&len,buf+i+16,2);
        if(len<20 || len>n-i || !memchr(buf+i+19,0,len-19)) return -1;
        if(!strcmp((const char *)buf+i+19,target)) return 1;
        i+=len;
    }
    return 0;
}
static int guest_guard(void) {
    char cwd[512], vendor[32], marker[128]; struct stat a,b;
    if(getuid()!=0 || geteuid()!=0 || !getcwd(cwd,sizeof cwd) || strcmp(cwd,"/tmp/parity-case") ||
       !getenv("HOME") || strcmp(getenv("HOME"),"/tmp/parity-home") ||
       stat("/proc",&a)<0 || stat("/tmp/parity-case/proc-live",&b)<0 ||
       a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) return -1;
    FILE *f=fopen("/sys/class/dmi/id/sys_vendor","r");
    if(!f || !fgets(vendor,sizeof vendor,f)) { if(f) fclose(f); return -1; }
    fclose(f);
    if(strcmp(vendor,"QEMU\n")) return -1;
    f=fopen("/etc/bashos-parity-vm","r");
    if(!f || !fgets(marker,sizeof marker,f)) { if(f) fclose(f); return -1; }
    fclose(f);
    if(strlen(marker)!=37 || marker[36]!='\n') return -1;
    for(int i=0;i<36;i++) {
        if(i==8||i==13||i==18||i==23) { if(marker[i]!='-') return -1; }
        else if(!((marker[i]>='0'&&marker[i]<='9')||(marker[i]>='a'&&marker[i]<='f')||(marker[i]>='A'&&marker[i]<='F'))) return -1;
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc<7 || guest_guard()<0) return 98;
    scenario=argv[1]; role=argv[2];
    if(strcmp(role,"native") && strcmp(role,"candidate")) return 98;
    if((!strcmp(role,"native") && (strcmp(argv[3],"/tmp/parity-home/native.out") || strcmp(argv[4],"/tmp/parity-home/native.err") || strcmp(argv[5],"/usr/bin/python3"))) ||
       (!strcmp(role,"candidate") && (strcmp(argv[3],"/tmp/parity-home/candidate.out") || strcmp(argv[4],"/tmp/parity-home/candidate.err") || strcmp(argv[5],"/opt/bashos-parity/candidate")))) return 98;
    child=fork();
    if(child<0) return 98;
    if(child==0) {
        int out=open(argv[3],O_WRONLY|O_CREAT|O_TRUNC,0600);
        int err=open(argv[4],O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(out<0 || err<0 || dup2(out,1)<0 || dup2(err,2)<0) _exit(96);
        close(out); close(err);
        if(ptrace(PTRACE_TRACEME,0,0,0)<0) _exit(97);
        raise(SIGSTOP);
        execv(argv[5],argv+5); _exit(95);
    }
    int st,entering=1; long nr=-1; unsigned long a[3]={0}; char path[256]={0};
    if(!wait_one(child,&st) || !WIFSTOPPED(st) || WSTOPSIG(st)!=SIGSTOP) goto bad;
    if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)<0) goto bad;
    printf("{\"kind\":\"start\",\"pid\":%ld,\"program_hex\":\"",(long)child); path_hex(argv[5]); puts("\"}");
    fflush(stdout);
    for(;;) {
        if(ptrace(PTRACE_SYSCALL,child,0,0)<0 || !wait_one(child,&st)) goto bad;
        if(WIFEXITED(st) || WIFSIGNALED(st)) {
            printf("{\"kind\":\"exit\",\"status\":%d,\"signal\":%d,\"cpu_opens\":%d,\"vanished\":%d}\n",
                   WIFEXITED(st)?WEXITSTATUS(st):-1,WIFSIGNALED(st)?WTERMSIG(st):0,epoch,vanished);
            return fflush(stdout)==0 ? 0 : 98;
        }
        if(!WIFSTOPPED(st)) goto bad;
        int sig=WSTOPSIG(st);
        if(sig==SIGTRAP && (st>>16)!=0) goto bad; /* reject tracee forks */
        if(sig==SIGTRAP) continue; /* exec trap */
        if(sig!=(SIGTRAP|0x80)) goto bad;
        struct user_regs_struct r;
        if(ptrace(PTRACE_GETREGS,child,0,&r)<0) goto bad;
        if(entering) {
            nr=(long)r.orig_rax; a[0]=r.rdi; a[1]=r.rsi; a[2]=r.rdx; path[0]=0;
            if(nr==SYS_execve && peek_string(child,a[0],path,sizeof path)<0) path[0]=0;
            if(nr==SYS_open || nr==SYS_openat) {
                unsigned long at=nr==SYS_open?a[0]:a[1];
                if(peek_string(child,at,path,sizeof path)<0) path[0]=0;
                if(!strcmp(path,"/proc/stat")) {
                    epoch++;
                    if(epoch==2 && action("advance")<0) goto bad;
                }
            }
            entering=0; continue;
        }
        long ret=(long)r.rax;
        if(nr==SYS_execve) {
            printf("{\"kind\":\"exec\",\"path_hex\":\""); path_hex(path);
            printf("\",\"result\":%ld}\n",ret);
        } else if((nr==SYS_open || nr==SYS_openat) && !strncmp(path,"/proc",5)) {
            printf("{\"kind\":\"open\",\"path_hex\":\""); path_hex(path);
            printf("\",\"result\":%ld,\"epoch\":%d}\n",ret,epoch);
            if(ret>=0 && ret<MAXFD) snprintf(paths[ret],sizeof paths[ret],"%s",path);
            if(ret>=MAXFD) goto bad;
        } else if(nr==SYS_close && a[0]<MAXFD && paths[a[0]][0]) {
            printf("{\"kind\":\"close\",\"fd\":%lu,\"result\":%ld}\n",a[0],ret);
            if(ret==0) paths[a[0]][0]=0;
        } else if((nr==SYS_read || nr==SYS_getdents64) && a[0]<MAXFD && paths[a[0]][0]) {
            if(ret>MAXDATA) goto bad;
            unsigned char buf[MAXDATA];
            if(ret>0 && peek_bytes(child,a[1],buf,(size_t)ret)<0) goto bad;
            printf("{\"kind\":\"%s\",\"fd\":%lu,\"path_hex\":\"",nr==SYS_read?"read":"getdents",a[0]);
            path_hex(paths[a[0]]); printf("\",\"result\":%ld,\"epoch\":%d,\"data_hex\":\"",ret,epoch);
            if(ret>0) hex(buf,(size_t)ret);
            puts("\"}"); fflush(stdout);
            if(nr==SYS_getdents64 && ret>0 && !strcmp(paths[a[0]],"/proc") && !strcmp(scenario,"vanish") && !vanished && epoch==1) {
                int found=has_name(buf,(size_t)ret,"777");
                if(found<0) goto bad;
                if(found) { if(action("vanish")<0) goto bad; vanished=1; }
            }
        } else if((nr==SYS_dup || nr==SYS_dup2 || nr==SYS_dup3 || nr==SYS_fcntl || nr==SYS_readv || nr==SYS_pread64 || nr==SYS_openat2) && a[0]<MAXFD && paths[a[0]][0]) {
            /* The data gate refuses unmodelled operations on a tracked fd. */
            if(nr!=SYS_fcntl || (a[1]!=F_GETFD && a[1]!=F_GETFL && a[1]!=F_SETFD && a[1]!=F_SETFL))
                printf("{\"kind\":\"unsupported\",\"nr\":%ld,\"fd\":%lu}\n",nr,a[0]);
        }
        fflush(stdout); entering=1;
    }
bad:
    fprintf(stderr,"observer failed: %s\n",strerror(errno));
    kill(child,SIGKILL); wait_one(child,&st); return 98;
}
