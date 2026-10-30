/* SPDX-License-Identifier: MIT
 * Guest-only x86_64 syscall observer for the private top proc fixture.
 * The tracee is our direct child; the controller never traces other tasks.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXFD 1024
#define MAXDATA 65536
#define HELPER "/opt/bashos-parity/harness/helpers/farm600-top-proc-lifecycle-reviewed.py"
static char paths[MAXFD][256];
static const char *scenario, *role;
static pid_t child;
static int child_waitable, child_pidfd=-1;
static int epoch, vanished;

static void bind_open(int fd,const char *path) {
    paths[fd][0]=0;
    if(path && !strncmp(path,"/proc",5)) snprintf(paths[fd],sizeof paths[fd],"%s",path);
}
static int invalidate_dup(unsigned long source,unsigned long destination,int success) {
    int tracked=(source<MAXFD && paths[source][0]) || (destination<MAXFD && paths[destination][0]);
    if(success && destination<MAXFD) paths[destination][0]=0;
    return tracked;
}
static int invalidate_range(unsigned long first,unsigned long last,int success) {
    int tracked=0;
    for(unsigned long i=0;i<MAXFD;i++) if(i>=first && i<=last && paths[i][0]) {
        tracked=1; if(success) paths[i][0]=0;
    }
    return tracked;
}
static int descriptor_controls(void) {
    memset(paths,0,sizeof paths); bind_open(3,"/proc/stat");
    if(!invalidate_dup(5,3,1) || paths[3][0]) return 1;
    bind_open(3,"/proc/stat"); bind_open(3,"/etc/passwd"); if(paths[3][0]) return 2;
    bind_open(3,"/proc/stat"); if(!invalidate_range(2,4,1) || paths[3][0]) return 3;
    bind_open(3,"/proc/stat"); if(!invalidate_dup(3,7,1) || paths[7][0]) return 4;
    bind_open(3,"/proc/stat"); if(!invalidate_dup(5,3,0) || !paths[3][0]) return 5;
    memset(paths,0,sizeof paths);
    puts("{\"kind\":\"descriptor-controls\",\"replacement\":true,\"rebind\":true,\"range\":true,\"dup_source\":true,\"failed_dup\":true,\"complete\":true}");
    return 0;
}

static int wait_one(pid_t p, int *st) {
    pid_t r; do r=waitpid(p,st,0); while(r<0 && errno==EINTR);
    return r==p;
}
static int wait_child(int *st) {
    if(!wait_one(child,st)) { child_waitable=0; return 0; }
    if(WIFEXITED(*st) || WIFSIGNALED(*st)) child_waitable=0;
    return 1;
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
static int read_at(int root, const char *name, char *buf, size_t cap) {
    int fd=openat(root,name,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return -1;
    size_t used=0;
    while(used<cap) {
        ssize_t n=read(fd,buf+used,cap-used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) { close(fd); return -1; }
        if(!n) break;
        used+=(size_t)n;
    }
    close(fd);
    if(used==cap) return -1;
    buf[used]=0; return 0;
}
static int check_map(int root,const char *path) {
    char buf[4096]; unsigned long a,b,c; int used=0;
    if(read_at(root,path,buf,sizeof buf)<0 || sscanf(buf,"%lu %lu %lu %n",&a,&b,&c,&used)!=3) return -1;
    for(char *p=buf+used;*p;p++) if(!isspace((unsigned char)*p)) return -1;
    return a==0 && b==2000 && c==1 ? 0 : -1;
}
static int identity(const char *dir,const char *name,uid_t uid,gid_t gid,char value[37]) {
    int d=-1,f=-1,ok=0; struct stat parent,before,after,entry;
    unsigned char data[38]; size_t used=0;
    d=open(dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(d<0 || fstat(d,&parent)<0 || parent.st_uid!=uid || parent.st_gid!=gid || (parent.st_mode&0022)) goto out;
    f=openat(d,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if(f<0 || fstat(f,&before)<0 || !S_ISREG(before.st_mode) || before.st_uid!=uid || before.st_gid!=gid ||
       (before.st_mode&07777)!=0444 || before.st_nlink!=1 || before.st_size!=37) goto out;
    while(used<sizeof data) {
        ssize_t n=read(f,data+used,sizeof data-used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) goto out;
        if(!n) break;
        used+=(size_t)n;
    }
    if(fstat(f,&after)<0 || fstatat(d,name,&entry,AT_SYMLINK_NOFOLLOW)<0 ||
       before.st_dev!=after.st_dev || before.st_ino!=after.st_ino || before.st_size!=after.st_size ||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
       entry.st_dev!=after.st_dev || entry.st_ino!=after.st_ino || entry.st_mode!=after.st_mode ||
       entry.st_uid!=after.st_uid || entry.st_gid!=after.st_gid || entry.st_nlink!=after.st_nlink ||
       entry.st_size!=after.st_size || entry.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
       entry.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || !S_ISREG(after.st_mode) ||
       after.st_uid!=uid || after.st_gid!=gid || (after.st_mode&07777)!=0444 || after.st_nlink!=1 ||
       used!=37 || data[36]!='\n') goto out;
    for(int i=0;i<36;i++) {
        if(i==8||i==13||i==18||i==23) { if(data[i]!='-') goto out; }
        else if(!((data[i]>='0'&&data[i]<='9')||(data[i]>='a'&&data[i]<='f'))) goto out;
    }
    memcpy(value,data,37); ok=1;
out:
    if(f>=0) close(f);
    if(d>=0) close(d);
    return ok;
}
static int valid_ns(const char *value) {
    unsigned long inode; int used=0;
    return value && sscanf(value,"mnt:[%lu]%n",&inode,&used)==1 && used>0 && value[used]=='\0';
}
static int guest_guard(void) {
    char cwd[512], vendor[32], marker[37], attested[37], ns[128], number[64], *end;
    struct stat a,b; struct statfs fs; struct utsname host;
    const char *fdstr=getenv("LIFECYCLE_REALPROC_FD"), *expected=getenv("LIFECYCLE_MNT_NS"), *outer=getenv("LIFECYCLE_OUTER_NS");
    if(!fdstr || !*fdstr || !valid_ns(expected) || !valid_ns(outer) || getuid()!=0 || geteuid()!=0 || getgid()!=0 || getegid()!=0 ||
       !getcwd(cwd,sizeof cwd) || strcmp(cwd,"/tmp/parity-case") || !getenv("HOME") ||
       strcmp(getenv("HOME"),"/tmp/parity-home") || uname(&host)<0 || strcmp(host.machine,"x86_64")) return -1;
    errno=0; long fdval=strtol(fdstr,&end,10);
    if(errno || *end || fdval<3 || fdval>INT32_MAX) return -1;
    int procfd=(int)fdval;
    if(fstatfs(procfd,&fs)<0 || fs.f_type!=PROC_SUPER_MAGIC || check_map(procfd,"self/uid_map")<0 ||
       check_map(procfd,"self/gid_map")<0) return -1;
    ssize_t nslen=readlinkat(procfd,"self/ns/mnt",ns,sizeof ns-1);
    if(nslen<=0 || (size_t)nslen>=sizeof ns-1) return -1;
    ns[nslen]=0;
    if(strcmp(ns,expected) || !strcmp(ns,outer)) return -1;
    char *rawinfo=malloc(131072);
    if(!rawinfo) return -1;
    if(read_at(procfd,"self/mountinfo",rawinfo,131072)<0) { free(rawinfo); return -1; }
    char *info=strdup(rawinfo);
    if(!info) { free(rawinfo); return -1; }
    char *save=NULL;
    for(char *line=strtok_r(info,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char *sep=strstr(line," - ");
        if(!sep) { free(info); free(rawinfo); return -1; }
        *sep=0;
        if(strstr(line," shared:") || strstr(line," master:") || strstr(line," propagate_from:")) { free(info); free(rawinfo); return -1; }
    }
    free(info);
    if(read_at(procfd,"sys/kernel/overflowuid",number,sizeof number)<0) { free(rawinfo); return -1; }
    errno=0; unsigned long uid=strtoul(number,&end,10);
    if(errno || !isspace((unsigned char)*end)) { free(rawinfo); return -1; }
    if(read_at(procfd,"sys/kernel/overflowgid",number,sizeof number)<0) { free(rawinfo); return -1; }
    errno=0; unsigned long gid=strtoul(number,&end,10);
    if(errno || !isspace((unsigned char)*end)) { free(rawinfo); return -1; }
    if(!identity("/etc","bashos-parity-vm",(uid_t)uid,(gid_t)gid,marker) ||
       !identity("/run","bashos-parity-vm-identity",(uid_t)uid,(gid_t)gid,attested) || memcmp(marker,attested,37) ||
       stat("/proc",&a)<0 || stat("/tmp/parity-case/proc-live",&b)<0 || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) { free(rawinfo); return -1; }
    FILE *f=fopen("/sys/class/dmi/id/sys_vendor","r");
    if(!f || !fgets(vendor,sizeof vendor,f)) { if(f) fclose(f); free(rawinfo); return -1; }
    fclose(f);
    if(strcmp(vendor,"QEMU\n")) { free(rawinfo); return -1; }
    printf("{\"kind\":\"guard\",\"identity\":\"%.*s\",\"uid_map\":\"0 2000 1\",\"gid_map\":\"0 2000 1\",\"mount_ns\":\"%s\",\"outer_ns\":\"%s\",\"overflow_uid\":%lu,\"overflow_gid\":%lu,\"private\":true,\"mountinfo_hex\":\"",36,marker,ns,outer,uid,gid);
    hex((const unsigned char *)rawinfo,strlen(rawinfo)); puts("\"}");
    free(rawinfo); fflush(stdout);
    return 0;
}

int main(int argc,char **argv) {
    if(guest_guard()<0) return 98;
    if(argc==2 && !strcmp(argv[1],"descriptor-controls")) return descriptor_controls();
    if(argc<7) return 98;
    scenario=argv[1]; role=argv[2];
    if(strcmp(role,"native") && strcmp(role,"candidate")) return 98;
    if((!strcmp(role,"native") && (strcmp(argv[3],"/tmp/parity-home/native.out") || strcmp(argv[4],"/tmp/parity-home/native.err") || strcmp(argv[5],"/usr/bin/python3"))) ||
       (!strcmp(role,"candidate") && (strcmp(argv[3],"/tmp/parity-home/candidate.out") || strcmp(argv[4],"/tmp/parity-home/candidate.err") || strcmp(argv[5],"/opt/bashos-parity/candidate")))) return 98;
    child=fork();
    if(child<0) return 98;
    if(child==0) {
        /* Only the trusted native reader needs the pre-mount proc descriptor.
           The candidate must not inherit access to the live proc tree. */
        if(!strcmp(role,"candidate")) {
            const char *saved=getenv("LIFECYCLE_REALPROC_FD");
            if(!saved || close((int)strtol(saved,NULL,10))<0) _exit(96);
            unsetenv("LIFECYCLE_REALPROC_FD"); unsetenv("LIFECYCLE_MNT_NS");
            unsetenv("LIFECYCLE_OUTER_NS");
        }
        int out=open(argv[3],O_WRONLY|O_CREAT|O_TRUNC,0600);
        int err=open(argv[4],O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(out<0 || err<0 || dup2(out,1)<0 || dup2(err,2)<0) _exit(96);
        close(out); close(err);
        if(ptrace(PTRACE_TRACEME,0,0,0)<0) _exit(97);
        raise(SIGSTOP);
        execv(argv[5],argv+5); _exit(95);
    }
    child_waitable=1;
#ifdef SYS_pidfd_open
    child_pidfd=(int)syscall(SYS_pidfd_open,child,0);
#endif
    int st,entering=1,known=0; long nr=-1; unsigned long a[6]={0}; char path[256]={0};
    if(!wait_child(&st) || !WIFSTOPPED(st) || WSTOPSIG(st)!=SIGSTOP) goto bad;
    if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)<0) goto bad;
    printf("{\"kind\":\"start\",\"pid\":%ld,\"program_hex\":\"",(long)child); path_hex(argv[5]);
    printf("\",\"live_proc_inherited\":%s}\n",!strcmp(role,"candidate")?"false":"true");
    fflush(stdout);
    for(;;) {
        if(ptrace(PTRACE_SYSCALL,child,0,0)<0 || !wait_child(&st)) goto bad;
        if(WIFEXITED(st) || WIFSIGNALED(st)) {
            printf("{\"kind\":\"exit\",\"status\":%d,\"signal\":%d,\"cpu_opens\":%d,\"vanished\":%d}\n",
                   WIFEXITED(st)?WEXITSTATUS(st):-1,WIFSIGNALED(st)?WTERMSIG(st):0,epoch,vanished);
            if(child_pidfd>=0) close(child_pidfd);
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
            nr=(long)r.orig_rax; a[0]=r.rdi; a[1]=r.rsi; a[2]=r.rdx; a[3]=r.r10; a[4]=r.r8; a[5]=r.r9; path[0]=0; known=0;
            if(nr==SYS_execve) {
                known=peek_string(child,a[0],path,sizeof path)==0;
                if(!known) path[0]=0;
            }
            if(nr==SYS_open || nr==SYS_openat) {
                unsigned long at=nr==SYS_open?a[0]:a[1];
                known=peek_string(child,at,path,sizeof path)==0;
                if(!known) path[0]=0;
                if(known && !strcmp(path,"/proc/stat")) {
                    epoch++;
                    if(epoch==2 && action("advance")<0) goto bad;
                }
            }
            entering=0; continue;
        }
        long ret=(long)r.rax;
        if(nr==SYS_execve) {
            if(!known) puts("{\"kind\":\"unsupported\",\"operation\":\"unknown-exec\"}");
            printf("{\"kind\":\"exec\",\"path_hex\":\""); path_hex(path);
            printf("\",\"result\":%ld}\n",ret);
            if(ret==0) {
                for(int i=0;i<MAXFD;i++) if(paths[i][0]) {
                    puts("{\"kind\":\"unsupported\",\"operation\":\"exec-with-proc-fds\"}"); break;
                }
                memset(paths,0,sizeof paths);
            }
        } else if(nr==SYS_open || nr==SYS_openat) {
            if(!known || path[0]!='/') {
                printf("{\"kind\":\"unresolved-open\",\"epoch\":%d,\"nr\":%ld,\"base\":%lu}\n",epoch,nr,a[0]);
                /* Pre-sample native guard reads its inherited real-proc fd.
                   Its unresolved opens are not attributed to synthetic proc. */
                if(epoch>0) puts("{\"kind\":\"unsupported\",\"operation\":\"unknown-or-relative-open\"}");
            }
            printf("{\"kind\":\"open\",\"path_hex\":\""); path_hex(path);
            printf("\",\"result\":%ld,\"epoch\":%d}\n",ret,epoch);
            if(ret>=MAXFD) goto bad;
            if(ret>=0) {
                bind_open((int)ret,known?path:NULL); /* all opens rebind */
            }
        } else if(nr==SYS_close && a[0]<MAXFD) {
            if(paths[a[0]][0]) printf("{\"kind\":\"close\",\"fd\":%lu,\"result\":%ld}\n",a[0],ret);
            if(ret==0) paths[a[0]][0]=0;
#ifdef SYS_close_range
        } else if(nr==SYS_close_range) {
            int tracked=invalidate_range(a[0],a[1],ret==0);
            printf("{\"kind\":\"fd-op\",\"operation\":\"close_range\",\"first\":%lu,\"last\":%lu,\"flags\":%lu,\"result\":%ld}\n",a[0],a[1],a[2],ret);
            if(tracked) puts("{\"kind\":\"unsupported\",\"operation\":\"close_range-tracked\"}");
#endif
        } else if((nr==SYS_dup || nr==SYS_dup2 || nr==SYS_dup3 ||
                   (nr==SYS_fcntl && (a[1]==F_DUPFD || a[1]==F_DUPFD_CLOEXEC)))) {
            unsigned long destination=(nr==SYS_dup2 || nr==SYS_dup3)?a[1]:(ret>=0?(unsigned long)ret:MAXFD);
            if(ret>=MAXFD) goto bad;
            int tracked=invalidate_dup(a[0],destination,ret>=0);
            printf("{\"kind\":\"fd-op\",\"operation\":\"dup\",\"nr\":%ld,\"source\":%lu,\"destination\":%lu,\"result\":%ld}\n",nr,a[0],destination,ret);
            if(tracked) puts("{\"kind\":\"unsupported\",\"operation\":\"dup-tracked\"}");
        } else if((nr==SYS_read || nr==SYS_getdents64) && a[0]<MAXFD && paths[a[0]][0]) {
            if(ret>MAXDATA) goto bad;
            unsigned char buf[MAXDATA];
            if(ret>0 && peek_bytes(child,a[1],buf,(size_t)ret)<0) goto bad;
            printf("{\"kind\":\"%s\",\"fd\":%lu,\"path_hex\":\"",nr==SYS_read?"read":"getdents",a[0]);
            path_hex(paths[a[0]]); printf("\",\"result\":%ld,\"epoch\":%d,\"data_hex\":\"",ret,epoch);
            if(ret>0) hex(buf,(size_t)ret);
            puts("\"}"); fflush(stdout);
            if(nr==SYS_getdents64 && ret>0 && !strcmp(paths[a[0]],"/proc") && !strcmp(scenario,"vanish") && !vanished && epoch==2) {
                int found=has_name(buf,(size_t)ret,"777");
                if(found<0) goto bad;
                if(found) { if(action("vanish")<0) goto bad; vanished=1; }
            }
        } else if(nr==SYS_openat2) {
            puts("{\"kind\":\"unsupported\",\"operation\":\"openat2\"}");
            memset(paths,0,sizeof paths);
        } else if(nr==SYS_pipe || nr==SYS_pipe2 || nr==SYS_socketpair) {
            int fds[2]={-1,-1}; unsigned long ptr=nr==SYS_socketpair?a[3]:a[0];
            if(ret==0 && (peek_bytes(child,ptr,(unsigned char *)fds,sizeof fds)<0 ||
                          fds[0]<0 || fds[0]>=MAXFD || fds[1]<0 || fds[1]>=MAXFD)) goto bad;
            printf("{\"kind\":\"fd-op\",\"operation\":\"fd-pair\",\"nr\":%ld,\"result\":%ld,\"fds\":[%d,%d]}\n",nr,ret,fds[0],fds[1]);
            if(ret==0) { bind_open(fds[0],NULL); bind_open(fds[1],NULL); }
        } else if(nr==SYS_socket || nr==SYS_accept || nr==SYS_accept4 || nr==SYS_eventfd || nr==SYS_eventfd2 ||
                  nr==SYS_epoll_create || nr==SYS_epoll_create1 || nr==SYS_timerfd_create ||
                  nr==SYS_signalfd || nr==SYS_signalfd4 || nr==SYS_memfd_create || nr==SYS_creat) {
            printf("{\"kind\":\"fd-op\",\"operation\":\"fd-create\",\"nr\":%ld,\"result\":%ld}\n",nr,ret);
            if(ret>=MAXFD) goto bad;
            if(ret>=0) bind_open((int)ret,NULL);
        } else if(nr==SYS_recvmsg || nr==SYS_recvmmsg || nr==SYS_pidfd_getfd ||
                  nr==SYS_open_by_handle_at || nr==SYS_io_uring_setup || nr==SYS_io_uring_enter) {
            printf("{\"kind\":\"unsupported\",\"operation\":\"unmodelled-fd-source\",\"nr\":%ld}\n",nr);
            memset(paths,0,sizeof paths);
        } else if(nr==SYS_mmap && a[4]<MAXFD && paths[a[4]][0]) {
            puts("{\"kind\":\"unsupported\",\"operation\":\"mmap-tracked\"}");
        } else if((nr==SYS_fcntl || nr==SYS_readv || nr==SYS_pread64 || nr==SYS_lseek) && a[0]<MAXFD && paths[a[0]][0]) {
            if(nr!=SYS_fcntl || (a[1]!=F_GETFD && a[1]!=F_GETFL && a[1]!=F_SETFD && a[1]!=F_SETFL))
                printf("{\"kind\":\"unsupported\",\"operation\":\"tracked-fd-syscall\",\"nr\":%ld,\"fd\":%lu}\n",nr,a[0]);
        }
        printf("{\"kind\":\"syscall\",\"nr\":%ld,\"args\":[%lu,%lu,%lu,%lu,%lu,%lu],\"result\":%ld}\n",nr,a[0],a[1],a[2],a[3],a[4],a[5],ret);
        fflush(stdout); entering=1;
    }
bad:
    fprintf(stderr,"observer failed: %s\n",strerror(errno));
    if(child_waitable) {
        int rc=-1;
#ifdef SYS_pidfd_send_signal
        if(child_pidfd>=0) rc=(int)syscall(SYS_pidfd_send_signal,child_pidfd,SIGKILL,NULL,0);
        else
#endif
            rc=kill(child,SIGKILL); /* unreaped direct child still reserves its PID */
        int waited=rc==0 ? wait_child(&st) : 0;
        printf("{\"kind\":\"cleanup\",\"waitable\":true,\"pidfd\":%s,\"signal_result\":%d,\"wait_result\":%d,\"terminal_reaped\":%s}\n",
               child_pidfd>=0?"true":"false",rc,waited,waited && !child_waitable?"true":"false");
        fflush(stdout);
    } else {
        puts("{\"kind\":\"cleanup\",\"waitable\":false,\"signal_attempted\":false}"); fflush(stdout);
    }
    if(child_pidfd>=0) close(child_pidfd);
    return 98;
}
