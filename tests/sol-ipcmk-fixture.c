/* SPDX-License-Identifier: MIT
 * Production code with narrow syscall faults; no duplicate implementation.
 */
#include <config.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <unistd.h>
static int fail_errno, fail_truncate, fail_close, last_id = -1, calls;
static int fault(void) { calls++; if (fail_errno) { errno = fail_errno; return 1; } return 0; }
static int test_shmget(key_t key, size_t size, int flags) { assert(key == IPC_PRIVATE && size == 4097 && flags == (IPC_CREAT|IPC_EXCL|0600)); if (fault()) return -1; return last_id = shmget(key,size,flags); }
static int test_semget(key_t key, int count, int flags) { assert(key == IPC_PRIVATE && count == 3 && flags == (IPC_CREAT|IPC_EXCL|0600)); if (fault()) return -1; return last_id = semget(key,count,flags); }
static int test_msgget(key_t key, int flags) { assert(key == IPC_PRIVATE && flags == (IPC_CREAT|IPC_EXCL|0600)); if (fault()) return -1; return last_id = msgget(key,flags); }
static int test_shm_open(const char *name, int flags, mode_t mode) { assert(flags == (O_RDWR|O_CREAT|O_EXCL) && mode == 0600); if (fault()) return -1; return shm_open(name,flags,mode); }
static sem_t *test_sem_open(const char *name, int flags, ...) { va_list ap; va_start(ap,flags); int mode=va_arg(ap,int); unsigned val=va_arg(ap,unsigned); va_end(ap); assert(flags == (O_CREAT|O_EXCL) && mode==0600 && val==0); if (fault()) return SEM_FAILED; return sem_open(name,flags,mode,val); }
static mqd_t test_mq_open(const char *name, int flags, ...) { va_list ap; va_start(ap,flags); int mode=va_arg(ap,int); struct mq_attr *attr=va_arg(ap,struct mq_attr*); va_end(ap); assert(flags == (O_RDWR|O_CREAT|O_EXCL) && mode==0600 && attr==NULL); if (fault()) return (mqd_t)-1; return mq_open(name,flags,mode,attr); }
static int test_ftruncate(int fd, off_t size) { assert(size == 4097); if(fail_truncate) { errno=ENOSPC; return -1; } return ftruncate(fd,size); }
static int test_close(int fd) { int rc=close(fd); if(fail_close && rc==0) { errno=EIO; return -1; } return rc; }
static int test_sem_close(sem_t *sem) { int rc=sem_close(sem); if(fail_close && rc==0) { errno=EIO; return -1; } return rc; }
static int test_mq_close(mqd_t mq) { int rc=mq_close(mq); if(fail_close && rc==0) { errno=EIO; return -1; } return rc; }
#define close test_close
#define sem_close test_sem_close
#define mq_close test_mq_close
#define shmget test_shmget
#define semget test_semget
#define msgget test_msgget
#define shm_open test_shm_open
#define sem_open test_sem_open
#define mq_open test_mq_open
#define ftruncate test_ftruncate
#include "../loadables/ipcmk.c"
#undef close
#undef sem_close
#undef mq_close
#undef shmget
#undef semget
#undef msgget
#undef shm_open
#undef sem_open
#undef mq_open
#undef ftruncate
static int run(int n, ...) {
    WORD_LIST words[8] = {0}; WORD_DESC desc[8] = {0};
    va_list ap; va_start(ap,n);
    for(int i=0;i<n;i++) { words[i].word=&desc[i]; desc[i].word=va_arg(ap,char*); words[i].next=i+1<n ? &words[i+1] : NULL; }
    va_end(ap); return ipcmk_builtin(n ? words : NULL);
}
int main(void) {
    unsigned mode; int count; size_t size;
    const char *bad[] = {"", "-1", "+1", " 1", "0", "18446744073709551616", "1junk", NULL};
    for(int i=0;bad[i];i++) { assert(ipcmk_parse_count(bad[i],&count)<0); assert(ipcmk_parse_size(bad[i],&size)<0); }
    assert(ipcmk_parse_mode("0",&mode)==0 && mode==0);
    assert(ipcmk_parse_mode("0777",&mode)==0 && mode==0777);
    assert(ipcmk_parse_mode("-0",&mode)<0 && ipcmk_parse_mode("+1",&mode)<0 && ipcmk_parse_mode(" 600",&mode)<0 && ipcmk_parse_mode("1000",&mode)<0);
    assert(ipcmk_parse_count("2147483647",&count)==0 && count==INT_MAX);
    assert(ipcmk_parse_count("2147483648",&count)<0);
    char bound[64]; snprintf(bound,sizeof bound,"%ju",(uintmax_t)SIZE_MAX);
    assert(ipcmk_parse_size(bound,&size)==0 && size==SIZE_MAX);
    assert(ipcmk_parse_size("18446744073709551615K",&size)<0);
    assert(ipcmk_parse_size("1KiB",&size)==0 && size==1024);
    assert(ipcmk_parse_size("2tib",&size)==0 && size==2199023255552ULL);
    char name[100]; snprintf(name,sizeof name,"/sol_ipcmk_fault_%ld",(long)getpid());
    for(int e=0;e<4;e++) {
        int errors[] = {ENOMEM, ENOSPC, EACCES, ENOSYS}; fail_errno=errors[e]; calls=0;
        assert(run(4,"-M","4097","-p","600")==1);
        assert(run(4,"-S","3","-p","600")==1);
        assert(run(3,"-Q","-p","600")==1);
        assert(run(6,"-m","4097","-n",name,"-p","600")==1);
        assert(run(5,"-s","-n",name,"-p","600")==1);
        assert(run(5,"-q","-n",name,"-p","600")==1);
        assert(calls==6);
    }
    fail_errno=0; fail_truncate=1;
    assert(run(6,"-m","4097","-n",name,"-p","600")==1);
    errno=0; assert(shm_open(name,O_RDONLY,0)==-1 && errno==ENOENT); fail_truncate=0;
    fail_close=1;
    assert(run(6,"-m","4097","-n",name,"-p","600")==1);
    assert(shm_open(name,O_RDONLY,0)==-1 && errno==ENOENT);
    assert(run(5,"-s","-n",name,"-p","600")==1);
    assert(sem_open(name,0)==SEM_FAILED && errno==ENOENT);
    assert(run(5,"-q","-n",name,"-p","600")==1);
    assert(mq_open(name,O_RDONLY)==(mqd_t)-1 && errno==ENOENT);
    fail_close=0;
    int saved=dup(STDOUT_FILENO), full=open("/dev/full",O_WRONLY); assert(saved>=0 && full>=0); assert(fflush(stdout)==0); assert(dup2(full,STDOUT_FILENO)>=0); close(full);
    for(int i=0;i<6;i++) {
        if(i==0) { assert(run(4,"-M","4097","-p","600")==1); struct shmid_ds ds; assert(shmctl(last_id,IPC_STAT,&ds)==-1 && errno==EINVAL); }
        if(i==1) { assert(run(4,"-S","3","-p","600")==1); assert(semctl(last_id,0,GETVAL)==-1 && errno==EINVAL); }
        if(i==2) { assert(run(3,"-Q","-p","600")==1); struct msqid_ds ds; assert(msgctl(last_id,IPC_STAT,&ds)==-1 && errno==EINVAL); }
        if(i==3) { assert(run(6,"-m","4097","-n",name,"-p","600")==1); assert(shm_open(name,O_RDONLY,0)==-1 && errno==ENOENT); }
        if(i==4) { assert(run(5,"-s","-n",name,"-p","600")==1); assert(sem_open(name,0)==SEM_FAILED && errno==ENOENT); }
        if(i==5) { assert(run(5,"-q","-n",name,"-p","600")==1); assert(mq_open(name,O_RDONLY)==(mqd_t)-1 && errno==ENOENT); }
    }
    assert(run(1,"--help")==1); assert(run(1,"--version")==1);
    assert(dup2(saved,STDOUT_FILENO)>=0); close(saved); clearerr(stdout);
    assert(run(1,"--version")==0);
    puts("production parser, request, ENOMEM/ENOSPC/EACCES/ENOSYS and rollback fixtures passed");
    return 0;
}
