/* SPDX-License-Identifier: MIT
 * Test-only independent Linux kernel metadata oracle and owned-object cleanup.
 * Load into the tested shell; no external command is needed with PATH empty.
 */
#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "loadables.h"
union check_semun { int val; struct semid_ds *buf; };
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "kernel check failed: %s (errno %d)\n", #x, errno); ok = 0; } } while (0)
int ipcmk_check_builtin(WORD_LIST *list)
{
    const char *args[4];
    int n = 0, ok = 1, id = -1;
    char line[512], expected[512], value[256];
    while (list && n < 4) { args[n++] = list->word->word; list = list->next; }
    if (n != 4 || list) return 1;
    const char *kind = args[0];
    size_t amount = strtoull(args[2], NULL, 10);
    unsigned mode = strtoul(args[3], NULL, 8);
    FILE *f = fopen(args[1], "r");
    if (!f) return 1;
    int got = fgets(line, sizeof line, f) != NULL;
    CHECK(got);
    CHECK(fgetc(f) == EOF);
    fclose(f);
    if (!got) return 1;
    const char *label = strstr(kind, "shm") ? "Shared memory" : strstr(kind, "sem") ? "Semaphore" : "Message queue";
    if (strncmp(kind, "posix-", 6)) {
        const char *colon = strchr(line, ':');
        if (!colon || sscanf(colon + 1, "%d", &id) != 1 || id < 0) return 1;
        snprintf(expected, sizeof expected, "%s id: %d\n", label, id);
        CHECK(!strcmp(line, expected));
        if (!strcmp(kind, "shm")) {
            struct shmid_ds ds = {0};
            CHECK(shmctl(id, IPC_STAT, &ds) == 0);
            CHECK(ds.shm_perm.uid == getuid() && ds.shm_perm.cuid == getuid());
            CHECK((ds.shm_perm.mode & 0777) == mode && ds.shm_segsz == amount);
            CHECK(ds.shm_nattch == 0 && ds.shm_perm.__key == IPC_PRIVATE);
            CHECK(shmctl(id, IPC_RMID, NULL) == 0);
            errno = 0; CHECK(shmctl(id, IPC_STAT, &ds) == -1 && (errno == EINVAL || errno == EIDRM));
        } else if (!strcmp(kind, "sem")) {
            struct semid_ds ds = {0}; union check_semun arg = {.buf = &ds};
            CHECK(semctl(id, 0, IPC_STAT, arg) == 0);
            CHECK(ds.sem_perm.uid == getuid() && ds.sem_perm.cuid == getuid());
            CHECK(ds.sem_perm.__key == IPC_PRIVATE);
            CHECK((ds.sem_perm.mode & 0777) == mode && ds.sem_nsems == amount);
            CHECK(semctl(id, 0, IPC_RMID) == 0);
            errno = 0; CHECK(semctl(id, 0, IPC_STAT, arg) == -1 && (errno == EINVAL || errno == EIDRM));
        } else if (!strcmp(kind, "msg")) {
            struct msqid_ds ds = {0};
            CHECK(msgctl(id, IPC_STAT, &ds) == 0);
            CHECK(ds.msg_perm.uid == getuid() && ds.msg_perm.cuid == getuid());
            CHECK(ds.msg_perm.__key == IPC_PRIVATE);
            CHECK((ds.msg_perm.mode & 0777) == mode && ds.msg_qnum == 0 && ds.msg_qbytes > 0);
            CHECK(msgctl(id, IPC_RMID, NULL) == 0);
            errno = 0; CHECK(msgctl(id, IPC_STAT, &ds) == -1 && (errno == EINVAL || errno == EIDRM));
        } else return 1;
    } else {
        const char *colon = strchr(line, ':');
        if (!colon || sscanf(colon + 1, "%255s", value) != 1 || value[0] != '/') return 1;
        snprintf(expected, sizeof expected, "%s name: %s\n", label, value);
        CHECK(!strcmp(line, expected));
        struct stat st = {0};
        if (!strcmp(kind, "posix-shm")) {
            int fd = shm_open(value, O_RDONLY, 0);
            CHECK(fd >= 0);
            if (fd >= 0) { CHECK(fstat(fd, &st) == 0); CHECK(st.st_uid == getuid() && (st.st_mode & 0777) == mode && st.st_size == (off_t)amount); CHECK(close(fd) == 0); }
            CHECK(shm_unlink(value) == 0);
            errno = 0; fd = shm_open(value, O_RDONLY, 0); CHECK(fd == -1 && errno == ENOENT); if (fd >= 0) close(fd);
        } else if (!strcmp(kind, "posix-sem")) {
            sem_t *sem = sem_open(value, 0); int count = -1;
            CHECK(sem != SEM_FAILED);
            if (sem != SEM_FAILED) { CHECK(sem_getvalue(sem, &count) == 0 && count == 0); CHECK(sem_close(sem) == 0); }
            snprintf(expected, sizeof expected, "/dev/shm/sem.%s", value + 1);
            CHECK(stat(expected, &st) == 0 && st.st_uid == getuid() && (st.st_mode & 0777) == mode);
            CHECK(sem_unlink(value) == 0);
            errno = 0; sem = sem_open(value, 0); CHECK(sem == SEM_FAILED && errno == ENOENT); if (sem != SEM_FAILED) sem_close(sem);
        } else if (!strcmp(kind, "posix-msg")) {
            mqd_t mq = mq_open(value, O_RDONLY | O_NONBLOCK); struct mq_attr attr = {0};
            CHECK(mq != (mqd_t)-1);
            if (mq != (mqd_t)-1) { CHECK(mq_getattr(mq, &attr) == 0 && attr.mq_curmsgs == 0 && attr.mq_maxmsg > 0 && attr.mq_msgsize > 0); CHECK(fstat(mq, &st) == 0 && st.st_uid == getuid() && (st.st_mode & 0777) == mode); CHECK(mq_close(mq) == 0); }
            CHECK(mq_unlink(value) == 0);
            errno = 0; mq = mq_open(value, O_RDONLY); CHECK(mq == (mqd_t)-1 && errno == ENOENT); if (mq != (mqd_t)-1) mq_close(mq);
        } else return 1;
    }
    return ok ? 0 : 1;
}
char *ipcmk_check_doc[] = {"Test-owned metadata and removal oracle", NULL};
struct builtin ipcmk_check_struct = {"ipcmk_check", ipcmk_check_builtin, BUILTIN_ENABLED, ipcmk_check_doc, "ipcmk_check kind output size mode", 0};
