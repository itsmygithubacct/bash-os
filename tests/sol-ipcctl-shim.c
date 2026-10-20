/* SPDX-License-Identifier: MIT
 * Closed syscall fixture: compile the actual production implementation. None
 * of these three interceptors can reach the kernel or remove a real object.
 */
#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include "loadables.h"

static int fixture_shmctl (int, int, struct shmid_ds *);
static int fixture_msgctl (int, int, struct msqid_ds *);
static int fixture_semctl (int, int, int, ...);
#define shmctl fixture_shmctl
#define msgctl fixture_msgctl
#define semctl fixture_semctl
#ifndef IPCCTL_SOURCE
#define IPCCTL_SOURCE "../loadables/ipcctl.c"
#endif
#include IPCCTL_SOURCE
#undef shmctl
#undef msgctl
#undef semctl

static int ids[] = { 17, 231, 4096 };
static int active[3], calls, bad, error_code, quiet;
static char fixture_trace[1024];
static size_t used;

static int request (int kind, int id, int command, int argument_ok)
{
    static const char *names[] = { "shm", "msg", "sem" };
    calls++;
    if (!quiet) {
        int n = snprintf (fixture_trace + used, sizeof fixture_trace - used, "%s %d %d %d\n",
                          names[kind], id, command, argument_ok);
        if (n < 0 || (size_t)n >= sizeof fixture_trace - used) bad++;
        else used += n;
    }
    if (id != ids[kind] || command != IPC_RMID || !argument_ok) {
        bad++; errno = EINVAL; return -1;
    }
    if (error_code) { errno = error_code; return -1; }
    if (!active[kind]) { errno = EINVAL; return -1; }
    active[kind] = 0;
    return 0;
}
static int fixture_shmctl (int id, int cmd, struct shmid_ds *arg)
{ return request (0, id, cmd, arg == NULL); }
static int fixture_msgctl (int id, int cmd, struct msqid_ds *arg)
{ return request (1, id, cmd, arg == NULL); }
/* IPC_RMID has no fourth argument. Reading a nonexistent vararg is invalid. */
static int fixture_semctl (int id, int semnum, int cmd, ...)
{ return request (2, id, cmd, semnum == 0); }

int ipcctl_fixture_builtin (WORD_LIST *list)
{
    const char *args[6]; int n = 0;
    for (; list && n < 6; list = list->next) args[n++] = list->word->word;
    if (list || !n) return 2;
    if (!strcmp (args[0], "reset") && (n == 1 || n == 6)) {
        if (n == 6) {
            for (int i = 0; i < 3; i++) ids[i] = atoi (args[i + 1]);
            error_code = atoi (args[4]); quiet = atoi (args[5]);
        } else {
            ids[0] = 17; ids[1] = 231; ids[2] = 4096;
            error_code = quiet = 0;
        }
        calls = bad = 0; used = 0; fixture_trace[0] = 0;
        for (int i = 0; i < 3; i++) active[i] = 1;
    } else if (!strcmp (args[0], "trace") && n == 1) {
        printf ("%scalls %d bad %d active %d%d%d\n", fixture_trace, calls, bad,
                active[0], active[1], active[2]);
    } else if (!strcmp (args[0], "verify") && n == 1) {
        return calls != 3 || bad || active[0] || active[1] || active[2];
    } else return 2;
    return 0;
}
static char *fixture_doc[] = { "Private ipcctl syscall fixture control.", NULL };
struct builtin ipcctl_fixture_struct = {
    "ipcctl_fixture", ipcctl_fixture_builtin, BUILTIN_ENABLED, fixture_doc,
    "ipcctl_fixture reset|trace|verify", 0
};
