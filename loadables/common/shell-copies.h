/* SPDX-License-Identifier: MIT */
/* Recognise copies of the invoking shell, for commands that signal processes
   by name and must leave the shell that runs them alone. */
#ifndef BASHOS_SHELL_COPIES_H
#define BASHOS_SHELL_COPIES_H

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern pid_t dollar_dollar_pid;

/* Copies of the invoking shell are never signalled.  Besides the shell
   itself those are the subshells between it and this invocation (a pipeline
   element, a command substitution), and their children that have been forked
   but have not yet executed a program, which still carry the shell's name.  */
#define KA_MAX_ANCESTORS 32
static long ka_ancestors[KA_MAX_ANCESTORS];
static int ka_nancestors;

static long
ka_parent_of (long pid)
{
    char path[64], buf[512];
    long ppid = -1;
    char *p;
    FILE *fp;
    snprintf (path, sizeof path, "/proc/%ld/stat", pid);
    fp = fopen (path, "r");
    if (!fp)
        return -1;
    if (!fgets (buf, sizeof buf, fp)) { fclose (fp); return -1; }
    fclose (fp);
    p = strrchr (buf, ')');
    if (!p || sscanf (p + 1, " %*c %ld", &ppid) != 1)
        return -1;
    return ppid;
}

static void
ka_collect_shell_copies (pid_t self)
{
    long pid = (long) self;
    ka_nancestors = 0;
    while (pid > 1 && ka_nancestors < KA_MAX_ANCESTORS) {
        ka_ancestors[ka_nancestors++] = pid;
        if (pid == (long) dollar_dollar_pid)
            return;
        pid = ka_parent_of (pid);
    }
    /* The invoking shell is not an ancestor: keep only this process. */
    ka_nancestors = 1;
    ka_ancestors[0] = (long) self;
}

static int
ka_child_of_shell_copy (int pid)
{
    long ppid = ka_parent_of ((long) pid);
    for (int k = 0; k < ka_nancestors; k++)
        if (ka_ancestors[k] == ppid)
            return 1;
    return 0;
}

static int
ka_same_file_bytes (const char *a, const char *b)
{
    char x[4096], y[4096];
    size_t nx, ny;
    FILE *fa = fopen (a, "r"), *fb = fopen (b, "r");
    int same = 0;
    if (fa && fb) {
        nx = fread (x, 1, sizeof x, fa);
        ny = fread (y, 1, sizeof y, fb);
        same = nx == ny && nx > 0 && memcmp (x, y, nx) == 0;
    }
    if (fa) fclose (fa);
    if (fb) fclose (fb);
    return same;
}

static int
ka_is_shell_copy (int pid)
{
    char path[64];
    struct stat mine, theirs;
    long ppid;
    int k;
    for (k = 0; k < ka_nancestors; k++)
        if (ka_ancestors[k] == (long) pid)
            return 1;
    ppid = ka_parent_of ((long) pid);
    for (k = 0; k < ka_nancestors; k++)
        if (ka_ancestors[k] == ppid)
            break;
    if (k == ka_nancestors)
        return 0;
    /* A forked copy runs the same executable with the same argument vector;
       a script or program the shell started has its own.  */
    snprintf (path, sizeof path, "/proc/%d/exe", pid);
    if (stat (path, &theirs) < 0 || stat ("/proc/self/exe", &mine) < 0)
        return 0;
    if (mine.st_dev != theirs.st_dev || mine.st_ino != theirs.st_ino)
        return 0;
    snprintf (path, sizeof path, "/proc/%d/cmdline", pid);
    return ka_same_file_bytes (path, "/proc/self/cmdline");
}

#endif
