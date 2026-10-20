/* Read-only /proc path adapter for an unmodified dynamic procps pgrep.
   No data or matching is synthesized here: both implementations read the same
   fixture bytes. Build separately through the build gate, never in a benchmark. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

static const char *mapped(const char *path, char buffer[PATH_MAX])
{
    const char *root = getenv("BASHOS_PROC_ROOT");
    if (root && (!strcmp(path,"/proc") || !strncmp(path,"/proc/",6))) {
        int n=snprintf(buffer,PATH_MAX,"%s%s",root,path+5);
        if (n>=0 && n<PATH_MAX) return buffer;
    }
    return path;
}
#define OPEN_WRAPPER(name) \
int name(const char *path, int flags, ...) { \
    static int (*real)(const char *,int,...); \
    if (!real) real=dlsym(RTLD_NEXT,#name); \
    mode_t mode=0; \
    if ((flags&O_CREAT) || ((flags&O_TMPFILE)==O_TMPFILE)) { \
        va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap); \
    } \
    char buffer[PATH_MAX]; return real(mapped(path,buffer),flags,mode); \
}
OPEN_WRAPPER(open)
OPEN_WRAPPER(open64)
#define OPENAT_WRAPPER(name) \
int name(int fd, const char *path, int flags, ...) { \
    static int (*real)(int,const char *,int,...); \
    if (!real) real=dlsym(RTLD_NEXT,#name); \
    mode_t mode=0; \
    if ((flags&O_CREAT) || ((flags&O_TMPFILE)==O_TMPFILE)) { \
        va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap); \
    } \
    char buffer[PATH_MAX]; return real(fd,mapped(path,buffer),flags,mode); \
}
OPENAT_WRAPPER(openat)
OPENAT_WRAPPER(openat64)
#define FOPEN_WRAPPER(name) \
FILE *name(const char *path, const char *mode) { \
    static FILE *(*real)(const char *, const char *); \
    if (!real) real=dlsym(RTLD_NEXT,#name); \
    char buffer[PATH_MAX]; return real(mapped(path,buffer),mode); \
}
FOPEN_WRAPPER(fopen)
FOPEN_WRAPPER(fopen64)
DIR *opendir(const char *path) {
    static DIR *(*real)(const char *);
    if (!real) real=dlsym(RTLD_NEXT,"opendir");
    char buffer[PATH_MAX]; return real(mapped(path,buffer));
}
/* libproc2 stats each directory before reading its records. */
#include <sys/stat.h>
int stat(const char *path, struct stat *buf) {
    static int (*real)(const char *,struct stat *);
    if (!real) real=dlsym(RTLD_NEXT,"stat");
    char buffer[PATH_MAX]; return real(mapped(path,buffer),buf);
}
int lstat(const char *path, struct stat *buf) {
    static int (*real)(const char *,struct stat *);
    if (!real) real=dlsym(RTLD_NEXT,"lstat");
    char buffer[PATH_MAX]; return real(mapped(path,buffer),buf);
}
