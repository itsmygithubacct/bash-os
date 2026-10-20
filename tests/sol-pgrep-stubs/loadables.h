#ifndef SOL_PGREP_LOADABLES_H
#define SOL_PGREP_LOADABLES_H
#include <stdarg.h>
#include <stdio.h>
#define EXECUTION_SUCCESS 0
#define EXECUTION_FAILURE 1
#define EX_USAGE 2
#define BUILTIN_ENABLED 1
typedef struct word_desc { char *word; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
struct builtin { const char *name; int (*function)(WORD_LIST *); int flags; char **doc; const char *usage; void *handle; };
static void builtin_usage(void) { }
static void builtin_error(const char *format, ...) {
    va_list ap; va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap); fputc('\n', stderr);
}
#endif
