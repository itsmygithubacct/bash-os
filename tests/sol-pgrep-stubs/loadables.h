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
/* Bash's $$. The harness is not a shell, so no ancestor is the invoking
   shell and only the harness process itself counts as a shell copy. */
pid_t dollar_dollar_pid;
/* The shell variables shim-prog-name.h reads. The harness has none, so
   diagnostics use the command's own name, as outside the /bin shim. */
typedef struct variable { char *value; int attributes; } SHELL_VAR;
char *this_command_name;
static SHELL_VAR *find_variable(const char *name) { (void) name; return 0; }
#define exported_p(var) ((var)->attributes & 1)
#define array_p(var) ((var)->attributes & 4)
#define assoc_p(var) ((var)->attributes & 64)
#define value_cell(var) ((var)->value)
static int sh_chkwrite(int status) {
    if (fflush(stdout) == EOF || ferror(stdout)) {
        builtin_error("write error");
        clearerr(stdout);
        return EXECUTION_FAILURE;
    }
    return status;
}
#endif
