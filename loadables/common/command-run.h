/* SPDX-License-Identifier: MIT */
/* Child-side dispatch for commands run by env, nice, nohup, xargs and find.
   Arguments are already split: never send them through the shell parser. */
#ifndef BASHOS_COMMAND_RUN_H
#define BASHOS_COMMAND_RUN_H

#include "execute_cmd.h"
#include "jobs.h"
#include "trap.h"
#include "flags.h"
#include "unwind_prot.h"

/* Set by patches/builtin-sole-child.patch in the child bash forks for one
   simple command (`CMD &`, a pipeline element). Weak, so a harness linked
   without that shell patch still links and simply never sees one. */
extern sh_builtin_func_t *bashos_sole_builtin;
extern int bashos_sole_depth;
#pragma weak bashos_sole_builtin
#pragma weak bashos_sole_depth

/* True, once, when the running builtin is the whole job of this process:
   it is the command bash forked a child for, at that command's own depth
   (not reached through eval, source, command or a function). A wrapper may
   then run its child side here instead of forking, so the command replaces
   this process exactly as GNU env/nice/nohup exec it. */
static int
bos_owns_process (void)
{
    if (!&bashos_sole_builtin || !&bashos_sole_depth || !bashos_sole_builtin)
        return 0;
    if (bashos_sole_builtin != this_shell_builtin || executing_builtin != bashos_sole_depth)
        return 0;
    bashos_sole_builtin = 0;
    return 1;
}

/* A raw fork must not let a builtin jump into the caller's function, loop,
   trap or cleanup stack. Run this before applying child-specific signals. */
static void
bos_prepare_child (void)
{
    interactive = interactive_shell = login_shell = 0;
    function_trace_mode = error_trace_mode = 0;
    reset_terminating_signals ();
    restore_original_signals ();
    without_job_control ();
    clear_unwind_protect_list (0);
    subshell_environment |= SUBSHELL_FORK;
    subshell_level++;
    return_catch_flag = loop_level = running_trap = 0;
    funcnest = evalnest = sourcenest = 0;
}

/* Only env supplies a replacement environment. A fresh variable context also
   removes inherited readonly/nameref attributes and function-local bindings.
   Keep the inherited allocations alive until _exit: argv/envp can refer to
   them, and this process will never return to the calling shell. */
static void
bos_builtin_environment (char **envp)
{
    extern HASH_TABLE *invalid_env;
    variable_context = 0;
    temporary_env = invalid_env = NULL;
    shell_variables = global_variables = new_var_context (NULL, 0);
    shell_variables->table = hash_create (0);
    shell_functions = hash_create (0);
    for (char **entry = envp; *entry; entry++) {
        const char *eq = strchr (*entry, '=');
        if (!eq || eq == *entry)
            continue;
        char *name = savestring (*entry);
        name[eq - *entry] = '\0';
        SHELL_VAR *var = bind_variable (name, eq + 1, 0);
        if (var)
            VSETATTR (var, att_exported);
        free (name);
    }
    array_needs_making = 1;
    maybe_make_export_env ();
}

/* Returns only when PROGRAM is not an enabled builtin (an enabled printf
   runs as `coreutils printf` when that bundle is present). The caller then uses
   its existing exec path, including its own 126/127 error handling. A slash
   always requests an external executable. PROGRAM is separate from argv[0]
   so env --argv0 cannot change which builtin is selected. */
static void
bos_run_builtin (const char *program, char **argv, char **envp)
{
    struct builtin *entry;
    if (strchr (program, '/') || !(entry = builtin_address_internal (program, 0)))
        return;
    /* The external printf these wrappers stand in for is coreutils printf
       (no -v, %q as 'a b'), not Bash's builtin: while printf is enabled,
       run `coreutils printf`. A disabled printf still reaches PATH. */
    const char *verb = NULL;
    if (!strcmp (program, "printf")) {
        struct builtin *cu = builtin_address_internal ("coreutils", 0);
        if (!cu)
            cu = builtin_address_internal ("bashcoreutils", 0);
        if (cu) {
            entry = cu;
            verb = "printf";
        }
    }

    /* A wrapper may have called chdir without using Bash's cd builtin. */
    free (the_current_working_directory);
    the_current_working_directory = NULL;

    /* exit/eval and fatal builtin errors use Bash's non-local exit path. */
    int jump = setjmp_nosigs (top_level);
    int status;
    if (jump) {
        status = (jump == EXITPROG || jump == EXITBLTIN || jump == ERREXIT)
            ? last_command_exit_value : EXECUTION_FAILURE;
    } else {
        if (envp)
            bos_builtin_environment (envp);
        WORD_LIST *words = strvec_to_word_list (argv + 1, 1, 0);
        if (verb)
            words = make_word_list (make_word (verb), words);
        this_command_name = (char *) program;
        current_builtin = entry;
        this_shell_builtin = entry->function;
        executing_builtin = 1;
        reset_internal_getopt ();
        status = entry->function (words);
        dispose_words (words);
    }
    if (fflush (stdout) == EOF && status == EXECUTION_SUCCESS)
        status = EXECUTION_FAILURE;
    fflush (stderr);
    _exit (status == EX_USAGE ? EX_BADUSAGE : status);
}

#endif
