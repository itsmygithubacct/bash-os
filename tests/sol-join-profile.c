/* Instrument the production translation unit; profile builds are never timed
   as throughput results. Build with -finstrument-functions -Wl,-Bsymbolic. */
#define join_builtin sol_join_impl
#define join_struct sol_join_production_struct
#include "../loadables/join.c"
#undef join_builtin
#undef join_struct
#include <time.h>

static unsigned long long split_calls, group_calls, split_ns, group_ns;
static unsigned long long split_start, group_start;
static int profiling;
#define NI __attribute__((no_instrument_function))
static unsigned long long NI now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000 + t.tv_nsec;
}
void NI __cyg_profile_func_enter(void *fn, void *caller)
{
    (void)caller;
    if (!profiling) return;
    if (fn == (void *)bj_split) { split_calls++; split_start = now_ns(); }
    if (fn == (void *)bj_group_add) { group_calls++; group_start = now_ns(); }
}
void NI __cyg_profile_func_exit(void *fn, void *caller)
{
    (void)caller;
    if (!profiling) return;
    if (fn == (void *)bj_split) split_ns += now_ns() - split_start;
    if (fn == (void *)bj_group_add) group_ns += now_ns() - group_start;
}
int NI join_builtin(WORD_LIST *list)
{
    split_calls = group_calls = split_ns = group_ns = 0;
    profiling = 1;
    int rc = sol_join_impl(list);
    profiling = 0;
    fprintf(stderr, "PROFILE split_calls=%llu group_calls=%llu split_ns=%llu group_ns=%llu\n",
            split_calls, group_calls, split_ns, group_ns);
    return rc;
}
/* The production struct above names sol_join_impl after macro expansion. */
struct builtin join_struct = {
    "join", join_builtin, BUILTIN_ENABLED, join_doc, "join FILE1 FILE2", 0
};
