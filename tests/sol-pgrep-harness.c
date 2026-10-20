/* Compile this translation unit under ASan/UBSan through the campaign build
   gate. Only the Bash ABI is stubbed; the entire production backend executes.
   CLI: harness MODE ARG...; MODE is pgrep, pkill, killall or killall5. */
#include "../loadables/pgrep.c"

int main (int argc, char **argv)
{
    if (argc < 2) return 2;
    int mode = !strcmp (argv[1], "pkill") ? BP_MODE_KILL :
               !strcmp (argv[1], "killall") ? BP_MODE_KILLALL :
               !strcmp (argv[1], "killall5") ? BP_MODE_KILLALL5 : BP_MODE_GREP;
    WORD_LIST *words = calloc (argc, sizeof *words);
    WORD_DESC *descs = calloc (argc, sizeof *descs);
    if (!words || !descs) return 3;
    for (int i = 2; i < argc; i++) {
        descs[i].word = argv[i];
        words[i].word = &descs[i];
        words[i].next = i + 1 < argc ? &words[i + 1] : NULL;
    }
    int result = 0;
    /* Explicitly repeat successful and failed dispatch in one address space. */
    const char *repeat_env = getenv ("SOL_PGREP_REPEAT");
    int repeats = repeat_env ? atoi (repeat_env) : 1;
    for (int i = 0; i < repeats; i++)
        result = bp_dispatch (argc > 2 ? &words[2] : NULL, mode);
    free (words);
    free (descs);
    return result;
}
