/* Execute the real pkill entry point and shared backend with Bash ABI stubs.
   Build separately through the build gate. No actual signals are possible. */
#define SOL_PKILL_LINKED
#include "sol-pkill-intercept.c"
#define open sol_open
#define opendir sol_opendir
#define kill sol_kill
#include "../loadables/pgrep.c"
#include "../loadables/pkill.c"

int main(int argc, char **argv)
{
    WORD_LIST *words = calloc(argc, sizeof *words);
    WORD_DESC *descs = calloc(argc, sizeof *descs);
    if (!words || !descs) return 3;
    for (int i = 1; i < argc; i++) {
        descs[i].word = argv[i];
        words[i].word = &descs[i];
        words[i].next = i + 1 < argc ? &words[i + 1] : NULL;
    }
    const char *repeat = getenv("SOL_PKILL_REPEAT");
    int repeats = repeat ? atoi(repeat) : 1;
    int result = 0;
    for (int i = 0; i < repeats; i++)
        result = pkill_builtin(argc > 1 ? &words[1] : NULL);
    free(words);
    free(descs);
    return result;
}
