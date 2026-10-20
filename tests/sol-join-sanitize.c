/* Standalone ASan/UBSan entry into the real production builtin. Bash's word
   list and diagnostics are the only host interfaces mocked here. */
#include <stdarg.h>
#include "../loadables/join.c"

void builtin_error (const char *fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    fputs ("join: ", stderr);
    vfprintf (stderr, fmt, ap);
    fputc ('\n', stderr);
    va_end (ap);
}
void builtin_usage (void) { fputs ("join: usage error\n", stderr); }

int main (int argc, char **argv)
{
    WORD_LIST *list = calloc ((size_t) argc, sizeof (*list));
    WORD_DESC *words = calloc ((size_t) argc, sizeof (*words));
    if (!list || !words) return 2;
    for (int i = 1; i < argc; i++) {
        words[i].word = argv[i];
        list[i].word = &words[i];
        list[i].next = i + 1 < argc ? &list[i + 1] : NULL;
    }
    int count = getenv ("SOL_JOIN_REPEAT") ? atoi (getenv ("SOL_JOIN_REPEAT")) : 1;
    int rc = 0;
    for (int i = 0; i < count && !rc; i++) rc = join_builtin (argc > 1 ? &list[1] : NULL);
    free (words);
    free (list);
    return rc;
}
