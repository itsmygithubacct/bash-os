/* Run only in a disposable VM. Exercises the same parser used by list. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../loadables/common/bashkmod-inventory.h"

int main (void)
{
    FILE *in = tmpfile (), *out = tmpfile ();
    char *got = NULL, *expected = NULL;
    size_t expected_cap = 0;
    if (!in || !out) return 1;
    FILE *want = open_memstream (&expected, &expected_cap);
    if (!want) return 1;
    fputs ("long 42 2 ", in);
    fputs ("long 42 2 ", want);
    for (int i = 0; i < 300; i++) {
        fprintf (in, "dependent%d,", i);
        fprintf (want, "dependent%d,", i);
    }
    fputs (" Live 0x1234\nshort 1 -1 - Live 0x0\n", in);
    fputs (" Live\nshort 1 -1 - Live\n", want);
    fclose (want);
    rewind (in);
    if (bk_list_stream (in, out) || fflush (out) || fseek (out, 0, SEEK_SET)) return 1;
    size_t len = strlen (expected), off = 0;
    got = malloc (len + 1);
    if (!got) return 1;
    off = fread (got, 1, len + 1, out);
    int ok = off == len && memcmp (got, expected, len) == 0 && !ferror (out);
    free (got); free (expected); fclose (in); fclose (out);
    return ok ? 0 : 1;
}
