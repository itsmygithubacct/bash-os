/* Shared stream parser for /proc/modules and its regression fixture. */
#ifndef BASHKMOD_INVENTORY_H
#define BASHKMOD_INVENTORY_H

static int
bk_list_stream (FILE *in, FILE *out)
{
    char *line = NULL;
    size_t cap = 0;
    int failed = 0;
    while (getline (&line, &cap, in) >= 0) {
        char *fields[5], *save = NULL;
        int n = 0;
        for (char *p = strtok_r (line, " \t\r\n", &save);
             p && n < 5; p = strtok_r (NULL, " \t\r\n", &save))
            fields[n++] = p;
        if (n == 5 && fprintf (out, "%s %s %s %s %s\n", fields[0],
                               fields[1], fields[2], fields[3], fields[4]) < 0) {
            failed = 1;
            break;
        }
    }
    if (ferror (in) || !feof (in))
        failed = 1;
    free (line);
    return failed ? -1 : 0;
}
#endif
