/* SPDX-License-Identifier: MIT */
/* apropos(1) query over the shared whatis index. */
#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <fnmatch.h>
#include <ctype.h>
#include "loadables.h"

extern FILE *bm_open_whatis (void);
extern char *apropos_doc[];

/* -w matches a complete comma-separated name, not the description or
   section.  Copy the token to give fnmatch a terminating NUL. */
static int
word_matches (const char *line, const char *pattern)
{
    const char *p = line;
    while (*p && *p != '(')
    {
        const char *start, *end;
        char *name;
        int match;
        while (*p == ',' || isspace ((unsigned char)*p)) p++;
        start = p;
        while (*p && *p != ',' && *p != '(' && !isspace ((unsigned char)*p)) p++;
        end = p;
        if (end == start) break;
        name = malloc ((size_t)(end - start) + 1);
        if (!name) return 0;
        memcpy (name, start, (size_t)(end - start));
        name[end - start] = '\0';
#ifdef FNM_CASEFOLD
        match = fnmatch (pattern, name, FNM_CASEFOLD) == 0;
#else
        match = fnmatch (pattern, name, 0) == 0;
#endif
        free (name);
        if (match) return 1;
    }
    return 0;
}

int
apropos_builtin (WORD_LIST *list)
{
    int word_match = 0, all = 0, hits = 0, count = 0, compiled = 0;
    WORD_LIST *p;
    regex_t *patterns = NULL;
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    while (list && list->word && list->word->word[0] == '-' && list->word->word[1])
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-w") || !strcmp (w, "--wildcard") || !strcmp (w, "--word"))
            { word_match = 1; list = list->next; continue; }
        if (!strcmp (w, "-a") || !strcmp (w, "--and"))
            { all = 1; list = list->next; continue; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help"))
            { char **lp; for (lp = apropos_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-V") || !strcmp (w, "--version"))
            { puts ("apropos 0.1 (bash-os whatis search)"); return EXECUTION_SUCCESS; }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (!list || !list->word) { puts ("apropos what?"); return EXECUTION_FAILURE; }
    for (p = list; p; p = p->next) count++;
    if (!word_match)
    {
        patterns = calloc ((size_t)count, sizeof (*patterns));
        if (!patterns) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
        for (p = list; p; p = p->next)
        {
            int err = regcomp (&patterns[compiled], p->word->word,
                               REG_EXTENDED | REG_ICASE | REG_NOSUB);
            if (err)
            {
                char message[256];
                regerror (err, &patterns[compiled], message, sizeof message);
                builtin_error ("%s: %s", p->word->word, message);
                while (compiled) regfree (&patterns[--compiled]);
                free (patterns);
                return EXECUTION_FAILURE;
            }
            compiled++;
        }
    }
    f = bm_open_whatis ();
    if (!f)
    {
        builtin_error ("no whatis index found under $MANPATH (corpus may be absent)");
        while (compiled) regfree (&patterns[--compiled]);
        free (patterns);
        return EXECUTION_FAILURE;
    }
    while ((n = getline (&line, &cap, f)) != -1)
    {
        int matched = all, i = 0;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        for (p = list; p; p = p->next, i++)
        {
            int m = word_match ? word_matches (line, p->word->word)
                               : regexec (&patterns[i], line, 0, NULL, 0) == 0;
            if (all && !m) { matched = 0; break; }
            if (!all && m) { matched = 1; break; }
        }
        if (matched) { puts (line); hits++; }
    }
    free (line);
    fclose (f);
    while (compiled) regfree (&patterns[--compiled]);
    free (patterns);
    if (!hits)
    {
        for (p = list; p; p = p->next)
            printf ("%s: nothing appropriate.\n", p->word->word);
        return 16;
    }
    return EXECUTION_SUCCESS;
}

char *apropos_doc[] = {
    "Search the whatis index for manpages matching PATTERN.",
    "",
    "    apropos [-a] [-w] PATTERN [PATTERN ...]",
    "",
    "    -a, --and       require all patterns to match",
    "    -w, --wildcard  match wildcard patterns against whole names",
    "",
    "Patterns are case-insensitive extended regular expressions by default.",
    "Multiple patterns match any entry unless -a is given.",
    "Reads the whatis cache from $MANPATH (default /usr/share/man).",
    (char *)NULL
};

struct builtin apropos_struct = {
    "apropos", apropos_builtin, BUILTIN_ENABLED, apropos_doc,
    "apropos [-a] [-w] PATTERN [PATTERN ...]", 0
};
