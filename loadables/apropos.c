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

/* A whatis record reads "NAME[, NAME...] (SECTION) - DESCRIPTION".  Like
   man-db, test each keyword against every page name and, separately, against
   the description, never against the formatted record: "^alp" finds a page
   whose description starts with "alpha", and "^aleph$" finds an alias. */
static int
keyword_matches_name (const char *line, const regex_t *re, const char *pattern)
{
    const char *p = line;
    while (*p && *p != '(')
    {
        const char *start;
        char *name;
        int match;
        while (*p == ',' || isspace ((unsigned char)*p)) p++;
        start = p;
        while (*p && *p != ',' && *p != '(' && !isspace ((unsigned char)*p)) p++;
        if (p == start) break;
        name = malloc ((size_t)(p - start) + 1);
        if (!name) return 0;
        memcpy (name, start, (size_t)(p - start));
        name[p - start] = '\0';
        if (re)
            match = regexec (re, name, 0, NULL, 0) == 0;
        else
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

static const char *
record_description (const char *line)
{
    const char *close = strchr (line, ')');
    const char *dash = close ? strstr (close, " - ") : NULL;
    return dash ? dash + 3 : "";
}

/* With -w the description is matched word by word, as man-db 2.13 does it:
   lower-cased, it is cut at every character that is not a lowercase letter or
   '_', and each piece of two or more characters is matched whole.  A piece is
   only tested when such a character ends it, so a description's last word is
   never tested.  A piece of zero or one characters is passed over by moving
   its start one character, so the piece after a one-letter word keeps the
   separator in front of it (" b_c" in "a b_c d").  These are observed results
   of the reference, reproduced rather than corrected. */
static int
keyword_matches_description_words (const char *desc, const char *pattern)
{
    size_t len = strlen (desc), begin = 0, i;
    char *low = malloc (len + 1);
    int match = 0;
    if (!low) return 0;
    for (i = 0; i <= len; i++) low[i] = (char) tolower ((unsigned char) desc[i]);
    for (i = 0; i < len && !match; i++)
    {
        if (islower ((unsigned char) low[i]) || low[i] == '_') continue;
        if (i <= begin + 1) { begin++; continue; }
        low[i] = '\0';
#ifdef FNM_CASEFOLD
        match = fnmatch (pattern, low + begin, FNM_CASEFOLD) == 0;
#else
        match = fnmatch (pattern, low + begin, 0) == 0;
#endif
        begin = i + 1;
    }
    free (low);
    return match;
}

static int
keyword_matches (const char *line, const regex_t *re, const char *pattern)
{
    if (keyword_matches_name (line, re, pattern)) return 1;
    if (re) return regexec (re, record_description (line), 0, NULL, 0) == 0;
    return keyword_matches_description_words (record_description (line), pattern);
}

int
apropos_builtin (WORD_LIST *list)
{
    int word_match = 0, all = 0, count = 0, compiled = 0, any_found = 0, i;
    int *found = NULL;
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
    found = calloc ((size_t)count, sizeof (*found));
    if (!found)
    {
        builtin_error ("out of memory");
        fclose (f);
        while (compiled) regfree (&patterns[--compiled]);
        free (patterns);
        return EXECUTION_FAILURE;
    }
    while ((n = getline (&line, &cap, f)) != -1)
    {
        /* Test every keyword, even once the record is decided: man-db reports
           each keyword that matched no record, with or without -a. */
        int matched = all;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        for (p = list, i = 0; p; p = p->next, i++)
        {
            int m = keyword_matches (line, word_match ? NULL : &patterns[i], p->word->word);
            if (m) found[i] = 1;
            if (all ? !m : m) matched = !all;
        }
        if (matched) puts (line);
    }
    free (line);
    fclose (f);
    while (compiled) regfree (&patterns[--compiled]);
    free (patterns);
    fflush (stdout);
    for (p = list, i = 0; p; p = p->next, i++)
    {
        if (found[i]) any_found = 1;
        else fprintf (stderr, "%s: nothing appropriate.\n", p->word->word);
    }
    free (found);
    /* man-db fails only when no keyword matched anything, even with -a. */
    if (!any_found) return 16;
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
