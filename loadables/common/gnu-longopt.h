/* SPDX-License-Identifier: MIT */
/* GNU getopt_long option scanning over a bash WORD_LIST, for loadables that
   follow coreutils: short clusters ("-rf"), "-oARG"/"-o ARG", optional
   short arguments ("o::" takes only the rest of its word), long options
   in the "--name=value" and "--name value" forms, unambiguous prefixes
   ("--rec"), "--" ending the options, and operands collected in order
   while options after them are still recognised (unless POSIXLY_CORRECT
   is set). Diagnostics are glibc's, followed by coreutils' "Try 'PROG
   --help' for more information." line; the caller then returns status 1.
   Also keyword-argument matching (bos_argmatch) and the backup helpers
   (-b/--backup/-S) shared by cp, install, ln and mv. Written for bash-os
   from the coreutils manual, POSIX and observed GNU behaviour. */
#ifndef BASHOS_GNU_LONGOPT_H
#define BASHOS_GNU_LONGOPT_H

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "gnu-quote.h"

enum { BOS_NO_ARG, BOS_REQ_ARG, BOS_OPT_ARG };

/* Values for --help and --version; a caller's own long-only options use
   values from BOS_OPT_FIRST upward. */
enum { BOS_OPT_ERROR = '?', BOS_OPT_HELP = 0x100, BOS_OPT_VERSION, BOS_OPT_FIRST = 0x110 };

struct bos_longopt
{
    const char *name;           /* without the leading "--" */
    int has_arg;                /* BOS_NO_ARG, BOS_REQ_ARG or BOS_OPT_ARG */
    int val;
};

typedef struct
{
    const char *prog;                   /* name used in diagnostics */
    const char *shortopts;              /* "ab:c::" as for getopt */
    const struct bos_longopt *longopts; /* ends with a NULL name; may be NULL */
    WORD_LIST *next;                    /* next word to examine */
    const char *cluster;                /* rest of a short-option cluster */
    const char *optarg;                 /* argument of the last option */
    const char *word;                   /* the word that held the last option */
    const char *longname;               /* full name of the last long option */
    int optopt;                         /* the last short option character */
    int ended;                          /* "--" seen, or POSIXLY_CORRECT stop */
    int no_hint;                        /* the caller prints the help hint */
    int posix;
    char **operands;                    /* operands, in order; NULL-terminated */
    int noperands, cap;
} bos_getopt;

static inline void
bos_getopt_init (bos_getopt *g, const char *prog, const char *shortopts,
                 const struct bos_longopt *longopts, WORD_LIST *list)
{
    memset (g, 0, sizeof *g);
    g->prog = prog;
    g->shortopts = shortopts;
    g->longopts = longopts;
    g->next = list;
    g->posix = getenv ("POSIXLY_CORRECT") != NULL;
}

static inline void
bos_getopt_free (bos_getopt *g)
{
    free (g->operands);
    g->operands = NULL;
    g->noperands = g->cap = 0;
}

/* coreutils' usage (EXIT_FAILURE) tail. */
static inline void
bos_try_help (const char *prog)
{
    fflush (stdout);
    fprintf (stderr, "Try '%s --help' for more information.\n", prog);
}

static inline int
bos_getopt_operand (bos_getopt *g, char *word)
{
    if (g->noperands + 1 >= g->cap)
    {
        int cap = g->cap ? g->cap * 2 : 16;
        char **v = realloc (g->operands, (size_t) cap * sizeof *v);
        if (v == NULL)
        {
            builtin_error ("memory exhausted");
            return -1;
        }
        g->operands = v;
        g->cap = cap;
    }
    g->operands[g->noperands++] = word;
    g->operands[g->noperands] = NULL;
    return 0;
}

static inline int
bos_getopt_long (bos_getopt *g, const char *word)
{
    const char *name = word + 2, *eq = strchr (name, '=');
    size_t len = eq ? (size_t) (eq - name) : strlen (name);
    const struct bos_longopt *found = NULL, *o;
    int ambiguous = 0;

    for (o = g->longopts; o && o->name; o++)
        if (strncmp (o->name, name, len) == 0)
        {
            if (strlen (o->name) == len)
            {
                found = o;
                ambiguous = 0;
                break;
            }
            if (found == NULL)
                found = o;
            else if (found->has_arg != o->has_arg || found->val != o->val)
                ambiguous = 1;
        }
    if (ambiguous)
    {
        size_t size = strlen (word) + 64, at;
        char *text;

        for (o = g->longopts; o->name; o++)
            size += strlen (o->name) + 5;
        text = malloc (size);
        if (text == NULL)
        {
            builtin_error ("memory exhausted");
            return BOS_OPT_ERROR;
        }
        at = (size_t) snprintf (text, size, "option '%s' is ambiguous; possibilities:", word);
        for (o = g->longopts; o->name; o++)
            if (strncmp (o->name, name, len) == 0)
                at += (size_t) snprintf (text + at, size - at, " '--%s'", o->name);
        builtin_error ("%s", text);
        free (text);
        if (!g->no_hint)
            bos_try_help (g->prog);
        return BOS_OPT_ERROR;
    }
    if (found == NULL)
    {
        builtin_error ("unrecognized option '%s'", word);
        if (!g->no_hint)
            bos_try_help (g->prog);
        return BOS_OPT_ERROR;
    }
    g->longname = found->name;
    g->optarg = NULL;
    if (eq)
    {
        if (found->has_arg == BOS_NO_ARG)
        {
            builtin_error ("option '--%s' doesn't allow an argument", found->name);
            if (!g->no_hint)
                bos_try_help (g->prog);
            return BOS_OPT_ERROR;
        }
        g->optarg = eq + 1;
    }
    else if (found->has_arg == BOS_REQ_ARG)
    {
        if (g->next == NULL)
        {
            builtin_error ("option '--%s' requires an argument", found->name);
            if (!g->no_hint)
                bos_try_help (g->prog);
            return BOS_OPT_ERROR;
        }
        g->optarg = g->next->word->word;
        g->next = g->next->next;
    }
    return found->val;
}

/* The next option: its character or long value, -1 when the words are
   exhausted (operands are then in g->operands), or BOS_OPT_ERROR after a
   diagnostic. */
static inline int
bos_getopt_next (bos_getopt *g)
{
    const char *spec;
    int c;

    g->optarg = NULL;
    g->longname = NULL;
    while (g->cluster == NULL || *g->cluster == '\0')
    {
        char *word;

        g->cluster = NULL;
        if (g->next == NULL)
            return -1;
        word = g->next->word->word;
        g->next = g->next->next;
        if (g->ended || word[0] != '-' || word[1] == '\0')
        {
            if (bos_getopt_operand (g, word) < 0)
                return BOS_OPT_ERROR;
            if (g->posix)
                g->ended = 1;
            continue;
        }
        g->word = word;
        if (word[1] == '-')
        {
            if (word[2] == '\0')
            {
                g->ended = 1;
                continue;
            }
            return bos_getopt_long (g, word);
        }
        g->cluster = word + 1;
    }
    c = (unsigned char) *g->cluster++;
    g->optopt = c;
    spec = c == ':' ? NULL : strchr (g->shortopts, c);
    if (spec == NULL)
    {
        builtin_error ("invalid option -- '%c'", c);
        if (!g->no_hint)
            bos_try_help (g->prog);
        return BOS_OPT_ERROR;
    }
    if (spec[1] == ':')
    {
        if (*g->cluster)
            g->optarg = g->cluster;
        else if (spec[2] != ':')
        {
            if (g->next == NULL)
            {
                builtin_error ("option requires an argument -- '%c'", c);
                if (!g->no_hint)
                    bos_try_help (g->prog);
                return BOS_OPT_ERROR;
            }
            g->optarg = g->next->word->word;
            g->next = g->next->next;
        }
        g->cluster = NULL;
    }
    return c;
}


/* ---- keyword arguments ("--backup=numbered", "--interactive=once") ----
   Written for bash-os from the coreutils manual and observed GNU behaviour:
   an argument names a keyword exactly, or is a prefix of keywords that all
   mean the same thing; otherwise the diagnostic lists the keywords, with
   synonyms (adjacent names sharing a value) on one line. */

static inline void
bos_argmatch_list (const char *const *names, const int *vals)
{
    size_t i;

    fputs ("Valid arguments are:", stderr);
    for (i = 0; names[i]; i++)
    {
        char *q = bos_quote (names[i]);
        if (i == 0 || vals[i] != vals[i - 1])
            fprintf (stderr, "\n  - %s", q ? q : names[i]);
        else
            fprintf (stderr, ", %s", q ? q : names[i]);
        free (q);
    }
    fputc ('\n', stderr);
}

static inline int
bos_argmatch (const char *prog, const char *context, const char *arg,
              const char *const *names, const int *vals)
{
    size_t i, len = strlen (arg);
    int found = -1, ambiguous = 0;
    char *qa, *qc;

    for (i = 0; names[i]; i++)
        if (strncmp (names[i], arg, len) == 0)
        {
            if (names[i][len] == '\0')
                return vals[i];
            if (found < 0)
                found = (int) i;
            else if (vals[found] != vals[i])
                ambiguous = 1;
        }
    if (found >= 0 && !ambiguous)
        return vals[found];
    fflush (stdout);
    qa = bos_quote (arg);
    qc = bos_quote (context);
    builtin_error ("%s argument %s for %s", ambiguous ? "ambiguous" : "invalid",
                   qa ? qa : arg, qc ? qc : context);
    free (qa);
    free (qc);
    bos_argmatch_list (names, vals);
    if (prog)
        bos_try_help (prog);
    return -1;
}

/* ---- backups (-b, --backup[=CONTROL], -S/--suffix) ----
   Behaviour follows the coreutils manual's "Backup options" section and
   observed GNU behaviour: numbered backups are NAME.~N~ with N a decimal
   number without leading zeros; the next one is one more than the highest
   present, of any length. */

enum { BOS_BACKUP_NONE, BOS_BACKUP_SIMPLE, BOS_BACKUP_EXISTING, BOS_BACKUP_NUMBERED };

static const char *const bos_backup_names[] = {
    "none", "off", "simple", "never", "existing", "nil", "numbered", "t", NULL
};
static const int bos_backup_vals[] = {
    BOS_BACKUP_NONE, BOS_BACKUP_NONE, BOS_BACKUP_SIMPLE, BOS_BACKUP_SIMPLE,
    BOS_BACKUP_EXISTING, BOS_BACKUP_EXISTING, BOS_BACKUP_NUMBERED, BOS_BACKUP_NUMBERED
};

static inline int
bos_backup_kind (const char *prog, const char *control)
{
    if (control && *control)
        return bos_argmatch (prog, "backup type", control, bos_backup_names, bos_backup_vals);
    control = getenv ("VERSION_CONTROL");
    if (control == NULL || *control == '\0')
        return BOS_BACKUP_EXISTING;
    return bos_argmatch (prog, "$VERSION_CONTROL", control, bos_backup_names, bos_backup_vals);
}

/* A usable suffix is not empty and has no '/' except in a trailing run;
   anything else means "~". */
static inline int
bos_backup_suffix_ok (const char *suffix)
{
    const char *p;

    if (suffix == NULL || *suffix == '\0' || *suffix == '/')
        return 0;
    for (p = suffix; *p; p++)
        if (*p == '/' && p[1] != '/' && p[1] != '\0')
            return 0;
    return 1;
}

static inline const char *
bos_backup_suffix (const char *suffix)
{
    if (suffix == NULL)
        suffix = getenv ("SIMPLE_BACKUP_SUFFIX");
    return bos_backup_suffix_ok (suffix) ? suffix : "~";
}

/* The highest N among DIR's entries named BASE.~N~, as decimal text in a
   malloc'd string, or NULL when there are none (errno 0) or on error. */
static inline char *
bos_backup_highest (const char *dir, const char *base)
{
    size_t blen = strlen (base), best_len = 0;
    const char *best = NULL;
    char *result = NULL;
    struct dirent *de;
    DIR *d = opendir (dir);

    if (d == NULL)
    {
        errno = 0;
        return NULL;
    }
    while ((de = readdir (d)) != NULL)
    {
        const char *n = de->d_name, *digits, *p;
        size_t len;

        if (strncmp (n, base, blen) != 0 || n[blen] != '.' || n[blen + 1] != '~')
            continue;
        digits = n + blen + 2;
        if (*digits < '1' || *digits > '9')
            continue;
        for (p = digits; *p >= '0' && *p <= '9'; p++)
            ;
        if (p[0] != '~' || p[1] != '\0')
            continue;
        len = (size_t) (p - digits);
        if (best == NULL || len > best_len || (len == best_len && memcmp (digits, best, len) > 0))
        {
            char *copy = malloc (len + 1);
            if (copy == NULL)
            {
                free (result);
                closedir (d);
                errno = ENOMEM;
                return NULL;
            }
            memcpy (copy, digits, len);
            copy[len] = '\0';
            free (result);
            result = copy;
            best = result;
            best_len = len;
        }
    }
    closedir (d);
    errno = 0;
    return result;
}

static inline char *
bos_backup_name (const char *file, int kind, const char *suffix)
{
    const char *slash, *base;
    char *dir, *highest = NULL, *name;
    size_t flen = strlen (file);

    if (kind != BOS_BACKUP_SIMPLE && kind != BOS_BACKUP_EXISTING && kind != BOS_BACKUP_NUMBERED)
    {
        errno = EINVAL;
        return NULL;
    }
    suffix = bos_backup_suffix (suffix);
    if (kind != BOS_BACKUP_SIMPLE)
    {
        /* The directory part keeps its own slashes; "/f" scans "/". */
        slash = strrchr (file, '/');
        base = slash ? slash + 1 : file;
        if (slash == NULL)
            dir = strdup (".");
        else if (slash == file)
            dir = strdup ("/");
        else if ((dir = malloc ((size_t) (slash - file) + 1)) != NULL)
        {
            memcpy (dir, file, (size_t) (slash - file));
            dir[slash - file] = '\0';
        }
        if (dir == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }
        highest = bos_backup_highest (dir, base);
        free (dir);
        if (highest == NULL && errno)
            return NULL;
        if (highest == NULL && kind == BOS_BACKUP_EXISTING)
            kind = BOS_BACKUP_SIMPLE;
        else
            kind = BOS_BACKUP_NUMBERED;
    }
    if (kind == BOS_BACKUP_SIMPLE)
    {
        name = malloc (flen + strlen (suffix) + 1);
        if (name == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }
        memcpy (name, file, flen);
        strcpy (name + flen, suffix);
        return name;
    }
    {
        /* NAME.~N+1~, adding one to the decimal text. */
        size_t hlen = highest ? strlen (highest) : 0, i;
        char *num = malloc (hlen + 2);
        if (num == NULL)
        {
            free (highest);
            errno = ENOMEM;
            return NULL;
        }
        if (highest == NULL)
            strcpy (num, "1");
        else
        {
            int carry = 1;
            memcpy (num + 1, highest, hlen + 1);
            for (i = hlen; i > 0 && carry; i--)
            {
                if (num[i] == '9')
                    num[i] = '0';
                else
                {
                    num[i]++;
                    carry = 0;
                }
            }
            if (carry)
                num[0] = '1';
            else
                memmove (num, num + 1, hlen + 1);
        }
        free (highest);
        name = malloc (flen + strlen (num) + 5);
        if (name == NULL)
        {
            free (num);
            errno = ENOMEM;
            return NULL;
        }
        sprintf (name, "%s.~%s~", file, num);
        free (num);
        return name;
    }
}

#endif
