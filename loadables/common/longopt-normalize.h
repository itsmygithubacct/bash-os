/* SPDX-License-Identifier: MIT */
/* GNU getopt_long argument normalization for builtins whose own option loop
   only knows short options and exact long spellings.

   lon_normalize () rewrites an argument list the way glibc getopt_long reads
   it, so the builtin's existing parser sees a canonical list:

     - a long option may be abbreviated to any unambiguous prefix; an exact
       spelling always wins over a longer name it prefixes;
     - a long option with a short equivalent ("to" = "-l") becomes that short
       option: a required argument (from --opt=VALUE or the next word) follows
       as its own word, an optional one is joined ("-w8");
     - a long-only option ("to" = NULL) becomes its full name, with any
       argument joined as "--name=VALUE";
     - options are moved ahead of operands (GNU permutation) unless
       POSIXLY_CORRECT is in the environment or PERMUTE is 0; an explicit
       "--" is kept so operands after it stay operands.

   Diagnostics follow glibc exactly ("unrecognized option '--x'", "option
   '--x' is ambiguous; possibilities: ...", "requires an argument", "doesn't
   allow an argument"), then "Try 'NAME --help' for more information.".
   Short options are passed through untouched; SHORTSPEC (getopt syntax,
   "b:w::") only tells which of them consume the following text.

   Diagnostics go through builtin_error, unless the caller sets lon_prog
   (a verb of a multi-call builtin): then they are printed exactly as the
   GNU program prints them, "PROG: message", with no shell prefix. */
#ifndef BASHOS_LONGOPT_NORMALIZE_H
#define BASHOS_LONGOPT_NORMALIZE_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern WORD_LIST *make_word_list (WORD_DESC *, WORD_LIST *);
extern WORD_DESC *make_word (const char *);
extern void dispose_words (WORD_LIST *);
extern char *this_command_name;

#define LON_NONE 0
#define LON_REQUIRED 1
#define LON_OPTIONAL 2

struct lon_option {
    const char *name;       /* without the leading "--" */
    int has_arg;            /* LON_NONE, LON_REQUIRED or LON_OPTIONAL */
    const char *to;         /* short replacement such as "-l", or NULL */
};

/* When set, the program name for plain GNU-style diagnostics. */
static const char *lon_prog __attribute__ ((unused));

/* The user-facing command name for diagnostics: bash-os registers some
   builtins as "bashNAME" and the /bin shim maps NAME to them. */
static inline const char *
lon_display_name (void)
{
    if (lon_prog)
        return lon_prog;
    const char *n = this_command_name ? this_command_name : "";
    if (!strncmp (n, "bash", 4) && n[4])
        return n + 4;
    return n;
}

static inline void
lon_error (const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (buf, sizeof buf, fmt, ap);
    va_end (ap);
    if (lon_prog)
        fprintf (stderr, "%s: %s\n", lon_prog, buf);
    else
        builtin_error ("%s", buf);
}

static inline void
lon_try_help (void)
{
    fprintf (stderr, "Try '%s --help' for more information.\n", lon_display_name ());
    fflush (stderr);
}

/* Append WORD (copied) to the list being built at *TAIL. */
static inline void
lon_append (WORD_LIST ***tail, const char *word)
{
    WORD_LIST *node = make_word_list (make_word (word), (WORD_LIST *) NULL);
    **tail = node;
    *tail = &node->next;
}

static inline void
lon_append2 (WORD_LIST ***tail, const char *a, const char *b, size_t blen)
{
    size_t alen = strlen (a);
    char *s = (char *) malloc (alen + blen + 1);
    if (!s)
        return;
    memcpy (s, a, alen);
    memcpy (s + alen, b, blen);
    s[alen + blen] = '\0';
    lon_append (tail, s);
    free (s);
}

/* Find the option named by TEXT[0..LEN). Returns its index, -1 when none
   matches and -2 when the prefix is ambiguous (diagnostic printed). */
static inline int
lon_lookup (const struct lon_option *opts, const char *text, size_t len,
            const char *word)
{
    int found = -1, ambiguous = 0;
    for (int i = 0; opts[i].name; i++) {
        if (strncmp (opts[i].name, text, len))
            continue;
        if (strlen (opts[i].name) == len)
            return i;
        if (found < 0)
            found = i;
        else if (opts[found].has_arg != opts[i].has_arg
                 || (opts[found].to == NULL) != (opts[i].to == NULL)
                 || (opts[found].to && strcmp (opts[found].to, opts[i].to))
                 || (!opts[found].to && strcmp (opts[found].name, opts[i].name)))
            ambiguous = 1;
    }
    if (ambiguous) {
        /* One diagnostic line, as glibc prints it. */
        size_t need = strlen (word) + 1;
        for (int i = 0; opts[i].name; i++)
            if (!strncmp (opts[i].name, text, len))
                need += strlen (opts[i].name) + 5;
        char *poss = (char *) malloc (need);
        if (poss) {
            poss[0] = '\0';
            for (int i = 0; opts[i].name; i++)
                if (!strncmp (opts[i].name, text, len)) {
                    strcat (poss, " '--");
                    strcat (poss, opts[i].name);
                    strcat (poss, "'");
                }
        }
        lon_error ("option '%s' is ambiguous; possibilities:%s", word, poss ? poss : "");
        free (poss);
        return -2;
    }
    return found;
}

static inline int
lon_short_arg (const char *shortspec, char c)
{
    const char *p = c && c != ':' ? strchr (shortspec, c) : NULL;
    if (!p)
        return LON_NONE;
    if (p[1] == ':')
        return p[2] == ':' ? LON_OPTIONAL : LON_REQUIRED;
    return LON_NONE;
}

static inline int
lon_permute_allowed (int permute)
{
    if (!permute)
        return 0;
    SHELL_VAR *v = find_variable ("POSIXLY_CORRECT");
    return !(v && exported_p (v));
}

/* Normalize LIST into a new list at *OUT (free it with dispose_words; NULL
   for an empty result). Returns 0, or -1 after a usage diagnostic. */
static inline int
lon_normalize (WORD_LIST *list, const struct lon_option *opts,
               const char *shortspec, int permute, WORD_LIST **out)
{
    WORD_LIST *opt_head = NULL, **opt_tail = &opt_head;
    WORD_LIST *arg_head = NULL, **arg_tail = &arg_head;
    int moving = lon_permute_allowed (permute), dashdash = 0;

    *out = NULL;
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (w[0] != '-' || w[1] == '\0') {
            if (!moving) break;
            lon_append (&arg_tail, w);
            continue;
        }
        if (w[1] == '-' && w[2] == '\0') {
            dashdash = 1;
            list = list->next;
            break;
        }
        if (w[1] == '-') {
            const char *name = w + 2, *eq = strchr (name, '=');
            size_t len = eq ? (size_t) (eq - name) : strlen (name);
            int i = lon_lookup (opts, name, len, w);
            if (i == -2)
                goto usage;
            if (i < 0) {
                lon_error ("unrecognized option '%s'", w);
                goto usage;
            }
            const struct lon_option *o = &opts[i];
            const char *value = eq ? eq + 1 : NULL;
            if (o->has_arg == LON_NONE && value) {
                lon_error ("option '--%s' doesn't allow an argument", o->name);
                goto usage;
            }
            if (o->has_arg == LON_REQUIRED && !value) {
                if (!list->next) {
                    lon_error ("option '--%s' requires an argument", o->name);
                    goto usage;
                }
                list = list->next;
                value = list->word->word;
            }
            if (o->to) {
                if (o->has_arg == LON_REQUIRED) {
                    lon_append (&opt_tail, o->to);
                    lon_append (&opt_tail, value);
                } else if (value)
                    lon_append2 (&opt_tail, o->to, value, strlen (value));
                else
                    lon_append (&opt_tail, o->to);
            } else {
                char *full = (char *) malloc (strlen (o->name) + 4);
                if (!full)
                    goto usage;
                strcpy (full, "--");
                strcat (full, o->name);
                if (value) {
                    strcat (full, "=");
                    lon_append2 (&opt_tail, full, value, strlen (value));
                } else
                    lon_append (&opt_tail, full);
                free (full);
            }
            continue;
        }
        /* A cluster of short options: copy it, and its argument word. */
        lon_append (&opt_tail, w);
        for (const char *p = w + 1; *p; p++) {
            int kind = lon_short_arg (shortspec, *p);
            if (kind == LON_NONE)
                continue;
            if (kind == LON_REQUIRED && p[1] == '\0' && list->next) {
                list = list->next;
                lon_append (&opt_tail, list->word->word);
            }
            break;
        }
    }
    if (dashdash)
        lon_append (&opt_tail, "--");
    for (; list; list = list->next)
        lon_append (&arg_tail, list->word->word);
    *opt_tail = arg_head;
    *out = opt_head ? opt_head : arg_head;
    return 0;

usage:
    *opt_tail = arg_head;
    if (opt_head)
        dispose_words (opt_head);
    else if (arg_head)
        dispose_words (arg_head);
    lon_try_help ();
    return -1;
}

#endif
