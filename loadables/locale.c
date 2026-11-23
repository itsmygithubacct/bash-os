/* SPDX-License-Identifier: MIT */
/* locale.c - minimal LC_* environment plumbing for bash-os. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

#include "loadables.h"

static const char *cats[] = {
  "ALL", "CTYPE", "NUMERIC", "TIME", "COLLATE", "MONETARY", "MESSAGES",
  "PAPER", "NAME", "ADDRESS", "TELEPHONE", "MEASUREMENT", "IDENTIFICATION", NULL
};

static int
recognized_locale (const char *s)
{
  return s && (!strcmp (s, "C") || !strcmp (s, "POSIX") || !strcmp (s, "C.UTF-8")
               || !strcmp (s, "C.utf8") || !strcmp (s, "C.UTF8"));
}

static const char *
canonical_locale (const char *s)
{
  if (!s) return NULL;
  if (!strcmp (s, "C.utf8") || !strcmp (s, "C.UTF8")) return "C.UTF-8";
  return s;
}

static int
known_cat (const char *s)
{
  int i;
  for (i = 0; cats[i]; i++)
    if (!strcmp (cats[i], s)) return 1;
  return 0;
}

static const char *
var_value (const char *name)
{
  const char *v = getenv (name);
  if (!v || !*v)
    {
      SHELL_VAR *sv = find_variable (name);
      if (sv) v = get_variable_value (sv);
    }
  return (v && *v) ? v : NULL;
}

static const char *
effective_locale (const char *cat)
{
  const char *v = var_value ("LC_ALL");
  char name[80];

  if (v) return v;
  if (cat && strcmp (cat, "ALL"))
    {
      snprintf (name, sizeof name, "LC_%s", cat);
      v = var_value (name);
      if (v) return v;
    }
  v = var_value ("LANG");
  return v ? v : "C";
}

static void
upper_copy (char *dst, size_t dstsz, const char *src)
{
  size_t i;
  for (i = 0; i + 1 < dstsz && src && src[i]; i++)
    dst[i] = (char) toupper ((unsigned char) src[i]);
  dst[i] = '\0';
}

/* ---- POSIX locale(1): listing, -a, -m and keyword queries ----------------
   bash-os ships the C/POSIX locale and C.UTF-8 and no locale data. Output
   follows glibc's locale for those locales (guest compatibility pass 1). */

static const char *const posix_cats[] = {
  "CTYPE", "NUMERIC", "TIME", "COLLATE", "MONETARY", "MESSAGES", "PAPER",
  "NAME", "ADDRESS", "TELEPHONE", "MEASUREMENT", "IDENTIFICATION", NULL
};

static int
is_utf8_locale (const char *v)
{
  const char *dot = v ? strchr (v, '.') : NULL;
  if (!dot) return 0;
  dot++;
  return !strcasecmp (dot, "UTF-8") || !strcasecmp (dot, "utf8");
}

static const char *
locale_charmap (void)
{
  const char *v = var_value ("LC_ALL");
  if (!v) v = var_value ("LC_CTYPE");
  if (!v) v = var_value ("LANG");
  return is_utf8_locale (v) ? "UTF-8" : "ANSI_X3.4-1968";
}

static void
locale_list (void)
{
  const char *lang = var_value ("LANG"), *all = var_value ("LC_ALL");
  char name[64];
  printf ("LANG=%s\n", lang ? lang : "");
  printf ("LANGUAGE=%s\n", var_value ("LANGUAGE") ? var_value ("LANGUAGE") : "");
  for (int i = 0; posix_cats[i]; i++)
    {
      snprintf (name, sizeof name, "LC_%s", posix_cats[i]);
      const char *own = var_value (name);
      if (!all && own)
        printf ("%s=%s\n", name, own);
      else
        printf ("%s=\"%s\"\n", name, all ? all : lang ? lang : "POSIX");
    }
  printf ("LC_ALL=%s\n", all ? all : "");
}

/* One keyword: 1 printed, 0 unknown. */
static int
locale_keyword (const char *k, int show_cat, int show_key)
{
  static const struct { const char *cat, *key, *val; int numeric; } kw[] = {
    { "LC_NUMERIC", "decimal_point", ".", 0 },
    { "LC_NUMERIC", "thousands_sep", "", 0 },
    { "LC_NUMERIC", "grouping", "-1", 1 },
    { NULL, NULL, NULL, 0 }
  };
  if (!strcmp (k, "charmap"))
    {
      if (show_cat) puts ("LC_CTYPE");
      if (show_key) printf ("charmap=\"%s\"\n", locale_charmap ());
      else puts (locale_charmap ());
      return 1;
    }
  for (int i = 0; kw[i].key; i++)
    {
      int whole = !strcmp (k, kw[i].cat);
      if (!whole && strcmp (k, kw[i].key)) continue;
      if (whole)
        {
          /* A category name prints each of its keywords. */
          if (show_cat) puts (kw[i].cat);
          for (int j = i; kw[j].key && !strcmp (kw[j].cat, kw[i].cat); j++)
            {
              if (show_key)
                printf (kw[j].numeric ? "%s=%s\n" : "%s=\"%s\"\n", kw[j].key, kw[j].val);
              else
                puts (kw[j].val);
            }
          return 1;
        }
      if (show_cat) puts (kw[i].cat);
      if (show_key)
        printf (kw[i].numeric ? "%s=%s\n" : "%s=\"%s\"\n", kw[i].key, kw[i].val);
      else
        puts (kw[i].val);
      return 1;
    }
  return 0;
}

static int
locale_posix (WORD_LIST *list)
{
  int all = 0, maps = 0, show_cat = 0, show_key = 0, rc = EXECUTION_SUCCESS;
  WORD_LIST *names = NULL, **tail = &names;
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-a") || !strcmp (w, "--all-locales")) all = 1;
      else if (!strcmp (w, "-m") || !strcmp (w, "--charmaps")) maps = 1;
      else if (!strcmp (w, "-c") || !strcmp (w, "--category-name")) show_cat = 1;
      else if (!strcmp (w, "-k") || !strcmp (w, "--keyword-name")) show_key = 1;
      else if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) ;
      else if (w[0] == '-' && w[1] && w[1] != '-' && strspn (w + 1, "amckv") == strlen (w + 1))
        {
          all |= strchr (w, 'a') != NULL; maps |= strchr (w, 'm') != NULL;
          show_cat |= strchr (w, 'c') != NULL; show_key |= strchr (w, 'k') != NULL;
        }
      else if (w[0] == '-' && w[1])
        {
          fflush (stdout);
          fprintf (stderr, "locale: invalid option -- '%s'\nTry 'locale --help' for more information.\n", w + 1);
          return EX_USAGE;
        }
      else
        {
          *tail = p;          /* keyword operands keep their order */
          tail = &p->next;
          break;
        }
    }
  if (all)
    {
      puts ("C");
      puts ("C.utf8");
      puts ("POSIX");
      return EXECUTION_SUCCESS;
    }
  if (maps)
    {
      puts ("ANSI_X3.4-1968");
      puts ("UTF-8");
      return EXECUTION_SUCCESS;
    }
  if (!names)
    {
      locale_list ();
      return EXECUTION_SUCCESS;
    }
  for (WORD_LIST *p = names; p; p = p->next)
    if (!locale_keyword (p->word->word, show_cat, show_key))
      {
        fflush (stdout);
        fprintf (stderr, "locale: unknown name \"%s\"\n", p->word->word);
        rc = EXECUTION_FAILURE;
      }
  return rc;
}

int
locale_builtin (WORD_LIST *list)
{
  const char *verb;
  int i;

  if (!list || (strcmp (list->word->word, "validate") && strcmp (list->word->word, "current")
                && strcmp (list->word->word, "set")))
    return locale_posix (list);
  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "validate"))
    {
      if (!list) { builtin_error ("validate needs VALUE"); return EX_USAGE; }
      if (recognized_locale (list->word->word)) return EXECUTION_SUCCESS;
      builtin_error ("unsupported locale: %s (supported: C, POSIX, C.UTF-8)",
                     list->word->word);
      return EXECUTION_FAILURE;
    }

  if (!strcmp (verb, "current"))
    {
      char name[64];
      const char *v;
      if (list)
        {
          char cat[64];
          upper_copy (cat, sizeof cat, list->word->word);
          if (!strncmp (cat, "LC_", 3)) memmove (cat, cat + 3, strlen (cat + 3) + 1);
          if (!strcmp (cat, "LANG"))
            {
              printf ("LANG=%s\n", effective_locale (NULL));
              return EXECUTION_SUCCESS;
            }
          if (!known_cat (cat)) { builtin_error ("unknown category: %s", cat); return EX_USAGE; }
          snprintf (name, sizeof name, "LC_%s", cat);
          printf ("%s=%s\n", name, effective_locale (cat));
          return EXECUTION_SUCCESS;
        }
      for (i = 0; cats[i]; i++)
        {
          snprintf (name, sizeof name, "LC_%s", cats[i]);
          printf ("%s=%s\n", name, effective_locale (cats[i]));
        }
      v = var_value ("LANG");
      if (v) printf ("LANG=%s\n", v);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "set"))
    {
      char cat[64], name[80];
      const char *val;
      if (!list || !list->next) { builtin_error ("set needs CATEGORY VALUE"); return EX_USAGE; }
      upper_copy (cat, sizeof cat, list->word->word);
      if (!strncmp (cat, "LC_", 3)) memmove (cat, cat + 3, strlen (cat + 3) + 1);
      val = canonical_locale (list->next->word->word);
      if (!known_cat (cat)) { builtin_error ("unknown category: %s", cat); return EX_USAGE; }
      if (!recognized_locale (val))
        {
          builtin_error ("unsupported locale: %s (supported: C, POSIX, C.UTF-8)",
                         list->next->word->word);
          return EXECUTION_FAILURE;
        }
      if (!strcmp (cat, "ALL"))
        {
          setenv ("LC_ALL", val, 1);
          builtin_bind_variable ("LC_ALL", (char *) val, 0);
        }
      else
        {
          snprintf (name, sizeof name, "LC_%s", cat);
          setenv (name, val, 1);
          builtin_bind_variable (name, (char *) val, 0);
        }
      return EXECUTION_SUCCESS;
    }

  return EX_USAGE;
}

char *locale_doc[] = {
  "Print locale settings (POSIX locale) and manage LC_* for bash-os.",
  "",
  "    locale                       LANG, LANGUAGE, LC_* and LC_ALL, as glibc does",
  "    locale -a                    available locales (C, C.utf8, POSIX)",
  "    locale -m                    available charmaps",
  "    locale [-ck] NAME...         keyword or category values: charmap,",
  "                                 decimal_point, thousands_sep, grouping, LC_NUMERIC",
  "    locale set CATEGORY VALUE",
  "    locale current",
  "    locale validate VALUE",
  "",
  "Recognized locale values: C, POSIX, C.UTF-8. Other names are rejected;",
  "core bash-os does not ship locale data.",
  (char *)NULL
};

struct builtin locale_struct = {
  "locale",
  locale_builtin,
  BUILTIN_ENABLED,
  locale_doc,
  "locale [-a|-m] | [-ck] NAME... | set|current|validate ...",
  0
};
