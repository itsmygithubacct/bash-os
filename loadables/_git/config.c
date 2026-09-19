/* SPDX-License-Identifier: MIT */
/* _git/config.c — git's configuration files. See config.h.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#include "loadables.h"

#include "config.h"
#include "lock.h"
#include "repo.h"

#define BGIT_CONFIG_INCLUDE_DEPTH 10

static char *
bgit_config_join (const char *a, const char *b)
{
    size_t n = strlen (a) + 1 + strlen (b) + 1;
    char *out = malloc (n);
    if (out) snprintf (out, n, "%s/%s", a, b);
    return out;
}

static int
bgit_config_add (bgit_config *cfg, const char *key, const char *value, int level)
{
    if (cfg->n == cfg->cap) {
        size_t next = cfg->cap ? cfg->cap * 2 : 32;
        bgit_config_entry *grown = realloc (cfg->entries, next * sizeof *grown);
        if (!grown) return -1;
        cfg->entries = grown;
        cfg->cap = next;
    }
    bgit_config_entry *e = &cfg->entries[cfg->n];
    e->key = strdup (key);
    e->value = value ? strdup (value) : NULL;
    e->level = level;
    if (!e->key || (value && !e->value)) {
        free (e->key); free (e->value);
        return -1;
    }
    cfg->n++;
    return 0;
}

/* A growing string, for values assembled from escapes and continuations. */
typedef struct { char *data; size_t len, cap; } bgit_buf;

static int
bgit_buf_putc (bgit_buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t next = b->cap ? b->cap * 2 : 64;
        char *grown = realloc (b->data, next);
        if (!grown) return -1;
        b->data = grown;
        b->cap = next;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
    return 0;
}

/* Parse one file's text. Sections, subsections, values with quotes,
   escapes, comments and continuations, and include.path. */
static int
bgit_config_parse (bgit_config *cfg, const char *path, const char *text,
                   int level, int depth)
{
    char section[512] = "";
    const char *p = text;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        if (*p == '#' || *p == ';') {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (*p == '[') {
            p++;
            char name[512];
            size_t n = 0;
            while (*p && *p != ']' && *p != '"' && !isspace ((unsigned char) *p)) {
                if (n + 1 < sizeof name)
                    name[n++] = (char) tolower ((unsigned char) *p);
                p++;
            }
            name[n] = '\0';
            while (*p == ' ' || *p == '\t') p++;
            char subsection[512] = "";
            size_t sn = 0;
            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p++;
                    if (sn + 1 < sizeof subsection) subsection[sn++] = *p;
                    p++;
                }
                subsection[sn] = '\0';
                if (*p == '"') p++;
                while (*p == ' ' || *p == '\t') p++;
            }
            if (*p != ']') {
                builtin_error ("bad config line in %s", path);
                return -1;
            }
            p++;
            if (sn)
                snprintf (section, sizeof section, "%s.%s.", name, subsection);
            else
                snprintf (section, sizeof section, "%s.", name);
            continue;
        }
        /* A key, and the value that may follow it. */
        char key[512];
        size_t kn = 0;
        while (*p && (isalnum ((unsigned char) *p) || *p == '-')) {
            if (kn + 1 < sizeof key)
                key[kn++] = (char) tolower ((unsigned char) *p);
            p++;
        }
        key[kn] = '\0';
        if (!kn) {
            builtin_error ("bad config line in %s", path);
            return -1;
        }
        while (*p == ' ' || *p == '\t') p++;
        bgit_buf value = {0};
        int has_value = 0;
        if (*p == '=') {
            has_value = 1;
            p++;
            while (*p == ' ' || *p == '\t') p++;
            int quoted = 0;
            size_t trailing = 0;   /* unquoted whitespace, dropped if the value ends */
            while (*p) {
                if (*p == '\n') { p++; break; }
                if (*p == '\\') {
                    p++;
                    if (*p == '\n') { p++; continue; }   /* continuation */
                    char c = *p;
                    char decoded = c == 'n' ? '\n' : c == 't' ? '\t'
                                 : c == 'b' ? '\b' : c;
                    if (!c) break;
                    for (size_t i = 0; i < trailing; i++) bgit_buf_putc (&value, ' ');
                    trailing = 0;
                    if (bgit_buf_putc (&value, decoded) < 0) { free (value.data); return -1; }
                    p++;
                    continue;
                }
                if (*p == '"') { quoted = !quoted; p++; continue; }
                if (!quoted && (*p == '#' || *p == ';')) {
                    while (*p && *p != '\n') p++;
                    break;
                }
                if (!quoted && (*p == ' ' || *p == '\t')) { trailing++; p++; continue; }
                for (size_t i = 0; i < trailing; i++) bgit_buf_putc (&value, ' ');
                trailing = 0;
                if (bgit_buf_putc (&value, *p) < 0) { free (value.data); return -1; }
                p++;
            }
        } else {
            while (*p && *p != '\n') {
                if (*p == '#' || *p == ';') break;
                if (!isspace ((unsigned char) *p)) {
                    builtin_error ("bad config line in %s", path);
                    free (value.data);
                    return -1;
                }
                p++;
            }
            while (*p && *p != '\n') p++;
        }
        char full[1100];
        snprintf (full, sizeof full, "%s%s", section, key);
        if (bgit_config_add (cfg, full, has_value ? (value.data ? value.data : "") : NULL,
                             level) < 0) {
            free (value.data);
            return -1;
        }
        /* include.path pulls in another file at this point. */
        if (strcmp (full, "include.path") == 0 && value.data && depth < BGIT_CONFIG_INCLUDE_DEPTH) {
            char *included;
            if (value.data[0] == '/') {
                included = strdup (value.data);
            } else if (value.data[0] == '~' && value.data[1] == '/' && getenv ("HOME")) {
                included = bgit_config_join (getenv ("HOME"), value.data + 2);
            } else {
                char dir[4096];
                snprintf (dir, sizeof dir, "%s", path);
                char *slash = strrchr (dir, '/');
                if (slash) *slash = '\0'; else snprintf (dir, sizeof dir, ".");
                included = bgit_config_join (dir, value.data);
            }
            if (included) {
                char *text2 = NULL;
                FILE *f = fopen (included, "r");
                if (f) {
                    size_t cap = 4096, len = 0;
                    text2 = malloc (cap);
                    if (text2) {
                        size_t got;
                        while ((got = fread (text2 + len, 1, cap - len - 1, f)) > 0) {
                            len += got;
                            if (len + 1 >= cap) {
                                cap *= 2;
                                char *grown = realloc (text2, cap);
                                if (!grown) break;
                                text2 = grown;
                            }
                        }
                        text2[len] = '\0';
                    }
                    fclose (f);
                }
                if (text2) bgit_config_parse (cfg, included, text2, level, depth + 1);
                free (text2);
                free (included);
            }
        }
        free (value.data);
    }
    return 0;
}

int
bgit_config_read_file (bgit_config *cfg, const char *path, int level)
{
    FILE *f = fopen (path, "r");
    if (!f) return 1;
    size_t cap = 4096, len = 0;
    char *text = malloc (cap);
    if (!text) { fclose (f); return -1; }
    size_t got;
    while ((got = fread (text + len, 1, cap - len - 1, f)) > 0) {
        len += got;
        if (len + 1 >= cap) {
            cap *= 2;
            char *grown = realloc (text, cap);
            if (!grown) { free (text); fclose (f); return -1; }
            text = grown;
        }
    }
    text[len] = '\0';
    fclose (f);
    int rc = bgit_config_parse (cfg, path, text, level, 0);
    free (text);
    return rc;
}

int
bgit_config_global_file (char *out, size_t outsz)
{
    const char *env = getenv ("GIT_CONFIG_GLOBAL");
    if (env && *env)
        return snprintf (out, outsz, "%s", env) < (int) outsz ? 0 : -1;
    const char *home = getenv ("HOME");
    if (!home || !*home) return -1;
    return snprintf (out, outsz, "%s/.gitconfig", home) < (int) outsz ? 0 : -1;
}

int
bgit_config_repo_file (const bgit_repo *repo, char *out, size_t outsz)
{
    if (!repo) return -1;
    return snprintf (out, outsz, "%s/config", repo->common_dir) < (int) outsz
           ? 0 : -1;
}

int
bgit_config_load (bgit_config *cfg, const bgit_repo *repo,
                  const char *const *overrides, size_t n_overrides)
{
    memset (cfg, 0, sizeof *cfg);
    if (!getenv ("GIT_CONFIG_NOSYSTEM"))
        bgit_config_read_file (cfg, "/etc/gitconfig", 0);
    char path[4096];
    if (bgit_config_global_file (path, sizeof path) == 0)
        bgit_config_read_file (cfg, path, 1);
    const char *xdg = getenv ("XDG_CONFIG_HOME");
    const char *home = getenv ("HOME");
    if (!getenv ("GIT_CONFIG_GLOBAL")) {
        if (xdg && *xdg) {
            snprintf (path, sizeof path, "%s/git/config", xdg);
            bgit_config_read_file (cfg, path, 1);
        } else if (home && *home) {
            snprintf (path, sizeof path, "%s/.config/git/config", home);
            bgit_config_read_file (cfg, path, 1);
        }
    }
    if (repo && bgit_config_repo_file (repo, path, sizeof path) == 0)
        bgit_config_read_file (cfg, path, 2);
    for (size_t i = 0; i < n_overrides; i++) {
        const char *eq = strchr (overrides[i], '=');
        char key[1100];
        if (eq) {
            size_t n = (size_t) (eq - overrides[i]);
            if (n >= sizeof key) n = sizeof key - 1;
            memcpy (key, overrides[i], n);
            key[n] = '\0';
        } else {
            snprintf (key, sizeof key, "%s", overrides[i]);
        }
        for (char *p = key; *p; p++) {
            /* A subsection keeps its case; the rest is folded. */
            if (*p == '"') break;
            *p = (char) tolower ((unsigned char) *p);
        }
        if (bgit_config_add (cfg, key, eq ? eq + 1 : NULL, 3) < 0) return -1;
    }
    return 0;
}

void
bgit_config_release (bgit_config *cfg)
{
    if (!cfg) return;
    for (size_t i = 0; i < cfg->n; i++) {
        free (cfg->entries[i].key);
        free (cfg->entries[i].value);
    }
    free (cfg->entries);
    memset (cfg, 0, sizeof *cfg);
}

const char *
bgit_config_get (const bgit_config *cfg, const char *key)
{
    const char *found = NULL;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, key) == 0)
            found = cfg->entries[i].value ? cfg->entries[i].value : "true";
    return found;
}

size_t
bgit_config_get_all (const bgit_config *cfg, const char *key,
                     const char ***values)
{
    size_t n = 0;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, key) == 0) n++;
    if (!n) { *values = NULL; return 0; }
    const char **out = calloc (n, sizeof *out);
    if (!out) { *values = NULL; return 0; }
    size_t w = 0;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, key) == 0)
            out[w++] = cfg->entries[i].value ? cfg->entries[i].value : "true";
    *values = out;
    return n;
}

int
bgit_config_bool (const bgit_config *cfg, const char *key, int fallback)
{
    const char *value = bgit_config_get (cfg, key);
    if (!value) return fallback;
    if (!*value) return 0;
    if (!strcasecmp (value, "true") || !strcasecmp (value, "yes") ||
        !strcasecmp (value, "on") || !strcmp (value, "1"))
        return 1;
    if (!strcasecmp (value, "false") || !strcasecmp (value, "no") ||
        !strcasecmp (value, "off") || !strcmp (value, "0"))
        return 0;
    return fallback;
}

/* ---- writing ----------------------------------------------------------- */

/* Split "section.subsection.key" into its parts. The subsection, if any, is
   everything between the first and last dot. */
static int
bgit_config_split (const char *key, char *section, size_t section_sz,
                   char *subsection, size_t subsection_sz,
                   char *name, size_t name_sz)
{
    const char *first = strchr (key, '.');
    const char *last = strrchr (key, '.');
    if (!first || first == key || !last[1]) return -1;
    size_t sn = (size_t) (first - key);
    if (sn >= section_sz) return -1;
    memcpy (section, key, sn);
    section[sn] = '\0';
    for (char *p = section; *p; p++) *p = (char) tolower ((unsigned char) *p);
    /* The variable's name keeps the case it was typed in, as git writes it;
       matching is case-insensitive either way. */
    snprintf (name, name_sz, "%s", last + 1);
    if (first == last) {
        subsection[0] = '\0';
    } else {
        size_t len = (size_t) (last - first - 1);
        if (len >= subsection_sz) return -1;
        memcpy (subsection, first + 1, len);
        subsection[len] = '\0';
    }
    return 0;
}

/* A value needs quoting when it has edge whitespace or a comment character. */
static void
bgit_config_quote (const char *value, char *out, size_t outsz)
{
    int needs = !*value || isspace ((unsigned char) value[0]) ||
                isspace ((unsigned char) value[strlen (value) - 1]) ||
                strpbrk (value, "#;\"\\\n\t") != NULL;
    size_t w = 0;
    if (!needs) { snprintf (out, outsz, "%s", value); return; }
    if (w + 1 < outsz) out[w++] = '"';
    for (const char *p = value; *p && w + 3 < outsz; p++) {
        if (*p == '"' || *p == '\\') { out[w++] = '\\'; out[w++] = *p; }
        else if (*p == '\n') { out[w++] = '\\'; out[w++] = 'n'; }
        else if (*p == '\t') { out[w++] = '\\'; out[w++] = 't'; }
        else out[w++] = *p;
    }
    if (w + 1 < outsz) out[w++] = '"';
    out[w] = '\0';
}

/* Is LINE the header of the section we want? */
static int
bgit_config_is_section (const char *line, const char *section,
                        const char *subsection)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '[') return 0;
    p++;
    size_t n = strlen (section);
    if (strncasecmp (p, section, n) != 0) return 0;
    p += n;
    while (*p == ' ' || *p == '\t') p++;
    if (*subsection) {
        if (*p != '"') return 0;
        p++;
        size_t sn = strlen (subsection);
        if (strncmp (p, subsection, sn) != 0) return 0;
        p += sn;
        if (*p != '"') return 0;
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    return *p == ']';
}

/* Is LINE "name = ..." for the key we want? */
static int
bgit_config_is_key (const char *line, const char *name)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen (name);
    if (strncasecmp (p, name, n) != 0) return 0;
    p += n;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '=' || *p == '\n' || *p == '\0';
}

/* Rewrite PATH with the key set, added or removed. */
static int
bgit_config_edit (const char *path, const char *key, const char *value,
                  int multiple, int remove)
{
    char section[256], subsection[512], name[256];
    if (bgit_config_split (key, section, sizeof section, subsection,
                           sizeof subsection, name, sizeof name) < 0) {
        builtin_error ("invalid key: %s", key);
        return -1;
    }
    char **lines = NULL;
    size_t n = 0, cap = 0;
    FILE *f = fopen (path, "r");
    if (f) {
        char buf[8192];
        while (fgets (buf, sizeof buf, f)) {
            if (n == cap) {
                size_t next = cap ? cap * 2 : 64;
                char **grown = realloc (lines, next * sizeof *grown);
                if (!grown) { fclose (f); goto oom; }
                lines = grown;
                cap = next;
            }
            lines[n] = strdup (buf);
            if (!lines[n]) { fclose (f); goto oom; }
            n++;
        }
        fclose (f);
    }

    char quoted[8192];
    if (value) bgit_config_quote (value, quoted, sizeof quoted);

    int in_section = 0, done = 0;
    size_t section_end = 0;
    int section_seen = 0;
    for (size_t i = 0; i < n; i++) {
        const char *line = lines[i];
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') {
            in_section = bgit_config_is_section (line, section, subsection);
            if (in_section) { section_seen = 1; section_end = i + 1; }
            continue;
        }
        if (!in_section) continue;
        section_end = i + 1;
        if (!bgit_config_is_key (line, name)) continue;
        if (remove) {
            free (lines[i]);
            memmove (lines + i, lines + i + 1, (n - i - 1) * sizeof *lines);
            n--; i--;
            done = 1;
            continue;
        }
        if (multiple) continue;   /* --add leaves existing values alone */
        char replacement[8192];
        snprintf (replacement, sizeof replacement, "\t%s = %s\n", name, quoted);
        free (lines[i]);
        lines[i] = strdup (replacement);
        if (!lines[i]) goto oom;
        done = 1;
    }

    if (!remove && (!done || multiple)) {
        char addition[8192];
        snprintf (addition, sizeof addition, "\t%s = %s\n", name, quoted);
        size_t at;
        if (section_seen) {
            at = section_end;
        } else {
            char header[1024];
            if (*subsection)
                snprintf (header, sizeof header, "[%s \"%s\"]\n", section, subsection);
            else
                snprintf (header, sizeof header, "[%s]\n", section);
            if (n == cap) {
                size_t next = cap ? cap * 2 : 8;
                char **grown = realloc (lines, next * sizeof *grown);
                if (!grown) goto oom;
                lines = grown;
                cap = next;
            }
            lines[n] = strdup (header);
            if (!lines[n]) goto oom;
            n++;
            at = n;
        }
        if (n == cap) {
            size_t next = cap ? cap * 2 : 8;
            char **grown = realloc (lines, next * sizeof *grown);
            if (!grown) goto oom;
            lines = grown;
            cap = next;
        }
        memmove (lines + at + 1, lines + at, (n - at) * sizeof *lines);
        lines[at] = strdup (addition);
        if (!lines[at]) goto oom;
        n++;
    }

    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) goto oom;
    for (size_t i = 0; i < n; i++) {
        if (bgit_lock_write (&lock, lines[i], strlen (lines[i])) < 0) {
            bgit_lock_rollback (&lock);
            goto oom;
        }
    }
    int rc = bgit_lock_commit (&lock);
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return rc;
oom:
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return -1;
}

int
bgit_config_set_file (const char *path, const char *key, const char *value,
                      int multiple)
{
    return bgit_config_edit (path, key, value, multiple, 0);
}

int
bgit_config_unset_file (const char *path, const char *key)
{
    return bgit_config_edit (path, key, NULL, 0, 1);
}

int
bgit_ident (const bgit_config *cfg, int committer, char *out, size_t outsz)
{
    const char *name = getenv (committer ? "GIT_COMMITTER_NAME" : "GIT_AUTHOR_NAME");
    const char *email = getenv (committer ? "GIT_COMMITTER_EMAIL" : "GIT_AUTHOR_EMAIL");
    const char *date = getenv (committer ? "GIT_COMMITTER_DATE" : "GIT_AUTHOR_DATE");
    if ((!name || !*name) && cfg) name = bgit_config_get (cfg, "user.name");
    if ((!email || !*email) && cfg) email = bgit_config_get (cfg, "user.email");
    if (!name || !*name) name = "bash-os";
    if (!email || !*email) email = "bash-os@localhost";

    char when[64];
    if (date && *date) {
        long long seconds;
        char zone[8];
        if (sscanf (date, "%lld %5s", &seconds, zone) == 2 &&
            (zone[0] == '+' || zone[0] == '-')) {
            snprintf (when, sizeof when, "%lld %s", seconds, zone);
            return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
                   (int) outsz ? 0 : -1;
        }
    }
    time_t now = time (NULL);
    struct tm local;
    long offset = 0;
    if (localtime_r (&now, &local)) offset = local.tm_gmtoff;
    long absolute = offset < 0 ? -offset : offset;
    snprintf (when, sizeof when, "%lld %c%02ld%02ld", (long long) now,
              offset < 0 ? '-' : '+', absolute / 3600, (absolute % 3600) / 60);
    return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
           (int) outsz ? 0 : -1;
}
