/* SPDX-License-Identifier: MIT */
/* GNU/BSD checksum files shared by sha256sum and md5sum. The includer
   defines SUM_NAME, SUM_TAG, SUM_HEX and the SUM_CTX/SUM_* hash calls. */
#ifndef BASHOS_SUM_FILE_H
#define BASHOS_SUM_FILE_H
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include "gnu-quote.h"
#include "shim-prog-name.h"

#define SUM_MAX_HEX 64

/* GNU's name for a checksum list or a listed file in a diagnostic: quoted
   only when needed, and standard input (a list read from "-") called
   'standard input'. Each returns its own static buffer, replaced on the
   next call. */
static const char *
sum_list_label (const char *file)
{
    static char *shown;
    free (shown);
    shown = bos_quotef (strcmp (file, "-") ? file : "standard input");
    return shown ? shown : file;
}

static const char *
sum_file_label (const char *file)
{
    static char *shown;
    free (shown);
    shown = bos_quotef (file);
    return shown ? shown : file;
}

struct sum_options { int binary, zero, tag, check, quiet, status, strict, warn, ignore; };

/* QUIET_MISSING (--ignore-missing) silences only a file that does not
   exist; GNU reports every other open error, even under --status. */
static int sum_digest(const char *name, char hex[SUM_MAX_HEX + 1], int quiet_missing, int *missing)
{
    int fd = !strcmp(name, "-") ? 0 : open(name, O_RDONLY | O_CLOEXEC);
    *missing = fd < 0 && errno == ENOENT;
    if (fd < 0) {
        if (!(quiet_missing && *missing)) builtin_error("%s: %s", sum_file_label(name), strerror(errno));
        return 1;
    }
    unsigned char data[32768], hash[SUM_MAX_HEX / 2];
    SUM_CTX ctx;
    SUM_INIT(&ctx);
    int rc = SUM_STARTS(&ctx);
    while (!rc) {
        ssize_t n = read(fd, data, sizeof data);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { rc = -1; break; }
        if (!n) break;
        rc = SUM_UPDATE(&ctx, data, (size_t)n);
    }
    if (!rc) rc = SUM_FINISH(&ctx, hash);
    SUM_FREE(&ctx);
    if (fd && close(fd) < 0) rc = -1;
    if (rc) {
        builtin_error("%s: cannot read or hash input", sum_file_label(name));
        return 1;
    }
    for (int i = 0; i < SUM_HEX / 2; i++) snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    return 0;
}

static int sum_needs_escape(const char *s) { return strpbrk(s, "\\\n\r") != NULL; }
static void sum_name(const char *s, int escape)
{
    for (; *s; s++) {
        if (escape && *s == '\\') fputs("\\\\", stdout);
        else if (escape && *s == '\n') fputs("\\n", stdout);
        else if (escape && *s == '\r') fputs("\\r", stdout);
        else putchar((unsigned char)*s);
    }
}

static int sum_unescape(char *s)
{
    char *out = s;
    while (*s) {
        if (*s == '\\') {
            s++;
            if (*s == 'n') *out++ = '\n';
            else if (*s == 'r') *out++ = '\r';
            else if (*s == '\\') *out++ = '\\';
            else return -1;
            s++;
        } else *out++ = *s++;
    }
    *out = 0;
    return 0;
}

static int sum_verify(const char *file, const struct sum_options *o)
{
    FILE *f = !strcmp(file, "-") ? fdopen(dup(0), "r") : fopen(file, "r");
    if (!f) { builtin_error("%s: %s", sum_file_label(file), strerror(errno)); return 1; }
    char *line = NULL;
    size_t cap = 0, number = 0, valid = 0, checked = 0, bad = 0, mismatched = 0, unreadable = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        number++;
        if (n && line[n-1] == '\n') line[--n] = 0;
        if (n && line[n-1] == '\r') line[--n] = 0;
        if (!n || line[0] == '#') continue;
        if ((size_t)n != strlen(line)) goto malformed;
        char *p = line, *name = NULL, *digest = NULL;
        int escape = *p == '\\';
        if (escape) p++;
        size_t tag_len = strlen(SUM_TAG);
        if (!strncmp(p, SUM_TAG " (", tag_len + 2)) {
            name = p + tag_len + 2;
            char *end = strrchr(name, ')');
            if (!end || strncmp(end, ") = ", 4)) goto malformed;
            *end = 0; digest = end + 4;
            if (strlen(digest) != SUM_HEX) goto malformed;
        } else {
            if (strlen(p) < SUM_HEX + 3 || p[SUM_HEX] != ' ' || (p[SUM_HEX + 1] != ' ' && p[SUM_HEX + 1] != '*')) goto malformed;
            digest = p; name = p + SUM_HEX + 2; p[SUM_HEX] = 0;
        }
        for (int i = 0; i < SUM_HEX; i++) if (!isxdigit((unsigned char)digest[i])) goto malformed;
        if (!*name || (escape && sum_unescape(name))) goto malformed;
        valid++;
        char actual[SUM_MAX_HEX + 1]; int missing = 0;
        int failed = sum_digest(name, actual, o->ignore, &missing);
        if (failed && missing && o->ignore) continue;
        checked++;
        int matches = !failed && !strcasecmp(actual, digest);
        if (!matches) { rc = 1; if (failed) unreadable++; else mismatched++; }
        if (!o->status && (!o->quiet || !matches)) {
            int escaped = sum_needs_escape(name);
            if (escaped) putchar('\\');
            sum_name(name, escaped);
            printf(": %s\n", matches ? "OK" : failed ? "FAILED open or read" : "FAILED");
        }
        continue;
malformed:
        bad++;
        if (o->warn && !o->status) builtin_error("%s: %zu: improperly formatted %s checksum line", sum_list_label(file), number, SUM_TAG);
    }
    if (ferror(f)) { if (!o->status) builtin_error("%s: read error", sum_list_label(file)); rc = 1; }
    free(line);
    if (fclose(f)) rc = 1;
    /* GNU's summary: with no well-formed line only that error (shown even
       under --status); otherwise, unless --status, the WARNING counts and
       then "no file was verified" when --ignore-missing skipped them all. */
    if (!valid) {
        builtin_error("%s: no properly formatted checksum lines found", sum_list_label(file));
        rc = 1;
    } else {
        if (!o->status) {
            if (bad) builtin_error(bad == 1 ? "WARNING: %zu line is improperly formatted" : "WARNING: %zu lines are improperly formatted", bad);
            if (unreadable) builtin_error("WARNING: %zu listed file%s could not be read", unreadable, unreadable == 1 ? "" : "s");
            if (mismatched) builtin_error("WARNING: %zu computed checksum%s did NOT match", mismatched, mismatched == 1 ? "" : "s");
        }
        if (!checked) {
            if (!o->status) builtin_error("%s: no file was verified", sum_list_label(file));
            rc = 1;
        }
    }
    if (bad && o->strict) rc = 1;
    return rc;
}

static int sum_main(WORD_LIST *list)
{
    struct sum_options o = {0};
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc(count + 1, sizeof *files);
    if (!files) { builtin_error("out of memory"); return 1; }
    size_t used = 0;
    int end_options = 0, rc = 0;
    /* --quiet, --status and --warn are one setting in coreutils: the last
       one given is the one a misuse is reported for. */
    const char *verbosity = NULL;
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            printf("Usage: %s [-bctwz] [--tag] [FILE...]\nCheck options: --quiet --status --strict --warn --ignore-missing\nWith no FILE, or FILE '-', read standard input.\n", SUM_NAME); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { printf("%s (bash-os) 0.1.1\n", SUM_NAME); goto done; }
        if (!end_options && w[0] == '-' && w[1]) {
            if (!strcmp(w, "--binary")) o.binary = 1;
            else if (!strcmp(w, "--text")) o.binary = 0;
            else if (!strcmp(w, "--check")) o.check = 1;
            else if (!strcmp(w, "--zero")) o.zero = 1;
            else if (!strcmp(w, "--tag")) o.tag = 1;
            else if (!strcmp(w, "--quiet")) o.quiet = 1, verbosity = "quiet";
            else if (!strcmp(w, "--status")) o.status = 1, verbosity = "status";
            else if (!strcmp(w, "--strict")) o.strict = 1;
            else if (!strcmp(w, "--warn")) o.warn = 1, verbosity = "warn";
            else if (!strcmp(w, "--ignore-missing")) o.ignore = 1;
            else if (w[1] == '-') {
                builtin_error("unrecognized option '%s'", w);
                bos_shim_try_help(SUM_NAME); rc = 1; goto done;
            }
            else for (const char *p = w + 1; *p; p++) switch (*p) {
                case 'b': o.binary = 1; break;
                case 't': o.binary = 0; break;
                case 'c': o.check = 1; break;
                case 'w': o.warn = 1; verbosity = "warn"; break;
                case 'z': o.zero = 1; break;
                default:
                    builtin_error("invalid option -- '%c'", *p);
                    bos_shim_try_help(SUM_NAME); rc = 1; goto done;
            }
        } else files[used++] = w;
    }
    if (verbosity) {
        o.quiet = verbosity[0] == 'q';
        o.status = verbosity[0] == 's';
        o.warn = verbosity[0] == 'w';
    }
    {
        /* coreutils' wording for options that do not fit the mode. */
        const char *why = NULL;
        if (o.check && o.zero) why = "the --zero option is not supported when verifying checksums";
        else if (o.check && o.tag) why = "the --tag option is meaningless when verifying checksums";
        else if (!o.check && o.ignore) why = "the --ignore-missing option is meaningful only when verifying checksums";
        else if (!o.check && verbosity) why = verbosity;
        else if (!o.check && o.strict) why = "the --strict option is meaningful only when verifying checksums";
        if (why == verbosity && why) {
            builtin_error("the --%s option is meaningful only when verifying checksums", verbosity);
            bos_shim_try_help(SUM_NAME); rc = 1; goto done;
        }
        if (why) { builtin_error("%s", why); bos_shim_try_help(SUM_NAME); rc = 1; goto done; }
    }
    if (!used) files[used++] = "-";
    for (size_t i = 0; i < used; i++) {
        if (o.check) { rc |= sum_verify(files[i], &o); continue; }
        char hex[SUM_MAX_HEX + 1]; int missing;
        if (sum_digest(files[i], hex, 0, &missing)) { rc = 1; continue; }
        int escape = !o.zero && sum_needs_escape(files[i]);
        if (escape) putchar('\\');
        if (o.tag) fputs(SUM_TAG " (", stdout);
        else printf("%s %c", hex, o.binary ? '*' : ' ');
        sum_name(files[i], escape);
        if (o.tag) printf(") = %s", hex);
        putchar(o.zero ? 0 : '\n');
    }
done:
    free(files);
    if (fflush(stdout) || ferror(stdout)) { builtin_error("write error"); clearerr(stdout); rc = 1; }
    return rc;
}

#endif
