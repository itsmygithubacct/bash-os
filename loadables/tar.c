/* SPDX-License-Identifier: MIT */
/* GNU-style tar interface to bash-os's ustar/PAX archive engine. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "loadables.h"
#include "pax-stream.h"
#include "gzip-stream.h"

struct tar_arg { const char *text; int directory; };

int tar_builtin(WORD_LIST *list)
{
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    struct tar_arg *args = calloc(count + 1, sizeof *args);
    const char **members = calloc(count + 1, sizeof *members);
    const char **excludes = calloc(count + 1, sizeof *excludes);
    if (!args || !members || !excludes) { free(args); free(members); free(excludes); builtin_error("out of memory"); return 2; }
    size_t exclude_count = 0;
    int absolute_names = 0;
    struct bashos_pax_xform *xforms = NULL;
    size_t used = 0, member_count = 0;
    int mode = 0, zip = 0, verbose = 0, end_options = 0, first = 1, no_recurse = 0;
    int saved = -1, rc = 0;
    const char *archive = "-";
    FILE *stream = NULL, *temporary = NULL;
    struct bashos_pax_write_context writer = {0};
    struct bashos_pax_read_options read_options = { .tar_mode = 1 };
    /* -1: GNU tar's default, on for root and off for other users. */
    int same_owner = -1, same_permissions = -1;
    for (; list; list = list->next) {
        const char *w = list->word->word, *opts = NULL, *value = NULL;
        char value_option = 0;
        int old_style = first && *w && w[0] != '-';
        first = 0;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: tar -c|-t|-x|--delete [-zvPS] [-f ARCHIVE] [-C DIR] [FILE...]\nCreate, list, or extract ustar/PAX archives. '-' means stdin/stdout.\n-O extracts to stdout; --strip-components=N removes leading path components.\n-p preserves permissions; --no-recursion archives only directory entries.\n--same-owner/--no-same-owner restore the archived owner (default for root);\n--numeric-owner uses archived ids rather than names.\n--exclude=PATTERN skips members; --wildcards makes member operands patterns.\n--transform=s/RE/REPL/FLAGS rewrites member names; -P keeps a leading '/'.\n-S stores files with holes as sparse members; --acls stores and restores ACLs.\n--delete removes the named members from ARCHIVE; --to-command=CMD pipes each\nregular member to CMD with GNU's TAR_* variables."); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("tar (bash-os) 0.1.1"); goto done; }
        if (!end_options && !strcmp(w, "--create")) opts = "c";
        else if (!end_options && !strcmp(w, "--extract")) opts = "x";
        else if (!end_options && !strcmp(w, "--get")) opts = "x";
        else if (!end_options && !strcmp(w, "--list")) opts = "t";
        else if (!end_options && (!strcmp(w, "--gzip") || !strcmp(w, "--gunzip"))) opts = "z";
        else if (!end_options && !strcmp(w, "--verbose")) opts = "v";
        else if (!end_options && !strcmp(w, "--to-stdout")) opts = "O";
        else if (!end_options && (!strcmp(w, "--same-permissions") || !strcmp(w, "--preserve-permissions"))) opts = "p";
        else if (!end_options && !strcmp(w, "--no-same-permissions")) { same_permissions = 0; continue; }
        else if (!end_options && !strcmp(w, "--same-owner")) { same_owner = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-same-owner")) { same_owner = 0; continue; }
        else if (!end_options && !strcmp(w, "--numeric-owner")) { read_options.numeric_owner = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-recursion")) { no_recurse = 1; continue; }
        else if (!end_options && (!strcmp(w, "--to-command") || !strncmp(w, "--to-command=", 13))) {
            if (w[12] == '=') value = w + 13;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            read_options.to_command = value; continue;
        }
        else if (!end_options && !strcmp(w, "--wildcards")) { read_options.wildcards = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-wildcards")) { read_options.wildcards = 0; continue; }
        else if (!end_options && !strcmp(w, "--absolute-names")) opts = "P";
        else if (!end_options && !strcmp(w, "--sparse")) opts = "S";
        else if (!end_options && !strcmp(w, "--acls")) { read_options.acls = writer.acls = 1; continue; }
        else if (!end_options && !strcmp(w, "--no-acls")) { read_options.acls = writer.acls = 0; continue; }
        else if (!end_options && !strcmp(w, "--delete")) {
            if (mode && mode != 'D') goto invalid;
            mode = 'D'; continue;
        }
        else if (!end_options && (!strcmp(w, "--exclude") || !strncmp(w, "--exclude=", 10))) {
            if (w[9] == '=') value = w + 10;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            excludes[exclude_count++] = value; continue;
        }
        else if (!end_options && (!strcmp(w, "--transform") || !strcmp(w, "--xform") ||
                                  !strncmp(w, "--transform=", 12) || !strncmp(w, "--xform=", 8))) {
            const char *eq = strchr(w, '=');
            if (eq) value = eq + 1;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            if (bashos_pax_xform_add(&xforms, value) < 0) { rc = 2; goto done; }
            continue;
        }
        else if (!end_options && (!strcmp(w, "--mtime") || !strncmp(w, "--mtime=", 8))) {
            if (w[7] == '=') value = w + 8;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            if (*value != '@' || bashos_pax_set_mtime(&writer, value + 1) < 0) goto invalid;
            continue;
        }
        else if (!end_options && !strcmp(w, "--file")) opts = "f";
        else if (!end_options && !strcmp(w, "--directory")) opts = "C";
        else if (!end_options && !strncmp(w, "--file=", 7)) { value_option = 'f'; value = w + 7; }
        else if (!end_options && !strncmp(w, "--directory=", 12)) { value_option = 'C'; value = w + 12; }
        else if (!end_options && (!strcmp(w, "--strip-components") || !strncmp(w, "--strip-components=", 19))) {
            value = w + 18;
            if (*value == '=') value++;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            char *end; errno = 0;
            unsigned long n = strtoul(value, &end, 10);
            if (!*value || *value == '-' || *end || errno || n > UINT_MAX) goto invalid;
            read_options.strip = (unsigned)n; continue;
        }
        else if (!end_options && w[0] == '-' && w[1]) opts = w + 1;
        else if (!end_options && old_style) opts = w;
        if (opts) {
            for (; *opts; opts++) {
                if (*opts == 'c' || *opts == 't' || *opts == 'x') {
                    if (mode && mode != *opts) goto invalid;
                    mode = *opts;
                } else if (*opts == 'z') zip = 1;
                else if (*opts == 'v') verbose = 1;
                else if (*opts == 'O') read_options.to_stdout = 1;
                else if (*opts == 'p') same_permissions = 1;
                else if (*opts == 'P') absolute_names = 1;
                else if (*opts == 'S') writer.sparse = 1;
                else if (*opts == 'f' || *opts == 'C') {
                    char option = *opts;
                    if (!old_style && opts[1]) { value = opts + 1; opts += strlen(opts) - 1; }
                    else { if (!(list = list->next)) goto invalid; value = list->word->word; }
                    if (option == 'f') archive = value;
                    else args[used++] = (struct tar_arg){value, 1};
                } else goto invalid;
            }
        } else if (value_option == 'f') archive = value;
        else if (value_option == 'C') args[used++] = (struct tar_arg){value, 1};
        else { args[used++] = (struct tar_arg){w, 0}; members[member_count++] = w; }
    }
    if (!mode || (mode == 'c' && !member_count) || (writer.override_mtime && mode != 'c')) goto invalid;
    if (mode == 'D' && (zip || read_options.to_stdout || read_options.strip)) goto invalid;
    if (read_options.to_command && (mode != 'x' || read_options.to_stdout)) goto invalid;
    read_options.archive = archive;
    read_options.excludes = excludes; read_options.nexcludes = exclude_count;
    read_options.absolute_names = absolute_names;
    read_options.xforms = xforms;
    writer.excludes = excludes; writer.nexcludes = exclude_count;
    writer.xforms = xforms;
    writer.strip_slash = !absolute_names;
    read_options.same_owner = same_owner < 0 ? geteuid() == 0 : same_owner;
    read_options.preserve = same_permissions < 0 ? geteuid() == 0 : same_permissions;
    if (mode == 'c' && (read_options.to_stdout || read_options.strip)) goto invalid;
    saved = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved < 0) { builtin_error("save working directory: %s", strerror(errno)); rc = 2; goto done; }
    /* Open the archive before -C affects member paths. */
    if (!strcmp(archive, "-")) {
        int fd = dup(mode == 'c' ? 1 : 0);
        stream = fd < 0 ? NULL : fdopen(fd, mode == 'c' ? "wb" : "rb");
        if (!stream && fd >= 0) close(fd);
    } else stream = fopen(archive, mode == 'c' ? "wb" : mode == 'D' ? "r+b" : "rb");
    if (!stream) { builtin_error("%s: %s", archive, strerror(errno)); rc = 2; goto done; }
    FILE *payload = stream;
    if (zip) {
        temporary = tmpfile();
        if (!temporary) { builtin_error("temporary archive: %s", strerror(errno)); rc = 2; goto done; }
        payload = temporary;
        if (mode != 'c') {
            if (bgz_decode(fileno(stream), fileno(temporary), NULL) || fseek(temporary, 0, SEEK_SET)) { rc = 2; goto done; }
        }
    }
    if (mode == 'D') {
        /* Rewrite the archive without the named members, in place. */
        FILE *copy = tmpfile();
        if (!copy) { builtin_error("temporary archive: %s", strerror(errno)); rc = 2; goto done; }
        read_options.members = members; read_options.count = member_count;
        int drc = bashos_pax_delete(stream, copy, &read_options);
        if (drc != 2 && strcmp(archive, "-")) {
            char buf[16384]; size_t n;
            if (fflush(copy) || fseek(copy, 0, SEEK_SET) || fseek(stream, 0, SEEK_SET)) drc = 2;
            while (drc != 2 && (n = fread(buf, 1, sizeof buf, copy)) > 0)
                if (fwrite(buf, 1, n, stream) != n) drc = 2;
            if (drc != 2 && (fflush(stream) || ftruncate(fileno(stream), ftello(stream)) < 0)) drc = 2;
        } else if (drc != 2) {
            char buf[16384]; size_t n;
            if (fflush(copy) || fseek(copy, 0, SEEK_SET)) drc = 2;
            while (drc != 2 && (n = fread(buf, 1, sizeof buf, copy)) > 0)
                if (fwrite(buf, 1, n, stdout) != n) drc = 2;
        }
        fclose(copy);
        if (drc) { if (drc == 1) builtin_error("Exiting with failure status due to previous errors"); rc = 2; }
        goto done;
    }
    if (mode == 'c') {
        writer.no_recurse = no_recurse;
        int warned = 0;
        for (size_t i = 0; i < used; i++) {
            if (args[i].directory) {
                if (chdir(args[i].text)) { builtin_error("%s: %s", args[i].text, strerror(errno)); rc = 2; break; }
            } else {
                if (args[i].text[0] == '/' && !absolute_names && !xforms && !warned++)
                    builtin_error("Removing leading `/' from member names");
                if (verbose) fprintf(!strcmp(archive, "-") ? stderr : stdout, "%s\n", args[i].text);
                if (bashos_pax_write_member_context(payload, args[i].text, &writer)) rc = 2;
            }
        }
        unsigned char zero[1024] = {0};
        if (fwrite(zero, 1, sizeof zero, payload) != sizeof zero || fflush(payload)) rc = 2;
        if (!rc && zip) {
            if (fseek(payload, 0, SEEK_SET) || bgz_encode(fileno(payload), fileno(stream), 6, NULL, 0)) rc = 2;
        }
    } else {
        for (size_t i = 0; i < used; i++) if (args[i].directory && chdir(args[i].text)) {
            builtin_error("%s: %s", args[i].text, strerror(errno)); rc = 2; goto done;
        }
        read_options.extract = mode == 'x'; read_options.verbose = verbose;
        read_options.members = members; read_options.count = member_count;
        int member_errors = 0;
        read_options.member_errors = &member_errors;
        if (bashos_pax_read(payload, &read_options)) rc = 2;
        if (member_errors) builtin_error("Exiting with failure status due to previous errors");
    }
    goto done;
invalid:
    builtin_error("unsupported option, missing argument, or conflicting operation; try tar --help"); rc = 2;
done:
    bashos_pax_write_clear(&writer);
    bashos_pax_xform_free(&xforms);
    free(excludes);
    if (temporary && fclose(temporary)) rc = 2;
    if (stream && fclose(stream)) rc = 2;
    if (saved >= 0) {
        if (fchdir(saved)) { builtin_error("restore working directory: %s", strerror(errno)); rc = 2; }
        close(saved);
    }
    free(args); free(members);
    if (fflush(stdout) || ferror(stdout)) { clearerr(stdout); rc = 2; }
    return rc;
}

char *tar_doc[] = {
    "Create (-c), list (-t), or extract (-x) ustar/PAX archives; -f selects the archive.",
    "Supports -C directory, -z gzip, -v, -O stdout, -p permissions, --strip-components.",
    "Extraction restores the archived owner and modes when run as root, as GNU tar does;",
    "--same-owner/--no-same-owner, -p/--no-same-permissions and --numeric-owner override.",
    "Creation accepts --mtime=@EPOCH_SECONDS to normalize all archived timestamps.",
    "--exclude=PATTERN, --wildcards, --transform=s/RE/REPL/FLAGS, -P/--absolute-names,",
    "-S/--sparse (GNU PAX 1.0 sparse members) and --acls (SCHILY.acl.* records) as in GNU tar;",
    "a leading '/' is removed from member names unless -P. --delete removes members;",
    "--to-command=CMD pipes each regular member to CMD (TAR_FILENAME, TAR_SIZE, ...).",
    "Uses the pax engine. Unsupported options fail instead of being ignored.",
    "Preserves regular-file hardlinks with nonconflicting member names; supports FIFOs and devices.",
    "No append/update or automatic compression detection (the tar command adds those).", NULL
};
struct builtin tar_struct = {
    "tar", tar_builtin, BUILTIN_ENABLED, tar_doc, "tar -c|-t|-x|--delete [-zvPS] [-f ARCHIVE] [-C DIR] [FILE...]", 0
};
