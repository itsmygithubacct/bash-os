/* bashnl.c — POSIX nl(1) as a bash builtin.
 *
 *   bashnl [-ba|-bt|-bn] [-ha|-ht|-hn] [-fa|-ft|-fn]
 *          [-d XY] [-i N] [-s SEP] [-v N] [-w W] [-n FORMAT] [-p] [FILE...]
 *
 * Numbers lines from FILE(s) (or stdin). POSIX-shape; supports the
 * standard header/body/footer section delimiters.
 *
 * Body type:
 *   -ba   number all lines
 *   -bt   number only non-empty lines (default)
 *   -bn   no numbering (silent passthrough)
 *   -bpBRE number only lines matching BRE
 *
 * Other flags:
 *   -i N        increment between numbered lines (default 1)
 *   -l N        group N empty lines as one numbered blank line (default 1)
 *   -s SEP      separator between number and text (default \t)
 *   -w W        line-number column width (default 6)
 *   -n FORMAT   number format: ln (left), rn (right, default), rz (right zero-pad)
 *   -v N        initial line number (default 1)
 *   -d XY       section delimiter characters (default \:)
 *   -p          do NOT reset numbering at logical page breaks
 *
 * Long aliases mirror nl(1) for the supported option surface:
 *   --body-numbering, --header-numbering, --footer-numbering,
 *   --section-delimiter, --line-increment, --join-blank-lines,
 *   --number-separator, --number-width, --number-format,
 *   --starting-line-number, --no-renumber
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <regex.h>

#include "loadables.h"

typedef enum { BNL_ALL = 0, BNL_NONEMPTY, BNL_NONE, BNL_REGEX } bnl_body;
typedef enum { BNL_RN = 0, BNL_LN, BNL_RZ } bnl_fmt;
typedef enum { BNL_BODY = 0, BNL_HEADER, BNL_FOOTER } bnl_section;

typedef struct {
    bnl_body body;
    regex_t  body_re;
    int      body_re_compiled;
    int      incr;
    int      width;
    long     start;
    int      blank_join;
    bnl_fmt  fmt;
    bnl_body header;
    regex_t  header_re;
    int      header_re_compiled;
    bnl_body footer;
    regex_t  footer_re;
    int      footer_re_compiled;
    const char *sep;
    char     delim1;
    char     delim2;
    int      no_reset;
} bnl_opts;

extern char *nl_doc[];

static void
bnl_print_help (void)
{
    for (char **p = nl_doc; *p; p++)
        puts (*p);
}

static void
bnl_emit_number (long n, const bnl_opts *o)
{
    /* Mirror nl(1)'s printf formats exactly (FORMAT_LEFT / FORMAT_RIGHT_LZ /
     * FORMAT_RIGHT_NOLZ). printf rather than hand-rolled padding gets
     * negative line numbers right: "%0*ld" yields "-0005", not "0000-5". */
    const char *fmt;
    switch (o->fmt) {
        case BNL_LN: fmt = "%-*ld%s"; break;
        case BNL_RZ: fmt = "%0*ld%s"; break;
        case BNL_RN:
        default:     fmt = "%*ld%s";  break;
    }
    printf (fmt, o->width, n, o->sep);
}

static int
bnl_parse_mode (const char *v, bnl_body *out, regex_t *re, int *re_compiled)
{
    /* GNU nl (build_type_arg) switches on the FIRST character of the style
       only: for a/t/n any trailing characters are ignored ("-bary" == "-ba"),
       and 'p' takes the remainder as the BRE. Match that leniency rather than
       requiring an exact "a"/"t"/"n". */
    switch (v[0]) {
        case 'a': *out = BNL_ALL;      return 0;
        case 't': *out = BNL_NONEMPTY; return 0;
        case 'n': *out = BNL_NONE;     return 0;
        case 'p': {
            regex_t next;
            int rc = regcomp (&next, v + 1, REG_NOSUB);
            if (rc != 0)
                return -1;
            if (*re_compiled)
                regfree (re);
            *re = next;
            *re_compiled = 1;
            *out = BNL_REGEX;
            return 0;
        }
        default: return -1;
    }
}

static int
bnl_parse_positive_int (const char *v, int *out)
{
    char *end = NULL;
    long n;
    if (!v || !*v)
        return -1;
    errno = 0;
    n = strtol (v, &end, 10);
    if (errno || !end || *end || n < 1 || n > 1000000)
        return -1;
    *out = (int)n;
    return 0;
}

/* Parse any signed integer (-v / -i). nl(1) accepts the full intmax range,
 * including zero and negatives; junk is rejected rather than coerced. */
static int
bnl_parse_int (const char *v, long *out)
{
    char *end = NULL;
    long n;
    if (!v || !*v)
        return -1;
    errno = 0;
    n = strtol (v, &end, 10);
    if (errno || !end || *end)
        return -1;
    *out = n;
    return 0;
}

static int
bnl_take_long_arg (WORD_LIST **plist, const char *w, const char *name,
                   const char **out)
{
    size_t len = strlen (name);
    if (!strcmp (w, name)) {
        if (!(*plist)->next)
            return -1;
        *plist = (*plist)->next;
        *out = (*plist)->word->word;
        return 1;
    }
    if (!strncmp (w, name, len) && w[len] == '=') {
        *out = w + len + 1;
        return 1;
    }
    return 0;
}

static regex_t *
bnl_current_regex (bnl_section section, bnl_opts *o)
{
    if (section == BNL_HEADER)
        return o->header_re_compiled ? &o->header_re : NULL;
    if (section == BNL_FOOTER)
        return o->footer_re_compiled ? &o->footer_re : NULL;
    return o->body_re_compiled ? &o->body_re : NULL;
}

static int
bnl_section_delim (const char *line, ssize_t n, const bnl_opts *o)
{
    size_t len = (size_t) n;
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        len--;
    if (len == 6
        && line[0] == o->delim1 && line[1] == o->delim2
        && line[2] == o->delim1 && line[3] == o->delim2
        && line[4] == o->delim1 && line[5] == o->delim2)
        return 3;
    if (len == 4
        && line[0] == o->delim1 && line[1] == o->delim2
        && line[2] == o->delim1 && line[3] == o->delim2)
        return 2;
    if (len == 2 && line[0] == o->delim1 && line[1] == o->delim2)
        return 1;
    return 0;
}

static int
bnl_process (FILE *f, bnl_opts *o, long *counter)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    bnl_section section = BNL_BODY;
    int blank_count = 0;
    while ((n = getline (&line, &cap, f)) != -1) {
        int delim = bnl_section_delim (line, n, o);
        if (delim) {
            if (delim == 3)
                section = BNL_HEADER;
            else if (delim == 2)
                section = BNL_BODY;
            else
                section = BNL_FOOTER;
            if (!o->no_reset) *counter = o->start;
            blank_count = 0;
            fputc ('\n', stdout);
            continue;
        }
        int empty = (n == 1 && line[0] == '\n') || (n == 0);
        int do_number = 0;
        bnl_body mode = o->body;
        if (section == BNL_HEADER) mode = o->header;
        else if (section == BNL_FOOTER) mode = o->footer;
        switch (mode) {
            case BNL_ALL:
                if (empty) {
                    blank_count++;
                    if (blank_count >= o->blank_join) {
                        do_number = 1;
                        blank_count = 0;
                    }
                } else {
                    blank_count = 0;
                    do_number = 1;
                }
                break;
            case BNL_NONEMPTY:
                if (!empty) {
                    blank_count = 0;
                    do_number = 1;
                }
                break;
            case BNL_REGEX: {
                regex_t *re = bnl_current_regex (section, o);
                blank_count = 0;
                /* GNU matches against the line content WITHOUT the trailing
                   newline (re_search over line_buf.length - 1), so e.g. the
                   BRE "." never matches an empty line. Temporarily terminate
                   at the content length for regexec, then restore. */
                size_t clen = (size_t) n;
                if (clen > 0 && line[clen - 1] == '\n') clen--;
                char saved = line[clen];
                line[clen] = '\0';
                do_number = (re && regexec (re, line, 0, NULL, 0) == 0);
                line[clen] = saved;
                break;
            }
            case BNL_NONE:     do_number = 0; break;
        }
        if (do_number) {
            bnl_emit_number (*counter, o);
            *counter += o->incr;
        } else {
            /* Match nl(1): unnumbered lines reserve the number+separator width. */
            for (int i = 0; i < o->width + (int)strlen (o->sep); i++)
                fputc (' ', stdout);
        }
        fwrite (line, 1, (size_t) n, stdout);
        /* GNU's readlinebuffer appends the line delimiter on EOF, so a final
           line lacking a trailing newline still gets one in the output. */
        if (n == 0 || line[n - 1] != '\n')
            fputc ('\n', stdout);
    }
    free (line);
    return EXECUTION_SUCCESS;
}

int
nl_builtin (WORD_LIST *list)
{
    bnl_opts o = { .body = BNL_NONEMPTY, .incr = 1, .width = 6,
                   .start = 1, .blank_join = 1, .fmt = BNL_RN, .header = BNL_NONE,
                   .footer = BNL_NONE, .sep = "\t",
                   .delim1 = '\\', .delim2 = ':' };

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) {
            bnl_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashnl 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--")) { list = list->next; break; }
        const char *lv = NULL;
        int lr;
        lr = bnl_take_long_arg (&list, w, "--body-numbering", &lv);
        if (lr) {
            if (lr < 0 || bnl_parse_mode (lv, &o.body, &o.body_re, &o.body_re_compiled) < 0)
                { builtin_error ("--body-numbering needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--header-numbering", &lv);
        if (lr) {
            if (lr < 0 || bnl_parse_mode (lv, &o.header, &o.header_re, &o.header_re_compiled) < 0)
                { builtin_error ("--header-numbering needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--footer-numbering", &lv);
        if (lr) {
            if (lr < 0 || bnl_parse_mode (lv, &o.footer, &o.footer_re, &o.footer_re_compiled) < 0)
                { builtin_error ("--footer-numbering needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--section-delimiter", &lv);
        if (lr) {
            if (lr < 0 || strlen (lv) < 1)
                { builtin_error ("--section-delimiter needs delimiter chars"); builtin_usage (); return EX_USAGE; }
            o.delim1 = lv[0]; o.delim2 = lv[1] ? lv[1] : ':';
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--line-increment", &lv);
        if (lr) {
            long incr_v;
            if (lr < 0 || bnl_parse_int (lv, &incr_v) < 0)
                { builtin_error ("--line-increment needs an integer"); builtin_usage (); return EX_USAGE; }
            o.incr = (int) incr_v;
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--join-blank-lines", &lv);
        if (lr) {
            if (lr < 0 || bnl_parse_positive_int (lv, &o.blank_join) < 0)
                { builtin_error ("--join-blank-lines needs positive N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--starting-line-number", &lv);
        if (lr) {
            if (lr < 0 || bnl_parse_int (lv, &o.start) < 0)
                { builtin_error ("--starting-line-number needs an integer"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--number-separator", &lv);
        if (lr) {
            if (lr < 0) { builtin_error ("--number-separator needs SEP"); builtin_usage (); return EX_USAGE; }
            o.sep = lv;
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--number-width", &lv);
        if (lr) {
            long wv;
            if (lr < 0 || bnl_parse_int (lv, &wv) < 0 || wv < 1 || wv > 2147483647L)
                { builtin_error ("invalid line number field width: %s", lr < 0 ? "" : lv); builtin_usage (); return EX_USAGE; }
            o.width = (int) wv;
            list = list->next;
            continue;
        }
        lr = bnl_take_long_arg (&list, w, "--number-format", &lv);
        if (lr) {
            if (lr < 0) { builtin_error ("--number-format needs FORMAT"); builtin_usage (); return EX_USAGE; }
            if (!strcmp (lv, "ln"))      o.fmt = BNL_LN;
            else if (!strcmp (lv, "rn")) o.fmt = BNL_RN;
            else if (!strcmp (lv, "rz")) o.fmt = BNL_RZ;
            else { builtin_error ("--number-format: bad format (use ln, rn, rz)"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--no-renumber")) { o.no_reset = 1; list = list->next; continue; }
        if (!strncmp (w, "-b", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : "");
            if (bnl_parse_mode (v, &o.body, &o.body_re, &o.body_re_compiled) < 0)
                { builtin_error ("-b needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-h", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : "");
            if (bnl_parse_mode (v, &o.header, &o.header_re, &o.header_re_compiled) < 0)
                { builtin_error ("-h needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-f", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : "");
            if (bnl_parse_mode (v, &o.footer, &o.footer_re, &o.footer_re_compiled) < 0)
                { builtin_error ("-f needs a / t / n / pBRE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-d", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v || strlen (v) < 1) { builtin_error ("-d needs delimiter chars"); builtin_usage (); return EX_USAGE; }
            o.delim1 = v[0]; o.delim2 = v[1] ? v[1] : ':';
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-i", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            long incr_v;
            if (!v || bnl_parse_int (v, &incr_v) < 0) { builtin_error ("-i needs an integer"); builtin_usage (); return EX_USAGE; }
            o.incr = (int) incr_v;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-l", 2) || !strcmp (w, "--join-blank-lines")) {
            const char *v = NULL;
            if (!strncmp (w, "-l", 2))
                v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            else
                v = (list = list->next, list ? list->word->word : NULL);
            if (bnl_parse_positive_int (v, &o.blank_join) < 0)
                { builtin_error ("-l needs positive N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--join-blank-lines=", 19)) {
            if (bnl_parse_positive_int (w + 19, &o.blank_join) < 0)
                { builtin_error ("--join-blank-lines needs positive N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-v", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v || bnl_parse_int (v, &o.start) < 0) { builtin_error ("-v needs an integer"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-s", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-s needs SEP"); builtin_usage (); return EX_USAGE; }
            o.sep = v;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-w", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            long wv;
            /* GNU requires width in 1..INT_MAX; 0/negative/junk is rejected. */
            if (!v || bnl_parse_int (v, &wv) < 0 || wv < 1 || wv > 2147483647L)
                { builtin_error ("invalid line number field width: %s", v ? v : ""); builtin_usage (); return EX_USAGE; }
            o.width = (int) wv;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-n", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-n needs FORMAT"); builtin_usage (); return EX_USAGE; }
            if (!strcmp (v, "ln"))      o.fmt = BNL_LN;
            else if (!strcmp (v, "rn")) o.fmt = BNL_RN;
            else if (!strcmp (v, "rz")) o.fmt = BNL_RZ;
            else { builtin_error ("-n: bad format (use ln, rn, rz)"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-p")) { o.no_reset = 1; list = list->next; continue; }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    long counter = o.start;
    int rc = EXECUTION_SUCCESS;
    if (!list) {
        bnl_process (stdin, &o, &counter);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            bnl_process (f, &o, &counter);
            if (f != stdin) fclose (f);
        }
    }
    if (o.body_re_compiled) regfree (&o.body_re);
    if (o.header_re_compiled) regfree (&o.header_re);
    if (o.footer_re_compiled) regfree (&o.footer_re);
    return rc;
}

char *nl_doc[] = {
    "Number lines (POSIX nl).",
    "",
    "    bashnl [-ba|-bt|-bn] [-ha|-ht|-hn] [-fa|-ft|-fn]",
    "           [-d XY] [-i N] [-l N] [-s SEP] [-v N] [-w W]",
    "           [-n ln|rn|rz] [-p] [--help|--version] [FILE...]",
    "",
    "    -ba       number all lines",
    "    -bt       number only non-empty lines (default)",
    "    -bn       silent passthrough (no numbering)",
    "    -bpBRE    number only lines matching BRE",
    "    -h MODE   header numbering mode: a, t, n, or pBRE (default n)",
    "    -f MODE   footer numbering mode: a, t, n, or pBRE (default n)",
    "    -d XY     section delimiter chars (default \\:)",
    "    -i N      increment between numbered lines (default 1)",
    "    -l N      group N empty lines as one numbered blank line (default 1)",
    "    -s SEP    separator after the number (default tab)",
    "    -v N      starting line number (default 1)",
    "    -w W      column width (default 6)",
    "    -n FMT    ln (left), rn (right, default), rz (zero-pad)",
    "    -p        do not reset at logical page/header delimiters",
    "    --help    display this help and exit",
    "    --version display version information and exit",
    "    Long aliases: --body-numbering, --header-numbering, --footer-numbering,",
    "                  --section-delimiter, --line-increment, --join-blank-lines,",
    "                  --number-separator, --number-width, --number-format,",
    "                  --starting-line-number, --no-renumber",
    "",
    "Reads stdin when no FILE given (or use `-` in the list).",
    (char *)NULL
};

struct builtin bashnl_struct = {
    "bashnl",
    nl_builtin,
    BUILTIN_ENABLED,
    nl_doc,
    "bashnl [-ba|-bt|-bn] [-ha|-ht|-hn] [-fa|-ft|-fn] [-d XY] [-i N] [-l N] [-s SEP] [-v N] [-w W] [-n FORMAT] [-p] [--help|--version] [FILE...]",
    0
};
