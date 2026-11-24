/* SPDX-License-Identifier: MIT */
/* awk.c — POSIX-subset awk(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. Hand-rolled recursive descent,
 * no generated grammar, no vendored bwk source. Targets the patterns that real-world awk
 * one-liners need.
 *
 * Supported (v1):
 *   - BEGIN { ... } / END { ... } blocks
 *   - pattern { action } pairs
 *   - patterns: /regex/, comparison expressions, BEGIN/END
 *   - actions: print, printf, gsub, sub, getline (next-line form),
 *     control flow (if/else, while, for, for-in, break, continue)
 *   - operators: + - * / % ^ **, == != < <= > >=, ~ !~, && || !,
 *     concat (juxtaposition), assignment (= += -= *= /= %= ^= **=),
 *     prefix/postfix ++/-- on variables, arrays, and fields,
 *     and ternary ?:
 *   - variables: NR, FNR, NF, FS, OFS, RS, ORS, FILENAME, $0..$N, user
 *     scalars, assoc arrays. NR and FNR are writable scalar values;
 *     automatic record reads increment their current integer values. FNR
 *     resets at startup and when a new named input file is opened.
 *   - builtins: length, substr, index, split, sprintf, gsub, sub,
 *     match, int, sqrt, sin, cos, log, exp, close, fflush, system
 *     (refuses unless BASHAWK_ALLOW_SYSTEM is set — see security
 *     review §3.4)
 *   - pipe redirections (`print | "cmd"`, `"cmd" | getline`) execute
 *     "/bin/sh -c CMD" via explicit fork+execv with SIGCHLD-disposition
 *     reset + blocked critical section + O_CLOEXEC pipe FDs (V42-11
 *     helper-exec hardening replacing the prior popen()/pclose() pair;
 *     /bin/sh -c quoting/command semantics preserved verbatim)
 *   - flags: -F:, -v var=val, -f script-file, -e SCRIPT (multi-OK)
 *   - NUL bytes as data everywhere (gawk): records, program strings and
 *     escapes ("\0", "\000", "\x00"), -v/-F/operand values, regex literals,
 *     and RS/FS/OFS/ORS/SUBSEP; `print (a, b)` / `printf (fmt, ...)` lists
 *
 * Also supported (added since v1, code-vs-doc audit 2026-05-07):
 *   - user-defined functions: `function name(args, locals) { body }`
 *   - do-while loops
 *   - nextfile statement
 *   - ENVIRON associative array (populated from host environment)
 *   - getline from FILE (`getline var < "file"`, `getline < "file"`)
 *   - command pipes: `cmd | getline var`
 *   - file/pipe print redirects: `print > "file"`, `print >> "file"`,
 *     `print | "cmd"`
 *   - SUBSEP-shaped multi-dim arrays via `a[i,j]` → `a["i" SUBSEP "j"]`
 *
 * Output buffering (gawk/mawk parity): standard output is fully buffered
 * while it is not a terminal, instead of Bash's line buffering (one write
 * per record). All output is flushed before system(), before a command
 * pipe (`print | "cmd"`, `"cmd" | getline`) starts, before close(), on
 * fflush() and at exit; stdout is flushed at the opening of any other
 * redirection. "/dev/stdout" and "/dev/stderr" name the standard streams
 * themselves. A terminal stdout keeps line buffering, and partial output
 * is flushed before each record read from a terminal. The shell's own
 * line buffering is restored on every exit, including an interrupt.
 *
 * Genuinely out of scope:
 *   - RT (record terminator) variable
 * For those use system+ awk.
 *
 * Re-entrance: all interpreter state in a single context allocated at
 * builtin entry, freed at exit. No static globals. Repeated invocation
 * in one bash session must not leak.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
/* Records may hold NUL bytes, so matching needs REG_STARTEND and GNU syntax
   bits. Non-glibc C libraries (musl) lack them; those builds use sed's
   private copy of the GNU regex engine. BASHAWK_PORTABLE_REGEX selects that
   engine on glibc too, so the same path can be checked on the host. */
#if defined (__GLIBC__) && !defined (BASHAWK_PORTABLE_REGEX)
#  include <regex.h>
#else
#  include "sed-regex.h"
#endif
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "error.h"

/* Use the shell's checked allocation convention throughout the interpreter.
   Returning a null or partially reallocated variable table is not recoverable. */
static void *bawk_calloc (size_t n, size_t size)
{
    if (size && n > SIZE_MAX / size) { fatal_error ("awk: allocation too large"); abort (); }
    size_t total = n * size;
    void *p = xmalloc (total ? total : 1);
    memset (p, 0, total);
    return p;
}
static char *bawk_strndup (const char *s, size_t limit)
{
    size_t n = strnlen (s, limit);
    if (n == SIZE_MAX) { fatal_error ("awk: string too large"); abort (); }
    char *p = xmalloc (n + 1);
    memcpy (p, s, n); p[n] = 0;
    return p;
}
static char *bawk_strdup (const char *s) { return bawk_strndup (s, strlen (s)); }
/* A NUL-terminated copy of the LEN bytes at S, which may themselves hold NUL. */
static char *bawk_strndup_mem (const char *s, size_t len)
{
    if (len == SIZE_MAX) { fatal_error ("awk: string too large"); abort (); }
    char *p = xmalloc (len + 1);
    if (len) memcpy (p, s, len);
    p[len] = 0;
    return p;
}

/* Regular expressions see the whole counted string: REG_STARTEND bounds the
   search, so a NUL is data and \< or ^ know the byte before OFF. Patterns are
   compiled with GNU awk's dot: `.` and [^x] match NUL (gawk, mawk). Offsets in
   *M are from S. Process-global syntax is restored for other loadables. */
static int
bawk_regcomp (regex_t *re, const char *pat, size_t len)
{
    memset (re, 0, sizeof *re);
    re->fastmap = malloc (256);
    if (!re->fastmap) return -1;
    reg_syntax_t saved = re_set_syntax ((RE_SYNTAX_POSIX_EXTENDED & ~RE_DOT_NOT_NULL));
    const char *error = re_compile_pattern (pat, len, re);
    re_set_syntax (saved);
    re->newline_anchor = 0;
    if (error) { regfree (re); memset (re, 0, sizeof *re); return -1; }
    if (re_compile_fastmap (re) != 0) { regfree (re); memset (re, 0, sizeof *re); return -1; }
    return 0;
}
static int
bawk_regexec (const regex_t *re, const char *s, size_t len, size_t off, regmatch_t *m)
{
    regmatch_t mm[1];
    if (len > (size_t) INT_MAX || off > len) return REG_NOMATCH;
    mm[0].rm_so = (regoff_t) off;
    mm[0].rm_eo = (regoff_t) len;
    int rc = regexec (re, s, 1, mm, REG_STARTEND);
    if (m) *m = mm[0];
    return rc;
}


/* ================================================================ */
/* Lexer                                                             */
/* ================================================================ */

typedef enum {
    T_EOF, T_NUMBER, T_STRING, T_REGEX, T_IDENT, T_FUNC,
    T_LBRACE, T_RBRACE, T_LPAREN, T_RPAREN, T_LBRACK, T_RBRACK,
    T_SEMI, T_NEWLINE, T_COMMA,
    T_ASSIGN, T_PLUSEQ, T_MINUSEQ, T_MULEQ, T_DIVEQ, T_MODEQ, T_POWEQ,
    T_INC, T_DEC,
    T_PLUS, T_MINUS, T_MUL, T_DIV, T_MOD, T_POW,
    T_LT, T_LE, T_GT, T_GE, T_EQ, T_NEQ,
    T_AND, T_OR, T_NOT,
    T_PIPE,           /* single '|' — used for print > / | redirects + getline pipe */
    T_APPEND,         /* '>>' — print redirect */
    T_TILDE, T_NTILDE,
    T_QMARK, T_COLON,
    T_DOLLAR,
    T_KW_BEGIN, T_KW_END, T_KW_IF, T_KW_ELSE, T_KW_WHILE,
    T_KW_FOR, T_KW_IN, T_KW_BREAK, T_KW_CONTINUE,
    T_KW_NEXT, T_KW_EXIT, T_KW_RETURN,
    T_KW_PRINT, T_KW_PRINTF, T_KW_GETLINE, T_KW_DELETE,
    T_KW_FUNCTION, T_KW_DO, T_KW_NEXTFILE,
    T_BUILTIN
} bawk_tok;

typedef struct {
    bawk_tok  kind;
    char     *sval;       /* for IDENT, STRING, REGEX, BUILTIN */
    size_t    slen;       /* STRING: byte length (NUL bytes are data) */
    double    nval;       /* for NUMBER */
    int       builtin_id; /* for BUILTIN */
    size_t    off;        /* byte offset of the token in the program text */
} bawk_token;

/* Builtin function ids. */
typedef enum {
    BFN_LENGTH, BFN_SUBSTR, BFN_INDEX, BFN_SPLIT, BFN_SPRINTF,
    BFN_GSUB, BFN_SUB, BFN_MATCH, BFN_INT, BFN_SQRT,
    BFN_SIN, BFN_COS, BFN_LOG, BFN_EXP, BFN_ATAN2, BFN_RAND, BFN_SRAND,
    BFN_CLOSE, BFN_FFLUSH, BFN_SYSTEM,
    BFN_TOLOWER, BFN_TOUPPER, BFN_SYSTIME, BFN_STRFTIME, BFN_MKTIME
} bawk_builtin_id;

typedef struct {
    bawk_token *toks;
    int        n, cap, pos;
} bawk_lex;

static int
bawk_addtok (bawk_lex *L, bawk_token t)
{
    if (L->n == L->cap) {
        int nc = L->cap ? L->cap * 2 : 64;
        bawk_token *nt = xrealloc (L->toks, (size_t) nc * sizeof *nt);
        if (!nt) return -1;
        L->toks = nt; L->cap = nc;
    }
    L->toks[L->n++] = t;
    return 0;
}

static int
bawk_match_kw (const char *s, bawk_token *out, int *bid)
{
    struct { const char *kw; bawk_tok t; } kws[] = {
        {"BEGIN", T_KW_BEGIN}, {"END", T_KW_END},
        {"if", T_KW_IF}, {"else", T_KW_ELSE}, {"while", T_KW_WHILE},
        {"for", T_KW_FOR}, {"in", T_KW_IN},
        {"break", T_KW_BREAK}, {"continue", T_KW_CONTINUE},
        {"next", T_KW_NEXT}, {"exit", T_KW_EXIT}, {"return", T_KW_RETURN},
        {"print", T_KW_PRINT}, {"printf", T_KW_PRINTF},
        {"getline", T_KW_GETLINE}, {"delete", T_KW_DELETE},
        {"function", T_KW_FUNCTION}, {"do", T_KW_DO},
        {"nextfile", T_KW_NEXTFILE},
        {NULL, T_EOF}
    };
    for (int i = 0; kws[i].kw; i++)
        if (!strcmp (s, kws[i].kw)) { out->kind = kws[i].t; return 1; }
    struct { const char *n; bawk_builtin_id id; } bfns[] = {
        {"length", BFN_LENGTH}, {"substr", BFN_SUBSTR},
        {"index",  BFN_INDEX},  {"split",  BFN_SPLIT},
        {"sprintf",BFN_SPRINTF},{"gsub",   BFN_GSUB},
        {"sub",    BFN_SUB},    {"match",  BFN_MATCH},
        {"int",    BFN_INT},    {"sqrt",   BFN_SQRT},
        {"sin",    BFN_SIN},    {"cos",    BFN_COS},
        {"log",    BFN_LOG},    {"exp",    BFN_EXP},
        {"atan2",  BFN_ATAN2},  {"rand",   BFN_RAND}, {"srand", BFN_SRAND},
        {"close",  BFN_CLOSE},  {"fflush", BFN_FFLUSH},
        {"system", BFN_SYSTEM},
        {"tolower",BFN_TOLOWER},{"toupper",BFN_TOUPPER},
        {"systime",BFN_SYSTIME},{"strftime",BFN_STRFTIME},
        {"mktime", BFN_MKTIME},
        {NULL, 0}
    };
    for (int i = 0; bfns[i].n; i++)
        if (!strcmp (s, bfns[i].n)) {
            out->kind = T_BUILTIN; *bid = bfns[i].id; return 1;
        }
    return 0;
}

static int
bawk_hex_digit (int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char
bawk_decode_escape (const char **pp)
{
    const char *p = *pp;
    int v = 0, n = 0, h;
    if (!*p) return '\\';
    switch (*p) {
        case 'n': (*pp)++; return '\n';
        case 't': (*pp)++; return '\t';
        case 'r': (*pp)++; return '\r';
        case 'a': (*pp)++; return '\a';
        case 'b': (*pp)++; return '\b';
        case 'f': (*pp)++; return '\f';
        case 'v': (*pp)++; return '\v';
        case '\\': (*pp)++; return '\\';
        case '"': (*pp)++; return '"';
        case '/': (*pp)++; return '/';
        case 'x':
            p++;
            while (n < 2 && (h = bawk_hex_digit ((unsigned char) *p)) >= 0) {
                v = (v << 4) | h; p++; n++;
            }
            *pp = p;
            return n ? (char) v : 'x';
        default:
            if (*p >= '0' && *p <= '7') {
                while (n < 3 && *p >= '0' && *p <= '7') {
                    v = (v << 3) | (*p - '0'); p++; n++;
                }
                *pp = p;
                return (char) v;
            }
            (*pp)++;
            return p[0];
    }
}

/* Escape processing for -v and VAR=VALUE values and -F, "as if the value
   appeared in a STRING token" (POSIX). Returns a malloc'd string of *LENP
   bytes; "\0" and the like decode to NUL bytes, which are data (gawk). */
static char *
bawk_unescape (const char *s, size_t *lenp)
{
    size_t l = strlen (s);
    char *out = xmalloc (l + 1), *o = out;
    if (!out) return NULL;
    for (const char *p = s; *p; ) {
        if (*p == '\\' && p[1]) { p++; *o++ = bawk_decode_escape (&p); }
        else *o++ = *p++;
    }
    *o = '\0';
    if (lenp) *lenp = (size_t) (o - out);
    return out;
}

/* A regex literal's awk escapes, decoded the way gawk reads /.../: \n \t \r
   \a \b \f \v, octal \NNN (so \0 is a NUL byte), hex \xHH, \/ and \" become
   the bytes they name, and the decoded byte keeps its regex meaning. Any
   other backslash pair (\. \\ \( ...) is left for the regex compiler. The
   result is malloc'd, *LENP bytes, and may hold NUL bytes. */
static char *
bawk_regex_unescape (const char *s, size_t *lenp)
{
    size_t l = strlen (s);
    char *out = xmalloc (l + 1), *o = out;
    if (!out) return NULL;
    for (const char *p = s; *p; ) {
        if (*p == '\\' && p[1]) {
            char e = p[1];
            if (strchr ("ntrabfv/\"x", e) || (e >= '0' && e <= '7')) {
                p++;
                *o++ = bawk_decode_escape (&p);
                continue;
            }
            *o++ = *p++;
            *o++ = *p++;
            continue;
        }
        *o++ = *p++;
    }
    *o = '\0';
    *lenp = (size_t) (o - out);
    return out;
}

/* Is this operand a VAR=VALUE assignment rather than a file name? */
static int
bawk_operand_assignment (const char *w)
{
    if (!(isalpha ((unsigned char) *w) || *w == '_')) return 0;
    const char *p = w + 1;
    while (isalnum ((unsigned char) *p) || *p == '_') p++;
    return *p == '=';
}

/* Lex a script string into the L->toks array. Returns 0 on success. */
static int
bawk_lex_string (bawk_lex *L, const char *src)
{
    const char *p = src;
    int prev_can_regex = 1;    /* /…/ valid after operators / start */
    while (*p)
    {
        bawk_token t = {0};
        if (*p == ' ' || *p == '\t' || (*p == '\\' && p[1] == '\n')) {
            if (*p == '\\') p++;
            p++; continue;
        }
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }
        t.off = (size_t) (p - src);
        if (*p == '\n' || *p == ';') {
            t.kind = (*p == ';') ? T_SEMI : T_NEWLINE;
            p++;
            if (bawk_addtok (L, t) < 0) return -1;
            prev_can_regex = 1;
            continue;
        }
        if (*p == '"') {
            p++;
            char *buf = NULL; size_t blen = 0, bcap = 0;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) {
                    p++;
                    char esc = bawk_decode_escape (&p);
                    if (blen+1 >= bcap) {
                        size_t nc = bcap?bcap*2:16;
                        char *nb = xrealloc (buf, nc);
                        if (!nb) { free(buf); builtin_error("oom in string literal"); return -1; }
                        buf = nb; bcap = nc;
                    }
                    buf[blen++] = esc;
                    continue;
                }
                if (blen+1 >= bcap) {
                    size_t nc = bcap?bcap*2:16;
                    char *nb = xrealloc (buf, nc);
                    if (!nb) { free(buf); builtin_error("oom in string literal"); return -1; }
                    buf = nb; bcap = nc;
                }
                buf[blen++] = *p++;
            }
            if (*p != '"') { free(buf); builtin_error("unterminated string"); return -1; }
            p++;
            if (!buf) buf = bawk_strdup ("");
            else buf[blen] = '\0';
            t.kind = T_STRING; t.sval = buf; t.slen = blen;
            if (bawk_addtok (L, t) < 0) { free(buf); return -1; }
            prev_can_regex = 0;
            continue;
        }
        if (*p == '/' && prev_can_regex) {
            p++;
            const char *s = p;
            while (*p && *p != '/' && *p != '\n') {
                if (*p == '\\' && p[1]) p += 2;
                else if (*p == '[') {
                    /* A bracket expression may hold '/', as in gawk: /[/]/.
                       ']' first (after an optional '^') is literal, and
                       [:class:], [.x.] and [=x=] run to their own closer. */
                    const char *q = p + 1;
                    if (*q == '^') q++;
                    if (*q == ']') q++;
                    while (*q && *q != ']' && *q != '\n') {
                        if (*q == '[' && (q[1] == ':' || q[1] == '.' || q[1] == '=')) {
                            char kind = q[1];
                            const char *r = q + 2;
                            while (*r && *r != '\n' && !(r[0] == kind && r[1] == ']')) r++;
                            if (*r == kind) { q = r + 2; continue; }
                        }
                        if (*q == '\\' && q[1] && q[1] != '\n') q++;
                        q++;
                    }
                    /* An unclosed '[' is an ordinary character here; let
                       the regex compiler report it. */
                    p = *q == ']' ? q + 1 : p + 1;
                }
                else p++;
            }
            if (*p != '/') { builtin_error("unterminated regex"); return -1; }
            t.kind = T_REGEX; t.sval = bawk_strndup (s, (size_t)(p-s));
            p++;
            if (bawk_addtok (L, t) < 0) { free(t.sval); return -1; }
            prev_can_regex = 0;
            continue;
        }
        if ((*p >= '0' && *p <= '9') || (*p == '.' && p[1] >= '0' && p[1] <= '9')) {
            char *end;
            t.nval = strtod (p, &end);
            t.kind = T_NUMBER;
            p = end;
            if (bawk_addtok (L, t) < 0) return -1;
            prev_can_regex = 0;
            continue;
        }
        if (*p == '_' || (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) {
            const char *s = p;
            while (*p == '_' || (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))
                p++;
            char *id = bawk_strndup (s, (size_t)(p - s));
            if (!id) return -1;
            int bid = 0;
            if (bawk_match_kw (id, &t, &bid)) {
                if (t.kind == T_BUILTIN) { t.builtin_id = bid; t.sval = id; }
                else free (id);
            } else {
                t.kind = T_IDENT; t.sval = id;
            }
            if (bawk_addtok (L, t) < 0) { free(id); return -1; }
            prev_can_regex = 0;
            continue;
        }
        switch (*p) {
            case '$': t.kind = T_DOLLAR; p++; break;
            case '{': t.kind = T_LBRACE; p++; break;
            case '}': t.kind = T_RBRACE; p++; break;
            case '(': t.kind = T_LPAREN; p++; break;
            case ')': t.kind = T_RPAREN; p++; break;
            case '[': t.kind = T_LBRACK; p++; break;
            case ']': t.kind = T_RBRACK; p++; break;
            case ',': t.kind = T_COMMA;  p++; break;
            case '?': t.kind = T_QMARK;  p++; break;
            case ':': t.kind = T_COLON;  p++; break;
            case '+': p++; if (*p=='+'){p++;t.kind=T_INC;}else if (*p=='='){p++;t.kind=T_PLUSEQ;}else t.kind=T_PLUS; break;
            case '-': p++; if (*p=='-'){p++;t.kind=T_DEC;}else if (*p=='='){p++;t.kind=T_MINUSEQ;}else t.kind=T_MINUS; break;
            case '*': p++;
                if (*p=='*') { p++; if (*p=='='){p++;t.kind=T_POWEQ;}else t.kind=T_POW; }
                else if (*p=='='){p++;t.kind=T_MULEQ;}
                else t.kind=T_MUL;
                break;
            case '/': p++; if (*p=='='){p++;t.kind=T_DIVEQ;}else t.kind=T_DIV; break;
            case '%': p++; if (*p=='='){p++;t.kind=T_MODEQ;}else t.kind=T_MOD; break;
            case '^': p++; if (*p=='='){p++;t.kind=T_POWEQ;}else t.kind=T_POW; break;
            case '<': p++; if (*p=='='){p++;t.kind=T_LE;}else t.kind=T_LT; break;
            case '>': p++;
                if (*p=='=') { p++; t.kind=T_GE; }
                else if (*p=='>') { p++; t.kind=T_APPEND; }
                else t.kind=T_GT;
                break;
            case '=': p++; if (*p=='='){p++;t.kind=T_EQ;}else t.kind=T_ASSIGN; break;
            case '!': p++;
                if (*p=='='){p++;t.kind=T_NEQ;}
                else if (*p=='~'){p++;t.kind=T_NTILDE;}
                else t.kind=T_NOT;
                break;
            case '~': t.kind=T_TILDE; p++; break;
            case '&': p++; if (*p=='&'){p++;t.kind=T_AND;}else { builtin_error("unexpected &"); return -1; } break;
            case '|': p++; if (*p=='|'){p++;t.kind=T_OR;}else { t.kind=T_PIPE; } break;
            default: builtin_error ("unexpected char '%c' at offset %ld", *p, (long)(p - src)); return -1;
        }
        if (bawk_addtok (L, t) < 0) return -1;
        prev_can_regex = (t.kind != T_RPAREN && t.kind != T_RBRACK
                       && t.kind != T_NUMBER && t.kind != T_STRING
                       && t.kind != T_IDENT  && t.kind != T_DOLLAR);
    }
    bawk_token eof = { .kind = T_EOF };
    bawk_addtok (L, eof);
    return 0;
}

static void
bawk_lex_free (bawk_lex *L)
{
    for (int i = 0; i < L->n; i++)
        if (L->toks[i].kind == T_IDENT || L->toks[i].kind == T_STRING
         || L->toks[i].kind == T_REGEX || L->toks[i].kind == T_BUILTIN)
            free (L->toks[i].sval);
    free (L->toks);
    memset (L, 0, sizeof *L);
}

/* ================================================================ */
/* Parser — produces an AST                                          */
/* ================================================================ */

typedef enum {
    N_NUMBER, N_STRING, N_REGEX, N_IDENT, N_DOLLAR,
    N_INDEX,      /* a[i] : sval=arr name, A=index expr */
    N_ASSIGN,     /* = += -= *= /= %= : op in nval, A=lhs, B=rhs */
    N_INCDEC,     /* ++/-- : nval=delta, builtin_id=1 prefix / 0 postfix, A=lhs */
    N_BINOP,      /* op field (BAWK_BINOP_*), A=lhs, B=rhs */
    N_UNARY,      /* op (NOT / NEG): A=operand */
    N_TERNARY,    /* ?: : A=cond, B=then, C=else */
    N_REGEX_MATCH,/* lhs ~ /re/ : A=lhs, B=regex node, nval=0 ~, 1 !~ */
    N_CALL,       /* builtin: builtin_id, A=arg_list */
    N_GETLINE,    /* simple getline (next record) */
    N_GETLINE_PIPE, /* cmd | getline [var]: A=cmd_expr, sval=var (or NULL) */
    N_LIST,       /* arg list / statement list. A=head, B=tail (linked) */
    N_PRINT,      /* print: A=arg list (or NULL = $0) */
    N_PRINTF,     /* printf: A=arg list */
    N_IF,         /* A=cond, B=then, C=else */
    N_WHILE,      /* A=cond, B=body */
    N_FOR,        /* C-style: A=init, B=cond, C=step, body=loop body */
    N_FORIN,      /* for (k in a) body : sval=k, array_name=a, C=body */
    N_BREAK, N_CONTINUE, N_NEXT, N_NEXTFILE, N_EXIT,
    N_RETURN,     /* return [EXPR]: A=expr (or NULL) */
    N_BLOCK,      /* { stmts } : A=stmt list */
    N_RULE,       /* program rule: A=pattern (or NULL), B=action block, nval: 0=normal, 1=BEGIN, 2=END */
    N_FUNCDEF,    /* function NAME(params) { body }: sval=name, A=param list (chain of N_IDENT via ->next), B=body */
    N_USERCALL,   /* user function call: sval=name, A=arg list (chain via ->next) */
    N_DELETE,     /* delete a[subscript] or delete a : sval=arr name, A=subscript list (NULL = whole array) */
    N_INARRAY     /* (key in array) membership test : sval=arr name, A=subscript expr -> 1/0 */
} bawk_nkind;

typedef enum {
    BAWK_BINOP_CONCAT = -1,
    BAWK_BINOP_ADD = T_PLUS,
    BAWK_BINOP_SUB = T_MINUS,
    BAWK_BINOP_MUL = T_MUL,
    BAWK_BINOP_DIV = T_DIV,
    BAWK_BINOP_MOD = T_MOD,
    BAWK_BINOP_POW = T_POW,
    BAWK_BINOP_LT = T_LT,
    BAWK_BINOP_LE = T_LE,
    BAWK_BINOP_GT = T_GT,
    BAWK_BINOP_GE = T_GE,
    BAWK_BINOP_EQ = T_EQ,
    BAWK_BINOP_NE = T_NEQ,
    BAWK_BINOP_AND = T_AND,
    BAWK_BINOP_OR = T_OR
} bawk_binop;

typedef enum {
    BAWK_SPECIAL_NONE = 0,
    BAWK_SPECIAL_NR,
    BAWK_SPECIAL_FNR,
    BAWK_SPECIAL_NF,
    BAWK_SPECIAL_FS,
    BAWK_SPECIAL_OFS,
    BAWK_SPECIAL_SUBSEP,
    BAWK_SPECIAL_CONVFMT,
    BAWK_SPECIAL_OFMT,
    BAWK_SPECIAL_ORS,
    BAWK_SPECIAL_FILENAME,
    BAWK_SPECIAL_RSTART,
    BAWK_SPECIAL_RLENGTH
} bawk_special_id;

#ifdef BASHAWK_DEBUG_AST
static const char *
bawk_node_kind_name (bawk_nkind k)
{
    static const char *names[] = {
        "N_NUMBER", "N_STRING", "N_REGEX", "N_IDENT", "N_DOLLAR",
        "N_INDEX", "N_ASSIGN", "N_INCDEC", "N_BINOP", "N_UNARY",
        "N_TERNARY", "N_REGEX_MATCH", "N_CALL", "N_GETLINE",
        "N_GETLINE_PIPE", "N_LIST", "N_PRINT", "N_PRINTF", "N_IF",
        "N_WHILE", "N_FOR", "N_FORIN", "N_BREAK", "N_CONTINUE",
        "N_NEXT", "N_NEXTFILE", "N_EXIT", "N_RETURN", "N_BLOCK",
        "N_RULE", "N_FUNCDEF", "N_USERCALL", "N_DELETE", "N_INARRAY"
    };
    if ((unsigned) k < (sizeof names / sizeof names[0])) return names[k];
    return "N_UNKNOWN";
}
#endif

typedef enum {
    BAWK_GETLINE_MAIN = 0,
    BAWK_GETLINE_FILE,
    BAWK_GETLINE_PIPE
} bawk_getline_source;

typedef enum {
    BAWK_GETLINE_TARGET_RECORD = 0,
    BAWK_GETLINE_TARGET_SCALAR
} bawk_getline_target;

typedef struct bawk_node {
    bawk_nkind kind;
    char *sval, *array_name;
    size_t slen;          /* N_STRING: byte length of sval (may hold NUL) */
    double nval;
    int op;
    int builtin_id;
    bawk_getline_source getline_source;
    bawk_getline_target getline_target;
    struct bawk_node *A, *B, *C;
    struct bawk_node *next;
    /* For FOR (C-style): A=init B=cond C=step; body is in `body`. */
    struct bawk_node *body;
    /* For LIST: head/tail managed via next links. */
    /* Compiled regex (cached for /…/ literals). */
    regex_t  re;
    int      re_ok;
    int      parenthesized;
    size_t   src_off;     /* N_BINOP / N_ASSIGN: offset of the operator */
} bawk_node;

#define bawk_n_lhs(n)        ((n)->A)
#define bawk_n_rhs(n)        ((n)->B)
#define bawk_n_cond(n)       ((n)->A)
#define bawk_n_then(n)       ((n)->B)
#define bawk_n_else(n)       ((n)->C)
#define bawk_n_array_name(n) ((n)->array_name ? (n)->array_name : (n)->sval)
#define bawk_n_op(n)         ((n)->op)
#define bawk_n_getline_source(n) ((n)->getline_source)
#define bawk_n_getline_target(n) ((n)->getline_target)

static int
bawk_binop_from_token (bawk_tok t)
{
    switch (t) {
        case T_PLUS:  return BAWK_BINOP_ADD;
        case T_MINUS: return BAWK_BINOP_SUB;
        case T_MUL:   return BAWK_BINOP_MUL;
        case T_DIV:   return BAWK_BINOP_DIV;
        case T_MOD:   return BAWK_BINOP_MOD;
        case T_POW:   return BAWK_BINOP_POW;
        case T_LT:    return BAWK_BINOP_LT;
        case T_LE:    return BAWK_BINOP_LE;
        case T_GT:    return BAWK_BINOP_GT;
        case T_GE:    return BAWK_BINOP_GE;
        case T_EQ:    return BAWK_BINOP_EQ;
        case T_NEQ:   return BAWK_BINOP_NE;
        case T_AND:   return BAWK_BINOP_AND;
        case T_OR:    return BAWK_BINOP_OR;
        default:      return 0;
    }
}

#ifdef BASHAWK_DEBUG_AST
static void
bawk_debug_ast_print (FILE *out, const bawk_node *n, int depth)
{
    if (!n) {
        fprintf (out, "%*s(null)\n", depth * 2, "");
        return;
    }
    fprintf (out, "%*s%s", depth * 2, "", bawk_node_kind_name (n->kind));
    if (n->sval) fprintf (out, " sval=%s", n->sval);
    if (n->array_name) fprintf (out, " array=%s", n->array_name);
    if (n->kind == N_BINOP || n->kind == N_IDENT) fprintf (out, " op=%d", n->op);
    fprintf (out, "\n");
    bawk_debug_ast_print (out, n->A, depth + 1);
    bawk_debug_ast_print (out, n->B, depth + 1);
    bawk_debug_ast_print (out, n->C, depth + 1);
    if (n->body) bawk_debug_ast_print (out, n->body, depth + 1);
    for (const bawk_node *p = n->next; p; p = p->next)
        bawk_debug_ast_print (out, p, depth);
}
#endif

typedef struct {
    bawk_lex   *L;
    bawk_node **all;     /* pool for free-on-exit */
    int         n_all, cap_all;
    int         depth;   /* recursion depth in parse_expr / parse_stmt */
    int         print_arg_stop_depth;
    int         const_div_errors;  /* x/0, x%0 with a constant zero divisor */
} bawk_parser;

/* Where each piece of the program text came from, for gawk-style source
   locations in diagnostics: "cmd. line:N" for the program operand and each
   -e SCRIPT, "FILE:N" for each -f FILE, N counting lines within that piece.
   The names point at the builtin's own argument words. */
typedef struct { size_t off; const char *name; } bawk_srcseg;
static bawk_srcseg *bawk_segs;
static int bawk_nsegs, bawk_cap_segs;
static const char *bawk_src;

static void
bawk_seg_add (size_t off, const char *name)
{
    if (bawk_nsegs == bawk_cap_segs) {
        int nc = bawk_cap_segs ? bawk_cap_segs * 2 : 8;
        bawk_segs = xrealloc (bawk_segs, (size_t) nc * sizeof *bawk_segs);
        bawk_cap_segs = nc;
    }
    bawk_segs[bawk_nsegs].off = off;
    bawk_segs[bawk_nsegs].name = name;
    bawk_nsegs++;
}

static void
bawk_srcloc (size_t off, char *buf, size_t size)
{
    const char *name = "cmd. line";
    size_t start = 0;
    long line = 1;
    for (int i = 0; i < bawk_nsegs; i++)
        if (bawk_segs[i].off <= off) { start = bawk_segs[i].off; name = bawk_segs[i].name; }
    if (bawk_src)
        for (size_t k = start; k < off && bawk_src[k]; k++)
            if (bawk_src[k] == '\n') line++;
    snprintf (buf, size, "%s:%ld", name, line);
}

/* The value of a divisor that gawk folds at parse time: a numeric literal,
   possibly under unary minus or !, or a power of such literals, with no
   parentheses. Returns 0 when N is not such a constant. */
static int
bawk_const_value (const bawk_node *n, double *v)
{
    double a, b;
    if (!n || n->parenthesized) return 0;
    if (n->kind == N_NUMBER) { *v = n->nval; return 1; }
    if (n->kind == N_UNARY) {
        /* gawk folds - and ! but not +: 1/+0 fails only when run. */
        if ((int) n->nval == T_PLUS || !bawk_const_value (n->A, &a)) return 0;
        *v = (int) n->nval == T_MINUS ? -a : (a == 0);
        return 1;
    }
    if (n->kind == N_BINOP && n->op == BAWK_BINOP_POW) {
        if (!bawk_const_value (n->A, &a) || !bawk_const_value (n->B, &b)) return 0;
        *v = pow (a, b);
        return 1;
    }
    return 0;
}

/* Hard limit for recursive-descent parser depth — prevents stack
   exhaustion via deeply-nested input like `((((((((((((...))))))))))))`. */
#define BAWK_MAX_DEPTH 256

/* Default runtime eval/user-call stack limit. BASHAWK_MAX_STACK=N can
   lower or raise this guard for focused recursion tests or constrained
   guests without changing the parser recursion limit above. */
#define BAWK_DEFAULT_MAX_STACK 256

static bawk_node *
bawk_new (bawk_parser *P, bawk_nkind k)
{
    bawk_node *n = bawk_calloc (1, sizeof *n);
    if (!n) return NULL;
    n->kind = k;
    if (P->n_all == P->cap_all) {
        int nc = P->cap_all ? P->cap_all * 2 : 64;
        bawk_node **na = xrealloc (P->all, (size_t) nc * sizeof *na);
        if (!na) { free (n); return NULL; }
        P->all = na; P->cap_all = nc;
    }
    P->all[P->n_all++] = n;
    return n;
}

static bawk_token *bawk_peek (bawk_parser *P) { return &P->L->toks[P->L->pos]; }
static bawk_token *bawk_advance (bawk_parser *P) { return &P->L->toks[P->L->pos++]; }
static int bawk_accept (bawk_parser *P, bawk_tok t) {
    if (bawk_peek(P)->kind == t) { bawk_advance(P); return 1; }
    return 0;
}
static int bawk_expect (bawk_parser *P, bawk_tok t, const char *msg) {
    if (bawk_peek(P)->kind != t) { builtin_error("parse: %s (got tok %d at pos %d)", msg, bawk_peek(P)->kind, P->L->pos); return -1; }
    bawk_advance(P); return 0;
}
static void bawk_skip_nl (bawk_parser *P) {
    while (bawk_peek(P)->kind == T_NEWLINE || bawk_peek(P)->kind == T_SEMI) bawk_advance(P);
}

/* forward decls */
static bawk_node *bawk_parse_expr (bawk_parser *P);
static bawk_node *bawk_parse_primary (bawk_parser *P);
static bawk_node *bawk_parse_unary (bawk_parser *P);

static int
bawk_tok_starts_primary (bawk_tok t)
{
    return t == T_NUMBER || t == T_STRING || t == T_REGEX || t == T_IDENT
        || t == T_DOLLAR || t == T_LPAREN || t == T_BUILTIN
        || t == T_KW_GETLINE || t == T_INC || t == T_DEC
        || t == T_MINUS || t == T_PLUS || t == T_NOT;
}
static bawk_node *bawk_parse_stmt (bawk_parser *P);
static bawk_node *bawk_parse_block (bawk_parser *P);
static bawk_node *bawk_parse_field_operand (bawk_parser *P);

static bawk_node *
bawk_parse_expr_allow_gt (bawk_parser *P)
{
    int save = P->print_arg_stop_depth;
    P->print_arg_stop_depth = 0;
    bawk_node *n = bawk_parse_expr (P);
    P->print_arg_stop_depth = save;
    return n;
}

static bawk_node *
bawk_parse_print_arg (bawk_parser *P)
{
    int save = P->print_arg_stop_depth;
    P->print_arg_stop_depth = P->depth + 1;
    bawk_node *n = bawk_parse_expr (P);
    P->print_arg_stop_depth = save;
    return n;
}

/* Compile a regex literal once for each /re/ node. */
static int
bawk_compile_regex (bawk_node *n)
{
    size_t len;
    char *pat = bawk_regex_unescape (n->sval, &len);
    if (!pat) return -1;
    int rc = bawk_regcomp (&n->re, pat, len);
    free (pat);
    if (rc != 0) return -1;
    n->re_ok = 1;
    return 0;
}

static bawk_node *
bawk_parse_getline_after_keyword (bawk_parser *P, bawk_getline_source source,
                                  bawk_node *source_expr)
{
    bawk_node *n = bawk_new (P, source == BAWK_GETLINE_PIPE ? N_GETLINE_PIPE : N_GETLINE);
    if (!n) return NULL;
    n->getline_source = source;
    n->getline_target = BAWK_GETLINE_TARGET_RECORD;
    n->A = source_expr;

    /* Optional VAR after getline: `getline VAR` assigns to VAR instead
       of $0 (and deliberately skips field splitting). */
    if (bawk_peek(P)->kind == T_IDENT) {
        bawk_token *id = bawk_advance(P);
        n->sval = bawk_strdup (id->sval);
        n->getline_target = BAWK_GETLINE_TARGET_SCALAR;
    }

    /* POSIX awk file forms: `getline < FILE` and `getline VAR < FILE`.
       Parse the redirection as part of getline so `<` is not mistaken for
       an ordinary comparison expression. Pipe getline cannot take this
       redirection tail. */
    if (source != BAWK_GETLINE_PIPE && bawk_peek(P)->kind == T_LT) {
        bawk_advance(P);
        n->A = bawk_parse_expr (P);
        if (!n->A) return NULL;
        n->getline_source = BAWK_GETLINE_FILE;
    }
    return n;
}

static bawk_node *
bawk_parse_incdec_node (bawk_parser *P, bawk_node *lhs, bawk_tok op, int prefix)
{
    if (!lhs) return NULL;
    if (lhs->kind != N_IDENT && lhs->kind != N_INDEX && lhs->kind != N_DOLLAR) {
        builtin_error ("parse: ++/-- needs assignable operand");
        return NULL;
    }
    bawk_node *n = bawk_new (P, N_INCDEC);
    if (!n) return NULL;
    n->A = lhs;
    n->nval = (op == T_INC) ? 1.0 : -1.0;
    n->builtin_id = prefix ? 1 : 0;
    return n;
}

/* Parse the expression immediately after `$` without stealing a postfix
   ++/-- that belongs to the resulting field lvalue.  The general primary
   parser must consume postfix increments for `i++`, but `$i++` is `($i)++`
   in awk, not `$(i++)`. */
static bawk_node *
bawk_parse_field_operand (bawk_parser *P)
{
    bawk_token *t = bawk_peek (P);
    if (t->kind == T_NUMBER) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_NUMBER);
        n->nval = t->nval;
        return n;
    }
    if (t->kind == T_STRING) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_STRING);
        n->sval = bawk_strndup_mem (t->sval, t->slen);
        n->slen = t->slen;
        return n;
    }
    if (t->kind == T_REGEX) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_REGEX);
        n->sval = bawk_strdup (t->sval);
        if (bawk_compile_regex (n) < 0) { builtin_error("bad regex"); return NULL; }
        return n;
    }
    if (t->kind == T_LPAREN) {
        bawk_advance(P);
        bawk_node *e = bawk_parse_expr_allow_gt (P);
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        if (e) e->parenthesized = 1;
        return e;
    }
    if (t->kind == T_IDENT) {
        bawk_token *id = bawk_advance(P);
        if (bawk_peek(P)->kind == T_LPAREN) {
            bawk_advance(P);
            bawk_node *n = bawk_new (P, N_USERCALL);
            n->sval = bawk_strdup (id->sval);
            bawk_node *head = NULL, *tail = NULL;
            if (bawk_peek(P)->kind != T_RPAREN) {
                for (;;) {
                    bawk_node *a = bawk_parse_expr_allow_gt (P);
                    if (!a) return NULL;
                    bawk_node *cell = bawk_new (P, N_LIST);
                    cell->A = a;
                    if (!head) head = cell;
                    if (tail) tail->next = cell;
                    tail = cell;
                    if (!bawk_accept (P, T_COMMA)) break;
                }
            }
            if (bawk_expect (P, T_RPAREN, "expected ) at user-call args") < 0) return NULL;
            n->A = head;
            return n;
        }
        if (bawk_peek(P)->kind == T_LBRACK) {
            bawk_advance(P);
            bawk_node *idx_head = bawk_parse_expr_allow_gt (P);
            if (idx_head) {
                bawk_node *tail = idx_head;
                while (bawk_accept (P, T_COMMA)) {
                    bawk_node *next_idx = bawk_parse_expr_allow_gt (P);
                    if (!next_idx) break;
                    tail->next = next_idx;
                    tail = next_idx;
                }
            }
            if (bawk_expect (P, T_RBRACK, "expected ]") < 0) return NULL;
            bawk_node *n = bawk_new (P, N_INDEX);
            n->sval = bawk_strdup (id->sval);
            n->A = idx_head;
            return n;
        }
        bawk_node *n = bawk_new (P, N_IDENT);
        n->sval = bawk_strdup (id->sval);
        return n;
    }
    return bawk_parse_primary (P);
}

/* primary = NUMBER | STRING | REGEX | IDENT (with optional [...] index)
            | $ primary | (expr) | builtin(args) | getline */
static bawk_node *
bawk_parse_primary (bawk_parser *P)
{
    bawk_token *t = bawk_peek (P);
    if (t->kind == T_NUMBER) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_NUMBER);
        n->nval = t->nval;
        return n;
    }
    if (t->kind == T_STRING) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_STRING);
        n->sval = bawk_strndup_mem (t->sval, t->slen);
        n->slen = t->slen;
        return n;
    }
    if (t->kind == T_REGEX) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_REGEX);
        n->sval = bawk_strdup (t->sval);
        if (bawk_compile_regex (n) < 0) { builtin_error("bad regex"); return NULL; }
        return n;
    }
    if (t->kind == T_DOLLAR) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_DOLLAR);
        n->A = bawk_parse_field_operand (P);
        if (bawk_peek(P)->kind == T_INC || bawk_peek(P)->kind == T_DEC) {
            bawk_tok op = bawk_advance(P)->kind;
            return bawk_parse_incdec_node (P, n, op, 0);
        }
        return n;
    }
    if (t->kind == T_LPAREN) {
        bawk_advance(P);
        bawk_node *e = bawk_parse_expr_allow_gt (P);
        if (!e) return NULL;
        if (bawk_peek(P)->kind == T_COMMA) {
            /* (e1, e2, ...) is only valid as the LHS of `in` (multi-dim
               membership). Collect the subscript chain and require
               `) in NAME`, building an N_INARRAY directly. */
            bawk_node *tail = e;
            while (bawk_accept (P, T_COMMA)) {
                bawk_node *nx = bawk_parse_expr_allow_gt (P);
                if (!nx) return NULL;
                tail->next = nx; tail = nx;
            }
            if (bawk_expect (P, T_RPAREN, "expected ) after subscript list") < 0) return NULL;
            if (bawk_peek(P)->kind != T_KW_IN) {
                builtin_error ("parse: (subscript list) is only valid before 'in'");
                return NULL;
            }
            bawk_advance(P);
            bawk_token *nm = bawk_peek(P);
            if (nm->kind != T_IDENT) { builtin_error ("'in' expects an array name"); return NULL; }
            bawk_advance(P);
            bawk_node *n = bawk_new (P, N_INARRAY);
            n->sval = bawk_strdup (nm->sval);
            n->A = e;
            return n;
        }
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        if (e) e->parenthesized = 1;
        return e;
    }
    if (t->kind == T_BUILTIN) {
        bawk_token *bt = bawk_advance(P);
        bawk_node *n = bawk_new (P, N_CALL);
        n->builtin_id = bt->builtin_id;
        /* POSIX: bare `length` (no parentheses) means length($0). Only
           `length` may be called this way; it is identical to length(). */
        if (n->builtin_id == BFN_LENGTH && bawk_peek (P)->kind != T_LPAREN) {
            n->A = NULL;
            return n;
        }
        if (bawk_expect (P, T_LPAREN, "expected ( after builtin") < 0) return NULL;
        bawk_node *head = NULL, *tail = NULL;
        if (bawk_peek(P)->kind != T_RPAREN) {
            for (;;) {
                bawk_node *a = bawk_parse_expr (P);
                if (!a) return NULL;
                bawk_node *cell = bawk_new (P, N_LIST);
                cell->A = a;
                if (!head) head = cell;
                if (tail) tail->next = cell;
                tail = cell;
                if (!bawk_accept (P, T_COMMA)) break;
            }
        }
        if (bawk_expect (P, T_RPAREN, "expected ) at builtin args") < 0) return NULL;
        n->A = head;
        return n;
    }
    if (t->kind == T_KW_GETLINE) {
        bawk_advance(P);
        return bawk_parse_getline_after_keyword (P, BAWK_GETLINE_MAIN, NULL);
    }
    if (t->kind == T_IDENT) {
        bawk_token *id = bawk_advance(P);
        /* User-function call: IDENT immediately followed by `(`. */
        if (bawk_peek(P)->kind == T_LPAREN) {
            bawk_advance(P);
            bawk_node *n = bawk_new (P, N_USERCALL);
            n->sval = bawk_strdup (id->sval);
            bawk_node *head = NULL, *tail = NULL;
            if (bawk_peek(P)->kind != T_RPAREN) {
                for (;;) {
                    bawk_node *a = bawk_parse_expr_allow_gt (P);
                    if (!a) return NULL;
                    bawk_node *cell = bawk_new (P, N_LIST);
                    cell->A = a;
                    if (!head) head = cell;
                    if (tail) tail->next = cell;
                    tail = cell;
                    if (!bawk_accept (P, T_COMMA)) break;
                }
            }
            if (bawk_expect (P, T_RPAREN, "expected ) at user-call args") < 0) return NULL;
            n->A = head;
            return n;
        }
        if (bawk_peek(P)->kind == T_LBRACK) {
            bawk_advance(P);
            /* Parse comma-separated index list. Multiple parts are
               joined with SUBSEP at eval time per POSIX awk. */
            bawk_node *idx_head = bawk_parse_expr_allow_gt (P);
            if (idx_head) {
                bawk_node *tail = idx_head;
                while (bawk_accept (P, T_COMMA)) {
                    bawk_node *next_idx = bawk_parse_expr_allow_gt (P);
                    if (!next_idx) break;
                    tail->next = next_idx;
                    tail = next_idx;
                }
            }
            if (bawk_expect (P, T_RBRACK, "expected ]") < 0) return NULL;
            bawk_node *n = bawk_new (P, N_INDEX);
            n->sval = bawk_strdup (id->sval);
            n->A = idx_head;
            if (bawk_peek(P)->kind == T_INC || bawk_peek(P)->kind == T_DEC) {
                bawk_tok op = bawk_advance(P)->kind;
                return bawk_parse_incdec_node (P, n, op, 0);
            }
            return n;
        }
        bawk_node *n = bawk_new (P, N_IDENT);
        n->sval = bawk_strdup (id->sval);
        if (bawk_peek(P)->kind == T_INC || bawk_peek(P)->kind == T_DEC) {
            bawk_tok op = bawk_advance(P)->kind;
            return bawk_parse_incdec_node (P, n, op, 0);
        }
        return n;
    }
    if (t->kind == T_INC || t->kind == T_DEC) {
        bawk_tok op = bawk_advance(P)->kind;
        bawk_node *operand = bawk_parse_primary (P);
        return bawk_parse_incdec_node (P, operand, op, 1);
    }
    /* Unary minus / logical-not are handled one precedence level up, in
       bawk_parse_unary (above ^), so that -2^2 parses as -(2^2). */
    builtin_error ("parse: unexpected token (kind %d) at pos %d", t->kind, P->L->pos);
    return NULL;
}

/* exponentiation: ^ / ** (right-assoc). The right operand is a unary
   expression so 2^-2 parses as 2^(-2); the recursion through unary->power
   keeps ^ right-associative (2^3^2 == 2^(3^2)). */
static bawk_node *
bawk_parse_power (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_primary (P); if (!lhs) return NULL;
    bawk_tok t = bawk_peek(P)->kind;
    if (t == T_POW) {
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_unary (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = bawk_binop_from_token (t);
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        return n;
    }
    return lhs;
}

/* unary - + ! : bind looser than ^ (POSIX), so -2^2 == -(2^2). Recurses on
   itself for stacked prefixes (e.g. !-x). */
static bawk_node *
bawk_parse_unary (bawk_parser *P)
{
    bawk_tok t = bawk_peek(P)->kind;
    if (t == T_MINUS || t == T_PLUS || t == T_NOT) {
        bawk_advance(P);
        bawk_node *operand = bawk_parse_unary (P); if (!operand) return NULL;
        bawk_node *n = bawk_new (P, N_UNARY);
        n->nval = (double) t;
        n->A = operand;
        return n;
    }
    return bawk_parse_power (P);
}

/* multiplicative: * / %  (left-assoc) */
static bawk_node *
bawk_parse_mul (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_unary (P); if (!lhs) return NULL;
    while (1) {
        bawk_tok t = bawk_peek(P)->kind;
        if (t != T_MUL && t != T_DIV && t != T_MOD) break;
        size_t off = bawk_peek(P)->off;
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_unary (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = bawk_binop_from_token (t);
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        n->src_off = off;
        /* gawk rejects a constant zero divisor while parsing: an "error"
           (not fatal), parsing goes on, and nothing runs; status 1. */
        double dv;
        if (t != T_MUL && bawk_const_value (rhs, &dv) && dv == 0) {
            char loc[512];
            bawk_srcloc (off, loc, sizeof loc);
            builtin_error ("%s: error: division by zero attempted%s", loc, t == T_MOD ? " in `%'" : "");
            P->const_div_errors++;
        }
        lhs = n;
    }
    return lhs;
}

/* additive: + -  (left-assoc) */
static bawk_node *
bawk_parse_add (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_mul (P); if (!lhs) return NULL;
    while (1) {
        bawk_tok t = bawk_peek(P)->kind;
        if (t != T_PLUS && t != T_MINUS) break;
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_mul (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = bawk_binop_from_token (t);
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        lhs = n;
    }
    return lhs;
}

/* concatenation: juxtaposition (no operator). Parse strings of additive. */
static bawk_node *
bawk_parse_concat (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_add (P); if (!lhs) return NULL;
    while (1) {
        bawk_tok t = bawk_peek(P)->kind;
        /* concat continues if the next token can start a primary, including
           prefix ++/-- and other unary forms used in compact awk scripts. */
        if (bawk_tok_starts_primary (t)) {
            bawk_node *rhs = bawk_parse_add (P); if (!rhs) return NULL;
            bawk_node *n = bawk_new (P, N_BINOP);
            bawk_n_op (n) = BAWK_BINOP_CONCAT;
            bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
            lhs = n;
        } else break;
    }
    return lhs;
}

/* relational: < <= > >= == != */
static bawk_node *
bawk_parse_rel (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_concat (P); if (!lhs) return NULL;
    bawk_tok t = bawk_peek(P)->kind;
    if (t == T_GT && P->print_arg_stop_depth == P->depth) return lhs;
    if (t == T_LT || t == T_LE || t == T_GT || t == T_GE
     || t == T_EQ || t == T_NEQ) {
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_concat (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = bawk_binop_from_token (t);
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        lhs = n;
    }
    return lhs;
}

/* regex match: ~ !~ */
static bawk_node *
bawk_parse_regex_match (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_rel (P); if (!lhs) return NULL;
    bawk_tok t = bawk_peek(P)->kind;
    if (t == T_TILDE || t == T_NTILDE) {
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_rel (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_REGEX_MATCH);
        n->A = lhs; n->B = rhs;
        n->nval = (t == T_NTILDE) ? 1 : 0;
        lhs = n;
    }
    return lhs;
}

/* membership: KEY in ARRAY  (binds between matchop ~ and &&). Single-subscript
   form only; multi-dim `(i,j) in a` is not yet parsed. */
static bawk_node *
bawk_parse_in (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_regex_match (P); if (!lhs) return NULL;
    while (bawk_peek(P)->kind == T_KW_IN) {
        bawk_advance(P);
        bawk_token *nm = bawk_peek(P);
        if (nm->kind != T_IDENT) { builtin_error ("'in' expects an array name"); return NULL; }
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_INARRAY);
        n->sval = bawk_strdup (nm->sval);
        n->A = lhs;
        lhs = n;
    }
    return lhs;
}

/* logical AND */
static bawk_node *
bawk_parse_and (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_in (P); if (!lhs) return NULL;
    while (bawk_peek(P)->kind == T_AND) {
        bawk_advance(P);
        /* POSIX: a newline may follow && (line continuation). */
        while (bawk_peek(P)->kind == T_NEWLINE) bawk_advance(P);
        bawk_node *rhs = bawk_parse_in (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = BAWK_BINOP_AND;
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        lhs = n;
    }
    return lhs;
}

/* logical OR */
static bawk_node *
bawk_parse_or (bawk_parser *P)
{
    bawk_node *lhs = bawk_parse_and (P); if (!lhs) return NULL;
    while (bawk_peek(P)->kind == T_OR) {
        bawk_advance(P);
        /* POSIX: a newline may follow || (line continuation). */
        while (bawk_peek(P)->kind == T_NEWLINE) bawk_advance(P);
        bawk_node *rhs = bawk_parse_and (P); if (!rhs) return NULL;
        bawk_node *n = bawk_new (P, N_BINOP);
        bawk_n_op (n) = BAWK_BINOP_OR;
        bawk_n_lhs (n) = lhs; bawk_n_rhs (n) = rhs;
        lhs = n;
    }
    /* Stage B-final: `cmd | getline [VAR]` form. Recognized AFTER the
       OR-precedence level so most expressions with `|` are unaffected
       (and awk has no other operator semantics for single `|`). */
    if (bawk_peek (P)->kind == T_PIPE) {
        int p2 = P->L->pos + 1;
        bawk_token *peek2 = (p2 < P->L->n) ? &P->L->toks[p2] : NULL;
        if (peek2 && peek2->kind == T_KW_GETLINE) {
            bawk_advance (P);   /* eat | */
            bawk_advance (P);   /* eat getline */
            lhs = bawk_parse_getline_after_keyword (P, BAWK_GETLINE_PIPE, lhs);
            if (!lhs) return NULL;
        }
    }
    return lhs;
}

/* ternary ?: */
static bawk_node *
bawk_parse_tern (bawk_parser *P)
{
    bawk_node *cond = bawk_parse_or (P); if (!cond) return NULL;
    if (bawk_peek(P)->kind == T_QMARK) {
        bawk_advance(P);
        bawk_node *th = bawk_parse_tern (P); if (!th) return NULL;
        if (bawk_expect (P, T_COLON, "expected : after ?") < 0) return NULL;
        bawk_node *el = bawk_parse_tern (P); if (!el) return NULL;
        bawk_node *n = bawk_new (P, N_TERNARY);
        n->A = cond; n->B = th; n->C = el;
        return n;
    }
    return cond;
}

/* assignment (right-assoc): lhs = | += | -= | *= | /= | %= | ^= | **= rhs */
static bawk_node *
bawk_parse_expr (bawk_parser *P)
{
    if (++P->depth > BAWK_MAX_DEPTH) {
        builtin_error ("awk: parse depth limit (%d) exceeded", BAWK_MAX_DEPTH);
        P->depth--;
        return NULL;
    }
    bawk_node *lhs = bawk_parse_tern (P);
    if (!lhs) { P->depth--; return NULL; }
    bawk_tok t = bawk_peek(P)->kind;
    if (t == T_ASSIGN || t == T_PLUSEQ || t == T_MINUSEQ
     || t == T_MULEQ  || t == T_DIVEQ  || t == T_MODEQ
     || t == T_POWEQ) {
        size_t off = bawk_peek(P)->off;
        bawk_advance(P);
        bawk_node *rhs = bawk_parse_expr (P);
        if (!rhs) { P->depth--; return NULL; }
        bawk_node *n = bawk_new (P, N_ASSIGN);
        n->src_off = off;
        n->nval = (double) t;
        n->A = lhs; n->B = rhs;
        P->depth--;
        return n;
    }
    P->depth--;
    return lhs;
}

/* statement: print | printf | if | while | for | break | continue
            | next | exit | block | expression-stmt */
static bawk_node *
bawk_parse_stmt (bawk_parser *P)
{
    bawk_skip_nl (P);
    bawk_token *t = bawk_peek (P);
    if (t->kind == T_LBRACE) return bawk_parse_block (P);
    if (t->kind == T_KW_PRINT || t->kind == T_KW_PRINTF) {
        bawk_nkind k = (t->kind == T_KW_PRINT) ? N_PRINT : N_PRINTF;
        bawk_advance(P);
        bawk_node *n = bawk_new (P, k);
        bawk_node *head = NULL, *tail = NULL;
        bawk_token *nt = bawk_peek (P);
        /* print (e1, e2, ...) and printf (fmt, args...): a parenthesized list
           of two or more expressions that ends the statement (or precedes a
           redirection) is the argument list. Anything else, such as
           `print (a, b) in arr` or `print (a) b`, is parsed again as an
           ordinary expression list. */
        if (nt->kind == T_LPAREN) {
            int save_pos = P->L->pos;
            bawk_advance (P);
            int count = 0, ok = 1;
            for (;;) {
                bawk_node *a = bawk_parse_expr_allow_gt (P);
                if (!a) { ok = 0; break; }
                bawk_node *cell = bawk_new (P, N_LIST);
                cell->A = a;
                if (!head) head = cell;
                if (tail) tail->next = cell;
                tail = cell;
                count++;
                if (!bawk_accept (P, T_COMMA)) break;
            }
            bawk_tok after = ok && bawk_accept (P, T_RPAREN) ? bawk_peek (P)->kind : T_LPAREN;
            if (count < 2 || (after != T_RBRACE && after != T_NEWLINE && after != T_SEMI
                              && after != T_EOF && after != T_GT && after != T_APPEND
                              && after != T_PIPE)) {
                P->L->pos = save_pos;
                head = tail = NULL;
            }
            nt = bawk_peek (P);
        }
        if (!head && nt->kind != T_RBRACE && nt->kind != T_NEWLINE && nt->kind != T_SEMI && nt->kind != T_EOF
            && nt->kind != T_GT && nt->kind != T_APPEND && nt->kind != T_PIPE) {
            for (;;) {
                bawk_node *a = bawk_parse_print_arg (P); if (!a) return NULL;
                bawk_node *cell = bawk_new (P, N_LIST);
                cell->A = a;
                if (!head) head = cell;
                if (tail) tail->next = cell;
                tail = cell;
                if (!bawk_accept (P, T_COMMA)) break;
            }
        }
        n->A = head;
        /* Stage B: optional redirect — print ARGS [> | >> | |] EXPR.
           Stored in n->B (target expr) + n->nval (op: 1=trunc, 2=append, 3=pipe). */
        n->nval = 0;
        bawk_token *rt = bawk_peek (P);
        if (rt->kind == T_APPEND) { bawk_advance (P); n->nval = 2; n->B = bawk_parse_expr (P); }
        else if (rt->kind == T_PIPE) { bawk_advance (P); n->nval = 3; n->B = bawk_parse_expr (P); }
        else if (rt->kind == T_GT) { bawk_advance (P); n->nval = 1; n->B = bawk_parse_expr (P); }
        return n;
    }
    if (t->kind == T_KW_DELETE) {
        bawk_advance (P);
        bawk_token *nm = bawk_peek (P);
        if (nm->kind != T_IDENT) { builtin_error ("delete: expected array name"); return NULL; }
        bawk_advance (P);
        bawk_node *n = bawk_new (P, N_DELETE);
        n->sval = bawk_strdup (nm->sval);
        n->A = NULL;   /* NULL subscript list = delete the whole array */
        if (bawk_accept (P, T_LBRACK)) {
            /* Chain subscript exprs directly via ->next, matching N_INDEX so
               the SUBSEP key is computed the same way. */
            bawk_node *idx_head = bawk_parse_expr (P); if (!idx_head) return NULL;
            bawk_node *tail = idx_head;
            while (bawk_accept (P, T_COMMA)) {
                bawk_node *nx = bawk_parse_expr (P); if (!nx) return NULL;
                tail->next = nx; tail = nx;
            }
            if (bawk_expect (P, T_RBRACK, "expected ] after delete subscript") < 0) return NULL;
            n->A = idx_head;
        }
        return n;
    }
    if (t->kind == T_KW_IF) {
        bawk_advance(P);
        if (bawk_expect (P, T_LPAREN, "expected ( after if") < 0) return NULL;
        bawk_node *cond = bawk_parse_expr (P); if (!cond) return NULL;
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        bawk_skip_nl (P);
        bawk_node *th = bawk_parse_stmt (P); if (!th) return NULL;
        bawk_skip_nl (P);
        bawk_node *el = NULL;
        if (bawk_accept (P, T_KW_ELSE)) {
            bawk_skip_nl (P);
            el = bawk_parse_stmt (P);
        }
        bawk_node *n = bawk_new (P, N_IF);
        n->A = cond; n->B = th; n->C = el;
        return n;
    }
    if (t->kind == T_KW_WHILE) {
        bawk_advance(P);
        if (bawk_expect (P, T_LPAREN, "expected ( after while") < 0) return NULL;
        bawk_node *cond = bawk_parse_expr (P); if (!cond) return NULL;
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        bawk_skip_nl (P);
        bawk_node *body = bawk_parse_stmt (P); if (!body) return NULL;
        bawk_node *n = bawk_new (P, N_WHILE);
        n->A = cond; n->B = body;
        return n;
    }
    if (t->kind == T_KW_FOR) {
        bawk_advance(P);
        if (bawk_expect (P, T_LPAREN, "expected ( after for") < 0) return NULL;
        /* Could be for (k in a) body */
        if (bawk_peek(P)->kind == T_IDENT) {
            int save = P->L->pos;
            bawk_token *id = bawk_advance(P);
            if (bawk_peek(P)->kind == T_KW_IN) {
                bawk_advance(P);
                bawk_token *arr = bawk_peek(P);
                if (arr->kind != T_IDENT) { builtin_error("for-in needs array name"); return NULL; }
                bawk_advance(P);
                if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
                bawk_skip_nl (P);
                bawk_node *body = bawk_parse_stmt (P); if (!body) return NULL;
                bawk_node *n = bawk_new (P, N_FORIN);
                n->sval = bawk_strdup (id->sval);
                n->array_name = bawk_strdup (arr->sval);
                n->C = body;
                return n;
            }
            P->L->pos = save;
        }
        /* C-style for (init; cond; step) body */
        bawk_node *init = NULL, *cond = NULL, *step = NULL;
        if (bawk_peek(P)->kind != T_SEMI) init = bawk_parse_expr (P);
        if (bawk_expect (P, T_SEMI, "expected ;") < 0) return NULL;
        if (bawk_peek(P)->kind != T_SEMI) cond = bawk_parse_expr (P);
        if (bawk_expect (P, T_SEMI, "expected ;") < 0) return NULL;
        if (bawk_peek(P)->kind != T_RPAREN) step = bawk_parse_expr (P);
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        bawk_skip_nl (P);
        bawk_node *body = bawk_parse_stmt (P); if (!body) return NULL;
        bawk_node *n = bawk_new (P, N_FOR);
        n->A = init; n->B = cond; n->C = step; n->body = body;
        return n;
    }
    if (t->kind == T_KW_BREAK)    { bawk_advance(P); return bawk_new (P, N_BREAK); }
    if (t->kind == T_KW_CONTINUE) { bawk_advance(P); return bawk_new (P, N_CONTINUE); }
    if (t->kind == T_KW_NEXT)     { bawk_advance(P); return bawk_new (P, N_NEXT); }
    if (t->kind == T_KW_NEXTFILE) { bawk_advance(P); return bawk_new (P, N_NEXTFILE); }
    if (t->kind == T_KW_EXIT) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_EXIT);
        if (bawk_peek(P)->kind != T_NEWLINE && bawk_peek(P)->kind != T_SEMI
         && bawk_peek(P)->kind != T_RBRACE && bawk_peek(P)->kind != T_EOF)
            n->A = bawk_parse_expr (P);
        return n;
    }
    if (t->kind == T_KW_RETURN) {
        bawk_advance(P);
        bawk_node *n = bawk_new (P, N_RETURN);
        if (bawk_peek(P)->kind != T_NEWLINE && bawk_peek(P)->kind != T_SEMI
         && bawk_peek(P)->kind != T_RBRACE && bawk_peek(P)->kind != T_EOF)
            n->A = bawk_parse_expr (P);
        return n;
    }
    if (t->kind == T_KW_DO) {
        /* do { body } while (cond) — represented as N_WHILE with a flag.
           Use sval = "do" to distinguish from regular while. */
        bawk_advance(P);
        bawk_skip_nl (P);
        bawk_node *body = bawk_parse_stmt (P); if (!body) return NULL;
        bawk_skip_nl (P);
        if (bawk_expect (P, T_KW_WHILE, "expected while after do-body") < 0) return NULL;
        if (bawk_expect (P, T_LPAREN, "expected ( after while") < 0) return NULL;
        bawk_node *cond = bawk_parse_expr (P); if (!cond) return NULL;
        if (bawk_expect (P, T_RPAREN, "expected )") < 0) return NULL;
        bawk_node *n = bawk_new (P, N_WHILE);
        n->A = cond; n->B = body;
        n->nval = 1;   /* 1 = do-while semantics: run body at least once */
        return n;
    }
    /* Expression statement. */
    return bawk_parse_expr (P);
}

static bawk_node *
bawk_parse_block (bawk_parser *P)
{
    if (bawk_expect (P, T_LBRACE, "expected {") < 0) return NULL;
    bawk_node *blk = bawk_new (P, N_BLOCK);
    bawk_node *head = NULL, *tail = NULL;
    while (1) {
        bawk_skip_nl (P);
        if (bawk_peek(P)->kind == T_RBRACE) break;
        if (bawk_peek(P)->kind == T_EOF) { builtin_error("unterminated {"); return NULL; }
        bawk_node *s = bawk_parse_stmt (P); if (!s) return NULL;
        bawk_node *cell = bawk_new (P, N_LIST);
        cell->A = s;
        if (!head) head = cell;
        if (tail) tail->next = cell;
        tail = cell;
        bawk_accept (P, T_SEMI);
    }
    if (bawk_expect (P, T_RBRACE, "expected }") < 0) return NULL;
    blk->A = head;
    return blk;
}

/*
 * awk grammar (EBNF), documenting the hand-written recursive-descent
 * parser below. Newlines and semicolons are statement separators.
 *
 * program      ::= (funcdef | rule)* EOF
 * funcdef      ::= "function" IDENT "(" [ident-list] ")" block
 * rule         ::= "BEGIN" action | "END" action | [expr] action?
 * action       ::= block | default-print
 * block        ::= "{" stmt* "}"
 *
 * stmt         ::= block
 *                | "print" [print-args] [redir]
 *                | "printf" [print-args] [redir]
 *                | "delete" IDENT ["[" expr-list "]"]
 *                | "if" "(" expr ")" stmt ["else" stmt]
 *                | "while" "(" expr ")" stmt
 *                | "do" stmt "while" "(" expr ")"
 *                | "for" "(" IDENT "in" IDENT ")" stmt
 *                | "for" "(" [expr] ";" [expr] ";" [expr] ")" stmt
 *                | "break" | "continue" | "next" | "nextfile"
 *                | "exit" [expr] | "return" [expr] | expr
 *
 * expr         ::= assignment
 * assignment   ::= ternary [("="|"+="|"-="|"*="|"/="|"%="|"^="|"**=") assignment]
 * ternary      ::= or ["?" ternary ":" ternary]
 * or           ::= and ("||" and)* ["|" "getline" [IDENT]]
 * and          ::= in-expr ("&&" in-expr)*
 * in-expr      ::= match-expr ("in" IDENT)*
 * match-expr   ::= relational (("~"|"!~") relational)?
 * relational   ::= concat (("<"|"<="|">"|">="|"=="|"!=") concat)?
 * concat       ::= additive additive*
 * additive     ::= multiplicative (("+"|"-") multiplicative)*
 * multiplicative ::= unary (("*"|"/"|"%") unary)*
 * unary        ::= ("-"|"!") unary | power
 * power        ::= primary [("^"|"**") unary]
 * primary      ::= NUMBER | STRING | REGEX | IDENT ["(" args? ")" | "[" expr-list "]"]
 *                | "$" field-operand | "(" expr ")" | "(" expr-list ")" "in" IDENT
 *                | builtin-call | "getline" [IDENT] [("<" expr)]
 *
 * expr-list    ::= expr ("," expr)*
 * print-args   ::= print-arg ("," print-arg)*
 * redir        ::= (">"|">>"|"|") expr
 */
static bawk_node *
bawk_parse_program (bawk_parser *P)
{
    bawk_node *prog = bawk_new (P, N_LIST);
    bawk_node *head = NULL, *tail = NULL;
    while (1) {
        bawk_skip_nl (P);
        if (bawk_peek(P)->kind == T_EOF) break;
        /* Function definition at top level. */
        if (bawk_peek(P)->kind == T_KW_FUNCTION) {
            bawk_advance (P);
            if (bawk_peek(P)->kind != T_IDENT) {
                builtin_error ("expected function name"); return NULL;
            }
            bawk_node *fdef = bawk_new (P, N_FUNCDEF);
            fdef->sval = bawk_strdup (bawk_peek(P)->sval);
            bawk_advance (P);
            if (bawk_expect (P, T_LPAREN, "expected ( after function name") < 0) return NULL;
            /* Parse comma-separated parameter list. */
            bawk_node *plist = NULL, *ptail = NULL;
            while (bawk_peek(P)->kind == T_IDENT) {
                bawk_node *param = bawk_new (P, N_IDENT);
                param->sval = bawk_strdup (bawk_peek(P)->sval);
                bawk_advance (P);
                if (!plist) plist = param;
                if (ptail) ptail->next = param;
                ptail = param;
                if (bawk_peek(P)->kind == T_COMMA) bawk_advance (P);
                else break;
            }
            if (bawk_expect (P, T_RPAREN, "expected ) after parameters") < 0) return NULL;
            fdef->A = plist;
            bawk_skip_nl (P);
            fdef->B = bawk_parse_block (P);
            if (!fdef->B) return NULL;
            bawk_node *cell = bawk_new (P, N_LIST);
            cell->A = fdef;
            if (!head) head = cell;
            if (tail) tail->next = cell;
            tail = cell;
            bawk_accept (P, T_SEMI);
            continue;
        }
        bawk_node *r = bawk_new (P, N_RULE);
        if (bawk_peek(P)->kind == T_KW_BEGIN) { bawk_advance(P); r->nval = 1; }
        else if (bawk_peek(P)->kind == T_KW_END) { bawk_advance(P); r->nval = 2; }
        else if (bawk_peek(P)->kind != T_LBRACE) {
            r->A = bawk_parse_expr (P); if (!r->A) return NULL;
            r->nval = 0;
        }
        bawk_skip_nl (P);
        if (bawk_peek(P)->kind == T_LBRACE) {
            r->B = bawk_parse_block (P); if (!r->B) return NULL;
        } else if (r->A) {
            /* pattern without action: default action is print $0 */
            bawk_node *pr = bawk_new (P, N_PRINT);
            r->B = pr;
        }
        bawk_node *cell = bawk_new (P, N_LIST);
        cell->A = r;
        if (!head) head = cell;
        if (tail) tail->next = cell;
        tail = cell;
        bawk_accept (P, T_SEMI);
    }
    prog->A = head;
    return prog;
}

static bawk_special_id
bawk_special_id_from_name (const char *s)
{
    if (!s) return BAWK_SPECIAL_NONE;
    if (!strcmp (s, "NR")) return BAWK_SPECIAL_NR;
    if (!strcmp (s, "FNR")) return BAWK_SPECIAL_FNR;
    if (!strcmp (s, "NF")) return BAWK_SPECIAL_NF;
    if (!strcmp (s, "FS")) return BAWK_SPECIAL_FS;
    if (!strcmp (s, "OFS")) return BAWK_SPECIAL_OFS;
    if (!strcmp (s, "SUBSEP")) return BAWK_SPECIAL_SUBSEP;
    if (!strcmp (s, "CONVFMT")) return BAWK_SPECIAL_CONVFMT;
    if (!strcmp (s, "OFMT")) return BAWK_SPECIAL_OFMT;
    if (!strcmp (s, "ORS")) return BAWK_SPECIAL_ORS;
    if (!strcmp (s, "FILENAME")) return BAWK_SPECIAL_FILENAME;
    if (!strcmp (s, "RSTART")) return BAWK_SPECIAL_RSTART;
    if (!strcmp (s, "RLENGTH")) return BAWK_SPECIAL_RLENGTH;
    return BAWK_SPECIAL_NONE;
}

static void
bawk_lower_node (bawk_node *n)
{
    if (!n) return;

    if (n->kind == N_IDENT)
        bawk_n_op (n) = bawk_special_id_from_name (n->sval);

    if (n->kind == N_GETLINE || n->kind == N_GETLINE_PIPE) {
        if (n->kind == N_GETLINE_PIPE)
            bawk_n_getline_source (n) = BAWK_GETLINE_PIPE;
        else if (n->A && bawk_n_getline_source (n) == BAWK_GETLINE_MAIN)
            bawk_n_getline_source (n) = BAWK_GETLINE_FILE;
        bawk_n_getline_target (n) = n->sval ? BAWK_GETLINE_TARGET_SCALAR
                                            : BAWK_GETLINE_TARGET_RECORD;
    }

    if ((n->kind == N_INDEX || n->kind == N_DELETE || n->kind == N_INARRAY)
        && n->A && n->A->next)
        bawk_n_op (n) = 1;       /* subscript list uses SUBSEP join shape */

    bawk_lower_node (n->A);
    bawk_lower_node (n->B);
    bawk_lower_node (n->C);
    bawk_lower_node (n->body);
    bawk_lower_node (n->next);
}

static void
bawk_lower_program (bawk_parser *P, bawk_node *prog)
{
    (void) P;
    const char *disable = getenv ("BASHAWK_NO_LOWER");
    if (disable && !strcmp (disable, "1")) return;
    bawk_lower_node (prog);
}

/* ================================================================ */
/* Interpreter                                                       */
/* ================================================================ */

/* Values: number or string. We store strings for everything and lazy-
   convert. Simplification vs full POSIX, but adequate for most uses. */
/* Strings carry their length: NUL bytes are data (gawk, mawk), so records,
   fields and values keep them. s[len] is always a NUL terminator too. */
typedef struct {
    char  *s;
    size_t len;
    double n;
    int    have_n;
    /* POSIX "numeric string" marking. BAWK_STRNUM: the string came from
       input (a field, getline, -v or VAR=VALUE, split(), ARGV, ENVIRON)
       and compares as a number when it looks like one. BAWK_UNINIT: an
       unset variable, which is both "" and 0. 0: an ordinary string. */
    int    strnum;
} bawk_val;
enum { BAWK_STRNUM = 1, BAWK_UNINIT = 2 };

static void bawk_val_free (bawk_val *v) { free (v->s); v->s = NULL; v->len = 0; v->n = 0; v->have_n = 0; v->strnum = 0; }
/* A copy of the LEN bytes at S, NUL-terminated. */
static char *bawk_memdup (const char *s, size_t len)
{
    if (len == SIZE_MAX) { fatal_error ("awk: string too large"); abort (); }
    char *p = xmalloc (len + 1);
    if (len) memcpy (p, s, len);
    p[len] = 0;
    return p;
}
static void bawk_val_set_mem (bawk_val *v, const char *s, size_t len) {
    char *copy = bawk_memdup (s ? s : "", s ? len : 0);
    free (v->s);
    v->s = copy;
    v->len = s ? len : 0;
    v->have_n = 0;
    v->strnum = 0;
}
static void bawk_val_set_str (bawk_val *v, const char *s) {
    bawk_val_set_mem (v, s, s ? strlen (s) : 0);
}
static void bawk_val_set_num (bawk_val *v, double n) {
    free (v->s); v->s = NULL; v->len = 0;
    v->n = n; v->have_n = 1;
    v->strnum = 0;
}
/* A string from input data: a numeric string when it looks like a number. */
static void bawk_val_set_input_mem (bawk_val *v, const char *s, size_t len) {
    bawk_val_set_mem (v, s, len);
    v->strnum = BAWK_STRNUM;
}
static void bawk_val_set_input (bawk_val *v, const char *s) {
    bawk_val_set_input_mem (v, s, s ? strlen (s) : 0);
}
/* Read a stored scalar into a fresh value, keeping its strnum mark; an unset
   scalar reads as the uninitialized value. */
static void bawk_val_read (bawk_val *r, const bawk_val *v) {
    if (v->s) { bawk_val_set_mem (r, v->s, v->len); r->strnum = v->strnum; }
    else if (v->have_n) bawk_val_set_num (r, v->n);
    else { bawk_val_set_str (r, ""); r->strnum = BAWK_UNINIT; }
}

static double
bawk_val_to_num (bawk_val *v)
{
    if (v->have_n) return v->n;
    if (!v->s) return 0;
    return strtod (v->s, NULL);
}

/* Counter reads copy the scalar value so assignment preserves strings until
   the next numeric operation, just like other writable awk variables. */
static bawk_val
bawk_val_copy (const bawk_val *v)
{
    bawk_val r = {0};
    if (v->s) { bawk_val_set_mem (&r, v->s, v->len); r.strnum = v->strnum; }
    else if (v->have_n) bawk_val_set_num (&r, v->n);
    return r;
}

static void
bawk_counter_advance (bawk_val *v)
{
    double n = trunc (bawk_val_to_num (v));
    bawk_val_set_num (v, n + 1);
}

/* GNU awk exposes integer counter reads, while an assignment expression
   still returns its original RHS. Preserve an assigned string's spelling
   when its numeric value is already integral. No integer cast is needed. */
static bawk_val
bawk_counter_read (bawk_val *v)
{
    double n = bawk_val_to_num (v), integral = trunc (n);
    if (n != integral) bawk_val_set_num (v, integral);
    return bawk_val_copy (v);
}

/* Active CONVFMT / OFMT formats. bawk_val_to_str takes no ctx, so the
   current CONVFMT is tracked here (reset to "%.6g" at each run start, and
   repointed whenever CONVFMT/OFMT is assigned). Integer-valued numbers are
   always rendered as integers and ignore both formats (POSIX). */
static const char *bawk_convfmt = "%.6g";
static const char *bawk_ofmt    = "%.6g";

/* Render a number with `fmt` (or as an integer when it has no fractional
   part). Used by bawk_val_to_str (CONVFMT) and by print (OFMT). */
static const char *
bawk_num_to_str (double n, const char *fmt, char *buf, size_t bufsz)
{
    if (isfinite (n) && n >= -0x1p63 && n < 0x1p63 && n == trunc (n))
        snprintf (buf, bufsz, "%lld", (long long) n);
    else
        snprintf (buf, bufsz, fmt ? fmt : "%.6g", n);
    return buf;
}

/* Validate a script-supplied CONVFMT/OFMT before it is handed to snprintf()
   in bawk_num_to_str(). The only argument is a scalar double, so the format
   must hold at most one conversion and it must be numeric: reject the %n/%N
   write primitive and the %s pointer deref (mirrors bawk_format()'s
   conversion allow-list). Falls back to the default "%.6g". */
static const char *
bawk_safe_numfmt (const char *fmt)
{
    if (!fmt) return "%.6g";
    int nconv = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;                 /* literal %% */
        while (*p && strchr ("-+ #0", *p)) p++;
        while (isdigit ((unsigned char) *p)) p++;
        if (*p == '.') { p++; while (isdigit ((unsigned char) *p)) p++; }
        while (*p && strchr ("hlLjzt", *p)) p++;
        if (!*p || !strchr ("eEfgGdiouxXc", *p)) return "%.6g";
        if (++nconv > 1) return "%.6g";
    }
    return fmt;
}

static const char *
bawk_val_to_str (bawk_val *v, char *buf, size_t bufsz)
{
    if (v->s) return v->s;
    if (v->have_n)
        return bawk_num_to_str (v->n, bawk_convfmt, buf, bufsz);
    return "";
}

/* bawk_val_to_str with the string's length, NUL bytes included. */
static const char *
bawk_val_to_strl (bawk_val *v, char *buf, size_t bufsz, size_t *lenp)
{
    if (v->s) { *lenp = v->len; return v->s; }
    const char *s = bawk_val_to_str (v, buf, bufsz);
    *lenp = strlen (s);
    return s;
}

/* A value's truth: a nonzero number or a non-empty string ("\0" is not empty). */
static int
bawk_val_true (bawk_val *v)
{
    return bawk_val_to_num (v) != 0 || (v->s && v->len);
}

/* Byte comparison of two counted strings (strcmp order for NUL-free ones). */
static int
bawk_memcmp2 (const char *a, size_t al, const char *b, size_t bl)
{
    int r = memcmp (a, b, al < bl ? al : bl);
    if (r) return r;
    return al < bl ? -1 : al > bl;
}


/* Shared awk-style printf formatter. Walks `fmt`, consuming one entry from
   `args[]` per conversion. Returns malloc'd output (caller frees) or NULL
   on internal error / disallowed conversion. Rejects %n/%N (write-pointer
   primitive). Unknown conversion characters are silently absorbed (matching
   the prior, less-paranoid behavior); future hardening may reject them.
   FMT is FMTLEN bytes and the result is *OUTLEN bytes: either may hold NUL
   bytes (gawk), and %s copies its argument's NUL bytes. */
static char *
bawk_format (const char *fmt, size_t fmtlen, bawk_val *args, int nargs, size_t *outlen)
{
    size_t cap = 4096; size_t op = 0;
    char *out = xmalloc (cap);
    if (!out) return NULL;
    int ai = 0;
    bawk_val empty = {0};
    const char *fend = fmt + fmtlen;
    *outlen = 0;
    for (const char *p = fmt; p < fend; p++) {
        if (op + 32 >= cap) {
            size_t nc = cap * 2;
            char *no = xrealloc (out, nc);
            if (!no) { free (out); return NULL; }
            out = no; cap = nc;
        }
        if (*p != '%') { out[op++] = *p; continue; }
        p++;
        if (*p == '%') { out[op++] = '%'; continue; }

        char spec[64]; int sp = 0;
        spec[sp++] = '%';
        while (*p && strchr ("-+ #0", *p) && sp < (int) sizeof spec - 1)
            spec[sp++] = *p++;
        if (*p == '*') {
            bawk_val *w = (ai < nargs) ? &args[ai++] : &empty;
            int width = (int) bawk_val_to_num (w);
            int n = snprintf (spec + sp, sizeof spec - (size_t) sp, "%d", width);
            if (n < 0 || sp + n >= (int) sizeof spec) { free (out); return NULL; }
            sp += n; p++;
        } else {
            while (isdigit ((unsigned char) *p) && sp < (int) sizeof spec - 1)
                spec[sp++] = *p++;
        }
        if (*p == '.') {
            spec[sp++] = *p++;
            if (*p == '*') {
                bawk_val *pr = (ai < nargs) ? &args[ai++] : &empty;
                int prec = (int) bawk_val_to_num (pr);
                if (prec < 0) prec = 0;
                int n = snprintf (spec + sp, sizeof spec - (size_t) sp, "%d", prec);
                if (n < 0 || sp + n >= (int) sizeof spec) { free (out); return NULL; }
                sp += n; p++;
            } else {
                while (isdigit ((unsigned char) *p) && sp < (int) sizeof spec - 1)
                    spec[sp++] = *p++;
            }
        }
        /* awk values are stored as strings or doubles, so C printf length
           modifiers do not add storage precision here. Accept the common C
           modifiers for script compatibility, but normalize them away before
           dispatching to snprintf with awk's scalar argument types. */
        if (*p == 'h' || *p == 'l') {
            int c = *p++;
            if (*p == c) p++;
        } else if (*p == 'L' || *p == 'j' || *p == 'z' || *p == 't') {
            p++;
        }
        if (*p == 'n' || *p == 'N') {
            builtin_error ("awk: %%n/%%N is not allowed in format");
            free (out); return NULL;
        }
        if (p >= fend) break;
        if (!*p || !strchr ("dioxXucsfeEgG", *p)) continue;
        char conv = *p;
        /* Integer conversions: widen to long long so large awk numbers (stored
           as doubles) are not truncated by a 32-bit int (e.g. printf "%d" of
           2147483648). Insert the "ll" length modifier before the spec char. */
        /* The fill loops cap sp at sizeof spec - 1 and the precision '.'
           append is unbounded; the "ll" length modifier + conversion char +
           NUL write through index sp+3, so bail once 4 more bytes would not
           fit (sp+4 > sizeof spec, i.e. sp >= 61 for spec[64]). */
        if (sp + 4 > (int) sizeof spec) { free (out); return NULL; }
        if (strchr ("diouxX", conv)) { spec[sp++] = 'l'; spec[sp++] = 'l'; }
        spec[sp++] = conv; spec[sp] = '\0';
        bawk_val *a = (ai < nargs) ? &args[ai++] : &empty;
        char chunk[1024];
        char *big = NULL;
        int cn = 0;
        if (conv == 's') {
            /* Strings are not cut at sizeof chunk, and NUL bytes are kept:
               the precision and width count bytes, as in snprintf. */
            char b2[64]; size_t sl;
            const char *sv = bawk_val_to_strl (a, b2, sizeof b2, &sl);
            const char *q = spec + 1;
            int left = 0;
            long width = 0, prec = -1;
            for (; *q && strchr ("-+ #0", *q); q++) if (*q == '-') left = 1;
            for (; isdigit ((unsigned char) *q); q++) if (width < INT_MAX / 10) width = width * 10 + (*q - '0');
            if (*q == '.') {
                prec = 0;
                for (q++; isdigit ((unsigned char) *q); q++) if (prec < INT_MAX / 10) prec = prec * 10 + (*q - '0');
            }
            size_t take = (prec >= 0 && (size_t) prec < sl) ? (size_t) prec : sl;
            size_t pad = (size_t) width > take ? (size_t) width - take : 0;
            if (take + pad > (size_t) INT_MAX) { free (out); return NULL; }
            big = xmalloc (take + pad + 1);
            if (left) { memcpy (big, sv, take); memset (big + take, ' ', pad); }
            else { memset (big, ' ', pad); memcpy (big + pad, sv, take); }
            cn = (int) (take + pad);
        } else if (strchr ("di", conv)) {
            snprintf (chunk, sizeof chunk, spec, (long long) bawk_val_to_num (a));
        } else if (strchr ("oxXu", conv)) {
            snprintf (chunk, sizeof chunk, spec, (unsigned long long) bawk_val_to_num (a));
        } else if (conv == 'c') {
            /* POSIX: a numeric argument is a character code; a string
               argument contributes its first character. awk stores
               pure numbers with s==NULL and strings with s!=NULL. */
            if (a->s != NULL)
                cn = snprintf (chunk, sizeof chunk, spec, (int) (unsigned char) a->s[0]);
            else
                cn = snprintf (chunk, sizeof chunk, spec, (int) bawk_val_to_num (a));
        } else {
            snprintf (chunk, sizeof chunk, spec, bawk_val_to_num (a));
        }
        /* %c of NUL (or of an empty string) writes a NUL byte, as in gawk:
           take the snprintf count, not strlen. */
        if (conv == 'c') {
            if (cn < 0) cn = 0;
            if (cn >= (int) sizeof chunk) cn = (int) sizeof chunk - 1;
        }
        const char *src = big ? big : chunk;
        size_t cl = big || conv == 'c' ? (size_t) cn : strlen (chunk);
        if (op + cl + 1 > cap) {
            size_t nc = cap;
            while (op + cl + 1 > nc) nc *= 2;
            char *no = xrealloc (out, nc);
            if (!no) { free (out); free (big); return NULL; }
            out = no; cap = nc;
        }
        memcpy (out + op, src, cl); op += cl;
        free (big);
    }
    out[op] = '\0';
    *outlen = op;
    return out;
}

/* Variable / array store. Linear search — fine for the sizes typical
   awk scripts use. */
typedef struct bawk_var {
    char  *name;
    bawk_val val;
    int    is_array;
    /* If is_array, key/val arrays. */
    char     **akey;
    size_t    *aklen;     /* key lengths: subscripts may contain NUL bytes */
    bawk_val  *aval;
    int       n_a, cap_a;
    /* A function parameter bound to the caller's array (or to an untyped
       variable that may become one): array operations act on *ref. */
    struct bawk_var *ref;
    struct bawk_var *next;
} bawk_var;

typedef struct {
    bawk_var *head;
    /* Fields: $0 stored as fld[0], $1..$NF as fld[1..nf]; fldlen[i] is the
       byte length of fld[i], which may contain NUL bytes. */
    char    **fld;
    size_t   *fldlen;
    int       nf;
    int       fld_cap;
    bawk_val  NR;
    bawk_val  FNR;          /* writable per-file counter; reset at input open */
    char     *FS;
    char     *OFS;
    char     *ORS;
    char     *SUBSEP;       /* multi-dim array key separator (default \034) */
    /* Byte lengths of FS, OFS, ORS and SUBSEP: a separator may be or hold a
       NUL byte (FS = "\0", -F '\0', ORS = sprintf("%c", 0)), as in gawk. */
    size_t    FSlen, OFSlen, ORSlen, SUBSEPlen;
    char     *CONVFMT;      /* number->string format for non-output contexts */
    char     *OFMT;         /* number->string format for print */
    char     *FILENAME;
    long      RSTART;
    long      RLENGTH;
    int       rs_para;      /* last record was read with RS="" (paragraphs) */
    /* control-flow flags set by statements */
    int       brk_flag;
    int       cont_flag;
    int       next_flag;
    int       nextfile_flag;      /* set by N_NEXTFILE; cleared by outer file walker */
    int       exit_flag;
    int       exit_code;
    int       fatal_flag;         /* fatal runtime error: skip END rules too */
    int       eval_depth;
    int       max_stack;
    /* User-function support. */
    int       return_flag;        /* set by N_RETURN; consumed by N_USERCALL */
    bawk_val  return_val;
    /* User-function table. Linked list keyed by name. */
    struct bawk_func *funcs;
    /* Output: usually stdout. */
    FILE     *out;
    int       out_tty;            /* stdout is a terminal: flush before tty reads */
    /* Stage B: open output streams for `print > FILE`, `print >> FILE`,
       `print | "cmd"` and input streams for `"cmd" | getline`.
       Linear lookup; closed in bawk_free_all. For pipe-style streams
       (op 3/4) `pid` is the child /bin/sh fork that bawk_pclose_guarded
       reaps with an EINTR-safe waitpid; for fopen-style streams (op
       1/2/5) `pid` is -1. */
    struct bawk_stream {
        char *key;        /* filename or command string */
        int   op;         /* 1=trunc, 2=append, 3=pipe-out, 4=pipe-in */
        FILE *fp;
        pid_t pid;        /* child pid for op 3/4; -1 otherwise; -2 for a
                             shared standard stream (/dev/stdout, /dev/stderr)
                             that close() flushes but never fcloses */
    } *streams;
    size_t n_streams, cap_streams;
} bawk_ctx;

typedef struct bawk_func {
    char *name;
    char **params;        /* parameter names; NULL-terminated */
    int   n_params;
    bawk_node *body;
    struct bawk_func *next;
} bawk_func;

static bawk_var *
bawk_lookup_or_create (bawk_ctx *c, const char *name)
{
    for (bawk_var *v = c->head; v; v = v->next)
        if (!strcmp (v->name, name)) return v;
    bawk_var *v = bawk_calloc (1, sizeof *v);
    v->name = bawk_strdup (name);
    v->next = c->head;
    c->head = v;
    return v;
}

/* Variables the interpreter keeps outside the variable list. */
static int
bawk_special_name (const char *name)
{
    static const char *const names[] = { "NR", "FNR", "NF", "FS", "OFS", "ORS",
        "SUBSEP", "CONVFMT", "OFMT", "FILENAME", "RSTART", "RLENGTH", NULL };
    for (int i = 0; names[i]; i++) if (!strcmp (name, names[i])) return 1;
    return 0;
}

/* The variable an array operation on NAME acts on. */
static bawk_var *
bawk_lookup_array (bawk_ctx *c, const char *name)
{
    bawk_var *v = bawk_lookup_or_create (c, name);
    while (v->ref) v = v->ref;
    return v;
}

/* NAME used as a scalar. A parameter bound to an untyped caller variable is
   a local scalar from here on (awk passes scalars by value). */
static bawk_var *
bawk_lookup_scalar (bawk_ctx *c, const char *name)
{
    bawk_var *v = bawk_lookup_or_create (c, name);
    if (v->ref) {
        bawk_var *t = v->ref;
        while (t->ref) t = t->ref;
        if (!t->is_array) v->ref = NULL;
    }
    return v;
}

static bawk_val *
bawk_array_slot (bawk_var *arr, const char *key, size_t klen, int create)
{
    arr->is_array = 1;
    for (int i = 0; i < arr->n_a; i++)
        if (arr->aklen[i] == klen && !memcmp (arr->akey[i], key, klen)) return &arr->aval[i];
    if (!create) return NULL;
    if (arr->n_a == arr->cap_a) {
        int nc = arr->cap_a ? arr->cap_a * 2 : 8;
        char **nk = xrealloc (arr->akey, (size_t) nc * sizeof *nk);
        arr->akey = nk;
        size_t *nl = xrealloc (arr->aklen, (size_t) nc * sizeof *nl);
        arr->aklen = nl;
        bawk_val *nv = xrealloc (arr->aval, (size_t) nc * sizeof *nv);
        if (!nk || !nl || !nv) return NULL;
        arr->aval = nv; arr->cap_a = nc;
    }
    arr->aklen[arr->n_a] = klen;
    arr->akey[arr->n_a] = bawk_memdup (key, klen);
    memset (&arr->aval[arr->n_a], 0, sizeof arr->aval[arr->n_a]);
    return &arr->aval[arr->n_a++];
}

/* Ensure c->fld[] has space for index n. Returns 0 on success, -1 on OOM. */
static int
bawk_fld_grow (bawk_ctx *c, int n)
{
    if (n < c->fld_cap) return 0;
    int nc = c->fld_cap ? c->fld_cap : 16;
    while (n >= nc) {
        if (nc > INT_MAX / 2) return -1;
        nc *= 2;
    }
    char **nf = xrealloc (c->fld, (size_t) nc * sizeof *nf);
    if (!nf) return -1;
    c->fld = nf;
    size_t *nl = xrealloc (c->fldlen, (size_t) nc * sizeof *nl);
    if (!nl) return -1;
    c->fldlen = nl;
    /* zero new slots */
    for (int i = c->fld_cap; i < nc; i++) { nf[i] = NULL; nl[i] = 0; }
    c->fld_cap = nc;
    return 0;
}

/* Store the LEN bytes at S as field N (already allocated by bawk_fld_grow). */
static void
bawk_fld_set (bawk_ctx *c, int n, const char *s, size_t len)
{
    free (c->fld[n]);
    c->fld[n] = bawk_memdup (s, len);
    c->fldlen[n] = len;
}

/* Split record into fields based on FS. On OOM, leaves c->nf at the count
   of successfully-copied fields (caller will see truncation). The record is
   LEN bytes and may contain NUL bytes, which are ordinary field data. */
static void
bawk_split_record (bawk_ctx *c, const char *line, size_t len)
{
    /* free old fields */
    for (int i = 0; i <= c->nf; i++) { free (c->fld[i]); c->fld[i] = NULL; c->fldlen[i] = 0; }
    c->nf = 0;
    if (bawk_fld_grow (c, 16) < 0) { builtin_error ("awk: oom in split"); return; }
    if (!line) { line = ""; len = 0; }
    bawk_fld_set (c, 0, line, len);

    if (!len) return;

    const char *p = line, *end = line + len;
    size_t fslen = c->FS ? c->FSlen : 0;
    if (!fslen || (fslen == 1 && c->FS[0] == ' ')) {
        /* default: split on runs of blanks and newlines, trimming (POSIX) */
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        while (p < end) {
            const char *s = p;
            while (p < end && *p != ' ' && *p != '\t' && *p != '\n') p++;
            int n = ++c->nf;
            if (bawk_fld_grow (c, n) < 0) { c->nf--; return; }
            bawk_fld_set (c, n, s, (size_t) (p - s));
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        }
    } else if (fslen == 1) {
        /* In paragraph mode newline separates fields whatever FS is. A NUL
           FS splits at NUL bytes. */
        char delim = c->FS[0], delim2 = c->rs_para ? '\n' : delim;
        for (;;) {
            const char *s = p;
            while (p < end && *p != delim && *p != delim2) p++;
            int n = ++c->nf;
            if (bawk_fld_grow (c, n) < 0) { c->nf--; return; }
            bawk_fld_set (c, n, s, (size_t) (p - s));
            if (p >= end) break;
            p++;
        }
    } else {
        /* regex FS — compile & loop */
        regex_t re;
        char *fsre = NULL;
        const char *fs = c->FS;
        size_t fsrelen = fslen;
        if (c->rs_para) {
            fsre = xmalloc (fslen + 6);
            fsre[0] = '(';
            memcpy (fsre + 1, c->FS, fslen);
            memcpy (fsre + 1 + fslen, ")|\n", 4);
            fsrelen = fslen + 4;
            fs = fsre;
        }
        int rc = bawk_regcomp (&re, fs, fsrelen);
        free (fsre);
        if (rc != 0) {
            /* compile failed: surface and fall back to single-field */
            builtin_warning ("awk: bad FS regex: %s", c->FS);
            c->nf = 1;
            if (bawk_fld_grow (c, 1) < 0) { c->nf = 0; return; }
            bawk_fld_set (c, 1, line, len);
            return;
        }
        regmatch_t m;
        size_t off = 0;
        while (off < len && bawk_regexec (&re, line, len, off, &m) == 0
               && m.rm_so >= 0) {
            int n = ++c->nf;
            if (bawk_fld_grow (c, n) < 0) { c->nf--; regfree (&re); return; }
            bawk_fld_set (c, n, line + off, (size_t) m.rm_so - off);
            int empty_here = (size_t) m.rm_eo == off;
            off = (size_t) m.rm_eo;
            if (empty_here) off++;     /* zero-width safety */
        }
        int n = ++c->nf;
        if (bawk_fld_grow (c, n) < 0) { c->nf--; regfree (&re); return; }
        if (off > len) off = len;
        bawk_fld_set (c, n, line + off, len - off);
        regfree (&re);
    }
}

/* RS handling. "\n" (the default) or any one character: records end at
   that byte. RS="": paragraph mode, records end at one or more blank lines
   and leading newlines are skipped (POSIX). A longer RS is an extended
   regular expression, as in gawk and mawk; that form reads the rest of the
   stream first. Returns the record length, or -1 at end of input. */
typedef struct { FILE *fp; char *buf; size_t len, off; } bawk_rsbuf;
static bawk_rsbuf bawk_rsbufs[16];

static void
bawk_rs_forget (FILE *fp)
{
    for (size_t i = 0; i < sizeof bawk_rsbufs / sizeof *bawk_rsbufs; i++)
        if (bawk_rsbufs[i].fp == fp) {
            free (bawk_rsbufs[i].buf);
            bawk_rsbufs[i] = (bawk_rsbuf){0};
        }
}

static int
bawk_line_room (char **line, size_t *cap, size_t need)
{
    if (*line && *cap >= need) return 0;
    size_t nc = *cap ? *cap : 128;
    while (nc < need) nc *= 2;
    char *nl = xrealloc (*line, nc);
    if (!nl) return -1;
    *line = nl; *cap = nc;
    return 0;
}

static ssize_t
bawk_read_record (bawk_ctx *c, FILE *fp, char **line, size_t *cap)
{
    const char *rs = "\n";
    size_t rslen = 1;
    char rb[64];
    /* gawk flushes terminal output before it waits on terminal input, so a
       prompt printed without a newline is visible. */
    if (c->out_tty && isatty (fileno (fp))) fflush (stdout);
    for (bawk_var *v = c->head; v; v = v->next)
        if (!strcmp (v->name, "RS")) {
            if (v->val.s || v->val.have_n) rs = bawk_val_to_strl (&v->val, rb, sizeof rb, &rslen);
            break;
        }
    /* RS of one byte, NUL included (RS = "\0" reads find -print0 output),
       ends records at that byte; RS = "" is paragraph mode. */
    c->rs_para = (rslen == 0);
    if (rslen == 1) {
        ssize_t rd = getdelim (line, cap, (unsigned char) rs[0], fp);
        if (rd > 0 && (*line)[rd - 1] == rs[0]) (*line)[--rd] = '\0';
        return rd;
    }
    if (!rslen) {
        char *l = NULL; size_t lc = 0, len = 0; ssize_t rd; int got = 0;
        while ((rd = getline (&l, &lc, fp)) != -1) {
            if (rd > 0 && l[rd - 1] == '\n') l[--rd] = '\0';
            if (rd == 0) { if (got) break; continue; }
            if (bawk_line_room (line, cap, len + (size_t) rd + 2) < 0) break;
            if (got) (*line)[len++] = '\n';
            memcpy (*line + len, l, (size_t) rd);
            len += (size_t) rd;
            got = 1;
        }
        free (l);
        if (!got) return -1;
        (*line)[len] = '\0';
        return (ssize_t) len;
    }
    bawk_rsbuf *b = NULL;
    for (size_t i = 0; i < sizeof bawk_rsbufs / sizeof *bawk_rsbufs; i++)
        if (bawk_rsbufs[i].fp == fp) { b = &bawk_rsbufs[i]; break; }
    if (!b) {
        for (size_t i = 0; i < sizeof bawk_rsbufs / sizeof *bawk_rsbufs; i++)
            if (!bawk_rsbufs[i].fp) { b = &bawk_rsbufs[i]; break; }
        if (!b) { builtin_error ("awk: too many regex-RS inputs"); return -1; }
        b->fp = fp;
        size_t bc = 0;
        char chunk[8192]; size_t rd;
        while ((rd = fread (chunk, 1, sizeof chunk, fp)) > 0) {
            if (bawk_line_room (&b->buf, &bc, b->len + rd + 1) < 0) break;
            memcpy (b->buf + b->len, chunk, rd);
            b->len += rd;
        }
        if (bawk_line_room (&b->buf, &bc, b->len + 1) < 0) { bawk_rs_forget (fp); return -1; }
        b->buf[b->len] = '\0';
    }
    if (b->off >= b->len) return -1;
    regex_t re;
    if (bawk_regcomp (&re, rs, rslen) != 0) {
        builtin_error ("awk: bad RS regex: %s", rs);
        return -1;
    }
    const char *p = b->buf + b->off;
    size_t rem = b->len - b->off, rlen = rem, adv = rem;
    regmatch_t m;
    if (bawk_regexec (&re, b->buf, b->len, b->off, &m) == 0
        && m.rm_eo > m.rm_so && (size_t) m.rm_so - b->off < rem) {
        rlen = (size_t) m.rm_so - b->off;
        adv = (size_t) m.rm_eo - b->off;
    }
    regfree (&re);
    if (bawk_line_room (line, cap, rlen + 1) < 0) return -1;
    memcpy (*line, p, rlen);
    (*line)[rlen] = '\0';
    b->off += adv;
    return (ssize_t) rlen;
}

static void
bawk_set_record (bawk_ctx *c, const char *line, size_t len)
{
    bawk_split_record (c, line ? line : "", line ? len : 0);
}

static void
bawk_set_scalar_from_getline (bawk_ctx *c, const char *name, const char *line, size_t len)
{
    if (!name) return;
    if (!line) { line = ""; len = 0; }
    if (!strcmp (name, "NR") || !strcmp (name, "FNR")) {
        bawk_val_set_mem (!strcmp (name, "NR") ? &c->NR : &c->FNR, line, len);
        return;
    }
    bawk_var *v = bawk_lookup_scalar (c, name);
    bawk_val_free (&v->val);
    bawk_val_set_input_mem (&v->val, line, len);
}

static int
bawk_rebuild_record (bawk_ctx *c)
{
    const char *ofs = c->OFS ? c->OFS : " ";
    size_t olen = c->OFS ? c->OFSlen : 1, total = 0;

    for (int i = 1; i <= c->nf; i++) {
        if (i > 1) total += olen;
        total += c->fld[i] ? c->fldlen[i] : 0;
    }

    char *buf = xmalloc (total + 1);
    if (!buf) {
        builtin_error ("awk: out of memory rebuilding $0");
        bawk_fld_set (c, 0, "", 0);
        return -1;
    }

    size_t off = 0;
    for (int i = 1; i <= c->nf; i++) {
        const char *field = c->fld[i] ? c->fld[i] : "";
        size_t flen = c->fld[i] ? c->fldlen[i] : 0;
        if (i > 1 && olen) {
            memcpy (buf + off, ofs, olen);
            off += olen;
        }
        if (flen) {
            memcpy (buf + off, field, flen);
            off += flen;
        }
    }
    buf[off] = '\0';

    free (c->fld[0]);
    c->fld[0] = buf;
    c->fldlen[0] = off;
    return 0;
}

static void
bawk_assign_nf (bawk_ctx *c, int newnf)
{
    if (newnf < 0) newnf = 0;
    if (newnf > c->nf) {
        if (bawk_fld_grow (c, newnf) < 0) return;
        while (c->nf < newnf) {
            c->nf++;
            bawk_fld_set (c, c->nf, "", 0);
        }
    } else if (newnf < c->nf) {
        for (int i = newnf + 1; i <= c->nf; i++) {
            free (c->fld[i]);
            c->fld[i] = NULL;
            c->fldlen[i] = 0;
        }
        c->nf = newnf;
    }
    bawk_rebuild_record (c);
}

static void
bawk_assign_field (bawk_ctx *c, int n, const char *s, size_t len)
{
    if (n < 0 || n > 100000) return;
    if (!s) { s = ""; len = 0; }
    if (n == 0) {
        bawk_set_record (c, s, len);
        return;
    }
    if (n > c->nf) {
        if (bawk_fld_grow (c, n) < 0) return;
        while (c->nf < n) {
            c->nf++;
            bawk_fld_set (c, c->nf, "", 0);
        }
    }
    bawk_fld_set (c, n, s, len);
    bawk_rebuild_record (c);
}

/* V42-11 helper-exec hardening: explicit fork+execv replacement for
   popen(3). Preserves /bin/sh -c quoting and command semantics while
   adding three properties popen() does not give us:
     - SIGCHLD disposition reset to SIG_DFL before fork() so the
       /bin/sh child does not inherit bash's async-aware handler /
       SIG_IGN state (V42-09 class-fix pattern, made fatal by
       V42-10's audit-sigchld-pattern.sh).
     - SIGCHLD blocked around the parent fork() so a stray signal
       can't be delivered before the child's pid is recorded.
     - O_CLOEXEC on the parent pipe FD via pipe2() so the FD does
       not leak across any subsequent execve in the bash process.
   Returns FILE* and writes the child pid into *pid_out on success;
   returns NULL with errno set on failure (errno from pipe2/fork/
   sigprocmask/sigaction/fdopen). */
static FILE *
bawk_popen_guarded (const char *cmd, int read_mode, pid_t *pid_out)
{
    int pfd[2];
    if (pipe2 (pfd, O_CLOEXEC) < 0) return NULL;

    sigset_t mask, oldmask;
    sigemptyset (&mask);
    sigaddset (&mask, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &mask, &oldmask) < 0) {
        close (pfd[0]); close (pfd[1]); return NULL;
    }
    struct sigaction sa_dfl, sa_save;
    memset (&sa_dfl, 0, sizeof sa_dfl);
    sa_dfl.sa_handler = SIG_DFL;
    sigemptyset (&sa_dfl.sa_mask);
    sigaction (SIGCHLD, &sa_dfl, &sa_save);

    pid_t pid = fork ();
    if (pid < 0) {
        sigaction (SIGCHLD, &sa_save, NULL);
        sigprocmask (SIG_SETMASK, &oldmask, NULL);
        close (pfd[0]); close (pfd[1]);
        return NULL;
    }
    if (pid == 0) {
        /* Child: SIGCHLD already SIG_DFL via sa_dfl inheritance. Wire
           up stdin or stdout to the pipe, clear the other end, restore
           signal mask, and exec /bin/sh -c CMD. */
        if (read_mode) {
            close (pfd[0]);
            if (dup2 (pfd[1], STDOUT_FILENO) < 0) _exit (127);
            close (pfd[1]);
        } else {
            close (pfd[1]);
            if (dup2 (pfd[0], STDIN_FILENO) < 0) _exit (127);
            close (pfd[0]);
        }
        sigprocmask (SIG_SETMASK, &oldmask, NULL);
        execl ("/bin/sh", "sh", "-c", cmd, (char *) NULL);
        _exit (127);
    }

    /* Parent. Restore signal state. */
    sigaction (SIGCHLD, &sa_save, NULL);
    sigprocmask (SIG_SETMASK, &oldmask, NULL);

    int parent_fd;
    if (read_mode) { close (pfd[1]); parent_fd = pfd[0]; }
    else           { close (pfd[0]); parent_fd = pfd[1]; }

    FILE *fp = fdopen (parent_fd, read_mode ? "r" : "w");
    if (!fp) {
        int save = errno;
        close (parent_fd);
        int wstat;
        while (waitpid (pid, &wstat, 0) < 0 && errno == EINTR) { /* retry */ }
        errno = save;
        return NULL;
    }
    *pid_out = pid;
    return fp;
}

/* EINTR-safe paired close for bawk_popen_guarded streams. fclose(fp)
   reaches the child's stdin/stdout EOF; waitpid() drains the child
   status. Returns 0 on clean reap, -1 on a non-EINTR waitpid failure. */
static int
bawk_pclose_guarded (FILE *fp, pid_t pid)
{
    if (fp) fclose (fp);
    if (pid <= 0) return 0;
    int wstat;
    while (waitpid (pid, &wstat, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return 0;
}

/* Stage B: open or reuse a stream for redirected I/O. op:
   1 = "w" (truncate), 2 = "a" (append), 3 = pipe out (write to cmd),
   4 = pipe in (read from cmd), 5 = "r" (file getline). Pipe ops use
   the V42-11 guarded fork+execv helper above; file ops use fopen.
   Returns FILE* on success, NULL on error. The stream lives until
   bawk_free_all closes it. */
static FILE *
bawk_get_stream (bawk_ctx *c, const char *key, int op)
{
    for (size_t i = 0; i < c->n_streams; i++) {
        if (c->streams[i].op == op && strcmp (c->streams[i].key, key) == 0)
            return c->streams[i].fp;
    }
    /* gawk and mawk write "/dev/stdout" and "/dev/stderr" through the
       standard streams themselves, so buffered output keeps its order and
       a regular-file stdout is not truncated by a second open. */
    FILE *shared = NULL;
    if (op == 1 || op == 2) {
        if (!strcmp (key, "/dev/stdout")) shared = stdout;
        else if (!strcmp (key, "/dev/stderr")) shared = stderr;
    }
    if (c->n_streams + 1 > c->cap_streams) {
        size_t nc = c->cap_streams ? c->cap_streams * 2 : 8;
        struct bawk_stream *ns = xrealloc (c->streams, nc * sizeof *ns);
        if (!ns) return NULL;
        c->streams = ns;
        c->cap_streams = nc;
    }
    FILE *fp = NULL;
    pid_t pid = -1;
    /* Buffered output written so far precedes anything the new stream
       produces; a command additionally sees every redirection flushed. */
    if (op == 3 || op == 4) fflush (NULL);
    else if (!shared) fflush (stdout);
    if (shared) { fp = shared; pid = -2; }
    else if (op == 1) fp = fopen (key, "w");
    else if (op == 2) fp = fopen (key, "a");
    else if (op == 3) fp = bawk_popen_guarded (key, 0, &pid);
    else if (op == 4) fp = bawk_popen_guarded (key, 1, &pid);
    else if (op == 5) fp = fopen (key, "r");
    if (!fp) return NULL;
    c->streams[c->n_streams].key = bawk_strdup (key);
    c->streams[c->n_streams].op = op;
    c->streams[c->n_streams].fp = fp;
    c->streams[c->n_streams].pid = pid;
    c->n_streams++;
    return fp;
}

static int
bawk_close_one_stream (struct bawk_stream *s)
{
    int rc;
    if (!s->fp) return 0;
    bawk_rs_forget (s->fp);
    if (s->pid == -2)
        rc = fflush (s->fp);
    else if (s->op == 3 || s->op == 4)
        rc = bawk_pclose_guarded (s->fp, s->pid);
    else
        rc = fclose (s->fp);
    s->fp = NULL;
    s->pid = -1;
    return rc == 0 ? 0 : -1;
}

static int
bawk_close_stream_key (bawk_ctx *c, const char *key)
{
    int found = 0, rc = 0;
    for (size_t i = 0; i < c->n_streams; ) {
        if (strcmp (c->streams[i].key, key) != 0) {
            i++;
            continue;
        }
        found = 1;
        if (bawk_close_one_stream (&c->streams[i]) < 0)
            rc = -1;
        free (c->streams[i].key);
        if (i + 1 < c->n_streams)
            memmove (&c->streams[i], &c->streams[i + 1],
                     (c->n_streams - i - 1) * sizeof c->streams[i]);
        c->n_streams--;
    }
    return found ? rc : -1;
}

static int
bawk_fflush_stream_key (bawk_ctx *c, const char *key)
{
    int found = 0, rc = 0;
    for (size_t i = 0; i < c->n_streams; i++) {
        if (strcmp (c->streams[i].key, key) != 0)
            continue;
        if (c->streams[i].op != 1 && c->streams[i].op != 2 && c->streams[i].op != 3)
            continue;
        found = 1;
        if (fflush (c->streams[i].fp) != 0)
            rc = -1;
    }
    return found ? rc : -1;
}

static bawk_val bawk_eval_inner (bawk_ctx *c, bawk_node *n);

/* Depth-guarded entry. Wrapping the recursive interior is enough — every
   recursive call in bawk_eval_inner spells `bawk_eval(...)` and so is
   re-checked. */
static bawk_val
bawk_eval (bawk_ctx *c, bawk_node *n)
{
    int limit = c->max_stack > 0 ? c->max_stack : BAWK_DEFAULT_MAX_STACK;
    if (++c->eval_depth > limit) {
        c->eval_depth--;
        builtin_error ("awk: eval depth limit (%d) exceeded", limit);
        c->exit_flag = 1; c->exit_code = 2; c->fatal_flag = 1;
        bawk_val r = {0};
        return r;
    }
    bawk_val r = bawk_eval_inner (c, n);
    c->eval_depth--;
    return r;
}

static void bawk_assign_lhs (bawk_ctx *c, bawk_node *lhs, bawk_val rhs);
static char *bawk_eval_subscript_key (bawk_ctx *c, bawk_node *head, size_t *lenp);

/* Apply a VAR=VALUE operand. */
static void
bawk_apply_assignment (bawk_ctx *c, const char *w)
{
    const char *eq = strchr (w, '=');
    char *name = bawk_strndup (w, (size_t) (eq - w));
    size_t uvl = 0;
    char *uv = bawk_unescape (eq + 1, &uvl);
    bawk_node lhs = {0};
    bawk_val v = {0};
    lhs.kind = N_IDENT;
    lhs.sval = name;
    if (uv) bawk_val_set_input_mem (&v, uv, uvl);
    else bawk_val_set_input (&v, eq + 1);
    bawk_assign_lhs (c, &lhs, v);
    free (uv);
    free (name);
}

static bawk_val
bawk_eval_getline (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_getline_source source = bawk_n_getline_source (n);
    bawk_getline_target target = bawk_n_getline_target (n);
    FILE *src = stdin;
    bawk_val sv = {0};

    if (n->kind == N_GETLINE_PIPE) source = BAWK_GETLINE_PIPE;
    else if (n->A && source == BAWK_GETLINE_MAIN) source = BAWK_GETLINE_FILE;
    if (n->sval) target = BAWK_GETLINE_TARGET_SCALAR;

    if (source == BAWK_GETLINE_FILE || source == BAWK_GETLINE_PIPE) {
        sv = bawk_eval (c, n->A);
        char sbuf[256];
        const char *key = bawk_val_to_str (&sv, sbuf, sizeof sbuf);
        src = bawk_get_stream (c, key, source == BAWK_GETLINE_PIPE ? 4 : 5);
        bawk_val_free (&sv);
        if (!src) {
            bawk_val_set_num (&r, -1);
            return r;
        }
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t rd = bawk_read_record (c, src, &line, &cap);
    if (rd < 0) {
        free (line);
        bawk_val_set_num (&r, 0);
        return r;
    }

    if (source != BAWK_GETLINE_PIPE) {
        bawk_counter_advance (&c->NR);
        /* Retain the existing subset rule: main-input getline advances
           both counters; getline from an explicit file advances
           NR only and leaves the current input file's FNR alone. */
        if (source == BAWK_GETLINE_MAIN) bawk_counter_advance (&c->FNR);
    }

    if (target == BAWK_GETLINE_TARGET_SCALAR) {
        bawk_set_scalar_from_getline (c, n->sval, line, (size_t) rd);
    } else {
        bawk_set_record (c, line, (size_t) rd);
        if (source == BAWK_GETLINE_PIPE) {
            /* Preserve awk's existing measured divergence: record-form
               command-pipe getline advances both counters; scalar target
               command-pipe getline does not. */
            bawk_counter_advance (&c->NR);
            bawk_counter_advance (&c->FNR);
        }
    }

    free (line);
    bawk_val_set_num (&r, 1);
    return r;
}

typedef enum {
    BAWK_LREF_BAD,
    BAWK_LREF_SLOT,
    BAWK_LREF_FIELD,
    BAWK_LREF_NF        /* assignment to NF: truncate/pad fields + rebuild $0 */
} bawk_lref_kind;

typedef struct {
    bawk_lref_kind kind;
    bawk_val *slot;
    int field;
    char **special;
    size_t *special_len;    /* FS, OFS, ORS, SUBSEP: byte length of *special */
} bawk_lref;

static bawk_lref
bawk_lref_resolve (bawk_ctx *c, bawk_node *lhs)
{
    bawk_lref ref = {0};
    if (!lhs) return ref;
    if (lhs->kind == N_IDENT) {
        if (!strcmp (lhs->sval, "FS")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->FS;
            ref.special_len = &c->FSlen;
            return ref;
        }
        if (!strcmp (lhs->sval, "OFS")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->OFS;
            ref.special_len = &c->OFSlen;
            return ref;
        }
        if (!strcmp (lhs->sval, "ORS")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->ORS;
            ref.special_len = &c->ORSlen;
            return ref;
        }
        if (!strcmp (lhs->sval, "SUBSEP")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->SUBSEP;
            ref.special_len = &c->SUBSEPlen;
            return ref;
        }
        if (!strcmp (lhs->sval, "CONVFMT")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->CONVFMT;
            return ref;
        }
        if (!strcmp (lhs->sval, "OFMT")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->OFMT;
            return ref;
        }
        /* FILENAME is assignable; the value read back (and shown in a
           fatal error's "(FILENAME=F FNR=N)") is the one assigned. */
        if (!strcmp (lhs->sval, "FILENAME")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.special = &c->FILENAME;
            return ref;
        }
        /* NF is assignable (POSIX): setting it truncates or zero-pads the
           field list and rebuilds $0 via OFS. */
        if (!strcmp (lhs->sval, "NF")) {
            ref.kind = BAWK_LREF_NF;
            return ref;
        }
        if (!strcmp (lhs->sval, "NR") || !strcmp (lhs->sval, "FNR")) {
            ref.kind = BAWK_LREF_SLOT;
            ref.slot = !strcmp (lhs->sval, "NR") ? &c->NR : &c->FNR;
            return ref;
        }
        bawk_var *v = bawk_lookup_scalar (c, lhs->sval);
        ref.kind = BAWK_LREF_SLOT;
        ref.slot = &v->val;
        return ref;
    }
    if (lhs->kind == N_INDEX) {
        bawk_var *v = bawk_lookup_array (c, lhs->sval);
        size_t skey_len;
        char *skey = bawk_eval_subscript_key (c, lhs->A, &skey_len);
        if (!skey) return ref;
        bawk_val *slot = bawk_array_slot (v, skey, skey_len, 1);
        free (skey);
        if (slot) {
            ref.kind = BAWK_LREF_SLOT;
            ref.slot = slot;
        }
        return ref;
    }
    if (lhs->kind == N_DOLLAR) {
        bawk_val idx = bawk_eval (c, lhs->A);
        int n = (int) bawk_val_to_num (&idx);
        bawk_val_free (&idx);
        if (n < 0 || n > 100000) return ref;
        ref.kind = BAWK_LREF_FIELD;
        ref.field = n;
        return ref;
    }
    return ref;
}

static bawk_val
bawk_lref_get (bawk_ctx *c, bawk_lref *ref)
{
    bawk_val r = {0};
    if (!ref || ref->kind == BAWK_LREF_BAD) return r;
    if (ref->kind == BAWK_LREF_NF) {
        bawk_val_set_num (&r, (double) c->nf);
        return r;
    }
    if (ref->kind == BAWK_LREF_SLOT) {
        if (!ref->special && (ref->slot == &c->NR || ref->slot == &c->FNR))
            return bawk_counter_read (ref->slot);
        if (ref->special) {
            if (ref->special_len) bawk_val_set_mem (&r, *ref->special, *ref->special ? *ref->special_len : 0);
            else bawk_val_set_str (&r, *ref->special ? *ref->special : "");
            return r;
        }
        bawk_val_read (&r, ref->slot);
        return r;
    }
    if (ref->kind == BAWK_LREF_FIELD) {
        int i = ref->field;
        if (i < 0 || i > c->nf || !c->fld[i]) bawk_val_set_input (&r, "");
        else bawk_val_set_input_mem (&r, c->fld[i], c->fldlen[i]);
    }
    return r;
}

static void
bawk_lref_set (bawk_ctx *c, bawk_lref *ref, bawk_val rhs)
{
    if (!ref || ref->kind == BAWK_LREF_BAD) {
        bawk_val_free (&rhs);
        return;
    }
    if (ref->kind == BAWK_LREF_SLOT) {
        if (ref->special) {
            char buf[64]; size_t sl;
            const char *s = bawk_val_to_strl (&rhs, buf, sizeof buf, &sl);
            free (*ref->special);
            if (ref->special_len) {
                *ref->special = bawk_strndup_mem (s, sl);
                *ref->special_len = sl;
            } else {
                *ref->special = bawk_strdup (s);
            }
            /* Keep the active CONVFMT/OFMT format pointers in sync. The format
               is handed straight to snprintf() in bawk_num_to_str(), so a
               script setting e.g. CONVFMT="%n" would be a format-string sink;
               sanitize it first (mirrors the bawk_format() %n guard). */
            if (ref->special == &c->CONVFMT) bawk_convfmt = bawk_safe_numfmt (*ref->special);
            else if (ref->special == &c->OFMT) bawk_ofmt = bawk_safe_numfmt (*ref->special);
            bawk_val_free (&rhs);
            return;
        }
        bawk_val_free (ref->slot);
        *ref->slot = rhs;
        return;
    }
    if (ref->kind == BAWK_LREF_NF) {
        int newnf = (int) bawk_val_to_num (&rhs);
        bawk_val_free (&rhs);
        bawk_assign_nf (c, newnf);
        return;
    }
    if (ref->kind == BAWK_LREF_FIELD) {
        int n = ref->field;
        char buf[64]; size_t sl;
        const char *s = bawk_val_to_strl (&rhs, buf, sizeof buf, &sl);
        bawk_assign_field (c, n, s, sl);
        bawk_val_free (&rhs);
    }
}

/* Set lhs := rhs. Handles IDENT, INDEX, DOLLAR. */
static void
bawk_assign_lhs (bawk_ctx *c, bawk_node *lhs, bawk_val rhs)
{
    bawk_lref ref = bawk_lref_resolve (c, lhs);
    bawk_lref_set (c, &ref, rhs);
}

/* Does the string (ignoring surrounding blanks) parse fully as a number? */
static int
bawk_str_looks_numeric (const char *s, size_t len)
{
    if (!s) return 0;
    const char *lim = s + len;
    while (s < lim && (*s==' '||*s=='\t'||*s=='\n')) s++;
    if (s >= lim) return 0;
    char *end = NULL;
    strtod (s, &end);
    if (end == s) return 0;
    while (end < lim && (*end==' '||*end=='\t'||*end=='\n')) end++;
    return end == lim;
}

/* POSIX comparison typing: a number, an uninitialized value, or a numeric
   string (input data that looks numeric) is numeric. Two numeric operands
   compare as numbers; anything else, including a string constant such as
   "10", compares as strings. */
static int
bawk_val_numeric (const bawk_val *v)
{
    if (v->have_n || !v->s || v->strnum == BAWK_UNINIT) return 1;
    return v->strnum == BAWK_STRNUM && bawk_str_looks_numeric (v->s, v->len);
}

static int
bawk_both_numeric (bawk_val *a, bawk_val *b)
{
    return bawk_val_numeric (a) && bawk_val_numeric (b);
}

static bawk_val
bawk_eval_ident (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    switch ((bawk_special_id) bawk_n_op (n)) {
        case BAWK_SPECIAL_NR: return bawk_counter_read (&c->NR);
        case BAWK_SPECIAL_FNR: return bawk_counter_read (&c->FNR);
        case BAWK_SPECIAL_NF: bawk_val_set_num (&r, (double) c->nf); return r;
        case BAWK_SPECIAL_FS: bawk_val_set_mem (&r, c->FS ? c->FS : " ", c->FS ? c->FSlen : 1); return r;
        case BAWK_SPECIAL_OFS: bawk_val_set_mem (&r, c->OFS ? c->OFS : " ", c->OFS ? c->OFSlen : 1); return r;
        case BAWK_SPECIAL_SUBSEP: bawk_val_set_mem (&r, c->SUBSEP ? c->SUBSEP : "\034", c->SUBSEP ? c->SUBSEPlen : 1); return r;
        case BAWK_SPECIAL_CONVFMT: bawk_val_set_str (&r, c->CONVFMT ? c->CONVFMT : "%.6g"); return r;
        case BAWK_SPECIAL_OFMT: bawk_val_set_str (&r, c->OFMT ? c->OFMT : "%.6g"); return r;
        case BAWK_SPECIAL_ORS: bawk_val_set_mem (&r, c->ORS ? c->ORS : "\n", c->ORS ? c->ORSlen : 1); return r;
        case BAWK_SPECIAL_FILENAME: bawk_val_set_str (&r, c->FILENAME ? c->FILENAME : ""); return r;
        case BAWK_SPECIAL_RSTART: bawk_val_set_num (&r, (double) c->RSTART); return r;
        case BAWK_SPECIAL_RLENGTH: bawk_val_set_num (&r, (double) c->RLENGTH); return r;
        case BAWK_SPECIAL_NONE: break;
    }
    if      (!strcmp (n->sval, "NR")) return bawk_counter_read (&c->NR);
    else if (!strcmp (n->sval, "FNR")) return bawk_counter_read (&c->FNR);
    else if (!strcmp (n->sval, "NF")) bawk_val_set_num (&r, (double) c->nf);
    else if (!strcmp (n->sval, "FS")) bawk_val_set_mem (&r, c->FS ? c->FS : " ", c->FS ? c->FSlen : 1);
    else if (!strcmp (n->sval, "OFS")) bawk_val_set_mem (&r, c->OFS ? c->OFS : " ", c->OFS ? c->OFSlen : 1);
    else if (!strcmp (n->sval, "SUBSEP")) bawk_val_set_mem (&r, c->SUBSEP ? c->SUBSEP : "\034", c->SUBSEP ? c->SUBSEPlen : 1);
    else if (!strcmp (n->sval, "CONVFMT")) bawk_val_set_str (&r, c->CONVFMT ? c->CONVFMT : "%.6g");
    else if (!strcmp (n->sval, "OFMT")) bawk_val_set_str (&r, c->OFMT ? c->OFMT : "%.6g");
    else if (!strcmp (n->sval, "ORS")) bawk_val_set_mem (&r, c->ORS ? c->ORS : "\n", c->ORS ? c->ORSlen : 1);
    else if (!strcmp (n->sval, "FILENAME")) bawk_val_set_str (&r, c->FILENAME ? c->FILENAME : "");
    else if (!strcmp (n->sval, "RSTART")) bawk_val_set_num (&r, (double) c->RSTART);
    else if (!strcmp (n->sval, "RLENGTH")) bawk_val_set_num (&r, (double) c->RLENGTH);
    else {
        bawk_var *v = bawk_lookup_scalar (c, n->sval);
        bawk_val_read (&r, &v->val);
    }
    return r;
}

static bawk_val
bawk_eval_index (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_var *v = bawk_lookup_array (c, n->sval);
    size_t skey_len;
    char *skey = bawk_eval_subscript_key (c, n->A, &skey_len);
    if (!skey) { bawk_val_set_str (&r, ""); return r; }
    bawk_val *slot = bawk_array_slot (v, skey, skey_len, 1);
    free (skey);
    bawk_val_read (&r, slot);
    return r;
}

/* gawk's fatal error for a zero divisor at run time: "awk: LOC: fatal:
   division by zero attempted[ in `OP']", with "(FILENAME=F FNR=N) " before
   "fatal" once input has been read (FNR > 0). The program stops, END rules
   are skipped and the status is 2. */
static void
bawk_div_zero_fatal (bawk_ctx *c, size_t off, const char *what)
{
    char loc[512];
    double fnr = bawk_val_to_num (&c->FNR);
    bawk_srcloc (off, loc, sizeof loc);
    /* Output printed so far comes first, as gawk flushes it. */
    if (c->out) fflush (c->out);
    fflush (stdout);
    if (fnr > 0)
        builtin_error ("%s: (FILENAME=%s FNR=%ld) fatal: division by zero attempted%s", loc,
                       c->FILENAME && *c->FILENAME ? c->FILENAME : "-", (long) fnr, what);
    else
        builtin_error ("%s: fatal: division by zero attempted%s", loc, what);
    c->exit_flag = 1;
    c->exit_code = 2;
    c->fatal_flag = 1;
}

static bawk_val
bawk_eval_assign (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_val rhs = bawk_eval (c, bawk_n_rhs (n));
    int op = (int) n->nval;
    bawk_lref ref = bawk_lref_resolve (c, bawk_n_lhs (n));
    if (op == T_ASSIGN) {
        int counter = ref.kind == BAWK_LREF_SLOT && !ref.special
                      && (ref.slot == &c->NR || ref.slot == &c->FNR);
        bawk_val assigned = {0};
        if (counter) assigned = bawk_val_copy (&rhs);
        bawk_lref_set (c, &ref, rhs);
        return counter ? assigned : bawk_lref_get (c, &ref);
    }
    bawk_val cur = bawk_lref_get (c, &ref);
    double a = bawk_val_to_num (&cur);
    double b = bawk_val_to_num (&rhs);
    double v = a;
    switch (op) {
        case T_PLUSEQ:  v = a + b; break;
        case T_MINUSEQ: v = a - b; break;
        case T_MULEQ:   v = a * b; break;
        case T_DIVEQ:   if (b == 0) { bawk_div_zero_fatal (c, n->src_off, " in `/='"); v = 0; } else v = a / b; break;
        case T_MODEQ:   if (b == 0) { bawk_div_zero_fatal (c, n->src_off, " in `%='"); v = 0; } else v = fmod (a, b); break;
        case T_POWEQ:   v = pow (a, b); break;
    }
    bawk_val nv = {0};
    bawk_val_set_num (&nv, v);
    bawk_val_free (&cur);
    bawk_val_free (&rhs);
    bawk_lref_set (c, &ref, nv);
    bawk_val_set_num (&r, v);
    return r;
}

static bawk_val
bawk_eval_binop (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    int op = bawk_n_op (n);
    if (op == BAWK_BINOP_AND) {
        bawk_val a = bawk_eval (c, bawk_n_lhs (n));
        int t = bawk_val_true (&a);
        bawk_val_free (&a);
        if (!t) { bawk_val_set_num (&r, 0); return r; }
        bawk_val b = bawk_eval (c, bawk_n_rhs (n));
        int u = bawk_val_true (&b);
        bawk_val_free (&b);
        bawk_val_set_num (&r, u ? 1 : 0);
        return r;
    }
    if (op == BAWK_BINOP_OR) {
        bawk_val a = bawk_eval (c, bawk_n_lhs (n));
        int t = bawk_val_true (&a);
        bawk_val_free (&a);
        if (t) { bawk_val_set_num (&r, 1); return r; }
        bawk_val b = bawk_eval (c, bawk_n_rhs (n));
        int u = bawk_val_true (&b);
        bawk_val_free (&b);
        bawk_val_set_num (&r, u ? 1 : 0);
        return r;
    }
    bawk_val A = bawk_eval (c, bawk_n_lhs (n));
    bawk_val B = bawk_eval (c, bawk_n_rhs (n));
    if (op == BAWK_BINOP_CONCAT) {
        char ab[64], bb[64]; size_t ll, rl;
        const char *as = bawk_val_to_strl (&A, ab, sizeof ab, &ll);
        const char *bs = bawk_val_to_strl (&B, bb, sizeof bb, &rl);
        if (ll > SIZE_MAX - rl - 1) { fatal_error ("awk: string too large"); abort (); }
        char *m = xmalloc (ll + rl + 1);
        memcpy (m, as, ll); memcpy (m + ll, bs, rl); m[ll + rl] = '\0';
        free (r.s);
        r.s = m; r.len = ll + rl; r.have_n = 0; r.strnum = 0;
    } else if (op == BAWK_BINOP_ADD || op == BAWK_BINOP_SUB
            || op == BAWK_BINOP_MUL || op == BAWK_BINOP_DIV
            || op == BAWK_BINOP_MOD || op == BAWK_BINOP_POW) {
        double a = bawk_val_to_num (&A), b = bawk_val_to_num (&B), v = 0;
        switch (op) {
            case BAWK_BINOP_ADD: v = a + b; break;
            case BAWK_BINOP_SUB: v = a - b; break;
            case BAWK_BINOP_MUL: v = a * b; break;
            case BAWK_BINOP_DIV: if (b == 0) { bawk_div_zero_fatal (c, n->src_off, ""); v = 0; } else v = a / b; break;
            case BAWK_BINOP_MOD: if (b == 0) { bawk_div_zero_fatal (c, n->src_off, " in `%'"); v = 0; } else v = fmod (a, b); break;
            case BAWK_BINOP_POW: v = pow (a, b); break;
        }
        bawk_val_set_num (&r, v);
    } else {
        int both_n = bawk_both_numeric (&A, &B);
        int cmp;
        if (both_n) {
            double a = bawk_val_to_num (&A), b = bawk_val_to_num (&B);
            cmp = (a < b) ? -1 : (a > b) ? 1 : 0;
        } else {
            char ab[64], bb[64]; size_t al, bl;
            const char *as = bawk_val_to_strl (&A, ab, sizeof ab, &al);
            const char *bs = bawk_val_to_strl (&B, bb, sizeof bb, &bl);
            cmp = bawk_memcmp2 (as, al, bs, bl);
        }
        int t = 0;
        switch (op) {
            case BAWK_BINOP_EQ: t = (cmp == 0); break;
            case BAWK_BINOP_NE: t = (cmp != 0); break;
            case BAWK_BINOP_LT: t = (cmp <  0); break;
            case BAWK_BINOP_LE: t = (cmp <= 0); break;
            case BAWK_BINOP_GT: t = (cmp >  0); break;
            case BAWK_BINOP_GE: t = (cmp >= 0); break;
        }
        bawk_val_set_num (&r, t);
    }
    bawk_val_free (&A); bawk_val_free (&B);
    return r;
}

static bawk_val
bawk_eval_print (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    const char *ofs = c->OFS ? c->OFS : " ";
    const char *ors = c->ORS ? c->ORS : "\n";
    size_t ofslen = c->OFS ? c->OFSlen : 1, orslen = c->ORS ? c->ORSlen : 1;
    FILE *out = c->out;
    if (n->nval && n->B) {
        bawk_val tv = bawk_eval (c, n->B);
        char tb[256]; const char *target = bawk_val_to_str (&tv, tb, sizeof tb);
        FILE *redir = bawk_get_stream (c, target, (int) n->nval);
        if (redir) out = redir;
        bawk_val_free (&tv);
    }
    if (!n->A) {
        if (c->fld[0]) fwrite (c->fld[0], 1, c->fldlen[0], out);
    } else {
        /* Every argument is evaluated before anything is written, so a
           fatal error in one (division by zero) prints nothing, as gawk. */
        int nargs = 0, i = 0;
        for (bawk_node *p = n->A; p; p = p->next) nargs++;
        bawk_val *vals = bawk_calloc ((size_t) nargs, sizeof *vals);
        for (bawk_node *p = n->A; p; p = p->next) vals[i++] = bawk_eval (c, p->A);
        if (c->fatal_flag) {
            for (i = 0; i < nargs; i++) bawk_val_free (&vals[i]);
            free (vals);
            return r;
        }
        for (i = 0; i < nargs; i++) {
            bawk_val *v = &vals[i];
            if (i) fwrite (ofs, 1, ofslen, out);
            char b[64]; size_t sl = 0;
            const char *s = (!v->s && v->have_n)
                ? bawk_num_to_str (v->n, bawk_ofmt, b, sizeof b)
                : bawk_val_to_strl (v, b, sizeof b, &sl);
            if (!v->s && v->have_n) sl = strlen (s);
            fwrite (s, 1, sl, out);
            bawk_val_free (v);
        }
        free (vals);
    }
    fwrite (ors, 1, orslen, out);
    return r;
}

static bawk_val
bawk_eval_printf (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    if (!n->A) return r;
    FILE *out = c->out;
    if (n->nval && n->B) {
        bawk_val tv = bawk_eval (c, n->B);
        char tb[256]; const char *target = bawk_val_to_str (&tv, tb, sizeof tb);
        FILE *redir = bawk_get_stream (c, target, (int) n->nval);
        if (redir) out = redir;
        bawk_val_free (&tv);
    }
    bawk_val fmtv = bawk_eval (c, n->A->A);
    char b[64]; size_t fl; const char *fmt = bawk_val_to_strl (&fmtv, b, sizeof b, &fl);
    int nargs = 0;
    for (bawk_node *p = n->A->next; p; p = p->next) nargs++;
    bawk_val *aargs = nargs > 0 ? bawk_calloc ((size_t) nargs, sizeof *aargs) : NULL;
    int ai = 0;
    for (bawk_node *p = n->A->next; p; p = p->next) aargs[ai++] = bawk_eval (c, p->A);
    size_t rl = 0;
    char *res = c->fatal_flag ? NULL : bawk_format (fmt, fl, aargs, nargs, &rl);
    if (res) fwrite (res, 1, rl, out);
    free (res);
    for (int j = 0; j < nargs; j++) bawk_val_free (&aargs[j]);
    free (aargs);
    bawk_val_free (&fmtv);
    return r;
}

static bawk_val
bawk_eval_if (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_val cv = bawk_eval (c, bawk_n_cond (n));
    int t = bawk_val_true (&cv);
    bawk_val_free (&cv);
    if (t) bawk_eval (c, bawk_n_then (n));
    else if (bawk_n_else (n)) bawk_eval (c, bawk_n_else (n));
    return r;
}

static bawk_val
bawk_eval_while (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    int do_while = (int) n->nval;   /* 1 = do-while semantics */
    for (;;) {
        if (!do_while) {
            bawk_val cv = bawk_eval (c, n->A);
            int t = bawk_val_true (&cv);
            bawk_val_free (&cv);
            if (!t) break;
        }
        bawk_val v = bawk_eval (c, n->B);
        bawk_val_free (&v);
        if (c->brk_flag)  { c->brk_flag = 0; break; }
        if (c->cont_flag) { c->cont_flag = 0; }
        if (c->exit_flag || c->next_flag || c->nextfile_flag || c->return_flag) break;
        if (do_while) {
            bawk_val cv = bawk_eval (c, n->A);
            int t = bawk_val_true (&cv);
            bawk_val_free (&cv);
            if (!t) break;
        }
    }
    return r;
}

static bawk_val
bawk_eval_for (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    if (n->A) { bawk_val v = bawk_eval (c, n->A); bawk_val_free (&v); }
    for (;;) {
        if (n->B) {
            bawk_val cv = bawk_eval (c, n->B);
            int t = bawk_val_true (&cv);
            bawk_val_free (&cv);
            if (!t) break;
        }
        bawk_val v = bawk_eval (c, n->body);
        bawk_val_free (&v);
        if (c->brk_flag)  { c->brk_flag = 0; break; }
        if (c->cont_flag) { c->cont_flag = 0; }
        if (c->exit_flag || c->next_flag || c->nextfile_flag || c->return_flag) break;
        if (n->C) { bawk_val s = bawk_eval (c, n->C); bawk_val_free (&s); }
    }
    return r;
}

static bawk_val
bawk_eval_forin (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_var *arr = bawk_lookup_array (c, bawk_n_array_name (n));
    for (int i = 0; i < arr->n_a; i++) {
        bawk_var *kv = bawk_lookup_scalar (c, n->sval);
        bawk_val_free (&kv->val);
        bawk_val_set_mem (&kv->val, arr->akey[i], arr->aklen[i]);
        bawk_val v = bawk_eval (c, n->C);
        bawk_val_free (&v);
        if (c->brk_flag)  { c->brk_flag = 0; break; }
        if (c->cont_flag) { c->cont_flag = 0; }
        if (c->exit_flag || c->next_flag || c->nextfile_flag || c->return_flag) break;
    }
    return r;
}

/* The subscript of a[e1, e2, ...]: the values joined by SUBSEP, as a
   malloc'd string of *LENP bytes (NUL bytes in the values are kept). */
static char *
bawk_eval_subscript_key (bawk_ctx *c, bawk_node *head, size_t *lenp)
{
    const char *subsep = c->SUBSEP ? c->SUBSEP : "\034";
    size_t sslen = c->SUBSEP ? c->SUBSEPlen : 1;
    size_t cap = 64, len = 0;
    char *skey = xmalloc (cap);
    if (!skey) return NULL;
    skey[0] = '\0';
    for (bawk_node *p = head; p; p = p->next) {
        bawk_val kv = bawk_eval (c, p);
        char tmp[64]; size_t kl;
        const char *ks = bawk_val_to_strl (&kv, tmp, sizeof tmp, &kl);
        size_t need = len + kl + (p != head ? sslen : 0) + 1;
        if (need > cap) {
            while (cap < need) cap *= 2;
            char *ns = xrealloc (skey, cap);
            if (!ns) { free (skey); bawk_val_free (&kv); return NULL; }
            skey = ns;
        }
        if (p != head) { memcpy (skey + len, subsep, sslen); len += sslen; }
        memcpy (skey + len, ks, kl); len += kl; skey[len] = '\0';
        bawk_val_free (&kv);
    }
    *lenp = len;
    return skey;
}

static bawk_val
bawk_eval_delete (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_var *v = bawk_lookup_array (c, n->sval);
    v->is_array = 1;
    if (!n->A) {
        for (int i = 0; i < v->n_a; i++) { free (v->akey[i]); bawk_val_free (&v->aval[i]); }
        v->n_a = 0;
        return r;
    }
    size_t skey_len;
    char *skey = bawk_eval_subscript_key (c, n->A, &skey_len);
    if (!skey) return r;
    for (int i = 0; i < v->n_a; i++) {
        if (v->aklen[i] == skey_len && !memcmp (v->akey[i], skey, skey_len)) {
            free (v->akey[i]);
            bawk_val_free (&v->aval[i]);
            for (int j = i + 1; j < v->n_a; j++) { v->akey[j-1] = v->akey[j]; v->aklen[j-1] = v->aklen[j]; v->aval[j-1] = v->aval[j]; }
            v->n_a--;
            break;
        }
    }
    free (skey);
    return r;
}

static bawk_val
bawk_eval_inarray (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    bawk_var *v = bawk_lookup_array (c, n->sval);
    if (n->A && !n->A->next) {
        bawk_val kv = bawk_eval (c, n->A);
        char tmp[64]; size_t kl;
        const char *ks = bawk_val_to_strl (&kv, tmp, sizeof tmp, &kl);
        bawk_val *slot = bawk_array_slot (v, ks, kl, 0);
        bawk_val_set_num (&r, slot ? 1.0 : 0.0);
        bawk_val_free (&kv);
        return r;
    }
    size_t skey_len;
    char *skey = bawk_eval_subscript_key (c, n->A, &skey_len);
    if (!skey) return r;
    bawk_val *slot = bawk_array_slot (v, skey, skey_len, 0);
    bawk_val_set_num (&r, slot ? 1.0 : 0.0);
    free (skey);
    return r;
}

static bawk_val
bawk_eval_inner (bawk_ctx *c, bawk_node *n)
{
    bawk_val r = {0};
    if (!n) return r;
    if (c->exit_flag || c->next_flag || c->nextfile_flag) return r;

    switch (n->kind) {
        case N_NUMBER:
            bawk_val_set_num (&r, n->nval);
            return r;
        case N_STRING:
            bawk_val_set_mem (&r, n->sval, n->slen);
            return r;
        case N_IDENT:
            return bawk_eval_ident (c, n);
        case N_INDEX:
            return bawk_eval_index (c, n);
        case N_DOLLAR: {
            bawk_val idx = bawk_eval (c, n->A);
            int i = (int) bawk_val_to_num (&idx);
            bawk_val_free (&idx);
            if (i < 0 || i > c->nf || !c->fld[i]) bawk_val_set_input (&r, "");
            else bawk_val_set_input_mem (&r, c->fld[i], c->fldlen[i]);
            return r;
        }
        case N_ASSIGN:
            return bawk_eval_assign (c, n);
        case N_INCDEC: {
            bawk_lref ref = bawk_lref_resolve (c, n->A);
            bawk_val cur = bawk_lref_get (c, &ref);
            double oldv = bawk_val_to_num (&cur);
            double newv = oldv + n->nval;
            bawk_val nv = {0};
            bawk_val_set_num (&nv, newv);
            bawk_lref_set (c, &ref, nv);
            bawk_val_set_num (&r, n->builtin_id ? newv : oldv);
            bawk_val_free (&cur);
            return r;
        }
        case N_UNARY: {
            bawk_val v = bawk_eval (c, n->A);
            if ((int) n->nval == T_MINUS) bawk_val_set_num (&r, -bawk_val_to_num (&v));
            else if ((int) n->nval == T_PLUS) bawk_val_set_num (&r, bawk_val_to_num (&v));
            else                          bawk_val_set_num (&r, !bawk_val_true (&v));
            bawk_val_free (&v);
            return r;
        }
        case N_BINOP:
            return bawk_eval_binop (c, n);
        case N_REGEX: {
            /* Bare /re/ as expression: matches against $0. */
            const char *s = c->fld[0] ? c->fld[0] : "";
            int ok = (bawk_regexec (&n->re, s, c->fld[0] ? c->fldlen[0] : 0, 0, NULL) == 0);
            bawk_val_set_num (&r, ok);
            return r;
        }
        case N_REGEX_MATCH: {
            bawk_val A = bawk_eval (c, n->A);
            char buf[64]; size_t sl;
            const char *s = bawk_val_to_strl (&A, buf, sizeof buf, &sl);
            int ok;
            if (n->B->kind == N_REGEX) {
                ok = (bawk_regexec (&n->B->re, s, sl, 0, NULL) == 0);
            } else {
                bawk_val B = bawk_eval (c, n->B);
                regex_t re;
                char pb[64]; size_t pl;
                const char *ps = bawk_val_to_strl (&B, pb, sizeof pb, &pl);
                if (bawk_regcomp (&re, ps, pl) != 0) ok = 0;
                else { ok = (bawk_regexec (&re, s, sl, 0, NULL) == 0); regfree (&re); }
                bawk_val_free (&B);
            }
            if ((int) n->nval == 1) ok = !ok;
            bawk_val_free (&A);
            bawk_val_set_num (&r, ok);
            return r;
        }
        case N_TERNARY: {
            bawk_val cv = bawk_eval (c, n->A);
            int t = bawk_val_true (&cv);
            bawk_val_free (&cv);
            r = bawk_eval (c, t ? n->B : n->C);
            return r;
        }
        case N_GETLINE:
        case N_GETLINE_PIPE:
            return bawk_eval_getline (c, n);
        case N_CALL: {
            /* gather args */
            int n_args = 0;
            for (bawk_node *p = n->A; p; p = p->next) n_args++;
            bawk_val *args = bawk_calloc ((size_t) (n_args + 1), sizeof *args);
            int i = 0;
            for (bawk_node *p = n->A; p; p = p->next) args[i++] = bawk_eval (c, p->A);
            switch (n->builtin_id) {
                case BFN_LENGTH: {
                    if (n_args == 0) { bawk_val_set_num (&r, (double) (c->fld[0] ? c->fldlen[0] : 0)); break; }
                    /* length(array) returns the element count. Detect an array
                       argument from the AST (the evaluated value can't tell us). */
                    bawk_node *arg0 = n->A ? n->A->A : NULL;
                    if (arg0 && arg0->kind == N_IDENT) {
                        bawk_var *v = bawk_lookup_array (c, arg0->sval);
                        if (v && v->is_array) { bawk_val_set_num (&r, (double) v->n_a); break; }
                    }
                    char b[64]; size_t sl;
                    bawk_val_to_strl (&args[0], b, sizeof b, &sl);
                    bawk_val_set_num (&r, (double) sl);
                    break;
                }
                case BFN_SUBSTR: {
                    char b[64]; size_t slen;
                    const char *s = bawk_val_to_strl (&args[0], b, sizeof b, &slen);
                    long long sl = (long long) slen;
                    /* Clamp inputs through double to avoid signed-int overflow on
                       attacker-controlled arguments (e.g. INT_MIN start). */
                    double dstart = bawk_val_to_num (&args[1]);
                    double dlen = (n_args >= 3) ? bawk_val_to_num (&args[2]) : (double) sl;
                    if (dstart < -1e15) dstart = -1e15;
                    if (dstart > 1e15)  dstart = 1e15;
                    if (dlen < 0) dlen = 0;
                    if (dlen > 1e15) dlen = 1e15;
                    long long start = (long long) dstart;
                    long long len = (long long) dlen;
                    if (start < 1) { len += start - 1; start = 1; }
                    if (len < 0) len = 0;
                    if (start - 1 > sl) { bawk_val_set_str (&r, ""); break; }
                    if (start - 1 + len > sl) len = sl - (start - 1);
                    if (len < 0) len = 0;
                    bawk_val_set_mem (&r, s + start - 1, (size_t) len);
                    break;
                }
                case BFN_INDEX: {
                    char ab[64], bb[64]; size_t hl, nl;
                    const char *hay = bawk_val_to_strl (&args[0], ab, sizeof ab, &hl);
                    const char *nd  = bawk_val_to_strl (&args[1], bb, sizeof bb, &nl);
                    const char *p = memmem (hay, hl, nd, nl);
                    bawk_val_set_num (&r, p ? (double) (p - hay + 1) : 0);
                    break;
                }
                case BFN_SPRINTF: {
                    if (n_args == 0) { bawk_val_set_str (&r, ""); break; }
                    char b[64]; size_t fl; const char *fmt = bawk_val_to_strl (&args[0], b, sizeof b, &fl);
                    size_t rl = 0;
                    char *res = bawk_format (fmt, fl, args + 1, n_args - 1, &rl);
                    bawk_val_set_mem (&r, res ? res : "", res ? rl : 0);
                    free (res);
                    break;
                }
                case BFN_INT: {
                    bawk_val_set_num (&r, (double) (long long) bawk_val_to_num (&args[0]));
                    break;
                }
                case BFN_SQRT: bawk_val_set_num (&r, sqrt (bawk_val_to_num (&args[0]))); break;
                case BFN_SIN:  bawk_val_set_num (&r, sin  (bawk_val_to_num (&args[0]))); break;
                case BFN_COS:  bawk_val_set_num (&r, cos  (bawk_val_to_num (&args[0]))); break;
                case BFN_LOG:  bawk_val_set_num (&r, log  (bawk_val_to_num (&args[0]))); break;
                case BFN_EXP:  bawk_val_set_num (&r, exp  (bawk_val_to_num (&args[0]))); break;
                case BFN_ATAN2:
                    bawk_val_set_num (&r, atan2 (bawk_val_to_num (&args[0]),
                                                 bawk_val_to_num (&args[1])));
                    break;
                case BFN_RAND:
                    /* Uniform in [0,1). bash-os uses random(); values differ
                       from gawk's PRNG but the contract (range + reproducible
                       after srand(seed)) matches. */
                    bawk_val_set_num (&r, (double) random () / 2147483648.0);
                    break;
                case BFN_SRAND: {
                    /* Seed the PRNG; return the PREVIOUS seed (POSIX). No arg
                       seeds from the wall clock. */
                    static unsigned bawk_prev_seed = 0;
                    unsigned prev = bawk_prev_seed;
                    unsigned seed = (n_args >= 1)
                        ? (unsigned) bawk_val_to_num (&args[0])
                        : (unsigned) time (NULL);
                    srandom (seed);
                    bawk_prev_seed = seed;
                    bawk_val_set_num (&r, (double) prev);
                    break;
                }
                case BFN_CLOSE: {
                    if (n_args < 1) { bawk_val_set_num (&r, -1); break; }
                    char b[256];
                    const char *key = bawk_val_to_str (&args[0], b, sizeof b);
                    /* gawk synchronizes regular output before closing. */
                    fflush (stdout);
                    bawk_val_set_num (&r, (double) bawk_close_stream_key (c, key));
                    break;
                }
                case BFN_FFLUSH: {
                    int rc;
                    if (n_args == 0) {
                        rc = fflush (NULL);
                    } else {
                        char b[256];
                        const char *key = bawk_val_to_str (&args[0], b, sizeof b);
                        if (*key == '\0') rc = fflush (NULL);
                        else if (!strcmp (key, "/dev/stdout")) rc = fflush (stdout);
                        else if (!strcmp (key, "/dev/stderr")) rc = fflush (stderr);
                        else rc = bawk_fflush_stream_key (c, key);
                    }
                    bawk_val_set_num (&r, rc == 0 ? 0 : -1);
                    break;
                }
                case BFN_SYSTIME: {
                    bawk_val_set_num (&r, (double) time (NULL));
                    break;
                }
                case BFN_STRFTIME: {
                    const char *fmt = "%a %b %e %H:%M:%S %Z %Y";
                    char fb[128];
                    time_t ts = time (NULL);
                    if (n_args >= 1) {
                        fmt = bawk_val_to_str (&args[0], fb, sizeof fb);
                    }
                    if (n_args >= 2)
                        ts = (time_t) bawk_val_to_num (&args[1]);
                    struct tm tmv;
                    char out[256];
                    if (!localtime_r (&ts, &tmv) ||
                        strftime (out, sizeof out, fmt, &tmv) == 0)
                        bawk_val_set_str (&r, "");
                    else
                        bawk_val_set_str (&r, out);
                    break;
                }
                case BFN_MKTIME: {
                    if (n_args < 1) { bawk_val_set_num (&r, -1); break; }
                    char mb[128];
                    const char *s = bawk_val_to_str (&args[0], mb, sizeof mb);
                    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0, dst = -1;
                    int got = sscanf (s, "%d %d %d %d %d %d %d",
                                      &y, &mo, &d, &h, &mi, &se, &dst);
                    if (got < 6) { bawk_val_set_num (&r, -1); break; }
                    struct tm tmv;
                    memset (&tmv, 0, sizeof tmv);
                    tmv.tm_year = y - 1900;
                    tmv.tm_mon = mo - 1;
                    tmv.tm_mday = d;
                    tmv.tm_hour = h;
                    tmv.tm_min = mi;
                    tmv.tm_sec = se;
                    tmv.tm_isdst = dst;
                    time_t ts = mktime (&tmv);
                    bawk_val_set_num (&r, ts == (time_t) -1 ? -1.0 : (double) ts);
                    break;
                }
                case BFN_TOLOWER: {
                    char b[64]; size_t sl;
                    const char *s = bawk_val_to_strl (&args[0], b, sizeof b, &sl);
                    bawk_val_set_mem (&r, s, sl);
                    for (size_t k = 0; k < sl; k++) r.s[k] = (char) tolower ((unsigned char) r.s[k]);
                    break;
                }
                case BFN_TOUPPER: {
                    char b[64]; size_t sl;
                    const char *s = bawk_val_to_strl (&args[0], b, sizeof b, &sl);
                    bawk_val_set_mem (&r, s, sl);
                    for (size_t k = 0; k < sl; k++) r.s[k] = (char) toupper ((unsigned char) r.s[k]);
                    break;
                }
                case BFN_SYSTEM: {
                    if (!getenv ("BASHAWK_ALLOW_SYSTEM")) {
                        builtin_error ("system() refused; export BASHAWK_ALLOW_SYSTEM=1 to enable");
                        bawk_val_set_num (&r, 1);
                    } else {
                        char b[64]; const char *cmd = bawk_val_to_str (&args[0], b, sizeof b);
                        fflush (NULL);      /* gawk/mawk: output precedes the command's */
                        bawk_val_set_num (&r, (double) system (cmd));
                    }
                    break;
                }
                case BFN_GSUB:
                case BFN_SUB: {
                    /* gsub(re, repl[, in]) — replace all (or first for sub).
                       Returns count of substitutions. */
                    if (n_args < 2) break;
                    char *src; size_t srclen;
                    bawk_lref target_ref = {0};
                    int have_target = 0;
                    if (n_args >= 3) {
                        bawk_node *cell = n->A;
                        if (cell) cell = cell->next;
                        if (cell) cell = cell->next;
                        if (cell && cell->A) {
                            target_ref = bawk_lref_resolve (c, cell->A);
                            have_target = (target_ref.kind != BAWK_LREF_BAD);
                        }
                    }
                    if (have_target) {
                        bawk_val tv = bawk_lref_get (c, &target_ref);
                        char sb[64];
                        const char *ts = bawk_val_to_strl (&tv, sb, sizeof sb, &srclen);
                        src = bawk_memdup (ts, srclen);
                        bawk_val_free (&tv);
                    } else {
                        srclen = c->fld[0] ? c->fldlen[0] : 0;
                        src = bawk_memdup (c->fld[0] ? c->fld[0] : "", srclen);
                    }
                    if (!src) {
                        bawk_val_set_num (&r, 0);
                        break;
                    }
                    char rb[64]; size_t repllen;
                    const char *replstr = bawk_val_to_strl (&args[1], rb, sizeof rb, &repllen);
                    const char *replend = replstr + repllen;
                    /* Use the AST node's pre-compiled regex when the first arg
                       is a literal /…/ — avoids per-record regcomp in hot loops. */
                    regex_t local_re;
                    regex_t *re_p = NULL;
                    int own_re = 0;
                    if (n->A->A->kind == N_REGEX && n->A->A->re_ok) {
                        re_p = &n->A->A->re;
                    } else {
                        char ab[64]; size_t patlen;
                        const char *patstr = bawk_val_to_strl (&args[0], ab, sizeof ab, &patlen);
                        if (bawk_regcomp (&local_re, patstr, patlen) != 0) {
                            bawk_val_set_num (&r, 0); free (src); break;
                        }
                        own_re = 1;
                        re_p = &local_re;
                    }
#define re (*re_p)  /* lets the unchanged body below say `regexec(&re, ...)` */
                    regmatch_t m;
                    long count = 0;
                    char *out = NULL; size_t olen = 0, ocap = 0;
                    size_t off = 0;
                    /* Grow `out` to hold at least `need` bytes; on OOM, jump to gsub_oom. */
#define GSUB_GROW(need_n) do { \
    if ((need_n) >= ocap) { \
        size_t nc = ocap ? ocap : 64; \
        while (nc < (need_n)) { if (nc > SIZE_MAX/2) goto gsub_oom; nc *= 2; } \
        char *nb = xrealloc (out, nc); \
        if (!nb) goto gsub_oom; \
        out = nb; ocap = nc; \
    } \
} while (0)
                    while (bawk_regexec (&re, src, srclen, off, &m) == 0 && m.rm_so >= 0) {
                        size_t mso = (size_t) m.rm_so, meo = (size_t) m.rm_eo;
                        GSUB_GROW (olen + (mso - off) + repllen + 1);
                        memcpy (out + olen, src + off, mso - off);
                        olen += mso - off;
                        for (const char *rp = replstr; rp < replend; rp++) {
                            if (*rp == '\\' && rp + 1 < replend) { rp++; GSUB_GROW (olen + 1); out[olen++] = *rp; continue; }
                            if (*rp == '&') {
                                size_t mlen = meo - mso;
                                GSUB_GROW (olen + mlen + 1);
                                memcpy (out + olen, src + mso, mlen);
                                olen += mlen;
                                continue;
                            }
                            GSUB_GROW (olen + 1);
                            out[olen++] = *rp;
                        }
                        off = meo;
                        count++;
                        if (n->builtin_id == BFN_SUB) break;
                        if (mso == meo) {
                            if (off >= srclen) break;
                            GSUB_GROW (olen + 2);
                            out[olen++] = src[off++];
                        }
                    }
                    /* Append rest. */
                    size_t restlen = srclen - off;
                    GSUB_GROW (olen + restlen + 1);
                    memcpy (out + olen, src + off, restlen);
                    olen += restlen;
                    if (!out) out = bawk_strdup ("");
                    goto gsub_done;
                gsub_oom:
                    builtin_error ("awk: out of memory in gsub/sub");
                    free (out); out = bawk_strdup ("");
                    olen = 0; count = 0;
                gsub_done:
#undef GSUB_GROW
                    if (out) out[olen] = '\0';
                    if (have_target) {
                        bawk_val nv = {0};
                        bawk_val_set_mem (&nv, out ? out : "", out ? olen : 0);
                        bawk_lref_set (c, &target_ref, nv);
                    } else {
                        bawk_split_record (c, out ? out : "", out ? olen : 0);
                    }
                    bawk_val_set_num (&r, (double) count);
                    free (out); free (src);
                    if (own_re) regfree (&re);
#undef re
                    break;
                }
                case BFN_MATCH: {
                    /* Detect a regex-literal /…/ as the second arg and
                     * use the AST node's pre-compiled regex directly.
                     * Without this, the eager `bawk_eval(c, p->A)` at
                     * the top of N_CALL would route N_REGEX through
                     * its eval-as-expression path (line 1948-1956),
                     * collapsing /re/ to the boolean ($0 ~ /re/) and
                     * leaving args[1] holding "1" or "0". The
                     * regcomp("1") fallback would then look for the
                     * literal digit `1` in $0, producing the
                     * RSTART=4/RLENGTH=1 partial-match shape and the
                     * /b/-against-"abc" not-found shape that the
                     * 2026-05-19 C02 dialect-counterpart strict-parity
                     * sweep surfaced. Mirrors the BFN_GSUB/BFN_SUB
                     * pattern at lines 2181–2191; the regex-typed
                     * arg is `n->A->next->A` (second arg-list cell,
                     * its expression node). */
                    char ab[64]; size_t sl;
                    const char *s = bawk_val_to_strl (&args[0], ab, sizeof ab, &sl);
                    regex_t local_re;
                    regex_t *re_p;
                    int own_re = 0;
                    if (n->A->next && n->A->next->A->kind == N_REGEX
                        && n->A->next->A->re_ok) {
                        re_p = &n->A->next->A->re;
                    } else {
                        char bb[64]; size_t pl;
                        const char *p = bawk_val_to_strl (&args[1], bb, sizeof bb, &pl);
                        if (bawk_regcomp (&local_re, p, pl) != 0) {
                            bawk_val_set_num (&r, 0); break;
                        }
                        own_re = 1;
                        re_p = &local_re;
                    }
                    regmatch_t m;
                    int rrc = bawk_regexec (re_p, s, sl, 0, &m);
                    if (own_re) regfree (re_p);
                    if (rrc != 0) {
                        c->RSTART = 0;
                        c->RLENGTH = -1;
                        bawk_val_set_num (&r, 0);
                    } else {
                        c->RSTART = (long) m.rm_so + 1;
                        c->RLENGTH = (long) (m.rm_eo - m.rm_so);
                        bawk_val_set_num (&r, (double) c->RSTART);
                    }
                    break;
                }
                case BFN_SPLIT: {
                    /* split(str, arr, [sep]) */
                    if (n_args < 2) { bawk_val_set_num (&r, 0); break; }
                    char ab[64]; size_t sl;
                    const char *s = bawk_val_to_strl (&args[0], ab, sizeof ab, &sl);
                    const char *send = s + sl;
                    /* Need the array name from the AST, not the value. */
                    bawk_node *arr_node = n->A->next ? n->A->next->A : NULL;
                    if (!arr_node || arr_node->kind != N_IDENT) { bawk_val_set_num (&r, 0); break; }
                    bawk_var *arr = bawk_lookup_array (c, arr_node->sval);
                    /* Reset array. */
                    for (int j = 0; j < arr->n_a; j++) {
                        free (arr->akey[j]);
                        bawk_val_free (&arr->aval[j]);
                    }
                    arr->n_a = 0;
                    arr->is_array = 1;
                    int cnt = 0;
                    /* Store element ++cnt: the LEN bytes at PIECE. */
#define SPLIT_PUT(piece, plen) do { \
    char keybuf[16]; snprintf (keybuf, sizeof keybuf, "%d", ++cnt); \
    bawk_val *slot = bawk_array_slot (arr, keybuf, strlen (keybuf), 1); \
    if (slot) bawk_val_set_input_mem (slot, (piece), (plen)); \
} while (0)
                    /* Detect a regex-literal /.../ as the third arg and
                     * use the AST node's pre-compiled regex directly.
                     * Without this, the eager `bawk_eval(c, p->A)` at
                     * the top of N_CALL would route N_REGEX through
                     * its eval-as-expression path, collapsing /sep/ to
                     * the boolean ($0 ~ /sep/) and leaving args[2]
                     * holding "1" or "0", so the split would use the
                     * literal `1` or `0` character instead of the
                     * intended regex. Mirrors the BFN_GSUB/BFN_SUB and
                     * BFN_MATCH handling; the regex-typed arg is
                     * `n->A->next->next->A` (third arg-list cell, its
                     * expression node). String / variable separator
                     * forms fall through to the string-delim paths
                     * (whitespace / single-char / regcomp). */
                    bawk_node *sep_node = (n_args >= 3 && n->A->next && n->A->next->next)
                                          ? n->A->next->next->A : NULL;
                    regex_t sre;
                    regex_t *re_p = NULL;
                    int own_re = 0;
                    char db[64]; size_t dl = 0;
                    const char *delim = NULL;
                    if (sep_node && sep_node->kind == N_REGEX && sep_node->re_ok) {
                        re_p = &sep_node->re;
                    } else {
                        if (n_args >= 3) delim = bawk_val_to_strl (&args[2], db, sizeof db, &dl);
                        else { delim = c->FS ? c->FS : " "; dl = c->FS ? c->FSlen : 1; }
                    }
                    if (re_p) {
                        ;
                    } else if (!dl) {
                        /* Empty FS: one element per character. awk is
                           byte-oriented, so each byte becomes a field (matches
                           GNU awk for single-byte/ASCII text). */
                        for (const char *p = s; p < send; p++) SPLIT_PUT (p, 1);
                    } else if (dl == 1 && delim[0] == ' ') {
                        const char *p = s;
                        while (p < send) {
                            while (p < send && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
                            if (p >= send) break;
                            const char *q = p;
                            while (p < send && *p != ' ' && *p != '\t' && *p != '\n') p++;
                            SPLIT_PUT (q, (size_t) (p - q));
                        }
                    } else if (dl == 1) {
                        char d = delim[0];
                        const char *p = s;
                        for (;;) {
                            const char *q = p;
                            while (p < send && *p != d) p++;
                            SPLIT_PUT (q, (size_t) (p - q));
                            if (p >= send) break;
                            p++;
                        }
                    } else {
                        /* multi-char delim: regex split, matching POSIX awk. */
                        if (bawk_regcomp (&sre, delim, dl) != 0) {
                            builtin_warning ("awk: split: bad regex: %s", delim);
                            break;
                        }
                        own_re = 1;
                        re_p = &sre;
                    }
                    if (re_p) {
                        regmatch_t m;
                        size_t off = 0;
                        while (off < sl && bawk_regexec (re_p, s, sl, off, &m) == 0
                               && m.rm_so >= 0 && m.rm_eo > m.rm_so) {
                            SPLIT_PUT (s + off, (size_t) m.rm_so - off);
                            off = (size_t) m.rm_eo;
                        }
                        SPLIT_PUT (s + off, sl - off);
                        if (own_re) regfree (re_p);
                    }
#undef SPLIT_PUT
                    bawk_val_set_num (&r, (double) cnt);
                    break;
                }
            }
            for (int j = 0; j < n_args; j++) bawk_val_free (&args[j]);
            free (args);
            return r;
        }
        case N_PRINT:
            return bawk_eval_print (c, n);
        case N_PRINTF:
            return bawk_eval_printf (c, n);
        case N_IF:
            return bawk_eval_if (c, n);
        case N_WHILE:
            return bawk_eval_while (c, n);
        case N_FOR:
            return bawk_eval_for (c, n);
        case N_FORIN:
            return bawk_eval_forin (c, n);
        case N_DELETE:
            return bawk_eval_delete (c, n);
        case N_INARRAY:
            return bawk_eval_inarray (c, n);
        case N_BREAK:    c->brk_flag = 1; return r;
        case N_CONTINUE: c->cont_flag = 1; return r;
        case N_NEXT:     c->next_flag = 1; return r;
        case N_NEXTFILE: c->nextfile_flag = 1; return r;
        case N_EXIT:
            /* Evaluate the status expression BEFORE raising exit_flag:
               bawk_eval short-circuits to an empty value once the flag is
               set, which silently turned `exit 3` into `exit 0`. */
            if (n->A) {
                bawk_val v = bawk_eval (c, n->A);
                c->exit_code = (int) bawk_val_to_num (&v);
                bawk_val_free (&v);
            }
            c->exit_flag = 1;
            return r;
        case N_RETURN:
            bawk_val_free (&c->return_val);
            if (n->A) c->return_val = bawk_eval (c, n->A);
            else c->return_val = (bawk_val){0};
            c->return_flag = 1;
            return r;
        case N_FUNCDEF: {
            /* Register or update in function table. Idempotent (if program
               re-evaluates the FUNCDEF — shouldn't normally happen). */
            bawk_func *f = c->funcs;
            while (f && strcmp (f->name, n->sval) != 0) f = f->next;
            if (!f) {
                f = bawk_calloc (1, sizeof *f);
                if (!f) return r;
                f->name = bawk_strdup (n->sval);
                f->next = c->funcs;
                c->funcs = f;
            }
            /* Count + capture parameter names (each is an N_IDENT node
               in the linked list under n->A). */
            int np = 0;
            for (bawk_node *p = n->A; p; p = p->next) np++;
            f->params = xrealloc (f->params, (size_t) (np + 1) * sizeof *f->params);
            int i = 0;
            for (bawk_node *p = n->A; p; p = p->next) {
                f->params[i++] = bawk_strdup (p->sval ? p->sval : "");
            }
            f->params[np] = NULL;
            f->n_params = np;
            f->body = n->B;
            return r;
        }
        case N_USERCALL: {
            /* Find function by name. */
            bawk_func *f = c->funcs;
            while (f && strcmp (f->name, n->sval) != 0) f = f->next;
            if (!f) {
                builtin_error ("awk: undefined function: %s", n->sval);
                c->exit_flag = 1;
                c->exit_code = 2;
                c->fatal_flag = 1;
                return r;
            }
            /* Evaluate args first (in caller scope). */
            int n_args = 0;
            for (bawk_node *p = n->A; p; p = p->next) n_args++;
            bawk_val *args = (n_args > 0) ? bawk_calloc ((size_t) n_args, sizeof *args) : NULL;
            /* An argument naming an array, or an untyped variable, is passed
               by reference: resolve the targets before any parameter is
               rebound, since parameters share the global name space. Such an
               argument is not evaluated as a scalar (that would turn an
               untyped forwarded parameter into a local scalar). */
            bawk_var **byref = (f->n_params > 0) ? bawk_calloc ((size_t) f->n_params, sizeof *byref) : NULL;
            int ai = 0;
            for (bawk_node *p = n->A; p && ai < f->n_params; p = p->next, ai++) {
                if (!p->A || p->A->kind != N_IDENT || bawk_special_name (p->A->sval)) continue;
                bawk_var *t = bawk_lookup_array (c, p->A->sval);
                if (t->is_array || (!t->val.s && !t->val.have_n && t->n_a == 0))
                    byref[ai] = t;
            }
            ai = 0;
            for (bawk_node *p = n->A; p; p = p->next, ai++) {
                if (ai < f->n_params && byref[ai]) { args[ai].strnum = BAWK_UNINIT; continue; }
                args[ai] = bawk_eval (c, p->A);
            }
            /* Save each parameter's whole state (for local-scope semantics):
               its scalar, its array and any reference binding. */
            bawk_var *saved = (f->n_params > 0) ? bawk_calloc ((size_t) f->n_params, sizeof *saved) : NULL;
            unsigned char *kept = (f->n_params > 0) ? bawk_calloc ((size_t) f->n_params, 1) : NULL;
            for (int j = 0; j < f->n_params; j++) {
                bawk_var *v = bawk_lookup_or_create (c, f->params[j]);
                bawk_var *self = v;
                while (self->ref) self = self->ref;
                if (byref[j] && byref[j] == self) {
                    /* f(a) with parameter a: the same array already. */
                    kept[j] = 1;
                    if (j < n_args) bawk_val_free (&args[j]);
                    continue;
                }
                saved[j] = *v;
                v->val = (bawk_val){0};
                v->is_array = 0; v->akey = NULL; v->aklen = NULL; v->aval = NULL;
                v->n_a = v->cap_a = 0; v->ref = byref[j];
                /* Bind to arg value (or zero if not enough args). */
                if (j < n_args) v->val = args[j];
            }
            free (byref);
            /* Eval body. */
            bawk_val v = bawk_eval (c, f->body);
            bawk_val_free (&v);
            /* Capture return value. */
            bawk_val ret = c->return_val;
            c->return_val = (bawk_val){0};
            c->return_flag = 0;
            /* Restore params, dropping the call's local arrays. */
            for (int j = 0; j < f->n_params; j++) {
                if (kept[j]) continue;
                bawk_var *v2 = bawk_lookup_or_create (c, f->params[j]);
                bawk_val_free (&v2->val);
                for (int k = 0; k < v2->n_a; k++) { free (v2->akey[k]); bawk_val_free (&v2->aval[k]); }
                free (v2->akey); free (v2->aklen); free (v2->aval);
                v2->val = saved[j].val;
                v2->is_array = saved[j].is_array;
                v2->akey = saved[j].akey; v2->aklen = saved[j].aklen; v2->aval = saved[j].aval;
                v2->n_a = saved[j].n_a; v2->cap_a = saved[j].cap_a;
                v2->ref = saved[j].ref;
            }
            free (saved);
            free (kept);
            free (args);
            return ret;
        }
        case N_BLOCK: {
            for (bawk_node *p = n->A; p; p = p->next) {
                bawk_val v = bawk_eval (c, p->A);
                bawk_val_free (&v);
                if (c->brk_flag || c->cont_flag || c->exit_flag || c->next_flag || c->nextfile_flag || c->return_flag) break;
            }
            return r;
        }
        case N_LIST: case N_RULE:
            /* RULE is handled by the runner, not eval. */
            return r;
        default:
            builtin_warning ("awk: internal: unhandled node kind %d", (int) n->kind);
            return r;
    }
    return r;
}

/* Free everything in a parser pool + ctx. */
static void
bawk_free_all (bawk_parser *P, bawk_ctx *c)
{
    if (P) {
        for (int i = 0; i < P->n_all; i++) {
            bawk_node *n = P->all[i];
            free (n->sval); free (n->array_name);
            if (n->re_ok) regfree (&n->re);
            free (n);
        }
        free (P->all);
    }
    if (c) {
        for (int i = 0; i <= c->nf; i++) free (c->fld[i]);
        free (c->fld);
        free (c->fldlen);
        bawk_var *v = c->head;
        while (v) {
            bawk_var *nx = v->next;
            free (v->name);
            bawk_val_free (&v->val);
            for (int i = 0; i < v->n_a; i++) {
                free (v->akey[i]);
                bawk_val_free (&v->aval[i]);
            }
            free (v->akey); free (v->aklen); free (v->aval);
            free (v);
            v = nx;
        }
        bawk_val_free (&c->NR); bawk_val_free (&c->FNR);
        /* Regex-RS buffers are per run: the builtin runs in the shell. */
        for (size_t i = 0; i < sizeof bawk_rsbufs / sizeof *bawk_rsbufs; i++) {
            free (bawk_rsbufs[i].buf);
            bawk_rsbufs[i] = (bawk_rsbuf){0};
        }
        free (c->FS); free (c->OFS); free (c->ORS); free (c->SUBSEP); free (c->FILENAME);
        free (c->CONVFMT); free (c->OFMT);
        /* Drop the active-format pointers (they aliased freed ctx storage). */
        bawk_convfmt = "%.6g"; bawk_ofmt = "%.6g";
        /* Stage B: close any open redirected streams. Pipe streams (op
           3/4) use the V42-11 guarded EINTR-safe waitpid reap; file
           streams (op 1/2/5) use plain fclose. */
        for (size_t i = 0; i < c->n_streams; i++) {
            if (c->streams[i].fp) {
                bawk_close_one_stream (&c->streams[i]);
            }
            free (c->streams[i].key);
        }
        free (c->streams);
        c->streams = NULL; c->n_streams = c->cap_streams = 0;
        /* Free user-function table. */
        bawk_func *f = c->funcs;
        while (f) {
            bawk_func *nx = f->next;
            free (f->name);
            for (int i = 0; i < f->n_params; i++) free (f->params[i]);
            free (f->params);
            free (f);
            f = nx;
        }
        bawk_val_free (&c->return_val);
    }
}

/* Run one input line through every applicable rule. */
static void
bawk_run_line (bawk_ctx *c, bawk_node *prog, const char *line, size_t len)
{
    bawk_set_record (c, line, len);
    for (bawk_node *p = prog->A; p; p = p->next) {
        bawk_node *r = p->A;
        if (r->kind == N_FUNCDEF) continue;   /* skip funcdefs at run time */
        if ((int) r->nval != 0) continue;   /* skip BEGIN/END */
        int matched = 1;
        if (r->A) {
            bawk_val v = bawk_eval (c, r->A);
            matched = bawk_val_true (&v);
            bawk_val_free (&v);
        }
        if (matched && r->B) {
            bawk_val v = bawk_eval (c, r->B);
            bawk_val_free (&v);
        }
        if (c->next_flag) { c->next_flag = 0; break; }
        if (c->nextfile_flag) break;   /* propagated to outer file walker */
        if (c->exit_flag) break;
    }
}

static int bawk_main (WORD_LIST *list);

/* Bash line-buffers stdout, which costs one write(2) per record. While
   stdout is not a terminal, buffer it fully for the run, as gawk and mawk
   do, and give the shell back its line buffering afterwards. The unwind
   frame also restores it when an interrupt unwinds the builtin. */
static int bawk_stdout_full;

static void
bawk_stdout_restore (void *unused)
{
    (void) unused;
    fflush (stdout);
    if (bawk_stdout_full) {
        setvbuf (stdout, NULL, _IOLBF, 0);
        bawk_stdout_full = 0;
    }
}

int
awk_builtin (WORD_LIST *list)
{
    int rc;
    fflush (stdout);
    begin_unwind_frame ("bashawk-stdout");
    add_unwind_protect (bawk_stdout_restore, NULL);
    if (!bawk_stdout_full && !isatty (fileno (stdout)) && __flbf (stdout)
        && setvbuf (stdout, NULL, _IOFBF, 0) == 0)
        bawk_stdout_full = 1;
    rc = bawk_main (list);
    run_unwind_frame ("bashawk-stdout");
    return rc;
}

static int
bawk_main (WORD_LIST *list)
{
    /* Bash applies builtin redirections by swapping the underlying file
       descriptor for stdio's fd.  The libc FILE object can still carry EOF
       from a prior `awk ... </dev/null`; clear it so later pipeline-fed
       invocations read from their new fd 0. */
    clearerr (stdin);
    clearerr (stdout);
    clearerr (stderr);

    /* Collect script text + flags. */
    char *script = bawk_strdup (""); size_t script_cap = 1, script_len = 0;
    int n_files = 0, files_cap = 8;
    const char **files = xmalloc ((size_t) files_cap * sizeof *files);
    char *fs_override = NULL;
    size_t fs_override_len = 0;

    bawk_ctx ctx = {0};
    bawk_val_set_num (&ctx.NR, 0); bawk_val_set_num (&ctx.FNR, 0);
    ctx.out = stdout;
    ctx.out_tty = isatty (fileno (stdout));
    ctx.max_stack = BAWK_DEFAULT_MAX_STACK;
    ctx.FS = bawk_strdup (" "); ctx.OFS = bawk_strdup (" "); ctx.ORS = bawk_strdup ("\n");
    ctx.SUBSEP = bawk_strdup ("\034");
    ctx.FSlen = ctx.OFSlen = ctx.ORSlen = ctx.SUBSEPlen = 1;
    ctx.CONVFMT = bawk_strdup ("%.6g"); ctx.OFMT = bawk_strdup ("%.6g");
    /* Reset the active number-format pointers for this run (they are
       repointed at ctx.CONVFMT/ctx.OFMT storage on assignment). */
    bawk_convfmt = ctx.CONVFMT ? ctx.CONVFMT : "%.6g";
    bawk_ofmt    = ctx.OFMT ? ctx.OFMT : "%.6g";
    ctx.fld_cap = 16;
    ctx.fld = bawk_calloc (16, sizeof *ctx.fld);
    ctx.fldlen = bawk_calloc (16, sizeof *ctx.fldlen);
    if (!ctx.fld || !ctx.fldlen || !ctx.FS || !ctx.OFS || !ctx.ORS || !ctx.SUBSEP || !ctx.CONVFMT || !ctx.OFMT) {
        builtin_error ("awk: out of memory");
        free (ctx.fld); free (ctx.fldlen); free (ctx.FS); free (ctx.OFS); free (ctx.ORS); free (ctx.SUBSEP);
        free (ctx.CONVFMT); free (ctx.OFMT);
        bawk_convfmt = "%.6g"; bawk_ofmt = "%.6g";
        free ((void *) files);
        return EXECUTION_FAILURE;
    }
    ctx.fld[0] = bawk_strdup ("");

    const char *max_stack_env = getenv ("BASHAWK_MAX_STACK");
    if (max_stack_env && *max_stack_env) {
        char *end = NULL;
        errno = 0;
        long n = strtol (max_stack_env, &end, 10);
        if (errno || end == max_stack_env || *end || n < 1 || n > INT_MAX) {
            builtin_error ("BASHAWK_MAX_STACK must be a positive integer");
            bawk_free_all (NULL, &ctx);
            return EX_USAGE;
        }
        ctx.max_stack = (int) n;
    }

    /* Populate ENVIRON associative array from the host environment. */
    extern char **environ;
    bawk_var *envv = bawk_lookup_or_create (&ctx, "ENVIRON");
    envv->is_array = 1;
    if (environ) {
        for (char **e = environ; *e; e++) {
            const char *eq = strchr (*e, '=');
            if (!eq) continue;
            char *key = bawk_strndup (*e, (size_t) (eq - *e));
            const char *val = eq + 1;
            bawk_val *slot = bawk_array_slot (envv, key, strlen (key), 1);
            if (slot) bawk_val_set_input (slot, val);
            free (key);
        }
    }

    /* preset -v assignments */
    typedef struct { char *name; char *val; } prev_var;
    prev_var *pre_vars = NULL; int n_pre = 0, cap_pre = 0;

    int script_seen = 0;
    WORD_LIST *p = list;
    bawk_nsegs = 0;
    bawk_src = NULL;
    while (p) {
        const char *w = p->word->word;
        if (w[0] == '-' && w[1] != '\0' && strcmp (w, "--") != 0) {
	            if (!strcmp (w, "--help")) {
	                puts ("awk: POSIX-subset awk");
	                puts ("Usage: awk [-F SEP] [-v VAR=VAL] [-e SCRIPT] [-f FILE] [SCRIPT] [FILE...]");
	                bawk_free_all (NULL, &ctx);
	                free (script); free ((void *) files); free (fs_override);
	                for (int i = 0; i < n_pre; i++) { free (pre_vars[i].name); free (pre_vars[i].val); }
	                free (pre_vars);
	                return EXECUTION_SUCCESS;
	            }
	            if (w[1] == '-') {
	                builtin_error ("unknown flag: %s", w);
	                builtin_usage ();
	                goto err_usage;
	            }
	            for (const char *cc = w + 1; *cc; cc++) {
	                switch (*cc) {
                    case 'F': {
                        const char *val;
                        if (cc[1]) { val = cc + 1; cc += strlen (cc) - 1; }
                        else if (p->next) { p = p->next; val = p->word->word; }
                        else { builtin_error ("-F needs SEP"); goto err; }
                        free (fs_override); fs_override = bawk_unescape (val, &fs_override_len);
                        goto next_word;
                    }
                    case 'v': {
                        if (!p->next) { builtin_error ("-v needs VAR=VAL"); goto err; }
                        p = p->next;
                        const char *eq = strchr (p->word->word, '=');
                        if (!eq) { builtin_error ("-v expects VAR=VAL"); goto err; }
                        if (n_pre == cap_pre) { cap_pre = cap_pre ? cap_pre * 2 : 8; pre_vars = xrealloc (pre_vars, (size_t) cap_pre * sizeof *pre_vars); }
                        pre_vars[n_pre].name = bawk_strndup (p->word->word, (size_t) (eq - p->word->word));
                        pre_vars[n_pre].val  = bawk_strdup (eq + 1);
                        n_pre++;
                        goto next_word;
                    }
                    case 'e': {
                        if (!p->next) { builtin_error ("-e needs SCRIPT"); goto err; }
                        p = p->next;
                        size_t l = strlen (p->word->word);
                        size_t need = script_len + l + 2;
                        if (script_cap < need) { while (script_cap < need) script_cap = script_cap ? script_cap * 2 : 256; script = xrealloc (script, script_cap); }
                        if (script_len) script[script_len++] = '\n';
                        bawk_seg_add (script_len, "cmd. line");
                        memcpy (script + script_len, p->word->word, l);
                        script_len += l;
                        script[script_len] = '\0';
                        script_seen = 1;
                        goto next_word;
                    }
                    case 'f': {
                        if (!p->next) { builtin_error ("-f needs FILE"); goto err; }
                        p = p->next;
                        FILE *f = fopen (p->word->word, "r");
                        if (!f) { builtin_error ("-f %s: %s", p->word->word, strerror (errno)); goto err; }
                        if (script_len) {
                            if (script_len + 2 > script_cap) {
                                script_cap = script_len + 2;
                                script = xrealloc (script, script_cap);
                            }
                            script[script_len++] = '\n'; script[script_len] = 0;
                        }
                        bawk_seg_add (script_len, p->word->word);
                        char buf[4096]; size_t rd;
                        while ((rd = fread (buf, 1, sizeof buf, f)) > 0) {
                            size_t need = script_len + rd + 2;
                            if (script_cap < need) { while (script_cap < need) script_cap = script_cap ? script_cap * 2 : 256; script = xrealloc (script, script_cap); }
                            memcpy (script + script_len, buf, rd);
                            script_len += rd;
                            script[script_len] = '\0';
                        }
                        int read_failed = ferror (f);
                        if (fclose (f) != 0) read_failed = 1;
                        if (read_failed) { builtin_error ("-f %s: read failed", p->word->word); goto err; }
                        script_seen = 1;
                        goto next_word;
	                    }
	                    default:
	                        builtin_error ("unknown flag: -%c", *cc);
	                        builtin_usage ();
	                        goto err_usage;
	                }
	            }
	        }
        else if (!script_seen) {
            size_t l = strlen (w);
            size_t need = l + 2;
            if (script_cap < need) { script_cap = need; script = xrealloc (script, script_cap); }
            memcpy (script, w, l);
            script[l] = '\0';
            script_len = l;
            script_seen = 1;
            bawk_seg_add (0, "cmd. line");
        }
        else {
            if (n_files == files_cap) { files_cap *= 2; files = xrealloc (files, (size_t) files_cap * sizeof *files); }
            files[n_files++] = w;
        }
    next_word:
        p = p ? p->next : NULL;
    }

    if (!script_seen) { builtin_usage (); goto err_usage; }

    if (fs_override) {
        free (ctx.FS); ctx.FS = fs_override; ctx.FSlen = fs_override_len; fs_override = NULL;
    }

    /* POSIX-visible argument vector for BEGIN/program use. This prepopulates
       ARGC/ARGV; mutating ARGV to control the input walk is a larger awk
       compatibility surface and is intentionally not implemented here. */
    {
        bawk_var *argc = bawk_lookup_or_create (&ctx, "ARGC");
        bawk_var *argv = bawk_lookup_or_create (&ctx, "ARGV");
        char key[32];
        bawk_val_set_num (&argc->val, (double) (n_files + 1));
        argv->is_array = 1;
        bawk_val *slot = bawk_array_slot (argv, "0", 1, 1);
        if (slot) bawk_val_set_str (slot, "awk");
        for (int i = 0; i < n_files; i++) {
            snprintf (key, sizeof key, "%d", i + 1);
            slot = bawk_array_slot (argv, key, strlen (key), 1);
            if (slot) bawk_val_set_input (slot, files[i]);
        }
    }

    /* Lex + parse. */
    bawk_src = script;
    bawk_lex L = {0};
    if (bawk_lex_string (&L, script) < 0) { bawk_lex_free (&L); goto err; }

    bawk_parser P = { .L = &L };
    bawk_node *prog = bawk_parse_program (&P);
    if (!prog || P.const_div_errors) { bawk_lex_free (&L); bawk_free_all (&P, NULL); goto err; }
    bawk_lower_program (&P, prog);

    /* Apply -v presets. */
    for (int i = 0; i < n_pre; i++) {
        bawk_node lhs = {0};
        bawk_val pv = {0};
        lhs.kind = N_IDENT;
        lhs.sval = pre_vars[i].name;
        size_t uvl = 0;
        char *uv = bawk_unescape (pre_vars[i].val, &uvl);
        if (uv) bawk_val_set_input_mem (&pv, uv, uvl);
        else bawk_val_set_input (&pv, pre_vars[i].val);
        free (uv);
        bawk_assign_lhs (&ctx, &lhs, pv);
    }

    /* GNU awk initializes the per-file counter after command-line presets. */
    bawk_val_set_num (&ctx.FNR, 0);

    /* Pre-register all user-defined functions BEFORE any rule runs, so
       BEGIN/per-line/END blocks can call functions regardless of source
       order. */
    for (bawk_node *q = prog->A; q; q = q->next) {
        bawk_node *r = q->A;
        if (r->kind == N_FUNCDEF) {
            bawk_val v = bawk_eval (&ctx, r);
            bawk_val_free (&v);
        }
    }

    /* BEGIN blocks. */
    for (bawk_node *q = prog->A; q && !ctx.exit_flag; q = q->next) {
        bawk_node *r = q->A;
        if (r->kind == N_FUNCDEF) continue;
        if ((int) r->nval == 1 && r->B) {
            bawk_val v = bawk_eval (&ctx, r->B);
            bawk_val_free (&v);
        }
    }

    /* Only auto-read input when a normal rule or END block can observe it.
       BEGIN-only programs must return without waiting for stdin; explicit
       getline inside BEGIN reads stdin directly and is unaffected. */
    int needs_input = 0;
    for (bawk_node *q = prog->A; q; q = q->next) {
        bawk_node *r = q->A;
        if (r->kind == N_FUNCDEF) continue;
        int kind = (int) r->nval; /* 0=normal, 1=BEGIN, 2=END */
        if (kind == 0 || kind == 2) {
            needs_input = 1;
            break;
        }
    }

    /* Per-line execution. */
    /* Operands of the form VAR=VALUE are assignments made when the walk
       reaches them; with no file operands, standard input is read after
       all of them (POSIX awk OPERANDS). */
    int n_real_files = 0;
    for (int i = 0; i < n_files; i++)
        if (!bawk_operand_assignment (files[i])) n_real_files++;
    if (needs_input) {
        if (n_real_files == 0) {
            for (int i = 0; i < n_files && !ctx.exit_flag; i++)
                bawk_apply_assignment (&ctx, files[i]);
            if (!ctx.exit_flag) {
                char *line = NULL; size_t cap = 0; ssize_t rd;
                while ((rd = bawk_read_record (&ctx, stdin, &line, &cap)) != -1) {
                    bawk_counter_advance (&ctx.NR);
                    bawk_counter_advance (&ctx.FNR);
                    bawk_run_line (&ctx, prog, line, (size_t) rd);
                    if (ctx.exit_flag) break;
                }
                free (line);
            }
        }
        else {
            for (int i = 0; i < n_files && !ctx.exit_flag; i++) {
                if (bawk_operand_assignment (files[i])) {
                    bawk_apply_assignment (&ctx, files[i]);
                    continue;
                }
                int is_stdin = !strcmp (files[i], "-");
                FILE *f = is_stdin ? stdin : fopen (files[i], "r");
                if (!f) { builtin_error ("%s: %s", files[i], strerror (errno)); ctx.exit_code = 2; ctx.fatal_flag = ctx.exit_flag = 1; break; }
                free (ctx.FILENAME);
                ctx.FILENAME = bawk_strdup (files[i]);
                bawk_val_set_num (&ctx.FNR, 0);        /* gawk: FNR resets to 0 at each new input file */
                char *line = NULL; size_t cap = 0; ssize_t rd;
                while ((rd = bawk_read_record (&ctx, f, &line, &cap)) != -1) {
                    bawk_counter_advance (&ctx.NR);
                    bawk_counter_advance (&ctx.FNR);
                    bawk_run_line (&ctx, prog, line, (size_t) rd);
                    if (ctx.exit_flag) break;
                    /* `nextfile` abandons the current input file; clear the
                       flag so subsequent files in argv are still processed.
                       The eval-time short-circuits (in bawk_run_line + the
                       per-rule executor + per-stmt eval) prevent any further
                       patterns/actions from firing against the current file
                       before we get here. */
                    if (ctx.nextfile_flag) { ctx.nextfile_flag = 0; break; }
                }
                free (line);
                bawk_rs_forget (f);
                if (is_stdin) clearerr (f);
                else fclose (f);
            }
        }
    }

    /* END blocks. A user `exit` in BEGIN/main rules still runs the END
       rules (gawk/POSIX); clear the flag so eval does not short-circuit,
       keeping exit_code. Fatal errors leave the flag raised and skip END.
       `exit` inside an END rule re-raises the flag and stops the
       remaining END rules. */
    if (!ctx.fatal_flag) ctx.exit_flag = 0;
    for (bawk_node *q = prog->A; q && !ctx.exit_flag; q = q->next) {
        bawk_node *r = q->A;
        if (r->kind == N_FUNCDEF) continue;
        if ((int) r->nval == 2 && r->B) {
            bawk_val v = bawk_eval (&ctx, r->B);
            bawk_val_free (&v);
        }
    }

    int rc = ctx.exit_code;
    bawk_free_all (&P, &ctx);
    bawk_lex_free (&L);
    free (script); free ((void *) files);
    for (int i = 0; i < n_pre; i++) { free (pre_vars[i].name); free (pre_vars[i].val); }
    free (pre_vars);
    return rc == 0 ? EXECUTION_SUCCESS : rc;

	err:
	    bawk_free_all (NULL, &ctx);
	    free (script); free ((void *) files); free (fs_override);
	    for (int i = 0; i < n_pre; i++) { free (pre_vars[i].name); free (pre_vars[i].val); }
	    free (pre_vars);
	    return EXECUTION_FAILURE;

	err_usage:
	    bawk_free_all (NULL, &ctx);
	    free (script); free ((void *) files); free (fs_override);
	    for (int i = 0; i < n_pre; i++) { free (pre_vars[i].name); free (pre_vars[i].val); }
	    free (pre_vars);
	    return EXECUTION_FAILURE;
}

char *awk_doc[] = {
    "POSIX-subset awk(1) — pattern-action language.",
    "",
    "    awk [-F SEP] [-v VAR=VAL] [-f FILE] [-e SCRIPT] [SCRIPT] [FILE...]",
    "",
    "Supports BEGIN/END, pattern { action }, regex /…/, fields $0..$NF,",
    "NR/FNR/NF/FS/OFS/ORS/FILENAME, assoc arrays (incl. SUBSEP multi-dim),",
    "NR/FNR are writable; FNR resets at startup and for each named input file.",
    "if/else/while/for/for-in/do-while, break/continue/next/nextfile/exit,",
    "+-*/%^ ** == != < <= > >= ~ !~ && || ! ?:, string concat (juxtaposition),",
    "length/substr/index/split/sprintf/gsub/sub/match/int/sqrt/sin/cos/",
    "log/exp/tolower/toupper/systime/strftime/mktime, user-defined",
    "functions, getline (var or from file), ENVIRON, RSTART/RLENGTH,",
    "system (gated by BASHAWK_ALLOW_SYSTEM=1).",
    "NUL bytes are data (gawk): in input, in strings and escapes (\"\\0\"),",
    "in -v/-F values, in regex literals (/\\0/), and as RS, FS, OFS or ORS.",
    "Output that is not a terminal is fully buffered (gawk/mawk): it is",
    "flushed before system(), a command pipe, close(), on fflush() and at",
    "exit. \"/dev/stdout\" and \"/dev/stderr\" are the standard streams.",
    "Division or modulo by a constant zero is an error before anything runs",
    "(status 1); a zero divisor found while running is fatal (status 2), as",
    "in gawk.",
    "Pipe redirections `print|\"cmd\"` and `\"cmd\"|getline` run /bin/sh -c",
    "via explicit fork+execv (V42-11 helper-exec hardening: SIGCHLD",
    "disposition reset + O_CLOEXEC pipe FDs + EINTR-safe wait).",
    "",
    "Out of scope: RT.",
    "Use system+ awk for those.",
    (char *)NULL
};

struct builtin awk_struct = {
    "awk",
    awk_builtin,
    BUILTIN_ENABLED,
    awk_doc,
    "awk [-F SEP] [-v VAR=VAL] [-f FILE] [-e SCRIPT] [SCRIPT] [FILE...]",
    0
};
