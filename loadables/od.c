/* bashod.c — POSIX / GNU od(1) as a bash builtin.
 *
 *   od [OPTION]... [FILE]...
 *   od [-abcdfhilosxBDeFHILOX]... [FILE] [[+]OFFSET[b]]
 *   od --traditional [OPTION]... [FILE] [[+]OFFSET[b] [[+]LABEL[b]]]
 *
 *   -A, --address-radix=x|o|d|n   address radix; default o
 *   -j, --skip-bytes=BYTES        skip BYTES first
 *   -N, --read-bytes=BYTES        dump at most BYTES
 *   -S BYTES, --strings[=BYTES]   GNU NUL-terminated strings (default 3)
 *   -t, --format=TYPE             a, c, [doux]{1,2,4,8,C,S,I,L}, f{4,8,F,D};
 *                                 a trailing z adds ">printable<"
 *   -v, --output-duplicates       do not collapse repeated lines into "*"
 *   -w[N], --width[=N]            bytes per line (16; bare -w => 32)
 *   --endian=big|little           byte order of multi-byte elements
 *   --traditional                 accept OFFSET and LABEL operands
 *   -s [N]                        bash-os strings: runs of >= N printable
 *                                 chars (not GNU's -s, which is -t d2)
 *
 * Long options take GNU's unambiguous-prefix abbreviations. Reads stdin
 * when no FILE is given. Multiple display modes stack under one address,
 * each type's column padded and aligned GNU-style.
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
#include <limits.h>
#include <sys/types.h>

#include "loadables.h"
#include "longopt-normalize.h"

#define OD_DEFAULT_WIDTH 16   /* default bytes per output line */
#define OD_MAX_SPECS     16   /* max stacked -t / legacy selectors */

/* A single display format. kind: 'c' char-escape, 'a' named-char,
   'i' integer (then base in 'x'/'o'/'d'/'u' and bytes in {1,2,4,8}),
   'f' IEEE float (bytes in {4,8}). */
typedef struct {
    char kind;
    char base;     /* for kind 'i': 'x' 'o' 'd' (signed) 'u' (unsigned) */
    int  bytes;    /* element width in bytes (1,2,4,8) */
    int  field;    /* natural field width incl. leading separator space */
    int  zchars;   /* 'z' suffix: append ">printable<" to each line */
} od_spec;

typedef struct {
    char addr_radix;       /* 'x' 'o' 'd' 'n' */
    od_spec specs[OD_MAX_SPECS];
    int  nspecs;
    int  width;            /* bytes per output line */
    int  no_dedup;         /* -v: disable '*' run collapsing */
    int  strings_min;      /* 0 = -s mode off; otherwise minimum run length */
    int  gnu_strings_min;  /* -1 = -S mode off; >=0 = GNU NUL-terminated mode */
    long long skip_bytes;  /* -j: bytes to skip before dumping */
    long long max_bytes;   /* -1 = unlimited; >=0 = stop after N bytes (-N) */
    int  has_label;        /* --traditional LABEL operand given */
    long long label;       /* pseudo-address of the first byte dumped */
} od_opts;

/* --endian=big: multi-byte elements are read most significant byte first. */
static int od_big_endian;

/* Named ASCII control chars for -t a (bytes 0x00..0x1f, 0x20=sp, 0x7f=del). */
static const char *od_ascii_names[] = {
    "nul","soh","stx","etx","eot","enq","ack","bel",
    " bs"," ht"," nl"," vt"," ff"," cr"," so"," si",
    "dle","dc1","dc2","dc3","dc4","nak","syn","etb",
    "can"," em","sub","esc"," fs"," gs"," rs"," us"
};

static int
od_spec_field (char kind, char base, int bytes)
{
    if (kind == 'c' || kind == 'a')
        return 4;            /* "   A" / " nul" */
    if (kind == 'f')         /* GNU: f4 => 16 cols, f8 => 25 cols (incl sep) */
        return (bytes == 4) ? 16 : 25;
    switch (base) {
        case 'x': return (bytes == 1) ? 3 : (bytes == 2) ? 5 : (bytes == 4) ? 9 : 17;
        case 'o': return (bytes == 1) ? 4 : (bytes == 2) ? 7 : (bytes == 4) ? 12 : 23;
        case 'd': return (bytes == 1) ? 5 : (bytes == 2) ? 7 : (bytes == 4) ? 12 : 21;
        case 'u':
        default:  return (bytes == 1) ? 4 : (bytes == 2) ? 6 : (bytes == 4) ? 11 : 21;
    }
}

static od_spec *
od_add_spec (od_opts *o, char kind, char base, int bytes)
{
    if (o->nspecs >= OD_MAX_SPECS)
        return NULL;
    od_spec *s = &o->specs[o->nspecs++];
    s->kind  = kind;
    s->base  = base;
    s->bytes = bytes;
    s->field = od_spec_field (kind, base, bytes);
    s->zchars = 0;
    return s;
}

/* The 'z' column: pad the line to its full width, then two spaces and
   the line's bytes between '>' and '<', non-printables shown as '.'. */
static void
od_emit_zchars (const unsigned char *buf, size_t n, int pad)
{
    for (int p = 0; p < pad + 2; p++) putchar (' ');
    putchar ('>');
    for (size_t i = 0; i < n; i++)
        putchar (buf[i] >= 0x20 && buf[i] < 0x7f ? buf[i] : '.');
    putchar ('<');
}

static void
od_print_addr (long long off, char rad)
{
    switch (rad) {
        case 'x': printf ("%06llx", off); break;
        case 'd': printf ("%07lld", off); break;
        case 'n': return;
        case 'o':
        default:  printf ("%07llo", off); break;
    }
}

/* The address column of a line. A --traditional LABEL adds the
   pseudo-address in parentheses; with -A n only the parenthesized
   column remains, and it shows the octal offset (as GNU od does). */
static void
od_print_prefix (const od_opts *o, long long off)
{
    if (!o->has_label) {
        od_print_addr (off, o->addr_radix);
        return;
    }
    if (o->addr_radix == 'n') {
        printf ("(%07llo)", off);
        return;
    }
    od_print_addr (off, o->addr_radix);
    fputs (" (", stdout);
    od_print_addr (o->label + (off - o->skip_bytes), o->addr_radix);
    putchar (')');
}

/* Width of the blank prefix on the second and later type rows. */
static int
od_prefix_width (const od_opts *o)
{
    if (o->addr_radix == 'n')
        return o->has_label ? 7 : 0;
    return o->addr_radix == 'x' ? 6 : 7;
}

/* Render a single byte under the char-escape format ('-c'). */
static void
od_emit_c (unsigned char c)
{
    const char *e = NULL;
    switch (c) {
        case '\0': e = "\\0"; break;
        case '\a': e = "\\a"; break;
        case '\b': e = "\\b"; break;
        case '\t': e = "\\t"; break;
        case '\n': e = "\\n"; break;
        case '\v': e = "\\v"; break;
        case '\f': e = "\\f"; break;
        case '\r': e = "\\r"; break;
        case ' ' : e = "  "; break;
    }
    if (e)                printf ("  %s", e);
    else if (isprint (c)) printf ("   %c", c);
    else                  printf (" %03o", c);
}

/* Render a single byte under the named-char format ('-t a'). */
static void
od_emit_a (unsigned char c)
{
    c &= 0x7f;               /* GNU -t a strips the high bit */
    if (c < 0x20)            printf (" %s", od_ascii_names[c]);
    else if (c == 0x20)      printf ("  sp");
    else if (c == 0x7f)      printf (" del");
    else                     printf ("   %c", c);
}

/* Read an element of `bytes` width starting at buf[i], little-endian or
   (--endian=big) big-endian; bytes past `n` are treated as zero (GNU pads
   short trailing groups with NUL). */
static unsigned long long
od_read_le (const unsigned char *buf, size_t i, size_t n, int bytes)
{
    unsigned long long v = 0;
    for (int k = 0; k < bytes; k++) {
        unsigned long long b = (i + (size_t) k < n) ? buf[i + (size_t) k] : 0ull;
        if (od_big_endian)
            v = (v << 8) | b;
        else
            v |= b << (8 * k);
    }
    return v;
}

static void
od_emit_int (unsigned long long v, char base, int bytes)
{
    switch (base) {
        case 'x':
            if (bytes == 1)      printf (" %02x", (unsigned) (v & 0xffULL));
            else if (bytes == 2) printf (" %04x", (unsigned) (v & 0xffffULL));
            else if (bytes == 4) printf (" %08llx", v & 0xffffffffULL);
            else                 printf (" %016llx", v);
            break;
        case 'o':
            if (bytes == 1)      printf (" %03o", (unsigned) (v & 0xffULL));
            else if (bytes == 2) printf (" %06o", (unsigned) (v & 0xffffULL));
            else if (bytes == 4) printf (" %011llo", v & 0xffffffffULL);
            else                 printf (" %022llo", v);
            break;
        case 'd': {
            long long sv;
            if (bytes == 1)      sv = (long long) (signed char) (v & 0xffULL);
            else if (bytes == 2) sv = (long long) (short) (v & 0xffffULL);
            else if (bytes == 4) sv = (long long) (int) (unsigned int) (v & 0xffffffffULL);
            else                 sv = (long long) v;
            if (bytes == 1)      printf (" %4lld", sv);
            else if (bytes == 2) printf (" %6lld", sv);
            else if (bytes == 4) printf (" %11lld", sv);
            else                 printf (" %20lld", sv);
            break;
        }
        case 'u':
        default:
            if (bytes == 1)      printf (" %3llu", v & 0xffULL);
            else if (bytes == 2) printf (" %5llu", v & 0xffffULL);
            else if (bytes == 4) printf (" %10llu", v & 0xffffffffULL);
            else                 printf (" %20llu", v);
            break;
    }
}

/* Render a float (bytes==4) or double (bytes==8) element. GNU emits the
   shortest decimal that round-trips (minimal %.*g precision), right-justified
   in a fixed column: 15 chars for f4, 24 chars for f8 (the leading separator
   space brings totals to 16 / 25). */
static void
od_emit_float (unsigned long long bits, int bytes)
{
    char buf[384];           /* %g of a double is at most ~310 chars */
    int width = (bytes == 4) ? 15 : 24;
    int maxprec = (bytes == 4) ? 9 : 17;
    double val;

    if (bytes == 4) {
        union { unsigned int u; float f; } cv;
        cv.u = (unsigned int) (bits & 0xffffffffULL);
        val = (double) cv.f;
    } else {
        union { unsigned long long u; double d; } cv;
        cv.u = bits;
        val = cv.d;
    }

    /* Shortest round-tripping representation. */
    int prec;
    for (prec = 1; prec < maxprec; prec++) {
        snprintf (buf, sizeof buf, "%.*g", prec, val);
        if (bytes == 4) {
            if ((float) strtod (buf, NULL) == (float) val) break;
        } else {
            if (strtod (buf, NULL) == val) break;
        }
    }
    printf (" %*.*g", width, prec, val);
}

/* Print one spec's line for `n` bytes of `buf`, padding each `groupbytes`-byte
   group on the left so columns align across stacked types (GNU layout). */
static void
od_emit_spec_line (const od_spec *s, const unsigned char *buf, size_t n,
                   int width, int groupbytes, int gwidth)
{
    if (s->kind == 'i' && s->base == 'x' && s->bytes == 1 &&
        groupbytes == 1 && gwidth == 3) {
        /* Hex bytes need no general integer formatting or column padding.
           Encode bounded chunks, including for arbitrarily wide -w lines. */
        static const char hex[] = "0123456789abcdef";
        char text[768];
        size_t used = 0;
        for (size_t i = 0; i < n; i++) {
            text[used++] = ' ';
            text[used++] = hex[buf[i] >> 4];
            text[used++] = hex[buf[i] & 15];
            if (used == sizeof text) {
                fwrite (text, 1, used, stdout);
                used = 0;
            }
        }
        if (s->zchars) {
            fwrite (text, 1, used, stdout);
            used = 0;
            od_emit_zchars (buf, n, (int) ((size_t) width - n) * 3);
        }
        text[used++] = '\n';
        fwrite (text, 1, used, stdout);
        return;
    }
    /* Each group of `groupbytes` bytes is a column of total width `gwidth`,
       shared by this spec's `elems_per_group` elements. GNU divides the
       column evenly; any remainder is added to the FIRST element's field. */
    int elems_per_group = groupbytes / s->bytes;
    int base_field = gwidth / elems_per_group;
    int extra = gwidth - base_field * elems_per_group;   /* goes on first elem */
    int printed = 0;
    for (int g = 0; g < width; g += groupbytes) {
        if ((size_t) g >= n) break;                  /* no data left */
        int e = 0;
        for (size_t i = (size_t) g;
             i < (size_t) (g + groupbytes) && i < n;
             i += (size_t) s->bytes, e++) {
            int target = base_field + (e == 0 ? extra : 0);
            int pad = target - s->field;             /* left-pad to align */
            printed += target;
            for (int p = 0; p < pad; p++) putchar (' ');
            if (s->kind == 'c')      od_emit_c (buf[i]);
            else if (s->kind == 'a') od_emit_a (buf[i]);
            else if (s->kind == 'f') od_emit_float (od_read_le (buf, i, n, s->bytes), s->bytes);
            else od_emit_int (od_read_le (buf, i, n, s->bytes), s->base, s->bytes);
        }
    }
    if (s->zchars)
        od_emit_zchars (buf, n, (width / groupbytes) * gwidth - printed);
    putchar ('\n');
}

/* All operands form one logical input stream. Open lazily so -N does not
   inspect later operands, and retain one stdin stream for repeated '-'. */
typedef struct {
    WORD_LIST *next;
    FILE *file, *input;
    const char *name;
    int implicit_stdin, status;
    long long remaining;             /* -1 until skipping is complete */
} od_input;

static FILE *od_open_stdin (void);

static int
od_next_input (od_input *in)
{
    if (in->file && in->file != in->input)
        fclose (in->file);
    in->file = NULL;
    while (in->next || in->implicit_stdin) {
        if (in->implicit_stdin) {
            in->name = "-";
            in->implicit_stdin = 0;
        } else {
            in->name = in->next->word->word;
            in->next = in->next->next;
        }
        if (!strcmp (in->name, "-")) {
            if (!in->input) in->input = od_open_stdin ();
            in->file = in->input;
        } else {
            in->file = fopen (in->name, "rb");
            if (!in->file) {
                int e = errno;
                fflush (stdout);   /* keep GNU's order on a shared stream */
                builtin_error ("%s: %s", in->name, strerror (e));
            }
        }
        if (in->file) return 1;
        in->status = EXECUTION_FAILURE;
    }
    return 0;
}

static size_t
od_read_input (od_input *in, unsigned char *buf, size_t want)
{
    size_t n = 0;
    if (in->remaining >= 0 && (unsigned long long) in->remaining < want)
        want = (size_t) in->remaining;
    while (n < want) {
        if (!in->file && !od_next_input (in)) break;
        size_t got = fread (buf + n, 1, want - n, in->file);
        n += got;
        if (n == want) break;
        if (ferror (in->file)) {
            builtin_error ("%s: %s", in->name, strerror (errno ? errno : EIO));
            in->status = EXECUTION_FAILURE;
        }
        if (!od_next_input (in)) break;
    }
    if (in->remaining >= 0) in->remaining -= (long long) n;
    return n;
}

static void
od_close_input (od_input *in)
{
    if (in->file && in->file != in->input) fclose (in->file);
    if (in->input) fclose (in->input);
}

static int
od_dump (od_input *in, od_opts *o, int *seen_block, unsigned char *prev,
         size_t *prev_n, int *dedup_active)
{
    /* Largest element width and the aligned group width across all specs. */
    int groupbytes = 1;
    for (int k = 0; k < o->nspecs; k++)
        if (o->specs[k].bytes > groupbytes) groupbytes = o->specs[k].bytes;
    int gwidth = 0;
    for (int k = 0; k < o->nspecs; k++) {
        int gw = (groupbytes / o->specs[k].bytes) * o->specs[k].field;
        if (gw > gwidth) gwidth = gw;
    }

    /* GNU requires the line width to be a multiple of the largest element
       size; round down (min one group) so columns stay aligned. */
    int width = o->width - (o->width % groupbytes);
    if (width < groupbytes) width = groupbytes;
    unsigned char *buf = (unsigned char *) malloc ((size_t) width);
    if (!buf) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }

    long long off = o->skip_bytes;
    long long emitted = 0;
    size_t n;
    while (1) {
        size_t want = (size_t) width;
        if (o->max_bytes >= 0) {
            long long remaining = o->max_bytes - emitted;
            if (remaining <= 0) break;
            if ((long long) want > remaining) want = (size_t) remaining;
        }
        n = od_read_input (in, buf, want);
        if (n == 0) break;

        /* '*' dedup: only full-width lines that match the previous full-width
           line collapse; partial trailing lines never dedup. */
        if (!o->no_dedup && *seen_block && *prev_n == (size_t) width
            && n == (size_t) width && memcmp (buf, prev, n) == 0) {
            if (!*dedup_active) { printf ("*\n"); *dedup_active = 1; }
            off += (long long) n;
            emitted += (long long) n;
            continue;
        }
        *dedup_active = 0;

        for (int k = 0; k < o->nspecs; k++) {
            if (k == 0) od_print_prefix (o, off);
            else {
                int aw = od_prefix_width (o);
                for (int p = 0; p < aw; p++) putchar (' ');
            }
            od_emit_spec_line (&o->specs[k], buf, n, width, groupbytes, gwidth);
        }

        memcpy (prev, buf, n);
        *prev_n = n;
        *seen_block = 1;
        off += (long long) n;
        emitted += (long long) n;
    }

    free (buf);
    /* Trailing address. */
    if (o->addr_radix != 'n' || o->has_label) {
        od_print_prefix (o, off);
        putchar ('\n');
    }
    return EXECUTION_SUCCESS;
}

static int
od_strings (FILE *f, int min)
{
    /* Print each contiguous run of printable bytes (including space)
       of length >= min, NUL-terminated. */
    unsigned char buf[8192];
    size_t n;
    int run = 0;
    char run_buf[4096];
    long long off = 0, run_start = 0;
    while ((n = fread (buf, 1, sizeof buf, f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            int p = (c >= 0x20 && c < 0x7f) || c == '\t';
            if (p) {
                if (run == 0) run_start = off + (long long) i;
                if (run < (int) sizeof run_buf - 1) run_buf[run++] = (char) c;
            } else {
                if (run >= min) {
                    run_buf[run] = '\0';
                    printf ("%07llo %s\n", run_start, run_buf);
                }
                run = 0;
            }
        }
        off += (long long) n;
    }
    if (run >= min) {
        run_buf[run] = '\0';
        printf ("%07llo %s\n", run_start, run_buf);
    }
    return EXECUTION_SUCCESS;
}

/* GNU `od -S N` / `--strings[=N]`: print each NUL-terminated run of >= N
   ASCII-graphic bytes (0x20..0x7e only; tab/newline/high-bit break the run
   and a run NOT terminated by NUL is discarded). The offset of the run's
   first byte is printed in the address radix (suppressed when 'n'). */
static int
od_strings_gnu (od_input *in, const od_opts *o, int min, long long start)
{
    unsigned char buf[8192];
    size_t n;
    int run = 0;
    static char run_buf[1 << 20];    /* GNU has no fixed cap; this is generous */
    long long off = start, run_start = 0;

    while ((n = od_read_input (in, buf, sizeof buf)) > 0) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (c >= 0x20 && c <= 0x7e) {           /* ASCII graphic + space */
                if (run == 0) run_start = off + (long long) i;
                if (run < (int) sizeof run_buf - 1) run_buf[run++] = (char) c;
            } else {
                if (c == '\0' && run >= min) {       /* only NUL closes a string */
                    if (run == 0) run_start = off + (long long) i;
                    run_buf[run] = '\0';
                    if (o->addr_radix == 'n' && !o->has_label)
                        printf ("%s\n", run_buf);
                    else {
                        od_print_prefix (o, run_start);
                        printf (" %s\n", run_buf);
                    }
                }
                run = 0;                             /* any non-graphic resets */
            }
        }
        off += (long long) n;
    }
    /* A run ending at EOF (no NUL terminator) is intentionally discarded. */
    return EXECUTION_SUCCESS;
}

static int
od_skip_file (FILE *f, long long n)
{
    unsigned char discard[4096];

    if (n <= 0)
        return 0;

    /* Skip from the current position, as GNU od does: stdin is shared with
       the shell, and a `read' before od leaves its offset past the start. */
    if (fseeko (f, (off_t)n, SEEK_CUR) == 0)
        return 0;

    if (ferror (f))
        clearerr (f);

    while (n > 0) {
        size_t want = sizeof discard;
        size_t got;

        if ((long long)want > n)
            want = (size_t)n;
        got = fread (discard, 1, want, f);
        if (got == 0)
            return -1;
        n -= (long long)got;
    }
    return 0;
}

/* The custom -s mode has no GNU oracle. Retain its per-file behavior;
   the concatenated reader below serves numeric dumps and GNU -S only. */
static int
od_custom_strings (WORD_LIST *list, od_opts *o)
{
    int rc = EXECUTION_SUCCESS;
    FILE *input = NULL;
    if (!list) {
        input = od_open_stdin ();
        if (!input) return EXECUTION_FAILURE;
        if (od_skip_file (input, o->skip_bytes) < 0) {
            builtin_error ("stdin: cannot skip %lld bytes", o->skip_bytes);
            rc = EXECUTION_FAILURE;
        } else
            rc = od_strings (input, o->strings_min);
        fclose (input);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f;
            if (!strcmp (p->word->word, "-")) {
                if (!input) input = od_open_stdin ();
                f = input;
            } else
                f = fopen (p->word->word, "rb");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (od_skip_file (f, o->skip_bytes) < 0) {
                builtin_error ("%s: cannot skip %lld bytes", p->word->word, o->skip_bytes);
                rc = EXECUTION_FAILURE;
            } else
                od_strings (f, o->strings_min);
            if (f != input) fclose (f);
        }
        if (input) fclose (input);
    }
    return rc;
}

static int
od_skip_input (od_input *in, long long n)
{
    unsigned char discard[4096];
    /* Reading also handles short and empty files without seeking past EOF
       or restarting the skip count at the next operand. */
    while (n > 0) {
        size_t want = sizeof discard;
        if ((long long) want > n) want = (size_t) n;
        size_t got = od_read_input (in, discard, want);
        if (got == 0) return -1;
        n -= (long long) got;
    }
    return 0;
}

/* Map a named-size letter (C/S/I/L) to a byte width for int types.
   Returns 0 if the char is not a size letter. */
static int
od_size_letter (char c)
{
    switch (c) {
        case 'C': return 1;   /* char  */
        case 'S': return 2;   /* short */
        case 'I': return 4;   /* int   */
        case 'L': return 8;   /* long  */
        default:  return 0;
    }
}

/* Parse a -t TYPE token. Accepts: c, a, {d,o,u,x} with an optional
   decimal size 1/2/4/8 or named-size letter C/S/I/L (default 4), and f
   with size 4/8 or named-size F(4)/D(8) (default 8). Multiple specs may be
   packed into one token (e.g. "x1c"); each may end in 'z' for the ">...<"
   printable column (e.g. "x1z"). Diagnostics are GNU od's. Returns 0 on
   success. */
static int
od_parse_type (const char *type, od_opts *o)
{
    const char *p = type;
    while (*p) {
        char base = *p++;
        int bytes;
        od_spec *added;
        if (base == 'c' || base == 'a') {
            added = od_add_spec (o, base, 0, 1);
        } else if (base == 'f' || base == 'x' || base == 'o' || base == 'd'
                   || base == 'u') {
            int is_float = base == 'f';
            if (isdigit ((unsigned char) *p)) {
                long n = 0;
                for (; isdigit ((unsigned char) *p); p++)
                    if (n < 100000) n = n * 10 + (*p - '0');
                bytes = (int) n;
                if (is_float ? (bytes != 4 && bytes != 8)
                             : (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)) {
                    builtin_error ("invalid type string '%s';", type);
                    fprintf (stderr, "this system doesn't provide a %ld-byte %s type\n",
                             n, is_float ? "floating point" : "integral");
                    return -1;
                }
            } else if (is_float && (*p == 'F' || *p == 'D')) {
                bytes = (*p == 'F') ? 4 : 8;
                p++;
            } else if (!is_float && od_size_letter (*p)) {
                bytes = od_size_letter (*p);
                p++;
            } else
                bytes = is_float ? 8 : 4;    /* GNU defaults: double, int */
            added = is_float ? od_add_spec (o, 'f', 0, bytes)
                             : od_add_spec (o, 'i', base, bytes);
        } else {
            builtin_error ("invalid character '%c' in type string '%s'", base, type);
            return -1;
        }
        if (*p == 'z') {
            if (added) added->zchars = 1;
            p++;
        }
    }
    return 0;
}

extern char *od_doc[];

/* A -j, -N or -S BYTES argument: decimal, 0x hex or leading-0 octal, with
   an optional multiplier suffix: b (512), K/k M/m G T P E Z Y R Q (powers
   of 1024), the same letter + B (powers of 1000) or + iB (1024). */
static int
od_parse_size (const char *s, const char *what, long long *out)
{
    static const char powers[] = "KMGTPEZYRQ";
    const char *p = s;
    unsigned long long v = 0, mult = 1;
    int digits = 0, over = 0;

    while (isspace ((unsigned char) *p)) p++;
    if (*p == '-') goto invalid;
    if (*p == '+') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && isxdigit ((unsigned char) p[2])) {
        for (p += 2; isxdigit ((unsigned char) *p); p++, digits++) {
            unsigned d = isdigit ((unsigned char) *p) ? (unsigned) (*p - '0')
                         : (unsigned) (tolower ((unsigned char) *p) - 'a' + 10);
            if (v > (ULLONG_MAX - d) / 16) over = 1; else v = v * 16 + d;
        }
    } else {
        unsigned radix = (*p == '0') ? 8 : 10;
        for (; *p >= '0' && *p <= (radix == 8 ? '7' : '9'); p++, digits++) {
            unsigned d = (unsigned) (*p - '0');
            if (v > (ULLONG_MAX - d) / radix) over = 1; else v = v * radix + d;
        }
    }
    if (!digits) goto invalid;
    if (*p) {
        if (p[0] == 'b' && !p[1])
            mult = 512;
        else {
            const char *q = (*p == 'k' || *p == 'm') ? strchr (powers, toupper ((unsigned char) *p))
                            : (*p ? strchr (powers, *p) : NULL);
            unsigned base = 1024;
            if (!q) goto badsuffix;
            if (!p[1]) ;
            else if (p[1] == 'B' && !p[2]) base = 1000;
            else if (p[1] == 'i' && p[2] == 'B' && !p[3]) ;
            else goto badsuffix;
            for (long e = (long) (q - powers) + 1; e > 0; e--) {
                if (mult > ULLONG_MAX / base) over = 1; else mult *= base;
            }
        }
    }
    if (over || (v && mult > (unsigned long long) LLONG_MAX / v)
        || v * mult > (unsigned long long) LLONG_MAX) {
        builtin_error ("%s argument '%s' too large", what, s);
        return -1;
    }
    *out = (long long) (v * mult);
    return 0;
invalid:
    builtin_error ("invalid %s argument '%s'", what, s);
    return -1;
badsuffix:
    builtin_error ("invalid suffix in %s argument '%s'", what, s);
    return -1;
}

/* -w BYTES: a plain decimal count. */
static int
od_parse_width (const char *s, const char *what, int *out)
{
    const char *p = s;
    long long v = 0;
    int digits = 0;
    while (isspace ((unsigned char) *p)) p++;
    if (*p == '+') p++;
    for (; isdigit ((unsigned char) *p); p++, digits++)
        if (v < INT_MAX) v = v * 10 + (*p - '0');
    if (!digits || (!*p && v == 0)) {
        builtin_error ("invalid %s argument '%s'", what, s);
        return -1;
    }
    if (*p) {
        builtin_error ("invalid suffix in %s argument '%s'", what, s);
        return -1;
    }
    if (v >= INT_MAX) {
        builtin_error ("%s argument '%s' too large", what, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

/* A traditional OFFSET or LABEL operand: [+]OCTAL or [+]0xHEX, then an
   optional b or B (times 512). Returns 1 and sets *OUT when S is one. */
static int
od_parse_offset (const char *s, long long *out)
{
    const char *p = s;
    unsigned long long v = 0;
    int digits = 0;
    if (*p == '+') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        for (p += 2; isxdigit ((unsigned char) *p); p++, digits++) {
            unsigned d = isdigit ((unsigned char) *p) ? (unsigned) (*p - '0')
                         : (unsigned) (tolower ((unsigned char) *p) - 'a' + 10);
            if (v > ((unsigned long long) LLONG_MAX - d) / 16) return 0;
            v = v * 16 + d;
        }
    } else {
        for (; *p >= '0' && *p <= '7'; p++, digits++) {
            unsigned d = (unsigned) (*p - '0');
            if (v > ((unsigned long long) LLONG_MAX - d) / 8) return 0;
            v = v * 8 + d;
        }
    }
    if (!digits) return 0;
    if (*p == 'b' || *p == 'B') {
        if (v > (unsigned long long) LLONG_MAX / 512) return 0;
        v *= 512;
        p++;
    }
    if (*p) return 0;
    *out = (long long) v;
    return 1;
}

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF across redirections. Repeated '-' operands share this stream.
   Never fclose stdin. */
static FILE *
od_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *in = fd < 0 ? NULL : fdopen (fd, "rb");
    if (!in) {
        int error = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (error));
    }
    return in;
}

/* GNU od's long options; abbreviations and --opt=VALUE / --opt VALUE are
   resolved by lon_normalize before the parser below sees the words. */
static const struct lon_option od_longopts[] = {
    { "address-radix",     LON_REQUIRED, "-A" },
    { "endian",            LON_REQUIRED, NULL },
    { "format",            LON_REQUIRED, "-t" },
    { "help",              LON_NONE,     NULL },
    { "output-duplicates", LON_NONE,     "-v" },
    { "read-bytes",        LON_REQUIRED, NULL },
    { "skip-bytes",        LON_REQUIRED, NULL },
    { "strings",           LON_OPTIONAL, NULL },
    { "traditional",       LON_NONE,     NULL },
    { "version",           LON_NONE,     NULL },
    { "width",             LON_OPTIONAL, NULL },
    { NULL, 0, NULL }
};

/* --endian=WORD: an exact word or an unambiguous prefix of one. */
static int
od_parse_endian (const char *v)
{
    static const char *const names[] = { "little", "big" };
    size_t len = strlen (v);
    int match = -1, count = 0;
    for (int i = 0; i < 2; i++) {
        if (!strcmp (v, names[i])) { match = i; count = 1; break; }
        if (!strncmp (v, names[i], len)) { match = i; count++; }
    }
    if (count == 1) {
        od_big_endian = (match == 1);
        return 0;
    }
    builtin_error ("%s argument '%s' for '--endian'",
                   count > 1 ? "ambiguous" : "invalid", v);
    fputs ("Valid arguments are:\n  - 'little'\n  - 'big'\n", stderr);
    lon_try_help ();
    return -1;
}

/* GNU's compatibility-mode operand error. */
static int
od_extra_operand (const char *w)
{
    builtin_error ("extra operand '%s'", w);
    builtin_error ("compatibility mode supports at most one file");
    lon_try_help ();
    return EXECUTION_FAILURE;
}

int
od_builtin (WORD_LIST *list)
{
    od_opts o = { .addr_radix = 'o', .nspecs = 0, .width = OD_DEFAULT_WIDTH,
                  .no_dedup = 0, .strings_min = 0, .gnu_strings_min = -1,
                  .skip_bytes = 0, .max_bytes = -1, .has_label = 0, .label = 0 };
    WORD_LIST *norm = NULL, *files = NULL, *l;
    int own_files = 0, traditional = 0, modern = 0, rc = EXECUTION_SUCCESS;

    od_big_endian = 0;
    if (lon_normalize (list, od_longopts, "A:j:N:S:t:w::", 1, &norm) < 0)
        return EXECUTION_FAILURE;

    for (l = norm; l; l = l->next) {
        const char *w = l->word->word;
        if (w[0] != '-' || w[1] == '\0')
            break;
        if (!strcmp (w, "--")) { l = l->next; break; }
        if (w[1] == '-') {
            /* Only the long-only options remain after normalization. */
            if (!strcmp (w, "--help")) {
                for (char **dp = od_doc; *dp; dp++) puts (*dp);
                goto out;
            }
            if (!strcmp (w, "--version")) {
                puts ("od (bash-os) 0.1.5");
                goto out;
            }
            if (!strcmp (w, "--traditional")) { traditional = 1; continue; }
            if (!strncmp (w, "--endian=", 9)) {
                if (od_parse_endian (w + 9) < 0) { rc = EXECUTION_FAILURE; goto out; }
                continue;
            }
            if (!strcmp (w, "--strings")) { o.gnu_strings_min = 3; modern = 1; continue; }
            /* These keep their long names for GNU's diagnostics. */
            if (!strncmp (w, "--read-bytes=", 13) || !strncmp (w, "--skip-bytes=", 13)) {
                long long n;
                char what[13];
                memcpy (what, w, 12);
                what[12] = '\0';
                if (od_parse_size (w + 13, what, &n) < 0) { rc = EXECUTION_FAILURE; goto out; }
                if (w[2] == 'r') o.max_bytes = n; else o.skip_bytes = n;
                modern = 1;
                continue;
            }
            if (!strcmp (w, "--width")) { o.width = 32; modern = 1; continue; }
            if (!strncmp (w, "--width=", 8)) {
                if (od_parse_width (w + 8, "--width", &o.width) < 0) { rc = EXECUTION_FAILURE; goto out; }
                modern = 1;
                continue;
            }
            if (!strncmp (w, "--strings=", 10)) {
                long long n;
                if (od_parse_size (w + 10, "--strings", &n) < 0) { rc = EXECUTION_FAILURE; goto out; }
                o.gnu_strings_min = n > INT_MAX ? INT_MAX : (int) n;
                modern = 1;
                continue;
            }
            lon_error ("unrecognized option '%s'", w);
            lon_try_help ();
            rc = EXECUTION_FAILURE;
            goto out;
        }
        /* A cluster of short options; one that takes an argument ends it. */
        for (const char *c = w + 1; *c; c++) {
            const char *arg;
            long long n;
            switch (*c) {
                case 'a': od_add_spec (&o, 'a', 0, 1);   continue;
                case 'b': od_add_spec (&o, 'i', 'o', 1); continue;
                case 'c': od_add_spec (&o, 'c', 0, 1);   continue;
                case 'd': od_add_spec (&o, 'i', 'u', 2); continue;
                case 'f': od_add_spec (&o, 'f', 0, 4);   continue;
                case 'i': od_add_spec (&o, 'i', 'd', 4); continue;
                case 'l': od_add_spec (&o, 'i', 'd', 8); continue;
                case 'o': od_add_spec (&o, 'i', 'o', 2); continue;
                case 'x':
                case 'h': od_add_spec (&o, 'i', 'x', 2); continue;
                /* Undocumented GNU legacy selectors. */
                case 'B': od_add_spec (&o, 'i', 'o', 2); continue;
                case 'D': od_add_spec (&o, 'i', 'u', 4); continue;
                case 'e':
                case 'F': od_add_spec (&o, 'f', 0, 8);   continue;
                case 'H':
                case 'X': od_add_spec (&o, 'i', 'x', 4); continue;
                case 'I':
                case 'L': od_add_spec (&o, 'i', 'd', 8); continue;
                case 'O': od_add_spec (&o, 'i', 'o', 4); continue;
                case 'v': o.no_dedup = 1; modern = 1;    continue;
                case 's':
                    /* bash-os strings mode: -s, -sN or -s N (not GNU's -s). */
                    o.strings_min = 3;
                    if (isdigit ((unsigned char) c[1])) {
                        o.strings_min = atoi (c + 1);
                    } else if (c[1] == '\0' && l->next
                               && isdigit ((unsigned char) l->next->word->word[0])) {
                        l = l->next;
                        o.strings_min = atoi (l->word->word);
                    } else
                        continue;
                    if (o.strings_min < 1) o.strings_min = 3;
                    break;
                case 'w':
                    modern = 1;
                    if (c[1] == '\0') o.width = 32;    /* bare -w => 32 */
                    else if (od_parse_width (c + 1, "-w", &o.width) < 0) {
                        rc = EXECUTION_FAILURE;
                        goto out;
                    }
                    break;
                case 'A': case 'j': case 'N': case 'S': case 't':
                    modern = 1;
                    if (c[1]) arg = c + 1;
                    else if (l->next) { l = l->next; arg = l->word->word; }
                    else {
                        lon_error ("option requires an argument -- '%c'", *c);
                        lon_try_help ();
                        rc = EXECUTION_FAILURE;
                        goto out;
                    }
                    if (*c == 'A') {
                        if (!arg[0] || !strchr ("doxn", arg[0])) {
                            builtin_error ("invalid output address radix '%c'; it must be one character from [doxn]",
                                           arg[0] ? arg[0] : ' ');
                            rc = EXECUTION_FAILURE;
                            goto out;
                        }
                        o.addr_radix = arg[0];
                    } else if (*c == 't') {
                        if (od_parse_type (arg, &o) < 0) { rc = EXECUTION_FAILURE; goto out; }
                    } else {
                        char what[3] = { '-', *c, '\0' };
                        if (od_parse_size (arg, what, &n) < 0) { rc = EXECUTION_FAILURE; goto out; }
                        if (*c == 'j') o.skip_bytes = n;
                        else if (*c == 'N') o.max_bytes = n;
                        else o.gnu_strings_min = n > INT_MAX ? INT_MAX : (int) n;
                    }
                    break;
                default:
                    lon_error ("invalid option -- '%c'", *c);
                    lon_try_help ();
                    rc = EXECUTION_FAILURE;
                    goto out;
            }
            break;
        }
    }

    /* Operands: FILE... or the traditional [FILE] [[+]OFFSET [[+]LABEL]]. */
    {
        const char *op[4] = { NULL, NULL, NULL, NULL };
        int nops = 0;
        long long a, b;
        for (WORD_LIST *p = l; p; p = p->next, nops++)
            if (nops < 4) op[nops] = p->word->word;
        files = l;
        if (traditional) {
            if (nops == 1) {
                if (od_parse_offset (op[0], &a)) { o.skip_bytes = a; files = NULL; }
            } else if (nops == 2) {
                if (!od_parse_offset (op[1], &b)) { rc = od_extra_operand (op[1]); goto out; }
                if (od_parse_offset (op[0], &a)) {
                    o.skip_bytes = a; o.label = b; o.has_label = 1; files = NULL;
                } else {
                    o.skip_bytes = b; files = NULL; own_files = 1;
                }
            } else if (nops == 3) {
                if (!od_parse_offset (op[1], &a) || !od_parse_offset (op[2], &b)) {
                    rc = od_extra_operand (op[1]);
                    goto out;
                }
                o.skip_bytes = a; o.label = b; o.has_label = 1; files = NULL; own_files = 1;
            } else if (nops > 3) {
                rc = od_extra_operand (op[1]);
                goto out;
            }
        } else if (!modern) {
            /* POSIX XSI form, recognized only with the traditional
               format selectors: `od FILE [+]OFFSET` or `od +OFFSET`. */
            if (nops == 1 && op[0][0] == '+' && od_parse_offset (op[0], &a)) {
                o.skip_bytes = a; files = NULL;
            } else if (nops == 2 && (op[1][0] == '+' || isdigit ((unsigned char) op[1][0]))
                       && od_parse_offset (op[1], &a)) {
                o.skip_bytes = a; files = NULL; own_files = 1;
            }
        }
        if (own_files)
            files = make_word_list (make_word (op[0]), (WORD_LIST *) NULL);
    }

    /* If no display flag set and not in either strings mode, default to -t o2. */
    if (!o.strings_min && o.gnu_strings_min < 0 && o.nspecs == 0)
        od_add_spec (&o, 'i', 'o', 2);

    /* The width must be a multiple of the widest element; GNU warns and
       falls back to one element per line. */
    int buffer_width = o.width;
    if (o.nspecs && !o.strings_min && o.gnu_strings_min < 0) {
        int gb = 1;
        for (int k = 0; k < o.nspecs; k++)
            if (o.specs[k].bytes > gb) gb = o.specs[k].bytes;
        if (o.width % gb) {
            builtin_error ("warning: invalid width %d; using %d instead", o.width, gb);
            o.width = buffer_width = gb;
        }
    }

    if (o.strings_min && o.gnu_strings_min < 0)
        rc = od_custom_strings (files, &o);
    else {
        od_input in = { .next = files, .implicit_stdin = files == NULL,
                        .status = EXECUTION_SUCCESS, .remaining = -1 };
        if (!od_next_input (&in)) {
            od_close_input (&in);
            rc = EXECUTION_FAILURE;
            goto out;
        }
        if (od_skip_input (&in, o.skip_bytes) < 0) {
            builtin_error ("cannot skip past end of combined input");
            rc = EXECUTION_FAILURE;
        } else {
            in.remaining = o.max_bytes;
            if (o.gnu_strings_min >= 0)
                rc = od_strings_gnu (&in, &o, o.gnu_strings_min, o.skip_bytes);
            else {
                int seen = 0, dactive = 0; size_t pn = 0;
                unsigned char *prev = (unsigned char *) malloc ((size_t) buffer_width);
                if (!prev) {
                    builtin_error ("out of memory");
                    rc = EXECUTION_FAILURE;
                } else {
                    rc = od_dump (&in, &o, &seen, prev, &pn, &dactive);
                    free (prev);
                }
            }
        }
        if (in.status != EXECUTION_SUCCESS) rc = in.status;
        od_close_input (&in);
    }

out:
    if (own_files && files)
        dispose_words (files);
    if (norm)
        dispose_words (norm);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        rc = EXECUTION_FAILURE;
    }
    return rc;
}

char *od_doc[] = {
    "Octal / hex / decimal / char dump (POSIX and GNU od).",
    "",
    "    od [OPTION]... [FILE]...",
    "    od [-abcdfhilosxBDeFHILOX]... [FILE] [[+]OFFSET[b]]",
    "    od --traditional [OPTION]... [FILE] [[+]OFFSET[b] [[+]LABEL[b]]]",
    "",
    "    -A, --address-radix=RADIX  address radix: x (hex), o (octal, default),",
    "               d (decimal), n (no address field)",
    "        --endian=big|little    byte order of multi-byte elements",
    "    -j, --skip-bytes=BYTES     skip BYTES input bytes first",
    "    -N, --read-bytes=BYTES     dump at most BYTES input bytes",
    "    -S BYTES, --strings[=BYTES]  print NUL-terminated runs of at least",
    "               BYTES (3) printable characters (GNU strings mode)",
    "    -t, --format=TYPE  a, c, [doux] with size 1/2/4/8 or C/S/I/L (e.g. x4,",
    "               dL), or f with size 4/8 or F/D (IEEE float/double);",
    "               a trailing z (e.g. x1z) appends each line's printable",
    "               bytes as >...<, non-printables as '.'",
    "    -v, --output-duplicates  do not collapse repeated lines into '*'",
    "    -w[BYTES], --width[=BYTES]  bytes per output line (default 16;",
    "               32 when BYTES is omitted)",
    "        --traditional  accept the OFFSET and LABEL operands above",
    "        --help, --version",
    "",
    "    Traditional selectors: -a (= -t a), -b (o1), -c (c), -d (u2),",
    "    -f (fF), -i (dI), -l (dL), -o (o2), -x and -h (x2), and GNU's",
    "    -B (o2), -D (u4), -e and -F (fD), -H and -X (x4), -I and -L (dL),",
    "    -O (o4).",
    "    -s [N]     bash-os strings mode: print printable-byte runs of",
    "               length >= N (default 3); GNU's -s (= -t d2) is not provided",
    "",
    "BYTES is decimal, 0x hex or 0-prefixed octal, with an optional suffix",
    "b (512), K/k, M/m, G, T, P, E, Z, Y, R, Q (powers of 1024), KB, MB, ...",
    "(powers of 1000) or KiB, MiB, .... OFFSET and LABEL are octal, or hex",
    "with 0x; a b suffix multiplies by 512. The OFFSET form works without",
    "--traditional only with the traditional selectors: `od FILE [+]OFFSET`",
    "(two operands) or `od +OFFSET`. Long options may be abbreviated.",
    "",
    "Reads stdin when no FILE given (or `-` in the list); operands form one",
    "input stream. Combinable modes (`-cx`, `-t o2 -t x2`) print each on",
    "stacked lines under the same address, with per-type columns aligned.",
    (char *)NULL
};

struct builtin bashod_struct = {
    "bashod",
    od_builtin,
    BUILTIN_ENABLED,
    od_doc,
    "bashod [-abcdfhilosxBDeFHILOXv] [-A RADIX] [-j BYTES] [-N BYTES] [-S BYTES] [-t TYPE] [-w[BYTES]] [--endian=big|little] [--traditional] [FILE...] [[+]OFFSET [[+]LABEL]]",
    0
};
