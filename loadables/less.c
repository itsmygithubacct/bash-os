/* SPDX-License-Identifier: MIT */
/* less.c - less-shaped pager as a bash builtin.
 *
 * This is not a wholesale import of upstream less. It borrows the
 * behavioral contract from less(1) and keeps a small implementation that
 * fits bash-os' compiled-loadable model:
 *
 *   less [-F] [-N] [-S] [-n LINES] [FILE...]
 *   less [-eEFiIMmNsSRrX] [-p PATTERN] [-x N] [-z N] [+CMD] [FILE...]
 *
 * Options come from LESS first, then the arguments, in clusters (-FRX)
 * or long form, as less(1) reads them; unknown ones are reported and
 * ignored, as less does. When standard output is not a terminal, input
 * is copied unchanged whatever the options (less acts like cat there). Interactive mode reads files/stdin into a line
 * vector, renders one screen at a time, and supports the less muscle
 * memory most scripts/users expect first: space/f/^F, b/^B, j/down,
 * k/up, g, G, /PATTERN, n, N, q.
 *
 * Upstream less source is kept for study under research/refs/less.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "loadables.h"
#include "unwind_prot.h"

/* Shared CSI/SS3 key decoder (arrows, PgUp/PgDn, Home/End, Delete).
 * The inline ESC-[ parser this file used to ship was replaced
 * 2026-05-18 by a single bl_read_key() call so less/more/vi/nano/top
 * share one decoder. See scripts/loadables/_bl_key/bl_key.h. */
#include "_bl_key_bl_key.h"

typedef struct {
    char **v;
    size_t *len;    /* byte length of each line (excludes our NUL terminator);
                       tracked so binary content with embedded NULs round-trips
                       byte-exact instead of being truncated by strlen(). */
    size_t n;
    size_t cap;
} bl_lines;

static void
bl_lines_free (bl_lines *ls)
{
    if (!ls) return;
    for (size_t i = 0; i < ls->n; i++)
        free (ls->v[i]);
    free (ls->v);
    free (ls->len);
    memset (ls, 0, sizeof *ls);
}

static int
bl_lines_push (bl_lines *ls, const char *s, size_t n)
{
    if (ls->n == ls->cap)
    {
        size_t nc = ls->cap ? ls->cap * 2 : 128;
        char **nv = realloc (ls->v, nc * sizeof *nv);
        if (!nv) return -1;
        ls->v = nv;
        size_t *nl = realloc (ls->len, nc * sizeof *nl);
        if (!nl) return -1;
        ls->len = nl;
        ls->cap = nc;
    }
    char *copy = malloc (n + 1);
    if (!copy) return -1;
    memcpy (copy, s, n);
    copy[n] = '\0';
    ls->v[ls->n] = copy;
    ls->len[ls->n] = n;
    ls->n++;
    return 0;
}

static int
bl_read_stream (FILE *f, bl_lines *ls)
{
    /* Clear the EOF flag a previous invocation left on a persistent stream:
       a builtin does not fork, so stdin's FILE is reused across calls. */
    clearerr (f);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline (&line, &cap, f)) != -1)
    {
        if (bl_lines_push (ls, line, (size_t) n) < 0)
        {
            free (line);
            return -1;
        }
    }
    free (line);
    return ferror (f) ? -1 : 0;
}

static int
bl_copy_stream (FILE *f)
{
    /* Redirected plain output needs neither a line index nor one allocation
       per line. Bound memory use independently of the length of the input. */
    unsigned char buf[65536];
    clearerr (f);
    for (;;) {
        size_t n = fread (buf, 1, sizeof buf, f);
        int read_errno = errno;
        QUIT;
        if (n && fwrite (buf, 1, n, stdout) != n) return -1;
        if (ferror (f)) {
            if (read_errno == EINTR) { clearerr (f); continue; }
            errno = read_errno;
            return -1;
        }
        if (feof (f)) return 0;
    }
}

static void
bl_close_input (void *arg)
{
    fclose ((FILE *) arg);
}

static int
bl_read_file_operand (const char *path, bl_lines *ls)
{
    FILE *f = !strcmp (path, "-") ? stdin : fopen (path, "r");
    if (!f)
    {
        /* less(1)'s nonterminal copy path writes file-open diagnostics
           into the output stream and continues with a successful status.
           An actual failure writing that diagnostic still fails. */
        if (!ls)
            return fprintf (stdout, "%s: %s\n", path, strerror (errno)) < 0 ? -1 : 0;
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    /* QUIT in the copy loop can unwind past this caller. Borrowed stdin
       remains the shell's responsibility; only owned operands are closed. */
    if (f != stdin) {
        begin_unwind_frame ("less input");
        add_unwind_protect (bl_close_input, f);
    }
    int rc = ls ? bl_read_stream (f, ls) : bl_copy_stream (f);
    int read_errno = errno;
    if (f != stdin) run_unwind_frame ("less input");
    if (rc < 0)
        builtin_error ("%s: %s", path, strerror (read_errno));
    return rc;
}

static int
bl_term_rows (void)
{
    struct winsize ws;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 2)
        return (int) ws.ws_row - 1;
    return 23;
}

static volatile sig_atomic_t bl_resize_seen = 0;

static void
bl_sigwinch (int sig)
{
    (void) sig;
    bl_resize_seen = 1;
}

static void
bl_install_sigwinch (struct sigaction *oldsa, int *installed)
{
    struct sigaction sa;

    *installed = 0;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = bl_sigwinch;
    sigemptyset (&sa.sa_mask);
    if (sigaction (SIGWINCH, &sa, oldsa) == 0)
        *installed = 1;
}

static void
bl_restore_sigwinch (const struct sigaction *oldsa, int installed)
{
    if (installed)
        sigaction (SIGWINCH, oldsa, NULL);
}

/* Return non-zero when every byte of s is an ASCII digit. Mirrors
   more's bm_str_is_num for G02 option-parity: `-n` rejects
   non-numeric and signed arguments instead of silently falling back
   to the default via atoi() returning 0. */
static int
bl_str_is_num (const char *s)
{
    if (!s || !*s) return 0;
    while (*s) { if (!isdigit ((unsigned char) *s)) return 0; s++; }
    return 1;
}

static void
bl_write (int fd, const char *s)
{
    size_t n = strlen (s);
    while (n)
    {
        ssize_t w = write (fd, s, n);
        if (w < 0)
        {
            if (errno == EINTR) continue;
            return;
        }
        s += w;
        n -= (size_t) w;
    }
}

/* Options, from LESS and then the command line, as less(1) reads them. */
typedef struct {
    int rows, chop, numbers, quit_if_one;
    int eof_quit;          /* 1 for -e (second end of file), 2 for -E (first) */
    int icase;             /* 1 for -i (unless the pattern has capitals), 2 for -I */
    int squeeze;           /* -s */
    int tabs;              /* -x N; 0 leaves tabs to the terminal */
    int prompt;            /* 0, 'm' or 'M' */
    int start_end;         /* +G */
    long start_line;       /* +N, +Ng: 1-based, 0 for none */
    char *pattern;         /* -p PAT, +/PAT */
} bl_less_opts;

static void
bl_render_line (const char *line, size_t linelen, const bl_less_opts *o, size_t lineno, int cols)
{
    int prefix = 0;
    if (o->numbers)
        prefix = printf ("%7zu ", lineno + 1);
    int room = cols > prefix ? cols - prefix : cols;
    size_t len = linelen;
    if (len && line[len - 1] == '\n') len--;
    if (o->tabs > 0 && memchr (line, '\t', len))
    {
        /* -x N: tab stops every N columns. */
        int col = 0;
        for (size_t i = 0; i < len; i++)
        {
            if (o->chop && room > 0 && col >= room) break;
            if (line[i] == '\t')
            {
                do { putchar (' '); col++; } while (col % o->tabs && !(o->chop && room > 0 && col >= room));
                continue;
            }
            putchar ((unsigned char) line[i]);
            col++;
        }
    }
    else if (o->chop && room > 0 && len > (size_t) room)
        fwrite (line, 1, (size_t) room, stdout);
    else
        fwrite (line, 1, len, stdout);
    putchar ('\n');
}

/* Search with -i/-I: -i ignores case only for a pattern in lower case. */
static const char *
bl_search_line (const char *line, const char *pat, int icase)
{
    int fold = icase == 2;
    if (icase == 1)
    {
        fold = 1;
        for (const char *p = pat; *p; p++)
            if (isupper ((unsigned char) *p)) { fold = 0; break; }
    }
    if (!fold) return strstr (line, pat);
    size_t n = strlen (pat);
    for (const char *s = line; *s; s++)
    {
        size_t i = 0;
        while (i < n && s[i] && tolower ((unsigned char) s[i]) == tolower ((unsigned char) pat[i])) i++;
        if (i == n) return s;
    }
    return NULL;
}

static int
bl_find (const bl_lines *ls, const char *pat, size_t from, int reverse, size_t *hit, int icase)
{
    if (!pat || !*pat || ls->n == 0) return 0;
    if (reverse)
    {
        size_t i = from >= ls->n ? ls->n - 1 : from;
        for (;;)
        {
            if (bl_search_line (ls->v[i], pat, icase)) { *hit = i; return 1; }
            if (i == 0) break;
            i--;
        }
        return 0;
    }
    for (size_t i = from; i < ls->n; i++)
        if (bl_search_line (ls->v[i], pat, icase)) { *hit = i; return 1; }
    return 0;
}

static int
bl_prompt_line (int tty, const char *label, char *buf, size_t bufsz)
{
    if (bufsz == 0) return -1;
    bl_write (tty, label);
    size_t n = 0;
    for (;;)
    {
        unsigned char c;
        ssize_t r = read (tty, &c, 1);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0 || c == '\n' || c == '\r') break;
        if (c == 0x7f || c == 0x08)
        {
            if (n) { n--; bl_write (tty, "\b \b"); }
            continue;
        }
        if (!isprint (c) || n + 1 >= bufsz) continue;
        buf[n++] = (char) c;
        write (tty, &c, 1);
    }
    buf[n] = '\0';
    bl_write (tty, "\r\n");
    return 0;
}

/* The prompt: ":" (the file name first), -m adds the percentage, -M the
   line range and line count too, and "(END)" at the end of the input. */
static void
bl_show_prompt (const bl_lines *ls, size_t top, int rows, const bl_less_opts *o,
                const char *name, int first_prompt)
{
    size_t last = top + (size_t) rows < ls->n ? top + (size_t) rows : ls->n;
    int at_end = ls->n - top <= (size_t) rows;
    char buf[512];
    if (!o->prompt)
    {
        bl_write (STDERR_FILENO, at_end ? "(END)" : first_prompt && name ? name : ":");
        return;
    }
    const char *shown = name ? name : "";
    unsigned pct = ls->n ? (unsigned) (last * 100 / ls->n) : 100;
    if (o->prompt == 'M')
        snprintf (buf, sizeof buf, "%s%slines %zu-%zu/%zu %s", shown, *shown ? " " : "",
                  top + 1, last, ls->n, at_end ? "(END)" : "");
    else
        snprintf (buf, sizeof buf, "%s%s", shown, *shown ? " " : "");
    bl_write (STDERR_FILENO, buf);
    if (!at_end || o->prompt == 'm')
    {
        if (at_end) bl_write (STDERR_FILENO, "(END)");
        else { snprintf (buf, sizeof buf, "%u%%", pct); bl_write (STDERR_FILENO, buf); }
    }
}

static int
bl_interactive (bl_lines *ls, bl_less_opts *o, const char *name)
{
    int rows = o->rows;
    if (ls->n == 0) return EXECUTION_SUCCESS;
    if (o->squeeze)
    {
        /* -s: runs of blank lines show as one. */
        size_t w = 0;
        for (size_t i = 0; i < ls->n; i++)
        {
            int blank = ls->len[i] == 0 || (ls->len[i] == 1 && ls->v[i][0] == '\n');
            int prev_blank = w && (ls->len[w - 1] == 0 || (ls->len[w - 1] == 1 && ls->v[w - 1][0] == '\n'));
            if (blank && prev_blank) { free (ls->v[i]); continue; }
            ls->v[w] = ls->v[i];
            ls->len[w] = ls->len[i];
            w++;
        }
        ls->n = w;
    }
    if (o->quit_if_one && ls->n <= (size_t) rows)
    {
        for (size_t i = 0; i < ls->n; i++)
            bl_render_line (ls->v[i], ls->len[i], o, i, 80);
        return EXECUTION_SUCCESS;
    }

    int tty = open ("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty < 0)
    {
        for (size_t i = 0; i < ls->n; i++)
            fwrite (ls->v[i], 1, ls->len[i], stdout);
        return EXECUTION_SUCCESS;
    }

    struct termios old, raw;
    int have_termios = (tcgetattr (tty, &old) == 0);
    if (have_termios)
    {
        raw = old;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr (tty, TCSANOW, &raw);
    }

    size_t top = 0;
    char last_pat[128] = "";
    int last_reverse = 0;
    /* The starting position: +G, +N, then -p/+/ PATTERN. */
    if (o->start_end)
        top = ls->n > (size_t) rows ? ls->n - (size_t) rows : 0;
    else if (o->start_line > 0)
        top = (size_t) o->start_line <= ls->n ? (size_t) o->start_line - 1 : ls->n - 1;
    if (o->pattern && o->pattern[0])
    {
        strncpy (last_pat, o->pattern, sizeof last_pat - 1);
        last_pat[sizeof last_pat - 1] = '\0';
        size_t hit;
        if (bl_find (ls, last_pat, top, 0, &hit, o->icase))
            top = hit;
    }
    int cols = 80;
    struct winsize ws;
    struct sigaction old_winch;
    int have_winch = 0;
    int first_prompt = 1;
    int ends_seen = 0;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        cols = (int) ws.ws_col;

    bl_resize_seen = 0;
    bl_install_sigwinch (&old_winch, &have_winch);
    bl_key_reset ();

    for (;;)
    {
        if (bl_resize_seen)
        {
            int new_rows = bl_term_rows ();
            rows = new_rows > 0 ? new_rows : rows;
            if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
                cols = (int) ws.ws_col;
            if (top >= ls->n)
                top = ls->n - 1;
            bl_resize_seen = 0;
        }
        bl_write (STDOUT_FILENO, "\033[H\033[J");
        for (int r = 0; r < rows && top + (size_t) r < ls->n; r++)
            bl_render_line (ls->v[top + (size_t) r], ls->len[top + (size_t) r],
                            o, top + (size_t) r, cols);
        /* The prompt sits below the page: on the terminal's last row for a
           full-screen page, even when fewer lines remain, and directly under
           a shorter page set with -n. Flush the stdio content before writing
           control sequences through write(2). */
        fflush (stdout);
        int at_end = ls->n - top <= (size_t) rows;
        /* -E leaves at the first end of the input, -e at the second. */
        if (at_end && o->eof_quit == 2) break;
        int prompt_row = 24;
        if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
            prompt_row = (int) ws.ws_row;
        if (rows + 1 < prompt_row)
            prompt_row = rows + 1;
        char position[32];
        snprintf (position, sizeof position, "\033[%d;1H\033[K\033[7m", prompt_row);
        bl_write (STDERR_FILENO, position);
        bl_show_prompt (ls, top, rows, o, name, first_prompt);
        bl_write (STDERR_FILENO, "\033[m");
        first_prompt = 0;

        /* One keystroke. bl_read_key() blocks on the first byte and
         * (when it sees ESC) assembles the CSI/SS3 follow-up burst
         * with its own grace-window timeouts. Plain ASCII keys come
         * back as their byte value; specials come back as BL_KEY_*
         * constants ≥ 0x100, which we fold into the legacy ASCII
         * dispatch below so the rest of the loop is unchanged. */
        /* The shared decoder retries EINTR internally. Wait here first so a
           WINCH can trigger a redraw without requiring a keypress. A bounded
           timeout closes the race between checking the flag and entering poll. */
        int input_error = 0;
        while (!bl_resize_seen && !bl_key_pending ())
        {
            struct pollfd pfd = { .fd = tty, .events = POLLIN, .revents = 0 };
            int ready = poll (&pfd, 1, 100);
            if (ready > 0) break;
            if (ready < 0 && errno != EINTR) { input_error = 1; break; }
        }
        if (bl_resize_seen)
        {
            bl_write (STDERR_FILENO, "\r\033[K");
            continue;
        }
        int c = input_error ? BL_KEY_NONE : bl_read_key (tty);
        bl_write (STDERR_FILENO, "\r\033[K");
        if (c == BL_KEY_NONE) break;

        switch (c)
        {
        case BL_KEY_UP:    c = 'k'; break;
        case BL_KEY_DOWN:  c = 'j'; break;
        case BL_KEY_HOME:  c = 'g'; break;
        case BL_KEY_END:   c = 'G'; break;
        case BL_KEY_PGUP:  c = 'b'; break;
        case BL_KEY_PGDN:  c = ' '; break;
        case BL_KEY_LEFT:
        case BL_KEY_RIGHT:
        case BL_KEY_INS:
        case BL_KEY_DEL:
        case BL_KEY_ESC:
            continue;  /* ignore */
        default: break; /* plain ASCII byte — fall through */
        }

        if (c == 'q' || c == 'Q') break;
        int forward = c == ' ' || c == 'f' || c == 0x06 || c == 'j' || c == '\n' || c == '\r';
        if (forward && at_end && o->eof_quit == 1 && ++ends_seen >= 1) break;
        if (c == ' ' || c == 'f' || c == 0x06)
        {
            top = top + (size_t) rows < ls->n ? top + (size_t) rows : ls->n - 1;
        }
        else if (c == 'b' || c == 0x02)
        {
            top = top > (size_t) rows ? top - (size_t) rows : 0;
        }
        else if (c == 'j' || c == '\n' || c == '\r')
        {
            if (top + 1 < ls->n) top++;
        }
        else if (c == 'k')
        {
            if (top > 0) top--;
        }
        else if (c == 'g' || c == '<')
        {
            top = 0;
        }
        else if (c == 'G' || c == '>')
        {
            top = ls->n > (size_t) rows ? ls->n - (size_t) rows : 0;
        }
        else if (c == '/' || c == '?')
        {
            if (have_termios) tcsetattr (tty, TCSANOW, &old);
            char pat[128];
            if (bl_prompt_line (tty, c == '/' ? "/" : "?", pat, sizeof pat) == 0 && pat[0])
            {
                strncpy (last_pat, pat, sizeof last_pat - 1);
                last_pat[sizeof last_pat - 1] = '\0';
                last_reverse = (c == '?');
                size_t hit = top;
                size_t start = last_reverse ? (top ? top - 1 : 0) : top + 1;
                if (bl_find (ls, last_pat, start, last_reverse, &hit, o->icase))
                    top = hit;
            }
            if (have_termios) tcsetattr (tty, TCSANOW, &raw);
        }
        else if ((c == 'n' || c == 'N') && last_pat[0])
        {
            int rev = (c == 'N') ? !last_reverse : last_reverse;
            size_t hit = top;
            size_t start = rev ? (top ? top - 1 : 0) : top + 1;
            if (bl_find (ls, last_pat, start, rev, &hit, o->icase))
                top = hit;
        }
        else if (c == 'h' || c == 'H')
        {
            bl_write (STDOUT_FILENO,
                      "\033[H\033[Jspace/f/PgDn next page  b/PgUp previous page\n"
                      "j/down/enter next line     k/up previous line\n"
                      "g/Home top                  G/End bottom\n"
                      "/ search forward            ? search backward   n/N repeat\n"
                      "q quit\n");
            (void) bl_read_key (tty);
        }
    }

    if (have_termios) tcsetattr (tty, TCSANOW, &old);
    bl_restore_sigwinch (&old_winch, have_winch);
    close (tty);
    return EXECUTION_SUCCESS;
}

/* less(1)'s options: the letter, its long name, and whether it takes a
   number ('n') or a string ('s'). Options that only change how a real
   terminal is driven (-R, -X, -c, -q, ...) are accepted and need nothing
   here: bash-os less writes the input's bytes as they are. */
static const struct { char letter; const char *name; char arg; } bl_less_options[] = {
    { 'a', "search-skip-screen", 0 }, { 'A', "SEARCH-SKIP-SCREEN", 0 },
    { 'b', "buffers", 'n' }, { 'B', "auto-buffers", 0 },
    { 'c', "clear-screen", 0 }, { 'C', "CLEAR-SCREEN", 0 },
    { 'd', "dumb", 0 }, { 'D', "color", 's' },
    { 'e', "quit-at-eof", 0 }, { 'E', "QUIT-AT-EOF", 0 },
    { 'f', "force", 0 }, { 'F', "quit-if-one-screen", 0 },
    { 'g', "hilite-search", 0 }, { 'G', "HILITE-SEARCH", 0 },
    { 'h', "max-back-scroll", 'n' }, { 'i', "ignore-case", 0 },
    { 'I', "IGNORE-CASE", 0 }, { 'j', "jump-target", 'n' },
    { 'J', "status-column", 0 }, { 'k', "lesskey-file", 's' },
    { 'K', "quit-on-intr", 0 }, { 'L', "no-lessopen", 0 },
    { 'm', "long-prompt", 0 }, { 'M', "LONG-PROMPT", 0 },
    { 'n', "line-numbers", 0 }, { 'N', "LINE-NUMBERS", 0 },
    { 'o', "log-file", 's' }, { 'O', "LOG-FILE", 's' },
    { 'p', "pattern", 's' }, { 'P', "prompt", 's' },
    { 'q', "quiet", 0 }, { 'q', "silent", 0 }, { 'Q', "QUIET", 0 }, { 'Q', "SILENT", 0 },
    { 'r', "raw-control-chars", 0 }, { 'R', "RAW-CONTROL-CHARS", 0 },
    { 's', "squeeze-blank-lines", 0 }, { 'S', "chop-long-lines", 0 },
    { 't', "tag", 's' }, { 'T', "tag-file", 's' },
    { 'u', "underline-special", 0 }, { 'U', "UNDERLINE-SPECIAL", 0 },
    { 'V', "version", 0 }, { 'w', "hilite-unread", 0 }, { 'W', "HILITE-UNREAD", 0 },
    { 'x', "tabs", 'n' }, { 'X', "no-init", 0 },
    { 'y', "max-forw-scroll", 'n' }, { 'z', "window", 'n' },
    { '"', "quotes", 's' }, { '~', "tilde", 0 }, { '#', "shift", 'n' },
    { '?', "help", 0 },
    /* Long-only options; letter 1 means "accepted, no effect", 2 takes a value. */
    { 1, "no-keypad", 0 }, { 1, "mouse", 0 }, { 1, "use-color", 0 },
    { 1, "incsearch", 0 }, { 1, "redraw-on-quit", 0 }, { 1, "save-marks", 0 },
    { 1, "no-histdups", 0 }, { 1, "no-vbell", 0 }, { 1, "follow-name", 0 },
    { 1, "file-size", 0 }, { 1, "exit-follow-on-close", 0 }, { 1, "wordwrap", 0 },
    { 1, "no-number-headers", 0 }, { 1, "no-search-headers", 0 },
    { 1, "show-preproc-errors", 0 }, { 1, "use-backslash", 0 },
    { 2, "rscroll", 's' }, { 2, "wheel-lines", 'n' }, { 2, "line-num-width", 'n' },
    { 2, "status-col-width", 'n' }, { 2, "header", 's' }, { 2, "intr", 's' },
    { 2, "modelines", 'n' }, { 2, "search-options", 's' },
};
#define BL_LESS_NOPTS (sizeof bl_less_options / sizeof bl_less_options[0])

static const char *
bl_less_long_name (char letter)
{
    for (size_t i = 0; i < BL_LESS_NOPTS; i++)
        if (bl_less_options[i].letter == letter) return bl_less_options[i].name;
    return "";
}

/* Apply option LETTER with VALUE (NULL for a flag). Returns 1 for --help,
   2 for --version, else 0. */
static int
bl_less_apply (bl_less_opts *o, char letter, const char *value)
{
    switch (letter)
    {
    case 'e': o->eof_quit = o->eof_quit == 2 ? 2 : 1; break;
    case 'E': o->eof_quit = 2; break;
    case 'F': o->quit_if_one = 1; break;
    case 'i': o->icase = o->icase == 2 ? 2 : 1; break;
    case 'I': o->icase = 2; break;
    case 'm': if (o->prompt != 'M') o->prompt = 'm'; break;
    case 'M': o->prompt = 'M'; break;
    case 'n': o->numbers = 0; break;
    case 'N': o->numbers = 1; break;
    case 's': o->squeeze = 1; break;
    case 'S': o->chop = 1; break;
    case 'x': o->tabs = atoi (value) > 0 ? atoi (value) : 8; break;
    case 'z':
        if (atoi (value) > 0) o->rows = atoi (value);
        else if (atoi (value) < 0 && bl_term_rows () + atoi (value) > 1) o->rows = bl_term_rows () + atoi (value);
        break;
    case 'p':
        free (o->pattern);
        o->pattern = strdup (value);
        break;
    case '?': return 1;
    case 'V': return 2;
    default: break;
    }
    return 0;
}

/* Is VALUE a less number (an optional sign and digits; -x takes a list
   such as "4,8", of which the first stop is used)? */
static int
bl_less_number (const char *value)
{
    const char *p = value;
    if (*p == '-' || *p == '+') p++;
    if (!isdigit ((unsigned char) *p)) return 0;
    while (isdigit ((unsigned char) *p)) p++;
    return !*p || *p == ',' || *p == '.';
}

/* Parse WORDS[0..N) as less does (LESS uses IN_ENV: the leading dash is
   optional and a string value ends at '$'). Options end at the first file
   name, which with the rest goes to FILES when it is set. Unknown options
   and missing values are reported as less reports them, and parsing goes
   on; a bad number in the option's own word ends less quietly, as it does
   there. Returns 1 for --help, 2 for --version, 3 to quit, -1 for a
   bash-os usage error (-n LINES), else 0. */
static int
bl_less_parse (bl_less_opts *o, char **words, int n, int in_env, char **files, int *nfiles)
{
    int end_options = 0;
    for (int i = 0; i < n; i++)
    {
        char *w = words[i];
        if (!end_options && !strcmp (w, "--") && !in_env) { end_options = 1; continue; }
        if (!end_options && w[0] == '+')
        {
            /* +CMD: +G the end, +N or +Ng line N, +/PAT the first match;
               ++CMD applies to every file, as one file is shown here. */
            const char *cmd = w + 1 + (w[1] == '+');
            if (!strcmp (cmd, "G") || !strcmp (cmd, ">")) o->start_end = 1;
            else if (isdigit ((unsigned char) cmd[0]))
            {
                char *end;
                long v = strtol (cmd, &end, 10);
                if (!*end || !strcmp (end, "g")) { o->start_line = v; o->start_end = 0; }
                else if (!strcmp (end, "G")) { o->start_line = v; o->start_end = 0; }
            }
            else if (cmd[0] == '/' && cmd[1])
            {
                free (o->pattern);
                o->pattern = strdup (cmd + 1);
            }
            else if (!strcmp (cmd, "g") || !strcmp (cmd, "<")) { o->start_end = 0; o->start_line = 0; }
            continue;
        }
        if (!end_options && w[0] == '-' && w[1] == '-' && w[2])
        {
            const char *name = w + 2, *eq = strchr (name, '=');
            size_t nl = eq ? (size_t) (eq - name) : strlen (name);
            int found = -1, matches = 0;
            for (size_t k = 0; k < BL_LESS_NOPTS; k++)
            {
                if (strncmp (bl_less_options[k].name, name, nl)) continue;
                if (!bl_less_options[k].name[nl]) { found = (int) k; matches = 1; break; }
                if (found < 0 || bl_less_options[k].letter <= 2
                    || bl_less_options[found].letter != bl_less_options[k].letter) matches++;
                found = (int) k;
            }
            if (matches != 1)
            {
                fprintf (stderr, "There is no %.*s option (\"less --help\" for help)\n", (int) nl, name);
                continue;
            }
            char letter = bl_less_options[found].letter, arg = bl_less_options[found].arg;
            const char *value = eq ? eq + 1 : NULL;
            char shown[64];
            if (letter > 2)
                snprintf (shown, sizeof shown, "-%c (--%s)", letter, bl_less_options[found].name);
            else
                snprintf (shown, sizeof shown, "--%s", bl_less_options[found].name);
            if (arg && !value)
            {
                if (i + 1 < n) value = words[++i];
                else
                {
                    fprintf (stderr, "%s is required after %s\n", arg == 'n' ? "Number" : "Value", shown);
                    continue;
                }
            }
            if (arg == 'n' && !bl_less_number (value))
            {
                /* less: "--window=x" names the word; "--tabs=x" is silent. */
                if (!eq)
                    fprintf (stderr, "Number is required after %s\n", shown);
                else if (letter != 'x')
                    fprintf (stderr, "Number is required after %s\n", name);
                if (eq) return 3;
                continue;
            }
            if (letter > 2)
            {
                int r = bl_less_apply (o, letter, arg ? value : NULL);
                if (r) return r;
            }
            continue;
        }
        int cluster = !end_options && ((w[0] == '-' && w[1]) || (in_env && w[0]));
        if (!cluster)
        {
            if (files) files[(*nfiles)++] = w;
            end_options = 1;
            continue;
        }
        const char *p = w[0] == '-' ? w + 1 : w;
        /* bash-os: a word "-n LINES" or "-nLINES" sets the page size. */
        if (!in_env && !strcmp (w, "-n"))
        {
            if (i + 1 >= n) { builtin_error ("-n needs LINES"); return -1; }
            if (!bl_str_is_num (words[i + 1])) { builtin_error ("-n: invalid number: %s", words[i + 1]); return -1; }
            o->rows = atoi (words[++i]);
            if (o->rows < 2) o->rows = bl_term_rows ();
            continue;
        }
        if (!in_env && w[0] == '-' && w[1] == 'n' && w[2])
        {
            if (!bl_str_is_num (w + 2)) { builtin_error ("-n: invalid number: %s", w + 2); return -1; }
            o->rows = atoi (w + 2);
            if (o->rows < 2) o->rows = bl_term_rows ();
            continue;
        }
        if (!in_env && !strcmp (w, "-h")) return 1;
        for (; *p; p++)
        {
            char letter = *p;
            if (letter == '-' || letter == '+')
                continue;   /* "-+X" resets X in less; here a sign is skipped */
            int k = -1;
            for (size_t j = 0; j < BL_LESS_NOPTS; j++)
                if (bl_less_options[j].letter == letter) { k = (int) j; break; }
            if (k < 0)
            {
                fprintf (stderr, "There is no -%c option (\"less --help\" for help)\n", letter);
                continue;
            }
            char arg = bl_less_options[k].arg;
            if (!arg)
            {
                int r = bl_less_apply (o, letter, NULL);
                if (r) return r;
                continue;
            }
            /* The value is the rest of the word, else the next word. */
            char *value = p[1] ? (char *) p + 1 : NULL;
            char *owned = NULL;
            int attached = value != NULL;
            if (!value && i + 1 < n) value = words[++i];
            if (value && in_env && arg == 's' && strchr (value, '$'))
            {
                owned = strndup (value, (size_t) (strchr (value, '$') - value));
                value = owned;
            }
            if (!value)
                fprintf (stderr, "%s is required after -%c (--%s)\n", arg == 'n' ? "Number" : "Value",
                         letter, bl_less_long_name (letter));
            else if (arg == 'n' && !bl_less_number (value))
            {
                if (!attached)
                    fprintf (stderr, "Number is required after -%c (--%s)\n", letter, bl_less_long_name (letter));
                else
                {
                    if (letter != 'x') fprintf (stderr, "Number is required after -%c\n", letter);
                    return 3;
                }
            }
            else
            {
                int r = bl_less_apply (o, letter, value);
                if (r) { free (owned); return r; }
            }
            free (owned);
            break;
        }
    }
    return 0;
}

static void
bl_less_usage (void)
{
    puts ("less [-F] [-N] [-S] [-n LINES] [FILE...]");
    puts ("less [-eEFiIMmNsSRrX] [-p PATTERN] [-x N] [-z N] [+CMD] [FILE...]");
}

int
less_builtin (WORD_LIST *list)
{
    bl_less_opts o;
    memset (&o, 0, sizeof o);
    o.rows = bl_term_rows ();
    bl_lines ls = { 0 };
    int rc = EXECUTION_SUCCESS;

    /* LESS first (git runs its pager with LESS=FRX), then the arguments;
       options may follow file names, as in less. */
    int nwords = 0;
    for (WORD_LIST *p = list; p; p = p->next) nwords++;
    char **words = malloc ((size_t) (nwords + 1) * sizeof *words);
    char **files = malloc ((size_t) (nwords + 1) * sizeof *files);
    char *env = getenv ("LESS") ? strdup (getenv ("LESS")) : NULL;
    if (!words || !files || (getenv ("LESS") && !env))
    {
        free (words); free (files); free (env);
        builtin_error ("out of memory");
        return EXECUTION_FAILURE;
    }
    int nfiles = 0, r = 0;
    if (env)
    {
        char *ewords[64];
        int ne = 0;
        for (char *t = strtok (env, " \t"); t && ne < 64; t = strtok (NULL, " \t"))
            ewords[ne++] = t;
        r = bl_less_parse (&o, ewords, ne, 1, NULL, NULL);
    }
    if (!r)
    {
        nwords = 0;
        for (WORD_LIST *p = list; p; p = p->next) words[nwords++] = p->word->word;
        r = bl_less_parse (&o, words, nwords, 0, files, &nfiles);
    }
    free (env);
    if (r)
    {
        if (r == 1) bl_less_usage ();
        else if (r == 2) puts ("less 0.1 (bash-os less-shaped pager)");
        free (words); free (files); free (o.pattern);
        return r < 0 ? EX_USAGE : EXECUTION_SUCCESS;   /* 3: less quits quietly */
    }

    /* Output that is not a terminal is copied as cat would, whatever the
       options say, as less does. */
    int drain = !isatty (STDOUT_FILENO);
    if (!nfiles && isatty (STDIN_FILENO))
    {
        /* less(1) does not page a terminal: it names the problem, on the
           output when that is not a terminal, and succeeds. */
        fputs ("Missing filename (\"less --help\" for help)\n", drain ? stdout : stderr);
        fflush (drain ? stdout : stderr);
    }
    else if (!nfiles)
    {
        if ((drain ? bl_copy_stream (stdin) : bl_read_stream (stdin, &ls)) < 0)
            rc = EXECUTION_FAILURE;
    }
    else
    {
        for (int i = 0; i < nfiles; i++)
        {
            /* Like less(1), redirected plain output concatenates payloads
               without the interactive file-separator display. */
            if (nfiles > 1 && !drain)
            {
                char hdr[512];
                snprintf (hdr, sizeof hdr, "::::::::::::::\n%s\n::::::::::::::\n", files[i]);
                size_t len = strlen (hdr);
                if (bl_lines_push (&ls, hdr, len) < 0)
                    rc = EXECUTION_FAILURE;
            }
            if (bl_read_file_operand (files[i], drain ? NULL : &ls) < 0)
                rc = EXECUTION_FAILURE;
        }
    }

    if (drain) {
        if (fflush (stdout) == EOF || ferror (stdout)) {
            builtin_error ("write error: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    } else if (rc == EXECUTION_SUCCESS)
        rc = bl_interactive (&ls, &o, nfiles == 1 && strcmp (files[0], "-") ? files[0] : NULL);
    bl_lines_free (&ls);
    free (words);
    free (files);
    free (o.pattern);
    return rc;
}

char *less_doc[] = {
    "Page through input with a small less-shaped interface.",
    "",
    "    less [-F] [-N] [-S] [-n LINES] [FILE...]",
    "    less [-eEFiIMmNsSRrX] [-p PATTERN] [-x N] [-z N] [+CMD] [FILE...]",
    "",
    "    -F          quit if content fits on one screen",
    "    -N          show line numbers",
    "    -S          chop long lines to screen width",
    "    -n LINES    override screen-page size",
    "    -e, -E      quit at the second or the first end of the input",
    "    -i, -I      searches ignore case (-i only for lower-case patterns)",
    "    -m, -M      longer prompts: percentage, then line range",
    "    -s          show runs of blank lines as one",
    "    -x N        tab stops every N columns; -z N  N lines per page",
    "    -p PATTERN  start at the first line matching PATTERN",
    "    +G, +N, +/PATTERN  start at the end, at line N, at PATTERN",
    "    -R -r -X and the other less(1) options are accepted; options may be",
    "    clustered (-FRX), and LESS is read first, as git sets LESS=FRX.",
    "",
    "Interactive keys: space/f next page, b previous page, j/k line",
    "movement, g/G top/bottom, / and ? search, n/N repeat search, q quit.",
    "When /dev/tty is unavailable, drains input without pausing.",
    "When standard output is not a terminal, input is copied as cat does",
    "whatever the options. Unknown options are reported and ignored, as",
    "less(1) does. With redirected plain output, file-open errors are",
    "printed to standard output and remaining operands are read; file-open",
    "errors alone do not set a failure status, matching less(1). With no",
    "FILE and a terminal as input, less reports \"Missing filename\".",
    (char *)NULL
};

struct builtin less_struct = {
    "less",
    less_builtin,
    BUILTIN_ENABLED,
    less_doc,
    "less [-F] [-N] [-S] [-n LINES] [FILE...]",
    0
};
