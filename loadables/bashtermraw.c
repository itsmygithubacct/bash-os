/* bashtermraw.c — termios primitives + ANSI key decoder for bash.
 *
 * Lets a bash-os script build a TUI without ncurses: toggle raw mode,
 * read decoded keypresses, query terminal size, position the cursor,
 * clear lines. The state machine handles enough of the xterm/kitty
 * keypress vocabulary to cover an interactive editor or pager.
 *
 * Subcommands:
 *   bashtermraw raw                  — save current termios, set raw mode
 *                                       (no echo, no canon, VMIN=1 VTIME=0)
 *   bashtermraw cooked               — restore termios saved by `raw`,
 *                                       or fall back to a sane canonical
 *                                       default if no save
 *   bashtermraw size                 — echo "ROWS COLS" (TIOCGWINSZ)
 *   bashtermraw stty [-F DEV] [-a|-g|SETTING...]
 *                                    — GNU stty(1) on stdin or DEV
 *   bashtermraw keypress             — read one key, echo the name
 *                                       (UP / DOWN / F1 / C-x / TAB / RET
 *                                       / ESC / BS / DEL / printable char)
 *   bashtermraw cup ROW COL          — write CSI cursor-position ANSI
 *   bashtermraw clr-eol              — write CSI K (clear to EOL)
 *   bashtermraw clr-screen           — write CSI 2J + cursor home
 *   bashtermraw clear [-x|--no-scrollback]
 *                                    — clear screen, home cursor, optionally
 *                                       erase scrollback
 *   bashtermraw reset                — RIS + recovery sequences + sane termios
 *   bashtermraw show [on|off]        — show/hide cursor (CSI ?25 h/l)
 *
 * All terminal-side writes go to /dev/tty when available so bashtermraw
 * keeps working under stdout redirection (`bashtermraw cup 5 3 > /dev/null`
 * still moves the cursor on the user-visible terminal).
 *
 * Bracketed paste (DEC private mode 2004):
 *   - `bashtermraw paste on`  emits CSI ?2004 h
 *   - `bashtermraw paste off` emits CSI ?2004 l
 *   - `bashtermraw keypress` decodes the wrap markers as
 *     PASTE-START (CSI 200~) and PASTE-END (CSI 201~)
 *
 * Limitations / non-goals at v1:
 *   - No mouse mode
 *   - keypress timeout is fixed at 50ms after ESC (long enough for a
 *     CSI sequence to arrive on a slow pty, short enough that a user
 *     pressing ESC alone gets recognized as ESC)
 *   - No SIGWINCH handler — caller traps SIGWINCH and re-reads `size`
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software. See the
 * full MIT text for the standard disclaimer.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdarg.h>

#include "loadables.h"
#include "clear-impl.h"

/* --- termios state -------------------------------------------------------
 * Static save: a single saved-termios slot. Sufficient for the
 * interactive single-shell case. Multi-shell coordination is out of
 * scope; the saved state belongs to the bash process that called -raw. */
static struct termios btr_saved;
static int            btr_saved_valid = 0;

/* Pick the right fd for terminal I/O. /dev/tty is the controlling
 * terminal regardless of stdin/stdout redirection. Falls back to
 * STDIN_FILENO if /dev/tty isn't accessible (background script,
 * detached daemon, etc.). Caller must close() the returned fd when
 * done IF it's not stdin. */
static int
btr_open_tty_quiet (int *out_fd, int *out_should_close, int quiet)
{
  int fd = open ("/dev/tty", O_RDWR | O_NOCTTY);
  if (fd >= 0) { *out_fd = fd; *out_should_close = 1; return 0; }
  /* Fallback: use stdin. */
  if (isatty (STDIN_FILENO))
    { *out_fd = STDIN_FILENO; *out_should_close = 0; return 0; }
  if (!quiet)
    builtin_error ("not connected to a terminal");
  return -1;
}

static int
btr_open_tty (int *out_fd, int *out_should_close)
{
  return btr_open_tty_quiet (out_fd, out_should_close, 0);
}

static int
btr_raw (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;

  struct termios cur;
  if (tcgetattr (fd, &cur) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  btr_saved = cur;
  btr_saved_valid = 1;

  /* Raw mode per cfmakeraw(3): clear ICANON, ECHO, IGNBRK, BRKINT,
     PARMRK, ISTRIP, INLCR, IGNCR, ICRNL, IXON, OPOST, ECHONL, ISIG;
     set CS8; VMIN=1, VTIME=0 (blocking byte-at-a-time read). */
  cur.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
                              | IGNCR | ICRNL | IXON);
  cur.c_oflag &= (tcflag_t) ~(OPOST);
  cur.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  cur.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
  cur.c_cflag |= CS8;
  cur.c_cc[VMIN] = 1;
  cur.c_cc[VTIME] = 0;
  if (tcsetattr (fd, TCSANOW, &cur) < 0)
    {
      builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_cooked_quiet (int quiet)
{
  int fd, close_fd;
  if (btr_open_tty_quiet (&fd, &close_fd, quiet) < 0) return 1;

  struct termios target;
  if (btr_saved_valid)
    {
      target = btr_saved;
    }
  else
    {
      /* No prior raw call: synthesize a sane canonical mode. */
      if (tcgetattr (fd, &target) < 0) target = (struct termios) { 0 };
      target.c_iflag |= ICRNL | IXON | BRKINT;
      target.c_iflag &= (tcflag_t) ~(INLCR | IGNCR | ISTRIP);
      target.c_oflag |= OPOST | ONLCR;
      target.c_lflag |= ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ISIG | IEXTEN;
      target.c_cflag &= (tcflag_t) ~CSIZE;
      target.c_cflag |= CS8 | CREAD;
    }
  if (tcsetattr (fd, TCSANOW, &target) < 0)
    {
      if (!quiet)
        builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_cooked (void)
{
  return btr_cooked_quiet (0);
}

static int
btr_size (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct winsize ws;
  if (ioctl (fd, TIOCGWINSZ, &ws) < 0)
    {
      builtin_error ("ioctl(TIOCGWINSZ): %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  printf ("%u %u\n", (unsigned) ws.ws_row, (unsigned) ws.ws_col);
  if (close_fd) close (fd);
  return 0;
}

static int
btr_stty_g (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct termios t;
  if (tcgetattr (fd, &t) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  struct winsize ws = {0};
  (void) ioctl (fd, TIOCGWINSZ, &ws);
  printf ("bashtermraw2:%lx:%lx:%lx:%lx:",
          (unsigned long) t.c_iflag, (unsigned long) t.c_oflag,
          (unsigned long) t.c_cflag, (unsigned long) t.c_lflag);
  for (int i = 0; i < NCCS; i++)
    {
      if (i) putchar (',');
      printf ("%u", (unsigned) t.c_cc[i]);
    }
  printf (":%lu:%lu:%u:%u\n",
          (unsigned long) cfgetispeed (&t), (unsigned long) cfgetospeed (&t),
          (unsigned) ws.ws_row, (unsigned) ws.ws_col);
  if (close_fd) close (fd);
  return 0;
}

static int
btr_parse_ulong (const char *s, int base, unsigned long *out)
{
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul (s, &end, base);
  if (errno || end == s || *end != '\0') return -1;
  *out = v;
  return 0;
}

static int
btr_stty_set (const char *state)
{
  if (!state || strncmp (state, "bashtermraw2:", 13) != 0)
    {
      builtin_error ("stty-set: unsupported state string");
      return 1;
    }

  char copy[1024];
  if (strlen (state) >= sizeof copy)
    {
      builtin_error ("stty-set: state string too long");
      return 1;
    }
  strcpy (copy, state);

  char *save = NULL;
  char *tok = strtok_r (copy, ":", &save); /* bashtermraw2 */
  unsigned long vals[8] = {0};
  for (int i = 0; i < 4; i++)
    {
      tok = strtok_r (NULL, ":", &save);
      if (!tok || btr_parse_ulong (tok, 16, &vals[i]) < 0)
        {
          builtin_error ("stty-set: malformed flag field");
          return 1;
        }
    }
  char *ccs = strtok_r (NULL, ":", &save);
  char *is = strtok_r (NULL, ":", &save);
  char *os = strtok_r (NULL, ":", &save);
  char *rows_s = strtok_r (NULL, ":", &save);
  char *cols_s = strtok_r (NULL, ":", &save);
  if (!ccs || !is || !os || !rows_s || !cols_s)
    {
      builtin_error ("stty-set: incomplete state string");
      return 1;
    }
  if (btr_parse_ulong (is, 10, &vals[4]) < 0 ||
      btr_parse_ulong (os, 10, &vals[5]) < 0 ||
      btr_parse_ulong (rows_s, 10, &vals[6]) < 0 ||
      btr_parse_ulong (cols_s, 10, &vals[7]) < 0)
    {
      builtin_error ("stty-set: malformed speed/size field");
      return 1;
    }

  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct termios t;
  if (tcgetattr (fd, &t) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  t.c_iflag = (tcflag_t) vals[0];
  t.c_oflag = (tcflag_t) vals[1];
  t.c_cflag = (tcflag_t) vals[2];
  t.c_lflag = (tcflag_t) vals[3];

  char *ccsave = NULL;
  char *cc = strtok_r (ccs, ",", &ccsave);
  for (int i = 0; i < NCCS; i++)
    {
      unsigned long cv;
      if (!cc || btr_parse_ulong (cc, 10, &cv) < 0 || cv > 255)
        {
          builtin_error ("stty-set: malformed cc field");
          if (close_fd) close (fd);
          return 1;
        }
      t.c_cc[i] = (cc_t) cv;
      cc = strtok_r (NULL, ",", &ccsave);
    }
  (void) cfsetispeed (&t, (speed_t) vals[4]);
  (void) cfsetospeed (&t, (speed_t) vals[5]);
  if (tcsetattr (fd, TCSANOW, &t) < 0)
    {
      builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }

  if (vals[6] > 0 || vals[7] > 0)
    {
      struct winsize ws;
      memset (&ws, 0, sizeof ws);
      ws.ws_row = (unsigned short) vals[6];
      ws.ws_col = (unsigned short) vals[7];
      (void) ioctl (fd, TIOCSWINSZ, &ws);
    }
  if (close_fd) close (fd);
  return 0;
}

/* stty rows/cols: set the kernel window size (TIOCSWINSZ), which also
   delivers SIGWINCH to the terminal's foreground process group. */
static int
btr_resize (const char *rows_s, const char *cols_s)
{
  char *end;
  long rows, cols;
  int fd, close_fd;

  errno = 0;
  rows = strtol (rows_s, &end, 10);
  if (errno || end == rows_s || *end || rows < 0 || rows > 65535)
    { builtin_error ("resize: invalid row count: %s", rows_s); return 1; }
  cols = strtol (cols_s, &end, 10);
  if (errno || end == cols_s || *end || cols < 0 || cols > 65535)
    { builtin_error ("resize: invalid column count: %s", cols_s); return 1; }
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct winsize ws;
  memset (&ws, 0, sizeof ws);
  (void) ioctl (fd, TIOCGWINSZ, &ws);
  ws.ws_row = (unsigned short) rows;
  ws.ws_col = (unsigned short) cols;
  if (ioctl (fd, TIOCSWINSZ, &ws) < 0)
    {
      builtin_error ("ioctl(TIOCSWINSZ): %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  if (close_fd) close (fd);
  return 0;
}

/* --- Keypress decoder ----------------------------------------------------
 * Reads one logical keypress event from /dev/tty (in whatever mode the
 * terminal is currently in — this builtin is most useful right after
 * `bashtermraw raw`). Decodes:
 *
 *   0x09         → TAB
 *   0x0d / 0x0a  → RET
 *   0x1b         → ESC (or start of CSI / SS3 if more bytes follow within 50ms)
 *   0x7f / 0x08  → BS
 *   0x01..0x1a   → C-a..C-z (excluding TAB, RET, ESC, BS already mapped)
 *   ESC [ A      → UP
 *   ESC [ B      → DOWN
 *   ESC [ C      → RIGHT
 *   ESC [ D      → LEFT
 *   ESC [ H      → HOME
 *   ESC [ F      → END
 *   ESC [ 1~     → HOME (some terms)
 *   ESC [ 2~     → INS
 *   ESC [ 3~     → DEL
 *   ESC [ 4~     → END (some terms)
 *   ESC [ 5~     → PGUP
 *   ESC [ 6~     → PGDN
 *   ESC [ 11~..15~ → F1..F5
 *   ESC [ 17~..21~ → F6..F10
 *   ESC [ 23~..24~ → F11..F12
 *   ESC O P/Q/R/S  → F1..F4 (xterm ss3)
 *   ESC <printable> → M-x (Alt-x)
 *   printable      → returned as-is (single char)
 *
 * Output: one line on stdout, the key name (or character).
 */

/* Read one byte with `to_ms` timeout. Returns 1 on success (byte in *out),
 * 0 on timeout, -1 on error. */
static int
btr_read_byte (int fd, int to_ms, unsigned char *out)
{
  struct pollfd pfd = { fd, POLLIN, 0 };
  int pr = poll (&pfd, 1, to_ms);
  if (pr < 0) return -1;
  if (pr == 0) return 0;
  ssize_t n = read (fd, out, 1);
  if (n == 1) return 1;
  if (n == 0) return 0;
  return -1;
}

static int
btr_keypress (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;

  unsigned char b;
  /* Block on first byte. */
  ssize_t n = read (fd, &b, 1);
  if (n != 1)
    {
      if (close_fd) close (fd);
      return 1;
    }

  /* Plain control chars first. */
  if (b == 0x09) { puts ("TAB");           if (close_fd) close (fd); return 0; }
  if (b == 0x0d || b == 0x0a) { puts ("RET"); if (close_fd) close (fd); return 0; }
  if (b == 0x7f || b == 0x08) { puts ("BS"); if (close_fd) close (fd); return 0; }

  if (b == 0x1b)
    {
      /* Look for a follow-up byte within 50ms. If none, plain ESC. */
      unsigned char b2;
      int r = btr_read_byte (fd, 50, &b2);
      if (r <= 0) { puts ("ESC"); if (close_fd) close (fd); return 0; }

      if (b2 == '[' || b2 == 'O')
        {
          int csi_o = (b2 == 'O');
          /* Collect bytes until a final byte (0x40..0x7e) arrives. */
          char param[32]; size_t plen = 0;
          unsigned char fb = 0;
          for (;;)
            {
              unsigned char c;
              int rr = btr_read_byte (fd, 200, &c);
              if (rr <= 0) break;
              if (c >= 0x40 && c <= 0x7e) { fb = c; break; }
              if (plen + 1 < sizeof param) param[plen++] = (char) c;
            }
          param[plen] = '\0';

          if (csi_o)
            {
              /* SS3: ESC O <fb>. F1..F4 are P Q R S. Arrows in app mode
                 are A B C D (same as CSI). */
              switch (fb)
                {
                case 'P': puts ("F1"); break;
                case 'Q': puts ("F2"); break;
                case 'R': puts ("F3"); break;
                case 'S': puts ("F4"); break;
                case 'A': puts ("UP"); break;
                case 'B': puts ("DOWN"); break;
                case 'C': puts ("RIGHT"); break;
                case 'D': puts ("LEFT"); break;
                case 'H': puts ("HOME"); break;
                case 'F': puts ("END"); break;
                default:  printf ("SS3-%c\n", fb);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* CSI: ESC [ <param> <fb> */
          if (plen == 0)
            {
              switch (fb)
                {
                case 'A': puts ("UP"); break;
                case 'B': puts ("DOWN"); break;
                case 'C': puts ("RIGHT"); break;
                case 'D': puts ("LEFT"); break;
                case 'H': puts ("HOME"); break;
                case 'F': puts ("END"); break;
                case 'Z': puts ("S-TAB"); break;
                default:  printf ("CSI-%c\n", fb);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* CSI <num>~ — function-key family. */
          if (fb == '~')
            {
              int code = atoi (param);
              switch (code)
                {
                case  1: puts ("HOME"); break;
                case  2: puts ("INS");  break;
                case  3: puts ("DEL");  break;
                case  4: puts ("END");  break;
                case  5: puts ("PGUP"); break;
                case  6: puts ("PGDN"); break;
                case 11: puts ("F1");   break;
                case 12: puts ("F2");   break;
                case 13: puts ("F3");   break;
                case 14: puts ("F4");   break;
                case 15: puts ("F5");   break;
                case 17: puts ("F6");   break;
                case 18: puts ("F7");   break;
                case 19: puts ("F8");   break;
                case 20: puts ("F9");   break;
                case 21: puts ("F10");  break;
                case 23: puts ("F11");  break;
                case 24: puts ("F12");  break;
                /* Bracketed paste (DEC private mode 2004). The terminal
                   wraps every paste in CSI 200~ ... CSI 201~ when the
                   caller has enabled `bashtermraw paste on`. Decode
                   the delimiters so a TUI loop can switch into a
                   "accept literal characters" branch between them. */
                case 200: puts ("PASTE-START"); break;
                case 201: puts ("PASTE-END");   break;
                default: printf ("CSI-%d~\n", code);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* Modifiers: e.g. ESC [ 1;5A (C-Up). Param is "1;5", fb is 'A'.
             Best-effort decode. */
          {
            int npar1 = 0, npar2 = 0;
            sscanf (param, "%d;%d", &npar1, &npar2);
            const char *base = NULL;
            switch (fb)
              {
              case 'A': base = "UP"; break;
              case 'B': base = "DOWN"; break;
              case 'C': base = "RIGHT"; break;
              case 'D': base = "LEFT"; break;
              case 'H': base = "HOME"; break;
              case 'F': base = "END"; break;
              default:  base = NULL;
              }
            if (base && npar2 > 1)
              {
                /* Modifier code: 2=Shift, 3=Alt, 4=Shift-Alt, 5=Ctrl,
                   6=Shift-Ctrl, 7=Alt-Ctrl, 8=Shift-Alt-Ctrl. */
                const char *prefix = "";
                switch (npar2)
                  {
                  case 2: prefix = "S-"; break;
                  case 3: prefix = "M-"; break;
                  case 4: prefix = "M-S-"; break;
                  case 5: prefix = "C-"; break;
                  case 6: prefix = "C-S-"; break;
                  case 7: prefix = "C-M-"; break;
                  case 8: prefix = "C-M-S-"; break;
                  }
                printf ("%s%s\n", prefix, base);
              }
            else if (base)
              printf ("%s\n", base);
            else
              printf ("CSI-%s%c\n", param, fb);
            if (close_fd) close (fd);
            return 0;
          }
        }

      /* ESC followed by a printable: M-<char>. */
      if (b2 >= 0x20 && b2 < 0x7f)
        {
          printf ("M-%c\n", b2);
          if (close_fd) close (fd);
          return 0;
        }
      /* ESC + control char: M-C-<char>. */
      if (b2 < 0x20)
        {
          printf ("M-C-%c\n", b2 + '@');
          if (close_fd) close (fd);
          return 0;
        }
      printf ("ESC-0x%02x\n", b2);
      if (close_fd) close (fd);
      return 0;
    }

  if (b < 0x20)
    {
      /* Letter controls use the documented lowercase names.  Preserve the
         traditional punctuation names for NUL and 0x1c..0x1f. */
      printf ("C-%c\n", b >= 0x01 && b <= 0x1a ? b + '`' : b + '@');
      if (close_fd) close (fd);
      return 0;
    }

  if (b < 0x7f)
    {
      /* Printable ASCII — return as-is. */
      printf ("%c\n", b);
      if (close_fd) close (fd);
      return 0;
    }

  /* High-bit byte: fragment of UTF-8 or 8-bit input. Echo as 0x.. */
  printf ("0x%02x\n", b);
  if (close_fd) close (fd);
  return 0;
}

/* --- Cursor / line manipulation ------------------------------------------ */

static int
btr_write_seq_quiet (const char *seq, int quiet)
{
  int fd, close_fd;
  if (btr_open_tty_quiet (&fd, &close_fd, quiet) < 0) return 1;
  /* In raw mode the tty doesn't translate \n→\r\n, so write as-is. */
  size_t left = strlen (seq);
  const char *p = seq;
  while (left > 0)
    {
      ssize_t w = write (fd, p, left);
      if (w < 0)
        {
          if (errno == EINTR) continue;
          if (!quiet)
            builtin_error ("write: %s", strerror (errno));
          if (close_fd) close (fd);
          return 1;
        }
      p += w;
      left -= (size_t) w;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_write_seq (const char *seq)
{
  return btr_write_seq_quiet (seq, 0);
}

static int
btr_cup (int row, int col)
{
  /* CSI R;C H — 1-indexed. */
  char seq[32];
  if (row < 1) row = 1;
  if (col < 1) col = 1;
  snprintf (seq, sizeof seq, "\033[%d;%dH", row, col);
  return btr_write_seq (seq);
}

static int
btr_clr_eol (void)   { return btr_write_seq ("\033[K"); }
static int
btr_clr_screen (void){ return btr_write_seq ("\033[2J\033[H"); }
static int
btr_cursor_show (int on) { return btr_write_seq (on ? "\033[?25h" : "\033[?25l"); }

/* Bracketed paste mode (DEC private mode 2004). When on, the terminal
   wraps pasted text in CSI 200~ ... CSI 201~ so a TUI can distinguish
   it from typed input. The keypress decoder surfaces these as
   PASTE-START / PASTE-END key names. */
static int
btr_bracketed_paste (int on) { return btr_write_seq (on ? "\033[?2004h" : "\033[?2004l"); }

/* clear — erase-scrollback + cursor-home + erase-display. The xterm
   E3 capability (CSI 3 J) is needed for the scrollback wipe; without
   it `clear` only blanks the visible viewport. Most modern terminals
   (xterm, gnome-terminal, kitty, alacritty, foot, st) honor it. */
/* Non-zero when the /bin shim runs `bashtermraw clear' as the standalone
   clear command (an unexported BASHOS_SHIM_COMMAND=bashtermraw=NAME). */
static int
btr_shim_clear (void)
{
  SHELL_VAR *v = find_variable ("BASHOS_SHIM_COMMAND");
  const char *val;

  if (v == 0 || exported_p (v) || array_p (v) || assoc_p (v))
    return 0;
  val = value_cell (v);
  return val && strncmp (val, "bashtermraw=", 12) == 0 && val[12];
}

static int
btr_clear (WORD_LIST *args)
{
  int scrollback = 1;

  /* As the clear command, behave as ncurses clear(1): the sequence for
     the environment's TERM (or -T TERM) goes to stdout, terminal or not,
     and -x keeps the scrollback. */
  if (btr_shim_clear ())
    return bashclear_run_env (args, 1);
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-x"))
        scrollback = 1;
      else if (!strcmp (w, "--no-scrollback"))
        scrollback = 0;
      else
        {
          builtin_error ("clear: unsupported option: %s", w);
          return 1;
        }
    }
  return btr_write_seq (scrollback ? "\033[3J\033[H\033[2J" : "\033[H\033[2J");
}

/* reset — RIS (Reset to Initial State, ESC c). Stronger than `clear`:
   resets character set, scrolling region, attributes, alt-screen state,
   plus everything `clear` does. Then restore sane canonical termios
   (delegates to btr_cooked, which knows the right defaults). */
static int
btr_reset (WORD_LIST *args)
{
  int quiet = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-q"))
        quiet = 1;
      else
        {
          builtin_error ("reset: unsupported option: %s", w);
          return 1;
        }
    }
  /* RIS first, then busybox/toybox-style recovery sequences: select
     US-ASCII G0, reset SGR, clear to end of display, show cursor, and
     explicitly re-enable autowrap for terminals that leave it off. */
  if (btr_write_seq_quiet ("\033c\033(B\033[m\033[J\033[?25h\033[?7h", quiet) != 0) return 1;
  /* Then sane termios. btr_cooked falls back to ICANON/ECHO/etc
     synthesis when no prior `raw` save exists, which is exactly what
     a from-scratch reset wants. */
  return btr_cooked_quiet (quiet);
}

/* --- bash builtin entry --------------------------------------------------- */

extern char *bashtermraw_doc[];

/* ---- bashtermraw stty: GNU stty(1) mode words over termios --------------
 *
 * Operates on standard input like GNU stty (or on -F DEVICE), so a script
 * whose stdin is not a terminal gets GNU's "Inappropriate ioctl" failure.
 * Settings follow coreutils' mode table: every input, output, control and
 * local flag, the combination modes, control characters, speeds, rows and
 * columns. -g emits and accepts GNU's hex state; bashtermraw2 states from
 * older images are still accepted. */

enum { BST_C, BST_I, BST_O, BST_L };
#define BST_SANE_SET   1
#define BST_SANE_UNSET 2
#define BST_REV        4
#define BST_OMIT       8

typedef struct {
  const char *name;
  int type, flags;
  tcflag_t bits, mask;
} bst_mode;

static const bst_mode bst_modes[] = {
  {"parenb", BST_C, BST_REV, PARENB, 0},
  {"parodd", BST_C, BST_REV, PARODD, 0},
#ifdef CMSPAR
  {"cmspar", BST_C, BST_REV, CMSPAR, 0},
#endif
  {"cs5", BST_C, 0, CS5, CSIZE},
  {"cs6", BST_C, 0, CS6, CSIZE},
  {"cs7", BST_C, 0, CS7, CSIZE},
  {"cs8", BST_C, 0, CS8, CSIZE},
  {"hupcl", BST_C, BST_REV, HUPCL, 0},
  {"hup", BST_C, BST_REV | BST_OMIT, HUPCL, 0},
  {"cstopb", BST_C, BST_REV, CSTOPB, 0},
  {"cread", BST_C, BST_SANE_SET | BST_REV, CREAD, 0},
  {"clocal", BST_C, BST_REV, CLOCAL, 0},
#ifdef CRTSCTS
  {"crtscts", BST_C, BST_REV, CRTSCTS, 0},
#endif
  {"ignbrk", BST_I, BST_SANE_UNSET | BST_REV, IGNBRK, 0},
  {"brkint", BST_I, BST_SANE_SET | BST_REV, BRKINT, 0},
  {"ignpar", BST_I, BST_REV, IGNPAR, 0},
  {"parmrk", BST_I, BST_REV, PARMRK, 0},
  {"inpck", BST_I, BST_REV, INPCK, 0},
  {"istrip", BST_I, BST_REV, ISTRIP, 0},
  {"inlcr", BST_I, BST_SANE_UNSET | BST_REV, INLCR, 0},
  {"igncr", BST_I, BST_SANE_UNSET | BST_REV, IGNCR, 0},
  {"icrnl", BST_I, BST_SANE_SET | BST_REV, ICRNL, 0},
  {"ixon", BST_I, BST_REV, IXON, 0},
  {"ixoff", BST_I, BST_SANE_UNSET | BST_REV, IXOFF, 0},
  {"tandem", BST_I, BST_REV | BST_OMIT, IXOFF, 0},
#ifdef IUCLC
  {"iuclc", BST_I, BST_SANE_UNSET | BST_REV, IUCLC, 0},
#endif
  {"ixany", BST_I, BST_SANE_UNSET | BST_REV, IXANY, 0},
  {"imaxbel", BST_I, BST_SANE_SET | BST_REV, IMAXBEL, 0},
#ifdef IUTF8
  {"iutf8", BST_I, BST_SANE_UNSET | BST_REV, IUTF8, 0},
#endif
  {"opost", BST_O, BST_SANE_SET | BST_REV, OPOST, 0},
#ifdef OLCUC
  {"olcuc", BST_O, BST_SANE_UNSET | BST_REV, OLCUC, 0},
#endif
  {"ocrnl", BST_O, BST_SANE_UNSET | BST_REV, OCRNL, 0},
  {"onlcr", BST_O, BST_SANE_SET | BST_REV, ONLCR, 0},
  {"onocr", BST_O, BST_SANE_UNSET | BST_REV, ONOCR, 0},
  {"onlret", BST_O, BST_SANE_UNSET | BST_REV, ONLRET, 0},
  {"ofill", BST_O, BST_SANE_UNSET | BST_REV, OFILL, 0},
  {"ofdel", BST_O, BST_SANE_UNSET | BST_REV, OFDEL, 0},
  {"nl1", BST_O, BST_SANE_UNSET, NL1, NLDLY},
  {"nl0", BST_O, BST_SANE_SET, NL0, NLDLY},
  {"cr3", BST_O, BST_SANE_UNSET, CR3, CRDLY},
  {"cr2", BST_O, BST_SANE_UNSET, CR2, CRDLY},
  {"cr1", BST_O, BST_SANE_UNSET, CR1, CRDLY},
  {"cr0", BST_O, BST_SANE_SET, CR0, CRDLY},
  {"tab3", BST_O, BST_SANE_UNSET, TAB3, TABDLY},
  {"tab2", BST_O, BST_SANE_UNSET, TAB2, TABDLY},
  {"tab1", BST_O, BST_SANE_UNSET, TAB1, TABDLY},
  {"tab0", BST_O, BST_SANE_SET, TAB0, TABDLY},
  {"bs1", BST_O, BST_SANE_UNSET, BS1, BSDLY},
  {"bs0", BST_O, BST_SANE_SET, BS0, BSDLY},
  {"vt1", BST_O, BST_SANE_UNSET, VT1, VTDLY},
  {"vt0", BST_O, BST_SANE_SET, VT0, VTDLY},
  {"ff1", BST_O, BST_SANE_UNSET, FF1, FFDLY},
  {"ff0", BST_O, BST_SANE_SET, FF0, FFDLY},
  {"isig", BST_L, BST_SANE_SET | BST_REV, ISIG, 0},
  {"icanon", BST_L, BST_SANE_SET | BST_REV, ICANON, 0},
  {"iexten", BST_L, BST_SANE_SET | BST_REV, IEXTEN, 0},
  {"echo", BST_L, BST_SANE_SET | BST_REV, ECHO, 0},
  {"echoe", BST_L, BST_SANE_SET | BST_REV, ECHOE, 0},
  {"crterase", BST_L, BST_REV | BST_OMIT, ECHOE, 0},
  {"echok", BST_L, BST_SANE_SET | BST_REV, ECHOK, 0},
  {"echonl", BST_L, BST_SANE_UNSET | BST_REV, ECHONL, 0},
  {"noflsh", BST_L, BST_SANE_UNSET | BST_REV, NOFLSH, 0},
#ifdef XCASE
  {"xcase", BST_L, BST_SANE_UNSET | BST_REV, XCASE, 0},
#endif
  {"tostop", BST_L, BST_SANE_UNSET | BST_REV, TOSTOP, 0},
  {"echoprt", BST_L, BST_SANE_UNSET | BST_REV, ECHOPRT, 0},
  {"prterase", BST_L, BST_REV | BST_OMIT, ECHOPRT, 0},
  {"echoctl", BST_L, BST_SANE_SET | BST_REV, ECHOCTL, 0},
  {"ctlecho", BST_L, BST_REV | BST_OMIT, ECHOCTL, 0},
  {"echoke", BST_L, BST_SANE_SET | BST_REV, ECHOKE, 0},
  {"crtkill", BST_L, BST_REV | BST_OMIT, ECHOKE, 0},
  {"flusho", BST_L, BST_SANE_UNSET | BST_REV, FLUSHO, 0},
#ifdef EXTPROC
  {"extproc", BST_L, BST_SANE_UNSET | BST_REV, EXTPROC, 0},
#endif
  {NULL, 0, 0, 0, 0}
};

#define BST_CTRL(c) ((c) & 037)
typedef struct { const char *name; cc_t saneval; int offset; } bst_cc;
static const bst_cc bst_ccs[] = {
  {"intr", BST_CTRL ('c'), VINTR},
  {"quit", 28, VQUIT},
  {"erase", 127, VERASE},
  {"kill", BST_CTRL ('u'), VKILL},
  {"eof", BST_CTRL ('d'), VEOF},
  {"eol", _POSIX_VDISABLE, VEOL},
#ifdef VEOL2
  {"eol2", _POSIX_VDISABLE, VEOL2},
#endif
#ifdef VSWTC
  {"swtch", _POSIX_VDISABLE, VSWTC},
#endif
  {"start", BST_CTRL ('q'), VSTART},
  {"stop", BST_CTRL ('s'), VSTOP},
  {"susp", BST_CTRL ('z'), VSUSP},
#ifdef VREPRINT
  {"rprnt", BST_CTRL ('r'), VREPRINT},
#endif
#ifdef VWERASE
  {"werase", BST_CTRL ('w'), VWERASE},
#endif
#ifdef VLNEXT
  {"lnext", BST_CTRL ('v'), VLNEXT},
#endif
#ifdef VDISCARD
  {"discard", BST_CTRL ('o'), VDISCARD},
#endif
  {"min", 1, VMIN},
  {"time", 0, VTIME},
  {NULL, 0, 0}
};

static const struct { unsigned long baud; speed_t code; } bst_speeds[] = {
  {0, B0}, {50, B50}, {75, B75}, {110, B110}, {134, B134}, {150, B150},
  {200, B200}, {300, B300}, {600, B600}, {1200, B1200}, {1800, B1800},
  {2400, B2400}, {4800, B4800}, {9600, B9600}, {19200, B19200},
  {38400, B38400}, {57600, B57600}, {115200, B115200}, {230400, B230400},
#ifdef B460800
  {460800, B460800}, {500000, B500000}, {576000, B576000},
  {921600, B921600}, {1000000, B1000000}, {1152000, B1152000},
  {1500000, B1500000}, {2000000, B2000000}, {2500000, B2500000},
  {3000000, B3000000}, {3500000, B3500000}, {4000000, B4000000},
#endif
  {0, 0}
};

static const char *bst_device;  /* NULL → standard input */
static int bst_col, bst_max_col;

static const char *
bst_devname (void)
{
  return bst_device ? bst_device : "'standard input'";
}

static void
bst_err (const char *what, int err)
{
  fflush (stdout);
  if (err)
    fprintf (stderr, "stty: %s: %s\n", what,
             err == ENOTTY ? "Inappropriate ioctl for device" : strerror (err));
  else
    fprintf (stderr, "stty: %s\n", what);
}

static int
bst_speed_code (const char *s, speed_t *out)
{
  unsigned long v;
  if (!strcmp (s, "exta")) s = "19200";
  else if (!strcmp (s, "extb")) s = "38400";
  if (btr_parse_ulong (s, 10, &v) < 0)
    return -1;
  for (int i = 0; bst_speeds[i].baud || i == 0; i++)
    if (bst_speeds[i].baud == v)
      {
        *out = bst_speeds[i].code;
        return 0;
      }
  return -1;
}

static unsigned long
bst_speed_baud (speed_t code)
{
  for (int i = 0; bst_speeds[i].baud || i == 0; i++)
    if (bst_speeds[i].code == code)
      return bst_speeds[i].baud;
  return 0;
}

static tcflag_t *
bst_field (struct termios *t, int type)
{
  switch (type)
    {
    case BST_C: return &t->c_cflag;
    case BST_I: return &t->c_iflag;
    case BST_O: return &t->c_oflag;
    default:    return &t->c_lflag;
    }
}

/* Set or clear one named flag. 0 handled, -1 not a flag name. */
static int
bst_set_flag (struct termios *t, const char *arg)
{
  int rev = arg[0] == '-';
  const char *name = arg + rev;
  for (const bst_mode *m = bst_modes; m->name; m++)
    {
      if (strcmp (m->name, name))
        continue;
      if (rev && !(m->flags & BST_REV))
        return -1;
      tcflag_t *f = bst_field (t, m->type);
      if (rev)
        *f &= ~(m->bits | m->mask);
      else
        *f = (*f & ~m->mask) | m->bits;
      return 0;
    }
  return -1;
}

static void
bst_flags (struct termios *t, const char *const *words)
{
  for (; *words; words++)
    (void) bst_set_flag (t, *words);
}

static void
bst_sane (struct termios *t)
{
  for (const bst_cc *c = bst_ccs; c->name; c++)
    t->c_cc[c->offset] = c->saneval;
  for (const bst_mode *m = bst_modes; m->name; m++)
    {
      tcflag_t *f = bst_field (t, m->type);
      if (m->flags & BST_SANE_SET)
        *f = (*f & ~m->mask) | m->bits;
      else if (m->flags & BST_SANE_UNSET)
        *f &= ~(m->mask | m->bits);
    }
}

static void
bst_raw (struct termios *t, int on)
{
  static const char *const raw[] = {
    "-ignbrk", "-brkint", "-ignpar", "-parmrk", "-inpck", "-istrip",
    "-inlcr", "-igncr", "-icrnl", "-ixon", "-ixoff", "-icanon", "-opost",
    "-isig", "-iuclc", "-ixany", "-imaxbel", "-xcase", NULL };
  static const char *const cooked[] = {
    "brkint", "ignpar", "istrip", "icrnl", "ixon", "opost", "isig",
    "icanon", NULL };
  if (on)
    {
      bst_flags (t, raw);
      t->c_cc[VMIN] = 1;
      t->c_cc[VTIME] = 0;
    }
  else
    {
      bst_flags (t, cooked);
      t->c_cc[VEOF] = BST_CTRL ('d');
      t->c_cc[VEOL] = _POSIX_VDISABLE;
    }
}

/* Combination modes. 0 handled, -1 unknown. */
static int
bst_combination (struct termios *t, const char *arg)
{
  int rev = arg[0] == '-';
  const char *n = arg + rev;
#define BST_W(...) do { static const char *const w_[] = { __VA_ARGS__, NULL }; bst_flags (t, w_); } while (0)
  if (!strcmp (n, "raw")) bst_raw (t, !rev);
  else if (!strcmp (n, "cooked")) bst_raw (t, rev);
  else if (!strcmp (n, "sane") && !rev) bst_sane (t);
  else if (!strcmp (n, "cbreak")) bst_set_flag (t, rev ? "icanon" : "-icanon");
  else if (!strcmp (n, "evenp") || !strcmp (n, "parity"))
    { if (rev) BST_W ("-parenb", "cs8"); else BST_W ("parenb", "-parodd", "cs7"); }
  else if (!strcmp (n, "oddp"))
    { if (rev) BST_W ("-parenb", "cs8"); else BST_W ("parenb", "parodd", "cs7"); }
  else if (!strcmp (n, "nl"))
    { if (rev) BST_W ("icrnl", "-inlcr", "-igncr", "onlcr", "-ocrnl", "-onlret");
      else BST_W ("-icrnl", "-onlcr"); }
  else if (!strcmp (n, "ek") && !rev)
    { t->c_cc[VERASE] = 127; t->c_cc[VKILL] = BST_CTRL ('u'); }
  else if (!strcmp (n, "litout"))
    { if (rev) BST_W ("parenb", "istrip", "opost", "cs7"); else BST_W ("-parenb", "-istrip", "-opost", "cs8"); }
  else if (!strcmp (n, "pass8"))
    { if (rev) BST_W ("parenb", "istrip", "cs7"); else BST_W ("-parenb", "-istrip", "cs8"); }
  else if (!strcmp (n, "lcase") || !strcmp (n, "LCASE"))
    { if (rev) BST_W ("-xcase", "-iuclc", "-olcuc"); else BST_W ("xcase", "iuclc", "olcuc"); }
  else if (!strcmp (n, "tabs")) bst_set_flag (t, rev ? "tab3" : "tab0");
  else if (!strcmp (n, "crt") && !rev) BST_W ("echoe", "echoctl", "echoke");
  else if (!strcmp (n, "dec") && !rev)
    {
      BST_W ("echoe", "echoctl", "echoke", "-ixany");
      t->c_cc[VINTR] = BST_CTRL ('c');
      t->c_cc[VERASE] = 127;
      t->c_cc[VKILL] = BST_CTRL ('u');
    }
  else if (!strcmp (n, "decctlq")) bst_set_flag (t, rev ? "ixany" : "-ixany");
  else
    return -1;
#undef BST_W
  return 0;
}

/* GNU's control-character operand: one char, ^X, ^?, ^- / undef, or an
   integer (C syntax). */
static int
bst_cc_value (const char *s, cc_t *out)
{
  unsigned long v;
  if (s[0] && !s[1])
    v = (unsigned char) s[0];
  else if (!strcmp (s, "^-") || !strcmp (s, "undef"))
    v = _POSIX_VDISABLE;
  else if (s[0] == '^' && s[1] && !s[2])
    v = s[1] == '?' ? 127 : (unsigned char) s[1] & 037;
  else
    {
      char *end;
      errno = 0;
      v = strtoul (s, &end, 0);
      if (errno || end == s || *end || v > 255)
        return -1;
    }
  *out = (cc_t) v;
  return 0;
}

static const char *
bst_visible (cc_t c)
{
  static char buf[8];
  char *p = buf;
  if (c == _POSIX_VDISABLE)
    return "<undef>";
  if (c >= 128)
    {
      *p++ = 'M';
      *p++ = '-';
      c -= 128;
    }
  if (c < 32)
    {
      *p++ = '^';
      *p++ = (char) (c + '@');
    }
  else if (c == 127)
    {
      *p++ = '^';
      *p++ = '?';
    }
  else
    *p++ = (char) c;
  *p = '\0';
  return buf;
}

static void
bst_wrapf (const char *fmt, ...)
{
  char buf[128];
  va_list ap;
  va_start (ap, fmt);
  int len = vsnprintf (buf, sizeof buf, fmt, ap);
  va_end (ap);
  if (len < 0)
    return;
  if (bst_col > 0)
    {
      if (bst_max_col - bst_col <= len)
        {
          putchar ('\n');
          bst_col = 0;
        }
      else
        {
          putchar (' ');
          bst_col++;
        }
    }
  fputs (buf, stdout);
  bst_col += len;
}

static void
bst_newline (void)
{
  if (bst_col)
    putchar ('\n');
  bst_col = 0;
}

static void
bst_show_speed (const struct termios *t)
{
  speed_t is = cfgetispeed (t), os = cfgetospeed (t);
  if (is == 0 || is == os)
    bst_wrapf ("speed %lu baud;", bst_speed_baud (os));
  else
    bst_wrapf ("ispeed %lu baud; ospeed %lu baud;", bst_speed_baud (is), bst_speed_baud (os));
}

static void
bst_show (int fd, const struct termios *t, int all)
{
  bst_col = 0;
  bst_show_speed (t);
  if (all)
    {
      struct winsize ws;
      if (ioctl (fd, TIOCGWINSZ, &ws) == 0)
        bst_wrapf ("rows %u; columns %u;", (unsigned) ws.ws_row, (unsigned) ws.ws_col);
    }
  bst_wrapf ("line = %d;", (int) t->c_line);
  bst_newline ();

  int canon = (t->c_lflag & ICANON) != 0;
  for (const bst_cc *c = bst_ccs; c->name; c++)
    {
      if (c->offset == VMIN || c->offset == VTIME)
        continue;
      if (!all && t->c_cc[c->offset] == c->saneval)
        continue;
      bst_wrapf ("%s = %s;", c->name, bst_visible (t->c_cc[c->offset]));
    }
  if (all || !canon)
    bst_wrapf ("min = %u; time = %u;", (unsigned) t->c_cc[VMIN], (unsigned) t->c_cc[VTIME]);
  bst_newline ();

  int prev = -1;
  for (const bst_mode *m = bst_modes; m->name; m++)
    {
      if (m->flags & BST_OMIT)
        continue;
      if (m->type != prev)
        {
          bst_newline ();
          prev = m->type;
        }
      tcflag_t v = *bst_field ((struct termios *) t, m->type);
      tcflag_t mask = m->mask ? m->mask : m->bits;
      int set = (v & mask) == m->bits;
      if (all)
        {
          if (set)
            bst_wrapf ("%s", m->name);
          else if (m->flags & BST_REV)
            bst_wrapf ("-%s", m->name);
        }
      else if (set)
        {
          if (m->flags & BST_SANE_UNSET)
            bst_wrapf ("%s", m->name);
        }
      else if ((m->flags & (BST_SANE_SET | BST_REV)) == (BST_SANE_SET | BST_REV))
        bst_wrapf ("-%s", m->name);
    }
  bst_newline ();
}

static int
bst_parse_gnu_state (const char *s, struct termios *t)
{
  unsigned long v[4];
  const char *p = s;
  for (int i = 0; i < 4 + NCCS; i++)
    {
      char *end;
      errno = 0;
      unsigned long x = strtoul (p, &end, 16);
      if (errno || end == p || (*end != ':' && *end != '\0') || !isxdigit ((unsigned char) *p))
        return -1;
      if (i < 4)
        v[i] = x;
      else if (x > 255)
        return -1;
      else
        t->c_cc[i - 4] = (cc_t) x;
      if (*end == '\0')
        {
          if (i != 3 + NCCS)
            return -1;
          break;
        }
      p = end + 1;
    }
  t->c_iflag = (tcflag_t) v[0];
  t->c_oflag = (tcflag_t) v[1];
  t->c_cflag = (tcflag_t) v[2];
  t->c_lflag = (tcflag_t) v[3];
  return 0;
}

static int
bst_parse_ulong_arg (const char *name, const char *v, unsigned long max, unsigned long *out)
{
  if (!v)
    {
      fflush (stdout);
      fprintf (stderr, "stty: missing argument to '%s'\n", name);
      fputs ("Try 'stty --help' for more information.\n", stderr);
      return -1;
    }
  char *end;
  errno = 0;
  unsigned long x = strtoul (v, &end, 0);
  if (errno || end == v || *end || x > max || v[0] == '-')
    {
      fflush (stdout);
      fprintf (stderr, "stty: invalid integer argument: '%s'\n", v);
      return -1;
    }
  *out = x;
  return 0;
}

static void
bst_usage_hint (void)
{
  fputs ("Try 'stty --help' for more information.\n", stderr);
}

/* GNU's checking pass, run before the device is touched: unknown words,
   missing operands, bad speeds and asymmetric speeds fail even without a
   terminal. Integer operands are checked when applied. */
static int
bst_check (const char **modes, int nmodes)
{
  struct termios scratch;
  long is = -1, os = -1;
  memset (&scratch, 0, sizeof scratch);
  for (int k = 0; k < nmodes; k++)
    {
      const char *w = modes[k];
      const char *next = k + 1 < nmodes ? modes[k + 1] : NULL;
      speed_t sp;
      int takes = 0;
      for (const bst_cc *c = bst_ccs; c->name; c++)
        if (!strcmp (c->name, w))
          takes = 1;
      if (!strcmp (w, "rows") || !strcmp (w, "cols") || !strcmp (w, "columns") ||
          !strcmp (w, "line") || !strcmp (w, "ispeed") || !strcmp (w, "ospeed"))
        takes = 1;
      if (takes)
        {
          if (!next)
            {
              fflush (stdout);
              fprintf (stderr, "stty: missing argument to '%s'\n", w);
              bst_usage_hint ();
              return -1;
            }
          if (!strcmp (w, "ispeed") || !strcmp (w, "ospeed"))
            {
              if (bst_speed_code (next, &sp) < 0)
                {
                  fflush (stdout);
                  fprintf (stderr, "stty: invalid %s '%s'\n", w, next);
                  return -1;
                }
              if (w[0] == 'i') is = (long) sp; else os = (long) sp;
            }
          k++;
        }
      else if (!strcmp (w, "size") || !strcmp (w, "speed") || !strcmp (w, "drain") ||
               !strcmp (w, "-drain") || !strncmp (w, "bashtermraw2:", 13))
        ;
      else if (bst_set_flag (&scratch, w) == 0 || bst_combination (&scratch, w) == 0)
        ;
      else if (bst_speed_code (w, &sp) == 0)
        is = os = (long) sp;
      else if (!(strchr (w, ':') && bst_parse_gnu_state (w, &scratch) == 0))
        {
          fflush (stdout);
          fprintf (stderr, "stty: invalid argument '%s'\n", w);
          bst_usage_hint ();
          return -1;
        }
    }
  if (is > 0 && os >= 0 && is != os)
    {
      fflush (stdout);
      fprintf (stderr, "stty: asymmetric input (%lu), output (%lu) speeds not supported\n",
               bst_speed_baud ((speed_t) is), bst_speed_baud ((speed_t) os));
      return -1;
    }
  return 0;
}

static int
btr_stty (WORD_LIST *args)
{
  int all = 0, save = 0, nmodes = 0;
  bst_device = NULL;

  /* Pass 1: options. Mode words are applied in order afterwards. */
  int cap = 1;
  for (WORD_LIST *p = args; p; p = p->next)
    cap++;
  const char **modes = calloc ((size_t) cap, sizeof *modes);
  if (!modes)
    {
      bst_err ("out of memory", 0);
      return 1;
    }
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-a") || !strcmp (w, "--all")) all = 1;
      else if (!strcmp (w, "-g") || !strcmp (w, "--save")) save = 1;
      else if (!strcmp (w, "-ag") || !strcmp (w, "-ga")) all = save = 1;
      else if (!strncmp (w, "--file=", 7)) bst_device = w + 7;
      else if (!strncmp (w, "-F", 2) || !strcmp (w, "--file"))
        {
          if (w[1] == 'F' && w[2]) bst_device = w + 2;
          else if (p->next) { p = p->next; bst_device = p->word->word; }
          else
            {
              fflush (stdout);
              fprintf (stderr, "stty: option requires an argument -- 'F'\n");
              bst_usage_hint ();
              free (modes);
              return 1;
            }
        }
      else if (!strcmp (w, "--"))
        continue;
      else
        modes[nmodes++] = w;
    }
  if (all && save)
    {
      bst_err ("the options for verbose and stty-readable output styles are\nmutually exclusive", 0);
      free (modes);
      return 1;
    }
  if ((all || save) && nmodes)
    {
      bst_err ("when specifying an output style, modes may not be set", 0);
      free (modes);
      return 1;
    }

  if (bst_check (modes, nmodes) < 0)
    {
      free (modes);
      return 1;
    }

  int fd = 0, close_fd = 0;
  if (bst_device)
    {
      fd = open (bst_device, O_RDONLY | O_NONBLOCK | O_NOCTTY);
      if (fd < 0)
        {
          bst_err (bst_device, errno);
          free (modes);
          return 1;
        }
      close_fd = 1;
      int fl = fcntl (fd, F_GETFL);
      if (fl >= 0)
        (void) fcntl (fd, F_SETFL, fl & ~O_NONBLOCK);
    }
  int rc = 0;
  /* libc's struct may hold more control characters than the kernel
     fills (musl NCCS 32, kernel 19): zero it so -g and the read-back
     comparison never see stack bytes. */
  struct termios t, want;
  memset (&t, 0, sizeof t);
  if (tcgetattr (fd, &t) < 0)
    {
      bst_err (bst_devname (), errno);
      rc = 1;
      goto done;
    }
  {
    struct winsize ws;
    bst_max_col = 80;
    const char *cols = getenv ("COLUMNS");
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
      bst_max_col = ws.ws_col;
    else if (cols && atoi (cols) > 0)
      bst_max_col = atoi (cols);
  }

  if (save)
    {
      printf ("%lx:%lx:%lx:%lx", (unsigned long) t.c_iflag, (unsigned long) t.c_oflag,
              (unsigned long) t.c_cflag, (unsigned long) t.c_lflag);
      for (int i = 0; i < NCCS; i++)
        printf (":%lx", (unsigned long) t.c_cc[i]);
      putchar ('\n');
      goto done;
    }
  if (!nmodes)
    {
      bst_show (fd, &t, all);
      goto done;
    }

  want = t;
  int set_termios = 0, ws_rows = -1, ws_cols = -1;
  /* musl's cfsetispeed writes the output speed: track requests here. */
  long req_is = -1, req_os = -1;
  for (int k = 0; k < nmodes; k++)
    {
      const char *w = modes[k];
      const char *next = k + 1 < nmodes ? modes[k + 1] : NULL;
      unsigned long n;
      speed_t sp;
      const bst_cc *cc = NULL;
      for (const bst_cc *c = bst_ccs; c->name; c++)
        if (!strcmp (c->name, w))
          cc = c;
      if (cc)
        {
          if (!next)
            {
              fflush (stdout);
              fprintf (stderr, "stty: missing argument to '%s'\n", w);
              bst_usage_hint ();
              rc = 1;
              goto done;
            }
          cc_t v;
          if (cc->offset == VMIN || cc->offset == VTIME)
            {
              if (bst_parse_ulong_arg (w, next, 255, &n) < 0) { rc = 1; goto done; }
              v = (cc_t) n;
            }
          else if (bst_cc_value (next, &v) < 0)
            {
              fflush (stdout);
              fprintf (stderr, "stty: invalid integer argument: '%s'\n", next);
              rc = 1;
              goto done;
            }
          want.c_cc[cc->offset] = v;
          set_termios = 1;
          k++;
        }
      else if (!strcmp (w, "rows") || !strcmp (w, "cols") || !strcmp (w, "columns"))
        {
          if (bst_parse_ulong_arg (w, next, 65535, &n) < 0) { rc = 1; goto done; }
          if (w[0] == 'r') ws_rows = (int) n; else ws_cols = (int) n;
          k++;
        }
      else if (!strcmp (w, "ispeed") || !strcmp (w, "ospeed"))
        {
          if (!next || bst_speed_code (next, &sp) < 0)
            {
              fflush (stdout);
              if (next) fprintf (stderr, "stty: invalid %s '%s'\n", w, next);
              else fprintf (stderr, "stty: missing argument to '%s'\n", w);
              rc = 1;
              goto done;
            }
          if (w[0] == 'i') req_is = (long) sp; else req_os = (long) sp;
          set_termios = 1;
          k++;
        }
      else if (!strcmp (w, "line"))
        {
          if (bst_parse_ulong_arg (w, next, 255, &n) < 0) { rc = 1; goto done; }
          want.c_line = (cc_t) n;
          set_termios = 1;
          k++;
        }
      else if (!strcmp (w, "size") || !strcmp (w, "speed"))
        {
          /* Readers run against the settings applied so far. */
          if (set_termios && tcsetattr (fd, TCSADRAIN, &want) < 0)
            {
              bst_err (bst_devname (), errno);
              rc = 1;
              goto done;
            }
          if (w[1] == 'i')
            {
              struct winsize ws;
              if (ioctl (fd, TIOCGWINSZ, &ws) < 0)
                {
                  bst_err (bst_devname (), errno);
                  rc = 1;
                  goto done;
                }
              printf ("%u %u\n", (unsigned) ws.ws_row, (unsigned) ws.ws_col);
            }
          else
            printf ("%lu\n", bst_speed_baud (cfgetospeed (&want)));
        }
      else if (!strcmp (w, "drain") || !strcmp (w, "-drain"))
        ;
      else if (bst_set_flag (&want, w) == 0 || bst_combination (&want, w) == 0)
        set_termios = 1;
      else if (bst_speed_code (w, &sp) == 0)
        {
          req_is = req_os = (long) sp;
          set_termios = 1;
        }
      else if (strchr (w, ':') && bst_parse_gnu_state (w, &want) == 0)
        set_termios = 1;
      else if (!strncmp (w, "bashtermraw2:", 13))
        {
          if (set_termios && tcsetattr (fd, TCSADRAIN, &want) < 0)
            {
              bst_err (bst_devname (), errno);
              rc = 1;
              goto done;
            }
          if (btr_stty_set (w) != 0) { rc = 1; goto done; }
          memset (&want, 0, sizeof want);
          if (tcgetattr (fd, &want) < 0) { bst_err (bst_devname (), errno); rc = 1; goto done; }
          set_termios = 0;
        }
      else
        {
          fflush (stdout);
          fprintf (stderr, "stty: invalid argument '%s'\n", w);
          bst_usage_hint ();
          rc = 1;
          goto done;
        }
    }

  if (req_is >= 0 || req_os >= 0)
    {
      speed_t is = req_is >= 0 ? (speed_t) req_is : cfgetispeed (&t);
      speed_t os = req_os >= 0 ? (speed_t) req_os : cfgetospeed (&t);
      if (is != 0 && is != os)
        {
          fflush (stdout);
          fprintf (stderr, "stty: asymmetric input (%lu), output (%lu) speeds not supported\n",
                   bst_speed_baud (is), bst_speed_baud (os));
          rc = 1;
          goto done;
        }
      cfsetospeed (&want, os);
      cfsetispeed (&want, os);
    }
  if (set_termios)
    {
      if (tcsetattr (fd, TCSADRAIN, &want) < 0)
        {
          bst_err (bst_devname (), errno);
          rc = 1;
          goto done;
        }
      /* tcsetattr succeeds if any change applied; GNU re-reads and
         reports what the driver refused. */
      struct termios got;
      memset (&got, 0, sizeof got);
      if (tcgetattr (fd, &got) < 0)
        {
          bst_err (bst_devname (), errno);
          rc = 1;
          goto done;
        }
      if (got.c_iflag != want.c_iflag || got.c_oflag != want.c_oflag ||
          got.c_cflag != want.c_cflag || got.c_lflag != want.c_lflag || memcmp (got.c_cc, want.c_cc, sizeof got.c_cc))
        {
          fflush (stdout);
          fprintf (stderr, "stty: %s: unable to perform all requested operations\n", bst_devname ());
          rc = 1;
        }
    }
  if (ws_rows >= 0 || ws_cols >= 0)
    {
      struct winsize ws;
      if (ioctl (fd, TIOCGWINSZ, &ws) < 0)
        memset (&ws, 0, sizeof ws);
      if (ws_rows >= 0) ws.ws_row = (unsigned short) ws_rows;
      if (ws_cols >= 0) ws.ws_col = (unsigned short) ws_cols;
      if (ioctl (fd, TIOCSWINSZ, &ws) < 0)
        {
          bst_err (bst_devname (), errno);
          rc = 1;
        }
    }

done:
  free (modes);
  if (close_fd)
    close (fd);
  fflush (stdout);
  return rc;
}

int
bashtermraw_builtin (WORD_LIST *list)
{
  if (list == 0)
    {
      builtin_usage ();
      return (EX_USAGE);
    }

  if (list && (!strcmp (list->word->word, "--help") || !strcmp (list->word->word, "-h")))
    {
      char *const *dp;
      for (dp = bashtermraw_doc; *dp; dp++)
        puts (*dp);
      return (EX_USAGE);
    }

  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "raw") == 0)        return btr_raw () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "cooked") == 0)     return btr_cooked () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "size") == 0)       return btr_size () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "resize") == 0)
    {
      if (!args || !args->next)
        { builtin_error ("resize: ROWS and COLS arguments required"); return (EX_USAGE); }
      return btr_resize (args->word->word, args->next->word->word) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "stty") == 0)       return btr_stty (args) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "stty-g") == 0)     return btr_stty_g () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "stty-set") == 0)
    {
      if (!args) { builtin_error ("stty-set: STATE argument required"); return (EX_USAGE); }
      return btr_stty_set (args->word->word) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "keypress") == 0)   return btr_keypress () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clr-eol") == 0)    return btr_clr_eol () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clr-screen") == 0) return btr_clr_screen () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clear") == 0)      return btr_clear (args) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "reset") == 0)      return btr_reset (args) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

  if (strcmp (cmd, "cup") == 0)
    {
      if (!args || !args->next)
        {
          builtin_error ("cup: ROW and COL arguments required");
          return (EX_USAGE);
        }
      int row = atoi (args->word->word);
      int col = atoi (args->next->word->word);
      return btr_cup (row, col) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "show") == 0)
    {
      int on = 1;
      if (args)
        {
          const char *v = args->word->word;
          if (strcmp (v, "off") == 0 || strcmp (v, "0") == 0) on = 0;
          else if (strcmp (v, "on") == 0 || strcmp (v, "1") == 0) on = 1;
          else { builtin_error ("show: argument must be on|off"); return (EX_USAGE); }
        }
      return btr_cursor_show (on) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "paste") == 0)
    {
      if (!args)
        {
          builtin_error ("paste: argument must be on|off");
          return (EX_USAGE);
        }
      const char *v = args->word->word;
      int on;
      if (strcmp (v, "off") == 0 || strcmp (v, "0") == 0) on = 0;
      else if (strcmp (v, "on") == 0 || strcmp (v, "1") == 0) on = 1;
      else { builtin_error ("paste: argument must be on|off"); return (EX_USAGE); }
      return btr_bracketed_paste (on) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  builtin_error ("unknown subcommand: %s", cmd);
  builtin_usage ();
  return (EX_USAGE);
}

char *bashtermraw_doc[] = {
  "termios primitives + ANSI key decoder for bash-os TUI scripts.",
  "",
  "Subcommands:",
  "    raw                save current termios + switch to raw mode",
  "                       (no echo, no canon, VMIN=1 VTIME=0)",
  "    cooked             restore termios saved by `raw`, or a sane",
  "                       canonical default if none saved",
  "    size               echo \"ROWS COLS\" (TIOCGWINSZ)",
  "    stty [-F DEV] [-a|-g|SETTING...]",
  "                       GNU stty on stdin (or DEV): every termios flag,",
  "                       raw/cooked/sane/cbreak and other combinations,",
  "                       control characters, speeds, rows/cols, -g state",
  "    stty-g             echo saveable full termios state string",
  "    stty-set STATE     restore state emitted by stty-g",
  "    resize ROWS COLS   set the window size (TIOCSWINSZ)",
  "    keypress           read one key, echo decoded name on stdout",
  "                       (UP / DOWN / F1 / C-x / TAB / RET / ESC /",
  "                       BS / DEL / S-UP / C-LEFT / M-a / printable /",
  "                       PASTE-START / PASTE-END for bracketed paste)",
  "    cup ROW COL        write CSI cursor-position (1-indexed)",
  "    clr-eol            CSI K (clear from cursor to EOL)",
  "    clr-screen         CSI 2J + CSI H (clear screen + home)",
  "    clear [-x|--no-scrollback]",
  "                       erase-scrollback + cursor-home + erase-display",
  "                       (CSI 3J + CSI H + CSI 2J; --no-scrollback omits 3J)",
  "                       Run by the /bin shim as clear, it is ncurses clear:",
  "                       [-x] [-T TERM], the TERM sequence on stdout.",
  "    reset [-q]         RIS/recovery sequences + restore sane canonical termios.",
  "                       Stronger than clear; recovers from corruption.",
  "    show [on|off]      show/hide cursor (CSI ?25 h/l), default on",
  "    paste on|off       enable/disable bracketed paste mode",
  "                       (CSI ?2004 h/l); when on, `keypress` decodes",
  "                       paste boundaries as PASTE-START / PASTE-END",
  "",
  "Terminal I/O goes to /dev/tty (or stdin if /dev/tty is unavailable),",
  "so `bashtermraw cup 5 3 > /dev/null` still moves the visible cursor.",
  "",
  "Typical TUI loop:",
  "    bashtermraw raw",
  "    trap 'bashtermraw cooked' EXIT",
  "    while k=$(bashtermraw keypress); do",
  "        case \"$k\" in",
  "            UP)    ... ;;",
  "            q)     break ;;",
  "        esac",
  "    done",
  (char *) NULL
};

struct builtin bashtermraw_struct = {
  "bashtermraw",
  bashtermraw_builtin,
  BUILTIN_ENABLED,
  bashtermraw_doc,
  "bashtermraw raw|cooked|size|resize ROWS COLS|stty [-F DEV] [-a|-g|SETTING...]|stty-g|stty-set STATE|keypress|cup ROW COL|clr-eol|clr-screen|clear|reset|show [on|off]|paste on|off",
  0
};
