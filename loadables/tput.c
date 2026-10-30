/* SPDX-License-Identifier: MIT */
/* tput.c - small terminfo-shaped capability builtin for bash-os.
 *
 * Curated ANSI/xterm names come from the built-in table. Operators can
 * add key=value sidecars. Before an unknown terminal is rejected, a
 * compiled terminfo entry is loaded from TERMINFO, ~/.terminfo,
 * TERMINFO_DIRS, or the system database, aliases included. A loaded
 * entry supplies its standard and extended capabilities. Mandatory
 * padding is applied from the output baud rate.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <termios.h>
#include <time.h>

#include "loadables.h"

#define BTP_MAX_SIDE_CAPS 96
#define BTP_MAX_NAME 64
#define BTP_MAX_VALUE 256
#define BTP_DEFAULT_DIR "/etc/bash-os/terminfo.d"
#define BTP_COMPAT_DIR "/etc/bash-os/terminfo"

static const char *terms[] = {
  "xterm-256color", "xterm", "screen-256color", "tmux-256color", "linux", "vt100", "dumb", NULL
};

static const char *caps[] = {
  "clear", "home", "cup", "cuu", "cud", "cuf", "cub", "el", "el1", "ed",
  "bold", "smso", "dim", "smul", "rmul", "rev", "blink", "invis", "sgr0",
  "sgr", "sitm", "ritm", "setaf", "setab", "civis", "cnorm", "smcup",
  "rmcup", "smkx", "rmkx", "smacs", "rmacs", "acsc", "sc", "rc",
  "hpa", "vpa", "ich", "dch", "dl", "il", "kf1", "kf2", "kf3", "kf4",
  "kf5", "kf6", "kf7", "kf8", "kf9", "kf10", "kf11", "kf12", "cols",
  "lines", "colors", "longname", "reset", "init",
  "am", "bw", "xenl", "bce", "km", "mir", "msgr", "xon", "ccc",
  "hc", "npc", "hs", NULL
};

typedef struct {
  char key[BTP_MAX_NAME];
  char val[BTP_MAX_VALUE];
} sidecap;

typedef struct {
  int loaded;
  int found;
  int ncap;
  char name[BTP_MAX_NAME];
  sidecap caps[BTP_MAX_SIDE_CAPS];
} sideterm;

static int
safe_term_name (const char *term)
{
  const unsigned char *p = (const unsigned char *) term;
  if (!term || !*term || strlen (term) >= BTP_MAX_NAME)
    return 0;
  for (; *p; p++)
    if (!(isalnum (*p) || *p == '-' || *p == '_' || *p == '.' || *p == '+'))
      return 0;
  return 1;
}

static char *
trim_ws (char *s)
{
  char *e;
  while (*s && isspace ((unsigned char) *s))
    s++;
  e = s + strlen (s);
  while (e > s && isspace ((unsigned char) e[-1]))
    *--e = '\0';
  return s;
}

static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void
decode_escapes (const char *in, char *out, size_t outsz)
{
  size_t o = 0;
  while (*in && o + 1 < outsz)
    {
      if (*in == '\\')
        {
          int h1, h2;
          in++;
          if (!*in) break;
          switch (*in)
            {
            case 'E': case 'e': out[o++] = '\033'; in++; continue;
            case 'n': out[o++] = '\n'; in++; continue;
            case 'r': out[o++] = '\r'; in++; continue;
            case 't': out[o++] = '\t'; in++; continue;
            case 'b': out[o++] = '\b'; in++; continue;
            case 'f': out[o++] = '\f'; in++; continue;
            case '\\': out[o++] = '\\'; in++; continue;
            case 'x':
              h1 = hexval ((unsigned char) in[1]);
              h2 = hexval ((unsigned char) in[2]);
              if (h1 >= 0 && h2 >= 0)
                {
                  out[o++] = (char) ((h1 << 4) | h2);
                  in += 3;
                  continue;
                }
              break;
            }
        }
      out[o++] = *in++;
    }
  out[o] = '\0';
}

static const char *
side_dir_primary (void)
{
  const char *d = getenv ("BASHTPUT_TERMINFO_DIR");
  return (d && *d) ? d : BTP_DEFAULT_DIR;
}

static int
load_side_from_dir (sideterm *st, const char *dir, const char *term)
{
  char path[512], line[512];
  FILE *f;
  int saw_name = 0;
  snprintf (path, sizeof path, "%s/%s", dir, term);
  f = fopen (path, "r");
  if (!f)
    return 0;
  st->found = 1;
  snprintf (st->name, sizeof st->name, "%s", term);
  while (fgets (line, sizeof line, f))
    {
      char *s = trim_ws (line);
      char *eq, *key, *val;
      if (!*s || *s == '#')
        continue;
      eq = strchr (s, '=');
      if (!eq)
        continue;
      *eq = '\0';
      key = trim_ws (s);
      val = trim_ws (eq + 1);
      if (!safe_term_name (key))
        continue;
      if (!strcmp (key, "name"))
        {
          snprintf (st->name, sizeof st->name, "%s", val);
          saw_name = 1;
          continue;
        }
      if (st->ncap < BTP_MAX_SIDE_CAPS)
        {
          snprintf (st->caps[st->ncap].key, sizeof st->caps[st->ncap].key, "%s", key);
          decode_escapes (val, st->caps[st->ncap].val, sizeof st->caps[st->ncap].val);
          st->ncap++;
        }
    }
  fclose (f);
  if (!saw_name)
    snprintf (st->name, sizeof st->name, "%s", term);
  return 1;
}

static int
load_side_term (sideterm *st, const char *term)
{
  memset (st, 0, sizeof *st);
  st->loaded = 1;
  if (!safe_term_name (term))
    return 0;
  if (load_side_from_dir (st, side_dir_primary (), term))
    return 1;
  if (strcmp (side_dir_primary (), BTP_COMPAT_DIR) &&
      load_side_from_dir (st, BTP_COMPAT_DIR, term))
    return 1;
  return 0;
}

static const char *
side_lookup (const sideterm *st, const char *cap)
{
  int i;
  if (!st || !st->found || !cap)
    return NULL;
  for (i = 0; i < st->ncap; i++)
    if (!strcmp (st->caps[i].key, cap))
      return st->caps[i].val;
  return NULL;
}

static int
known_term (const char *term)
{
  int i;
  if (!term || !*term) return 1;
  for (i = 0; terms[i]; i++)
    if (!strcmp (term, terms[i])) return 1;
  return 0;
}

/* Curated boolean values, qualified against the same terminal profiles as
 * the string table.  Bit positions follow terms[].  A missing boolean is
 * false, not an unknown cap-code. */
static const struct {
  const char *code;
  const char *alias;
  unsigned int terminals;
} boolcaps[] = {
  { "am", "auto_right_margin", 0x7f },
  { "bw", "auto_left_margin", 0 },
  { "xenl", "eat_newline_glitch", 0x3f },
  { "bce", "back_color_erase", 0x13 },
  { "km", "has_meta_key", 0x0f },
  { "mir", "move_insert_mode", 0x1f },
  { "msgr", "move_standout_mode", 0x3f },
  { "xon", "xon_xoff", 0x30 },
  { "ccc", "can_change", 0x11 },
  { "hc", "hard_copy", 0 },
  { "npc", "no_pad_char", 0x03 },
  { "hs", "has_status_line", 0x08 }
};

static int
boolean_index (const char *cap)
{
  int i;
  for (i = 0; i < (int) (sizeof boolcaps / sizeof boolcaps[0]); i++)
    if (!strcmp (cap, boolcaps[i].code) || !strcmp (cap, boolcaps[i].alias))
      return i;
  return -1;
}

static int
known_cap (const char *cap)
{
  int i;
  if (!cap) return 0;
  if (boolean_index (cap) >= 0) return 1;
  for (i = 0; caps[i]; i++)
    if (!strcmp (cap, caps[i])) return 1;
  if (!strcmp (cap, "clear_screen") || !strcmp (cap, "cursor_home")
      || !strcmp (cap, "cursor_address") || !strcmp (cap, "cursor_up")
      || !strcmp (cap, "cursor_down") || !strcmp (cap, "cursor_right")
      || !strcmp (cap, "cursor_left") || !strcmp (cap, "clr_eol")
      || !strcmp (cap, "clr_bol") || !strcmp (cap, "clr_eos")
      || !strcmp (cap, "rmso") || !strcmp (cap, "enter_standout_mode")
      || !strcmp (cap, "exit_standout_mode") || !strcmp (cap, "enter_bold_mode")
      || !strcmp (cap, "enter_italics_mode") || !strcmp (cap, "exit_italics_mode")
      || !strcmp (cap, "save_cursor") || !strcmp (cap, "restore_cursor")
      || !strcmp (cap, "parm_ich") || !strcmp (cap, "parm_dch")
      || !strcmp (cap, "parm_delete_line") || !strcmp (cap, "parm_insert_line")
      || !strcmp (cap, "column_address") || !strcmp (cap, "row_address")
      || !strcmp (cap, "key_f1") || !strcmp (cap, "key_f2")
      || !strcmp (cap, "key_f3") || !strcmp (cap, "key_f4")
      || !strcmp (cap, "key_f5") || !strcmp (cap, "key_f6")
      || !strcmp (cap, "key_f7") || !strcmp (cap, "key_f8")
      || !strcmp (cap, "key_f9") || !strcmp (cap, "key_f10")
      || !strcmp (cap, "key_f11") || !strcmp (cap, "key_f12")
      || !strcmp (cap, "columns") || !strcmp (cap, "rows"))
    return 1;
  return 0;
}

static int
bind_or_print (const char *var, const char *s, int newline)
{
  if (var)
    {
      builtin_bind_variable ((char *) var, (char *) s, 0);
      return EXECUTION_SUCCESS;
    }
  fputs (s, stdout);
  if (newline) putchar ('\n');
  return EXECUTION_SUCCESS;
}

static int
side_expand (const char *tmpl, WORD_LIST *args, char *out, size_t outsz)
{
  int p[9] = {0};
  int i = 0, inc = 0;
  size_t o = 0;
  while (args && i < 9)
    {
      p[i++] = atoi (args->word->word);
      args = args->next;
    }
  for (i = 0; i < 9; i++)
    p[i] += inc;
  while (*tmpl && o + 1 < outsz)
    {
      if (*tmpl == '%' && tmpl[1])
        {
          tmpl++;
          if (*tmpl == 'i')
            {
              int j;
              inc = 1;
              for (j = 0; j < 9; j++)
                p[j]++;
              tmpl++;
              continue;
            }
          if (*tmpl == 'p' && tmpl[1] >= '1' && tmpl[1] <= '9')
            {
              int idx = tmpl[1] - '1';
              tmpl += 2;
              if (*tmpl == '%' && tmpl[1] == 'd')
                {
                  int n = snprintf (out + o, outsz - o, "%d", p[idx]);
                  if (n < 0) return -1;
                  o += (size_t) n;
                  if (o >= outsz) o = outsz - 1;
                  tmpl += 2;
                  continue;
                }
            }
          if (*tmpl == '%')
            {
              out[o++] = *tmpl++;
              continue;
            }
        }
      out[o++] = *tmpl++;
    }
  out[o] = '\0';
  return 0;
}

static int
emit_side_cap (const sideterm *st, const char *cap, WORD_LIST *args,
               const char *var)
{
  char buf[512];
  const char *tmpl = side_lookup (st, cap);
  if (!tmpl)
    return -1;
  if (side_expand (tmpl, args, buf, sizeof buf) < 0)
    return EX_USAGE;
  return bind_or_print (var, buf, 0);
}

/* Raw templates are observable CLI data when no arguments are supplied.
 * Keep profile-specific templates here rather than assuming ANSI defaults.
 * These strings describe the curated entries, not a compiled terminfo parser. */
static const char *
parameter_template (const char *cap, const char *term)
{
  int xterm = !strncmp (term, "xterm", 5);
  if (!strcmp (cap, "cup")) return "\033[%i%p1%d;%p2%dH";
  if (!strcmp (cap, "cuu")) return "\033[%p1%dA";
  if (!strcmp (cap, "cud")) return "\033[%p1%dB";
  if (!strcmp (cap, "cuf")) return "\033[%p1%dC";
  if (!strcmp (cap, "cub")) return "\033[%p1%dD";
  if (!strcmp (cap, "hpa")) return "\033[%i%p1%dG";
  if (!strcmp (cap, "vpa")) return "\033[%i%p1%dd";
  if (!strcmp (cap, "ich")) return "\033[%p1%d@";
  if (!strcmp (cap, "dch")) return "\033[%p1%dP";
  if (!strcmp (cap, "dl")) return "\033[%p1%dM";
  if (!strcmp (cap, "il")) return "\033[%p1%dL";
  if (!strcmp (cap, "setaf") || !strcmp (cap, "setab"))
    {
      int fg = !strcmp (cap, "setaf");
      if (!strcmp (term, "xterm") || !strcmp (term, "linux"))
        return fg ? "\033[3%p1%dm" : "\033[4%p1%dm";
      return fg
        ? "\033[%?%p1%{8}%<%t3%p1%d%e%p1%{16}%<%t9%p1%{8}%-%d%e38;5;%p1%d%;m"
        : "\033[%?%p1%{8}%<%t4%p1%d%e%p1%{16}%<%t10%p1%{8}%-%d%e48;5;%p1%d%;m";
    }
  if (!strcmp (cap, "sgr"))
    {
      if (xterm)
        return "%?%p9%t\033(0%e\033(B%;\033[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p7%t;8%;m";
      if (!strcmp (term, "linux"))
        return "\033[0;10%?%p1%t;7%;%?%p2%t;4%;%?%p3%t;7%;%?%p4%t;5%;%?%p5%t;2%;%?%p6%t;1%;m%?%p9%t\016%e\017%;";
      if (!strcmp (term, "screen-256color"))
        return "\033[0%?%p6%t;1%;%?%p1%t;3%;%?%p2%t;4%;%?%p3%t;7%;%?%p4%t;5%;%?%p5%t;2%;m%?%p9%t\016%e\017%;";
      if (!strcmp (term, "vt100"))
        return "\033[0%?%p1%p6%|%t;1%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;m%?%p9%t\016%e\017%;";
      return "\033[0%?%p6%t;1%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p5%t;2%;%?%p7%t;8%;m%?%p9%t\016%e\017%;";
    }
  return NULL;
}

static const char *
parameter_code (const char *cap)
{
  static const char *aliases[][2] = {
    { "cursor_address", "cup" }, { "cursor_up", "cuu" },
    { "cursor_down", "cud" }, { "cursor_right", "cuf" },
    { "cursor_left", "cub" }, { "column_address", "hpa" },
    { "row_address", "vpa" }, { "parm_ich", "ich" },
    { "parm_dch", "dch" }, { "parm_delete_line", "dl" },
    { "parm_insert_line", "il" }
  };
  int i;
  for (i = 0; i < (int) (sizeof aliases / sizeof aliases[0]); i++)
    if (!strcmp (cap, aliases[i][0])) return aliases[i][1];
  return cap;
}

/* Compiled terminfo is resolved before the unknown-terminal return.
 * A loaded entry supplies standard and extended capabilities. Mandatory
 * $<N/> delays become floor(ms * baud / 9000) pad bytes, or a sleep when
 * the entry sets npc. Non-mandatory $<N> delays are omitted. init, reset,
 * and the environment-backed size queries stay on the curated path. */
#define TP_MAX_OUT (512 * 1024)

extern int bt_compiled_lookup (const char *term, const char *cap,
                               int *flag, int32_t *num, char **str, int *npc);

static int
tp_leave_curated (const char *cap)
{
  return !strcmp (cap, "init") || !strcmp (cap, "reset")
      || !strcmp (cap, "cols") || !strcmp (cap, "columns")
      || !strcmp (cap, "lines") || !strcmp (cap, "rows");
}

static int
tp_string_supported (const char *s)
{
  while (*s)
    {
      if (s[0] == '$' && s[1] == '<')
        {
          const char *end = strchr (s + 2, '>');
          if (end) { s = end + 1; continue; }
        }
      if (s[0] == '%' && s[1])
        {
          if (s[1] == '%' || s[1] == 'i' || s[1] == 'd' || s[1] == 's' || s[1] == 'c')
            { s += 2; continue; }
          if (s[1] == 'p' && s[2] >= '1' && s[2] <= '9')
            { s += 3; continue; }
          return 0;
        }
      s++;
    }
  return 1;
}

static int
tp_baud (void)
{
  struct termios tio;
  speed_t speed;

  if (tcgetattr (STDOUT_FILENO, &tio) < 0)
    return 0;
  speed = cfgetospeed (&tio);
  switch (speed)
    {
    case B0: return 0;
    case B50: return 50;
    case B75: return 75;
    case B110: return 110;
    case B134: return 134;
    case B150: return 150;
    case B200: return 200;
    case B300: return 300;
    case B600: return 600;
    case B1200: return 1200;
    case B1800: return 1800;
    case B2400: return 2400;
    case B4800: return 4800;
    case B9600: return 9600;
    case B19200: return 19200;
    case B38400: return 38400;
#ifdef B57600
    case B57600: return 57600;
#endif
#ifdef B115200
    case B115200: return 115200;
#endif
#ifdef B230400
    case B230400: return 230400;
#endif
    default: return 0;
    }
}

struct tp_out {
  char *data;
  size_t len;
  size_t cap;
};

static int
tp_out_add (struct tp_out *o, const void *bytes, size_t n)
{
  size_t want;
  char *grown;

  if (n > TP_MAX_OUT || o->len > TP_MAX_OUT - n)
    return -1;
  want = o->len + n + 1;
  if (want > o->cap)
    {
      size_t cap = o->cap ? o->cap : 64;
      while (cap < want)
        {
          if (cap > TP_MAX_OUT / 2) { cap = want; break; }
          cap *= 2;
        }
      grown = realloc (o->data, cap);
      if (!grown) return -1;
      o->data = grown;
      o->cap = cap;
    }
  if (n && bytes)
    memcpy (o->data + o->len, bytes, n);
  o->len += n;
  o->data[o->len] = '\0';
  return 0;
}

static int
tp_out_pad (struct tp_out *o, const char *var, int npc, long whole, long frac, long scale)
{
  long num, den, nuls;
  int baud;

  if (scale < 1) scale = 1;
  num = whole * scale + frac;
  if (num < 0) num = 0;
  if (var)
    return 0;
  if (npc)
    {
      struct timespec ts;
      long ms = num / scale;
      long usec = ((num % scale) * 1000000L) / scale;
      if (o->len)
        {
          fwrite (o->data, 1, o->len, stdout);
          o->len = 0;
          if (o->data) o->data[0] = '\0';
        }
      fflush (stdout);
      ts.tv_sec = ms / 1000;
      ts.tv_nsec = (ms % 1000) * 1000000L + usec * 1000L;
      if (ts.tv_nsec >= 1000000000L)
        {
          ts.tv_sec += ts.tv_nsec / 1000000000L;
          ts.tv_nsec %= 1000000000L;
        }
      nanosleep (&ts, NULL);
      return 0;
    }
  baud = tp_baud ();
  den = 9000L * scale;
  nuls = den > 0 ? (num * (long) baud) / den : 0;
  while (nuls-- > 0)
    if (tp_out_add (o, "", 1) < 0)
      return -1;
  return 0;
}

static int
tp_expand_compiled (const char *tmpl, WORD_LIST *args, const char *var,
                    int npc, struct tp_out *o)
{
  const char *pstr[9];
  int pnum[9];
  struct { int num; const char *str; } stack[16];
  int i, sp;

  for (i = 0; i < 9; i++)
    {
      pstr[i] = "";
      pnum[i] = 0;
    }
  i = 0;
  while (args && i < 9)
    {
      pstr[i] = (args->word && args->word->word) ? args->word->word : "";
      pnum[i] = atoi (pstr[i]);
      i++;
      args = args->next;
    }
  sp = 0;
  while (*tmpl)
    {
      if (tmpl[0] == '$' && tmpl[1] == '<')
        {
          const char *start = tmpl;
          const char *p = tmpl + 2;
          const char *end = strchr (p, '>');
          long whole = 0, frac = 0, scale = 1;
          int seen_dot = 0, mandatory = 0, ok = 1;
          if (!end) { if (tp_out_add (o, tmpl, 1) < 0) return -1; tmpl++; continue; }
          while (p < end)
            {
              if (*p >= '0' && *p <= '9')
                {
                  if (!seen_dot) whole = whole * 10 + (*p - '0');
                  else { frac = frac * 10 + (*p - '0'); scale *= 10; }
                }
              else if (*p == '.' && !seen_dot)
                seen_dot = 1;
              else if (*p == '/')
                mandatory = 1;
              else if (*p == '*')
                ;
              else
                ok = 0;
              p++;
            }
          tmpl = end + 1;
          if (!ok)
            {
              if (tp_out_add (o, start, (size_t) (tmpl - start)) < 0) return -1;
              continue;
            }
          if (mandatory && tp_out_pad (o, var, npc, whole, frac, scale) < 0)
            return -1;
          continue;
        }
      if (tmpl[0] != '%' || tmpl[1] == '\0')
        {
          if (tp_out_add (o, tmpl, 1) < 0) return -1;
          tmpl++;
          continue;
        }
      tmpl++;
      if (*tmpl == '%')
        {
          if (tp_out_add (o, tmpl, 1) < 0) return -1;
          tmpl++;
          continue;
        }
      if (*tmpl == 'i')
        {
          pnum[0]++;
          pnum[1]++;
          tmpl++;
          continue;
        }
      if (*tmpl == 'p' && tmpl[1] >= '1' && tmpl[1] <= '9')
        {
          int idx = tmpl[1] - '1';
          if (sp >= (int) (sizeof stack / sizeof stack[0])) return -1;
          stack[sp].num = pnum[idx];
          stack[sp].str = pstr[idx];
          sp++;
          tmpl += 2;
          continue;
        }
      if (*tmpl == 'd' || *tmpl == 's' || *tmpl == 'c')
        {
          char kind = *tmpl++;
          int num;
          const char *str;
          char digits[32];
          int wrote;
          if (sp <= 0) return -1;
          sp--;
          num = stack[sp].num;
          str = stack[sp].str ? stack[sp].str : "";
          if (kind == 's')
            {
              if (tp_out_add (o, str, strlen (str)) < 0) return -1;
            }
          else if (kind == 'c')
            {
              char ch = (char) (num & 0xff);
              if (tp_out_add (o, &ch, 1) < 0) return -1;
            }
          else
            {
              wrote = snprintf (digits, sizeof digits, "%d", num);
              if (wrote < 0 || tp_out_add (o, digits, (size_t) wrote) < 0) return -1;
            }
          continue;
        }
      if (tp_out_add (o, "%", 1) < 0 || tp_out_add (o, tmpl, 1) < 0) return -1;
      tmpl++;
    }
  return 0;
}

/* -1: no compiled entry, or this capability stays on the curated path.
   Otherwise a tput status. */
static int
emit_compiled (const char *term, const char *cap, WORD_LIST *args, const char *var)
{
  int flag = 0, npc = 0, kind;
  int32_t num = 0;
  char *str = NULL;
  struct tp_out out;
  int rc;

  if (!safe_term_name (term))
    return -1;
  kind = bt_compiled_lookup (term, cap, &flag, &num, &str, &npc);
  if (kind < 0)
    return -1;
  if (kind == 4)
    {
      if (known_term (term))
        return -1;
      fprintf (stderr, "tput: unknown terminfo capability '%s'\n", cap);
      return 4;
    }
  if (kind == 0)
    return flag ? 0 : 1;
  if (kind == 1)
    {
      char text[32];
      snprintf (text, sizeof text, "%d", (int) num);
      return bind_or_print (var, text, var ? 0 : 1);
    }
  if (!str)
    return -1;
  if (!tp_string_supported (str) && known_cap (cap) && known_term (term))
    {
      free (str);
      return -1;
    }
  memset (&out, 0, sizeof out);
  rc = tp_expand_compiled (str, args, var, npc, &out);
  free (str);
  if (rc < 0)
    {
      free (out.data);
      return 2;
    }
  if (var)
    rc = bind_or_print (var, out.data ? out.data : "", 0);
  else if (out.len && fwrite (out.data, 1, out.len, stdout) != out.len)
    rc = 2;
  else
    rc = 0;
  free (out.data);
  return rc;
}

extern char *tput_doc[];   /* forward decl */

static int
emit_cap (const char *cap, WORD_LIST *args, const char *var, const char *term, int explicit_term)
{
  char buf[128];
  const char *tmpl;
  int n, r, c, bi;
  sideterm st;

  memset (&st, 0, sizeof st);
  if (!term || !*term)
    {
      builtin_error ("no terminal type specified");
      return 2;
    }
  if (!tp_leave_curated (cap))
    {
      int crc = emit_compiled (term, cap, args, var);
      if (crc >= 0)
        return crc;
    }
  if (!known_term (term) && !load_side_term (&st, term))
    {
      fprintf (stderr, "tput: unknown terminal: %s\n", term ? term : "");
      return 3;
    }
  if (st.found)
    {
      int rc = emit_side_cap (&st, cap, args, var);
      if (rc >= 0)
        return rc;
    }
  if (!known_cap (cap))
    {
      fprintf (stderr, "tput: unknown capability: %s\n", cap);
      return 4;
    }
  bi = boolean_index (cap);
  if (bi >= 0)
    {
      for (n = 0; terms[n]; n++)
        if (!strcmp (term, terms[n]))
          return (boolcaps[bi].terminals & (1U << n)) ? 0 : 1;
      return 1;
    }
  if (!strcmp (term, "dumb") && strcmp (cap, "cols") && strcmp (cap, "columns")
      && strcmp (cap, "lines") && strcmp (cap, "rows")
      && strcmp (cap, "colors") && strcmp (cap, "longname"))
    {
      if (!strcmp (cap, "clear") || !strcmp (cap, "clear_screen"))
        { builtin_error ("terminal has no clear capability"); return 2; }
      return 1;
    }
  cap = parameter_code (cap);
  /* VT100 has cursor motion, but no ANSI color or editing extensions. */
  if (!strcmp (term, "vt100") &&
      (!strcmp (cap, "setaf") || !strcmp (cap, "setab") ||
       !strcmp (cap, "hpa") || !strcmp (cap, "vpa") ||
       !strcmp (cap, "ich") || !strcmp (cap, "dch") ||
       !strcmp (cap, "dl") || !strcmp (cap, "il")))
    return 1;
  tmpl = parameter_template (cap, term);
  if (!args && tmpl)
    return bind_or_print (var, tmpl, 0);

  if (!strcmp (cap, "clear") || !strcmp (cap, "clear_screen"))
    {
      if (!strncmp (term, "xterm", 5))
        return bind_or_print (var, "\033[H\033[2J\033[3J", 0);
      return bind_or_print (var, !strcmp (term, "linux") || !strcmp (term, "tmux-256color")
                            ? "\033[H\033[J\033[3J" : "\033[H\033[J", 0);
    }
  if (!strcmp (cap, "reset") || !strcmp (cap, "init"))
    return bind_or_print (var, "\033[0m\033[2J\033[H", 0);
  if (!strcmp (cap, "home") || !strcmp (cap, "cursor_home"))
    return bind_or_print (var, "\033[H", 0);
  if (!strcmp (cap, "cup") || !strcmp (cap, "cursor_address"))
    {
      r = atoi (args->word->word);
      c = args->next ? atoi (args->next->word->word) : 0;
      snprintf (buf, sizeof buf, "\033[%d;%dH", r + 1, c + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "cuu") || !strcmp (cap, "cursor_up"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dA", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cud") || !strcmp (cap, "cursor_down"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dB", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cuf") || !strcmp (cap, "cursor_right"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dC", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cub") || !strcmp (cap, "cursor_left"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dD", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "el") || !strcmp (cap, "clr_eol"))
    return bind_or_print (var, "\033[K", 0);
  if (!strcmp (cap, "el1") || !strcmp (cap, "clr_bol"))
    return bind_or_print (var, "\033[1K", 0);
  if (!strcmp (cap, "ed") || !strcmp (cap, "clr_eos"))
    return bind_or_print (var, "\033[J", 0);
  if (!strcmp (cap, "bold"))
    return bind_or_print (var, "\033[1m", 0);
  if (!strcmp (cap, "smso") || !strcmp (cap, "enter_standout_mode"))
    return bind_or_print (var, !strcmp (term, "screen-256color") ? "\033[3m" : "\033[7m", 0);
  if (!strcmp (cap, "enter_bold_mode"))
    return bind_or_print (var, "\033[1m", 0);
  if (!strcmp (cap, "dim"))
    return bind_or_print (var, "\033[2m", 0);
  if (!strcmp (cap, "sitm") || !strcmp (cap, "enter_italics_mode"))
    return bind_or_print (var, "\033[3m", 0);
  if (!strcmp (cap, "ritm") || !strcmp (cap, "exit_italics_mode"))
    return bind_or_print (var, "\033[23m", 0);
  if (!strcmp (cap, "smul"))
    return bind_or_print (var, "\033[4m", 0);
  if (!strcmp (cap, "rmul"))
    return bind_or_print (var, "\033[24m", 0);
  if (!strcmp (cap, "rev"))
    return bind_or_print (var, "\033[7m", 0);
  if (!strcmp (cap, "blink"))
    return bind_or_print (var, "\033[5m", 0);
  if (!strcmp (cap, "invis"))
    return bind_or_print (var, "\033[8m", 0);
  if (!strcmp (cap, "sgr0"))
    return bind_or_print (var, !strncmp (term, "xterm", 5) ? "\033(B\033[m" : "\033[m\017", 0);
  if (!strcmp (cap, "rmso") || !strcmp (cap, "exit_standout_mode"))
    return bind_or_print (var, !strcmp (term, "screen-256color") ? "\033[23m" :
                         !strcmp (term, "vt100") ? "\033[m" : "\033[27m", 0);
  if (!strcmp (cap, "sgr"))
    {
      int p[9] = {0};
      int i = 0, off = 0;
      while (args && i < 9)
        {
          p[i++] = atoi (args->word->word) ? 1 : 0;
          args = args->next;
        }
      if (!strncmp (term, "xterm", 5))
        off += snprintf (buf + off, sizeof buf - (size_t) off, "\033(%c", p[8] ? '0' : 'B');
      off += snprintf (buf + off, sizeof buf - (size_t) off, "\033[0");
      if (!strcmp (term, "linux"))
        {
          off += snprintf (buf + off, sizeof buf - (size_t) off, ";10");
          if (p[0]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";7");
          if (p[1]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";4");
          if (p[2]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";7");
          if (p[3]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";5");
          if (p[4]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";2");
          if (p[5]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";1");
        }
      else
        {
          int vt = !strcmp (term, "vt100");
          int screen = !strcmp (term, "screen-256color");
          int xt = !strncmp (term, "xterm", 5);
          if (p[5] || (vt && p[0])) off += snprintf (buf + off, sizeof buf - (size_t) off, ";1");
          if (xt && p[4]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";2");
          if (screen && p[0]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";3");
          if (p[1]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";4");
          if (p[2] || (!screen && p[0])) off += snprintf (buf + off, sizeof buf - (size_t) off, ";7");
          if (p[3]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";5");
          if (!xt && !vt && p[4]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";2");
          if (!vt && !screen && p[6]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";8");
        }
      snprintf (buf + off, sizeof buf - (size_t) off, "m%s",
                !strncmp (term, "xterm", 5) ? "" : p[8] ? "\016" : "\017");
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "civis"))
    return bind_or_print (var, "\033[?25l", 0);
  if (!strcmp (cap, "cnorm"))
    return bind_or_print (var, "\033[?25h", 0);
  if (!strcmp (cap, "smcup"))
    return bind_or_print (var, "\033[?1049h", 0);
  if (!strcmp (cap, "rmcup"))
    return bind_or_print (var, "\033[?1049l", 0);
  if (!strcmp (cap, "smkx"))
    return bind_or_print (var, "\033[?1h\033=", 0);
  if (!strcmp (cap, "rmkx"))
    return bind_or_print (var, "\033[?1l\033>", 0);
  if (!strcmp (cap, "smacs"))
    return bind_or_print (var, "\033(0", 0);
  if (!strcmp (cap, "rmacs"))
    return bind_or_print (var, "\033(B", 0);
  if (!strcmp (cap, "acsc"))
    return bind_or_print (var, "``aaffggjjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~", 0);
  if (!strcmp (cap, "sc") || !strcmp (cap, "save_cursor"))
    return bind_or_print (var, "\0337", 0);
  if (!strcmp (cap, "rc") || !strcmp (cap, "restore_cursor"))
    return bind_or_print (var, "\0338", 0);
  if (!strcmp (cap, "hpa") || !strcmp (cap, "column_address"))
    {
      if (!args) { builtin_error ("%s needs COL", cap); return EX_USAGE; }
      c = atoi (args->word->word);
      snprintf (buf, sizeof buf, "\033[%dG", c + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "vpa") || !strcmp (cap, "row_address"))
    {
      if (!args) { builtin_error ("%s needs ROW", cap); return EX_USAGE; }
      r = atoi (args->word->word);
      snprintf (buf, sizeof buf, "\033[%dd", r + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "ich") || !strcmp (cap, "parm_ich"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%d@", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "dch") || !strcmp (cap, "parm_dch"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dP", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "dl") || !strcmp (cap, "parm_delete_line"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dM", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "il") || !strcmp (cap, "parm_insert_line"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dL", n); return bind_or_print (var, buf, 0); }
  if (!strncmp (cap, "kf", 2) || !strncmp (cap, "key_f", 5))
    {
      const char *num = !strncmp (cap, "kf", 2) ? cap + 2 : cap + 5;
      n = atoi (num);
      switch (n)
        {
        case 1: return bind_or_print (var, "\033OP", 0);
        case 2: return bind_or_print (var, "\033OQ", 0);
        case 3: return bind_or_print (var, "\033OR", 0);
        case 4: return bind_or_print (var, "\033OS", 0);
        case 5: return bind_or_print (var, "\033[15~", 0);
        case 6: return bind_or_print (var, "\033[17~", 0);
        case 7: return bind_or_print (var, "\033[18~", 0);
        case 8: return bind_or_print (var, "\033[19~", 0);
        case 9: return bind_or_print (var, "\033[20~", 0);
        case 10: return bind_or_print (var, "\033[21~", 0);
        case 11: return bind_or_print (var, "\033[23~", 0);
        case 12: return bind_or_print (var, "\033[24~", 0);
        }
    }
  if (!strcmp (cap, "setaf") || !strcmp (cap, "setab"))
    {
      int fg = !strcmp (cap, "setaf");
      if (!args) { builtin_error ("%s needs COLOR", cap); return EX_USAGE; }
      n = atoi (args->word->word);
      if (n < 0 || n > 255) { builtin_error ("%s color must be 0..255", cap); return EX_USAGE; }
      if (!strcmp (term, "xterm") || !strcmp (term, "linux"))
        snprintf (buf, sizeof buf, "\033[%d%dm", fg ? 3 : 4, n);
      else if (n < 8) snprintf (buf, sizeof buf, "\033[%dm", (fg ? 30 : 40) + n);
      else if (n < 16) snprintf (buf, sizeof buf, "\033[%dm", (fg ? 90 : 100) + n - 8);
      else snprintf (buf, sizeof buf, "\033[%d;5;%dm", fg ? 38 : 48, n);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "cols") || !strcmp (cap, "columns"))
    return bind_or_print (var, !explicit_term && getenv ("COLUMNS") ? getenv ("COLUMNS") : "80", 1);
  if (!strcmp (cap, "lines") || !strcmp (cap, "rows"))
    return bind_or_print (var, !explicit_term && getenv ("LINES") ? getenv ("LINES") : "24", 1);
  if (!strcmp (cap, "colors"))
    return bind_or_print (var, !strcmp (term, "vt100") || !strcmp (term, "dumb") ? "-1" :
                          !strcmp (term, "xterm") || !strcmp (term, "linux") ? "8" : "256", 1);
  if (!strcmp (cap, "longname"))
    {
      static const char *names[] = {
        "xterm with 256 colors", "xterm terminal emulator (X Window System)",
        "GNU Screen with 256 colors", "tmux with 256 colors", "Linux console",
        "DEC VT100 (w/advanced video)", "80-column dumb tty"
      };
      if (st.found)
        return bind_or_print (var, st.name, 1);
      for (n = 0; terms[n]; n++)
        if (!strcmp (term, terms[n])) return bind_or_print (var, names[n], 0);
    }

  return EXECUTION_SUCCESS;
}

int
tput_builtin (WORD_LIST *list)
{
  const char *term = getenv ("TERM");
  const char *var = NULL;
  const char *verb;
  int i, explicit_term = 0;

  if (!list) { builtin_usage (); return EX_USAGE; }
  if (!strcmp (list->word->word, "--help") || !strcmp (list->word->word, "-h"))
    {
      char *const *dp;
      for (dp = tput_doc; *dp; dp++)
        puts (*dp);
      return (EX_USAGE);
    }
  while (list && list->word->word[0] == '-')
    {
      const char *opt = list->word->word;
      if (!strcmp (opt, "--")) { list = list->next; break; }
      if (!strncmp (opt, "-T", 2))
        {
          if (opt[2]) term = opt + 2;
          else
            {
              list = list->next;
              if (!list) { builtin_error ("-T needs TERM"); return EX_USAGE; }
              term = list->word->word;
            }
          explicit_term = 1;
        }
      else { builtin_error ("unknown option: %s", opt); return EX_USAGE; }
      list = list->next;
    }
  if (!list) { builtin_usage (); return EX_USAGE; }
  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "entry-list"))
    {
      DIR *d;
      for (i = 0; terms[i]; i++) puts (terms[i]);
      d = opendir (side_dir_primary ());
      if (!d && strcmp (side_dir_primary (), BTP_COMPAT_DIR))
        d = opendir (BTP_COMPAT_DIR);
      if (d)
        {
          struct dirent *de;
          while ((de = readdir (d)) != NULL)
            {
              if (de->d_name[0] == '.')
                continue;
              if (safe_term_name (de->d_name))
                puts (de->d_name);
            }
          closedir (d);
        }
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "cap-list"))
    {
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; explicit_term = 1; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else { builtin_error ("unknown cap-list arg: %s", w); return EX_USAGE; }
          list = list->next;
        }
      if (term && *term)
        {
          sideterm st;
          if (load_side_term (&st, term))
            {
              if (var)
                {
                  char joined[1024] = "";
                  for (i = 0; i < st.ncap; i++)
                    {
                      if (i) strncat (joined, " ", sizeof joined - strlen (joined) - 1);
                      strncat (joined, st.caps[i].key, sizeof joined - strlen (joined) - 1);
                    }
                  builtin_bind_variable ((char *) var, joined, 0);
                }
              else
                for (i = 0; i < st.ncap; i++) puts (st.caps[i].key);
              return EXECUTION_SUCCESS;
            }
          if (!known_term (term))
            {
              fprintf (stderr, "tput: unknown terminal: %s\n", term);
              return 3;
            }
        }
      if (var)
        {
          char joined[1024] = "";
          for (i = 0; caps[i]; i++)
            {
              if (i) strncat (joined, " ", sizeof joined - strlen (joined) - 1);
              strncat (joined, caps[i], sizeof joined - strlen (joined) - 1);
            }
          builtin_bind_variable ((char *) var, joined, 0);
        }
      else
        for (i = 0; caps[i]; i++) puts (caps[i]);
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "info"))
    {
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; explicit_term = 1; }
          else { builtin_error ("unknown info arg: %s", w); return EX_USAGE; }
          list = list->next;
        }
      if (!term || !*term) term = "xterm-256color";
      if (!known_term (term))
        {
          sideterm st;
          if (load_side_term (&st, term))
            {
              printf ("name=%s\n", st.name[0] ? st.name : term);
              for (i = 0; i < st.ncap; i++)
                if (!strcmp (st.caps[i].key, "cols") ||
                    !strcmp (st.caps[i].key, "lines") ||
                    !strcmp (st.caps[i].key, "colors"))
                  printf ("%s=%s\n", st.caps[i].key, st.caps[i].val);
              return EXECUTION_SUCCESS;
            }
          fprintf (stderr, "tput: unknown terminal: %s\n", term);
          return 3;
        }
      printf ("name=%s\ncols=80\nlines=24\ncolors=%s\n", term,
              !strcmp (term, "dumb") || !strcmp (term, "vt100") ? "-1" :
              !strcmp (term, "linux") || !strcmp (term, "xterm") ? "8" : "256");
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "query"))
    {
      const char *cap;
      if (!list) { builtin_error ("query needs CAP"); return EX_USAGE; }
      cap = list->word->word;
      list = list->next;
      while (list && list->word->word[0] == '-')
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; explicit_term = 1; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else if (isdigit ((unsigned char) w[1])) break;
          else { builtin_error ("unknown or incomplete query option: %s", w); return EX_USAGE; }
          list = list->next;
        }
      return emit_cap (cap, list, var, term, explicit_term);
    }

  return emit_cap (verb, list, NULL, term, explicit_term);
}

char *tput_doc[] = {
  "Query a curated terminfo-compatible ANSI capability table.",
  "",
  "    tput query CAP [-T TERM] [-V VAR] [ARGS...]",
  "    tput [-T TERM] CAP [ARGS...]",
  "    tput cap-list [-T TERM] [-V VAR]",
  "    tput entry-list",
  "    tput info [-T TERM]",
  "",
  "Common boolean queries return 0 for true and 1 for false, without output.",
  "With no parameters, built-in parameterized strings are returned verbatim.",
  "Statuses: 2 for usage/missing TERM, 3 for unknown terminal, 4 for unknown CAP.",
  "A compiled terminfo entry (TERMINFO, ~/.terminfo, TERMINFO_DIRS, or the",
  "system database) is used before an unknown terminal is reported.",
  "Supported terminal entries: xterm-256color, xterm, screen-256color,",
  "tmux-256color, linux, vt100, dumb.",
  "Sidecar entries: BASHTPUT_TERMINFO_DIR/TERM or /etc/bash-os/terminfo.d/TERM,",
  "with key=value lines and escapes like \\E, \\n, and %i%p1%d parameters.",
  (char *)NULL
};

struct builtin tput_struct = {
  "tput",
  tput_builtin,
  BUILTIN_ENABLED,
  tput_doc,
  "tput query CAP [-T TERM] [-V VAR]",
  0
};
