/* SPDX-License-Identifier: MIT */
/* wgetch.c - screen-context wrapper for bash-os key input.
 *
 * Phase 3 slice from PROPOSAL_NCURSES_INPUT.md. This is a small
 * ncurses-style wgetch surface over per-screen input contexts. It keeps
 * state in-process, uses the same 50 ms ESC grace and max(400,
 * ESCDELAY*8) cap as kgetch, and returns "NAME CODE" records.
 *
 * Surface:
 *   wgetch open [FD] [NAME]   -> HANDLE
 *   wgetch close HANDLE
 *   wgetch read HANDLE|FD
 *   wgetch unget HANDLE CODE
 *   wgetch peek HANDLE
 *   wgetch list
 *   wgetch define-key NAME CODE SEQUENCE
 *   wgetch undefine-key NAME
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loadables.h"
#include "escdelay-resolve.h"

#define BW_MAX_SCREENS 16
#define BW_FIFO_CAP 64
#define BW_MAX_CUSTOM_KEYS 32

enum {
  BW_NONE = 0,
  BW_ESC = 27,
  BW_UP = 0x101,
  BW_DOWN = 0x102,
  BW_LEFT = 0x103,
  BW_RIGHT = 0x104,
  BW_HOME = 0x105,
  BW_END = 0x106,
  BW_BS = 0x107,
  BW_RET = 0x108,
  BW_DEL = 0x109,
  BW_PGUP = 0x10a,
  BW_PGDN = 0x10b,
  BW_INS = 0x10c,
  BW_TAB = 0x10d,
  BW_F1 = 0x110,
  BW_F2 = 0x111,
  BW_F3 = 0x112,
  BW_F4 = 0x113,
  BW_F5 = 0x114,
  BW_F6 = 0x115,
  BW_F7 = 0x116,
  BW_F8 = 0x117,
  BW_F9 = 0x118,
  BW_F10 = 0x119,
  BW_F11 = 0x11a,
  BW_F12 = 0x11b,
  BW_PASTE_START = 0x120,
  BW_PASTE_END = 0x121,
  BW_S_UP = 0x130,
  BW_S_DOWN = 0x131,
  BW_S_LEFT = 0x132,
  BW_S_RIGHT = 0x133
};

typedef struct {
  int used;
  int handle;
  int fd;
  char name[64];
  int ring[BW_FIFO_CAP];
  int head;
  int tail;
  int count;
} bw_screen;

typedef struct {
  const char *name;
  int code;
  const char *seq;
} bw_keydef;

static bw_screen bw_screens[BW_MAX_SCREENS];
static int bw_next_handle = 1;

static const bw_keydef bw_keys[] = {
  { "key_up", BW_UP, "\033[A" },
  { "key_down", BW_DOWN, "\033[B" },
  { "key_right", BW_RIGHT, "\033[C" },
  { "key_left", BW_LEFT, "\033[D" },
  { "key_home", BW_HOME, "\033[H" },
  { "key_end", BW_END, "\033[F" },
  { "key_f1", BW_F1, "\033OP" },
  { "key_f2", BW_F2, "\033OQ" },
  { "key_f3", BW_F3, "\033OR" },
  { "key_f4", BW_F4, "\033OS" },
  { "key_home", BW_HOME, "\033[1~" },
  { "key_ic", BW_INS, "\033[2~" },
  { "key_dc", BW_DEL, "\033[3~" },
  { "key_end", BW_END, "\033[4~" },
  { "key_ppage", BW_PGUP, "\033[5~" },
  { "key_npage", BW_PGDN, "\033[6~" },
  { "key_f1", BW_F1, "\033[11~" },
  { "key_f2", BW_F2, "\033[12~" },
  { "key_f3", BW_F3, "\033[13~" },
  { "key_f4", BW_F4, "\033[14~" },
  { "key_f5", BW_F5, "\033[15~" },
  { "key_f6", BW_F6, "\033[17~" },
  { "key_f7", BW_F7, "\033[18~" },
  { "key_f8", BW_F8, "\033[19~" },
  { "key_f9", BW_F9, "\033[20~" },
  { "key_f10", BW_F10, "\033[21~" },
  { "key_f11", BW_F11, "\033[23~" },
  { "key_f12", BW_F12, "\033[24~" },
  { "key_s_up", BW_S_UP, "\033[1;2A" },
  { "key_s_down", BW_S_DOWN, "\033[1;2B" },
  { "key_s_right", BW_S_RIGHT, "\033[1;2C" },
  { "key_s_left", BW_S_LEFT, "\033[1;2D" },
  { "paste_start", BW_PASTE_START, "\033[200~" },
  { "paste_end", BW_PASTE_END, "\033[201~" },
  { NULL, 0, NULL }
};

/* Applications can describe keys sent by their terminal without recompiling
   the default table. Prefix ambiguity is resolved by the same timed reader. */
static struct {
  bw_keydef key;
  char name[32];
  char seq[64];
} bw_custom_keys[BW_MAX_CUSTOM_KEYS];

#define BW_BUILTIN_KEYS ((int) (sizeof bw_keys / sizeof bw_keys[0]) - 1)
#define BW_ALL_KEYS (BW_BUILTIN_KEYS + BW_MAX_CUSTOM_KEYS)

static const bw_keydef *
bw_key_at (int i)
{
  if (i < BW_BUILTIN_KEYS) return &bw_keys[i];
  i -= BW_BUILTIN_KEYS;
  return bw_custom_keys[i].key.code ? &bw_custom_keys[i].key : NULL;
}

static const char *
bw_name_for_code (int code)
{
  for (int i = 0; i < BW_ALL_KEYS; i++)
    {
      const bw_keydef *key = bw_key_at (i);
      if (key && key->code == code) return key->name;
    }
  switch (code) {
  case BW_NONE: return "none";
  case BW_ESC: return "esc";
  case BW_BS: return "backspace";
  case BW_RET: return "enter";
  case BW_TAB: return "tab";
  default: return "char";
  }
}

static long
bw_now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int
bw_read_to (int fd, int ms, unsigned char *out)
{
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int pr = poll (&pfd, 1, ms);
  if (pr <= 0)
    return pr;
  ssize_t n;
  do
    n = read (fd, out, 1);
  while (n < 0 && errno == EINTR);
  return n == 1 ? 1 : -1;
}

static int
bw_exact (const unsigned char *buf, size_t len)
{
  for (int i = 0; i < BW_ALL_KEYS; i++)
    {
      const bw_keydef *key = bw_key_at (i);
      if (key && strlen (key->seq) == len && memcmp (key->seq, buf, len) == 0)
        return key->code;
    }
  return 0;
}

static int
bw_has_prefix (const unsigned char *buf, size_t len)
{
  for (int i = 0; i < BW_ALL_KEYS; i++)
    {
      const bw_keydef *key = bw_key_at (i);
      if (key && strlen (key->seq) >= len && memcmp (key->seq, buf, len) == 0)
        return 1;
    }
  return 0;
}

static int
bw_has_longer (const unsigned char *buf, size_t len)
{
  for (int i = 0; i < BW_ALL_KEYS; i++)
    {
      const bw_keydef *key = bw_key_at (i);
      if (key && strlen (key->seq) > len && memcmp (key->seq, buf, len) == 0)
        return 1;
    }
  return 0;
}

static int
bw_read_key_fd (int fd, const char *screen)
{
  unsigned char b;
  ssize_t n;
  do
    n = read (fd, &b, 1);
  while (n < 0 && errno == EINTR);
  if (n <= 0) return BW_NONE;
  if (b != 0x1b)
    {
      if (b == 0x7f || b == 0x08) return BW_BS;
      if (b == 0x0d || b == 0x0a) return BW_RET;
      if (b == 0x09) return BW_TAB;
      return (int) b;
    }

  int escdelay = bashos_escdelay_resolve (screen, 0);
  int cap = escdelay * 8;
  if (cap < 400) cap = 400;

  unsigned char seq[64];
  size_t len = 0;
  seq[len++] = b;
  if (bw_read_to (fd, escdelay, &b) <= 0)
    return BW_ESC;
  seq[len++] = b;

  long start = bw_now_ms ();
  for (;;)
    {
      int exact = bw_exact (seq, len);
      if (exact && !bw_has_longer (seq, len))
        return exact;
      if (!bw_has_prefix (seq, len))
        return exact ? exact : BW_ESC;
      long elapsed = bw_now_ms () - start;
      if (elapsed >= cap || len >= sizeof seq)
        return exact ? exact : BW_ESC;
      int rem = cap - (int) elapsed;
      int slice = rem < 50 ? rem : 50;
      if (bw_read_to (fd, slice, &b) <= 0)
        return exact ? exact : BW_ESC;
      seq[len++] = b;
    }
}

static bw_screen *
bw_find (int handle)
{
  for (int i = 0; i < BW_MAX_SCREENS; i++)
    if (bw_screens[i].used && bw_screens[i].handle == handle)
      return &bw_screens[i];
  return NULL;
}

static int
bw_parse_int (const char *s, int *out)
{
  char *end = NULL;
  long v;
  if (!s || !*s) return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || end == s || *end || v < -2147483647L || v > 2147483647L)
    return -1;
  *out = (int) v;
  return 0;
}

static int
bw_define_key (const char *name, int code, const char *seq)
{
  if (!name || !*name || strlen (name) >= sizeof bw_custom_keys[0].name ||
      code < 1024 || code > 65535 || !seq || seq[0] != '\033' ||
      strlen (seq) < 2 || strlen (seq) >= sizeof bw_custom_keys[0].seq)
    return EX_USAGE;
  for (const unsigned char *p = (const unsigned char *) name; *p; ++p)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '_')) return EX_USAGE;
  if (!strcmp (name,"none") || !strcmp (name,"esc") || !strcmp (name,"char") ||
      !strcmp (name,"backspace") || !strcmp (name,"enter") || !strcmp (name,"tab"))
    return EX_USAGE;
  for (int i = 0; i < BW_ALL_KEYS; ++i)
    {
      const bw_keydef *key = bw_key_at (i);
      if (key && (key->code == code || !strcmp (key->name,name) || !strcmp (key->seq,seq)))
        return EX_USAGE;
    }
  for (int i = 0; i < BW_MAX_CUSTOM_KEYS; ++i)
    if (!bw_custom_keys[i].key.code)
      {
        strcpy (bw_custom_keys[i].name,name);
        strcpy (bw_custom_keys[i].seq,seq);
        bw_custom_keys[i].key.name = bw_custom_keys[i].name;
        bw_custom_keys[i].key.seq = bw_custom_keys[i].seq;
        bw_custom_keys[i].key.code = code;
        return EXECUTION_SUCCESS;
      }
  return EXECUTION_FAILURE;
}

static int
bw_unget (bw_screen *s, int code)
{
  if (s->count >= BW_FIFO_CAP)
    return -1;
  s->head = (s->head + BW_FIFO_CAP - 1) % BW_FIFO_CAP;
  s->ring[s->head] = code;
  s->count++;
  return 0;
}

static int
bw_pull (bw_screen *s, int *code)
{
  if (s->count <= 0)
    return -1;
  *code = s->ring[s->head];
  s->head = (s->head + 1) % BW_FIFO_CAP;
  s->count--;
  if (s->count == 0)
    s->tail = s->head;
  return 0;
}

static const char *
bw_next (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

static void
bw_print (int code)
{
  printf ("%s %d\n", bw_name_for_code (code), code);
}

int
wgetch_builtin (WORD_LIST *list)
{
  const char *cmd = bw_next (&list);
  if (!cmd || !strcmp (cmd, "--help") || !strcmp (cmd, "-h"))
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "define-key"))
    {
      const char *name = bw_next (&list), *number = bw_next (&list), *seq = bw_next (&list);
      int code;
      if (!name || !number || !seq || list || bw_parse_int (number,&code) < 0)
        { builtin_error ("usage: wgetch define-key NAME CODE SEQUENCE"); return EX_USAGE; }
      int rc = bw_define_key (name,code,seq);
      if (rc) builtin_error (rc == EX_USAGE ? "invalid or duplicate key definition" : "key table full");
      return rc;
    }
  if (!strcmp (cmd, "undefine-key"))
    {
      const char *name = bw_next (&list);
      if (!name || list)
        { builtin_error ("usage: wgetch undefine-key NAME"); return EX_USAGE; }
      for (int i = 0; i < BW_MAX_CUSTOM_KEYS; ++i)
        if (bw_custom_keys[i].key.code && !strcmp (bw_custom_keys[i].name,name))
          { memset (&bw_custom_keys[i],0,sizeof bw_custom_keys[i]); return EXECUTION_SUCCESS; }
      return EXECUTION_FAILURE;
    }

  if (!strcmp (cmd, "open"))
    {
      int fd = STDIN_FILENO;
      const char *fd_s = bw_next (&list);
      const char *name = bw_next (&list);
      if (fd_s && bw_parse_int (fd_s, &fd) < 0)
        { builtin_error ("open: invalid fd: %s", fd_s); return EX_USAGE; }
      if (list)
        { builtin_error ("usage: wgetch open [FD] [NAME]"); return EX_USAGE; }
      for (int i = 0; i < BW_MAX_SCREENS; i++)
        if (!bw_screens[i].used)
          {
            memset (&bw_screens[i], 0, sizeof bw_screens[i]);
            bw_screens[i].used = 1;
            bw_screens[i].handle = bw_next_handle++;
            bw_screens[i].fd = fd;
            snprintf (bw_screens[i].name, sizeof bw_screens[i].name, "%s",
                      name ? name : "screen");
            printf ("%d\n", bw_screens[i].handle);
            return EXECUTION_SUCCESS;
          }
      builtin_error ("open: screen table full");
      return EXECUTION_FAILURE;
    }

  if (!strcmp (cmd, "close"))
    {
      int h;
      const char *hs = bw_next (&list);
      if (!hs || list || bw_parse_int (hs, &h) < 0)
        { builtin_error ("usage: wgetch close HANDLE"); return EX_USAGE; }
      bw_screen *s = bw_find (h);
      if (!s) return EXECUTION_FAILURE;
      memset (s, 0, sizeof *s);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "list"))
    {
      if (list)
        { builtin_error ("list: unexpected argument: %s", list->word->word); return EX_USAGE; }
      for (int i = 0; i < BW_MAX_SCREENS; i++)
        if (bw_screens[i].used)
          printf ("%d %d %s depth=%d\n", bw_screens[i].handle, bw_screens[i].fd,
                  bw_screens[i].name, bw_screens[i].count);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "unget"))
    {
      int h, code;
      const char *hs = bw_next (&list);
      const char *cs = bw_next (&list);
      if (!hs || !cs || list || bw_parse_int (hs, &h) < 0 || bw_parse_int (cs, &code) < 0)
        { builtin_error ("usage: wgetch unget HANDLE CODE"); return EX_USAGE; }
      bw_screen *s = bw_find (h);
      if (!s || bw_unget (s, code) < 0)
        return EXECUTION_FAILURE;
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "peek") || !strcmp (cmd, "read"))
    {
      int h, code;
      const char *hs = bw_next (&list);
      if (!hs || list || bw_parse_int (hs, &h) < 0)
        { builtin_error ("usage: wgetch %s HANDLE|FD", cmd); return EX_USAGE; }
      bw_screen *s = bw_find (h);
      if (s)
        {
          if (!strcmp (cmd, "peek"))
            {
              if (s->count <= 0) return EXECUTION_FAILURE;
              bw_print (s->ring[s->head]);
              return EXECUTION_SUCCESS;
            }
          if (bw_pull (s, &code) == 0)
            { bw_print (code); return EXECUTION_SUCCESS; }
          bw_print (bw_read_key_fd (s->fd, s->name));
          return EXECUTION_SUCCESS;
        }
      if (!strcmp (cmd, "peek"))
        return EXECUTION_FAILURE;
      bw_print (bw_read_key_fd (h, NULL));
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown command: %s", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *wgetch_doc[] = {
  "Read decoded keys through ncurses-style screen contexts.",
  "",
  "    wgetch open [FD] [NAME]",
  "    wgetch read HANDLE|FD",
  "    wgetch unget HANDLE CODE",
  "    wgetch peek HANDLE",
  "    wgetch close HANDLE",
  "    wgetch list",
  "    wgetch define-key NAME CODE SEQUENCE",
  "    wgetch undefine-key NAME",
  "Custom keys: at most 32, unique names/codes/sequences; CODE 1024..65535.",
  "NAME is 1..31 ASCII letters/digits/underscores; SEQUENCE is 2..63 bytes",
  "beginning with ESC. Definitions are local to this shell; defaults cannot",
  "be replaced. A removed key's queued numeric codes retain their value.",
  "",
  "The decoder keeps bash-os timing invariants: 50 ms ESC grace and",
  "a total ESC-sequence cap of max(400 ms, ESCDELAY*8).",
  (char *)NULL
};

struct builtin wgetch_struct = {
  "wgetch",
  wgetch_builtin,
  BUILTIN_ENABLED,
  wgetch_doc,
  "wgetch open|read|unget|peek|close|list|define-key|undefine-key ...",
  0
};
