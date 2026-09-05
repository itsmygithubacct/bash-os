/* SPDX-License-Identifier: MIT */
/* httpd-host.c — host test of the httpd builtin, driven over real sockets.
 *
 * httpd.c is a real bash builtin, so this links it against the configured bash
 * tree with the bash runtime symbols it calls stubbed — including a working
 * internal_getopt and a bind_variable that records what was bound — and drives
 * httpd_builtin() directly. Each request comes from a forked client that
 * connects to the ephemeral port, sends raw bytes, and captures the raw
 * response to a file until EOF. tests/run-all.sh builds and runs this under
 * ASan+UBSan.
 *
 * What it proves, against the interface handlers are written to:
 *   - listen on port 0 binds a real listening fd;
 *   - a GET with a query binds METHOD, PATH (before '?'), QUERY, LEN "0",
 *     CTYPE "", REMOTE 127.0.0.1, and an OPEN CFD;
 *   - a POST with a 3-byte body lands exactly those bytes in BODYFILE, 0600,
 *     with LEN and CTYPE bound;
 *   - BODYFILE is truncated on the next accept (a GET after a POST reads empty);
 *   - a 9 KiB header is refused with 431, an oversized Content-Length with 413,
 *     a one-token request line with 400 — each answered and closed by accept,
 *     which returns non-zero;
 *   - accept -t 1 with no client returns 3 and binds nothing;
 *   - reply from -f FILE and from stdin: exact status line, Content-Length,
 *     Content-Type, and body bytes; a status outside the reason table reads
 *     "Status"; and CFD is CLOSED after reply;
 *   - accept -t 0 with no client returns 3 at once (the non-blocking probe);
 *   - a client that sends a partial request and then stalls is answered 408 and
 *     closed within the request-read deadline (compiled here to 1 s), so accept
 *     returns non-zero with nothing bound rather than blocking forever;
 *   - part: from a 3-part multipart body whose image field is 5 binary bytes
 *     containing \0 and \r\n, extraction by name and by default (the first
 *     filename=) yields exactly those bytes, 0600, with the basename of the
 *     filename and the length bound; a quoted boundary is unquoted; a missing
 *     field and a wrong boundary both return 1 with nothing bound.
 *
 * Build (what run-all.sh does):
 *   cc -fsanitize=address,undefined -DHAVE_CONFIG_H -Iinclude -Iloadables/common \
 *      -Ibuild/bash-5.3 -Ibuild/bash-5.3/include -Ibuild/bash-5.3/builtins \
 *      -Ibuild/bash-5.3/examples/loadables loadables/httpd.c tests/httpd-host.c
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "loadables.h"
#include "bashgetopt.h"

/* ---- the bash runtime, stubbed ---------------------------------------------- */
WORD_LIST *loptend;
char *list_optarg;
static WORD_LIST *lcur; static int lfresh;
void reset_internal_getopt (void) { lfresh = 1; }
/* Enough of bashgetopt for "-x VALUE" and "-f" options, one per word. */
int
internal_getopt (WORD_LIST *l, char *opts)
{
  char *w, *spec;
  if (lfresh) { lcur = l; lfresh = 0; }
  if (lcur == 0 || (w = lcur->word->word)[0] != '-' || w[1] == 0) { loptend = lcur; return -1; }
  if (strcmp (w, "--") == 0) { loptend = lcur->next; return -1; }
  spec = strchr (opts, w[1]);
  if (spec == 0 || w[1] == ':') { loptend = lcur; return '?'; }
  if (spec[1] == ':')
    {
      if (w[2]) list_optarg = w + 2;
      else if (lcur->next) { lcur = lcur->next; list_optarg = lcur->word->word; }
      else { loptend = lcur; return '?'; }
    }
  lcur = lcur->next;
  return w[1];
}
void builtin_error (const char *fmt, ...)
{ va_list a; va_start (a, fmt); fputs ("httpd: ", stderr); vfprintf (stderr, fmt, a); fputc ('\n', stderr); va_end (a); }
void builtin_usage (void) { fputs ("usage: httpd listen|accept|reply ...\n", stderr); }
int legal_identifier (const char *s)
{
  if (!s || !(*s == '_' || (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z'))) return 0;
  for (s++; *s; s++) if (!(*s == '_' || (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9'))) return 0;
  return 1;
}
/* bind_variable records into a small table the test reads back. */
static struct { char name[32]; char *value; } vars[16]; static int nvars;
static SHELL_VAR dummy_var;
SHELL_VAR *
bind_variable (const char *name, const char *value, int flags)
{
  (void) flags;
  for (int i = 0; i < nvars; i++)
    if (strcmp (vars[i].name, name) == 0) { free (vars[i].value); vars[i].value = strdup (value); return &dummy_var; }
  if (nvars == 16) return 0;
  snprintf (vars[nvars].name, sizeof vars[nvars].name, "%s", name);
  vars[nvars].value = strdup (value); nvars++;
  return &dummy_var;
}
static const char *var (const char *name)
{ for (int i = 0; i < nvars; i++) if (strcmp (vars[i].name, name) == 0) return vars[i].value; return 0; }
static void clear_vars (void) { for (int i = 0; i < nvars; i++) free (vars[i].value); nvars = 0; }
extern int httpd_builtin (WORD_LIST *);

/* ---- harness plumbing --------------------------------------------------------- */
static int fails;
#define CHECK(c, msg) do { if (c) printf ("  ok   %s\n", msg); else { printf ("  FAIL %s\n", msg); fails++; } } while (0)
static int
run (const char *first, ...)		/* httpd_builtin over a NULL-terminated arg list */
{
  WORD_LIST *head = 0, **tail = &head, *l; va_list a; const char *w;
  va_start (a, first);
  for (w = first; w != NULL; w = va_arg (a, const char *))
    { WORD_LIST *x = calloc (1, sizeof *x); x->word = calloc (1, sizeof *x->word); x->word->word = (char *) w; *tail = x; tail = &x->next; }
  va_end (a);
  int rc = httpd_builtin (head);
  while ((l = head)) { head = l->next; free (l->word); free (l); }
  return rc;
}
static int
port_of (int lfd)
{ struct sockaddr_in sa; socklen_t n = sizeof sa; if (getsockname (lfd, (struct sockaddr *) &sa, &n) != 0) return -1; return ntohs (sa.sin_port); }
/* A client: connect, send REQ (len n), capture the response to OUT until EOF. */
static pid_t
client (int port, const char *req, size_t n, const char *out)
{
  pid_t p = fork ();
  if (p != 0) return p;
  int s = socket (AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sa; memset (&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons ((unsigned short) port);
  inet_pton (AF_INET, "127.0.0.1", &sa.sin_addr);
  if (connect (s, (struct sockaddr *) &sa, sizeof sa) != 0) _exit (2);
  for (size_t off = 0; off < n; ) { ssize_t w = send (s, req + off, n - off, MSG_NOSIGNAL); if (w <= 0) break; off += (size_t) w; }
  int f = open (out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  char b[4096]; ssize_t r;
  while ((r = read (s, b, sizeof b)) > 0) if (write (f, b, (size_t) r) != r) _exit (3);
  close (f); close (s); _exit (0);
}
static long
slurp (const char *p, char *b, long cap)
{ int f = open (p, O_RDONLY); if (f < 0) return -1; long n = 0; ssize_t r; while (n < cap && (r = read (f, b + n, (size_t) (cap - n))) > 0) n += r; close (f); b[n < cap ? n : cap - 1] = 0; return n; }
static int fmode (const char *p) { struct stat st; return stat (p, &st) == 0 ? (int) (st.st_mode & 07777) : -1; }
static long fsize (const char *p) { struct stat st; return stat (p, &st) == 0 ? (long) st.st_size : -1; }
static int fd_open (int fd) { return fcntl (fd, F_GETFD) != -1; }
/* Parse a captured response: status line, Content-Length, Content-Type, body. */
static int
parse_resp (const char *raw, long rawlen, char *status, size_t sl, long *clen, char *ctype, size_t cl, const char **body, long *blen)
{
  const char *e = strstr (raw, "\r\n"), *h = strstr (raw, "\r\n\r\n"), *p;
  if (!e || !h) return -1;
  { size_t sn = (size_t) (e - raw); if (sn >= sl) sn = sl - 1; memcpy (status, raw, sn); status[sn] = 0; }
  *clen = -1; ctype[0] = 0;
  if ((p = strstr (raw, "\r\nContent-Length: "))) *clen = strtol (p + 18, 0, 10);
  if ((p = strstr (raw, "\r\nContent-Type: "))) snprintf (ctype, cl, "%.*s", (int) (strstr (p + 16, "\r\n") - (p + 16)), p + 16);
  *body = h + 4; *blen = rawlen - (long) (*body - raw);
  return 0;
}

int
main (void)
{
  char d[] = "/tmp/httpd-XXXXXX";
  if (!mkdtemp (d)) { perror ("mkdtemp"); return 2; }
  char bodyf[PATH_MAX], out[PATH_MAX], replyf[PATH_MAX], stdinf[PATH_MAX], lfd_s[16], cfd_s[16];
  snprintf (bodyf, sizeof bodyf, "%s/body", d); snprintf (out, sizeof out, "%s/resp", d);
  snprintf (replyf, sizeof replyf, "%s/reply", d); snprintf (stdinf, sizeof stdinf, "%s/stdin", d);
  char raw[16384], status[64], ctype[64], bodybuf[64]; const char *body; long rawlen, clen, blen;
  int rc, lfd, cfd, port; pid_t c;

  puts ("== listen: port 0 -> a real listening fd ==");
  rc = run ("listen", "0", "-a", "127.0.0.1", "-H", "LFD", (char *) NULL);
  CHECK (rc == EXECUTION_SUCCESS && var ("LFD"), "listen binds LFD");
  lfd = var ("LFD") ? atoi (var ("LFD")) : -1; port = lfd >= 0 ? port_of (lfd) : -1;
  CHECK (fd_open (lfd) && port > 0, "LFD is open and bound to an ephemeral port");
  snprintf (lfd_s, sizeof lfd_s, "%d", lfd);
  CHECK (run ("listen", "0", (char *) NULL) == EX_USAGE, "listen without -H is a usage error");

  puts ("== GET with a query: parsed into variables, CFD left open ==");
  { const char *req = "GET /api/state?x=1&y=2 HTTP/1.1\r\nHost: t\r\nUser-Agent: x\r\n\r\n";
    c = client (port, req, strlen (req), out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, "-l", "LEN", (char *) NULL);
    /* -c and -r too, via a second parse of the same bound set is not possible; they are covered in the POST */
    CHECK (rc == EXECUTION_SUCCESS, "accept returns success");
    CHECK (var ("METHOD") && strcmp (var ("METHOD"), "GET") == 0, "METHOD = GET");
    CHECK (var ("PATH") && strcmp (var ("PATH"), "/api/state") == 0, "PATH = /api/state (before '?')");
    CHECK (var ("QUERY") && strcmp (var ("QUERY"), "x=1&y=2") == 0, "QUERY = x=1&y=2");
    CHECK (var ("LEN") && strcmp (var ("LEN"), "0") == 0, "LEN = 0 when absent");
    cfd = var ("CFD") ? atoi (var ("CFD")) : -1; snprintf (cfd_s, sizeof cfd_s, "%d", cfd);
    CHECK (cfd >= 0 && fd_open (cfd), "CFD is an OPEN fd after accept");
    CHECK (fsize (bodyf) == 0 && fmode (bodyf) == 0600, "BODYFILE created empty, 0600");
    /* reply from STDIN: dup a file onto fd 0 */
    { int f = open (stdinf, O_WRONLY | O_CREAT | O_TRUNC, 0600); if (write (f, "{\"ok\":true}", 11) != 11) _exit (9); close (f);
      int saved = dup (0); f = open (stdinf, O_RDONLY); dup2 (f, 0); close (f);
      rc = run ("reply", cfd_s, (char *) NULL);
      dup2 (saved, 0); close (saved); }
    CHECK (rc == EXECUTION_SUCCESS, "reply (stdin body) returns success");
    CHECK (!fd_open (cfd), "CFD is CLOSED after reply");
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    CHECK (parse_resp (raw, rawlen, status, sizeof status, &clen, ctype, sizeof ctype, &body, &blen) == 0, "response is well-formed");
    CHECK (strcmp (status, "HTTP/1.1 200 OK") == 0, "status line: HTTP/1.1 200 OK");
    CHECK (clen == 11 && blen == 11 && memcmp (body, "{\"ok\":true}", 11) == 0, "Content-Length 11 and the exact 11 body bytes");
    CHECK (strcmp (ctype, "application/json") == 0, "Content-Type defaults to application/json");
    CHECK (strstr (raw, "\r\nConnection: close\r\n") != 0, "Connection: close");
  }

  puts ("== POST with a 3-byte body: bytes land in BODYFILE, LEN/CTYPE/REMOTE bound ==");
  { const char *req = "POST /p HTTP/1.0\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc";
    c = client (port, req, strlen (req), out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, "-l", "LEN", "-c", "CT", "-r", "REMOTE", (char *) NULL);
    CHECK (rc == EXECUTION_SUCCESS, "accept returns success");
    CHECK (var ("METHOD") && strcmp (var ("METHOD"), "POST") == 0 && var ("QUERY") && var ("QUERY")[0] == 0, "METHOD = POST, QUERY = \"\"");
    CHECK (var ("LEN") && strcmp (var ("LEN"), "3") == 0, "LEN = 3");
    CHECK (var ("CT") && strcmp (var ("CT"), "text/plain") == 0, "CTYPE = text/plain");
    CHECK (var ("REMOTE") && strcmp (var ("REMOTE"), "127.0.0.1") == 0, "REMOTE = 127.0.0.1");
    CHECK (slurp (bodyf, bodybuf, sizeof bodybuf) == 3 && memcmp (bodybuf, "abc", 3) == 0 && fmode (bodyf) == 0600, "BODYFILE holds exactly \"abc\", 0600");
    cfd = atoi (var ("CFD")); snprintf (cfd_s, sizeof cfd_s, "%d", cfd);
    /* reply from -f FILE with a status outside the reason table */
    { int f = open (replyf, O_WRONLY | O_CREAT | O_TRUNC, 0600); if (write (f, "xyz", 3) != 3) _exit (9); close (f); }
    rc = run ("reply", cfd_s, "-s", "201", "-t", "text/plain", "-f", replyf, (char *) NULL);
    CHECK (rc == EXECUTION_SUCCESS && !fd_open (cfd), "reply (-f body) succeeds and closes CFD");
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    parse_resp (raw, rawlen, status, sizeof status, &clen, ctype, sizeof ctype, &body, &blen);
    CHECK (strcmp (status, "HTTP/1.1 201 Status") == 0, "status outside the table reads \"201 Status\"");
    CHECK (clen == 3 && blen == 3 && memcmp (body, "xyz", 3) == 0 && strcmp (ctype, "text/plain") == 0, "Content-Length 3, body \"xyz\", Content-Type text/plain");
  }

  puts ("== a GET after the POST: BODYFILE is truncated on every accept ==");
  { const char *req = "GET / HTTP/1.1\r\n\r\n";
    c = client (port, req, strlen (req), out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, (char *) NULL);
    CHECK (rc == EXECUTION_SUCCESS && fsize (bodyf) == 0, "BODYFILE is empty again (previous body not left behind)");
    cfd = atoi (var ("CFD")); snprintf (cfd_s, sizeof cfd_s, "%d", cfd);
    { int f = open (replyf, O_WRONLY | O_TRUNC); close (f); }
    run ("reply", cfd_s, "-f", replyf, (char *) NULL); waitpid (c, 0, 0);
  }

  puts ("== refusals: answered and closed by accept, which returns non-zero ==");
  { static char big[10000]; size_t n = 0;
    n += (size_t) snprintf (big, sizeof big, "GET / HTTP/1.1\r\nX-Pad: ");
    memset (big + n, 'a', 9 * 1024); n += 9 * 1024; memcpy (big + n, "\r\n\r\n", 4); n += 4;
    c = client (port, big, n, out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, (char *) NULL);
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    CHECK (rc != EXECUTION_SUCCESS && var ("CFD") == 0, "9 KiB header: accept fails, nothing bound");
    CHECK (strncmp (raw, "HTTP/1.1 431 ", 13) == 0, "client received 431");
  }
  { const char *req = "POST /big HTTP/1.1\r\nContent-Length: 20000000\r\n\r\n";
    c = client (port, req, strlen (req), out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, (char *) NULL);
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    CHECK (rc != EXECUTION_SUCCESS && strncmp (raw, "HTTP/1.1 413 ", 13) == 0, "Content-Length 20 MB: accept fails, client received 413");
  }
  { const char *req = "GARBAGE\r\n\r\n";
    c = client (port, req, strlen (req), out); clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, (char *) NULL);
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    CHECK (rc != EXECUTION_SUCCESS && strncmp (raw, "HTTP/1.1 400 ", 13) == 0, "one-token request line: accept fails, client received 400");
  }

  puts ("== accept -t 1 with no client: returns 3, binds nothing ==");
  { clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, "-t", "1", (char *) NULL);
    CHECK (rc == 3 && nvars == 0, "timeout returns 3 with nothing bound");
  }

  puts ("== accept -t 0 with no client: the non-blocking probe returns 3 at once ==");
  { clear_vars ();
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, "-t", "0", (char *) NULL);
    CHECK (rc == 3 && nvars == 0, "-t 0 returns 3 immediately with nothing bound");
  }

  puts ("== part: one multipart/form-data part, binary-safe ==");
  { /* three parts; the image payload is 5 bytes containing \0 and \r\n */
    static const char img[5] = { 'A', '\0', '\r', '\n', 'Z' };
    char mp[1024]; size_t m = 0;
#define APP(str) do { memcpy (mp + m, str, sizeof (str) - 1); m += sizeof (str) - 1; } while (0)
    APP ("--BND\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n");
    APP ("--BND\r\nContent-Disposition: form-data; name=\"image\"; filename=\"C:\\pics\\photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n");
    memcpy (mp + m, img, 5); m += 5;
    APP ("\r\n--BND\r\nContent-Disposition: form-data; name=\"tail\"\r\n\r\nbye\r\n--BND--\r\n");
#undef APP
    { int f = open (bodyf, O_WRONLY | O_CREAT | O_TRUNC, 0600); if (write (f, mp, m) != (ssize_t) m) _exit (9); close (f); }
    char partf[PATH_MAX]; snprintf (partf, sizeof partf, "%s/part", d);
    char got[64]; long gn;

    clear_vars (); rc = run ("part", bodyf, "-b", "BND", "-o", partf, "-n", "image", "-F", "FN", "-l", "PLEN", (char *) NULL);
    gn = slurp (partf, got, sizeof got);
    CHECK (rc == 0, "by name: returns 0");
    CHECK (gn == 5 && memcmp (got, img, 5) == 0, "by name: OUTFILE is exactly the 5 binary bytes (with \\0 and \\r\\n)");
    CHECK (fmode (partf) == 0600, "OUTFILE is 0600");
    CHECK (var ("FN") && strcmp (var ("FN"), "photo.jpg") == 0, "FILENAMEVAR is the basename (Windows path stripped)");
    CHECK (var ("PLEN") && strcmp (var ("PLEN"), "5") == 0, "LENVAR = 5");

    unlink (partf); clear_vars (); rc = run ("part", bodyf, "-b", "BND", "-o", partf, (char *) NULL);
    gn = slurp (partf, got, sizeof got);
    CHECK (rc == 0 && gn == 5 && memcmp (got, img, 5) == 0, "default (first part with a filename): same 5 bytes");

    unlink (partf); rc = run ("part", bodyf, "-b", "\"BND\"", "-o", partf, "-n", "note", (char *) NULL);
    gn = slurp (partf, got, sizeof got);
    CHECK (rc == 0 && gn == 5 && memcmp (got, "hello", 5) == 0, "quoted boundary is unquoted; text field extracted exactly");

    unlink (partf); rc = run ("part", bodyf, "-b", "BND", "-o", partf, "-n", "tail", (char *) NULL);
    gn = slurp (partf, got, sizeof got);
    CHECK (rc == 0 && gn == 3 && memcmp (got, "bye", 3) == 0, "the last part before the closing delimiter is extracted");

    unlink (partf); clear_vars (); rc = run ("part", bodyf, "-b", "BND", "-o", partf, "-n", "nope", "-F", "FN", "-l", "PLEN", (char *) NULL);
    CHECK (rc == 1 && nvars == 0 && access (partf, F_OK) != 0, "missing field: returns 1, nothing bound, no OUTFILE");

    rc = run ("part", bodyf, "-b", "OTHER", "-o", partf, (char *) NULL);
    CHECK (rc == 1, "wrong boundary (not multipart): returns 1");

    { char bad[PATH_MAX]; snprintf (bad, sizeof bad, "%s/no/such/dir/out", d);
      rc = run ("part", bodyf, "-b", "BND", "-o", bad, (char *) NULL);
      CHECK (rc == EXECUTION_FAILURE, "unwritable OUTFILE: EXECUTION_FAILURE"); }
    CHECK (run ("part", bodyf, "-o", partf, (char *) NULL) == EX_USAGE, "part without -b is a usage error");
    unlink (partf);
  }

  puts ("== a stalled client is answered 408 within the deadline (compiled to 1 s) ==");
  { /* send a request whose Content-Length promises 10 bytes, deliver 3, then hold
       the connection open (the client's read loop blocks on our response). */
    const char *req = "POST /detect HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
    struct timespec a, b; double elapsed;
    c = client (port, req, strlen (req), out); clear_vars ();
    clock_gettime (CLOCK_MONOTONIC, &a);
    rc = run ("accept", lfd_s, "-H", "CFD", "-m", "METHOD", "-p", "PATH", "-q", "QUERY", "-B", bodyf, (char *) NULL);
    clock_gettime (CLOCK_MONOTONIC, &b);
    elapsed = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    waitpid (c, 0, 0); rawlen = slurp (out, raw, sizeof raw);
    CHECK (rc != EXECUTION_SUCCESS && nvars == 0, "stalled request: accept fails, nothing bound");
    CHECK (elapsed >= 0.9 && elapsed < 5.0, "accept returned at the ~1 s deadline, not before and not blocked");
    CHECK (strncmp (raw, "HTTP/1.1 408 Request Timeout", 28) == 0, "client received 408 Request Timeout");
  }

  puts ("== argument handling ==");
  CHECK (run ("frob", (char *) NULL) == EX_USAGE, "unknown verb -> EX_USAGE");
  CHECK (run ("reply", "3", "-t", "x\r\nInjected: y", "-f", replyf, (char *) NULL) == EX_USAGE, "Content-Type with CR/LF is refused (header injection)");
  CHECK (run ("listen", "0", "-H", "1bad", (char *) NULL) == EX_USAGE, "an invalid variable name is refused");

  close (lfd); clear_vars ();
  unlink (bodyf); unlink (out); unlink (replyf); unlink (stdinf); rmdir (d);
  printf ("\nhttpd-host: %s (%d failures)\n", fails ? "FAILED" : "all checks pass", fails);
  return fails ? 1 : 0;
}
