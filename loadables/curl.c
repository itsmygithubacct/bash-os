/* SPDX-License-Identifier: MIT */
/* curl.c — curl(1) / wget(1) command surface over http + crypto.
 *
 * MISSING_LOADABLES T1 (ML-T1-08) of the bash-os deployable-distro track.
 * Shell scripts in the wild hard-code `curl -fsSL URL` and `wget URL`;
 * this loadable wraps the http + crypto primitives in the curl
 * argv shape so those scripts work unchanged.
 *
 * Subset implemented (curl side):
 *     -X METHOD | --request METHOD
 *                         HTTP verb (default GET, auto-POST when -d set)
 *     -H "K: V" | --header "K: V"
 *                         add request header (repeatable)
 *     -d DATA | --data DATA | --data-raw DATA | --data-ascii DATA
 *                         request body (POST default unless -X set); repeats
 *                         join with '&'; -d @FILE/@- strips CR and LF, and
 *                         the body defaults to x-www-form-urlencoded
 *     --data-binary DATA  request body; @- reads bytes from stdin
 *     -o FILE | --output FILE | -
 *                         output to FILE or stdout (default stdout)
 *     -D FILE | --dump-header FILE | -
 *                         dump response headers
 *     -w FORMAT | --write-out FORMAT
 *                         write-out; curl's common %{variables}, %header{NAME}
 *     -O                  output to basename of URL
 *     -u USER:PASS | --user USER:PASS
 *                         Basic auth (Authorization header)
 *     -A AGENT | --user-agent AGENT
 *                         User-Agent override
 *     -b COOKIE|FILE | --cookie COOKIE|FILE
 *                         literal Cookie: request header value or cookie jar
 *     -c FILE | --cookie-jar FILE
 *                         write Set-Cookie values to a cookie jar
 *     -k / --insecure     skip TLS cert verification
 *     --cacert PEM        use PEM as the TLS trust anchor for HTTPS
 *     -f / --fail         exit 22 on HTTP status >= 400
 *     --fail-with-body    the same, after writing the error page
 *     -s / --silent       suppress progress + non-error chatter
 *     -S / --show-error   pair with -s to keep error diagnostics
 *     -L / --location     follow 3xx Location: redirects (max 20)
 *     --connect-timeout SEC
 *                         maximum time allowed to connect
 *     -m / --max-time SEC overall timeout for the request
 *     -                   read POST body from stdin when -d @-
 *     -I / --head         HEAD request; the response head is the output
 *     -v / --verbose      request and response heads on stderr
 *     -F / --form NAME=VALUE|NAME=@FILE|NAME=<FILE [;type=T][;filename=F]
 *                         multipart/form-data body
 *     -T / --upload-file FILE|-
 *                         PUT the file (a URL without a file part gets
 *                         its name)
 *     -G / --get          send the -d data as the URL query
 *     --data-urlencode [NAME]=TEXT | [NAME]@FILE
 *     --json DATA         JSON body with JSON Content-Type and Accept
 *     --retry N [--retry-delay S] [--retry-connrefused] [--retry-all-errors]
 *                         retry timeouts and HTTP 408/429/500/502/503/504
 *     -x / --proxy [http://][USER:PASS@]HOST[:PORT]
 *                         HTTP proxy; https:// goes through a CONNECT
 *                         tunnel. Proxy environment variables are not read.
 *     --compressed        ask for and decode gzip/deflate
 *     --http2, --http1.1  accepted; the exchange is HTTP/1.1, the
 *                         fallback curl takes when HTTP/2 is not agreed
 *     -r / --range RANGE  byte range
 *     -C / --continue-at OFFSET|-
 *                         resume into the output file
 *     --unix-socket PATH  connect to the unix-domain stream socket PATH
 *                         instead of HOST:PORT (TLS runs over it for
 *                         https://); proxies are not used with it
 *     --abstract-unix-socket NAME
 *                         the same over Linux's abstract namespace
 *
 * Parser compatibility:
 *     Supported long options accept --name=value where Debian curl does.
 *     Short options with arguments accept attached spelling (-oFILE, -m10),
 *     and flag-only short options can be bundled before an argument option
 *     (for example: -fsSLo FILE).
 *
 * Deliberately omitted (out of scope, per work-doc):
 *     non-HTTP cookie schemes, --resolve, HTTP/2 framing, SOCKS proxies, OAuth.
 *
 * Transport layer:
 *     http://  — raw TCP socket via getaddrinfo + connect.
 *     https:// — popen() a bash subshell that pipes the request through
 *                `crypto tls connect HOST:PORT -s HOST [-k]`. The
 *                bash-os variant compiles crypto IN (not as a
 *                dynamically-loaded .so), so the child shell has the
 *                builtin available with no `enable -f` dance.
 *
 * Verb dispatch keeps with the rest of the bash-os loadable family:
 * `curl URL` is the default GET; explicit verbs are not exposed
 * because the curl argv idiom doesn't have a leading verb.
 *
 * --- LICENSE ---
 * MIT License. Copyright (c) 2026 bash_linux contributors.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"
#include "command-run.h"
#include <zlib.h>

/* Caps. Response buffer is the dominant memory footprint; curl is
 * meant for small page/file fetches, not multi-GiB downloads. The cap
 * protects against runaway responses without a Content-Length. */
#define BCURL_MAX_RESPONSE   (512 * 1024 * 1024) /* 512 MiB response ceiling. */
#define BCURL_READ_CHUNK      32768
#define BCURL_HEADER_MAX      16384
#define BCURL_HDRBUF_MAX       8192
#define BCURL_MAX_REDIRECTS       20   /* RFC 9110 §15.4 minimum recommendation; user override via --max-redirs */
#define BCURL_DEFAULT_TIMEOUT 300                /* seconds */
#define BCURL_HEADER_SLOTS       32
#define BCURL_URL_MAX          8192   /* signed storage redirects run past 1 KB */
#define BCURL_VERSION          "0.1"

typedef struct {
  char  scheme[8];
  char  host[256];
  char  port[8];
  char  path[BCURL_URL_MAX];
} bc_url;

typedef struct {
  const char *method;
  const char *url;
  const char *body;
  char       *body_alloc;
  size_t      body_len;
  int         body_set;
  const char *outfile;
  const char *dump_headers;
  const char *write_out;
  const char *user_agent;
  const char *userpass;        /* "user:pass" */
  const char *cookie;          /* literal Cookie: header value or jar path */
  const char *cookie_input;    /* original -b/--cookie value */
  const char *cookie_jar;      /* -c/--cookie-jar output path */
  const char *cacert;          /* --cacert PEM for HTTPS */
  char       *cookie_alloc;    /* loaded jar -> Cookie: value */
  char       *headers[BCURL_HEADER_SLOTS];
  int         nheaders;
  int         use_basename;    /* -O */
  int         follow;          /* -L */
  int         fail_on_error;   /* -f */
  int         fail_with_body;  /* --fail-with-body */
  int         silent;          /* -s */
  int         show_error;      /* -S */
  int         insecure;        /* -k */
  int         connect_time;    /* --connect-timeout SEC */
  int         max_time;        /* --max-time SEC */
  int         max_redirs;      /* --max-redirs N (0 = use BCURL_MAX_REDIRECTS) */
  int         method_set;      /* -X/--request given: keep it across redirects */
  int         offsite;         /* this hop is not on the first URL's origin */
  int         auth_dropped;    /* a hop left the first origin: -u stays off */
  int         features;        /* --features */
  int         head;            /* -I/--head: print the response headers */
  int         verbose;         /* -v/--verbose */
  int         get_query;       /* -G/--get: -d data goes into the URL */
  int         compressed;      /* --compressed */
  int         retries;         /* --retry N */
  int         retry_delay;     /* --retry-delay SEC (0 = doubling from 1) */
  int         retry_connrefused; /* --retry-connrefused */
  int         retry_all;       /* --retry-all-errors */
  int         json;            /* --json given */
  int         resume_set;      /* -C/--continue-at given */
  long long   resume_from;     /* -C offset; -1 = from the output file */
  int         head_hops;       /* -I -L: response heads written so far */
  const char *content_type;    /* NULL: form default; "": send none */
  char       *content_type_alloc;
  const char *accept;          /* default Accept value */
  const char *upload;          /* -T/--upload-file FILE */
  const char *range;           /* -r/--range RANGE */
  const char *proxy;           /* -x/--proxy [scheme://][user:pass@]host[:port] */
  const char *unix_socket;     /* --unix-socket / --abstract-unix-socket PATH */
  int         abstract_unix;   /* unix_socket names an abstract socket */
  const char *forms[BCURL_HEADER_SLOTS]; /* -F/--form specs */
  int         nforms;
  char        proxy_auth[512]; /* base64 user:pass from the proxy URL */
} bc_opts;

typedef struct {
  int   status;
  char *headers;               /* malloc'd; raw header block (no trailer CRLFCRLF) */
  unsigned char *informational; /* preceding 1xx heads for -D */
  size_t informational_len;
  size_t hlen;
  unsigned char *body;         /* malloc'd; raw decoded body */
  size_t blen;
  char  location[BCURL_URL_MAX]; /* extracted Location: header if 3xx */
  int   location_too_long;     /* the Location: header did not fit */
  int   location_bad;          /* the Location: header holds a control byte */
  long  missing;               /* Content-Length bytes the peer never sent */
} bc_response;

/* Transfer-phase state for one invocation. -s without -S silences the
 * diagnostics curl would also silence; bc_errcode carries curl's exit
 * code (CURLE_*) out of the transport, 0 meaning a plain failure. */
static int bc_quiet;
static int bc_errcode;
#define bc_error(...) do { if (!bc_quiet) builtin_error (__VA_ARGS__); } while (0)

/* curl(1)-shaped "curl: (N) message" diagnostic, shown unless silenced. */
/* What -w/--write-out reports about this invocation. */
static struct
{
  struct timespec start, connected, received;
  int have_connected, have_received;
  /* remote_ip holds a socket path under --unix-socket, as curl reports. */
  char remote_ip[sizeof ((struct sockaddr_un *) 0)->sun_path + 1], local_ip[INET6_ADDRSTRLEN];
  int remote_port, local_port, connects;
  const char *url;             /* as given */
  const char *effective;       /* the last URL fetched */
  int redirects;
  long header_bytes;           /* all response heads, as size_header */
  int exitcode;
  char errormsg[256];
} bc_wo;

static double bc_wo_seconds (const struct timespec *t);
static void bc_curl_error (int code, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));
static void
bc_curl_error (int code, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vsnprintf (bc_wo.errormsg, sizeof bc_wo.errormsg, fmt, ap);
  va_end (ap);
  bc_wo.exitcode = code;
  if (bc_quiet) return;
  fprintf (stderr, "curl: (%d) %s\n", code, bc_wo.errormsg);
}

static void
bc_wo_address (const struct sockaddr_storage *ss, char *ip, size_t ipsz, int *port)
{
  ip[0] = '\0';
  *port = 0;
  if (ss->ss_family == AF_INET)
    {
      const struct sockaddr_in *a = (const struct sockaddr_in *) ss;
      inet_ntop (AF_INET, &a->sin_addr, ip, (socklen_t) ipsz);
      *port = ntohs (a->sin_port);
    }
  else if (ss->ss_family == AF_INET6)
    {
      const struct sockaddr_in6 *a = (const struct sockaddr_in6 *) ss;
      inet_ntop (AF_INET6, &a->sin6_addr, ip, (socklen_t) ipsz);
      *port = ntohs (a->sin6_port);
    }
}

/* ---- url parser (mirrors http's, with bigger path buffer) ---- */
static int
bc_parse_url (const char *url, bc_url *u)
{
  memset (u, 0, sizeof *u);
  const char *p = strstr (url, "://");
  if (!p) return -1;
  size_t sl = (size_t) (p - url);
  if (sl == 0 || sl >= sizeof u->scheme) return -1;
  memcpy (u->scheme, url, sl);
  p += 3;
  const char *slash = strchr (p, '/');
  const char *end = slash ? slash : url + strlen (url);
  const char *colon = NULL;
  for (const char *q = p; q < end; q++)
    if (*q == ':') { colon = q; break; }
  size_t hl = (size_t) ((colon ? colon : end) - p);
  if (hl == 0 || hl >= sizeof u->host) return -1;
  memcpy (u->host, p, hl);
  if (colon)
    {
      size_t pl = (size_t) (end - colon - 1);
      if (pl == 0 || pl >= sizeof u->port) return -1;
      memcpy (u->port, colon + 1, pl);
    }
  else
    snprintf (u->port, sizeof u->port, "%s",
              strcasecmp (u->scheme, "https") == 0 ? "443" : "80");
  if (snprintf (u->path, sizeof u->path, "%s", slash ? slash : "/") >= (int) sizeof u->path)
    return -1;
  return 0;
}

/* ---- minimal base64 encoder (RFC 4648) for Basic auth ---- */
static const char bc_b64tab[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *
bc_b64encode (const unsigned char *in, size_t n)
{
  size_t out_len = 4 * ((n + 2) / 3) + 1;
  char *out = malloc (out_len);
  if (!out) return NULL;
  size_t i, j = 0;
  for (i = 0; i + 3 <= n; i += 3)
    {
      unsigned v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
      out[j++] = bc_b64tab[(v >> 18) & 0x3F];
      out[j++] = bc_b64tab[(v >> 12) & 0x3F];
      out[j++] = bc_b64tab[(v >>  6) & 0x3F];
      out[j++] = bc_b64tab[ v        & 0x3F];
    }
  if (i < n)
    {
      unsigned v = in[i] << 16;
      if (i + 1 < n) v |= in[i+1] << 8;
      out[j++] = bc_b64tab[(v >> 18) & 0x3F];
      out[j++] = bc_b64tab[(v >> 12) & 0x3F];
      out[j++] = (i + 1 < n) ? bc_b64tab[(v >> 6) & 0x3F] : '=';
      out[j++] = '=';
    }
  out[j] = '\0';
  return out;
}

/* ---- header buffer helpers ---- */
static int
bc_hdr_append (char *buf, size_t cap, const char *line)
{
  size_t blen = strlen (buf);
  size_t nlen = strlen (line);
  if (blen + nlen + 3 >= cap) return -1;
  memcpy (buf + blen, line, nlen);
  buf[blen + nlen + 0] = '\r';
  buf[blen + nlen + 1] = '\n';
  buf[blen + nlen + 2] = '\0';
  return 0;
}

/* ---- request framing ---- */

/* Does the -H value H name header NAME ("Name: v", "Name:" or "Name;")? */
static int
bc_header_is (const char *h, const char *name)
{
  size_t n = strlen (name);
  return strncasecmp (h, name, n) == 0 && (h[n] == ':' || h[n] == ';');
}

/* Any -H for NAME replaces curl's own header; an empty one removes it. */
static int
bc_user_header (const bc_opts *o, const char *name)
{
  for (int i = 0; i < o->nheaders; i++)
    if (bc_header_is (o->headers[i], name))
      return 1;
  return 0;
}

/* curl's rule for credentials on a redirect: an origin is the scheme, the
   host (any case) and the port. */
static int
bc_same_origin (const bc_url *a, const bc_url *b)
{
  return strcasecmp (a->scheme, b->scheme) == 0
         && strcasecmp (a->host, b->host) == 0
         && strtol (a->port, NULL, 10) == strtol (b->port, NULL, 10);
}

static char *
bc_build_request (const bc_opts *o, const bc_url *u, size_t *out_len)
{
  char hdrs[BCURL_HDRBUF_MAX];
  hdrs[0] = '\0';

  for (int i = 0; i < o->nheaders; i++)
    {
      const char *h = o->headers[i];
      const char *colon = strchr (h, ':');
      const char *semi = strchr (h, ';');
      char empty[BCURL_HDRBUF_MAX];
      /* Like curl, -H Authorization and Cookie go only to the first
         origin; there is no option that sends them elsewhere. */
      if (o->offsite && (bc_header_is (h, "Authorization") || bc_header_is (h, "Cookie")))
        continue;
      if (colon)
        {
          /* "Name:" with no value removes the header instead of sending it. */
          const char *v = colon + 1;
          while (*v == ' ' || *v == '\t') v++;
          if (!*v) continue;
        }
      else if (semi && semi[1] == '\0' && semi > h)
        {
          /* "Name;" sends the header with an empty value. */
          snprintf (empty, sizeof empty, "%.*s:", (int) (semi - h), h);
          h = empty;
        }
      if (bc_hdr_append (hdrs, sizeof hdrs, h) < 0)
        { bc_error ("-H aggregate exceeds %d bytes", BCURL_HDRBUF_MAX); return NULL; }
    }

  char auth_hdrs[BCURL_HDRBUF_MAX] = "";
  /* Basic auth: only injected when -u is set and the caller did not
   * already supply an Authorization header. As in curl, a redirect that
   * leaves the first origin drops -u for the rest of the transfer. */
  if (o->userpass && !o->auth_dropped && !bc_user_header (o, "Authorization"))
    {
      char *b64 = bc_b64encode ((const unsigned char *) o->userpass,
                                strlen (o->userpass));
      if (!b64) { bc_error ("out of memory"); return NULL; }
      char line[BCURL_HDRBUF_MAX];
      snprintf (line, sizeof line, "Authorization: Basic %s", b64);
      free (b64);
      if (bc_hdr_append (auth_hdrs, sizeof auth_hdrs, line) < 0)
        { bc_error ("header buffer exceeded"); return NULL; }
    }

  /* curl -b/--cookie accepts either a literal cookie string or a cookie
   * jar path; a caller-supplied Cookie: via -H wins. */
  if (o->cookie && !bc_user_header (o, "Cookie"))
    {
      char line[BCURL_HDRBUF_MAX];
      snprintf (line, sizeof line, "Cookie: %s", o->cookie);
      if (bc_hdr_append (hdrs, sizeof hdrs, line) < 0)
        { bc_error ("header buffer exceeded"); return NULL; }
    }

  /* RFC 9110 7.2: Host carries the port unless it is the scheme default. */
  char host[sizeof u->host + sizeof u->port + 1];
  int is_https = strcasecmp (u->scheme, "https") == 0;
  if (strcmp (u->port, is_https ? "443" : "80") != 0)
    snprintf (host, sizeof host, "%s:%s", u->host, u->port);
  else
    snprintf (host, sizeof host, "%s", u->host);

  /* A -H header of the same name replaces (or, when empty, removes) these. */
  char builtin_hdrs[BCURL_HDRBUF_MAX + 64];
  builtin_hdrs[0] = '\0';
  const char *ua = o->user_agent ? o->user_agent : "curl/" BCURL_VERSION;
  char line[BCURL_HDRBUF_MAX + 16];
  if (!bc_user_header (o, "Host"))
    { snprintf (line, sizeof line, "Host: %s", host); bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line); }
  if (strlen (builtin_hdrs) + strlen (auth_hdrs) >= sizeof builtin_hdrs)
    { bc_error ("header buffer exceeded"); return NULL; }
  strcat (builtin_hdrs, auth_hdrs);
  if (!bc_user_header (o, "User-Agent"))
    {
      snprintf (line, sizeof line, "User-Agent: %s", ua);
      if (bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line) < 0)
        { bc_error ("header buffer exceeded"); return NULL; }
    }
  if (!bc_user_header (o, "Accept"))
    {
      snprintf (line, sizeof line, "Accept: %s", o->accept ? o->accept : "*/*");
      bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line);
    }
  if (o->range && !bc_user_header (o, "Range"))
    {
      snprintf (line, sizeof line, "Range: bytes=%s", o->range);
      if (bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line) < 0)
        { bc_error ("header buffer exceeded"); return NULL; }
    }
  else if (o->resume_set && o->resume_from > 0 && !bc_user_header (o, "Range"))
    {
      snprintf (line, sizeof line, "Range: bytes=%lld-", o->resume_from);
      bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line);
    }
  if (o->compressed && !bc_user_header (o, "Accept-Encoding"))
    bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, "Accept-Encoding: deflate, gzip");
  if (o->proxy && strcasecmp (u->scheme, "http") == 0 && o->proxy_auth[0]
      && !bc_user_header (o, "Proxy-Authorization"))
    {
      snprintf (line, sizeof line, "Proxy-Authorization: Basic %s", o->proxy_auth);
      bc_hdr_append (builtin_hdrs, sizeof builtin_hdrs, line);
    }

  /* The buffer holds the request line, both header blocks, the framing
     lines (" HTTP/1.1", Content-Length, Content-Type and CRLFs: under
     160 bytes) and the body. An -X method of any length is counted. */
  size_t body_len = o->body_set ? o->body_len : 0;
  size_t parts[] = { strlen (o->method), strlen (u->path), strlen (builtin_hdrs),
                     strlen (hdrs), body_len, 160 + 512 };
  size_t need = 1;
  for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++)
    {
      if (parts[i] > SIZE_MAX - need)
        { bc_error ("request too large"); return NULL; }
      need += parts[i];
    }
  char *req = malloc (need);
  if (!req) { bc_error ("out of memory"); return NULL; }

  char framing[512] = "";
  if (o->body_set && !bc_user_header (o, "Content-Length"))
    snprintf (framing, sizeof framing, "Content-Length: %zu\r\n", body_len);
  const char *ctype = o->content_type ? o->content_type
                      : "application/x-www-form-urlencoded";
  if (o->body_set && *ctype && !bc_user_header (o, "Content-Type"))
    {
      size_t used = strlen (framing);
      snprintf (framing + used, sizeof framing - used, "Content-Type: %s\r\n", ctype);
    }
  /* Through an HTTP proxy, a plain http:// request names its absolute URL. */
  char target_prefix[sizeof u->host + sizeof u->port + 16] = "";
  if (o->proxy && strcasecmp (u->scheme, "http") == 0)
    snprintf (target_prefix, sizeof target_prefix, "http://%s", host);
  if (strlen (target_prefix) > SIZE_MAX - need)
    { free (req); bc_error ("request too large"); return NULL; }
  need += strlen (target_prefix);
  char *grown = realloc (req, need);
  if (!grown) { free (req); bc_error ("out of memory"); return NULL; }
  req = grown;
  int n = snprintf (req, need, "%s %s%s HTTP/1.1\r\n%s%s%s\r\n",
                    o->method, target_prefix, u->path, builtin_hdrs, hdrs, framing);
  if (n < 0 || (size_t) n >= need || body_len > need - 1 - (size_t) n)
    { free (req); bc_error ("request framing overflow"); return NULL; }
  if (body_len)
    memcpy (req + n, o->body, body_len);
  *out_len = (size_t) n + body_len;
  return req;
}

static int
bc_slurp_fd_string (int fd, char **out, size_t *out_len)
{
  size_t cap = 4096, len = 0;
  char *buf = malloc (cap + 1);
  if (!buf) { bc_error ("out of memory"); return -1; }
  for (;;)
    {
      if (len == cap)
        {
          if (cap >= BCURL_MAX_RESPONSE)
            { free (buf); bc_error ("stdin body exceeds %d bytes", BCURL_MAX_RESPONSE); return -1; }
          size_t ncap = cap * 2;
          if (ncap > BCURL_MAX_RESPONSE) ncap = BCURL_MAX_RESPONSE;
          char *nb = realloc (buf, ncap + 1);
          if (!nb) { free (buf); bc_error ("out of memory"); return -1; }
          buf = nb; cap = ncap;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0)
        { if (errno == EINTR) continue;
          free (buf); bc_error ("read stdin: %s", strerror (errno)); return -1; }
      if (r == 0) break;
      len += (size_t) r;
    }
  buf[len] = '\0';
  *out = buf;
  *out_len = len;
  return 0;
}

/* ---- minimal cookie jar support ---- */
static int
bc_cookie_domain_match (const char *host, const char *domain, int tailmatch)
{
  if (!host || !domain || !*host || !*domain) return 0;
  const char *d = strncmp (domain, "#HttpOnly_", 10) == 0 ? domain + 10 : domain;
  d = d[0] == '.' ? d + 1 : d;
  if (strcasecmp (host, d) == 0) return 1;
  if (!tailmatch) return 0;
  size_t hl = strlen (host), dl = strlen (d);
  return hl > dl && host[hl - dl - 1] == '.' && strcasecmp (host + hl - dl, d) == 0;
}

static int
bc_cookie_path_match (const char *req_path, const char *cookie_path)
{
  if (!cookie_path || !*cookie_path) return 1;
  if (!req_path || !*req_path) req_path = "/";
  size_t n = strlen (cookie_path);
  if (strncmp (req_path, cookie_path, n) != 0) return 0;
  return cookie_path[n - 1] == '/' || req_path[n] == '\0' || req_path[n] == '/';
}

static int
bc_cookie_samesite_value (const char *s, char *out, size_t outsz);

static void
bc_cookie_canon_domain (const char *in, char *out, size_t outsz)
{
  if (!in || !out || outsz == 0) return;
  if (strncmp (in, "#HttpOnly_", 10) == 0) in += 10;
  while (*in == '.') in++;
  size_t n = strlen (in);
  while (n > 0 && in[n - 1] == '.') n--;
  if (n >= outsz) n = outsz - 1;
  for (size_t i = 0; i < n; i++)
    out[i] = (char) tolower ((unsigned char) in[i]);
  out[n] = '\0';
}

static int
bc_cookie_is_ip_literal (const char *host)
{
  if (!host || !*host) return 0;
  for (const char *p = host; *p; p++)
    if (!isdigit ((unsigned char) *p) && *p != '.' && *p != ':')
      return 0;
  return 1;
}

static int
bc_cookie_is_public_suffix (const char *domain)
{
  static const char *exact[] = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "github.io", "appspot.com", "cloudfront.net", "s3.amazonaws.com",
    NULL
  };
  char d[256];
  bc_cookie_canon_domain (domain, d, sizeof d);
  if (!d[0] || bc_cookie_is_ip_literal (d)) return 0;
  for (int i = 0; exact[i]; i++)
    if (strcmp (d, exact[i]) == 0)
      return 1;
  return 0;
}

static int
bc_cookie_accept_domain (const char *host, const char *attr,
                         char *out, size_t outsz, int *tailmatch)
{
  char h[256], d[256];
  bc_cookie_canon_domain (host, h, sizeof h);
  bc_cookie_canon_domain (attr, d, sizeof d);
  if (!h[0] || !d[0]) return 0;
  if (bc_cookie_is_public_suffix (d) && strcmp (h, d) != 0)
    return 0;
  if (!bc_cookie_domain_match (h, d, 1))
    return 0;
  snprintf (out, outsz, "%s", d);
  if (tailmatch) *tailmatch = strcmp (h, d) != 0 || (attr && attr[0] == '.');
  return 1;
}

typedef struct {
  char domain[256];
  char path[256];
  char name[128];
  char value[8];
} bc_samesite_meta;

static int
bc_cookie_same_site (const bc_url *a, const bc_url *b)
{
  char ah[256], bh[256];
  if (!a || !b) return 1;
  bc_cookie_canon_domain (a->host, ah, sizeof ah);
  bc_cookie_canon_domain (b->host, bh, sizeof bh);
  if (!ah[0] || !bh[0]) return 1;
  if (strcmp (ah, bh) == 0) return 1;
  if (bc_cookie_is_ip_literal (ah) || bc_cookie_is_ip_literal (bh))
    return 0;
  const char *adot = strchr (ah, '.');
  const char *bdot = strchr (bh, '.');
  if (!adot || !bdot) return 0;
  return strcmp (adot + 1, bdot + 1) == 0;
}

static const char *
bc_cookie_find_samesite (bc_samesite_meta *meta, int nmeta,
                         const char *domain, const char *path, const char *name)
{
  char d[256];
  bc_cookie_canon_domain (domain, d, sizeof d);
  for (int i = 0; i < nmeta; i++)
    if (strcmp (meta[i].domain, d) == 0
        && strcmp (meta[i].path, path ? path : "") == 0
        && strcmp (meta[i].name, name ? name : "") == 0)
      return meta[i].value;
  return "Lax";
}

static int
bc_cookie_samesite_allows (const char *same, int secure,
                           const char *method, const bc_url *request_url,
                           const bc_url *site_url)
{
  int same_site = bc_cookie_same_site (request_url, site_url);
  if (!same || !*same) same = "Lax";
  if (strcasecmp (same, "None") == 0)
    return secure;
  if (strcasecmp (same, "Strict") == 0)
    return same_site;
  if (same_site) return 1;
  return !method || strcasecmp (method, "GET") == 0
         || strcasecmp (method, "HEAD") == 0
         || strcasecmp (method, "OPTIONS") == 0
         || strcasecmp (method, "TRACE") == 0;
}

static char *
bc_cookie_from_jar (const char *path, const bc_url *u,
                    const bc_url *site_url, const char *method)
{
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  char *buf = NULL;
  size_t len = 0;
  if (bc_slurp_fd_string (fd, &buf, &len) < 0)
    { close (fd); return NULL; }
  close (fd);

  char *scan = malloc (len + 1);
  if (!scan) { free (buf); bc_error ("out of memory"); return NULL; }
  memcpy (scan, buf, len + 1);

  bc_samesite_meta meta[64];
  int nmeta = 0;
  char *msave = NULL;
  for (char *line = strtok_r (scan, "\n", &msave); line; line = strtok_r (NULL, "\n", &msave))
    {
      while (*line == ' ' || *line == '\t' || *line == '\r') line++;
      if (strncmp (line, "# Bashcurl-SameSite\t", 20) != 0) continue;
      char *cols[5] = {0};
      int n = 0;
      for (char *tok = strtok (line + 20, "\t"); tok && n < 5; tok = strtok (NULL, "\t"))
        cols[n++] = tok;
      if (n < 4 || nmeta >= 64) continue;
      bc_cookie_canon_domain (cols[0], meta[nmeta].domain, sizeof meta[nmeta].domain);
      snprintf (meta[nmeta].path, sizeof meta[nmeta].path, "%s", cols[1]);
      snprintf (meta[nmeta].name, sizeof meta[nmeta].name, "%s", cols[2]);
      if (bc_cookie_samesite_value (cols[3], meta[nmeta].value, sizeof meta[nmeta].value))
        nmeta++;
    }
  free (scan);

  char *out = malloc (len + 1);
  if (!out) { free (buf); bc_error ("out of memory"); return NULL; }
  out[0] = '\0';
  size_t out_len = 0;
  char *save = NULL;
  for (char *line = strtok_r (buf, "\n", &save); line; line = strtok_r (NULL, "\n", &save))
    {
      while (*line == ' ' || *line == '\t' || *line == '\r') line++;
      if (*line == '\0') continue;
      if (*line == '#' && strncmp (line, "#HttpOnly_", 10) != 0) continue;
      char *cols[7] = {0};
      int n = 0;
      for (char *tok = strtok (line, "\t"); tok && n < 7; tok = strtok (NULL, "\t"))
        cols[n++] = tok;
      if (n < 7 || !cols[5] || !cols[6]) continue;
      int tailmatch = strcasecmp (cols[1], "TRUE") == 0 || cols[0][0] == '.';
      int secure = strcasecmp (cols[3], "TRUE") == 0;
      long expires = strtol (cols[4], NULL, 10);
      const char *same = bc_cookie_find_samesite (meta, nmeta, cols[0], cols[2], cols[5]);
      if (!bc_cookie_domain_match (u->host, cols[0], tailmatch)) continue;
      if (!bc_cookie_path_match (u->path, cols[2])) continue;
      if (secure && strcasecmp (u->scheme, "https") != 0) continue;
      if (expires > 0 && expires < (long) time (NULL)) continue;
      if (!bc_cookie_samesite_allows (same, secure, method, u, site_url)) continue;
      size_t need = strlen (cols[5]) + strlen (cols[6]) + 3 + (out_len ? 2 : 0);
      if (out_len + need + 1 > len + 1) continue;
      if (out_len)
        { out[out_len++] = ';'; out[out_len++] = ' '; }
      size_t nl = strlen (cols[5]), vl = strlen (cols[6]);
      memcpy (out + out_len, cols[5], nl); out_len += nl;
      out[out_len++] = '=';
      memcpy (out + out_len, cols[6], vl); out_len += vl;
      out[out_len] = '\0';
    }
  free (buf);
  if (out_len == 0) { free (out); return NULL; }
  return out;
}

static long
bc_cookie_max_age (const char *s)
{
  if (!s || !*s) return 0;
  char *end = NULL;
  long n = strtol (s, &end, 10);
  if (end == s) return 0;
  return n;
}

static long
bc_days_from_civil (int y, unsigned m, unsigned d)
{
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = (unsigned) (y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return (long) era * 146097L + (long) doe - 719468L;
}

static int
bc_cookie_month (const char *m)
{
  static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  for (int i = 0; i < 12; i++)
    if (strncasecmp (m, months + i * 3, 3) == 0)
      return i + 1;
  return 0;
}

static int
bc_cookie_parse_http_date (const char *s, long *out)
{
  if (!s || !*s || !out) return -1;
  while (*s == ' ' || *s == '\t') s++;

  int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
  char mon[4] = {0};
  if (sscanf (s, "%*3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d GMT",
              &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%d %3[A-Za-z] %d %d:%d:%d GMT",
                 &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%*[^,], %d-%3[A-Za-z]-%d %d:%d:%d GMT",
                 &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%*3[A-Za-z] %3[A-Za-z] %d %d:%d:%d %d",
                 mon, &day, &hh, &mm, &ss, &year) != 6)
    return -1;
  if (year >= 0 && year < 100)
    year += year >= 70 ? 1900 : 2000;

  int month = bc_cookie_month (mon);
  if (year < 1970 || month < 1 || day < 1 || day > 31
      || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60)
    return -1;
  long days = bc_days_from_civil (year, (unsigned) month, (unsigned) day);
  if (days < 0) return -1;
  *out = days * 86400L + hh * 3600L + mm * 60L + ss;
  return 0;
}

static void
bc_trim_cookie_token (char *s)
{
  char *e = s + strlen (s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
    *--e = '\0';
}

static int
bc_cookie_samesite_value (const char *s, char *out, size_t outsz)
{
  if (!s || !*s || !out || outsz == 0) return 0;
  if (strcasecmp (s, "Strict") == 0)
    snprintf (out, outsz, "Strict");
  else if (strcasecmp (s, "Lax") == 0)
    snprintf (out, outsz, "Lax");
  else if (strcasecmp (s, "None") == 0)
    snprintf (out, outsz, "None");
  else
    return 0;
  return 1;
}

static int
bc_save_cookie_jar (const char *path, const bc_url *u, const char *hdrs)
{
  if (!path) return 0;
  /* libcurl creates the jar as 0666 and lets the process umask apply,
   * so umask 022 yields 0644 and umask 000 yields 0666. */
  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  FILE *fp = fd < 0 ? NULL : fdopen (fd, "wb");
  if (!fp)
    { int saved = errno; if (fd >= 0) close (fd);
      bc_error ("%s: %s", path, strerror (saved)); return -1; }
  fprintf (fp, "# Netscape HTTP Cookie File\n");
  fprintf (fp, "# https://curl.se/docs/http-cookies.html\n");
  fprintf (fp, "# This file was generated by libcurl! Edit at your own risk.\n\n");

  int wrote = 0;
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Set-Cookie:", 11) == 0)
        {
          const char *v = p + 11;
          while (*v == ' ' || *v == '\t') v++;
          const char *eol = strstr (v, "\r\n");
          size_t n = eol ? (size_t) (eol - v) : strlen (v);
          char line[1024];
          if (n >= sizeof line) n = sizeof line - 1;
          memcpy (line, v, n); line[n] = '\0';

          char *attrs = strchr (line, ';');
          if (attrs) *attrs++ = '\0';
          char *eq = strchr (line, '=');
          if (!eq || eq == line) goto next_line;
          *eq++ = '\0';
          bc_trim_cookie_token (line);
          bc_trim_cookie_token (eq);

          char pathbuf[256] = "/";
          char domainbuf[256];
          snprintf (domainbuf, sizeof domainbuf, "%s", u->host);
          int tailmatch = 0;
          int secure = 0;
          int httponly = 0;
          char samesite[8] = "";
          long expires = 0;
          int drop_cookie = 0;
          for (char *tok = attrs; tok; )
            {
              while (*tok == ' ' || *tok == '\t' || *tok == ';') tok++;
              char *next = strchr (tok, ';');
              if (next) *next++ = '\0';
              bc_trim_cookie_token (tok);
              if (strncasecmp (tok, "Path=", 5) == 0 && tok[5])
                snprintf (pathbuf, sizeof pathbuf, "%s", tok + 5);
              else if (strncasecmp (tok, "Domain=", 7) == 0 && tok[7])
                {
                  const char *d = tok + 7;
                  if (!bc_cookie_accept_domain (u->host, d, domainbuf,
                                                sizeof domainbuf, &tailmatch))
                    drop_cookie = 1;
                }
              else if (strncasecmp (tok, "Max-Age=", 8) == 0)
                {
                  long age = bc_cookie_max_age (tok + 8);
                  if (age <= 0)
                    drop_cookie = 1;
                  else
                    expires = (long) time (NULL) + age;
                }
              else if (strncasecmp (tok, "Expires=", 8) == 0)
                {
                  long when = 0;
                  if (bc_cookie_parse_http_date (tok + 8, &when) == 0)
                    {
                      if (when <= (long) time (NULL))
                        drop_cookie = 1;
                      else if (expires == 0)
                        expires = when;
                    }
                }
              else if (strcasecmp (tok, "Secure") == 0)
                secure = 1;
              else if (strcasecmp (tok, "HttpOnly") == 0)
                httponly = 1;
              else if (strncasecmp (tok, "SameSite=", 9) == 0)
                bc_cookie_samesite_value (tok + 9, samesite, sizeof samesite);
              tok = next;
            }
          if (strcasecmp (samesite, "None") == 0 && !secure)
            drop_cookie = 1;
          if (drop_cookie) goto next_line;
          fprintf (fp, "%s%s\t%s\t%s\t%s\t%ld\t%s\t%s\n",
                   httponly ? "#HttpOnly_" : "", domainbuf,
                   tailmatch ? "TRUE" : "FALSE", pathbuf,
                   secure ? "TRUE" : "FALSE", expires, line, eq);
          if (samesite[0])
            fprintf (fp, "# Bashcurl-SameSite\t%s\t%s\t%s\t%s\n",
                     domainbuf, pathbuf, line, samesite);
          wrote++;
        }
next_line:
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }

  if (fclose (fp) != 0)
    { bc_error ("%s: %s", path, strerror (errno)); return -1; }
  return wrote >= 0 ? 0 : -1;
}

/* ---- network: HTTP (plain TCP) ---- */
static int
bc_connect_tcp (const char *host, const char *port, int timeout_s)
{
  struct addrinfo hints, *ai = NULL, *p;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  /* Retry getaddrinfo on EAI_AGAIN (a *temporary* resolver failure that means
   * "try again") with a short backoff, mirroring crypto's TLS connect: under
   * QEMU slirp the built-in DNS forwarder is intermittently flaky on some names,
   * which would otherwise fail a plain-HTTP fetch on the first hiccup. Permanent
   * errors (EAI_NONAME, ...) still fail at once. */
  int rc;
  for (int attempt = 0; ; attempt++)
    {
      ai = NULL;
      rc = getaddrinfo (host, port, &hints, &ai);
      if (rc != EAI_AGAIN || attempt >= 5) break;   /* up to 6 attempts */
      long ms = 200 + attempt * 200; if (ms > 1000) ms = 1000;
      struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
      nanosleep (&ts, NULL);
    }
  if (rc != 0)
    {
      bc_error ("getaddrinfo %s:%s: %s", host, port, gai_strerror (rc));
      snprintf (bc_wo.errormsg, sizeof bc_wo.errormsg, "Could not resolve host: %s", host);
      bc_errcode = 6;                     /* CURLE_COULDNT_RESOLVE_HOST */
      return -1;
    }
  int fd = -1;
  int timed_out = 0;
  for (p = ai; p; p = p->ai_next)
    {
      fd = socket (p->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (fd < 0) continue;

      int flags = fcntl (fd, F_GETFL, 0);
      fcntl (fd, F_SETFL, flags | O_NONBLOCK);
      rc = connect (fd, p->ai_addr, p->ai_addrlen);
      if (rc == 0) { fcntl (fd, F_SETFL, flags); break; }
      if (errno != EINPROGRESS) { close (fd); fd = -1; continue; }

      fd_set wfds;
      FD_ZERO (&wfds); FD_SET (fd, &wfds);
      struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
      int sr = select (fd + 1, NULL, &wfds, NULL, &tv);
      if (sr <= 0) { timed_out |= sr == 0; close (fd); fd = -1; continue; }

      int err = 0; socklen_t el = sizeof err;
      if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0)
        { close (fd); fd = -1; continue; }
      fcntl (fd, F_SETFL, flags);
      break;
    }
  freeaddrinfo (ai);
  if (fd >= 0)
    {
      struct sockaddr_storage ss;
      socklen_t sl = sizeof ss;
      if (getpeername (fd, (struct sockaddr *) &ss, &sl) == 0)
        bc_wo_address (&ss, bc_wo.remote_ip, sizeof bc_wo.remote_ip, &bc_wo.remote_port);
      sl = sizeof ss;
      if (getsockname (fd, (struct sockaddr *) &ss, &sl) == 0)
        bc_wo_address (&ss, bc_wo.local_ip, sizeof bc_wo.local_ip, &bc_wo.local_port);
      clock_gettime (CLOCK_MONOTONIC, &bc_wo.connected);
      bc_wo.have_connected = 1;
      bc_wo.connects++;
    }
  if (fd < 0)
    {
      bc_error ("cannot connect to %s:%s", host, port);
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);
      if (!timed_out)
        snprintf (bc_wo.errormsg, sizeof bc_wo.errormsg,
                  "Failed to connect to %s port %s after %.0f ms: Could not connect to server",
                  host, port, bc_wo_seconds (&now) * 1000.0);
      bc_errcode = timed_out ? 28 : 7;    /* CURLE_OPERATION_TIMEDOUT / CURLE_COULDNT_CONNECT */
    }
  return fd;
}

/* ---- network: --unix-socket / --abstract-unix-socket ---- */
static int
bc_connect_unix (const char *path, int abstract, const char *host, const char *port)
{
  struct sockaddr_un sun;
  size_t n = strlen (path), off = abstract ? 1 : 0;
  memset (&sun, 0, sizeof sun);
  sun.sun_family = AF_UNIX;
  int fd = -1, err = ENAMETOOLONG;
  if (n + off < sizeof sun.sun_path)
    {
      memcpy (sun.sun_path + off, path, n);
      /* An abstract name is the bytes after the leading NUL, unterminated. */
      socklen_t sl = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + off + n + !abstract);
      fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (fd >= 0)
        {
          int rc;
          do rc = connect (fd, (struct sockaddr *) &sun, sl);
          while (rc < 0 && errno == EINTR);
          if (rc < 0) { err = errno; close (fd); fd = -1; }
        }
      else
        err = errno;
    }
  if (fd < 0)
    {
      bc_error ("cannot connect to %s%s: %s", abstract ? "@" : "", path, strerror (err));
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);
      snprintf (bc_wo.errormsg, sizeof bc_wo.errormsg,
                "Failed to connect to %s port %s after %.0f ms: Could not connect to server",
                host, port, bc_wo_seconds (&now) * 1000.0);
      bc_errcode = 7;                     /* CURLE_COULDNT_CONNECT */
      return -1;
    }
  snprintf (bc_wo.remote_ip, sizeof bc_wo.remote_ip, "%s", path);
  bc_wo.remote_port = 0;
  bc_wo.local_ip[0] = '\0';
  bc_wo.local_port = 0;
  clock_gettime (CLOCK_MONOTONIC, &bc_wo.connected);
  bc_wo.have_connected = 1;
  bc_wo.connects++;
  return fd;
}

static int
bc_write_all (int fd, const char *buf, size_t n)
{
  size_t off = 0;
  while (off < n)
    {
      ssize_t w = write (fd, buf + off, n - off);
      if (w < 0) { if (errno == EINTR) continue; return -1; }
      off += (size_t) w;
    }
  return 0;
}

/* Informational heads precede the final response. Leave incomplete heads in
   the buffer until the rest arrives; never treat them as the final response. */
static int
bc_skip_informational (const unsigned char **data, size_t *len)
{
  while (*len >= 12 && memcmp (*data, "HTTP/", 5) == 0 &&
         (*data)[9] >= '0' && (*data)[9] <= '9' &&
         (*data)[10] >= '0' && (*data)[10] <= '9' &&
         (*data)[11] >= '0' && (*data)[11] <= '9')
    {
      int code = ((*data)[9] - '0') * 100 + ((*data)[10] - '0') * 10 + ((*data)[11] - '0');
      if (code < 100 || code >= 200 || code == 101) break;
      size_t end = 0;
      for (size_t i = 0; i + 4 <= *len && i < BCURL_HEADER_MAX; i++)
        if (memcmp (*data + i, "\r\n\r\n", 4) == 0)
          { end = i + 4; break; }
      if (!end) return 0;
      *data += end;
      *len -= end;
    }
  return 1;
}

/* Return 0 for a valid (or absent) Content-Length, -1 for invalid or
   conflicting fields. Identical repeated values are safe. */
static int
bc_checked_response_length (const char *headers, long long *length)
{
  const char *line = strstr (headers, "\r\n");
  *length = -1;
  while (line && line[2] && line[2] != '\r')
    {
      line += 2;
      if (strncasecmp (line, "Content-Length:", 15) == 0)
        {
          const char *v = line + 15;
          while (*v == ' ' || *v == '\t') v++;
          if (!isdigit ((unsigned char) *v)) return -1;
          char *end;
          errno = 0;
          long long n = strtoll (v, &end, 10);
          if (errno || n < 0) return -1;
          while (*end == ' ' || *end == '\t') end++;
          if (end[0] != '\r' || end[1] != '\n' ||
              (*length >= 0 && *length != n)) return -1;
          *length = n;
        }
      line = strstr (line, "\r\n");
    }
  return 0;
}

/* Detect a complete framed response without waiting for a persistent peer to
   close. Unframed responses still require EOF. */
static int
bc_response_complete (const unsigned char *buf, size_t len, int head_request)
{
  if (!bc_skip_informational (&buf, &len)) return 0;
  size_t body = 0;
  for (size_t i = 0; i + 4 <= len && i < BCURL_HEADER_MAX; i++)
    if (memcmp (buf + i, "\r\n\r\n", 4) == 0)
      { body = i + 4; break; }
  if (!body || memchr (buf, 0, body)) return 0;
  char *headers = malloc (body + 1);
  if (!headers) return 0;
  memcpy (headers, buf, body); headers[body] = 0;
  int status = body >= 12 ? atoi (headers + 9) : 0;
  int chunked = 0;
  long long length;
  if (bc_checked_response_length (headers, &length) < 0)
    { free (headers); return -1; }
  char *line = strstr (headers, "\r\n");
  while (line && line[2] && line[2] != '\r')
    {
      line += 2;
      if (strncasecmp (line, "Transfer-Encoding:", 18) == 0)
        {
          char *v = line + 18;
          while (*v == ' ' || *v == '\t') v++;
          if (strncasecmp (v, "chunked", 7) == 0) chunked = 1;
        }
      line = strstr (line, "\r\n");
    }
  free (headers);
  if (head_request || status == 204 || status == 304) return 1;
  if (status < 200) return 0;
  if (!chunked) return length >= 0 && (unsigned long long) length <= len - body;
  size_t p = body;
  for (;;)
    {
      size_t start = p;
      unsigned long long size = 0;
      while (p < len && isxdigit (buf[p]))
        {
          unsigned int d = isdigit (buf[p]) ? buf[p] - '0' :
                           (unsigned int) (tolower (buf[p]) - 'a' + 10);
          if (size > (ULLONG_MAX - d) / 16) return 0;
          size = size * 16 + d; p++;
        }
      if (p == start) return 0;
      while (p + 1 < len && !(buf[p] == '\r' && buf[p+1] == '\n')) p++;
      if (p + 1 >= len) return 0;
      p += 2;
      if (size == 0)
        {
          /* Consume the trailer section, including its empty final line. */
          for (;;)
            {
              size_t start_line = p;
              while (p + 1 < len && !(buf[p] == '\r' && buf[p+1] == '\n')) p++;
              if (p + 1 >= len) return 0;
              p += 2;
              if (p == start_line + 2) return 1;
            }
        }
      if (size > len - p || len - p - (size_t) size < 2) return 0;
      p += (size_t) size;
      if (buf[p] != '\r' || buf[p+1] != '\n') return 0;
      p += 2;
    }
}

static unsigned char *
bc_read_until_close (int fd, int timeout_s, int head_request,
                     int *framed, size_t *out_len)
{
  size_t cap = BCURL_READ_CHUNK;
  size_t got = 0;
  *framed = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) { bc_error ("out of memory"); return NULL; }

  time_t deadline = time (NULL) + timeout_s;
  for (;;)
    {
      time_t now = time (NULL);
      if (now >= deadline)
        { bc_error ("timeout reading response"); bc_errcode = 28; free (buf); return NULL; }
      struct timeval tv = { .tv_sec = deadline - now, .tv_usec = 0 };
      fd_set rfds;
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
      if (sr < 0)  { if (errno == EINTR) continue;
                     bc_error ("select: %s", strerror (errno));
                     free (buf); return NULL; }
      if (sr == 0) { bc_error ("timeout reading response");
                     bc_errcode = 28; free (buf); return NULL; }

      if (got + BCURL_READ_CHUNK > cap)
        {
          if (cap >= BCURL_MAX_RESPONSE)
            { bc_error ("response exceeds %d bytes", BCURL_MAX_RESPONSE);
              free (buf); return NULL; }
          size_t ncap = cap * 2;
          if (ncap > BCURL_MAX_RESPONSE) ncap = BCURL_MAX_RESPONSE;
          unsigned char *nb = realloc (buf, ncap);
          if (!nb) { bc_error ("out of memory"); free (buf); return NULL; }
          buf = nb; cap = ncap;
        }
      ssize_t r = read (fd, buf + got, cap - got);
      if (r < 0) { if (errno == EINTR) continue;
                   bc_error ("read: %s", strerror (errno));
                   free (buf); return NULL; }
      if (r == 0) break;                       /* clean EOF */
      got += (size_t) r;
      if (bc_response_complete (buf, got, head_request))
        { *framed = 1; break; }
    }
  *out_len = got;
  return buf;
}

/* ---- HTTPS transport: tunnel the request through crypto tls connect ---- */
static unsigned char *
bc_https_exchange (const bc_url *u, const char *req, size_t reqlen,
                   int insecure, const char *cacert, int timeout_s,
                   int head_request, int tunnel_fd, size_t *out_len)
{
  /* Build a bash one-liner that:
   *   1. cats the request from FIFO-fd 0 via a here-doc-style printf
   *   2. pipes it into `crypto tls connect HOST:PORT -s HOST [-k]`
   *
   * We use bidirectional popen-style coupling: fork a child that runs
   * `bash -c CMD`, with parent->child stdin = request, child->parent
   * stdout = response. socketpair would also work; pipe pairs are fine.
   *
   * (void) timeout_s — TLS connect timeout is enforced by crypto
   * internally (its own connect()); we re-check the read clock on the
   * parent side via select() in the read loop below. */
  int in_pipe[2], out_pipe[2];
  if (pipe (in_pipe) < 0)  { bc_error ("pipe: %s", strerror (errno)); return NULL; }
  if (pipe (out_pipe) < 0) { close (in_pipe[0]); close (in_pipe[1]);
                             bc_error ("pipe: %s", strerror (errno)); return NULL; }
  struct sigaction chld_dfl, chld_save;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);

  sigset_t chld_set, prev_mask;
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

  pid_t pid = fork ();
  if (pid < 0)
    { close (in_pipe[0]); close (in_pipe[1]); close (out_pipe[0]); close (out_pipe[1]);
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      bc_error ("fork: %s", strerror (errno)); return NULL; }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      dup2 (in_pipe[0], 0);
      dup2 (out_pipe[1], 1);
      close (in_pipe[0]); close (in_pipe[1]);
      close (out_pipe[0]); close (out_pipe[1]);
      char hostport[320], fdbuf[16];
      snprintf (hostport, sizeof hostport, "%s:%s", u->host, u->port);
      /* A proxy tunnel is already connected: TLS runs over it as fd 3. */
      if (tunnel_fd >= 0)
        {
          if (tunnel_fd != 3 && (dup2 (tunnel_fd, 3) < 0 || close (tunnel_fd) < 0)) _exit (1);
          snprintf (fdbuf, sizeof fdbuf, "3");
        }
      /* Run the crypto builtin in this child, so HTTPS works whatever
       * /bin/bash is. The exec below is only for a shell without crypto. */
      char *argv[13];
      int argc = 0;
      argv[argc++] = "crypto";
      argv[argc++] = "tls";
      argv[argc++] = "connect";
      argv[argc++] = "--curl-status";
      if (tunnel_fd >= 0)
        {
          argv[argc++] = "--fd";
          argv[argc++] = fdbuf;
        }
      argv[argc++] = hostport;
      argv[argc++] = "-s";
      argv[argc++] = (char *) u->host;
      if (cacert && *cacert)
        {
          argv[argc++] = "-c";
          argv[argc++] = (char *) cacert;
        }
      if (insecure)
        argv[argc++] = "-k";
      argv[argc] = NULL;
      if (bc_quiet)
        {
          int nullfd = open ("/dev/null", O_WRONLY);
          if (nullfd < 0 || dup2 (nullfd, STDERR_FILENO) < 0) _exit (1);
          if (nullfd != STDERR_FILENO) close (nullfd);
        }
      bos_prepare_child ();
      bos_run_builtin ("crypto", argv, NULL);
      if (tunnel_fd >= 0) _exit (127);   /* no TLS over a tunnel without the builtin */
      /* crypto is a builtin (no PATH binary). Use `builtin` to
       * force builtin-lookup dispatch; the wrapping /bin/bash is the
       * bash-os shell that has crypto compiled in. `exec
       * crypto …` would walk PATH for an external crypto and
       * fail with "not found", silently dropping the TLS handshake. */
      if (cacert && *cacert && insecure)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect --curl-status \"$1\" -s \"$2\" -c \"$3\" -k",
               "bash", hostport, u->host, cacert, (char *) NULL);
      else if (cacert && *cacert)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect --curl-status \"$1\" -s \"$2\" -c \"$3\"",
               "bash", hostport, u->host, cacert, (char *) NULL);
      else if (insecure)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect --curl-status \"$1\" -s \"$2\" -k",
               "bash", hostport, u->host, (char *) NULL);
      else
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect --curl-status \"$1\" -s \"$2\"",
               "bash", hostport, u->host, (char *) NULL);
      _exit (127);
    }
  close (in_pipe[0]); close (out_pipe[1]);
  if (tunnel_fd >= 0) close (tunnel_fd);

  /* Push request to child stdin. */
  if (bc_write_all (in_pipe[1], req, reqlen) < 0)
    {
      bc_error ("write to tls subshell: %s", strerror (errno));
      close (in_pipe[1]); close (out_pipe[0]);
      while (waitpid (pid, NULL, 0) < 0 && errno == EINTR) ;
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return NULL;
    }
  close (in_pipe[1]);

  int framed = 0;
  unsigned char *resp = bc_read_until_close (out_pipe[0], timeout_s, head_request,
                                             &framed, out_len);
  close (out_pipe[0]);
  if (framed) kill (pid, SIGTERM);

  int wstat = 0;
  while (waitpid (pid, &wstat, 0) < 0 && errno == EINTR) ;
  sigprocmask (SIG_SETMASK, &prev_mask, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  if (!resp) return NULL;
  /* crypto exit-non-zero only matters if response is empty; otherwise
   * the response was already piped through and is usable. */
  if (*out_len == 0 && WIFEXITED (wstat) && WEXITSTATUS (wstat) != 0)
    {
      if (WEXITSTATUS (wstat) == 60)
        {
          bc_errcode = 60;
          bc_curl_error (60, "SSL peer certificate verification failed");
        }
      else
        bc_error ("tls subshell failed (rc=%d)", WEXITSTATUS (wstat));
      free (resp);
      return NULL;
    }
  return resp;
}

/* ---- response parser: split status/headers/body, handle chunked + Location ---- */
static int
bc_chunked (const char *hdrs)
{
  /* Walk lines, look for Transfer-Encoding: chunked (case-insensitive). */
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Transfer-Encoding:", 18) == 0)
        {
          const char *v = p + 18;
          while (*v == ' ' || *v == '\t') v++;
          if (strncasecmp (v, "chunked", 7) == 0) return 1;
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return 0;
}

static long
bc_content_length (const char *hdrs)
{
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Content-Length:", 15) == 0)
        {
          const char *v = p + 15;
          while (*v == ' ' || *v == '\t') v++;
          return strtol (v, NULL, 10);
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return -1;
}

/* Returns -1, leaving OUT empty, when the target does not fit: following a
   truncated URL would fetch some other resource. Like curl, a bare CR or
   LF ends the header line, trailing blanks are dropped, and spaces and
   bytes past 0x7e are percent-encoded so the target stays one token of
   the next request line. Another control byte is percent-encoded in a
   relative target and makes an absolute one malformed: -2, OUT empty. */
static int
bc_extract_location (const char *hdrs, char *out, size_t cap)
{
  static const char hex[] = "0123456789abcdef";
  out[0] = '\0';
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Location:", 9) == 0)
        {
          const char *v = p + 9;
          while (*v == ' ' || *v == '\t') v++;
          size_t n = strcspn (v, "\r\n");
          while (n > 0 && (v[n - 1] == ' ' || v[n - 1] == '\t')) n--;
          int absolute = 0;
          for (size_t i = 0; i + 3 <= n && !absolute; i++)
            absolute = memcmp (v + i, "://", 3) == 0;
          size_t o = 0;
          for (size_t i = 0; i < n; i++)
            {
              unsigned char c = (unsigned char) v[i];
              int ctl = c < 0x20 || c == 0x7f;
              if (ctl && absolute)
                { out[0] = '\0'; return -2; }
              if (ctl || c == ' ' || c > 0x7e)
                {
                  if (cap - o <= 3) { out[0] = '\0'; return -1; }
                  out[o++] = '%';
                  out[o++] = hex[c >> 4];
                  out[o++] = hex[c & 15];
                }
              else
                {
                  if (cap - o <= 1) { out[0] = '\0'; return -1; }
                  out[o++] = (char) c;
                }
            }
          out[o] = '\0';
          return 0;
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return 0;
}

/* De-chunk a chunked-transfer body in place; returns new length, or -1 on
 * malformed input. */
static long
bc_dechunk (unsigned char *body, size_t blen)
{
  size_t in = 0, out = 0;
  while (in < blen)
    {
      size_t start = in;
      unsigned long chunk = 0;
      while (in < blen && isxdigit (body[in]))
        {
          unsigned int d = isdigit (body[in]) ? body[in] - '0' :
                           (unsigned int) (tolower (body[in]) - 'a' + 10);
          if (chunk > ((unsigned long) LONG_MAX - d) / 16) return -1;
          chunk = chunk * 16 + d;
          in++;
        }
      if (in == start || in >= blen || (body[in] != ';' && body[in] != '\r')) return -1;
      if (body[in] == ';')
        while (in < blen && body[in] != '\r' && body[in] != '\n') in++;
      if (in + 1 >= blen || body[in] != '\r' || body[in + 1] != '\n') return -1;
      in += 2;
      if (chunk == 0)
        {
          for (;;)
            {
              size_t line = in;
              while (in + 1 < blen && !(body[in] == '\r' && body[in + 1] == '\n')) in++;
              if (in + 1 >= blen) return -1;
              in += 2;
              if (in == line + 2) return (long) out;
            }
        }
      if (chunk > blen - in || blen - in - (size_t) chunk < 2) return -1;
      memmove (body + out, body + in, (size_t) chunk);
      out += (size_t) chunk;
      in += (size_t) chunk;
      if (body[in] != '\r' || body[in + 1] != '\n') return -1;
      in += 2;
    }
  return -1;
}

static int
bc_parse_response (unsigned char *raw, size_t rawlen, int head_request, bc_response *r)
{
  memset (r, 0, sizeof *r);
  const unsigned char *first = raw;
  const unsigned char *final = raw;
  if (!bc_skip_informational (&final, &rawlen))
    { bc_error ("incomplete informational response"); bc_errcode = 8; return -1; }
  raw = (unsigned char *) final;
  if (rawlen == 0)
    { bc_error ("empty reply from server"); bc_errcode = 52; return -1; }
  if (rawlen < 12 || memcmp (raw, "HTTP/", 5) != 0)
    { bc_error ("malformed response (no HTTP/ status line)"); bc_errcode = 8; return -1; }
  r->status = atoi ((char *) raw + 9);

  /* find header/body separator */
  size_t i, body = rawlen;
  int found = 0;
  size_t end = rawlen > BCURL_HEADER_MAX ? BCURL_HEADER_MAX : rawlen;
  for (i = 0; i + 4 <= end; i++)
    if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n')
      { body = i + 4; found = 1; break; }
  if (!found)
    { bc_error ("no header/body separator"); bc_errcode = 8; return -1; }
  /* The header block is handled as a string; curl refuses a NUL in it. */
  if (memchr (raw, '\0', body))
    { bc_curl_error (8, "Nul byte in header"); bc_errcode = 8; return -1; }

  size_t hlen = body - 2;       /* keep trailing \r\n before the blank line */
  r->headers = malloc (hlen + 1);
  if (!r->headers) { bc_error ("out of memory"); return -1; }
  memcpy (r->headers, raw, hlen);
  r->headers[hlen] = '\0';
  r->hlen = hlen;
  long long checked_length;
  if (bc_checked_response_length (r->headers, &checked_length) < 0)
    { bc_error ("invalid or conflicting Content-Length"); bc_errcode = 8;
      free (r->headers); r->headers = NULL; return -1; }


  size_t blen = rawlen - body;
  r->body = malloc (blen ? blen : 1);
  if (!r->body) { free (r->headers); bc_error ("out of memory"); return -1; }
  if (blen) memcpy (r->body, raw + body, blen);
  r->blen = blen;

  if (bc_chunked (r->headers))
    {
      long n = bc_dechunk (r->body, r->blen);
      if (n < 0) { bc_error ("malformed chunked body");
                   free (r->headers); free (r->body); return -1; }
      r->blen = (size_t) n;
    }
  else
    {
      long cl = bc_content_length (r->headers);
      if (cl >= 0 && (size_t) cl < r->blen)
        r->blen = (size_t) cl;
      /* RFC 9110 6.4.1/9.3.2: HEAD, 1xx, 204 and 304 responses have no
       * content, whatever Content-Length says; otherwise a short body
       * means the peer closed early (CURLE_PARTIAL_FILE). */
      else if (cl >= 0 && (size_t) cl > r->blen && !head_request
               && r->status >= 200 && r->status != 204 && r->status != 304)
        r->missing = cl - (long) r->blen;
    }

  if (r->status >= 300 && r->status < 400)
    {
      int lrc = bc_extract_location (r->headers, r->location, sizeof r->location);
      r->location_too_long = lrc == -1;
      r->location_bad = lrc == -2;
    }

  r->informational_len = (size_t) (final - first);
  if (r->informational_len)
    {
      r->informational = malloc (r->informational_len);
      if (!r->informational)
        { free (r->headers); free (r->body); r->headers = NULL; r->body = NULL; return -1; }
      memcpy (r->informational, first, r->informational_len);
    }
  return 0;
}

static void
bc_response_free (bc_response *r)
{
  if (!r) return;
  free (r->headers); free (r->body); free (r->informational);
  r->headers = NULL; r->body = NULL; r->informational = NULL;
}

/* ---- emit body to outfile/stdout ---- */
static int
bc_emit (bc_opts *o, const bc_url *u, const bc_response *r)
{
  const char *out = o->outfile;
  /* nbuf must match u->path's size (BCURL_URL_MAX) so -Wformat-truncation
   * is silenced for the pathological case of a path with no '/'. */
  char nbuf[BCURL_URL_MAX];
  if (!out && o->use_basename)
    {
      const char *end = u->path + strcspn (u->path, "?#");
      const char *base = end;
      while (base > u->path && base[-1] != '/') base--;
      size_t len = (size_t) (end - base);
      if (!len) { base = "index.html"; len = strlen (base); }
      memcpy (nbuf, base, len);
      nbuf[len] = '\0';
      out = nbuf;
    }
  FILE *fp;
  /* -I -L writes every hop's head to one output; -C appends. */
  const char *mode = (o->head && o->head_hops > 0) || (o->resume_set && o->resume_from != 0)
                     ? "ab" : "wb";
  if (!out || strcmp (out, "-") == 0)
    fp = stdout;
  else
    {
      fp = fopen (out, mode);
      if (!fp)
        { bc_error ("%s: %s", out, strerror (errno)); return -1; }
    }
  size_t w, want;
  if (o->head)
    {
      want = r->informational_len + r->hlen + 2;
      w = r->informational_len ? fwrite (r->informational, 1, r->informational_len, fp) : 0;
      w += fwrite (r->headers, 1, r->hlen, fp);
      w += fwrite ("\r\n", 1, 2, fp);
    }
  else
    {
      want = r->blen;
      w = fwrite (r->body, 1, r->blen, fp);
    }
  if (fp != stdout) { if (fclose (fp) == EOF) w = 0; }
  else fflush (fp);
  return (w == want) ? 0 : -1;
}

static int
bc_emit_headers (const bc_opts *o, const bc_response *r)
{
  if (!o->dump_headers) return 0;
  FILE *fp;
  if (strcmp (o->dump_headers, "-") == 0)
    fp = stdout;
  else
    {
      fp = fopen (o->dump_headers, "wb");
      if (!fp)
        { bc_error ("%s: %s", o->dump_headers, strerror (errno)); return -1; }
    }
  size_t w = 0;
  if (r->informational_len)
    w = fwrite (r->informational, 1, r->informational_len, fp);
  if (w == r->informational_len)
    w += fwrite (r->headers, 1, r->hlen, fp);
  if (w == r->informational_len + r->hlen)
    w += fwrite ("\r\n", 1, 2, fp);
  if (fp != stdout) fclose (fp);
  else fflush (fp);
  return (w == r->informational_len + r->hlen + 2) ? 0 : -1;
}

static int bc_resolve_redirect (const char *cur, const char *loc, char *out, size_t cap);
static int bc_read_data_file (const char *arg, char **out, size_t *out_len);

static double
bc_wo_seconds (const struct timespec *t)
{
  return (double) (t->tv_sec - bc_wo.start.tv_sec)
         + (double) (t->tv_nsec - bc_wo.start.tv_nsec) / 1e9;
}

/* The value of response header NAME (case-insensitive), or "". */
static void
bc_wo_header (const bc_response *r, const char *name, size_t nlen, char *out, size_t outsz)
{
  out[0] = '\0';
  const char *h = r->headers;
  if (!h) return;
  const char *end = h + r->hlen;
  const char *line = memchr (h, '\n', r->hlen);   /* skip the status line */
  while (line && line < end)
    {
      line++;
      const char *eol = memchr (line, '\n', (size_t) (end - line));
      if (!eol) eol = end;
      if ((size_t) (eol - line) > nlen && line[nlen] == ':' && !strncasecmp (line, name, nlen))
        {
          const char *v = line + nlen + 1, *ve = eol;
          while (v < ve && (*v == ' ' || *v == '\t')) v++;
          while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t')) ve--;
          snprintf (out, outsz, "%.*s", (int) (ve - v), v);
          return;
        }
      line = eol;
    }
}

/* Expand one %{NAME}. Returns 0, or -1 when NAME is not a variable. */
static int
bc_wo_var (const bc_opts *o, const bc_response *r, const char *name, size_t n, FILE *fp)
{
#define IS(x) (n == sizeof (x) - 1 && !memcmp (name, x, n))
  struct timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);
  double total = bc_wo_seconds (&now);
  double connect = bc_wo.have_connected ? bc_wo_seconds (&bc_wo.connected) : 0.0;
  double first = bc_wo.have_received ? bc_wo_seconds (&bc_wo.received) : 0.0;
  char buf[BCURL_URL_MAX];
  if (IS ("http_code") || IS ("response_code")) fprintf (fp, "%03d", r->status);
  else if (IS ("size_download")) fprintf (fp, "%zu", r->blen);
  else if (IS ("size_header")) fprintf (fp, "%ld", bc_wo.header_bytes);
  else if (IS ("size_upload")) fprintf (fp, "%zu", o->body_set ? o->body_len : (size_t) 0);
  else if (IS ("content_type"))
    { bc_wo_header (r, "Content-Type", 12, buf, sizeof buf); fputs (buf, fp); }
  else if (IS ("url_effective")) fputs (bc_wo.effective ? bc_wo.effective : "", fp);
  else if (IS ("url")) fputs (bc_wo.url ? bc_wo.url : "", fp);
  else if (IS ("redirect_url"))
    {
      buf[0] = '\0';
      if (r->status >= 300 && r->status < 400 && r->location[0] && bc_wo.effective)
        bc_resolve_redirect (bc_wo.effective, r->location, buf, sizeof buf);
      fputs (buf, fp);
    }
  else if (IS ("num_redirects")) fprintf (fp, "%d", bc_wo.redirects);
  else if (IS ("num_connects")) fprintf (fp, "%d", bc_wo.connects);
  else if (IS ("num_headers"))
    {
      /* Header lines after the status line. */
      int count = 0;
      const char *h = r->headers, *end = h ? h + r->hlen : NULL;
      for (const char *line = h; line && line < end; )
        {
          const char *eol = memchr (line, '\n', (size_t) (end - line));
          if (!eol) eol = end;
          size_t len = (size_t) (eol - line);
          if (len && line[len - 1] == '\r') len--;
          if (len) count++;
          line = eol + 1;
        }
      fprintf (fp, "%d", count > 0 ? count - 1 : 0);
    }
  else if (IS ("method")) fputs (o->method, fp);
  else if (IS ("scheme"))
    {
      const char *u = bc_wo.effective ? bc_wo.effective : "", *c = strstr (u, "://");
      for (const char *q = u; c && q < c; q++) fputc (tolower ((unsigned char) *q), fp);
    }
  else if (IS ("http_version"))
    {
      const char *v = r->headers && !strncmp (r->headers, "HTTP/", 5) ? r->headers + 5 : NULL;
      if (!v) fputc ('0', fp);
      else fprintf (fp, "%.*s", (int) strcspn (v, " \r\n"), v);
    }
  else if (IS ("exitcode")) fprintf (fp, "%d", bc_wo.exitcode);
  else if (IS ("errormsg")) fputs (bc_wo.errormsg, fp);
  else if (IS ("filename_effective")) fputs (o->outfile ? o->outfile : "", fp);
  else if (IS ("remote_ip")) fputs (bc_wo.remote_ip, fp);
  else if (IS ("remote_port")) fprintf (fp, "%d", bc_wo.remote_port);
  else if (IS ("local_ip")) fputs (bc_wo.local_ip, fp);
  else if (IS ("local_port")) fprintf (fp, "%d", bc_wo.local_port);
  else if (IS ("time_total")) fprintf (fp, "%.6f", total);
  else if (IS ("time_namelookup") || IS ("time_connect")) fprintf (fp, "%.6f", connect);
  else if (IS ("time_appconnect") || IS ("time_redirect")) fprintf (fp, "%.6f", 0.0);
  else if (IS ("time_pretransfer")) fprintf (fp, "%.6f", connect);
  else if (IS ("time_starttransfer")) fprintf (fp, "%.6f", first);
  else if (IS ("speed_download")) fprintf (fp, "%.0f", total > 0 ? (double) r->blen / total : 0.0);
  else if (IS ("speed_upload"))
    fprintf (fp, "%.0f", total > 0 && o->body_set ? (double) o->body_len / total : 0.0);
  else return -1;
  return 0;
#undef IS
}

/* -w FORMAT: curl's %{variable}s, %header{NAME}, %{stdout}/%{stderr}
   output switches, %{onerror} (the rest only after a failure), %% and the
   \n \t \r \\ escapes. An unknown variable is reported and skipped. */
static int
bc_emit_write_out (const bc_opts *o, const bc_response *r)
{
  if (!o->write_out) return 0;
  const char *fmt = o->write_out;
  char *from_file = NULL;
  if (*fmt == '@')
    {
      /* -w @FILE / @- reads the format from a file or stdin. */
      size_t len = 0;
      if (bc_read_data_file (fmt, &from_file, &len) != EXECUTION_SUCCESS) return -1;
      /* curl joins the file's lines, dropping their line endings. */
      char *w = from_file;
      for (const char *q = from_file; *q; q++) if (*q != '\n' && *q != '\r') *w++ = *q;
      *w = '\0';
      fmt = from_file;
    }
  FILE *fp = stdout;
  while (*fmt)
    {
      if (fmt[0] == '%' && fmt[1] == '{')
        {
          const char *name = fmt + 2, *close = strchr (name, '}');
          if (!close) { putc (*fmt++, fp); continue; }
          size_t n = (size_t) (close - name);
          fmt = close + 1;
          if (n == 6 && !memcmp (name, "stdout", 6)) { fflush (fp); fp = stdout; continue; }
          if (n == 6 && !memcmp (name, "stderr", 6)) { fflush (fp); fp = stderr; continue; }
          if (n == 7 && !memcmp (name, "onerror", 7)) { if (bc_wo.exitcode == 0) break; continue; }
          if (bc_wo_var (o, r, name, n, fp) < 0)
            fprintf (stderr, "curl: unknown --write-out variable: '%.*s'\n", (int) n, name);
          continue;
        }
      if (!strncmp (fmt, "%header{", 8))
        {
          const char *name = fmt + 8, *close = strchr (name, '}');
          if (close)
            {
              char value[1024];
              bc_wo_header (r, name, (size_t) (close - name), value, sizeof value);
              fputs (value, fp);
              fmt = close + 1;
              continue;
            }
        }
      /* GNU curl -w interprets C-style backslash escapes in the format. */
      if (*fmt == '\\' && fmt[1])
        {
          fmt++;
          switch (*fmt)
            {
            case 'n': putc ('\n', fp); break;
            case 't': putc ('\t', fp); break;
            case 'r': putc ('\r', fp); break;
            case '\\': putc ('\\', fp); break;
            default:  putc ('\\', fp); putc (*fmt, fp); break;
            }
          fmt++;
          continue;
        }
      if (fmt[0] == '%' && fmt[1] == '%')   /* %% -> literal % */
        { putc ('%', fp); fmt += 2; continue; }
      putc (*fmt++, fp);
    }
  fflush (stdout);
  fflush (stderr);
  free (from_file);
  return 0;
}

/* -x/--proxy: [scheme://][user:pass@]host[:port], port 1080 by default.
   Only HTTP proxies are spoken; user:pass becomes Proxy-Authorization. */
static int
bc_parse_proxy (const char *spec, char *host, size_t hostsz, char *port, size_t portsz,
                char *auth, size_t authsz)
{
  const char *p = spec;
  const char *scheme_end = strstr (p, "://");
  auth[0] = '\0';
  if (scheme_end)
    {
      size_t sl = (size_t) (scheme_end - p);
      if (!(sl == 4 && !strncasecmp (p, "http", 4)))
        { bc_curl_error (5, "Unsupported proxy scheme for '%s'", spec); bc_errcode = 5; return -1; }
      p = scheme_end + 3;
    }
  const char *end = p + strcspn (p, "/?#");
  const char *at = NULL;
  for (const char *q = p; q < end; q++) if (*q == '@') at = q;
  if (at)
    {
      char *b64 = bc_b64encode ((const unsigned char *) p, (size_t) (at - p));
      if (!b64) { bc_error ("out of memory"); return -1; }
      snprintf (auth, authsz, "%s", b64);
      free (b64);
      p = at + 1;
    }
  const char *colon = NULL;
  if (*p == '[')
    {
      const char *close = memchr (p, ']', (size_t) (end - p));
      if (!close) { bc_curl_error (5, "Couldn't resolve proxy '%s'", spec); bc_errcode = 5; return -1; }
      snprintf (host, hostsz, "%.*s", (int) (close - p - 1), p + 1);
      if (close + 1 < end && close[1] == ':') colon = close + 1;
    }
  else
    {
      colon = memchr (p, ':', (size_t) (end - p));
      size_t hl = colon ? (size_t) (colon - p) : (size_t) (end - p);
      snprintf (host, hostsz, "%.*s", (int) hl, p);
    }
  if (colon) snprintf (port, portsz, "%.*s", (int) (end - colon - 1), colon + 1);
  else snprintf (port, portsz, "1080");
  if (!host[0] || !port[0])
    { bc_curl_error (5, "Couldn't resolve proxy '%s'", spec); bc_errcode = 5; return -1; }
  return 0;
}

/* Open a CONNECT tunnel to HOST:PORT through the proxy. */
static int
bc_proxy_tunnel (const bc_opts *o, const bc_url *u, int connect_timeout, int timeout)
{
  char phost[256], pport[16], auth[512];
  if (bc_parse_proxy (o->proxy, phost, sizeof phost, pport, sizeof pport, auth, sizeof auth) < 0)
    return -1;
  int fd = bc_connect_tcp (phost, pport, connect_timeout);
  if (fd < 0) return -1;
  char req[1024];
  int n = snprintf (req, sizeof req, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n%s%s%sUser-Agent: %s\r\n\r\n",
                    u->host, u->port, u->host, u->port,
                    auth[0] ? "Proxy-Authorization: Basic " : "", auth, auth[0] ? "\r\n" : "",
                    o->user_agent ? o->user_agent : "curl/" BCURL_VERSION);
  if (n < 0 || (size_t) n >= sizeof req || bc_write_all (fd, req, (size_t) n) < 0)
    { bc_error ("proxy CONNECT failed"); close (fd); return -1; }
  if (o->verbose)
    fprintf (stderr, "* Establish HTTP proxy tunnel to %s:%s\n> CONNECT %s:%s HTTP/1.1\n",
             u->host, u->port, u->host, u->port);
  /* Read the reply one byte at a time so nothing past its blank line is
     taken from the tunnel. */
  char reply[BCURL_HEADER_MAX];
  size_t got = 0;
  time_t deadline = time (NULL) + timeout;
  while (got < sizeof reply - 1)
    {
      fd_set rfds;
      time_t now = time (NULL);
      if (now >= deadline) { bc_error ("timeout reading proxy reply"); bc_errcode = 28; close (fd); return -1; }
      struct timeval tv = { .tv_sec = deadline - now, .tv_usec = 0 };
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
      if (sr < 0 && errno == EINTR) continue;
      if (sr <= 0) { bc_error ("timeout reading proxy reply"); bc_errcode = 28; close (fd); return -1; }
      ssize_t r = read (fd, reply + got, 1);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) break;
      got++;
      if (got >= 4 && !memcmp (reply + got - 4, "\r\n\r\n", 4)) break;
    }
  reply[got] = '\0';
  int status = got >= 12 && !strncmp (reply, "HTTP/", 5) ? atoi (reply + 9) : 0;
  if (o->verbose)
    {
      const char *eol = strstr (reply, "\r\n");
      fprintf (stderr, "< %.*s\n", eol ? (int) (eol - reply) : (int) got, reply);
    }
  if (status < 200 || status > 299)
    {
      bc_curl_error (56, "CONNECT tunnel failed, response %d", status);
      bc_errcode = 56;
      close (fd);
      return -1;
    }
  return fd;
}

/* -v: request and response heads on stderr, as curl marks them. */
static void
bc_verbose_block (char mark, const char *data, size_t len)
{
  const char *p = data, *end = data + len;
  while (p < end)
    {
      const char *eol = memchr (p, '\n', (size_t) (end - p));
      size_t n = eol ? (size_t) (eol - p) : (size_t) (end - p);
      size_t shown = n && p[n - 1] == '\r' ? n - 1 : n;
      fprintf (stderr, "%c %.*s\n", mark, (int) shown, p);
      if (!eol) break;
      p = eol + 1;
    }
  fflush (stderr);
}

/* --compressed: undo gzip or deflate Content-Encoding in place. */
static int
bc_header_value (const char *hdrs, const char *name, char *out, size_t outsz)
{
  size_t nl = strlen (name);
  for (const char *line = hdrs; line && *line; )
    {
      const char *eol = strstr (line, "\r\n");
      if (!strncasecmp (line, name, nl) && line[nl] == ':')
        {
          const char *v = line + nl + 1;
          while (*v == ' ' || *v == '\t') v++;
          size_t vl = eol ? (size_t) (eol - v) : strlen (v);
          while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
          snprintf (out, outsz, "%.*s", (int) vl, v);
          return 1;
        }
      line = eol ? eol + 2 : NULL;
    }
  return 0;
}

static int
bc_inflate_body (bc_response *r)
{
  char enc[64];
  if (!r->headers || !bc_header_value (r->headers, "Content-Encoding", enc, sizeof enc))
    return 0;
  int window;
  if (!strcasecmp (enc, "gzip") || !strcasecmp (enc, "x-gzip")) window = 15 + 16;
  else if (!strcasecmp (enc, "deflate")) window = 15;
  else if (!strcasecmp (enc, "identity")) return 0;
  else return 0;   /* not one we asked for: pass the bytes through, as curl does */
  if (r->blen == 0) return 0;
  for (int attempt = 0; attempt < 2; attempt++)
    {
      z_stream z;
      memset (&z, 0, sizeof z);
      if (inflateInit2 (&z, attempt ? -15 : window) != Z_OK) break;
      size_t cap = r->blen * 4 + 1024, len = 0;
      unsigned char *out = malloc (cap);
      if (!out) { inflateEnd (&z); bc_error ("out of memory"); return -1; }
      z.next_in = r->body;
      int zrc;
      size_t fed = 0;
      do
        {
          if (len == cap)
            {
              if (cap >= BCURL_MAX_RESPONSE) { zrc = Z_MEM_ERROR; break; }
              size_t ncap = cap * 2 > BCURL_MAX_RESPONSE ? BCURL_MAX_RESPONSE : cap * 2;
              unsigned char *nb = realloc (out, ncap);
              if (!nb) { zrc = Z_MEM_ERROR; break; }
              out = nb; cap = ncap;
            }
          size_t chunk = r->blen - fed > UINT_MAX ? UINT_MAX : r->blen - fed;
          if (z.avail_in == 0 && fed < r->blen) { z.next_in = r->body + fed; z.avail_in = (uInt) chunk; fed += chunk; }
          size_t room = cap - len > UINT_MAX ? UINT_MAX : cap - len;
          z.next_out = out + len;
          z.avail_out = (uInt) room;
          zrc = inflate (&z, Z_NO_FLUSH);
          len += room - z.avail_out;
        }
      while (zrc == Z_OK && (z.avail_in > 0 || fed < r->blen || z.avail_out == 0));
      inflateEnd (&z);
      if (zrc == Z_STREAM_END)
        {
          free (r->body);
          r->body = out;
          r->blen = len;
          return 0;
        }
      free (out);
      /* "deflate" is sometimes sent without its zlib wrapper. */
      if (window != 15) break;
    }
  bc_curl_error (61, "Error while processing content unencoding: invalid stored block lengths");
  bc_errcode = 61;
  return -1;
}

/* ---- file:// URLs (RFC 8089): read a local file, as curl does ----
   Host must be empty or "localhost"; %XX escapes are decoded. curl's
   errors: 37 for a file that cannot be read, 3 for another host. */
static int
bc_file_url (bc_opts *o, const char *url)
{
  const char *p = url + 7;              /* past "file://" */
  if (*p != '/')
    {
      size_t hl = strcspn (p, "/");
      if (!(hl == 9 && strncasecmp (p, "localhost", 9) == 0))
        { bc_curl_error (3, "URL using bad/illegal format or missing URL"); return 3; }
      p += hl;
    }
  char path[BCURL_URL_MAX];
  size_t n = 0;
  for (; *p && *p != '?' && *p != '#' && n + 1 < sizeof path; p++)
    {
      if (p[0] == '%' && isxdigit ((unsigned char) p[1]) && isxdigit ((unsigned char) p[2]))
        {
          char hx[3] = { p[1], p[2], 0 };
          path[n++] = (char) strtol (hx, NULL, 16);
          p += 2;
        }
      else
        path[n++] = *p;
    }
  path[n] = '\0';
  if (!n) strcpy (path, "/");
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  struct stat st;
  if (fd < 0 || fstat (fd, &st) < 0 || S_ISDIR (st.st_mode))
    {
      if (fd >= 0) close (fd);
      bc_curl_error (37, "Couldn't open file %s", path);
      return 37;
    }
  bc_response r;
  memset (&r, 0, sizeof r);
  size_t cap = 0;
  for (;;)
    {
      if (r.blen == cap)
        {
          size_t nc = cap ? cap * 2 : 65536;
          unsigned char *nb = realloc (r.body, nc);
          if (!nb) { close (fd); free (r.body); bc_error ("out of memory"); return 27; }
          r.body = nb; cap = nc;
        }
      ssize_t k = read (fd, r.body + r.blen, cap - r.blen);
      if (k < 0 && errno == EINTR) continue;
      if (k < 0) { close (fd); free (r.body); bc_curl_error (37, "Couldn't open file %s", path); return 37; }
      if (k == 0) break;
      r.blen += (size_t) k;
    }
  close (fd);
  if (o->resume_set && o->resume_from > 0)
    {
      size_t skip = (size_t) o->resume_from < r.blen ? (size_t) o->resume_from : r.blen;
      memmove (r.body, r.body + skip, r.blen - skip);
      r.blen -= skip;
    }
  bc_url u;
  memset (&u, 0, sizeof u);
  snprintf (u.scheme, sizeof u.scheme, "file");
  snprintf (u.path, sizeof u.path, "%s", path);
  int rc = 0;
  if (!o->head && bc_emit (o, &u, &r) < 0) rc = 23;
  else if (bc_emit_write_out (o, &r) < 0) rc = EXECUTION_FAILURE;
  bc_response_free (&r);
  return rc;
}

/* ---- single request roundtrip (no redirect handling at this layer) ---- */
static int
bc_one_request (const bc_opts *o, const char *url_override, bc_response *out_resp)
{
  bc_url u;
  const char *use_url = url_override ? url_override : o->url;
  if (bc_parse_url (use_url, &u) < 0)
    { bc_error ("invalid URL: %s", use_url); bc_errcode = 3; return -1; }

  int is_https = (strcasecmp (u.scheme, "https") == 0);
  int is_http  = (strcasecmp (u.scheme, "http")  == 0);
  if (!is_http && !is_https)
    { bc_error ("unsupported scheme: %s", u.scheme); return -1; }

  size_t reqlen = 0;
  char *req = bc_build_request (o, &u, &reqlen);
  if (!req) return -1;

  int timeout = o->max_time > 0 ? o->max_time : BCURL_DEFAULT_TIMEOUT;
  int connect_timeout = o->connect_time > 0 ? o->connect_time : timeout;
  size_t raw_len = 0;
  unsigned char *raw = NULL;
  if (o->verbose)
    {
      const char *end = strstr (req, "\r\n\r\n");
      fprintf (stderr, "* Connecting to %s port %s%s%s\n", u.host, u.port,
               o->proxy ? " via proxy " : "", o->proxy ? o->proxy : "");
      bc_verbose_block ('>', req, end ? (size_t) (end - req) + 2 : reqlen);
      fprintf (stderr, ">\n");
    }
  if (is_https)
    {
      int tunnel = -1;
      if (o->unix_socket)
        {
          /* TLS runs over the unix-domain socket as it would over a tunnel. */
          if ((tunnel = bc_connect_unix (o->unix_socket, o->abstract_unix, u.host, u.port)) < 0)
            { free (req); return -1; }
        }
      else if (o->proxy && (tunnel = bc_proxy_tunnel (o, &u, connect_timeout, timeout)) < 0)
        { free (req); return -1; }
      raw = bc_https_exchange (&u, req, reqlen, o->insecure, o->cacert,
                               timeout, strcmp (o->method, "HEAD") == 0, tunnel, &raw_len);
    }
  else
    {
      char phost[256], pport[16], pauth[512];
      const char *chost = u.host, *cport = u.port;
      if (o->proxy)
        {
          if (bc_parse_proxy (o->proxy, phost, sizeof phost, pport, sizeof pport, pauth, sizeof pauth) < 0)
            { free (req); return -1; }
          chost = phost;
          cport = pport;
        }
      int fd = o->unix_socket
               ? bc_connect_unix (o->unix_socket, o->abstract_unix, u.host, u.port)
               : bc_connect_tcp (chost, cport, connect_timeout);
      if (fd < 0) { free (req); return -1; }
      if (bc_write_all (fd, req, reqlen) < 0)
        { bc_error ("write: %s", strerror (errno)); close (fd); free (req); return -1; }
      int framed;
      raw = bc_read_until_close (fd, timeout, strcmp (o->method, "HEAD") == 0,
                                 &framed, &raw_len);
      close (fd);
    }
  free (req);
  if (!raw) return -1;

  clock_gettime (CLOCK_MONOTONIC, &bc_wo.received);
  bc_wo.have_received = 1;
  int rc = bc_parse_response (raw, raw_len, strcmp (o->method, "HEAD") == 0, out_resp);
  free (raw);
  if (rc == 0)
    bc_wo.header_bytes += (long) (out_resp->informational_len + out_resp->hlen + 2);
  if (rc == 0 && o->verbose)
    {
      if (out_resp->informational_len)
        bc_verbose_block ('<', (const char *) out_resp->informational, out_resp->informational_len);
      bc_verbose_block ('<', out_resp->headers, out_resp->hlen);
      fprintf (stderr, "<\n");
      fflush (stderr);
    }
  if (rc == 0 && o->compressed && strcmp (o->method, "HEAD") != 0
      && bc_inflate_body (out_resp) < 0)
    {
      bc_response_free (out_resp);
      return -1;
    }
  return rc;
}

/* Decode %2e/%2E to '.' so a segment that is only an encoded dot is a
 * dot segment. curl does this unless --path-as-is is set. Other escapes
 * stay encoded. The query is not part of path. */
static void
bc_decode_dot_escapes (char *path)
{
  char *read = path, *write = path;
  while (*read)
    {
      if (read[0] == '%' && read[1] == '2' && (read[2] == 'e' || read[2] == 'E'))
        {
          *write++ = '.';
          read += 3;
        }
      else
        *write++ = *read++;
    }
  *write = '\0';
}

/* Remove dot segments from a merged absolute path (RFC 3986 5.2.4).
 * Keep empty segments. Leave a query, if one was included, in place. */
static void
bc_remove_dot_segments (char *path)
{
  char result[BCURL_URL_MAX];
  const char *in;
  bc_decode_dot_escapes (path);
  in = path;
  size_t n = 0;
  while (*in)
    {
      if (strncmp (in, "../", 3) == 0) in += 3;
      else if (strncmp (in, "./", 2) == 0) in += 2;
      else if (strncmp (in, "/./", 3) == 0) in += 2;
      else if (strcmp (in, "/.") == 0) { in += 2; result[n++] = '/'; }
      else if (strncmp (in, "/../", 4) == 0 || strcmp (in, "/..") == 0)
        {
          int last = in[3] == '\0';
          in += 3;
          while (n && result[n - 1] != '/') n--;
          if (n) n--;
          if (last) result[n++] = '/';
        }
      else if (strcmp (in, ".") == 0 || strcmp (in, "..") == 0)
        break;
      else
        {
          if (*in == '/') result[n++] = *in++;
          while (*in && *in != '/') result[n++] = *in++;
        }
    }
  result[n] = '\0';
  memcpy (path, result, n + 1);
}

/* Resolve a relative Location against the current absolute URL. */
static int
bc_resolve_redirect (const char *cur, const char *loc, char *out, size_t cap)
{
  if (strstr (loc, "://"))
    return snprintf (out, cap, "%s", loc) >= (int) cap ? -1 : 0;
  bc_url u;
  if (bc_parse_url (cur, &u) < 0) return -1;
  const char *port_sep = "";
  const char *port_str = "";
  int is_https = (strcasecmp (u.scheme, "https") == 0);
  if ((is_https && strcmp (u.port, "443") != 0) ||
      (!is_https && strcmp (u.port, "80") != 0))
    { port_sep = ":"; port_str = u.port; }
  if (loc[0] == '/')
    {
      char path[BCURL_URL_MAX];
      size_t plen = strcspn (loc, "?#");
      if (plen >= sizeof path) return -1;
      memcpy (path, loc, plen);
      path[plen] = '\0';
      bc_remove_dot_segments (path);
      return snprintf (out, cap, "%s://%s%s%s%s%s", u.scheme, u.host, port_sep,
                       port_str, path, loc + plen) >= (int) cap ? -1 : 0;
    }

  /* A query in the base URL is not part of its directory. */
  char path[BCURL_URL_MAX];
  size_t base_len = strcspn (u.path, "?#");
  while (base_len && u.path[base_len - 1] != '/') base_len--;
  size_t loc_len = strcspn (loc, "?#");
  if (base_len + loc_len >= sizeof path) return -1;
  memcpy (path, u.path, base_len);
  memcpy (path + base_len, loc, loc_len);
  path[base_len + loc_len] = '\0';
  bc_remove_dot_segments (path);
  return snprintf (out, cap, "%s://%s%s%s%s%s", u.scheme, u.host,
                   port_sep, port_str, path, loc + loc_len)
         >= (int) cap ? -1 : 0;
}

/* ---- main builtin entrypoint ---- */
static void
bc_usage (void)
{
  builtin_error ("usage: curl [-fsSLkO] [-X METHOD] [-H HDR]... [-d DATA]");
  builtin_error ("                [--data-binary DATA] [-o FILE] [-D FILE] [-w FORMAT]");
  builtin_error ("                [-u USER:PASS] [-A AGENT] [-b COOKIE|FILE] [-c FILE]");
  builtin_error ("                [--cacert PEM] [--connect-timeout SEC] [-m|--max-time SEC]");
  builtin_error ("                [--max-redirs N] [-I] [-v] [-F PART] [-T FILE] [-G]");
  builtin_error ("                [--data-urlencode DATA] [--json DATA] [--retry N]");
  builtin_error ("                [-x PROXY] [--compressed] [--http2] [-r RANGE] [-C OFFSET|-]");
  builtin_error ("                [--unix-socket PATH] [--abstract-unix-socket NAME]");
  builtin_error ("                [--features] [-V|--version] URL");
  builtin_error ("                supported long aliases accept --name=value");
}

static void
bc_print_caps (void)
{
  puts ("Protocols: http https");
  puts ("Features: basic-auth cacert compressed connect-timeout continue-at cookie cookie-jar cookie-policy data-binary data-urlencode fail form get head json location max-redirs output-file output-remote-name proxy range retry show-error silent timeout unix-socket upload-file verbose write-out");
}

static void
bc_features (void)
{
  bc_print_caps ();
  puts ("TLS: crypto");
  puts ("Unsupported: ftp smtp scp http2-framing socks-proxy non-http-cookie-schemes");
}

static void
bc_version (void)
{
  puts ("curl " BCURL_VERSION " (bash-os) curl/" BCURL_VERSION " TLS:crypto");
  bc_print_caps ();
}

static const char *
bc_long_eq (const char *w, const char *name)
{
  size_t n = strlen (name);
  return strncmp (w, name, n) == 0 && w[n] == '=' ? w + n + 1 : NULL;
}

static int
bc_next_arg (WORD_LIST **pp, const char *opt, const char **out)
{
  WORD_LIST *p = *pp;
  if (!p->next)
    {
      builtin_error ("option requires an argument: %s", opt);
      return EX_USAGE;
    }
  p = p->next;
  *pp = p;
  *out = p->word->word;
  return EXECUTION_SUCCESS;
}

static int
bc_add_header_opt (bc_opts *o, const char *arg)
{
  if (o->nheaders >= BCURL_HEADER_SLOTS)
    {
      builtin_error ("too many -H headers");
      return EX_USAGE;
    }
  o->headers[o->nheaders++] = (char *) arg;
  return EXECUTION_SUCCESS;
}

/* Append one data option. Like curl, several are joined with '&'. */
static int
bc_add_data (bc_opts *o, const char *data, size_t n)
{
  size_t sep = o->body_set ? 1 : 0;
  char *nb = malloc (o->body_len + sep + n + 1);
  if (!nb) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  if (o->body_set) memcpy (nb, o->body, o->body_len);
  if (sep) nb[o->body_len] = '&';
  memcpy (nb + o->body_len + sep, data, n);
  o->body_len += sep + n;
  nb[o->body_len] = '\0';
  free (o->body_alloc);
  o->body_alloc = nb;
  o->body = nb;
  o->body_set = 1;
  if (!o->method_set && !strcmp (o->method, "GET")) o->method = "POST";
  return EXECUTION_SUCCESS;
}

/* Read the bytes named by @- (stdin) or @FILE. */
static int
bc_read_data_file (const char *arg, char **out, size_t *out_len)
{
  if (!strcmp (arg, "@-"))
    return bc_slurp_fd_string (STDIN_FILENO, out, out_len) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  int fd = open (arg + 1, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("%s: %s", arg + 1, strerror (errno));
      return EXECUTION_FAILURE;
    }
  int rc = bc_slurp_fd_string (fd, out, out_len) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  close (fd);
  return rc;
}

/* -d/--data/--data-ascii read @FILE with carriage returns and newlines
 * stripped; --data-raw (allow_file 0) sends a leading '@' literally. */
static int
bc_set_data_opt (bc_opts *o, const char *arg, int allow_file)
{
  if (!allow_file || arg[0] != '@')
    return bc_add_data (o, arg, strlen (arg));
  char *buf;
  size_t len, kept = 0;
  if (bc_read_data_file (arg, &buf, &len) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (size_t i = 0; i < len; i++)
    if (buf[i] != '\r' && buf[i] != '\n')
      buf[kept++] = buf[i];
  int rc = bc_add_data (o, buf, kept);
  free (buf);
  return rc;
}

static int
bc_set_data_binary_opt (bc_opts *o, const char *arg)
{
  if (arg[0] != '@')
    return bc_add_data (o, arg, strlen (arg));
  char *buf;
  size_t len;
  if (bc_read_data_file (arg, &buf, &len) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  int rc = bc_add_data (o, buf, len);
  free (buf);
  return rc;
}

/* --data-urlencode as curl 8 does it: unreserved bytes stay, a space
   becomes '+', and the rest become %XX. */
static char *
bc_urlencode (const char *data, size_t n, size_t *out_len)
{
  char *out = malloc (n * 3 + 1);
  if (!out) return NULL;
  size_t j = 0;
  for (size_t i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) data[i];
      if (isalnum (c) || c == '-' || c == '.' || c == '_' || c == '~')
        out[j++] = (char) c;
      else if (c == ' ')
        out[j++] = '+';
      else
        j += (size_t) sprintf (out + j, "%%%02X", c);
    }
  out[j] = '\0';
  *out_len = j;
  return out;
}

/* --data-urlencode: "content", "=content", "name=content", "@file" and
   "name@file", as curl reads them. */
static int
bc_set_data_urlencode (bc_opts *o, const char *arg)
{
  const char *sep = strpbrk (arg, "=@");
  const char *name = arg;
  size_t name_len = 0;
  char *content = NULL;
  size_t content_len;
  if (sep && *sep == '@')
    {
      name_len = (size_t) (sep - arg);
      if (bc_read_data_file (sep, &content, &content_len) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    }
  else
    {
      const char *value = sep ? sep + 1 : arg;
      name_len = sep ? (size_t) (sep - arg) : 0;
      content_len = strlen (value);
      content = malloc (content_len + 1);
      if (!content) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
      memcpy (content, value, content_len + 1);
    }
  size_t enc_len;
  char *enc = bc_urlencode (content, content_len, &enc_len);
  free (content);
  if (!enc) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  char *joined = malloc (name_len + 1 + enc_len + 1);
  if (!joined) { free (enc); builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  size_t len = 0;
  if (name_len)
    {
      memcpy (joined, name, name_len);
      joined[name_len] = '=';
      len = name_len + 1;
    }
  memcpy (joined + len, enc, enc_len + 1);
  len += enc_len;
  free (enc);
  int rc = bc_add_data (o, joined, len);
  free (joined);
  return rc;
}

/* --json: data as --data-binary, joined without a separator, sent as JSON. */
static int
bc_set_json (bc_opts *o, const char *arg)
{
  char *buf = NULL;
  size_t len;
  if (arg[0] == '@')
    {
      if (bc_read_data_file (arg, &buf, &len) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    }
  else
    len = strlen (arg);
  const char *data = buf ? buf : arg;
  char *nb = malloc (o->body_len + len + 1);
  if (!nb) { free (buf); builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  if (o->body_set) memcpy (nb, o->body, o->body_len);
  memcpy (nb + (o->body_set ? o->body_len : 0), data, len);
  o->body_len = (o->body_set ? o->body_len : 0) + len;
  nb[o->body_len] = '\0';
  free (buf);
  free (o->body_alloc);
  o->body_alloc = nb;
  o->body = nb;
  o->body_set = 1;
  o->json = 1;
  if (!o->method_set && !strcmp (o->method, "GET")) o->method = "POST";
  return EXECUTION_SUCCESS;
}

static const char *
bc_guess_type (const char *file)
{
  static const char *map[][2] = {
    /* curl's own table (lib/mime.c); anything else is octet-stream. */
    { ".gif", "image/gif" }, { ".jpg", "image/jpeg" }, { ".jpeg", "image/jpeg" },
    { ".png", "image/png" }, { ".svg", "image/svg+xml" }, { ".txt", "text/plain" },
    { ".htm", "text/html" }, { ".html", "text/html" }, { ".pdf", "application/pdf" },
    { ".xml", "application/xml" },
  };
  const char *dot = strrchr (file, '.');
  if (dot && !strchr (dot, '/'))
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
      if (!strcasecmp (dot, map[i][0])) return map[i][1];
  return "application/octet-stream";
}

static int
bc_buf_add (char **buf, size_t *len, size_t *cap, const void *data, size_t n)
{
  if (n > SIZE_MAX - *len - 1) return -1;
  if (*len + n + 1 > *cap)
    {
      size_t ncap = *cap ? *cap : 1024;
      while (ncap < *len + n + 1) { if (ncap > SIZE_MAX / 2) return -1; ncap *= 2; }
      char *nb = realloc (*buf, ncap);
      if (!nb) return -1;
      *buf = nb; *cap = ncap;
    }
  memcpy (*buf + *len, data, n);
  *len += n;
  (*buf)[*len] = '\0';
  return 0;
}

/* -F NAME=VALUE, NAME=@FILE (an upload part) and NAME=<FILE (the file's
   bytes as the value), each with optional ;type= and ;filename=. */
static int
bc_build_form (bc_opts *o)
{
  unsigned char rnd[8];
  int rfd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (rfd < 0 || read (rfd, rnd, sizeof rnd) != (ssize_t) sizeof rnd)
    {
      if (rfd >= 0) close (rfd);
      builtin_error ("cannot read /dev/urandom: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  close (rfd);
  char boundary[64];
  int bl = snprintf (boundary, sizeof boundary, "------------------------");
  for (size_t i = 0; i < sizeof rnd; i++) bl += snprintf (boundary + bl, sizeof boundary - (size_t) bl, "%02x", rnd[i]);
  char *body = NULL;
  size_t len = 0, cap = 0;
  int rc = EXECUTION_SUCCESS;
  for (int i = 0; i < o->nforms && rc == EXECUTION_SUCCESS; i++)
    {
      const char *spec = o->forms[i];
      const char *eq = strchr (spec, '=');
      if (!eq)
        { builtin_error ("Illegally formatted input field: %s", spec); rc = 26; break; }
      char name[1024], value[4096], type[256] = "", fname[1024] = "";
      snprintf (name, sizeof name, "%.*s", (int) (eq - spec), spec);
      const char *v = eq + 1;
      int kind = *v == '@' ? '@' : *v == '<' ? '<' : 0;
      if (kind) v++;
      /* ;type= and ;filename= after the value are attributes, for
         literal values as well as files; other text stays in the value. */
      size_t vl = strlen (v);
      for (const char *a = strchr (v, ';'); a; a = strchr (a + 1, ';'))
        if (!strncmp (a + 1, "type=", 5) || !strncmp (a + 1, "filename=", 9))
          {
            vl = (size_t) (a - v);
            for (; a; a = strchr (a + 1, ';'))
              {
                const char *next = strchr (a + 1, ';');
                size_t al = next ? (size_t) (next - a - 1) : strlen (a + 1);
                if (!strncmp (a + 1, "type=", 5)) snprintf (type, sizeof type, "%.*s", (int) al - 5, a + 6);
                else if (!strncmp (a + 1, "filename=", 9)) snprintf (fname, sizeof fname, "%.*s", (int) al - 9, a + 10);
              }
            break;
          }
      snprintf (value, sizeof value, "%.*s", (int) vl, v);
      char *content = NULL;
      size_t clen = 0;
      if (kind)
        {
          char at[4100];
          snprintf (at, sizeof at, "@%s", value);
          if (bc_read_data_file (at, &content, &clen) != EXECUTION_SUCCESS)
            { rc = 26; break; }      /* CURLE_READ_ERROR */
        }
      char head[3072];
      int hl;
      if (kind == '@')
        {
          const char *base = !strcmp (value, "-") ? "-" : strrchr (value, '/') ? strrchr (value, '/') + 1 : value;
          hl = snprintf (head, sizeof head,
                         "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n",
                         boundary, name, fname[0] ? fname : base, type[0] ? type : bc_guess_type (value));
        }
      else if (type[0])
        hl = snprintf (head, sizeof head, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: %s\r\n\r\n",
                       boundary, name, type);
      else
        hl = snprintf (head, sizeof head, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n",
                       boundary, name);
      if (hl < 0 || (size_t) hl >= sizeof head
          || bc_buf_add (&body, &len, &cap, head, (size_t) hl) < 0
          || bc_buf_add (&body, &len, &cap, kind ? content : value, kind ? clen : strlen (value)) < 0
          || bc_buf_add (&body, &len, &cap, "\r\n", 2) < 0)
        { builtin_error ("out of memory"); rc = EXECUTION_FAILURE; }
      free (content);
    }
  if (rc == EXECUTION_SUCCESS)
    {
      char tail[80];
      int tl = snprintf (tail, sizeof tail, "--%s--\r\n", boundary);
      char *ct = malloc (strlen (boundary) + 40);
      if (!ct || bc_buf_add (&body, &len, &cap, tail, (size_t) tl) < 0)
        { free (ct); builtin_error ("out of memory"); rc = EXECUTION_FAILURE; }
      else
        {
          sprintf (ct, "multipart/form-data; boundary=%s", boundary);
          free (o->content_type_alloc);
          o->content_type_alloc = ct;
          o->content_type = ct;
          free (o->body_alloc);
          o->body_alloc = body;
          o->body = body;
          o->body_len = len;
          o->body_set = 1;
          body = NULL;
          if (!o->method_set) o->method = "POST";
        }
    }
  free (body);
  return rc;
}

/* -T FILE: PUT the file; a URL with no file part gets the file's name. */
static int
bc_set_upload (bc_opts *o, char *url_buf, size_t url_cap)
{
  char *buf;
  size_t len;
  char at[BCURL_URL_MAX + 2];
  snprintf (at, sizeof at, "@%s", o->upload);
  if (bc_read_data_file (at, &buf, &len) != EXECUTION_SUCCESS)
    return 26;
  free (o->body_alloc);
  o->body_alloc = buf;
  o->body = buf;
  o->body_len = len;
  o->body_set = 1;
  o->content_type = "";
  if (!o->method_set) o->method = "PUT";
  if (strcmp (o->upload, "-"))
    {
      const char *base = strrchr (o->upload, '/');
      base = base ? base + 1 : o->upload;
      const char *rest = strstr (url_buf, "://");
      rest = rest ? rest + 3 : url_buf;
      const char *slash = strchr (rest, '/');
      size_t ul = strlen (url_buf);
      if (!slash || url_buf[ul - 1] == '/')
        if (snprintf (url_buf + ul, url_cap - ul, "%s%s", slash ? "" : "/", base) >= (int) (url_cap - ul))
          { builtin_error ("URL is longer than %d bytes", BCURL_URL_MAX - 1); return EX_USAGE; }
    }
  return EXECUTION_SUCCESS;
}

/* -C OFFSET or -C - (continue from the output file's size). */
static int
bc_set_resume (bc_opts *o, const char *arg)
{
  o->resume_set = 1;
  if (!strcmp (arg, "-")) { o->resume_from = -1; return EXECUTION_SUCCESS; }
  char *end;
  errno = 0;
  long long v = strtoll (arg, &end, 10);
  if (errno || end == arg || *end || v < 0)
    { builtin_error ("-C: expected a proper numerical parameter"); return 2; }
  o->resume_from = v;
  return EXECUTION_SUCCESS;
}

static int
bc_apply_short_options (bc_opts *o, const char *w, WORD_LIST **pp)
{
  for (const char *p = w + 1; *p; p++)
    {
      const char *arg;
      switch (*p)
        {
        case 'f': o->fail_on_error = 1; break;
        case 's': o->silent = 1; break;
        case 'S': o->show_error = 1; break;
        case 'L': o->follow = 1; break;
        case 'k': o->insecure = 1; break;
        case 'O': o->use_basename = 1; break;
        case 'I': o->head = 1; break;
        case 'v': o->verbose = 1; break;
        case 'G': o->get_query = 1; break;
        case 'F':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-F", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          if (o->nforms >= BCURL_HEADER_SLOTS) { builtin_error ("too many -F parts"); return EX_USAGE; }
          o->forms[o->nforms++] = arg;
          return EXECUTION_SUCCESS;
        case 'T':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-T", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->upload = arg;
          return EXECUTION_SUCCESS;
        case 'r':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-r", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->range = arg;
          return EXECUTION_SUCCESS;
        case 'x':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-x", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->proxy = arg;
          return EXECUTION_SUCCESS;
        case 'C':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-C", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          return bc_set_resume (o, arg);
        case 'X':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-X", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->method = arg;
          o->method_set = 1;
          return EXECUTION_SUCCESS;
        case 'H':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-H", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          return bc_add_header_opt (o, arg);
        case 'd':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-d", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          return bc_set_data_opt (o, arg, 1);
        case 'o':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-o", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->outfile = arg;
          return EXECUTION_SUCCESS;
        case 'D':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-D", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->dump_headers = arg;
          return EXECUTION_SUCCESS;
        case 'w':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-w", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->write_out = arg;
          return EXECUTION_SUCCESS;
        case 'u':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-u", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->userpass = arg;
          return EXECUTION_SUCCESS;
        case 'A':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-A", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->user_agent = arg;
          return EXECUTION_SUCCESS;
        case 'b':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-b", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->cookie = arg;
          o->cookie_input = arg;
          return EXECUTION_SUCCESS;
        case 'c':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-c", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->cookie_jar = arg;
          return EXECUTION_SUCCESS;
        case 'm':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-m", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->max_time = atoi (arg);
          return EXECUTION_SUCCESS;
        default:
          builtin_error ("unknown option: -%c", *p);
          return EX_USAGE;
        }
    }
  return EXECUTION_SUCCESS;
}

int
curl_builtin (WORD_LIST *list)
{
  bc_opts o; memset (&o, 0, sizeof o);
  o.method = "GET";
  bc_quiet = 0;
  bc_errcode = 0;
  memset (&bc_wo, 0, sizeof bc_wo);
  clock_gettime (CLOCK_MONOTONIC, &bc_wo.start);
  /* Parse-time exits (errors, --help, --version) release what -d read. */
#define BC_PARSE_FAIL(rc) do { free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc); return (rc); } while (0)

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      const char *v = NULL;
      if (!strcmp (w, "--request"))                  { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.method = v; o.method_set = 1; }
      else if ((v = bc_long_eq (w, "--request")))     { o.method = v; o.method_set = 1; }
      else if (!strcmp (w, "--header"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); int hrc = bc_add_header_opt (&o, v); if (hrc != EXECUTION_SUCCESS) BC_PARSE_FAIL (hrc); }
      else if ((v = bc_long_eq (w, "--header")))      { int hrc = bc_add_header_opt (&o, v); if (hrc != EXECUTION_SUCCESS) BC_PARSE_FAIL (hrc); }
      else if (!strcmp (w, "--data") || !strcmp (w, "--data-raw") || !strcmp (w, "--data-ascii"))
        {
          if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (bc_set_data_opt (&o, v, strcmp (w, "--data-raw") != 0) != EXECUTION_SUCCESS)
            BC_PARSE_FAIL (EXECUTION_FAILURE);
        }
      else if ((v = bc_long_eq (w, "--data")) || (v = bc_long_eq (w, "--data-ascii")))
        { if (bc_set_data_opt (&o, v, 1) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EXECUTION_FAILURE); }
      else if ((v = bc_long_eq (w, "--data-raw")))
        { if (bc_set_data_opt (&o, v, 0) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EXECUTION_FAILURE); }
      else if (!strcmp (w, "--data-binary"))
        {
          if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (bc_set_data_binary_opt (&o, v) != EXECUTION_SUCCESS)
            BC_PARSE_FAIL (EXECUTION_FAILURE);
        }
      else if ((v = bc_long_eq (w, "--data-binary"))) { if (bc_set_data_binary_opt (&o, v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EXECUTION_FAILURE); }
      else if (!strcmp (w, "--output"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.outfile = v; }
      else if ((v = bc_long_eq (w, "--output")))      { o.outfile = v; }
      else if (!strcmp (w, "--dump-header"))         { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.dump_headers = v; }
      else if ((v = bc_long_eq (w, "--dump-header"))) { o.dump_headers = v; }
      else if (!strcmp (w, "--write-out"))           { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.write_out = v; }
      else if ((v = bc_long_eq (w, "--write-out")))   { o.write_out = v; }
      else if (!strcmp (w, "--user"))                { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.userpass = v; }
      else if ((v = bc_long_eq (w, "--user")))        { o.userpass = v; }
      else if (!strcmp (w, "--user-agent"))          { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.user_agent = v; }
      else if ((v = bc_long_eq (w, "--user-agent")))  { o.user_agent = v; }
      else if (!strcmp (w, "--cookie"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.cookie = v; o.cookie_input = v; }
      else if ((v = bc_long_eq (w, "--cookie")))      { o.cookie = v; o.cookie_input = v; }
      else if (!strcmp (w, "--cookie-jar"))          { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.cookie_jar = v; }
      else if ((v = bc_long_eq (w, "--cookie-jar")))  { o.cookie_jar = v; }
      else if (!strcmp (w, "--cacert"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.cacert = v; }
      else if ((v = bc_long_eq (w, "--cacert")))      { o.cacert = v; }
      else if (!strcmp (w, "-k") || !strcmp (w, "--insecure"))   o.insecure = 1;
      else if (!strcmp (w, "-f") || !strcmp (w, "--fail"))       o.fail_on_error = 1;
      else if (!strcmp (w, "--fail-with-body"))                 o.fail_with_body = 1;
      else if (!strcmp (w, "-s") || !strcmp (w, "--silent"))     o.silent = 1;
      else if (!strcmp (w, "-S") || !strcmp (w, "--show-error")) o.show_error = 1;
      else if (!strcmp (w, "-L") || !strcmp (w, "--location"))   o.follow = 1;
      else if (!strcmp (w, "--connect-timeout"))      { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.connect_time = atoi (v); }
      else if ((v = bc_long_eq (w, "--connect-timeout"))) { o.connect_time = atoi (v); }
      else if (!strcmp (w, "--max-time"))             { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.max_time = atoi (v); }
      else if ((v = bc_long_eq (w, "--max-time")))     { o.max_time = atoi (v); }
      else if (!strcmp (w, "--max-redirs"))           { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.max_redirs = atoi (v); }
      else if ((v = bc_long_eq (w, "--max-redirs")))   { o.max_redirs = atoi (v); }
      else if (!strcmp (w, "--features"))              o.features = 1;
      else if (!strcmp (w, "--head"))                  o.head = 1;
      else if (!strcmp (w, "--verbose"))               o.verbose = 1;
      else if (!strcmp (w, "--get"))                   o.get_query = 1;
      else if (!strcmp (w, "--compressed"))            o.compressed = 1;
      else if (!strcmp (w, "--http2") || !strcmp (w, "--http1.1")) ;   /* HTTP/1.1 is what is spoken */
      else if (!strcmp (w, "--retry-connrefused"))     o.retry_connrefused = 1;
      else if (!strcmp (w, "--retry-all-errors"))      o.retry_all = 1;
      else if (!strcmp (w, "--form") || (v = bc_long_eq (w, "--form")))
        {
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (o.nforms >= BCURL_HEADER_SLOTS) { builtin_error ("too many -F parts"); BC_PARSE_FAIL (EX_USAGE); }
          o.forms[o.nforms++] = v;
        }
      else if (!strcmp (w, "--upload-file") || (v = bc_long_eq (w, "--upload-file")))
        { if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.upload = v; }
      else if (!strcmp (w, "--range") || (v = bc_long_eq (w, "--range")))
        { if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.range = v; }
      else if (!strcmp (w, "--unix-socket") || (v = bc_long_eq (w, "--unix-socket"))
               || !strcmp (w, "--abstract-unix-socket") || (v = bc_long_eq (w, "--abstract-unix-socket")))
        {
          const char *opt = strncmp (w, "--abstract", 10) ? "--unix-socket" : "--abstract-unix-socket";
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (!*v)
            {
              fprintf (stderr, "curl: option %s: blank argument where content is expected\n"
                       "curl: try 'curl --help' or 'curl --manual' for more information\n", opt);
              BC_PARSE_FAIL (2);
            }
          o.unix_socket = v;
          o.abstract_unix = opt[2] == 'a';
        }
      else if (!strcmp (w, "--proxy") || (v = bc_long_eq (w, "--proxy")))
        { if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE); o.proxy = *v ? v : NULL; }
      else if (!strcmp (w, "--continue-at") || (v = bc_long_eq (w, "--continue-at")))
        {
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          int crc = bc_set_resume (&o, v);
          if (crc != EXECUTION_SUCCESS) BC_PARSE_FAIL (crc);
        }
      else if (!strcmp (w, "--data-urlencode") || (v = bc_long_eq (w, "--data-urlencode")))
        {
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (bc_set_data_urlencode (&o, v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EXECUTION_FAILURE);
        }
      else if (!strcmp (w, "--json") || (v = bc_long_eq (w, "--json")))
        {
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          if (bc_set_json (&o, v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EXECUTION_FAILURE);
        }
      else if (!strcmp (w, "--retry") || (v = bc_long_eq (w, "--retry"))
               || !strcmp (w, "--retry-delay") || (v = bc_long_eq (w, "--retry-delay"))
               || !strcmp (w, "--retry-max-time") || (v = bc_long_eq (w, "--retry-max-time")))
        {
          const char *opt = w;
          if (!v && bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) BC_PARSE_FAIL (EX_USAGE);
          char *end;
          errno = 0;
          long n = strtol (v, &end, 10);
          if (errno || end == v || *end || n < 0 || n > 100000)
            { builtin_error ("%s: expected a proper numerical parameter", opt); BC_PARSE_FAIL (2); }
          if (!strncmp (opt, "--retry-delay", 13)) o.retry_delay = (int) n;
          else if (!strncmp (opt, "--retry-max-time", 16)) ;   /* accepted; each try keeps -m */
          else o.retries = (int) n;
        }
      else if (!strcmp (w, "--version") || !strcmp (w, "-V")) { bc_version (); BC_PARSE_FAIL (EXECUTION_SUCCESS); }
      else if (!strcmp (w, "-h") || !strcmp (w, "--help"))       { bc_usage (); BC_PARSE_FAIL (EXECUTION_SUCCESS); }
      else if (w[0] == '-' && w[1] != '-' && w[1] != '\0')
        {
          int brc = bc_apply_short_options (&o, w, &p);
          if (brc != EXECUTION_SUCCESS) BC_PARSE_FAIL (brc);
        }
      else if (w[0] == '-' && w[1] != '\0')
        { builtin_error ("unknown option: %s", w); BC_PARSE_FAIL (EX_USAGE); }
      else
        {
          if (o.url) { builtin_error ("extra URL: %s", w); BC_PARSE_FAIL (EX_USAGE); }
          o.url = w;
        }
    }
  if (o.features) { bc_features (); BC_PARSE_FAIL (EXECUTION_SUCCESS); }
  if (!o.url) { bc_usage (); BC_PARSE_FAIL (EX_USAGE); }
  if (o.nforms && (o.body_set || o.upload || o.head))
    {
      builtin_error ("You can only select one HTTP request method! You asked for both POST (-F, --form) and %s.",
                     o.head ? "HEAD (-I, --head)" : o.upload ? "PUT (-T, --upload-file)" : "POST (-d, --data)");
      BC_PARSE_FAIL (2);
    }
  if (o.head && (o.body_set || o.upload) && !o.get_query)
    {
      builtin_error ("You can only select one HTTP request method! You asked for both POST (-d, --data) and HEAD (-I, --head).");
      BC_PARSE_FAIL (2);
    }
  if (o.json)
    {
      if (!o.content_type) o.content_type = "application/json";
      o.accept = "application/json";
    }
  if (o.nforms)
    {
      int frc = bc_build_form (&o);
      if (frc != EXECUTION_SUCCESS) { BC_PARSE_FAIL (frc); }
    }
  if (o.fail_on_error && o.fail_with_body)
    {
      fprintf (stderr, "curl: You must select either --fail or --fail-with-body, not both.\n"
               "curl: option --fail-with-body: is badly used here\n"
               "curl: try 'curl --help' or 'curl --manual' for more information\n");
      BC_PARSE_FAIL (2);
    }
  if (o.head && !o.method_set) o.method = "HEAD";
  if (o.unix_socket) o.proxy = NULL;     /* curl does not mix a proxy with a unix socket */
  if (o.proxy)
    {
      char ph[256], pp[16];
      if (bc_parse_proxy (o.proxy, ph, sizeof ph, pp, sizeof pp, o.proxy_auth, sizeof o.proxy_auth) < 0)
        { BC_PARSE_FAIL (bc_errcode ? bc_errcode : 5); }
    }

  /* Coalesce silent/show_error: -s -S keeps error diagnostics, -s alone
   * suppresses them. The bash builtin_error path always goes to stderr;
   * we just gate the call. */
  int show_errs = (!o.silent) || o.show_error;
  bc_quiet = !show_errs;

  char cur_url[BCURL_URL_MAX];
  if (snprintf (cur_url, sizeof cur_url, "%s", o.url) >= (int) sizeof cur_url)
    {
      builtin_error ("URL is longer than %d bytes", BCURL_URL_MAX - 1);
      BC_PARSE_FAIL (EX_USAGE);
    }
  if (o.upload)
    {
      int urc = bc_set_upload (&o, cur_url, sizeof cur_url);
      if (urc != EXECUTION_SUCCESS) { BC_PARSE_FAIL (urc); }
    }
  /* -G: the -d data becomes the query string of a GET (or HEAD). */
  if (o.get_query && o.body_set && !o.upload)
    {
      size_t ul = strlen (cur_url);
      const char *join = strchr (cur_url, '?') ? "&" : "?";
      if (ul + 1 + o.body_len >= sizeof cur_url)
        {
          builtin_error ("URL is longer than %d bytes", BCURL_URL_MAX - 1);
          BC_PARSE_FAIL (EX_USAGE);
        }
      snprintf (cur_url + ul, sizeof cur_url - ul, "%s%.*s", join, (int) o.body_len, o.body);
      o.body_set = 0;
      o.body_len = 0;
      if (!o.method_set) o.method = o.head ? "HEAD" : "GET";
    }
  /* -C -: continue from what the output file already holds. */
  if (o.resume_set && o.resume_from < 0)
    {
      struct stat st;
      const char *target = o.outfile;
      char nbuf[BCURL_URL_MAX];
      if (!target && o.use_basename)
        {
          bc_url tu;
          if (bc_parse_url (cur_url, &tu) == 0)
            {
              const char *end = tu.path + strcspn (tu.path, "?#"), *base = end;
              while (base > tu.path && base[-1] != '/') base--;
              snprintf (nbuf, sizeof nbuf, "%.*s", (int) (end - base), base);
              target = nbuf;
            }
        }
      o.resume_from = target && strcmp (target, "-") && stat (target, &st) == 0 ? (long long) st.st_size : 0;
    }
  bc_wo.url = o.url;
  bc_wo.effective = cur_url;
  if (strncasecmp (cur_url, "file://", 7) == 0)
    {
      int frc = bc_file_url (&o, cur_url);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return frc;
    }
  bc_url start_url, hop_url_dummy;
  int have_start_url = bc_parse_url (cur_url, &start_url) == 0;
  memset (&hop_url_dummy, 0, sizeof hop_url_dummy);
  int cookie_from_file = o.cookie_input && strchr (o.cookie_input, '=') == NULL
                         && have_start_url && access (o.cookie_input, R_OK) == 0;

  bc_response r;
  int redirects = 0;
  int rc;
  int retried = 0;
  long backoff = 1;
  for (;;)
    {
      memset (&r, 0, sizeof r);
      if (cookie_from_file)
        {
          bc_url req_url;
          free (o.cookie_alloc);
          o.cookie_alloc = NULL;
          o.cookie = NULL;
          if (bc_parse_url (cur_url, &req_url) == 0)
            {
              o.cookie_alloc = bc_cookie_from_jar (o.cookie_input, &req_url,
                                                   &start_url, o.method);
              if (o.cookie_alloc)
                o.cookie = o.cookie_alloc;
            }
        }
      {
        bc_url hop;
        o.offsite = have_start_url && bc_parse_url (cur_url, &hop) == 0
                    && !bc_same_origin (&start_url, &hop);
        if (o.offsite)
          o.auth_dropped = 1;
      }
      bc_errcode = 0;
      rc = bc_one_request (&o, cur_url, &r);
      /* --retry: timeouts and HTTP 408, 429, 500, 502, 503 and 504 are
         transient; refused connections with --retry-connrefused, and any
         error with --retry-all-errors. */
      if (o.retries > retried)
        {
          int transient = 0;
          const char *what = NULL;
          if (rc < 0)
            {
              transient = bc_errcode == 28 || o.retry_all
                          || (bc_errcode == 7 && o.retry_connrefused);
              what = bc_errcode == 28 ? "timeout" : "error";
            }
          else if (r.status == 408 || r.status == 429 || r.status == 500 || r.status == 502
                   || r.status == 503 || r.status == 504 || (o.retry_all && r.status >= 400))
            {
              transient = 1;
              what = "HTTP error";
            }
          if (transient)
            {
              long delay = o.retry_delay > 0 ? o.retry_delay : backoff;
              char after[32];
              if (rc == 0 && o.retry_delay == 0 && r.headers
                  && bc_header_value (r.headers, "Retry-After", after, sizeof after))
                {
                  char *end;
                  long v = strtol (after, &end, 10);
                  if (end != after && !*end && v >= 0 && v <= 600) delay = v;
                }
              int left = o.retries - retried;
              if (!o.silent)
                fprintf (stderr, "Warning: Problem : %s. Will retry in %ld second%s. %d retr%s left.\n",
                         what, delay, delay == 1 ? "" : "s", left, left == 1 ? "y" : "ies");
              /* Without -f, curl writes each attempt's body before the
                 next try; a file output is rewritten by the next one. */
              if (rc == 0 && !o.fail_on_error && !o.head
                  && bc_emit (&o, have_start_url ? &start_url : &hop_url_dummy, &r) < 0)
                { bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc); return 23; }
              if (rc == 0) bc_response_free (&r);
              if (delay > 0) sleep ((unsigned) delay);
              if (o.retry_delay == 0 && backoff < 600) backoff *= 2;
              retried++;
              continue;
            }
        }
      if (rc < 0)
        {
          /* bc_error already honoured -s; report curl's code when known.
             -w is still written, as curl does (http_code 000). */
          int code = bc_errcode ? bc_errcode : EXECUTION_FAILURE;
          bc_response none;
          memset (&none, 0, sizeof none);
          if (!bc_wo.exitcode) bc_wo.exitcode = code;
          bc_emit_write_out (&o, &none);
          free (o.cookie_alloc);
          free (o.body_alloc); free (o.content_type_alloc);
          return code;
        }
      if (o.follow && r.status >= 300 && r.status < 400
          && (r.location[0] || r.location_too_long || r.location_bad))
        {
          int rcap = o.max_redirs > 0 ? o.max_redirs : BCURL_MAX_REDIRECTS;
          if (++redirects > rcap)
            { bc_curl_error (47, "Maximum (%d) redirects followed", rcap);
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc);
              return 47; /* CURLE_TOO_MANY_REDIRECTS */ }
          if (r.location_too_long)
            { if (show_errs) builtin_error ("redirect target is longer than %d bytes", BCURL_URL_MAX - 1);
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc); return EXECUTION_FAILURE; }
          if (r.location_bad)
            { bc_curl_error (3, "The redirect target URL could not be parsed: Malformed input to a URL function");
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc);
              return 3; /* CURLE_URL_MALFORMAT */ }
          char next[BCURL_URL_MAX];
          if (bc_resolve_redirect (cur_url, r.location, next, sizeof next) < 0)
            { if (show_errs) builtin_error ("bad redirect target: %s", r.location);
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc); return EXECUTION_FAILURE; }
          snprintf (cur_url, sizeof cur_url, "%s", next);
          bc_wo.redirects++;
          if (o.head)
            {
              if (bc_emit (&o, have_start_url ? &start_url : &hop_url_dummy, &r) < 0)
                { bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc); return 23; }
              o.head_hops++;
            }
          /* RFC 9110 15.4: 303 is retrieved with GET, and curl also turns a
           * POST into GET on 301/302. 307/308 and an explicit -X keep the
           * method and content. */
          if (!o.method_set && strcmp (o.method, "HEAD") != 0
              && (r.status == 303
                  || ((r.status == 301 || r.status == 302) && !strcmp (o.method, "POST"))))
            {
              o.method = "GET";
              o.body_set = 0;
              o.body_len = 0;
            }
          bc_response_free (&r);
          continue;
        }
      break;
    }

  if ((o.fail_on_error || o.fail_with_body) && r.status >= 400)
    {
      /* --fail-with-body writes the error page before failing. */
      int erc = 22;
      if (o.fail_with_body && (bc_emit_headers (&o, &r) < 0
                               || bc_emit (&o, have_start_url ? &start_url : &hop_url_dummy, &r) < 0))
        erc = 23;
      bc_curl_error (22, "The requested URL returned error: %d", r.status);
      bc_emit_write_out (&o, &r);
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return erc; /* curl's CURLE_HTTP_RETURNED_ERROR (or write error) */
    }

  if (o.resume_set && o.resume_from > 0 && !o.head)
    {
      /* A 416 to a resumed transfer means the file is already complete. */
      if (r.status == 416)
        {
          bc_response_free (&r);
          free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc);
          return EXECUTION_SUCCESS;
        }
      if (r.status >= 200 && r.status < 300 && r.status != 206)
        {
          bc_curl_error (33, "HTTP server doesn't seem to support byte ranges. Cannot resume.");
          bc_response_free (&r);
          free (o.cookie_alloc); free (o.body_alloc); free (o.content_type_alloc);
          return 33;
        }
    }

  bc_url eu;
  bc_parse_url (cur_url, &eu);
  if (bc_save_cookie_jar (o.cookie_jar, &eu, r.headers) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return EXECUTION_FAILURE;
    }
  if (bc_emit_headers (&o, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return 23; /* CURLE_WRITE_ERROR */
    }
  if (bc_emit (&o, have_start_url ? &start_url : &eu, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return 23; /* CURLE_WRITE_ERROR */
    }
  if (bc_emit_write_out (&o, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc); free (o.content_type_alloc);
      return EXECUTION_FAILURE;
    }

  /* The received part was written, as curl does, before reporting it. */
  long missing = r.missing;
  bc_response_free (&r);
  free (o.cookie_alloc);
  free (o.body_alloc); free (o.content_type_alloc);
  if (missing > 0)
    {
      bc_curl_error (18, "end of response with %ld bytes missing", missing);
      return 18; /* CURLE_PARTIAL_FILE */
    }
  return EXECUTION_SUCCESS;
#undef BC_PARSE_FAIL
}

char *curl_doc[] = {
  "curl(1)-shaped HTTP client over http + crypto.",
  "  curl [-fsSLkO] [-X METHOD] [-H HDR]... [-d DATA]",
  "           [--data-binary DATA] [-o FILE] [-D FILE] [-w FORMAT] [--fail-with-body]",
  "           [-u USER:PASS] [-A AGENT] [-b COOKIE|FILE] [-c FILE]",
  "           [--cacert PEM] [--connect-timeout SEC] [-m|--max-time SEC] [--max-redirs N]",
  "           [-I] [-v] [-F PART] [-T FILE] [-G] [--data-urlencode DATA] [--json DATA]",
  "           [--retry N] [-x PROXY] [--compressed] [--http2] [-r RANGE] [-C OFFSET|-]",
  "           [--unix-socket PATH] [--abstract-unix-socket NAME] [--features] [-V|--version] URL",
  "Long aliases and --name=value forms are normalized for supported options.",
  "Attached short arguments such as -oFILE and bundles like -fsSLo FILE work.",
  "Plain http:// uses raw TCP; https:// pipes the framed request through",
  "`crypto tls connect HOST:PORT -s HOST [-c PEM] [-k]` in a bash subshell.",
  "--unix-socket PATH / --abstract-unix-socket NAME connect to a unix-domain",
  "stream socket instead of HOST:PORT (TLS runs over it); no proxy is used.",
  "Subset: GET/POST/PUT/etc., common -f/-s/-S/-L/-k/-O bundles, -D, --fail-with-body,",
  "-w FORMAT|@FILE with %{http_code} %{response_code} %{size_download} %{size_header}",
  "  %{size_upload} %{content_type} %{url} %{url_effective} %{redirect_url} %{num_redirects}",
  "  %{num_connects} %{num_headers} %{method} %{scheme} %{http_version} %{exitcode} %{errormsg}",
  "  %{filename_effective} %{remote_ip} %{remote_port} %{local_ip} %{local_port} %{time_*}",
  "  %{speed_download} %{speed_upload} %header{NAME} %{stdout} %{stderr} %{onerror},",
  "--data-binary (@-/@FILE/literal), Basic auth, -b/--cookie literal or jar input, -c/--cookie-jar output, redirects (default max 20),",
  "chunked + Content-Length decoding, -F multipart, HTTP proxies (CONNECT for https),",
  "gzip/deflate with --compressed, ranges and resume. --http2 talks HTTP/1.1.",
  "Out of scope: non-HTTP cookie schemes, --resolve, HTTP/2 framing, SOCKS, OAuth.",
  (char *) NULL
};

struct builtin curl_struct = {
  "curl",
  curl_builtin,
  BUILTIN_ENABLED,
  curl_doc,
  "curl [opts] URL",
  0
};
