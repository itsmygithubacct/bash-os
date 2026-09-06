/* SPDX-License-Identifier: MIT */
/* zstd-host.c — the zstd loadable under AddressSanitizer+UBSan on the host:
 * the real loadables/zstd.c compiled against the built bash tree with the few
 * bash runtime symbols it calls stubbed. Exercises the buffer paths — a
 * round trip larger than the decoder's chunk, an empty input, a truncated
 * frame, garbage, the no-progress guard — and the library-absent path.
 *
 *   cc -fsanitize=address,undefined -DHAVE_CONFIG_H -Ibuild/bash-5.3 \
 *      -Ibuild/bash-5.3/include -Ibuild/bash-5.3/builtins -Ibuild/bash-5.3/examples/loadables \
 *      loadables/zstd.c tests/zstd-host.c -o /tmp/t && /tmp/t
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "loadables.h"

/* ---- the bash runtime, stubbed -------------------------------------------- */
static char last_error[512];
void builtin_error (const char *fmt, ...)
{ va_list a; va_start (a, fmt); vsnprintf (last_error, sizeof last_error, fmt, a); va_end (a); fprintf (stderr, "zstd: %s\n", last_error); }
void builtin_usage (void) { fputs ("usage: zstd ...\n", stderr); }
extern int bashos_zstd_run (WORD_LIST *, int);

/* ---- harness plumbing ------------------------------------------------------ */
static int fails;
#define CHECK(c, msg) do { if (c) printf ("  ok   %s\n", msg); else { printf ("  FAIL %s\n", msg); fails++; } } while (0)
static int
run (int cat_mode, const char *first, ...)
{
  WORD_LIST *head = 0, **tail = &head, *l; va_list a; const char *w;
  va_start (a, first);
  for (w = first; w != NULL; w = va_arg (a, const char *))
    { WORD_LIST *x = calloc (1, sizeof *x); x->word = calloc (1, sizeof *x->word); x->word->word = (char *) w; *tail = x; tail = &x->next; }
  va_end (a);
  /* the builtin writes to fd 1 (-c, zstdcat): send that to /dev/null, keep ours */
  fflush (stdout);
  int saved = dup (1), devnull = open ("/dev/null", O_WRONLY); dup2 (devnull, 1); close (devnull);
  int rc = bashos_zstd_run (head, cat_mode);
  fflush (stdout); dup2 (saved, 1); close (saved);
  while ((l = head)) { head = l->next; free (l->word); free (l); }
  return rc;
}
static void put (const char *path, const void *b, size_t n)
{ int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (fd < 0 || write (fd, b, n) != (ssize_t) n) { perror (path); exit (1); } close (fd); }
static long size_of (const char *path) { struct stat st; return stat (path, &st) == 0 ? (long) st.st_size : -1; }
static int same (const char *a, const char *b)
{
  FILE *fa = fopen (a, "rb"), *fb = fopen (b, "rb"); int ca, cb, eq = fa && fb;
  if (eq) do { ca = fgetc (fa); cb = fgetc (fb); if (ca != cb) eq = 0; } while (eq && ca != EOF);
  if (fa) fclose (fa); if (fb) fclose (fb); return eq;
}

int
main (void)
{
  char dir[] = "/tmp/zstd-host.XXXXXX"; if (!mkdtemp (dir)) return 1;
  if (chdir (dir) != 0) return 1;
  int has_lib = run (0, "-q", "-c", "/dev/null", (char *) 0) == 0;
  if (!has_lib) { printf ("zstd-host: SKIP (no libzstd on this host: %s)\n", last_error); return 0; }

  /* a text larger than the decoder's output chunk, so the growing buffer is exercised */
  size_t n = 3 * 1024 * 1024; char *big = malloc (n); for (size_t i = 0; i < n; i++) big[i] = "abcdefgh\n"[i % 9]; put ("big", big, n);
  CHECK (run (0, "-q", "big", (char *) 0) == 0 && size_of ("big.zst") > 0 && size_of ("big.zst") < (long) n / 10, "compress: 3 MiB of text shrinks tenfold");
  CHECK (run (0, "-d", "-o", "big.back", "big.zst", (char *) 0) == 0 && same ("big", "big.back"), "decompress through the growing buffer: identical");
  CHECK (size_of ("big") == (long) n, "the source is kept");
  put ("empty", "", 0);
  CHECK (run (0, "empty", (char *) 0) == 0 && run (0, "-d", "-o", "empty.back", "empty.zst", (char *) 0) == 0 && size_of ("empty.back") == 0, "an empty file round-trips");
  CHECK (run (0, "big", (char *) 0) == EXECUTION_FAILURE && strstr (last_error, "already exists"), "no overwrite without -f");
  CHECK (run (0, "-f", "--rm", "big", (char *) 0) == 0 && size_of ("big") < 0, "-f --rm: overwrote and removed the source");

  /* damaged inputs must fail cleanly, never crash or over-read */
  long z = size_of ("big.zst"); char *zb = malloc (z); FILE *f = fopen ("big.zst", "rb"); if (fread (zb, 1, z, f) != (size_t) z) return 1; fclose (f);
  put ("trunc.zst", zb, z / 2);
  CHECK (run (0, "-d", "-c", "trunc.zst", (char *) 0) == EXECUTION_FAILURE && strstr (last_error, "truncated"), "truncated frame: named error");
  put ("garbage.zst", "this is not a zstd frame at all, not even close", 47);
  CHECK (run (0, "-d", "-c", "garbage.zst", (char *) 0) == EXECUTION_FAILURE, "garbage: error");
  zb[10] ^= 0xff; put ("corrupt.zst", zb, z);
  CHECK (run (0, "-d", "-c", "corrupt.zst", (char *) 0) == EXECUTION_FAILURE, "a flipped byte: error");
  CHECK (run (0, "-d", "-c", "big.zst", (char *) 0) == 0, "and the intact file still decodes");
  CHECK (run (1, "big.zst", (char *) 0) == 0, "zstdcat mode");
  CHECK (run (0, "-o", "x", "a", "b", (char *) 0) == EX_USAGE, "-o with two inputs is a usage error");
  CHECK (run (0, "-40", "big.zst", (char *) 0) == EX_USAGE, "level 40 is a usage error");
  CHECK (run (0, "-d", "-c", "nope.zst", (char *) 0) == EXECUTION_FAILURE, "a missing input fails");
  free (big); free (zb);
  printf ("zstd-host: %s\n", fails ? "FAIL" : "all checks passed");
  return fails ? 1 : 0;
}
