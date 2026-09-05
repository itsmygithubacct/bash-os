/* SPDX-License-Identifier: MIT */
/* rngseed-host.c — host test of the rngseed builtin's seed-file contract.
 *
 * rngseed.c is a real bash builtin (it includes bash's config.h and calls the
 * bash runtime) and the built bash is riscv, so `enable -a` cannot run it
 * here. This links the REAL rngseed.c against the configured bash tree, stubs
 * only the five runtime symbols it calls, and drives rngseed_builtin()
 * directly. tests/run-all.sh builds and runs it under ASan+UBSan.
 *
 * What it proves — the parts a board boot would hide behind "did it wait":
 *   - save writes 512 bytes, mode 0600, atomically (no .tmp left behind);
 *   - a second save yields different bytes (fresh getrandom, not a repeat);
 *   - a MISSING seed on load is the first boot: exit 0, not an error;
 *   - a too-short seed is refused and left untouched;
 *   - a FAILED credit leaves the seed byte-identical — never consumed. The
 *     credit needs CAP_SYS_ADMIN, so as non-root it is EPERM: exactly the
 *     branch that must not destroy the seed. As root the credit runs for real
 *     and the seed must then have been REFRESHED instead;
 *   - verb and argument errors are EX_USAGE.
 * The credit's success path (RNDADDENTROPY initialising the pool) is proven on
 * the board by the two-boot test, not here.
 *
 * Build (what run-all.sh does):
 *   cc -fsanitize=address,undefined -DHAVE_CONFIG_H -Iinclude -Iloadables/common \
 *      -Ibuild/bash-5.3 -Ibuild/bash-5.3/include -Ibuild/bash-5.3/builtins \
 *      -Ibuild/bash-5.3/examples/loadables loadables/rngseed.c tests/rngseed-host.c
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "loadables.h"
#include "bashgetopt.h"

/* --- the five bash runtime symbols rngseed.c calls, stubbed ---------------- */
WORD_LIST *loptend;
void reset_internal_getopt (void) {}
int internal_getopt (WORD_LIST *l, char *o) { (void) o; loptend = l; return -1; }
void builtin_error (const char *fmt, ...)
{
  va_list a; va_start (a, fmt);
  fputs ("rngseed: ", stderr); vfprintf (stderr, fmt, a); fputc ('\n', stderr);
  va_end (a);
}
void builtin_usage (void) { fputs ("usage: rngseed load|save FILE\n", stderr); }
extern int rngseed_builtin (WORD_LIST *);

/* rngseed_builtin over a temporary arg list, freed afterwards so the harness
   is leak-clean and ASan's leak check stays meaningful for rngseed.c itself. */
static int
run (int n, ...)
{
  WORD_LIST *head = 0, **tail = &head, *l;
  va_list a; va_start (a, n);
  for (int i = 0; i < n; i++)
    {
      WORD_LIST *w = calloc (1, sizeof *w);
      w->word = calloc (1, sizeof *w->word);
      w->word->word = va_arg (a, char *);
      *tail = w; tail = &w->next;
    }
  va_end (a);
  int rc = rngseed_builtin (head);
  while ((l = head)) { head = l->next; free (l->word); free (l); }
  return rc;
}

static int fails;
#define CHECK(c, msg) \
  do { if (c) printf ("  ok   %s\n", msg); else { printf ("  FAIL %s\n", msg); fails++; } } while (0)
static long fsize (const char *p) { struct stat st; return stat (p, &st) == 0 ? (long) st.st_size : -1; }
static int  fmode (const char *p) { struct stat st; return stat (p, &st) == 0 ? (int) (st.st_mode & 07777) : -1; }
static long slurp (const char *p, unsigned char *b, long cap)
{ FILE *f = fopen (p, "rb"); if (!f) return -1; long n = (long) fread (b, 1, cap, f); fclose (f); return n; }

int
main (void)
{
  umask (0);				/* 0600 must come from the builtin, not the umask */
  char d[] = "/tmp/rngseed-XXXXXX";
  if (!mkdtemp (d)) { perror ("mkdtemp"); return 2; }
  char seed[PATH_MAX], tmp[PATH_MAX], shortf[PATH_MAX], missing[PATH_MAX];
  snprintf (seed,    sizeof seed,    "%s/random-seed",     d);
  snprintf (tmp,     sizeof tmp,     "%s/random-seed.tmp", d);
  snprintf (shortf,  sizeof shortf,  "%s/short",           d);
  snprintf (missing, sizeof missing, "%s/nope",            d);
  unsigned char a[512], b[512], c[512];
  int rc;

  puts ("== save: creates a 512-byte 0600 seed atomically ==");
  rc = run (2, "save", seed);
  CHECK (rc == EXECUTION_SUCCESS, "save returns success");
  CHECK (fsize (seed) == 512, "seed is 512 bytes");
  CHECK (fmode (seed) == 0600, "seed mode is 0600");
  CHECK (access (tmp, F_OK) != 0, "no .tmp left behind (rename completed)");
  slurp (seed, a, 512);

  puts ("== save again: fresh bytes, not a repeat ==");
  rc = run (2, "save", seed);
  slurp (seed, b, 512);
  CHECK (rc == EXECUTION_SUCCESS && memcmp (a, b, 512) != 0, "second save differs from the first (fresh getrandom)");
  CHECK (fsize (seed) == 512 && fmode (seed) == 0600, "still 512 bytes, 0600");

  puts ("== load on a MISSING file: first boot, exit 0 ==");
  CHECK (run (2, "load", missing) == EXECUTION_SUCCESS, "missing seed is a non-error (first boot)");

  puts ("== load on a too-short file: refused, untouched ==");
  { FILE *f = fopen (shortf, "wb"); fwrite ("0123456789", 1, 10, f); fclose (f); }
  CHECK (run (2, "load", shortf) == EXECUTION_FAILURE, "10-byte seed rejected");
  CHECK (fsize (shortf) == 10, "rejected seed left untouched");

  puts ("== load: the credit either fails and keeps the seed, or succeeds and refreshes it ==");
  rc = run (2, "load", seed);
  long got = slurp (seed, c, 512);
  if (geteuid () != 0)
    {
      CHECK (rc == EXECUTION_FAILURE, "non-root credit fails (RNDADDENTROPY needs CAP_SYS_ADMIN)");
      CHECK (got == 512 && memcmp (b, c, 512) == 0, "a FAILED credit leaves the seed byte-identical (not consumed)");
      CHECK (access (tmp, F_OK) != 0, "and no .tmp was created");
    }
  else
    {
      CHECK (rc == EXECUTION_SUCCESS, "root credit succeeds");
      CHECK (got == 512 && memcmp (b, c, 512) != 0, "credited seed was REPLACED with fresh bytes (never reused)");
      CHECK (fmode (seed) == 0600 && access (tmp, F_OK) != 0, "refreshed seed is 0600, no .tmp");
    }

  puts ("== argument handling ==");
  CHECK (run (2, "frob", seed) == EX_USAGE, "unknown verb -> EX_USAGE");
  CHECK (run (1, "save") == EX_USAGE, "missing FILE -> EX_USAGE");
  CHECK (run (3, "save", seed, "extra") == EX_USAGE, "extra arg -> EX_USAGE");

  unlink (seed); unlink (tmp); unlink (shortf); rmdir (d);
  printf ("\nrngseed-host: %s (%d failures)\n", fails ? "FAILED" : "all checks pass", fails);
  return fails ? 1 : 0;
}
