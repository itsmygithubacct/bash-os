/* SPDX-License-Identifier: MIT */
/* Compile this translation unit with ASan/UBSan through the build gate.
   Faults intercept calls in the actual production source, not a copied codec. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <zstd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include "loadables.h"

static int allocation = -1, read_fault, write_fault, short_io;
static int close_fault, mode_fault, times_fault, publish_fault, remove_fault;
static int race_target, swap_source;
static void *fault_malloc (size_t n)
{
  if (allocation == 0) { allocation = -1; return NULL; }
  if (allocation > 0) allocation--;
  return malloc (n);
}
static ssize_t fault_read (int fd, void *b, size_t n)
{
  if (read_fault) { errno = read_fault == 1 ? EINTR : EIO; read_fault = 0; return -1; }
  return read (fd, b, short_io && n > 17 ? 17 : n);
}
static ssize_t fault_write (int fd, const void *b, size_t n)
{
  if (write_fault) { int f = write_fault; write_fault = 0; errno = f == 1 ? EINTR : ENOSPC; return f == 3 ? 0 : -1; }
  return write (fd, b, short_io && n > 13 ? 13 : n);
}
static int fault_close (int fd)
{
  int rc = close (fd);
  if (close_fault > 0 && --close_fault == 0) { errno = EIO; return -1; }
  return rc;
}
static int fault_fchmod (int fd, mode_t m)
{ if (mode_fault) { mode_fault = 0; errno = EPERM; return -1; } return fchmod (fd, m); }
static int fault_futimens (int fd, const struct timespec ts[2])
{ if (times_fault) { times_fault = 0; errno = EPERM; return -1; } return futimens (fd, ts); }
static int fault_link (const char *src, const char *dst)
{
  if (race_target) { int fd = open (dst, O_WRONLY | O_CREAT | O_EXCL, 0600); if (fd >= 0) { write (fd, "racer", 5); close (fd); } race_target = 0; }
  if (publish_fault) { publish_fault = 0; errno = EIO; return -1; }
  return link (src, dst);
}
static int fault_rename (const char *src, const char *dst)
{
  if (swap_source)
    { rename ("input", "saved-input"); int fd = open ("input", O_WRONLY | O_CREAT | O_EXCL, 0600); if (fd >= 0) { write (fd, "replacement", 11); close (fd); } swap_source = 0; }
  if (publish_fault) { publish_fault = 0; errno = EIO; return -1; } return rename (src, dst); }
static int fault_unlink (const char *p)
{ if (remove_fault && strcmp (p, "input") == 0) { remove_fault = 0; errno = EACCES; return -1; } return unlink (p); }
#define malloc fault_malloc
#define read fault_read
#define write fault_write
#define close fault_close
#define fchmod fault_fchmod
#define futimens fault_futimens
#define link fault_link
#define rename fault_rename
#define unlink fault_unlink
#include "../loadables/zstd.c"
#undef malloc
#undef read
#undef write
#undef close
#undef fchmod
#undef futimens
#undef link
#undef rename
#undef unlink

/* Retain every historical harness assertion and its Bash-runtime stubs. */
#define main historical_main
#include "zstd-host.c"
#undef main
#include <dirent.h>
static ZSTD_CStream *no_cs (void) { return NULL; }
static ZSTD_DStream *no_ds (void) { return NULL; }
static size_t stalled (ZSTD_DStream *d, ZSTD_outBuffer *o, ZSTD_inBuffer *i)
{ (void) d; (void) o; (void) i; return 1; }
static size_t init_cs_error (ZSTD_CStream *cs, int level)
{ (void) cs; (void) level; return (size_t) -1; }
static size_t end_stalled (ZSTD_CStream *cs, ZSTD_outBuffer *ob)
{ (void) cs; (void) ob; return 1; }
static int no_temps (void)
{
  int clean = 1; struct dirent *e; DIR *d = opendir (".");
  while ((e = readdir (d))) if (strstr (e->d_name, ".tmp.")) clean = 0;
  closedir (d); return clean;
}
static int fd_count (void)
{
  DIR *d = opendir ("/proc/self/fd"); struct dirent *e; int n = 0;
  while ((e = readdir (d))) if (e->d_name[0] != '.') n++;
  closedir (d); return n;
}
static int compress (void) { return run (0, "-f", "--rm", "-o", "dest", "input", (char *) 0); }
static int intact (void) { return same ("input", "original") && same ("dest", "sentinel") && no_temps (); }
int main (void)
{
  int old = historical_main ();
  char dir[] = "/tmp/sol-zstd-host.XXXXXX";
  if (!mkdtemp (dir) || chdir (dir)) return 1;
  char data[300000]; for (size_t i = 0; i < sizeof data; i++) data[i] = (char) (i * 17 + i / 251);
  put ("original", data, sizeof data); put ("input", data, sizeof data);
  put ("sentinel", "old destination", 15); put ("dest", "old destination", 15);
  for (int i = 0; i < 2; i++)
    { allocation = i; CHECK (compress () == 1 && intact (), "buffer allocation failure keeps source/destination, no temporary"); }
  ZSTD_CStream *(*saved_cs)(void) = zs.createCStream;
  zs.createCStream = no_cs;
  CHECK (compress () == 1 && intact (), "compression context allocation failure is atomic");
  zs.createCStream = saved_cs;
  size_t (*saved_init)(ZSTD_CStream *, int) = zs.initCStream;
  zs.initCStream = init_cs_error;
  CHECK (compress () == 1 && intact (), "compression initialization error is atomic");
  zs.initCStream = saved_init;
  size_t (*saved_end)(ZSTD_CStream *, ZSTD_outBuffer *) = zs.endStream;
  zs.endStream = end_stalled;
  CHECK (compress () == 1 && intact (), "encoder no-progress guard is atomic");
  zs.endStream = saved_end;
  read_fault = 2; CHECK (compress () == 1 && intact (), "read error is atomic");
  write_fault = 2; CHECK (compress () == 1 && intact (), "write ENOSPC is atomic");
  write_fault = 3; CHECK (compress () == 1 && intact (), "zero-byte write fails without spinning");
  for (int i = 1; i <= 2; i++)
    { close_fault = i; CHECK (compress () == 1 && intact (), "input/output close error keeps source/destination"); }
  mode_fault = 1; CHECK (compress () == 1 && intact (), "mode error is atomic");
  times_fault = 1; CHECK (compress () == 1 && intact (), "timestamp error is atomic");
  publish_fault = 1; CHECK (compress () == 1 && intact (), "rename error is atomic");
  read_fault = write_fault = short_io = 1;
  CHECK (run (0, "-f", "-o", "good.zst", "input", (char *) 0) == 0, "short I/O and EINTR compression succeeds");
  read_fault = write_fault = 1;
  CHECK (run (0, "-d", "-o", "back", "good.zst", (char *) 0) == 0 && same ("back", "original"), "short I/O and EINTR decode round-trips");
  short_io = 0;
  ZSTD_DStream *(*saved_ds)(void) = zs.createDStream;
  zs.createDStream = no_ds;
  CHECK (run (0, "-df", "--rm", "-o", "dest", "good.zst", (char *) 0) == 1 && intact () && size_of ("good.zst") > 0, "decoder context allocation failure keeps files");
  zs.createDStream = saved_ds;
  size_t (*saved_decode)(ZSTD_DStream *, ZSTD_outBuffer *, ZSTD_inBuffer *) = zs.decompressStream;
  zs.decompressStream = stalled;
  CHECK (run (0, "-df", "--rm", "-o", "dest", "good.zst", (char *) 0) == 1 && intact (), "decoder no-progress guard is atomic");
  zs.decompressStream = saved_decode;
  publish_fault = 1;
  CHECK (run (0, "-o", "new", "input", (char *) 0) == 1 && size_of ("new") < 0 && no_temps (), "link publication error leaves no destination");
  race_target = 1;
  CHECK (run (0, "--rm", "-o", "racer", "input", (char *) 0) == 1 && size_of ("input") > 0 && size_of ("racer") == 5 && no_temps (), "no-force publication cannot clobber a concurrent creator");
  remove_fault = 1;
  CHECK (compress () == 1 && same ("input", "original") && !same ("dest", "sentinel") && no_temps (), "failed source removal reports failure after valid publication");
  int fds = fd_count ();
  for (int i = 0; i < 100; i++)
    {
      allocation = i % 2;
      if (compress () != 1 || !no_temps ()) fails++;
      if (run (0, "-c", "input", (char *) 0) || run (0, "-dc", "good.zst", (char *) 0)) fails++;
    }
  CHECK (fd_count () == fds, "100 alternating errors/successes retain no file descriptors");
  swap_source = 1;
  CHECK (compress () == 1 && size_of ("input") == 11 && same ("saved-input", "original") && no_temps (), "changed source path is not removed after publication");
  unlink ("input"); rename ("saved-input", "input");
  /* Exercise a valid explicit library override on a fresh loader state. */
  memset (&zs, 0, sizeof zs); setenv ("BASHOS_ZSTD_LIB", "libzstd.so.1", 1);
  CHECK (run (0, "-c", "input", (char *) 0) == 0, "explicit library loads streaming symbols");
  if (zs.handle) dlclose (zs.handle);
  DIR *d = opendir ("."); struct dirent *e;
  while ((e = readdir (d))) if (e->d_name[0] != '.') unlink (e->d_name);
  closedir (d); chdir ("/"); rmdir (dir);
  printf ("sol-zstd-host: %s\n", old || fails ? "FAIL" : "all checks passed");
  return old || fails ? 1 : 0;
}
