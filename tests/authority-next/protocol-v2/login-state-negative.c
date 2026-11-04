/* SPDX-License-Identifier: MIT */
/* Deliberately wrong actor for the independent guest-only storage observer.
 * It attempts exec after an actual selected storage syscall was denied. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int matching_file (const char *path, const char *expected)
{
  char text[256];
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t n = read (fd, text, sizeof text - 1);
  close (fd);
  if (n <= 0) return 0;
  text[n] = 0;
  text[strcspn (text, "\r\n")] = 0;
  return strcmp (text, expected) == 0;
}

int main (int argc, char **argv)
{
  const char *temporary = ".state-0123456789abcdef0123456789abcdef";
  char cwd[256], wanted[256];
  int directory, file, result = 0;
  if (argc != 5 || getuid () || geteuid () ||
      !getcwd (cwd, sizeof cwd) || strcmp (cwd, "/tmp/parity-case") ||
      !getenv ("HOME") || strcmp (getenv ("HOME"), "/tmp/parity-home") ||
      !matching_file ("/sys/class/dmi/id/sys_vendor", "QEMU") ||
      !matching_file ("/etc/bashos-parity-vm", argv[1]) ||
      !matching_file ("/run/bashos-parity-vm-identity", argv[1])) return 125;
  int length = snprintf (wanted, sizeof wanted, "/run/bashos-consumer-v2-%s/lock", argv[1]);
  if (length <= 0 || (size_t) length >= sizeof wanted) return 125;
  directory = open (wanted, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (directory < 0) return 125;
  file = openat (directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (file < 0) return 125;
  if (!strcmp (argv[2], "login-state-file-sync")) result = fsync (file);
  else if (!strcmp (argv[2], "login-state-rename"))
    result = renameat (directory, temporary, directory, "fail.42101");
  else if (!strcmp (argv[2], "login-state-directory-sync")) result = fsync (directory);
  else if (!strcmp (argv[2], "login-state-clear")) result = unlinkat (directory, "fail.42101", 0);
  else return 125;
  if (result != -1 || errno != EACCES) return 126;
  close (file);
  unlinkat (directory, temporary, 0);
  close (directory);
  /* Deliberately continue despite failure. The independent guard should deny
     this attempt, and the trace verdict must still reject the bad actor. */
  char *target[] = { argv[3], argv[4], NULL };
  execv (argv[3], target);
  return 1;
}
