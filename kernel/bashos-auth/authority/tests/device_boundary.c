/* SPDX-License-Identifier: MIT */
/* Guest-only negative availability control, not authentication qualification. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "../../uapi/linux/bashos_auth.h"

static unsigned checks, failed;
#define CHECK(x) do { checks++; if (!(x)) { \
  fprintf(stderr, "FAIL line=%u assertion=%s errno=%d\n", __LINE__, #x, errno); failed++; \
} } while (0)

static int text(const char *path, char *out, size_t cap)
{
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  int ok = fgets(out, (int)cap, f) != NULL;
  if (fclose(f)) ok = 0;
  if (ok) out[strcspn(out, "\r\n")] = 0;
  return ok ? 0 : -1;
}

static int guest(void)
{
  char vendor[64], marker[64], dmi[64], cwd[PATH_MAX];
  struct utsname u;
  const char *expected = getenv("AUTHORITY_NEXT_GUEST_UUID");
  return getuid() == 0 && geteuid() == 0 && expected && strlen(expected) == 36 &&
    getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/tmp/parity-case") &&
    !text("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor)) && !strcmp(vendor, "QEMU") &&
    !text("/etc/bashos-parity-vm", marker, sizeof(marker)) && !strcmp(marker, expected) &&
    !text("/sys/class/dmi/id/product_uuid", dmi, sizeof(dmi)) && !strcasecmp(dmi, marker) &&
    !uname(&u) && !strcmp(u.release, "6.12.113+deb13-cloud-amd64");
}

int main(int argc, char **argv)
{
  struct bashos_auth_version version = {0};
  struct stat before, after;
  if (argc != 2 || strcmp(argv[1], "--disposable-guest") || !guest()) return 125;
  if (lstat("/dev/bashos-auth", &before) || !S_ISCHR(before.st_mode) ||
      before.st_uid || (before.st_mode & 0777) != 0600) return 125;
  int fd = open("/dev/bashos-auth", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return 125;
  if (fstat(fd, &after) || before.st_ino != after.st_ino || before.st_dev != after.st_dev ||
      ioctl(fd, BASHOS_AUTH_IOC_VERSION, &version) || version.abi_major != 1 ||
      version.abi_minor != 0 || version.features != (BASHOS_AUTH_FEAT_SECRETS | BASHOS_AUTH_FEAT_STATS)) {
    close(fd);
    return 125; /* Wrong prerequisite is ERROR, not a product FAIL. */
  }
  struct bashos_auth_handle h = {0};
  int rc = ioctl(fd, BASHOS_AUTH_IOC_NEW_SECRET, &h);
  CHECK(rc == 0 && h.id != 0);
  if (!rc) {
    char secret[] = "synthetic-storage-is-not-authentication";
    struct bashos_auth_secret_write w = {.id = h.id, .len = sizeof(secret)-1,
                                        .user_ptr = (unsigned long long)(unsigned long)secret};
    CHECK(ioctl(fd, BASHOS_AUTH_IOC_WRITE_SECRET, &w) == 0);
    CHECK(ioctl(fd, BASHOS_AUTH_IOC_SEAL_SECRET, &h) == 0);
    CHECK(ioctl(fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h) == 0);
  }
  for (unsigned purpose = 1; purpose <= 3; purpose++) {
    struct bashos_auth_token_req request = {.purpose = purpose, .expires_sec = 5, .user = "root"};
    struct bashos_auth_token_req original = request;
    errno = 0;
    rc = ioctl(fd, BASHOS_AUTH_IOC_MINT_TOKEN, &request);
    CHECK(rc == -1 && errno == ENOTTY);
    CHECK(!memcmp(&request, &original, sizeof(request)));
    memset(request.token, 0xa5, sizeof(request.token));
    request.expires_sec = 0;
    errno = 0;
    rc = ioctl(fd, BASHOS_AUTH_IOC_CONSUME_TOKEN, &request);
    CHECK(rc == -1 && errno == ENOTTY);
  }
  struct bashos_auth_privcmd command = {.size = sizeof(command), .mode = BASHOS_AUTH_PRIVCMD_MODE_EXEC};
  errno = 0;
  rc = ioctl(fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &command);
  CHECK(rc == -1 && errno == ENOTTY);
  CHECK(command.decision == 0 && command.handle_id == 0);
  char stream[32];
  errno = 0;
  ssize_t n = read(fd, stream, sizeof(stream));
  CHECK(n == -1 && errno == EINVAL);
  CHECK(close(fd) == 0);
  printf("authority-boundary checks=%u failures=%u tokens=unavailable privcmd=unavailable coverage=control-only\n", checks, failed);
  return failed ? 1 : 0;
}
