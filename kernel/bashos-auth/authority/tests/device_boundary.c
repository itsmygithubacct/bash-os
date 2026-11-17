/* SPDX-License-Identifier: MIT */
/* Guest-only negative availability control, not authentication qualification.
 *
 *   device_boundary --disposable-guest [--production-v2]
 *
 * Always: /dev/bashos-auth is the stage-1 secret store and every one of the
 * eleven legacy ABI-1.5 token, PRIVCMD, policy, verify and audit ioctls fails
 * with ENOTTY, leaving its argument untouched.
 * With --production-v2 (both production v2 modules loaded): the production
 * nodes exist with their modes, report no qualification flag, and refuse the
 * legacy ioctls, the stage-1 operations outside the sealed-input subset and
 * the qualification-only 0xbb ioctls. */
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
#include "../../uapi/linux/bashos_auth_v2.h"
#include "../../uapi/linux/bashos_privcmd_v2.h"
#include "../v2/test-uapi.h"

static unsigned checks, failed;
#define CHECK(x) do { checks++; if (!(x)) { \
  fprintf(stderr, "FAIL line=%u assertion=%s errno=%d\n", __LINE__, #x, errno); failed++; \
} } while (0)

struct command { const char *name; unsigned long number; size_t size; };
#define COMMAND(name, type) { #name, name, sizeof(type) }
#define BARE(name) { #name, name, 0 }

/* The eleven operations the stage-1 contract leaves unimplemented. */
static const struct command legacy[] = {
  COMMAND(BASHOS_AUTH_IOC_MINT_TOKEN, struct bashos_auth_token_req),
  COMMAND(BASHOS_AUTH_IOC_CONSUME_TOKEN, struct bashos_auth_token_req),
  COMMAND(BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, struct bashos_auth_privcmd),
  COMMAND(BASHOS_AUTH_IOC_POLICY_INFO, struct bashos_auth_policy_info),
  COMMAND(BASHOS_AUTH_IOC_EXEC_HANDOFF, struct bashos_auth_exec_handoff_req),
  COMMAND(BASHOS_AUTH_IOC_EXEC_INTERACTIVE, struct bashos_auth_exec_handoff_req),
  COMMAND(BASHOS_AUTH_IOC_EXEC_VERIFY, struct bashos_auth_exec_verify_req),
  COMMAND(BASHOS_AUTH_IOC_MINT_TIMESTAMP, struct bashos_auth_timestamp_mint_req),
  COMMAND(BASHOS_AUTH_IOC_NOTE_VERIFY_FAILURE, struct bashos_auth_verify_failure_req),
  COMMAND(BASHOS_AUTH_IOC_AUDIT_READ, struct bashos_auth_audit_read_req),
  COMMAND(BASHOS_AUTH_IOC_AUDIT_READ_TEXT, struct bashos_auth_audit_read_text_req),
};
/* Stage-1 operations that the v2 nodes do not carry over. */
static const struct command stage1_only[] = {
  COMMAND(BASHOS_AUTH_IOC_VERSION, struct bashos_auth_version),
  COMMAND(BASHOS_AUTH_IOC_EXPORT_ONCE, struct bashos_auth_secret_export),
  COMMAND(BASHOS_AUTH_IOC_SAME_SECRET, struct bashos_auth_secret_compare),
  COMMAND(BASHOS_AUTH_IOC_STATS, struct bashos_auth_stats),
};
/* Qualification-only operations of the separately named identity test node. */
static const struct command test_only[] = {
  COMMAND(BA_V2_TEST_VERSION, struct ba_v2_test_version),
  COMMAND(BA_V2_TEST_VERIFY, struct ba_v2_test_verify),
  COMMAND(BA_V2_TEST_VERIFY_LEGACY, struct ba_v2_test_verify),
  COMMAND(BA_V2_TEST_CONSUME, struct ba_v2_test_consume),
  BARE(BA_V2_TEST_RESET),
  COMMAND(BA_V2_TEST_DELEGATE_SSH, struct ba_v2_test_delegate),
};
#define COUNT(table) (sizeof(table) / sizeof((table)[0]))

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

/* Every listed command must fail with ENOTTY and leave its argument as sent. */
static void refused(int fd, const struct command *table, size_t count)
{
  unsigned char sent[1024], seen[1024];
  for (size_t i = 0; i < count; i++) {
    int rc;
    if (table[i].size > sizeof(sent)) { CHECK(!"argument larger than the control buffer"); continue; }
    memset(sent, 0x5a, sizeof(sent));
    memcpy(seen, sent, sizeof(seen));
    errno = 0;
    rc = table[i].size ? ioctl(fd, table[i].number, seen) : ioctl(fd, table[i].number);
    if (rc != -1 || errno != ENOTTY)
      fprintf(stderr, "command=%s rc=%d errno=%d\n", table[i].name, rc, errno);
    CHECK(rc == -1 && errno == ENOTTY);
    CHECK(!memcmp(seen, sent, sizeof(seen)));
  }
}

/* A root-owned character device with exactly this mode, opened without
 * following links and proven to be the inode that was inspected. */
static int open_node(const char *path, mode_t mode)
{
  struct stat before, after;
  int fd;
  if (lstat(path, &before) || !S_ISCHR(before.st_mode) || before.st_uid ||
      (before.st_mode & 07777) != mode) return -1;
  fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  if (fstat(fd, &after) || before.st_ino != after.st_ino || before.st_dev != after.st_dev ||
      before.st_rdev != after.st_rdev) { close(fd); return -1; }
  return fd;
}

static void stage1_boundary(int fd)
{
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
  refused(fd, legacy, COUNT(legacy));
  refused(fd, test_only, COUNT(test_only));
  char stream[32];
  errno = 0;
  ssize_t n = read(fd, stream, sizeof(stream));
  CHECK(n == -1 && errno == EINVAL);
}

static void identity_boundary(void)
{
  struct bashos_auth_v2_info info;
  char stream[32];
  int fd = open_node(BASHOS_AUTH_V2_DEVICE, 0600);
  CHECK(fd >= 0);
  if (fd < 0) return;
  memset(&info, 0xff, sizeof(info));
  CHECK(ioctl(fd, BASHOS_AUTH_V2_INFO, &info) == 0);
  CHECK(info.size == sizeof(info) && info.version == BASHOS_AUTH_V2_VERSION);
  CHECK(info.flags == 0); /* not the qualification endpoint */
  CHECK(info.account_generation != 0 && info.policy_generation != 0);
  refused(fd, legacy, COUNT(legacy));
  refused(fd, stage1_only, COUNT(stage1_only));
  refused(fd, test_only, COUNT(test_only));
  /* No proof was requested, so the reference stream is empty. */
  CHECK(read(fd, stream, sizeof(stream)) == 0);
  CHECK(close(fd) == 0);
}

static void privcmd_boundary(void)
{
  struct bashos_privcmd_v2_info info;
  char stream[32];
  ssize_t n;
  int fd = open_node("/dev/bashos-privcmd-v2", 0666);
  CHECK(fd >= 0);
  if (fd < 0) return;
  memset(&info, 0xff, sizeof(info));
  CHECK(ioctl(fd, BASHOS_PRIVCMD_V2_INFO, &info) == 0);
  CHECK(info.size == sizeof(info) && info.version == BASHOS_PRIVCMD_V2_VERSION && info.reserved == 0);
  CHECK(info.flags == 0); /* not the qualification endpoint */
  CHECK(info.account_generation != 0 && info.policy_generation != 0 &&
        info.group_generation != 0 && info.verifier_generation != 0);
  refused(fd, legacy, COUNT(legacy));
  refused(fd, stage1_only, COUNT(stage1_only));
  refused(fd, test_only, COUNT(test_only));
  errno = 0;
  n = read(fd, stream, sizeof(stream));
  CHECK(n == -1 && errno == EINVAL);
  CHECK(close(fd) == 0);
}

int main(int argc, char **argv)
{
  struct bashos_auth_version version = {0};
  int production = argc == 3 && !strcmp(argv[2], "--production-v2");
  if ((argc != 2 && !production) || strcmp(argv[1], "--disposable-guest") || !guest()) return 125;
  int fd = open_node("/dev/bashos-auth", 0600);
  if (fd < 0) return 125;
  if (ioctl(fd, BASHOS_AUTH_IOC_VERSION, &version) || version.abi_major != 1 ||
      version.abi_minor != 0 || version.features != (BASHOS_AUTH_FEAT_SECRETS | BASHOS_AUTH_FEAT_STATS)) {
    close(fd);
    return 125; /* Wrong prerequisite is ERROR, not a product FAIL. */
  }
  stage1_boundary(fd);
  CHECK(close(fd) == 0);
  if (production) {
    identity_boundary();
    privcmd_boundary();
  }
  printf("authority-boundary checks=%u failures=%u tokens=unavailable privcmd=unavailable "
         "legacy-ioctls=%zu production-v2=%s coverage=control-only\n",
         checks, failed, COUNT(legacy), production ? "checked" : "not-checked");
  return failed ? 1 : 0;
}
