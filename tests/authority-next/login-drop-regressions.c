/* SPDX-License-Identifier: MIT */
/* Guest-only injected control. The real login function and shared drop helper
 * are compiled; credential syscalls and exec/exit are replaced. No native
 * credential transition, authentication, or kernel evidence is claimed. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "../../loadables/_bashauth/cred_exec.h"
static int fault, prefix, exec_seen, returned, exit_status, groups_changed, caps_changed;
static uid_t ru, eu, su;
static gid_t rg, eg, sg;
static unsigned failures;
static jmp_buf escape;
#define CHECK(x) do { if (!(x)) { failures++; \
  fprintf(stderr, "FAIL line=%u assertion=%s\n", __LINE__, #x); } } while (0)
static int step(int number)
{
  prefix++;
  CHECK(prefix == number);
  if (fault == number) { errno = EPERM; return -1; }
  return 0;
}
static uid_t injected_geteuid(void) { return eu; }
static int injected_setgroups(size_t n, const gid_t *groups)
{
  CHECK(n == 1 && groups[0] == 3102);
  if (step(1)) return -1;
  groups_changed = 1; return 0;
}
static int injected_setresgid(gid_t a, gid_t b, gid_t c)
{
  CHECK(a == 3102 && b == a && c == a);
  if (step(2)) return -1;
  rg = a; eg = b; sg = fault == 7 ? 0 : c; return 0;
}
static int injected_setresuid(uid_t a, uid_t b, uid_t c)
{
  CHECK(a == 3101 && b == a && c == a);
  if (step(3)) return -1;
  ru = a; eu = b; su = fault == 6 ? 0 : c; return 0;
}
static int injected_getresuid(uid_t *a, uid_t *b, uid_t *c)
{
  if (step(4)) return -1;
  *a = ru; *b = eu; *c = su; return 0;
}
static int injected_getresgid(gid_t *a, gid_t *b, gid_t *c)
{
  if (step(5)) return -1;
  *a = rg; *b = eg; *c = sg; return 0;
}
#define geteuid injected_geteuid
#define setgroups injected_setgroups
#define setresgid injected_setresgid
#define setresuid injected_setresuid
#define getresuid injected_getresuid
#define getresgid injected_getresgid
#include "../../loadables/common/bashcred_privdrop.h"
#undef geteuid
#undef setgroups
#undef setresgid
#undef setresuid
#undef getresuid
#undef getresgid

typedef bc_user_info bl_user;
#define BL_POLICY_MAX_ENV 16
typedef struct {
  int present;
  size_t n_env_keep, n_env_delete;
  char env_keep[BL_POLICY_MAX_ENV][64], env_delete[BL_POLICY_MAX_ENV][64];
} bl_login_policy;
#define EXECUTION_FAILURE 1
#define EX_USAGE 2
static void builtin_error(const char *fmt, ...) { (void)fmt; }
static int bl_rebind_tty_stdio(const char *tty) { CHECK(!tty); return 0; }
#include "bl_exec_user-abi.h"
#if BL_EXEC_USER_PINNED_TTY
static int bl_rebind_pinned_tty(int fd) { (void)fd; CHECK(0); return -1; }
#endif
static int bl_policy_apply_limits(const bl_login_policy *policy) { CHECK(!policy); return 0; }
static void bl_cat_file(const char *path) { (void)path; CHECK(0); }
static void __attribute__((noreturn)) injected_exit(int status)
{
  exit_status = status;
  longjmp(escape, 1);
}
static int injected_caps_clear(const char *keep, char *err, size_t size)
{
  CHECK(fault == 8 && keep && !*keep && !prefix && !exec_seen);
  caps_changed = 1; /* A bounding-set drop succeeded before a later error. */
  snprintf(err, size, "injected partial capability clear");
  errno = EPERM;
  return -1;
}
int bashos_cred_exec_user_shell_policy(const bashos_cred_exec_user *user,
    const char *name, int keep, int login, const char *cmd, int count,
    const char **args, const bashos_cred_exec_env_policy *policy)
{
  (void)args;
  CHECK(user->uid == 3101 && !strcmp(name, "login") && !keep && login && !cmd && !count && !policy);
  exec_seen++;
  injected_exit(0); /* successful replacement is modeled, never actually exec'd */
}
#define _exit injected_exit
#define bc_caps_clear injected_caps_clear
#include "bl_exec_user.inc"
#undef bc_caps_clear
#undef _exit

int main(int argc, char **argv)
{
  if (argc != 2 || strcmp(argv[1], "--injected-regressions")) return 125;
  const bl_user user = {.name = "fixture", .uid = 3101, .gid = 3102,
                        .home = "/fixture", .shell = "/fixture-shell"};
  for (fault = 0; fault < 9; fault++) {
    prefix = exec_seen = returned = groups_changed = 0;
    caps_changed = 0;
    exit_status = -1; ru = eu = su = 0; rg = eg = sg = 0;
    if (!setjmp(escape)) {
      (void)bl_exec_user(&user, 0, 1, 0, NULL, 0, NULL, NULL, 0, 0,
                         fault == 8 ? "" : NULL, NULL
#if BL_EXEC_USER_PINNED_TTY
                         , -1
#endif
                         );
      returned = 1;
    }
    CHECK(!returned);
    CHECK(exit_status == (fault ? 126 : 0));
    CHECK(exec_seen == !fault);
    CHECK(prefix == (fault == 8 ? 0 : fault >= 1 && fault <= 5 ? fault : 5));
    CHECK(groups_changed == (fault != 1 && fault != 8));
    CHECK(caps_changed == (fault == 8));
    CHECK(ru == ((fault >= 1 && fault <= 3) || fault == 8 ? 0 : 3101) && eu == ru);
    CHECK(su == ((fault >= 1 && fault <= 3) || fault == 6 || fault == 8 ? 0 : 3101));
    CHECK(rg == (fault == 1 || fault == 2 || fault == 8 ? 0 : 3102) && eg == rg);
    CHECK(sg == (fault == 1 || fault == 2 || fault == 7 || fault == 8 ? 0 : 3102));
    printf("drop case=%d prefix=%d returned=%d exit=%d exec=%d\n",
           fault, prefix, returned, exit_status, exec_seen);
  }
  printf("login-drop-regressions cases=9 failures=%u injected=yes\n", failures);
  return failures ? 1 : 0;
}
