/* SPDX-License-Identifier: MIT */
/* Closed boundary for the genuine builtins. Never forwards a host mutation. */
#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>
#include <utmpx.h>
#include <sys/reboot.h>
#include "loadables.h"

static unsigned long syncs, reboots, accounts;
static int command, failure;
static char order[16];
static unsigned int used;
static void event(char c) { if (used < sizeof(order)-1) order[used++] = c; }
void sync(void) { ++syncs; event('S'); }
int reboot(int cmd) {
  ++reboots; command = cmd; event('R');
  if (failure) { errno = failure; return -1; }
  return 0;
}
void updwtmp(const char *p, const struct utmp *u) { (void)p; (void)u; ++accounts; event('W'); }
void updwtmpx(const char *p, const struct utmpx *u) { (void)p; (void)u; ++accounts; event('W'); }
struct utmp *pututline(const struct utmp *u) { ++accounts; event('W'); return (struct utmp *)u; }
struct utmpx *pututxline(const struct utmpx *u) { ++accounts; event('W'); return (struct utmpx *)u; }
int halt_fixture_builtin(WORD_LIST *list) {
  const char *op = list ? list->word->word : "";
  if (!strcmp(op, "reset")) {
    syncs = reboots = accounts = used = 0; command = failure = 0;
    memset(order, 0, sizeof order);
    return 0;
  }
  if (!strcmp(op, "errno") && list->next) {
    failure = atoi(list->next->word->word); return 0;
  }
  if (!strcmp(op, "report")) {
    const char *name = command == RB_HALT_SYSTEM ? "RB_HALT_SYSTEM" :
      command == RB_AUTOBOOT ? "RB_AUTOBOOT" :
      command == RB_POWER_OFF ? "RB_POWER_OFF" : "none";
    printf("sync=%lu reboot=%lu accounting=%lu cmd=%s order=%s\n",
           syncs, reboots, accounts, name, order);
    return 0;
  }
  if (!strcmp(op, "check") && list->next && list->next->next) {
    const char *name = list->next->word->word;
    unsigned long n = strtoul(list->next->next->word->word, 0, 10);
    int want = !strcmp(name,"halt") ? RB_HALT_SYSTEM :
      !strcmp(name,"reboot") ? RB_AUTOBOOT : RB_POWER_OFF;
    return !(syncs == 0 && reboots == n && accounts == 0 && command == want);
  }
  return 2;
}
char *halt_fixture_doc[] = {"Closed reboot/sync/accounting fixture.", 0};
struct builtin halt_fixture_struct = {
  "halt_fixture", halt_fixture_builtin, BUILTIN_ENABLED, halt_fixture_doc,
  "halt_fixture reset|errno N|report|check NAME N", 0
};
