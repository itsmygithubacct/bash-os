/* SPDX-License-Identifier: MIT */
/* sudo.c - sudo-shaped entry point for doas.c. */

#include <config.h>

#include "loadables.h"

int bashdoas_dispatch (int is_sudo, WORD_LIST *list);

int
sudo_builtin (WORD_LIST *list)
{
  return bashdoas_dispatch (1, list);
}

char *sudo_doc[] = {
  "sudo - conservative sudo front-end backed by doas policy",
  "usage: sudo [-n] [-u USER] [-g GROUP] [-s|-i] [VAR=value ...] command [args...]",
  "       sudo -l|-ll       (read-only authority policy projection)",
  "       sudo -e FILE...     (sudoedit: edit one or more files via the kernel authority)",
  "       sudo -k|-K|-v     (-k before a command discards the cached credential first)",
  "--authority-v2 selects the separately configured native protocol for every uid.",
  "--authority-v2-qualification selects its disposable guest endpoint.",
  "--authority-v2-legacy-hex explicitly selects a trusted legacy PHC record.",
  "When /dev/bashos-privcmd-v2 exists, callers other than uid 0 use the native",
  "  protocol without a flag: command, -e, -v, -k and -K are decided by that",
  "  kernel authority. Its denial, error, per-user limit or full audit log is",
  "  final and no other route is tried; -s, -i and -l are refused on that route.",
  "Options bundle as in sudo (-iu USER, -ubob); -g without -u runs as the caller.",
  "Lists caller-matching policy entries; listing is not an execution approval.",
  "Refuses sudo-only semantics such as -E, -S, -A, prompts.",
  "sudoedit (-e/--edit): the kernel safe-opens each policy-bound target, you edit",
  "  private copies AS YOURSELF, then the authority atomically copies them back",
  "  (up to 16 files; the multi-file copyback is not atomic across files).",
  "Non-root callers use v2 authority when available, otherwise external doas;",
  "  that fallback refuses what doas cannot express (-i, -e, -v, -g, VAR=value).",
  (char *) 0
};

struct builtin sudo_struct = {
  "sudo",
  sudo_builtin,
  BUILTIN_ENABLED,
  sudo_doc,
  "sudo [-n] [-u USER] [-g GROUP] command [args...]",
  0
};
