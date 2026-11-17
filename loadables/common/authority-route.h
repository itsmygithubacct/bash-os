/* SPDX-License-Identifier: MIT */
/* Route selection shared by every authority consumer: auth, doas, sudo,
 * login, sshd and su. This comment is the single statement of the rules;
 * docs/authority-routes.md repeats them for administrators.
 *
 * Nodes
 *   identity  /dev/bashos-auth-v2     login, sshd, su, auth verify-login
 *   privcmd   /dev/bashos-privcmd-v2  doas, sudo, auth privcmd verbs
 *   secrets   /dev/bashos-auth        sealed secret slots only; root-only and
 *                                     never a route to an authorization
 *
 * Rules
 *  1. An explicit versioned verb or flag (auth *-v2*, login login-v2, login
 *     become --auth-v2-fd, doas/sudo/sshd --authority-v2*) selects the
 *     protocol it names and nothing else. Its qualification variant selects
 *     the separate -test node and nothing else.
 *  2. Without such a verb or flag a consumer probes its production node once
 *     per invocation, before it reads a secret or changes any state:
 *       ABSENT   lstat() fails with ENOENT. The consumer behaves exactly as
 *                it did before the versioned protocol existed.
 *       PRESENT  every other outcome, including a name that is not a
 *                character device and an lstat() error other than ENOENT.
 *                The consumer is committed to the versioned protocol.
 *  3. A committed consumer opens the node with the checking opener
 *     (bashos_v2_open or bpv2_open: root-owned character device that is the
 *     same inode as the name, exact protocol version, non-zero trust
 *     generations). From the probe onward every failure is final for the
 *     invocation: a failed open or check, a policy or verifier refusal, a
 *     per-user limit, a full audit log, a malformed reply, an interrupted
 *     password read. The consumer reports it and stops.
 *  4. A committed consumer never continues on a legacy device ioctl, a
 *     userspace password comparison, an external setuid helper, the
 *     qualification node, or an environment opt-out such as
 *     BASHLOGIN_REQUIRE_KERNEL_TOKEN=0.
 *  5. No environment variable selects or disables a route.
 *  6. A successful probe, open or version check is transport only. It is
 *     never authentication and never an authorization.
 *  7. A daemon latches PRESENT: once sshd has seen the node it does not
 *     return to the legacy route when the node later disappears.
 *
 * Consumers
 *   doas, sudo   Callers other than uid 0 follow rule 2 on the privcmd node.
 *                uid 0 needs no authorization and keeps the direct
 *                drop-and-exec route unless --authority-v2 is given.
 *   login login  Rule 2 on the identity node; PRESENT makes it login-v2.
 *   login become Rule 2 on the identity node; PRESENT makes --auth-fd N
 *                redeem the versioned proof on descriptor N, refuses
 *                --auth-token, and requires a proof.
 *   sshd run     Rule 2 on the identity node for --encrypted password
 *                authentication; PRESENT is --authority-v2.
 *   su           Rule 2 on the identity node. A caller other than uid 0 must
 *                pass the kernel verifier for the target account. uid 0 has
 *                no password to verify and the protocol has no
 *                assertion-only proof, so uid 0 drops directly, but only
 *                after the node passes the checking opener (rule 3).
 *   auth         Verbs name their descriptor. PRESENT makes verify-login a
 *                versioned verification on an open-v2 descriptor, and makes
 *                the legacy privcmd, policy and audit verbs refuse in favour
 *                of their -v2 forms.
 */
#ifndef BASHOS_AUTHORITY_ROUTE_H
#define BASHOS_AUTHORITY_ROUTE_H
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

/* The same names the checking openers use: BASHOS_AUTH_V2_DEVICE in
 * _bashos_auth_v2_uapi.h and the production name in privcmd-v2-client.h. */
#define BASHOS_ROUTE_IDENTITY_NODE "/dev/bashos-auth-v2"
#define BASHOS_ROUTE_PRIVCMD_NODE  "/dev/bashos-privcmd-v2"

/* Rule 2. Returns 0 for ABSENT and 1 for PRESENT; errno is preserved. */
static inline int
bashos_route_present (const char *node)
{
  struct stat ignored;
  int saved = errno, present;
  present = lstat (node, &ignored) == 0 || errno != ENOENT;
  errno = saved;
  return present;
}

/* Refusals a caller can act on get their own wording; rule 3 still applies. */
static inline const char *
bashos_route_strerror (int error)
{
  switch (error)
    {
    case EDQUOT:
      return "per-user authority limit reached; finish or cancel this user's pending requests, or have an administrator drain the audit log";
    case ENOSPC:
      return "authority audit log is full; an administrator must drain it with auth audit-v2-drain";
    default:
      return strerror (error);
    }
}
#endif
