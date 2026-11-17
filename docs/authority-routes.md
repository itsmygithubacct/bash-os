# Kernel authority routes

bash-os can hand password verification and privileged-command authorization
to three kernel modules built from `kernel/bashos-auth`. They are optional:
without them every command behaves as it did before they existed.

| Module | Device | Mode | Serves |
| --- | --- | --- | --- |
| `bashos_auth_stage1.ko` | `/dev/bashos-auth` | 0600 | sealed secret slots for `passwd` and `auth read-secret`; root only; never authorizes anything |
| `bashos_auth_v2.ko` | `/dev/bashos-auth-v2` | 0600 | identity proofs for `login`, `sshd`, `su` and `auth verify-login` |
| `bashos_privcmd_v2.ko` | `/dev/bashos-privcmd-v2` | 0666 | policy, verification, execution, `sudoedit` and audit for `doas`, `sudo` and the `auth privcmd-v2-*` verbs |

The eleven token, policy, hand-off and audit ioctls of the first protocol
(ABI 1.5) are not implemented by any module and fail with `ENOTTY`. The
two `-v2` devices replace them.

## Building and loading

```
kernel/bashos-auth/tools/build-authority.sh --kdir KDIR --out DIR
```

`KDIR` is the configured build or headers tree of the exact kernel the
modules are for. The tool compiles in a private copy, loads nothing, and
writes the three modules, the static helpers `verifier-v2` and `executor-v2`,
`bashos-policy-check` and a `receipt.json` naming every output by SHA-256.
`--qualification` adds separately named test modules (`*_test.ko`, devices
`*-test`) and the native control programs; those are for disposable guests
and are never selected by a command unless its qualification flag is given.

The `-v2` modules pin their trust inputs when they load. Build the inputs
with

```
kernel/bashos-auth/tools/bashos-auth-bundle --passwd FILE --shadow FILE \
    --group FILE --policy FILE --verifier verifier-v2 --executor executor-v2 \
    --generation N --out DIR
```

and check an existing bundle as root with `bashos-auth-bundle --check DIR`.
The tool prints the `insmod` parameters (path and SHA-256 of each file). A
bundle holds at most 32 accounts; an account whose stored hash is not an
Argon2id PHC string can be a target but can never authenticate. Changing
accounts or policy means building a new bundle with a higher generation and
reloading the module.

## How a command chooses its route

1. A versioned verb or flag (`auth *-v2*`, `login login-v2`,
   `login become --auth-v2-fd`, `--authority-v2` on `doas`, `sudo` and
   `sshd`) selects the protocol it names and nothing else.
2. Otherwise the command looks once for its device before it reads a secret
   or changes anything. If the name does not exist the command behaves as it
   always has. Anything else, including a name that is not the expected
   device, commits the command to the kernel route.
3. A committed command opens the device with full checks (root-owned
   character device, exact protocol version, non-zero trust generations).
   From then on every failure is final: a failed check, a policy or verifier
   refusal, a per-user limit, a full audit log, an interrupted password
   read. The command reports it and stops.
4. A committed command never continues on a legacy ioctl, a userspace
   password comparison, an external setuid helper or the test device.
5. No environment variable selects or disables a route.
6. `sshd` remembers that it saw the device and does not return to the old
   route if the device later disappears.

Per command:

- `doas`, `sudo`: callers other than uid 0 follow rule 2 on
  `/dev/bashos-privcmd-v2`. uid 0 needs no authorization and keeps the direct
  route unless `--authority-v2` is given. On the kernel route `-s`, `-i` and
  `-l` are refused; a command, `-e`, `-v`, `-k` and `-K` work.
- `login login`: with `/dev/bashos-auth-v2` present it is `login login-v2`.
- `login become`: with the device present `--auth-fd N` redeems the proof on
  descriptor `N`, `--auth-token` is refused, and a proof is required.
- `sshd run --encrypted`: password authentication goes through the device.
- `su`: a caller other than uid 0 must pass the kernel verifier for the
  target account. uid 0 has no password to verify and drops directly, after
  the device passes the checks of rule 3.
- `auth`: `verify-login` on an `open-v2` descriptor is a kernel
  verification; the legacy privcmd, policy and audit verbs refuse in favour
  of their `-v2` forms.

## Limits on the shared device

`/dev/bashos-privcmd-v2` is open to every user, so one user cannot take a
whole shared table. Per uid: 4 open contexts, 1 verification in progress,
48 of the 128 pending audit records, 16 timestamp scopes and 32 timestamp
entries. Passing a limit fails the request with `EDQUOT`; a full table
fails it with `ENOSPC`. The commands report both in words.

A policy denial starts neither helper. The audit log applies backpressure:
when it is full, requests that would add a record are refused until root
drains it with `auth audit-v2-drain`.

## Qualification

`tests/parity-vm/suites/qualification-authority-v2.json` runs the control
packets in `tests/authority-next` against the production modules in a root
guest that loads them itself, and again against the test modules for the
controls that need a fault knob. `tests/authority-next/stage-qualification.py`
assembles the reference directory from a `build-authority.sh --qualification`
output and refreshes the pins; `qualification-matrix.json` lists every
control each case must report. The executor case additionally needs
`vm.py --ancestor-executor-observer`.
