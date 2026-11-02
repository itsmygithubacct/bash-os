Experimental bash-os secret-slot backend, stage 1

This is newly authored code reconstructed from reviewed caller behavior. The
original kernel module was NOT recovered. It is a real bounded in-kernel secret
store, not a policy authority or an ioctl reply fixture. The qualification record is described below. Device operations were confined to disposable rental guests.

Device: /dev/bashos-auth, misc device, mode 0600.
Runtime VERSION: abi=1.0 features=0x5 (SECRETS | STATS).
The preserved transport header describes ABI 1.5, but later ioctls are absent.
MINT_TOKEN, CONSUME_TOKEN, all PRIVCMD/policy/verify/timestamp/audit/handoff calls
return ENOTTY. No read/write token stream, executor, credential transition,
account lookup, policy parser, or password verifier is implemented.

Supported behavior

* Each open file description owns one context. dup/fork share it. The final
  file release erases all slots and the context. Close of one duplicate does
  not destroy another duplicate's slots. All ioctls serialize on that context.
* NEW creates an empty writable slot. IDs never repeat within a context.
* WRITE appends, including one-byte writes made by passwd. Maximum total size
  is 4096 bytes. Failed or partial input copies commit no bytes. Zero-length
  writes succeed on writable slots without dereferencing their pointer.
* SEAL makes the slot immutable. Empty slots may be sealed. A second SEAL,
  a WRITE to a sealed/exported slot, or a comparison of an unsealed/exported
  slot fails with EPERM.
* SAME compares sealed slots inside the kernel, with length-aware binary
  equality and crypto_memneq over the full zero-padded 4096-byte buffers.
* EXPORT requires a sealed slot and adequate destination capacity. A short
  capacity returns ENOSPC without consuming it. Once a data copy is attempted,
  the slot is consumed and its entire buffer erased, including on partial
  copy failure. Failure to copy the reply cannot restore exportability.
  The erased slot remains allocated until CLEAR or final close; repeat export
  fails with EPERM. A successful empty export also consumes its slot.
* CLEAR removes and erases one slot. An absent ID returns ENOENT. Failed NEW
  reply copying rolls back and erases its allocation, with no unreachable slot.
* No secret bytes are logged or exposed in debugfs/procfs/sysfs test endpoints.

Deliberate provisional choices, not recovered historical semantics

There are 16 live slots per context and 128 contexts module-wide. Independent
opens can use numerically equal IDs; an ID only has meaning together with its
fd. Exhausting a context's 32-bit ID sequence returns EOVERFLOW permanently
until final close. A full slot table returns ENOSPC; the context cap is EMFILE.
NEW requires input id=0. All supported flags must be zero. Unknown commands,
including wrong size/direction encodings, return ENOTTY before reading payloads
for an authorized caller. Unsupported commands from other callers get EPERM.

Opening and every ioctl require effective initial-namespace UID 0 plus
CAP_SYS_ADMIN in the initial user namespace, with O_RDWR at open. This stricter
review-stage rule prevents descriptor transfer or a credential drop from
bypassing the storage access check. Release always erases regardless of the
closing process's credentials. Non-root production consumers are NOT qualified.

Counters are per-context: created increments on allocated NEW (including a
subsequent reply-copy rollback); cleared increments on actual slot destruction
(including rollback and final-close destruction). Export erasure does not count
as slot destruction. refused_exports counts errors after a complete EXPORT
request was copied, including short capacity, bad ID/state, data-copy or reply
copy errors. An unreadable request header is not counted. Token/reserved fields
remain zero. These exact counter/error/fault semantics need review against any
future recovered source. See CONTRACT.txt for evidence and open questions.

Build, without device operations

Use a prepared Linux 6.12 kernel build directory and its Module.symvers; the
kernel must have CONFIG_MODULES and CONFIG_CRYPTO_LIB_UTILS. Builds were checked for x86-64 Linux 6.12.115+deb13.1-amd64 and the exact
6.12.113+deb13-cloud-amd64 guest target. Other kernels and architectures remain
unqualified. External-module builds write to this tree only.

  make KDIR=/path/to/prepared/guest/kernel/build -j2 modules
  make userspace
  ./tests/abi_check

The last command is a pure userspace ABI check; it opens no device. The separate
device_test executable must never be run on the workstation. Rebuild the .ko
for the exact guest kernel; the local .ko is only build evidence.

Qualified kernel controls

A separate x86-64 test kernel built from Debian linux-source-6.12 6.12.113-1
ran the identical storage core with CONFIG_KUNIT, PROVE_LOCKING, KASAN_GENERIC
and KASAN_INLINE. All twelve exact tests passed with the official KUnit parser,
no KASAN/lockdep error, and normal QEMU exit. It had no root disk or network.
An earlier held-mutex test-fixture error was repaired before acceptance: no lock
spans KUnit callbacks or assertions, and erase observations are asserted after
unlocking. Production storage code did not change for that test repair.

The real module was separately rebuilt against matching
6.12.113+deb13-cloud-amd64 headers and loaded only in disposable rental guests.
Its C device control passed 392 checks: actual uaccess faults, atomic append,
export replay/faults and concurrency, fd sharing, access checks, counters and
quotas. Both unchanged 0.1.3 release binaries passed the three new real-backend
client contracts: auth PTY compare/clear/close, passwd set-fd and verify-fd with
BASHPASSWD_REQUIRE_KERNEL_SECRETS=1. All other historical FAILs remain.

This qualifies the documented stage-1 behavior in these guests. It does not
recover the historical module, qualify non-root deployment, or establish token,
verifier, policy, audit, handoff, timestamp or sudoedit authority. Those ioctls
remain unavailable. Four historical secret-storage topics close only when the
separate source-bound kernel receipt and executed client fixtures both validate.
The receipt is supporting evidence, not an extra candidate behavior case.

Reproduce the KUnit build on a build host

Use a NEW extracted Debian 6.12.113 source tree outside any checkout. Do not
modify a shared kernel tree. Set task-specific paths:

  STAGE1=/absolute/path/to/kernel/bashos-auth
  LINUX_PRIVATE=/absolute/path/to/new/linux-source-6.12
  BUILD=/absolute/path/to/new/kunit-build
  DEST="$LINUX_PRIVATE/lib/kunit/bashos_auth_stage1"
  mkdir -p "$DEST/tests" "$DEST/uapi/linux"
  cp "$STAGE1/secrets.c" "$STAGE1/secrets.h" "$DEST/"
  cp "$STAGE1/tests/kunit.c" "$STAGE1/tests/core_under_test.c" "$DEST/tests/"
  cp "$STAGE1/uapi/linux/bashos_auth.h" "$DEST/uapi/linux/"
  cp "$STAGE1/tests/Kconfig" "$DEST/Kconfig"
  cp "$STAGE1/tests/Makefile.kunit" "$DEST/Makefile"
  printf '\nsource "lib/kunit/bashos_auth_stage1/Kconfig"\n' >> "$LINUX_PRIVATE/lib/kunit/Kconfig"
  printf '\nobj-$(CONFIG_BASHOS_AUTH_STAGE1_KUNIT_TEST) += bashos_auth_stage1/\n' >> "$LINUX_PRIVATE/lib/kunit/Makefile"
  cd "$LINUX_PRIVATE"
  python3 tools/testing/kunit/kunit.py build --arch=x86_64 \
    --kunitconfig="$STAGE1/tests/kunit.config" --build_dir="$BUILD" --jobs=2

The build host needs the usual kernel build tools, including libelf-dev. The
hidden CRYPTO_LIB_UTILS dependency is selected by the adapter Kconfig. The
separate external-module KUnit target in the main Makefile is also available
for a prepared CONFIG_KUNIT kernel; the recorded run used the built-in target.
The test module compiles secrets.c with a pre-free observer. It checks staging,
export, slot and context bytes after explicit erase and before free; it never
reads freed memory or registers a test-only secret export interface.

Only on the authorized disposable rental, boot the chosen bzImage in a bounded
QEMU scope, with no disks/NICs and serial capture. The recorded run used KVM,
1 GiB RAM, two vCPUs, CPUQuota=150%, MemoryMax=3G and TasksMax=256:

  qemu-system-x86_64 -no-user-config -machine q35,accel=kvm -cpu host \
    -m 1024 -smp 2 -nodefaults -nic none -display none -monitor none \
    -serial stdio -no-reboot -kernel /absolute/path/to/bzImage \
    -append 'console=ttyS0 kunit.enable=1 kunit.filter_glob=bashos-auth-stage1-secrets kunit_shutdown=reboot'

Bound execution and require normal QEMU exit, all twelve exact KTAP cases,
zero fail/skip counts, no kernel diagnostic errors, and parser success. Use
kunit_shutdown=reboot together with -no-reboot; the minimal kernel does not
provide the ACPI poweroff path. Retain the full serial log, config, kernel image,
source/package hashes, commands and parser output. A successful boot is not a
KUnit pass. See tests/parity-vm/kernel_secret_control.py for acceptance checks.

Real-device/client reproduction

Rebuild the device module for the exact sealed guest kernel, not the KUnit
kernel. Run tests/device_test --disposable-guest only inside that disposable
root guest with the module loaded. The 128-context quota control requires
RLIMIT_NOFILE >=256. It changes credentials only in a forked owned child.
The qualified fixture restores the descriptor limit and unloads the module.

The ordinary VM fixtures pin the stripped module, device control and official
Debian libargon2 oracle by SHA-256. Supply these retained artifacts through
vm.py run --references DIR and --allow-root-fixtures on the rental. The input
names are auth-stage1.ko, auth-stage1-device-test and libargon2.so.1. Hashes are
in helpers/auth-stage1-fixture.py. A locally rebuilt artifact with different
bytes needs a reviewed new pin; it cannot reuse the recorded qualification.
The independent libargon2 oracle accepts binary salts and checks the project's
hex-field transport. It does not erase existing standard-PHC failures.

Memory limits and limits of assurance

Live logical secret storage is bounded by 128 * 16 * 4096 = 8 MiB, plus slot,
context and allocator overhead; each active context can have one <=4096-byte
staging allocation. Actual slab consumption is larger than the payload bound.
The code uses memzero_explicit plus kfree_sensitive. It does not protect against
a compromised kernel, privileged tracing, crash dumps or hardware remanence.
KCSAN, additional architectures and production deployment remain unqualified.

Transport provenance

The complete transport header mirrors loadables/common/_bashos_auth_uapi.h at
bash-os commit 1f4412f245700d7ba5b8dd1bf40e7a4c86afb818. The original module
source was not recovered from the inspected project history, backups, appliance
snapshot or accessible upstream sources. The kernel implementation is newly
authored GPL-2.0-only; the mirrored UAPI and userspace tests are MIT.

https://docs.kernel.org/6.12/kbuild/modules.html
https://docs.kernel.org/6.12/dev-tools/kunit/running_tips.html
