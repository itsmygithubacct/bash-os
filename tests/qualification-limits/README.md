These are separate qualification builds and guest-only observation drivers for
the proposed 0.1.4 source and interfaces. Merely preparing or compiling them does
not establish a behavioral result. New builds never qualify an unchanged release.

Build on an authorized build host. `build-stock-shell.sh` builds the pinned,
Bash 5.3.20 without injected builtins (all official patches 001–020, applied in
order and hash-checked). It rejects a stale version pin set. `build-variants.sh`
takes its configured
source tree as headers and creates a new output directory. Both require
`BASHOS_QUALIFICATION_BUILD=1`; neither runs the resulting shell or test programs.
The native target builds the four changed interface modules, the bashpoll unload
module and controls, and isolated decoder/grapheme/key-clock probes. The i686
mode requires a compatible 32-bit compiler, sysroot and Bash configuration; it
builds a separate vec module and a CPU instruction control.
Configured headers must identify Bash 5.3.20. Build manifests record the version
and patchlevel header hash; a version label alone never replaces build provenance.

Run drivers only through the authorized disposable-guest controller. They require
`BASHOS_QUALIFICATION_GUEST=1`, a UUID guest marker and QEMU identity. These local
checks supplement the controller's authorization and attestation; they are not
authorization to create a guest or access a device. Kernel observers require
guest root. Keep stdout/stderr, return status, build manifests and guest provenance.

| Driver | Scope and independent control |
| --- | --- |
| `signalfd-unload.py` | Separate loadable module; `/proc` mask/fd observations, raw kernel close control and deliberately omitted unload hook. |
| `unicode-corpus.py` | Length-aware library API; hash-pinned Unicode break markers and a deliberately truncating input adapter. |
| `unicode-interface.py` | All 766 corpus lengths and 1391 cluster slices through the new descriptor API; explicit NUL, input-bound and descriptor-ownership controls. |
| `wgetch-interface.py` | Public key registration/removal, defaults, uniqueness, validation and capacity. |
| `wgetch-cases.py` | Rebuilt reader with scripted clock; literal time/key contracts and default-table negative control. Use `wgetch-runtime` for production registration or `wgetch-extended` for the isolated table variant. |
| `vec-nosse2.py` | New i686 shell/module; exact arithmetic oracle, CPUID and actual illegal-instruction control. |
| `dmesg-record-cases.py` | Rebuilt decoder with synthetic whole-record/error returns; never evidence of a real kernel property. |
| `dmesg-interface.py` | Explicit record/flag oracle and long file stream; distinct from the live ring. |
| `dmesg-hook.py` | Proposed fixture-only no-syslog invariant, with a pinned syscall-filter negative control. |
| `tput-interface.py` | Specified terminfo bytes/files, private-PTY termios and no-tty errors against pinned ncurses; no physical claim. |
| `kmsg-abi.py` | Real kernel prerequisite measurements with at most eight writes; no candidate result. |
| `kmsg-boundary.py` | Hash-checked binaries on independently observed real records, reference utility and inclusion/exclusion controls. Default is frozen 0.1.3; `--release 0.1.4` requires explicit new hashes and covers 8191/8192/8193. |

Use each Python driver's `--help` for arguments. `prepare.py` is data-only: it
records source hashes and proves the original key table has no strict-prefix
pairs before producing an isolated table extension. It does not execute a reader.

Driver results distinguish `PASS`, `FAIL`, and prerequisite/observer `ERROR` (125).
The kernel prerequisite driver reports `OBSERVED`, which is not a product PASS.
A variant result cannot be substituted for evidence about an unchanged binary.
No physical-terminal result is claimed by any of these programs.

The four interface drivers accept `--module PATH` with the stock shell for
component qualification. Omit it for integrated binaries, and run against both
new release artifacts. All retained parity cases also need new-binary execution.
The original case definitions are left intact, including conflicting raw/notime
and fixture-hook expectations that require an explicit oracle review.

Fresh 0.1.4 shell-based drivers require Bash 5.3.20 inside the authorized guest
before proceeding. This covers the native and i686 stock loaders and both
integrated candidates. The boundary driver's explicit 0.1.3 mode retains the
immutable historical hashes. Old builds, headers and results are not fresh
0.1.4 evidence. The release controller's separately built GNU Bash reference
shell/image must also be updated before new qualification.
