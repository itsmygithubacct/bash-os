# Debian parity reference image

`Dockerfile.parity` builds an independent Debian 13 reference userland for the
same functional scope as bash-os's full catalog and its optional integrations.
It supplies ordinary programs and language/library APIs for comparison. Build
from the repository root; a bash-os binary is not needed:

```sh
docker build -f Dockerfile.parity -t bash-os:parity-debian .
docker run --rm -it --user "$(id -u):$(id -g)" bash-os:parity-debian
docker run --rm bash-os:parity-debian -c 'parity-reference-inventory --check-image' > reference-inventory.json
docker run --rm bash-os:parity-debian -c 'parity-reference-inventory --format tsv' > reference-scope.tsv
docker run --rm -i --user 2000:2000 --network none bash-os:parity-debian -s < tests/parity-debian/smoke.sh
```

The default shell is stock GNU Bash, built from the source and patches pinned
in `config/versions.sh`, without injected loadables. `/bin/bash` remains Debian's
packaged shell. The default `PATH` selects the pinned shell and includes
`/usr/sbin` and `/usr/games`; `LC_ALL=C` and `TZ=UTC` make output predictable.
`C.UTF-8` and `en_US.UTF-8` are also available when a fixture needs Unicode.
The working directory `/work` is writable scratch space and `HOME=/tmp`,
including with a numeric user. Managed uv interpreter downloads are disabled
by `UV_PYTHON_DOWNLOADS=never`; controlled fixtures can override that setting.

The installed tools cover these areas:

| Scope | Debian references |
| --- | --- |
| Files, text, archives, compression | GNU coreutils/findutils/diffutils/grep/sed/gawk, util-linux, pax, GNU tar/gzip, zstd, xz, bzip2, binutils |
| Processes, devices, filesystems | procps, psmisc, sysstat, strace, kmod, e2fsprogs, dosfstools, dmsetup, ACL/xattr tools |
| Network and protocols | iproute2, net-tools, curl, OpenSSH, netcat, tcpdump, Scapy, BIND DNS tools, DHCP clients and Kea servers, chrony, WireGuard, LDAP tools, ffmpeg |
| Services and security | cron/at, runit, lighttpd, rsyslog, Exim, lpr, audit tools, PAM, Argon2, OpenSSL, capabilities/keyrings, sudo/doas, nftables/iptables, fail2ban, certbot |
| Terminal, editing and graphics | ncurses/terminfo, Expect, Screen, nano/vi, dialog/whiptail, ncdu, kitty, Chafa, Sixel, Mesa EGL/GLES, Xvfb, Pillow, pyte |
| Data and language APIs | jq, bc, SQLite, Python including TOML/Unicode/regex/NumPy/cryptography, Perl, tree-sitter CLI, highlight, pinned upstream uv |

`tests/parity-debian/references.json` maps every entry in
`config/bash-loadables.list` and `config/bash-loadables-optional.list`:

- `cli`: a counterpart executable exists; compare the common operations chosen
  by a fixture. This does not promise identical options, diagnostics or limits.
- `adapter`: a different program or API supplies the reference. The mapping
  names the tools/modules and the normalization or controlled peer required.
- `contract-only`: the project interface has no stock Debian equivalent.
  Supporting tools are installed, but an independently specified model, protocol
  peer or separately qualified backend remains necessary.

The current catalog has 286 standard and three optional entries: 179 `cli`,
98 `adapter` and 12 `contract-only` mappings. The contract cases include the
project authority ABI, package/payload policy, membership protocol, integrity
policy and shell-local queues/buffers. Presence of a supporting tool never
changes those entries into CLI parity claims. Tree-sitter fixtures must supply
independently pinned grammars and queries; candidate grammar sources are not
copied into the reference image. Physical terminals, protocol peers and device
fixtures are supplied by the test environment.

Build-time validation rejects missing, duplicate or stale catalog mappings,
undeclared packages, absent executable/API references and an unexpected Bash
or uv version. It also rejects a reference Bash containing candidate loadables.
The checked image manifest is stored at `/opt/bash-os-parity/inventory.json`;
it includes input hashes, exact installed Debian versions, executable paths,
available Python APIs and the stock Bash/uv hashes and versions. Capture it
with each parity run. An inventory `PASS` means the declared reference tools
are available; behavioral results come from the actual fixtures.

The base is a digest-pinned official Debian image. A signed Debian snapshot
pins package resolution, including security updates. Snapshot Release-file
expiry is disabled for that fixed archive; package authentication remains
enabled. HTTP bootstrap avoids depending on a CA bundle absent from the slim
base. Subsequent upstream Bash and uv downloads use HTTPS and the existing
repository SHA-256 pins. No install script is downloaded and executed.

Debian 13 does not ship `write` or `utmpdump`. The build adds those two
unmodified util-linux programs from the SHA-256-pinned upstream source archive
listed in Debian's snapshot source index (`tests/parity-debian/util-linux.json`).
Their manuals, license notices, versions and binary hashes are retained.
`write` uses the traditional UTMP interface and the `tty` group; session/PTY
records still belong to a controlled fixture. Other util-linux references come
from Debian packages.

For a deliberate refresh, change the Dockerfile's base digest and snapshot,
then rebuild and retain the new manifest. `DEBIAN_IMAGE`, `DEBIAN_SNAPSHOT` and
`BUILD_JOBS` are build arguments. The pinned uv artifacts support Debian
`amd64`, `arm64` and `riscv64`; other architectures fail explicitly.

Services are installed with automatic startup disabled. SSH host keys created
during package installation are removed; SSH fixtures generate private keys
for their own disposable environment. The image starts only Bash and mounts
no host paths by default. It contains no bash-os candidate, account secrets or
project authority module. The existing scratch `Dockerfile` remains available
for running the actual static binary.

## Paired bash-os image

`Dockerfile.parity-bash-os` builds the corresponding candidate directly from
the checked-out source. Both images use the pinned Bash 5.3.20 source for
0.1.4 development. It uses the same Debian base digest and signed package
snapshot during compilation and runtime-library preparation, then assembles a
`scratch` image with the full static binary and all optional integrations:

```sh
docker build -f Dockerfile.parity-bash-os -t bash-os:parity-bash-os .
docker run --rm bash-os:parity-bash-os /usr/share/bash-os/inventory.sh
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  bash-os:parity-bash-os /usr/share/bash-os/smoke.sh
docker run --rm bash-os:parity-bash-os -c 'type ls; printf "a\nb\n" | grep b'
docker image inspect bash-os:parity-debian bash-os:parity-bash-os --format '{{index .RepoTags 0}} {{.Size}}'
```

`BUILD_JOBS` controls compilation. Perl and Python come from the project's
`config/perl.json` and `config/python.json` pins; uv uses the same upstream
artifact as the reference image. Their versions are recorded, so a fixture can
account for differences from Debian's packaged interpreters. Python and Perl
standard-library data are kept at the prefixes embedded in the binary.
Certificates, timezone/locale/terminfo data, fonts and Mesa EGL/GLES libraries
support the corresponding loadable interfaces. Kernel devices and authority
services remain properties of the external test environment.

The default user is `2000:2000`, the working directory is writable `/work`, and
`HOME=/tmp`. `/bin/bash` and `/bin/sh` select bash-os. Its `PATH` contains only
the bash-os shell launchers; command implementations are the compiled builtins.
The build checks every selected catalog name with `type -t` and verifies that
disabling `ls` does not expose an external implementation through `PATH`.
Peer programs or fixture helpers should be supplied explicitly at known paths.
The Debian image can be run with `--user 2000:2000` for matching user IDs.

`/usr/share/bash-os/build.json` records the binary size/hash, source input
hashes, architecture, version and selected loadables. `inventory.sh` checks
the complete catalog and the optional interpreter/runtime data as a nonroot
user. `runtime-packages.tsv` identifies the Debian packages from which shared
libraries/data were staged; it is provenance for those providers, not a package
database for the scratch image. The nonroot smoke check exercises file/text
builtins, compression exchange between Perl/Python/bash-os, SQLite, certificates,
timezones and loading the graphics libraries. These checks establish
build/runtime availability.
Behavioral parity requires the actual fixtures on each image, with controlled
accounts, files, peers and runtime capabilities.

Containers share the host kernel. Tools being installed does not supply
`CONFIG_UCLAMP_TASK`, kernel audit/keyring/module support, the project authority
device, real GPU/RTC/serial hardware or the privileges needed by those tests.
Keep privileged/root qualification in the [disposable VM workflow](parity-vm.md).
Run ordinary reference comparisons as a nonroot user, with explicit fixtures,
and record the kernel and runtime capabilities separately from the image.

The catalog check and its data-only regression tests run without Docker:

```sh
python3 tests/parity-debian/inventory.py --check
python3 -m unittest discover -s tests/parity-debian -p 'test_*.py'
```

Docker's [Dockerfile-specific ignore files](https://docs.docker.com/build/building/context/#dockerignore-files)
let `Dockerfile.parity.dockerignore` include only the recipe, catalogs, pins and
reference metadata. The existing minimal-image `.dockerignore` is unchanged.
Use a current Docker builder with support for these ignore files.
