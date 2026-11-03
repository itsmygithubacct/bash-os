#!/bin/bash
# Build stock GNU Bash and fetch stock uv; no bash-os loadables are compiled.
set -euo pipefail
jobs=${1:?usage: build-reference.sh JOBS}
[[ $jobs =~ ^[1-9][0-9]*$ && $jobs -le 16 ]] || exit 2
cd /build
source config/versions.sh
mkdir source downloads
curl --fail --location --retry 3 "$BASH_URL" -o downloads/bash.tar.gz
printf '%s  %s\n' "$BASH_SRC_SHA256" downloads/bash.tar.gz | sha256sum --check -
tar --no-same-owner -xzf downloads/bash.tar.gz -C source
for pin in "${BASH_PATCHES[@]}"; do
    read -r name digest <<< "$pin"
    curl --fail --location --retry 3 "$BASH_PATCH_URL/$name" -o "downloads/$name"
    printf '%s  %s\n' "$digest" "downloads/$name" | sha256sum --check -
    patch --batch -d "source/bash-$BASH_SRC_VERSION" -p0 < "downloads/$name"
done
cd "source/bash-$BASH_SRC_VERSION"
grep -Eq "^#define[[:space:]]+PATCHLEVEL[[:space:]]+$BASH_PATCHLEVEL$" patchlevel.h
printf '%s\n' "$BASH_BUILD_NUMBER" > .build
./configure --prefix=/opt/bash-reference --without-bash-malloc --disable-nls
make -j"$jobs"
make install
cd /build
sha256sum config/versions.sh downloads/* /opt/bash-reference/bin/bash \
    > /opt/bash-reference/SHA256SUMS
case "$(dpkg --print-architecture)" in
    amd64) arch=x86_64 ;;
    arm64) arch=aarch64 ;;
    riscv64) arch=riscv64 ;;
    *) echo 'uv reference is pinned for amd64, arm64 and riscv64 only' >&2; exit 2 ;;
esac
python3 config/fetch-uv.py "$arch" --out /opt/uv-reference

# Debian 13 omits these two upstream tools. Build their unmodified source.
mapfile -t util_pin < <(python3 -c 'import json; p=json.load(open("util-linux.json")); print(p["version"]); print(p["url"]); print(p["sha256"])')
curl --fail --location --retry 3 "${util_pin[1]}" -o downloads/util-linux.tar.xz
printf '%s  %s\n' "${util_pin[2]}" downloads/util-linux.tar.xz | sha256sum --check -
tar --no-same-owner -xJf downloads/util-linux.tar.xz -C source
cd "source/util-linux-${util_pin[0]}"
./configure --prefix=/opt/util-linux-reference --disable-all-programs \
    --enable-write --enable-utmpdump --disable-asciidoc --disable-nls --without-systemd
make -j"$jobs" write utmpdump
install -Dm0755 write /opt/util-linux-reference/bin/write
install -Dm0755 utmpdump /opt/util-linux-reference/bin/utmpdump
install -Dm0644 term-utils/write.1 /opt/util-linux-reference/share/man/man1/write.1
install -Dm0644 login-utils/utmpdump.1 /opt/util-linux-reference/share/man/man1/utmpdump.1
install -Dm0644 COPYING /opt/util-linux-reference/share/doc/util-linux-reference/COPYING
install -Dm0644 term-utils/write.c /opt/util-linux-reference/share/doc/util-linux-reference/write.c
install -Dm0644 login-utils/utmpdump.c /opt/util-linux-reference/share/doc/util-linux-reference/utmpdump.c
cd /build
sha256sum util-linux.json downloads/util-linux.tar.xz /opt/util-linux-reference/bin/* \
    > /opt/util-linux-reference/SHA256SUMS
