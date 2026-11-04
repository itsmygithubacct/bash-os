#!/bin/bash
# Coordinator-only build-host recipe. Never run on the workstation.
set -euo pipefail
[[ ${CLAMP_BUILD_AUTHORIZED:-} == coordinator-build-host ]] || {
  echo 'Set CLAMP_BUILD_AUTHORIZED=coordinator-build-host only on the designated build host.' >&2
  exit 125
}
[[ $# == 6 ]] || { echo 'usage: build-uclamp-r1.sh SOURCE.deb BASE.config NEW_PRIVATE_DIR JOBS LIBELF_DEV.deb LIBELF_RUNTIME.deb' >&2; exit 125; }
source_deb=$(realpath "$1")
base_config=$(realpath "$2")
clamp_build_root=$3
jobs=$4
libelf_dev=$(realpath "$5")
libelf_runtime=$(realpath "$6")
[[ $clamp_build_root == /* && ! -e $clamp_build_root && $jobs =~ ^[1-9][0-9]*$ && $jobs -le 16 ]] || exit 125
recipe=$(cd -- "$(dirname -- "$0")" && pwd)
printf '%s  %s\n' 6ad4a0316ddefced87cef8cd9a25a268e0cdfe0a10adc5148401f49f90b336b5 "$source_deb" | sha256sum -c -
printf '%s  %s\n' 04c00b56970744a01abef55e381335af7fced55ee607893709dceb74f7233f70 "$base_config" | sha256sum -c -
printf '%s  %s\n' 7a67f944281523d6e3c55c1797449bab223b08665cc6ad8b51293056b65d9bd6 "$libelf_dev" | sha256sum -c -
printf '%s  %s\n' 94497b7e17b6f574a0605b380d454e20d3f01a9c63b70c2a2263f679d30053e1 "$libelf_runtime" | sha256sum -c -
mkdir -m 700 -- "$clamp_build_root"
exec > >(tee "$clamp_build_root/build.log") 2>&1
mkdir "$clamp_build_root/package" "$clamp_build_root/source" "$clamp_build_root/build" "$clamp_build_root/stage" "$clamp_build_root/dependencies"
cp -- "$base_config" "$clamp_build_root/base.config"
cp -- "$recipe/uclamp-r1.config" "$clamp_build_root/fragment.config"
dpkg-deb -x "$source_deb" "$clamp_build_root/package"
dpkg-deb -x "$libelf_dev" "$clamp_build_root/dependencies"
dpkg-deb -x "$libelf_runtime" "$clamp_build_root/dependencies"
tar --no-same-owner -xf "$clamp_build_root/package/usr/src/linux-source-6.12.tar.xz" -C "$clamp_build_root/source"
src=$clamp_build_root/source/linux-source-6.12
obj=$clamp_build_root/build
stage=$clamp_build_root/stage
deps=$clamp_build_root/dependencies
make_options=(-C "$src" O="$obj" ARCH=x86_64
  "HOSTCFLAGS=-I$deps/usr/include" "HOSTLDFLAGS=-L$deps/usr/lib/x86_64-linux-gnu"
  "LIBELF_FLAGS=-I$deps/usr/include" "LIBELF_LIBS=-L$deps/usr/lib/x86_64-linux-gnu -lelf")
export LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KBUILD_BUILD_USER=builder KBUILD_BUILD_HOST=build
export KBUILD_BUILD_TIMESTAMP='2026-11-02 00:00:00 +0000' KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH=1793577600
export LC_ALL=C
unset LOCALVERSION KCONFIG_ALLCONFIG KCONFIG_CONFIG
bash "$src/scripts/kconfig/merge_config.sh" -m -O "$obj" "$clamp_build_root/base.config" "$clamp_build_root/fragment.config"
make "${make_options[@]}" olddefconfig
python3 "$recipe/verify-uclamp-config-r1.py" "$clamp_build_root/base.config" "$obj/.config" "$clamp_build_root/fragment.config" > "$clamp_build_root/config-check.json"
release=$(make -s "${make_options[@]}" kernelrelease)
[[ $release == 6.12.113-clamp-parity-r1 ]] || exit 125
{ gcc --version; ld --version; make --version; pahole --version; } > "$clamp_build_root/toolchain.txt"
timeout --signal=TERM --kill-after=60 10800 make "${make_options[@]}" -j"$jobs" bzImage modules
make "${make_options[@]}" INSTALL_MOD_PATH="$stage" INSTALL_MOD_STRIP=1 modules_install
# Remove build-host source pointers from the transport tree; private keys stay in obj.
rm -- "$stage/lib/modules/$release/build"
if [[ -L $stage/lib/modules/$release/source ]]; then rm -- "$stage/lib/modules/$release/source"; fi
mkdir "$stage/boot"
cp "$obj/arch/x86/boot/bzImage" "$stage/boot/vmlinuz-$release"
cp "$obj/System.map" "$stage/boot/System.map-$release"
cp "$obj/.config" "$stage/boot/config-$release"
python3 "$recipe/verify-uclamp-config-r1.py" "$clamp_build_root/base.config" "$obj/.config" "$clamp_build_root/fragment.config"
python3 - "$stage" "$clamp_build_root" <<'PY'
import hashlib,json,sys
from pathlib import Path
stage,root=map(Path,sys.argv[1:])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files={str(p.relative_to(stage)):sha(p) for p in sorted(stage.rglob('*')) if p.is_file() and not p.is_symlink()}
manifest={'schema':1,'profile':'uclamp-r1','kernel_release':'6.12.113-clamp-parity-r1','source_deb_sha256':'6ad4a0316ddefced87cef8cd9a25a268e0cdfe0a10adc5148401f49f90b336b5','baseline_config_sha256':sha(root/'base.config'),'fragment_sha256':sha(root/'fragment.config'),'config_sha256':sha(root/'build/.config'),'files':files,'qualification':'build-only; boot and independent controls pending'}
manifest['private_dependencies']={'libelf-dev_0.192-4_amd64.deb':'7a67f944281523d6e3c55c1797449bab223b08665cc6ad8b51293056b65d9bd6','libelf1t64_0.192-4_amd64.deb':'94497b7e17b6f574a0605b380d454e20d3f01a9c63b70c2a2263f679d30053e1'}
(stage/'clamp-build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
tar --sort=name --mtime=@1793577600 --owner=0 --group=0 --numeric-owner -C "$stage" -cJf "$clamp_build_root/clamp-kernel-r1.tar.xz" .
sha256sum "$clamp_build_root/clamp-kernel-r1.tar.xz" "$stage/clamp-build-manifest.json" > "$clamp_build_root/SHA256SUMS"
