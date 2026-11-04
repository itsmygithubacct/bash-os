#!/bin/bash
# Coordinator-only: run inside a fresh disposable preparation guest overlay.
set -euo pipefail
[[ ${CLAMP_GUEST_PREPARATION:-} == coordinator-disposable-overlay && $EUID == 0 && $# == 1 ]] || exit 125
[[ $(</sys/class/dmi/id/sys_vendor) == QEMU ]] || exit 125
python3 - <<'PY'
import uuid
from pathlib import Path
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
PY
bundle=$(realpath "$1")
release=6.12.113-clamp-parity-r1
[[ -d $bundle/boot && -d $bundle/lib/modules/$release && ! -e /boot/vmlinuz-$release && ! -e /etc/bashos-clamp-profile.json ]] || exit 125
python3 - "$bundle" <<'PY'
import hashlib,json,sys
from pathlib import Path,PurePosixPath
root=Path(sys.argv[1]);m=json.loads((root/'clamp-build-manifest.json').read_text())
if m['kernel_release']!='6.12.113-clamp-parity-r1' or not m['files']:raise SystemExit(125)
for name,want in m['files'].items():
    rel=PurePosixPath(name)
    if rel.is_absolute() or '..' in rel.parts:raise SystemExit(125)
    p=root/name
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):raise SystemExit(125)
    if hashlib.sha256(p.read_bytes()).hexdigest()!=want:raise SystemExit(125)
PY
cp -a -- "$bundle/lib/modules/$release" /lib/modules/
for prefix in vmlinuz System.map config; do install -m 0644 "$bundle/boot/$prefix-$release" "/boot/$prefix-$release"; done
install -m 0644 "$bundle/clamp-build-manifest.json" /etc/bashos-clamp-profile.json
depmod -a "$release"
update-initramfs -c -k "$release"
update-grub
# Select this entry for every boot of the new image, leaving the old kernel available.
install -d /etc/default/grub.d
printf '%s\n' 'GRUB_DEFAULT="Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux 6.12.113-clamp-parity-r1"' > /etc/default/grub.d/99-clamp-profile.cfg
update-grub
grep -F "with Linux $release" /boot/grub/grub.cfg
sha256sum "/boot/vmlinuz-$release" "/boot/config-$release" "/boot/initrd.img-$release" /etc/bashos-clamp-profile.json
printf '%s\n' 'Installation complete. Coordinator must reboot, verify the selected kernel, run controls, and seal a NEW image/cache.'
