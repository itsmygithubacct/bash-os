# SPDX-License-Identifier: MIT
# Sourced by the authority-route cases. Guest root fixture only.
#
# The production authority nodes are names in /dev. Creating a stand-in there
# would outlive the case on the shared devtmpfs, so the case replaces /dev in
# its own mount namespace with a tmpfs that carries the few real devices the
# actors need. Everything made here disappears with the namespace.
#
# A stand-in is never a working authority: it only makes the name exist, so
# each control observes what a consumer does when the name is present and the
# authority cannot answer. Working authorities are exercised by the
# qualification cases that load the real modules.

route_guard() {
  local vendor token
  [[ $EUID == 0 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || return 1
  IFS= read -r vendor </sys/class/dmi/id/sys_vendor || return 1
  IFS= read -r token </etc/bashos-parity-vm || return 1
  [[ $vendor == QEMU && $token =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
  [[ ! -e /dev/bashos-auth && ! -e /dev/bashos-auth-v2 && ! -e /dev/bashos-privcmd-v2 ]] || return 1
}

route_private_dev() {
  local real=$PWD/real-dev name
  /usr/bin/mkdir "$real" || return 1
  /usr/bin/mount --rbind /dev "$real" || return 1
  /usr/bin/mount -t tmpfs -o mode=0755,nosuid tmpfs /dev || return 1
  for name in null zero full random urandom tty ptmx; do
    /usr/bin/touch "/dev/$name" || return 1
    /usr/bin/mount --bind "$real/$name" "/dev/$name" || return 1
  done
  for name in pts shm; do
    /usr/bin/mkdir "/dev/$name" || return 1
    /usr/bin/mount --rbind "$real/$name" "/dev/$name" || return 1
  done
  /usr/bin/ln -s /proc/self/fd /dev/fd || return 1
  [[ -c /dev/null && ! -e /dev/bashos-auth-v2 && ! -e /dev/bashos-privcmd-v2 ]] || return 1
  [[ ! -e $real/bashos-auth-v2 && ! -e $real/bashos-privcmd-v2 ]]
}

route_accounts() {
  printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' \
    'alice:x:3001:3001:Alice:/tmp/parity-case/home-alice:/bin/bash' >passwd.fx || return 1
  printf '%s\n' 'root:x:0:' 'alice:x:3001:' >group.fx || return 1
  /usr/bin/chmod 644 passwd.fx group.fx || return 1
  /usr/bin/mount --bind "$PWD/passwd.fx" /etc/passwd || return 1
  /usr/bin/mount --bind "$PWD/group.fx" /etc/group || return 1
  /usr/bin/mkdir -m 755 home-alice || return 1
  /usr/bin/mkdir -m 1777 marks || return 1
  /usr/bin/chmod 711 "$PWD" || return 1
}

# route_node NAME KIND: make /dev/NAME exist as KIND, or remove it.
#   absent   no such name
#   chardev  root-owned character device that answers no authority ioctl
#   regular  root-owned regular file
#   symlink  dangling symbolic link
#   dir      directory
route_node() {
  local path=/dev/$1
  if [[ -d $path && ! -L $path ]]; then /usr/bin/rmdir "$path" || return 1
  elif [[ -e $path || -L $path ]]; then /usr/bin/rm -f "$path" || return 1; fi
  case $2 in
    absent) ;;
    chardev) /usr/bin/mknod -m 0666 "$path" c 1 3 || return 1 ;;
    regular) /usr/bin/touch "$path" && /usr/bin/chmod 0666 "$path" || return 1 ;;
    symlink) /usr/bin/ln -s /dev/no-such-authority "$path" || return 1 ;;
    dir) /usr/bin/mkdir "$path" || return 1 ;;
    *) return 1 ;;
  esac
}

# route_as_alice SCRIPT: run SCRIPT in the candidate as uid/gid 3001 with no
# supplementary groups; the uid change drops every capability.
route_as_alice() {
  /usr/bin/setpriv --reuid 3001 --regid 3001 --clear-groups \
    "$BASH" --noprofile --norc -c "$1"
}

route_mark() { [[ -e marks/$1 ]] && printf ran || printf absent; }
route_clear() { /usr/bin/rm -f marks/* ; }
