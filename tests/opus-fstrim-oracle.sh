#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# fstrim against util-linux fstrim(8), both run inside a private user and
# mount namespace over the same freshly mounted tmpfs instances.
#
#   tests/opus-fstrim-oracle.sh BASH-OS-BINARY [FITRIM-PRELOAD.so]
#
# Dry-run scenarios never reach FITRIM. With the preload (built by
# tests/opus-fstrim-build.sh) the non-dry scenarios run too: the interposer
# answers every FITRIM itself and records the request, so both
# implementations' range arguments, verbose output and exit codes are
# compared without trimming anything. The targets are tmpfs, which has no
# FITRIM, and the namespace has no CAP_SYS_ADMIN over the host either.
#
# Exit 0 when every scenario matches. Exit 0 with a SKIP line when the host
# lacks util-linux fstrim or unprivileged user namespaces. Exit 1 on a difference.
set -uo pipefail
bin=$(realpath "${1:?usage: $0 BASH-OS-BINARY [PRELOAD]}")
preload=${2:+$(realpath "$2")}
if [[ -n ${OPUS_FSTRIM_REFERENCE:-} ]]; then
  ul=$(realpath "$OPUS_FSTRIM_REFERENCE")
  [[ -x $ul ]] || { echo 'FAIL: OPUS_FSTRIM_REFERENCE is not executable'; exit 1; }
else
  ul=$(PATH=/usr/sbin:/sbin:/usr/bin:/bin command -v fstrim) || { echo 'SKIP: no util-linux fstrim'; exit 0; }
fi
unshare -rm true 2>/dev/null || { echo 'SKIP: unprivileged user namespaces unavailable'; exit 0; }
"$bin" -c 'type -t fstrim' 2>/dev/null | grep -qx builtin || { echo "FAIL: $bin has no fstrim builtin"; exit 1; }
[[ -z $preload || -f $preload ]] || { echo "FAIL: missing preload $preload"; exit 1; }
normalize_old=0
ver=$("$ul" -V 2>&1 || true)
if [[ $ver =~ fstrim\ from\ util-linux\ ([0-9]+)\.([0-9]+) ]]; then
  if (( BASH_REMATCH[1] < 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] < 41) )); then
    normalize_old=1
    echo "NOTE: util-linux ${BASH_REMATCH[1]}.${BASH_REMATCH[2]} predates 2.41; normalising the usage line and the fuse.portal dry-run row"
  fi
else
  echo 'NOTE: fstrim version line not recognised; comparing the transcript unchanged'
fi

T=$(mktemp -d /tmp/opus-fstrim-oracle.XXXXXX)
trap 'rm -rf "$T"' EXIT
export T

cat > "$T/setup.sh" <<'EOF'
# Mount fresh tmpfs instances: each has its own st_dev, so it is a real
# mountpoint; the plain directories beside them are not.
B=$T/root
mkdir -p "$B" "$T/lists"
for m in m1 m2 'm 3' m4 m5 'tab	x' 'back\slash'; do mkdir -p "$B/$m"; mount -t tmpfs fixture "$B/$m"; done
mkdir -p "$B/ro"; mount -t tmpfs -o ro fixture "$B/ro"
mkdir -p "$B/un" "$B/m1/nested" "$T/lists/dir"; : > "$B/file"; : > "$B/m1/regular"
mount --bind "$B/file" "$B/file" 2>/dev/null
for i in $(seq 1 120); do mkdir -p "$B/t$i"; mount -t tmpfs fixture "$B/t$i"; done
L=$T/lists
EOF

cat > "$T/dry.sh" <<'EOF'
run() {
  printf '== %s\n' "$*"; $FSTRIM "$@" 2> "$T/stderr"; printf 'rc=%d\n' $?
  while IFS= read -r l; do printf 'stderr: %s\n' "$l"; done < "$T/stderr"
}
dry() { run -n "$@"; }
p() { printf "$@"; }
p '/dev/fx1 %s/m1 ext4 defaults 0 0\n/dev/fx2 %s/m2 ext4 defaults 0 0\n/dev/fx3 %s/un ext4 defaults 0 0\n/dev/fx4 %s/file ext4 defaults 0 0\n/dev/fx5 %s/m1/regular ext4 defaults 0 0\n/dev/fx6 %s/nonexist ext4 defaults 0 0\n/dev/fx7 %s/m1/nested ext4 defaults 0 0\n' $B $B $B $B $B $B $B > $L/basic
dry -I $L/basic; dry -v -I $L/basic; dry --listed-in=$L/basic; dry --listed-in $L/basic --verbose
p '/dev/fx1 %s/m1 ext4 defaults 0 0\n/dev/fx9 %s/m1 xfs defaults 0 0\n/dev/fx1 %s/m2 ext4 defaults 0 0\n/dev/fx7 %s/m4 ext4 defaults 0 0\n/dev/fx7 %s/m5 ext4 defaults 0 0\n/dev/fx8 %s/t1 ext4\n/dev/fx8 %s/t1 tmpfs\n/dev/fx10 %s/t2/ ext4\n/dev/fx11 %s//t2 ext4\n' $B $B $B $B $B $B $B $B $B > $L/dup
dry -I $L/dup
p '/dev/fx1 %s/m\\0403 ext4 defaults 0 0\n/dev/fx2 %s/m\\0403/ ext4 defaults 0 0\n/dev/fx3 %s//m4 ext4 defaults 0 0\n/dev/fx4 %s/m5/ ext4 defaults 0 0\n/dev/f\\134x5 %s/m2 ext4 defaults\n/dev/fx6 %s/m\\0401 ext4 defaults\n/dev/fx7 %s/tab\\011x ext4\n/dev/fx8 %s/back\\134slash ext4\n/dev/f\\0409 %s/t3 ext4\n/dev/fx10 %s/t\\064 ext4\n/dev/fx11 %s/t5\\ ext4\n/dev/fx12 %s/t\\66 ext4\n' $B $B $B $B $B $B $B $B $B $B $B $B > $L/esc
dry -I $L/esc
p '/dev/fx1 %s/m1 ext4 ro 0 0\n/dev/fx2 %s/m2 ext4 rw,X-fstrim.notrim 0 0\n/dev/fx3 %s/m4 tmpfs defaults 0 0\n/dev/fx4 %s/m5 nfs defaults 0 0\n/dev/fx6 %s/ro ext4 defaults 0 0\n/dev/fx7 %s/m\\0403 autofs defaults\n/dev/fx8 %s/t1 ext4 ro=x\n/dev/fx9 %s/t2 ext4 nosuid,ro\n/dev/fx10 %s/t3 ext4 X-fstrim.notrim=1\n/dev/fx11 %s/t4 Ext4 RO\n/dev/fx12 %s/t5 ext4 rox,X-fstrim.notrimmed\n' $B $B $B $B $B $B $B $B $B $B $B > $L/filt
dry -I $L/filt
p 'LABEL=foo %s/m1 ext4 defaults 0 0\nnone %s/m2 ext4 defaults 0 0\nrel %s/m4 ext4 defaults 0 0\n/dev/fx8 %s/m5 swap defaults 0 0\n/dev/fx9 m5 ext4 defaults\nUUID=abc %s/m\\0403 ext4\nPARTUUID=x %s/t1 ext4\n"/dev/fx3" %s/t2 ext4\n/dev/fx4 "%s/t3" ext4\n' $B $B $B $B $B $B $B $B > $L/src
dry -I $L/src
p '/dev/fx1 %s/m1 ext4 defaults 0 0\n/dev/fx2 %s/m2 xfs defaults 0 0\n/dev/fx3 %s/m4 btrfs defaults 0 0\n' $B $B $B > $L/types
for t in xfs noxfs noxfs,btrfs ext4,btrfs xfs,nobtrfs XFS nobtrfs,noext4 '' ext no xf xfs, ,xfs; do dry -t "$t" -I $L/types; done
p '# c\n\n  /dev/fx1 %s/m1 ext4\n/dev/fx2\t%s/m2\text4 defaults\n/dev/fx4 %s/m4\n%s/m5\n\t# indented comment\n/dev/fx5 %s/t1 ext4 defaults 0 0 extra fields\n' $B $B $B $B $B > $L/short
dry -I $L/short
p '36 35 98:0 / %s/m1 rw,noatime master:1 - ext4 /dev/fx1 rw,errors=continue\n37 35 98:0 / %s/m2 rw - xfs /dev/fx2 rw\n38 35 98:0 / %s/un rw - xfs /dev/fx3 rw\n39 35 98:0 / %s/m4 ro - xfs /dev/fx4 rw\n40 35 98:0 / %s/m\\0403 rw - xfs /dev/fx5 ro\n41 35 98:0 /sub %s/m5 rw shared:2 master:3 - ext4 /dev/f\\040x6 rw\n42 35 98:0 / %s/t1 rw - tmpfs /dev/fx7 rw\n43 35 98:0 / %s/t2 rw - ext4 /dev/fx8 rw,X-fstrim.notrim\n44 35 98:0 / %s/t3 rw - ext4\n45 35 98:0 / %s/t4 rw ext4 /dev/fx9 rw\n46 35 98:0 / %s/t5 rw - ext4 /dev/fx10\n' $B $B $B $B $B $B $B $B $B $B $B > $L/mi
dry -I $L/mi; dry -t xfs -I $L/mi
p '/dev/fx7 %s/un ext4 defaults\n/dev/fx7 %s/m1 ext4\n/dev/fx8 %s/ro ext4\n/dev/fx8 %s/m2 ext4\n/dev/fx9 %s/file ext4\n/dev/fx9 %s/m4 ext4\n/dev/fy %s/m5 tmpfs\n/dev/fy %s/m\\0403 ext4\n' $B $B $B $B $B $B $B $B > $L/ord
dry -I $L/ord
p '/dev/fx1 %s/m1 ext4\n' $B > $L/one; : > $L/empty; p '# only\n\n' > $L/comment; p 'garbage\n' > $L/garb
for l in $L/one $L/empty $L/comment $L/garb $L/garb:$L/one $L/comment:$L/one :$L/one $L/one: $L/dir $L/dir:$L/one /dev/null:$L/one $L/nonexist $L/nonexist:$L/one $L/empty:$L/empty "" ::: $L/one:$L/basic $L/basic:$L/one; do dry -I "$l"; done
dry -I $L/one -I $L/empty; dry -I $L/empty -I $L/one; dry -I $L/basic $B/m1; dry -a -I $L/one; dry -I $L/one -A; dry -A -I $L/one
dry -a -a; dry -a; dry -a $B/m1; dry -a -t ext4
i=0; : > $L/fstypes
for t in ext4 xfs btrfs vfat f2fs fuse fuse.portal fuse.sshfs fuse.lxcfs fuseblk overlay tmpfs ramfs none swap nfs nfs4 cifs smb3 smbfs 9p ceph afs glusterfs gfs2 ocfs2 lustre davfs autofs proc sysfs devtmpfs squashfs iso9660 zfs virtiofs vboxsf bcachefs ntfs3 ntfs exfat fuse.glusterfs fuse.curlftpfs ncpfs nfsd rootfs bdev anon_inodefs apparmorfs binder binfmt_misc bpf cgroup cgroup2 configfs cpuset debugfs devfs devpts dlmfs dmabuf drm efivarfs fuse.archivemount fuse.avfsd fuse.dumpfs fuse.encfs fuse.gvfs-fuse-daemon fuse.gvfsd-fuse fuse.rofiles-fuse fuse.vmware-vmblock fuse.xwmfs fusectl hugetlbfs ipathfs mqueue nsfs pipefs pstore resctrl rpc_pipefs securityfs selinuxfs smackfs sockfs spufs tracefs jfs reiserfs hfsplus udf nilfs2 erofs cramfs orangefs coda shiftfs fuse.s3fs; do
  i=$((i+1)); p '/dev/fz%d %s/t%d %s defaults\n' $i $B $i $t >> $L/fstypes; done
dry -I $L/fstypes
dry $B/m1; dry -v $B/m1; dry $B/un; dry "$B/m 3"; dry $B/file; dry $B/nonexist; dry $B/m1 $B/m2; dry; run; dry -- $B/m1; dry $B/m1 -v; dry -nv $B/m1; dry -vn $B/m1; dry --dry $B/m1; dry --verb $B/m1; dry --l $L/one; dry --list=$L/one; dry --off=1K $B/m1; dry --quiet $B/m1
dry -x; dry --bogus; dry -t; dry -I; dry -o; dry --types; dry --all=x; dry -o; dry -h
for v in 1 1k 1K 1KB 1kb 1KiB 1kib 1.5K 0x10 010 -1 ' 1' '1 ' 1B 1b 1iB 1E 1P 16E 17179869184G 1Z 1Y '' 1KiBx 18446744073709551615 18446744073709551616 +5 1.5 1. .5K 1.0 0.0 1.K 1.05M 1,5K 0X1fk 0.25G 1kiB 1KIB 1Ki 1mb ' -1' 1e3 08; do
  dry -o "$v" $B/m1; dry -l "$v" $B/m1; dry -m "$v" $B/m1; done
EOF

cat > "$T/live.sh" <<'EOF'
run() {
  printf '== %s\n' "$*"; $FSTRIM "$@" 2> "$T/stderr"; printf 'rc=%d\n' $?
  while IFS= read -r l; do printf 'stderr: %s\n' "$l"; done < "$T/stderr"
}
p() { printf "$@"; }
p '/dev/fx1 %s/m1 ext4\n/dev/fx2 %s/m2 ext4\n/dev/fx4 %s/m4 ext4\n/dev/fx5 %s/m5 ext4\n/dev/fx6 %s/un ext4\n' $B $B $B $B $B > $L/live
export OPUS_FSTRIM_PLAN='m1=len:1610612736;m2=len:0;m4=len:1023;m5=len:1048575;t1=len:1;t2=len:1099511627776;t3=len:18446744073709551615;t4=len:1153;t5=len:5000000000'
run -v -I $L/live; run -I $L/live
for n in 1 2 3 4 5; do run -v $B/t$n; done
run $B/m1; run -v $B/m1; run -v $B/un; run $B/un; run --quiet-unsupported $B/un; run -v "$B/m 3"
OPUS_FSTRIM_PLAN='m1=err:5;m2=len:4096;m4=err:95;m5=err:9' run -v -I $L/live
OPUS_FSTRIM_PLAN='m1=err:5;m2=len:4096;m4=err:95;m5=err:9' run -v --quiet-unsupported -I $L/live
OPUS_FSTRIM_PLAN='m1=err:5;m2=err:1;m4=err:22;m5=err:30' run -I $L/live
OPUS_FSTRIM_PLAN='m1=err:95;m2=err:25;m4=err:9;m5=err:95' run -I $L/live
OPUS_FSTRIM_PLAN='m1=err:1' run -v $B/m1
OPUS_FSTRIM_PLAN='m1=err:95' run -v $B/m1
OPUS_FSTRIM_PLAN='m1=err:95' run --quiet-unsupported $B/m1
OPUS_FSTRIM_PLAN='m1=err:9' run $B/m1
OPUS_FSTRIM_PLAN='m1=err:22' run $B/m1
for v in 0 1 4096 1M 2G 1.5K 0.5K 1KB 0x10 010 1.25M 0.001G 1.05M 0X1fk 0.25G 1E 1.999999999999999999999K 18446744073709551615; do
  run -o "$v" $B/m1; run -l "$v" $B/m1; run -m "$v" $B/m1; done
run -o 1M -l 2G -m 64k -v $B/m1
run -o 1M -l 2G -m 64k -v -I $L/live
EOF

status=0
compare() {
  local name=$1 script=$2 uenv=$3
  local u="$T/$name.util-linux" o="$T/$name.bash-os" o2="$T/$name.bash-os-repeat"
  rm -f "$T/$name".*log
  env $uenv OPUS_FSTRIM_LOG="$T/$name.ul.log" FSTRIM="$ul" unshare -rm bash -c '. "$T/setup.sh"; . "$1"' _ "$script" > "$u" 2>&1
  env $uenv OPUS_FSTRIM_LOG="$T/$name.bo.log" FSTRIM=fstrim unshare -rm "$bin" --noprofile --norc -c '
    . "$T/setup.sh"; saved=$PATH; PATH=
    before=(/proc/$$/fd/*)
    . "$1" > "$T/first" 2>&1; . "$1" > "$T/second" 2>&1
    after=(/proc/$$/fd/*)
    PATH=$saved
    cat "$T/first"; cmp -s "$T/first" "$T/second" || echo "REPEAT-DIFFERS"
    [[ ${#before[@]} == "${#after[@]}" ]] || echo "FD-LEAK ${#before[@]} -> ${#after[@]}"' _ "$script" > "$o" 2>&1
  sed -i "s#^stderr: $ul: #stderr: fstrim: #" "$u"
  if [[ $normalize_old == 1 ]]; then
    # Before 2.41 the usage names only a mount point, and the pseudo-fs list
    # omits fuse.portal, so a dry run prints one extra trimmed row.
    sed -i \
      -e 's/ fstrim \[options\] <mount point>/ fstrim [options] <-A|-a|mount point>/' \
      -e '\#/t7: 0 B (dry run) trimmed on /dev/fz7#d' \
      "$u"
  fi
  local cases; cases=$(grep -c '^== ' "$u")
  if diff -u "$u" "$o" > "$T/$name.diff"; then
    echo "PASS $name: $cases invocations identical to util-linux, repeated in-shell run identical"
  else
    echo "FAIL $name"; cat "$T/$name.diff"; status=1
  fi
  if [[ -n $uenv ]]; then
    local ulog="$T/$name.ul.log" blog="$T/$name.bo.log"
    # the bash-os side ran the script twice; compare against its first half
    local n; n=$(wc -l < "$ulog" 2>/dev/null || echo 0)
    if [[ $n -gt 0 ]] && head -n "$n" "$blog" | cmp -s - "$ulog" \
       && tail -n +"$((n+1))" "$blog" | cmp -s - "$ulog"; then
      echo "PASS $name: $n intercepted FITRIM requests identical (start, len, minlen), twice"
    else
      echo "FAIL $name: FITRIM request logs differ"; diff "$ulog" "$blog" | head -40; status=1
    fi
  fi
  cp "$u" "$o" "${OPUS_FSTRIM_EVIDENCE:-$T}/" 2>/dev/null || true
  [[ -n $uenv ]] && cp "$T/$name.ul.log" "$T/$name.bo.log" "${OPUS_FSTRIM_EVIDENCE:-$T}/" 2>/dev/null
  return 0
}

compare dry "$T/dry.sh" ""
if [[ -n $preload ]]; then
  compare live "$T/live.sh" "LD_PRELOAD=$preload"
else
  echo 'NOTE: no preload given; non-dry FITRIM scenarios not run'
fi
exit $status
