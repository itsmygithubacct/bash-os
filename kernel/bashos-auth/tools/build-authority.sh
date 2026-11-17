#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# build-authority.sh — build the bash-os kernel authority for one kernel.
#
#   build-authority.sh --kdir KDIR --out DIR [--qualification] [--jobs N]
#
# KDIR is a configured kernel build tree or distribution headers tree for the
# exact kernel the modules will be loaded into (it must hold Module.symvers and
# include/config/kernel.release). DIR must not exist or be empty.
#
# Written into DIR:
#   bashos_auth_stage1.ko   /dev/bashos-auth        secret slots, root only
#   bashos_auth_v2.ko       /dev/bashos-auth-v2     identity proof, root only
#   bashos_privcmd_v2.ko    /dev/bashos-privcmd-v2  policy, verify, run, audit
#   verifier-v2, executor-v2    static native helpers the modules pin at load
#   bashos-policy-check     parses a policy with the module's parser (--check)
#   receipt.json, source-manifest.txt, build.log
# With --qualification also the separately named test modules
# (bashos_auth_v2_test.ko, bashos_privcmd_v2_test.ko) and the native control
# programs the guest drivers use. Those are for disposable guests only.
#
# Nothing is loaded or executed, the source tree is not written to (every
# compile happens in a private copy under DIR/.build), and no network access or
# package installation is needed: make, a C compiler with a static libc,
# binutils and coreutils are enough.
set -euo pipefail

die(){ echo "build-authority.sh: $*" >&2; exit 1; }
say(){ echo "build-authority.sh: $*"; }

KDIR=""; OUT=""; QUALIFICATION=0; JOBS=2
while [[ $# -gt 0 ]]; do case "$1" in
  --kdir) [[ $# -ge 2 ]] || die "--kdir requires a directory"; KDIR=$2; shift 2 ;;
  --out) [[ $# -ge 2 ]] || die "--out requires a directory"; OUT=$2; shift 2 ;;
  --jobs) [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || die "--jobs requires a positive number"; JOBS=$2; shift 2 ;;
  --qualification) QUALIFICATION=1; shift ;;
  --help|-h) sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown argument $1 (see --help)" ;;
esac; done
[[ -n $KDIR && -n $OUT ]] || die "--kdir and --out are required (see --help)"

HERE=$(cd "$(dirname "$0")" && pwd)
AUTH=$(cd "$HERE/.." && pwd)            # kernel/bashos-auth
REPO=$(cd "$AUTH/../.." && pwd)
CC=${CC:-cc}
STRIP=${STRIP:-strip}
MODULE_LIMIT=$((2 * 1024 * 1024))

for tool in make "$CC" "$STRIP" readelf sha256sum stat cp find sort xargs; do
  command -v "$tool" >/dev/null || die "required tool not found: $tool"
done
[[ -d $KDIR ]] || die "--kdir is not a directory: $KDIR"
KDIR=$(cd "$KDIR" && pwd)
[[ -f $KDIR/include/config/kernel.release ]] || die "KDIR is not configured: no include/config/kernel.release"
[[ -f $KDIR/Module.symvers ]] || die "KDIR has no Module.symvers"
RELEASE=$(<"$KDIR/include/config/kernel.release")
[[ $RELEASE =~ ^[A-Za-z0-9._+~-]+$ ]] || die "unexpected kernel release string"
for path in "$AUTH/device.c" "$AUTH/authority/Makefile.protocol" "$AUTH/authority/Makefile.privcmd" \
            "$REPO/loadables/common/auth-policy-model.h" "$REPO/loadables/_monocypher/monocypher.c"; do
  [[ -f $path ]] || die "source file missing: ${path#"$REPO"/}"
done

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ -z $(ls -A "$OUT") ]] || die "--out must be empty: $OUT"
[[ $OUT != *[[:space:]]* && $KDIR != *[[:space:]]* ]] || die "paths cannot contain whitespace"
case "$OUT/" in "$REPO"/kernel/*|"$REPO"/loadables/*|"$REPO"/tests/*) die "--out must be outside the source directories" ;; esac
BUILD="$OUT/.build"; LOG="$OUT/build.log"
mkdir "$BUILD"; : > "$LOG"

# --- private source copy ----------------------------------------------------
# One pristine tree; every module is then compiled in its own copy of it so no
# object is shared between modules and the checkout never sees build output.
stage_tree(){   # stage_tree DEST
  local dest=$1
  mkdir -p "$dest/kernel" "$dest/loadables"
  cp -R "$AUTH" "$dest/kernel/bashos-auth"
  find "$dest/kernel/bashos-auth" \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' \
       -o -name '.*.cmd' -o -name 'Module.symvers' -o -name 'modules.order' -o -name '.tmp_versions' \) \
       -prune -exec rm -rf {} +
  rm -f "$dest/kernel/bashos-auth/tests/abi_check" "$dest/kernel/bashos-auth/tests/device_test"
  mkdir "$dest/loadables/common" "$dest/loadables/_monocypher"
  cp "$REPO"/loadables/common/*.h "$dest/loadables/common/"
  cp "$REPO"/loadables/_monocypher/monocypher.[ch] "$dest/loadables/_monocypher/"
  if [[ $QUALIFICATION == 1 ]]; then
    mkdir -p "$dest/tests/authority-next"
    local part
    for part in policy-v2 privcmd-v2 protocol-v2; do
      mkdir "$dest/tests/authority-next/$part"
      cp "$REPO/tests/authority-next/$part"/*.c "$dest/tests/authority-next/$part/"
    done
  fi
  chmod -R u+rwX,go+rX,go-w "$dest"
}
SRC="$BUILD/source"
stage_tree "$SRC"
(cd "$SRC" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "$OUT/source-manifest.txt"

ARTIFACTS=()
run(){   # run LABEL COMMAND...
  local label=$1; shift
  { echo "== $label"; printf '+'; printf ' %q' "$@"; echo; } >> "$LOG"
  "$@" >> "$LOG" 2>&1 || die "$label failed; see $LOG"
}

# --- kernel modules -----------------------------------------------------------
install_module(){   # install_module BUILT.ko
  local built=$1 name size
  name=$(basename "$built")
  [[ -f $built ]] || die "module was not produced: $name"
  run "strip $name" "$STRIP" --strip-debug -o "$OUT/$name" "$built"
  size=$(stat -c %s "$OUT/$name")
  (( size < MODULE_LIMIT )) || die "$name is $size bytes; the limit is $MODULE_LIMIT"
  ARTIFACTS+=("$name")
}

build_stage1(){
  local tree="$BUILD/stage1"
  cp -R "$SRC" "$tree"
  run "bashos_auth_stage1" make -C "$KDIR" M="$tree/kernel/bashos-auth" -j"$JOBS" modules
  install_module "$tree/kernel/bashos-auth/bashos_auth_stage1.ko"
}

build_v2_module(){   # build_v2_module MODULE KBUILD-FILE
  local module=$1 kbuild=$2 tree="$BUILD/$1"
  cp -R "$SRC" "$tree"
  cp "$tree/kernel/bashos-auth/authority/$kbuild" "$tree/kernel/bashos-auth/authority/Makefile"
  run "$module" make -C "$KDIR" M="$tree/kernel/bashos-auth/authority" -j"$JOBS" modules
  install_module "$tree/kernel/bashos-auth/authority/$module.ko"
}

say "kernel $RELEASE"
build_stage1
build_v2_module bashos_auth_v2 Makefile.protocol
build_v2_module bashos_privcmd_v2 Makefile.privcmd
if [[ $QUALIFICATION == 1 ]]; then
  build_v2_module bashos_auth_v2_test Makefile.protocol-test
  build_v2_module bashos_privcmd_v2_test Makefile.privcmd-test
fi

# --- native programs ----------------------------------------------------------
NATIVE_FLAGS=(-std=c11 -O2 -Wall -Wextra -Werror -static -no-pie)
native(){   # native NAME [-DFLAG...] SOURCE...
  local name=$1 headers; shift
  run "$name" "$CC" "${NATIVE_FLAGS[@]}" "$@" -o "$OUT/$name"
  headers=$(LC_ALL=C readelf -hl "$OUT/$name" 2>/dev/null) || die "$name is not an ELF image"
  grep -Eq '^[[:space:]]*Type:[[:space:]]+EXEC' <<< "$headers" || die "$name is not a fixed-address executable"
  if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<< "$headers"; then
    die "$name has a dynamic interpreter or dependencies"
  fi
  ARTIFACTS+=("$name")
}
V2="$SRC/kernel/bashos-auth/authority/v2"
native verifier-v2 "$V2/verifier.c" "$SRC/loadables/_monocypher/monocypher.c"
native executor-v2 "$V2/executor.c"
native bashos-policy-check "$SRC/kernel/bashos-auth/tools/policy-check.c"

# Replace exactly one occurrence of OLD in the executor source, for the two
# deliberately broken executors the observer controls must reject.
mutate(){   # mutate FILE OLD NEW
  local file=$1 old=$2 new=$3 text
  [[ $(grep -cF -- "$old" "$file") == 1 ]] || die "executor control mutation no longer matches: $old"
  text=$(<"$file")
  printf '%s\n' "${text/"$old"/"$new"}" > "$file"
}

if [[ $QUALIFICATION == 1 ]]; then
  T="$SRC/tests/authority-next"
  native device-boundary "$SRC/kernel/bashos-auth/authority/tests/device_boundary.c"
  native privcmd-target "$T/privcmd-v2/target.c"
  native safeedit-editor "$T/privcmd-v2/safeedit-editor.c"
  native policy-model-controls "$T/policy-v2/model-controls.c"
  native consumer-target "$T/protocol-v2/consumer-target.c"
  native login-state-negative "$T/protocol-v2/login-state-negative.c"
  for mode in $(seq 1 15); do
    native "fault-verifier-$mode" "-DFAULT_MODE=$mode" "$T/protocol-v2/fault-verifier.c"
  done
  CONTROL="$BUILD/executor-controls"; mkdir "$CONTROL"
  cp "$V2/executor.c" "$CONTROL/executor-bad-continue.c"
  mutate "$CONTROL/executor-bad-continue.c" \
    'if (setgroups(r->group_count, r->groups)) child_fail(errors, BA_V2_EXEC_STEP_GROUPS, errno);' \
    '(void)setgroups(r->group_count, r->groups); /* deliberately broken observer control */'
  cp "$V2/executor.c" "$CONTROL/executor-bad-saved.c"
  mutate "$CONTROL/executor-bad-saved.c" \
    'if (setresuid(r->uid, r->uid, r->uid)) child_fail(errors, BA_V2_EXEC_STEP_UID, errno);' \
    'if (setresuid(r->uid, r->uid, 0)) child_fail(errors, BA_V2_EXEC_STEP_UID, errno);'
  mutate "$CONTROL/executor-bad-saved.c" \
    'if (check_ids(r)) child_fail(errors, BA_V2_EXEC_STEP_IDS, errno);' \
    '(void)check_ids(r); /* deliberately ignore retained saved root ID */'
  # The mutated copies include executor-protocol.h relative to themselves.
  cp "$V2/executor-protocol.h" "$CONTROL/"
  BOOTSTRAP="$T/privcmd-v2/executor-observer-bootstrap.c"
  native executor-observed "-DBA_EXECUTOR_SOURCE=\"$V2/executor.c\"" "$BOOTSTRAP"
  native executor-bad-continue "-DBA_EXECUTOR_SOURCE=\"$CONTROL/executor-bad-continue.c\"" "$BOOTSTRAP"
  native executor-bad-saved "-DBA_EXECUTOR_SOURCE=\"$CONTROL/executor-bad-saved.c\"" "$BOOTSTRAP"
fi

# --- receipt --------------------------------------------------------------------
digest(){ sha256sum "$1" | cut -d' ' -f1; }
{
  printf '{\n  "schema": 1,\n  "kind": "bashos-authority-build",\n'
  printf '  "kernel_release": "%s",\n' "$RELEASE"
  printf '  "headers_symvers_sha256": "%s",\n' "$(digest "$KDIR/Module.symvers")"
  printf '  "source_manifest_sha256": "%s",\n' "$(digest "$OUT/source-manifest.txt")"
  printf '  "qualification": %s,\n' "$([[ $QUALIFICATION == 1 ]] && echo true || echo false)"
  printf '  "behavior_executed": false,\n  "files": {\n'
  separator=""
  while IFS= read -r name; do
    printf '%s    "%s": {"sha256": "%s", "bytes": %s}' "$separator" "$name" \
      "$(digest "$OUT/$name")" "$(stat -c %s "$OUT/$name")"
    separator=$',\n'
  done < <(printf '%s\n' "${ARTIFACTS[@]}" | LC_ALL=C sort)
  printf '\n  }\n}\n'
} > "$OUT/receipt.json"

rm -rf "$BUILD"
say "wrote ${#ARTIFACTS[@]} artifacts and receipt.json to $OUT"
