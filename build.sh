#!/usr/bin/env bash
# build.sh — build a standalone bash-os: GNU bash with the loadables in
# config/bash-loadables.list compiled in as static builtins, indistinguishable
# from bash's own (`type ls` says "ls is a shell builtin"). No busybox, no
# coreutils, no forks for the commands it covers.
#
# The technique (originally the upstream bash-os build tree's; see
# docs/PROVENANCE.md):
#   1. copy each listed loadable into bash's builtins/, rewriting its relative
#      includes and un-static-ing NAME_builtin / NAME_doc;
#   2. add NAME.o to OFILES in builtins/Makefile.in so it lands in libbuiltins.a;
#   3. after mkbuiltins generates builtins.c / builtext.h, append extern decls
#      and splice rows into shell_builtins[]. bash 5.3 computes num_shell_builtins
#      from sizeof(), so nothing else changes.
#
# Usage:  ./build.sh [--list FILE] [--static] [--no-strip] [--clean]
#   --list FILE   loadable list to inject   (default config/bash-loadables.list)
#   --static      link the binary statically (a single self-contained file)
#   --no-strip    keep symbols in the output (default: stripped)
#   --clean       force a full rebuild
#   env:  CC=… JOBS=N CFLAGS=… LOCAL_LIBS=… CONFIGURE_EXTRA=… BASH_TARBALL=/path
#
# Outputs (each with .manifest.txt, .log and .stamp beside it):
#   out/bash                host, the default list
#   out/bash-pure           host, config/bash-loadables-pure.list
#   out/bash-static         host, --static            (tags combine: bash-pure-static)
#   out/<triple>/bash…      a cross build: CC is a cross compiler, or
#                           CONFIGURE_EXTRA carries --host=
#
# Cross-compiling:  CC=<triple>-gcc ./build.sh   — that is all. --host is added,
# and because a cross configure cannot run its test programs, the Linux answers
# it needs (job control, named pipes, /dev/fd, …) are supplied below.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
source config/versions.sh
source config/loadables.sh

LIST="config/bash-loadables.list"; STATIC=0; STRIP=1; CLEAN=0
while [[ $# -gt 0 ]]; do case "$1" in
  --list) LIST="$2"; shift 2 ;;
  --static) STATIC=1; shift ;;
  --no-strip) STRIP=0; shift ;;
  --clean) CLEAN=1; shift ;;
  *) echo "build.sh: unknown arg $1" >&2; exit 2 ;;
esac; done
die(){ echo "build.sh: $*" >&2; exit 1; }
say(){ echo "build.sh: $*"; }
[[ -f "$LIST" ]] || die "no such list: $LIST"
LIST=$(cd "$(dirname "$LIST")" && pwd)/$(basename "$LIST")     # absolute: we cd into the tree later
CC="${CC:-cc}"; JOBS="${JOBS:-$(nproc)}"
DL="$HERE/dl"; SRC="$HERE/build/bash-$BASH_SRC_VERSION"

# --- target and output naming ----------------------------------------------
TARGET=$("$CC" -dumpmachine 2>/dev/null) || die "cannot run CC=$CC"
HOSTM=$(cc -dumpmachine 2>/dev/null || echo "$TARGET")
CROSS=0; [[ "$TARGET" != "$HOSTM" || "${CONFIGURE_EXTRA:-}" == *--host=* ]] && CROSS=1
LISTTAG=$(basename "$LIST" .list); LISTTAG=${LISTTAG#bash-loadables}; LISTTAG=${LISTTAG#-}
NAME="bash${LISTTAG:+-$LISTTAG}"; [[ $STATIC == 1 ]] && NAME="$NAME-static"
OUTDIR="$HERE/out"; [[ $CROSS == 1 ]] && OUTDIR="$HERE/out/$TARGET"
OUTBIN="$OUTDIR/$NAME"; LOG="$OUTBIN.log"; STAMPFILE="$OUTBIN.stamp"; MANIFEST="$OUTBIN.manifest.txt"
STRIPTOOL=strip; [[ "$CC" == *-gcc ]] && STRIPTOOL="${CC%-gcc}-strip"

# Hardened by default; a consumer overrides CFLAGS/LDFLAGS_EXTRA wholesale.
CFLAGS="${CFLAGS:--O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2}"
LDFLAGS="-Wl,--build-id=none -Wl,-z,relro -Wl,-z,now"; [[ $STATIC == 1 ]] && LDFLAGS="-static $LDFLAGS"
# LOCAL_LIBS is bash's own hook for libraries the injected builtins pull in:
# fltexpr needs libm, so -lm by default (a consumer adds e.g. -lz).
LOCAL_LIBS="${LOCAL_LIBS:--lm}"
# A cross configure cannot run test programs; these are the Linux answers.
CROSS_CACHE=(bash_cv_getcwd_malloc=yes bash_cv_job_control_missing=present
  bash_cv_sys_named_pipes=present bash_cv_func_sigsetjmp=present bash_cv_printf_a_format=yes
  bash_cv_ulimit_maxblocks=yes bash_cv_unusable_rtsigs=no bash_cv_wcwidth_broken=no
  bash_cv_dev_fd=standard bash_cv_dev_stdin=present)
CFGX=(); if [[ $CROSS == 1 ]]; then CFGX=("${CROSS_CACHE[@]}"); [[ "${CONFIGURE_EXTRA:-}" == *--host=* ]] || CFGX+=("--host=$TARGET"); fi

# Stamp: a hash of every input, so an unchanged rebuild is a no-op.
mkdir -p "$OUTDIR" "$DL" build
STAMP=$( { echo "$BASH_SRC_SHA256 ${BASH_PATCHES[*]} $BASH_PATCHLEVEL static=$STATIC strip=$STRIP cc=$CC target=$TARGET cflags=$CFLAGS ldflags=$LDFLAGS local_libs=$LOCAL_LIBS extra=${CONFIGURE_EXTRA:-} list=$LIST";
           cat "$LIST"; find loadables -type f \( -name '*.c' -o -name '*.h' \) | LC_ALL=C sort | xargs sha256sum; } | sha256sum | cut -c1-64)
if [[ "$CLEAN" != 1 && -f "$OUTBIN" && -f "$STAMPFILE" && "$(cat "$STAMPFILE")" == "$STAMP" ]]; then
  say "up to date — $OUTBIN (pass --clean to force)"; exit 0
fi
: > "$LOG"

# --- 1. bash source and its patch set, pinned by sha256 --------------------
TARBALL="$DL/bash-$BASH_SRC_VERSION.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  if [[ -n "${BASH_TARBALL:-}" ]]; then cp "$BASH_TARBALL" "$TARBALL"
  else say "downloading $BASH_URL"; curl -fL -o "$TARBALL" "$BASH_URL"; fi
fi
echo "$BASH_SRC_SHA256  $TARBALL" | sha256sum -c - >/dev/null || die "bash tarball sha256 mismatch"
mkdir -p "$DL/patches"
for entry in "${BASH_PATCHES[@]}"; do
  pname=${entry%% *}; psha=${entry##* }; pfile="$DL/patches/$pname"
  [[ -f "$pfile" ]] || { say "downloading $pname"; curl -fL -o "$pfile" "$BASH_PATCH_URL/$pname"; }
  echo "$psha  $pfile" | sha256sum -c - >/dev/null || die "$pname sha256 mismatch"
done

# --- 2. fresh tree in a staging dir, swapped in at the end (atomic) --------
STAGE_PARENT=$(mktemp -d "$HERE/build/.stage.XXXXXX"); trap 'rm -rf "$STAGE_PARENT"' EXIT
tar xzf "$TARBALL" -C "$STAGE_PARENT"
STAGE="$STAGE_PARENT/bash-$BASH_SRC_VERSION"; [[ -d "$STAGE" ]] || die "tarball did not unpack as expected"
cd "$STAGE"
for entry in "${BASH_PATCHES[@]}"; do
  pname=${entry%% *}
  patch -p0 -s < "$DL/patches/$pname" >>"$LOG" 2>&1 || die "$pname did not apply (see $LOG)"
done
pl=$(awk '$1=="#define" && $2=="PATCHLEVEL" {print $3}' patchlevel.h)
[[ "$pl" == "$BASH_PATCHLEVEL" ]] || die "patchlevel $pl after patching, expected $BASH_PATCHLEVEL"

# --- 3. stage the loadable sources + helper headers ------------------------
say "staging loadables"
cp "$HERE/loadables"/*.c examples/loadables/
shopt -s nullglob
for h in "$HERE"/loadables/common/*.h; do cp "$h" builtins/; cp "$h" examples/loadables/; done
for d in "$HERE"/loadables/_*/; do
  base=$(basename "${d%/}")
  for f in "$d"*.h; do flat="${base}_$(basename "$f")"; cp "$f" "builtins/$flat"; cp "$f" "examples/loadables/$flat"; done
done
shopt -u nullglob
cp examples/loadables/*.h builtins/ 2>/dev/null || true

# --- 4. the injected set: into builtins/ with include fixups + un-static ----
mapfile -t NAMES < <(loadables_names "$LIST") || die "cannot parse $LIST"
(( ${#NAMES[@]} > 0 )) || die "empty list"
say "injecting ${#NAMES[@]} loadables ($NAME, $TARGET)"
for n in "${NAMES[@]}"; do
  src="examples/loadables/$n.c"; [[ -f "$src" ]] || die "no source for '$n' ($src) — neither loadables/$n.c nor a stock example"
  sed -e 's|#include "builtins.h"|#include "../builtins.h"|' \
      -e 's|#include "shell.h"|#include "../shell.h"|' \
      -e 's|#include "bashansi.h"|#include "../bashansi.h"|' \
      -e 's|#include "arrayfunc.h"|#include "../arrayfunc.h"|' \
      -e 's|#include "array.h"|#include "../array.h"|' \
      -e "s|^static \\(int ${n}_builtin\\)|\\1|" \
      -e "s|^static \\(char \\*${n}_doc\\)|\\1|" \
      "$src" > "builtins/$n.c"
  case "$n" in
    fltexpr)
      sed -i 's|^static sh_float_t nanval, infval;$|static sh_float_t nanval = NAN, infval = INFINITY;|' builtins/fltexpr.c
      grep -q 'nanval = NAN' builtins/fltexpr.c || die "fltexpr fixup did not match" ;;
    cut)
      python3 - <<'PYCUT'
from pathlib import Path
p = Path("builtins/cut.c"); t = p.read_text()
old_decl = "  field = buf = line;\n  do\n"
assert t.count(old_decl) == 1, "cut: field-split anchor not found"
t = t.replace(old_decl, "  llen = strlen (line);\t\t/* BEFORE strsep destroys the delimiters */\n  field = buf = line;\n  do\n", 1)
old_alloc = "  buf = xmalloc (strlen (line) + 1);\n"
assert t.count(old_alloc) == 1, "cut: output-buffer anchor not found"
t = t.replace(old_alloc, "  buf = xmalloc (llen + 1);\n", 1)
p.write_text(t)
PYCUT
      grep -q 'BEFORE strsep destroys' builtins/cut.c || die "cut fixup did not match" ;;
    mkdir)
      python3 - <<'PYMK'
from pathlib import Path
p = Path("builtins/mkdir.c"); t = p.read_text()
t = t.replace("  int tail;\n", "  int tail, created;\n")
t = t.replace("      if (mkdir (npath, 0) < 0)\n", "      created = 0;\n      if (mkdir (npath, 0) == 0)\n\tcreated = 1;\n      else\n")
t = t.replace("      if (chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n", "      if (created && chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n")
p.write_text(t)
PYMK
      grep -q 'created && chmod' builtins/mkdir.c || die "mkdir fixup did not match" ;;
  esac
done

# --- 5. OFILES in builtins/Makefile.in -------------------------------------
OBJS="$(printf '%s.o ' "${NAMES[@]}")" python3 - <<'PY'
import os
from pathlib import Path
p = Path("builtins/Makefile.in"); s = p.read_text()
old = "OFILES = builtins.o \\\n"
assert s.count(old) == 1, "OFILES anchor not found"
p.write_text(s.replace(old, "OFILES = builtins.o " + os.environ["OBJS"] + "\\\n", 1))
PY

# --- 6. configure ----------------------------------------------------------
say "configure"
./configure --disable-nls --without-bash-malloc ${CONFIGURE_EXTRA:-} "${CFGX[@]}" \
    CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" LOCAL_LIBS="$LOCAL_LIBS" \
    >>"$LOG" 2>&1 || { tail -30 "$LOG"; die "configure failed (see $LOG)"; }
echo "$BASH_BUILD_NUMBER" > .build      # pin the build counter

# --- 7. mkbuiltins, then splice our builtins into the generated table ------
say "mkbuiltins"
make -C builtins builtins.c >>"$LOG" 2>&1 || { tail -30 "$LOG"; die "mkbuiltins failed"; }
{
  echo "/* bash-os loadables injected */"
  for n in "${NAMES[@]}"; do echo "extern int ${n}_builtin (WORD_LIST *);"; echo "extern char * const ${n}_doc[];"; done
} >> builtins/builtext.h
ENTRIES=""
while IFS=$'\t' read -r n short; do ENTRIES+="  { \"$n\", ${n}_builtin, BUILTIN_ENABLED, ${n}_doc, \"$short\", 0 },"$'\n'; done < <(loadables_parse "$LIST")
awk -v e="$ENTRIES" '/\{ \(char \*\)0x0,/ && !d { printf "%s", e; d=1 } { print }' builtins/builtins.c > builtins/builtins.c.new
mv builtins/builtins.c.new builtins/builtins.c
grep -q "^  { \"${NAMES[0]}\", ${NAMES[0]}_builtin," builtins/builtins.c || die "shell_builtins[] splice did not stick"

# --- 8. build --------------------------------------------------------------
say "make -j$JOBS"
make -j"$JOBS" >>"$LOG" 2>&1 || { grep -nE 'error|Error' "$LOG" | tail -30; die "make failed (see $LOG)"; }
[[ -f bash ]] || die "no bash binary"

# --- 9. output + manifest --------------------------------------------------
cp bash "$OUTBIN"
if [[ $STRIP == 1 ]]; then
  if command -v "$STRIPTOOL" >/dev/null; then "$STRIPTOOL" "$OUTBIN"; else say "warning: $STRIPTOOL not found, output left unstripped"; fi
fi
{
  echo "# bash-os manifest  $(date -u +%FT%TZ)"
  echo "bash $BASH_SRC_VERSION patchlevel $BASH_PATCHLEVEL  target=$TARGET static=$STATIC stripped=$STRIP"
  echo "cc=$($CC --version | head -1)"
  echo "cflags=$CFLAGS"
  echo "list=${LIST#$HERE/}"
  echo "injected builtins (${#NAMES[@]}): ${NAMES[*]}"
  ( cd "$OUTDIR" && sha256sum "$NAME" && wc -c "$NAME" )
} | tee "$MANIFEST"
echo "$STAMP" > "$STAMPFILE"

# --- 10. swap the finished tree into place: two renames, no gap ------------
cd "$HERE"; rm -rf "$SRC.old"; [[ -d "$SRC" ]] && mv "$SRC" "$SRC.old"; mv "$STAGE" "$SRC"; rm -rf "$SRC.old"
say "done: ${OUTBIN#$HERE/}  ($(wc -c < "$OUTBIN") bytes, ${#NAMES[@]} injected builtins)"
