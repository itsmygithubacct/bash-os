#!/usr/bin/env bash
# tests/zstd-check.sh [BINARY] — the zstd builtin against the host's zstd(1)
# and libzstd: round trips, interoperability both ways, the file semantics of
# zstd(1), and the library-absent path. Skips without a host zstd.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
command -v zstd >/dev/null || { echo "zstd-check: SKIP (no host zstd)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
pass=0; fail=0; ok(){ echo "  PASS  $*"; pass=$((pass+1)); }; no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }          # run a builtin with an empty PATH
printf 'x' > probe; if ! B zstd -q probe 2>err; then echo "zstd-check: SKIP ($(cat err | head -1))"; exit 0; fi

echo "== round trips (byte-identical), 5 MB text, 0 bytes, NULs =="
python3 -c "import random; r=random.Random(7); open('text','w').write(''.join('line %d %s\n' % (i, ' '.join(r.choice(['alpha','beta','gamma','delta']) for _ in range(8))) for i in range(150000)))"
: > empty; head -c 4096 /dev/urandom > nul; printf '\0\0\0abc\0' >> nul
for f in text empty nul; do
  B zstd -q "$f" && B zstd -d -o "$f.back" "$f.zst" && cmp -s "$f" "$f.back" && ok "$f: zstd, zstd -d -o -> identical ($(stat -c %s $f) -> $(stat -c %s $f.zst) bytes)" || no "$f round trip"
done
echo "== interoperability with the host zstd $(zstd --version | grep -oE 'v[0-9.]+') =="
zstd -q -d -c text.zst | cmp -s - text && ok "host zstd -d reads the builtin's file" || no "host reads ours"
zstd -q -3 -c text > host.zst; B zstd -dc host.zst | cmp -s - text && ok "builtin reads the host's -3 file" || no "we read host"
B zstdcat host.zst | cmp -s - text && ok "zstdcat = zstd -dc" || no "zstdcat"
B zstd -19 -c text > l19.zst && zstd -q -d -c l19.zst | cmp -s - text && [[ $(stat -c %s l19.zst) -lt $(stat -c %s text.zst) ]] && ok "-19 is smaller than -3 and valid" || no "-19"
echo "== zstd(1) file semantics =="
printf 'keep me\n' > k; B zstd -q k; [[ -f k && -f k.zst ]] && ok "the source is kept by default" || no "keep default"
B zstd -q --rm -f k; [[ ! -f k && -f k.zst ]] && ok "--rm removes the source after success" || no "--rm"
B zstd -q -d k.zst; [[ -f k ]] && B zstd -q k 2>err; grep -q 'already exists' err && [[ "$(B zstd -q k 2>/dev/null; echo $?)" == 1 ]] && ok "no overwrite without -f: named error, exit 1" || no "overwrite refusal"
B zstd -q -f k && ok "-f overwrites" || no "-f"
touch -d '2020-02-02 02:02:02' k; B zstd -q -f k; [[ "$(stat -c %Y k.zst)" == "$(stat -c %Y k)" ]] && ok "target takes the source's mtime" || no "mtime"
chmod 640 k; B zstd -q -f k; [[ "$(stat -c %a k.zst)" == 640 ]] && ok "target takes the source's mode" || no "mode"
B zstd -c k | zstd -q -d -c | cmp -s - k && ok "-c to stdout, source untouched" || no "-c"
B zstd -o named.zst -f k && zstd -q -d -c named.zst | cmp -s - k && ok "-o names the target" || no "-o"
B zstd - < text | B zstd -d - | cmp -s - text && ok "- is stdin to stdout, both ways" || no "stdin"
printf 'a\n' > m1; printf 'b\n' > m2; B zstd -q m1 m2 && [[ -f m1.zst && -f m2.zst ]] && ok "several inputs" || no "several"
B zstd -q -o x.zst m1 m2 2>/dev/null; [[ $? == 2 ]] && ok "-o with several inputs is a usage error" || no "-o several"
echo "== errors =="
head -c 100 text.zst > trunc.zst; B zstd -d -c trunc.zst >/dev/null 2>err; [[ $? == 1 ]] && grep -qi 'truncated\|incomplete\|error' err && ok "truncated input: error, exit 1" || no "truncated: $(cat err)"
printf 'not zstd\n' > bad.zst; B zstd -d -c bad.zst >/dev/null 2>err; [[ $? == 1 ]] && ok "not a zstd file: error, exit 1" || no "bad magic"
B zstd -d -c nonexistent.zst 2>err; [[ $? == 1 ]] && grep -q 'No such file' err && ok "missing input named" || no "missing input"
B zstd -q -d text 2>err; [[ $? == 1 ]] && grep -q 'unknown suffix' err && ok "-d on a file without .zst: named error" || no "suffix"
BASHOS_ZSTD_LIB=/nonexistent/libzstd.so.1 "$BX" -c 'PATH=; zstd -c k' >/dev/null 2>err; [[ $? == 1 ]] && grep -q 'not available' err && ok "library absent: named error, exit 1, shell unaffected" || no "library absent: $(cat err)"
B zstd -25 k 2>/dev/null; [[ $? == 2 ]] && ok "-25 rejected (levels 1..19)" || no "level range"
echo; echo "zstd-check: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
