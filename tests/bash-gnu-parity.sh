#!/usr/bin/env bash
# Run the same bounded fixtures in GNU userland or a builtin-only bash-os.
# Usage: bash bash-gnu-parity.sh NEW-RESULT-DIR gnu|builtins [REFERENCE-DIR]
# All writes stay inside NEW-RESULT-DIR. Keep its trees for compare-parity.py.
set -uo pipefail
export LC_ALL=C LANG=C TZ=UTC TERM=xterm-256color
export BASH_ENV= ENV=
umask 022

if [[ $# -lt 2 || $# -gt 3 || ( $2 != gnu && $2 != builtins ) ]]; then
    printf 'usage: %s NEW-RESULT-DIR gnu|builtins [REFERENCE-DIR]\n' "$0" >&2
    exit 2
fi
mode=$2
reference=${3-}
shell=$BASH
if [[ $mode == builtins ]]; then
    export PATH=
else
    export PATH=/usr/bin:/bin
fi
if [[ -n $reference ]]; then
    reference=$(cd -- "$reference" && pwd -P) || exit 2
fi
mkdir -- "$1" || exit 2
output=$(cd -- "$1" && pwd -P) || exit 2
mkdir -- "$output/cases" || exit 2
printf 'bash-gnu-parity-v1\n' > "$output/suite"
printf 'mode=%s\nbash=%s\nversion=%s\nPATH=%s\n' \
    "$mode" "$shell" "$BASH_VERSION" "$PATH" > "$output/environment.txt"
for tool in ls cat cp mv rm mkdir rmdir ln readlink stat chmod touch truncate \
    grep sed awk sort uniq head tail wc cut tr tee seq expr paste join comm \
    split csplit fold expand unexpand nl pr tac od cksum basename dirname \
    find xargs env printenv date base64 sha256sum tar gzip clear; do
    printf '%s\t%s\n' "$tool" "$(type -t "$tool" || :)" >> "$output/tools.tsv"
done
: > "$output/catalog.tsv"
total=0
failed=0

run_case() {
    local name=$1 expected=$2 diagnostic=$3 code=$4 rc=0 valid=1
    local directory="$output/cases/$1"
    mkdir -p -- "$directory/tree" || exit 2
    printf '%s\n' "$code" > "$directory/command"
    printf '%s\t%s\t%s\n' "$name" "$expected" "$diagnostic" >> "$output/catalog.tsv"
    (
        cd -- "$directory/tree" || exit 125
        "$shell" --noprofile --norc -c \
            'set -e; set -o pipefail; umask 022; eval "$1"' parity-case "$code"
    ) > "$directory/stdout" 2> "$directory/stderr" || rc=$?
    printf '%s\n' "$rc" > "$directory/status"
    [[ $rc == "$expected" ]] || valid=0
    if [[ $diagnostic == diagnostic ]]; then
        [[ -s "$directory/stderr" ]] || valid=0
    else
        [[ ! -s "$directory/stderr" ]] || valid=0
    fi
    total=$((total + 1))
    if [[ -n $reference ]]; then
        cmp -s "$directory/stdout" "$reference/cases/$name/stdout" || valid=0
        cmp -s "$directory/status" "$reference/cases/$name/status" || valid=0
        if [[ $diagnostic == exact ]]; then
            cmp -s "$directory/stderr" "$reference/cases/$name/stderr" || valid=0
        fi
    fi
    if [[ $valid == 1 ]]; then
        printf 'PASS %03d  %s\n' "$total" "$name"
    else
        failed=$((failed + 1))
        printf 'FAIL %03d  %s (exit %s; expected %s)\n' "$total" "$name" "$rc" "$expected"
    fi
    if [[ ${PARITY_DELAY:-0} != 0 ]]; then sleep "$PARITY_DELAY"; fi
}

printf 'Bash/GNU parity: %s, Bash %s\n' "$mode" "$BASH_VERSION"
printf 'Each case has a private fixture directory; no system files are changed.\n\n'

run_case shell-arguments 0 exact 'set -- "a b" "" "*" "semi;colon"; printf "<%s>\n" "$@"'
run_case shell-expansion 0 exact 's=alpha_beta_beta; printf "%s\n" "${s#*_}" "${s//beta/B}" "${s:2:5}" "${unset_value:-fallback}"'
run_case shell-arithmetic 0 exact 'n=7; ((n += 5)); printf "%s %s %s\n" "$n" "$((2**10))" "$((16#ff))"'
run_case shell-indexed-array 0 exact 'a=("a b" c); a[4]=d; printf "%s\n" "${#a[@]}" "${a[@]}"'
run_case shell-associative-array 0 exact 'declare -A a=([x]=one [y]="two words"); printf "%s|%s\n" "${a[x]}" "${a[y]}"'
run_case shell-local-nameref 0 exact 'v=outer; f(){ local v=inner; printf "%s\n" "$v"; }; f; declare -n ref=v; ref=changed; printf "%s\n" "$v"'
run_case shell-regex 0 exact '[[ item-42 =~ ^([a-z]+)-([0-9]+)$ ]]; printf "%s %s\n" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"'
run_case shell-globbing 0 exact 'touch b.txt a.txt .hidden; printf "%s\n" *.txt; shopt -s nullglob; a=(missing*); printf "missing=%s\n" "${#a[@]}"'
run_case shell-brace-expansion 0 exact 'printf "%s\n" item{03..05} {left,right}{1,2}'
run_case shell-mapfile 0 exact 'mapfile -t a < <(printf "one\ntwo words\n"); printf "[%s]\n" "${a[@]}"'
run_case shell-read-nul 0 exact 'printf "a b\0c\0" > input; while IFS= read -r -d "" item; do printf "[%s]\n" "$item"; done < input'
run_case shell-process-substitution 0 exact 'diff <(printf "same\n") <(printf "same\n"); printf "equal\n"'
run_case shell-pipeline-status 0 exact 'set +e; false | true; printf "status=%s stages=%s\n" "$?" "${PIPESTATUS[*]}"'
run_case shell-errexit 7 exact '(set -e; exit 7); printf unreachable'
run_case shell-trap-exit 0 exact 'trap "printf cleanup\\n" EXIT; printf "body\n"'
run_case shell-subshell 0 exact 'v=parent; (v=child; printf "%s\n" "$v"); printf "%s\n" "$v"'
run_case shell-fd-redirection 0 exact 'exec 3> data; printf "one\n" >&3; exec 3>&-; printf "two\n" >> data; cat data'
run_case shell-read-write-fd 0 exact 'printf "abc\n" > data; exec 3<> data; IFS= read -r line <&3; printf "def\n" >&3; exec 3>&-; cat data'
run_case shell-background-wait 0 exact '(exit 6) & p=$!; set +e; wait "$p"; printf "wait=%s\n" "$?"'
run_case shell-child-executable 0 exact '"$BASH" --noprofile --norc -c "printf child-ok\\n"; /bin/sh -c "printf sh-ok\\n"'
run_case shell-script-shebang 0 exact 'printf "#!/bin/bash\nprintf script-ok\\\\n\n" > script; chmod 755 script; ./script'
run_case shell-command-substitution 0 exact 'v=$(printf "a\n\n"); printf "<%s>\n" "$v"'
run_case text-cat-binary 0 exact 'printf "a\0b\n\n" > data; cat data'
run_case text-grep-extended 0 exact 'printf "alpha\nbeta\nALPHA\n" | grep -Ein "^(alpha|beta)$"'
run_case text-grep-no-match 1 exact 'printf "alpha\n" | grep -q missing'
run_case text-grep-invalid 2 diagnostic 'printf "alpha\n" | grep "["'
run_case text-grep-nul 0 exact 'printf "a\0b\0ab\0" | grep -z "a"'
run_case text-sed-groups 0 exact 'printf "item:12\nother:3\n" | sed -E "s/^([^:]+):([0-9]+)/\2 \1/"'
run_case text-sed-in-place 0 exact 'printf "old\nkeep\n" > data; sed -i.bak "s/old/new/" data; cat data data.bak'
run_case text-awk-fields 0 exact 'printf "a,2\nb,3\na,4\n" | awk -F, "{sum+=\$2} END {printf \"sum=%d rows=%d\\n\",sum,NR}"'
run_case text-sort-numeric 0 exact 'printf "10\n-2\n3\n3\n" | sort -nu'
run_case text-sort-fields 0 exact 'printf "b 2\na 10\nc 2\n" | sort -k2,2n -k1,1'
run_case text-sort-nul 0 exact 'printf "b\0a\0b\0" | sort -zu'
run_case text-uniq-count 0 exact 'printf "a\na\nb\n" | uniq -c'
run_case text-head-tail 0 exact 'printf "one\ntwo\nthree\nfour\n" > data; head -n 2 data; tail -n +3 data'
run_case text-head-bytes 0 exact 'printf "a\0b\ncd" | head -c 4'
run_case text-tail-bytes 0 exact 'printf "a\0b\ncd" | tail -c 3'
run_case text-wc 0 exact 'printf "one two\nthree\n" | wc -l -w -c'
run_case text-cut-fields 0 exact 'printf "a::c\none:two:three\n" | cut -d: -f1,3'
run_case text-cut-complement 0 exact 'printf "abcdef\n" | cut -b2-4 --complement'
run_case text-tr 0 exact 'printf "a1  b2\n" | tr -d "[:digit:]" | tr -s " " | tr "[:lower:]" "[:upper:]"'
run_case text-tr-nul 0 exact 'printf "a\0b\0\n" | tr -d "\000"'
run_case text-tee 0 exact 'printf "one\n" | tee a b; cmp a b; cat a'
run_case text-paste 0 exact 'printf "a\nb\n" > a; printf "1\n2\n" > b; paste -d: a b'
run_case text-join 0 exact 'printf "1 alpha\n2 beta\n" > a; printf "1 A\n3 C\n" > b; join -a1 a b'
run_case text-comm 0 exact 'printf "a\nb\n" > a; printf "b\nc\n" > b; comm a b'
run_case text-split 0 exact 'printf "a\nb\nc\n" > data; split -l 2 data chunk_; cat chunk_aa chunk_ab'
run_case text-csplit 0 exact 'printf "a\nb\nc\n" > data; csplit -s data 3; cat xx00 xx01'
run_case text-fold 0 exact 'printf "abcdefghij\n" | fold -w 4'
run_case text-expand 0 exact 'printf "a\tb\n" | expand -t 4'
run_case text-unexpand 0 exact 'printf "a   b\n" | unexpand -a -t 4'
run_case text-nl 0 exact 'printf "a\n\nb\n" | nl -ba'
run_case text-pr 0 exact 'printf "a\nb\n" | pr -t -n'
run_case text-tac 0 exact 'printf "one\ntwo\n" | tac'
run_case text-seq 0 exact 'seq -w -s, 8 2 12; seq 0.5 0.5 2'
run_case text-expr 0 exact 'expr 6 \* 7 + 1'
run_case text-expr-false 1 exact 'expr 1 = 2'
run_case text-od 0 exact 'printf "a\0b\n" | od -An -tx1'
run_case text-cksum 0 exact 'printf "abc\n" | cksum'
run_case files-ls 0 exact 'mkdir folder; touch a .hidden "two words"; ls -1A --color=never'
run_case files-cp-preserve 0 exact 'printf "payload\n" > source; chmod 640 source; cp -p source copy; cmp source copy; stat -c "%a %s" copy'
run_case files-cp-tree 0 exact 'mkdir -p source/sub; printf x > source/sub/file; ln -s sub/file source/link; cp -a source copy; [[ -L copy/link ]]; cat copy/link'
run_case files-cp-no-clobber 0 exact 'printf old > destination; printf new > source; cp -n source destination; cat destination'
run_case files-mv 0 exact 'printf data > original; mv original renamed; [[ ! -e original ]]; cat renamed'
run_case files-links 0 exact 'printf data > original; ln original hard; ln -s original soft; [[ original -ef hard && -L soft ]]; readlink soft; stat -c "%h" original'
run_case files-chmod 0 exact 'touch data; chmod 600 data; chmod u+x,g+r data; stat -c "%a" data'
run_case files-touch-time 0 exact 'touch -d @1234567890 data; stat -c "%Y" data'
run_case files-truncate 0 exact 'printf abcdef > data; truncate -s 3 data; cat data; truncate -s 5 data; od -An -tx1 data'
run_case files-remove 0 exact 'mkdir -p private/sub; touch private/sub/file; rm private/sub/file; rmdir private/sub private; [[ ! -e private ]]; printf removed'
run_case files-dash-name 0 exact 'printf data > ./-n; cat -- -n; cp -- -n copy; rm -- -n; cat copy'
run_case files-basename-dirname 0 exact 'basename /a/b/file.txt .txt; dirname /a/b/file.txt'
run_case files-find 0 exact 'mkdir -p a/b; touch a/b/file a/other; find a -type f -print | sort'
run_case files-find-exec 0 exact 'mkdir a; touch a/x a/y; find a -type f -exec printf "[%s]\n" "{}" ";" | sort'
run_case files-find-nul-xargs 0 exact 'mkdir a; touch "a/two words" a/one; find a -type f -print0 | xargs -0 -n1 printf "[%s]\n" | sort'
run_case files-missing-diagnostic 1 diagnostic 'cat missing-file'
run_case files-cmp-different 1 exact 'printf a > a; printf b > b; cmp -s a b'
run_case environment-clean-child 0 exact 'env -i PARITY_VALUE="two words" printenv PARITY_VALUE'
run_case environment-date-utc 0 exact 'date -u -d @0 "+%Y-%m-%d %H:%M:%S %s"'
run_case command-base64 0 exact 'printf "hello\n" | base64'
run_case command-sha256sum 0 exact 'printf abc | sha256sum'
run_case command-tar-roundtrip 0 exact 'mkdir source restored; printf payload > source/data; tar -cf archive.tar -C source data; tar -xf archive.tar -C restored; cat restored/data; rm archive.tar'
run_case command-gzip-roundtrip 0 exact 'printf payload | gzip -c | gzip -dc'
run_case command-base64-wrap 0 exact 'printf "%090d" 0 | base64; printf "hello" | base64 -w0'
run_case command-base64-decode 0 exact 'printf "YQ==Yg==\nY2Q=" | base64 -d'
run_case command-base64-garbage 0 exact 'printf "Y Q!I=\n" | base64 -di'
run_case command-base64-invalid 1 diagnostic 'printf "YQ=" | base64 -d'
run_case command-sha256-file 0 exact 'printf "hello\0world\n" > data; sha256sum data; sha256sum -b data; sha256sum --tag data'
run_case command-sha256-check 0 exact 'printf payload > data; sha256sum data > sums; sha256sum -c sums; sha256sum -c --quiet sums'
run_case command-sha256-failed 1 exact 'printf old > data; sha256sum data > sums; printf new > data; sha256sum -c --status sums'
run_case command-gzip-files 0 exact 'printf "payload\0bytes" > data; gzip -nk data; gzip -t data.gz; rm data; gzip -d data.gz; cat data'
run_case command-gzip-members 0 exact 'printf one | gzip -nc > members.gz; printf two | gzip -nc >> members.gz; gzip -dc members.gz; rm members.gz'
run_case command-tar-list 0 exact 'printf data > data; tar -cf archive.tar data; tar -tf archive.tar; rm archive.tar'
run_case command-tar-gzip 0 exact 'mkdir source restored; printf payload > source/data; tar -czf archive.tar.gz -C source data; tar -xzf archive.tar.gz -C restored; cat restored/data; rm archive.tar.gz'
run_case command-tar-pipe 0 exact 'printf payload > data; tar -cf - data | tar -xOf - data'
run_case command-tar-cwd 0 exact 'mkdir source; printf payload > source/data; before=$PWD; tar -cf archive.tar -C source data; [[ $PWD == "$before" ]]; tar -xOf archive.tar data; rm archive.tar'
run_case command-tar-strip 0 exact 'mkdir source restored; printf payload > source/data; tar -cf archive.tar source/data; tar -xf archive.tar --strip-components=1 -C restored; cat restored/data; rm archive.tar'
run_case files-cp-no-clobber-force 0 exact 'printf old > destination; printf new > source; cp -nf source destination; cp -fn source destination; cat destination'
run_case files-cp-no-clobber-last 0 exact 'printf old > destination; printf new > source; cp -in source destination; cat destination'
run_case files-cp-no-clobber-link 1 diagnostic 'printf new > source; ln -s absent destination; cp -n source destination'
run_case files-cp-no-clobber-same 0 exact 'printf payload > source; cp -n source source; cat source'
run_case files-touch-negative 0 exact 'touch -d @-1 data; stat -c "%Y" data'
run_case files-cat-display 0 exact 'printf "\n\nhello\n\n\000\t\377\n" | cat -nbsA'
run_case files-cat-stdin 0 exact 'printf data | cat --'
run_case terminal-clear 0 exact 'clear'

printf '\n%s: %s cases, %s passed, %s failed\n' "$mode" "$total" "$((total-failed))" "$failed"
printf '%s\t%s\t%s\n' "$mode" "$total" "$failed" > "$output/summary.tsv"
printf 'complete\n' > "$output/complete"
[[ $failed == 0 ]]
