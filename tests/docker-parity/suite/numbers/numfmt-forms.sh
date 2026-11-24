# numbers/numfmt-forms: numfmt --to/--from units, padding, rounding, fields
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v numfmt >/dev/null || numfmt() { coreutils numfmt "$@"; }
numfmt --to=si 1000 1500000 999; numfmt --to=iec 1024 1536 1048576; numfmt --to=iec-i 2048; numfmt --from=si 1K 2.5M; numfmt --from=iec 1K 1M
numfmt --from=auto 1Ki 1K; numfmt --to=si --round=down 1999; numfmt --to=si --round=up 1001; numfmt --padding=8 42; numfmt --format='%08.2f' 3.14159
printf 'a 1000 x\nb 2000 y\n' | numfmt --field=2 --to=si; printf 'H 1\nv 2048\n' | numfmt --header --field=2 --to=iec; numfmt --suffix=B --to=si 3000
numfmt --invalid=ignore abc 10 2>/dev/null; echo "rc=$?"
