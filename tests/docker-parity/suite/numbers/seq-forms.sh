# numbers/seq-forms: seq ranges, steps, -w, -s, -f, negatives and floats
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 3; seq 2 5; seq 10 -3 1; seq -w 8 11; seq -s, 1 5; seq -f '%03g' 1 3; seq 0.5 0.25 1.5; seq -1 -1 -3; seq 5 1; echo "rc=$?"
seq -s '' 1 9; echo; seq 1e2 1e2; seq -w 0.9 0.1 1.1; seq 18446744073709551615 18446744073709551617; seq -f '%.2e' 1000 1000 2000
# --- seq output widths and precision follow the arguments
mkdir part-seq-precision && (cd part-seq-precision || exit
seq 1 0.1 1.3; seq 0.10 0.05 0.20; seq -w -1 1; seq -w 1 0.5 2; seq 1.0 3; seq 1e0 3
)
