# awk/awk-fields: fields, NF, NR, FS, OFS and $0 rebuild
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a b c\nd  e\n\n f:g \n' > f
awk '{print NR, NF, $1, $NF}' f; awk -F: '{print $2}' f; awk 'BEGIN{OFS="-"}{$1=$1; print}' f; awk '{$5="X"; print; print NF}' f
awk 'NF{NF=1; print}' f; awk -F'[ :]+' '{print NF}' f; awk -v FS=' ' '{print $2}' f; awk '{print length($0)}' f
# --- uninitialized values, string/number duality and concatenation precedence
mkdir part-awk-uninit-concat && (cd part-awk-uninit-concat || exit
awk 'BEGIN{print x+0, "[" x "]", length(x); print 1 " " 2, 1 2+3, -1 " " -2; a="10"; b=9; print (a<b), (a+0<b); print substr("hello", 2) 1}'
)
