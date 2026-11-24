# shell/arrays: indexed and associative arrays, slices, keys
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
a=(zero one two three); echo "${#a[@]} ${a[2]} ${a[@]:1:2} ${!a[*]}"; a+=(four); unset 'a[1]'; echo "${a[*]}" "${!a[@]}"
declare -A m=([b]=2 [a]=1 [c]=3); for k in $(printf '%s\n' "${!m[@]}" | sort); do printf '%s=%s ' "$k" "${m[$k]}"; done; echo
declare -a n; n[5]=x; echo "${#n[@]} ${!n[@]}"; b=("${a[@]/o/0}"); echo "${b[*]}"; echo "${a[@]: -1}"
# --- printf -v into scalars and array elements
mkdir part-printf-v && (cd part-printf-v || exit
printf -v x '%05d' 42; echo "$x"; declare -a arr; printf -v 'arr[2]' '%s-%s' a b; echo "${arr[2]}"; printf -v y '%s,' 1 2 3; echo "${y%,}"
)
