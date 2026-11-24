# awk/awk-records: RS paragraph mode, regex RS, ORS, RT-free checks (G22 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\nb\n\n\nc\nd\n\ne\n' | awk 'BEGIN{RS=""}{print NR": "$1"/"$NF" nf="NF}'
printf 'a1b22c333d' | awk 'BEGIN{RS="[0-9]+"}{print NR, $0}'; printf 'x;y;z' | awk 'BEGIN{RS=";"; ORS="|"}{print}'; echo
printf 'a b\nc d\n' | awk 'BEGIN{RS=""; FS="\n"}{print $2}'
# --- NUL bytes in data and printf %c 0
mkdir part-awk-nul-data && (cd part-awk-nul-data || exit
printf 'a\0b\nc\n' | awk '{print length($0)}'; awk 'BEGIN{printf "%c", 0}' | od -An -c; printf 'x\0y\0' | awk -v RS='\0' '{print NR, $0}'
)
