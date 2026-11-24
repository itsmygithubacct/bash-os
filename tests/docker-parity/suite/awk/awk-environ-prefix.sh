# awk/awk-environ-prefix: a VAR=value prefix assignment reaches ENVIRON
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
FOO=bar awk 'BEGIN{print "[" ENVIRON["FOO"] "]"}'; X=1 awk 'BEGIN{print ("X" in ENVIRON)}'; export LATER=set; awk 'BEGIN{print "[" ENVIRON["LATER"] "]"}'
