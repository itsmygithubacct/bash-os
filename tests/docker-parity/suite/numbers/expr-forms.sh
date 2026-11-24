# numbers/expr-forms: expr arithmetic, comparison, string and regex ops
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
expr 1 + 2; expr 7 / 2; expr 7 % 3; expr -7 / 2; expr 3 \* 4; expr 5 \> 3; expr a \< b; expr 2 = 2; expr 2 != 2; echo "rc=$?"
expr length hello; expr substr hello 2 3; expr index hello l; expr hello : 'h\(.*\)o'; expr hello : '.*'; expr match abc 'a.'
expr 0 \| 5; expr 0 \& 5; echo "rc=$?"; expr '' \| ''; echo "rc=$?"; expr 9223372036854775807 + 0; expr 1 + a; echo "rc=$?"; expr 1 / 0; echo "rc=$?"
