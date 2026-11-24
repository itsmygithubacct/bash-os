# shell/errexit-pipefail: set -euo pipefail behaviour
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
( set -e; false; echo not-reached ); echo "rc=$?"; ( set -e; false || true; echo reached ); ( set -o pipefail; false | true; echo "pipe=$?" )
( set -u; echo "${unset_var-default}"; echo "$unset_var" ) 2>&1 | sed 's/^.*line [0-9]*: //'; ( set -e; if false; then :; fi; echo if-ok )
( set -euo pipefail; printf 'x\n' | grep -q x; echo grep-ok ); ( set -e; f() { false; echo in-f; }; f || echo f-failed )
