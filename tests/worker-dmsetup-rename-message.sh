#!/usr/bin/env bash
# Run only in a disposable privileged VM. DMSETUP_TEST_BASH is the candidate;
# DMSETUP_TEST_SO optionally names the dynamic loadable. /usr/sbin/dmsetup
# creates and reads back the independent kernel state.
set -eu
: "${DMSETUP_TEST_BASH:?}"
export BASHOS_DMSETUP_ALLOW_MUTATE=1
export DMSETUP_TEST_SO=${DMSETUP_TEST_SO-}
ref=/usr/sbin/dmsetup
p="w064-$$"
a="$p-a" b="$p-b" c="$p-c"
cleanup() { "$ref" remove --noudevsync "$a" >/dev/null 2>&1 || :; "$ref" remove --noudevsync "$b" >/dev/null 2>&1 || :; "$ref" remove --noudevsync "$c" >/dev/null 2>&1 || :; }
trap cleanup EXIT
cand() {
    "$DMSETUP_TEST_BASH" --noprofile --norc -c '
        if [[ -n $DMSETUP_TEST_SO ]]; then enable -f "$DMSETUP_TEST_SO" dmsetup || exit 90; fi
        dmsetup "$@"
    ' test "$@"
}
"$ref" create --noudevsync "$a" --table '0 8 zero'
"$ref" create --noudevsync "$b" --table '0 8 zero'
cand rename --noudevsync "$a" "$c"
if "$ref" info "$a" >/dev/null 2>&1 || ! "$ref" info "$c" >/dev/null 2>&1; then exit 1; fi
cand rename --noudevsync --setuuid "$c" "W064-UUID-$$"
"$ref" info "$c" | /usr/bin/grep -F "W064-UUID-$$" >/dev/null
if cand rename --noudevsync --setuuid "$c" "W064-OTHER-$$"; then exit 1; fi
if cand rename --noudevsync "$c" "$b"; then exit 1; fi
long=$(printf '%0130d' 0)
if cand rename --noudevsync "$c" "$long"; then exit 1; fi
if cand rename --noudevsync "$c" x/y; then exit 1; fi
"$ref" info "$c" >/dev/null
reply=$(cand message --noudevsync "$b" 0 @stats_create - /100)
[[ -n $reply ]]
reply=$(cand message --noudevsync "$b" 0 @stats_list)
[[ -n $reply ]]
cand message --noudevsync "$b" 5 @stats_list >/dev/null
if cand message --noudevsync "$b" 0 bogus; then exit 1; fi
printf 'rename-message kernel checks passed\n'
