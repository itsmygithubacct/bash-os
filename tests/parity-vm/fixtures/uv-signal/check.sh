# Run only in a disposable guest with the candidate shell. The coordinator
# installs helper.c's compiled executable at the appropriate uv helper path.
# For a dynamic module, set UV_TEST_MODULE to its absolute staged path;
# for a compiled-in uv, leave UV_TEST_MODULE unset.
if [[ -n ${UV_TEST_MODULE-} ]]; then
    enable -f "$UV_TEST_MODULE" uv || exit 90
fi
[[ $(type -t uv) == builtin ]] || exit 91
trap 'echo unexpected-trap' INT QUIT
uv defaults || exit 92
for sig in term kill usr1; do
    uv "$sig"
    printf '%s=%s\n' "$sig" "$?"
done
