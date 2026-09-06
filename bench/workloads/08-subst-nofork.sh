# Workload 02 written the bash 5.3 way: ${ cmd; } captures output with no
# subshell at all, so a builtin runs in-process. Needs a shell with that
# syntax; the harness skips the cell otherwise.
D=$1; total=0
for f in "$D"/files/*; do n=${ wc -c < "$f"; }; total=$((total+n)); done
echo "bytes $total"
