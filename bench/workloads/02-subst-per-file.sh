# The same, but capturing the result with $(...): a subshell per call in every
# shell, so this measures the fork that bash-os still pays, without the exec.
D=$1; total=0
for f in "$D"/files/*; do n=$(wc -c < "$f"); total=$((total+n)); done
echo "bytes $total"
