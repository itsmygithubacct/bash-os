# A small tool called once per file, output discarded: the shell-script pattern
# that forks a process per call everywhere but here.
D=$1; n=0
for f in "$D"/files/*; do wc -c < "$f" > /dev/null; basename "$f" > /dev/null; n=$((n+1)); done
echo "calls $((n*2))"
