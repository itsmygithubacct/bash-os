# 200 x wc -l on 423 KB and 200 x tail -n 1 on an 89 KB log, called directly
# (no $(...) — that pattern is workload 02): the tools' own cost.
D=$1; i=0
while [ $i -lt 200 ]; do wc -l "$D/words.txt" > /dev/null; tail -n 1 "$D/log.txt" > /dev/null; i=$((i+1)); done
echo "calls 400"
