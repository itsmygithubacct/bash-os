# What init scripts and monitors do: stat, ps, df, date, uname, hostname, in loops.
D=$1; i=0; s=0
while [ $i -lt 200 ]; do s=$((s + $(stat -c %s "$D/words.txt"))); i=$((i+1)); done
i=0; while [ $i -lt 20 ]; do ps > /dev/null; df > /dev/null 2>&1; i=$((i+1)); done
i=0; while [ $i -lt 100 ]; do date +%s > /dev/null; uname -m > /dev/null; hostname > /dev/null; i=$((i+1)); done
echo "stat $s"
