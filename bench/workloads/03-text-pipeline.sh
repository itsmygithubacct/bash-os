# Pipelines of text tools over a 423 KB file: throughput of the tools themselves.
D=$1; i=0; a=0; b=0; c=0
while [ $i -lt 10 ]; do
  a=$((a + $(grep -c the "$D/words.txt")))
  b=$((b + $(tr ' ' '\n' < "$D/words.txt" | sort | uniq -c | sort -rn | head -n 3 | wc -l)))
  c=$((c + $(cut -d' ' -f1 "$D/words.txt" | sort -u | wc -l)))
  sed 's/e/E/g' "$D/words.txt" | wc -c > /dev/null
  i=$((i+1))
done
echo "grep $a top $b uniq $c"
