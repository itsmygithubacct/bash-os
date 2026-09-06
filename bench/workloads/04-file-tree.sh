# Build, copy, list, search and remove a tree of 50 directories x 20 files.
D=$1; T=$D/tree; rm -rf "$T" "$T.2"
i=0; while [ $i -lt 50 ]; do mkdir -p "$T/d$i"; j=0; while [ $j -lt 20 ]; do touch "$T/d$i/f$j"; j=$((j+1)); done; i=$((i+1)); done
cp -r "$T" "$T.2"
l=$(ls -l "$T.2"/* | wc -l); f=$(find "$T.2" -name 'f1*' | wc -l); du -s "$T.2" > /dev/null
mv "$T.2" "$T.3"; rm -rf "$T" "$T.3"
echo "ls $l find $f"
