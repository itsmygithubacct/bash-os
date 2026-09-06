# 100 launches of the userland's own shell: what find -exec sh -c, cron and
# init scripts pay per script.
S=$2; i=0
while [ $i -lt 100 ]; do "$S" -c 'true'; i=$((i+1)); done
echo "launched 100"
