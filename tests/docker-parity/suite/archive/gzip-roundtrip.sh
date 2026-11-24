# archive/gzip-roundtrip: gzip/gunzip -c, -d, -k, -t, zcat
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 200 > f; cp f g
gzip -n -c f | gzip -d -c | cmp - f && echo roundtrip; gzip -k g; ls g*; gzip -t g.gz && echo tested; zcat g.gz | tail -n 1
gzip -d -f g.gz; ls g*; gzip -n f; ls f*; zcat < f.gz | wc -l; gzip -dc f.gz | head -n 2
# --- every level decompresses to the same bytes
mkdir part-gzip-levels && (cd part-gzip-levels || exit
seq 1 3000 > f; for l in 1 5 9; do gzip -n -$l -c f | zcat | md5sum; done; gzip -c -n f > f.gz; gzip -dc f.gz | wc -c
)
