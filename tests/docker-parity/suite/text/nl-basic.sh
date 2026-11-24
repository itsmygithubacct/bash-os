# text/nl-basic: nl numbering styles and formats
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\n\nb\nc\n' > f
nl f; echo --; nl -ba f; echo --; nl -nln -w3 -s: f; echo --; nl -nrz -w4 f
echo --; nl -v10 -i5 -ba f; echo --; nl -bpb f
# --- nl -d custom delimiter and -l blank grouping
mkdir part-nl-misc && (cd part-nl-misc || exit
printf 'a\n\n\n\nb\n' | nl -ba -l2
printf '@@@\nh\n@@\nb\n' | nl -d@@ -ha
)
