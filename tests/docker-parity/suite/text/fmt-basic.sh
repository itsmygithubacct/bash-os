# text/fmt-basic: fmt width and paragraph handling
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v fmt >/dev/null || fmt() { coreutils fmt "$@"; }
cat > f <<'EOF'
The quick brown fox jumps over the lazy dog. Pack my box with five dozen
liquor jugs.

  Indented paragraph line one
  continues here and keeps going for a while to wrap.
EOF
fmt -w 30 f; echo --; fmt -w 40 -u f; echo --; fmt -s -w 20 f
