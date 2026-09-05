# config/loadables.sh — the ONE parser of config/bash-loadables-nano.list.
#
# Sourced by build/build-bash.sh, tests/run-all.sh and tests/check-ramfs-commands.sh.
# Four hand-rolled parsers used to disagree on trailing whitespace and on lines
# without a '|', so one function now defines the grammar:
#
#   NAME[|SHORT-DOC]          # comment
#
#   NAME       the builtin's name: NAME_builtin/NAME_doc/NAME_struct in C, and
#              the source is always loadables/NAME.c (or a vendored/stock NAME.c).
#   SHORT-DOC  the one-line usage `help NAME` shows; defaults to NAME.
#
# The doc is EVERYTHING after the first '|', because usage strings legitimately
# contain '|' themselves ("bashnpu load|feed|forward|read ..."). A three-field
# grammar would split those and is why this file must not add one: to compile a
# builtin from a differently-named source, add a NAME.c that includes the shared
# implementation (see loadables/common/reboot-impl.h and reboot/halt/poweroff).
#
# Whitespace around each field is trimmed; a '#' starts a comment, whole-line
# only (a '#' inside a doc string is kept); blank lines are ignored.
#
#   loadables_parse LIST   prints one "NAME<TAB>DOC" per entry
#   loadables_names LIST   prints NAME per entry (the common case)
loadables_parse() {
    local line name doc
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"         # ltrim
        [[ -z "$line" || "$line" == \#* ]] && continue  # blank / whole-line comment
        line="${line%"${line##*[![:space:]]}"}"         # rtrim
        name="${line%%|*}"
        name="${name%"${name##*[![:space:]]}"}"         # rtrim the name
        if [[ "$line" == *'|'* ]]; then
            doc="${line#*|}"                            # everything after the FIRST |
            doc="${doc#"${doc%%[![:space:]]*}"}"
            [[ -z "$doc" ]] && doc="$name"
        else
            doc="$name"
        fi
        [[ "$name" =~ ^[a-z_][a-z0-9_]*$ ]] || { echo "loadables.sh: bad loadable name '$name'" >&2; return 1; }
        printf '%s\t%s\n' "$name" "$doc"
    done < "$1"
}
loadables_names() { loadables_parse "$1" | cut -f1; }
