# config/versions.sh — pinned inputs for a reproducible bash-os build.
#
# bash-os is GNU bash with a curated set of loadables compiled in as static
# builtins (see build.sh and README.md). Only the bash source is pinned here;
# a consumer that cross-compiles for a device supplies its own toolchain.
BASH_SRC_VERSION=5.3
BASH_URL="https://ftp.gnu.org/gnu/bash/bash-${BASH_SRC_VERSION}.tar.gz"
BASH_SRC_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba
BASH_PATCHLEVEL=0          # upstream bash53-NNN patches not applied (yet)
BASH_BUILD_NUMBER=0        # pinned so mkversion.sh does not stamp a rebuild counter
