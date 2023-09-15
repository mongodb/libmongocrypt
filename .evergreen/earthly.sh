#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

set -euo pipefail

: "${EARTHLY_VERSION:=0.7.8}"

# Calc the arch of the executable we want
arch="$(uname -m)"
case "$arch" in
    x86_64)
        arch=amd64
        ;;
    aarch64|arm64)
        arch=arm64
        ;;
    *)
        echo "Unknown architecture: $arch" 1>&1
        exit 99
        ;;
esac

# The location where the Earthly executable will live
cache_dir="$USER_CACHES_DIR/earthly-sh/$EARTHLY_VERSION"
mkdir -p "$cache_dir"

exe_filename="earthly-$OS_NAME-$arch$EXE_SUFFIX"
exe_path="$cache_dir/$exe_filename"

# Download if it isn't already present
if ! test -f "$exe_path"; then
    echo "Downloading $exe_filename $EARTHLY_VERSION"
    url="https://github.com/earthly/earthly/releases/download/v$EARTHLY_VERSION/$exe_filename"
    curl --retry 5 -LsS --max-time 120 --fail "$url" --output "$exe_path"
fi

chmod a+x "$exe_path"

"$exe_path" "$@"
