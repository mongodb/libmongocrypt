#!/bin/bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

: "${PPA_BUILD_ONLY:=}"
: "${WINDOWS_32BIT:=}"
: "${OS:=unspecified}"

evergreen_root="$(dirname "$LIBMONGOCRYPT_DIR")"

: "${MONGOCRYPT_INSTALL_PREFIX:="$evergreen_root/install/libmongocrypt"}"
MONGOCRYPT_INSTALL_PREFIX="$(native_path "$MONGOCRYPT_INSTALL_PREFIX")"

mkdir -p "$MONGOCRYPT_INSTALL_PREFIX"

if test -f /proc/cpuinfo; then
    # Count the number of lines beginning with "processor" in the cpuinfo
    jobs="$(grep -c '^processor' /proc/cpuinfo)"
    if have_command bc; then
        # Add two (hueristic to compensate for I/O latency)
        jobs="$(echo "$jobs+2" | bc)"
    fi
    export CMAKE_BUILD_PARALLEL_LEVEL="$jobs"
else
    # Cannot tell the best number of jobs. Provide a reasonable default.
    export CMAKE_BUILD_PARALLEL_LEVEL="8"
fi
