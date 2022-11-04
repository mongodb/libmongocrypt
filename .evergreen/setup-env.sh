#!/bin/bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

: "${ADDITIONAL_CMAKE_FLAGS:=}"
: "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS:=}"
: "${LIBMONGOCRYPT_EXTRA_CFLAGS:=}"
: "${PPA_BUILD_ONLY:=}"
: "${MACOS_UNIVERSAL:=}"
: "${WINDOWS_32BIT:=}"
: "${OS:=unspecified}"

IS_MULTICONF=false
if test "$OS_NAME" = "windows" && ! "${USE_NINJA-false}"; then
    IS_MULTICONF=true
fi

: "$IS_MULTICONF"  # Silence shellcheck

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
    export MAKEFLAGS="-j$jobs ${MAKEFLAGS-}"
else
    # Cannot tell the best number of jobs. Provide a reasonable default.
    export MAKEFLAGS="-j8 ${MAKEFLAGS-}"
fi
