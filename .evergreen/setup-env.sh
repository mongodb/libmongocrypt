#!/bin/bash
evergreen_root="$(pwd)"

[ -d "${MONGOCRYPT_INSTALL_PREFIX:=${evergreen_root}/install/libmongocrypt}" ] || mkdir -p "${MONGOCRYPT_INSTALL_PREFIX}"

if [ "$OS" == "Windows_NT" ]; then
	MONGOCRYPT_INSTALL_PREFIX=$(cygpath -w $MONGOCRYPT_INSTALL_PREFIX)
fi

if test -f /proc/cpuinfo; then
    # Count the number of lines beginning with "processor" in the cpuinfo
    jobs="$(grep -c '^processor' /proc/cpuinfo)"
    if command -v bc; then
        # Add two (hueristic to compensate for I/O latency)
        jobs="$(echo "$jobs+2" | bc)"
    fi
    export MAKEFLAGS="-j$jobs ${MAKEFLAGS-}"
else
    # Cannot tell the best number of jobs. Provide a reasonable default.
    export MAKEFLAGS="-j8 ${MAKEFLAGS-}"
fi
