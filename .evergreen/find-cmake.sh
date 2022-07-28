#!/bin/sh

set -euxo pipefail

find_cmake ()
{
  if [ ! -z "${CMAKE-}" ]; then
    return 0
  elif [ -f "/Applications/cmake-3.2.2-Darwin-x86_64/CMake.app/Contents/bin/cmake" ]; then
    CMAKE="/Applications/cmake-3.2.2-Darwin-x86_64/CMake.app/Contents/bin/cmake"
  elif [ -f "/Applications/Cmake.app/Contents/bin/cmake" ]; then
    CMAKE="/Applications/Cmake.app/Contents/bin/cmake"
  elif [ -f "/opt/cmake/bin/cmake" ]; then
    CMAKE="/opt/cmake/bin/cmake"
  elif [ -z "${IGNORE_SYSTEM_CMAKE-}" ] && command -v cmake 2>/dev/null; then
    CMAKE=cmake
  elif uname -a | grep -iq 'GNU/Linux'; then
    version="3.19.4"  # First version that ships arm64 binaries
    root="$PWD/cmake-$version"
    expect_exe="$root/bin/cmake"
    if [ -f "$expect_exe" ]; then
      CMAKE="$expect_exe"
      return 0
    fi
    arch="$(uname -m)"
    curl --retry 5 "https://github.com/Kitware/CMake/releases/download/v$version/cmake-$version-Linux-$arch.tar.gz" \
      -LsS --max-time 120 --fail --output cmake.tgz
    mkdir -p "$root"
    tar xzf "$PWD/cmake.tgz" -C "$root" --strip-components=1
    CMAKE=$expect_exe
  elif [ -f "/cygdrive/c/cmake/bin/cmake" ]; then
    CMAKE="/cygdrive/c/cmake/bin/cmake"
  fi
  if [ -z "$CMAKE" -o -z "$( $CMAKE --version 2>/dev/null )" ]; then
    # Some images have no cmake yet, or a broken cmake (see: BUILD-8570)
    echo "-- MAKE CMAKE --"
    CMAKE_INSTALL_DIR=$(readlink -f cmake-install)
    curl --retry 5 https://cmake.org/files/v3.11/cmake-3.11.0.tar.gz -sS --max-time 120 --fail --output cmake.tar.gz
    tar xzf cmake.tar.gz
    cd cmake-3.11.0
    ./bootstrap --prefix="${CMAKE_INSTALL_DIR}"
    make -j8
    make install
    cd ..
    CMAKE="${CMAKE_INSTALL_DIR}/bin/cmake"
    echo "-- DONE MAKING CMAKE --"
  fi
}

find_cmake
