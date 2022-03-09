#!/bin/bash

set -o xtrace
set -o errexit

evergreen_root="$(pwd)"
pushd $evergreen_root

. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh

# Build and install libbson.
pushd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    if [ "$WINDOWS_32BIT" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    chmod u+x ./.evergreen/find-cmake.sh
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . ./.evergreen/find-cmake.sh
    # Check if on macOS with arm64. Use system cmake. See BUILD-14565.
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        CMAKE=cmake
    fi
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

$CMAKE --version

# Remove remnants of any earlier build
[ -d cmake-build ] && rm -rf cmake-build

mkdir cmake-build
pushd cmake-build
$CMAKE -DENABLE_MONGOC=OFF ${ADDITIONAL_CMAKE_FLAGS} ${BSON_EXTRA_CMAKE_FLAGS} -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_EXTRA_ALIGNMENT=OFF -DCMAKE_C_FLAGS="${BSON_EXTRA_CFLAGS}" -DCMAKE_INSTALL_PREFIX="${BSON_INSTALL_PREFIX}" ../
echo "Installing libbson"
# TODO - Upgrade to cmake 3.12 and use "-j" to increase parallelism
$CMAKE --build . --target install --config RelWithDebInfo

popd
popd
popd

