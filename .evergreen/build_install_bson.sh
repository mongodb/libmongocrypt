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
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

$CMAKE --version

# Remove remnants of any earlier build
[ -d cmake-build ] && rm -rf cmake-build

mkdir cmake-build
pushd cmake-build
# To statically link when using a shared library, compile shared library with -fPIC: https://stackoverflow.com/a/8810996/774658
$CMAKE -DENABLE_MONGOC=OFF ${ADDITIONAL_CMAKE_FLAGS} ${BSON_EXTRA_CMAKE_FLAGS} -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_EXTRA_ALIGNMENT=OFF -DCMAKE_C_FLAGS="-fPIC ${BSON_EXTRA_CFLAGS}" -DCMAKE_INSTALL_PREFIX="${BSON_INSTALL_PREFIX}" ../
echo "Installing libbson"
# TODO - Upgrade to cmake 3.12 and use "-j" to increase parallelism
$CMAKE --build . --target install --config RelWithDebInfo

popd
popd
popd

