#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
# 
# Assumes the current working directory contains libmongocrypt.
# So script should be called like: ./libmongocrypt/.evergreen/compile.sh
# The current working directory should be empty aside from 'libmongocrypt'
# since this script creates new directories/files (e.g. mongo-c-driver, venv).
#
# Set extra cflags for libmongocrypt variables by setting LIBMONGOCRYPT_EXTRA_CFLAGS.
#

set -o xtrace
set -o errexit

echo "Begin compile process"

evergreen_root="$(pwd)"

. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh

cd $evergreen_root

# Build and install libbson.
# Force checkout of with lf endings since .sh must have lf, not crlf on Windows
git clone git@github.com:mongodb/mongo-c-driver.git --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

$CMAKE --version
python ./build/calc_release_version.py > VERSION_CURRENT
python ./build/calc_release_version.py -p > VERSION_RELEASED
mkdir cmake-build
cd cmake-build
# To statically link when using a shared library, compile shared library with -fPIC: https://stackoverflow.com/a/8810996/774658
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=Debug -DENABLE_EXTRA_ALIGNMENT=OFF -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/mongo-c-driver ../
echo "Installing libbson"
# TODO - Upgrade to cmake 3.12 and use "-j" to increase parallelism
$CMAKE --build . --target install
cd $evergreen_root

# Build and install libmongocrypt.
cd libmongocrypt
mkdir cmake-build
cd cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=Debug "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="-fPIC ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}/mongo-c-driver" "-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/libmongocrypt" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
$CMAKE --build . --target install
# CDRIVER-3187, ensure the final distributed tarball contains the libbson static
# library to support consumers that static link to libmongocrypt
find ${INSTALL_PREFIX}/mongo-c-driver \( -name libbson-static-1.0.a -o -name bson-1.0.lib \) -execdir cp {} $(dirname $(find ${INSTALL_PREFIX}/libmongocrypt -name libmongocrypt-static.a -o -name mongocrypt-static.lib)) \;
$CMAKE --build . --target test-mongocrypt
$CMAKE --build ./kms-message --target test_kms_request
cd $evergreen_root

# Build and install libmongocrypt with no native crypto.
cd libmongocrypt
mkdir cmake-build-nocrypto
cd cmake-build-nocrypto
$CMAKE -DDISABLE_NATIVE_CRYPTO=ON -DCMAKE_BUILD_TYPE=Debug "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="-fPIC ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}/mongo-c-driver" "-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/libmongocrypt/nocrypto" ../
echo "Installing libmongocrypt with no crypto"
$CMAKE --build . --target install
echo "Building test-mongocrypt with no crypto"
$CMAKE --build . --target test-mongocrypt
