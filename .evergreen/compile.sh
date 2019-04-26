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

. ${evergreen_root}/libmongocrypt/.evergreen/setup-venv.sh

cd $evergreen_root

# Build and install libbson.
# Force checkout of with lf endings since .sh must have lf, not crlf on Windows
git clone git@github.com:mongodb/mongo-c-driver.git --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    ADDITIONAL_CMAKE_FLAGS=
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

$CMAKE --version
python ./build/calc_release_version.py > VERSION_CURRENT
python ./build/calc_release_version.py -p > VERSION_RELEASED
mkdir cmake-build
cd cmake-build
# To statically link when using a shared library, compile shared library with -fPIC: https://stackoverflow.com/a/8810996/774658
$CMAKE -DENABLE_MONGOC=OFF $ADDITIONAL_CMAKE_FLAGS -DCMAKE_BUILD_TYPE=Debug -DENABLE_EXTRA_ALIGNMENT=OFF -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/mongo-c-driver ../
echo "Installing libbson"
# TODO - Upgrade to cmake 3.12 and use "-j" to increase parallelism
$CMAKE --build . --target install
cd $evergreen_root

# Build and install kms-message.
git clone --depth=1 git@github.com:10gen/kms-message.git
cd kms-message
mkdir cmake-build
cd cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=Debug $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" "-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/kms-message" ../
echo "Installing kms-message"
$CMAKE --build . --target install
cd $evergreen_root

# Build and install libmongocrypt.
cd libmongocrypt
mkdir cmake-build
cd cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=Debug $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_EXTRA_CLFAGS}" -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}/mongo-c-driver;${INSTALL_PREFIX}/kms-message" "-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}/libmongocrypt" ../
echo "Installing libmongocrypt"
$CMAKE --build . --target install
$CMAKE --build . --target test-mongocrypt
cd $evergreen_root
