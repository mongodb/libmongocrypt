#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
#
# Assumes the current working directory contains libmongocrypt.
# So script should be called like: ./libmongocrypt/.evergreen/build_all.sh
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
. ${evergreen_root}/libmongocrypt/.evergreen/build_install_bson.sh

cd $evergreen_root

# CMAKE should be set in build_install_bson.sh; this error should not occur
command -v $CMAKE || (echo "CMake could not be found...aborting!"; exit 1)

# Build and install libmongocrypt.
cd libmongocrypt
mkdir cmake-build
cd cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="-fPIC ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
$CMAKE --build . --target install --config RelWithDebInfo
# CDRIVER-3187, ensure the final distributed tarball contains the libbson static
# library to support consumers that static link to libmongocrypt
find ${BSON_INSTALL_PREFIX} \( -name libbson-static-1.0.a -o -name bson-1.0.lib \) -execdir cp {} $(dirname $(find ${MONGOCRYPT_INSTALL_PREFIX} -name libmongocrypt-static.a -o -name mongocrypt-static.lib)) \;
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
$CMAKE --build ./kms-message --target test_kms_request --config RelWithDebInfo
cd $evergreen_root

# Build and install libmongocrypt with no native crypto.
cd libmongocrypt
mkdir cmake-build-nocrypto
cd cmake-build-nocrypto
$CMAKE -DDISABLE_NATIVE_CRYPTO=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="-fPIC ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}/nocrypto" ../
echo "Installing libmongocrypt with no crypto"
$CMAKE --build . --target install --config RelWithDebInfo
echo "Building test-mongocrypt with no crypto"
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
