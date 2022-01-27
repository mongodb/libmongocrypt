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

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    cd $evergreen_root
    rm -rf libmongocrypt/cmake-build* "${MONGOCRYPT_INSTALL_PREFIX}"
    ADDITIONAL_CMAKE_FLAGS="${ADDITIONAL_CMAKE_FLAGS} -DENABLE_BUILD_FOR_PPA=ON"
fi

. ${evergreen_root}/libmongocrypt/.evergreen/build_install_bson.sh

cd $evergreen_root

# CMAKE should be set in build_install_bson.sh; this error should not occur
command -v $CMAKE || (echo "CMake could not be found...aborting!"; exit 1)

# Build and install libmongocrypt.
cd libmongocrypt
mkdir cmake-build
cd cmake-build

if [ "$OS" = "Windows_NT" ]; then
    # W4996 - POSIX name for this item is deprecated
    # TODO: add support for clang-cl which is detected as MSVC
    LIBMONGOCRYPT_CFLAGS="/W3 /wd4996 /D_CRT_SECURE_NO_WARNINGS /WX"
else
    # GNU, Clang, AppleClang
    LIBMONGOCRYPT_CFLAGS="-Wall -Werror -Wno-missing-braces"
fi

$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_CFLAGS} ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
$CMAKE --build . --target install --config RelWithDebInfo
# CDRIVER-3187, ensure the final distributed tarball contains the libbson static
# library to support consumers that static link to libmongocrypt
find ${BSON_INSTALL_PREFIX} \( -name libbson-static-1.0.a -o -name bson-1.0.lib -o -name bson-static-1.0.lib \) -execdir cp {} $(dirname $(find ${MONGOCRYPT_INSTALL_PREFIX} -name libmongocrypt-static.a -o -name mongocrypt-static.lib)) \;
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
$CMAKE --build ./kms-message --target test_kms_request --config RelWithDebInfo
cd $evergreen_root

# MONGOCRYPT-372, ensure macOS universal builds contain both x86_64 and arm64 architectures.
if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures..."
    ARCHS=$(lipo -archs $MONGOCRYPT_INSTALL_PREFIX/lib/libmongocrypt.dylib)
    if [[ "$ARCHS" == *"x86_64"* && "$ARCHS" == *"arm64"* ]]; then
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... OK"
    else
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... ERROR. Got: $ARCHS"
        exit
    fi
fi

if [ "$PPA_BUILD_ONLY" ]; then
    echo "Only building/installing for PPA";
    exit 0;
fi

# Build and install libmongocrypt with no native crypto.
cd libmongocrypt
mkdir cmake-build-nocrypto
cd cmake-build-nocrypto
$CMAKE -DDISABLE_NATIVE_CRYPTO=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_CFLAGS} ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}/nocrypto" ../
echo "Installing libmongocrypt with no crypto"
$CMAKE --build . --target install --config RelWithDebInfo
echo "Building test-mongocrypt with no crypto"
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
cd $evergreen_root

# Build and install libmongocrypt without statically linking libbson
cd libmongocrypt
mkdir cmake-build-sharedbson
cd cmake-build-sharedbson
$CMAKE -DENABLE_SHARED_BSON=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_CFLAGS} ${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}/sharedbson" ../
echo "Installing libmongocrypt with shared libbson"
$CMAKE --build . --target install  --config RelWithDebInfo
