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

# We may need some more C++ flags
_cxxflags=""

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    : "${CMAKE:=/cygdrive/c/cmake/bin/cmake}"
    # Enable exception handling for MSVC
    _cxxflags="-EHsc"
    if [ "$WINDOWS_32BIT" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . ${evergreen_root}/libmongocrypt/.evergreen/find-cmake.sh
    # Check if on macOS with arm64. Use system cmake. See BUILD-14565.
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        CMAKE=cmake
    fi
fi

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    cd $evergreen_root
    rm -rf libmongocrypt/cmake-build* "${MONGOCRYPT_INSTALL_PREFIX}"
    ADDITIONAL_CMAKE_FLAGS="${ADDITIONAL_CMAKE_FLAGS} -DENABLE_BUILD_FOR_PPA=ON"
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

cd $evergreen_root

# Build and install libmongocrypt.
cd libmongocrypt
mkdir cmake-build
cd cmake-build

for suffix in "dll" "dylib" "so"; do
    if test -f "mongo_crypt_v1.$suffix"; then
        ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DMONGOCRYPT_TESTING_CRYPT_SHARED_FILE=$PWD/mongo_crypt_v1.$suffix"
    fi
done

ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"

$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_CXX_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS} $_cxxflags" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
$CMAKE --build . --target install --config RelWithDebInfo
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
$CMAKE --build . --target test_kms_request --config RelWithDebInfo
cd $evergreen_root

# MONGOCRYPT-372, ensure macOS universal builds contain both x86_64 and arm64 architectures.
if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures..."
    ARCHS=$(lipo -archs $MONGOCRYPT_INSTALL_PREFIX/lib/libmongocrypt.dylib)
    if [[ "$ARCHS" == *"x86_64"* && "$ARCHS" == *"arm64"* ]]; then
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... OK"
    else
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... ERROR. Got: $ARCHS"
        exit 1
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
$CMAKE -DDISABLE_NATIVE_CRYPTO=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_CXX_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS} $_cxxflags" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}/nocrypto" ../
echo "Installing libmongocrypt with no crypto"
$CMAKE --build . --target install --config RelWithDebInfo
echo "Building test-mongocrypt with no crypto"
$CMAKE --build . --target test-mongocrypt --config RelWithDebInfo
cd $evergreen_root

# Build and install libmongocrypt without statically linking libbson
cd libmongocrypt
mkdir cmake-build-sharedbson
cd cmake-build-sharedbson
$CMAKE -DUSE_SHARED_LIBBSON=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_CXX_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS} $_cxxflags" "-DCMAKE_INSTALL_PREFIX=${MONGOCRYPT_INSTALL_PREFIX}/sharedbson" ../
echo "Installing libmongocrypt with shared libbson"
$CMAKE --build . --target install  --config RelWithDebInfo
