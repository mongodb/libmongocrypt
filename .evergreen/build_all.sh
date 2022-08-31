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

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"
set -x
echo "Begin compile process"

evergreen_root="$(pwd)"

. "$EVG_DIR/setup-env.sh"

# We may need some more C++ flags
_cxxflags=""

: "${ADDITIONAL_CMAKE_FLAGS:=}"
: "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS:=}"
: "${LIBMONGOCRYPT_EXTRA_CFLAGS:=}"
: "${CONFIGURE_ONLY:=}"
: "${MACOS_UNIVERSAL:=}"
: "${PPA_BUILD_ONLY:=}"

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS_NAME" = "windows" ]; then
    : "${CMAKE:=/cygdrive/c/cmake/bin/cmake}"
    # Enable exception handling for MSVC
    _cxxflags="-EHsc"
    if [ "${WINDOWS_32BIT-}" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . "$EVG_DIR/find-cmake.sh"
    # Check if on macOS with arm64. Use system cmake. See BUILD-14565.
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        CMAKE=cmake
    fi
fi

: "${CTEST:="${CMAKE%cmake*}ctest"}"
# Have CTest print test failure info to stderr
export CTEST_OUTPUT_ON_FAILURE=1

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    rm -rf -- "$LIBMONGOCRYPT_DIR"/cmake-build* "$MONGOCRYPT_INSTALL_PREFIX"
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_BUILD_FOR_PPA=ON"
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

: "${CMAKE:=cmake}"

for suffix in "dll" "dylib" "so"; do
    cand="$(abspath "$LIBMONGOCRYPT_DIR/../mongocrypt_v1.$suffix")"
    if test -f "$cand"; then
        ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DMONGOCRYPT_TESTING_CRYPT_SHARED_FILE=$cand"
    fi
done

ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"

build_dir="$LIBMONGOCRYPT_DIR/cmake-build"
common_cmake_args=(
    $ADDITIONAL_CMAKE_FLAGS
    $LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS
    -DCMAKE_C_FLAGS="$LIBMONGOCRYPT_EXTRA_CFLAGS"
    -DCMAKE_CXX_FLAGS="$LIBMONGOCRYPT_EXTRA_CFLAGS $_cxxflags"
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
    -H"$LIBMONGOCRYPT_DIR"
    -B"$build_dir"
)

# Build and install libmongocrypt.
"$CMAKE" \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX" \
    "${common_cmake_args[@]}"

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
$CMAKE --build "$build_dir" --target install --config RelWithDebInfo
$CMAKE --build "$build_dir" --target test-mongocrypt --config RelWithDebInfo
$CMAKE --build "$build_dir" --target test_kms_request --config RelWithDebInfo
run_chdir "$build_dir" "$CTEST" -C RelWithDebInfo

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
"$CMAKE" \
    -DDISABLE_NATIVE_CRYPTO=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/nocrypto" \
    "${common_cmake_args[@]}"

$CMAKE --build "$build_dir" --target install --config RelWithDebInfo
$CMAKE --build "$build_dir" --target test-mongocrypt --config RelWithDebInfo
run_chdir "$build_dir" "$CTEST" -C RelWithDebInfo

# Build and install libmongocrypt without statically linking libbson
"$CMAKE" \
    -UDISABLE_NATIVE_CRYPTO \
    -DUSE_SHARED_LIBBSON=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/sharedbson" \
    "${common_cmake_args[@]}"

"$CMAKE" --build "$build_dir" --target install  --config RelWithDebInfo
run_chdir "$build_dir" "$CTEST" -C RelWithDebInfo
