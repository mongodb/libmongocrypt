#!/bin/bash

# Directory layout
# .evergreen
# -linker_tests_deps
# --app
# --bson_patches
#
# linker_tests (created by this script)
# -libmongocrypt-cmake-build (for artifacts built from libmongocrypt source)
# -app-cmake-build
# -mongo-c-driver
# --cmake-build
# -install
# --bson1
# --bson2
# --libmongocrypt
#

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"
. "$EVG_DIR/setup-env.sh"

linker_tests_root="$LIBMONGOCRYPT_DIR/linker_tests"
linker_tests_deps_root="$EVG_DIR/linker_tests_deps"

rm -rf -- "$linker_tests_root"
mkdir -p "$linker_tests_root"/{install,libmongocrypt-cmake-build,app-cmake-build}

# Make libbson1 and libbson2
pushd "$linker_tests_root"
  . "$EVG_DIR/prep_c_driver_source.sh"
  MONGOC_DIR="$linker_tests_root/mongo-c-driver"
popd

: "${ADDITIONAL_CMAKE_FLAGS:=}"
: "${MACOS_UNIVERSAL:=}"

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS_NAME" = "windows" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    if [ "${WINDOWS_32BIT-}" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . "$EVG_DIR/find-cmake.sh"
    # Check if on macOS with arm64. Use system cmake. See BUILD-14565.
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        CMAKE=cmake
    fi
fi

if [ "${MACOS_UNIVERSAL-}" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

pushd "$MONGOC_DIR"
  git apply --ignore-whitespace "$linker_tests_deps_root/bson_patches/libbson1.patch"
popd

BUILD_PATH="$MONGOC_DIR/cmake-build"
BSON1_INSTALL_PATH="$linker_tests_root/install/bson1"
SRC_PATH="$MONGOC_DIR"
$CMAKE \
  -DENABLE_MONGOC=OFF \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  $ADDITIONAL_CMAKE_FLAGS \
  -DCMAKE_INSTALL_PREFIX="$BSON1_INSTALL_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_PATH"
$CMAKE --build "$BUILD_PATH" --target install --config RelWithDebInfo
# Make libbson2

pushd "$MONGOC_DIR"
  git reset --hard
  git apply --ignore-whitespace "$linker_tests_deps_root/bson_patches/libbson2.patch"
popd
LIBBSON2_SRC_DIR="$MONGOC_DIR"

# Build libmongocrypt, static linking against libbson2
BUILD_DIR="$linker_tests_root/libmongocrypt-cmake-build"
LMC_INSTALL_PATH="$linker_tests_root/install/libmongocrypt"
SRC_PATH="$LIBMONGOCRYPT_DIR"
$CMAKE \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  "-DMONGOCRYPT_MONGOC_DIR=$LIBBSON2_SRC_DIR" \
  $ADDITIONAL_CMAKE_FLAGS \
  -DCMAKE_INSTALL_PREFIX="$LMC_INSTALL_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_DIR"
$CMAKE --build "$BUILD_DIR" --target install --config RelWithDebInfo

echo "Test case: Modelling libmongoc's use"
# app links against libbson1.so
# app links against libmongocrypt.so
BUILD_DIR="$linker_tests_root/app-cmake-build"
PREFIX_PATH="$LMC_INSTALL_PATH;$BSON1_INSTALL_PATH"
SRC_PATH="$linker_tests_deps_root/app"
$CMAKE \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  $ADDITIONAL_CMAKE_FLAGS \
  -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_DIR"
$CMAKE --build "$BUILD_DIR" --target app --config RelWithDebInfo

if [ "$OS_NAME" = "windows" ]; then
    export PATH="$PATH:$BSON1_INSTALL_PATH/bin:$LMC_INSTALL_PATH/bin"
    APP_CMD="$BUILD_DIR/RelWithDebInfo/app.exe"
else
    APP_CMD="$BUILD_DIR/app"
fi

check_output () {
    output="$($APP_CMD)"
    if [[ "$output" != *"$1"* ]]; then
        printf "     Got: %s\nExpected: %s\n" "$output" "$1"
        exit 1;
    fi
    echo "ok"
}
check_output ".calling bson_malloc0..from libbson1..calling mongocrypt_binary_new..from libbson2."
exit 0
