#!/bin/bash
set -o xtrace
set -o errexit

system_path () {
    if [ "$OS" == "Windows_NT" ]; then
        cygpath -a "$1" -w
    else
        echo $1
    fi
}

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

if [ ! -e ./.evergreen ]; then
    echo "Error: run from libmongocrypt root"
    exit 1;
fi

libmongocrypt_root=$(pwd)
linker_tests_root=${libmongocrypt_root}/linker_tests
linker_tests_deps_root=${libmongocrypt_root}/.evergreen/linker_tests_deps

rm -rf linker_tests
mkdir -p linker_tests/{install,libmongocrypt-cmake-build,app-cmake-build}
cd linker_tests

# Make libbson1 and libbson2
$libmongocrypt_root/.evergreen/prep_c_driver_source.sh
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    if [ "$WINDOWS_32BIT" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . "$libmongocrypt_root/.evergreen/find-cmake.sh"
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

git apply --ignore-whitespace "$(system_path $linker_tests_deps_root/bson_patches/libbson1.patch)"
mkdir cmake-build
cd cmake-build
INSTALL_PATH="$(system_path $linker_tests_root/install/bson1)"
SRC_PATH="$(system_path ../)"
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo
# Make libbson2
cd ..
git reset --hard
git apply --ignore-whitespace "$(system_path $linker_tests_deps_root/bson_patches/libbson2.patch)"
LIBBSON2_SRC_DIR="$(system_path "$PWD")"

# Build libmongocrypt, static linking against libbson2
cd $linker_tests_root/libmongocrypt-cmake-build
INSTALL_PATH="$(system_path $linker_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo "-DMONGOCRYPT_MONGOC_DIR=$LIBBSON2_SRC_DIR" $ADDITIONAL_CMAKE_FLAGS -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

echo "Test case: Modelling libmongoc's use"
# app links against libbson1.so
# app links against libmongocrypt.so
cd $linker_tests_root/app-cmake-build
PREFIX_PATH="$(system_path $linker_tests_root/install/bson1);$(system_path $linker_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $linker_tests_deps_root/app)"
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="$PREFIX_PATH" "$SRC_PATH"
$CMAKE --build . --target app --config RelWithDebInfo

if [ "$OS" == "Windows_NT" ]; then
    export PATH="$PATH:$linker_tests_root/install/bson1/bin:$linker_tests_root/install/libmongocrypt/bin"
    APP_CMD="./RelWithDebInfo/app.exe"
else
    APP_CMD="./app"
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
