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
$libmongocrypt_root/clone-mongo-c-driver.sh
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

git apply --ignore-whitespace "$(system_path $linker_tests_deps_root/bson_patches/libbson1.patch)"
mkdir cmake-build
cd cmake-build
INSTALL_PATH="$(system_path $linker_tests_root/install/bson1)"
SRC_PATH="$(system_path ../)"
$CMAKE -DBUILD_VERSION=1.18.0-pre -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo
# Make libbson2
cd ..
git reset --hard
git apply --ignore-whitespace "$(system_path $linker_tests_deps_root/bson_patches/libbson2.patch)"
cd cmake-build
INSTALL_PATH="$(system_path $linker_tests_root/install/bson2)"
SRC_PATH="$(system_path ../)"
$CMAKE -DBUILD_VERSION=1.18.0-pre -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

# Build libmongocrypt, static linking against libbson2
cd $linker_tests_root/libmongocrypt-cmake-build
PREFIX_PATH="$(system_path $linker_tests_root/install/bson2)"
INSTALL_PATH="$(system_path $linker_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="$PREFIX_PATH" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
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
        echo "got '$output', expecting '$1'"
        exit 1;
    fi
    echo "ok"
}
check_output ".calling bson_malloc0..from libbson1..calling mongocrypt_binary_new..from libbson2."
exit 0
