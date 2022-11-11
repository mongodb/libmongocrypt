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

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

linker_tests_root="$LIBMONGOCRYPT_DIR/linker_tests"
linker_tests_deps_root="$EVG_DIR/linker_tests_deps"

rm -rf -- "$linker_tests_root"
mkdir -p "$linker_tests_root"/{install,libmongocrypt-cmake-build,app-cmake-build}

# Make libbson1
run_chdir "$linker_tests_root" bash "$EVG_DIR/prep_c_driver_source.sh"
MONGOC_DIR="$linker_tests_root/mongo-c-driver"

if test "$OS_NAME" = "windows" && is_false WINDOWS_32BIT && is_false USE_NINJA; then
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
fi

if [ "${MACOS_UNIVERSAL-}" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

common_cmake_args=(
  $ADDITIONAL_CMAKE_FLAGS
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
)

if is_true USE_NINJA; then
    export NINJA_EXE
    : "${NINJA_EXE:="$linker_tests_root/ninja$EXE_SUFFIX"}"
    common_cmake_args+=(
        -GNinja
        -DCMAKE_MAKE_PROGRAM="$NINJA_EXE"
    )
    bash "$EVG_DIR/ensure-ninja.sh"
fi

run_chdir "$MONGOC_DIR" git apply --ignore-whitespace "$linker_tests_deps_root/bson_patches/libbson1.patch"

BUILD_PATH="$MONGOC_DIR/cmake-build"
BSON1_INSTALL_PATH="$linker_tests_root/install/bson1"
SRC_PATH="$MONGOC_DIR"
run_cmake \
  -DENABLE_MONGOC=OFF \
  "${common_cmake_args[@]}" \
  -DCMAKE_INSTALL_PREFIX="$BSON1_INSTALL_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_PATH"
run_cmake --build "$BUILD_PATH" --target install --config RelWithDebInfo

# Prepare libbson2
run_chdir "$MONGOC_DIR" git reset --hard
run_chdir "$MONGOC_DIR" git apply --ignore-whitespace "$linker_tests_deps_root/bson_patches/libbson2.patch"
LIBBSON2_SRC_DIR="$MONGOC_DIR"

# Build libmongocrypt, static linking against libbson2
BUILD_DIR="$linker_tests_root/libmongocrypt-cmake-build"
LMC_INSTALL_PATH="$linker_tests_root/install/libmongocrypt"
SRC_PATH="$LIBMONGOCRYPT_DIR"
run_cmake \
  "-DMONGOCRYPT_MONGOC_DIR=$LIBBSON2_SRC_DIR" \
  "${common_cmake_args[@]}" \
  -DCMAKE_INSTALL_PREFIX="$LMC_INSTALL_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_DIR"
run_cmake --build "$BUILD_DIR" --target install --config RelWithDebInfo

echo "Test case: Modelling libmongoc's use"
# app links against libbson1.so
# app links against libmongocrypt.so
BUILD_DIR="$linker_tests_root/app-cmake-build"
PREFIX_PATH="$LMC_INSTALL_PATH;$BSON1_INSTALL_PATH"
SRC_PATH="$linker_tests_deps_root/app"
run_cmake \
  "${common_cmake_args[@]}" \
  -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
  "-H$SRC_PATH" \
  "-B$BUILD_DIR"
run_cmake --build "$BUILD_DIR" --target app --config RelWithDebInfo

export PATH="$PATH:$BSON1_INSTALL_PATH/bin:$LMC_INSTALL_PATH/bin"
if is_true IS_MULTICONF; then
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
