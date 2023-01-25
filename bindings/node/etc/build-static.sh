#!/usr/bin/env bash

set -o errexit

THIS_DIR="$(dirname "${BASH_SOURCE[0]}")"
. "$THIS_DIR/../../../.evergreen/init.sh"

NODE_DIR="$(abspath "$THIS_DIR/..")"

DEPS_PREFIX="$NODE_DIR/deps"
BUILD_DIR=$DEPS_PREFIX/tmp
: "${CMAKE_FLAGS:=}"
: "${WINDOWS_CMAKE_FLAGS:=}"
: "${NPM_OPTIONS:=}"

export NPM_OPTIONS="${NPM_OPTIONS}"

# build and install libmongocrypt
mkdir -p $BUILD_DIR/libmongocrypt-build
pushd $BUILD_DIR/libmongocrypt-build  #./deps/tmp/libmongocrypt-build

CMAKE_FLAGS="-DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"
if [ "$OS_NAME" == "windows" ]; then
  if [ "${WINDOWS_32BIT-}" != "ON" ]; then
    WINDOWS_CMAKE_FLAGS="-Thost=x64 -A x64 -DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
  else
    WINDOWS_CMAKE_FLAGS="-DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
  fi
  run_cmake $CMAKE_FLAGS $WINDOWS_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="$(native_path "$DEPS_PREFIX")" -DCMAKE_INSTALL_PREFIX="$(native_path "$DEPS_PREFIX")" "$(native_path "$LIBMONGOCRYPT_DIR")"
else
  run_cmake $CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX -DCMAKE_OSX_DEPLOYMENT_TARGET="10.12" $LIBMONGOCRYPT_DIR
fi

run_cmake --build . --target install --config RelWithDebInfo

popd #./

# build the `mongodb-client-encryption` addon
env BUILD_TYPE=static npm install
