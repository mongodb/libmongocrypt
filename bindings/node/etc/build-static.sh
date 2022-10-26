#!/usr/bin/env bash -x

DEPS_PREFIX="$(pwd)/deps"
BUILD_DIR=$DEPS_PREFIX/tmp
LIBMONGOCRYPT_DIR="$(pwd)/../../"
TOP_DIR="$(pwd)/../../../"

export NPM_OPTIONS="${NPM_OPTIONS}"

if [[ -z $CMAKE ]]; then
  CMAKE=`type -P cmake`
fi

# build and install libmongocrypt
mkdir -p $BUILD_DIR/libmongocrypt-build
pushd $BUILD_DIR/libmongocrypt-build  #./deps/tmp/libmongocrypt-build

CMAKE_FLAGS="-DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"
if [ "$OS" == "Windows_NT" ]; then
  if [ "$WINDOWS_32BIT" != "ON" ]; then
    WINDOWS_CMAKE_FLAGS="-Thost=x64 -A x64 -DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
  else
    WINDOWS_CMAKE_FLAGS="-DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
  fi
  $CMAKE $CMAKE_FLAGS $WINDOWS_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="`cygpath -w $DEPS_PREFIX`" -DCMAKE_INSTALL_PREFIX="`cygpath -w $DEPS_PREFIX`" "`cygpath -w $LIBMONGOCRYPT_DIR`"
else
  $CMAKE $CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX -DCMAKE_OSX_DEPLOYMENT_TARGET="10.12" $LIBMONGOCRYPT_DIR
fi

$CMAKE --build . --target install --config RelWithDebInfo

popd #./

# build the `mongodb-client-encryption` addon
# note the --unsafe-perm parameter to make the build work
# when running as root. See https://github.com/npm/npm/issues/3497
BUILD_TYPE=static npm install --unsafe-perm --build-from-source ${NPM_OPTIONS}
