#!/usr/bin/env bash -x

DEPS_PREFIX="$(pwd)/deps"
BUILD_DIR=$DEPS_PREFIX/tmp
LIBMONGOCRYPT_DIR="$(pwd)/../../"
TOP_DIR="$(pwd)/../../../"

if [[ -z $CMAKE ]]; then
  CMAKE=`which cmake`
fi

# create relevant folders
mkdir -p $DEPS_PREFIX
mkdir -p $BUILD_DIR
mkdir -p $BUILD_DIR/libmongocrypt-build

export BSON_INSTALL_PREFIX=$DEPS_PREFIX
export MONGOCRYPT_INSTALL_PREFIX=$DEPS_PREFIX

pushd $DEPS_PREFIX #./deps
pushd $BUILD_DIR #./deps/tmp

pushd $TOP_DIR
# build and install bson

# NOTE: we are setting -DCMAKE_INSTALL_LIBDIR=lib to ensure that the built
# files are always installed to lib instead of alternate directories like
# lib64.
# NOTE: On OSX, -DCMAKE_OSX_DEPLOYMENT_TARGET can be set to an OSX version
# to suppress build warnings. However, doing that tends to break some
# of the versions that can be built
export BSON_EXTRA_CMAKE_FLAGS="-DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_OSX_DEPLOYMENT_TARGET=\"10.12\""
if [ "$OS" == "Windows_NT" ]; then
  export BSON_EXTRA_CMAKE_FLAGS="${BSON_EXTRA_CMAKE_FLAGS} -DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
fi

. ${TOP_DIR}/libmongocrypt/.evergreen/build_install_bson.sh

popd #./deps/tmp

# build and install libmongocrypt
pushd libmongocrypt-build #./deps/tmp/libmongocrypt-build

CMAKE_FLAGS="-DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_C_FLAGS=\"-fPIC\" -DCMAKE_INSTALL_LIBDIR=lib "
if [ "$OS" == "Windows_NT" ]; then
  WINDOWS_CMAKE_FLAGS="-Thost=x64 -A x64 -DCMAKE_C_FLAGS_RELWITHDEBINFO=\"/MT\""
  $CMAKE $CMAKE_FLAGS $WINDOWS_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="`cygpath -w $DEPS_PREFIX`" -DCMAKE_INSTALL_PREFIX="`cygpath -w $DEPS_PREFIX`" "`cygpath -w $LIBMONGOCRYPT_DIR`"
else
  $CMAKE $CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX -DCMAKE_OSX_DEPLOYMENT_TARGET="10.12" $LIBMONGOCRYPT_DIR
fi

$CMAKE --build . --target install --config RelWithDebInfo

popd #./deps/tmp

popd #./deps
popd #./

# build the `mongodb-client-encryption` addon
# note the --unsafe-perm parameter to make the build work
# when running as root. See https://github.com/npm/npm/issues/3497
BUILD_TYPE=static npm install --unsafe-perm --build-from-source
