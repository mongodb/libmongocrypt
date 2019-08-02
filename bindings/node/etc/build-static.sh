#!/usr/bin/env bash -x

DEPS_PREFIX="$(pwd)/deps"
MONGOC_URL="https://github.com/mongodb/mongo-c-driver/releases/download/1.14.0/mongo-c-driver-1.14.0.tar.gz"
BUILD_DIR=$DEPS_PREFIX/tmp
LIBMONGOCRYPT_DIR="$(pwd)/../../"

if [[ -z $CMAKE ]]; then
  CMAKE=`which cmake`
fi

# create relevant folders
mkdir -p $DEPS_PREFIX
mkdir -p $BUILD_DIR
mkdir -p $BUILD_DIR/bson-build
mkdir -p $BUILD_DIR/libmongocrypt-build

pushd $DEPS_PREFIX #./deps
pushd $BUILD_DIR #./deps/tmp

# build and install bson
curl -L -o mongo-c-driver-1.14.0.tar.gz $MONGOC_URL
tar xzf mongo-c-driver-1.14.0.tar.gz

# NOTE: we are setting -DCMAKE_INSTALL_LIBDIR=lib to ensure that the built 
# files are always installed to lib instead of alternate directories like
# lib64.
# NOTE: On OSX, -DCMAKE_OSX_DEPLOYMENT_TARGET can be set to an OSX version
# to suppress build warnings. However, doing that tends to break some
# of the versions that can be built

pushd bson-build #./deps/tmp/bson-build
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX -DCMAKE_INSTALL_LIBDIR=lib ../mongo-c-driver-1.14.0
make -j8 install
popd #./deps/tmp

# build and install libmongocrypt
pushd libmongocrypt-build #./deps/tmp/libmongocrypt-build
$CMAKE -DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX  -DCMAKE_INSTALL_LIBDIR=lib $LIBMONGOCRYPT_DIR
  make -j8 install
popd #./deps/tmp

popd #./deps
popd #./

# build the `mongodb-client-encryption` addon
# note the --unsafe-perm parameter to make the build work
# when running as root. See https://github.com/npm/npm/issues/3497
BUILD_TYPE=static npm install --unsafe-perm --build-from-source
