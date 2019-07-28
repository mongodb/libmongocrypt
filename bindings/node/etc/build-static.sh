#!/bin/bash -x

DEPS_PREFIX="$(pwd)/deps"
MONGOC_URL="https://github.com/mongodb/mongo-c-driver/releases/download/1.14.0/mongo-c-driver-1.14.0.tar.gz"
BUILD_DIR=$DEPS_PREFIX/tmp
LIBMONGOCRYPT_DIR="$(pwd)/../../"

# create relevant folders
mkdir -p $DEPS_PREFIX
mkdir -p $BUILD_DIR
mkdir -p $BUILD_DIR/bson-build
mkdir -p $BUILD_DIR/libmongocrypt-build

pushd $BUILD_DIR

# build and install bson
wget $MONGOC_URL
tar xzf mongo-c-driver-1.14.0.tar.gz

pushd bson-build
cmake -DENABLE_MONGOC=OFF -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX ../mongo-c-driver-1.14.0
make -j8 install
popd

# build and install libmongocrypt
pushd libmongocrypt-build
cmake -DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX $LIBMONGOCRYPT_DIR
make -j8 install
popd

# build the `mongodb-client-encryption` addon
BUILD_TYPE=static npm install
