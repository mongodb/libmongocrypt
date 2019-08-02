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

# Copied from the mongo-c-driver
find_cmake ()
{
  if [ ! -z "$CMAKE" ]; then
    return 0
  elif [ -f "/Applications/cmake-3.2.2-Darwin-x86_64/CMake.app/Contents/bin/cmake" ]; then
    CMAKE="/Applications/cmake-3.2.2-Darwin-x86_64/CMake.app/Contents/bin/cmake"
  elif [ -f "/Applications/Cmake.app/Contents/bin/cmake" ]; then
    CMAKE="/Applications/Cmake.app/Contents/bin/cmake"
  elif [ -f "/opt/cmake/bin/cmake" ]; then
    CMAKE="/opt/cmake/bin/cmake"
  elif command -v cmake 2>/dev/null; then
     CMAKE=cmake
  elif uname -a | grep -iq 'x86_64 GNU/Linux'; then
     curl --retry 5 https://cmake.org/files/v3.11/cmake-3.11.0-Linux-x86_64.tar.gz -sS --max-time 120 --fail --output cmake.tar.gz
     mkdir cmake-3.11.0
     tar xzf cmake.tar.gz -C cmake-3.11.0 --strip-components=1
     CMAKE=$(pwd)/cmake-3.11.0/bin/cmake
  fi
  if [ -z "$CMAKE" -o -z "$( $CMAKE --version 2>/dev/null )" ]; then
     # Some images have no cmake yet, or a broken cmake (see: BUILD-8570)
     echo "-- MAKE CMAKE --"
     CMAKE_INSTALL_DIR=$(readlink -f cmake-install)
     curl --retry 5 https://cmake.org/files/v3.11/cmake-3.11.0.tar.gz -sS --max-time 120 --fail --output cmake.tar.gz
     tar xzf cmake.tar.gz
     cd cmake-3.11.0
     ./bootstrap --prefix="${CMAKE_INSTALL_DIR}"
     make -j8
     make install
     cd ..
     CMAKE="${CMAKE_INSTALL_DIR}/bin/cmake"
     echo "-- DONE MAKING CMAKE --"
  fi
}

find_cmake

pushd $DEPS_PREFIX #./deps
pushd $BUILD_DIR #./deps/tmp

# build and install bson
curl -L -o mongo-c-driver-1.14.0.tar.gz $MONGOC_URL
tar xzf mongo-c-driver-1.14.0.tar.gz

pushd bson-build #./deps/tmp/bson-build
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX ../mongo-c-driver-1.14.0
make -j8 install
popd #./deps/tmp

# build and install libmongocrypt
pushd libmongocrypt-build #./deps/tmp/libmongocrypt-build
$CMAKE -DDISABLE_NATIVE_CRYPTO=1 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH=$DEPS_PREFIX -DCMAKE_INSTALL_PREFIX=$DEPS_PREFIX $LIBMONGOCRYPT_DIR
  make -j8 install
popd #./deps/tmp

popd #./deps

# We need all built files to exist in lib.
# Sometimes on linux systems they get installed to lib64 instead,
# so we need to copy them over
if [ -d lib64 ]
then
  cp -R lib64/* lib/
fi

# build the `mongodb-client-encryption` addon
# note the --unsafe-perm parameter to make the build work
# when running as root. See https://github.com/npm/npm/issues/3497
BUILD_TYPE=static npm install --unsafe-perm
