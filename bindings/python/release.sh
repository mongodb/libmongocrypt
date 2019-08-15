#!/bin/bash -ex

# This script should be run on macOS to create the following distributions:
# pymongocrypt-<version>.tar.gz
# pymongocrypt-<version>-py2.py3-none-manylinux2010_x86_64.whl
# pymongocrypt-<version>-py2.py3-none-macosx_10_9_x86_64.whl

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# Build the source dist first
rm -rf build
python3.7 setup.py sdist

# The libmongocrypt git revision release to embed in our wheels.
REVISION=latest

# Build the manylinux2010 wheel
rm -rf ./libmongocrypt
curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt/rhel-62-64-bit/master/${REVISION}/libmongocrypt.tar.gz
curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt/rhel-62-64-bit/master/latest/libmongocrypt.tar.gz
mkdir libmongocrypt
tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
NOCRYPTO_SO=libmongocrypt/nocrypto/lib64/libmongocrypt.so
chmod +x ${NOCRYPTO_SO}
cp ${NOCRYPTO_SO} pymongocrypt/
rm -rf ./libmongocrypt libmongocrypt.tar.gz

docker run --rm -v `pwd`:/python quay.io/pypa/manylinux2010_x86_64 /python/build-manylinux-wheel.sh

rm -rf pymongocrypt/libmongocrypt.so


# Build the mac wheel
rm -rf ./libmongocrypt
curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt/macos/master/${REVISION}/libmongocrypt.tar.gz
mkdir libmongocrypt
tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
NOCRYPTO_SO=libmongocrypt/nocrypto/lib/libmongocrypt.dylib
chmod +x ${NOCRYPTO_SO}
cp ${NOCRYPTO_SO} pymongocrypt/
rm -rf ./libmongocrypt libmongocrypt.tar.gz

rm -rf build
python3.7 setup.py bdist_wheel

rm -rf pymongocrypt/libmongocrypt.dylib

ls dist
