#!/bin/bash -ex

# The libmongocrypt git revision release to embed in our wheels.
REVISION=$(git rev-list -n 1 1.5.0)
# The libmongocrypt release branch.
BRANCH="r1.5"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

# Clear any current binary files.
rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib


# Build the Windows wheel
if [ "windows" = "$LIBMONGOCRYPT_TARGET" ]; then
    DOWNLOAD_TARGET="windows-test"
    NOCRYPTO_SO=libmongocrypt/nocrypto/bin/mongocrypt.dll
elif [ "macos" = "$LIBMONGOCRYPT_TARGET" ]; then
    DOWNLOAD_TARGET="macos"
    NOCRYPTO_SO=libmongocrypt/nocrypto/lib/libmongocrypt.dylib
elif [ "linux" = "$LIBMONGOCRYPT_TARGET" ]; then
    DOWNLOAD_TARGET="rhel-62-64-bit"
    NOCRYPTO_SO=libmongocrypt/nocrypto/lib64/libmongocrypt.so
else
    echo "ERROR: Unknown LIBMONGOCRYPT_TARGET"
   exit 1
fi

curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/$DOWNLOAD_TARGET/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
mkdir libmongocrypt
tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
chmod +x ${NOCRYPTO_SO}
cp ${NOCRYPTO_SO} pymongocrypt/
rm -rf ./libmongocrypt libmongocrypt.tar.gz
