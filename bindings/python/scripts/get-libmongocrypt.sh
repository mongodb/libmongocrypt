#!/bin/bash -ex

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# The libmongocrypt git revision release to embed in our wheels.
REVISION=$(git rev-list -n 1 1.8.1)
# The libmongocrypt release branch.
BRANCH="r1.8"
PYTHON_ARCH="${PYTHON_ARCH:-x86_64}"
TARGET=""

if [ "Windows_NT" = "$OS" ]; then 
    TARGET="windows-test"

elif [ "Darwin" = "$(uname -s)" ]; then
    if [ "$PYTHON_ARCH" ==  "x86_64" ]; then 
        TARGET="macos_x86_64"
    else
        TARGET="macos"
    fi
else
    if [ "$PYTHON_ARCH" ==  "x86_64" ]; then 
        TARGET="rhel-70-64-bit"
    elif [ "$PYTHON_ARCH" ==  "ppc64le" ]; then 
        TARGET="rhel-71-ppc64el"
    elif [ "$PYTHON_ARCH" ==  "s390x" ]; then 
        TARGET="rhel72-zseries-test"
    elif [ "$PYTHON_ARCH" ==  "aarch64" ]; then 
        TARGET="ubuntu2204-arm64"
    else 
        echo "Unsupported PYTHON_ARCH: $PYTHON_ARCH for Linux"
    fi
fi

rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/$TARGET/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
mkdir libmongocrypt
tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
NOCRYPTO_SO=libmongocrypt/nocrypto/bin/mongocrypt.dll
chmod +x ${NOCRYPTO_SO}
cp ${NOCRYPTO_SO} pymongocrypt/
rm -rf ./libmongocrypt libmongocrypt.tar.gz
