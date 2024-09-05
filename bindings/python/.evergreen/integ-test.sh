#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
# MONGOCRYPT_DIR="$MONGOCRYPT_DIR"

MACHINE=$(uname -m)
if [ $MACHINE == "aarch64" ]; then
    PYTHON="/opt/mongodbtoolchain/v4/bin/python3"
    TARGET_CRYPT=rhel82
    TARGET_LIB=rhel-82-arm64
else
    TARGET_CRYPT=rhel80
    TARGET_LIB=rhel-80-64-bit
    PYTHON="/opt/python/3.13/bin/python3"
fi
LIBMONGOCRYPT_URL="https://s3.amazonaws.com/mciuploads/libmongocrypt/$TARGET_LIB/master/latest/libmongocrypt.tar.gz"
curl -O "$LIBMONGOCRYPT_URL"
mkdir libmongocrypt
tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
MONGOCRYPT_DIR=./libmongocrypt/nocrypto
BASE=$(pwd)/libmongocrypt/nocrypto
if [ -f "${BASE}/lib/libmongocrypt.so" ]; then
    PYMONGOCRYPT_LIB=${BASE}/lib/libmongocrypt.so
elif [ -f "${BASE}/lib/libmongocrypt.dylib" ]; then
    PYMONGOCRYPT_LIB=${BASE}/lib/libmongocrypt.dylib
elif [ -f "${BASE}/bin/mongocrypt.dll" ]; then
    PYMONGOCRYPT_LIB=${BASE}/bin/mongocrypt.dll
    # libmongocrypt's windows dll is not marked executable.
    chmod +x $PYMONGOCRYPT_LIB
    PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
elif [ -f "${BASE}/lib64/libmongocrypt.so" ]; then
    PYMONGOCRYPT_LIB=${BASE}/lib64/libmongocrypt.so
else
    echo "Cannot find libmongocrypt shared object file"
    exit 1
fi
export PYMONGOCRYPT_LIB

CRYPT_SHARED_DIR="$DRIVERS_TOOLS"
ls -ls $CRYPT_SHARED_DIR

createvirtualenv $PYTHON .venv
pip install -e .
pushd $PYMONGO_DIR
pip install -e ".[test,encryption]"
source ${DRIVERS_TOOLS}/.evergreen/csfle/secrets-export.sh
set -x
TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=$CRYPT_SHARED_DIR:${DYLD_FALLBACK_LIBRARY_PATH:-} \
    LD_LIBRARY_PATH=$CRYPT_SHARED_DIR:${LD_LIBRARY_PATH-} \
    PATH=$CRYPT_SHARED_DIR:$PATH \
    AUTH=auth SSL=ssl \
    .evergreen/run-tests.sh -m encryption

popd
deactivate
rm -rf .venv
popd
