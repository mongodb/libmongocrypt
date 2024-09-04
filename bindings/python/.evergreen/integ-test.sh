#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"

if [ -e "${MONGOCRYPT_DIR}/lib64/" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so
fi

createvirtualenv $PYTHON .venv
pip install -e .
pushd $PYMONGO_DIR
pip install -e ".[test,encryption]"
source ${DRIVERS_TOOLS}/.evergreen/csfle/secrets-export.sh
set -x
DYLD_FALLBACK_LIBRARY_PATH=$CRYPT_SHARED_DIR/lib/:${DYLD_FALLBACK_LIBRARY_PATH:-} \
    LD_LIBRARY_PATH=$CRYPT_SHARED_DIR/lib:${LD_LIBRARY_PATH-} \
    PATH=$CRYPT_SHARED_DIR/bin:$PATH \
    AUTH=auth SSL=ssl \
    .evergreen/run-tests.sh -m encryption

popd
deactivate
rm -rf .venv
popd
