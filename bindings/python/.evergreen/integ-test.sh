#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"

if [ -e "${MONGOCRYPT_DIR}/lib64/" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/lib64/libmongocrypt.so
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/lib/libmongocrypt.so
fi

createvirtualenv $BASE_PYTHON .venv
pip install -e .
pushd $PYMONGO_DIR
python -c 'from pymongocrypt.binding import lib;assert lib.mongocrypt_is_crypto_available(), "mongocrypt_is_crypto_available() returned False"'
pip install -e ".[test,encryption]"
source ${DRIVERS_TOOLS}/.evergreen/csfle/secrets-export.sh
set -x
AUTH=auth SSL=ssl .evergreen/run-tests.sh -m encryption

popd
deactivate
rm -rf .venv
popd
