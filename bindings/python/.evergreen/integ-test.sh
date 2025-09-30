#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
CRYPT_SHARED_DIR="$DRIVERS_TOOLS"
MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"

MACHINE=$(uname -m)
if [ $MACHINE == "aarch64" ]; then
    PYTHON="/opt/mongodbtoolchain/v4/bin/python3"
else
    PYTHON="/opt/python/3.13/bin/python3"
fi

if [ -d "${MONGOCRYPT_DIR}/nocrypto/lib64" ]; then
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so"
else
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so"
fi
export PYMONGOCRYPT_LIB

createvirtualenv $PYTHON .venv
pip install -e .
pip install uv
pushd $PYMONGO_DIR
pip install -e ".[test,encryption]"
source ${DRIVERS_TOOLS}/.evergreen/csfle/secrets-export.sh
set -x
export DB_USER="bob"
export DB_PASSWORD="pwd123"
export CLIENT_PEM="$DRIVERS_TOOLS/.evergreen/x509gen/client.pem"
export CA_PEM="$DRIVERS_TOOLS/.evergreen/x509gen/ca.pem"
export DYLD_FALLBACK_LIBRARY_PATH=$CRYPT_SHARED_DIR:${DYLD_FALLBACK_LIBRARY_PATH:-}
export LD_LIBRARY_PATH=$CRYPT_SHARED_DIR:${LD_LIBRARY_PATH-}
export PATH=$CRYPT_SHARED_DIR:$MONGODB_BINARIES:$PATH
export TEST_CRYPT_SHARED="1"
pytest --maxfail=10 -v -m encryption

# Now test with stable pymongo.
pip uninstall -y pymongo
pip install pymongo
pytest --maxfail=10 -v -m encryption

popd
deactivate
rm -rf .venv
popd
