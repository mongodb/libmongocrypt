#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_pythons
. .evergreen/utils.sh

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
CRYPT_SHARED_DIR="$DRIVERS_TOOLS"
MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"

# Use the latest toolchain Python, if any qualifies.
PYTHON=$(find_pythons | tail -1)

# pymongo (unreleased master) requires Python 3.11+ (PYTHON-6138). Some
# distros (e.g. rhel82) only provide older interpreters, or none at all
# now that find_pythons requires 3.11+, so provision one with uv.
if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    . "${DRIVERS_TOOLS}/.evergreen/ensure-uv.sh"
    ensure_uv
    uv python install 3.11
    PYTHON=$(uv python find 3.11)
    echo "Using uv-provisioned Python: $PYTHON"
fi

if [ -d "${MONGOCRYPT_DIR}/nocrypto/lib64" ]; then
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so"
else
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so"
fi
export PYMONGOCRYPT_LIB

# $PYTHON is guaranteed to be Python 3.11+ at this point.
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
