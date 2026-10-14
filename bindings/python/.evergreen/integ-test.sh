#! /bin/bash
set -eux

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_pythons
. .evergreen/utils.sh

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
CRYPT_SHARED_DIR="$DRIVERS_TOOLS"
MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"

# Use the latest toolchain Python.
PYTHON=$(find_pythons | tail -1)
if [ -z "$PYTHON" ]; then
    echo "No Python interpreter found!"
    exit 1
fi

if [ -d "${MONGOCRYPT_DIR}/nocrypto/lib64" ]; then
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so"
else
    PYMONGOCRYPT_LIB="${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so"
fi
export PYMONGOCRYPT_LIB

# PyMongo master requires Python 3.11+ (PYTHON-6138), but the newest
# interpreter on some distros is the MongoDB toolchain Python 3.10 (e.g.
# rhel-82-arm64). Provision a modern interpreter with uv in that case.
if "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    createvirtualenv $PYTHON .venv
else
    . "${DRIVERS_TOOLS}/.evergreen/ensure-uv.sh"
    ensure_uv
    uv python install 3.13
    uv venv --seed --python 3.13 .venv
    . .venv/bin/activate
fi
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
