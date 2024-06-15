set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

pushd $(pwd)/libmongocrypt/bindings/python

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone https://github.com/mongodb/mongo-python-driver.git

MACHINE=$(uname -m)
if [ $MACHINE == "aarch64" ]; then
    PYTHON="/opt/mongodbtoolchain/v4/bin/python3"
    TARGET=rhel82
else
    TARGET=rhel80
    PYTHON="/opt/python/3.8/bin/python3"
fi

CRYPT_SHARED_DIR="$(pwd)/crypt_shared"
/opt/mongodbtoolchain/v3/bin/python3 $DRIVERS_TOOLS/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out $CRYPT_SHARED_DIR --target $TARGET

# Get the secrets
bash $DRIVERS_TOOLS/.evergreen/csfle/setup-secrets.sh

if [ -e "${MONGOCRYPT_DIR}/lib64/" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
    PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib64/libmongocrypt.so
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so
    PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib/libmongocrypt.so
fi

createvirtualenv $PYTHON .venv
pip install -e .
echo "Running tests with crypto enabled libmongocrypt..."
PYMONGOCRYPT_LIB=$PYMONGOCRYPT_LIB_CRYPTO python -c 'from pymongocrypt.binding import lib;assert lib.mongocrypt_is_crypto_available(), "mongocrypt_is_crypto_available() returned False"'
pushd mongo-python-driver
pip install -e .
TEST_ENCRYPTION=1 .evergreen/run-tests.sh

echo "Running tests with crypt_shared on dynamic library path..."
TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=$CRYPT_SHARED_DIR/lib/:$DYLD_FALLBACK_LIBRARY_PATH \
    LD_LIBRARY_PATH=$CRYPT_SHARED_DIR/lib:$LD_LIBRARY_PATH \
    PATH=$CRYPT_SHARED_DIR/bin:$PATH TEST_ENCRYPTION=1 \
    .evergreen/run-tests.sh

popd
deactivate
rm -rf .venv
popd