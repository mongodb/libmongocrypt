set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone https://github.com/mongodb/mongo-python-driver.git
DRIVERS_TOOLS=$(pwd)/drivers-evergreen-tools

/opt/mongodbtoolchain/v3/bin/python3 $DRIVERS_TOOLS/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out ../crypt_shared/ --target rhel80

# Get the secrets
bash $DRIVERS_TOOLS/.evergreen/csfle/setup-secrets.sh

ROOT=$(pwd)/..

git clean -dffx
createvirtualenv /opt/python/3.9/bin/python3 .venv
pip install -e .
echo "Running tests with crypto enabled libmongocrypt..."
PYMONGOCRYPT_LIB=$PYMONGOCRYPT_LIB_CRYPTO python -c 'from pymongocrypt.binding import lib;assert lib.mongocrypt_is_crypto_available(), "mongocrypt_is_crypto_available() returned False"'
pushd mongo-python-driver
pip install -e .
TEST_ENCRYPTION=1 .evergreen/run_test.sh

echo "Running tests with crypt_shared on dynamic library path..."
TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=$ROOT/crypt_shared/lib/:$DYLD_FALLBACK_LIBRARY_PATH \
    LD_LIBRARY_PATH=$ROOT/crypt_shared/lib:$LD_LIBRARY_PATH \
    PATH=$ROOT/crypt_shared/bin:$PATH TEST_ENCRYPTION=1 \
    .evergreen/run_test.sh

popd
deactivate
rm -rf .venv
