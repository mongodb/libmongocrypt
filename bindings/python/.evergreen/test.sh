#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# For createvirtualenv and find_pythons
. .evergreen/utils.sh

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git

# Discover the toolchain pythons to test against.
PYTHONS=($(find_pythons))
if [ ${#PYTHONS[@]} -eq 0 ]; then
    echo "No Python interpreters found to test with!"
    exit 1
fi
echo "Testing with pythons: ${PYTHONS[*]}"

# Use the latest for the mongodl.py invocation.
BASE_PYTHON=$(find_pythons | tail -1)

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    PYMONGOCRYPT_LIB_CRYPTO=$(cygpath -m ${MONGOCRYPT_DIR}/bin/mongocrypt.dll)
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    export CRYPT_SHARED_PATH=../crypt_shared/bin/mongo_crypt_v1.dll
    "$BASE_PYTHON" drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib/libmongocrypt.dylib
    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.dylib"
    "$BASE_PYTHON" drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
else
    if [ -e "${MONGOCRYPT_DIR}/lib64/" ]; then
        export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
        PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib64/libmongocrypt.so
    else
        export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.so
        PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib/libmongocrypt.so
    fi

    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.so"
    "$BASE_PYTHON" drivers-evergreen-tools/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out ../crypt_shared/
fi

for PYTHON_BINARY in "${PYTHONS[@]}"; do
    echo "Running test with python: $PYTHON_BINARY"
    $PYTHON_BINARY -c 'import sys; print(sys.version)'
    git clean -dffx
    createvirtualenv $PYTHON_BINARY .venv
    python -m pip install --prefer-binary -v -e ".[test]" || python -m pip install --pre --prefer-binary -v -e ".[test]"
    echo "Running tests with crypto enabled libmongocrypt..."
    PYMONGOCRYPT_LIB=$PYMONGOCRYPT_LIB_CRYPTO python -c 'from pymongocrypt.binding import lib;assert lib.mongocrypt_is_crypto_available(), "mongocrypt_is_crypto_available() returned False"'
    PYMONGOCRYPT_LIB=$PYMONGOCRYPT_LIB_CRYPTO python -m pytest -v --ignore=test/performance .
    echo "Running tests with crypt_shared on dynamic library path..."
    TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=../crypt_shared/lib/:$DYLD_FALLBACK_LIBRARY_PATH \
      LD_LIBRARY_PATH=../crypt_shared/lib:$LD_LIBRARY_PATH \
      PATH=../crypt_shared/bin:$PATH \
      python -m pytest -v --ignore=test/performance .
    deactivate
    rm -rf .venv
done

# Verify the sbom file
LIBMONGOCRYPT_VERSION=$(cat ./scripts/libmongocrypt-version.txt)
EXPECTED="pkg:github/mongodb/libmongocrypt@$LIBMONGOCRYPT_VERSION"
if grep -q $EXPECTED sbom.json; then
  echo "SBOM is up to date!"
else
  echo "SBOM is out of date! Run the \"scripts/update-version.sh\" script."
  exit 1
fi
