#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# For createvirtualenv and find_python3
. .evergreen/utils.sh

BASE_PYTHON=$(find_python3)

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    PYMONGOCRYPT_LIB_CRYPTO=$(cygpath -m ${MONGOCRYPT_DIR}/bin/mongocrypt.dll)
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    PYTHONS=("C:/python/Python38/python.exe"
             "C:/python/Python39/python.exe"
             "C:/python/Python310/python.exe"
             "C:/python/Python311/python.exe"
             "C:/python/Python312/python.exe")
    export CRYPT_SHARED_PATH=../crypt_shared/bin/mongo_crypt_v1.dll
    C:/python/Python310/python.exe drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    PYMONGOCRYPT_LIB_CRYPTO=${MONGOCRYPT_DIR}/lib/libmongocrypt.dylib
    PYTHONS=(
          "/Library/Frameworks/Python.framework/Versions/3.9/bin/python3"
          "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
          "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3"
          "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
          )

    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.dylib"
    python3 drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
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
    MACHINE=$(uname -m)
    if [ $MACHINE == "aarch64" ]; then
        PYTHONS=("/opt/mongodbtoolchain/v3/bin/python3"
          "/opt/mongodbtoolchain/v4/bin/python3"
        )
    else
        PYTHONS=("/opt/python/3.8/bin/python3"
          "/opt/python/3.9/bin/python3"
          "/opt/python/3.10/bin/python3"
          "/opt/python/3.11/bin/python3"
          "/opt/python/3.12/bin/python3"
          "/opt/python/3.13/bin/python3"
        )
    fi
    /opt/mongodbtoolchain/v3/bin/python3 drivers-evergreen-tools/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out ../crypt_shared/
fi

for PYTHON_BINARY in "${PYTHONS[@]}"; do
    echo "Running test with python: $PYTHON_BINARY"
    $PYTHON_BINARY -c 'import sys; print(sys.version)'
    git clean -dffx
    createvirtualenv $PYTHON_BINARY .venv
    python -m pip install --prefer-binary -v -e ".[test]"
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
  echo "SBOM is out of date! Run the \"update-sbom.sh\" script."
  exit 1
fi
