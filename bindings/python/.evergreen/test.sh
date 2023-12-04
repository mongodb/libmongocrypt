#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# For createvirtualenv.
. .evergreen/utils.sh

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    PYTHONS=("C:/python/Python37/python.exe"
             "C:/python/Python38/python.exe"
             "C:/python/Python39/python.exe"
             "C:/python/Python310/python.exe"
             "C:/python/Python311/python.exe"
             "C:/python/Python312/python.exe")
    export CRYPT_SHARED_PATH=../crypt_shared/bin/mongo_crypt_v1.dll
    C:/python/Python310/python.exe drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    MACOS_VER=$(sw_vers -productVersion)
    if [ $MACOS_VER == "10.14" ]; then
      PYTHONS=("python3"  # Python 3 from brew
               "/Library/Frameworks/Python.framework/Versions/3.7/bin/python3")
    else
          PYTHONS=("python3"  # Python 3 from brew
               "/Library/Frameworks/Python.framework/Versions/3.8/bin/python3"
               "/Library/Frameworks/Python.framework/Versions/3.9/bin/python3"
               "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
               "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3"
               "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
               )
    fi

    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.dylib"
    python3 drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
    PYTHONS=("/opt/python/3.7/bin/python3"
             "/opt/python/3.8/bin/python3"
             "/opt/python/3.9/bin/python3"
             "/opt/python/3.10/bin/python3"
             "/opt/python/3.11/bin/python3"
             "/opt/python/3.12/bin/python3"
            )
    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.so"
    /opt/mongodbtoolchain/v3/bin/python3 drivers-evergreen-tools/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out ../crypt_shared/ --target rhel70
fi


for PYTHON_BINARY in "${PYTHONS[@]}"; do
    echo "Running test with python: $PYTHON_BINARY"
    $PYTHON_BINARY -c 'import sys; print(sys.version)'
    createvirtualenv $PYTHON_BINARY .venv
    python -m pip install --prefer-binary -r test-requirements.txt
    python -m pip install -v -e .
    python -m pytest -v .
    echo "Running tests with CSFLE on dynamic library path..."
    TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=../crypt_shared/lib/:$DYLD_FALLBACK_LIBRARY_PATH \
      LD_LIBRARY_PATH=../crypt_shared/lib:$LD_LIBRARY_PATH \
      PATH=../crypt_shared/bin:$PATH \
      python -m pytest -v .
    deactivate
    rm -rf .venv
done
