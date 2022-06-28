#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# For createvirtualenv.
. .evergreen/utils.sh

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"
git clone git@github.com:mongodb-labs/drivers-evergreen-tools.git

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    PYTHONS=("C:/python/Python27/python.exe"
             "C:/python/Python34/python.exe"
             "C:/python/Python35/python.exe"
             "C:/python/Python36/python.exe"
             "C:/python/Python37/python.exe"
             "C:/python/Python38/python.exe"
             "C:/python/Python39/python.exe"
             "C:/python/Python310/python.exe")
    export CRYPT_SHARED_PATH=../crypt_shared/bin/mongo_crypt_v1.dll
    C:/python/Python310/python.exe drivers-evergreen-tools/.evergreen/mongodl.py --component crypt_shared \
      --version latest --out ../crypt_shared/
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    if [[ $(uname -m) == 'arm64' ]]; then
      PYTHONS=("python3"  # Python 3 from brew
             "/Library/Frameworks/Python.framework/Versions/3.4/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.5/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.6/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.7/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.8/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.9/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3")
    else
      PYTHONS=("python"   # Python 2.7 from brew
             "python3"  # Python 3 from brew
             "/System/Library/Frameworks/Python.framework/Versions/2.7/bin/python"
             "/Library/Frameworks/Python.framework/Versions/3.4/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.5/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.6/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.7/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.8/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.9/bin/python3"
             "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3")
    fi

    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.dylib"
    createvirtualenv python3 .venv
    python -m pip install certifi
    python drivers-evergreen-tools/.evergreen/mongodl.py \
      --component crypt_shared \
      --version latest --out ../crypt_shared/
    deactivate
    rm -rf .venv
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
    PYTHONS=("/opt/python/2.7/bin/python"
             "/opt/python/3.4/bin/python3"
             "/opt/python/3.5/bin/python3"
             "/opt/python/3.6/bin/python3"
             "/opt/python/pypy/bin/pypy"
             "/opt/python/pypy3.6/bin/pypy3")
    export CRYPT_SHARED_PATH="../crypt_shared/lib/mongo_crypt_v1.so"
    /opt/mongodbtoolchain/v3/bin/python3 drivers-evergreen-tools/.evergreen/mongodl.py --component \
      crypt_shared --version latest --out ../crypt_shared/ --target rhel70
fi


for PYTHON_BINARY in "${PYTHONS[@]}"; do
    echo "Running test with python: $PYTHON_BINARY"
    $PYTHON_BINARY -c 'import sys; print(sys.version)'
    createvirtualenv $PYTHON_BINARY .venv
    python -m pip install --prefer-binary -r test-requirements.txt
    python setup.py test
    echo "Running tests with CSFLE on dynamic library path..."
    TEST_CRYPT_SHARED=1 DYLD_FALLBACK_LIBRARY_PATH=../crypt_shared/lib/:$DYLD_FALLBACK_LIBRARY_PATH \
      LD_LIBRARY_PATH=../crypt_shared/lib:$LD_LIBRARY_PATH \
      PATH=../crypt_shared/bin:$PATH \
      python setup.py test
    deactivate
    rm -rf .venv
done
