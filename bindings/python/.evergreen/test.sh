#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    PYTHONS=("C:/python/Python27/python.exe" \
             "C:/python/Python34/python.exe" \
             "C:/python/Python35/python.exe" \
             "C:/python/Python36/python.exe" \
             "C:/python/Python37/python.exe" \
             "C:/python/Python38/python.exe")
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    PYTHONS=("python")
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
    PYTHONS=("/opt/python/2.7/bin/python" \
             "/opt/python/3.4/bin/python3" \
             "/opt/python/3.5/bin/python3" \
             "/opt/python/3.6/bin/python3")
             # Enable when MONGOCRYPT-279 is fixed.
             #"/opt/python/pypy/bin/pypy" \
             #"/opt/python/pypy3.6/bin/pypy3")
fi

for PYTHON_BINARY in "${PYTHONS[@]}"; do
    # Clear cached eggs for different python versions.
    rm -rf .eggs
    $PYTHON_BINARY -c 'import sys; print(sys.version)'

    $PYTHON_BINARY setup.py test
done
