#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# MONGOCRYPT_DIR is set by libmongocrypt/.evergreen/config.yml
MONGOCRYPT_DIR="$MONGOCRYPT_DIR"

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/bin/mongocrypt.dll
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    # We need to create virtualenvs to install pymongocrypt's
    # cffi, cryptography, and pymongo dependencies correctly from
    # wheels. Otherwise, setup.py attempts and fails to install
    # from the source distributions (.tar.gz).
    VIRTUALENV="/cygdrive/c/python/Python27/python -m virtualenv"
    $VIRTUALENV -p C:/python/Python27/python.exe venv27
    PYTHON27="$(pwd)/venv27/Scripts/python"
    # Upgrade pip to install the cryptography wheel and not the tar.
    # <20.1 because 20.0.2 says a future release may drop support for 2.7.
    $PYTHON27 -m pip install --upgrade 'pip<20.1'
    # Upgrade setuptools because cryptography requires 18.5+.
    # <45 because 45.0 dropped support for 2.7.
    $PYTHON27 -m pip install --upgrade 'setuptools<45'
    $PYTHON27 -m pip install . pymongo

    $VIRTUALENV -p C:/python/Python34/python.exe venv34
    PYTHON34="$(pwd)/venv34/Scripts/python"
    # Upgrade pip to install the cryptography wheel and not the tar.
    # <19.2 because 19.2 dropped support for 3.4.
    $PYTHON34 -m pip install --upgrade 'pip<19.2'
    $PYTHON34 -m pip install . pymongo

    $VIRTUALENV -p C:/python/Python35/python.exe venv35
    PYTHON35="$(pwd)/venv35/Scripts/python"
    $PYTHON35 -m pip install --upgrade pip
    $PYTHON35 -m pip install . pymongo

    $VIRTUALENV -p C:/python/Python36/python.exe venv36
    PYTHON36="$(pwd)/venv36/Scripts/python"
    $PYTHON36 -m pip install --upgrade pip
    $PYTHON36 -m pip install . pymongo

    $VIRTUALENV -p C:/python/Python37/python.exe venv37
    PYTHON37="$(pwd)/venv37/Scripts/python"
    $PYTHON37 -m pip install --upgrade pip
    $PYTHON37 -m pip install . pymongo

    $VIRTUALENV -p C:/python/Python38/python.exe venv38
    PYTHON38="$(pwd)/venv38/Scripts/python"
    $PYTHON38 -m pip install --upgrade pip
    $PYTHON38 -m pip install . pymongo

    PYTHONS=("python" \
             "$PYTHON27" \
             "$PYTHON34" \
             "$PYTHON35" \
             "$PYTHON36" \
             "$PYTHON37" \
             "$PYTHON38")
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib/libmongocrypt.dylib
    PYTHONS=("python")
else
    export PYMONGOCRYPT_LIB=${MONGOCRYPT_DIR}/nocrypto/lib64/libmongocrypt.so
    PYTHONS=("/opt/python/2.7/bin/python" \
             "/opt/python/3.4/bin/python3" \
             "/opt/python/3.5/bin/python3" \
             "/opt/python/3.6/bin/python3" \
             "/opt/python/pypy/bin/pypy" \
             "/opt/python/pypy3.6/bin/pypy3")
fi

for PYTHON_BINARY in "${PYTHONS[@]}"; do
    # Clear cached eggs for different python versions.
    rm -rf .eggs
    $PYTHON_BINARY -c 'import sys; print(sys.version)'

    $PYTHON_BINARY setup.py test
done
