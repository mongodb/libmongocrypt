#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# libmongocrypt is built by libmongocrypt/.evergreen/compile.sh
evergreen_root="$(cd ../../../; pwd)"

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    PYMONGOCRYPT_LIB=${evergreen_root}/install/libmongocrypt/bin/mongocrypt.dll
    export PYMONGOCRYPT_LIB=$(cygpath -m $PYMONGOCRYPT_LIB)
    # We need to create virtualenvs to install pymongocrypt's
    # cffi, cryptography, and pymongo dependencies correctly from
    # wheels. Otherwise, setup.py attempts and fails to install
    # from the source distributions (.tar.gz).
    /cygdrive/c/python/Python27/python -m virtualenv venv27
    PYTHON27="$(pwd)/venv27/Scripts/python"
    $PYTHON27 -m pip install . pymongo

    /cygdrive/c/python/Python36/python -m virtualenv venv36
    PYTHON36="$(pwd)/venv36/Scripts/python"
    $PYTHON36 -m pip install . pymongo

    # 3.4 supports '-m venv', not '-m virtualenv'.
#    /cygdrive/c/python/Python34/python -m venv venv34
#    PYTHON34="$(pwd)/venv34/Scripts/python"
#    $PYTHON34 -m pip install --upgrade pip
#    $PYTHON34 -m pip install . pymongo

    # 3.5 supports '-m venv', not '-m virtualenv'.
#    /cygdrive/c/python/Python35/python -m venv venv35
#    PYTHON35="$(pwd)/venv35/Scripts/python"
#    $PYTHON35 -m pip install --upgrade pip
#    $PYTHON35 -m pip install . pymongo

    # 3.7 supports '-m venv', not '-m virtualenv'.
    /cygdrive/c/python/Python37/python -m venv venv37
    PYTHON37="$(pwd)/venv37/Scripts/python"
    $PYTHON37 -m pip install --upgrade pip
    $PYTHON37 -m pip install . pymongo

    PYTHONS=("python" \
             "$PYTHON27" \
#             "$PYTHON34" \
#             "$PYTHON35" \
             "$PYTHON36" \
             "$PYTHON37")
elif [ "Darwin" = "$(uname -s)" ]; then
    export PYMONGOCRYPT_LIB=${evergreen_root}/install/libmongocrypt/lib/libmongocrypt.dylib
    PYTHONS=("python")
else
    export PYMONGOCRYPT_LIB=${evergreen_root}/install/libmongocrypt/lib64/libmongocrypt.so
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
