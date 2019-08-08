#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# This library is built by libmongocrypt/.evergreen/compile.sh
evergreen_root="$(cd ../../../; pwd)"
export PYMONGOCRYPT_LIB=${evergreen_root}/install/libmongocrypt/lib64/libmongocrypt.so

PYTHONS=("/opt/python/2.7/bin/python" \
         "/opt/python/3.4/bin/python3" \
         "/opt/python/3.5/bin/python3" \
         "/opt/python/3.6/bin/python3" \
#         "/opt/python/pypy/bin/pypy" \  # TODO: PyPy segfaults on RHEL 6.2
         "/opt/python/pypy3.6/bin/pypy3")

for PYTHON_BINARY in "${PYTHONS[@]}"; do
    $PYTHON_BINARY -c 'import sys; print(sys.version)'

    $PYTHON_BINARY setup.py test
done
