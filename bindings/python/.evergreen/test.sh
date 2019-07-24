#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# Supported/used environment variables:
#   PYTHON_BINARY           The Python version to use.
PYTHON_BINARY=${PYTHON_BINARY:-"/opt/python/3.6/bin/python3"}

evergreen_root="$(pwd)"/../../..
INSTALL_PREFIX=${evergreen_root}/install/libmongocrypt/lib64

$PYTHON_BINARY -c 'import sys; print(sys.version)'

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$INSTALL_PREFIX $PYTHON_BINARY setup.py test
