#!/bin/bash

# Test the Python bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# Supported/used environment variables:
#   PYTHON_BINARY           The Python version to use. Defaults to "/opt/python/2.7/bin/python"
PYTHON_BINARY=${PYTHON_BINARY:-"/opt/python/2.7/bin/python"}

$PYTHON_BINARY -c 'import sys; print(sys.version)'

$PYTHON_BINARY setup.py test
