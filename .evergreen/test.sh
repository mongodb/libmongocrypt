#!/bin/sh
# Sets up a testing environment and runs test-mongocrypt.
#
# Assumes the current working directory contains libmongocrypt.
# So script should be called like: ./libmongocrypt/.evergreen/test.sh
# The current working directory should be empty aside from 'libmongocrypt'.
#
# Set the VALGRIND environment variable to "valgrind <opts>" to run through valgrind.
#

set -o errexit
set -o xtrace

evergreen_root="$(pwd)"
. ${evergreen_root}/libmongocrypt/.evergreen/setup-venv.sh

echo "Running tests."
cd libmongocrypt
MONGOCRYPT_TRACE=ON $VALGRIND ./cmake-build/test-mongocrypt
cd ..