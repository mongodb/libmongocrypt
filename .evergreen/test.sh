#!/bin/bash
#
# Sets up a testing environment and runs test_kms_request and test-mongocrypt.
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

. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh

BIN_DIR=./cmake-build
KMS_BIN_DIR=./cmake-build/kms-message
if [ "Windows_NT" == "$OS" ]; then
    BIN_DIR=./cmake-build/Debug
    KMS_BIN_DIR=./cmake-build/kms-message/Debug
    # Make sure libbson dll is in the path
    export PATH=${INSTALL_PREFIX}/mongo-c-driver/bin:$PATH
fi

echo "Running kms-message tests."
cd libmongocrypt/kms-message
$VALGRIND ../${KMS_BIN_DIR}/test_kms_request
cd ../..

echo "Running libmongocrypt tests."
cd libmongocrypt
MONGOCRYPT_TRACE=ON $VALGRIND ${BIN_DIR}/test-mongocrypt
echo "Running example state machine."
$VALGRIND ${BIN_DIR}/example-state-machine
cd ..
