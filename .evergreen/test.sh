#!/bin/sh
# Sets up a testing environment and runs test-mongocrypt.
#
# Assumes the current working directory contains libmongocrypt.
# So script should be called like: ./libmongocrypt/.evergreen/test.sh
# The current working directory should be empty aside from 'libmongocrypt'.
#

set -o errexit
set -o xtrace

evergreen_root="$(pwd)"
. ${evergreen_root}/libmongocrypt/.evergreen/setup-venv.sh

# Turn off tracing when starting mongo orchestration -- it's a lot of unhelpful logs.
set +o xtrace
echo "Starting MongoDB replica set."
git clone --depth=1 git@github.com:mongodb-labs/drivers-evergreen-tools.git
chmod u+x ./drivers-evergreen-tools/.evergreen/*.sh

# run-orchestration (or scripts it calls) expect a few environment variables to be set
# DRIVERS_TOOLS - absolute path to the checked out driver-evergreen-tools repository
# MONGO_ORCHESTRATION_HOME - location of orchestration configuration
# TOPOLOGY, SSL, STORAGE_ENGINE, and MONGDOB_VERSION, all of which have sensible defaults.
# An unspecified TOPOLOGY defaults to a standalone.
# It took some trial and error to get this right. C++ driver evergreen was used for reference.
export DRIVERS_TOOLS=$(pwd)/drivers-evergreen-tools
export MONGO_ORCHESTRATION_HOME="$(pwd)/drivers-evergreen-tools/.evergreen/orchestration"

# Create a config pointing to the mongodb binaries (surprisingly, run-orchestration.sh does not do this).
printf '{ "releases": { "default": "%s" } }' ${DRIVERS_TOOLS}/mongodb/bin > $MONGO_ORCHESTRATION_HOME/orchestration.config
./drivers-evergreen-tools/.evergreen/run-orchestration.sh

# Turn tracing back on.
set -o xtrace

echo "Creating key vault."
python ./libmongocrypt/etc/setup-key-vault.py > ./libmongocrypt/test/schema.json
if [ ! -s ./libmongocrypt/test/schema.json  ]; then
    echo "failed to create key vault"
    exit 1
fi

echo "Starting mockupcryptd in background."
MOCKUPCRYPTD_DEBUG=ON mockupcryptd > mockupcryptd.logs 2>&1 &
echo $! > mockupcryptd.pid

echo "Running tests."
cd libmongocrypt
MONGOCRYPT_TRACE=ON ./cmake-build/test-mongocrypt
cd ..

echo "Cleaning up."
evergreen_root="$(pwd)"
. ${evergreen_root}/libmongocrypt/.evergreen/setup-venv.sh
./drivers-evergreen-tools/.evergreen/stop-orchestration.sh

kill $(cat mockupcryptd.pid)