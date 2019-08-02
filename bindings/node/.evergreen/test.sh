#!/bin/sh
# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

source ./.evergreen/setup_environment.sh

# install node dependencies
echo "Installing package dependencies (includes a static build)"
source ./etc/build-static.sh
# npm install

# Run tests
echo "Running tests"
NODE_SKIP_LIVE_TESTS=true npm test
