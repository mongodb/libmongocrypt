#!/usr/bin/env bash
# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Setting up environment"
. ./.evergreen/setup_environment.sh

# install node dependencies
echo "Installing package dependencies (includes a static build)"
. ./etc/build-static.sh
# npm install

# Run tests
echo "Running tests"
MONGODB_NODE_SKIP_LIVE_TESTS=true npm test

# Run prebuild and deploy
echo "Running prebuild and deploy"
. ./.evergreen/prebuild.sh
