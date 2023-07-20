#!/usr/bin/env bash

# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Setting up environment"

export PATH="/opt/mongodbtoolchain/v2/bin:$PATH"
hash -r

NODE_LTS_VERSION=${NODE_LTS_VERSION:-16}
export NODE_LTS_VERSION=${NODE_LTS_VERSION}
source ./.evergreen/install-dependencies.sh

# install node dependencies
echo "Installing package dependencies (includes a static build)"
bash ./etc/build-static.sh

# Run tests
echo "Running tests"
npm test
