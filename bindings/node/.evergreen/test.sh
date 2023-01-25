#!/usr/bin/env bash

# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Setting up environment"
. ./.evergreen/setup_environment.sh

# Handle the circular dependency when testing with a real client.
MONGODB_CLIENT_ENCRYPTION_OVERRIDE="$(pwd)"
export MONGODB_CLIENT_ENCRYPTION_OVERRIDE

# install node dependencies
echo "Installing package dependencies (includes a static build)"
bash ./etc/build-static.sh

if [[ $OMIT_PEER_DEPS != "true" ]]; then
    npm install '@aws-sdk/credential-providers'
fi

# Run tests
echo "Running tests"
npm run check:lint
MONGODB_NODE_SKIP_LIVE_TESTS=true npm test

# Run prebuild and deploy
echo "Running prebuild and deploy"
bash ./.evergreen/prebuild.sh
