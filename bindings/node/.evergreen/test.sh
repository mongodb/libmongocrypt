#!/usr/bin/env bash
# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Setting up environment"
export NPM_OPTIONS="${NPM_OPTIONS}"
. ./.evergreen/setup_environment.sh

# Handle the circular dependency when testing with a real client.
export MONGODB_CLIENT_ENCRYPTION_OVERRIDE="$(pwd)"

# install node dependencies
echo "Installing package dependencies (includes a static build)"
bash ./etc/build-static.sh
# npm install

# Run tests
echo "Running tests"
npm run check:lint
MONGODB_NODE_SKIP_LIVE_TESTS=true npm test

# Run prebuild and deploy
echo "Running prebuild and deploy"
bash ./.evergreen/prebuild.sh
