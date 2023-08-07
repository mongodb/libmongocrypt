#!/usr/bin/env bash

if [ -z ${LINT_TARGET+omitted} ]; then echo "LINT_TARGET is unset, must have value typescript or cpp" && exit 1; fi

# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Setting up environment"

export PATH="/opt/mongodbtoolchain/v2/bin:$PATH"
hash -r

NODE_LTS_VERSION=${NODE_LTS_VERSION:-16}
export NODE_LTS_VERSION=${NODE_LTS_VERSION}
source ./.evergreen/install-dependencies.sh

# install dependencies but intentionally do not
# run prebuild or Typescript, since we are only
# linting.
npm install --ignore-scripts

if [ "$LINT_TARGET" == "typescript" ]; then
  npm run check:eslint
elif [ "$LINT_TARGET" == "cpp" ]; then
  npm run check:clang-format
else
  echo "unsupported value for LINT_TARGET: $LINT_TARGET"
  exit 1
fi
