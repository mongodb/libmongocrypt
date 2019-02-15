#!/bin/sh

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

echo "Machine environment"
git --version
openssl --version
python --version