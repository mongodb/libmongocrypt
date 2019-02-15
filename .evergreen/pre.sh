#!/bin/sh

# Print information about the environment.

set -o xtrace

evergreen_root=$(pwd)

git --version
openssl version
python --version

if which gcc; then
    gcc --version
fi

if which clang; then
    clang --version
fi