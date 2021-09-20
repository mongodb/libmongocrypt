#!/bin/bash

set -o xtrace
set -o errexit

./clone-mongo-c-driver.sh

if [ -z "$MONGO_C_DRIVER_VERSION" ]; then
    echo "No MONGO_C_DRIVER_VERSION specified, calculating release version"
    python ./build/calc_release_version.py > VERSION_CURRENT
else
    echo $MONGO_C_DRIVER_VERSION > VERSION_CURRENT
fi

cd ..
