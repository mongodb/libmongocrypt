#!/bin/bash

set -o xtrace
set -o errexit

MONOGO_C_DRIVER_REF=1.17.0

# Force checkout with lf endings since .sh must have lf, not crlf on Windows
git clone git@github.com:mongodb/mongo-c-driver.git --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver
git checkout $MONOGO_C_DRIVER_REF || (echo "Could not checkout to specified ref (${MONOGO_C_DRIVER_REF})...aborting!"; exit 1)

if [ -z "$MONGO_C_DRIVER_VERSION" ]; then
    echo "No MONGO_C_DRIVER_VERSION specified, calculating release version"
    python ./build/calc_release_version.py > VERSION_CURRENT
else
    echo $MONGO_C_DRIVER_VERSION > VERSION_CURRENT
fi

cd ..
