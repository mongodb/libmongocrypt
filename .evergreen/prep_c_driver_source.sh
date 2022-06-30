#!/bin/bash

set -o xtrace
set -o errexit

# Clone mongo-c-driver and check out to a tagged version.
MONGO_C_DRIVER_VERSION=1.17.0

# Force checkout with lf endings since .sh must have lf, not crlf on Windows
git clone https://github.com/mongodb/mongo-c-driver.git --config core.eol=lf --config core.autocrlf=false --depth=1 --branch $MONGO_C_DRIVER_VERSION
echo $MONGO_C_DRIVER_VERSION > mongo-c-driver/VERSION_CURRENT

