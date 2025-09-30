#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname ${BASH_SOURCE:-$0})

if [ -z "${1:-}" ]; then
    echo "Provide the new version of libmongocrypt!"
    exit 1
fi

LIBMONGOCRYPT_VERSION=$1

echo $LIBMONGOCRYPT_VERSION > $SCRIPT_DIR/libmongocrypt-version.txt

pushd $SCRIPT_DIR/..
if [ $(command -v podman) ]; then
    DOCKER=podman
else
    DOCKER=docker
fi

echo "pkg:github/mongodb/libmongocrypt@$LIBMONGOCRYPT_VERSION" > purls.txt
$DOCKER run --platform="linux/amd64" -it --rm -v $(pwd):$(pwd) artifactory.corp.mongodb.com/release-tools-container-registry-public-local/silkbomb:2.0 update --purls=$(pwd)/purls.txt -o $(pwd)/sbom.json
rm purls.txt

popd
