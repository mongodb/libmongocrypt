#!/bin/bash

set -eux

LIBMONGOCRYPT_VERSION=$(cat ./libmongocrypt-version.txt)
if [ $(command -v podman) ]; then
    DOCKER=podman
else
    DOCKER=docker
fi

echo "pkg:github/mongodb/libmongocrypt@$LIBMONGOCRYPT_VERSION" > purls.txt
$DOCKER run --platform="linux/amd64" -it --rm -v $(pwd):$(pwd) artifactory.corp.mongodb.com/release-tools-container-registry-public-local/silkbomb:1.0 update --purls=$(pwd)/purls.txt -o $(pwd)/sbom.json
rm purls.txt
