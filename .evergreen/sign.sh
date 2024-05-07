#!/usr/bin/env bash

# Use Garasign to sign a file with the libmongocrypt key.
# See: https://docs.devprod.prod.corp.mongodb.com/release-tools-container-images/garasign/garasign_signing/.

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

# Check for required environment variables:
: "${file_to_sign:?}"
: "${output_file:?}"
: "${garasign_username:?}"
: "${garasign_password:?}"
: "${artifactory_username:?}"
: "${artifactory_password:?}"

echo "${artifactory_password}" | docker login --password-stdin --username "${artifactory_username}" artifactory.corp.mongodb.com

echo "GRS_CONFIG_USER1_USERNAME=${garasign_username}" >> "signing-envfile"
echo "GRS_CONFIG_USER1_PASSWORD=${garasign_password}" >> "signing-envfile"

# Create signature.
docker run \
  --env-file="signing-envfile" \
  --rm \
  -v "$(pwd):$(pwd)" \
  -w "$(pwd)" \
  artifactory.corp.mongodb.com/release-tools-container-registry-local/garasign-gpg \
  /bin/bash -c "gpgloader && gpg --yes -v --armor -o ${output_file} --detach-sign ${file_to_sign}"

rm signing-envfile
