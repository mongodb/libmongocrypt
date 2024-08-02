#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

# Check for required commands:
if ! command -v jq > /dev/null 2>&1; then
    echo "jq not found. Install jq"
    exit 1
fi

if ! command -v curl > /dev/null 2>&1; then
    echo "curl not found. Install curl"
    exit 1
fi

# Check for required environment variables:
: "${silk_client_id:?}"
: "${silk_client_secret:?}"
: "${branch:?}"

# Get Silk token:
json_payload=$(cat <<EOF
{
    "client_id": "${silk_client_id}",
    "client_secret": "${silk_client_secret}"
}
EOF
)
silk_jwt_token=$(curl --no-progress-meter --fail --location -X POST "https://silkapi.us1.app.silk.security/api/v1/authenticate" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d "$json_payload" \
  | jq -e -r '.token')

asset_id="libmongocrypt-${branch}"

# Create Silk asset group:
json_payload=$(cat <<EOF
{
    "active": true,
    "name": "${asset_id}",
    "code_repo_url": "https://github.com/mongodb/libmongocrypt",
    "branch": "${branch}",
    "metadata": {
        "sbom_lite_path": "etc/cyclonedx.sbom.json"
    },
    "file_paths": [],
    "asset_id": "${asset_id}"
}
EOF
)
if ! reply=$(curl --no-progress-meter --fail-with-body --location -X 'POST' \
  'https://silkapi.us1.app.silk.security/api/v1/raw/asset_group' \
  -H "Accept: application/json" \
  -H "Authorization: ${silk_jwt_token}" \
  -H 'Content-Type: application/json' \
  -d "$json_payload"); then
    echo "Failed to create silk asset group. Got reply: $reply"
    exit 1
fi

if silkid=$(echo "$reply" | jq -e ".silk_id"); then
    echo "Created silk asset group with asset_id=$asset_id and silk_id=$silkid"
else
    echo "Reply does not contain expected 'silk_id': $reply"
    exit 1
fi

