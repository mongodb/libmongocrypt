#!/usr/bin/env bash

# set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

NODE_LTS_NAME=${NODE_LTS_NAME:-dubnium}
NODE_BINDINGS_PATH="${PROJECT_DIRECTORY}/bindings/node"
NODE_ARTIFACTS_PATH="${NODE_BINDINGS_PATH}/node-artifacts"
NPM_CACHE_DIR="${NODE_ARTIFACTS_PATH}/npm"
NPM_TMP_DIR="${NODE_ARTIFACTS_PATH}/tmp"
BUILD_STATIC_SCRIPT="${NODE_BINDINGS_PATH}/etc/build_static.sh"


# Add mongodb toolchain to path
export PATH="/opt/mongodbtoolchain/v2/bin:$PATH"

# create node artifacts path if needed
mkdir -p ${NODE_ARTIFACTS_PATH}
mkdir -p ${NPM_CACHE_DIR}
mkdir -p "${NPM_TMP_DIR}"

# this needs to be explicitly exported for the nvm install below
export NVM_DIR="${NODE_ARTIFACTS_PATH}/nvm"
mkdir -p ${NVM_DIR}

# install Node.js
echo "Installing NVM"
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.34.0/install.sh | bash
[ -s "${NVM_DIR}/nvm.sh" ] && \. "${NVM_DIR}/nvm.sh"
echo "Installing Node ${NODE_LTS_NAME}"
nvm install --lts=${NODE_LTS_NAME}

# setup npm cache in a local directory
cat <<EOT > .npmrc
devdir=${NPM_CACHE_DIR}/.node-gyp
init-module=${NPM_CACHE_DIR}/.npm-init.js
cache=${NPM_CACHE_DIR}
tmp=${NPM_TMP_DIR}
EOT

# if no mongocryptd installed, install mongocryptd and add it to path
if ! [ -x "$(command -v mongocryptd)" ]
then
  echo "Installing mongocryptd"
  curl -o mongocryptd.tgz https://s3.amazonaws.com/mciuploads/mongodb-mongo-v4.2/enterprise-ubuntu1604-64/f92115cad9d2a4c2ddcf3c2c65092dda2fd7147a/binaries/mongo-cryptd-mongodb_mongo_v4.2_enterprise_ubuntu1604_64_f92115cad9d2a4c2ddcf3c2c65092dda2fd7147a_19_06_13_17_31_40.tgz
  mkdir -p mongocryptd && tar xzf mongocryptd.tgz -C mongocryptd --strip-components 1
  export PATH="$PATH:$(pwd)/mongocryptd/bin"
fi
