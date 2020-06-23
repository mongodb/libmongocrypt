#!/usr/bin/env bash

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

NODE_VERSION=14
NODE_BINDINGS_PATH="${PROJECT_DIRECTORY}/bindings/node"
NODE_ARTIFACTS_PATH="${NODE_BINDINGS_PATH}/node-artifacts"
NPM_CACHE_DIR="${NODE_ARTIFACTS_PATH}/npm"
NPM_TMP_DIR="${NODE_ARTIFACTS_PATH}/tmp"
BIN_DIR="$(pwd)/bin"
NVM_WINDOWS_URL="https://github.com/coreybutler/nvm-windows/releases/download/1.1.7/nvm-noinstall.zip"
NVM_URL="https://raw.githubusercontent.com/creationix/nvm/v0.34.0/install.sh"

# create node artifacts path if needed
mkdir -p ${NODE_ARTIFACTS_PATH}
mkdir -p ${NPM_CACHE_DIR}
mkdir -p "${NPM_TMP_DIR}"
mkdir -p ${BIN_DIR}

# Add mongodb toolchain to path
export PATH="$BIN_DIR:/opt/mongodbtoolchain/v2/bin:$PATH"

# locate cmake
if [ "$OS" == "Windows_NT" ]; then
  CMAKE=/cygdrive/c/cmake/bin/cmake
  ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
  chmod u+x ./.evergreen/find_cmake.sh
  . ./.evergreen/find_cmake.sh
fi

# this needs to be explicitly exported for the nvm install below
export NVM_DIR="${NODE_ARTIFACTS_PATH}/nvm"
mkdir -p ${NVM_DIR}

# install Node.js
echo "Installing Node ${NODE_LTS_NAME}"
if [ "$OS" == "Windows_NT" ]; then
  export NVM_HOME=`cygpath -w "$NVM_DIR"`
  export NVM_SYMLINK=`cygpath -w "$NODE_ARTIFACTS_PATH/bin"`
  export PATH=`cygpath $NVM_SYMLINK`:`cygpath $NVM_HOME`:$PATH

  # download and install nvm
  curl -L $NVM_WINDOWS_URL -o nvm.zip
  unzip -d $NVM_DIR nvm.zip
  rm nvm.zip

  chmod 777 $NVM_DIR
  chmod -R a+rx $NVM_DIR

  cat <<EOT > $NVM_DIR/settings.txt
root: $NVM_HOME
path: $NVM_SYMLINK
EOT

  nvm install $NODE_VERSION
  nvm use $NODE_VERSION
else
  curl -o- $NVM_URL | bash
  [ -s "${NVM_DIR}/nvm.sh" ] && \. "${NVM_DIR}/nvm.sh"

  nvm install $NODE_VERSION
  nvm use $NODE_VERSION
fi

# setup npm cache in a local directory
cat <<EOT > .npmrc
devdir=${NPM_CACHE_DIR}/.node-gyp
init-module=${NPM_CACHE_DIR}/.npm-init.js
cache=${NPM_CACHE_DIR}
tmp=${NPM_TMP_DIR}
EOT

