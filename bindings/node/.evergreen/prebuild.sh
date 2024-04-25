#!/usr/bin/env bash

if [ -z ${DISTRO_ID+omitted} ]; then echo "DISTRO_ID is unset" && exit 1; fi

set -o errexit
set +o xtrace

echo "Setting up environment"

export PATH="/opt/mongodbtoolchain/v2/bin:$PATH"
hash -r

NODE_LTS_VERSION=${NODE_LTS_VERSION:-16}
export NODE_LTS_VERSION=${NODE_LTS_VERSION}
source ./.evergreen/install-dependencies.sh

# install node dependencies
echo "Installing package dependencies (includes a static build)"
bash ./etc/build-static.sh

# FLE platform matrix (as of 22 May 2023)
# macos   arm64  (compiled on 11.00)
# macos   x86_64 (compiled on 10.14)
# windows x86_64 (compiled on vs2019)
# linux   x86_64 (compiled on Ubuntu 16.04)
# linux   arm64  (compiled on Ubuntu 16.04)

# Determines the OS name through uname results
# Returns 'windows' 'linux' 'macos' or 'unknown'
os_name() {
  local WINDOWS_REGEX="cygwin|windows|mingw|msys"
  local UNAME
  UNAME=$(uname | tr '[:upper:]' '[:lower:]')

  local OS_NAME="unknown"

  if [[ $UNAME =~ $WINDOWS_REGEX ]]; then
    OS_NAME="windows"
  elif [[ $UNAME == "darwin" ]]; then
    OS_NAME="macos"
  elif [[ $UNAME == "linux" ]]; then
    OS_NAME="linux"
  fi

  echo $OS_NAME
}

OS=$(os_name)

get_version_at_git_rev () {
  local REV=$1
  local VERSION
  VERSION=$(node -r child_process -e "console.log(JSON.parse(child_process.execSync('git show $REV:./package.json', { encoding: 'utf8' })).version);")
  echo "$VERSION"
}

run_prebuild() {
  if [ -z ${NODE_GITHUB_TOKEN+omitted} ]; then echo "NODE_GITHUB_TOKEN is unset" && exit 1; fi
  echo "Github token detected. Running prebuild."
  npm run prebuild -- -u "$NODE_GITHUB_TOKEN"
  echo "Prebuild's successfully submitted"
}

VERSION_AT_HEAD=$(get_version_at_git_rev "HEAD")
VERSION_AT_HEAD_1=$(get_version_at_git_rev "HEAD~1")

if [[ "$OS" == "macos" ]]; then
  ARCH=$(uname -m)
  if [[ "$ARCH" == "arm64" ]]; then
    # TODO(NODE-5174): node-gyp fails to run prebuild if Python 3.11+
    echo "Exporting PYTHON location for version $(/opt/homebrew/opt/python@3.9/bin/python3.9 --version)"
    export PYTHON="/opt/homebrew/opt/python@3.9/bin/python3.9"
  fi
fi

if [[ -n $NODE_FORCE_PUBLISH ]]; then
  echo "\$NODE_FORCE_PUBLISH=${NODE_FORCE_PUBLISH} detected"
  echo "Beginning prebuild"
  run_prebuild
elif [[ "$VERSION_AT_HEAD" != "$VERSION_AT_HEAD_1" ]]; then
  echo "Difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Beginning prebuild"
  run_prebuild
else
  echo "No difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Will prebuild without submit ($OS - $DISTRO_ID)"
  npm run prebuild
  echo "Local prebuild successful."
fi
