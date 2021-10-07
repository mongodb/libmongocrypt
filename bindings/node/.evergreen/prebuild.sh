#!/usr/bin/env bash

if [ -z ${DISTRO_ID+omitted} ]; then echo "DISTRO_ID is unset" && exit 1; fi

set -o errexit
set +o xtrace

# FLE platform matrix (as of Oct 7th 2021)
# macos   x86_64 (compiled on 10.14)
# windows x86_64 (compiled on vs2017)
# linux   x86_64 (releases on RHEL7)
# linux   s390x
# linux   arm64

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

export OS
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

if [[ -n $NODE_FORCE_PUBLISH ]]; then
  echo "\$NODE_FORCE_PUBLISH=${NODE_FORCE_PUBLISH} detected"
  echo "Beginning prebuild"
  run_prebuild
elif [[ "$VERSION_AT_HEAD" != "$VERSION_AT_HEAD_1" ]]; then
  echo "Difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Beginning prebuild"

  if [[ "$OS" == "linux" ]]; then
    # Handle limiting which linux gets to publish prebuild
    ARCH=$(uname -m)

    if [[ $DISTRO_ID == "rhel70-small" ]]; then
      # only publish x86_64 linux prebuilds from RHEL 7
      run_prebuild
    elif [[ "$ARCH" != "x86_64" ]]; then
      # Non-x86 linux variants should just publish
      run_prebuild
    else
      # Non RHEL 7 linux variants should just test the prebuild task
      echo "Will prebuild without submit ($OS - $ARCH - $DISTRO_ID)"
      npm run prebuild
    fi

    exit 0
  fi

  # Windows and MacOS
  run_prebuild
else
  echo "No difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Will prebuild without submit ($OS - $DISTRO_ID)"
  npm run prebuild
  echo "Local prebuild successful."
fi
