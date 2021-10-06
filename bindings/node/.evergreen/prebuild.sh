#!/usr/bin/env bash

set -o errexit
set +o xtrace

# FLE platform matrix (as of Oct 6th 2021)
# macos   x86_64 (compiled on 10.14)
# windows x86_64 (compiled on vs2017)
# linux   x86_64
# linux   s390x
# linux   arm64

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

  if [[ "$OS" == "LINUX" ]]; then
    # We're on linux should be able to use uname -m
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" && $DISTRO_ID == "rhel70-small" ]]; then
      # only publish x86_64 linux prebuilds from RHEL 7
      run_prebuild
    elif [[ "$ARCH" != "x86_64" ]]; then
      run_prebuild
    fi
  else
    run_prebuild
  fi
else
  echo "No difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Will prebuild without submit"
  npm run prebuild
  echo "Local prebuild successful."
fi
