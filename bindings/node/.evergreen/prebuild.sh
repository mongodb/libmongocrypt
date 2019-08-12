#!/usr/bin/env bash

set -o errexit

get_version_at_git_rev () {
  local REV=$1
  local GIT_OUTPUT=$(git show $REV:./package.json)
  local VERSION=$(echo $GIT_OUTPUT | node -r fs -e 'console.log(JSON.parse(fs.readFileSync("/dev/stdin", "utf-8")).version);')
  echo $VERSION
}

run_prebuild() {
  if [[ -z $NODE_GITHUB_TOKEN ]];then
    echo "No github token set. Cannot run prebuild."
    exit 1
  else
    echo "Github token detected. Running prebuild."
    npm run prebuild -- -u $NODE_GITHUB_TOKEN
  fi
}

VERSION_AT_HEAD=$(get_version_at_git_rev "HEAD")
VERSION_AT_HEAD_1=$(get_version_at_git_rev "HEAD~1")

if [[ ! -z $NODE_FORCE_PUBLISH ]]; then
  echo '$NODE_FORCE_PUBLISH detected'
  echo "Beginning prebuild"
  run_prebuild
elif [[ $VERSION_AT_HEAD != $VERSION_AT_HEAD_1 ]]; then
  echo "Difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "Beginning prebuild"
  run_prebuild
else
  echo "No difference is package version ($VERSION_AT_HEAD_1 -> $VERSION_AT_HEAD)"
  echo "No prebuild required"
fi
