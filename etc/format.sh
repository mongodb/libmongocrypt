#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/../.evergreen/init.sh"

: "${CLANG_FORMAT_VERSION:=15.0.7}"
export PIPX_HOME="${BUILD_CACHE_DIR}/pipx"

if ! run_python -c ''; then
  fail "No Python found?"
fi


# Give default clang-format an empty string on stdin if there are no inputs files
printf '' | run_python -m pipx run "clang-format==${CLANG_FORMAT_VERSION:?}" "$@"
