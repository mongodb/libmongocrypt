#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/../.evergreen/init.sh"

: "${CLANG_FORMAT_VERSION:=15.0.7}"
export PIPX_HOME="${BUILD_CACHE_DIR}/pipx"

if ! run_python -c ''; then
  fail "No Python found?"
fi

# Check that we have a pipx of the proper version:
run_python -c 'import pkg_resources; pkg_resources.require("pipx>=0.17.0<2.0")'

# Give default clang-format an empty string on stdin if there are no inputs files
printf '' | run_python -m pipx run "clang-format==${CLANG_FORMAT_VERSION:?}" "$@"
