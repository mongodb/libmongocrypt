#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

. "$EVG_DIR/ensure-cmake.sh"

# Execute CMake:
command "$CMAKE_EXE" "$@"
