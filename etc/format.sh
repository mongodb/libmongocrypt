#!/usr/bin/env bash

: "${CLANG_FORMAT_VERSION:=15.0.7}"

# Give default clang-format an empty string on stdin if there are no inputs files
printf '' | uvx "clang-format==${CLANG_FORMAT_VERSION:?}" "$@"
