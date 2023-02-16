#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/../.evergreen/init.sh"

files="$(find "$LIBMONGOCRYPT_DIR/src" "$LIBMONGOCRYPT_DIR/test" -type f -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp')"
# shellcheck disable=SC2206
IFS=$'\n' files=($files)
bash "$LIBMONGOCRYPT_DIR/etc/format.sh" \
    --style="file:$LIBMONGOCRYPT_DIR/.clang-format" \
    -i \
    "$@" \
    -- "${files[@]:?}"
