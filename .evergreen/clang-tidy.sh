#!/bin/bash
# Run after running "CONFIGURE_ONLY=ON compile.sh" to run the clang-tidy
# static analyzer.
#

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

set -o xtrace
set -o errexit

echo "Begin compile process"

. "$EVG_DIR/setup-env.sh"

CLANG_TIDY=/opt/mongodbtoolchain/v3/bin/clang-tidy

$CLANG_TIDY --version

python "$LIBMONGOCRYPT_DIR/etc/list-compile-files.py" \
    "$LIBMONGOCRYPT_DIR/cmake-build/" \
| xargs $CLANG_TIDY -p "$LIBMONGOCRYPT_DIR/cmake-build/"
