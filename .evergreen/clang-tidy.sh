#!/bin/bash
# Run after running "CONFIGURE_ONLY=ON compile.sh" to run the clang-tidy
# static analyzer.
#

set -euxo pipefail

echo "Begin compile process"

evergreen_root="$(pwd)"

. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh

cd $evergreen_root

CLANG_TIDY=/opt/mongodbtoolchain/v3/bin/clang-tidy

$CLANG_TIDY --version

cd libmongocrypt

python ./etc/list-compile-files.py ./cmake-build/ | xargs $CLANG_TIDY -p ./cmake-build