#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

if test "$OS_NAME" != "linux"; then
    log "Warning: Script is expected only to run on distro: rhel90-dbx-perf-large"
    log "More changes may be needed to run on other distros.";
fi

MONGOCRYPT_INSTALL_PREFIX=$LIBMONGOCRYPT_DIR/.install

. "$(dirname "${BASH_SOURCE[0]}")/install-build-tools.sh"
install_build_tools

# Install libmongocrypt.
build_dir="$LIBMONGOCRYPT_DIR/cmake-build"
cmake \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX" \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -B"$build_dir"
cmake --build "$build_dir" --target install

# Run Python benchmarks.
# Include path to installed libmongocrypt.so
export LD_LIBRARY_PATH="$MONGOCRYPT_INSTALL_PREFIX/lib64"
cd bindings/python/

uv venv venv
. ./venv/bin/activate
uv python install
uv pip install -r requirements-test.txt
uv pip install -e .

export OUTPUT_FILE=results.json

python test/performance/perf_test.py -v
