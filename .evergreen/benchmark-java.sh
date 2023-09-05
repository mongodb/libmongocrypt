#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

if test "$OS_NAME" != "linux"; then
    log "Warning: Script is expected only to run on distro: rhel90-dbx-perf-large"
    log "More changes may be needed to run on other distros.";
fi

MONGOCRYPT_INSTALL_PREFIX=$LIBMONGOCRYPT_DIR/.install

# Install libmongocrypt.
build_dir="$LIBMONGOCRYPT_DIR/cmake-build"
run_cmake \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX" \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -B"$build_dir"
run_cmake --build "$build_dir" --target install

# Run Java benchmarks. Do not use JDK 8 to avoid hang in gradle observed in MONGOCRYPT-590.
export JAVA_HOME=/opt/java/jdk17
# Include path to installed libmongocrypt.so
export LD_LIBRARY_PATH="$MONGOCRYPT_INSTALL_PREFIX/lib64"
cd bindings/java/mongocrypt
./gradlew --version
./gradlew clean benchmarks:run --info
