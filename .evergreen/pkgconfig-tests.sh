#!/bin/bash

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

if ! have_command pkg-config; then
    echo "pkg-config not present on this platform; skipping test ..."
    exit 0
fi

pkgconfig_tests_root=$LIBMONGOCRYPT_DIR/_build/pkgconfig_tests
rm -rf "$pkgconfig_tests_root"

mongoc_src_dir="$pkgconfig_tests_root/mongo-c-driver"
mkdir -p "$mongoc_src_dir"
run_chdir "$pkgconfig_tests_root" "$EVG_DIR/prep_c_driver_source.sh"

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS_NAME" = "windows" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    if [ "${WINDOWS_32BIT-}" != "ON" ]; then
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
else
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . "$EVG_DIR/find-cmake.sh"
    # Check if on macOS with arm64. Use system cmake. See BUILD-14565.
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        CMAKE=cmake
    fi
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

common_cmake_flags=(
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
    $ADDITIONAL_CMAKE_FLAGS
)

libbson_install_dir="$pkgconfig_tests_root/install/libbson"
build_dir="$mongoc_src_dir/_build"
$CMAKE -DENABLE_MONGOC=OFF \
       "${common_cmake_flags[@]}" \
       -DCMAKE_INSTALL_PREFIX="$libbson_install_dir" \
       -H"$mongoc_src_dir" \
       -B"$build_dir"
$CMAKE --build "$build_dir" --target install --config RelWithDebInfo
libbson_pkg_config_path="$(native_path "$(dirname "$(find "$libbson_install_dir" -name libbson-1.0.pc)")")"

# Build libmongocrypt, static linking against libbson and configured for the PPA
mongocrypt_install_dir="$pkgconfig_tests_root/install/libmongocrypt"
build_dir=$pkgconfig_tests_root/mongocrypt-build
$CMAKE -DUSE_SHARED_LIBBSON=OFF \
       -DENABLE_BUILD_FOR_PPA=ON \
       "${common_cmake_flags[@]}" \
       -DCMAKE_INSTALL_PREFIX="$mongocrypt_install_dir" \
       -H"$LIBMONGOCRYPT_DIR" \
       -B"$build_dir"
$CMAKE --build "$build_dir" --target install --config RelWithDebInfo

# To validate the pkg-config scripts, we don't want the libbson script to be visible
mongocrypt_pkg_config_path="$(native_path "$(dirname "$(find "$mongocrypt_install_dir" -name libmongocrypt.pc)")")"

export PKG_CONFIG_PATH
PKG_CONFIG_PATH="$mongocrypt_pkg_config_path:$libbson_pkg_config_path"

echo "Validating pkg-config scripts"
pkg-config --debug --print-errors --exists libmongocrypt-static
pkg-config --debug --print-errors --exists libmongocrypt

# Build example-state-machine, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt-static)
run_chdir "$LIBMONGOCRYPT_DIR" "$pkgconfig_tests_root/example-state-machine"

# Build example-no-bson, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt-static)
command "$pkgconfig_tests_root/example-no-bson"

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"

# Build example-no-bson, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt)
env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"

# Clean up prior to next execution
rm -r "$mongocrypt_install_dir"

# Build libmongocrypt, dynamic linking against libbson
$CMAKE -DUSE_SHARED_LIBBSON=ON \
       -DENABLE_BUILD_FOR_PPA=OFF \
       "${common_cmake_flags[@]}" \
       -DCMAKE_INSTALL_PREFIX="$mongocrypt_install_dir" \
       -H"$LIBMONGOCRYPT_DIR" \
       -B"$build_dir"
$CMAKE --build "$build_dir" --target install --config RelWithDebInfo

# Build example-state-machine, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt-static)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$libbson_install_dir/lib:/$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"

# Build example-no-bson, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt-static)
env LD_LIBRARY_PATH="$libbson_install_dir/lib:/$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64:$libbson_install_dir/lib:$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"

# Build example-no-bson, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt)
env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64:$libbson_install_dir/lib:$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"

echo "pkg-config tests PASS"
