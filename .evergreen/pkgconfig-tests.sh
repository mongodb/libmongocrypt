#!/bin/bash

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

if test "$OS_NAME" = "windows" && is_false WINDOWS_32BIT && is_false USE_NINJA; then
    # These options are only needed for VS CMake generators to force it to
    # generate a 64-bit build. Default is 32-bit. Ninja inherits settings
    # from the build environment variables.
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

# Disable extra alignment in libbson and libmongocrypt to ensure agreement.
# libmongocrypt disables by default, but may enable if a system install of libbson is detected with extra alignment.
common_cmake_args=(
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
    -DENABLE_EXTRA_ALIGNMENT=OFF
    $ADDITIONAL_CMAKE_FLAGS
)

if is_true USE_NINJA; then
    export NINJA_EXE
    : "${NINJA_EXE:="$pkgconfig_tests_root/ninja$EXE_SUFFIX"}"
    common_cmake_args+=(
        -GNinja
        -DCMAKE_MAKE_PROGRAM="$NINJA_EXE"
    )
    bash "$EVG_DIR/ensure-ninja.sh"
fi

echo "Building libbson ..."
libbson_install_dir="$pkgconfig_tests_root/install/libbson"
build_dir="$mongoc_src_dir/_build"
run_cmake -DENABLE_MONGOC=OFF \
       "${common_cmake_args[@]}" \
       -DCMAKE_INSTALL_PREFIX="$libbson_install_dir" \
       -H"$mongoc_src_dir" \
       -B"$build_dir"
run_cmake --build "$build_dir" --target install --config RelWithDebInfo
libbson_pkg_config_path="$(native_path "$(dirname "$(find "$libbson_install_dir" -name libbson-1.0.pc)")")"
echo "Building libbson ... done"

echo "Build libmongocrypt, static linking against libbson and configured for the PPA ..."
mongocrypt_install_dir="$pkgconfig_tests_root/install/libmongocrypt"
build_dir=$pkgconfig_tests_root/mongocrypt-build
run_cmake -DUSE_SHARED_LIBBSON=OFF \
       -DENABLE_BUILD_FOR_PPA=ON \
       "${common_cmake_args[@]}" \
       -DCMAKE_INSTALL_PREFIX="$mongocrypt_install_dir" \
       -H"$LIBMONGOCRYPT_DIR" \
       -B"$build_dir"
run_cmake --build "$build_dir" --target install --config RelWithDebInfo
echo "Build libmongocrypt, static linking against libbson and configured for the PPA ... done"

# To validate the pkg-config scripts, we don't want the libbson script to be visible
mongocrypt_pkg_config_path="$(native_path "$(dirname "$(find "$mongocrypt_install_dir" -name libmongocrypt.pc)")")"

export PKG_CONFIG_PATH
PKG_CONFIG_PATH="$mongocrypt_pkg_config_path:$libbson_pkg_config_path"

echo "Validating pkg-config scripts ..."
pkg-config --debug --print-errors --exists libmongocrypt-static
pkg-config --debug --print-errors --exists libmongocrypt
echo "Validating pkg-config scripts ... done"

echo "Build example-state-machine, static linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt-static)
run_chdir "$LIBMONGOCRYPT_DIR" "$pkgconfig_tests_root/example-state-machine"
echo "Build example-state-machine, static linking against libmongocrypt ... done"

echo "Build example-no-bson, static linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt-static) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt-static)
command "$pkgconfig_tests_root/example-no-bson"
echo "Build example-no-bson, static linking against libmongocrypt ... done"

echo "Build example-state-machine, dynamic linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"
echo "Build example-state-machine, dynamic linking against libmongocrypt ... done"

echo "Build example-no-bson, dynamic linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt)
env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"
echo "Build example-no-bson, dynamic linking against libmongocrypt ... done"

# Clean up prior to next execution
rm -r "$mongocrypt_install_dir"

echo "Build libmongocrypt, dynamic linking against libbson ..."
run_cmake -DUSE_SHARED_LIBBSON=ON \
       -DENABLE_BUILD_FOR_PPA=OFF \
       "${common_cmake_args[@]}" \
       -DCMAKE_INSTALL_PREFIX="$mongocrypt_install_dir" \
       -H"$LIBMONGOCRYPT_DIR" \
       -B"$build_dir"
run_cmake --build "$build_dir" --target install --config RelWithDebInfo
echo "Build libmongocrypt, dynamic linking against libbson ... done"

echo "Build example-state-machine, static linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt-static)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$libbson_install_dir/lib:/$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"
echo "Build example-state-machine, static linking against libmongocrypt ..."

echo "Build example-no-bson, static linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt-static) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt-static)
env LD_LIBRARY_PATH="$libbson_install_dir/lib:/$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"
echo "Build example-no-bson, static linking against libmongocrypt ... done"

echo "Build example-state-machine, dynamic linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) \
    -o "$pkgconfig_tests_root/example-state-machine" \
    "$LIBMONGOCRYPT_DIR/test/example-state-machine.c" \
    $(pkg-config --libs libmongocrypt)
run_chdir "$LIBMONGOCRYPT_DIR" \
    env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64:$libbson_install_dir/lib:$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-state-machine"
echo "Build example-state-machine, dynamic linking against libmongocrypt ... done"

echo "Build example-no-bson, dynamic linking against libmongocrypt ..."
gcc $(pkg-config --cflags libmongocrypt) \
    -o "$pkgconfig_tests_root/example-no-bson" \
    "$LIBMONGOCRYPT_DIR/test/example-no-bson.c" \
    $(pkg-config --libs libmongocrypt)
env LD_LIBRARY_PATH="$mongocrypt_install_dir/lib:$mongocrypt_install_dir/lib64:$libbson_install_dir/lib:$libbson_install_dir/lib64" \
    "$pkgconfig_tests_root/example-no-bson"
echo "Build example-no-bson, dynamic linking against libmongocrypt ... done"

echo "pkg-config tests PASS"
