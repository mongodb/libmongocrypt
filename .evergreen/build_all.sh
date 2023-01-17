#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
#
# Set extra cflags for libmongocrypt variables by setting LIBMONGOCRYPT_EXTRA_CFLAGS.
#

set -x
echo "Begin compile process"

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

# We may need some more C++ flags
_cxxflags=""

: "${CONFIGURE_ONLY:=}"
: "${LIBMONGOCRYPT_BUILD_TYPE:=RelWithDebInfo}"

if [ "$OS_NAME" = "windows" ]; then
    # Enable exception handling for MSVC
    _cxxflags="-EHsc"
    if is_false WINDOWS_32BIT && is_false USE_NINJA; then
        # These options are only needed for VS CMake generators to force it to
        # generate a 64-bit build. Default is 32-bit. Ninja inherits settings
        # from the build environment variables.
        ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
    fi
fi

# Have CTest print test failure info to stderr
export CTEST_OUTPUT_ON_FAILURE=1

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    rm -rf -- "$LIBMONGOCRYPT_DIR"/cmake-build* "$MONGOCRYPT_INSTALL_PREFIX"
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_BUILD_FOR_PPA=ON"
fi

if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES='arm64;x86_64'"
fi

: "${CMAKE:=cmake}"

for suffix in "dll" "dylib" "so"; do
    cand="$(abspath "$LIBMONGOCRYPT_DIR/../mongocrypt_v1.$suffix")"
    if test -f "$cand"; then
        ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DMONGOCRYPT_TESTING_CRYPT_SHARED_FILE=$cand"
    fi
done

ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"

build_dir="$LIBMONGOCRYPT_DIR/cmake-build"
common_cmake_args=(
    $ADDITIONAL_CMAKE_FLAGS
    $LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS
    -DCMAKE_C_FLAGS="$LIBMONGOCRYPT_EXTRA_CFLAGS"
    -DCMAKE_CXX_FLAGS="$LIBMONGOCRYPT_EXTRA_CFLAGS $_cxxflags"
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DCMAKE_BUILD_TYPE="$LIBMONGOCRYPT_BUILD_TYPE"
    -H"$LIBMONGOCRYPT_DIR"
    -B"$build_dir"
)

if is_true USE_NINJA; then
    export NINJA_EXE
    : "${NINJA_EXE:="$build_dir/ninja$EXE_SUFFIX"}"
    common_cmake_args+=(
        -GNinja
        -DCMAKE_MAKE_PROGRAM="$NINJA_EXE"
    )
    bash "$EVG_DIR/ensure-ninja.sh"
fi

# Build and install libmongocrypt.
run_cmake \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX" \
    "${common_cmake_args[@]}"

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
run_cmake --build "$build_dir" --target install --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_cmake --build "$build_dir" --target test-mongocrypt --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_cmake --build "$build_dir" --target test_kms_request --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_chdir "$build_dir" run_ctest -C "$LIBMONGOCRYPT_BUILD_TYPE"

# MONGOCRYPT-372, ensure macOS universal builds contain both x86_64 and arm64 architectures.
if [ "$MACOS_UNIVERSAL" = "ON" ]; then
    echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures..."
    ARCHS=$(lipo -archs $MONGOCRYPT_INSTALL_PREFIX/lib/libmongocrypt.dylib)
    if [[ "$ARCHS" == *"x86_64"* && "$ARCHS" == *"arm64"* ]]; then
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... OK"
    else
        echo "Checking if libmongocrypt.dylib contains both x86_64 and arm64 architectures... ERROR. Got: $ARCHS"
        exit 1
    fi
fi

if [ "$PPA_BUILD_ONLY" ]; then
    echo "Only building/installing for PPA";
    exit 0;
fi

if "${DEFAULT_BUILD_ONLY:-false}"; then
    echo "Skipping nocrypto+sharedbson builds"
    exit 0
fi

# Build and install libmongocrypt with no native crypto.
run_cmake \
    -DDISABLE_NATIVE_CRYPTO=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/nocrypto" \
    "${common_cmake_args[@]}"

run_cmake --build "$build_dir" --target install --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_cmake --build "$build_dir" --target test-mongocrypt --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_chdir "$build_dir" run_ctest -C "$LIBMONGOCRYPT_BUILD_TYPE"

# Build and install libmongocrypt without statically linking libbson
run_cmake \
    -UDISABLE_NATIVE_CRYPTO \
    -DUSE_SHARED_LIBBSON=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/sharedbson" \
    "${common_cmake_args[@]}"

run_cmake --build "$build_dir" --target install  --config "$LIBMONGOCRYPT_BUILD_TYPE"
run_chdir "$build_dir" run_ctest -C "$LIBMONGOCRYPT_BUILD_TYPE"
