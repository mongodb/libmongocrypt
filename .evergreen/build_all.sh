#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
#
# Set extra compilation for libmongocrypt variables by setting CFLAGS and CXXFLAGS.

echo "Begin compile process"

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

set -eu

# Poke our CMake runner to initialize it before we set environment variables
# that could affect the CMake sub-build if we are building it from source.
CFLAGS='' CXXFLAGS='' run_cmake --version

# Directory where build files will be stored
: "${BINARY_DIR:="$LIBMONGOCRYPT_DIR/cmake-build"}"

# Control the build configuration that is generated.
export CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-RelWithDebInfo}"
# Sets the default config for --build and CTest
export CMAKE_CONFIG_TYPE="$CMAKE_BUILD_TYPE"
# Control the install prefix
export CMAKE_INSTALL_PREFIX="${MONGOCRYPT_INSTALL_PREFIX-}"

# Have CTest print test failure info to stderr
export CTEST_OUTPUT_ON_FAILURE=1
# Generate a compilation database for use by other tools
export CMAKE_EXPORT_COMPILE_COMMANDS=1

# Accumulate arguments that are passed to CMake
cmake_args=(
    --fresh
    # Set the source directory
    "-H$LIBMONGOCRYPT_DIR"
    # Set the build directory
    "-B$BINARY_DIR"
    # Set the build type. CMake 3.22 recognizes this via environment variable
    -D CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    # Set the install preifx. CMake 3.29 recognizes this via environment variable
    -D CMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX"
    # Toggle compiling with shared BSON
    -D USE_SHARED_LIBBSON="${USE_SHARED_LIBBSON-FALSE}"
    # Toggle building of tests
    -D BUILD_TESTING="${BUILD_TESTING-TRUE}"
    # Enable additional warnings-as-errors
    -D ENABLE_MORE_WARNINGS_AS_ERRORS=TRUE
)

: "${CONFIGURE_ONLY:=}"

if [ "$OS_NAME" = "windows" ]; then
    # Enable exception handling for MSVC
    CXXFLAGS="${CXXFLAGS-} -EHsc"
fi

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    rm -rf -- "$LIBMONGOCRYPT_DIR"/cmake-build* "$MONGOCRYPT_INSTALL_PREFIX"
    cmake_args+=(-DENABLE_BUILD_FOR_PPA=ON)
fi

for suffix in "dll" "dylib" "so"; do
    cand="$(abspath "$LIBMONGOCRYPT_DIR/../mongocrypt_v1.$suffix")"
    if test -f "$cand"; then
        cmake_args+=("-DMONGOCRYPT_TESTING_CRYPT_SHARED_FILE=$cand")
    fi
done

build_dir="$LIBMONGOCRYPT_DIR/cmake-build"

if test "${CMAKE_GENERATOR-}" = Ninja; then
    export NINJA_EXE
    : "${NINJA_EXE:="$build_dir/ninja$EXE_SUFFIX"}"
    cmake_args+=(-DCMAKE_MAKE_PROGRAM="$NINJA_EXE")
    bash "$EVG_DIR/ensure-ninja.sh"
fi

# Build and install libmongocrypt.
run_cmake "${cmake_args[@]}"

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
run_cmake --build "$build_dir" --target install test-mongocrypt test_kms_request
run_chdir "$build_dir" run_ctest

# MONGOCRYPT-372, ensure macOS universal builds contain both x86_64 and arm64 architectures.
if test "${CMAKE_OSX_ARCHITECTURES-}" != ''; then
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

# Build and install libmongocrypt with no native crypto.
run_cmake \
    -DDISABLE_NATIVE_CRYPTO=ON \
    "${cmake_args[@]}" \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/nocrypto"

run_cmake --build "$build_dir" --target install test-mongocrypt
run_chdir "$build_dir" run_ctest

# Build and install libmongocrypt without statically linking libbson
run_cmake \
    -UDISABLE_NATIVE_CRYPTO \
    -DUSE_SHARED_LIBBSON=ON \
    "${cmake_args[@]}" \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/sharedbson"

run_cmake --build "$build_dir" --target install
run_chdir "$build_dir" run_ctest
