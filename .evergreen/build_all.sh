#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
#
# Set extra compilation for libmongocrypt variables by setting CFLAGS and CXXFLAGS.

echo "Begin compile process"

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

set -eu

# Directory where build files will be stored
: "${BINARY_DIR:="$LIBMONGOCRYPT_DIR/cmake-build"}"
# Additional compilation flags that apply only to the libmongocrypt build
: "${LIBMONGOCRYPT_COMPILE_FLAGS:=}"

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
    # Set the build type. CMake 3.22 recognizes this via environment variable
    -D CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    # Set the install prefix. CMake 3.29 recognizes this via environment variable
    -D CMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX"
    # Toggle compiling with shared BSON
    -D USE_SHARED_LIBBSON="${USE_SHARED_LIBBSON-FALSE}"
    # Toggle building of tests
    -D BUILD_TESTING="${BUILD_TESTING-TRUE}"
    # Enable additional warnings-as-errors
    -D ENABLE_MORE_WARNINGS_AS_ERRORS=TRUE
)

: "${CONFIGURE_ONLY:=}"

if [ "$PPA_BUILD_ONLY" ]; then
    # Clean-up from previous build iteration
    rm -rf -- "$LIBMONGOCRYPT_DIR"/cmake-build* "$CMAKE_INSTALL_PREFIX"
    cmake_args+=(-DENABLE_BUILD_FOR_PPA=ON)
fi

for suffix in "dll" "dylib" "so"; do
    cand="$(abspath "$LIBMONGOCRYPT_DIR/../mongocrypt_v1.$suffix")"
    if test -f "$cand"; then
        cmake_args+=("-DMONGOCRYPT_TESTING_CRYPT_SHARED_FILE=$cand")
    fi
done

if test "${CMAKE_GENERATOR-}" = Ninja; then
    export NINJA_EXE
    : "${NINJA_EXE:="$BINARY_DIR/ninja$EXE_SUFFIX"}"
    cmake_args+=(-DCMAKE_MAKE_PROGRAM="$NINJA_EXE")
    bash "$EVG_DIR/ensure-ninja.sh"
fi

# A command that prepends our custom compile flags for any CMake execution
_cmake_with_env() {
    # Prepend our custom C and CXX flags for any possible CMake builds
    CFLAGS="$LIBMONGOCRYPT_COMPILE_FLAGS ${CFLAGS-}" \
    CXXFLAGS="$LIBMONGOCRYPT_COMPILE_FLAGS ${CXXFLAGS-}" \
        run_cmake "$@"
}

# Build and install libmongocrypt.
_cmake_with_env "${cmake_args[@]}" \
    -B "$BINARY_DIR" -S "$LIBMONGOCRYPT_DIR"

if [ "$CONFIGURE_ONLY" ]; then
    echo "Only running cmake";
    exit 0;
fi
echo "Installing libmongocrypt"
_cmake_with_env --build "$BINARY_DIR" --target install test-mongocrypt test_kms_request
run_chdir "$BINARY_DIR" run_ctest

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
_cmake_with_env "${cmake_args[@]}" \
    -DDISABLE_NATIVE_CRYPTO=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/nocrypto" \
    -B "$BINARY_DIR" -S "$LIBMONGOCRYPT_DIR"
_cmake_with_env --build "$BINARY_DIR" --target install test-mongocrypt
run_chdir "$BINARY_DIR" run_ctest

# Build and install libmongocrypt without statically linking libbson
_cmake_with_env "${cmake_args[@]}" \
    -DUSE_SHARED_LIBBSON=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/sharedbson" \
    -B "$BINARY_DIR" -S "$LIBMONGOCRYPT_DIR"
_cmake_with_env --build "$BINARY_DIR" --target install test-mongocrypt
run_chdir "$BINARY_DIR" run_ctest
