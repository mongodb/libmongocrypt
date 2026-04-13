#!/bin/bash
# Compiles libmongocrypt dependencies and targets.
#
# Set extra compilation for libmongocrypt variables by setting CFLAGS and CXXFLAGS.

echo "Begin compile process"

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

set -eu

if command -v ldd &> /dev/null; then
    # Print verison of libc:
    echo "Output of 'ldd --version':"
    ldd --version || true
fi

# Directory where build files will be stored
: "${BINARY_DIR:="$LIBMONGOCRYPT_DIR/cmake-build"}"
# Additional compilation flags that apply only to the libmongocrypt build
: "${LIBMONGOCRYPT_COMPILE_FLAGS:=}"
# Additional CMake flags that apply only to the libmongocrypt build. (Used by the C driver)
: "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS:=}"
# release_os_arch is set for release builds.
: "${release_os_arch:=}"

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
# Permit skipping build of tests.
BUILD_TESTING="${BUILD_TESTING-TRUE}"
# Build nocrypto and sharedbson variants (true by defualt).
LIBMONGOCRYPT_BUILD_VARIANTS="${LIBMONGOCRYPT_BUILD_VARIANTS:-TRUE}"

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
    -D BUILD_TESTING="${BUILD_TESTING:?}"
    # Enable additional warnings-as-errors
    -D ENABLE_MORE_WARNINGS_AS_ERRORS=TRUE
)

# shellcheck disable=SC2206
cmake_args+=($LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS)

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
_cmake_with_env --build "$BINARY_DIR" --target install

# If release_os_arch names a minimum glibc requirement (e.g. "linux-x86_64-glibc_2_17-nocrypto"),
# verify it matches the maximum glibc symbol used.
if [[ "$release_os_arch" == *glibc* ]]; then
    expected_glibc=$(echo "$release_os_arch" | sed -r 's/.*glibc_([0-9]+)_([0-9]+).*/\1.\2/')
    if [ -f "$CMAKE_INSTALL_PREFIX/lib64/libmongocrypt.so" ]; then
        check_lib="$CMAKE_INSTALL_PREFIX/lib64/libmongocrypt.so"
    elif [ -f "$CMAKE_INSTALL_PREFIX/lib/libmongocrypt.so" ]; then
        check_lib="$CMAKE_INSTALL_PREFIX/lib/libmongocrypt.so"
    else
        echo "glibc version check failed: libmongocrypt.so not found under $CMAKE_INSTALL_PREFIX"
        exit 1
    fi
    actual_glibc=$(objdump -T "$check_lib" | grep 'GLIBC_' | sed -r -e 's/.*GLIBC_([0-9.]+).*/\1/' | sort -u | tail -1)
    if [ "$actual_glibc" != "$expected_glibc" ]; then
        echo "glibc version check failed: release_os_arch requires glibc $expected_glibc but library uses glibc $actual_glibc"
        exit 1
    fi
    echo "glibc version check passed: $actual_glibc"
fi

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

if [ "${LIBMONGOCRYPT_BUILD_VARIANTS:?}" != "TRUE" ]; then
    echo "Skipping build of libmongocrypt variants";
    exit 0;
fi

# Build and install libmongocrypt with no native crypto.
_cmake_with_env "${cmake_args[@]}" \
    -DDISABLE_NATIVE_CRYPTO=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/nocrypto" \
    -B "$BINARY_DIR" -S "$LIBMONGOCRYPT_DIR"
_cmake_with_env --build "$BINARY_DIR" --target install
run_chdir "$BINARY_DIR" run_ctest

# Build and install libmongocrypt without statically linking libbson
_cmake_with_env "${cmake_args[@]}" \
    -DUSE_SHARED_LIBBSON=ON \
    -DCMAKE_INSTALL_PREFIX="$MONGOCRYPT_INSTALL_PREFIX/sharedbson" \
    -B "$BINARY_DIR" -S "$LIBMONGOCRYPT_DIR"
_cmake_with_env --build "$BINARY_DIR" --target install
run_chdir "$BINARY_DIR" run_ctest
