#!/bin/bash
set -o xtrace
set -o errexit

system_path () {
    if [ "$OS" == "Windows_NT" ]; then
        cygpath -a "$1" -w
    else
        echo $1
    fi
}

if [ ! -e ./.evergreen ]; then
    echo "Error: run from libmongocrypt root"
    exit 1;
fi

if [ ! $(command -v pkg-config) ]; then
    echo "pkg-config not present on this platform; skipping test ..."
    exit 0
fi

libmongocrypt_root=$(pwd)
pkgconfig_tests_root=${libmongocrypt_root}/pkgconfig_tests

rm -rf pkgconfig_tests
mkdir -p pkgconfig_tests/{install,libmongocrypt-cmake-build}
cd pkgconfig_tests

git clone https://github.com/mongodb/mongo-c-driver.git --depth=1 --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

mkdir cmake-build
cd cmake-build
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install)"
SRC_PATH="$(system_path ../)"
$CMAKE -DBUILD_VERSION=1.18.0-pre -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

# Build libmongocrypt, static linking against libbson
cd $pkgconfig_tests_root/libmongocrypt-cmake-build
PREFIX_PATH="$(system_path $pkgconfig_tests_root/install)"
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DENABLE_SHARED_BSON=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH="$PREFIX_PATH" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

export PKG_CONFIG_PATH="$(system_path $(/usr/bin/dirname $(/usr/bin/find $pkgconfig_tests_root/install -name libbson-1.0.pc))):$(system_path $(/usr/bin/dirname $(/usr/bin/find $pkgconfig_tests_root/install/libmongocrypt -name libmongocrypt.pc)))"

# Build example-state-machine, static linking against libmongocrypt
cd $libmongocrypt_root
gcc $(pkg-config --cflags libmongocrypt-static) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt-static)
./example-state-machine

rm -f example-state-machine

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib64)"
./example-state-machine
unset LD_LIBRARY_PATH

rm -f example-state-machine

# Clean up prior to next execution
cd $pkgconfig_tests_root
rm -rf libmongocrypt-cmake-build install/libmongocrypt
mkdir -p libmongocrypt-cmake-build

# Build libmongocrypt, dynamic linking against libbson
cd $pkgconfig_tests_root/libmongocrypt-cmake-build
PREFIX_PATH="$(system_path $pkgconfig_tests_root/install)"
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DENABLE_SHARED_BSON=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH="$PREFIX_PATH" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

# Build example-state-machine, static linking against libmongocrypt
cd $libmongocrypt_root
gcc $(pkg-config --cflags libmongocrypt-static) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt-static)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/lib):$(system_path $pkgconfig_tests_root/install/lib64)"
./example-state-machine
unset LD_LIBRARY_PATH

rm -f example-state-machine

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/lib):$(system_path $pkgconfig_tests_root/install/lib64):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib64)"
./example-state-machine
unset LD_LIBRARY_PATH

rm -f example-state-machine

