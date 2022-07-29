#!/bin/bash -ex

# This script should be run on macOS and Cygwin on Windows.
# On macOS it will create the following distributions:
# pymongocrypt-<version>.tar.gz
# pymongocrypt-<version>-py2.py3-none-manylinux2010_x86_64.whl
# pymongocrypt-<version>-py2.py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.whl
# pymongocrypt-<version>-py2.py3-none-macosx_10_9_x86_64.whl
#
# On Windows it will create the following distribution:
# pymongocrypt-<version>-py2.py3-none-win_amd64.whl

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

# The libmongocrypt git revision release to embed in our wheels.
REVISION=$(git rev-list -n 1 1.5.2)
# The libmongocrypt release branch.
BRANCH="r1.5"

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    rm -rf venv37
    virtualenv -p C:\\python\\Python37\\python.exe venv37 && . ./venv37/Scripts/activate

    # Build the Windows wheel
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/windows-test/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
    mkdir libmongocrypt
    tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
    NOCRYPTO_SO=libmongocrypt/nocrypto/bin/mongocrypt.dll
    chmod +x ${NOCRYPTO_SO}
    cp ${NOCRYPTO_SO} pymongocrypt/
    rm -rf ./libmongocrypt libmongocrypt.tar.gz

    python setup.py bdist_wheel
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    ls dist
elif [ "Darwin" = "$(uname -s)" ]; then
    PYTHON="/Library/Frameworks/Python.framework/Versions/3.7/bin/python3"
    # Build the source dist first
    rm -rf build pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    $PYTHON setup.py sdist

    # Build the manylinux2010 wheels
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/rhel-62-64-bit/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
    mkdir libmongocrypt
    tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
    NOCRYPTO_SO=libmongocrypt/nocrypto/lib64/libmongocrypt.so
    chmod +x ${NOCRYPTO_SO}
    cp ${NOCRYPTO_SO} pymongocrypt/
    rm -rf ./libmongocrypt libmongocrypt.tar.gz

    # 2021-05-05-1ac6ef3 was the last release to generate pip < 20.3 compatible
    # wheels. After that auditwheel was upgraded to v4 which produces PEP 600
    # manylinux_x_y wheels which requires pip >= 20.3. We use the older docker
    # image to support older pip versions.
    images=(quay.io/pypa/manylinux2010_x86_64:2021-05-05-1ac6ef3 \
            quay.io/pypa/manylinux2010_x86_64)
    for image in "${images[@]}"; do
        docker pull $image
        docker run --rm -v `pwd`:/python $image /python/build-manylinux-wheel.sh
    done

    # Build the x86_64 only mac wheel
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/macos_x86_64/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
    mkdir libmongocrypt
    tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
    NOCRYPTO_SO=libmongocrypt/nocrypto/lib/libmongocrypt.dylib
    chmod +x ${NOCRYPTO_SO}
    cp ${NOCRYPTO_SO} pymongocrypt/
    rm -rf ./libmongocrypt libmongocrypt.tar.gz

    $PYTHON setup.py bdist_wheel

    # Build the universal mac wheel
    PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/macos/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
    mkdir libmongocrypt
    tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
    NOCRYPTO_SO=libmongocrypt/nocrypto/lib/libmongocrypt.dylib
    chmod +x ${NOCRYPTO_SO}
    cp ${NOCRYPTO_SO} pymongocrypt/
    rm -rf ./libmongocrypt libmongocrypt.tar.gz

    $PYTHON setup.py bdist_wheel
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    ls dist
else
   echo "ERROR: Run this script on macOS or Windows"
   exit 1
fi
