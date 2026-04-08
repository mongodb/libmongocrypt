#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# OSS-Fuzz build script for libmongocrypt
# This script is called by OSS-Fuzz to build the fuzzing targets

cd $SRC/libmongocrypt

# Build the library
mkdir -p build
cd build

# Configure with CMake
# Note: OSS-Fuzz sets CC, CXX, CFLAGS, CXXFLAGS, LIB_FUZZING_ENGINE
cmake .. \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DENABLE_ONLINE_TESTS=OFF \
    -DENABLE_STATIC=ON

# Build the library
make -j$(nproc) mongocrypt_static

# Build the fuzzers
# fuzz_kms - existing KMS fuzzer
$CC $CFLAGS -c ../test/fuzz_kms.c -I../kms-message/src -I../src -o fuzz_kms.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_kms.o \
    -o $OUT/fuzz_kms \
    libmongocrypt_static.a \
    kms-message/libkms_message_static.a \
    -Wl,--start-group \
    _mongo-c-driver/src/libbson/libbson-static-for-libmongocrypt.a \
    -Wl,--end-group

# fuzz_mongocrypt - main libmongocrypt fuzzer (placeholder)
$CC $CFLAGS -c ../test/fuzz_mongocrypt.c -I../src -I. -o fuzz_mongocrypt.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_mongocrypt.o \
    -o $OUT/fuzz_mongocrypt \
    libmongocrypt_static.a \
    kms-message/libkms_message_static.a \
    -Wl,--start-group \
    _mongo-c-driver/src/libbson/libbson-static-for-libmongocrypt.a \
    -Wl,--end-group

# Package seed corpus for fuzz_mongocrypt
mkdir -p $OUT/fuzz_mongocrypt_seed_corpus
cp ../test/data/fuzz_mongocrypt_corpus/* $OUT/fuzz_mongocrypt_seed_corpus/
zip -j $OUT/fuzz_mongocrypt_seed_corpus.zip $OUT/fuzz_mongocrypt_seed_corpus/*

