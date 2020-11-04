# Copyright 2019-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test the binding module."""

import sys

sys.path[0:0] = [""]

import pymongocrypt
from pymongocrypt.binding import ffi, lib, _parse_version

from test import unittest


class TestBinding(unittest.TestCase):

    def assertVersionLike(self, version):
        self.assertTrue(isinstance(version, str), msg=version)
        # There should be at least one dot: "1.0" or "1.0.0" not "1".
        self.assertGreaterEqual(len(version.split('.')), 2, msg=version)

    def test_pymongocrypt_version(self):
        self.assertVersionLike(pymongocrypt.__version__)

    def test_libmongocrypt_version(self):
        self.assertVersionLike(pymongocrypt.libmongocrypt_version())

    def test_mongocrypt_new(self):
        data = lib.mongocrypt_new()
        self.assertNotEqual(data, ffi.NULL)
        lib.mongocrypt_destroy(data)

    def test_mongocrypt_binary_new(self):
        data = lib.mongocrypt_binary_new()
        self.assertNotEqual(data, ffi.NULL)
        lib.mongocrypt_binary_destroy(data)

    def test_mongocrypt_status_new(self):
        data = lib.mongocrypt_status_new()
        self.assertNotEqual(data, ffi.NULL)
        lib.mongocrypt_status_destroy(data)

    def test_parse_version(self):
        # Dev versions, betas, RCs should be less than stable releases.
        for v in ('1.1.0-beta1', '1.1.0-b2', '1.1.0-rc1',
                  '1.1.0-beta1', '1.1.0-pre1'):
            self.assertLess(_parse_version(v),
                            _parse_version('1.1.0'))

        # Dev versions should parse correctly.
        _parse_version('1.1.0-beta1+20201102git80202647fc')

        # Hyphenation in patch version should be disregarded.
        self.assertEqual(_parse_version('1.1.0-beta1'),
                         _parse_version('1.1.0beta1'))


if __name__ == "__main__":
    unittest.main()
