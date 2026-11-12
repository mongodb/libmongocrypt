# Copyright 2026-present MongoDB, Inc.
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

"""Test the binary module."""

import sys

sys.path[0:0] = [""]

from test import unittest

from pymongocrypt.binary import MongoCryptBinaryIn, _write_bytes
from pymongocrypt.errors import MongoCryptError


class TestWriteBytesBoundsCheck(unittest.TestCase):
    def test_rejects_write_larger_than_capacity(self):
        data = bytearray(512)
        with MongoCryptBinaryIn(data) as out:
            out.bin.len = 256
            with self.assertRaises(MongoCryptError):
                _write_bytes(out.bin, b"\xff" * 300)
        self.assertTrue(
            all(byte == 0 for byte in data),
            "a rejected write must not modify the buffer at all",
        )

    def test_allows_write_equal_to_capacity(self):
        data = bytearray(256)
        with MongoCryptBinaryIn(data) as out:
            _write_bytes(out.bin, b"\xab" * 256)
            self.assertEqual(out.bin.len, 256)
            self.assertEqual(out.to_bytes(), b"\xab" * 256)

    def test_allows_write_smaller_than_capacity(self):
        data = bytearray(256)
        with MongoCryptBinaryIn(data) as out:
            _write_bytes(out.bin, b"\xcd" * 100)
            self.assertEqual(out.bin.len, 100)
            self.assertEqual(out.to_bytes(), b"\xcd" * 100)


if __name__ == "__main__":
    unittest.main()
