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

"""Internal helpers for dealing with mongocrypt_binary_t."""

from pymongocrypt.binding import ffi, lib
from pymongocrypt.errors import MongoCryptError


def _to_bytes(mongocrypt_binary):
    """Returns this mongocrypt_binary_t as bytes."""
    data = lib.mongocrypt_binary_data(mongocrypt_binary)
    if data == ffi.NULL:
        raise MongoCryptError('mongocrypt_binary_data returned NULL')
    data_len = lib.mongocrypt_binary_len(mongocrypt_binary)
    return ffi.unpack(ffi.cast("char*", data), data_len)


def _write_bytes(mongocrypt_binary, data):
    """Writes the given data to a mongocrypt_binary_t."""
    buf = lib.mongocrypt_binary_data(mongocrypt_binary)
    if buf == ffi.NULL:
        raise MongoCryptError('mongocrypt_binary_data returned NULL')

    ffi.memmove(buf, data, len(data))


class _MongoCryptBinary(object):
    __slots__ = ("bin",)

    def __init__(self, binary):
        """Wraps a mongocrypt_binary_t."""
        if binary == ffi.NULL:
            raise MongoCryptError(
                "unable to create new mongocrypt_binary object")
        self.bin = binary

    def _close(self):
        """Cleanup resources."""
        if self.bin:
            lib.mongocrypt_binary_destroy(self.bin)
            self.bin = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    def to_bytes(self):
        """Returns this mongocrypt_binary_t as bytes."""
        data = lib.mongocrypt_binary_data(self.bin)
        if data == ffi.NULL:
            return b''
        data_len = lib.mongocrypt_binary_len(self.bin)
        return ffi.unpack(ffi.cast("char*", data), data_len)


class MongoCryptBinaryOut(_MongoCryptBinary):
    __slots__ = ()

    def __init__(self):
        """Wraps a mongocrypt_binary_t."""
        super(MongoCryptBinaryOut, self).__init__(lib.mongocrypt_binary_new())


class MongoCryptBinaryIn(_MongoCryptBinary):
    __slots__ = ("cref",)

    def __init__(self, data):
        """Creates a mongocrypt_binary_t from binary data."""
        # mongocrypt_binary_t does not own the data it is passed so we need to
        # create a separate reference to keep the data alive.
        self.cref = ffi.from_buffer("uint8_t[]", data)
        super(MongoCryptBinaryIn, self).__init__(
            lib.mongocrypt_binary_new_from_data(self.cref, len(data)))

    def _close(self):
        """Cleanup resources."""
        super(MongoCryptBinaryIn, self)._close()
        if self.cref is not None:
            ffi.release(self.cref)
            self.cref = None
