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

from pymongocrypt.binding import ffi, lib, _to_string


class MongoCryptError(Exception):
    def __init__(self, msg, code=-1):
        """Top level Exception for all MongoCrypt errors.

        :Parameters:
          - `msg`: An error message.
          - `code`: The mongocrypt_status_t code.
        """
        super(MongoCryptError, self).__init__(msg)
        self.code = code

    @classmethod
    def from_status(cls, status):
        """Constructs an error from a mongocrypt_status_t.

        :Parameters:
          - `status`: A CFFI mongocrypt_status_t.
        """
        if lib.mongocrypt_status_ok(status):
            raise ValueError("status must not be ok")
        msg = _to_string(lib.mongocrypt_status_message(status, ffi.NULL))
        return cls(msg, lib.mongocrypt_status_code(status))
