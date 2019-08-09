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

"""Internal crypto callbacks for libmongocrypt."""

import os
import traceback

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

from pymongocrypt.binary import _to_bytes, _write_bytes
from pymongocrypt.binding import ffi, lib
from pymongocrypt.compat import str_to_bytes


def _callback_error_handler(exception, exc_value, tb):
    """Set the mongocrypt_status_t on error."""
    # From cffi docs: "First check if traceback is not None (it is None e.g.
    # if the whole function ran successfully but there was an error converting
    # the value returned: this occurs after the call)."
    if tb is None:
        return

    status = tb.tb_frame.f_locals['status']
    msg = str_to_bytes(''.join(traceback.format_exception(
        exception, exc_value, tb)))
    # TODO: the +1 in len(msg)+1 is a libmongocrypt bug.
    lib.mongocrypt_status_set(
        status, lib.MONGOCRYPT_STATUS_ERROR_CLIENT, 1, msg, len(msg)+1)

    return False


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, mongocrypt_binary_t *,"
    "     mongocrypt_binary_t *, mongocrypt_binary_t *, uint32_t *,"
    "     mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def aes_256_cbc_encrypt(ctx, key, iv, input, output, bytes_written, status):
    # TODO: Java uses noPadding but CBC says padding is required:
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC
    cipher = Cipher(algorithms.AES(_to_bytes(key)), modes.CBC(_to_bytes(iv)),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    data = encryptor.update(_to_bytes(input)) + encryptor.finalize()
    _write_bytes(output, data)
    bytes_written[0] = len(data)
    return True


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, mongocrypt_binary_t *,"
    "     mongocrypt_binary_t *, mongocrypt_binary_t *, uint32_t *,"
    "     mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def aes_256_cbc_decrypt(ctx, key, iv, input, output, bytes_written, status):
    cipher = Cipher(algorithms.AES(_to_bytes(key)), modes.CBC(_to_bytes(iv)),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(_to_bytes(input)) + decryptor.finalize()
    _write_bytes(output, data)
    bytes_written[0] = len(data)
    return True


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, mongocrypt_binary_t *, "
    "     mongocrypt_binary_t *, mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def hmac_sha_256(ctx, key, input, output, status):
    h = HMAC(_to_bytes(key), SHA256(), backend=default_backend())
    h.update(_to_bytes(input))
    data = h.finalize()
    _write_bytes(output, data)
    return True


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, mongocrypt_binary_t *, "
    "     mongocrypt_binary_t *, mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def hmac_sha_512(ctx, key, input, output, status):
    h = HMAC(_to_bytes(key), SHA512(), backend=default_backend())
    h.update(_to_bytes(input))
    data = h.finalize()
    _write_bytes(output, data)
    return True


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, mongocrypt_binary_t *, "
    "     mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def sha_256(ctx, input, output, status):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(_to_bytes(input))
    data = digest.finalize()
    _write_bytes(output, data)
    return True


@ffi.callback(
    "bool(void *, mongocrypt_binary_t *, uint32_t, mongocrypt_status_t *)",
    onerror=_callback_error_handler)
def secure_random(ctx, output, count, status):
    data = os.urandom(int(count))
    _write_bytes(output, data)
    return True
