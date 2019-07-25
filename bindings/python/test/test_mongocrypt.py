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

"""Test the mongocrypt module."""

import os
import sys

from bson import json_util, BSON
from bson.binary import STANDARD
from bson.codec_options import CodecOptions

sys.path[0:0] = [""]

from pymongocrypt.binding import lib
from pymongocrypt.errors import MongoCryptError
from pymongocrypt.mongocrypt import (MongoCrypt,
                                     MongoCryptBinaryIn,
                                     MongoCryptBinaryOut,
                                     MongoCryptOptions)

from test import enable_faulthandler, unittest


enable_faulthandler()


# Data for testing libbmongocrypt binding.
DATA_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), 'data'))


class TestMongoCryptBinary(unittest.TestCase):

    def test_mongocrypt_binary_in(self):
        with MongoCryptBinaryIn(b'1\x0023') as binary:
            self.assertIsNotNone(binary.bin)
            self.assertEqual(binary.to_bytes(), b'1\x0023')
        self.assertIsNone(binary.bin)

        with MongoCryptBinaryIn(b'') as binary:
            self.assertIsNotNone(binary.bin)
            self.assertEqual(binary.to_bytes(), b'')
        self.assertIsNone(binary.bin)

    def test_mongocrypt_binary_out(self):
        with MongoCryptBinaryOut() as binary:
            self.assertIsNotNone(binary.bin)
            self.assertEqual(binary.to_bytes(), b'')
        self.assertIsNone(binary.bin)


class TestMongoCryptOptions(unittest.TestCase):

    def test_mongocrypt_options(self):
        valid = [
            ({'aws': {'accessKeyId': '', 'secretAccessKey': ''}}, None),
            ({'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'}}, None),
            ({'local': {'key': b'1'*96}}, None),
            ({'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'},
              'local': {'key': b'1'*96}}, None),
        ]
        for kms_providers, schema_map in valid:
            opts = MongoCryptOptions(kms_providers, schema_map)
            self.assertEqual(opts.kms_providers, kms_providers)
            self.assertEqual(opts.schema_map, schema_map)

    def test_mongocrypt_options_validation(self):
        with self.assertRaisesRegex(
                ValueError, 'at least one KMS provider must be configured'):
            MongoCryptOptions({})
        for invalid_kms_providers in [
                {'aws': {}},
                {'aws': {'accessKeyId': 'foo'}},
                {'aws': {'secretAccessKey': 'foo'}}]:
            with self.assertRaisesRegex(
                    ValueError, "kms_providers\['aws'\] must contain "
                                "'accessKeyId' and 'secretAccessKey'"):
                MongoCryptOptions(invalid_kms_providers)
        with self.assertRaisesRegex(
                TypeError, "kms_providers\['local'\]\['key'\] must be a "
                           "bytes \(or str in Python 2\)"):
            MongoCryptOptions({'local': {'key': None}})


class TestMongoCrypt(unittest.TestCase):

    def test_mongocrypt(self):
        kms_providers = {
            'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'}}
        opts = MongoCryptOptions(kms_providers)
        mc = MongoCrypt(opts)
        mc.close()
        mc.close()

    def test_mongocrypt_validation(self):
        with self.assertRaisesRegex(
                TypeError, 'options must be a MongoCryptOptions'):
            MongoCrypt({})
        with self.assertRaisesRegex(
                TypeError, 'options must be a MongoCryptOptions'):
            MongoCrypt(None)

        invalid_key_len_opts = MongoCryptOptions({'local': {'key': b'1'}})
        with self.assertRaisesRegex(
                MongoCryptError, "local key must be 96 bytes"):
            MongoCrypt(invalid_key_len_opts)

    @staticmethod
    def create_mongocrypt():
        return MongoCrypt(MongoCryptOptions({
            'aws': {'accessKeyId': 'example', 'secretAccessKey': 'example'},
            'local': {'key': b'\x00'*96}}))

    def _test_kms_context(self, ctx):
        key_filter = ctx.mongo_operation()
        self.assertEqual(key_filter, bson_data('key-filter.json'))
        ctx.add_mongo_operation_result(bson_data('key-document.json'))
        ctx.complete_mongo_operation()
        self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_KMS)

        km_contexts = list(ctx.kms_contexts())
        self.assertEqual(len(km_contexts), 1)
        with km_contexts[0] as kms_ctx:
            self.assertEqual(kms_ctx.endpoint, "kms.us-east-1.amazonaws.com")
            self.assertEqual(len(kms_ctx.message), 781)
            self.assertEqual(kms_ctx.bytes_needed, 1024)

            kms_ctx.feed(http_data('kms-reply.txt'))
            self.assertEqual(kms_ctx.bytes_needed, 0)

        ctx.complete_kms()

    def test_encrypt(self):
        mc = self.create_mongocrypt()
        self.addCleanup(mc.close)
        with mc.encryption_context('text', bson_data('command.json')) as ctx:
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO)

            list_colls_filter = ctx.mongo_operation()
            self.assertEqual(list_colls_filter,
                             bson_data('list-collections-filter.json'))

            ctx.add_mongo_operation_result(bson_data('collection-info.json'))
            ctx.complete_mongo_operation()
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS)

            mongocryptd_cmd = ctx.mongo_operation()
            self.assertEqual(mongocryptd_cmd,
                             bson_data('mongocryptd-command.json'))

            ctx.add_mongo_operation_result(bson_data('mongocryptd-reply.json'))
            ctx.complete_mongo_operation()
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)

            self._test_kms_context(ctx)

            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_READY)

            encrypted = ctx.finish()
            self.assertEqual(
                BSON(encrypted).decode(), json_data('encrypted-command.json'))
            self.assertEqual(encrypted, bson_data('encrypted-command.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_DONE)

    def test_decrypt(self):
        mc = self.create_mongocrypt()
        self.addCleanup(mc.close)
        with mc.decryption_context(
                bson_data('encrypted-command-reply.json')) as ctx:
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)

            self._test_kms_context(ctx)

            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_READY)

            encrypted = ctx.finish()
            self.assertEqual(
                BSON(encrypted).decode(), json_data('command-reply.json'))
            self.assertEqual(encrypted, bson_data('command-reply.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_DONE)


def read(filename, **kwargs):
    print(filename)
    with open(os.path.join(DATA_DIR, filename), **kwargs) as fp:
        return fp.read()


OPTS = CodecOptions(uuid_representation=STANDARD)


def json_data(filename):
    return json_util.loads(read(filename))


def bson_data(filename):
    return BSON.encode(json_data(filename), codec_options=OPTS)


def http_data(filename):
    data = read(filename, mode='rb')
    return data.replace(b'\n', b'\r\n')


if __name__ == "__main__":
    unittest.main()
