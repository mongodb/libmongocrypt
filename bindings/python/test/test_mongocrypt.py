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

import base64
import copy
import json
import os
import sys

import bson
from bson.raw_bson import RawBSONDocument
from bson import json_util
from bson.binary import Binary, UuidRepresentation
from bson.codec_options import CodecOptions
from bson.json_util import JSONOptions
from bson.son import SON

sys.path[0:0] = [""]

import pymongocrypt.mongocrypt
from pymongo_auth_aws.auth import AwsCredential
from pymongocrypt.auto_encrypter import AutoEncrypter
from pymongocrypt.binding import lib
from pymongocrypt.compat import unicode_type, PY3
from pymongocrypt.errors import MongoCryptError
from pymongocrypt.explicit_encrypter import ExplicitEncrypter
from pymongocrypt.mongocrypt import (MongoCrypt,
                                     MongoCryptBinaryIn,
                                     MongoCryptBinaryOut,
                                     MongoCryptOptions)
from pymongocrypt.state_machine import MongoCryptCallback

from test import unittest, mock

import requests.exceptions
import requests_mock


# Data for testing libbmongocrypt binding.
DATA_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), 'data'))


def to_base64(data):
    b64 = base64.b64encode(data)
    if not PY3:
        return unicode_type(b64)
    return b64.decode('utf-8')


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

        # Memoryview
        with MongoCryptBinaryIn(memoryview(b'1\x0023')) as binary:
            self.assertIsNotNone(binary.bin)
            self.assertEqual(binary.to_bytes(), b'1\x0023')
        self.assertIsNone(binary.bin)

    def test_mongocrypt_binary_out(self):
        with MongoCryptBinaryOut() as binary:
            self.assertIsNotNone(binary.bin)
            self.assertEqual(binary.to_bytes(), b'')
        self.assertIsNone(binary.bin)


class TestMongoCryptOptions(unittest.TestCase):

    def test_mongocrypt_options(self):
        schema_map = bson_data('schema-map.json')
        valid = [
            ({'local': {'key': b'1' * 96}}, None),
            ({ 'aws' : {} }, schema_map),
            ({'aws': {'accessKeyId': '', 'secretAccessKey': ''}}, schema_map),
            ({'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'}}, None),
            ({'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo',
                      'sessionToken': 'token'}}, None),
            ({'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'},
              'local': {'key': b'1' * 96}}, None),
            ({'local': {'key': to_base64(b'1' * 96)}}, None),
            ({'local': {'key': Binary(b'1' * 96)}}, None),
            ({'azure': {}}, None),
            ({'azure': {'clientId': 'foo', 'clientSecret': 'bar'}}, None),
            ({'gcp': {}}, None),
            ({'gcp': {'email': 'foo@bar.baz',
                      'privateKey': b'1'}}, None),
            ({'gcp': {'email': 'foo@bar.baz',
                      'privateKey': to_base64(b'1')}}, None),
            ({'gcp': {'email': 'foo@bar.baz',
                      'privateKey': Binary(b'1')}}, None)
        ]
        for kms_providers, schema_map in valid:
            opts = MongoCryptOptions(kms_providers, schema_map)
            self.assertEqual(opts.kms_providers, kms_providers, msg=kms_providers)
            self.assertEqual(opts.schema_map, schema_map)
            self.assertIsNone(opts.encrypted_fields_map)
            self.assertFalse(opts.bypass_query_analysis)

        encrypted_fields_map = bson_data('encrypted-field-config-map.json')
        opts = MongoCryptOptions(valid[0][0], schema_map, encrypted_fields_map=encrypted_fields_map,
                                 bypass_query_analysis=True)
        self.assertEqual(opts.encrypted_fields_map, encrypted_fields_map)
        self.assertTrue(opts.bypass_query_analysis)

    def test_mongocrypt_options_validation(self):
        with self.assertRaisesRegex(
                ValueError, 'at least one KMS provider must be configured'):
            MongoCryptOptions({})
        for invalid_kms_providers in [
                {'aws': {'accessKeyId': 'foo'}},
                {'aws': {'secretAccessKey': 'foo'}}]:
            with self.assertRaisesRegex(
                    ValueError, r"kms_providers\['aws'\] must contain "
                                "'accessKeyId' and 'secretAccessKey'"):
                MongoCryptOptions(invalid_kms_providers)
        with self.assertRaisesRegex(
                TypeError, r"kms_providers\['local'\]\['key'\] must be an "
                           r"instance of bytes or str \(unicode in Python 2\)"):
            MongoCryptOptions({'local': {'key': None}})
        with self.assertRaisesRegex(
                TypeError, r"kms_providers\['gcp'\]\['privateKey'\] must be an "
                           r"instance of bytes or str \(unicode in Python 2\)"):
            MongoCryptOptions({'gcp': {'email': "foo@bar.baz",
                                       "privateKey": None}})

        valid_kms = {'aws': {'accessKeyId': '', 'secretAccessKey': ''}}
        with self.assertRaisesRegex(
                TypeError, "schema_map must be bytes or None"):
            MongoCryptOptions(valid_kms, schema_map={})

        with self.assertRaisesRegex(
                TypeError, "encrypted_fields_map must be bytes or None"):
            MongoCryptOptions(valid_kms, encrypted_fields_map={})


class TestMongoCrypt(unittest.TestCase):
    maxDiff = None

    def test_mongocrypt(self):
        kms_providers = {
            'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo'}}
        opts = MongoCryptOptions(kms_providers)
        mc = MongoCrypt(opts, MockCallback())
        mc.close()
        mc.close()

    def test_mongocrypt_aws_session_token(self):
        kms_providers = {
            'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'foo',
                    'sessionToken': 'token'}}
        opts = MongoCryptOptions(kms_providers)
        mc = MongoCrypt(opts, MockCallback())
        mc.close()

    def test_mongocrypt_validation(self):
        callback = MockCallback()
        options = MongoCryptOptions({'local': {'key': b'\x00' * 96}})

        with self.assertRaisesRegex(
                TypeError, 'options must be a MongoCryptOptions'):
            MongoCrypt({}, callback)
        with self.assertRaisesRegex(
                TypeError, 'options must be a MongoCryptOptions'):
            MongoCrypt(None, callback)

        with self.assertRaisesRegex(
                TypeError, 'callback must be a MongoCryptCallback'):
            MongoCrypt(options, {})
        with self.assertRaisesRegex(
                TypeError, 'callback must be a MongoCryptCallback'):
            MongoCrypt(options, None)

        invalid_key_len_opts = MongoCryptOptions({'local': {'key': b'1'}})
        with self.assertRaisesRegex(
                MongoCryptError, "local key must be 96 bytes"):
            MongoCrypt(invalid_key_len_opts, callback)

    def test_setopt_kms_provider_base64_or_bytes(self):
        test_fields = [("local", "key"), ("gcp", "privateKey")]
        callback = MockCallback()
        base_kms_dict = {'local': {'key': b'\x00' * 96},
                         'gcp': {'email': 'foo@bar.baz',
                                 'privateKey': b'\x00'}}

        for f1, f2 in test_fields:
            kms_dict = copy.deepcopy(base_kms_dict)

            # Case 1: pass key as string containing bytes (valid)
            kms_dict[f1][f2] = b'\x00' * 96
            options = MongoCryptOptions(kms_dict)
            mc = MongoCrypt(options, callback)
            mc.close()

            # Case 2: pass key as base64-encoded unicode literal (valid)
            kms_dict[f1][f2] = to_base64(b'\x00' * 96)
            options = MongoCryptOptions(kms_dict)
            mc = MongoCrypt(options, callback)
            mc.close()

            # Case 3: pass key as unicode string containing bytes (invalid)
            kms_dict[f1][f2] = unicode_type(b'\x00' * 96)
            options = MongoCryptOptions(kms_dict)
            with self.assertRaisesRegex(
                    MongoCryptError,
                    "unable to parse base64 from UTF-8 field %s.%s" % (
                            f1, f2)):
                MongoCrypt(options, callback)

        # Case 4: pass key as base64-encoded string (invalid)
        # Only applicable to "local" as key length is not validated for gcp.
        kms_dict = copy.deepcopy(base_kms_dict)
        kms_dict['local']['key'] = base64.b64encode(b'\x00' * 96)
        options = MongoCryptOptions(kms_dict)
        with self.assertRaisesRegex(
                MongoCryptError, "local key must be 96 bytes"):
            MongoCrypt(options, callback)

    @staticmethod
    def create_mongocrypt(**kwargs):
        return MongoCrypt(MongoCryptOptions({
            'aws': {'accessKeyId': 'example', 'secretAccessKey': 'example'},
            'local': {'key': b'\x00'*96}}, **kwargs), MockCallback())

    def _test_kms_context(self, ctx):
        key_filter = ctx.mongo_operation()
        self.assertEqual(key_filter, bson_data('key-filter.json'))
        ctx.add_mongo_operation_result(bson_data('key-document.json'))
        ctx.complete_mongo_operation()
        self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_KMS)

        km_contexts = list(ctx.kms_contexts())
        self.assertEqual(len(km_contexts), 1)
        with km_contexts[0] as kms_ctx:
            self.assertEqual(kms_ctx.kms_provider, "aws")
            self.assertEqual(kms_ctx.endpoint, "kms.us-east-1.amazonaws.com:443")
            self.assertEqual(len(kms_ctx.message), 790)
            self.assertEqual(kms_ctx.bytes_needed, 1024)

            kms_ctx.feed(http_data('kms-reply.txt'))
            self.assertEqual(kms_ctx.bytes_needed, 0)
            self.assertEqual(kms_ctx.kms_provider, "aws")

        ctx.complete_kms()

    def test_encrypt(self):
        mc = self.create_mongocrypt()
        self.addCleanup(mc.close)
        if mc.crypt_shared_lib_version is not None:
            self.skipTest("this test must be skipped when crypt_shared is loaded")
        with mc.encryption_context('text', bson_data('command.json')) as ctx:
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO)

            list_colls_filter = ctx.mongo_operation()
            self.assertEqual(list_colls_filter,
                             bson_data('list-collections-filter.json'))

            ctx.add_mongo_operation_result(bson_data('collection-info.json'))
            ctx.complete_mongo_operation()
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS)

            mongocryptd_cmd = ctx.mongo_operation()
            self.assertEqual(bson.decode(mongocryptd_cmd, OPTS),
                             json_data('mongocryptd-command.json'))
            self.assertEqual(mongocryptd_cmd,
                             bson_data('mongocryptd-command.json'))

            ctx.add_mongo_operation_result(bson_data('mongocryptd-reply.json'))
            ctx.complete_mongo_operation()
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)

            self._test_kms_context(ctx)

            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_READY)

            encrypted = ctx.finish()
            self.assertEqual(bson.decode(encrypted, OPTS),
                             json_data('encrypted-command.json'))
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
            self.assertEqual(bson.decode(encrypted, OPTS),
                             json_data('command-reply.json'))
            self.assertEqual(encrypted, bson_data('command-reply.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_DONE)

    def test_encrypt_encrypted_fields_map(self):
        encrypted_fields_map = bson_data('compact/success/encrypted-field-config-map.json')
        mc = self.create_mongocrypt(encrypted_fields_map=encrypted_fields_map)
        self.addCleanup(mc.close)
        with mc.encryption_context('db', bson_data('compact/success/cmd.json')) as ctx:
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)

            ctx.mongo_operation()
            ctx.add_mongo_operation_result(bson_data(
                'keys/12345678123498761234123456789012-local-document.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)
            ctx.mongo_operation()
            ctx.add_mongo_operation_result(bson_data(
                'keys/ABCDEFAB123498761234123456789012-local-document.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS)
            ctx.mongo_operation()
            ctx.add_mongo_operation_result(bson_data(
                'keys/12345678123498761234123456789013-local-document.json'))
            ctx.complete_mongo_operation()

            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_READY)

            encrypted = ctx.finish()
            self.assertEqual(bson.decode(encrypted, OPTS),
                             json_data('compact/success/encrypted-payload.json'))
            self.assertEqual(encrypted, bson_data('compact/success/encrypted-payload.json'))
            self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_DONE)


class MockCallback(MongoCryptCallback):
    def __init__(self,
                 list_colls_result=None,
                 mongocryptd_reply=None,
                 key_docs=None,
                 kms_reply=None):
        self.list_colls_result = list_colls_result
        self.mongocryptd_reply = mongocryptd_reply
        self.key_docs = key_docs
        self.kms_reply = kms_reply
        self.kms_endpoint = None

    def kms_request(self, kms_context):
        self.kms_endpoint = kms_context.endpoint
        kms_context.feed(self.kms_reply)

    def collection_info(self, ns, filter):
        return self.list_colls_result

    def mark_command(self, ns, cmd):
        return self.mongocryptd_reply

    def fetch_keys(self, filter):
        return self.key_docs

    def insert_data_key(self, data_key):
        raise NotImplementedError

    def bson_encode(self, doc):
        return bson.encode(doc)

    def close(self):
        pass


class TestMongoCryptCallback(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def mongo_crypt_opts():
        return MongoCryptOptions({
            'aws': {'accessKeyId': 'example', 'secretAccessKey': 'example'},
            'local': {'key': b'\x00'*96}})

    @unittest.skipUnless(os.getenv("TEST_CRYPT_SHARED"), "this test requires TEST_CRYPT_SHARED=1")
    def test_crypt_shared(self):
        kms_providers = {
            'aws': {'accessKeyId': 'example', 'secretAccessKey': 'example'},
            'local': {'key': b'\x00'*96}}
        mc = MongoCrypt(MongoCryptOptions(kms_providers), MockCallback())
        self.addCleanup(mc.close)
        self.assertIsNotNone(mc.crypt_shared_lib_version)
        # Test that we can pick up crypt_shared automatically
        encrypter = AutoEncrypter(MockCallback(), MongoCryptOptions(
            kms_providers,
            bypass_encryption=False,
            crypt_shared_lib_required=True))
        self.addCleanup(encrypter.close)
        encrypter = AutoEncrypter(MockCallback(), MongoCryptOptions(
            kms_providers,
            crypt_shared_lib_path=os.environ["CRYPT_SHARED_PATH"],
            crypt_shared_lib_required=True))
        self.addCleanup(encrypter.close)
        with self.assertRaisesRegex(MongoCryptError, "/doesnotexist"):
            AutoEncrypter(MockCallback(), MongoCryptOptions(
                kms_providers,
                crypt_shared_lib_path="/doesnotexist",
                crypt_shared_lib_required=True))

    def test_encrypt(self):
        encrypter = AutoEncrypter(MockCallback(
            list_colls_result=bson_data('collection-info.json'),
            mongocryptd_reply=bson_data('mongocryptd-reply.json'),
            key_docs=[bson_data('key-document.json')],
            kms_reply=http_data('kms-reply.txt')), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)
        encrypted = encrypter.encrypt('test', bson_data('command.json'))
        self.assertEqual(bson.decode(encrypted, OPTS),
                         json_data('encrypted-command.json'))
        self.assertEqual(encrypted, bson_data('encrypted-command.json'))

    def test_decrypt(self):
        encrypter = AutoEncrypter(MockCallback(
            list_colls_result=bson_data('collection-info.json'),
            mongocryptd_reply=bson_data('mongocryptd-reply.json'),
            key_docs=[bson_data('key-document.json')],
            kms_reply=http_data('kms-reply.txt')), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)
        decrypted = encrypter.decrypt(
            bson_data('encrypted-command-reply.json'))
        self.assertEqual(bson.decode(decrypted, OPTS),
                         json_data('command-reply.json'))
        self.assertEqual(decrypted, bson_data('command-reply.json'))

    def test_need_kms_aws_credentials(self):
        kms_providers = { 'aws': {} }
        opts = MongoCryptOptions(kms_providers)
        callback = MockCallback(
            list_colls_result=bson_data('collection-info.json'),
            mongocryptd_reply=bson_data('mongocryptd-reply.json'),
            key_docs=[bson_data('key-document.json')],
            kms_reply=http_data('kms-reply.txt'))
        encrypter = AutoEncrypter(callback, opts)
        self.addCleanup(encrypter.close)

        with mock.patch("pymongocrypt.credentials.aws_temp_credentials") as m:
            m.return_value = AwsCredential("example", "example", None)
            decrypted = encrypter.decrypt(
                bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertEqual(bson.decode(decrypted, OPTS),
                         json_data('command-reply.json'))
        self.assertEqual(decrypted, bson_data('command-reply.json'))

    def test_need_kms_gcp_credentials(self):
        kms_providers = { 'gcp': {} }
        opts = MongoCryptOptions(kms_providers)
        callback = MockCallback(
            list_colls_result=bson_data('collection-info.json'),
            mongocryptd_reply=bson_data('mongocryptd-reply.json'),
            key_docs=[bson_data('key-document-gcp.json')],
            kms_reply=http_data('kms-reply-gcp.txt'))
        encrypter = AutoEncrypter(callback, opts)
        self.addCleanup(encrypter.close)

        with requests_mock.Mocker() as m:
            data = {"access_token": "foo"}
            url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
            m.get(url, text=json.dumps(data))
            decrypted = encrypter.decrypt(
                bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertEqual(bson.decode(decrypted, OPTS),
                         json_data('command-reply.json'))
        self.assertEqual(decrypted, bson_data('command-reply.json'))


class TestNeedKMSAzureCredentials(unittest.TestCase):
    maxDiff = None

    def get_encrypter(self, clear_cache=True):
        if clear_cache:
            pymongocrypt.credentials._azure_creds_cache = None
        kms_providers = { 'azure': {} }
        opts = MongoCryptOptions(kms_providers)
        callback = MockCallback(
            list_colls_result=bson_data('collection-info.json'),
            mongocryptd_reply=bson_data('mongocryptd-reply.json'),
            key_docs=[bson_data('key-document-azure.json')],
            kms_reply=http_data('kms-reply-azure.txt'))
        encrypter = AutoEncrypter(callback, opts)
        self.addCleanup(encrypter.close)
        return encrypter

    def test_success(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            data = {"access_token": "foo", "expires_in": 4000}
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, text=json.dumps(data))
            decrypted = encrypter.decrypt(
                bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertEqual(bson.decode(decrypted, OPTS),
                         json_data('command-reply.json'))
        self.assertEqual(decrypted, bson_data('command-reply.json'))
        self.assertIsNotNone(pymongocrypt.credentials._azure_creds_cache)

    def test_empty_json(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, text=json.dumps({}))
            with self.assertRaisesRegex(MongoCryptError, "Azure IMDS response must contain"):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)
        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)

    def test_bad_json(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, text="a'")
            with self.assertRaisesRegex(MongoCryptError, "Azure IMDS response must be in JSON format"):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)
        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)

    def test_http_404(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, status_code=404)
            with self.assertRaisesRegex(MongoCryptError, "Failed to acquire IMDS access token."):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)
        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)

    def test_http_500(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, status_code=500)
            with self.assertRaisesRegex(MongoCryptError, "Failed to acquire IMDS access token."):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)
        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)

    def test_slow_response(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, exc=requests.exceptions.ConnectTimeout)
            with self.assertRaisesRegex(MongoCryptError, "Failed to acquire IMDS access token: "):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)
        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)

    def test_cache(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            data = {"access_token": "foo", "expires_in": 4000}
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, text=json.dumps(data))
            decrypted = encrypter.decrypt(
                bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertIsNotNone(pymongocrypt.credentials._azure_creds_cache)

        # Should use the cached value.
        decrypted = encrypter.decrypt(bson_data('encrypted-command-reply.json'))
        self.assertEqual(decrypted, bson_data('command-reply.json'))

        self.assertIsNotNone(pymongocrypt.credentials._azure_creds_cache)

    def test_cache_expires_soon(self):
        encrypter = self.get_encrypter()
        with requests_mock.Mocker() as m:
            data = {"access_token": "foo", "expires_in": 10}
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, text=json.dumps(data))
            decrypted = encrypter.decrypt(
                bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertIsNotNone(pymongocrypt.credentials._azure_creds_cache)

        # Should not use the cached value.
        encrypter = self.get_encrypter(False)
        self.assertIsNotNone(pymongocrypt.credentials._azure_creds_cache)
        with requests_mock.Mocker() as m:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            m.get(url, exc=requests.exceptions.ConnectTimeout)
            with self.assertRaisesRegex(MongoCryptError, "Failed to acquire IMDS access token: "):
                encrypter.decrypt(bson_data('encrypted-command-reply.json'))
            self.assertTrue(m.called)

        self.assertIsNone(pymongocrypt.credentials._azure_creds_cache)


class KeyVaultCallback(MockCallback):
    def __init__(self, kms_reply=None):
        super(KeyVaultCallback, self).__init__(kms_reply=kms_reply)
        self.data_key = None

    def fetch_keys(self, filter):
        return self.data_key

    def insert_data_key(self, data_key):
        self.data_key = data_key
        return bson.decode(data_key, OPTS)['_id']


class TestExplicitEncryption(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def mongo_crypt_opts():
        return MongoCryptOptions({
            'aws': {'accessKeyId': 'example', 'secretAccessKey': 'example'},
            'local': {'key': b'\x00'*96}})

    def _test_encrypt_decrypt(self, key_id=None, key_alt_name=None):
        encrypter = ExplicitEncrypter(MockCallback(
            key_docs=[bson_data('key-document.json')],
            kms_reply=http_data('kms-reply.txt')), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        val = {'v': 'hello'}
        encoded_val = bson.encode(val)
        algo = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
        encrypted = encrypter.encrypt(
            encoded_val, algo, key_id=key_id, key_alt_name=key_alt_name)
        self.assertEqual(bson.decode(encrypted, OPTS),
                         json_data('encrypted-value.json'))
        self.assertEqual(encrypted, bson_data('encrypted-value.json'))

        decrypted = encrypter.decrypt(encrypted)
        self.assertEqual(bson.decode(decrypted, OPTS), val)
        self.assertEqual(encoded_val, decrypted)

    def test_encrypt_decrypt(self):
        key_id = json_data('key-document.json')['_id']
        self._test_encrypt_decrypt(key_id=key_id)

    def test_encrypt_decrypt_key_alt_name(self):
        key_alt_name = json_data('key-document.json')['keyAltNames'][0]
        self._test_encrypt_decrypt(key_alt_name=key_alt_name)

    def test_encrypt_errors(self):
        key_id = json_data('key-document.json')['_id']
        encrypter = ExplicitEncrypter(MockCallback(key_docs=[]), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        val = {'v': 'value123'}
        encoded_val = bson.encode(val)
        # Invalid algorithm.
        with self.assertRaisesRegex(MongoCryptError, "algorithm"):
            encrypter.encrypt(encoded_val, "Invalid", key_id)
        # Invalid query_type type.
        with self.assertRaisesRegex(TypeError, "query_type"):
            encrypter.encrypt(encoded_val, "Indexed", key_id, query_type=42)
        # Invalid query_type string.
        with self.assertRaisesRegex(MongoCryptError, "query_type"):
            encrypter.encrypt(encoded_val, "Indexed", key_id, query_type='invalid query type string')
        # Invalid contention_factor type.
        with self.assertRaisesRegex(TypeError, "contention_factor"):
            encrypter.encrypt(encoded_val, "Indexed", key_id, contention_factor='not an int')
        with self.assertRaisesRegex(MongoCryptError, "contention"):
            encrypter.encrypt(encoded_val, "Indexed", key_id, contention_factor=-1)
        # Invalid: Unindexed + query_type is an error.
        with self.assertRaisesRegex(MongoCryptError, "query"):
            encrypter.encrypt(encoded_val, "Unindexed", key_id, query_type='equality')
        # Invalid: Unindexed + contention_factor is an error.
        with self.assertRaisesRegex(MongoCryptError, "contention"):
            encrypter.encrypt(encoded_val, "Unindexed", key_id, contention_factor=1)

    def test_encrypt_indexed(self):
        key_path = 'keys/ABCDEFAB123498761234123456789012-local-document.json'
        key_id = json_data(key_path)['_id']
        encrypter = ExplicitEncrypter(MockCallback(
            key_docs=[bson_data(key_path)],
            kms_reply=http_data('kms-reply.txt')), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        val = {'v': 'value123'}
        encoded_val = bson.encode(val)
        for kwargs in [
            dict(algorithm='Indexed', contention_factor=0),
            dict(algorithm='Indexed', query_type='equality', contention_factor=0),
            dict(algorithm='Indexed', contention_factor=100),
            dict(algorithm='Unindexed'),
        ]:
            kwargs['key_id'] = key_id
            encrypted = encrypter.encrypt(encoded_val, **kwargs)
            encrypted_val = bson.decode(encrypted, OPTS)['v']
            self.assertIsInstance(encrypted_val, Binary)
            self.assertEqual(encrypted_val.subtype, 6)

            # Queryable Encryption find payloads cannot be round-tripped.
            if 'query_type' not in kwargs:
                decrypted = encrypter.decrypt(encrypted)
                self.assertEqual(bson.decode(decrypted, OPTS), val)
                self.assertEqual(encoded_val, decrypted)

    def test_data_key_creation(self):
        mock_key_vault = KeyVaultCallback(
            kms_reply=http_data('kms-encrypt-reply.txt'))
        encrypter = ExplicitEncrypter(mock_key_vault, self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        valid_args = [
            ('local', None, ['first', 'second']),
            ('aws', {'region': 'region', 'key': 'cmk'}, ['third', 'forth']),
            # Unicode region and key
            ('aws', {'region': u'region-unicode', 'key': u'cmk-unicode'}, []),
            # Endpoint
            ('aws', {'region': 'region', 'key': 'cmk',
                     'endpoint': 'kms.us-east-1.amazonaws.com:443'}, []),
        ]
        for kms_provider, master_key, key_alt_names in valid_args:
            key_id = encrypter.create_data_key(
                kms_provider, master_key=master_key,
                key_alt_names=key_alt_names)
            self.assertIsInstance(key_id, Binary)
            self.assertEqual(key_id.subtype, 4)
            data_key = bson.decode(mock_key_vault.data_key, OPTS)
            # CDRIVER-3277 The order of key_alt_names is not maintained.
            for name in key_alt_names:
                self.assertIn(name, data_key['keyAltNames'])

        # Assert that the custom endpoint is passed to libmongocrypt.
        master_key = {
            "region": "region",
            "key": "key",
            "endpoint": "example.com"
        }
        key_material = base64.b64decode('xPTAjBRG5JiPm+d3fj6XLi2q5DMXUS/f1f+SMAlhhwkhDRL0kr8r9GDLIGTAGlvC+HVjSIgdL+RKwZCvpXSyxTICWSXTUYsWYPyu3IoHbuBZdmw2faM3WhcRIgbMReU5')
        if not PY3:
            key_material = Binary(key_material)
        encrypter.create_data_key("aws", master_key=master_key, key_material=key_material)
        self.assertEqual("example.com:443", mock_key_vault.kms_endpoint)

    def test_data_key_creation_bad_key_material(self):
        mock_key_vault = KeyVaultCallback(
            kms_reply=http_data('kms-encrypt-reply.txt'))
        encrypter = ExplicitEncrypter(mock_key_vault, self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        key_material = Binary(b'0' * 97)
        with self.assertRaisesRegex(MongoCryptError, "keyMaterial should have length 96, but has length 97"):
            encrypter.create_data_key("local", key_material=key_material)

    def test_rewrap_many_data_key(self):
        key_path = 'keys/ABCDEFAB123498761234123456789012-local-document.json'
        key_path2 = 'keys/12345678123498761234123456789012-local-document.json'
        encrypter = ExplicitEncrypter(MockCallback(
            key_docs=[bson_data(key_path), bson_data(key_path2)]), self.mongo_crypt_opts())
        self.addCleanup(encrypter.close)

        result = encrypter.rewrap_many_data_key({})
        raw_doc = RawBSONDocument(result)
        assert len(raw_doc['v']) == 2

def read(filename, **kwargs):
    with open(os.path.join(DATA_DIR, filename), **kwargs) as fp:
        return fp.read()


OPTS = CodecOptions(uuid_representation=UuidRepresentation.UNSPECIFIED)

# Use SON to preserve the order of fields while parsing json.
if sys.version_info[:2] < (3, 6):
    document_class = SON
else:
    document_class = dict
JSON_OPTS = JSONOptions(document_class=document_class,
                        uuid_representation=UuidRepresentation.UNSPECIFIED)


def json_data(filename):
    return json_util.loads(read(filename), json_options=JSON_OPTS)


def bson_data(filename):
    return bson.encode(json_data(filename), codec_options=OPTS)


def http_data(filename):
    data = read(filename, mode='rb')
    return data.replace(b'\n', b'\r\n')


if __name__ == "__main__":
    unittest.main()
