# Copyright 2023-present MongoDB, Inc.
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

"""Benchmark pymongocrypt performance."""
from __future__ import annotations

import os
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import List

try:
    import simplejson as json
except ImportError:
    import json  # type: ignore[no-redef]

import bson
from bson import json_util

sys.path[0:0] = [""]


from test.test_mongocrypt import MockCallback

from pymongocrypt.binding import lib, libmongocrypt_version
from pymongocrypt.mongocrypt import MongoCrypt, MongoCryptOptions
from pymongocrypt.synchronous.explicit_encrypter import ExplicitEncrypter
from pymongocrypt.version import __version__

NUM_ITERATIONS = 10
MAX_TIME = 1
NUM_FIELDS = 1500
LOCAL_MASTER_KEY = (
    b"\x9d\x94K\r\x93\xd0\xc5D\xa5r\xfd2\x1b\x940\x90#5s|\xf0\xf6\xc2\xf4\xda#V\xe7\x8f\x04"
    b"\xcc\xfa\xdeu\xb4Q\x87\xf3\x8b\x97\xd7KD;\xac9\xa2\xc6M\x91\x00>\xd1\xfaJ0\xc1\xd2"
    b"\xc6^\xfb\xacA\xf2H\x13<\x9bP\xfc\xa7$z.\x02c\xa3\xc6\x16%QPx>\x0f\xd8n\x84\xa6\xec"
    b"\x8d-$G\xe5\xaf"
)

OUTPUT_FILE = os.environ.get("OUTPUT_FILE")

result_data: List = []


def read(filename, **kwargs):
    with open(os.path.join(os.path.dirname(__file__), filename), **kwargs) as fp:
        return fp.read()


def json_data(filename):
    return json_util.loads(read(filename))


def bson_data(filename):
    return bson.encode(json_data(filename))


def tearDownModule():
    output = json.dumps(result_data, indent=4)
    if OUTPUT_FILE:
        with open(OUTPUT_FILE, "w") as opf:
            opf.write(output)
    else:
        print(output)


class TestBulkDecryption(unittest.TestCase):
    def setUp(self):
        opts = MongoCryptOptions({"local": {"key": LOCAL_MASTER_KEY}})
        callback = MockCallback(key_docs=[bson_data("keyDocument.json")])
        self.mongocrypt = MongoCrypt(opts, callback)
        self.encrypter = ExplicitEncrypter(callback, opts)
        self.addCleanup(self.mongocrypt.close)
        self.addCleanup(self.encrypter.close)

    def do_task(self, encrypted, duration=MAX_TIME):
        start = time.monotonic()
        ops = 0
        while time.monotonic() - start < duration:
            with self.mongocrypt.decryption_context(encrypted) as ctx:
                if ctx.state == lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS:
                    # Key is requested on the first operation, then expected to be cached for one minute.
                    ctx.add_mongo_operation_result(bson_data("keyDocument.json"))
                    ctx.complete_mongo_operation()
                self.assertEqual(ctx.state, lib.MONGOCRYPT_CTX_READY)
                decrypted = ctx.finish()
            ops += 1
        # Assert that decryption actually occurred.
        self.assertGreater(ops, 0)
        doc = bson.decode(decrypted)
        for val in doc.values():
            self.assertIsInstance(val, str)
        return ops

    def percentile(self, percentile):
        sorted_results = sorted(self.results)
        percentile_index = int(len(sorted_results) * percentile / 100) - 1
        return sorted_results[percentile_index]

    def runTest(self):
        doc = {}
        key_id = json_data("keyDocument.json")["_id"]
        for i in range(NUM_FIELDS):
            val = f"value {i:04}"
            val_encrypted = bson.decode(
                self.encrypter.encrypt(
                    bson.encode({"v": val}),
                    "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                    key_id=key_id,
                )
            )["v"]
            doc[f"key{i:04}"] = val_encrypted
        encrypted = bson.encode(doc)
        # Warm up benchmark and discard the result.
        self.do_task(encrypted, duration=2)

        for n_threads in [1, 2, 8, 64]:
            with ThreadPoolExecutor(max_workers=n_threads) as executor:
                self.results = []
                for _ in range(NUM_ITERATIONS):
                    start = time.monotonic()
                    thread_results = list(
                        executor.map(self.do_task, [encrypted] * n_threads)
                    )
                    interval = time.monotonic() - start
                    self.results.append(sum(thread_results) / interval)
            median = self.percentile(50)
            print(
                f"Finished {self.__class__.__name__}, threads={n_threads}, median ops_per_second={median:.2f}"
            )
            # Remove "Test" so that TestBulkDecryption is reported as "BulkDecryption".
            name = self.__class__.__name__[4:]
            result_data.append(
                {
                    "info": {
                        "test_name": name,
                        "args": {
                            "threads": n_threads,
                        },
                    },
                    "metrics": [
                        {"name": "ops_per_second", "type": "MEDIAN", "value": median},
                    ],
                }
            )


if __name__ == "__main__":
    print(
        f"Running benchmark with pymongocrypt: {__version__} libmongocrypt: {libmongocrypt_version()}"
    )
    unittest.main()
