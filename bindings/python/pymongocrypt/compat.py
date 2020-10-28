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

"""Utility functions and definitions for Python compatibility."""

import base64
import sys

PY3 = sys.version_info[0] == 3

if PY3:
    from abc import ABC
    unicode_type = str
else:
    from abc import ABCMeta as _ABCMeta
    ABC = _ABCMeta('ABC', (object,), {})
    unicode_type = unicode


def str_to_bytes(string):
    """Convert a str (or unicode) to bytes."""
    if isinstance(string, bytes):
        return string
    return string.encode('utf-8')


def safe_bytearray_or_base64(data):
    """Convert the given value to a type that, when BSON-encoded can be safely
    passed to libmongocrypt functions that expect a BSON document containing
    BSON Binary data or a base64-encoded string.

    pymongo.bson encodes bytes to BSON string in Python 2, while the
    libmongocrypt API expects BSON Binary or a base64 encoded string.
    To avoid needing to import bson.Binary, we return a base64 encoded string
    when using Python 2.
    """
    # On Python 3 byte-arrays are encoded as BSON Binary and
    # base64 encoded strings can be passed as-is.
    if PY3:
        return data

    # On Python 2 unicode literals are assumed to contain base64-encoded
    # strings that can be passed to libmongocrypt as-is.
    if isinstance(data, unicode_type):
        return data

    # On Python 2, all other types are assumed to contain raw bytes.
    # To avoid importing bson.binary.Binary, we convert these to
    # base64 strings.
    return unicode_type(base64.b64encode(data))
