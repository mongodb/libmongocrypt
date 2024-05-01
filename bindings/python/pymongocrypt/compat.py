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

import sys

PY3 = sys.version_info[0] >= 3

if PY3:
    from abc import ABC

    unicode_type = str
else:
    from abc import ABCMeta as _ABCMeta

    ABC = _ABCMeta("ABC", (object,), {})
    unicode_type = "unicode"


def str_to_bytes(string):
    """Convert a str (or unicode) to bytes."""
    if isinstance(string, bytes):
        return string
    return string.encode("utf-8")
