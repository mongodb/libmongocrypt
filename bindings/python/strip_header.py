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

"""Generate a CFFI.cdef() string from a C header file

Usage (on macOS):: python strip_header.py ../../src/mongocrypt.h | pbcopy
"""

import itertools
import re
import sys

DROP_RE = re.compile(r"^\s*(#|MONGOCRYPT_EXPORT)")


def strip_file(content):
    fold = content.replace("\\\n", " ")
    all_lines = [*fold.split("\n"), ""]
    keep_lines = (line for line in all_lines if not DROP_RE.match(line))
    fin = ""
    for line, peek in itertools.pairwise(keep_lines):
        if peek == "" and line == "":
            # Drop adjacent empty lines
            continue
        yield line
        fin = peek
    yield fin


def strip(hdr):
    with open(hdr) as fp:
        out = strip_file(fp.read())
        print("\n".join(out))  # noqa: T201


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise Exception("Usage: strip_header.py header.h")
    strip(sys.argv[1])
