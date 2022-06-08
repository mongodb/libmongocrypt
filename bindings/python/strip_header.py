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

import re
import sys

HEADER_RE = re.compile(r'^\s*(#|MONGOCRYPT_EXPORT)')
BLANK_RE = re.compile(r'^\s*$')


def strip_file(fp, out):
    for line in fp:
        if not HEADER_RE.match(line):
            out.append(line)


def strip(hdr):
    out = []
    with open(hdr) as fp:
        strip_file(fp, out)

    # Strip consecutive blank lines
    last_blank = True
    new = []
    for line in out:
        if BLANK_RE.match(line):
            if last_blank:
                continue
            last_blank = True
        else:
            last_blank = False
        new.append(line)

    if new:
        print(''.join(new))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise Exception("Usage: strip_header.py header.h")
    strip(sys.argv[1])
