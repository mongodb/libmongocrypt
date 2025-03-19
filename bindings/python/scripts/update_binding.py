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

"""Update pymongocrypt/bindings.py using mongocrypt.h.
"""

import re
from pathlib import Path

DROP_RE = re.compile(r"^\s*(#|MONGOCRYPT_EXPORT)")
HERE = Path(__file__).absolute().parent


# itertools.pairwise backport for Python 3.9 support.
def pairwise(iterable):
    # pairwise('ABCDEFG') → AB BC CD DE EF FG

    iterator = iter(iterable)
    a = next(iterator, None)

    for b in iterator:
        yield a, b
        a = b


def strip_file(content):
    fold = content.replace("\\\n", " ")
    all_lines = [*fold.split("\n"), ""]
    keep_lines = (line for line in all_lines if not DROP_RE.match(line))
    fin = ""
    for line, peek in pairwise(keep_lines):
        if peek == "" and line == "":
            # Drop adjacent empty lines
            continue
        yield line
        fin = peek
    yield fin


def update_bindings():
    header_file = HERE.parent.parent.parent / "src/mongocrypt.h"
    with header_file.open(encoding="utf-8") as fp:
        header_lines = strip_file(fp.read())

    target = HERE.parent / "pymongocrypt/binding.py"
    source_lines = target.read_text().splitlines()
    new_lines = []
    skip = False
    for line in source_lines:
        if not skip:
            new_lines.append(line)
        if line.strip() == "# Start embedding from update_binding.py":
            skip = True
            new_lines.append("ffi.cdef(")
            new_lines.append('"""')
            new_lines.extend(header_lines)
        if line.strip() == "# End embedding from update_binding.py":
            new_lines.append('"""')
            new_lines.append(")")
            new_lines.append(line)
            skip = False
    with target.open("w") as f:
        f.write("\n".join(new_lines))


if __name__ == "__main__":
    update_bindings()
