# Copyright 2024-present MongoDB, Inc.
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

from os import listdir
from pathlib import Path

from unasync import Rule, unasync_files

replacements = {
    "asynchronous": "synchronous",
    "AsyncMongoCryptCallback": "MongoCryptCallback",
    "AsyncExplicitEncrypter": "ExplicitEncrypter",
    "AsyncAutoEncrypter": "AutoEncrypter",
    "AsyncClient": "Client",
    "AsyncMongoCrypt": "MongoCrypt",
    "aclose": "close",
}

_base = "pymongocrypt"

async_files = [
    f"./{_base}/asynchronous/{f}"
    for f in listdir("pymongocrypt/asynchronous")
    if (Path(_base) / "asynchronous" / f).is_file()
]


unasync_files(
    async_files,
    [
        Rule(
            fromdir="/pymongocrypt/asynchronous/",
            todir="/pymongocrypt/synchronous/",
            additional_replacements=replacements,
        )
    ],
)

sync_files = [
    f"./{_base}/synchronous/{f}"
    for f in listdir("pymongocrypt/synchronous")
    if (Path(_base) / "synchronous" / f).is_file()
]

for file in sync_files:
    with open(file, "r+") as f:
        lines = f.readlines()
        for i in range(len(lines)):
            for s in replacements:
                lines[i] = lines[i].replace(s, replacements[s])
        f.seek(0)
        f.truncate()
        f.writelines(lines)
