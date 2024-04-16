from __future__ import annotations

from os import listdir
from os.path import isfile, join

from unasync import Rule, unasync_files

replacements = {
    "asynchronous": "synchronous",
    "AsyncMongoCryptCallback": "MongoCryptCallback",
    "AsyncExplicitEncrypter": "ExplicitEncrypter",
    "AsyncAutoEncrypter": "AutoEncrypter"
}

async_files = [
    "./pymongocrypt/asynchronous/" + f
    for f in listdir("pymongocrypt/asynchronous")
    if isfile(join("pymongocrypt/asynchronous", f))
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


# with open("gridfs/synchronous/grid_file.py", "r+") as f:
#     lines = f.readlines()
#     is_sync = [line for line in lines if line.startswith("IS_SYNC = ")][0]
#     index = lines.index(is_sync)
#     is_sync = is_sync.replace("False", "True")
#     lines[index] = is_sync
#     f.seek(0)
#     f.writelines(lines)
#     f.truncate()
