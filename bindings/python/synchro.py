from __future__ import annotations

from os import listdir
from os.path import isfile, join

from unasync import Rule, unasync_files

replacements = {
    "asynchronous": "synchronous",
    "AsyncMongoCryptCallback": "MongoCryptCallback",
    "AsyncExplicitEncrypter": "ExplicitEncrypter",
    "AsyncAutoEncrypter": "AutoEncrypter",
    "AsyncClient": "Client",
    "aclose": "close"
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

sync_files = [
    "./pymongocrypt/synchronous/" + f
    for f in listdir("pymongocrypt/synchronous")
    if isfile(join("pymongocrypt/synchronous", f))
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
