description = """Prints the list of files in a compilation database.
Run with python ./list-compile-files.py <path/to/compile_commands.json>
"""

from fnmatch import fnmatch
import sys
import json
import os

if len(sys.argv) != 2:
    print(description)
    sys.exit(1)

compile_db = json.load(open(sys.argv[1] + "compile_commands.json", "r"))
for entry in compile_db:
    fname = os.path.basename(entry)
    if fnmatch(fname, 'mc-*') or fnmatch(fname, 'mongocrypt-*'):
        print(entry["file"])
print("")
