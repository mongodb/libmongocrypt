description = """Prints the list of files in a compilation database.
Run with python ./list-compile-files.py <path/to/compile_commands.json>
"""

import sys
import json

if len(sys.argv) != 2:
    print(description)
    sys.exit(1)

compile_db = json.load(open(sys.argv[1] + "compile_commands.json", "r"))
for entry in compile_db:
    print(entry["file"])
print("")