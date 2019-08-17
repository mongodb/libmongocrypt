instructions = """
Print the contents of a marking from mongocryptd.

Usage:
python print-marking.py <base64 representation of marking>

Example:
python ./etc/print-marking.py ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
"""

import sys
import base64
import bson
from bson import BSON
from bson import json_util
from bson.codec_options import CodecOptions

if len(sys.argv) != 2:
    print(instructions)
    sys.exit(1)

marking = base64.b64decode(sys.argv[1])
codec_options = CodecOptions(uuid_representation=bson.binary.STANDARD)
json_options = json_util.JSONOptions(json_mode=json_util.JSONMode.CANONICAL, uuid_representation=bson.binary.STANDARD)

if marking[0] != 0:
    print("Invalid first byte: {}".format(marking[0]))

marking_bson = BSON(marking[1:]).decode(codec_options=codec_options)
print(json_util.dumps(marking_bson, indent=4, json_options=json_options))

if "a" in marking_bson:
    if marking_bson["a"] == 1:
        print ("Algorithm is deterministic")
    elif marking_bson["a"] == 2:
        print ("Algorithm is random")