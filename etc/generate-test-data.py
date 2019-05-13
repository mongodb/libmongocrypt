#!/usr/bin/env python2
import boto3
import sys
import os
import bson
import uuid
from bson.codec_options import CodecOptions
from datetime import datetime
from bson import json_util
import base64

instructions = """
This setup script generates schemas, list collections responses, and KMS replies in the test directory.
Run this script from the root of the libmongocrypt repository.

Set the following environment variables:
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_REGION - e.g. "us-east-1"
AWS_CMK_ID - customer master key. e.g: arn:aws:kms:us-east-1:524754917239:key/70b3825c-602f-4d65-aeeb-087e565c6abc

TODO: only Python 2 supported currently. base64 returns bytes in Python 3. Not a string.
"""

if sys.version_info >= (3, 0):
    print("Sorry - only python 2 supported currently.")
    sys.exit(1)

if not os.path.exists("test"):
    print(instructions)
    sys.exit(1)

try:
    cmk_id = os.environ["AWS_CMK_ID"]
    access_key_id = os.environ["AWS_ACCESS_KEY_ID"]
    secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    region = os.environ["AWS_REGION"]
except KeyError:
    print(instructions)
    sys.exit(1)

kms_client = boto3.client("kms", aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

# Not sure if this is the right way to create a random bson.binary.UUID in pymongo.
uuid_bytes = bytearray([0] * 16)
def nextUUID():
    uuid = bson.binary.UUID(bytes=bytes(uuid_bytes))
    i = 0
    while uuid_bytes[i] == 255:
        i += 1
    assert (i < 16)
    uuid_bytes [i] += 1
    return uuid

master_key_doc = { # not currently used in demo.
    "provider": "aws",
    "key": cmk_id,
    "region": region
}

# Create three example keys.
key_docs = [
    {
        "_id": nextUUID(),
        "keyMaterial": None, # to be filled
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 1, # active
        "masterKey": master_key_doc
    },
    {
        "_id": nextUUID(),
        "keyAltNames": [ "Sharlene", "Kasey" ],
        "keyMaterial": None, # to be filled.
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 1, # active
        "masterKey": master_key_doc
    },
    {
        "_id": nextUUID(),
        "keyMaterial": None, # to be filled.
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 0,  # inactive
        "masterKey": master_key_doc
    },
    {
        "_id": nextUUID(),
        "keyAltNames": [ "Sharlene", "Kasey" ],
        "keyMaterial": None, # to be filled.
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 1, # active
        "masterKey": master_key_doc
    },
]

data_keys = [
    b"a" * 64,
    b"b" * 64,
    b"c" * 64,
    b"d" * 64
]

for (data_key, key_doc) in zip(data_keys, key_docs):
    response = kms_client.encrypt(KeyId=cmk_id, Plaintext=data_key)
    # replace the key material after encrypting.
    key_doc["keyMaterial"] = bson.binary.Binary(response["CiphertextBlob"])

command = {
    "find": "test",
    "filter": {
        "ssn": "457-55-5462"
    }
}

collection_info = {
    "name": "test",
    "type": "collection",
    "options": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "properties": {
                    "ssn": {
                        "encrypt": {
                            "keyId": key_docs[0]["_id"],
                            "type": "string",
                            "algorithm": "Deterministic",
                            "iv": bson.binary.Binary(b"i" * 16)
                        }
                    }
                }
            }
        }
    },
    "idIndex": {
        "v": 2,
        "key": {
            "_id": 1
        },
        "name": "_id_",
        "ns": "test.test"
    }
}

marked_reply = {
    "result": {
        "find": "test",
        "filter": {
            "ssn": bson.binary.Binary(b"\00" + bson.BSON.encode({
                "v": "457-55-5462",
                "a": 1,
                "iv": bson.binary.Binary(b"i" * 16),
                "ki": key_docs[0]["_id"]
            }, codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD)), subtype=6)
        }
    },
    "hasEncryptedPlaceholders": True,
    "schemaRequiresEncryption": True,
    "ok": 1
}

marked_reply_key_alt_name = {
    "result": {
        "find": "test",
        "filter": {
            "ssn": bson.binary.Binary(b"\00" + bson.BSON.encode({
                "v": "457-55-5462",
                "a": 1,
                "iv": bson.binary.Binary(b"i" * 16),
                "ka": "Sharlene"
            }, codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD)), subtype=6)
        }
    },
    "hasEncryptedPlaceholders": True,
    "schemaRequiresEncryption": True,
    "ok": 1
}

invalid_marked_reply = {
    "result": {
        "find": "test",
        "filter": {
            "ssn": bson.binary.Binary(b"\00" + bson.BSON.encode({
                # missing "v"
                "a": 1,
                "iv": bson.binary.Binary(b"i" * 16),
                "ki": key_docs[0]["_id"]
            }, codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD)), subtype=6)
        }
    },
    "hasEncryptedPlaceholders": True,
    "schemaRequiresEncryption": True,
    "ok": 1
}

marked_reply_random = {
    "result": {
        "find": "test",
        "filter": {
            "ssn": bson.binary.Binary(b"\00" + bson.BSON.encode({
                "v": "457-55-5462",
                "a": 2,
                "ki": key_docs[0]["_id"]
            }, codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD)), subtype=6)
        }
    },
    "hasEncryptedPlaceholders": True,
    "schemaRequiresEncryption": True,
    "ok": 1
}

kms_reply_json = json_util.dumps({
    "KeyId": cmk_id,
    "Plaintext": base64.b64encode(data_key)
})

kms_reply = "HTTP/1.1 200 OK\n" + \
    "x-amzn-RequestId: deeb35e5-4ecb-4bf1-9af5-84a54ff0af0e\n" + \
    "Content-Type: application/x-amz-json-1.1\n" + \
    "Content-Length: %d\n\n" % len(kms_reply_json) + \
    kms_reply_json


opts = json_util.JSONOptions(json_mode=json_util.JSONMode.CANONICAL,
                             uuid_representation=bson.binary.STANDARD)

with open("test/example/key-document.json", "w") as f:
    f.write(json_util.dumps(key_docs[0], indent=4, json_options=opts))

with open("test/example/key-document-with-alt-name.json", "w") as f:
    f.write(json_util.dumps(key_docs[1], indent=4, json_options=opts))

with open("test/example/key-document-with-alt-name-duplicate-id.json", "w") as f:
    f.write(json_util.dumps(key_docs[3], indent=4, json_options=opts))    

with open("test/example/collection-info.json", "w") as f:
    f.write(json_util.dumps(collection_info, indent=4, json_options=opts))

with open("test/example/command.json", "w") as f:
    f.write(json_util.dumps(command, indent=4, json_options=opts))

with open("test/example/mongocryptd-reply.json", "w") as f:
    f.write(json_util.dumps(marked_reply, indent=4, json_options=opts))

with open("test/example/mongocryptd-reply-key-alt-name.json", "w") as f:
    f.write(json_util.dumps(marked_reply_key_alt_name, indent=4, json_options=opts))

with open("test/data/mongocryptd-reply-no-encryption-needed.json", "w") as f:
    f.write(json_util.dumps({
        "hasEncryptedPlaceholders": False,
        "schemaRequiresEncryption": False,
        "ok": 1
    }, indent=4, json_options=opts))

with open("test/data/mongocryptd-reply-no-markings.json", "w") as f:
    f.write(json_util.dumps({
        "hasEncryptedPlaceholders": False,
        "schemaRequiresEncryption": True,
        "ok": 1
    }, indent=4, json_options=opts))

with open("test/data/mongocryptd-reply-invalid.json", "w") as f:
    f.write(json_util.dumps(invalid_marked_reply, indent=4, json_options=opts))

with open("test/data/mongocryptd-reply-random.json", "w") as f:
    f.write(json_util.dumps(marked_reply_random, indent=4, json_options=opts))

with open("test/example/kms-decrypt-reply.txt", "w") as f:
    f.write(kms_reply)



print("Done writing to test/ directory.")

