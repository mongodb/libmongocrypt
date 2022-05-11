#!/usr/bin/env python2
import boto3
import sys
import os
import bson
import uuid
from bson.codec_options import CodecOptions
from datetime import datetime
from bson import json_util
import json
import base64

instructions = """
This setup script prints a realistic example key document, schema, list collections responses, and KMS reply, and marking, to be used for test data.
Run this script from the root of the libmongocrypt repository.

Set the following environment variables:
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_REGION - e.g. "us-east-1"
AWS_CMK_ID - customer master key. e.g: arn:aws:kms:us-east-1:524754917239:key/70b3825c-602f-4d65-aeeb-087e565c6abc
"""

try:
    cmk_id = os.environ["AWS_CMK_ID"]
    access_key_id = os.environ["AWS_ACCESS_KEY_ID"]
    secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    region = os.environ["AWS_REGION"]
except KeyError:
    print(instructions)
    sys.exit(1)

# Ensure UUIDs are encoded as BSON binary subtype 6.
codec_options = CodecOptions(uuid_representation=bson.binary.STANDARD)
json_options = json_util.JSONOptions(json_mode=json_util.JSONMode.CANONICAL, uuid_representation=bson.binary.STANDARD)
kms_client = boto3.client("kms", aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)


print ("A key document:")
key_doc = {
        "_id": bson.binary.UUID(bytes=bytes(b"a" * 16)),
        "keyMaterial": None, # to be filled
        "creationDate": datetime.now(),
        "updateDate": datetime.now(),
        "status": 1, # active
        "masterKey": { # not currently used in demo.
            "provider": "aws",
            "key": cmk_id,
            "region": region
        }
    }

plaintext_key_material = base64.b64decode("TqhXy3tKckECjy4/ZNykMWG8amBF46isVPzeOgeusKrwheBmYaU8TMG5AHR/NeUDKukqo8hBGgogiQOVpLPkqBQHD8YkLsNbDmHoGOill5QAHnniF/Lz405bGucB5TfR")
# get real encrypted key material using AWS KMS.
response = kms_client.encrypt(KeyId=cmk_id, Plaintext=plaintext_key_material)
print(len(response["CiphertextBlob"]))
# replace the key material after encrypting.
key_doc["keyMaterial"] = bson.binary.Binary(response["CiphertextBlob"])
print (json_util.dumps (key_doc, indent=4, json_options=json_options))


print ("A KMS reply for encrypted key material")
kms_encrypt_reply_json = json.dumps({
    "KeyId": cmk_id,
    "CiphertextBlob": base64.b64encode(key_doc["keyMaterial"]).decode("utf-8")
})
kms_encrypt_reply = "HTTP/1.1 200 OK\n" + \
    "x-amzn-RequestId: deeb35e5-4ecb-4bf1-9af5-84a54ff0af0e\n" + \
    "Content-Type: application/x-amz-json-1.1\n" + \
    "Content-Length: %d\n" % len(kms_encrypt_reply_json) + \
    "Connection: close\n\n" + \
    kms_encrypt_reply_json
print (kms_encrypt_reply)


print ("\n\nA KMS reply for decrypting the key material")
kms_decrypt_reply_json = json.dumps({
    "KeyId": cmk_id,
    "Plaintext": base64.b64encode(bytes(plaintext_key_material)).decode("utf-8")
})
kms_reply = "HTTP/1.1 200 OK\n" + \
    "x-amzn-RequestId: deeb35e5-4ecb-4bf1-9af5-84a54ff0af0e\n" + \
    "Content-Type: application/x-amz-json-1.1\n" + \
    "Content-Length: %d\n\n" % len(kms_decrypt_reply_json) + \
    kms_decrypt_reply_json
print (kms_reply)


print ("\n\nA marking indicating a value to be encrypted:")
value_to_mark = "457-55-5462"
marking = bson.binary.Binary(b"\00" + bson.BSON.encode({
    "a": 1,
    "ki": key_doc["_id"]
}, codec_options=codec_options), subtype=6)
print (json_util.dumps ({"marking": marking}, indent=4, json_options=json_options))


print ("\n\nA mongocryptd reply with the marking above:")
marked_reply = {
    "result": {
        "find": "test",
        "filter": {
            "ssn": marking
        }
    },
    "hasEncryptedPlaceholders": True,
    "schemaRequiresEncryption": True,
    "ok": 1
}
print (json_util.dumps (marked_reply, indent=4, json_options=json_options))


print ("\n\nA listCollections result with a JSONSchema referencing the key:")
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
                            "keyId": [key_doc["_id"]],
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                        }
                    },
                    "random": {
                        "encrypt": {
                            "keyId": [key_doc["_id"]],
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                        }
                    }
                }
            }
        }
    }
}
print (json_util.dumps (collection_info, indent=4, json_options=json_options))