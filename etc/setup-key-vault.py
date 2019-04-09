import boto3
import pymongo
import sys
import os
import bson
import uuid
from bson.codec_options import CodecOptions
from datetime import datetime
from bson import json_util
import base64

instructions = """
This setup script does the following:
1. drops admin.datakeys collection
2. uses your AWS credentials and customer master key (CMK) to encrypt three example 64-byte keys 
3. inserts those keys into the admin.datakeys collection
4. prints an example schema using the resulting data key ids

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

mongo_client = pymongo.MongoClient()
datakeys = mongo_client.admin.get_collection("datakeys", codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD))
datakeys.drop()

kms_client = boto3.client("kms", aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

# Not sure if this is the right way to create a random bson.binary.UUID in pymongo.
def randomUUID():
    return bson.binary.UUID(bytes=uuid.uuid4().bytes)

master_key_doc = { # not currently used in demo.
    "provider": "aws",
    "rey": cmk_id,
    "region": boto3.session.Session().region_name
}

# Create three example keys.
example_keys = [
    {
        "_id": randomUUID(),
        "keyMaterial": b"a" * 64,
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 1, # active
        "masterKey": master_key_doc
    },
    {
        "_id": randomUUID(),
        "keyAltName": ["Todd Davis"],
        "keyMaterial": b"b" * 64,
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 1, # active
        "masterKey": master_key_doc
    },
    {
        "_id": randomUUID(),
        "keyMaterial": b"c" * 64,
        "creationDate": datetime.now(),
        "updatedDate": datetime.now(),
        "status": 0,  # inactive
        "masterKey": master_key_doc
    }
]

for data_key in example_keys:
    response = kms_client.encrypt(KeyId=cmk_id, Plaintext=base64.b64encode(data_key["keyMaterial"]))
    # replace the key material after encrypting.
    data_key["keyMaterial"] = bson.binary.Binary(response["CiphertextBlob"])
    datakeys.insert_one(data_key)

example_schema = {
   "test.crypt" : {
        "schema": {
            "bsonType": "object",
            "properties": {
                    "ssn": {
                    "encrypt": {
                        "type": "string",
                        "algorithm": "Deterministic",
                        "keyId": example_keys[0]["_id"],
                        "iv": bson.binary.Binary(b"i" * 16)
                    }
                }
            }
        }
   }
}

opts = json_util.JSONOptions(json_mode=json_util.JSONMode.CANONICAL,
                             uuid_representation=bson.binary.STANDARD
                             )

print(json_util.dumps(example_schema, indent=4, json_options=opts))

