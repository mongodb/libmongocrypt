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
4. creates an example-schemas.json file using the resulting data key ids

AWS_CMK_ID may be set as an environment variable.

Prior to running, install the AWS CLI tools and run `aws configure` to set your AWS access key id,
secret key, and region in ~/.aws.

Run with Python 3.
"""
print(instructions)

response = input("Proceed? (y/n) ")
if response != "y":
    sys.exit(0)

if "AWS_CMK_ID" in os.environ:
    cmk_id = os.environ["AWS_CMK_ID"]
else:
    cmk_id = input("Enter CMK key ID\n(example: arn:aws:kms:us-east-1:524754917239:key/70b3825c-602f-4d65-aeeb-087e565c6abc)\n")

mongo_client = pymongo.MongoClient()
datakeys = mongo_client.admin.get_collection("datakeys", codec_options=CodecOptions(uuid_representation=bson.binary.STANDARD))
datakeys.drop()

print("cmk_id=%s\n" % cmk_id)
kms_client = boto3.client("kms")

# Not sure if this is the right way to create a random bson.binary.UUID in pymongo.
def randomUUID():
    return bson.binary.UUID(bytes=uuid.uuid4().bytes)

master_key_doc = { # not currently used in demo.
    "provider": "aws",
    "awsKey": cmk_id,
    "awsRegion": boto3.session.Session().region_name
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


print("Inserted %d keys into %s" % (len(example_keys), datakeys.full_name))

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
                        "iv": bson.binary.Binary(b"i" * 16),
                        "keyVaultURI": "mongodb://localhost:27017/admin"
                    }
                }
            }
        }
   }
}

opts = json_util.JSONOptions(json_mode=json_util.JSONMode.CANONICAL,
                             uuid_representation=bson.binary.STANDARD
                             )

print("Created an example schema for the test.crypt collection:")
print(json_util.dumps(example_schema, indent=4, json_options=opts))

print("Saved schema to ../test/schema.json")
f = open("../test/schema.json", "w")
f.write(json_util.dumps(example_schema, indent=4, json_options=opts))
f.close()

