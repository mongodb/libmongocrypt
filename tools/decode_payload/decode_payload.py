# /// script
# dependencies = [
#   "pymongo",
# ]
# ///

import base64
import sys
import bson
import bson.json_util
import bson.errors
import argparse


def decode_payload(data):
    blob_subtypes = {
        0: "FLE1EncryptionPlaceholder",
        1: "FLE1DeterministicEncryptedValue",
        2: "FLE1RandomEncryptedValue",
        3: "FLE2EncryptionPlaceholder",
        4: "FLE2InsertUpdatePayload",
        5: "FLE2FindEqualityPayload",
        6: "FLE2UnindexedEncryptedValue",
        7: "FLE2IndexedEqualityEncryptedValue",
        9: "FLE2IndexedRangeEncryptedValue",
        10: "FLE2FindRangePayload",
        11: "FLE2InsertUpdatePayloadV2",
        12: "FLE2FindEqualityPayloadV2",
        13: "FLE2FindRangePayloadV2",
        14: "FLE2EqualityIndexedValueV2",
        15: "FLE2RangeIndexedValueV2",
        16: "FLE2UnindexedEncryptedValueV2",
        17: "FLE2IndexedTextEncryptedValue",
        18: "FLE2FindTextPayload",
    }

    blob_subtype = data[0]

    payload_name = blob_subtypes[blob_subtype]

    result = {"name": payload_name}

    # Some payloads are light wrappers around BSON.
    try:
        as_bson = bson.decode(data[1:])
        result["dump"] = as_bson
    except bson.errors.InvalidBSON:
        pass

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json", action="store_true", help="Print output in JSON format"
    )

    parser.add_argument("base64", type=str, help="base64 of a CSFLE/QE payload")

    args = parser.parse_args()

    data = base64.b64decode(args.base64)
    result = decode_payload(data)
    if args.json:
        print(bson.json_util.dumps(result, indent=4))
    else:
        print(result["name"])
