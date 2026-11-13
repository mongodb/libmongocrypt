# decode_payload

Decode In-Use Encryption (IUE) payloads.

This tool is not a supported product and has no stability guarantees.

# Example Usage

```bash
# Print name of payload:
./tools/decode_payload.sh ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
# FLE1EncryptionPlaceholder

# Pass --json to dump JSON of payloads that wrap BSON:
./tools/decode_payload.sh --json ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
# {
#     "name": "FLE1EncryptionPlaceholder",
#     "dump": {
#         "a": 1,
#         "ki": {
#             "$binary": {
#                 "base64": "YWFhYWFhYWFhYWFhYWFhYQ==",
#                 "subType": "04"
#             }
#         },
#         "v": "457-55-5462"
#     }
# }

# Use test directory for sample payloads:
./tools/decode_payload.sh $(cat ./tools/decode_payload/tests/payload2.b64)
# FLE1RandomEncryptedValue
```

# Explanation

FLE1 refers to payloads for CSFLE. FLE2 refers to payloads for QE. See [Naming](https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/client-side-encryption/client-side-encryption.md#naming).

## FLE1EncryptionPlaceholder (0)

<table>
  <tr>
    <td>Created by</td>
    <td>mongocryptd / crypt_shared</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md">Spec</a> / <a href="https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L134-L159">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-marking.c#L48-L143">libmongocrypt</a></td>
  </tr>
</table>


## FLE1DeterministicEncryptedValue (1)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md">Spec</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-ciphertext-private.h#L31-L36">libmongocrypt</a></td>
  </tr>
</table>

## FLE1RandomEncryptedValue (2)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md">Spec</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-ciphertext-private.h#L31-L36">libmongocrypt</a></td>
  </tr>
</table>

## FLE2EncryptionPlaceholder (3)

<table>
  <tr>
    <td>Created by</td>
    <td>mongocryptd / crypt_shared</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L161-L198">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-encryption-placeholder-private.h#L219-L228">libmongocrypt</a></td>
  </tr>
</table>

## FLE2InsertUpdatePayload (4)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongocryptd / crypt_shared</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L232-L272">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-insert-update-payload-private.h#L64-L76">libmongocrypt</a></td>
  </tr>
</table>

## FLE2FindEqualityPayload (5)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L334-L359">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-equality-payload-private.h#L24-L30">libmongocrypt</a></td>
  </tr>
</table>

## FLE2UnindexedEncryptedValue (6)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-uev-private.h#L24-L44">libmongocrypt</a></td>
  </tr>
</table>

## FLE2IndexedEqualityEncryptedValue (7)

<table>
  <tr>
    <td>Created by</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private.h#L38-L66">libmongocrypt</a></td>
  </tr>
</table>

## FLE2IndexedRangeEncryptedValue (9)

<table>
  <tr>
    <td>Created by</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private.h#L68-L84">libmongocrypt</a></td>
  </tr>
</table>

## FLE2FindRangePayload (10)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L447-L466">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-range-payload-private.h#L53-L67">libmongocrypt</a></td>
  </tr>
</table>

## FLE2InsertUpdatePayloadV2 (11)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L326-L404">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-insert-update-payload-private-v2.h#L107-L131">libmongocrypt</a></td>
  </tr>
</table>

## FLE2FindEqualityPayloadV2 (12)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L406-L426">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-equality-payload-private-v2.h#L24-L29">libmongocrypt</a></td>
  </tr>
</table>

## FLE2FindRangePayloadV2 (13)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L458-L505">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-range-payload-private-v2.h#L58-L78">libmongocrypt</a></td>
  </tr>
</table>

## FLE2EqualityIndexedValueV2 (14)

<table>
  <tr>
    <td>Created by</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L42-L62">libmongocrypt</a></td>
  </tr>
</table>

## FLE2RangeIndexedValueV2 (15)

<table>
  <tr>
    <td>Created by</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L65-L74">libmongocrypt</a></td>
  </tr>
</table>

## FLE2UnindexedEncryptedValueV2 (16)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-uev-v2-private.h#L24-L44">libmongocrypt</a></td>
  </tr>
</table>

## FLE2IndexedTextEncryptedValue (17)

<table>
  <tr>
    <td>Created by</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L81-L102">libmongocrypt</a></td>
  </tr>
</table>

## FLE2FindTextPayload (18)

<table>
  <tr>
    <td>Created by</td>
    <td>libmongocrypt</td>
  </tr>
  <tr>
    <td>Intended for</td>
    <td>mongod / mongos</td>
  </tr>
  <tr>
    <td>References</td>
    <td><a href="https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L815-L850">Server IDL</a> / <a href="https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-text-payload-private.h#L92-L112">libmongocrypt</a></td>
  </tr>
</table>
