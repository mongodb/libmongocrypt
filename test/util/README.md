`csfle` is a small utility for testing the state machine with real data.

To build `csfle`, ensure libmongoc is installed (in addition to libbson) and set the option -DENABLE_ONLINE_TESTS=ON when configuring with `cmake`.

Options can also be provided through a config flag.

Global options
    --options_file <string>
        Alternative way to pass all options.
    --kms_providers_file <string>
        Defaults to ~/.csfle/kms_providers.json
    --mongocryptd_uri <string>
        Defaults to "mongodb://localhost:27020".
    --mongodb_uri <string>
        Defaults to "mongodb://localhost:27017".
    --mongodb_keyvault_uri <string>
        Defaults to "mongodb://localhost:27017".
    --keyvault_namespace <string>
        Defaults to "keyvault.datakeys".
    --schema_map_file <string> (optional)
        Defaults to using remote schemas.
    --trace <bool>
        Defaults to false.

csfle create_datakey
    --kms_provider <string>
    --key_alt_names <comma separated strings>

    AWS options.
    --aws_kek_region <string>
    --aws_kek_key <string>
    --aws_kek_endpoint <string>

    Azure options.
    --azure_kek_keyvaultendpoint <string>
    --azure_kek_keyname <string>
    --azure_kek_keyversion <string> (optional)

    GCP options.
    --gcp_kek_endpoint <string>
    --gcp_kek_projectid <string>
    --gcp_kek_location <string>
    --gcp_kek_keyring <string>
    --gcp_kek_keyname <string>
    --gcp_kek_keyversion <string> (optional)

csfle auto_encrypt
    --command <JSON string> or --command_file <string>
    --db <string>

csfle auto_decrypt
    --document <JSON string> or --document_file <string>

csfle explicit_encrypt
    --value <JSON string> Document must have form { "v": ... }
    --key_id <base64 string>
    --key_alt_name <string>
    --algorithm <string>

csfle explicit_decrypt
    --value <JSON string> Document must have form { "v": ... }


The KMS providers file must be extended canonical JSON of the following form.

```
{
    "aws": {
        "accessKeyId": <string>,
        "secretAccessKey": <string>
    }

    "local": {
        "key": <binary of 96 bytes>
    }
}
```

No KMS providers are required.


## Examples

```
csfle create_datakey --kms_provider aws --aws_kek_region us-east-1 --aws_kek_key "arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0"

csfle auto_encrypt --command '{"insert": "coll", "documents": [{"ssn": "123"}]}' --db "db" --schema_map_file ./.csfle/schema_map.json

csfle auto_decrypt --document '{ "insert" : "coll", "documents" : [ { "ssn" : { "$binary" : { "base64": "ARG+PK8ud0RZlDIzKwQmFoMCOuSIPyrfYleSqMZRXgaPCQOAurv0LTLNL6Tn/G7TuVOyf/Qv3j6VxSxCQEeu/yO7vv/UDE5niDE0itjOqjmf5Q==", "subType" : "06" } } } ] }'

csfle explicit_encrypt --key_id "Eb48ry53RFmUMjMrBCYWgw==" --value '{"v": "test"}' --algorithm "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
```