Documents in this test data directory provide inputs and corresponding expected outputs for token derivation functions in libmongocrypt.
Each document is a single-depth set of key value pairs. All values are 32 octet hexit string except `counter` which is numeric.

[server.json](server.json) comes from [TEST(FLETokens, TestVectors)](https://github.com/mongodb/mongo/blob/master/src/mongo/crypto/fle_crypto_test.cpp).

| field | Description |
| ----- | ----------- |
| root | The base key from which all other tokens are derived. |
| value | Data used in `DerivedFromData` tokens. |
| contentionFactor | Data used in `DerivedFromDataAndContentionFactor` tokens. |
| collectionsLevel1Token | HMAC(root, 1) |
| serverTokenDerivationLevel1Token | HMAC(root, 2) |
| serverDataEncryptionLevel1Token | HMAC(root, 3) |
| EDCToken | HMAC(collectionsLevel1Token, 1) |
| ESCToken | HMAC(collectionsLevel1Token, 2) |
| ECCToken | HMAC(collectionsLevel1Token, 3) |
| ECOCToken | HMAC(collectionsLevel1Token, 4) |
| EDCDerivedFromDataToken | HMAC(EDCToken, value) |
| ESCDerivedFromDataToken | HMAC(ESCToken, value) |
| ECCDerivedFromDataToken | HMAC(ECCToken, value) |
| EDCDerivedFromDataTokenAndContentionFactor| HMAC(EDCDerivedFromDataToken, contentionFactor) |
| ESCDerivedFromDataTokenAndContentionFactor| HMAC(ESCDerivedFromDataToken, contentionFactor) |
| ECCDerivedFromDataTokenAndContentionFactor| HMAC(ECCDerivedFromDataToken, contentionFactor) |
| EDCTwiceDerivedToken | HMAC(EDCDerivedFromDataTokenAndContentionFactor, 1) |
| ESCTwiceDerivedTagToken | HMAC(ESCDerivedFromDataTokenAndContentionFactor, 1) |
| ESCTwiceDerivedValueToken | HMAC(ESCDerivedFromDataTokenAndContentionFactor, 2) |
| serverDerivedFromDataToken | HMAC(serverTokenDerivationLevel1Token, value) |
| serverCountAndContentionFactorEncryptionToken | HMAC(serverDerivedFromDataToken, 1) |
| serverZerosEncryptionToken | HMAC(serverDerivedFromDataToken, 2) |

