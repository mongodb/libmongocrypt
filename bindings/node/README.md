MongoDB Client Encryption
=========================

The Node.js wrapper for [`libmongocrypt`](../../README.md)

### Requirements

Follow the instructions for building `libmongocrypt` [here](../../README.md#building-libmongocrypt).

### Installation

Now you can install `mongodb-client-encryption` with the following:

```bash
npm install mongodb-client-encryption
```

### Testing

Run the test suite using:

```bash
npm test
```

# Documentation

## Classes

<dl>
<dt><a href="#AutoEncrypter">AutoEncrypter</a></dt>
<dd><p>An internal class to be used by the driver for auto encryption
<strong>NOTE</strong>: Not meant to be instantiated directly, this is for internal use only.</p>
</dd>
<dt><a href="#ClientEncryption">ClientEncryption</a></dt>
<dd><p>The public interface for explicit client side encryption</p>
</dd>
<dt><a href="#MongoCryptError">MongoCryptError</a></dt>
<dd><p>An error indicating that something went wrong specifically with MongoDB Client Encryption</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#KMSProviders">KMSProviders</a></dt>
<dd><p>Configuration options that are used by specific kms providers during key generation, encryption, and decryption.</p>
</dd>
</dl>

<a name="AutoEncrypter"></a>

## AutoEncrypter
An internal class to be used by the driver for auto encryption
**NOTE**: Not meant to be instantiated directly, this is for internal use only.


* [AutoEncrypter](#AutoEncrypter)

    * [new AutoEncrypter(client, [options])](#new_AutoEncrypter_new)

    * [~AutoEncryptionExtraOptions](#AutoEncrypter..AutoEncryptionExtraOptions)


<a name="new_AutoEncrypter_new"></a>

### new AutoEncrypter(client, [options])

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| client | <code>MongoClient</code> |  | The client autoEncryption is enabled on |
| [options] | <code>object</code> |  | Optional settings |
| [options.keyVaultNamespace] | <code>string</code> | <code>&quot;&#x27;admin.dataKeys&#x27;&quot;</code> | The namespace of the key vault, used to store encryption keys |
| [options.schemaMap] | <code>object</code> |  | A local specification of a JSON schema used for encryption |
| [options.kmsProviders] | [<code>KMSProviders</code>](#KMSProviders) |  | options for specific kms providers to use |
| [options.logger] | <code>function</code> |  | An optional hook to catch logging messages from the underlying encryption engine |
| [options.extraOptions] | [<code>AutoEncryptionExtraOptions</code>](#AutoEncrypter..AutoEncryptionExtraOptions) |  | Extra options related to mongocryptd |

Create an AutoEncrypter

**Note: Do not instantiate this class directly. Rather, supply the relevant options to a MongoClient**

**Note: Supplying `options.schemaMap` provides more security than relying on JSON Schemas obtained from the server.**
**It protects against a malicious server advertising a false JSON Schema, which could trick the client into sending unencrypted data that should be encrypted.**
**Schemas supplied in the schemaMap only apply to configuring automatic encryption for client side encryption.**
**Other validation rules in the JSON schema will not be enforced by the driver and will result in an error.**

**Example**  
```js
// Enabling autoEncryption via a MongoClient
const { MongoClient } = require('mongodb');
const client = new MongoClient(URL, {
  autoEncryption: {
    kmsProviders: {
      aws: {
        accessKeyId: AWS_ACCESS_KEY,
        secretAccessKey: AWS_SECRET_KEY
      }
    }
  }
});

await client.connect();
// From here on, the client will be encrypting / decrypting automatically
```
<a name="AutoEncrypter..AutoEncryptionExtraOptions"></a>

### *AutoEncrypter*~AutoEncryptionExtraOptions
**Properties**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| [mongocryptdURI] | <code>string</code> |  | overrides the uri used to connect to mongocryptd |
| [mongocryptdBypassSpawn] | <code>boolean</code> | <code>false</code> | if true, autoEncryption will not spawn a mongocryptd |
| [mongocryptdSpawnPath] | <code>string</code> |  | the path to the mongocryptd executable |
| [mongocryptdSpawnArgs] | <code>Array.&lt;string&gt;</code> |  | command line arguments to pass to the mongocryptd executable |

<a name="ClientEncryption"></a>

## ClientEncryption
The public interface for explicit client side encryption


* [ClientEncryption](#ClientEncryption)

    * [new ClientEncryption(client, options)](#new_ClientEncryption_new)

    * _instance_
        * [.createDataKey(provider, [options], [callback])](#ClientEncryption+createDataKey)

        * [.encrypt(value, options, [callback])](#ClientEncryption+encrypt)

        * [.decrypt(value, callback)](#ClientEncryption+decrypt)

    * _inner_
        * [~dataKey](#ClientEncryption..dataKey)

        * [~createDataKeyCallback](#ClientEncryption..createDataKeyCallback)

        * [~encryptCallback](#ClientEncryption..encryptCallback)

        * [~decryptCallback](#ClientEncryption..decryptCallback)


<a name="new_ClientEncryption_new"></a>

### new ClientEncryption(client, options)

| Param | Type | Description |
| --- | --- | --- |
| client | <code>MongoClient</code> | The client used for encryption |
| options | <code>object</code> | Optional settings |
| options.keyVaultNamespace | <code>string</code> | The namespace of the key vault, used to store encryption keys |
| [options.kmsProviders] | [<code>KMSProviders</code>](#KMSProviders) | options for specific kms providers to use |

Create a new encryption instance

**Example**  
```js
new ClientEncryption(mongoClient, {
  keyVaultNamespace: 'client.encryption',
  kmsProviders: {
    local: {
      key: masterKey // The master key used for encryption/decryption. A 96-byte long Buffer
    }
  }
});
```
**Example**  
```js
new ClientEncryption(mongoClient, {
  keyVaultNamespace: 'client.encryption',
  kmsProviders: {
    aws: {
      accessKeyId: AWS_ACCESS_KEY,
      secretAccessKey: AWS_SECRET_KEY
    }
  }
});
```
<a name="ClientEncryption+createDataKey"></a>

### *clientEncryption*.createDataKey(provider, [options], [callback])

| Param | Type | Description |
| --- | --- | --- |
| provider | <code>string</code> | The KMS provider used for this data key. Must be `'aws'` or `'local'` |
| [options] | <code>object</code> | Options for creating the data key |
| [options.masterKey] | <code>object</code> | Idenfities a new KMS-specific key used to encrypt the new data key. If the kmsProvider is "aws" it is required. |
| [options.masterKey.region] | <code>string</code> | The AWS region of the KMS |
| [options.masterKey.key] | <code>string</code> | The Amazon Resource Name (ARN) to the AWS customer master key (CMK) |
| [options.keyAltNames] | <code>Array.&lt;string&gt;</code> | An optional list of string alternate names used to reference a key. If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id. |
| [callback] | [<code>createDataKeyCallback</code>](#ClientEncryption..createDataKeyCallback) | Optional callback to invoke when key is created |

Creates a data key used for explicit encryption

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with the created data key, or rejects with an error. If a callback is provided, returns nothing.  
**Example**  
```js
// Using callbacks to create a local key
clientEncrypion.createDataKey('local', (err, dataKey) => {
  if (err) {
    // This means creating the key failed.
  } else {
    // key creation succeeded
  }
});
```
**Example**  
```js
// Using async/await to create a local key
const dataKey = await clientEncryption.createDataKey('local');
```
**Example**  
```js
// Using async/await to create an aws key
const dataKey = await clientEncryption.createDataKey('aws', {
  masterKey: {
    region: 'us-east-1',
    key: 'xxxxxxxxxxxxxx' // CMK ARN here
  }
});
```
**Example**  
```js
// Using async/await to create an aws key with a keyAltName
const dataKey = await clientEncryption.createDataKey('aws', {
  masterKey: {
    region: 'us-east-1',
    key: 'xxxxxxxxxxxxxx' // CMK ARN here
  },
  keyAltNames: [ 'mySpecialKey' ]
});
```
<a name="ClientEncryption+encrypt"></a>

### *clientEncryption*.encrypt(value, options, [callback])

| Param | Type | Description |
| --- | --- | --- |
| value | <code>\*</code> | The value that you wish to serialize. Must be of a type that can be serialized into BSON |
| options | <code>object</code> |  |
| [options.dataKey] | [<code>dataKey</code>](#ClientEncryption..dataKey) | The Binary dataKey to use for encryption |
| [options.keyAltName] | <code>string</code> | A unique string name corresponding to an already existing {[dataKey](#ClientEncryption..dataKey)} |
| options.algorithm |  | The algorithm to use for encryption. Must be either `'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'` or `AEAD_AES_256_CBC_HMAC_SHA_512-Random'` |
| [callback] | [<code>encryptCallback</code>](#ClientEncryption..encryptCallback) | Optional callback to invoke when value is encrypted |

Explicitly encrypt a provided value. Note that either `options.dataKey` or `options.keyAltName` must
be specified. Specifying both `options.dataKey` and `options.keyAltName` is considered an error.

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with the encrypted value, or rejects with an error. If a callback is provided, returns nothing.  
**Example**  
```js
// Encryption with callback API
function encryptMyData(value, callback) {
  clientEncryption.createDataKey('local', (err, dataKey) => {
    if (err) {
      return callback(err);
    }
    clientEncryption.encrypt(value, { dataKey, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' }, callback);
  });
}
```
**Example**  
```js
// Encryption with async/await api
async function encryptMyData(value) {
  const dataKey = await clientEncryption.createDataKey('local');
  return clientEncryption.encrypt(value, { dataKey, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' });
}
```
**Example**  
```js
// Encryption using a keyAltName
async function encryptMyData(value) {
  await clientEncryption.createDataKey('local', { keyAltNames: 'mySpecialKey' });
  return clientEncryption.encrypt(value, { keyAltName: 'mySpecialKey', algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' });
}
```
<a name="ClientEncryption+decrypt"></a>

### *clientEncryption*.decrypt(value, callback)

| Param | Type | Description |
| --- | --- | --- |
| value | <code>Buffer</code> | An encrypted value |
| callback | [<code>decryptCallback</code>](#ClientEncryption..decryptCallback) | Optional callback to invoke when value is decrypted |

Explicitly decrypt a provided encrypted value

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with the decryped value, or rejects with an error. If a callback is provided, returns nothing.  
**Example**  
```js
// Decrypting value with callback API
function decryptMyValue(value, callback) {
  clientEncryption.decrypt(value, callback);
}
```
**Example**  
```js
// Decrypting value with async/await API
async function decryptMyValue(value) {
  return clientEncryption.decrypt(value);
}
```
<a name="ClientEncryption..dataKey"></a>

### *ClientEncryption*~dataKey
A key used for manual encryption / decryption. Is a BSON Binary object.

<a name="ClientEncryption..createDataKeyCallback"></a>

### *ClientEncryption*~createDataKeyCallback

| Param | Type | Description |
| --- | --- | --- |
| [error] | <code>Error</code> | If present, indicates an error that occurred in the creation of the data key |
| [dataKey] | [<code>dataKey</code>](#ClientEncryption..dataKey) | If present, returns the new data key |

<a name="ClientEncryption..encryptCallback"></a>

### *ClientEncryption*~encryptCallback

| Param | Type | Description |
| --- | --- | --- |
| [err] | <code>Error</code> | If present, indicates an error that occurred in the process of encryption |
| [result] | <code>Buffer</code> | If present, is the encrypted result |

<a name="ClientEncryption..decryptCallback"></a>

### *ClientEncryption*~decryptCallback

| Param | Type | Description |
| --- | --- | --- |
| [err] | <code>Error</code> | If present, indicates an error that occurred in the process of decryption |
| [result] | <code>object</code> | If present, is the decrypted result |

<a name="MongoCryptError"></a>

## MongoCryptError
An error indicating that something went wrong specifically with MongoDB Client Encryption

<a name="KMSProviders"></a>

## KMSProviders
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [aws] | <code>object</code> | Configuration options for using 'aws' as your kms provider |
| [aws.accessKeyId] | <code>string</code> | An AWS Access Key |
| [aws.secretAccessKey] | <code>string</code> | An AWS Secret Key |
| [local] | <code>object</code> | Configuration options for using 'local' as your kms provider |
| [local.key] | <code>Buffer</code> | A 96-byte long Buffer used for local encryption |

Configuration options that are used by specific kms providers during key generation, encryption, and decryption.

