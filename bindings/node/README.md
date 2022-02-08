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
<dt><a href="#KMSProviders">KMSProviders</a> : <code>object</code></dt>
<dd><p>Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.</p>
</dd>
<dt><a href="#AWSEncryptionKeyOptions">AWSEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making an AWS encryption key</p>
</dd>
<dt><a href="#GCPEncryptionKeyOptions">GCPEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making a GCP encryption key</p>
</dd>
<dt><a href="#AzureEncryptionKeyOptions">AzureEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making an Azure encryption key</p>
</dd>
</dl>

<a name="AutoEncrypter"></a>

## AutoEncrypter
An internal class to be used by the driver for auto encryption
**NOTE**: Not meant to be instantiated directly, this is for internal use only.


* [AutoEncrypter](#AutoEncrypter)

    * [new AutoEncrypter(client, [options])](#new_AutoEncrypter_new)

    * [~logLevel](#AutoEncrypter..logLevel)

    * [~AutoEncryptionOptions](#AutoEncrypter..AutoEncryptionOptions)

    * [~AutoEncryptionExtraOptions](#AutoEncrypter..AutoEncryptionExtraOptions)

    * [~logger](#AutoEncrypter..logger)


<a name="new_AutoEncrypter_new"></a>

### new AutoEncrypter(client, [options])

| Param | Type | Description |
| --- | --- | --- |
| client | <code>MongoClient</code> | The client autoEncryption is enabled on |
| [options] | [<code>AutoEncryptionOptions</code>](#AutoEncrypter..AutoEncryptionOptions) | Optional settings |

Create an AutoEncrypter

**Note**: Do not instantiate this class directly. Rather, supply the relevant options to a MongoClient

**Note**: Supplying `options.schemaMap` provides more security than relying on JSON Schemas obtained from the server.
It protects against a malicious server advertising a false JSON Schema, which could trick the client into sending unencrypted data that should be encrypted.
Schemas supplied in the schemaMap only apply to configuring automatic encryption for client side encryption.
Other validation rules in the JSON schema will not be enforced by the driver and will result in an error.

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
<a name="AutoEncrypter..logLevel"></a>

### *AutoEncrypter*~logLevel
The level of severity of the log message

| Value | Level |
|-------|-------|
| 0 | Fatal Error |
| 1 | Error |
| 2 | Warning |
| 3 | Info |
| 4 | Trace |

<a name="AutoEncrypter..AutoEncryptionOptions"></a>

### *AutoEncrypter*~AutoEncryptionOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [keyVaultClient] | <code>MongoClient</code> | A `MongoClient` used to fetch keys from a key vault |
| [keyVaultNamespace] | <code>string</code> | The namespace where keys are stored in the key vault |
| [kmsProviders] | [<code>KMSProviders</code>](#KMSProviders) | Configuration options that are used by specific KMS providers during key generation, encryption, and decryption. |
| [schemaMap] | <code>object</code> | A map of namespaces to a local JSON schema for encryption |
| [bypassAutoEncryption] | <code>boolean</code> | Allows the user to bypass auto encryption, maintaining implicit decryption |
| [options.logger] | [<code>logger</code>](#AutoEncrypter..logger) | An optional hook to catch logging messages from the underlying encryption engine |
| [extraOptions] | [<code>AutoEncryptionExtraOptions</code>](#AutoEncrypter..AutoEncryptionExtraOptions) | Extra options related to the mongocryptd process |

Configuration options for a automatic client encryption.

<a name="AutoEncrypter..AutoEncryptionExtraOptions"></a>

### *AutoEncrypter*~AutoEncryptionExtraOptions
**Properties**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| [mongocryptdURI] | <code>string</code> |  | A local process the driver communicates with to determine how to encrypt values in a command. Defaults to "mongodb://%2Fvar%2Fmongocryptd.sock" if domain sockets are available or "mongodb://localhost:27020" otherwise |
| [mongocryptdBypassSpawn] | <code>boolean</code> | <code>false</code> | If true, autoEncryption will not attempt to spawn a mongocryptd before connecting |
| [mongocryptdSpawnPath] | <code>string</code> |  | The path to the mongocryptd executable on the system |
| [mongocryptdSpawnArgs] | <code>Array.&lt;string&gt;</code> |  | Command line arguments to use when auto-spawning a mongocryptd |

Extra options related to the mongocryptd process

<a name="AutoEncrypter..logger"></a>

### *AutoEncrypter*~logger

| Param | Type | Description |
| --- | --- | --- |
| level | [<code>logLevel</code>](#AutoEncrypter..logLevel) | The level of logging. |
| message | <code>string</code> | The message to log |

A callback that is invoked with logging information from
the underlying C++ Bindings.

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
        * [~dataKeyId](#ClientEncryption..dataKeyId)

        * [~createDataKeyCallback](#ClientEncryption..createDataKeyCallback)

        * [~encryptCallback](#ClientEncryption..encryptCallback)

        * [~decryptCallback](#ClientEncryption..decryptCallback)


<a name="new_ClientEncryption_new"></a>

### new ClientEncryption(client, options)

| Param | Type | Description |
| --- | --- | --- |
| client | <code>MongoClient</code> | The client used for encryption |
| options | <code>object</code> | Additional settings |
| options.keyVaultNamespace | <code>string</code> | The namespace of the key vault, used to store encryption keys |
| options.tlsOptions | <code>object</code> | An object that maps KMS provider names to TLS options. |
| [options.keyVaultClient] | <code>MongoClient</code> | A `MongoClient` used to fetch keys from a key vault. Defaults to `client` |
| [options.kmsProviders] | [<code>KMSProviders</code>](#KMSProviders) | options for specific KMS providers to use |

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
| provider | <code>string</code> | The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'` |
| [options] | <code>object</code> | Options for creating the data key |
| [options.masterKey] | [<code>AWSEncryptionKeyOptions</code>](#AWSEncryptionKeyOptions) \| [<code>AzureEncryptionKeyOptions</code>](#AzureEncryptionKeyOptions) \| [<code>GCPEncryptionKeyOptions</code>](#GCPEncryptionKeyOptions) | Idenfities a new KMS-specific key used to encrypt the new data key |
| [options.keyAltNames] | <code>Array.&lt;string&gt;</code> | An optional list of string alternate names used to reference a key. If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id. |
| [callback] | [<code>createDataKeyCallback</code>](#ClientEncryption..createDataKeyCallback) | Optional callback to invoke when key is created |

Creates a data key used for explicit encryption and inserts it into the key vault namespace

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with [the id of the created data key](#ClientEncryption..dataKeyId), or rejects with an error. If a callback is provided, returns nothing.
**Example**
```js
// Using callbacks to create a local key
clientEncryption.createDataKey('local', (err, dataKey) => {
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
const dataKeyId = await clientEncryption.createDataKey('local');
```
**Example**
```js
// Using async/await to create an aws key
const dataKeyId = await clientEncryption.createDataKey('aws', {
  masterKey: {
    region: 'us-east-1',
    key: 'xxxxxxxxxxxxxx' // CMK ARN here
  }
});
```
**Example**
```js
// Using async/await to create an aws key with a keyAltName
const dataKeyId = await clientEncryption.createDataKey('aws', {
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
| [options.keyId] | [<code>dataKeyId</code>](#ClientEncryption..dataKeyId) | The id of the Binary dataKey to use for encryption |
| [options.keyAltName] | <code>string</code> | A unique string name corresponding to an already existing dataKey. |
| options.algorithm |  | The algorithm to use for encryption. Must be either `'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'` or `AEAD_AES_256_CBC_HMAC_SHA_512-Random'` |
| [callback] | [<code>encryptCallback</code>](#ClientEncryption..encryptCallback) | Optional callback to invoke when value is encrypted |

Explicitly encrypt a provided value. Note that either `options.keyId` or `options.keyAltName` must
be specified. Specifying both `options.keyId` and `options.keyAltName` is considered an error.

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with the encrypted value, or rejects with an error. If a callback is provided, returns nothing.
**Example**
```js
// Encryption with callback API
function encryptMyData(value, callback) {
  clientEncryption.createDataKey('local', (err, keyId) => {
    if (err) {
      return callback(err);
    }
    clientEncryption.encrypt(value, { keyId, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' }, callback);
  });
}
```
**Example**
```js
// Encryption with async/await api
async function encryptMyData(value) {
  const keyId = await clientEncryption.createDataKey('local');
  return clientEncryption.encrypt(value, { keyId, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' });
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
| value | `Buffer \| Binary` | An encrypted value |
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
<a name="ClientEncryption..dataKeyId"></a>

### *ClientEncryption*~dataKeyId
The id of an existing dataKey. Is a bson Binary value.
Can be used for [ClientEncryption.encrypt](ClientEncryption.encrypt), and can be used to directly
query for the data key itself against the key vault namespace.

<a name="ClientEncryption..createDataKeyCallback"></a>

### *ClientEncryption*~createDataKeyCallback

| Param | Type | Description |
| --- | --- | --- |
| [error] | <code>Error</code> | If present, indicates an error that occurred in the creation of the data key |
| [dataKeyId] | [<code>dataKeyId</code>](#ClientEncryption..dataKeyId) | If present, returns the id of the created data key |

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
| [aws] | <code>object</code> | Configuration options for using 'aws' as your KMS provider |
| [aws.accessKeyId] | <code>string</code> | The access key used for the AWS KMS provider |
| [aws.secretAccessKey] | <code>string</code> | The secret access key used for the AWS KMS provider |
| [local] | <code>object</code> | Configuration options for using 'local' as your KMS provider |
| [local.key] | <code>Buffer</code> | The master key used to encrypt/decrypt data keys. A 96-byte long Buffer. |
| [azure] | <code>object</code> | Configuration options for using 'azure' as your KMS provider |
| [azure.tenantId] | <code>string</code> | The tenant ID identifies the organization for the account |
| [azure.clientId] | <code>string</code> | The client ID to authenticate a registered application |
| [azure.clientSecret] | <code>string</code> | The client secret to authenticate a registered application |
| [azure.identityPlatformEndpoint] | <code>string</code> | If present, a host with optional port. E.g. "example.com" or "example.com:443". This is optional, and only needed if customer is using a non-commercial Azure instance (e.g. a government or China account, which use different URLs). Defaults to  "login.microsoftonline.com" |
| [gcp] | <code>object</code> | Configuration options for using 'gcp' as your KMS provider |
| [gcp.email] | <code>string</code> | The service account email to authenticate |
| [gcp.privateKey] | <code>string</code> \| <code>Binary</code> | A PKCS#8 encrypted key. This can either be a base64 string or a binary representation |
| [gcp.endpoint] | <code>string</code> | If present, a host with optional port. E.g. "example.com" or "example.com:443". Defaults to "oauth2.googleapis.com" |

Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.

<a name="AWSEncryptionKeyOptions"></a>

## AWSEncryptionKeyOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| region | <code>string</code> | The AWS region of the KMS |
| key | <code>string</code> | The Amazon Resource Name (ARN) to the AWS customer master key (CMK) |
| [endpoint] | <code>string</code> | An alternate host to send KMS requests to. May include port number |

Configuration options for making an AWS encryption key

<a name="GCPEncryptionKeyOptions"></a>

## GCPEncryptionKeyOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| projectId | <code>string</code> | GCP project id |
| location | <code>string</code> | Location name (e.g. "global") |
| keyRing | <code>string</code> | Key ring name |
| keyName | <code>string</code> | Key name |
| [keyVersion] | <code>string</code> | Key version |
| [endpoint] | <code>string</code> | KMS URL, defaults to `https://www.googleapis.com/auth/cloudkms` |

Configuration options for making a GCP encryption key

<a name="AzureEncryptionKeyOptions"></a>

## AzureEncryptionKeyOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| keyName | <code>string</code> | Key name |
| keyVaultEndpoint | <code>string</code> | Key vault URL, typically `<name>.vault.azure.net` |
| [keyVersion] | <code>string</code> | Key version |

Configuration options for making an Azure encryption key
