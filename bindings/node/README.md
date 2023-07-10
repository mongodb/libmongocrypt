MongoDB Client Encryption
=========================

The Node.js wrapper for [`libmongocrypt`](../../README.md)

### Installation

You can install `mongodb-client-encryption` with the following:

```bash
npm install mongodb-client-encryption
```

### Development
#### Setup

Run the following command to build libmongocrypt and setup the node bindings for development:

```shell
bash ./etc/build-static.sh
```


#### Testing

Some tests require a standalone server to be running with authentication enabled.  Set up a single
server running with the following conditions:

| param     | value     |
|-----------|-----------|
| host      | localhost |
| port      | 27017     |

This is the standard setup for a standalone server with no authentication.

Run the test suite using:

```bash
npm test
```

# Documentation

## Deprecation Notice

There are breaking changes planned for this package.  In the next major version, callbacks will be removed
from the public API on all asynchronous functions.  Additionally, the classes documented here will be
moved into [node-mongodb-native](https://github.com/mongodb/node-mongodb-native).

## Classes

<dl>
<dt><a href="#AutoEncrypter">AutoEncrypter</a></dt>
<dd><p>An internal class to be used by the driver for auto encryption
<strong>NOTE</strong>: Not meant to be instantiated directly, this is for internal use only.</p>
</dd>
<dt><del><a href="#ClientEncryption">ClientEncryption</a></del></dt>
<dd></dd>
<dt><del><a href="#MongoCryptError">MongoCryptError</a></del></dt>
<dd><p>An error indicating that something went wrong specifically with MongoDB Client Encryption</p>
</dd>
<dt><del><a href="#MongoCryptCreateDataKeyError">MongoCryptCreateDataKeyError</a></del></dt>
<dd><p>An error indicating that <code>ClientEncryption.createEncryptedCollection()</code> failed to create data keys</p>
</dd>
<dt><del><a href="#MongoCryptCreateEncryptedCollectionError">MongoCryptCreateEncryptedCollectionError</a></del></dt>
<dd><p>An error indicating that <code>ClientEncryption.createEncryptedCollection()</code> failed to create a collection</p>
</dd>
<dt><del><a href="#MongoCryptAzureKMSRequestError">MongoCryptAzureKMSRequestError</a></del></dt>
<dd><p>An error indicating that mongodb-client-encryption failed to auto-refresh Azure KMS credentials.</p>
</dd>
<dt><del><a href="#MongoCryptKMSRequestNetworkTimeoutError">MongoCryptKMSRequestNetworkTimeoutError</a></del></dt>
<dd></dd>
</dl>

## Typedefs

<dl>
<dt><a href="#BSONValue">BSONValue</a> : <code>*</code></dt>
<dd><p>any serializable BSON value</p>
</dd>
<dt><a href="#Long">Long</a> : <code>BSON.Long</code></dt>
<dd><p>A 64 bit integer, represented by the js-bson Long type.</p>
</dd>
<dt><a href="#KMSProviders">KMSProviders</a> : <code>object</code></dt>
<dd><p>Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.</p>
</dd>
<dt><a href="#DataKey">DataKey</a> : <code>object</code></dt>
<dd><p>A data key as stored in the database.</p>
</dd>
<dt><a href="#KmsProvider">KmsProvider</a> : <code>string</code></dt>
<dd><p>A string containing the name of a kms provider.  Valid options are &#39;aws&#39;, &#39;azure&#39;, &#39;gcp&#39;, &#39;kmip&#39;, or &#39;local&#39;</p>
</dd>
<dt><a href="#ClientSession">ClientSession</a> : <code>object</code></dt>
<dd><p>The ClientSession class from the MongoDB Node driver (see <a href="https://mongodb.github.io/node-mongodb-native/4.8/classes/ClientSession.html">https://mongodb.github.io/node-mongodb-native/4.8/classes/ClientSession.html</a>)</p>
</dd>
<dt><a href="#DeleteResult">DeleteResult</a> : <code>object</code></dt>
<dd><p>The result of a delete operation from the MongoDB Node driver (see <a href="https://mongodb.github.io/node-mongodb-native/4.8/interfaces/DeleteResult.html">https://mongodb.github.io/node-mongodb-native/4.8/interfaces/DeleteResult.html</a>)</p>
</dd>
<dt><a href="#BulkWriteResult">BulkWriteResult</a> : <code>object</code></dt>
<dd><p>The BulkWriteResult class from the MongoDB Node driver (<a href="https://mongodb.github.io/node-mongodb-native/4.8/classes/BulkWriteResult.html">https://mongodb.github.io/node-mongodb-native/4.8/classes/BulkWriteResult.html</a>)</p>
</dd>
<dt><a href="#FindCursor">FindCursor</a> : <code>object</code></dt>
<dd><p>The FindCursor class from the MongoDB Node driver (see <a href="https://mongodb.github.io/node-mongodb-native/4.8/classes/FindCursor.html">https://mongodb.github.io/node-mongodb-native/4.8/classes/FindCursor.html</a>)</p>
</dd>
<dt><a href="#ClientEncryptionDataKeyId">ClientEncryptionDataKeyId</a> : <code>Binary</code></dt>
<dd><p>The id of an existing dataKey. Is a bson Binary value.
Can be used for <a href="ClientEncryption.encrypt">ClientEncryption.encrypt</a>, and can be used to directly
query for the data key itself against the key vault namespace.</p>
</dd>
<dt><del><a href="#ClientEncryptionCreateDataKeyCallback">ClientEncryptionCreateDataKeyCallback</a> : <code>function</code></del></dt>
<dd></dd>
<dt><a href="#AWSEncryptionKeyOptions">AWSEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making an AWS encryption key</p>
</dd>
<dt><a href="#GCPEncryptionKeyOptions">GCPEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making a GCP encryption key</p>
</dd>
<dt><a href="#AzureEncryptionKeyOptions">AzureEncryptionKeyOptions</a> : <code>object</code></dt>
<dd><p>Configuration options for making an Azure encryption key</p>
</dd>
<dt><a href="#RewrapManyDataKeyResult">RewrapManyDataKeyResult</a> : <code>object</code></dt>
<dd></dd>
<dt><del><a href="#ClientEncryptionEncryptCallback">ClientEncryptionEncryptCallback</a> : <code>function</code></del></dt>
<dd></dd>
<dt><a href="#RangeOptions">RangeOptions</a> : <code>object</code></dt>
<dd><p>min, max, sparsity, and range must match the values set in the encryptedFields of the destination collection.
For double and decimal128, min/max/precision must all be set, or all be unset.</p>
</dd>
<dt><a href="#EncryptOptions">EncryptOptions</a> : <code>object</code></dt>
<dd><p>Options to provide when encrypting data.</p>
</dd>
</dl>

<a name="AutoEncrypter"></a>

## AutoEncrypter
An internal class to be used by the driver for auto encryption
**NOTE**: Not meant to be instantiated directly, this is for internal use only.


* [AutoEncrypter](#AutoEncrypter)

    * [new AutoEncrypter(client, [options])](#new_AutoEncrypter_new)

    * _instance_
        * [.cryptSharedLibVersionInfo](#AutoEncrypter+cryptSharedLibVersionInfo)

        * [.askForKMSCredentials()](#AutoEncrypter+askForKMSCredentials)

    * _inner_
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
Schemas supplied in the schemaMap only apply to configuring automatic encryption for Client-Side Field Level Encryption.
Other validation rules in the JSON schema will not be enforced by the driver and will result in an error.

**Example** *(Create an AutoEncrypter that makes use of mongocryptd)*  
```js
// Enabling autoEncryption via a MongoClient using mongocryptd
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
**Example** *(Create an AutoEncrypter that makes use of libmongocrypt&#x27;s CSFLE shared library)*  
```js
// Enabling autoEncryption via a MongoClient using CSFLE shared library
const { MongoClient } = require('mongodb');
const client = new MongoClient(URL, {
  autoEncryption: {
    kmsProviders: {
      aws: {}
    },
    extraOptions: {
      cryptSharedLibPath: '/path/to/local/crypt/shared/lib',
      cryptSharedLibRequired: true
    }
  }
});

await client.connect();
// From here on, the client will be encrypting / decrypting automatically
```
<a name="AutoEncrypter+cryptSharedLibVersionInfo"></a>

### *autoEncrypter*.cryptSharedLibVersionInfo
Return the current libmongocrypt's CSFLE shared library version
as `{ version: bigint, versionStr: string }`, or `null` if no CSFLE
shared library was loaded.

<a name="AutoEncrypter+askForKMSCredentials"></a>

### *autoEncrypter*.askForKMSCredentials()
Ask the user for KMS credentials.

This returns anything that looks like the kmsProviders original input
option. It can be empty, and any provider specified here will override
the original ones.

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
| [cryptSharedLibPath] | <code>string</code> |  | Full path to a MongoDB Crypt shared library on the system. If specified, autoEncryption will not attempt to spawn a mongocryptd, but makes use of the shared library file specified. Note that the path must point to the shared libary file itself, not the folder which contains it \* |
| [cryptSharedLibRequired] | <code>boolean</code> |  | If true, never use mongocryptd and fail when the MongoDB Crypt shared libary cannot be loaded. Defaults to true if [cryptSharedLibPath] is specified and false otherwise \* |

Extra options related to the mongocryptd process
\* _Available in MongoDB 6.0 or higher._

<a name="AutoEncrypter..logger"></a>

### *AutoEncrypter*~logger

| Param | Type | Description |
| --- | --- | --- |
| level | [<code>logLevel</code>](#AutoEncrypter..logLevel) | The level of logging. |
| message | <code>string</code> | The message to log |

A callback that is invoked with logging information from
the underlying C++ Bindings.

<a name="ClientEncryption"></a>

## ~~ClientEncryption~~
***Deprecated***


* ~~[ClientEncryption](#ClientEncryption)
~~
    * [new ClientEncryption(client, options)](#new_ClientEncryption_new)

    * _instance_
        * [.createDataKey(provider, [options], [callback])](#ClientEncryption+createDataKey)

        * [.rewrapManyDataKey(filter, [options])](#ClientEncryption+rewrapManyDataKey)

        * [.deleteKey(_id)](#ClientEncryption+deleteKey)

        * [.getKeys()](#ClientEncryption+getKeys)

        * [.getKey(_id)](#ClientEncryption+getKey)

        * [.getKeyByAltName(keyAltName)](#ClientEncryption+getKeyByAltName)

        * [.addKeyAltName(_id, keyAltName)](#ClientEncryption+addKeyAltName)

        * [.removeKeyAltName(_id, keyAltName)](#ClientEncryption+removeKeyAltName)

        * [.createEncryptedCollection(db, name, options)](#ClientEncryption+createEncryptedCollection)

        * [.encrypt(value, options, [callback])](#ClientEncryption+encrypt)

        * [.encryptExpression(expression, options)](#ClientEncryption+encryptExpression)

        * [.decrypt(value, callback)](#ClientEncryption+decrypt)

        * [.askForKMSCredentials()](#ClientEncryption+askForKMSCredentials)

    * _inner_
        * ~~[~decryptCallback](#ClientEncryption..decryptCallback)
~~

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
| [callback] | [<code>ClientEncryptionCreateDataKeyCallback</code>](#ClientEncryptionCreateDataKeyCallback) | DEPRECATED - Callbacks will be removed in the next major version.  Optional callback to invoke when key is created |

Creates a data key used for explicit encryption and inserts it into the key vault namespace

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with [the id of the created data key](ClientEncryption~dataKeyId), or rejects with an error. If a callback is provided, returns nothing.  
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
<a name="ClientEncryption+rewrapManyDataKey"></a>

### *clientEncryption*.rewrapManyDataKey(filter, [options])

| Param | Type | Description |
| --- | --- | --- |
| filter | <code>object</code> | A valid MongoDB filter. Any documents matching this filter will be re-wrapped. |
| [options] | <code>object</code> |  |
| options.provider | [<code>KmsProvider</code>](#KmsProvider) | The KMS provider to use when re-wrapping the data keys. |
| [options.masterKey] | [<code>AWSEncryptionKeyOptions</code>](#AWSEncryptionKeyOptions) \| [<code>AzureEncryptionKeyOptions</code>](#AzureEncryptionKeyOptions) \| [<code>GCPEncryptionKeyOptions</code>](#GCPEncryptionKeyOptions) |  |

Searches the keyvault for any data keys matching the provided filter.  If there are matches, rewrapManyDataKey then attempts to re-wrap the data keys using the provided options.

If no matches are found, then no bulk write is performed.

**Example**  
```js
// rewrapping all data data keys (using a filter that matches all documents)
const filter = {};

const result = await clientEncryption.rewrapManyDataKey(filter);
if (result.bulkWriteResult != null) {
 // keys were re-wrapped, results will be available in the bulkWrite object.
}
```
**Example**  
```js
// attempting to rewrap all data keys with no matches
const filter = { _id: new Binary() } // assume _id matches no documents in the database
const result = await clientEncryption.rewrapManyDataKey(filter);

if (result.bulkWriteResult == null) {
 // no keys matched, `bulkWriteResult` does not exist on the result object
}
```
<a name="ClientEncryption+deleteKey"></a>

### *clientEncryption*.deleteKey(_id)

| Param | Type | Description |
| --- | --- | --- |
| _id | [<code>ClientEncryptionDataKeyId</code>](#ClientEncryptionDataKeyId) | the id of the document to delete. |

Deletes the key with the provided id from the keyvault, if it exists.

**Returns**: [<code>Promise.&lt;DeleteResult&gt;</code>](#DeleteResult) - Returns a promise that either resolves to a [DeleteResult](#DeleteResult) or rejects with an error.  
**Example**  
```js
// delete a key by _id
const id = new Binary(); // id is a bson binary subtype 4 object
const { deletedCount } = await clientEncryption.deleteKey(id);

if (deletedCount != null && deletedCount > 0) {
  // successful deletion
}
```
<a name="ClientEncryption+getKeys"></a>

### *clientEncryption*.getKeys()
Finds all the keys currently stored in the keyvault.

This method will not throw.

**Returns**: [<code>FindCursor</code>](#FindCursor) - a FindCursor over all keys in the keyvault.  
**Example**  
```js
// fetching all keys
const keys = await clientEncryption.getKeys().toArray();
```
<a name="ClientEncryption+getKey"></a>

### *clientEncryption*.getKey(_id)

| Param | Type | Description |
| --- | --- | --- |
| _id | [<code>ClientEncryptionDataKeyId</code>](#ClientEncryptionDataKeyId) | the id of the document to delete. |

Finds a key in the keyvault with the specified _id.

**Returns**: [<code>Promise.&lt;DataKey&gt;</code>](#DataKey) - Returns a promise that either resolves to a [DataKey](#DataKey) if a document matches the key or null if no documents
match the id.  The promise rejects with an error if an error is thrown.  
**Example**  
```js
// getting a key by id
const id = new Binary(); // id is a bson binary subtype 4 object
const key = await clientEncryption.getKey(id);
if (!key) {
 // key is null if there was no matching key
}
```
<a name="ClientEncryption+getKeyByAltName"></a>

### *clientEncryption*.getKeyByAltName(keyAltName)

| Param | Type | Description |
| --- | --- | --- |
| keyAltName | <code>string</code> | a keyAltName to search for a key |

Finds a key in the keyvault which has the specified keyAltName.

**Returns**: <code>Promise.&lt;(DataKey\|null)&gt;</code> - Returns a promise that either resolves to a [DataKey](#DataKey) if a document matches the key or null if no documents
match the keyAltName.  The promise rejects with an error if an error is thrown.  
**Example**  
```js
// get a key by alt name
const keyAltName = 'keyAltName';
const key = await clientEncryption.getKeyByAltName(keyAltName);
if (!key) {
 // key is null if there is no matching key
}
```
<a name="ClientEncryption+addKeyAltName"></a>

### *clientEncryption*.addKeyAltName(_id, keyAltName)

| Param | Type | Description |
| --- | --- | --- |
| _id | [<code>ClientEncryptionDataKeyId</code>](#ClientEncryptionDataKeyId) | The id of the document to update. |
| keyAltName | <code>string</code> | a keyAltName to search for a key |

Adds a keyAltName to a key identified by the provided _id.

This method resolves to/returns the *old* key value (prior to adding the new altKeyName).

**Returns**: [<code>Promise.&lt;DataKey&gt;</code>](#DataKey) - Returns a promise that either resolves to a [DataKey](#DataKey) if a document matches the key or null if no documents
match the id.  The promise rejects with an error if an error is thrown.  
**Example**  
```js
// adding an keyAltName to a data key
const id = new Binary();  // id is a bson binary subtype 4 object
const keyAltName = 'keyAltName';
const oldKey = await clientEncryption.addKeyAltName(id, keyAltName);
if (!oldKey) {
 // null is returned if there is no matching document with an id matching the supplied id
}
```
<a name="ClientEncryption+removeKeyAltName"></a>

### *clientEncryption*.removeKeyAltName(_id, keyAltName)

| Param | Type | Description |
| --- | --- | --- |
| _id | [<code>ClientEncryptionDataKeyId</code>](#ClientEncryptionDataKeyId) | The id of the document to update. |
| keyAltName | <code>string</code> | a keyAltName to search for a key |

Adds a keyAltName to a key identified by the provided _id.

This method resolves to/returns the *old* key value (prior to removing the new altKeyName).

If the removed keyAltName is the last keyAltName for that key, the `altKeyNames` property is unset from the document.

**Returns**: <code>Promise.&lt;(DataKey\|null)&gt;</code> - Returns a promise that either resolves to a [DataKey](#DataKey) if a document matches the key or null if no documents
match the id.  The promise rejects with an error if an error is thrown.  
**Example**  
```js
// removing a key alt name from a data key
const id = new Binary();  // id is a bson binary subtype 4 object
const keyAltName = 'keyAltName';
const oldKey = await clientEncryption.removeKeyAltName(id, keyAltName);

if (!oldKey) {
 // null is returned if there is no matching document with an id matching the supplied id
}
```
<a name="ClientEncryption+createEncryptedCollection"></a>

### *clientEncryption*.createEncryptedCollection(db, name, options)
**Throws**:

- [<code>MongoCryptCreateDataKeyError</code>](#MongoCryptCreateDataKeyError) - If part way through the process a createDataKey invocation fails, an error will be rejected that has the partial `encryptedFields` that were created.
- [<code>MongoCryptCreateEncryptedCollectionError</code>](#MongoCryptCreateEncryptedCollectionError) - If creating the collection fails, an error will be rejected that has the entire `encryptedFields` that were created.


| Param | Type | Description |
| --- | --- | --- |
| db | <code>Db</code> | A Node.js driver Db object with which to create the collection |
| name | <code>string</code> | The name of the collection to be created |
| options | <code>object</code> | Options for createDataKey and for createCollection |
| options.provider | <code>string</code> | KMS provider name |
| [options.masterKey] | [<code>AWSEncryptionKeyOptions</code>](#AWSEncryptionKeyOptions) \| [<code>AzureEncryptionKeyOptions</code>](#AzureEncryptionKeyOptions) \| [<code>GCPEncryptionKeyOptions</code>](#GCPEncryptionKeyOptions) | masterKey to pass to createDataKey |
| options.createCollectionOptions | <code>CreateCollectionOptions</code> | options to pass to createCollection, must include `encryptedFields` |

A convenience method for creating an encrypted collection.
This method will create data keys for any encryptedFields that do not have a `keyId` defined
and then create a new collection with the full set of encryptedFields.

**Returns**: <code>Promise.&lt;{collection: Collection.&lt;TSchema&gt;, encryptedFields: Document}&gt;</code> - - created collection and generated encryptedFields  
<a name="ClientEncryption+encrypt"></a>

### *clientEncryption*.encrypt(value, options, [callback])

| Param | Type | Description |
| --- | --- | --- |
| value | <code>\*</code> | The value that you wish to serialize. Must be of a type that can be serialized into BSON |
| options | [<code>EncryptOptions</code>](#EncryptOptions) |  |
| [callback] | [<code>ClientEncryptionEncryptCallback</code>](#ClientEncryptionEncryptCallback) | DEPRECATED: Callbacks will be removed in the next major version.  Optional callback to invoke when value is encrypted |

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
<a name="ClientEncryption+encryptExpression"></a>

### *clientEncryption*.encryptExpression(expression, options)
**Experimental**: The Range algorithm is experimental only. It is not intended for production use. It is subject to breaking changes.  

| Param | Type | Description |
| --- | --- | --- |
| expression | <code>object</code> | a BSON document of one of the following forms:  1. A Match Expression of this form:      `{$and: [{<field>: {$gt: <value1>}}, {<field>: {$lt: <value2> }}]}`  2. An Aggregate Expression of this form:      `{$and: [{$gt: [<fieldpath>, <value1>]}, {$lt: [<fieldpath>, <value2>]}]}`    `$gt` may also be `$gte`. `$lt` may also be `$lte`. |
| options | [<code>EncryptOptions</code>](#EncryptOptions) |  |

Encrypts a Match Expression or Aggregate Expression to query a range index.

Only supported when queryType is "rangePreview" and algorithm is "RangePreview".

**Returns**: <code>Promise.&lt;object&gt;</code> - Returns a Promise that either resolves with the encrypted value or rejects with an error.  
<a name="ClientEncryption+decrypt"></a>

### *clientEncryption*.decrypt(value, callback)

| Param | Type | Description |
| --- | --- | --- |
| value | <code>Buffer</code> \| <code>Binary</code> | An encrypted value |
| callback | [<code>decryptCallback</code>](#ClientEncryption..decryptCallback) | DEPRECATED - Callbacks will be removed in the next major version.  Optional callback to invoke when value is decrypted |

Explicitly decrypt a provided encrypted value

**Returns**: <code>Promise</code> \| <code>void</code> - If no callback is provided, returns a Promise that either resolves with the decrypted value, or rejects with an error. If a callback is provided, returns nothing.  
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
<a name="ClientEncryption+askForKMSCredentials"></a>

### *clientEncryption*.askForKMSCredentials()
Ask the user for KMS credentials.

This returns anything that looks like the kmsProviders original input
option. It can be empty, and any provider specified here will override
the original ones.

<a name="ClientEncryption..decryptCallback"></a>

### ~~*ClientEncryption*~decryptCallback~~
***Deprecated***


| Param | Type | Description |
| --- | --- | --- |
| [err] | <code>Error</code> | If present, indicates an error that occurred in the process of decryption |
| [result] | <code>object</code> | If present, is the decrypted result |

<a name="MongoCryptError"></a>

## ~~MongoCryptError~~
***Deprecated***

An error indicating that something went wrong specifically with MongoDB Client Encryption

<a name="MongoCryptCreateDataKeyError"></a>

## ~~MongoCryptCreateDataKeyError~~
***Deprecated***

An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create data keys

<a name="MongoCryptCreateEncryptedCollectionError"></a>

## ~~MongoCryptCreateEncryptedCollectionError~~
***Deprecated***

An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create a collection

<a name="MongoCryptAzureKMSRequestError"></a>

## ~~MongoCryptAzureKMSRequestError~~
***Deprecated***

An error indicating that mongodb-client-encryption failed to auto-refresh Azure KMS credentials.

<a name="new_MongoCryptAzureKMSRequestError_new"></a>

### new MongoCryptAzureKMSRequestError(message, body)

| Param | Type |
| --- | --- |
| message | <code>string</code> | 
| body | <code>object</code> \| <code>undefined</code> | 

<a name="MongoCryptKMSRequestNetworkTimeoutError"></a>

## ~~MongoCryptKMSRequestNetworkTimeoutError~~
***Deprecated***

<a name="BSONValue"></a>

## BSONValue
any serializable BSON value

<a name="Long"></a>

## Long
A 64 bit integer, represented by the js-bson Long type.

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

<a name="DataKey"></a>

## DataKey
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| _id | <code>UUID</code> | A unique identifier for the key. |
| version | <code>number</code> | A numeric identifier for the schema version of this document. Implicitly 0 if unset. |
| [keyAltNames] | <code>Array.&lt;string&gt;</code> | Alternate names to search for keys by. Used for a per-document key scenario in support of GDPR scenarios. |
| keyMaterial | <code>Binary</code> | Encrypted data key material, BinData type General. |
| creationDate | <code>Date</code> | The datetime the wrapped data key material was imported into the Key Database. |
| updateDate | <code>Date</code> | The datetime the wrapped data key material was last modified. On initial import, this value will be set to creationDate. |
| status | <code>number</code> | 0 = enabled, 1 = disabled |
| masterKey | <code>object</code> | the encrypted master key |

A data key as stored in the database.

<a name="KmsProvider"></a>

## KmsProvider
A string containing the name of a kms provider.  Valid options are 'aws', 'azure', 'gcp', 'kmip', or 'local'

<a name="ClientSession"></a>

## ClientSession
The ClientSession class from the MongoDB Node driver (see https://mongodb.github.io/node-mongodb-native/4.8/classes/ClientSession.html)

<a name="DeleteResult"></a>

## DeleteResult
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| acknowledged | <code>boolean</code> | Indicates whether this write result was acknowledged. If not, then all other members of this result will be undefined. |
| deletedCount | <code>number</code> | The number of documents that were deleted |

The result of a delete operation from the MongoDB Node driver (see https://mongodb.github.io/node-mongodb-native/4.8/interfaces/DeleteResult.html)

<a name="BulkWriteResult"></a>

## BulkWriteResult
The BulkWriteResult class from the MongoDB Node driver (https://mongodb.github.io/node-mongodb-native/4.8/classes/BulkWriteResult.html)

<a name="FindCursor"></a>

## FindCursor
The FindCursor class from the MongoDB Node driver (see https://mongodb.github.io/node-mongodb-native/4.8/classes/FindCursor.html)

<a name="ClientEncryptionDataKeyId"></a>

## ClientEncryptionDataKeyId
The id of an existing dataKey. Is a bson Binary value.
Can be used for [ClientEncryption.encrypt](ClientEncryption.encrypt), and can be used to directly
query for the data key itself against the key vault namespace.

<a name="ClientEncryptionCreateDataKeyCallback"></a>

## ~~ClientEncryptionCreateDataKeyCallback~~
***Deprecated***


| Param | Type | Description |
| --- | --- | --- |
| [error] | <code>Error</code> | If present, indicates an error that occurred in the creation of the data key |
| [dataKeyId] | <code>ClientEncryption~dataKeyId</code> | If present, returns the id of the created data key |

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

<a name="RewrapManyDataKeyResult"></a>

## RewrapManyDataKeyResult
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [bulkWriteResult] | [<code>BulkWriteResult</code>](#BulkWriteResult) | An optional BulkWriteResult, if any keys were matched and attempted to be re-wrapped. |

<a name="ClientEncryptionEncryptCallback"></a>

## ~~ClientEncryptionEncryptCallback~~
***Deprecated***


| Param | Type | Description |
| --- | --- | --- |
| [err] | <code>Error</code> | If present, indicates an error that occurred in the process of encryption |
| [result] | <code>Buffer</code> | If present, is the encrypted result |

<a name="RangeOptions"></a>

## RangeOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| min | [<code>BSONValue</code>](#BSONValue) | is required if precision is set. |
| max | [<code>BSONValue</code>](#BSONValue) | is required if precision is set. |
| sparsity | <code>BSON.Long</code> |  |
| precision | <code>number</code> \| <code>undefined</code> | (may only be set for double or decimal128). |

min, max, sparsity, and range must match the values set in the encryptedFields of the destination collection.
For double and decimal128, min/max/precision must all be set, or all be unset.

<a name="EncryptOptions"></a>

## EncryptOptions
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [keyId] | [<code>ClientEncryptionDataKeyId</code>](#ClientEncryptionDataKeyId) | The id of the Binary dataKey to use for encryption. |
| [keyAltName] | <code>string</code> | A unique string name corresponding to an already existing dataKey. |
| [algorithm] | <code>string</code> | The algorithm to use for encryption. Must be either `'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'`, `'AEAD_AES_256_CBC_HMAC_SHA_512-Random'`, `'Indexed'` or `'Unindexed'` |
| [contentionFactor] | <code>bigint</code> \| <code>number</code> | the contention factor. |
| queryType | <code>&#x27;equality&#x27;</code> \| <code>&#x27;rangePreview&#x27;</code> | the query type supported.  only the query type `equality` is stable at this time.  queryType `rangePreview` is experimental. |
| [rangeOptions] | [<code>RangeOptions</code>](#RangeOptions) | (experimental) The index options for a Queryable Encryption field supporting "rangePreview" queries. |

Options to provide when encrypting data.

