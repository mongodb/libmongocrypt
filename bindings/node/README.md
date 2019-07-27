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
</dl>

## Typedefs

<dl>
<dt><a href="#AutoEncryptionExtraOptions">AutoEncryptionExtraOptions</a></dt>
<dd></dd>
</dl>

<a name="AutoEncrypter"></a>

## AutoEncrypter
An internal class to be used by the driver for auto encryption
**NOTE**: Not meant to be instantiated directly, this is for internal use only.


* [AutoEncrypter](#AutoEncrypter)

    * [new AutoEncrypter(options)](#new_AutoEncrypter_new)

    * [.encrypt(ns, cmd, callback)](#AutoEncrypter+encrypt)

    * [.decrypt(buffer, callback)](#AutoEncrypter+decrypt)


<a name="new_AutoEncrypter_new"></a>

### new AutoEncrypter(options)

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | Optional settings |
| options.client | <code>MongoClient</code> | The parent client auto encryption is enabled on |
| options.keyVaultNamespace | <code>string</code> | The namespace of the key vault, used to store encryption keys |
| options.schemaMap | <code>object</code> |  |
| options.kmsProviders | <code>object</code> |  |
| options.logger | <code>function</code> |  |
| [options.extraOptions] | [<code>AutoEncryptionExtraOptions</code>](#AutoEncryptionExtraOptions) | Extra options related to mongocryptd |

Create an AutoEncrypter

<a name="AutoEncrypter+encrypt"></a>

### *autoEncrypter*.encrypt(ns, cmd, callback)

| Param | Type | Description |
| --- | --- | --- |
| ns | <code>string</code> | The namespace for this encryption context |
| cmd | <code>object</code> | The command to encrypt |
| callback | <code>function</code> |  |

Encrypt a command for a given namespace

<a name="AutoEncrypter+decrypt"></a>

### *autoEncrypter*.decrypt(buffer, callback)

| Param | Type |
| --- | --- |
| buffer | <code>\*</code> | 
| callback | <code>\*</code> | 

Decrypt a command response

<a name="ClientEncryption"></a>

## ClientEncryption
The public interface for explicit client side encryption


* [ClientEncryption](#ClientEncryption)

    * [new ClientEncryption(client, options)](#new_ClientEncryption_new)

    * [.createDataKey(provider, options, callback)](#ClientEncryption+createDataKey)

    * [.encrypt(value, options, callback)](#ClientEncryption+encrypt)

    * [.decrypt(value, callback)](#ClientEncryption+decrypt)


<a name="new_ClientEncryption_new"></a>

### new ClientEncryption(client, options)

| Param | Type | Description |
| --- | --- | --- |
| client | <code>MongoClient</code> | The client used for encryption |
| options | <code>object</code> | Optional settings |
| options.keyVaultNamespace | <code>string</code> | The namespace of the key vault, used to store encryption keys |

Create a new encryption instance

<a name="ClientEncryption+createDataKey"></a>

### *clientEncryption*.createDataKey(provider, options, callback)

| Param | Type | Description |
| --- | --- | --- |
| provider | <code>string</code> | The KMS provider used for this data key |
| options | <code>\*</code> |  |
| callback | <code>function</code> |  |

Creates a data key used for explicit encryption

<a name="ClientEncryption+encrypt"></a>

### *clientEncryption*.encrypt(value, options, callback)

| Param | Type |
| --- | --- |
| value | <code>\*</code> | 
| options | <code>\*</code> | 
| callback | <code>\*</code> | 

Explicitly encrypt a provided value

<a name="ClientEncryption+decrypt"></a>

### *clientEncryption*.decrypt(value, callback)

| Param | Type |
| --- | --- |
| value | <code>\*</code> | 
| callback | <code>\*</code> | 

Explicitly decrypt a provided encrypted value

<a name="AutoEncryptionExtraOptions"></a>

## AutoEncryptionExtraOptions
**Properties**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| [mongocryptdURI] | <code>string</code> |  | overrides the uri used to connect to mongocryptd |
| [mongocryptdBypassSpawn] | <code>boolean</code> | <code>false</code> | if true, autoEncryption will not spawn a mongocryptd |
| [mongocryptdSpawnPath] | <code>string</code> |  | the path to the mongocryptd executable |
| [mongocryptdSpawnArgs] | <code>Array.&lt;string&gt;</code> |  | command line arguments to pass to the mongocryptd executable |

