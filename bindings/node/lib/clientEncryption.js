'use strict';

module.exports = function (modules) {
  const mc = require('bindings')('mongocrypt');
  const common = require('./common');
  const databaseNamespace = common.databaseNamespace;
  const collectionNamespace = common.collectionNamespace;
  const promiseOrCallback = common.promiseOrCallback;
  const StateMachine = modules.stateMachine.StateMachine;
  const cryptoCallbacks = require('./cryptoCallbacks');

  /**
   * @typedef {object} KMSProviders
   * @description Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.
   * @property {object} [aws] Configuration options for using 'aws' as your KMS provider
   * @property {string} [aws.accessKeyId] The access key used for the AWS KMS provider
   * @property {string} [aws.secretAccessKey] The secret access key used for the AWS KMS provider
   * @property {object} [local] Configuration options for using 'local' as your KMS provider
   * @property {Buffer} [local.key] The master key used to encrypt/decrypt data keys. A 96-byte long Buffer.
   * @property {object} [azure] Configuration options for using 'azure' as your KMS provider
   * @property {string} [azure.tenantId] The tenant ID identifies the organization for the account
   * @property {string} [azure.clientId] The client ID to authenticate a registered application
   * @property {string} [azure.clientSecret] The client secret to authenticate a registered application
   * @property {string} [azure.identityPlatformEndpoint] If present, a host with optional port. E.g. "example.com" or "example.com:443". This is optional, and only needed if customer is using a non-commercial Azure instance (e.g. a government or China account, which use different URLs). Defaults to  "login.microsoftonline.com"
   * @property {object} [gcp] Configuration options for using 'gcp' as your KMS provider
   * @property {string} [gcp.email] The service account email to authenticate
   * @property {string|Binary} [gcp.privateKey] A PKCS#8 encrypted key. This can either be a base64 string or a binary representation
   * @property {string} [gcp.endpoint] If present, a host with optional port. E.g. "example.com" or "example.com:443". Defaults to "oauth2.googleapis.com"
   */

  /**
   * The public interface for explicit client side encryption
   */
  class ClientEncryption {
    /**
     * Create a new encryption instance
     *
     * @param {MongoClient} client The client used for encryption
     * @param {object} options Additional settings
     * @param {string} options.keyVaultNamespace The namespace of the key vault, used to store encryption keys
     * @param {object} options.tlsOptions An object that maps KMS provider names to TLS options.
     * @param {MongoClient} [options.keyVaultClient] A `MongoClient` used to fetch keys from a key vault. Defaults to `client`
     * @param {KMSProviders} [options.kmsProviders] options for specific KMS providers to use
     *
     * @example
     * new ClientEncryption(mongoClient, {
     *   keyVaultNamespace: 'client.encryption',
     *   kmsProviders: {
     *     local: {
     *       key: masterKey // The master key used for encryption/decryption. A 96-byte long Buffer
     *     }
     *   }
     * });
     *
     * @example
     * new ClientEncryption(mongoClient, {
     *   keyVaultNamespace: 'client.encryption',
     *   kmsProviders: {
     *     aws: {
     *       accessKeyId: AWS_ACCESS_KEY,
     *       secretAccessKey: AWS_SECRET_KEY
     *     }
     *   }
     * });
     */
    constructor(client, options) {
      this._client = client;
      this._bson = options.bson || client.topology.bson;
      this._proxyOptions = options.proxyOptions;
      this._tlsOptions = options.tlsOptions;

      if (options.keyVaultNamespace == null) {
        throw new TypeError('Missing required option `keyVaultNamespace`');
      }

      Object.assign(options, { cryptoCallbacks });

      // kmsProviders will be parsed by libmongocrypt, must be provided as BSON binary data
      if (options.kmsProviders && !Buffer.isBuffer(options.kmsProviders)) {
        options.kmsProviders = this._bson.serialize(options.kmsProviders);
      } else if (!options.onKmsProviderRefresh) {
        throw new TypeError('Need to specify either kmsProviders ahead of time or when requested');
      }

      this._onKmsProviderRefresh = options.onKmsProviderRefresh;
      this._keyVaultNamespace = options.keyVaultNamespace;
      this._keyVaultClient = options.keyVaultClient || client;
      this._mongoCrypt = new mc.MongoCrypt(options);
    }

    /**
     * @typedef {Binary} ClientEncryption~dataKeyId
     * @description The id of an existing dataKey. Is a bson Binary value.
     * Can be used for {@link ClientEncryption.encrypt}, and can be used to directly
     * query for the data key itself against the key vault namespace.
     */

    /**
     * @callback ClientEncryption~createDataKeyCallback
     * @param {Error} [error] If present, indicates an error that occurred in the creation of the data key
     * @param {ClientEncryption~dataKeyId} [dataKeyId] If present, returns the id of the created data key
     */

    /**
     * @typedef {object} AWSEncryptionKeyOptions
     * @description Configuration options for making an AWS encryption key
     * @property {string} region The AWS region of the KMS
     * @property {string} key The Amazon Resource Name (ARN) to the AWS customer master key (CMK)
     * @property {string} [endpoint] An alternate host to send KMS requests to. May include port number
     */

    /**
     * @typedef {object} GCPEncryptionKeyOptions
     * @description Configuration options for making a GCP encryption key
     * @property {string} projectId GCP project id
     * @property {string} location Location name (e.g. "global")
     * @property {string} keyRing Key ring name
     * @property {string} keyName Key name
     * @property {string} [keyVersion] Key version
     * @property {string} [endpoint] KMS URL, defaults to `https://www.googleapis.com/auth/cloudkms`
     */

    /**
     * @typedef {object} AzureEncryptionKeyOptions
     * @description Configuration options for making an Azure encryption key
     * @property {string} keyName Key name
     * @property {string} keyVaultEndpoint Key vault URL, typically `<name>.vault.azure.net`
     * @property {string} [keyVersion] Key version
     */

    /**
     * Creates a data key used for explicit encryption and inserts it into the key vault namespace
     *
     * @param {string} provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
     * @param {object} [options] Options for creating the data key
     * @param {AWSEncryptionKeyOptions|AzureEncryptionKeyOptions|GCPEncryptionKeyOptions} [options.masterKey] Idenfities a new KMS-specific key used to encrypt the new data key
     * @param {string[]} [options.keyAltNames] An optional list of string alternate names used to reference a key. If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id.
     * @param {ClientEncryption~createDataKeyCallback} [callback] Optional callback to invoke when key is created
     * @returns {Promise|void} If no callback is provided, returns a Promise that either resolves with {@link ClientEncryption~dataKeyId the id of the created data key}, or rejects with an error. If a callback is provided, returns nothing.
     * @example
     * // Using callbacks to create a local key
     * clientEncryption.createDataKey('local', (err, dataKey) => {
     *   if (err) {
     *     // This means creating the key failed.
     *   } else {
     *     // key creation succeeded
     *   }
     * });
     *
     * @example
     * // Using async/await to create a local key
     * const dataKeyId = await clientEncryption.createDataKey('local');
     *
     * @example
     * // Using async/await to create an aws key
     * const dataKeyId = await clientEncryption.createDataKey('aws', {
     *   masterKey: {
     *     region: 'us-east-1',
     *     key: 'xxxxxxxxxxxxxx' // CMK ARN here
     *   }
     * });
     *
     * @example
     * // Using async/await to create an aws key with a keyAltName
     * const dataKeyId = await clientEncryption.createDataKey('aws', {
     *   masterKey: {
     *     region: 'us-east-1',
     *     key: 'xxxxxxxxxxxxxx' // CMK ARN here
     *   },
     *   keyAltNames: [ 'mySpecialKey' ]
     * });
     */
    createDataKey(provider, options, callback) {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      if (options == null) {
        options = {};
      }

      const bson = this._bson;

      const dataKey = Object.assign({ provider }, options.masterKey);

      if (options.keyAltNames && !Array.isArray(options.keyAltNames)) {
        throw new TypeError(
          `Option "keyAltNames" must be an array of strings, but was of type ${typeof options.keyAltNames}.`
        );
      }

      let keyAltNames = undefined;
      if (options.keyAltNames && options.keyAltNames.length > 0) {
        keyAltNames = options.keyAltNames.map((keyAltName, i) => {
          if (typeof keyAltName !== 'string') {
            throw new TypeError(
              `Option "keyAltNames" must be an array of strings, but item at index ${i} was of type ${typeof keyAltName}`
            );
          }

          return bson.serialize({ keyAltName });
        });
      }

      let keyMaterial = undefined;
      if (options.keyMaterial) {
        keyMaterial = bson.serialize({ keyMaterial: options.keyMaterial });
      }

      const dataKeyBson = bson.serialize(dataKey);
      const context = this._mongoCrypt.makeDataKeyContext(dataKeyBson, {
        keyAltNames,
        keyMaterial
      });
      const stateMachine = new StateMachine({
        bson,
        proxyOptions: this._proxyOptions,
        tlsOptions: this._tlsOptions
      });

      return promiseOrCallback(callback, cb => {
        stateMachine.execute(this, context, (err, dataKey) => {
          if (err) {
            cb(err, null);
            return;
          }

          const dbName = databaseNamespace(this._keyVaultNamespace);
          const collectionName = collectionNamespace(this._keyVaultNamespace);

          this._keyVaultClient
            .db(dbName)
            .collection(collectionName)
            .insertOne(dataKey, { writeConcern: { w: 'majority' } }, (err, result) => {
              if (err) {
                cb(err, null);
                return;
              }

              cb(null, result.insertedId);
            });
        });
      });
    }

    rewrapManyDataKey(filter, options, callback) {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }

      const bson = this._bson;

      let keyEncryptionKeyBson = undefined;
      if (options) {
        const keyEncryptionKey = Object.assign({ provider: options.provider }, options.masterKey);
        keyEncryptionKeyBson = bson.serialize(keyEncryptionKey);
      } else {
        // Always make sure `options` is an object below.
        options = {};
      }
      const filterBson = bson.serialize(filter);
      const context = this._mongoCrypt.makeRewrapManyDataKeyContext(
        filterBson,
        keyEncryptionKeyBson
      );
      const stateMachine = new StateMachine({
        bson,
        proxyOptions: this._proxyOptions,
        tlsOptions: this._tlsOptions,
        session: options.session
      });

      return promiseOrCallback(callback, cb => {
        stateMachine.execute(this, context, (err, dataKey) => {
          if (err) {
            cb(err, null);
            return;
          }

          if (dataKey.v.length === 0) {
            cb(null, {});
            return;
          }

          const dbName = databaseNamespace(this._keyVaultNamespace);
          const collectionName = collectionNamespace(this._keyVaultNamespace);
          const replacements = dataKey.v.map(key => ({
            updateOne: {
              filter: { _id: key._id },
              update: {
                $set: {
                  masterKey: key.masterKey,
                  keyMaterial: key.keyMaterial
                },
                $currentDate: {
                  updateDate: true
                }
              }
            }
          }));

          this._keyVaultClient
            .db(dbName)
            .collection(collectionName)
            .bulkWrite(
              replacements,
              {
                writeConcern: { w: 'majority' },
                session: options.session
              },
              (err, result) => {
                if (err) {
                  cb(err, null);
                  return;
                }

                cb(null, {
                  bulkWriteResult: result
                });
              }
            );
        });
      });
    }

    /**
     * @callback ClientEncryption~encryptCallback
     * @param {Error} [err] If present, indicates an error that occurred in the process of encryption
     * @param {Buffer} [result] If present, is the encrypted result
     */

    /**
     * Explicitly encrypt a provided value. Note that either `options.keyId` or `options.keyAltName` must
     * be specified. Specifying both `options.keyId` and `options.keyAltName` is considered an error.
     *
     * @param {*} value The value that you wish to serialize. Must be of a type that can be serialized into BSON
     * @param {object} options
     * @param {ClientEncryption~dataKeyId} [options.keyId] The id of the Binary dataKey to use for encryption
     * @param {string} [options.keyAltName] A unique string name corresponding to an already existing dataKey.
     * @param {} [options.algorithm] The algorithm to use for encryption. Must be either `'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'`, `'AEAD_AES_256_CBC_HMAC_SHA_512-Random'`, `'Indexed'` or `'Unindexed'`
     * @param {ClientEncryption~encryptCallback} [callback] Optional callback to invoke when value is encrypted
     * @returns {Promise|void} If no callback is provided, returns a Promise that either resolves with the encrypted value, or rejects with an error. If a callback is provided, returns nothing.
     *
     * @example
     * // Encryption with callback API
     * function encryptMyData(value, callback) {
     *   clientEncryption.createDataKey('local', (err, keyId) => {
     *     if (err) {
     *       return callback(err);
     *     }
     *     clientEncryption.encrypt(value, { keyId, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' }, callback);
     *   });
     * }
     *
     * @example
     * // Encryption with async/await api
     * async function encryptMyData(value) {
     *   const keyId = await clientEncryption.createDataKey('local');
     *   return clientEncryption.encrypt(value, { keyId, algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' });
     * }
     *
     * @example
     * // Encryption using a keyAltName
     * async function encryptMyData(value) {
     *   await clientEncryption.createDataKey('local', { keyAltNames: 'mySpecialKey' });
     *   return clientEncryption.encrypt(value, { keyAltName: 'mySpecialKey', algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' });
     * }
     */
    encrypt(value, options, callback) {
      const bson = this._bson;
      const valueBuffer = bson.serialize({ v: value });
      const contextOptions = Object.assign({}, options);
      if (options.keyId) {
        contextOptions.keyId = options.keyId.buffer;
      }
      if (options.keyAltName) {
        const keyAltName = options.keyAltName;
        if (options.keyId) {
          throw new TypeError(`"options" cannot contain both "keyId" and "keyAltName"`);
        }
        const keyAltNameType = typeof keyAltName;
        if (keyAltNameType !== 'string') {
          throw new TypeError(
            `"options.keyAltName" must be of type string, but was of type ${keyAltNameType}`
          );
        }

        contextOptions.keyAltName = bson.serialize({ keyAltName });
      }

      const stateMachine = new StateMachine({
        bson,
        proxyOptions: this._proxyOptions,
        tlsOptions: this._tlsOptions
      });
      const context = this._mongoCrypt.makeExplicitEncryptionContext(valueBuffer, contextOptions);

      return promiseOrCallback(callback, cb => {
        stateMachine.execute(this, context, (err, result) => {
          if (err) {
            cb(err, null);
            return;
          }

          cb(null, result.v);
        });
      });
    }

    /**
     * @callback ClientEncryption~decryptCallback
     * @param {Error} [err] If present, indicates an error that occurred in the process of decryption
     * @param {object} [result] If present, is the decrypted result
     */

    /**
     * Explicitly decrypt a provided encrypted value
     *
     * @param {Buffer | Binary} value An encrypted value
     * @param {ClientEncryption~decryptCallback} callback Optional callback to invoke when value is decrypted
     * @returns {Promise|void} If no callback is provided, returns a Promise that either resolves with the decryped value, or rejects with an error. If a callback is provided, returns nothing.
     *
     * @example
     * // Decrypting value with callback API
     * function decryptMyValue(value, callback) {
     *   clientEncryption.decrypt(value, callback);
     * }
     *
     * @example
     * // Decrypting value with async/await API
     * async function decryptMyValue(value) {
     *   return clientEncryption.decrypt(value);
     * }
     */
    decrypt(value, callback) {
      const bson = this._bson;
      const valueBuffer = bson.serialize({ v: value });
      const context = this._mongoCrypt.makeExplicitDecryptionContext(valueBuffer);

      const stateMachine = new StateMachine({
        bson,
        proxyOptions: this._proxyOptions,
        tlsOptions: this._tlsOptions
      });

      return promiseOrCallback(callback, cb => {
        stateMachine.execute(this, context, (err, result) => {
          if (err) {
            cb(err, null);
            return;
          }

          cb(null, result.v);
        });
      });
    }

    /**
     * Ask the user for KMS credentials.
     *
     * This returns anything that looks like the kmsProviders original input
     * option. It can be empty, and any provider specified here will override
     * the original ones.
     */
    async askForKMSCredentials() {
      return this._onKmsProviderRefresh ? this._onKmsProviderRefresh() : {};
    }
  }

  return { ClientEncryption };
};
