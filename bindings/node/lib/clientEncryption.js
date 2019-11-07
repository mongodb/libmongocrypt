'use strict';

module.exports = function(modules) {
  const mc = require('bindings')('mongocrypt');
  const common = require('./common');
  const databaseNamespace = common.databaseNamespace;
  const collectionNamespace = common.collectionNamespace;
  const promiseOrCallback = common.promiseOrCallback;
  const StateMachine = modules.stateMachine.StateMachine;
  const cryptoCallbacks = require('./cryptoCallbacks');

  function sanitizeDataKeyOptions(bson, options) {
    options = Object.assign({}, options);

    // To avoid using libbson inside the bindings, we pre-serialize
    // any keyAltNames here.
    if (options.keyAltNames) {
      if (!Array.isArray(options.keyAltNames)) {
        throw new TypeError(
          `Option "keyAltNames" must be an array of string, but was of type ${typeof options.keyAltNames}.`
        );
      }
      const serializedKeyAltNames = [];
      for (let i = 0; i < options.keyAltNames.length; i += 1) {
        const item = options.keyAltNames[i];
        const itemType = typeof item;
        if (itemType !== 'string') {
          throw new TypeError(
            `Option "keyAltNames" must be an array of string, but item at index ${i} was of type ${itemType} `
          );
        }

        serializedKeyAltNames.push(bson.serialize({ keyAltName: item }));
      }

      options.keyAltNames = serializedKeyAltNames;
    } else if (options.keyAltNames == null) {
      // If keyAltNames is null or undefined, we can assume the intent of
      // the user is to not pass in the value. B/c Nan::Has will still
      // register a value of null or undefined as present as long
      // as the key is present, we delete it off of the options
      // object here.
      delete options.keyAltNames;
    }

    return options;
  }

  /**
   * @typedef {object} KMSProviders
   * @description Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.
   * @prop {object} [aws] Configuration options for using 'aws' as your KMS provider
   * @prop {string} [aws.accessKeyId] The access key used for the AWS KMS provider
   * @prop {string} [aws.secretAccessKey] The secret access key used for the AWS KMS provider
   * @prop {object} [local] Configuration options for using 'local' as your KMS provider
   * @prop {Buffer} [local.key] The master key used to encrypt/decrypt data keys. A 96-byte long Buffer.
   */

  /**
   * The public interface for explicit client side encryption
   */
  class ClientEncryption {
    /**
     * Create a new encryption instance
     *
     * @param {MongoClient} client The client used for encryption
     * @param {object} options Optional settings
     * @param {string} options.keyVaultNamespace The namespace of the key vault, used to store encryption keys
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
      this._bson = client.topology.bson;

      if (options.keyVaultNamespace == null) {
        throw new TypeError('Missing required option `keyVaultNamespace`');
      }

      Object.assign(options, { cryptoCallbacks });
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
     * Creates a data key used for explicit encryption and inserts it into the key vault namespace
     *
     * @param {string} provider The KMS provider used for this data key. Must be `'aws'` or `'local'`
     * @param {object} [options] Options for creating the data key
     * @param {object} [options.masterKey] Idenfities a new KMS-specific key used to encrypt the new data key. If the kmsProvider is "aws" it is required.
     * @param {string} [options.masterKey.region] The AWS region of the KMS
     * @param {string} [options.masterKey.key] The Amazon Resource Name (ARN) to the AWS customer master key (CMK)
     * @param {string} [options.masterKey.endpoint] An alternate host to send KMS requests to. May include port number.
     * @param {string[]} [options.keyAltNames] An optional list of string alternate names used to reference a key. If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id.
     * @param {ClientEncryption~createDataKeyCallback} [callback] Optional callback to invoke when key is created
     * @returns {Promise|void} If no callback is provided, returns a Promise that either resolves with {@link ClientEncryption~dataKeyId the id of the created data key}, or rejects with an error. If a callback is provided, returns nothing.
     * @example
     * // Using callbacks to create a local key
     * clientEncrypion.createDataKey('local', (err, dataKey) => {
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
      if (typeof options === 'function') (callback = options), (options = {});
      options = sanitizeDataKeyOptions(this._bson, options);

      const context = this._mongoCrypt.makeDataKeyContext(provider, options);
      const stateMachine = new StateMachine();

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
            .insertOne(dataKey, { w: 'majority' }, (err, result) => {
              if (err) {
                cb(err, null);
                return;
              }

              cb(null, result.insertedId);
            });
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
     * @param {} options.algorithm The algorithm to use for encryption. Must be either `'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'` or `AEAD_AES_256_CBC_HMAC_SHA_512-Random'`
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

      const stateMachine = new StateMachine();
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
     * @param {Buffer} value An encrypted value
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

      const stateMachine = new StateMachine();

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
  }

  return { ClientEncryption };
};
