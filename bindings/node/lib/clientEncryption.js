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
    } else if (options.keyAltNAmes == null) {
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
   * The public interface for explicit client side encryption
   */
  class ClientEncryption {
    /**
     * Create a new encryption instance
     *
     * @param {MongoClient} client The client used for encryption
     * @param {object} options Optional settings
     * @param {string} options.keyVaultNamespace The namespace of the key vault, used to store encryption keys
     */
    constructor(client, options) {
      this._client = client;
      this._bson = client.topology.bson;

      if (options.keyVaultNamespace == null) {
        throw new TypeError('Missing required option `keyVaultNamespace`');
      }

      Object.assign(options, { cryptoCallbacks });
      this._keyVaultNamespace = options.keyVaultNamespace;
      this._mongoCrypt = new mc.MongoCrypt(options);
    }

    /**
     * Creates a data key used for explicit encryption
     *
     * @param {string} provider The KMS provider used for this data key
     * @param {*} options
     * @param {function} callback
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

          this._client
            .db(dbName)
            .collection(collectionName)
            .insertOne(dataKey, (err, result) => {
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
     * Explicitly encrypt a provided value
     *
     * @param {*} value
     * @param {*} options
     * @param {*} callback
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
     * Explicitly decrypt a provided encrypted value
     *
     * @param {*} value
     * @param {*} callback
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
