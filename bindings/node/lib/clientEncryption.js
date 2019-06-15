'use strict';
const mc = require('bindings')('mongocrypt');
const common = require('./common');
const databaseNamespace = common.databaseNamespace;
const collectionNamespace = common.collectionNamespace;
const promiseOrCallback = common.promiseOrCallback;
const StateMachine = require('./stateMachine').StateMachine;

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
    options = options || {};

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

module.exports = { ClientEncryption };
