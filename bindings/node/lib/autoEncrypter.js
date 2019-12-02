'use strict';

module.exports = function(modules) {
  const mc = require('bindings')('mongocrypt');
  const common = require('./common');
  const databaseNamespace = common.databaseNamespace;
  const StateMachine = modules.stateMachine.StateMachine;
  const MongocryptdManager = require('./mongocryptdManager').MongocryptdManager;
  const MongoClient = modules.mongodb.MongoClient;
  const MongoError = modules.mongodb.MongoError;
  const cryptoCallbacks = require('./cryptoCallbacks');

  /**
   * Configuration options for a automatic client encryption.
   *
   * @typedef {Object} AutoEncrypter~AutoEncryptionOptions
   * @property {MongoClient} [keyVaultClient] A `MongoClient` used to fetch keys from a key vault
   * @property {string} [keyVaultNamespace] The namespace where keys are stored in the key vault
   * @property {KMSProviders} [kmsProviders] Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.
   * @property {object} [schemaMap] A map of namespaces to a local JSON schema for encryption
   * @property {boolean} [bypassAutoEncryption] Allows the user to bypass auto encryption, maintaining implicit decryption
   * @property {AutoEncrypter~logger} [options.logger] An optional hook to catch logging messages from the underlying encryption engine
   * @property {AutoEncrypter~AutoEncryptionExtraOptions} [extraOptions] Extra options related to the mongocryptd process
   */

  /**
   * Extra options related to the mongocryptd process
   * @typedef {object} AutoEncrypter~AutoEncryptionExtraOptions
   * @property {string} [mongocryptdURI] A local process the driver communicates with to determine how to encrypt values in a command. Defaults to "mongodb://%2Fvar%2Fmongocryptd.sock" if domain sockets are available or "mongodb://localhost:27020" otherwise
   * @property {boolean} [mongocryptdBypassSpawn=false] If true, autoEncryption will not attempt to spawn a mongocryptd before connecting
   * @property {string} [mongocryptdSpawnPath] The path to the mongocryptd executable on the system
   * @property {string[]} [mongocryptdSpawnArgs] Command line arguments to use when auto-spawning a mongocryptd
   */

  /**
   * @callback AutoEncrypter~logger
   * @description A callback that is invoked with logging information from
   * the underlying C++ Bindings.
   * @param {AutoEncrypter~logLevel} level The level of logging.
   * @param {string} message The message to log
   */

  /**
   * @name AutoEncrypter~logLevel
   * @enum {number}
   * @description
   * The level of severity of the log message
   *
   * | Value | Level |
   * |-------|-------|
   * | 0 | Fatal Error |
   * | 1 | Error |
   * | 2 | Warning |
   * | 3 | Info |
   * | 4 | Trace |
   */

  /**
   * @classdesc An internal class to be used by the driver for auto encryption
   * **NOTE**: Not meant to be instantiated directly, this is for internal use only.
   */
  class AutoEncrypter {
    /**
     * Create an AutoEncrypter
     *
     * **Note**: Do not instantiate this class directly. Rather, supply the relevant options to a MongoClient
     *
     * **Note**: Supplying `options.schemaMap` provides more security than relying on JSON Schemas obtained from the server.
     * It protects against a malicious server advertising a false JSON Schema, which could trick the client into sending unencrypted data that should be encrypted.
     * Schemas supplied in the schemaMap only apply to configuring automatic encryption for client side encryption.
     * Other validation rules in the JSON schema will not be enforced by the driver and will result in an error.
     * @param {MongoClient} client The client autoEncryption is enabled on
     * @param {AutoEncrypter~AutoEncryptionOptions} [options] Optional settings
     *
     * @example
     * // Enabling autoEncryption via a MongoClient
     * const { MongoClient } = require('mongodb');
     * const client = new MongoClient(URL, {
     *   autoEncryption: {
     *     kmsProviders: {
     *       aws: {
     *         accessKeyId: AWS_ACCESS_KEY,
     *         secretAccessKey: AWS_SECRET_KEY
     *       }
     *     }
     *   }
     * });
     *
     * await client.connect();
     * // From here on, the client will be encrypting / decrypting automatically
     */
    constructor(client, options) {
      this._client = client;
      this._bson = client.topology.bson;
      this._mongocryptdManager = new MongocryptdManager(options.extraOptions);
      this._mongocryptdClient = new MongoClient(this._mongocryptdManager.uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 1000
      });
      this._keyVaultNamespace = options.keyVaultNamespace || 'admin.datakeys';
      this._keyVaultClient = options.keyVaultClient || client;

      const mongoCryptOptions = {};
      if (options.schemaMap) {
        mongoCryptOptions.schemaMap = Buffer.isBuffer(options.schemaMap)
          ? options.schemaMap
          : this._bson.serialize(options.schemaMap);
      }

      if (options.kmsProviders) {
        mongoCryptOptions.kmsProviders = options.kmsProviders;
      }

      if (options.logger) {
        mongoCryptOptions.logger = options.logger;
      }

      Object.assign(mongoCryptOptions, { cryptoCallbacks });
      this._mongocrypt = new mc.MongoCrypt(mongoCryptOptions);
      this._contextCounter = 0;
    }

    /**
     * @ignore
     * @param {Function} callback Invoked when the mongocryptd client either successfully connects or errors
     */
    init(callback) {
      const _callback = (err, res) => {
        if (err && err.message && err.message.match(/timed out after/)) {
          callback(
            new MongoError(
              'Unable to connect to `mongocryptd`, please make sure it is running or in your PATH for auto-spawn'
            )
          );
          return;
        }

        callback(err, res);
      };

      if (this._mongocryptdManager.bypassSpawn) {
        return this._mongocryptdClient.connect(_callback);
      }

      this._mongocryptdManager.spawn(() => this._mongocryptdClient.connect(_callback));
    }

    /**
     * @ignore
     * @param {Function} callback Invoked when the mongocryptd client either successfully disconnects or errors
     */
    teardown(force, callback) {
      this._mongocryptdClient.close(force, callback);
    }

    /**
     * @ignore
     * Encrypt a command for a given namespace.
     *
     * @param {string} ns The namespace for this encryption context
     * @param {object} cmd The command to encrypt
     * @param {Function} callback
     */
    encrypt(ns, cmd, options, callback) {
      if (typeof ns !== 'string') {
        throw new TypeError('Parameter `ns` must be a string');
      }

      if (typeof cmd !== 'object') {
        throw new TypeError('Parameter `cmd` must be an object');
      }

      if (typeof options === 'function' && callback == null) {
        callback = options;
        options = {};
      }

      const bson = this._bson;
      const commandBuffer = Buffer.isBuffer(cmd) ? cmd : bson.serialize(cmd, options);

      let context;
      try {
        context = this._mongocrypt.makeEncryptionContext(databaseNamespace(ns), commandBuffer);
      } catch (err) {
        callback(err, null);
        return;
      }

      // TODO: should these be accessors from the addon?
      context.id = this._contextCounter++;
      context.ns = ns;
      context.document = cmd;

      const stateMachine = new StateMachine(options);
      stateMachine.execute(this, context, callback);
    }

    /**
     * @ignore
     * Decrypt a command response
     *
     * @param {Buffer} buffer
     * @param {Function} callback
     */
    decrypt(response, options, callback) {
      if (typeof options === 'function' && callback == null) {
        callback = options;
        options = {};
      }

      const bson = this._bson;
      const buffer = Buffer.isBuffer(response) ? response : bson.serialize(response, options);

      let context;
      try {
        context = this._mongocrypt.makeDecryptionContext(buffer);
      } catch (err) {
        callback(err, null);
        return;
      }

      // TODO: should this be an accessor from the addon?
      context.id = this._contextCounter++;

      const stateMachine = new StateMachine(options);
      stateMachine.execute(this, context, callback);
    }
  }

  return { AutoEncrypter };
};
