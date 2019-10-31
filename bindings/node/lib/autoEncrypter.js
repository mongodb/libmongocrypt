'use strict';

module.exports = function(modules) {
  const mc = require('bindings')('mongocrypt');
  const common = require('./common');
  const databaseNamespace = common.databaseNamespace;
  const StateMachine = modules.stateMachine.StateMachine;
  const MongocryptdManager = require('./mongocryptdManager').MongocryptdManager;
  const MongoClient = modules.mongodb.MongoClient;
  const cryptoCallbacks = require('./cryptoCallbacks');

  /**
   * @typedef AutoEncrypter~AutoEncryptionExtraOptions
   * @prop {string} [mongocryptdURI] overrides the uri used to connect to mongocryptd
   * @prop {boolean} [mongocryptdBypassSpawn=false] if true, autoEncryption will not spawn a mongocryptd
   * @prop {string} [mongocryptdSpawnPath] the path to the mongocryptd executable
   * @prop {string[]} [mongocryptdSpawnArgs] command line arguments to pass to the mongocryptd executable
   */

  /**
   * An internal class to be used by the driver for auto encryption
   * **NOTE**: Not meant to be instantiated directly, this is for internal use only.
   */
  class AutoEncrypter {
    /**
     * @name AutoEncrypter~logLevel
     * @kind enum
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
     * @callback AutoEncrypter~logger
     * @descritpion A callback that is invoked with logging information from
     * the underlying C++ Bindings.
     * @param {AutoEncrypter~logLevel} level The level of logging. Valid values are 0 (Fatal Error), 1 (Error), 2 (Warning), 3 (Info), 4 (Trace)
     * @param {string} message The message to log
     */

    /**
     * Create an AutoEncrypter
     *
     * **Note**: Do not instantiate this class directly. Rather, supply the relevant options to a MongoClient
     *
     * **Note**: Supplying `options.schemaMap` provides more security than relying on JSON Schemas obtained from the server.
     * It protects against a malicious server advertising a false JSON Schema, which could trick the client into sending unencrypted data that should be encrypted.
     * Schemas supplied in the schemaMap only apply to configuring automatic encryption for client side encryption.
     * Other validation rules in the JSON schema will not be enforced by the driver and will result in an error.
     *
     * @param {MongoClient} client The client autoEncryption is enabled on
     * @param {object} [options] Optional settings
     * @param {string} [options.keyVaultNamespace='admin.dataKeys'] The namespace of the key vault, used to store encryption keys
     * @param {object} [options.schemaMap] A local specification of a JSON schema used for encryption
     * @param {KMSProviders} [options.kmsProviders] options for specific KMS providers to use
     * @param {function} [options.logger] An optional hook to catch logging messages from the underlying encryption engine
     * @param {AutoEncrypter~AutoEncryptionExtraOptions} [options.extraOptions] Extra options related to mongocryptd
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
        useUnifiedTopology: true
      });
      this._keyVaultNamespace = options.keyVaultNamespace || 'admin.datakeys';

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
      if (this._mongocryptdManager.bypassSpawn) {
        return this._mongocryptdClient.connect(callback);
      }

      this._mongocryptdManager.spawn(() => {
        this._mongocryptdClient.connect(callback);
      });
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
