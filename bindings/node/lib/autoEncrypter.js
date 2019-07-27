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
   * An internal class to be used by the driver for auto encryption
   * **NOTE**: Not meant to be instantiated directly, this is for internal use only.
   */
  class AutoEncrypter {
    /**
     * Create an AutoEncrypter
     *
     * @param {object} options Optional settings
     * @param {MongoClient} options.client The parent client auto encryption is enabled on
     * @param {string} options.keyVaultNamespace The namespace of the key vault, used to store encryption keys
     * @param {object} options.schemaMap
     * @param {object} options.kmsProviders
     * @param {function} options.logger
     * @param {AutoEncryptionExtraOptions} [options.extraOptions] Extra options related to mongocryptd
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

    init(callback) {
      if (this._mongocryptdManager.bypassSpawn) {
        return this._mongocryptdClient.connect(callback);
      }

      this._mongocryptdManager.spawn(() => {
        this._mongocryptdClient.connect(callback);
      });
    }

    teardown(force, callback) {
      this._mongocryptdClient.close(force, callback);
    }

    /**
     * Encrypt a command for a given namespace
     *
     * @param {string} ns The namespace for this encryption context
     * @param {object} cmd The command to encrypt
     * @param {function} callback
     */
    encrypt(ns, cmd, callback) {
      if (typeof ns !== 'string') {
        throw new TypeError('Parameter `ns` must be a string');
      }

      if (typeof cmd !== 'object') {
        throw new TypeError('Parameter `cmd` must be an object');
      }

      const bson = this._bson;
      const commandBuffer = Buffer.isBuffer(cmd) ? cmd : bson.serialize(cmd);

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

      const stateMachine = new StateMachine();
      stateMachine.execute(this, context, callback);
    }

    /**
     * Decrypt a command response
     *
     * @param {*} buffer
     * @param {*} callback
     */
    decrypt(response, callback) {
      const bson = this._bson;
      const buffer = Buffer.isBuffer(response) ? response : bson.serialize(response);

      let context;
      try {
        context = this._mongocrypt.makeDecryptionContext(buffer);
      } catch (err) {
        callback(err, null);
        return;
      }

      // TODO: should this be an accessor from the addon?
      context.id = this._contextCounter++;

      const stateMachine = new StateMachine();
      stateMachine.execute(this, context, callback);
    }
  }

  return { AutoEncrypter };
};
