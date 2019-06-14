'use strict';
const mc = require('bindings')('mongocrypt');
const common = require('./common');
const databaseNamespace = common.databaseNamespace;
const StateMachine = require('./stateMachine').StateMachine;

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
   * @param {MongoClient} options.mongocryptdClient The client used for communication with `mongocryptd`
   * @param {string} options.keyVaultNamespace The namespace of the key vault, used to store encryption keys
   * @param {object} options.schemaMap
   * @param {object} options.kmsProviders
   * @param {function} options.logger
   */
  constructor(client, options) {
    this._client = client;
    this._bson = client.topology.bson;
    this._mongocryptdClient = options.mongocryptdClient;
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

    this._mongocrypt = new mc.MongoCrypt(mongoCryptOptions);
    this._contextCounter = 0;
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

module.exports = { AutoEncrypter };
