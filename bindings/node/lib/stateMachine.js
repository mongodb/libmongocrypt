'use strict';

module.exports = function(modules) {
  const tls = require('tls');
  const MongoTimeoutError = modules.mongodb.MongoTimeoutError;
  const common = require('./common');
  const debug = common.debug;
  const databaseNamespace = common.databaseNamespace;
  const collectionNamespace = common.collectionNamespace;
  const MongoCryptError = common.MongoCryptError;

  // libmongocrypt states
  const MONGOCRYPT_CTX_ERROR = 0;
  const MONGOCRYPT_CTX_NEED_MONGO_COLLINFO = 1;
  const MONGOCRYPT_CTX_NEED_MONGO_MARKINGS = 2;
  const MONGOCRYPT_CTX_NEED_MONGO_KEYS = 3;
  const MONGOCRYPT_CTX_NEED_KMS = 4;
  const MONGOCRYPT_CTX_READY = 5;
  const MONGOCRYPT_CTX_DONE = 6;

  const HTTPS_PORT = 443;

  function stateToString(state) {
    if (state === MONGOCRYPT_CTX_ERROR) return 'MONGOCRYPT_CTX_ERROR';
    if (state === MONGOCRYPT_CTX_NEED_MONGO_COLLINFO) return 'MONGOCRYPT_CTX_NEED_MONGO_COLLINFO';
    if (state === MONGOCRYPT_CTX_NEED_MONGO_MARKINGS) return 'MONGOCRYPT_CTX_NEED_MONGO_MARKINGS';
    if (state === MONGOCRYPT_CTX_NEED_MONGO_KEYS) return 'MONGOCRYPT_CTX_NEED_MONGO_KEYS';
    if (state === MONGOCRYPT_CTX_NEED_KMS) return 'MONGOCRYPT_CTX_NEED_KMS';
    if (state === MONGOCRYPT_CTX_READY) return 'MONGOCRYPT_CTX_READY';
    if (state === MONGOCRYPT_CTX_DONE) return 'MONGOCRYPT_CTX_DONE';
  }

  class StateMachine {
    execute(autoEncrypter, context, callback) {
      const bson = autoEncrypter._bson;
      const client = autoEncrypter._client;
      const keyVaultNamespace = autoEncrypter._keyVaultNamespace;
      const mongocryptdClient = autoEncrypter._mongocryptdClient;
      const mongocryptdManager = autoEncrypter._mongocryptdManager;

      debug(`[context#${context.id}] ${stateToString(context.state)}`);
      switch (context.state) {
        case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO: {
          const filter = bson.deserialize(context.nextMongoOperation());
          this.fetchCollectionInfo(client, context.ns, filter, (err, collInfo) => {
            if (err) {
              return callback(err, null);
            }

            if (collInfo) {
              context.addMongoOperationResponse(collInfo);
            }

            context.finishMongoOperation();
            this.execute(autoEncrypter, context, callback);
          });

          return;
        }

        case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS: {
          const command = context.nextMongoOperation();
          this.markCommand(mongocryptdClient, context.ns, command, (err, markedCommand) => {
            if (err) {
              // If we are not bypassing spawning, then we should retry once on a MongoTimeoutError (server selection error)
              if (
                err instanceof MongoTimeoutError &&
                mongocryptdManager &&
                !mongocryptdManager.bypassSpawn
              ) {
                mongocryptdManager.spawn(() => {
                  // TODO: should we be shadowing the variables here?
                  this.markCommand(mongocryptdClient, context.ns, command, (err, markedCommand) => {
                    if (err) return callback(err, null);

                    context.addMongoOperationResponse(markedCommand);
                    context.finishMongoOperation();

                    this.execute(autoEncrypter, context, callback);
                  });
                });
                return;
              }
              return callback(err, null);
            }
            context.addMongoOperationResponse(markedCommand);
            context.finishMongoOperation();

            this.execute(autoEncrypter, context, callback);
          });

          return;
        }

        case MONGOCRYPT_CTX_NEED_MONGO_KEYS: {
          const filter = context.nextMongoOperation();
          this.fetchKeys(client, keyVaultNamespace, filter, (err, keys) => {
            if (err) return callback(err, null);
            keys.forEach(key => {
              context.addMongoOperationResponse(bson.serialize(key));
            });

            context.finishMongoOperation();
            this.execute(autoEncrypter, context, callback);
          });

          return;
        }

        case MONGOCRYPT_CTX_NEED_KMS: {
          const promises = [];

          let request;
          while ((request = context.nextKMSRequest())) {
            promises.push(this.kmsRequest(request));
          }

          Promise.all(promises)
            .then(() => {
              context.finishKMSRequests();
              this.execute(autoEncrypter, context, callback);
            })
            .catch(err => {
              callback(err, null);
            });

          return;
        }

        // terminal states
        case MONGOCRYPT_CTX_READY: {
          const finalizedContext = context.finalize();
          // TODO: Maybe rework the logic here so that instead of doing
          // the callback here, finalize stores the result, and then
          // we wait to MONGOCRYPT_CTX_DONE to do the callback
          if (context.state === MONGOCRYPT_CTX_ERROR) {
            const message = context.status.message || 'Finalization error';
            callback(new MongoCryptError(message));
            return;
          }
          callback(null, bson.deserialize(finalizedContext));
          return;
        }
        case MONGOCRYPT_CTX_ERROR: {
          const message = context.status.message;
          callback(new MongoCryptError(message));
          return;
        }

        case MONGOCRYPT_CTX_DONE:
          return;

        default:
          callback(new MongoCryptError(`Unknown state: ${context.state}`));
          return;
      }
    }

    /**
     *
     * @param {*} kmsContext
     */
    kmsRequest(request) {
      const options = { host: request.endpoint, port: HTTPS_PORT };
      const message = request.message;

      return new Promise((resolve, reject) => {
        const socket = tls.connect(options, () => {
          socket.write(message);
        });

        socket.once('timeout', () => {
          socket.removeAllListeners();
          socket.destroy();
          reject(new MongoCryptError('KMS request timed out'));
        });

        socket.once('error', err => {
          socket.removeAllListeners();
          socket.destroy();
          reject(err);
        });

        socket.on('data', buffer => {
          request.addResponse(buffer);

          if (request.bytesNeeded <= 0) {
            socket.end(resolve);
          }
        });
      });
    }

    /**
     * Fetches collection info for a provided namespace, when libmongocrypt
     * enters the `MONGOCRYPT_CTX_NEED_MONGO_COLLINFO` state. The result is
     * used to inform libmongocrypt of the schema associated with this
     * namespace.
     *
     * @param {MongoClient} client The shared
     * @param {string} ns The namespace to list collections from
     * @param {object} filter A filter used to select a particular
     * @param {function} callback
     */
    fetchCollectionInfo(client, ns, filter, callback) {
      const bson = client.topology.bson;
      const dbName = databaseNamespace(ns);

      client
        .db(dbName)
        .listCollections(filter)
        .toArray((err, collections) => {
          if (err) {
            callback(err, null);
            return;
          }

          const info = collections.length > 0 ? bson.serialize(collections[0]) : null;
          callback(null, info);
        });
    }

    /**
     *
     */
    markCommand(client, ns, command, callback) {
      const bson = client.topology.bson;
      const dbName = databaseNamespace(ns);
      const rawCommand = bson.deserialize(command);

      client.db(dbName).command(rawCommand, (err, response) => {
        if (err) {
          callback(err, null);
          return;
        }

        callback(err, bson.serialize(response));
      });
    }

    /**
     *
     */
    fetchKeys(client, keyVaultNamespace, filter, callback) {
      const bson = client.topology.bson;
      const dbName = databaseNamespace(keyVaultNamespace);
      const collectionName = collectionNamespace(keyVaultNamespace);
      filter = bson.deserialize(filter);

      client
        .db(dbName)
        .collection(collectionName)
        .find(filter)
        .toArray((err, keys) => {
          if (err) {
            callback(err, null);
            return;
          }

          callback(null, keys);
        });
    }
  }

  return { StateMachine };
};
