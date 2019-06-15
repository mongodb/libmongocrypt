'use strict';

function debug(msg) {
  if (process.env.MONGODB_CRYPT_DEBUG) {
    console.log(msg);
  }
}

function databaseNamespace(ns) {
  return ns.split('.')[0];
}

function collectionNamespace(ns) {
  return ns
    .split('.')
    .slice(1)
    .join('.');
}

class MongoCryptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MongoCryptError';
    Error.captureStackTrace(this, this.constructor);
  }
}

function promiseOrCallback(callback, fn) {
  if (typeof callback === 'function') {
    fn(function(err) {
      if (err != null) {
        try {
          callback(err);
        } catch (error) {
          return process.nextTick(() => {
            throw error;
          });
        }
        return;
      }

      callback.apply(this, arguments);
    });

    return;
  }

  return new Promise((resolve, reject) => {
    fn(function(err, res) {
      if (err != null) {
        return reject(err);
      }

      if (arguments.length > 2) {
        return resolve(Array.prototype.slice.call(arguments, 1));
      }

      resolve(res);
    });
  });
}

module.exports = {
  debug,
  databaseNamespace,
  collectionNamespace,
  MongoCryptError,
  promiseOrCallback
};
