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

module.exports = {
  debug,
  databaseNamespace,
  collectionNamespace,
  MongoCryptError
};
