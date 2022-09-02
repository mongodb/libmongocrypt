'use strict';

/**
 * @ignore
 * Helper function for logging. Enabled by setting the environment flag MONGODB_CRYPT_DEBUG.
 * @param {*} msg Anything you want to be logged.
 */
function debug(msg) {
  if (process.env.MONGODB_CRYPT_DEBUG) {
    // eslint-disable-next-line no-console
    console.error(msg);
  }
}

/**
 * @ignore
 * Gets the database portion of a namespace string
 * @param {string} ns A string in the format of a namespace (database.collection)
 * @returns {string} The database portion of the namespace
 */
function databaseNamespace(ns) {
  return ns.split('.')[0];
}
/**
 * @ignore
 * Gets the colleciton portion of a namespace string
 * @param {string} ns A string in the format of a namespace (database.collection)
 * @returns {string} The collection portion of the namespace
 */
function collectionNamespace(ns) {
  return ns.split('.').slice(1).join('.');
}

/**
 * @class
 * An error indicating that something went wrong specifically with MongoDB Client Encryption
 */
class MongoCryptError extends Error {
  constructor(message) {
    super(message);
    Error.captureStackTrace(this, this.constructor);
  }

  get name() {
    return 'MongoCryptError';
  }
}

/**
 * @ignore
 * A helper function. Invokes a function that takes a callback as the final
 * parameter. If a callback is supplied, then it is passed to the function.
 * If not, a Promise is returned that resolves/rejects with the result of the
 * callback
 * @param {Function} [callback] an optional callback.
 * @param {Function} fn A function that takes a callback
 * @returns {Promise|void} Returns nothing if a callback is supplied, else returns a Promise.
 */
function promiseOrCallback(callback, fn) {
  if (typeof callback === 'function') {
    fn(function (err) {
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
    fn(function (err, res) {
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

/**
 * Ask for KMS credentials.
 *
 * This returns anything that looks like the kmsProviders original input
 * option. It can be empty, and any provider specified here will override
 * the original ones.
 *
 * @param {AutoEncrypter|ClientEncryption} encrypter The encrypter.
 */
async function askForKMSCredentials(encrypter) {
  // First attempt to use the user provided callback to get the credentials.
  const creds = encrypter._onKmsProviderRefresh ? await encrypter._onKmsProviderRefresh() : {};
  // If the credentials are empty and we have an additional callback provided
  // by the driver to attempt to fetch them, attempt to use that. We single out
  // AWS for now since it's the only $external cloud provider auth that the driver
  // supports.
  if (!creds.aws && encrypter._onEmptyKmsProviders) {
    return encrypter._onEmptyKmsProviders();
  }
  // Return the credentials which could be populated or empty.
  return creds;
}

module.exports = {
  askForKMSCredentials,
  debug,
  databaseNamespace,
  collectionNamespace,
  MongoCryptError,
  promiseOrCallback
};
