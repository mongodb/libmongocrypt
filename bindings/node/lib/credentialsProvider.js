'use strict';

let awsCredentialProviders = null;

/**
 * Load cloud provider credentials for the user provided KMS providers.
 * Credentials will only attempt to get loaded if they do not exist
 * and no existing credentials will get overwritten.
 *
 * @param {Object} kmsProviders - The user provided KMS providers.
 * @returns {Promise} The new kms providers.
 *
 * @ignore
 */
async function loadCredentials(kmsProviders) {
  if (awsCredentialProviders == null) {
    try {
      // Ensure you always wrap an optional require in the try block NODE-3199
      awsCredentialProviders = require('@aws-sdk/credential-providers');
      // eslint-disable-next-line no-empty
    } catch {}
  }

  if (awsCredentialProviders != null) {
    const aws = kmsProviders.aws;
    if (!aws || Object.keys(aws).length === 0) {
      const { fromNodeProviderChain } = awsCredentialProviders;
      const provider = fromNodeProviderChain();
      // The state machine is the only place calling this so it will
      // catch if there is a rejection here.
      const awsCreds = await provider();
      return { ...kmsProviders, aws: awsCreds };
    }
  }

  return kmsProviders;
}

module.exports = { loadCredentials };
