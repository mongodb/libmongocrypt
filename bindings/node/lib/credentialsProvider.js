'use strict';

/**
 * @ignore
 * Auto credential fetching should only occur when the provider is defined on the kmsProviders map
 * and the settings are an empty object.
 *
 * This is distinct from a nullish provider key.
 *
 * @param {string} provider
 * @param {object} kmsProviders
 */
function isEmptyCredentials(provider, kmsProviders) {
  return (
    provider in kmsProviders &&
    kmsProviders[provider] != null &&
    typeof kmsProviders[provider] === 'object' &&
    Object.keys(kmsProviders[provider]).length === 0
  );
}

let awsCredentialProviders = null;
/** @ignore */
async function loadAWSCredentials(kmsProviders) {
  if (awsCredentialProviders == null) {
    try {
      // Ensure you always wrap an optional require in the try block NODE-3199
      awsCredentialProviders = require('@aws-sdk/credential-providers');
      // eslint-disable-next-line no-empty
    } catch {}
  }

  if (awsCredentialProviders != null) {
    const { fromNodeProviderChain } = awsCredentialProviders;
    const provider = fromNodeProviderChain();
    // The state machine is the only place calling this so it will
    // catch if there is a rejection here.
    const aws = await provider();
    return { ...kmsProviders, aws };
  }

  return kmsProviders;
}

let gcpMetadata = null;
/** @ignore */
async function loadGCPCredentials(kmsProviders) {
  if (gcpMetadata == null) {
    try {
      // Ensure you always wrap an optional require in the try block NODE-3199
      gcpMetadata = require('gcp-metadata');
      // eslint-disable-next-line no-empty
    } catch {}
  }

  if (gcpMetadata != null) {
    const { access_token: accessToken } = await gcpMetadata.instance({
      property: 'service-accounts/default/token'
    });
    return { ...kmsProviders, gcp: { accessToken } };
  }

  return kmsProviders;
}

/**
 * Load cloud provider credentials for the user provided KMS providers.
 * Credentials will only attempt to get loaded if they do not exist
 * and no existing credentials will get overwritten.
 *
 * @param {object} kmsProviders - The user provided KMS providers.
 * @returns {Promise} The new kms providers.
 *
 * @ignore
 */
async function loadCredentials(kmsProviders) {
  let finalKMSProviders = kmsProviders;

  if (isEmptyCredentials('aws', kmsProviders)) {
    finalKMSProviders = await loadAWSCredentials(finalKMSProviders);
  }

  if (isEmptyCredentials('gcp', kmsProviders)) {
    finalKMSProviders = await loadGCPCredentials(finalKMSProviders);
  }

  return finalKMSProviders;
}

module.exports = { loadCredentials, isEmptyCredentials };
