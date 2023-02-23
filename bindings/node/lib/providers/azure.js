'use strict';

const MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS = 6000;
/**
 * @type{import('@azure/identity')}
 */
let azureIdentityModule = null;

/**
 * @type{CredentialCacheProvider}
 */
let tokenCacheProvider = null;

const ADDITIONAL_POLICY_SYMBOL = Symbol.for('@@mdb.azureKMSAdditionalPolicies');

/**
 * @ignore
 * @implements {import('@azure/identity').TokenCredential}
 */
class CredentialCacheProvider {
  /**
   *
   * @param {import('@azure/identity').TokenCredential} internalProvider
   */
  constructor(internalProvider) {
    this.wrappedProvider = internalProvider;
    this.cachedToken = null;
  }

  /**
   * @param {string | string[]} scopes
   * @param {import('@azure/identity').GetTokenOptions} options
   */
  async getToken(scopes, options) {
    if (this._tokenNeedsRefresh()) {
      this.cachedToken = await this.wrappedProvider.getToken(scopes, options);
    }

    return this.cachedToken;
  }

  /**
   * Returns true if the cached token should be refreshed, false otherwise.
   * @param {import('@azure/identity').AccessToken | null} token
   */
  _tokenNeedsRefresh() {
    if (this.cachedToken == null) {
      return true;
    }
    const timeUntilExpirationMS = this.cachedToken.expiresOnTimestamp - Date.now();
    return timeUntilExpirationMS <= MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS;
  }
}

/**
 * @param {import('../../index').KMSProviders} kmsProviders
 * @ignore
 */
async function loadAzureCredentials(kmsProviders) {
  if (azureIdentityModule == null) {
    try {
      // Ensure you always wrap an optional require in the try block NODE-3199
      azureIdentityModule = require('@azure/identity');
      // eslint-disable-next-line no-empty
    } catch {}
  }

  if (azureIdentityModule != null) {
    if (tokenCacheProvider == null) {
      /**
       * @type{import('@azure/identity').TokenCredentialOptions}
       */
      const options = {
        additionalPolicies: kmsProviders[ADDITIONAL_POLICY_SYMBOL]
      };
      const provider = new azureIdentityModule.ManagedIdentityCredential(options);
      tokenCacheProvider = new CredentialCacheProvider(provider);
    }

    const token = await tokenCacheProvider.getToken(['https://vault.azure.net']);
    if (token != null) {
      return { ...kmsProviders, azure: { accessToken: token.token } };
    }
  }

  return kmsProviders;
}

module.exports = { loadAzureCredentials, CredentialCacheProvider };
