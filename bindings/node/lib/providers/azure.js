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

/**
 * @type{import('@azure/core-rest-pipeline').HttpClient | null}
 */
let mockHttpClient = null;

/**
 * @param{import('@azure/core-rest-pipeline').HttpClient | null} client
 */
function setMockClient(client) {
  mockHttpClient = client;
}

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
   *
   * @param {string | string[]} scopes
   * @param {import('@azure/identity').GetTokenOptions} options
   */
  async getToken(scopes, options) {
    if (this._tokenNeedsRefresh()) {
      const token = await this.wrappedProvider.getToken(scopes, options);
      if (token == null) {
        throw new Error('Unable to refresh credentials');
      }
      this.cachedToken = token;
    }

    return this.cachedToken;
  }

  /**
   *
   * @param {import('@azure/identity').AccessToken | null} token
   */
  _tokenNeedsRefresh(token) {
    if (token == null) {
      return false;
    }
    const timeUntilExpirationMS = Date.now() - token.expiresOnTimestamp;
    return timeUntilExpirationMS <= MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS;
  }
}

/** @ignore */
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
      const options = mockHttpClient == null ? {} : { httpClient: mockHttpClient };
      const provider = new azureIdentityModule.ManagedIdentityCredential(options);
      tokenCacheProvider = new CredentialCacheProvider(provider);
    }

    const token = await tokenCacheProvider.getToken();
    if (!token) {
      throw new Error('asdf');
    }

    return { ...kmsProviders, azure: { accessToken: token.token } };
  }

  return kmsProviders;
}

module.exports = { loadAzureCredentials, setMockClient };
